// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Bridge from async request handlers to the synchronous engine API (PD-050).
//!
//! `rustegon-engine` is synchronous: a call may block on disk I/O, on locks or on CPU-heavy
//! query evaluation. Running it on a Tokio worker would stall every other connection served
//! by that worker (coding-standards.md §3.3), so handlers hand engine calls to
//! [`Executor::run`], which
//!
//! 1. fails fast with RGN-5006 when the request deadline has already passed;
//! 2. waits for one of `max_in_flight` permits (a bounded queue: overload shows up as queueing
//!    bounded by the deadline, not as an unbounded number of blocking threads);
//! 3. runs the closure on Tokio's blocking pool with a [`CancelToken`];
//! 4. races it against the deadline and the caller dropping the request future.
//!
//! The engine has no preemption, so cancellation is cooperative: the token flips to cancelled
//! (client went away: RGN-5005) or expired (deadline: RGN-5006), and long-running engine code
//! polls [`CancelToken::check`] at safe points. What the handler sees depends on
//! [`Completion`]:
//! - [`Completion::Abandon`] (reads): at the deadline the handler returns RGN-5006 at once; the
//!   closure keeps its permit until it notices the token or finishes, and its result is dropped.
//! - [`Completion::Await`] (writes): the handler always waits for the closure's own result, so
//!   a mutation is never reported as failed while it actually committed; the token still tells
//!   the closure that the deadline passed, and the closure decides whether it can stop.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};

use rustegon_common::{Error, ErrorCode};
use rustegon_sim_api::Clock;
use tokio::sync::Semaphore;

use crate::services::{RequestContext, cancelled, context::Deadline, deadline_exceeded};

const RUNNING: u8 = 0;
const CANCELLED: u8 = 1;
const EXPIRED: u8 = 2;

/// Cooperative cancellation flag handed to engine closures.
#[derive(Debug, Clone)]
pub struct CancelToken {
    state: Arc<AtomicU8>,
    deadline: Option<Deadline>,
}

impl CancelToken {
    fn new(deadline: Option<Deadline>) -> Self {
        Self {
            state: Arc::new(AtomicU8::new(RUNNING)),
            deadline,
        }
    }

    /// A token that is never cancelled and has no deadline (tests, internal jobs).
    #[must_use]
    pub fn never() -> Self {
        Self::new(None)
    }

    /// `Ok` while the request is still wanted; RGN-5005 `Cancelled` after the client went away,
    /// RGN-5006 `DeadlineExceeded` after the deadline.
    ///
    /// # Errors
    /// See above.
    pub fn check(&self) -> Result<(), Error> {
        match self.state.load(Ordering::Acquire) {
            RUNNING => Ok(()),
            EXPIRED => Err(deadline_exceeded()),
            _ => Err(cancelled()),
        }
    }

    /// Whether the request was cancelled or expired.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire) != RUNNING
    }

    /// The request deadline, to propagate the remaining time to deeper layers
    /// (protocol.md §5.2).
    #[must_use]
    pub fn deadline(&self) -> Option<Deadline> {
        self.deadline
    }

    /// First reason wins: an expired request that is later dropped stays "expired".
    fn set(&self, reason: u8) {
        let _ = self
            .state
            .compare_exchange(RUNNING, reason, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Cancels the token when the handler future is dropped before the closure's result was
/// taken (client cancel, connection loss, server shutdown).
struct CancelOnDrop {
    token: CancelToken,
    armed: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.token.set(CANCELLED);
        }
    }
}

/// How [`Executor::run`] treats the deadline once the closure has started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// Return RGN-5006 as soon as the deadline passes and drop the closure's later result.
    /// For operations without side effects (reads, queries, explain).
    Abandon,
    /// Wait for the closure's result even after the deadline. For mutations, whose outcome
    /// must never be misreported.
    Await,
}

/// Decrements the queue gauge when a waiting call got its permit or gave up.
struct QueuedGuard(Arc<AtomicUsize>);

impl QueuedGuard {
    fn enter(queued: &Arc<AtomicUsize>) -> Self {
        // `Relaxed`: an independent statistic, read only for reporting.
        queued.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(queued))
    }
}

impl Drop for QueuedGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Default bound on concurrently running engine calls.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 256;

/// Runs synchronous engine calls off the async workers. Cheap to clone.
#[derive(Clone)]
pub struct Executor {
    clock: Arc<dyn Clock>,
    permits: Arc<Semaphore>,
    /// The bound `permits` was created with (`in_flight` = bound - available permits).
    max_in_flight: usize,
    /// Calls waiting for a permit (the executor queue, exported as a metric, PD-059).
    queued: Arc<AtomicUsize>,
}

impl std::fmt::Debug for Executor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executor")
            .field("available_permits", &self.permits.available_permits())
            .finish_non_exhaustive()
    }
}

impl Executor {
    /// An executor allowing `max_in_flight` concurrent engine calls (at least 1).
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, max_in_flight: usize) -> Self {
        let max_in_flight = max_in_flight.max(1);
        Self {
            clock,
            permits: Arc::new(Semaphore::new(max_in_flight)),
            max_in_flight,
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The bound on concurrently running engine calls.
    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// Engine calls holding a permit now (running, or abandoned and not yet finished).
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.max_in_flight
            .saturating_sub(self.permits.available_permits())
    }

    /// Engine calls waiting for a permit now.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    /// The clock deadlines are measured with.
    #[must_use]
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Runs `work` on the blocking pool under the request's deadline (see the module docs).
    ///
    /// # Errors
    /// The closure's own error; RGN-5006 when the deadline passes before the closure starts
    /// (or, with [`Completion::Abandon`], before it finishes); RGN-5005 when the runtime
    /// cancelled the task; RGN-5001 `Internal` when the closure panicked.
    pub async fn run<T, F>(
        &self,
        ctx: &RequestContext,
        completion: Completion,
        work: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(&CancelToken) -> Result<T, Error> + Send + 'static,
        T: Send + 'static,
    {
        let deadline = ctx.deadline();
        if deadline.is_some_and(|d| d.expired(self.clock.as_ref())) {
            return Err(deadline_exceeded());
        }
        let token = CancelToken::new(deadline);
        let mut guard = CancelOnDrop {
            token: token.clone(),
            armed: true,
        };

        // Counted while waiting for a permit; the guard also covers the deadline and drop paths.
        let waiting = QueuedGuard::enter(&self.queued);
        let permit = tokio::select! {
            permit = Arc::clone(&self.permits).acquire_owned() => permit.map_err(|_| {
                Error::new(ErrorCode::Cancelled, "executor closed")
            })?,
            () = self.until(deadline) => {
                token.set(EXPIRED);
                return Err(deadline_exceeded());
            }
        };
        drop(waiting);

        let task_token = token.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            // The permit lives as long as the closure, also after the handler gave up on it,
            // so abandoned work still counts against the bound.
            let _permit = permit;
            task_token.check()?;
            work(&task_token)
        });

        let joined = tokio::select! {
            joined = &mut task => joined,
            () = self.until(deadline) => {
                token.set(EXPIRED);
                match completion {
                    Completion::Abandon => {
                        guard.armed = false;
                        return Err(deadline_exceeded());
                    }
                    Completion::Await => task.await,
                }
            }
        };
        guard.armed = false;
        match joined {
            Ok(result) => result,
            Err(e) if e.is_panic() => {
                tracing::error!("engine call panicked");
                Err(Error::new(ErrorCode::Internal, "engine call failed"))
            }
            Err(_) => Err(cancelled()),
        }
    }

    /// Completes at `deadline` (never without one), measured on the sim-api clock.
    fn until(&self, deadline: Option<Deadline>) -> impl Future<Output = ()> + Send + 'static {
        let sleep = deadline.map(|d| self.clock.sleep(d.remaining(self.clock.as_ref())));
        async move {
            match sleep {
                Some(s) => s.await,
                None => std::future::pending().await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Duration;

    use rustegon_sim_api::{OsRng, SystemClock};

    use super::*;

    /// Upper bound on how long tests wait (keeps CI from hanging on a bug).
    const TEST_LIMIT: Duration = Duration::from_secs(10);

    fn executor(max: usize) -> Executor {
        Executor::new(Arc::new(SystemClock::new()), max)
    }

    fn ctx_with_timeout(exec: &Executor, timeout: Option<Duration>) -> RequestContext {
        let ctx = RequestContext::internal(exec.clock().as_ref(), &OsRng);
        ctx.with_deadline(timeout.map(|t| Deadline::after(exec.clock().as_ref(), t)))
    }

    #[tokio::test]
    async fn fr_api_001_executor_runs_closure_and_returns_its_result() {
        let exec = executor(2);
        let ctx = ctx_with_timeout(&exec, Some(TEST_LIMIT));
        let v = exec
            .run(&ctx, Completion::Abandon, |t| {
                t.check()?;
                Ok(41 + 1)
            })
            .await
            .unwrap();
        assert_eq!(v, 42);
        let err = exec
            .run::<(), _>(&ctx, Completion::Await, |_| {
                Err(Error::new(ErrorCode::NotFound, "nope"))
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn fr_api_001_executor_expired_deadline_fails_before_running() {
        let exec = executor(1);
        let ctx = ctx_with_timeout(&exec, Some(Duration::ZERO));
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let err = exec
            .run(&ctx, Completion::Await, move |_| {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
        assert!(!ran.load(Ordering::SeqCst));
    }

    /// Abandon: the handler returns RGN-5006 at the deadline while the closure is still
    /// running; the closure then observes the expired token.
    #[tokio::test]
    async fn fr_api_001_executor_abandon_returns_5006_and_token_expires() {
        let exec = executor(1);
        let ctx = ctx_with_timeout(&exec, Some(Duration::from_millis(50)));
        let (seen_tx, seen_rx) = mpsc::channel();
        let err = exec
            .run::<(), _>(&ctx, Completion::Abandon, move |token| {
                // Poll the token like a scan loop would.
                while token.check().is_ok() {
                    std::thread::yield_now();
                }
                let _ = seen_tx.send(token.check().unwrap_err().code());
                Ok(())
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
        let seen = tokio::task::spawn_blocking(move || seen_rx.recv_timeout(TEST_LIMIT))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(seen, ErrorCode::DeadlineExceeded);
    }

    /// Await: the handler waits for the closure's own outcome after the deadline.
    #[tokio::test]
    async fn fr_api_001_executor_await_reports_closure_outcome_after_deadline() {
        let exec = executor(1);
        // Long enough for the closure to start before the deadline even under QEMU (arm64
        // gate): a deadline that expires first fails the request before running anything.
        let ctx = ctx_with_timeout(&exec, Some(Duration::from_millis(500)));
        let v = exec
            .run(&ctx, Completion::Await, |token| {
                while !token.is_cancelled() {
                    std::thread::yield_now();
                }
                // A write that already committed reports success despite the deadline.
                Ok("committed")
            })
            .await
            .unwrap();
        assert_eq!(v, "committed");
    }

    /// Dropping the handler future (client cancel) flips the token to RGN-5005.
    #[tokio::test]
    async fn fr_api_001_executor_dropped_request_cancels_token() {
        let exec = executor(1);
        let ctx = ctx_with_timeout(&exec, None);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (seen_tx, seen_rx) = mpsc::channel();
        let exec2 = exec.clone();
        let handler = tokio::spawn(async move {
            exec2
                .run::<(), _>(&ctx, Completion::Abandon, move |token| {
                    let _ = started_tx.send(());
                    while token.check().is_ok() {
                        std::thread::yield_now();
                    }
                    let _ = seen_tx.send(token.check().unwrap_err().code());
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        handler.abort();
        let seen = tokio::task::spawn_blocking(move || seen_rx.recv_timeout(TEST_LIMIT))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(seen, ErrorCode::Cancelled);
    }

    /// With all permits held, a queued call fails with RGN-5006 at its deadline instead of
    /// spawning another blocking thread.
    #[tokio::test]
    async fn fr_api_001_executor_queue_wait_is_bounded_by_deadline() {
        let exec = executor(1);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let busy_ctx = ctx_with_timeout(&exec, None);
        let exec2 = exec.clone();
        let busy = tokio::spawn(async move {
            exec2
                .run(&busy_ctx, Completion::Await, move |_| {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv_timeout(TEST_LIMIT);
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        let ctx = ctx_with_timeout(&exec, Some(Duration::from_millis(30)));
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let err = exec
            .run(&ctx, Completion::Await, move |_| {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
        release_tx.send(()).unwrap();
        busy.await.unwrap().unwrap();
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn fr_api_001_executor_panic_maps_to_internal() {
        let exec = executor(1);
        let ctx = ctx_with_timeout(&exec, None);
        let err = exec
            .run::<(), _>(&ctx, Completion::Await, |_| panic!("engine bug"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        // The permit was released by the unwinding closure.
        exec.run(&ctx, Completion::Await, |_| Ok(())).await.unwrap();
    }
}
