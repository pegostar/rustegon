// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Task spawning.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use crate::BoxFuture;

/// Why a task did not run to completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskError {
    /// The task was aborted.
    Cancelled,
    /// The task panicked.
    Panicked,
}

impl fmt::Display for TaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "task cancelled",
            Self::Panicked => "task panicked",
        })
    }
}

impl std::error::Error for TaskError {}

/// Handle to a spawned task: await it to join, or [`JoinHandle::abort`] it. Dropping the handle
/// detaches the task (it keeps running).
pub struct JoinHandle {
    join: BoxFuture<'static, Result<(), TaskError>>,
    abort: Box<dyn Fn() + Send + Sync>,
}

impl JoinHandle {
    /// Builds a handle from an implementation's join future and abort action.
    pub fn new(
        join: BoxFuture<'static, Result<(), TaskError>>,
        abort: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        Self {
            join,
            abort: Box::new(abort),
        }
    }

    /// Requests cancellation; the join future then resolves to [`TaskError::Cancelled`] unless
    /// the task already finished.
    pub fn abort(&self) {
        (self.abort)();
    }
}

impl Future for JoinHandle {
    type Output = Result<(), TaskError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.join.as_mut().poll(cx)
    }
}

impl fmt::Debug for JoinHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JoinHandle")
    }
}

/// Spawns concurrent tasks.
pub trait Spawner: Send + Sync + 'static {
    /// Starts `task` concurrently.
    fn spawn(&self, task: BoxFuture<'static, ()>) -> JoinHandle;
}

/// Production spawner on a Tokio runtime.
#[derive(Debug, Clone)]
pub struct TokioSpawner {
    handle: tokio::runtime::Handle,
}

impl TokioSpawner {
    /// Spawns onto the given runtime.
    #[must_use]
    pub fn new(handle: tokio::runtime::Handle) -> Self {
        Self { handle }
    }
}

impl Spawner for TokioSpawner {
    fn spawn(&self, task: BoxFuture<'static, ()>) -> JoinHandle {
        let handle = self.handle.spawn(task);
        let abort = handle.abort_handle();
        JoinHandle::new(
            Box::pin(async move {
                handle.await.map_err(|e| {
                    if e.is_panic() {
                        TaskError::Panicked
                    } else {
                        TaskError::Cancelled
                    }
                })
            }),
            move || abort.abort(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    fn spawner() -> TokioSpawner {
        TokioSpawner::new(tokio::runtime::Handle::current())
    }

    #[tokio::test]
    async fn tokio_spawner_runs_and_joins() {
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let h = spawner().spawn(Box::pin(async move { flag.store(true, Ordering::SeqCst) }));
        assert_eq!(h.await, Ok(()));
        assert!(done.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tokio_spawner_abort_reports_cancelled() {
        let h = spawner().spawn(Box::pin(std::future::pending()));
        h.abort();
        assert_eq!(h.await, Err(TaskError::Cancelled));
    }

    #[tokio::test]
    async fn tokio_spawner_panic_reports_panicked() {
        let h = spawner().spawn(Box::pin(async {
            tokio::task::yield_now().await;
            panic!("boom");
        }));
        assert_eq!(h.await, Err(TaskError::Panicked));
    }
}
