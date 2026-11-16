// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rgn-request-id` deduplication of non-transactional writes (protocol.md §5.1, PD-053).
//!
//! A client that retries a write after a network error sends the same `rgn-request-id`; the
//! retry must not apply the write twice. The store keeps, per (principal, request id), the
//! successful outcome of the first attempt for `idempotency_retention` (10 min) and replays it.
//!
//! Rules (*Provisional (PD-053)*):
//! - only client-supplied request ids create records (a generated id is unique per attempt);
//! - only writes outside an interactive transaction are deduplicated (inside one, Commit is
//!   idempotent by transaction id, and statements are the client's to retry);
//! - only **successful** outcomes are recorded: a failed attempt wrote nothing (writes report
//!   their real outcome, `Completion::Await`), so its retry simply runs again; RGN-2006 is the
//!   exception the client resolves through the error itself;
//! - a retry arriving while the first attempt still runs waits for it and returns its outcome;
//! - the same id reused for another operation is RGN-1001;
//! - the operation runs in its own task, so a client that disconnects mid-write cannot leave
//!   the record "in flight" while the write commits behind it;
//! - **per node, in memory, not durable**: a restart or a retry sent to another node runs the
//!   write again. Bounded by `max_idempotency_records` (oldest finished records evicted
//!   first; when every record is in flight, new deduplicated writes fail with RGN-5004).

use std::{
    any::Any,
    collections::{HashMap, VecDeque},
    future::Future,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_sim_api::Clock;
use tokio::sync::watch;

use super::{RequestContext, RequestId, data::DataPlaneConfig};

type Key = (Option<String>, RequestId);

/// What one attempt does with its key.
enum Claim {
    Replay(Outcome),
    Wait(watch::Receiver<bool>),
    Run(watch::Sender<bool>),
}
type Outcome = Arc<dyn Any + Send + Sync>;

enum Slot {
    InFlight {
        op: &'static str,
        done: watch::Receiver<bool>,
    },
    Done {
        op: &'static str,
        at: Duration,
        value: Outcome,
    },
}

struct Inner {
    slots: HashMap<Key, Slot>,
    /// Finished records in completion order (eviction and expiry).
    finished: VecDeque<(Duration, Key)>,
}

/// The per-node idempotency store.
pub(crate) struct IdempotencyStore {
    inner: Mutex<Inner>,
    clock: Arc<dyn Clock>,
    retention: Duration,
    max_records: usize,
}

impl IdempotencyStore {
    pub(crate) fn new(clock: Arc<dyn Clock>, config: &DataPlaneConfig) -> Self {
        Self {
            inner: Mutex::new(Inner {
                slots: HashMap::new(),
                finished: VecDeque::new(),
            }),
            clock,
            retention: config.idempotency_retention,
            max_records: config.max_idempotency_records.max(1),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // The map holds no invariant a panic could break halfway (each update is one call).
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs the write `op` (named `name`) once per client request id (module docs).
    ///
    /// # Errors
    /// The write's own error; RGN-1001 when the id was used for another operation; RGN-5004
    /// when the store is full of in-flight writes; RGN-5006 when the deadline passes while
    /// waiting for a concurrent attempt.
    pub(crate) async fn run<T, F>(
        self: &Arc<Self>,
        ctx: &RequestContext,
        name: &'static str,
        op: F,
    ) -> Result<T, Error>
    where
        T: Clone + Send + Sync + 'static,
        F: Future<Output = Result<T, Error>> + Send + 'static,
    {
        if !ctx.has_client_request_id() {
            return op.await;
        }
        let key: Key = (super::data::owner_of(ctx), ctx.request_id());
        let mut op = Some(op);
        loop {
            match self.claim(&key, name)? {
                Claim::Replay(value) => {
                    return value
                        .downcast_ref::<T>()
                        .cloned()
                        .ok_or_else(|| reused(name));
                }
                Claim::Wait(done) => self.wait(ctx, done).await?,
                Claim::Run(tx) => {
                    let Some(op) = op.take() else {
                        return Err(Error::new(ErrorCode::Internal, "operation consumed"));
                    };
                    return self.execute(key, name, op, tx).await;
                }
            }
        }
    }

    /// Looks the key up under the lock and decides what this attempt does.
    fn claim(&self, key: &Key, name: &'static str) -> Result<Claim, Error> {
        let mut inner = self.lock();
        self.expire(&mut inner);
        match inner.slots.get(key) {
            Some(Slot::Done { op, value, .. }) if *op == name => {
                Ok(Claim::Replay(Arc::clone(value)))
            }
            Some(Slot::InFlight { op, done }) if *op == name => Ok(Claim::Wait(done.clone())),
            Some(_) => Err(reused(name)),
            None => {
                self.make_room(&mut inner)?;
                let (tx, rx) = watch::channel(false);
                inner
                    .slots
                    .insert(key.clone(), Slot::InFlight { op: name, done: rx });
                Ok(Claim::Run(tx))
            }
        }
    }

    /// Runs the first attempt in its own task and records its outcome there, so the record
    /// is completed even if this request is dropped.
    async fn execute<T, F>(
        self: &Arc<Self>,
        key: Key,
        name: &'static str,
        op: F,
        done: watch::Sender<bool>,
    ) -> Result<T, Error>
    where
        T: Clone + Send + Sync + 'static,
        F: Future<Output = Result<T, Error>> + Send + 'static,
    {
        let store = Arc::clone(self);
        let task = tokio::spawn(async move {
            let result = op.await;
            {
                let mut inner = store.lock();
                match &result {
                    Ok(value) => {
                        let at = store.clock.monotonic();
                        let value: Outcome = Arc::new(value.clone());
                        inner.slots.insert(
                            key.clone(),
                            Slot::Done {
                                op: name,
                                at,
                                value,
                            },
                        );
                        inner.finished.push_back((at, key));
                    }
                    Err(_) => {
                        inner.slots.remove(&key);
                    }
                }
            }
            // Wakes the waiting retries (also when the sender just drops on a panic).
            let _ = done.send(true);
            result
        });
        task.await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "deduplicated write task failed");
            Err(Error::new(ErrorCode::Internal, "write task failed"))
        })
    }

    async fn wait(
        &self,
        ctx: &RequestContext,
        mut done: watch::Receiver<bool>,
    ) -> Result<(), Error> {
        let deadline = ctx.deadline();
        let finished = async {
            // A closed channel also means "finished" (the slot was removed or replaced).
            let _ = done.wait_for(|d| *d).await;
        };
        match deadline {
            None => finished.await,
            Some(d) => {
                tokio::select! {
                    () = finished => {}
                    () = self.clock.sleep(d.remaining(self.clock.as_ref())) => {
                        return Err(super::deadline_exceeded());
                    }
                }
            }
        }
        Ok(())
    }

    fn expire(&self, inner: &mut Inner) {
        let now = self.clock.monotonic();
        while let Some((at, _)) = inner.finished.front() {
            if now.saturating_sub(*at) < self.retention {
                break;
            }
            if let Some((at, key)) = inner.finished.pop_front()
                && matches!(inner.slots.get(&key), Some(Slot::Done { at: a, .. }) if *a == at)
            {
                inner.slots.remove(&key);
            }
        }
    }

    fn make_room(&self, inner: &mut Inner) -> Result<(), Error> {
        while inner.slots.len() >= self.max_records {
            let Some((at, key)) = inner.finished.pop_front() else {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "too many concurrent deduplicated writes",
                ));
            };
            if matches!(inner.slots.get(&key), Some(Slot::Done { at: a, .. }) if *a == at) {
                inner.slots.remove(&key);
            }
        }
        Ok(())
    }

    /// Drops expired records (background sweep).
    pub(crate) fn sweep(&self) {
        let mut inner = self.lock();
        self.expire(&mut inner);
    }

    /// Records currently held (tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().slots.len()
    }
}

fn reused(name: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!("rgn-request-id was already used for another operation than {name}"),
    )
    .with_detail("header", "rgn-request-id")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::{AtomicU32, Ordering};

    use rustegon_sim_api::{OsRng, SystemClock};

    use super::*;
    use crate::services::RawRequestHeaders;

    fn ctx(id: &str) -> RequestContext {
        let headers = RawRequestHeaders {
            request_id: Some(id),
            ..RawRequestHeaders::default()
        };
        RequestContext::from_headers(&headers, &SystemClock::new(), &OsRng).unwrap()
    }

    #[tokio::test]
    async fn tc_api_009_same_request_id_runs_the_write_once() {
        let store = Arc::new(IdempotencyStore::new(
            Arc::new(SystemClock::new()),
            &DataPlaneConfig::default(),
        ));
        let runs = Arc::new(AtomicU32::new(0));
        let c = ctx("0190a6e2-3c4d-7abc-8def-0123456789ab");
        for _ in 0..3 {
            let r = Arc::clone(&runs);
            let v = store
                .run(&c, "op", async move {
                    Ok(r.fetch_add(1, Ordering::SeqCst) + 10)
                })
                .await
                .unwrap();
            assert_eq!(v, 10);
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        // Another operation with the same id: RGN-1001.
        let err = store
            .run(&c, "other", async { Ok(1u32) })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        // A failed attempt is not recorded: the retry runs.
        let c2 = ctx("0190a6e2-3c4d-7abc-8def-0123456789ac");
        let err = store
            .run::<u32, _>(&c2, "op", async {
                Err(Error::new(ErrorCode::DuplicateKey, "dup"))
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::DuplicateKey);
        assert_eq!(store.run(&c2, "op", async { Ok(5u32) }).await.unwrap(), 5);
        assert_eq!(store.len(), 2);
    }
}
