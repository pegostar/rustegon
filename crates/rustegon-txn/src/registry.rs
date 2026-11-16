// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! In-memory state of the coordinator's live transactions, shared between a transaction's own
//! handle and the transactions that meet its intents (push, wait, deadlock detection;
//! transaction-management.md §5).
//!
//! The persisted `TxnRecord` at the anchor key is the durable source of truth (§3); this state
//! is its authoritative *live* copy while the coordinator runs: a pusher decides on the holder's
//! fate under the holder's state mutex, so a status transition (`Pending → Committing →
//! Committed`, `Pending → Aborted`) happens exactly once and commit and abort push can never
//! both win. After a crash the registry is empty and conflicts fall back to the persisted
//! records (see `conflict.rs`).
//!
//! # Locking
//! `Registry::map` is only held to look up / insert / remove an `Arc<TxnShared>`, never while a
//! state mutex is taken. At most one `TxnShared::state` is locked at a time by any thread (the
//! deadlock detector walks the wait-for chain locking one state after the other), so state
//! mutexes cannot deadlock among themselves.

use std::{
    cmp::Reverse,
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use rustegon_mvcc::{SeqRange, Timestamp, TxnId};

use crate::error::AbortReason;

/// Bound on the wait-for chain followed by the deadlock detector (§5.2: depth 16).
pub const DEADLOCK_MAX_DEPTH: usize = 16;

/// Live status of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Running; may be pushed.
    Pending,
    /// The owner is evaluating its commit under the range latch: pushers wait.
    Committing,
    /// Committed (its intents are resolved in the same command).
    Committed {
        /// Commit timestamp.
        commit_ts: Timestamp,
        /// Committing epoch.
        epoch: u32,
        /// Final savepoint rollbacks.
        ignored: Vec<SeqRange>,
    },
    /// Aborted; its intents may be removed by anyone.
    Aborted(AbortReason),
    /// The commit proposal failed ambiguously: the outcome is in the log, unknown here.
    Ambiguous,
}

/// Mutable part of a live transaction.
#[derive(Debug)]
pub struct SharedState {
    /// Live status.
    pub status: Status,
    /// Provisional commit timestamp; readers push it forward (timestamp push, §5.1).
    pub write_ts: Timestamp,
    /// Current epoch.
    pub epoch: u32,
    /// Numeric priority (§5.3).
    pub priority: u32,
    /// Monotonic time of the last sign of life of the coordinator (any operation, or waiting).
    pub last_heartbeat: Duration,
    /// The transaction whose intent this one is waiting for (wait-for edge, §5.2).
    pub waiting_on: Option<TxnId>,
    /// Whether it may hold an intent: set under the range latch before its first intent is
    /// proposed, never cleared. Closing a timestamp (`TxnCoordinator::close_timestamp`) waits
    /// only for such transactions: one without intents writes above the closed timestamp.
    pub has_intents: bool,
}

/// A live transaction as seen by others.
#[derive(Debug)]
pub struct TxnShared {
    /// Transaction id.
    pub id: TxnId,
    /// Start timestamp: the larger, the younger (deadlock victim tie-break, §5.2).
    pub start_ts: Timestamp,
    state: Mutex<SharedState>,
    /// Notified on every status change (waiters re-evaluate).
    changed: Condvar,
}

impl TxnShared {
    /// A pending transaction.
    #[must_use]
    pub fn new(id: TxnId, start_ts: Timestamp, priority: u32, now: Duration) -> Self {
        Self {
            id,
            start_ts,
            state: Mutex::new(SharedState {
                status: Status::Pending,
                write_ts: start_ts,
                epoch: 0,
                priority,
                last_heartbeat: now,
                waiting_on: None,
                has_intents: false,
            }),
            changed: Condvar::new(),
        }
    }

    /// Locks the state. Every writer updates the fields of one consistent transition before
    /// unlocking and no code panics while holding it, so poison carries no information.
    pub fn lock(&self) -> MutexGuard<'_, SharedState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets `status` and wakes every waiter.
    pub fn set_status(&self, state: &mut SharedState, status: Status) {
        state.status = status;
        self.changed.notify_all();
    }

    /// Aborts the transaction for `reason` if it is still pending; returns whether it is now
    /// aborted (by this call or before).
    pub fn abort_if_pending(&self, reason: AbortReason) -> bool {
        let mut st = self.lock();
        match st.status {
            Status::Pending => {
                self.set_status(&mut st, Status::Aborted(reason));
                true
            }
            Status::Aborted(_) => true,
            _ => false,
        }
    }

    /// Blocks up to `slice` while the transaction is still pending or committing.
    pub fn wait_for_change(&self, slice: Duration) {
        let st = self.lock();
        if matches!(st.status, Status::Pending | Status::Committing) {
            // A spurious or timed-out wake-up only re-runs the caller's decision loop.
            drop(
                self.changed
                    .wait_timeout(st, slice)
                    .unwrap_or_else(PoisonError::into_inner),
            );
        }
    }

    /// Sets the wait-for edge.
    pub fn set_waiting_on(&self, holder: Option<TxnId>) {
        self.lock().waiting_on = holder;
    }
}

/// Live transactions of the coordinator by id.
#[derive(Debug, Default)]
pub struct Registry {
    map: Mutex<HashMap<TxnId, Arc<TxnShared>>>,
}

impl Registry {
    fn map(&self) -> MutexGuard<'_, HashMap<TxnId, Arc<TxnShared>>> {
        // Insert/remove/lookup are single map operations: poison carries no information.
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers a transaction.
    pub fn insert(&self, txn: Arc<TxnShared>) {
        self.map().insert(txn.id, txn);
    }

    /// Unregisters a finished transaction.
    pub fn remove(&self, id: &TxnId) {
        self.map().remove(id);
    }

    /// The live transaction `id`, if registered.
    #[must_use]
    pub fn get(&self, id: &TxnId) -> Option<Arc<TxnShared>> {
        self.map().get(id).cloned()
    }

    /// Every registered transaction (a snapshot of the map; states are read afterwards, one at
    /// a time, per the lock order of the module docs).
    #[must_use]
    pub fn all(&self) -> Vec<Arc<TxnShared>> {
        self.map().values().cloned().collect()
    }

    /// Number of registered transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map().len()
    }

    /// Whether no transaction is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Local wait-for graph check (§5.2) started from `waiter`, which has just recorded its
    /// wait-for edge: follows `waiting_on` edges (each transaction waits for at most one other,
    /// so the graph seen from `waiter` is a chain) up to [`DEADLOCK_MAX_DEPTH`]. If the chain
    /// returns to `waiter`, returns the victim of the cycle: the lowest priority, then the
    /// youngest (largest start timestamp), then the largest id — a deterministic choice, so
    /// concurrent detectors of the same cycle agree.
    ///
    /// The chain is read one state at a time, so it may be momentarily stale; a false positive
    /// only aborts a transaction (always safe, retryable `RGN-2005`).
    #[must_use]
    pub fn find_deadlock_victim(&self, waiter: &Arc<TxnShared>) -> Option<Arc<TxnShared>> {
        let mut cycle = vec![Arc::clone(waiter)];
        let mut current = Arc::clone(waiter);
        for _ in 0..DEADLOCK_MAX_DEPTH {
            let next_id = current.lock().waiting_on?;
            if next_id == waiter.id {
                return cycle
                    .into_iter()
                    .min_by_key(|t| (t.lock().priority, Reverse(t.start_ts), Reverse(t.id)));
            }
            if cycle.iter().any(|t| t.id == next_id) {
                // A cycle not through `waiter`: one of its members detects it.
                return None;
            }
            current = self.get(&next_id)?;
            cycle.push(Arc::clone(&current));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txn(n: u8, start: u64, priority: u32) -> Arc<TxnShared> {
        Arc::new(TxnShared::new(
            [n; 16],
            Timestamp::new(start, 0),
            priority,
            Duration::ZERO,
        ))
    }

    #[test]
    fn two_cycle_victim_is_the_youngest_of_equal_priority() {
        let reg = Registry::default();
        let (a, b) = (txn(1, 10, 5), txn(2, 20, 5));
        reg.insert(Arc::clone(&a));
        reg.insert(Arc::clone(&b));
        a.set_waiting_on(Some(b.id));
        assert!(reg.find_deadlock_victim(&a).is_none());
        b.set_waiting_on(Some(a.id));
        assert_eq!(reg.find_deadlock_victim(&a).map(|t| t.id), Some(b.id));
        assert_eq!(reg.find_deadlock_victim(&b).map(|t| t.id), Some(b.id));
    }

    #[test]
    fn three_cycle_victim_is_the_lowest_priority() {
        let reg = Registry::default();
        let (a, b, c) = (txn(1, 10, 5), txn(2, 20, 7), txn(3, 30, 6));
        for t in [&a, &b, &c] {
            reg.insert(Arc::clone(t));
        }
        a.set_waiting_on(Some(b.id));
        b.set_waiting_on(Some(c.id));
        c.set_waiting_on(Some(a.id));
        assert_eq!(reg.find_deadlock_victim(&c).map(|t| t.id), Some(a.id));
    }

    #[test]
    fn abort_if_pending_does_not_abort_a_committing_transaction() {
        let a = txn(1, 10, 5);
        a.lock().status = Status::Committing;
        assert!(!a.abort_if_pending(AbortReason::Conflict));
        a.lock().status = Status::Pending;
        assert!(a.abort_if_pending(AbortReason::Conflict));
        assert_eq!(a.lock().status, Status::Aborted(AbortReason::Conflict));
    }
}
