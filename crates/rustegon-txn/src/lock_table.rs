// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Per-key wait queues (transaction-management.md §5.1): transactions that met another
//! transaction's intent on a key queue on that key in arrival order. When the holder finishes,
//! the head of the queue proceeds at once; the others yield to it for one wait slice (until it
//! left the queue), so waiters retry roughly in FIFO order instead of stampeding the range
//! latch. The yield is bounded because a queue edge is not part of the wait-for graph: an
//! unbounded wait for the head could hide a deadlock. Pushes (expired holder, higher priority)
//! and deadlock detection do not depend on the queue position.
//!
//! The order is best effort: once the head has left the queue the next waiter may race it for
//! the range latch; whoever loses finds the winner's intent and queues again. Correctness never
//! depends on the queue (the intent and the range latch serialise writers).
//!
//! Locking: one mutex for all queues, a leaf of the coordinator's lock order; waiting happens on
//! its condition variable with that mutex only.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Condvar, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use rustegon_mvcc::TxnId;

/// The wait queues of a range.
#[derive(Debug, Default)]
pub struct LockTable {
    queues: Mutex<HashMap<Vec<u8>, VecDeque<TxnId>>>,
    /// Notified whenever a waiter leaves a queue.
    left: Condvar,
}

/// A waiter's place in a key's queue; leaving the scope dequeues it.
#[derive(Debug)]
pub struct QueueSlot<'a> {
    table: &'a LockTable,
    key: Vec<u8>,
    txn: TxnId,
}

impl LockTable {
    fn queues(&self) -> MutexGuard<'_, HashMap<Vec<u8>, VecDeque<TxnId>>> {
        // Queue edits are single push/remove operations: poison carries no information.
        self.queues.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `txn` on `key` (at the back).
    #[must_use]
    pub fn enqueue(&self, key: &[u8], txn: TxnId) -> QueueSlot<'_> {
        self.queues()
            .entry(key.to_vec())
            .or_default()
            .push_back(txn);
        QueueSlot {
            table: self,
            key: key.to_vec(),
            txn,
        }
    }

    /// The transactions queued on `key`, head first.
    #[must_use]
    pub fn waiters(&self, key: &[u8]) -> Vec<TxnId> {
        self.queues()
            .get(key)
            .map(|q| q.iter().copied().collect())
            .unwrap_or_default()
    }
}

impl QueueSlot<'_> {
    /// Whether this waiter is at the head of its queue.
    #[must_use]
    pub fn is_head(&self) -> bool {
        self.table
            .queues()
            .get(&self.key)
            .and_then(|q| q.front())
            .is_some_and(|t| *t == self.txn)
    }

    /// Blocks up to `slice` unless this waiter is at the head (woken when anyone leaves).
    pub fn wait_turn(&self, slice: Duration) {
        let queues = self.table.queues();
        let head = queues.get(&self.key).and_then(|q| q.front()).copied();
        if head != Some(self.txn) {
            drop(
                self.table
                    .left
                    .wait_timeout(queues, slice)
                    .unwrap_or_else(PoisonError::into_inner),
            );
        }
    }
}

impl Drop for QueueSlot<'_> {
    fn drop(&mut self) {
        let mut queues = self.table.queues();
        if let Some(q) = queues.get_mut(&self.key) {
            if let Some(pos) = q.iter().position(|t| *t == self.txn) {
                q.remove(pos);
            }
            if q.is_empty() {
                queues.remove(&self.key);
            }
        }
        self.table.left.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_is_fifo_and_slots_dequeue_on_drop() {
        let t = LockTable::default();
        let a = t.enqueue(b"k", [1; 16]);
        let b = t.enqueue(b"k", [2; 16]);
        assert!(a.is_head() && !b.is_head());
        assert_eq!(t.waiters(b"k"), [[1; 16], [2; 16]]);
        drop(a);
        assert!(b.is_head());
        b.wait_turn(Duration::from_millis(1));
        drop(b);
        assert_eq!(t.waiters(b"k"), Vec::<TxnId>::new());
        assert_eq!(t.queues().len(), 0);
    }
}
