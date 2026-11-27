// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The read rule of group commit (ADR-040, transaction-management.md §13).
//!
//! A commit is applied under the range latch and becomes durable after the latch is released
//! (`txn/commit.rs`), so the range may hold commits that a crash can still lose. The rule that
//! keeps the guarantees of transaction-management.md §1: **nothing computed from the range
//! leaves before every commit it may have seen is durable.** An operation that read the range
//! therefore ends by waiting for [`Replica::unsynced_index`], read *after* its last read (a
//! command reports there before it becomes visible), with [`Replica::sync_through`].
//!
//! The wait is usually short or absent: nothing unsynced, or a sync already running. But a
//! request runs many operations (a query takes the range latch about thirty times), and
//! waiting after each would put the log `fsync` back between them. [`settled`] is the scope of
//! one request: inside it the operations only note the index they would wait for, and the
//! scope waits once, for the newest, when its closure returns.

use std::{cell::RefCell, sync::Arc};

use rustegon_mvcc::{Replica, ReplicaError};

use crate::{
    coordinator::Core,
    error::{Result, TxnError},
};

/// A wait a scope owes: the replica and the log index to sync it through.
type Owed = (Arc<dyn Replica>, u64);

thread_local! {
    /// The waits the [`settled`] scope of this thread still owes; `None` outside a scope.
    static OWED: RefCell<Option<Vec<Owed>>> = const { RefCell::new(None) };
}

/// Ends the scope of this thread when dropped, also by a panic of the closure: a thread left
/// inside a scope would never wait again.
struct ScopeEnd;

impl Drop for ScopeEnd {
    fn drop(&mut self) {
        OWED.set(None);
    }
}

/// Runs `f` as one request: the [`crate::Txn`] operations it runs on this thread do not wait
/// for durability one by one (module docs); the scope waits once, after `f` returned, for
/// everything they may have seen. Nested scopes join the outermost one.
///
/// The caller must not let anything `f` computed leave the thread before `settled` returns:
/// code that streams results while it runs must stay outside a scope, or read at a timestamp
/// closed by [`crate::TxnCoordinator::close_timestamp`], which always waits by itself.
///
/// # Errors
/// The error of `f`; if the wait fails (the replica is poisoned, its log may lack what `f`
/// saw), that failure instead of the result of `f`.
pub fn settled<T, E: From<TxnError>>(
    f: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    if in_settled_scope() {
        return f();
    }
    OWED.set(Some(Vec::new()));
    let end = ScopeEnd;
    let result = f();
    let owed = OWED.take().unwrap_or_default();
    drop(end);
    for (replica, index) in owed {
        replica.sync_through(index).map_err(TxnError::from)?;
    }
    result
}

/// Whether the calling thread is inside a [`settled`] scope.
#[must_use]
pub fn in_settled_scope() -> bool {
    OWED.with_borrow(Option::is_some)
}

/// Leaves the wait for `index` of `replica` to the scope of this thread; `false` outside one.
fn owe(replica: &Arc<dyn Replica>, index: u64) -> bool {
    OWED.with_borrow_mut(|owed| {
        let Some(owed) = owed else {
            return false;
        };
        let same = |r: &Arc<dyn Replica>| std::ptr::addr_eq(Arc::as_ptr(r), Arc::as_ptr(replica));
        match owed.iter_mut().find(|(r, _)| same(r)) {
            Some((_, newest)) => *newest = (*newest).max(index),
            None => owed.push((Arc::clone(replica), index)),
        }
        true
    })
}

impl Core {
    /// Waits until everything applied to the range so far is durable, whatever the scope.
    pub(crate) fn settle_now(&self) -> std::result::Result<(), ReplicaError> {
        match self.replica.unsynced_index() {
            Some(index) => self.replica.sync_through(index),
            None => Ok(()),
        }
    }

    /// Ends an operation that read the range (module docs): `result` leaves only once what it
    /// may have seen is durable, or the enclosing [`settled`] scope takes the wait over.
    pub(crate) fn settled<T>(&self, result: Result<T>) -> Result<T> {
        if let Some(index) = self.replica.unsynced_index()
            && !owe(&self.replica, index)
        {
            self.replica.sync_through(index)?;
        }
        result
    }
}
