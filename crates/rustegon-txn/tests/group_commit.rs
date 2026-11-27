// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Group commit in the transaction layer (ADR-040; FR-TXN-001, NFR-REL-001, TC-TXN-004): a
//! commit is applied under the range latch and synced after the latch is released, so
//! - the commit is acknowledged only after its log sync, and a failed sync is `RGN-2006`;
//! - a reader gets through the latch while that sync runs, but what it saw leaves only after
//!   the sync (the read rule);
//! - inside `rustegon_txn::settled` the reads of one thread wait once, when the scope ends.
//!
//! The replica under test is the local one behind a wrapper whose `sync_through` can be held
//! back or made to fail.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    sync::{Arc, Condvar, Mutex, mpsc},
    time::Duration,
};

use bytes::Bytes;
use common::{as_int, coordinator, int, key, open_replica};
use rustegon_cluster::LocalReplica;
use rustegon_mvcc::{
    GcThreshold, RangeAppliedState, Replica, ReplicaCommand, ReplicaError, VersionValue,
};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::SystemClock;
use rustegon_storage::LsmEngine;
use rustegon_txn::{TxnConfig, TxnCoordinator, TxnError, TxnOptions, settled};

/// Upper bound on any wait of a test: a bug shows as a failure, not as a hang.
const LIMIT: Duration = Duration::from_secs(20);

#[derive(Default)]
struct GateState {
    /// `sync_through` waits while set.
    closed: bool,
    /// `sync_through` fails once it is let through.
    failing: bool,
    /// Callers held in `sync_through` now.
    held: usize,
    /// Calls of `sync_through` so far.
    calls: usize,
}

/// The local replica with a gate in front of `sync_through`.
struct GatedReplica {
    local: Arc<LocalReplica>,
    state: Mutex<GateState>,
    changed: Condvar,
}

impl GatedReplica {
    fn set(&self, change: impl FnOnce(&mut GateState)) {
        change(&mut self.state.lock().unwrap());
        self.changed.notify_all();
    }

    /// Waits until `n` callers are held in `sync_through`.
    fn wait_for_held(&self, n: usize) {
        let st = self.state.lock().unwrap();
        let (st, timeout) = self
            .changed
            .wait_timeout_while(st, LIMIT, |s| s.held < n)
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "{} caller(s) reached sync_through, expected {n}",
            st.held
        );
    }

    fn calls(&self) -> usize {
        self.state.lock().unwrap().calls
    }
}

impl Replica for GatedReplica {
    fn range_id(&self) -> u64 {
        self.local.range_id()
    }

    fn engine(&self) -> &LsmEngine {
        self.local.engine()
    }

    fn gc_threshold(&self) -> Option<&GcThreshold> {
        self.local.gc_threshold()
    }

    fn propose(&self, cmd: ReplicaCommand) -> Result<RangeAppliedState, ReplicaError> {
        self.local.propose(cmd)
    }

    fn propose_deferred(&self, cmd: ReplicaCommand) -> Result<RangeAppliedState, ReplicaError> {
        self.local.propose_deferred(cmd)
    }

    fn propose_unsynced(&self, cmd: ReplicaCommand) -> Result<RangeAppliedState, ReplicaError> {
        self.local.propose_unsynced(cmd)
    }

    fn sync_through(&self, index: u64) -> Result<(), ReplicaError> {
        {
            let mut st = self.state.lock().unwrap();
            st.calls += 1;
            st.held += 1;
            self.changed.notify_all();
            while st.closed {
                st = self.changed.wait(st).unwrap();
            }
            st.held -= 1;
            if st.failing {
                return Err(ReplicaError::Poisoned {
                    range_id: self.local.range_id(),
                });
            }
        }
        self.local.sync_through(index)
    }

    fn unsynced_index(&self) -> Option<u64> {
        self.local.unsynced_index()
    }

    fn applied_state(&self) -> RangeAppliedState {
        self.local.applied_state()
    }
}

/// A coordinator (system clock: the tests use threads) over a gated replica of a fresh store.
fn gated() -> (TxnCoordinator, Arc<GatedReplica>) {
    let fs = Arc::new(SimFileSystem::new());
    let replica = Arc::new(GatedReplica {
        local: open_replica(&fs).unwrap(),
        state: Mutex::default(),
        changed: Condvar::new(),
    });
    let co = coordinator(
        replica.clone(),
        Arc::new(SystemClock::new()),
        TxnConfig::default(),
        5,
    );
    (co, replica)
}

type Outcome<T> = mpsc::Receiver<Result<T, String>>;

/// Runs `f` on its own thread; the receiver gets its result.
fn in_background<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, TxnError> + Send + 'static,
) -> Outcome<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f().map_err(|e| e.to_string()));
    });
    rx
}

/// A transaction writing `value` at key 1 and committing, on its own thread.
fn commit_in_background(co: &TxnCoordinator, value: i64) -> Outcome<()> {
    let co = co.clone();
    in_background(move || {
        let mut t = co.begin(TxnOptions::default());
        t.put(&key(1), int(value))?;
        t.commit().map(|_| ())
    })
}

fn read(co: &TxnCoordinator) -> Result<Option<Bytes>, TxnError> {
    co.get_latest(&key(1))
}

#[test]
fn tc_txn_004_commit_is_acknowledged_only_after_its_log_sync() {
    let (co, replica) = gated();
    replica.set(|s| s.closed = true);
    let committed = commit_in_background(&co, 7);
    // The committer reaches the sync only after applying and releasing the latch.
    replica.wait_for_held(1);
    assert!(
        committed.try_recv().is_err(),
        "commit acknowledged before its log sync"
    );
    assert!(replica.unsynced_index().is_some(), "applied, not durable");
    replica.set(|s| s.closed = false);
    committed.recv_timeout(LIMIT).unwrap().unwrap();
    assert_eq!(replica.unsynced_index(), None);
    assert_eq!(as_int(read(&co).unwrap().as_ref()), 7);
}

#[test]
fn tc_txn_004_single_key_fast_path_is_acknowledged_only_after_its_log_sync() {
    let (co, replica) = gated();
    replica.set(|s| s.closed = true);
    let writer = co.clone();
    let written = in_background(move || {
        writer
            .put_single_key(&key(1), &VersionValue::Value(int(7)))
            .map(|_| ())
    });
    replica.wait_for_held(1);
    assert!(
        written.try_recv().is_err(),
        "fast-path write acknowledged before its log sync"
    );
    replica.set(|s| s.closed = false);
    written.recv_timeout(LIMIT).unwrap().unwrap();
    assert_eq!(as_int(read(&co).unwrap().as_ref()), 7);
}

#[test]
fn tc_txn_004_reader_of_an_unsynced_commit_returns_only_after_its_sync() {
    let (co, replica) = gated();
    replica.set(|s| s.closed = true);
    let committed = commit_in_background(&co, 7);
    replica.wait_for_held(1);
    // The latch is free while the commit syncs: the reader gets to the value, and then has to
    // wait for the same sync before it may return it.
    let reader = co.clone();
    let seen = in_background(move || read(&reader));
    replica.wait_for_held(2);
    assert!(
        seen.try_recv().is_err(),
        "a read returned a commit that is not durable"
    );
    replica.set(|s| s.closed = false);
    let value = seen.recv_timeout(LIMIT).unwrap().unwrap();
    assert_eq!(as_int(value.as_ref()), 7);
    committed.recv_timeout(LIMIT).unwrap().unwrap();
}

#[test]
fn tc_txn_004_settled_scope_waits_once_when_it_ends() {
    let (co, replica) = gated();
    replica.set(|s| s.closed = true);
    let committed = commit_in_background(&co, 7);
    replica.wait_for_held(1);
    let (inside_tx, inside_rx) = mpsc::channel();
    let reader = co.clone();
    let done = in_background(move || {
        settled(|| {
            let first = read(&reader)?;
            let second = read(&reader)?;
            // Both reads returned inside the scope.
            let _ = inside_tx.send(());
            Ok::<_, TxnError>((first, second))
        })
    });
    inside_rx
        .recv_timeout(LIMIT)
        .expect("a read inside a settled scope waited for the log sync");
    replica.wait_for_held(2);
    assert_eq!(
        replica.calls(),
        2,
        "the committer's sync and one for the scope"
    );
    assert!(
        done.try_recv().is_err(),
        "a settled scope returned a commit that is not durable"
    );
    replica.set(|s| s.closed = false);
    let (first, second) = done.recv_timeout(LIMIT).unwrap().unwrap();
    assert_eq!((as_int(first.as_ref()), as_int(second.as_ref())), (7, 7));
    committed.recv_timeout(LIMIT).unwrap().unwrap();
}

#[test]
fn tc_txn_004_settled_scope_ends_when_its_closure_panics() {
    let (co, replica) = gated();
    replica.set(|s| s.closed = true);
    let committed = commit_in_background(&co, 7);
    replica.wait_for_held(1);
    let reader = co.clone();
    let seen = in_background(move || {
        let panicked =
            std::panic::catch_unwind(|| settled(|| -> Result<(), TxnError> { panic!("bug") }));
        assert!(panicked.is_err());
        // The same thread, outside any scope again: this read waits on its own.
        read(&reader)
    });
    replica.wait_for_held(2);
    assert!(
        seen.try_recv().is_err(),
        "a read after a panicked scope returned a commit that is not durable"
    );
    replica.set(|s| s.closed = false);
    assert_eq!(
        as_int(seen.recv_timeout(LIMIT).unwrap().unwrap().as_ref()),
        7
    );
    committed.recv_timeout(LIMIT).unwrap().unwrap();
}

#[test]
fn tc_txn_004_failed_sync_is_an_unknown_commit_outcome_and_fails_later_reads() {
    let (co, replica) = gated();
    replica.set(|s| s.failing = true);
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(1), int(7)).unwrap();
    let err = t.commit().unwrap_err();
    assert!(matches!(err, TxnError::CommitOutcomeUnknown(_)), "{err}");
    // The value is in the engine and may not be in the log: nobody may be told about it.
    assert!(
        read(&co).is_err(),
        "a read returned a commit of unknown outcome"
    );
    let mut reader = co.begin(TxnOptions::default());
    assert!(settled(|| reader.get(&key(1))).is_err());
}
