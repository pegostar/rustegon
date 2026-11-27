// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The persisted outcome of a transaction whose coordinator died with the process
//! (`TxnCoordinator::orphan_status`; FR-TXN-005, FR-TXN-006, transaction-management.md §7,
//! PD-121 option (a')).
//!
//! Each test runs a coordinator on a simulated store, leaves the process "dead" (the `Txn`
//! handle is leaked, so no rollback runs), power-cuts the file system and reopens the store with
//! a new coordinator, as a node restart does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{sync::Arc, time::Duration};

use common::{ManualClock, T0, as_int, coordinator, int, key, open_replica};
use rustegon_cluster::LocalReplica;
use rustegon_mvcc::{Replica, TxnId};
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_txn::{OrphanStatus, TxnConfig, TxnCoordinator, TxnOptions};

/// The store after a power cut, reopened under a coordinator whose clock is `after` past `T0`.
fn restart(fs: &Arc<SimFileSystem>, after: Duration) -> (TxnCoordinator, Arc<ManualClock>) {
    let (co, clock, _) = restart_with_replica(fs, after);
    (co, clock)
}

fn restart_with_replica(
    fs: &Arc<SimFileSystem>,
    after: Duration,
) -> (TxnCoordinator, Arc<ManualClock>, Arc<LocalReplica>) {
    fs.crash(0, CrashMode::Clean);
    let clock = ManualClock::new(T0);
    clock.advance(after);
    let replica = open_replica(fs).unwrap();
    let co = coordinator(replica.clone(), clock.clone(), TxnConfig::default(), 2);
    (co, clock, replica)
}

fn store() -> (Arc<SimFileSystem>, TxnCoordinator) {
    let fs = Arc::new(SimFileSystem::new());
    let co = coordinator(
        open_replica(&fs).unwrap(),
        ManualClock::new(T0),
        TxnConfig::default(),
        1,
    );
    (fs, co)
}

/// A transaction that wrote keys 0 and 1 and never finished: its process dies with it.
fn abandoned_writer(co: &TxnCoordinator) -> TxnId {
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(0), int(7)).unwrap();
    t.put(&key(1), int(7)).unwrap();
    let id = t.id();
    // Intents reach the log with the next durable proposal (ADR-038): another transaction's
    // commit carries them.
    let mut other = co.begin(TxnOptions::default());
    other.put(&key(9), int(1)).unwrap();
    other.commit().unwrap();
    // The process dies: no rollback, the intents and the PENDING record stay on disk.
    std::mem::forget(t);
    id
}

#[test]
fn tc_txn_006_orphan_pending_is_in_doubt_then_aborted_after_liveness_timeout() {
    let (fs, co) = store();
    let id = abandoned_writer(&co);
    let liveness = TxnConfig::default().liveness_timeout;

    let (co, clock) = restart(&fs, Duration::from_millis(100));
    // Within the liveness timeout the outcome is not decided yet (it cannot commit any more on
    // one node, but the rule is the distributed one: wait for the heartbeat to expire).
    assert_eq!(co.orphan_status(&id).unwrap(), Some(OrphanStatus::InDoubt));

    clock.advance(liveness + Duration::from_secs(1));
    assert_eq!(co.orphan_status(&id).unwrap(), Some(OrphanStatus::Aborted));
    // Durable and stable: asked again, and after another restart, still aborted.
    assert_eq!(co.orphan_status(&id).unwrap(), Some(OrphanStatus::Aborted));
    drop(co);
    let (co, _) = restart(&fs, Duration::from_secs(3600));
    assert_eq!(co.orphan_status(&id).unwrap(), Some(OrphanStatus::Aborted));

    // Its writes are gone: a reader sees nothing, a writer is not blocked.
    assert_eq!(as_int(co.get_latest(&key(0)).unwrap().as_ref()), 0);
    assert_eq!(as_int(co.get_latest(&key(1)).unwrap().as_ref()), 0);
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(0), int(1)).unwrap();
    t.put(&key(1), int(1)).unwrap();
    t.commit().unwrap();
    assert_eq!(as_int(co.get_latest(&key(1)).unwrap().as_ref()), 1);
    assert_eq!(co.orphan_status(&id).unwrap(), Some(OrphanStatus::Aborted));
}

#[test]
fn tc_txn_006_orphan_abort_resolves_the_anchor_intent() {
    let (fs, co) = store();
    let id = abandoned_writer(&co);
    let (co, _, replica) = restart_with_replica(&fs, Duration::from_secs(3600));
    let intent = |k| replica.reader().get_intent(&key(k)).unwrap().is_some();
    assert!(intent(0) && intent(1), "intents present before the abort");
    assert_eq!(co.orphan_status(&id).unwrap(), Some(OrphanStatus::Aborted));
    // Key 0 is the anchor: resolved in the abort command. Key 1 is resolved by whoever meets
    // it (the record now says ABORTED).
    assert!(!intent(0), "anchor intent resolved with the abort");
    assert!(intent(1));
    assert_eq!(as_int(co.get_latest(&key(1)).unwrap().as_ref()), 0);
    assert!(!intent(1), "intent resolved on first contact");
}

#[test]
fn tc_txn_006_committed_transaction_is_never_reported_aborted() {
    let (fs, co) = store();
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(0), int(5)).unwrap();
    t.put(&key(1), int(5)).unwrap();
    t.commit().unwrap();
    let id = t.id();
    drop(t);
    drop(co);
    // Long past any liveness timeout: no record (1PC deleted it) → unknown, never aborted.
    let (co, _) = restart(&fs, Duration::from_secs(3600));
    assert_eq!(co.orphan_status(&id).unwrap(), None);
    assert_eq!(as_int(co.get_latest(&key(1)).unwrap().as_ref()), 5);
}

#[test]
fn tc_txn_006_rolled_back_read_only_and_unknown_ids_have_no_outcome() {
    let (fs, co) = store();
    let mut rolled_back = co.begin(TxnOptions::default());
    rolled_back.put(&key(0), int(1)).unwrap();
    rolled_back.rollback().unwrap();
    let mut read_only = co.begin(TxnOptions::default());
    assert_eq!(read_only.get(&key(0)).unwrap(), None);
    let (rolled_back, read_only_id) = (rolled_back.id(), read_only.id());
    // A transaction without writes never has a record, whether it finished or not.
    std::mem::forget(read_only);
    let (co, _) = restart(&fs, Duration::from_secs(3600));
    assert_eq!(co.orphan_status(&rolled_back).unwrap(), None);
    assert_eq!(co.orphan_status(&read_only_id).unwrap(), None);
    assert_eq!(co.orphan_status(&[0x42; 16]).unwrap(), None);
}

#[test]
fn tc_txn_006_live_transaction_is_not_an_orphan() {
    let (_fs, co) = store();
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(0), int(1)).unwrap();
    // Its coordinator is this process: the persisted record is not consulted, even expired.
    assert_eq!(co.orphan_status(&t.id()).unwrap(), None);
    t.commit().unwrap();
}
