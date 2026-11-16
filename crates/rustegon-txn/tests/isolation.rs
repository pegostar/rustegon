// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-TXN-003 expected-anomaly tests per isolation level and TC-TXN-007 savepoints
//! (transaction-management.md §4.2 anomaly matrix, §10; FR-TXN-002, FR-TXN-007).
//!
//! Interleavings are driven step by step from one thread with a manual clock, except where a
//! transaction must block (then a second thread runs it).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{as_int, int, key, manual};
use rustegon_mvcc::VersionValue;
use rustegon_txn::{Isolation, TxnConfig, TxnCoordinator, TxnError, TxnOptions};

fn opts(isolation: Isolation) -> TxnOptions {
    TxnOptions::with_isolation(isolation)
}

fn set(co: &TxnCoordinator, n: u8, v: i64) {
    co.put_single_key(&key(n), &VersionValue::Value(int(v)))
        .unwrap();
}

fn read(co: &TxnCoordinator, n: u8) -> i64 {
    as_int(co.get_latest(&key(n)).unwrap().as_ref())
}

fn code(e: &TxnError) -> u16 {
    e.code().code()
}

/// The doctors' on-call write skew: both read `x + y = 2`, each sets a different key to 0.
fn write_skew(isolation: Isolation) -> (Result<(), TxnError>, Result<(), TxnError>, i64) {
    let (co, _clock) = manual(TxnConfig::default());
    set(&co, 1, 1);
    set(&co, 2, 1);
    let mut t1 = co.begin(opts(isolation));
    let mut t2 = co.begin(opts(isolation));
    for t in [&mut t1, &mut t2] {
        let sum =
            as_int(t.get(&key(1)).unwrap().as_ref()) + as_int(t.get(&key(2)).unwrap().as_ref());
        assert_eq!(sum, 2);
    }
    t1.put(&key(1), int(0)).unwrap();
    t2.put(&key(2), int(0)).unwrap();
    let r1 = t1.commit().map(|_| ());
    let r2 = t2.commit().map(|_| ());
    drop((t1, t2));
    (r1, r2, read(&co, 1) + read(&co, 2))
}

#[test]
fn tc_txn_003_write_skew_blocked_serializable() {
    let (r1, r2, sum) = write_skew(Isolation::Serializable);
    assert!(r1.is_err() || r2.is_err(), "both committed: write skew");
    for e in [r1.err(), r2.err()].into_iter().flatten() {
        assert_eq!(code(&e), 2001, "{e}");
        assert!(e.is_retryable());
    }
    assert!(sum >= 1, "invariant x + y >= 1 broken: {sum}");
}

#[test]
fn tc_txn_003_write_skew_allowed_snapshot() {
    let (r1, r2, sum) = write_skew(Isolation::Snapshot);
    r1.unwrap();
    r2.unwrap();
    assert_eq!(sum, 0, "SNAPSHOT permits write skew (§4.2)");
}

#[test]
fn tc_txn_003_non_repeatable_read_rc() {
    for isolation in [
        Isolation::ReadCommitted,
        Isolation::Snapshot,
        Isolation::Serializable,
    ] {
        let (co, _clock) = manual(TxnConfig::default());
        set(&co, 1, 1);
        let mut t = co.begin(opts(isolation));
        assert_eq!(as_int(t.get(&key(1)).unwrap().as_ref()), 1);
        set(&co, 1, 2);
        let again = as_int(t.get(&key(1)).unwrap().as_ref());
        if isolation == Isolation::ReadCommitted {
            assert_eq!(again, 2, "READ COMMITTED reads the latest committed value");
        } else {
            assert_eq!(again, 1, "{isolation:?} must repeat its read");
        }
        t.commit().unwrap();
    }
}

#[test]
fn tc_txn_003_lost_update_prevented() {
    // Read-then-write of a counter by two interleaved transactions: the second one must not
    // overwrite the first one's increment.
    for isolation in [Isolation::Serializable, Isolation::Snapshot] {
        let (co, _clock) = manual(TxnConfig::default());
        set(&co, 1, 0);
        let mut t1 = co.begin(opts(isolation));
        let mut t2 = co.begin(opts(isolation));
        let v1 = as_int(t1.get(&key(1)).unwrap().as_ref());
        let v2 = as_int(t2.get(&key(1)).unwrap().as_ref());
        t1.put(&key(1), int(v1 + 1)).unwrap();
        t1.commit().unwrap();
        let second = t2
            .put(&key(1), int(v2 + 1))
            .and_then(|()| t2.commit().map(|_| ()));
        let e = second.expect_err("lost update");
        assert_eq!(code(&e), 2001, "{isolation:?}: {e}");
        t2.restart().unwrap();
        let v = as_int(t2.get(&key(1)).unwrap().as_ref());
        t2.put(&key(1), int(v + 1)).unwrap();
        t2.commit().unwrap();
        assert_eq!(read(&co, 1), 2, "{isolation:?}");
    }
    // READ COMMITTED: the read-modify-write statement waits for the conflicting intent and is
    // re-evaluated on the committed value (EvalPlanQual-like, §4.1).
    let (co, _clock) = manual(TxnConfig::default());
    set(&co, 1, 0);
    let increment = |v: Option<&bytes::Bytes>| Some(VersionValue::Value(int(as_int(v) + 1)));
    let mut t1 = co.begin(opts(Isolation::ReadCommitted));
    t1.update(&key(1), increment).unwrap();
    let co2 = co.clone();
    let second = std::thread::spawn(move || {
        let mut t2 = co2.begin(opts(Isolation::ReadCommitted));
        let seen = t2.update(&key(1), increment).unwrap();
        t2.commit().unwrap();
        as_int(seen.as_ref())
    });
    while co.waiters(&key(1)).is_empty() {
        std::thread::yield_now();
    }
    t1.commit().unwrap();
    assert_eq!(
        second.join().unwrap(),
        1,
        "re-evaluated on the committed value"
    );
    assert_eq!(read(&co, 1), 2);
}

#[test]
fn tc_txn_003_lost_update_prevented_concurrent_counters() {
    const THREADS: i64 = 4;
    const INCREMENTS: i64 = 25;
    let cases = [
        (Isolation::Serializable, false),
        (Isolation::Snapshot, false),
        (Isolation::Serializable, true),
        (Isolation::Snapshot, true),
        (Isolation::ReadCommitted, true),
    ];
    for (isolation, use_update) in cases {
        let co = common::system(TxnConfig::default());
        set(&co, 1, 0);
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let co = co.clone();
                std::thread::spawn(move || {
                    for _ in 0..INCREMENTS {
                        co.run(&opts(isolation), 10_000, |t| {
                            if use_update {
                                t.update(&key(1), |v| {
                                    Some(VersionValue::Value(int(as_int(v) + 1)))
                                })?;
                            } else {
                                let v = as_int(t.get(&key(1))?.as_ref());
                                t.put(&key(1), int(v + 1))?;
                            }
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        assert_eq!(
            read(&co, 1),
            THREADS * INCREMENTS,
            "{isolation:?}, update={use_update}"
        );
        assert_eq!(co.live_transactions(), 0);
    }
}

#[test]
fn tc_txn_003_snapshot_first_committer_wins() {
    let (co, _clock) = manual(TxnConfig::default());
    set(&co, 1, 0);
    let mut t = co.begin(opts(Isolation::Snapshot));
    assert_eq!(as_int(t.get(&key(1)).unwrap().as_ref()), 0);
    set(&co, 1, 5);
    let e = t.put(&key(1), int(1)).unwrap_err();
    assert_eq!(code(&e), 2001);
    // Restart required: other operations keep failing until restart or rollback.
    assert_eq!(code(&t.get(&key(1)).unwrap_err()), 2001);
    t.rollback().unwrap();
    assert_eq!(code(&t.get(&key(1)).unwrap_err()), 2002);
    assert_eq!(read(&co, 1), 5);
}

#[test]
fn tc_txn_001_reads_own_writes_and_commits_atomically() {
    let (co, _clock) = manual(TxnConfig::default());
    // Started first: its snapshot precedes the other transaction's commit.
    let mut other = co.begin(TxnOptions::default());
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(1), int(10)).unwrap();
    t.put(&key(2), int(20)).unwrap();
    t.delete(&key(2)).unwrap();
    assert_eq!(as_int(t.get(&key(1)).unwrap().as_ref()), 10);
    assert_eq!(t.get(&key(2)).unwrap(), None);
    let rows = t.scan(&key(0), &key(9), 100).unwrap();
    assert_eq!(rows.len(), 1);
    let commit = t.commit().unwrap();
    assert!(commit.commit_ts >= t.read_ts());
    assert_eq!(
        other.get(&key(1)).unwrap(),
        None,
        "snapshot taken before the commit"
    );
    other.commit().unwrap();
    assert_eq!(read(&co, 1), 10);
    assert_eq!(co.get_latest(&key(2)).unwrap(), None);
    assert_eq!(co.live_transactions(), 0);
}

#[test]
fn tc_txn_007_savepoint_rollback_discards_later_writes() {
    let (co, _clock) = manual(TxnConfig::default());
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(1), int(1)).unwrap();
    t.savepoint("s1").unwrap();
    t.put(&key(1), int(2)).unwrap();
    t.put(&key(2), int(1)).unwrap();
    t.savepoint("s2").unwrap();
    t.put(&key(3), int(1)).unwrap();
    t.rollback_to_savepoint("s1").unwrap();
    assert_eq!(as_int(t.get(&key(1)).unwrap().as_ref()), 1);
    assert_eq!(t.get(&key(2)).unwrap(), None);
    assert_eq!(t.get(&key(3)).unwrap(), None);
    // s2 was discarded with the rollback; s1 stays usable.
    assert_eq!(code(&t.rollback_to_savepoint("s2").unwrap_err()), 1001);
    t.put(&key(4), int(4)).unwrap();
    t.rollback_to_savepoint("s1").unwrap();
    t.put(&key(1), int(7)).unwrap();
    t.savepoint("s3").unwrap();
    t.put(&key(5), int(5)).unwrap();
    t.release_savepoint("s3").unwrap();
    assert_eq!(code(&t.release_savepoint("s3").unwrap_err()), 1001);
    t.commit().unwrap();
    assert_eq!(read(&co, 1), 7);
    for absent in [2, 3, 4] {
        assert_eq!(co.get_latest(&key(absent)).unwrap(), None, "key {absent}");
    }
    assert_eq!(read(&co, 5), 5);
}

#[test]
fn tc_txn_007_savepoint_rollback_of_only_write_leaves_no_version() {
    let (co, _clock) = manual(TxnConfig::default());
    set(&co, 1, 3);
    let mut t = co.begin(TxnOptions::default());
    t.savepoint("s").unwrap();
    t.put(&key(1), int(9)).unwrap();
    t.rollback_to_savepoint("s").unwrap();
    assert_eq!(as_int(t.get(&key(1)).unwrap().as_ref()), 3);
    t.commit().unwrap();
    assert_eq!(read(&co, 1), 3);
}

#[test]
fn tc_txn_001_fast_path_and_read_only_transactions() {
    let (co, _clock) = manual(TxnConfig::default());
    let ts1 = co
        .put_single_key(&key(1), &VersionValue::Value(int(1)))
        .unwrap();
    let ts2 = co
        .put_single_key(&key(1), &VersionValue::Value(int(2)))
        .unwrap();
    assert!(ts2 > ts1);
    let mut ro = co.begin(TxnOptions {
        access: rustegon_txn::AccessMode::ReadOnly,
        ..TxnOptions::default()
    });
    assert_eq!(as_int(ro.get(&key(1)).unwrap().as_ref()), 2);
    assert_eq!(code(&ro.put(&key(1), int(3)).unwrap_err()), 1001);
    ro.commit().unwrap();
    // A fast-path write lands above the newest committed version.
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(2), int(1)).unwrap();
    t.commit().unwrap();
    co.put_single_key(&key(2), &VersionValue::Tombstone)
        .unwrap();
    assert_eq!(co.get_latest(&key(2)).unwrap(), None);
}
