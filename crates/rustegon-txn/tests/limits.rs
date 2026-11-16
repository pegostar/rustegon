// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-TXN-008 limits and timeouts (transaction-management.md §9, §11; FR-TXN-008) and the
//! single-range part of TC-TXN-006 (deadlock 2-cycle detected within 1 s, §5.2).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{sync::Arc, time::Duration};

use common::{as_int, int, key, manual};
use rustegon_mvcc::VersionValue;
use rustegon_sim_api::{Clock, SystemClock};
use rustegon_txn::{AbortReason, TxnConfig, TxnError, TxnOptions};

fn code(e: &TxnError) -> u16 {
    e.code().code()
}

fn reason(e: &TxnError) -> Option<AbortReason> {
    match e {
        TxnError::Aborted { reason } => Some(*reason),
        _ => None,
    }
}

#[test]
fn tc_txn_008_max_duration_rgn_2003() {
    let config = TxnConfig {
        max_duration: Duration::from_secs(10),
        liveness_timeout: Duration::from_secs(600),
        ..TxnConfig::default()
    };
    let (co, clock) = manual(config);
    // Server maximum.
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(1), int(1)).unwrap();
    clock.advance(Duration::from_secs(11));
    let e = t.get(&key(1)).unwrap_err();
    assert_eq!(code(&e), 2003, "{e}");
    assert!(!e.is_retryable());
    let e = t.commit().unwrap_err();
    assert_eq!(code(&e), 2002);
    assert_eq!(reason(&e), Some(AbortReason::MaxDuration));
    // Its intent is gone: a writer does not wait.
    co.put_single_key(&key(1), &VersionValue::Value(int(2)))
        .unwrap();
    // The transaction's own, shorter timeout.
    let mut t = co.begin(TxnOptions {
        timeout: Some(Duration::from_secs(1)),
        ..TxnOptions::default()
    });
    t.get(&key(1)).unwrap();
    clock.advance(Duration::from_secs(2));
    assert_eq!(code(&t.put(&key(1), int(3)).unwrap_err()), 2003);
    assert_eq!(as_int(co.get_latest(&key(1)).unwrap().as_ref()), 2);
    assert_eq!(co.live_transactions(), 0);
}

#[test]
fn tc_txn_008_idle_heartbeat_abort() {
    let (co, clock) = manual(TxnConfig::default());
    // An idle holder is pushed out by the next writer once its heartbeat expired.
    let mut idle = co.begin(TxnOptions::default());
    idle.put(&key(1), int(1)).unwrap();
    clock.advance(Duration::from_secs(6));
    co.put_single_key(&key(1), &VersionValue::Value(int(2)))
        .unwrap();
    let e = idle.commit().unwrap_err();
    assert_eq!(code(&e), 2002, "{e}");
    assert_eq!(reason(&e), Some(AbortReason::TimeoutPushed));
    assert!(e.is_retryable());
    assert_eq!(as_int(co.get_latest(&key(1)).unwrap().as_ref()), 2);

    // An idle transaction notices its own expiry on its next operation.
    let mut idle = co.begin(TxnOptions::default());
    clock.advance(Duration::from_secs(6));
    let e = idle.get(&key(1)).unwrap_err();
    assert_eq!(reason(&e), Some(AbortReason::TimeoutPushed));

    // Heartbeats keep a slow transaction alive.
    let mut slow = co.begin(TxnOptions::default());
    slow.put(&key(2), int(5)).unwrap();
    for _ in 0..4 {
        clock.advance(Duration::from_secs(3));
        slow.heartbeat().unwrap();
    }
    slow.commit().unwrap();
    assert_eq!(as_int(co.get_latest(&key(2)).unwrap().as_ref()), 5);
    assert_eq!(co.live_transactions(), 0);
}

#[test]
fn tc_txn_008_expiry_is_observable_without_an_operation() {
    let config = TxnConfig {
        max_duration: Duration::from_secs(30),
        ..TxnConfig::default()
    };
    let (co, clock) = manual(config);
    // A read-write transaction: idle expiry after `liveness_timeout` (5 s).
    let mut t = co.begin(TxnOptions::default());
    t.put(&key(1), int(1)).unwrap();
    assert_eq!(t.expires_in(), Duration::from_secs(5));
    clock.advance(Duration::from_secs(2));
    assert_eq!(t.expires_in(), Duration::from_secs(3));
    assert_eq!(t.pending_abort(), None);
    t.heartbeat().unwrap();
    assert_eq!(t.expires_in(), Duration::from_secs(5));
    clock.advance(Duration::from_secs(6));
    // Observed without running an operation (no heartbeat side effect)…
    assert_eq!(t.expires_in(), Duration::ZERO);
    assert_eq!(t.pending_abort(), Some(AbortReason::TimeoutPushed));
    // …and confirmed by the next one.
    assert_eq!(
        reason(&t.get(&key(1)).unwrap_err()),
        Some(AbortReason::TimeoutPushed)
    );
    assert_eq!(t.pending_abort(), Some(AbortReason::TimeoutPushed));

    // A read-only transaction holds no intents: idleness does not abort it (PD-049), only
    // its maximum duration does.
    let mut ro = co.begin(TxnOptions {
        access: rustegon_txn::AccessMode::ReadOnly,
        ..TxnOptions::default()
    });
    ro.get(&key(1)).unwrap();
    clock.advance(Duration::from_secs(20));
    assert_eq!(ro.pending_abort(), None);
    assert_eq!(ro.expires_in(), Duration::from_secs(10));
    ro.get(&key(1)).unwrap();
    clock.advance(Duration::from_secs(11));
    assert_eq!(ro.pending_abort(), Some(AbortReason::MaxDuration));
    assert_eq!(code(&ro.get(&key(1)).unwrap_err()), 2003);
    // Finished transactions do not expire.
    let mut done = co.begin(TxnOptions::default());
    done.commit().unwrap();
    assert_eq!(done.expires_in(), Duration::ZERO);
    assert_eq!(done.pending_abort(), None);
    assert_eq!(co.live_transactions(), 0);
}

#[test]
fn tc_txn_008_write_set_rgn_2004() {
    let config = TxnConfig {
        max_write_keys: 3,
        max_write_bytes: 100,
        ..TxnConfig::default()
    };
    let (co, _clock) = manual(config);
    let mut t = co.begin(TxnOptions::default());
    for n in 1..=3 {
        t.put(&key(n), int(1)).unwrap();
    }
    // Rewriting a key already in the write set does not count as a new key.
    t.put(&key(1), int(2)).unwrap();
    let e = t.put(&key(4), int(1)).unwrap_err();
    assert_eq!(code(&e), 2004, "{e}");
    assert!(!e.is_retryable());
    assert_eq!(
        reason(&t.get(&key(1)).unwrap_err()),
        Some(AbortReason::TooLarge)
    );
    for n in 1..=4 {
        assert_eq!(co.get_latest(&key(n)).unwrap(), None, "key {n} leaked");
    }
    let mut t = co.begin(TxnOptions::default());
    let e = t.put(&key(1), vec![0u8; 200]).unwrap_err();
    assert!(matches!(e, TxnError::TooLarge { what: "bytes", .. }), "{e}");
    assert_eq!(co.live_transactions(), 0);
}

#[test]
fn tc_txn_006_deadlock_2_cycle_detected_single_range() {
    let clock = Arc::new(SystemClock::new());
    let co = common::coordinator(
        common::open_replica(&Arc::new(rustegon_sim::SimFileSystem::new())).unwrap(),
        clock.clone(),
        TxnConfig::default(),
        3,
    );
    let mut t1 = co.begin(TxnOptions::default());
    let mut t2 = co.begin(TxnOptions::default());
    t1.put(&key(1), int(1)).unwrap();
    t2.put(&key(2), int(2)).unwrap();
    let start = clock.monotonic();
    let c1 = clock.clone();
    let a = std::thread::spawn(move || {
        let r = t1.put(&key(2), int(1));
        (r.map(|()| t1.commit()), c1.monotonic())
    });
    let c2 = clock.clone();
    let b = std::thread::spawn(move || {
        let r = t2.put(&key(1), int(2));
        (r, c2.monotonic())
    });
    let (ra, _) = a.join().unwrap();
    let (rb, detected_at) = b.join().unwrap();
    // Equal priorities: the victim is the younger transaction, t2 (§5.2).
    let e = rb.unwrap_err();
    assert_eq!(code(&e), 2005, "{e}");
    assert!(e.is_retryable());
    ra.unwrap().unwrap();
    let latency = detected_at.saturating_sub(start);
    assert!(
        latency < Duration::from_secs(1),
        "detected after {latency:?}"
    );
    assert_eq!(as_int(co.get_latest(&key(1)).unwrap().as_ref()), 1);
    assert_eq!(as_int(co.get_latest(&key(2)).unwrap().as_ref()), 1);
    assert_eq!(co.live_transactions(), 0);
}

#[test]
fn tc_txn_006_higher_priority_writer_pushes_holder() {
    let (co, _clock) = manual(TxnConfig::default());
    let mut low = co.begin(TxnOptions {
        priority: rustegon_txn::Priority::Low,
        ..TxnOptions::default()
    });
    low.put(&key(1), int(1)).unwrap();
    let mut high = co.begin(TxnOptions {
        priority: rustegon_txn::Priority::High,
        ..TxnOptions::default()
    });
    high.put(&key(1), int(2)).unwrap();
    high.commit().unwrap();
    let e = low.commit().unwrap_err();
    assert_eq!(reason(&e), Some(AbortReason::Conflict));
    assert!(e.is_retryable());
    // A high-priority reader pushes the holder's timestamp instead of aborting it.
    let mut holder = co.begin(TxnOptions::default());
    holder.put(&key(1), int(3)).unwrap();
    let mut reader = co.begin(TxnOptions {
        priority: rustegon_txn::Priority::High,
        ..TxnOptions::default()
    });
    assert_eq!(as_int(reader.get(&key(1)).unwrap().as_ref()), 2);
    reader.commit().unwrap();
    let commit = holder.commit().unwrap();
    assert!(commit.commit_ts > reader.read_ts());
    assert_eq!(as_int(co.get_latest(&key(1)).unwrap().as_ref()), 3);
}
