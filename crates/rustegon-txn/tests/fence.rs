// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The write fence of an online backup (`TxnCoordinator::close_timestamp`, PD-063; TC-BKP-001
//! engine part): after it returns T, no transaction commits at or below T; transactions that
//! held intents at or below T finish first, and every write evaluated after the fence lands
//! above T.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    sync::mpsc::{self, TryRecvError},
    time::Duration,
};

use common::{int, key, manual};
use rustegon_common::ErrorCode;
use rustegon_mvcc::Timestamp;
use rustegon_txn::{TxnConfig, TxnCoordinator, TxnError, TxnOptions};

/// Runs the fence on another thread; its result arrives on the returned channel.
fn fence(coord: &TxnCoordinator) -> mpsc::Receiver<Result<Timestamp, TxnError>> {
    let (tx, rx) = mpsc::channel();
    let coord = coord.clone();
    std::thread::spawn(move || {
        let r = coord.close_timestamp(Duration::from_secs(3600), &|| false);
        let _ = tx.send(r);
    });
    rx
}

/// Gives the fence thread time to raise the low-water mark and start waiting, then checks it
/// is still waiting.
fn assert_waiting(rx: &mpsc::Receiver<Result<Timestamp, TxnError>>) {
    match rx.recv_timeout(Duration::from_millis(200)) {
        Err(mpsc::RecvTimeoutError::Timeout) => {}
        other => panic!("the fence did not wait: {other:?}"),
    }
}

#[test]
fn tc_bkp_001_fence_waits_for_intents_at_or_below_t_and_later_writes_land_above() {
    let (coord, _clock) = manual(TxnConfig::default());
    // A holds an intent below the coming T; B has read but not written yet.
    let mut a = coord.begin(TxnOptions::default());
    a.put(&key(1), int(1)).unwrap();
    let mut b = coord.begin(TxnOptions::default());
    assert!(b.get(&key(2)).unwrap().is_none());

    let rx = fence(&coord);
    assert_waiting(&rx);
    // B's first write is evaluated after the fence: above T, so B does not block it.
    b.put(&key(2), int(2)).unwrap();
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    // A commits below T (its timestamp never moved): the fence returns only now.
    let a_ts = a.commit().unwrap().commit_ts;
    let t = rx.recv_timeout(Duration::from_secs(30)).unwrap().unwrap();
    assert!(a_ts <= t, "A committed at {a_ts}, above T = {t}");
    let b_ts = b.commit().unwrap().commit_ts;
    assert!(b_ts > t, "B committed at {b_ts}, not above T = {t}");
    // A single-key write after the fence lands above T too.
    let fast = coord.put_single_key(&key(3), &rustegon_mvcc::VersionValue::Value(int(3)));
    assert!(fast.unwrap() > t);
}

#[test]
fn tc_bkp_001_fence_releases_a_holder_pushed_above_t() {
    let (coord, _clock) = manual(TxnConfig::default());
    let mut a = coord.begin(TxnOptions::default());
    a.put(&key(1), int(1)).unwrap();
    let rx = fence(&coord);
    assert_waiting(&rx);
    // A second write lands above T and raises A's provisional commit timestamp with it: A can
    // no longer commit at or below T, so the fence returns while A is still running.
    a.put(&key(2), int(2)).unwrap();
    let t = rx.recv_timeout(Duration::from_secs(30)).unwrap().unwrap();
    let a_ts = a.commit().unwrap().commit_ts;
    assert!(a_ts > t, "A committed at {a_ts}, not above T = {t}");
}

#[test]
fn tc_bkp_001_fence_aborts_expired_holders_times_out_and_cancels() {
    let config = TxnConfig::default();
    let liveness = config.liveness_timeout;
    let (coord, clock) = manual(config);

    // An idle holder past the liveness timeout is aborted, as any pusher would.
    let mut idle = coord.begin(TxnOptions::default());
    idle.put(&key(1), int(1)).unwrap();
    clock.advance(liveness + Duration::from_secs(1));
    let t = coord.close_timestamp(Duration::ZERO, &|| false).unwrap();
    let err = idle.commit().unwrap_err();
    assert_eq!(err.code(), ErrorCode::TransactionAborted, "{err}");

    // A live holder below the next T: the fence gives up at its deadline, or when cancelled.
    let mut live = coord.begin(TxnOptions::default());
    live.put(&key(2), int(2)).unwrap();
    let err = coord
        .close_timestamp(Duration::ZERO, &|| false)
        .unwrap_err();
    assert!(
        matches!(err, TxnError::CloseTimedOut { blockers: 1, .. }),
        "{err}"
    );
    assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
    let err = coord
        .close_timestamp(Duration::from_secs(3600), &|| true)
        .unwrap_err();
    assert!(matches!(err, TxnError::Cancelled), "{err}");
    assert_eq!(err.code(), ErrorCode::Cancelled);
    // The failed fences still raised the low-water mark: the holder commits, above the first T.
    assert!(live.commit().unwrap().commit_ts > t);
    // Nothing blocks any more.
    assert!(coord.close_timestamp(Duration::ZERO, &|| false).unwrap() > t);
}
