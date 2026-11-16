// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Hybrid logical clock tests (transaction-management.md §2, §7; TC-TXN-009).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{path::Path, sync::Arc};

use common::ManualClock;
use proptest::prelude::*;
use rustegon_mvcc::{
    Hlc, HlcBoundStore, Timestamp,
    hlc::{HLC_BOUND_AHEAD, decode_bound},
};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{FileSystem, OpenMode};

const SEC: u64 = 1_000_000_000;

#[test]
fn tc_txn_009_hlc_now_follows_physical_and_ticks_logical() {
    let clock = ManualClock::new(100);
    let hlc = Hlc::new(clock.clone());
    assert_eq!(hlc.now(), Timestamp::new(100, 0));
    assert_eq!(hlc.now(), Timestamp::new(100, 1));
    clock.set(50); // backward jump: the clock holds and ticks logically
    assert_eq!(hlc.now(), Timestamp::new(100, 2));
    clock.set(200);
    assert_eq!(hlc.now(), Timestamp::new(200, 0));
}

#[test]
fn tc_txn_009_hlc_update_orders_after_received() {
    let clock = ManualClock::new(100);
    let hlc = Hlc::new(clock.clone());
    hlc.update(Timestamp::new(500, 7));
    assert_eq!(hlc.now(), Timestamp::new(500, 8));
    hlc.update(Timestamp::new(10, 0)); // older: no effect
    assert_eq!(hlc.now(), Timestamp::new(500, 9));
}

#[test]
fn tc_txn_009_hlc_monotonic_across_restart_with_backward_clock() {
    let fs: Arc<dyn FileSystem> = Arc::new(SimFileSystem::new());
    let store = HlcBoundStore::new(fs.clone(), Path::new("/node"));
    let clock = ManualClock::new(10 * SEC);
    let hlc = Hlc::recover(clock.clone(), &store).unwrap();
    assert_eq!(hlc.bound(), None);
    let bound = hlc.persist_bound(&store, HLC_BOUND_AHEAD).unwrap();
    assert_eq!(bound, 11 * SEC);
    let mut last = hlc.now();
    // The physical clock runs past the bound (the persister is late): wall is held below it.
    clock.set(30 * SEC);
    for _ in 0..3 {
        let ts = hlc.now();
        assert!(ts > last);
        assert!(
            ts.wall < bound,
            "{ts} must stay below the persisted bound {bound}"
        );
        last = ts;
    }
    // Restart with the clock jumped far back: the new clock starts above everything issued.
    clock.set(SEC);
    let restarted = Hlc::recover(clock.clone(), &store).unwrap();
    let first = restarted.now();
    assert!(first > last, "{first} after restart must exceed {last}");
    restarted.persist_bound(&store, HLC_BOUND_AHEAD).unwrap();
    assert!(restarted.now() > first);
    // The file on disk is the documented format.
    let file = fs
        .open(Path::new("/node/HLC_BOUND"), OpenMode::Read)
        .unwrap();
    let mut buf = vec![0; usize::try_from(file.size().unwrap()).unwrap()];
    file.read_exact_at(&mut buf, 0).unwrap();
    assert!(decode_bound(&buf).unwrap() >= bound);
}

#[test]
fn tc_txn_009_hlc_bound_survives_crash_of_rewrite() {
    let fs = Arc::new(SimFileSystem::new());
    let store = HlcBoundStore::new(fs.clone(), Path::new("/node"));
    store.store(5 * SEC).unwrap();
    // A failed sync during the next rewrite leaves the old bound readable.
    fs.fail_next_syncs(1);
    assert!(store.store(9 * SEC).is_err());
    assert_eq!(store.load().unwrap(), Some(5 * SEC));
}

/// Largest offset of a received timestamp ahead of the anchor (wall time of the last persist)
/// in the model: below
/// `max_clock_offset` (500 ms), beyond which the offset guard terminates the node (§2).
const MAX_AHEAD: u64 = 400_000_000;

proptest! {
    /// Random interleavings of clock moves (forward and backward), receipts, timely persists
    /// and restarts: every timestamp is strictly greater than every one issued or received
    /// before, including across restarts.
    #[test]
    fn tc_txn_009_hlc_monotonic(ops in prop::collection::vec((0u8..4, 0u64..40 * SEC), 1..200)) {
        let fs: Arc<dyn FileSystem> = Arc::new(SimFileSystem::new());
        let store = HlcBoundStore::new(fs, Path::new("/node"));
        let clock = ManualClock::new(20 * SEC);
        let mut hlc = Hlc::recover(clock.clone(), &store).unwrap();
        hlc.persist_bound(&store, HLC_BOUND_AHEAD).unwrap();
        let mut max_seen = Timestamp::MIN;
        // Wall time of the last persist: received timestamps are at most MAX_AHEAD past it.
        let mut anchor = 20 * SEC;
        for (op, arg) in ops {
            match op {
                // A clock move; the persister runs at least every 500 ms, i.e. before the
                // physical clock can pass the bound by more than that.
                0 => {
                    anchor = arg;
                    clock.set(arg);
                    hlc.persist_bound(&store, HLC_BOUND_AHEAD).unwrap();
                }
                1 => {
                    let received = Timestamp::new(arg.min(anchor + MAX_AHEAD), 3);
                    hlc.update(received);
                    max_seen = max_seen.max(received);
                }
                // The local clock jumps (possibly past the bound) before the persister runs;
                // peers' timestamps stay near the last persisted time.
                2 => clock.set(arg),
                _ => {
                    anchor = arg;
                    clock.set(arg);
                    hlc = Hlc::recover(clock.clone(), &store).unwrap();
                    hlc.persist_bound(&store, HLC_BOUND_AHEAD).unwrap();
                }
            }
            let ts = hlc.now();
            prop_assert!(ts > max_seen, "{} <= {}", ts, max_seen);
            max_seen = ts;
        }
    }
}
