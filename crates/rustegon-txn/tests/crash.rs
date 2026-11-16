// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-TXN-004, single-range part (M2 exit, DEC-018; FR-TXN-001, NFR-REL-001): a one-phase
//! commit is atomic and durable across crashes of the `LocalReplica` store.
//!
//! A workload of multi-key transactions (every transaction writes the same keys with its own
//! number; each intent is its own proposal, the commit one more) runs on `SimFileSystem`, which
//! halts at every mutating file-system operation in turn and crashes in every [`CrashMode`].
//! After reopening the store and a new coordinator (whose clock is far ahead, so the records of
//! transactions interrupted before their commit have expired), every key must hold:
//! - the number of the last **acknowledged** commit (durability), or
//! - the number of the transaction whose commit was in flight (it may have been logged),
//!
//! and all keys the same number (atomicity: no transaction partially visible). Interrupted
//! transactions' intents are resolved through their expired `PENDING` records on first contact,
//! and the store then accepts and commits a new transaction.
//!
//! FR-TXN-005/006, PD-121: before anything else touches the recovered store, every transaction
//! of the workload is asked for its persisted outcome (`TxnCoordinator::orphan_status`, which
//! aborts expired `PENDING` records). A transaction that turns out committed is never reported
//! aborted, and the abort of the others never loses a committed write (the checks above run
//! after it).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{error::Error, sync::Arc, time::Duration};

use common::{ManualClock, T0, as_int, coordinator, int, key, open_replica};
use rustegon_mvcc::Replica;
use rustegon_mvcc::TxnId;
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_txn::{OrphanStatus, TxnConfig, TxnOptions};

/// Transactions in the workload.
const TXNS: i64 = 5;
const _: () = assert!(TXNS == 5, "resize `Outcome::ids`");
/// Keys written by each transaction.
const KEYS: u8 = 3;
/// Bound of the seed search for the "commit logged but not acknowledged" window (see
/// `tc_txn_004_single_range_commit_crash_atomic`).
const WINDOW_SEARCH_SEEDS: u64 = 4096;

/// What the workload achieved before the file system halted.
#[derive(Debug, Default, Clone, Copy)]
struct Outcome {
    acked: i64,
    in_flight: Option<i64>,
    /// Id of transaction `i` at index `i - 1`, once it wrote.
    ids: [Option<TxnId>; 5],
}

fn run(fs: &Arc<SimFileSystem>, out: &mut Outcome) -> Result<(), Box<dyn Error>> {
    let replica = open_replica(fs)?;
    let co = coordinator(
        replica.clone(),
        ManualClock::new(T0),
        TxnConfig::default(),
        11,
    );
    for i in 1..=TXNS {
        // Flushes put earlier commits into SSTs, so recovery mixes SST data and log replay.
        if i % 2 == 0 {
            replica.engine().flush()?;
        }
        let mut t = co.begin(TxnOptions::default());
        for k in 0..KEYS {
            t.put(&key(k), int(i))?;
        }
        out.ids[usize::try_from(i - 1)?] = Some(t.id());
        out.in_flight = Some(i);
        t.commit()?;
        out.acked = i;
        out.in_flight = None;
    }
    Ok(())
}

fn bootstrapped() -> Arc<SimFileSystem> {
    let fs = Arc::new(SimFileSystem::new());
    drop(open_replica(&fs).unwrap());
    fs
}

/// What one recovery observed.
#[derive(Debug, Default, Clone, Copy)]
struct Seen {
    /// The in-flight commit turned out committed.
    in_flight_committed: bool,
    /// Intents of an interrupted transaction were left to resolve.
    leftover_intents: bool,
}

/// Reopens after a crash and checks atomicity and durability (module docs).
fn check_recovery(fs: &Arc<SimFileSystem>, out: Outcome, ctx: &str) -> Seen {
    let replica = open_replica(fs).unwrap_or_else(|e| panic!("{ctx}: reopen failed: {e}"));
    let leftover_intents = (0..KEYS).any(|k| {
        replica
            .reader()
            .get_intent(&key(k))
            .unwrap_or_else(|e| panic!("{ctx}: {e}"))
            .is_some()
    });
    let clock = ManualClock::new(T0);
    clock.advance(Duration::from_secs(3600));
    let co = coordinator(replica, clock, TxnConfig::default(), 12);
    let orphans: Vec<(i64, Option<OrphanStatus>)> = (1..=TXNS)
        .zip(out.ids)
        .filter_map(|(i, id)| id.map(|id| (i, id)))
        .map(|(i, id)| {
            let status = co
                .orphan_status(&id)
                .unwrap_or_else(|e| panic!("{ctx}: orphan status of {i}: {e}"));
            (i, status)
        })
        .collect();
    let values: Vec<i64> = (0..KEYS)
        .map(|k| {
            as_int(
                co.get_latest(&key(k))
                    .unwrap_or_else(|e| panic!("{ctx}: {e}"))
                    .as_ref(),
            )
        })
        .collect();
    let first = values[0];
    assert!(
        values.iter().all(|v| *v == first),
        "{ctx}: partially visible transaction: {values:?}"
    );
    assert!(
        first == out.acked || Some(first) == out.in_flight,
        "{ctx}: recovered {first}, acknowledged {}, in flight {:?}",
        out.acked,
        out.in_flight
    );
    for (i, status) in orphans {
        let committed = i <= out.acked || (Some(i) == out.in_flight && first == i);
        if committed {
            // No record left by a 1PC commit: unknown, never aborted.
            assert_eq!(
                status, None,
                "{ctx}: committed transaction {i} reported {status:?}"
            );
        } else {
            // Its record expired an hour ago: aborted, or no record if it died before it.
            assert_ne!(
                status,
                Some(OrphanStatus::InDoubt),
                "{ctx}: transaction {i}"
            );
        }
    }
    // The store is usable: a new transaction over the same keys commits.
    let mut t = co.begin(TxnOptions::default());
    for k in 0..KEYS {
        t.put(&key(k), int(100))
            .unwrap_or_else(|e| panic!("{ctx}: {e}"));
    }
    t.commit()
        .unwrap_or_else(|e| panic!("{ctx}: commit after recovery: {e}"));
    assert_eq!(
        as_int(co.get_latest(&key(0)).unwrap().as_ref()),
        100,
        "{ctx}"
    );
    Seen {
        in_flight_committed: first != out.acked,
        leftover_intents,
    }
}

/// Runs the workload halting at crash point `point`, crashes with `seed` in `mode` and checks
/// recovery.
fn crash_once(point: u64, seed: u64, mode: CrashMode) -> (Outcome, Seen) {
    let fs = bootstrapped();
    fs.halt_after_ops(point);
    let mut out = Outcome::default();
    let result = run(&fs, &mut out);
    assert!(fs.is_halted(), "point {point} did not halt ({result:?})");
    fs.crash(seed, mode);
    let observed = check_recovery(
        &fs,
        out,
        &format!("crash point {point}, {mode:?}, seed {seed}"),
    );
    (out, observed)
}

#[test]
fn tc_txn_004_single_range_commit_crash_atomic() {
    let fs = bootstrapped();
    let start = fs.op_count();
    let mut full = Outcome::default();
    run(&fs, &mut full).unwrap();
    assert_eq!(full.acked, TXNS);
    let total = fs.op_count() - start;
    assert!(total >= 2 * 4 * TXNS as u64, "only {total} crash points");
    let mut seen = Seen::default();
    for point in 0..total {
        for mode in CrashMode::ALL {
            let (_, s) = crash_once(point, point, mode);
            seen.in_flight_committed |= s.in_flight_committed;
            seen.leftover_intents |= s.leftover_intents;
        }
    }
    // The "commit logged but not acknowledged" window is the halt at the log sync of a commit
    // whose record nevertheless reached the disk whole. A torn crash keeps a random prefix of the
    // unsynced tail, so one draw per point hits it with probability ~1/(record length + 1): the
    // coverage used to depend on which seed a point number happened to give (shifting the op
    // numbering once made this assertion fail). Search seeds deterministically instead, only at
    // points that interrupted a commit; every draw is still fully checked.
    'search: for point in 0..total {
        if seen.in_flight_committed {
            break;
        }
        for seed in 0..WINDOW_SEARCH_SEEDS {
            let (out, s) = crash_once(point, seed, CrashMode::TornPrefix);
            if out.in_flight.is_none() {
                continue 'search;
            }
            seen.in_flight_committed |= s.in_flight_committed;
            seen.leftover_intents |= s.leftover_intents;
            if seen.in_flight_committed {
                break 'search;
            }
        }
    }
    // The crash points must cover both interesting windows.
    assert!(
        seen.in_flight_committed,
        "no crash point found a logged, unacknowledged commit"
    );
    assert!(
        seen.leftover_intents,
        "no crash point left intents of an interrupted transaction"
    );
}

#[test]
fn tc_txn_004_single_range_commit_survives_clean_restart() {
    let fs = bootstrapped();
    let mut out = Outcome::default();
    run(&fs, &mut out).unwrap();
    fs.crash(0, CrashMode::Clean);
    let seen = check_recovery(&fs, out, "clean power cut after the workload");
    assert!(!seen.leftover_intents && !seen.in_flight_committed);
}
