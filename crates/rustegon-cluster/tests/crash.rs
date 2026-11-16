// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-TXN-004, single-range part (M2 exit, DEC-018; FR-TXN-001, NFR-REL-001): the local replica
//! survives a crash at every file-system operation through Raft log replay (ADR-009,
//! storage-engine.md §9, replication.md §2).
//!
//! Reproducible workloads of multi-op proposals, engine flushes and compactions, log purges and
//! restarts run on `SimFileSystem` with tiny memtables and log segments. The file system halts
//! at every mutating operation in turn (log appends and syncs, segment rollovers and deletions,
//! SST and MANIFEST writes, recovery's own writes), crashes in every [`CrashMode`] with several
//! seeds, and the store is reopened.
//!
//! Asserted after every crash:
//! - the reopen succeeds;
//! - the data is exactly the acknowledged state, or that state plus the whole in-flight
//!   proposal: no acknowledged proposal lost, no proposal partially applied;
//! - the persisted `RangeAppliedState` equals the replica's and names the last log entry, and
//!   the log still holds every entry after the engine's flushed applied state (`observe`);
//! - the store accepts a new proposal, and a further restart (memtables lost, replay again)
//!   returns the same state: replay is repeatable.
//!
//! A second test crashes *during recovery* too (open, replay, flush of the replayed data, purge)
//! at every operation, then recovers again and checks the same properties.
//!
//! Scale: `RUSTEGON_CRASH_SEEDS` (default 2) seeds per crash point and mode, workloads from
//! `RUSTEGON_CRASH_WORKLOADS` (default 2).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{error::Error, sync::Arc};

use common::{Model, Op, Step, Store, command, observe, open, workload};
use rustegon_mvcc::Replica;
use rustegon_sim::{CrashMode, SimFileSystem};

/// Workload length in steps.
const STEPS: usize = 40;
/// Lower bound on crash points per workload (each proposal costs at least an append and a
/// sync). Fewer means the workload silently shrank.
const MIN_CRASH_POINTS: u64 = 60;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// What the workload achieved before the file system halted.
#[derive(Default)]
struct Outcome {
    acked: Model,
    in_flight: Option<Model>,
}

fn run(fs: &Arc<SimFileSystem>, steps: &[Step], out: &mut Outcome) -> Result<(), Box<dyn Error>> {
    let mut store = open(fs)?;
    for (i, step) in steps.iter().enumerate() {
        match step {
            Step::Propose(ops) => {
                out.in_flight = Some(out.acked.after(ops));
                let state = store.replica.propose(command(ops, i as u64))?;
                out.acked = out.in_flight.take().unwrap();
                assert_eq!(state.applied_index, out.acked.applied);
            }
            Step::Flush => store.engine.flush()?,
            Step::Compact => {
                store.engine.compact()?;
            }
            Step::Purge => {
                store.replica.purge_flushed()?;
            }
            Step::Restart => {
                drop(store);
                store = open(fs)?;
                assert_eq!(observe(&store).unwrap(), out.acked, "restart without crash");
            }
        }
    }
    Ok(())
}

/// The recovered state must be the acknowledged one or it plus the in-flight proposal.
fn check_state(store: &Store, out: &Outcome, ctx: &str) -> Model {
    let got = observe(store).unwrap_or_else(|e| panic!("{ctx}: {e}"));
    if got == out.acked || out.in_flight.as_ref() == Some(&got) {
        return got;
    }
    panic!(
        "{ctx}: recovered state is neither the acknowledged one nor the in-flight one\n\
         got {got:?}\nacked {:?}\nin flight {:?}",
        out.acked, out.in_flight
    );
}

/// Checks recovery after a crash; panics with `ctx` on a violated property.
fn check_recovery(fs: &Arc<SimFileSystem>, out: &Outcome, ctx: &str) {
    let store = open(fs).unwrap_or_else(|e| panic!("{ctx}: recovery failed: {e}"));
    let model = check_state(&store, out, ctx);
    // Still writable and durable: one more proposal, then a restart that loses the memtables
    // and a clean power cut.
    let ops = [Op::Put(0, b"after".to_vec()), Op::Delete(1)];
    let next = model.after(&ops);
    store
        .replica
        .propose(command(&ops, 1_000))
        .unwrap_or_else(|e| panic!("{ctx}: proposal after recovery failed: {e}"));
    drop(store);
    fs.crash(0, CrashMode::Clean);
    let store = open(fs).unwrap_or_else(|e| panic!("{ctx}: second reopen: {e}"));
    assert_eq!(observe(&store).unwrap(), next, "{ctx}: second reopen");
}

/// A file system holding a freshly created, empty store. Creating a store (first engine MANIFEST
/// and `CURRENT`) is a one-time bootstrap covered by the storage crate's tests, so crash points
/// start after it, as in `rustegon-storage`'s TC-STO-002 campaign.
fn bootstrapped() -> Arc<SimFileSystem> {
    let fs = Arc::new(SimFileSystem::new());
    drop(open(&fs).unwrap());
    fs
}

/// Mutating operations of a full run of `steps`.
fn crash_points(steps: &[Step], w: u64) -> u64 {
    let fs = bootstrapped();
    let start = fs.op_count();
    run(&fs, steps, &mut Outcome::default()).unwrap();
    let total = fs.op_count() - start;
    assert!(total >= MIN_CRASH_POINTS, "workload {w}: only {total} ops");
    total
}

/// Runs `steps` on a bootstrapped store halting after `point` operations and crashes; returns
/// the file system and the outcome.
fn crash_run(
    steps: &[Step],
    point: u64,
    seed: u64,
    mode: CrashMode,
) -> (Arc<SimFileSystem>, Outcome) {
    let fs = bootstrapped();
    fs.halt_after_ops(point);
    let mut out = Outcome::default();
    let result = run(&fs, steps, &mut out);
    assert!(fs.is_halted(), "point {point} did not halt ({result:?})");
    fs.crash(seed, mode);
    (fs, out)
}

#[test]
fn tc_txn_004_local_replica_survives_crash_through_log_replay() {
    let seeds = env("RUSTEGON_CRASH_SEEDS", 2);
    let workloads = env("RUSTEGON_CRASH_WORKLOADS", 2);
    for w in 0..workloads {
        let steps = workload(0x5EED_0000 + w, STEPS);
        let total = crash_points(&steps, w);
        for point in 0..total {
            for mode in CrashMode::ALL {
                for seed in 0..seeds {
                    let (fs, out) = crash_run(&steps, point, seed, mode);
                    let ctx = format!("workload {w}, crash point {point}, {mode:?}, seed {seed}");
                    check_recovery(&fs, &out, &ctx);
                }
            }
        }
    }
}

/// Recovery that also flushes the replayed data and purges the log: every kind of write the
/// replica and the engine do on their way back up.
fn recover(fs: &Arc<SimFileSystem>) -> Result<Store, Box<dyn Error>> {
    let store = open(fs)?;
    store.engine.flush()?;
    store.replica.purge_flushed()?;
    Ok(store)
}

#[test]
fn tc_txn_004_local_replica_survives_crash_during_replay() {
    let workloads = env("RUSTEGON_CRASH_WORKLOADS", 2);
    for w in 0..workloads {
        let steps = workload(0x5EED_1000 + w, STEPS);
        let total = crash_points(&steps, w);
        // Every third crash point keeps the run time moderate; each gets every recovery point.
        for point in (0..total).step_by(3) {
            let mode = CrashMode::ALL[(point % 4) as usize];
            let mut inner = 0;
            loop {
                let (fs, out) = crash_run(&steps, point, point, mode);
                fs.halt_after_ops(inner);
                let recovered = recover(&fs);
                if !fs.is_halted() {
                    // The recovery finished before the halt: every recovery point was covered.
                    assert!(recovered.is_ok(), "{:?}", recovered.err());
                    break;
                }
                drop(recovered);
                let inner_mode = CrashMode::ALL[((point + inner) % 4) as usize];
                fs.crash(inner, inner_mode);
                let ctx = format!(
                    "workload {w}, crash point {point} ({mode:?}), recovery crash point {inner} \
                     ({inner_mode:?})"
                );
                check_recovery(&fs, &out, &ctx);
                inner += 1;
            }
        }
    }
}

#[test]
fn tc_txn_004_local_replica_workload_completes_and_reopens_without_crash() {
    let steps = workload(0x5EED_0000, STEPS);
    let fs = bootstrapped();
    let mut out = Outcome::default();
    run(&fs, &steps, &mut out).unwrap();
    assert!(
        out.acked.applied > 10,
        "too few proposals: {}",
        out.acked.applied
    );
    // The workloads of the crash tests must exercise purges and replays, otherwise the crash
    // points miss the interesting windows.
    for seed in [0x5EED_0000, 0x5EED_0001, 0x5EED_1000, 0x5EED_1001] {
        let steps = workload(seed, STEPS);
        assert!(steps.contains(&Step::Purge) && steps.contains(&Step::Restart));
        assert!(
            steps.contains(&Step::Flush),
            "workload {seed:#x} never flushes"
        );
    }
    let store = open(&fs).unwrap();
    let (first, _) = store.replica.log_bounds();
    assert!(first > 1, "workload never purged the log");
    drop(store);
    fs.crash(0, CrashMode::Clean);
    check_recovery(&fs, &out, "no crash point");
}
