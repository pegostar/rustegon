// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-TXN-004 (storage half of the M2 log-replay crash test, NFR-REL-003): crash simulation of
//! the Raft log store on the simulated file system (ADR-009, ADR-029, storage-engine.md §9,
//! replication.md §2).
//!
//! Reproducible workloads of multi-group batches (appends, overwrites, truncations, purges,
//! snapshot installs, removals, hard states) with reopens in between run on `SimFileSystem` with
//! small segments, so rollovers, segment deletions and torn-tail repairs are part of the
//! workload. The file system halts at every mutating operation in turn — inside appends, syncs,
//! segment creation, deletion and repair — then crashes in every [`CrashMode`] with several
//! seeds, and the store is reopened.
//!
//! Asserted after every crash:
//! - the open succeeds (a torn tail is never an error);
//! - the store holds exactly the last acknowledged state, or that state plus the whole batch that
//!   was in flight: no acknowledged batch lost, no batch partially visible;
//! - the recovered store accepts a new batch, and a further clean reopen returns it.
//!
//! Scale: `RUSTEGON_CRASH_SEEDS` (default 4) seeds per crash point and mode, workloads from
//! `RUSTEGON_CRASH_WORKLOADS` (default 2).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::{
    Model, Op, Step, assert_matches, batch, diff, open, open_encrypted, payload, workload,
};
use rustegon_raft::{LogStore, LogStoreError};
use rustegon_sim::{CrashMode, SimFileSystem};

/// Segment size: a rollover every few batches.
const SEGMENT_SIZE: u64 = 200;
/// Workload length in steps.
const STEPS: usize = 40;
/// Lower bound on crash points per workload: each batch costs at least an append and a sync.
/// Fewer means the workload silently shrank.
const MIN_CRASH_POINTS: u64 = 80;

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

/// Opens the store under test (plaintext or encrypted at rest).
type Opener = fn(&Arc<SimFileSystem>, u64) -> Result<LogStore, LogStoreError>;

fn run(
    open: Opener,
    fs: &Arc<SimFileSystem>,
    steps: &[Step],
    out: &mut Outcome,
) -> Result<(), LogStoreError> {
    let mut store = open(fs, SEGMENT_SIZE)?;
    for step in steps {
        match step {
            Step::Batch(ops) => {
                let next = out.acked.after(ops).expect("workload batches are valid");
                out.in_flight = Some(next);
                store.write(&batch(ops))?;
                out.acked = out.in_flight.take().unwrap();
            }
            Step::Reopen => {
                drop(store);
                store = open(fs, SEGMENT_SIZE)?;
                assert_matches(&store, &out.acked, "reopen without crash");
            }
        }
    }
    Ok(())
}

/// Checks recovery after a crash; panics with `ctx` on a violated property.
fn check_recovery(open: Opener, fs: &Arc<SimFileSystem>, out: &Outcome, ctx: &str) {
    let mut store: LogStore =
        open(fs, SEGMENT_SIZE).unwrap_or_else(|e| panic!("{ctx}: recovery failed: {e}"));
    // Exactly one of the two admissible states: the acknowledged one, or it plus the whole
    // in-flight batch.
    let model = match (diff(&store, &out.acked), &out.in_flight) {
        (None, _) => out.acked.clone(),
        (Some(_), Some(next)) if diff(&store, next).is_none() => next.clone(),
        (Some(d), next) => panic!(
            "{ctx}: recovered state is neither the acknowledged one ({d}) nor the in-flight one \
             ({:?})",
            next.as_ref().map(|n| diff(&store, n))
        ),
    };
    // The recovered store stays usable and durable.
    let group = 1;
    let index = model.group(group).last + 1;
    let term = model.group(group).last_term;
    let ops = [Op::Append {
        group,
        index,
        term,
        payload: payload(group, index, 99),
    }];
    let next = model.after(&ops).unwrap();
    store
        .write(&batch(&ops))
        .unwrap_or_else(|e| panic!("{ctx}: write after recovery failed: {e}"));
    drop(store);
    fs.crash(0, CrashMode::Clean);
    let store = open(fs, SEGMENT_SIZE).unwrap_or_else(|e| panic!("{ctx}: second reopen: {e}"));
    assert_matches(&store, &next, &format!("{ctx}, second reopen"));
}

/// Halts at every mutating operation of `workloads` workloads, crashes in every mode with
/// `seeds` seeds, and checks recovery.
fn crash_at_every_op(open: Opener, workloads: u64, seeds: u64) {
    for w in 0..workloads {
        let steps = workload(0x00C0_FFEE + w, STEPS);
        let total = {
            let fs = Arc::new(SimFileSystem::new());
            run(open, &fs, &steps, &mut Outcome::default()).unwrap();
            fs.op_count()
        };
        assert!(total >= MIN_CRASH_POINTS, "workload {w}: only {total} ops");
        for point in 0..total {
            for mode in CrashMode::ALL {
                for seed in 0..seeds {
                    let fs = Arc::new(SimFileSystem::new());
                    fs.halt_after_ops(point);
                    let mut out = Outcome::default();
                    let result = run(open, &fs, &steps, &mut out);
                    // The run may still succeed when the halt hit a best-effort segment deletion
                    // (or, encrypted, the forget of its DEK) after the last batch: those
                    // failures are logged, not returned.
                    assert!(fs.is_halted(), "point {point} did not halt ({result:?})");
                    fs.crash(seed, mode);
                    let ctx = format!("workload {w}, crash point {point}, {mode:?}, seed {seed}");
                    check_recovery(open, &fs, &out, &ctx);
                }
            }
        }
    }
}

#[test]
fn tc_txn_004_logstore_survives_crash_at_every_op() {
    crash_at_every_op(
        open,
        env("RUSTEGON_CRASH_WORKLOADS", 2),
        env("RUSTEGON_CRASH_SEEDS", 4),
    );
}

/// FR-EAR-001 / PD-057: the same crash sweep with the log encrypted at rest. Segment creation
/// also registers a DEK first (registry rewrite: temp file, sync, rename, directory sync) and
/// segment deletion forgets it, so each of those operations is a crash point too; every
/// acknowledged entry must still decrypt after any of them.
#[test]
fn tc_ear_001_encrypted_logstore_survives_crash_at_every_op() {
    crash_at_every_op(
        open_encrypted,
        env("RUSTEGON_CRASH_WORKLOADS", 1),
        env("RUSTEGON_CRASH_SEEDS", 2),
    );
}

#[test]
fn tc_txn_004_logstore_workload_completes_and_reopens_without_crash() {
    for open in [open as Opener, open_encrypted] {
        let steps = workload(0x00C0_FFEE, STEPS);
        let fs = Arc::new(SimFileSystem::new());
        let mut out = Outcome::default();
        run(open, &fs, &steps, &mut out).unwrap();
        fs.crash(0, CrashMode::Clean);
        check_recovery(open, &fs, &out, "no crash point");
    }
}
