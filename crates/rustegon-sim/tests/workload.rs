// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-TXN-001 (FR-TXN-001/002), single-range part: Elle rw-register histories of the M2
//! coordinator, checked at the strongest model of each isolation level, without and with seeded
//! faults (crash points, power cuts, `EIO`, restarts, pauses, timeouts).
//!
//! Scale: `RUSTEGON_SIM_SEEDS` seeds per test (default 10), starting at `RUSTEGON_SIM_SEED`
//! (default 1). A failure names the seed and the `cargo run -p rustegon-sim` command that
//! reproduces it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustegon_sim::workload::{RegisterConfig, RunStats, run_rw_register};
use rustegon_txn::Isolation;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| {
            v.strip_prefix("0x")
                .map_or_else(|| v.parse().ok(), |h| u64::from_str_radix(h, 16).ok())
        })
        .unwrap_or(default)
}

/// Runs the configured seeds; panics with the reproduction command on the first failure.
fn sweep(isolation: Isolation, faults: bool) -> RunStats {
    let start = env("RUSTEGON_SIM_SEED", 1);
    let seeds = env("RUSTEGON_SIM_SEEDS", 10);
    let mut total = RunStats::default();
    for seed in start..start + seeds {
        let config = RegisterConfig::new(seed, isolation, faults);
        match run_rw_register(&config) {
            Ok(report) => {
                assert!(
                    report.stats.committed > 0,
                    "seed {seed:#x}: nothing committed"
                );
                total.add(&report.stats);
            }
            Err(failure) => panic!("{failure}"),
        }
    }
    total
}

#[test]
fn tc_txn_001_rw_register_serializable() {
    let s = sweep(Isolation::Serializable, false);
    assert_eq!(s.crashes, 0);
    assert!(s.conflict_restarts > 0, "no contention: {s:?}");
}

#[test]
fn tc_txn_001_rw_register_snapshot() {
    let s = sweep(Isolation::Snapshot, false);
    assert!(s.conflict_restarts > 0, "no contention: {s:?}");
}

#[test]
fn tc_txn_001_rw_register_read_committed() {
    let s = sweep(Isolation::ReadCommitted, false);
    assert!(s.committed > 0);
}

/// The fault mix must actually fire across the default seeds, or the test proves nothing.
fn assert_faults_exercised(s: &RunStats) {
    assert!(s.crashes > 0, "no power cut: {s:?}");
    assert!(s.process_restarts > 0, "no restart: {s:?}");
    assert!(s.crash_points + s.io_faults > 0, "no armed fault: {s:?}");
    // PD-121: interrupted writers were found by their persisted record and aborted.
    assert!(
        s.orphans_aborted > 0,
        "no orphan aborted at a reopen: {s:?}"
    );
}

#[test]
fn tc_txn_001_rw_register_faults_serializable() {
    assert_faults_exercised(&sweep(Isolation::Serializable, true));
}

#[test]
fn tc_txn_001_rw_register_faults_snapshot() {
    assert_faults_exercised(&sweep(Isolation::Snapshot, true));
}

#[test]
fn tc_txn_001_rw_register_faults_read_committed() {
    assert_faults_exercised(&sweep(Isolation::ReadCommitted, true));
}

/// Regression (NFR-REL-003): after an `EIO` on the Raft log's sync, a process restart followed
/// later by a power cut made the log store unopenable (`RGN-5002`, torn record in a segment
/// that is not the last one) until `LogStore::open` synced the recovered segments.
#[test]
fn tc_txn_004_logstore_unsynced_tail_after_eio_restart() {
    let mut config = RegisterConfig::new(0xa, Isolation::Serializable, true);
    config.io_restart = true;
    if let Err(failure) = run_rw_register(&config) {
        panic!("{failure}");
    }
}

/// Reproducibility (ADR-029): the same seed yields the same history and the same counters.
#[test]
fn tc_txn_001_rw_register_seed_is_reproducible() {
    for (seed, isolation) in [
        (11, Isolation::Serializable),
        (12, Isolation::Snapshot),
        (13, Isolation::ReadCommitted),
    ] {
        let config = RegisterConfig::new(seed, isolation, true);
        let a = run_rw_register(&config).unwrap_or_else(|f| panic!("{f}"));
        let b = run_rw_register(&config).unwrap_or_else(|f| panic!("{f}"));
        assert_eq!(a.stats, b.stats, "seed {seed}: counters differ");
        assert_eq!(a.history, b.history, "seed {seed}: histories differ");
    }
}

/// Sensitivity: the workload's histories are strong enough for the checker to see the anomalies
/// the weaker levels permit (TC-TXN-003 flavour): some SNAPSHOT history violates SERIALIZABLE
/// (write skew) and some READ COMMITTED history violates SNAPSHOT. Searches seeds in order and
/// stops at the first hit, so it stays fast while the hit seed is small.
#[test]
fn tc_txn_001_rw_register_weaker_levels_show_their_anomalies() {
    use rustegon_sim::checker::{self, AnomalyKind, CheckOptions, ConsistencyModel};
    for (isolation, stronger, expected) in [
        (
            Isolation::Snapshot,
            ConsistencyModel::Serializable,
            AnomalyKind::G2Item,
        ),
        (
            Isolation::ReadCommitted,
            ConsistencyModel::Snapshot,
            AnomalyKind::GSingle,
        ),
    ] {
        let hit = (1..=200).find(|&seed| {
            let report = run_rw_register(&RegisterConfig::new(seed, isolation, false))
                .unwrap_or_else(|f| panic!("{f}"));
            let stricter = checker::check(&report.history, &CheckOptions::new(stronger)).unwrap();
            stricter.forbidden_kinds().contains(&expected)
        });
        assert!(
            hit.is_some(),
            "no {isolation:?} history shows {expected:?} under {stronger:?}"
        );
        eprintln!("{isolation:?}: {expected:?} under {stronger:?} at seed {hit:?}");
    }
}
