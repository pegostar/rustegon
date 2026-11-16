// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Simulation workloads (ADR-029, testing-strategy.md §3) driving the M2 single-range
//! transaction coordinator (`rustegon-txn`) on the Raft-less `LocalReplica` of
//! `rustegon-cluster`, on the simulated file system.
//!
//! - [`register`]: Elle rw-register (TC-TXN-001; FR-TXN-001/002), with or without seeded
//!   faults (crash points, power cuts in every [`crate::CrashMode`], `EIO`, process restarts,
//!   client pauses, transaction timeouts). The history is verified by [`crate::checker`] and
//!   durability/atomicity are checked after every reopen.
//! - [`index_build`]: an online index build (FR-IDX-003, TC-IDX-002/003) interleaved with
//!   writes, cancellations and clean restarts on the embedded API; the final index is checked
//!   against the documents.
//!
//! # Determinism
//! A run is a pure function of its seed: all clients are driven from **one OS thread**, by a
//! seeded scheduler that interleaves their operations one at a time; time is the virtual
//! [`clock::SimClock`]; random choices (including the coordinator's transaction ids) come from
//! seeded [`rng::SimRng`] streams; background maintenance (flush, compaction, log purge) runs at
//! fixed steps instead of on a thread; and faults come from the same seed. The coordinator's
//! blocking waits are the one thing a single thread cannot interleave, so the scheduler only
//! runs an operation that will not wait for another client (see `register::Driver`), except
//! when every client is blocked, where the stalling clock bounds the wait. A failure prints
//! the seed and the command that reproduces it.
//!
//! Not yet covered (later milestones): Raft, network nemeses (partitions, clock skew) and
//! multi-range transactions arrive with M3/M6 and the multi-node simulator; list-append on the
//! coordinator is exercised multi-threaded in `rustegon-txn/tests/concurrency.rs`.

pub mod clock;
pub mod index_build;
pub mod register;
pub mod rng;
mod store;

pub use index_build::{IndexBuildConfig, IndexBuildFailure, IndexBuildReport, run_index_build};
pub use register::{
    Failure, FailureKind, RegisterConfig, RunReport, RunStats, models, run_rw_register,
};
use rustegon_txn::Isolation;

/// Every isolation level, strongest first.
pub const ISOLATIONS: [Isolation; 3] = [
    Isolation::Serializable,
    Isolation::Snapshot,
    Isolation::ReadCommitted,
];

/// The CLI name of an isolation level.
#[must_use]
pub fn isolation_name(isolation: Isolation) -> &'static str {
    match isolation {
        Isolation::Serializable => "serializable",
        Isolation::Snapshot => "snapshot",
        Isolation::ReadCommitted => "read-committed",
    }
}

/// Parses a CLI isolation name (see [`isolation_name`]).
#[must_use]
pub fn parse_isolation(name: &str) -> Option<Isolation> {
    ISOLATIONS.into_iter().find(|&i| isolation_name(i) == name)
}
