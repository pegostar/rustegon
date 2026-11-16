// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Multi-Raft driver over raft-rs: log store, snapshots and quiescence.
//!
//! M2 provides the per-node segmented Raft [`logstore`] (ADR-009, replication.md §2), which backs
//! a single-voter local replica; the Multi-Raft driver over raft-rs arrives in M5.

pub mod logstore;
pub mod settings;

pub use logstore::{
    Entry, HardState, LogBatch, LogStore, LogStoreError, LogStoreOptions, RecoveryInfo,
    SealedSegment, SegmentEntry, SegmentKey, SegmentReader, read_segment,
};
pub use settings::RaftSettings;
