// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transaction coordinator: single-range ACID transactions (M2; transaction-management.md,
//! specifications/transactions.md; FR-TXN-001/002/007/008). Parallel commit across ranges is M6;
//! the coordinator is shaped so that it can grow into it (per-transaction record at the anchor
//! key, epochs, timestamp pushes, the same conflict rules), but a [`TxnCoordinator`] serves one
//! [`rustegon_mvcc::Replica`] and commits in one phase.
//!
//! # Design
//! - **[`TxnCoordinator`]** owns the range's in-memory concurrency state: the range latch, the
//!   [`ts_cache::TsCache`], the registry of live transactions and the per-key wait queues
//!   ([`lock_table`]). It hands out [`Txn`] handles, offers the single-key fast path and a retry
//!   helper ([`TxnCoordinator::run`]).
//! - **[`Txn`]** reads at its read timestamp (READ COMMITTED: per statement), writes intents
//!   with increasing sequence numbers (the first one with the `PENDING` record at the anchor
//!   key), supports savepoints via `ignored_seq_ranges`, restarts in a new epoch, and commits in
//!   one command that resolves every intent and deletes the record (1PC, `txn/commit.rs`).
//! - **Isolation** (§4.1): SERIALIZABLE refreshes its reads at commit when its timestamp moved;
//!   SNAPSHOT refuses writes to keys committed after its snapshot (first-committer-wins);
//!   READ COMMITTED re-evaluates read-modify-write statements on the latest committed value
//!   ([`Txn::update`]).
//! - **Conflicts** (§5): waiters queue per key, push expired or lower-priority holders, and run
//!   a local wait-for cycle check every wait slice (victim: lowest priority, then youngest,
//!   `RGN-2005`). Intents of transactions whose coordinator is gone are resolved through their
//!   persisted record (`conflict.rs`).
//! - **Limits** (§9, §11): maximum duration (`RGN-2003`), write-set keys and bytes
//!   (`RGN-2004`), idle heartbeat abort (`RGN-2002`, `timeout_pushed`).
//!
//! # Latching
//! The range latch is a reader-writer lock: reads (with their timestamp-cache registration) take
//! it shared; evaluating and proposing a write batch takes it exclusively, so the state a batch
//! is evaluated against cannot change before it applies (the `rustegon-mvcc` concurrency
//! contract). This serialises writes of the range — including their `fsync` — which is the M2
//! simplification; per-key latches of the M3 concurrency manager replace it without changing
//! the rules above.
//!
//! # Lock order
//! 1. range latch (never held while waiting for another transaction);
//! 2. one transaction's state mutex (`registry::TxnShared`), never two at once;
//! 3. leaves: the registry map, the timestamp cache, the wait queues.
//!
//! The replica's own locks are below all of them (`propose` is called under the latch only).
//! Condition-variable waits hold only the mutex they wait on.
//!
//! # Time
//! Timestamps come from the HLC; durations (liveness, maximum duration) from the injected
//! [`rustegon_sim_api::Clock`]'s monotonic time, so tests drive them deterministically.

pub mod config;
mod conflict;
mod coordinator;
pub mod error;
pub mod lock_table;
pub mod read_set;
pub mod registry;
pub mod stats;
pub mod ts_cache;
mod txn;

pub use config::{AccessMode, Isolation, Priority, TxnConfig, TxnOptions};
pub use conflict::OrphanStatus;
pub use coordinator::{CommitInfo, TxnCoordinator};
pub use error::{AbortReason, Result, TxnError};
pub use stats::{RestartReason, TxnStatsSnapshot};
pub use txn::Txn;
