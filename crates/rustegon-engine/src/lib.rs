// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Node-local engine facade (PD-044): [`EmbeddedDb`] runs document writes, DDL, RGQL
//! statements, cursors, index builds and statistics over the storage engine, the local
//! replica, the transaction coordinator, the catalog, the index layer and the query engine.
//!
//! It is a production crate so that the server (`rustegon-server`, M4) can host it; the
//! simulation harness (`rustegon-sim`) opens the same engine over its simulated file system,
//! clock and RNG. All I/O, time and randomness enter through the `rustegon-sim-api` traits
//! passed to [`EmbeddedDb::open`] (coding-standards.md), so production passes the real
//! implementations and simulation the deterministic ones.

pub mod embedded;

pub use embedded::{
    AnalyzeOutcome, CancelHandle, Cursor, CursorOptions, EmbeddedDb, IndexStats, OwnedCursor,
    QueryInput, QuerySession, SharedPartialFilter, SystemTxnHandle, Transaction, TransactionStatus,
    format_txn_id, parse_txn_id,
};
pub use rustegon_txn::{
    AccessMode, CommitInfo, Isolation, OrphanStatus, Priority, TxnConfig, TxnOptions,
};
