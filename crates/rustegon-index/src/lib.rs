// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Indexes: secondary, unique, TTL, full-text, geospatial, vector, map-reduce, advisor and builder.
//!
//! M3 lane C scope (F05; FR-IDX-001/002, indexing.md §3–§4):
//! - [`keygen`]: index key generation from a document and an index descriptor (compound,
//!   unique, sparse, partial via a caller-supplied [`PartialFilter`], multikey, wildcard,
//!   truncation of long keys);
//! - [`entry`]: the persisted entry key/value layout (index entry format 1);
//! - [`maintain`](mod@maintain): write-path maintenance through a `rustegon-txn` transaction, with unique
//!   enforcement (`RGN-1005`) by transactional read-modify-write of the unique key;
//! - [`scan`]: a minimal index range read used by consistency tests until the query executor
//!   exists.
//!
//! M3 lane H (FR-IDX-003, TC-IDX-002/003):
//! - [`build`]: the online, resumable, throttled build job (`DeleteOnly → WriteOnly →
//!   Backfilling → Validating → Public`, failure/cancel → `Dropping` + cleanup), with its
//!   persisted job record (index build record format 1).
//!
//! Index descriptors and their DDL live in `rustegon-catalog` (`index` module). The planner and
//! the other index kinds come in later lanes.

pub mod build;
pub mod entry;
pub mod keygen;
pub mod maintain;
pub mod scan;

pub use crate::{
    build::{BuildConfig, BuildProgress, BuildStep, IndexBuild},
    entry::EntryValue,
    keygen::{DocEntries, NoPartialFilter, PartialFilter, index_entries, key_directions},
    maintain::{IndexChanges, IndexError, apply_changes, maintain, plan_changes},
    scan::{
        IndexHit, IndexPage, document_key_for_element, index_span, scan_index, scan_index_page,
    },
};
