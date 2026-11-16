// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MVCC key encoding, readers and writers, write intents, garbage collection and hybrid logical
//! clocks (transaction-management.md §2, §3; ADR-006).
//!
//! Layering: logical keys are opaque bytes here (the document layer builds them per
//! data-model.md §3.2); this crate appends the MVCC suffix ([`key`]), encodes versions, intents
//! and transaction records ([`value`]), and reads ([`read`]) and writes ([`mod@write`]) them over the
//! [`rustegon_storage::LsmEngine`]. [`gc`] holds the GC threshold, the compaction filter and the
//! explicit GC batch; [`hlc`] the hybrid logical clock.
//!
//! Concurrency contract: MVCC operations are evaluated under the latches of the keys they touch
//! (the replica's concurrency manager, M3) — two writers never evaluate against the same key at
//! once. The crate itself holds no locks except the HLC state and the GC threshold.

pub mod error;
pub mod gc;
pub mod hlc;
pub mod key;
pub mod read;
pub mod replica;
pub mod value;
pub mod write;

pub use error::{MvccError, Result};
pub use gc::{GcPin, GcThreshold, MvccGcFilter, gc_batch, gc_batch_limited, mvcc_engine_options};
pub use hlc::{Hlc, HlcBoundStore, Timestamp};
pub use key::{MvccKey, MvccPrefixExtractor, meta_key, txn_record_key, version_key};
pub use read::{MvccReader, ReadOptions, TxnContext};
pub use replica::{RangeAppliedState, Replica, ReplicaCommand, ReplicaError};
pub use value::{
    Intent, IntentValue, SeqRange, TxnId, TxnMeta, TxnRecord, TxnStatus, VersionValue,
};
pub use write::{IntentResolution, MvccWriter, ResolveOutcome};
