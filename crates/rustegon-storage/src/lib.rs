// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The Rustegon LSM storage engine: memtable, `SSTables`, compaction, block cache, codecs, encryption, ingestion and checkpoints (ADR-003; the only storage engine).

pub mod admission;
pub mod cache;
pub mod checkpoint;
mod coding;
pub mod compaction;
pub mod encryption;
pub mod engine;
pub mod error;
pub mod flush;
pub mod ingest;
pub mod iter;
pub mod key;
pub mod memtable;
pub mod merge;
pub mod metrics;
pub mod range_del;
pub mod read;
pub mod settings;
pub mod sst;
pub mod table_cache;
pub mod version;

pub use admission::{
    AdmissionOptions, StallReason, WriteCondition, WriteConditionCell, pending_compaction_bytes,
    write_condition,
};
pub use cache::{BlockCache, CacheStats};
pub use checkpoint::{
    CHECKPOINT_KEYS_DIR, CheckpointInfo, CheckpointSource, checkpoint_keys_dir, create_checkpoint,
};
pub use engine::{BatchOp, EngineOptions, FlushBarrier, LsmEngine, Snapshot, WriteBatch};
pub use error::{Result, StorageError};
pub use flush::flush_memtable;
pub use key::{InternalKey, MAX_SEQNO, ParsedKey, SeqNo, ValueKind};
pub use memtable::{Memtable, MemtableEntry, MemtableIterator};
pub use read::{DbIterator, ReadView};
pub use table_cache::TableCache;
