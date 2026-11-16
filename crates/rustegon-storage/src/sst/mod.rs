// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Sorted string tables, format `rsst` v1 (storage-engine.md §4).
//!
//! File layout:
//! ```text
//! [data block]* [filter block] [index partition]* [top-level index] [properties] [metaindex] [footer]
//! ```
//! - Data blocks hold `internal key → value` entries in internal-key order (see [`crate::key`]).
//! - The index is two-level: index partitions map the *last key* of each data block to its
//!   handle; the top-level index maps the last key of each partition to the partition handle.
//!   Only the top level is held in memory per open file, which bounds memory for large files.
//! - The metaindex maps block names (bytewise order) to handles: `rustegon.filter.ribbon`
//!   (optional), `rustegon.index` (top level), `rustegon.properties`. A range-tombstone block is
//!   added by the range-tombstone task with its own name; readers ignore names they do not know.
//! - Every block carries the trailer described in [`format`]; the footer locates the metaindex.
//!
//! This format freezes at the end of M1 (development-phases.md §3); later changes bump
//! [`FORMAT_VERSION`] and keep reader support for v1 (implementation-rules.md §6).

mod block;
mod compression;
mod filter;
mod format;
mod properties;
mod reader;
mod writer;

use std::{fmt, sync::Arc};

pub(crate) use block::Block;
pub use compression::{
    CompressionPolicy, DEFAULT_BOTTOMMOST_ZSTD_LEVEL, DEFAULT_ZSTD_LEVEL, MAX_ZSTD_LEVEL,
    MIN_ZSTD_LEVEL,
};
pub use filter::{DEFAULT_RESULT_BITS, FilterPolicy};
pub use format::{BLOCK_TRAILER_LEN, BlockHandle, Compression, FOOTER_LEN, FORMAT_VERSION, MAGIC};
pub use properties::Properties;
pub use reader::{SstEntry, SstIterator, SstReader, SstReaderOptions};
pub use writer::{SstInfo, SstWriter, SstWriterOptions};

/// Metaindex name of the Ribbon filter block.
const META_FILTER: &[u8] = b"rustegon.filter.ribbon";
/// Metaindex name of the top-level index block.
const META_INDEX: &[u8] = b"rustegon.index";
/// Metaindex name of the properties block.
const META_PROPERTIES: &[u8] = b"rustegon.properties";
/// Metaindex name of the range-tombstone block (storage-engine.md §3, §4).
const META_RANGE_DEL: &[u8] = b"rustegon.range_del";

/// Default target size of a data block before compression: 16 KiB (storage-engine.md §4).
pub const DEFAULT_BLOCK_SIZE: usize = 16 << 10;
/// Restart interval of data blocks (storage-engine.md §4).
pub const DEFAULT_RESTART_INTERVAL: usize = 16;
/// Target size of one index partition: 4 KiB keeps a partition to a single page read while a
/// 256 MiB file still needs only a few hundred top-level entries.
pub const DEFAULT_INDEX_PARTITION_SIZE: usize = 4 << 10;

/// Maps a user key to the part the filter is built on. The MVCC layer installs an extractor that
/// strips the timestamp suffix so that point lookups of any version hit the filter
/// (storage-engine.md §4). The name is persisted in the SST properties; a reader whose extractor
/// has a different name ignores the filter instead of returning false negatives.
pub trait PrefixExtractor: Send + Sync + fmt::Debug {
    /// Stable name persisted in SST properties.
    fn name(&self) -> &str;
    /// The filter key of `user_key`.
    fn prefix<'a>(&self, user_key: &'a [u8]) -> &'a [u8];
}

/// Uses the whole user key as filter key.
#[derive(Debug, Clone, Copy, Default)]
pub struct FullKeyExtractor;

impl PrefixExtractor for FullKeyExtractor {
    fn name(&self) -> &'static str {
        "rustegon.full_key"
    }

    fn prefix<'a>(&self, user_key: &'a [u8]) -> &'a [u8] {
        user_key
    }
}

/// Shared default extractor.
fn default_extractor() -> Arc<dyn PrefixExtractor> {
    Arc::new(FullKeyExtractor)
}
