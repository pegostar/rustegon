// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! SST writer: streams sorted entries into an `rsst` v1 file (layout in [`super`]).
//!
//! Memory: one data block, the index partitions and the filter hashes (8 bytes per distinct
//! prefix) are buffered; everything else is streamed. Index partitions are buffered because the
//! format places them after the filter block, which can only be built once all keys are known;
//! for a 256 MiB file they amount to a few hundred KiB.
//!
//! Durability: [`SstWriter::finish`] syncs the file before returning, the first step of the
//! fsync discipline in storage-engine.md §9 (the MANIFEST record follows).
//!
//! Encryption (§7): when [`SstWriterOptions::encryption`] is set, writers are created with
//! [`SstWriter::create`], which registers a fresh DEK for the file number durably *before* the
//! first byte is written, and every block (data and metadata) is sealed after compression (see
//! `format.rs`). The footer stays plaintext: it holds only offsets, the format version and the
//! magic. [`SstWriter::new`] refuses to write when encryption is configured, so a caller that
//! forgets the file number can never produce a plaintext file in an encrypted store.

use std::{cmp::Ordering, sync::Arc};

use rustegon_sim_api::File;

use super::{
    DEFAULT_BLOCK_SIZE, DEFAULT_INDEX_PARTITION_SIZE, DEFAULT_RESTART_INTERVAL, META_FILTER,
    META_INDEX, META_PROPERTIES, META_RANGE_DEL, PrefixExtractor,
    block::BlockBuilder,
    compression::CompressionPolicy,
    default_extractor,
    filter::{FilterPolicy, RibbonBuilder, filter_hash},
    format::{BlockHandle, Compression, FORMAT_VERSION, Footer, frame_block},
    properties::Properties,
};
use crate::{
    encryption::{FileCipher, KeyManager},
    error::{Result, StorageError},
    key::{InternalKey, MAX_SEQNO, ParsedKey, ValueKind, compare_internal},
    range_del::RangeTombstone,
};

/// Writer configuration.
#[derive(Debug, Clone)]
pub struct SstWriterOptions {
    /// Target uncompressed data block size in bytes.
    pub block_size: usize,
    /// Entries between restart points in data blocks.
    pub restart_interval: usize,
    /// Target size of an index partition in bytes.
    pub index_partition_size: usize,
    /// Filter configuration.
    pub filter: FilterPolicy,
    /// Maps user keys to filter keys.
    pub prefix_extractor: Arc<dyn PrefixExtractor>,
    /// Codec tried for each data block (storage-engine.md §6); see
    /// [`CompressionPolicy::for_level`] for the per-level defaults.
    pub compression: CompressionPolicy,
    /// The store's encryption context (storage-engine.md §7); `None` writes plaintext files,
    /// byte-identical to a build without encryption support.
    pub encryption: Option<Arc<KeyManager>>,
}

impl Default for SstWriterOptions {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            restart_interval: DEFAULT_RESTART_INTERVAL,
            index_partition_size: DEFAULT_INDEX_PARTITION_SIZE,
            filter: FilterPolicy::default(),
            prefix_extractor: default_extractor(),
            compression: CompressionPolicy::default(),
            encryption: None,
        }
    }
}

/// Summary of a finished SST, recorded in the MANIFEST.
#[derive(Debug, Clone)]
pub struct SstInfo {
    /// Total file size in bytes.
    pub file_size: u64,
    /// Smallest internal key (`None` for an empty file).
    pub smallest: Option<InternalKey>,
    /// Largest internal key (`None` for an empty file).
    pub largest: Option<InternalKey>,
    /// The properties written into the file.
    pub properties: Properties,
}

/// Streams entries into a new SST. Entries must be added in strictly increasing internal-key
/// order. After any error the writer refuses further use; the caller deletes the partial file.
pub struct SstWriter {
    file: Box<dyn File>,
    options: SstWriterOptions,
    offset: u64,
    scratch: Vec<u8>,
    /// Data blocks in a row that the codec could not shrink below the keep threshold
    /// (see [`try_compress`]).
    incompressible_streak: u64,
    data_block: BlockBuilder,
    index: PartitionedIndexBuilder,
    filter: Option<RibbonBuilder>,
    properties: Properties,
    smallest: Option<InternalKey>,
    last_key: Vec<u8>,
    range_tombstones: Vec<RangeTombstone>,
    failed: bool,
    /// The file's DEK context; `None` for a plaintext file.
    cipher: Option<Arc<FileCipher>>,
    /// Set by [`SstWriter::new`] when encryption is configured (see module docs).
    needs_file_number: bool,
}

impl SstWriter {
    /// Starts writing a plaintext SST into `file`, which must be empty and opened for
    /// appending. With [`SstWriterOptions::encryption`] set the writer refuses every call
    /// (module docs); use [`SstWriter::create`].
    #[must_use]
    pub fn new(file: Box<dyn File>, options: SstWriterOptions) -> Self {
        let needs_file_number = options.encryption.is_some();
        let mut writer = Self::with_cipher(file, options, None);
        writer.needs_file_number = needs_file_number;
        writer.failed = needs_file_number;
        writer
    }

    /// Starts writing SST `file_number` into `file` (empty, opened for appending). With
    /// encryption configured, a fresh DEK is generated and made durable in the DEK registry
    /// first (storage-engine.md §7, §9).
    ///
    /// # Errors
    /// Registry errors from [`KeyManager::new_file_cipher`] (I/O, a number that already has a
    /// DEK, [`StorageError::KeyUnavailable`]).
    pub fn create(
        file: Box<dyn File>,
        file_number: u64,
        options: SstWriterOptions,
    ) -> Result<Self> {
        let cipher = match &options.encryption {
            Some(keys) => Some(keys.new_file_cipher(file_number)?),
            None => None,
        };
        Ok(Self::with_cipher(file, options, cipher))
    }

    fn with_cipher(
        file: Box<dyn File>,
        options: SstWriterOptions,
        cipher: Option<Arc<FileCipher>>,
    ) -> Self {
        let filter = match options.filter {
            FilterPolicy::Disabled => None,
            FilterPolicy::Ribbon { result_bits } => Some(RibbonBuilder::new(result_bits)),
        };
        Self {
            file,
            data_block: BlockBuilder::new(options.restart_interval),
            index: PartitionedIndexBuilder::new(options.index_partition_size),
            options,
            offset: 0,
            scratch: Vec::new(),
            incompressible_streak: 0,
            filter,
            properties: Properties::default(),
            smallest: None,
            last_key: Vec::new(),
            range_tombstones: Vec::new(),
            failed: false,
            cipher,
            needs_file_number: false,
        }
    }

    /// Number of entries added so far.
    #[must_use]
    pub fn entries(&self) -> u64 {
        self.properties.entries
    }

    /// Bytes written to the file so far plus the pending data block (drives output file
    /// splitting in compaction).
    #[must_use]
    pub fn estimated_file_size(&self) -> u64 {
        self.offset + self.data_block.estimated_size() as u64
    }

    /// Caller-supplied property stored under `user.<name>` (e.g. MVCC timestamp bounds).
    pub fn set_user_property(&mut self, name: &str, value: Vec<u8>) {
        self.properties.user.insert(name.to_owned(), value);
    }

    /// Adds a range tombstone (any order relative to entries and other tombstones). It is
    /// stored in the range-del block, and the file's key bounds and seqno range cover it.
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] for an empty range (`start >= end`), a seqno above
    /// 56 bits, or a writer that failed before.
    pub fn add_range_tombstone(&mut self, tombstone: RangeTombstone) -> Result<()> {
        self.check_usable()?;
        if tombstone.start >= tombstone.end || tombstone.seqno > MAX_SEQNO {
            return Err(StorageError::InvalidArgument(
                "range tombstone needs start < end and a 56-bit seqno".into(),
            ));
        }
        self.range_tombstones.push(tombstone);
        Ok(())
    }

    /// Adds an entry; `key` is an encoded internal key.
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] for a malformed key, a key not greater than the
    /// previous one, or a writer that failed before; I/O errors from flushing a block.
    pub fn add(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.check_usable()?;
        let parsed = ParsedKey::parse(key)
            .map_err(|e| StorageError::InvalidArgument(format!("invalid internal key: {e}")))?;
        if parsed.kind == ValueKind::RangeDelete {
            return Err(StorageError::InvalidArgument(
                "range tombstones go through add_range_tombstone".into(),
            ));
        }
        if self.properties.entries > 0 && compare_internal(&self.last_key, key) != Ordering::Less {
            return Err(StorageError::InvalidArgument(
                "SST keys must be added in strictly increasing order".into(),
            ));
        }
        if !self.data_block.is_empty()
            && self.data_block.estimated_size() >= self.options.block_size
        {
            self.guard(Self::flush_data_block)?;
        }
        if let Some(filter) = &mut self.filter {
            filter.add_hash(filter_hash(
                self.options.prefix_extractor.prefix(parsed.user_key),
            ));
        }
        self.guard(|w| w.data_block.add(key, value))?;
        self.record_stats(&parsed, key, value);
        Ok(())
    }

    fn record_stats(&mut self, parsed: &ParsedKey<'_>, key: &[u8], value: &[u8]) {
        let p = &mut self.properties;
        if p.entries == 0 {
            p.min_seqno = parsed.seqno;
            p.max_seqno = parsed.seqno;
            self.smallest = Some(InternalKey::new(parsed.user_key, parsed.seqno, parsed.kind));
        }
        p.entries += 1;
        p.min_seqno = p.min_seqno.min(parsed.seqno);
        p.max_seqno = p.max_seqno.max(parsed.seqno);
        p.raw_key_bytes += key.len() as u64;
        p.raw_value_bytes += value.len() as u64;
        match parsed.kind {
            ValueKind::Delete | ValueKind::SingleDelete => p.deletions += 1,
            ValueKind::Merge => p.merges += 1,
            // `add` rejects RangeDelete point entries.
            ValueKind::Put | ValueKind::RangeDelete => {}
        }
        self.last_key.clear();
        self.last_key.extend_from_slice(key);
    }

    /// Writes the remaining blocks and the footer, then syncs the file.
    ///
    /// # Errors
    /// I/O errors (the file is then incomplete and must be deleted) or a writer that failed
    /// before.
    pub fn finish(mut self) -> Result<SstInfo> {
        self.check_usable()?;
        if !self.data_block.is_empty() {
            self.flush_data_block()?;
        }
        self.properties.data_bytes = self.offset;

        let mut meta: Vec<(&[u8], BlockHandle)> = Vec::with_capacity(3);
        if let Some(contents) = self.filter.as_ref().and_then(RibbonBuilder::finish) {
            let handle = self.write_block(&contents)?;
            self.properties.filter_bytes = self.offset - handle.offset;
            self.options
                .prefix_extractor
                .name()
                .clone_into(&mut self.properties.filter_prefix_extractor);
            meta.push((META_FILTER, handle));
        }

        let index_start = self.offset;
        let partitions = self.index.finish();
        self.properties.index_partitions = partitions.len() as u64;
        let mut top = BlockBuilder::new(1);
        let mut handle_buf = Vec::new();
        for (last_key, contents) in partitions {
            let handle = self.write_block(&contents)?;
            handle_buf.clear();
            handle.encode_to(&mut handle_buf);
            top.add(&last_key, &handle_buf)?;
        }
        let top_handle = self.write_block(&top.finish())?;
        self.properties.index_bytes = self.offset - index_start;
        meta.push((META_INDEX, top_handle));

        // Range-del block before the properties (storage-engine.md §4 layout): entries
        // `InternalKey(start, seqno, RangeDelete) -> end` in internal-key order.
        self.range_tombstones
            .sort_by(|a, b| a.start.cmp(&b.start).then(b.seqno.cmp(&a.seqno)));
        if !self.range_tombstones.is_empty() {
            let mut block = BlockBuilder::new(1);
            for t in &self.range_tombstones {
                let key = InternalKey::new(&t.start, t.seqno, ValueKind::RangeDelete);
                block.add(key.as_bytes(), &t.end)?;
            }
            let handle = self.write_block(&block.finish())?;
            meta.push((META_RANGE_DEL, handle));
        }
        self.fold_tombstones_into_properties();

        let props_handle = self.write_block(&self.properties.encode()?)?;
        meta.push((META_PROPERTIES, props_handle));

        // Metaindex names must be in bytewise order.
        meta.sort_by(|a, b| a.0.cmp(b.0));
        let mut metaindex = BlockBuilder::new(1);
        for (name, handle) in meta {
            handle_buf.clear();
            handle.encode_to(&mut handle_buf);
            metaindex.add(name, &handle_buf)?;
        }
        let metaindex_handle = self.write_block(&metaindex.finish())?;
        let footer = Footer {
            metaindex: metaindex_handle,
            format_version: FORMAT_VERSION,
        }
        .encode();
        self.file.append(&footer)?;
        self.offset += footer.len() as u64;
        // storage-engine.md §9: the SST is durable before any MANIFEST record references it.
        self.file.sync_data()?;

        let largest = (self.properties.entries > 0)
            .then(|| InternalKey::decode(&self.last_key))
            .transpose()
            .map_err(|e| StorageError::corruption(format!("last key: {e}")))?;
        let (smallest, largest) = self.bounds_with_tombstones(self.smallest.clone(), largest);
        Ok(SstInfo {
            file_size: self.offset,
            smallest,
            largest,
            properties: self.properties,
        })
    }

    /// Seqno range covers the tombstones too: L0 ordering and the flush seqno check use it.
    fn fold_tombstones_into_properties(&mut self) {
        let seqnos = self.range_tombstones.iter().map(|t| t.seqno);
        let (Some(min), Some(max)) = (seqnos.clone().min(), seqnos.max()) else {
            return;
        };
        let p = &mut self.properties;
        if p.entries == 0 {
            (p.min_seqno, p.max_seqno) = (min, max);
        } else {
            p.min_seqno = p.min_seqno.min(min);
            p.max_seqno = p.max_seqno.max(max);
        }
    }

    /// File bounds that also cover every tombstone: `(start, MAX_SEQNO, RangeDelete)` sorts
    /// before every version of `start`; the exclusive `end` is represented by
    /// `(end, 0, Delete)`, the last internal key of user key `end` — an over-approximation by
    /// one user key, harmless for overlap checks (compaction never cuts an output so that the
    /// next file starts at a tombstone's end, `compaction/job.rs`).
    fn bounds_with_tombstones(
        &self,
        mut smallest: Option<InternalKey>,
        mut largest: Option<InternalKey>,
    ) -> (Option<InternalKey>, Option<InternalKey>) {
        for t in &self.range_tombstones {
            let lo = InternalKey::new(&t.start, MAX_SEQNO, ValueKind::RangeDelete);
            let hi = InternalKey::new(&t.end, 0, ValueKind::Delete);
            if smallest.as_ref().is_none_or(|s| lo < *s) {
                smallest = Some(lo);
            }
            if largest.as_ref().is_none_or(|l| hi > *l) {
                largest = Some(hi);
            }
        }
        (smallest, largest)
    }

    fn check_usable(&self) -> Result<()> {
        if self.needs_file_number {
            return Err(StorageError::InvalidArgument(
                "encryption is configured: SSTs must be created with SstWriter::create, which \
                 registers the file's DEK"
                    .into(),
            ));
        }
        if self.failed {
            return Err(StorageError::InvalidArgument(
                "SST writer is unusable after an earlier error".into(),
            ));
        }
        Ok(())
    }

    /// Runs `op`, poisoning the writer if it fails (the file content is then unknown).
    fn guard(&mut self, op: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let result = op(self);
        self.failed |= result.is_err();
        result
    }

    fn flush_data_block(&mut self) -> Result<()> {
        let contents = self.data_block.finish();
        let configured = self.options.compression;
        let policy = if try_compress(self.incompressible_streak, self.properties.data_blocks) {
            configured
        } else {
            CompressionPolicy::None
        };
        let (handle, codec) = self.write_framed(&contents, policy)?;
        if policy != CompressionPolicy::None {
            self.incompressible_streak = if codec == Compression::None {
                self.incompressible_streak + 1
            } else {
                0
            };
        }
        self.properties.data_blocks += 1;
        self.properties.data_raw_bytes += contents.len() as u64;
        if codec != Compression::None {
            self.properties.data_compressed_blocks += 1;
        }
        // The index key is the block's last key: a seek for any key <= it lands in this block or
        // an earlier one, so the first index entry >= target names the right block.
        self.index.add(&self.last_key, handle)
    }

    /// Writes a metadata block. Only data blocks are compressed: index, filter, properties and
    /// metaindex blocks are read on open or kept hot, and the filter is incompressible anyway.
    fn write_block(&mut self, contents: &[u8]) -> Result<BlockHandle> {
        self.write_framed(contents, CompressionPolicy::None)
            .map(|(handle, _)| handle)
    }

    fn write_framed(
        &mut self,
        contents: &[u8],
        policy: CompressionPolicy,
    ) -> Result<(BlockHandle, Compression)> {
        self.scratch.clear();
        let framed = frame_block(
            &mut self.scratch,
            contents,
            policy,
            self.cipher.as_deref(),
            self.offset,
        );
        self.failed |= framed.is_err();
        let (size, codec) = framed?;
        let handle = BlockHandle {
            offset: self.offset,
            size,
        };
        let result = self.file.append(&self.scratch);
        self.failed |= result.is_err();
        result?;
        self.offset += self.scratch.len() as u64;
        Ok((handle, codec))
    }
}

/// Accumulates index entries into partitions of bounded size.
struct PartitionedIndexBuilder {
    partition: BlockBuilder,
    partition_size: usize,
    done: Vec<(Vec<u8>, Vec<u8>)>,
    handle_buf: Vec<u8>,
}

impl PartitionedIndexBuilder {
    fn new(partition_size: usize) -> Self {
        Self {
            // Restart interval 1: every index entry is reachable by binary search.
            partition: BlockBuilder::new(1),
            partition_size,
            done: Vec::new(),
            handle_buf: Vec::new(),
        }
    }

    fn add(&mut self, last_key: &[u8], handle: BlockHandle) -> Result<()> {
        if !self.partition.is_empty() && self.partition.estimated_size() >= self.partition_size {
            self.cut();
        }
        self.handle_buf.clear();
        handle.encode_to(&mut self.handle_buf);
        self.partition.add(last_key, &self.handle_buf)
    }

    fn cut(&mut self) {
        let last = self.partition.last_key().to_vec();
        self.done.push((last, self.partition.finish()));
    }

    /// Returns `(last key, encoded partition)` pairs in key order.
    fn finish(&mut self) -> Vec<(Vec<u8>, Vec<u8>)> {
        if !self.partition.is_empty() {
            self.cut();
        }
        std::mem::take(&mut self.done)
    }
}

/// Consecutive incompressible data blocks after which the writer stops trying every block.
const INCOMPRESSIBLE_SKIP_AFTER: u64 = 8;
/// While skipping, every this-many-th data block is still tried, so compressible data that
/// follows an incompressible stretch is picked up again within this many blocks.
const INCOMPRESSIBLE_PROBE_EVERY: u64 = 16;

/// Whether data block number `block` (0-based in the file) is offered to the codec, given the
/// current run of blocks the codec could not shrink (storage-engine.md §6, PD-025).
///
/// Why: a block the codec cannot shrink by 12.5 % is stored raw anyway, so trying it only burns
/// CPU — for incompressible values (already compressed or encrypted payloads) Zstd 6 cut a
/// compaction thread from ~835 to ~217 MB/s (PD-025 probe). After [`INCOMPRESSIBLE_SKIP_AFTER`]
/// failures in a row only every [`INCOMPRESSIBLE_PROBE_EVERY`]-th block is tried; one success
/// resets the run. The stored form of a skipped block is a valid raw block (codec byte 0), so
/// readers and the format are unchanged; the only cost is that up to
/// `INCOMPRESSIBLE_PROBE_EVERY - 1` compressible blocks right after a long incompressible run
/// stay raw.
fn try_compress(incompressible_streak: u64, block: u64) -> bool {
    incompressible_streak < INCOMPRESSIBLE_SKIP_AFTER
        || block.is_multiple_of(INCOMPRESSIBLE_PROBE_EVERY)
}
