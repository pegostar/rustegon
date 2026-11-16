// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! SST reader: point lookups and forward iteration over an `rsst` v1 file (layout in
//! [`super`]).
//!
//! Opening reads the footer, metaindex, top-level index, filter and properties; data blocks and
//! index partitions are read on demand and verified on every read; with a [`BlockCache`] they are
//! looked up there first (keyed by a per-open cache id and the block offset) and inserted after a
//! verified read. No cache lock is held during I/O.
//!
//! Concurrency: a reader is immutable after `open` and shared through `Arc`; iterators hold their
//! own `Arc` so they outlive the handle that created them. Reads use positional I/O, so
//! concurrent readers never contend on a file cursor.
//!
//! Encryption (storage-engine.md §7): [`SstReader::open_numbered`] looks the file's DEK up in
//! [`SstReaderOptions::encryption`]; a file with a DEK must be encrypted throughout, a file
//! without one must be plaintext (`format.rs`). The block cache holds decrypted blocks: it is
//! process memory, which encryption at rest does not cover (security.md §6).

use std::sync::Arc;

use bytes::Bytes;
use rustegon_sim_api::File;

use super::{
    META_FILTER, META_INDEX, META_PROPERTIES, META_RANGE_DEL, PrefixExtractor,
    block::{Block, BlockIter, KeyOrder},
    default_extractor,
    filter::{RibbonFilter, filter_hash},
    format::{BlockHandle, FOOTER_LEN, Footer, read_block},
    properties::Properties,
};
use crate::{
    cache::{BlockCache, Priority},
    encryption::{FileCipher, KeyManager},
    error::{Result, StorageError},
    key::{ParsedKey, SeqNo, ValueKind, seek_key},
    range_del::RangeTombstone,
};

/// Reader configuration.
#[derive(Debug, Clone)]
pub struct SstReaderOptions {
    /// Must match the writer's extractor (by name) for the filter to be used.
    pub prefix_extractor: Arc<dyn PrefixExtractor>,
    /// Shared cache for data blocks and index partitions (storage-engine.md §5); `None` reads
    /// every block from the file.
    pub block_cache: Option<Arc<BlockCache>>,
    /// The store's encryption context, consulted by [`SstReader::open_numbered`]; `None`
    /// opens every file as plaintext (an encrypted file then fails with `KeyUnavailable`).
    pub encryption: Option<Arc<KeyManager>>,
}

impl Default for SstReaderOptions {
    fn default() -> Self {
        Self {
            prefix_extractor: default_extractor(),
            block_cache: None,
            encryption: None,
        }
    }
}

/// The newest version of a user key visible at a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SstEntry {
    /// Sequence number of the version.
    pub seqno: SeqNo,
    /// Kind of the version.
    pub kind: ValueKind,
    /// Value bytes (empty for tombstones).
    pub value: Bytes,
}

struct ReaderCore {
    file: Box<dyn File>,
    /// End of the block area (start of the footer); every block must lie below it.
    data_end: u64,
    top_index: Block,
    filter: Option<RibbonFilter>,
    properties: Properties,
    range_tombstones: Vec<RangeTombstone>,
    extractor: Arc<dyn PrefixExtractor>,
    /// The shared cache and this open file's id in it.
    cache: Option<(Arc<BlockCache>, u64)>,
    /// The file's DEK context; `None` for a plaintext file.
    cipher: Option<Arc<FileCipher>>,
}

impl ReaderCore {
    /// Reads the block whose encoded handle is an index entry value, through the cache if any.
    /// `priority` is [`Priority::High`] for index partitions and `Low` for data blocks.
    fn child_block(&self, handle_bytes: &[u8], priority: Priority) -> Result<Block> {
        let handle = BlockHandle::decode(handle_bytes)?;
        let read = || {
            Block::new(read_block(
                self.file.as_ref(),
                handle,
                self.data_end,
                self.cipher.as_deref(),
            )?)
        };
        let Some((cache, id)) = &self.cache else {
            return read();
        };
        let key = (*id, handle.offset);
        if let Some(block) = cache.lookup(key) {
            return Ok(block);
        }
        // Only verified, decoded blocks are inserted, so a hit needs no re-validation.
        let block = read()?;
        cache.insert(key, block.clone(), priority);
        Ok(block)
    }
}

/// An open SST.
#[derive(Clone)]
pub struct SstReader {
    core: Arc<ReaderCore>,
}

impl SstReader {
    /// Opens and validates a plaintext SST (no file number, so no DEK lookup).
    ///
    /// # Errors
    /// [`StorageError::Corruption`] for a damaged or foreign file,
    /// [`StorageError::KeyUnavailable`] for an encrypted one, I/O errors otherwise.
    pub fn open(file: Box<dyn File>, options: SstReaderOptions) -> Result<Self> {
        Self::open_with_cipher(file, options, None)
    }

    /// Opens and validates SST `file_number`, decrypting it with its DEK from
    /// [`SstReaderOptions::encryption`] when the registry has one.
    ///
    /// # Errors
    /// As [`SstReader::open`]; [`StorageError::KeyUnavailable`] if the DEK does not unwrap.
    pub fn open_numbered(
        file: Box<dyn File>,
        file_number: u64,
        options: SstReaderOptions,
    ) -> Result<Self> {
        let cipher = match &options.encryption {
            Some(keys) => keys.file_cipher(file_number)?,
            None => None,
        };
        Self::open_with_cipher(file, options, cipher)
    }

    fn open_with_cipher(
        file: Box<dyn File>,
        options: SstReaderOptions,
        cipher: Option<Arc<FileCipher>>,
    ) -> Result<Self> {
        let size = file.size()?;
        let data_end = size
            .checked_sub(FOOTER_LEN as u64)
            .ok_or_else(|| StorageError::corruption("file shorter than the rsst footer"))?;
        let mut footer = [0u8; FOOTER_LEN];
        file.read_exact_at(&mut footer, data_end)?;
        let footer = Footer::decode(&footer)?;
        let read = |h| read_block(file.as_ref(), h, data_end, cipher.as_deref());

        let (mut filter_handle, mut index_handle, mut props_handle) = (None, None, None);
        let mut range_del_handle = None;
        let mut it = Block::new(read(footer.metaindex)?)?.cursor(KeyOrder::Bytewise);
        it.seek_to_first()?;
        while it.valid() {
            let slot = match it.key() {
                META_FILTER => Some(&mut filter_handle),
                META_INDEX => Some(&mut index_handle),
                META_PROPERTIES => Some(&mut props_handle),
                META_RANGE_DEL => Some(&mut range_del_handle),
                // Blocks added by newer writers are skipped.
                _ => None,
            };
            if let Some(slot) = slot {
                *slot = Some(BlockHandle::decode(it.value_bytes())?);
            }
            it.next()?;
        }
        let missing = |name: &str| StorageError::corruption(format!("metaindex lacks {name}"));
        let index_handle = index_handle.ok_or_else(|| missing("index"))?;
        let props_handle = props_handle.ok_or_else(|| missing("properties"))?;

        let properties = Properties::decode(read(props_handle)?)?;
        let top_index = Block::new(read(index_handle)?)?;
        // A filter built with another extractor would give false negatives: ignore it.
        let filter = match filter_handle {
            Some(h) if properties.filter_prefix_extractor == options.prefix_extractor.name() => {
                Some(RibbonFilter::decode(&read(h)?)?)
            }
            _ => None,
        };
        let range_tombstones = match range_del_handle {
            Some(h) => decode_range_tombstones(&Block::new(read(h)?)?)?,
            None => Vec::new(),
        };
        Ok(Self {
            core: Arc::new(ReaderCore {
                file,
                data_end,
                top_index,
                filter,
                properties,
                range_tombstones,
                extractor: options.prefix_extractor,
                cache: options.block_cache.map(|c| {
                    let id = c.new_cache_id();
                    (c, id)
                }),
                cipher,
            }),
        })
    }

    /// The file's properties.
    #[must_use]
    pub fn properties(&self) -> &Properties {
        &self.core.properties
    }

    /// The file's range tombstones (loaded at open; small: `DeleteRange` is rare).
    #[must_use]
    pub fn range_tombstones(&self) -> &[RangeTombstone] {
        &self.core.range_tombstones
    }

    /// Whether the filter is loaded and usable with the configured extractor.
    #[must_use]
    pub fn has_filter(&self) -> bool {
        self.core.filter.is_some()
    }

    /// `false` if no user key with this filter prefix exists in the file; `true` if one may.
    #[must_use]
    pub fn may_contain_prefix(&self, prefix: &[u8]) -> bool {
        self.core
            .filter
            .as_ref()
            .is_none_or(|f| f.may_contain(filter_hash(prefix)))
    }

    /// Newest version of `user_key` with `seqno <= snapshot` stored in this file.
    ///
    /// # Errors
    /// [`StorageError::Corruption`] if a block on the path fails validation; I/O errors.
    pub fn get(&self, user_key: &[u8], snapshot: SeqNo) -> Result<Option<SstEntry>> {
        if !self.may_contain_prefix(self.core.extractor.prefix(user_key)) {
            return Ok(None);
        }
        let mut it = self.new_iterator();
        it.seek(&seek_key(user_key, snapshot))?;
        if !it.valid() {
            return Ok(None);
        }
        let parsed = ParsedKey::parse(it.key())
            .map_err(|e| StorageError::corruption(format!("data block key: {e}")))?;
        Ok((parsed.user_key == user_key).then(|| SstEntry {
            seqno: parsed.seqno,
            kind: parsed.kind,
            value: it.value(),
        }))
    }

    /// Whether the filter admits `user_key` (always `true` without a usable filter).
    pub(crate) fn may_contain_key(&self, user_key: &[u8]) -> bool {
        self.may_contain_prefix(self.core.extractor.prefix(user_key))
    }

    /// Index separators of the data blocks, in order: each is the internal key of the last
    /// entry of its block (storage-engine.md §4). Reads the index partitions only, never a data
    /// block; compaction uses them as candidate subcompaction boundaries (§3).
    ///
    /// # Errors
    /// [`StorageError::Corruption`] if an index partition fails validation; I/O errors.
    pub fn data_block_separators(&self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut top = self.core.top_index.cursor(KeyOrder::Internal);
        top.seek_to_first()?;
        while top.valid() {
            let mut partition = self
                .core
                .child_block(top.value_bytes(), Priority::High)?
                .cursor(KeyOrder::Internal);
            partition.seek_to_first()?;
            while partition.valid() {
                out.push(partition.key().to_vec());
                partition.next()?;
            }
            top.next()?;
        }
        Ok(out)
    }

    /// An unpositioned bidirectional iterator over all entries; call a seek method first.
    #[must_use]
    pub fn new_iterator(&self) -> SstIterator {
        SstIterator {
            top: self.core.top_index.cursor(KeyOrder::Internal),
            core: Arc::clone(&self.core),
            partition: None,
            data: None,
        }
    }
}

/// Bidirectional iterator over an SST (top-level index → index partition → data block).
///
/// Invariants: `partition` is `Some` only while `top` is positioned on its entry, and `data` is
/// `Some` only while `partition` is positioned on the entry of that data block. Advancing past an
/// exhausted level therefore always means "step the level above, then reload below".
pub struct SstIterator {
    core: Arc<ReaderCore>,
    top: BlockIter,
    partition: Option<BlockIter>,
    data: Option<BlockIter>,
}

impl SstIterator {
    /// Whether the iterator is positioned on an entry.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.data.as_ref().is_some_and(BlockIter::valid)
    }

    /// Encoded internal key of the current entry (empty unless [`Self::valid`]).
    #[must_use]
    pub fn key(&self) -> &[u8] {
        self.data.as_ref().map_or(&[], BlockIter::key)
    }

    /// Value of the current entry as a zero-copy slice of its block.
    #[must_use]
    pub fn value(&self) -> Bytes {
        self.data.as_ref().map_or_else(Bytes::new, BlockIter::value)
    }

    /// Positions at the first entry.
    ///
    /// # Errors
    /// Corruption or I/O errors; the iterator is then invalid.
    pub fn seek_to_first(&mut self) -> Result<()> {
        let result = self.position(None);
        self.invalidate_on_error(result)
    }

    /// Positions at the first entry whose encoded internal key is >= `target`.
    ///
    /// # Errors
    /// Corruption or I/O errors; the iterator is then invalid.
    pub fn seek(&mut self, target: &[u8]) -> Result<()> {
        let result = self.position(Some(target));
        self.invalidate_on_error(result)
    }

    /// Advances to the next entry. No-op on an invalid iterator.
    ///
    /// # Errors
    /// Corruption or I/O errors; the iterator is then invalid.
    // Not `Iterator::next`: advancing is fallible and the iterator exposes borrowed keys
    // (a lending iterator), which `Iterator` cannot express.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<()> {
        let result = match &mut self.data {
            Some(d) if d.valid() => d.next().and_then(|()| self.skip_exhausted()),
            _ => Ok(()),
        };
        self.invalidate_on_error(result)
    }

    /// Positions at the last entry.
    ///
    /// # Errors
    /// Corruption or I/O errors; the iterator is then invalid.
    pub fn seek_to_last(&mut self) -> Result<()> {
        let result = self.position_last();
        self.invalidate_on_error(result)
    }

    /// Steps to the previous entry; invalid before the first one, no-op when invalid.
    ///
    /// # Errors
    /// Corruption or I/O errors; the iterator is then invalid.
    pub fn prev(&mut self) -> Result<()> {
        let result = match &mut self.data {
            Some(d) if d.valid() => d.prev().and_then(|()| self.skip_exhausted_backward()),
            _ => Ok(()),
        };
        self.invalidate_on_error(result)
    }

    fn position_last(&mut self) -> Result<()> {
        self.partition = None;
        self.data = None;
        self.top.seek_to_last()?;
        if self.top.valid() {
            let mut partition = self
                .core
                .child_block(self.top.value_bytes(), Priority::High)?
                .cursor(KeyOrder::Internal);
            partition.seek_to_last()?;
            if partition.valid() {
                let mut data = self
                    .core
                    .child_block(partition.value_bytes(), Priority::Low)?
                    .cursor(KeyOrder::Internal);
                data.seek_to_last()?;
                self.data = Some(data);
            }
            self.partition = Some(partition);
        }
        self.skip_exhausted_backward()
    }

    /// Mirror of [`Self::skip_exhausted`]: moves backwards across exhausted data blocks and
    /// partitions until an entry or the beginning.
    fn skip_exhausted_backward(&mut self) -> Result<()> {
        while !self.valid() {
            if let Some(partition) = &mut self.partition {
                if self.data.is_some() {
                    partition.prev()?;
                }
                if partition.valid() {
                    let mut data = self
                        .core
                        .child_block(partition.value_bytes(), Priority::Low)?
                        .cursor(KeyOrder::Internal);
                    data.seek_to_last()?;
                    self.data = Some(data);
                    continue;
                }
                self.data = None;
                self.partition = None;
                self.top.prev()?;
            }
            if !self.top.valid() {
                return Ok(());
            }
            let mut partition = self
                .core
                .child_block(self.top.value_bytes(), Priority::High)?
                .cursor(KeyOrder::Internal);
            partition.seek_to_last()?;
            self.partition = Some(partition);
        }
        Ok(())
    }

    fn invalidate_on_error(&mut self, result: Result<()>) -> Result<()> {
        if result.is_err() {
            self.partition = None;
            self.data = None;
        }
        result
    }

    /// Positions all three levels at `target` (or at the start) and skips empty blocks.
    fn position(&mut self, target: Option<&[u8]>) -> Result<()> {
        self.partition = None;
        self.data = None;
        seek_or_first(&mut self.top, target)?;
        if self.top.valid() {
            let mut partition = self
                .core
                .child_block(self.top.value_bytes(), Priority::High)?
                .cursor(KeyOrder::Internal);
            seek_or_first(&mut partition, target)?;
            if partition.valid() {
                let mut data = self
                    .core
                    .child_block(partition.value_bytes(), Priority::Low)?
                    .cursor(KeyOrder::Internal);
                seek_or_first(&mut data, target)?;
                self.data = Some(data);
            }
            self.partition = Some(partition);
        }
        self.skip_exhausted()
    }

    /// Moves forward across exhausted data blocks and partitions until an entry or the end.
    fn skip_exhausted(&mut self) -> Result<()> {
        while !self.valid() {
            if let Some(partition) = &mut self.partition {
                if self.data.is_some() {
                    // The current data block is exhausted: step to the next one.
                    partition.next()?;
                }
                if partition.valid() {
                    let mut data = self
                        .core
                        .child_block(partition.value_bytes(), Priority::Low)?
                        .cursor(KeyOrder::Internal);
                    data.seek_to_first()?;
                    self.data = Some(data);
                    continue;
                }
                // The partition is exhausted: step the top level.
                self.data = None;
                self.partition = None;
                self.top.next()?;
            }
            if !self.top.valid() {
                return Ok(());
            }
            let mut partition = self
                .core
                .child_block(self.top.value_bytes(), Priority::High)?
                .cursor(KeyOrder::Internal);
            partition.seek_to_first()?;
            self.partition = Some(partition);
        }
        Ok(())
    }
}

/// Decodes and validates the range-del block (`writer.rs`).
fn decode_range_tombstones(block: &Block) -> Result<Vec<RangeTombstone>> {
    let mut out = Vec::new();
    let mut it = block.cursor(KeyOrder::Internal);
    it.seek_to_first()?;
    while it.valid() {
        let key = ParsedKey::parse(it.key())
            .map_err(|e| StorageError::corruption(format!("range-del key: {e}")))?;
        if key.kind != ValueKind::RangeDelete || key.user_key >= it.value_bytes() {
            return Err(StorageError::corruption(
                "range-del block: malformed tombstone",
            ));
        }
        out.push(RangeTombstone {
            start: key.user_key.to_vec(),
            end: it.value_bytes().to_vec(),
            seqno: key.seqno,
        });
        it.next()?;
    }
    Ok(out)
}

fn seek_or_first(it: &mut BlockIter, target: Option<&[u8]>) -> Result<()> {
    match target {
        Some(t) => it.seek(t),
        None => it.seek_to_first(),
    }
}
