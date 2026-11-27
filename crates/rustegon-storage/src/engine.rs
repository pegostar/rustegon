// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The LSM engine: write batches, snapshots, reads, memtable rotation, flush and compaction over
//! one store directory (storage-engine.md §1, §3, §9, §11).
//!
//! Durability: the engine has no WAL — the Raft log is the WAL (ADR-009). A write is durable once
//! its memtable is flushed; [`LsmEngine::flushed_seqno`] tells the caller up to which seqno its
//! log may be truncated, and after a crash the caller replays everything above it.
//!
//! Locking (each lock protects only what is listed; never held across another lock in the
//! opposite order):
//! - `write`: serialises seqno assignment, memtable insertion and rotation, so seqnos are
//!   published in order;
//! - `versions`: the `VersionSet` (MANIFEST writes, file numbers) and the set of files that
//!   running flushes/compactions read or write;
//! - `mem`: the active and immutable memtables and the current `Version`, swapped together so a
//!   reader always gets a consistent pair — a flushed memtable disappears in the same critical
//!   section in which the version holding its SST appears.
//!
//! Lock order: `write → mem` and `versions → mem`; nothing takes `versions` while holding `mem`.
//! Readers take only `mem`, briefly, to clone `Arc`s; reads then run lock-free.
//!
//! Background work: [`LsmEngine::flush`] and [`LsmEngine::compact`] run on the calling thread, so
//! a deterministic simulation can drive them; the server's scheduler (I/O pool,
//! `storage.max_compactions`) calls them from background threads. Write stalls are signalled to
//! admission control, never enforced by sleeping in the write path (§3).

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use rustegon_sim_api::FileSystem;

use crate::{
    admission::{AdmissionOptions, WriteCondition, write_condition},
    checkpoint::{CheckpointInfo, CheckpointSource, create_checkpoint},
    compaction::{
        CompactionFilter, CompactionOptions, delete_obsolete_files, install_compaction,
        pick_compaction, run_compaction,
    },
    encryption::KeyManager,
    error::{Result, StorageError},
    flush::flush_memtable,
    ingest::{KeyRange, pick_level, rewrite_with_seqno},
    iter::InternalIterator,
    key::{MAX_SEQNO, SeqNo, ValueKind, seek_key},
    memtable::Memtable,
    metrics::{EngineCounters, EngineMetrics},
    read::{DbIterator, ReadView},
    settings::StorageSettings,
    sst::{SstReader, SstReaderOptions},
    table_cache::TableCache,
    version::{
        FileKind, FileMeta, Version, VersionEdit, VersionSet, parse_file_name, sst_file_name,
    },
};

/// Default memtable size that triggers rotation (`storage.memtable_size`).
pub use crate::settings::DEFAULT_MEMTABLE_SIZE;
/// Immutable memtables kept before writes are signalled to stall (§3: "≤ 3").
pub const DEFAULT_MAX_IMMUTABLE_MEMTABLES: usize = 3;

/// Engine configuration.
#[derive(Clone)]
pub struct EngineOptions {
    /// Active memtable size (approximate bytes) that triggers rotation.
    pub memtable_size: usize,
    /// Immutable memtables beyond which the engine reports a write stall.
    pub max_immutable_memtables: usize,
    /// Picker and job tuning; `compaction.writer` also configures flushes.
    pub compaction: CompactionOptions,
    /// Options for opening SSTs (prefix extractor, block cache).
    pub reader: SstReaderOptions,
    /// Encryption at rest (§7): the store's key manager, built by the caller from
    /// `storage.encryption` with `KeyManager::open`/`create`; `None` writes plaintext. The engine
    /// hands it to every SST writer and reader and to the MANIFEST.
    pub encryption: Option<Arc<KeyManager>>,
    /// Filter consulted by every compaction the engine runs (§3 "compaction filters"; the MVCC
    /// GC filter of `rustegon-mvcc`); `None` keeps every value.
    pub compaction_filter: Option<Arc<dyn CompactionFilter>>,
}

impl fmt::Debug for EngineOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineOptions")
            .field("memtable_size", &self.memtable_size)
            .field("max_immutable_memtables", &self.max_immutable_memtables)
            .field("compaction", &self.compaction)
            .field("reader", &self.reader)
            .field("encryption", &self.encryption)
            .field("compaction_filter", &self.compaction_filter.is_some())
            .finish()
    }
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self::from_settings(&StorageSettings::default())
    }
}

impl EngineOptions {
    /// Options from the `[storage]` settings.
    #[must_use]
    pub fn from_settings(settings: &StorageSettings) -> Self {
        Self {
            memtable_size: usize::try_from(settings.memtable_size).unwrap_or(usize::MAX),
            max_immutable_memtables: DEFAULT_MAX_IMMUTABLE_MEMTABLES,
            compaction: CompactionOptions::from_settings(settings),
            reader: SstReaderOptions {
                block_cache: crate::cache::BlockCache::from_settings(settings),
                ..SstReaderOptions::default()
            },
            encryption: None,
            compaction_filter: None,
        }
    }
}

/// One operation of a [`WriteBatch`], in the order it was added. Exposed read-only through
/// [`WriteBatch::ops`] so that a batch can be serialised into a replicated command (the Raft
/// log is the WAL, ADR-009; replication.md "Command format v1"); batches are still built only
/// through the [`WriteBatch`] methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchOp {
    /// [`WriteBatch::put`]: key, value.
    Put(Vec<u8>, Bytes),
    /// [`WriteBatch::delete`]: key.
    Delete(Vec<u8>),
    /// [`WriteBatch::single_delete`]: key.
    SingleDelete(Vec<u8>),
    /// [`WriteBatch::merge`]: key, merge operand.
    Merge(Vec<u8>, Bytes),
    /// [`WriteBatch::delete_range`]: start (inclusive), end (exclusive).
    DeleteRange(Vec<u8>, Vec<u8>),
}

/// Operations applied atomically by [`LsmEngine::write`] (§1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteBatch {
    ops: Vec<BatchOp>,
}

impl WriteBatch {
    /// An empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `key` to `value`.
    pub fn put(&mut self, key: &[u8], value: impl Into<Bytes>) -> &mut Self {
        self.ops.push(BatchOp::Put(key.to_vec(), value.into()));
        self
    }

    /// Deletes `key`.
    pub fn delete(&mut self, key: &[u8]) -> &mut Self {
        self.ops.push(BatchOp::Delete(key.to_vec()));
        self
    }

    /// Deletes a key written exactly once (write intents, §1).
    pub fn single_delete(&mut self, key: &[u8]) -> &mut Self {
        self.ops.push(BatchOp::SingleDelete(key.to_vec()));
        self
    }

    /// Adds a merge operand (`merge::MergeOperand` encoding) to `key`.
    pub fn merge(&mut self, key: &[u8], operand: impl Into<Bytes>) -> &mut Self {
        self.ops.push(BatchOp::Merge(key.to_vec(), operand.into()));
        self
    }

    /// Deletes every key in `[start, end)` (range tombstone, storage-engine.md §3).
    pub fn delete_range(&mut self, start: &[u8], end: &[u8]) -> &mut Self {
        self.ops
            .push(BatchOp::DeleteRange(start.to_vec(), end.to_vec()));
        self
    }

    /// Number of operations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the batch has no operations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// The operations in application order (later operations on the same key win).
    #[must_use]
    pub fn ops(&self) -> &[BatchOp] {
        &self.ops
    }
}

/// A consistent read point; released when dropped. Compaction keeps every version a live
/// snapshot can read (§3).
pub struct Snapshot {
    seqno: SeqNo,
    registry: Arc<Mutex<BTreeMap<SeqNo, usize>>>,
}

impl Snapshot {
    /// The snapshot's seqno: it reads every write with a seqno <= this.
    #[must_use]
    pub fn seqno(&self) -> SeqNo {
        self.seqno
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let mut registry = lock(&self.registry);
        if let Some(count) = registry.get_mut(&self.seqno) {
            *count -= 1;
            if *count == 0 {
                registry.remove(&self.seqno);
            }
        }
    }
}

/// Memtables and version, swapped together under the `mem` lock (module docs).
struct MemState {
    active: Arc<Memtable>,
    /// Newest first, each with the largest seqno it may contain (its flush seqno).
    immutable: Vec<(Arc<Memtable>, SeqNo)>,
    version: Arc<Version>,
}

/// State guarded by the `versions` lock.
struct VersionState {
    set: VersionSet,
    /// Inputs of running compactions (not to be picked again).
    busy: BTreeSet<u64>,
    /// Numbers of files being written (not obsolete although unreferenced).
    in_flight: BTreeSet<u64>,
    /// Output level and input key hull of every running compaction: its outputs may land
    /// anywhere in the hull, so ingestion treats it as occupied (`ingest.rs`).
    running: Vec<(usize, KeyRange)>,
}

/// Called before memtables are flushed ([`LsmEngine::set_flush_barrier`]).
pub type FlushBarrier = Arc<dyn Fn() -> Result<()> + Send + Sync>;

/// The LSM engine over one store directory.
pub struct LsmEngine {
    fs: Arc<dyn FileSystem>,
    dir: PathBuf,
    options: EngineOptions,
    write: Mutex<()>,
    versions: Mutex<VersionState>,
    mem: Mutex<MemState>,
    tables: Arc<TableCache>,
    snapshots: Arc<Mutex<BTreeMap<SeqNo, usize>>>,
    counters: EngineCounters,
    /// Largest seqno whose write is fully in the memtable; readers default to it. Written under
    /// `write` with `Release` after the memtable inserts, read with `Acquire`, so a reader that
    /// sees seqno `s` also sees every entry with seqno <= `s`.
    visible: AtomicU64,
    /// [`Self::set_flush_barrier`].
    flush_barrier: Mutex<Option<FlushBarrier>>,
}

impl LsmEngine {
    /// Installs (or removes) the flush barrier: `barrier` runs before every memtable flush, with
    /// no engine lock held, and a flush only persists writes made before the barrier started. A
    /// failing barrier fails the flush.
    ///
    /// Why (ADR-038): the engine has no WAL; its owner logs writes elsewhere and may apply a
    /// write here before its log entry is durable. The barrier is where the owner makes the log
    /// durable, so that an SST never holds a write the log lost.
    pub fn set_flush_barrier(&self, barrier: Option<FlushBarrier>) {
        *lock(&self.flush_barrier) = barrier;
    }

    /// Opens the store in `dir`, creating it when it has no `CURRENT` file. Recovery (§9):
    /// replay the MANIFEST, refuse missing SSTs, delete orphan files.
    ///
    /// # Errors
    /// Corruption (missing SSTs, damaged MANIFEST) and I/O errors.
    pub fn open(fs: Arc<dyn FileSystem>, dir: &Path, mut options: EngineOptions) -> Result<Self> {
        options
            .compaction
            .writer
            .encryption
            .clone_from(&options.encryption);
        options.reader.encryption.clone_from(&options.encryption);
        let keys = options.encryption.clone();
        let set = if store_exists(fs.as_ref(), dir)? {
            VersionSet::open_with(Arc::clone(&fs), dir, keys)?
        } else {
            VersionSet::create_with(Arc::clone(&fs), dir, keys)?
        };
        // Orphans: SSTs of interrupted flushes/compactions and superseded MANIFESTs.
        delete_obsolete_files(fs.as_ref(), &set, &BTreeSet::new())?;
        let last = set.last_seqno();
        let version = set.current();
        let tables = Arc::new(TableCache::new(
            Arc::clone(&fs),
            dir.to_path_buf(),
            options.reader.clone(),
        ));
        Ok(Self {
            fs,
            dir: dir.to_path_buf(),
            options,
            write: Mutex::new(()),
            versions: Mutex::new(VersionState {
                set,
                busy: BTreeSet::new(),
                in_flight: BTreeSet::new(),
                running: Vec::new(),
            }),
            mem: Mutex::new(MemState {
                active: Arc::new(Memtable::new()),
                immutable: Vec::new(),
                version,
            }),
            tables,
            snapshots: Arc::new(Mutex::new(BTreeMap::new())),
            counters: EngineCounters::default(),
            visible: AtomicU64::new(last),
            flush_barrier: Mutex::new(None),
        })
    }

    /// Applies `batch` atomically and returns the seqno of its last operation (the previous
    /// visible seqno for an empty batch). Not durable by itself (module docs).
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] when the seqno space (56 bits) is exhausted or a range
    /// delete has `start >= end` (nothing is applied then).
    pub fn write(&self, batch: &WriteBatch) -> Result<SeqNo> {
        if batch
            .ops
            .iter()
            .any(|op| matches!(op, BatchOp::DeleteRange(s, e) if s >= e))
        {
            return Err(StorageError::InvalidArgument(
                "delete_range needs start < end".into(),
            ));
        }
        let _serial = checked(&self.write)?;
        let first = self.visible.load(Ordering::Relaxed) + 1;
        let count = batch.ops.len() as u64;
        if first.saturating_add(count) > MAX_SEQNO {
            return Err(StorageError::InvalidArgument(
                "seqno space exhausted".into(),
            ));
        }
        let active = Arc::clone(&lock(&self.mem).active);
        for (op, seqno) in batch.ops.iter().zip(first..) {
            match op {
                BatchOp::Put(k, v) => active.add(seqno, ValueKind::Put, k, v.clone()),
                BatchOp::Delete(k) => active.add(seqno, ValueKind::Delete, k, Bytes::new()),
                BatchOp::SingleDelete(k) => {
                    active.add(seqno, ValueKind::SingleDelete, k, Bytes::new());
                }
                BatchOp::Merge(k, v) => active.add(seqno, ValueKind::Merge, k, v.clone()),
                BatchOp::DeleteRange(start, end) => active.add_range_tombstone(seqno, start, end),
            }
        }
        let last = first + count - 1;
        // Publishes the batch: readers that load `last` see all its entries (field docs).
        self.visible.store(last, Ordering::Release);
        EngineCounters::add(&self.counters.write_batches, 1);
        if active.approximate_size() >= self.options.memtable_size {
            self.rotate_locked(last);
        }
        Ok(last)
    }

    /// Takes a snapshot at the current visible seqno.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let seqno = self.visible.load(Ordering::Acquire);
        *lock(&self.snapshots).entry(seqno).or_insert(0) += 1;
        Snapshot {
            seqno,
            registry: Arc::clone(&self.snapshots),
        }
    }

    /// Value of `key` at `snapshot` (latest when `None`), merge operands resolved.
    ///
    /// # Errors
    /// `RGN-1009` for an overflowing merged counter; corruption and I/O errors.
    pub fn get(&self, key: &[u8], snapshot: Option<&Snapshot>) -> Result<Option<Bytes>> {
        let seqno = self.read_seqno(snapshot);
        self.view().get(key, seqno)
    }

    /// An unpositioned user-key iterator at `snapshot` (latest when `None`). It pins the
    /// memtables and SSTs it reads until dropped.
    ///
    /// # Errors
    /// Corruption and I/O errors opening SSTs.
    pub fn iterator(&self, snapshot: Option<&Snapshot>) -> Result<DbIterator> {
        let seqno = self.read_seqno(snapshot);
        self.view().iterator(seqno)
    }

    /// An unpositioned user-key iterator at `snapshot` (latest when `None`) over the user keys
    /// in `[lower, upper)`: it reads only the sources that may hold a key of the range and is
    /// invalid outside it. `prefix`: the filter prefix shared by every key of the range, when
    /// they share one ([`ReadView::iterator_within`], [`Self::prefix_extractor_name`]).
    ///
    /// # Errors
    /// Corruption and I/O errors opening SSTs.
    pub fn iterator_within(
        &self,
        lower: &[u8],
        upper: &[u8],
        prefix: Option<&[u8]>,
        snapshot: Option<&Snapshot>,
    ) -> Result<DbIterator> {
        let seqno = self.read_seqno(snapshot);
        self.view().iterator_within(lower, upper, prefix, seqno)
    }

    /// Name of the prefix extractor the SST filters are read with: what a caller of
    /// [`Self::iterator_within`] checks before it claims a filter prefix for a range.
    #[must_use]
    pub fn prefix_extractor_name(&self) -> &str {
        self.options.reader.prefix_extractor.name()
    }

    /// Makes the active memtable immutable (if non-empty) and flushes every immutable memtable,
    /// oldest first. Afterwards every write acknowledged before the call is durable.
    ///
    /// # Errors
    /// I/O errors; a failed MANIFEST write leaves the engine refusing further flushes (the
    /// version set is poisoned, `version/set.rs`) until reopened.
    pub fn flush(&self) -> Result<()> {
        {
            let _serial = checked(&self.write)?;
            let last = self.visible.load(Ordering::Relaxed);
            self.rotate_locked(last);
        }
        self.flush_immutable().map(drop)
    }

    /// Flushes every immutable memtable, oldest first, and leaves the active one alone; returns
    /// how many were flushed. This is the background scheduler's step: rotating the active
    /// memtable on every tick would cut a small L0 file each time and feed compaction for
    /// nothing, while full memtables are rotated by the write path anyway.
    ///
    /// # Errors
    /// As [`Self::flush`].
    pub fn flush_immutable(&self) -> Result<usize> {
        // The memtables that are immutable now hold only writes made before this point, which
        // the barrier (run next, before any engine lock: it may wait for a writer) covers. A
        // memtable rotated later waits for the next call and its own barrier.
        let Some(limit) = lock(&self.mem).immutable.first().map(|(_, seqno)| *seqno) else {
            return Ok(0);
        };
        let barrier = lock(&self.flush_barrier).clone();
        if let Some(barrier) = barrier {
            barrier()?;
        }
        let mut versions = checked(&self.versions)?;
        let mut flushed = 0;
        loop {
            let Some((memtable, flushed_seqno)) = lock(&self.mem).immutable.last().cloned() else {
                return Ok(flushed);
            };
            if flushed_seqno > limit {
                return Ok(flushed);
            }
            let flushed_seqno = flushed_seqno.max(versions.set.flushed_seqno());
            let written = flush_memtable(
                self.fs.as_ref(),
                &self.dir,
                &mut versions.set,
                &memtable,
                &self.options.compaction.writer,
                flushed_seqno,
            )?;
            if let Some(meta) = written {
                EngineCounters::add(&self.counters.flushes, 1);
                EngineCounters::add(&self.counters.flush_bytes, meta.size);
            }
            let mut mem = lock(&self.mem);
            mem.immutable.pop();
            mem.version = versions.set.current();
            flushed += 1;
        }
    }

    /// Runs compactions until the picker finds nothing to do; returns how many ran.
    ///
    /// # Errors
    /// I/O and corruption errors of the failing compaction; its outputs are removed and its
    /// inputs stay live.
    pub fn compact(&self) -> Result<usize> {
        let mut runs = 0;
        while self.compact_once()? {
            runs += 1;
        }
        Ok(runs)
    }

    /// Picks and runs one compaction; `false` when there was nothing to do.
    ///
    /// # Errors
    /// As [`Self::compact`].
    pub fn compact_once(&self) -> Result<bool> {
        let compaction = {
            let mut versions = checked(&self.versions)?;
            let current = versions.set.current();
            let Some(c) = pick_compaction(&current, &self.options.compaction, &versions.busy)
            else {
                return Ok(false);
            };
            versions.busy.extend(c.inputs.iter().map(|(_, f)| f.number));
            versions.running.push((c.output_level, hull(&c.inputs)));
            c
        };
        let snapshots: Vec<SeqNo> = lock(&self.snapshots).keys().copied().collect();
        let mut outputs = Vec::new();
        let result = run_compaction(
            self.fs.as_ref(),
            &self.dir,
            &compaction,
            &self.options.compaction,
            &snapshots,
            self.options.compaction_filter.as_deref(),
            &mut || {
                // A bare counter increment: safe even on a poisoned lock; the install below
                // re-checks the poison flag.
                let mut versions = lock(&self.versions);
                let number = versions.set.new_file_number();
                versions.in_flight.insert(number);
                outputs.push(number);
                number
            },
        );
        let mut versions = checked(&self.versions)?;
        for (_, f) in &compaction.inputs {
            versions.busy.remove(&f.number);
        }
        let entry = (compaction.output_level, hull(&compaction.inputs));
        if let Some(at) = versions.running.iter().position(|r| *r == entry) {
            versions.running.swap_remove(at);
        }
        let installed = result.and_then(|out| {
            install_compaction(&mut versions.set, &compaction, &out)?;
            EngineCounters::add(&self.counters.compactions, 1);
            EngineCounters::add(&self.counters.subcompactions, out.subcompactions as u64);
            EngineCounters::add(&self.counters.compaction_read_bytes, out.bytes_in);
            EngineCounters::add(&self.counters.compaction_write_bytes, out.bytes_out);
            Ok(())
        });
        for number in &outputs {
            versions.in_flight.remove(number);
        }
        installed?;
        lock(&self.mem).version = versions.set.current();
        for (_, f) in &compaction.inputs {
            self.tables.evict(f.number);
        }
        delete_obsolete_files(self.fs.as_ref(), &versions.set, &versions.in_flight)?;
        Ok(true)
    }

    /// Ingests external SSTs written by `SstWriter` (§12): every entry gets one new global seqno
    /// (returned), visible atomically; each file lands on the deepest level without overlap
    /// above. Memtable data overlapping the files is flushed first. The source files are left in
    /// place. `flushed_seqno` does not move: unrelated memtable writes below the new seqno may
    /// still be unflushed (the Raft layer re-applies an ingest after a crash by command).
    ///
    /// The files must not overlap each other and must hold at most one entry per user key.
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] for overlapping, empty or multi-version inputs;
    /// corruption and I/O errors (created store files are removed).
    pub fn ingest(&self, files: &[PathBuf]) -> Result<SeqNo> {
        let mut ranges = Vec::with_capacity(files.len());
        for path in files {
            let file = self.fs.open(path, rustegon_sim_api::OpenMode::Read)?;
            let reader = SstReader::open(file, self.options.reader.clone())?;
            ranges.push(file_range(&reader)?.ok_or_else(|| {
                StorageError::InvalidArgument(format!("ingested file {} is empty", path.display()))
            })?);
        }
        let mut sorted: Vec<&KeyRange> = ranges.iter().collect();
        sorted.sort();
        if sorted.windows(2).any(|w| w[0].1 >= w[1].0) {
            return Err(StorageError::InvalidArgument(
                "ingested files overlap".into(),
            ));
        }
        loop {
            if self.memtables_overlap(&ranges) {
                self.flush()?;
            }
            let _serial = checked(&self.write)?;
            // Writes may have landed in the range since the flush: retry until clean.
            if self.memtables_overlap(&ranges) {
                continue;
            }
            let mut versions = checked(&self.versions)?;
            let seqno = self.visible.load(Ordering::Relaxed) + 1;
            if seqno > MAX_SEQNO {
                return Err(StorageError::InvalidArgument(
                    "seqno space exhausted".into(),
                ));
            }
            let mut created = Vec::new();
            let result = self.ingest_locked(&mut versions, files, &ranges, seqno, &mut created);
            for number in &created {
                versions.in_flight.remove(number);
            }
            if let Err(e) = result {
                // After a failed MANIFEST write the record may be durable and reference them.
                if !matches!(e, StorageError::Io(_)) {
                    for number in &created {
                        // Best effort: a leftover is an orphan deleted at the next open (§9).
                        drop(self.fs.remove_file(&self.dir.join(sst_file_name(*number))));
                    }
                }
                return Err(e);
            }
            lock(&self.mem).version = versions.set.current();
            // Publishes the ingested data (see `visible`).
            self.visible.store(seqno, Ordering::Release);
            return Ok(seqno);
        }
    }

    /// Rewrites, syncs and installs the files; caller holds `write` and `versions`.
    fn ingest_locked(
        &self,
        versions: &mut VersionState,
        files: &[PathBuf],
        ranges: &[KeyRange],
        seqno: SeqNo,
        created: &mut Vec<u64>,
    ) -> Result<()> {
        let mut edit = VersionEdit {
            last_seqno: Some(seqno),
            ..VersionEdit::default()
        };
        for (path, range) in files.iter().zip(ranges) {
            let number = versions.set.new_file_number();
            versions.in_flight.insert(number);
            created.push(number);
            let info = rewrite_with_seqno(
                self.fs.as_ref(),
                path,
                &self.dir.join(sst_file_name(number)),
                number,
                seqno,
                &self.options.compaction.writer,
                &self.options.reader,
            )?;
            let (Some(smallest), Some(largest)) = (info.smallest, info.largest) else {
                return Err(StorageError::InvalidArgument(
                    "ingested file is empty".into(),
                ));
            };
            EngineCounters::add(&self.counters.ingest_bytes, info.file_size);
            let level = pick_level(&versions.set.current(), range, &versions.running);
            edit.added.push((
                level,
                FileMeta {
                    number,
                    size: info.file_size,
                    smallest,
                    largest,
                    smallest_seqno: seqno,
                    largest_seqno: seqno,
                },
            ));
        }
        // §9: the new names are durable before the MANIFEST refers to them.
        self.fs.sync_dir(&self.dir)?;
        versions.set.log_and_apply(edit)
    }

    /// Whether any memtable holds a point entry or range tombstone inside one of `ranges`.
    fn memtables_overlap(&self, ranges: &[KeyRange]) -> bool {
        let memtables: Vec<Arc<Memtable>> = {
            let mem = lock(&self.mem);
            std::iter::once(Arc::clone(&mem.active))
                .chain(mem.immutable.iter().map(|(m, _)| Arc::clone(m)))
                .collect()
        };
        memtables.iter().any(|m| {
            let tombstones = m.range_tombstones();
            ranges.iter().any(|(lo, hi)| {
                let mut cursor = m.cursor();
                // An in-memory seek cannot fail on a valid target; treat failure as overlap.
                let point = cursor.seek(&seek_key(lo, MAX_SEQNO)).is_err()
                    || (cursor.valid() && user_key_of(cursor.key()) <= hi.as_slice());
                point
                    || tombstones.iter().any(|t| {
                        t.start.as_slice() <= hi.as_slice() && t.end.as_slice() > lo.as_slice()
                    })
            })
        })
    }

    /// Largest seqno whose data is durable in SSTs (Raft log truncation point, §9).
    #[must_use]
    pub fn flushed_seqno(&self) -> SeqNo {
        // Read-only access: a poisoned set still reports its last durable counter.
        lock(&self.versions).set.flushed_seqno()
    }

    /// Largest seqno visible to new reads.
    #[must_use]
    pub fn last_seqno(&self) -> SeqNo {
        self.visible.load(Ordering::Acquire)
    }

    /// The current version (file layout), for diagnostics and admission signals.
    #[must_use]
    pub fn current_version(&self) -> Arc<Version> {
        Arc::clone(&lock(&self.mem).version)
    }

    /// Current write condition for admission control (§3): computed from the live shape, never
    /// enforced here (writes do not sleep).
    #[must_use]
    pub fn write_condition(&self) -> WriteCondition {
        let (version, immutable) = {
            let mem = lock(&self.mem);
            (Arc::clone(&mem.version), mem.immutable.len())
        };
        let admission = AdmissionOptions {
            max_immutable_memtables: self.options.max_immutable_memtables,
            ..AdmissionOptions::default()
        };
        write_condition(&version, immutable, &self.options.compaction, &admission)
    }

    /// Flushes every acknowledged write, then creates a checkpoint (§10) in the empty directory
    /// `target`: a consistent image at the returned seqnos that opens as a store. Writes,
    /// flushes and compactions continue meanwhile; the captured version stays pinned so its SSTs
    /// are not deleted while they are linked. A checkpoint of an encrypted store is encrypted
    /// too and carries its own DEK registry in [`crate::checkpoint_keys_dir`]`(target)`, which
    /// opens with the store's KEK (`checkpoint.rs`, "Encrypted stores").
    ///
    /// # Errors
    /// As [`create_checkpoint`] (non-empty target, I/O, DEK registry); flush errors.
    pub fn checkpoint(&self, target: &Path) -> Result<CheckpointInfo> {
        self.flush()?;
        let source = self.capture_checkpoint()?;
        self.write_checkpoint(&source, target)
    }

    /// The first half of [`Self::checkpoint`] without its flush: captures the current version
    /// and counters (§10) and pins the version's SSTs until the source is dropped. The image
    /// will hold exactly the writes with seqno `<= source.flushed_seqno`. A caller that must
    /// know which writes those are (the replica's applied state, PD-063) flushes first and
    /// captures while no write can be applied, checking `flushed_seqno >= last_seqno()`.
    ///
    /// # Errors
    /// A poisoned version set.
    pub fn capture_checkpoint(&self) -> Result<CheckpointSource> {
        Ok(CheckpointSource::capture(&checked(&self.versions)?.set))
    }

    /// The second half of [`Self::checkpoint`]: writes the image of `source` (from
    /// [`Self::capture_checkpoint`]) into the empty directory `target`; runs without engine
    /// locks while writes, flushes and compactions continue.
    ///
    /// # Errors
    /// As [`create_checkpoint`].
    pub fn write_checkpoint(
        &self,
        source: &CheckpointSource,
        target: &Path,
    ) -> Result<CheckpointInfo> {
        create_checkpoint(self.fs.as_ref(), &self.dir, source, target)
    }

    /// Point-in-time statistics (§1 `metrics()`; names in `metrics.rs`).
    #[must_use]
    pub fn metrics(&self) -> EngineMetrics {
        let mut m = EngineMetrics::from_counters(&self.counters);
        let (version, immutable, memtable_bytes) = {
            let mem = lock(&self.mem);
            let bytes = mem.active.approximate_size()
                + mem
                    .immutable
                    .iter()
                    .map(|(t, _)| t.approximate_size())
                    .sum::<usize>();
            (Arc::clone(&mem.version), mem.immutable.len(), bytes)
        };
        m.memtable_bytes = u64::try_from(memtable_bytes).unwrap_or(u64::MAX);
        // `lock`, not `checked`: a statistic must still read after a failed install.
        m.running_compactions = lock(&self.versions).running.len();
        for level in 0..m.level_files.len() {
            m.level_files[level] = version.files(level).len();
            m.level_bytes[level] = version.level_size(level);
        }
        m.immutable_memtables = immutable;
        m.snapshots = lock(&self.snapshots).values().sum();
        m.block_cache = self.options.reader.block_cache.as_ref().map(|c| c.stats());
        m
    }

    /// Number of immutable memtables waiting for flush (write-stall input, §3).
    #[must_use]
    pub fn immutable_memtables(&self) -> usize {
        lock(&self.mem).immutable.len()
    }

    fn read_seqno(&self, snapshot: Option<&Snapshot>) -> SeqNo {
        snapshot.map_or_else(|| self.visible.load(Ordering::Acquire), Snapshot::seqno)
    }

    fn view(&self) -> ReadView {
        let mem = lock(&self.mem);
        let mut memtables = Vec::with_capacity(1 + mem.immutable.len());
        memtables.push(Arc::clone(&mem.active));
        memtables.extend(mem.immutable.iter().map(|(m, _)| Arc::clone(m)));
        ReadView::new(
            memtables,
            Arc::clone(&mem.version),
            Arc::clone(&self.tables),
        )
    }

    /// Makes a non-empty active memtable immutable; `last` is the largest seqno it holds. Caller
    /// holds `write`.
    fn rotate_locked(&self, last: SeqNo) {
        let mut mem = lock(&self.mem);
        if mem.active.is_empty() {
            return;
        }
        let old = std::mem::replace(&mut mem.active, Arc::new(Memtable::new()));
        mem.immutable.insert(0, (old, last));
    }
}

/// Locks `mutex`, ignoring poisoning. Only for `mem` and the snapshot registry: their critical
/// sections are single `Arc` swaps, vector pushes/pops and counter updates, which a panic cannot
/// leave half-applied.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Locks `write` or `versions`, refusing to continue after a panic under them: a half-applied
/// batch (entries above `visible` in the memtable) would make the next write reuse its seqnos,
/// and a half-applied version edit would desynchronise memory from the MANIFEST. The store must
/// be reopened, like after a failed fsync (§13).
fn checked<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| {
        StorageError::Io(std::io::Error::other(
            "storage engine state poisoned by an earlier panic; reopen the store",
        ))
    })
}

/// Inclusive user-key hull of compaction inputs.
fn hull(inputs: &[(usize, Arc<FileMeta>)]) -> KeyRange {
    let lo = inputs.iter().map(|(_, f)| f.smallest.user_key()).min();
    let hi = inputs.iter().map(|(_, f)| f.largest.user_key()).max();
    (
        lo.unwrap_or_default().to_vec(),
        hi.unwrap_or_default().to_vec(),
    )
}

/// User-key hull of an SST's entries and tombstones (a tombstone's exclusive end counts as
/// covered: a harmless over-approximation), or `None` for an empty file.
fn file_range(reader: &SstReader) -> Result<Option<KeyRange>> {
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut it = reader.new_iterator();
    it.seek_to_first()?;
    if it.valid() {
        keys.push(user_key_of(it.key()).to_vec());
        it.seek_to_last()?;
        keys.push(user_key_of(it.key()).to_vec());
    }
    for t in reader.range_tombstones() {
        keys.push(t.start.clone());
        keys.push(t.end.clone());
    }
    let lo = keys.iter().min().cloned();
    let hi = keys.iter().max().cloned();
    Ok(lo.zip(hi))
}

/// User key of an encoded internal key (the trailer is 8 bytes; shorter input yields itself).
fn user_key_of(key: &[u8]) -> &[u8] {
    &key[..key.len().saturating_sub(8)]
}

/// Whether `dir` holds a store (a `CURRENT` file).
fn store_exists(fs: &dyn FileSystem, dir: &Path) -> Result<bool> {
    match fs.read_dir(dir) {
        Ok(entries) => Ok(entries.iter().any(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(parse_file_name)
                == Some(FileKind::Current)
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
