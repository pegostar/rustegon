// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Compaction job: merge the inputs, resolve each user key's versions, write the outputs and
//! install the result (storage-engine.md §3, §8, §9).
//!
//! Version resolution: the live snapshots split each user key's versions (newest first) into
//! *stripes*; stripe `i` holds the seqnos in `(snapshots[i-1], snapshots[i]]`, the last stripe
//! everything newer than the newest snapshot. A reader at any snapshot sees only the newest entry
//! of a stripe, so within a stripe:
//! - a `Put`/`Delete`/`SingleDelete` shadows every older entry of the stripe;
//! - merge operands above such a base are folded into one `Put` (`merge::full_merge`); with no
//!   base in the stripe they are folded into one operand (`merge::partial_merge`), or into a `Put`
//!   when nothing older exists anywhere (last stripe of the key on a bottommost compaction).
//!   When the merged sum leaves `i64` the operands are kept unmerged: the job must never fail on a
//!   value the read path reports as `RGN-1009` (§8).
//!
//! On a bottommost compaction a tombstone with no older entry left beneath it is dropped: no
//! reader can tell it from absence. The compaction filter is consulted only for the newest entry
//! when it is a `Put` newer than every snapshot, so a filter can never change what a snapshot
//! reads; a removed value becomes a tombstone (dropped at once when bottommost) so older versions
//! of the key in lower levels cannot resurface.
//!
//! Range tombstones (`range_del.rs`): a version covered by a newer tombstone of the inputs in
//! the *same* stripe is invisible to every reader and is dropped. Tombstones are carried to the
//! outputs, except on a bottommost compaction when older than every snapshot (everything they
//! cover was then dropped here and nothing lies beneath).
//!
//! Outputs are split only between user keys, preserving the L1+ invariant that one user key's
//! versions live in one file (`version/set.rs`), and never inside a carried tombstone's range:
//! a split before user key `k` requires every tombstone of the finished file to end before `k`,
//! so the file bounds (which cover tombstones, `sst/writer.rs`) stay strictly below the next
//! file's.
//!
//! Durability (§9): every output is fsynced by `SstWriter::finish`, then the directory is fsynced
//! once, then the edit (inputs deleted, outputs added) is appended to the MANIFEST. Input files
//! are deleted only after the edit is durable and no pinned version references them.
//!
//! Encryption (§7): inputs are opened with their DEKs and every output gets a fresh DEK from
//! `options.writer.encryption` (registered before the output file is created), so compaction is
//! also the DEK rotation mechanism: rewritten data never reuses an old key.
//!
//! Subcompactions (§3, NFR-PERF-005): every compaction (L0 → base level and, since PD-025,
//! Ln → Ln+1) is split into disjoint user-key sub-ranges (`picker::subcompaction_boundaries`, which explains why range tombstones
//! and merge operands never straddle a boundary). Each sub-job merges only its sub-range into its
//! own output files, with the per-key rules above unchanged, so the concatenated outputs hold
//! exactly the entries and tombstones a single job would write; only the file cuts differ.
//! - Concurrency: sub-jobs run on scoped threads (`std::thread::scope`) and share nothing
//!   mutable except the output-number allocator and the list of created files (each behind a
//!   mutex, taken only to allocate a number) and a `failed` flag. The input readers are shared:
//!   they are immutable and read with positional I/O (`sst/reader.rs`).
//! - Atomicity: no sub-job installs anything. [`run_compaction`] waits for all of them, fsyncs
//!   the directory once, and returns every output in key order; [`install_compaction`] then
//!   records all of them with the deletion of all inputs in *one* MANIFEST edit, so a crash or
//!   error leaves either the old inputs or the complete new outputs live, never a mix. If any
//!   sub-job fails, the others stop at their next user key and every output file of every
//!   sub-job is removed (best effort; leftovers are orphans that startup deletes, §9).
//! - Determinism: with `parallel_subcompactions = false` the same sub-jobs run one after
//!   another in key order on the calling thread, so the simulation sees a reproducible sequence
//!   of file-system operations (TC-STO-002).

use std::{
    collections::BTreeSet,
    path::Path,
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use bytes::Bytes;
use rustegon_sim_api::{FileSystem, OpenMode};

use super::{
    CompactionFilter, CompactionOptions, FilterDecision,
    picker::{Compaction, subcompaction_boundaries},
};
use crate::{
    error::{Result, StorageError},
    iter::{InternalIterator, MergingIterator},
    key::{InternalKey, MAX_SEQNO, ParsedKey, SeqNo, ValueKind, seek_key},
    merge::{full_merge, partial_merge},
    range_del::{FragmentedTombstones, RangeTombstone},
    sst::{CompressionPolicy, SstReader, SstReaderOptions, SstWriter},
    version::{FileKind, FileMeta, VersionEdit, VersionSet, parse_file_name, sst_file_name},
};

/// Result of [`run_compaction`], to be installed with [`install_compaction`].
#[derive(Debug, Clone, Default)]
pub struct CompactionOutput {
    /// New files for the output level, in key order.
    pub files: Vec<FileMeta>,
    /// Entries read from the inputs.
    pub entries_in: u64,
    /// Entries written to the outputs.
    pub entries_out: u64,
    /// Bytes of the input files.
    pub bytes_in: u64,
    /// Bytes of the output files.
    pub bytes_out: u64,
    /// Sub-ranges the job was split into (1: no subcompaction).
    pub subcompactions: usize,
}

/// One version of the current user key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    seqno: SeqNo,
    kind: ValueKind,
    value: Bytes,
}

/// Per-job context of [`compact_key`]; each sub-job copies it with its own filter instance.
#[derive(Clone, Copy)]
struct KeyContext<'a> {
    /// Live snapshot seqnos, ascending, deduplicated.
    snapshots: &'a [SeqNo],
    bottommost: bool,
    output_level: usize,
    filter: Option<&'a dyn CompactionFilter>,
}

impl KeyContext<'_> {
    /// Snapshot stripe of `seqno` (module docs): the number of snapshots below it.
    fn stripe(&self, seqno: SeqNo) -> usize {
        self.snapshots.partition_point(|&s| s < seqno)
    }
}

/// Reads and merges the inputs of `compaction` and writes the output files to `dir`.
///
/// `snapshots` are the seqnos of all live snapshots (any order). Contract: a snapshot taken after
/// the list was captured must read at a seqno >= every seqno in the inputs (true for the
/// engine, whose new snapshots read the visible seqno), otherwise it could need a dropped
/// version. Memory: all versions of one user key are buffered (bounded by how many versions a
/// key accumulates between compactions; a hot merge key is the worst case). `next_file_number` allocates
/// output file numbers (normally `VersionSet::new_file_number`, called under the engine's lock);
/// with parallel subcompactions it is called from several threads, one call at a time.
/// Nothing is installed: pass the result to [`install_compaction`].
///
/// A compaction is split into up to `options.max_subcompactions` sub-jobs (module docs).
///
/// # Errors
/// I/O and corruption errors from reading or writing (of any sub-job); all output files created
/// by this call, by every sub-job, are then removed (best effort; a leftover is an orphan that
/// startup deletes, §9).
///
/// # Panics
/// A panic in a sub-job is propagated after all sub-jobs have stopped.
pub fn run_compaction(
    fs: &dyn FileSystem,
    dir: &Path,
    compaction: &Compaction,
    options: &CompactionOptions,
    snapshots: &[SeqNo],
    filter: Option<&dyn CompactionFilter>,
    next_file_number: &mut (dyn FnMut() -> u64 + Send),
) -> Result<CompactionOutput> {
    let mut snapshots = snapshots.to_vec();
    snapshots.sort_unstable();
    snapshots.dedup();
    let job = Job {
        fs,
        dir,
        compaction,
        options,
        ctx: KeyContext {
            snapshots: &snapshots,
            bottommost: compaction.bottommost,
            output_level: compaction.output_level,
            filter,
        },
        next_file_number: Mutex::new(next_file_number),
        created: Mutex::new(Vec::new()),
        failed: AtomicBool::new(false),
    };
    let result = job.run();
    if result.is_err() {
        job.abandon();
    }
    result
}

/// A half-open user-key range `[start, end)` of one sub-job; `None` is unbounded.
#[derive(Debug, Clone, Default)]
struct SubRange {
    start: Option<Vec<u8>>,
    end: Option<Vec<u8>>,
}

impl SubRange {
    fn contains(&self, user_key: &[u8]) -> bool {
        self.start.as_deref().is_none_or(|s| s <= user_key)
            && self.end.as_deref().is_none_or(|e| user_key < e)
    }

    /// Whether `file` may hold an entry or tombstone of the range (its bounds cover both).
    fn overlaps(&self, file: &FileMeta) -> bool {
        self.start
            .as_deref()
            .is_none_or(|s| file.largest.user_key() >= s)
            && self
                .end
                .as_deref()
                .is_none_or(|e| file.smallest.user_key() < e)
    }
}

/// What one sub-job produced.
struct SubOutput {
    files: Vec<FileMeta>,
    entries_in: u64,
    entries_out: u64,
}

/// State of one [`run_compaction`] call, shared by its sub-jobs (module docs, "Concurrency").
struct Job<'a> {
    fs: &'a dyn FileSystem,
    dir: &'a Path,
    compaction: &'a Compaction,
    options: &'a CompactionOptions,
    ctx: KeyContext<'a>,
    /// The caller's allocator; behind a mutex because sub-jobs allocate concurrently.
    next_file_number: Mutex<&'a mut (dyn FnMut() -> u64 + Send)>,
    /// Every output file number handed out to any sub-job, for the cleanup on failure.
    created: Mutex<Vec<u64>>,
    /// Set by the first failing sub-job; the others stop at their next user key. Only an early
    /// exit hint: results and errors travel through the thread joins, which synchronise.
    failed: AtomicBool,
}

/// Locks `m`, ignoring poison: the guarded data (a number allocator, a list of numbers) has no
/// invariant a panicking holder could break halfway.
fn lock<T: ?Sized>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Job<'_> {
    fn reader_options(&self) -> SstReaderOptions {
        SstReaderOptions {
            prefix_extractor: self.options.writer.prefix_extractor.clone(),
            // Compaction reads every block once; caching them would evict the foreground working
            // set.
            block_cache: None,
            encryption: self.options.writer.encryption.clone(),
        }
    }

    fn run(&self) -> Result<CompactionOutput> {
        // Open every input once; sub-jobs share the readers (immutable, positional reads).
        let options = self.reader_options();
        let mut readers = Vec::with_capacity(self.compaction.inputs.len());
        for (_, file) in &self.compaction.inputs {
            let handle = self
                .fs
                .open(&self.dir.join(sst_file_name(file.number)), OpenMode::Read)?;
            readers.push(SstReader::open_numbered(
                handle,
                file.number,
                options.clone(),
            )?);
        }
        let ranges = self.sub_ranges(&readers)?;
        let results: Vec<Result<Option<SubOutput>>> =
            if ranges.len() > 1 && self.options.parallel_subcompactions {
                thread::scope(|scope| {
                    let readers = &readers;
                    let handles: Vec<_> = ranges[1..]
                        .iter()
                        .map(|range| scope.spawn(move || self.run_sub(readers, range)))
                        .collect();
                    // The calling thread takes the first sub-range instead of idling.
                    let mut results = vec![self.run_sub(readers, &ranges[0])];
                    let mut panic = None;
                    for handle in handles {
                        match handle.join() {
                            Ok(result) => results.push(result),
                            // Join every thread first, then re-raise (doc: Panics).
                            Err(payload) => {
                                self.failed.store(true, Ordering::Release);
                                panic.get_or_insert(payload);
                            }
                        }
                    }
                    if let Some(payload) = panic {
                        std::panic::resume_unwind(payload);
                    }
                    results
                })
            } else {
                ranges
                    .iter()
                    .map(|range| self.run_sub(&readers, range))
                    .collect()
            };

        let mut output = CompactionOutput {
            bytes_in: self.compaction.inputs.iter().map(|(_, f)| f.size).sum(),
            subcompactions: ranges.len(),
            ..CompactionOutput::default()
        };
        let mut first_error = None;
        for result in results {
            match result {
                Ok(Some(sub)) => {
                    output.files.extend(sub.files);
                    output.entries_in += sub.entries_in;
                    output.entries_out += sub.entries_out;
                }
                // Stopped because another sub-job failed; that one's error is reported.
                Ok(None) => {}
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        if let Some(e) = first_error {
            return Err(e);
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(StorageError::InvalidArgument(
                "subcompaction stopped without an error".into(),
            ));
        }
        // §9: all output names durable before the caller writes the MANIFEST edit; once for
        // all sub-jobs (each output file itself was fsynced by `SstWriter::finish`).
        if !output.files.is_empty() {
            self.fs.sync_dir(self.dir)?;
        }
        output.bytes_out = output.files.iter().map(|f| f.size).sum();
        Ok(output)
    }

    /// The sub-ranges of this job: one unbounded range unless `max_subcompactions > 1` and the
    /// inputs can be split (`picker::subcompaction_boundaries`).
    ///
    /// Ln → Ln+1 jobs are split too (PD-025): with random keys every base-level file overlaps
    /// L0, so the L0 drain waits for running base → next-level jobs (`picker::pick_l0` skips busy
    /// inputs); splitting those multi-GB jobs shortens that wait. The correctness argument is
    /// the L0 one unchanged — it never relied on the source level.
    fn sub_ranges(&self, readers: &[SstReader]) -> Result<Vec<SubRange>> {
        if self.options.max_subcompactions < 2 {
            return Ok(vec![SubRange::default()]);
        }
        let mut candidates = Vec::new();
        let mut tombstones = Vec::new();
        for reader in readers {
            tombstones.extend_from_slice(reader.range_tombstones());
            for separator in reader.data_block_separators()? {
                let parsed = ParsedKey::parse(&separator)
                    .map_err(|e| StorageError::corruption(format!("index separator: {e}")))?;
                candidates.push(parsed.user_key.to_vec());
            }
        }
        let bounds =
            subcompaction_boundaries(candidates, &tombstones, self.options.max_subcompactions);
        let mut ranges = Vec::with_capacity(bounds.len() + 1);
        let mut start = None;
        for bound in bounds {
            ranges.push(SubRange {
                start: start.take(),
                end: Some(bound.clone()),
            });
            start = Some(bound);
        }
        ranges.push(SubRange { start, end: None });
        Ok(ranges)
    }

    /// Runs one sub-job; `Ok(None)` when it stopped because another sub-job failed.
    fn run_sub(&self, readers: &[SstReader], range: &SubRange) -> Result<Option<SubOutput>> {
        let mut outputs = Outputs::new(self);
        let result = self
            .merge_range(readers, range, &mut outputs)
            .and_then(|stats| match stats {
                Some((entries_in, entries_out)) => outputs.finish().map(|files| {
                    Some(SubOutput {
                        files,
                        entries_in,
                        entries_out,
                    })
                }),
                None => Ok(None),
            });
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        // `outputs` drops here, closing an unfinished writer before `abandon` removes its file
        // (Windows cannot delete an open file).
        result
    }

    fn new_file_number(&self) -> u64 {
        let number = {
            let mut allocate = lock(&self.next_file_number);
            (*allocate)()
        };
        lock(&self.created).push(number);
        number
    }

    /// Removes every file any sub-job created (all writers are closed by now).
    fn abandon(&self) {
        for number in lock(&self.created).drain(..) {
            // Best effort: a leftover is an unreferenced orphan that startup cleanup deletes.
            drop(self.fs.remove_file(&self.dir.join(sst_file_name(number))));
        }
    }
}

/// Durably records the result of a compaction: inputs deleted, outputs added at the output level.
///
/// # Errors
/// [`StorageError::InvalidArgument`] if the edit violates a level invariant (e.g. the inputs were
/// already compacted away); MANIFEST I/O errors (fatal for the version set, see `version/set.rs`).
/// The output files are not removed here: after a non-I/O error the caller deletes them, after an
/// I/O error the record may be durable and the files are left for the next open.
pub fn install_compaction(
    versions: &mut VersionSet,
    compaction: &Compaction,
    output: &CompactionOutput,
) -> Result<()> {
    let edit = VersionEdit {
        deleted: compaction
            .inputs
            .iter()
            .map(|(level, f)| (*level, f.number))
            .collect(),
        added: output
            .files
            .iter()
            .map(|f| (compaction.output_level, f.clone()))
            .collect(),
        ..VersionEdit::default()
    };
    versions.log_and_apply(edit)
}

/// Deletes the SSTs no live version references (§11). `in_flight` are the numbers of files that
/// running flushes and compactions are writing. Returns how many files were deleted.
///
/// With encryption (§7) the DEKs of the deleted files are then dropped from the registry in one
/// rewrite (after the deletes, so a crash in between leaves only unused entries). Entries of
/// files that are already gone (e.g. outputs of a failed job) are dropped with them.
///
/// # Errors
/// Directory listing, removal or registry rewrite errors. A file that disappeared meanwhile is
/// not an error.
pub fn delete_obsolete_files(
    fs: &dyn FileSystem,
    versions: &VersionSet,
    in_flight: &BTreeSet<u64>,
) -> Result<usize> {
    let mut deleted = 0;
    let mut numbers = Vec::new();
    for path in versions.obsolete_files(in_flight)? {
        match fs.remove_file(&path) {
            Ok(()) => deleted += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if let Some(FileKind::Sst(n) | FileKind::Manifest(n)) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(parse_file_name)
        {
            numbers.push(n);
        }
    }
    if let Some(keys) = versions.encryption() {
        // Registry entries without a file and without a live reference: DEKs registered for
        // outputs that were never installed (failed job, crash before the MANIFEST edit).
        let live = versions.live_files();
        let present = present_numbers(fs, versions)?;
        numbers.extend(keys.file_numbers().into_iter().filter(|n| {
            !live.contains(n)
                && !in_flight.contains(n)
                && *n != versions.manifest_number()
                && !present.contains(n)
        }));
        keys.forget(&numbers)?;
    }
    Ok(deleted)
}

/// Numbers of the SSTs and MANIFESTs present in the version set's directory.
fn present_numbers(fs: &dyn FileSystem, versions: &VersionSet) -> Result<BTreeSet<u64>> {
    Ok(fs
        .read_dir(versions.dir())?
        .iter()
        .filter_map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(parse_file_name)
        })
        .filter_map(|kind| match kind {
            FileKind::Sst(n) | FileKind::Manifest(n) => Some(n),
            _ => None,
        })
        .collect())
}

impl Job<'_> {
    /// Streams the merged inputs of `range` key by key into `outputs`; returns `(entries in,
    /// entries out)`, or `None` when it stopped because another sub-job failed.
    fn merge_range(
        &self,
        readers: &[SstReader],
        range: &SubRange,
        outputs: &mut Outputs<'_, '_>,
    ) -> Result<Option<(u64, u64)>> {
        // A stateful filter gets one instance per sub-job: it sees the keys of this sub-range
        // in order and nothing of the others (`CompactionFilter::for_subcompaction`).
        let forked = self
            .ctx
            .filter
            .and_then(CompactionFilter::for_subcompaction);
        let local = KeyContext {
            filter: forked.as_deref().or(self.ctx.filter),
            ..self.ctx
        };
        let ctx = &local;
        let mut children: Vec<Box<dyn InternalIterator>> = Vec::new();
        let mut tombstones: Vec<RangeTombstone> = Vec::new();
        for ((_, file), reader) in self.compaction.inputs.iter().zip(readers) {
            if range.overlaps(file) {
                tombstones.extend_from_slice(reader.range_tombstones());
                children.push(Box::new(reader.new_iterator()));
            }
        }
        // Coverage uses every tombstone of the opened files (one starting in an earlier range
        // can still cover keys here only if it straddled the boundary, which the picker
        // excludes, but using them all costs nothing and needs no such argument).
        let coverage = FragmentedTombstones::new(&tombstones, MAX_SEQNO);
        tombstones.sort();
        tombstones.dedup();
        // Each tombstone is carried by exactly one sub-job: the one whose range holds its start
        // (it ends inside that range too, `picker::subcompaction_boundaries`).
        tombstones
            .retain(|t| range.contains(&t.start) && !(ctx.bottommost && ctx.stripe(t.seqno) == 0));
        outputs.tombstones = tombstones;
        let mut iter = MergingIterator::new(children);
        match &range.start {
            // Before every version of the first user key of the range.
            Some(start) => iter.seek(&seek_key(start, MAX_SEQNO))?,
            None => iter.seek_to_first()?,
        }

        let (mut entries_in, mut entries_out) = (0u64, 0u64);
        let mut user_key: Vec<u8> = Vec::new();
        let mut versions: Vec<Entry> = Vec::new();
        while iter.valid() {
            let parsed = ParsedKey::parse(iter.key())
                .map_err(|e| StorageError::corruption(format!("compaction input key: {e}")))?;
            if range
                .end
                .as_deref()
                .is_some_and(|end| parsed.user_key >= end)
            {
                break;
            }
            if parsed.user_key != user_key.as_slice() && !versions.is_empty() {
                if self.failed.load(Ordering::Acquire) {
                    return Ok(None);
                }
                let kept = compact_key(&user_key, &versions, ctx)?;
                entries_out += kept.len() as u64;
                outputs.add_key(&user_key, &kept)?;
                versions.clear();
            }
            if versions.is_empty() {
                user_key.clear();
                user_key.extend_from_slice(parsed.user_key);
            }
            entries_in += 1;
            // Covered by a newer tombstone with no snapshot in between: no reader sees it.
            let covered = coverage
                .oldest_covering_above(parsed.user_key, parsed.seqno)
                .is_some_and(|t| ctx.stripe(t) == ctx.stripe(parsed.seqno));
            if !covered {
                versions.push(Entry {
                    seqno: parsed.seqno,
                    kind: parsed.kind,
                    value: iter.value(),
                });
            }
            iter.next()?;
        }
        if !versions.is_empty() {
            let kept = compact_key(&user_key, &versions, ctx)?;
            entries_out += kept.len() as u64;
            outputs.add_key(&user_key, &kept)?;
        }
        Ok(Some((entries_in, entries_out)))
    }
}

/// Resolves the versions of one user key (newest first) per the module-level rules.
fn compact_key(user_key: &[u8], versions: &[Entry], ctx: &KeyContext<'_>) -> Result<Vec<Entry>> {
    let stripe = |seqno: SeqNo| ctx.stripe(seqno);
    let mut out = Vec::new();
    let mut start = 0;
    while start < versions.len() {
        let current = stripe(versions[start].seqno);
        let len = versions[start..]
            .iter()
            .take_while(|e| stripe(e.seqno) == current)
            .count();
        let end = start + len;
        resolve_stripe(&versions[start..end], end == versions.len(), ctx, &mut out)?;
        start = end;
    }

    if let (Some(filter), Some(newest)) = (ctx.filter, out.first_mut()) {
        let unprotected = stripe(newest.seqno) == ctx.snapshots.len();
        if unprotected
            && newest.kind == ValueKind::Put
            && filter.filter(ctx.output_level, user_key, &newest.value) == FilterDecision::Remove
        {
            newest.kind = ValueKind::Delete;
            newest.value = Bytes::new();
        }
    }
    if ctx.bottommost {
        // SingleDelete is handled like Delete here (conservative and correct; the "drop the
        // SingleDelete together with its Put" optimisation is not implemented).
        while out
            .last()
            .is_some_and(|e| matches!(e.kind, ValueKind::Delete | ValueKind::SingleDelete))
        {
            out.pop();
        }
    }
    Ok(out)
}

/// Appends the surviving entries of one snapshot stripe (newest first) to `out`.
fn resolve_stripe(
    stripe: &[Entry],
    oldest_stripe_of_key: bool,
    ctx: &KeyContext<'_>,
    out: &mut Vec<Entry>,
) -> Result<()> {
    let operands = stripe
        .iter()
        .take_while(|e| e.kind == ValueKind::Merge)
        .count();
    if operands == 0 {
        out.push(stripe[0].clone());
        return Ok(());
    }
    let newest = stripe[0].seqno;
    let ops = || stripe[..operands].iter().map(|e| e.value.as_ref());
    let base = stripe.get(operands);
    let merged = match base {
        Some(b) => Some(full_merge(
            (b.kind == ValueKind::Put).then_some(b.value.as_ref()),
            ops(),
        )),
        None if oldest_stripe_of_key && ctx.bottommost => Some(full_merge(None, ops())),
        None => None,
    };
    match merged {
        Some(Ok(value)) => out.push(Entry {
            seqno: newest,
            kind: ValueKind::Put,
            value: value.into(),
        }),
        // §8: keep operands (and base) unmerged; the read path reports RGN-1009 (overflow) or
        // RGN-5002 (undecodable or type-mixed data). Failing the job instead would make the
        // picker retry the same inputs forever and the level would never drain.
        Some(Err(StorageError::CounterOverflow | StorageError::Corruption(_))) => {
            let keep = if base.is_some() {
                operands + 1
            } else {
                operands
            };
            out.extend_from_slice(&stripe[..keep]);
        }
        Some(Err(e)) => return Err(e),
        None if operands == 1 => out.push(stripe[0].clone()),
        None => match partial_merge(ops()) {
            Ok(Some(value)) => out.push(Entry {
                seqno: newest,
                kind: ValueKind::Merge,
                value: value.into(),
            }),
            // Out of i64 or undecodable: keep the operands (see above).
            Ok(None) | Err(StorageError::Corruption(_)) => {
                out.extend_from_slice(&stripe[..operands]);
            }
            Err(e) => return Err(e),
        },
    }
    Ok(())
}

/// Output files of one (sub-)job, rolled over at the level's target size between user keys.
struct Outputs<'j, 'a> {
    job: &'j Job<'a>,
    compression: CompressionPolicy,
    target_size: u64,
    current: Option<(u64, SstWriter)>,
    files: Vec<FileMeta>,
    /// Tombstones to carry, sorted; `tombstones[next_tombstone..]` are not written yet.
    tombstones: Vec<RangeTombstone>,
    next_tombstone: usize,
    /// Largest tombstone end written to the current file (split rule, module docs).
    current_max_end: Option<Vec<u8>>,
}

impl<'j, 'a> Outputs<'j, 'a> {
    fn new(job: &'j Job<'a>) -> Self {
        Self {
            job,
            compression: CompressionPolicy::for_level(
                job.compaction.output_level,
                job.compaction.bottommost,
                job.options.bottommost_zstd_level,
            ),
            target_size: job.options.target_file_size(job.compaction.output_level),
            current: None,
            files: Vec::new(),
            tombstones: Vec::new(),
            next_tombstone: 0,
            current_max_end: None,
        }
    }

    fn open_if_needed(&mut self) -> Result<&mut SstWriter> {
        if self.current.is_none() {
            // Recorded as created before the file exists, so a failed open is also cleaned up.
            let number = self.job.new_file_number();
            let path = self.job.dir.join(sst_file_name(number));
            let file = self.job.fs.open(&path, OpenMode::CreateNew)?;
            let mut writer_options = self.job.options.writer.clone();
            writer_options.compression = self.compression;
            self.current = Some((number, SstWriter::create(file, number, writer_options)?));
        }
        self.current
            .as_mut()
            .map(|(_, writer)| writer)
            .ok_or_else(|| StorageError::InvalidArgument("output writer missing".into()))
    }

    /// Writes the pending tombstones whose start satisfies `due` into the current file.
    fn write_tombstones(&mut self, due: impl Fn(&[u8]) -> bool) -> Result<()> {
        while let Some(t) = self.tombstones.get(self.next_tombstone) {
            if !due(&t.start) {
                break;
            }
            let t = t.clone();
            self.next_tombstone += 1;
            if self.current_max_end.as_ref().is_none_or(|e| t.end > *e) {
                self.current_max_end = Some(t.end.clone());
            }
            self.open_if_needed()?.add_range_tombstone(t)?;
        }
        Ok(())
    }

    fn add_key(&mut self, user_key: &[u8], entries: &[Entry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        // Tombstones starting before this key belong to the current file (split rule).
        self.write_tombstones(|start| start < user_key)?;
        let full = self
            .current
            .as_ref()
            .is_some_and(|(_, w)| w.estimated_file_size() >= self.target_size);
        let clear_of_tombstones = self
            .current_max_end
            .as_ref()
            .is_none_or(|end| end.as_slice() < user_key);
        if full && clear_of_tombstones {
            self.finish_current()?;
        }
        self.write_tombstones(|start| start <= user_key)?;
        let writer = self.open_if_needed()?;
        for e in entries {
            writer.add(
                InternalKey::new(user_key, e.seqno, e.kind).as_bytes(),
                &e.value,
            )?;
        }
        Ok(())
    }

    fn finish_current(&mut self) -> Result<()> {
        self.current_max_end = None;
        let Some((number, writer)) = self.current.take() else {
            return Ok(());
        };
        let info = writer.finish()?;
        let (Some(smallest), Some(largest)) = (info.smallest, info.largest) else {
            return Err(StorageError::InvalidArgument(
                "compaction output without entries".into(),
            ));
        };
        self.files.push(FileMeta {
            number,
            size: info.file_size,
            smallest,
            largest,
            smallest_seqno: info.properties.min_seqno,
            largest_seqno: info.properties.max_seqno,
        });
        Ok(())
    }

    /// Finishes the last output (each output is fsynced; the directory is fsynced once for all
    /// sub-jobs by `Job::run`, §9).
    fn finish(&mut self) -> Result<Vec<FileMeta>> {
        self.write_tombstones(|_| true)?;
        self.finish_current()?;
        Ok(std::mem::take(&mut self.files))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::MergeOperand;

    struct DropPrefix(&'static [u8]);
    impl CompactionFilter for DropPrefix {
        fn filter(&self, _level: usize, user_key: &[u8], _value: &[u8]) -> FilterDecision {
            if user_key.starts_with(self.0) {
                FilterDecision::Remove
            } else {
                FilterDecision::Keep
            }
        }
    }

    fn e(seqno: SeqNo, kind: ValueKind, value: &[u8]) -> Entry {
        Entry {
            seqno,
            kind,
            value: Bytes::copy_from_slice(value),
        }
    }

    fn op(delta: i64) -> Vec<u8> {
        MergeOperand::CounterDelta(delta).encode()
    }

    fn ctx(snapshots: &[SeqNo], bottommost: bool) -> KeyContext<'_> {
        KeyContext {
            snapshots,
            bottommost,
            output_level: 6,
            filter: None,
        }
    }

    #[test]
    fn newest_put_shadows_older_versions_without_snapshots() {
        let v = [e(9, ValueKind::Put, b"new"), e(5, ValueKind::Put, b"old")];
        let out = compact_key(b"k", &v, &ctx(&[], false)).unwrap();
        assert_eq!(out, [e(9, ValueKind::Put, b"new")]);
    }

    #[test]
    fn snapshot_keeps_the_version_it_reads() {
        let v = [
            e(9, ValueKind::Put, b"c"),
            e(6, ValueKind::Put, b"b"),
            e(5, ValueKind::Put, b"a"),
        ];
        // Snapshot 7 reads seqno 6; seqno 5 is shadowed in the same stripe.
        let out = compact_key(b"k", &v, &ctx(&[7], false)).unwrap();
        assert_eq!(
            out,
            [e(9, ValueKind::Put, b"c"), e(6, ValueKind::Put, b"b")]
        );
    }

    #[test]
    fn tombstone_dropped_only_at_bottommost() {
        let v = [e(9, ValueKind::Delete, b""), e(5, ValueKind::Put, b"a")];
        assert_eq!(
            compact_key(b"k", &v, &ctx(&[], false)).unwrap(),
            [e(9, ValueKind::Delete, b"")]
        );
        assert_eq!(compact_key(b"k", &v, &ctx(&[], true)).unwrap(), []);
        // A snapshot at 7 still needs the Put; the tombstone stays above it.
        assert_eq!(compact_key(b"k", &v, &ctx(&[7], true)).unwrap(), v);
    }

    #[test]
    fn operands_fold_into_put_over_base_and_into_operand_without() {
        let v = [
            e(9, ValueKind::Merge, &op(2)),
            e(8, ValueKind::Merge, &op(3)),
            e(5, ValueKind::Put, &op(10)),
        ];
        assert_eq!(
            compact_key(b"k", &v, &ctx(&[], false)).unwrap(),
            [e(9, ValueKind::Put, &op(15))]
        );
        let ops = &v[..2];
        assert_eq!(
            compact_key(b"k", ops, &ctx(&[], false)).unwrap(),
            [e(9, ValueKind::Merge, &op(5))]
        );
        // Bottommost with nothing older: the run becomes a value.
        assert_eq!(
            compact_key(b"k", ops, &ctx(&[], true)).unwrap(),
            [e(9, ValueKind::Put, &op(5))]
        );
    }

    #[test]
    fn compaction_keeps_operands_when_full_merge_overflows() {
        // §8: an overflowing sum must not fail the job nor be materialised.
        let v = [
            e(9, ValueKind::Merge, &op(i64::MAX)),
            e(5, ValueKind::Put, &op(1)),
        ];
        assert_eq!(compact_key(b"k", &v, &ctx(&[], true)).unwrap(), v);
        let ops = [
            e(9, ValueKind::Merge, &op(i64::MAX)),
            e(8, ValueKind::Merge, &op(i64::MAX)),
        ];
        assert_eq!(compact_key(b"k", &ops, &ctx(&[], false)).unwrap(), ops);
        assert_eq!(compact_key(b"k", &ops, &ctx(&[], true)).unwrap(), ops);
    }

    #[test]
    fn compaction_keeps_undecodable_operands_instead_of_failing() {
        // A merge operand over a document value (not a merge encoding) is RGN-5002 at read;
        // compaction must keep both and go on, or the level would never drain.
        let v = [
            e(9, ValueKind::Merge, &op(2)),
            e(5, ValueKind::Put, b"{\"doc\":1}"),
        ];
        assert_eq!(compact_key(b"k", &v, &ctx(&[], true)).unwrap(), v);
        let garbage = [
            e(9, ValueKind::Merge, b"\xff\xff"),
            e(8, ValueKind::Merge, &op(1)),
        ];
        assert_eq!(
            compact_key(b"k", &garbage, &ctx(&[], false)).unwrap(),
            garbage
        );
    }

    #[test]
    fn tc_sto_004_filter_never_touches_snapshot_protected_versions() {
        let filter = DropPrefix(b"gc/");
        let mut c = ctx(&[], true);
        c.filter = Some(&filter);
        let v = [e(9, ValueKind::Put, b"x")];
        assert_eq!(compact_key(b"gc/1", &v, &c).unwrap(), []);
        assert_eq!(compact_key(b"live", &v, &c).unwrap(), v);

        // Not bottommost: the removed value becomes a tombstone hiding lower levels.
        c.bottommost = false;
        assert_eq!(
            compact_key(b"gc/1", &v, &c).unwrap(),
            [e(9, ValueKind::Delete, b"")]
        );

        // A snapshot at 9 reads the value: the filter is not consulted.
        let snaps = [9];
        c.snapshots = &snaps;
        assert_eq!(compact_key(b"gc/1", &v, &c).unwrap(), v);
    }
}
