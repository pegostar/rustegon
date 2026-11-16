// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Leveled compaction integration tests (storage-engine.md §3, §8; TC-STO-004): random workloads
//! of puts, deletes, merge operands and snapshots are flushed and compacted until the picker is
//! quiet; every snapshot must still read exactly what a model reads, obsolete files must be gone
//! and the store must reopen.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

use bytes::Bytes;
use proptest::prelude::*;
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{FileSystem, OpenMode};
use rustegon_storage::{
    MAX_SEQNO, Memtable, ParsedKey, SeqNo, ValueKind,
    compaction::{
        Compaction, CompactionFilter, CompactionOptions, CompactionOutput, FilterDecision,
        delete_obsolete_files, install_compaction, pick_compaction, run_compaction,
    },
    flush_memtable,
    iter::{InternalIterator, MergingIterator},
    merge::{MergeOperand, full_merge},
    sst::{SstReader, SstReaderOptions, SstWriterOptions},
    version::{FileKind, FileMeta, NUM_LEVELS, VersionSet, parse_file_name, sst_file_name},
};

const DIR: &str = "/store";
const LAST_LEVEL: usize = NUM_LEVELS - 1;

/// Tiny shapes so that a few hundred entries already span several levels and output files.
fn options() -> CompactionOptions {
    CompactionOptions {
        l0_trigger: 2,
        level_base_bytes: 4 << 10,
        level_multiplier: 4,
        target_file_size_base: 2 << 10,
        max_target_file_size: 4 << 10,
        writer: SstWriterOptions {
            block_size: 256,
            ..SstWriterOptions::default()
        },
        ..CompactionOptions::default()
    }
}

#[derive(Debug, Clone)]
enum Op {
    Put(u8, u8),
    Delete(u8),
    Merge(u8, i8),
    DeleteRange(u8, u8),
    Snapshot,
    Flush,
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (0u8..40, any::<u8>()).prop_map(|(k, v)| Op::Put(k, v)),
        2 => (0u8..40).prop_map(Op::Delete),
        3 => (40u8..48, any::<i8>()).prop_map(|(k, d)| Op::Merge(k, d)),
        1 => (0u8..48, 1u8..10).prop_map(|(a, len)| Op::DeleteRange(a, a.saturating_add(len))),
        1 => Just(Op::Snapshot),
        1 => Just(Op::Flush),
    ]
}

fn user_key(k: u8) -> Vec<u8> {
    // Long keys and values so that files fill up quickly.
    format!("key-{k:03}-{}", "x".repeat(40)).into_bytes()
}

/// 200 incompressible bytes derived from `(k, v)` (xorshift64), so file sizes do not collapse
/// under LZ4/Zstd and outputs really reach their target size.
fn noise(k: u8, v: u8) -> Vec<u8> {
    let mut x = (u64::from(k) << 8 | u64::from(v)) ^ 0x9E37_79B9_7F4A_7C15;
    (0..200)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Versions of one user key, newest first, as `(seqno, kind, value)`.
type Versions = Vec<(SeqNo, ValueKind, Vec<u8>)>;

/// `(start, end, seqno)` range tombstones.
type Tombstones = Vec<(Vec<u8>, Vec<u8>, SeqNo)>;

/// What a reader at `snapshot` sees: newest visible full value, with merge operands above it
/// folded in (storage-engine.md §8); versions older than a visible covering range tombstone
/// read as deleted.
fn read_at(
    key: &[u8],
    versions: &Versions,
    tombstones: &Tombstones,
    snapshot: SeqNo,
) -> Option<Vec<u8>> {
    let cutoff = tombstones
        .iter()
        .filter(|(s, e, seq)| *seq <= snapshot && s.as_slice() <= key && key < e.as_slice())
        .map(|t| t.2)
        .max()
        .unwrap_or(0);
    let mut operands: Vec<&[u8]> = Vec::new();
    for (seqno, kind, value) in versions.iter().filter(|v| v.0 <= snapshot) {
        let kind = if *seqno < cutoff {
            &ValueKind::Delete
        } else {
            kind
        };
        match kind {
            ValueKind::Merge => operands.push(value),
            ValueKind::Put if operands.is_empty() => return Some(value.clone()),
            ValueKind::Put => return Some(full_merge(Some(value), operands).unwrap()),
            ValueKind::Delete | ValueKind::SingleDelete => break,
            ValueKind::RangeDelete => unreachable!("not a point entry"),
        }
    }
    (!operands.is_empty()).then(|| full_merge(None, operands).unwrap())
}

/// All entries and range tombstones of the live SSTs, read through the merging iterator.
fn stored(fs: &dyn FileSystem, versions: &VersionSet) -> (BTreeMap<Vec<u8>, Versions>, Tombstones) {
    let mut children: Vec<Box<dyn InternalIterator>> = Vec::new();
    let mut tombstones = Tombstones::new();
    for (_, f) in versions.current().all_files() {
        let file = fs
            .open(
                &Path::new(DIR).join(sst_file_name(f.number)),
                OpenMode::Read,
            )
            .unwrap();
        let reader = SstReader::open(file, SstReaderOptions::default()).unwrap();
        tombstones.extend(
            reader
                .range_tombstones()
                .iter()
                .map(|t| (t.start.clone(), t.end.clone(), t.seqno)),
        );
        children.push(Box::new(reader.new_iterator()));
    }
    let mut it = MergingIterator::new(children);
    it.seek_to_first().unwrap();
    let mut out: BTreeMap<Vec<u8>, Versions> = BTreeMap::new();
    while it.valid() {
        let p = ParsedKey::parse(it.key()).unwrap();
        out.entry(p.user_key.to_vec())
            .or_default()
            .push((p.seqno, p.kind, it.value().to_vec()));
        it.next().unwrap();
    }
    (out, tombstones)
}

fn sst_on_disk(fs: &dyn FileSystem) -> BTreeSet<u64> {
    fs.read_dir(Path::new(DIR))
        .unwrap()
        .iter()
        .filter_map(|p| match parse_file_name(p.file_name()?.to_str()?) {
            Some(FileKind::Sst(n)) => Some(n),
            _ => None,
        })
        .collect()
}

/// Compacts until the picker finds nothing; returns the number of compactions run.
fn compact_until_quiet(
    fs: &dyn FileSystem,
    versions: &mut VersionSet,
    options: &CompactionOptions,
    snapshots: &[SeqNo],
    filter: Option<&dyn CompactionFilter>,
) -> usize {
    let mut runs = 0;
    loop {
        // Bind and drop the version explicitly: a temporary in a `while let` scrutinee would pin
        // it for the whole body and keep the inputs from being deleted.
        let current = versions.current();
        let Some(c) = pick_compaction(&current, options, &BTreeSet::new()) else {
            break;
        };
        drop(current);
        let out = run_compaction(
            fs,
            Path::new(DIR),
            &c,
            options,
            snapshots,
            filter,
            &mut || versions.new_file_number(),
        )
        .unwrap();
        install_compaction(versions, &c, &out).unwrap();
        delete_obsolete_files(fs, versions, &BTreeSet::new()).unwrap();
        runs += 1;
        assert!(runs < 1000, "compaction does not converge");
    }
    runs
}

struct Store {
    fs: Arc<SimFileSystem>,
    versions: VersionSet,
    memtable: Memtable,
    seqno: SeqNo,
    model: BTreeMap<Vec<u8>, Versions>,
    tombstones: Tombstones,
    snapshots: Vec<SeqNo>,
    compactions: usize,
}

impl Store {
    fn new() -> Self {
        let fs = Arc::new(SimFileSystem::new());
        let versions = VersionSet::create(fs.clone(), Path::new(DIR)).unwrap();
        Self {
            fs,
            versions,
            memtable: Memtable::new(),
            seqno: 0,
            model: BTreeMap::new(),
            tombstones: Tombstones::new(),
            snapshots: Vec::new(),
            compactions: 0,
        }
    }

    fn write(&mut self, key: Vec<u8>, kind: ValueKind, value: Vec<u8>) {
        self.seqno += 1;
        self.memtable
            .add(self.seqno, kind, &key, Bytes::from(value.clone()));
        self.model
            .entry(key)
            .or_default()
            .insert(0, (self.seqno, kind, value));
    }

    fn apply(&mut self, op: &Op, options: &CompactionOptions) {
        match *op {
            Op::Put(k, v) => self.write(user_key(k), ValueKind::Put, noise(k, v)),
            Op::Delete(k) => self.write(user_key(k), ValueKind::Delete, Vec::new()),
            Op::Merge(k, d) => self.write(
                user_key(k),
                ValueKind::Merge,
                MergeOperand::CounterDelta(i64::from(d)).encode(),
            ),
            Op::DeleteRange(a, b) => {
                self.seqno += 1;
                let (start, end) = (user_key(a), user_key(b));
                self.memtable.add_range_tombstone(self.seqno, &start, &end);
                self.tombstones.push((start, end, self.seqno));
            }
            Op::Snapshot => self.snapshots.push(self.seqno),
            Op::Flush => self.flush(options),
        }
    }

    fn flush(&mut self, options: &CompactionOptions) {
        let memtable = std::mem::take(&mut self.memtable);
        flush_memtable(
            self.fs.as_ref(),
            Path::new(DIR),
            &mut self.versions,
            &memtable,
            &options.writer,
            self.seqno,
        )
        .unwrap();
        self.compactions += compact_until_quiet(
            self.fs.as_ref(),
            &mut self.versions,
            options,
            &self.snapshots,
            None,
        );
    }

    /// Flushes the memtable into a new L0 file without compacting.
    fn flush_to_l0(&mut self, options: &CompactionOptions) {
        let memtable = std::mem::take(&mut self.memtable);
        flush_memtable(
            self.fs.as_ref(),
            Path::new(DIR),
            &mut self.versions,
            &memtable,
            &options.writer,
            self.seqno,
        )
        .unwrap();
    }

    /// Runs `c` with `options` without installing it; `allocated` receives the output numbers.
    fn run(
        &mut self,
        c: &Compaction,
        options: &CompactionOptions,
        allocated: &mut Vec<u64>,
    ) -> rustegon_storage::Result<CompactionOutput> {
        let versions = &mut self.versions;
        run_compaction(
            self.fs.as_ref(),
            Path::new(DIR),
            c,
            options,
            &self.snapshots,
            None,
            &mut || {
                let n = versions.new_file_number();
                allocated.push(n);
                n
            },
        )
    }

    /// Every snapshot (and the latest state) reads what the model reads.
    fn check(&self) {
        let (stored, stored_tombstones) = stored(self.fs.as_ref(), &self.versions);
        let keys: BTreeSet<&Vec<u8>> = self.model.keys().chain(stored.keys()).collect();
        let empty = Vec::new();
        for snap in self.snapshots.iter().copied().chain([MAX_SEQNO]) {
            for key in &keys {
                let model = self.model.get(*key).unwrap_or(&empty);
                let want = read_at(key, model, &self.tombstones, snap);
                let got = read_at(
                    key,
                    stored.get(*key).unwrap_or(&empty),
                    &stored_tombstones,
                    snap,
                );
                assert_eq!(got, want, "key {key:?} at snapshot {snap}");
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// TC-STO-004 (correctness part): compaction preserves every snapshot's view, keeps the
    /// level invariants (checked by `VersionSet` on every install), deletes obsolete inputs and
    /// survives a reopen.
    #[test]
    fn tc_sto_004_compaction_preserves_every_snapshot_view(
        ops in proptest::collection::vec(arb_op(), 50..600),
    ) {
        let options = options();
        let mut store = Store::new();
        for op in &ops {
            store.apply(op, &options);
        }
        store.flush(&options);
        store.check();

        let live = store.versions.live_files();
        prop_assert_eq!(sst_on_disk(store.fs.as_ref()), live);
        let reopened = VersionSet::open(store.fs.clone(), Path::new(DIR)).unwrap();
        prop_assert_eq!(&*reopened.current(), &*store.versions.current());
    }
}

/// A larger workload spreads over several levels and splits outputs at the target size without
/// splitting a user key (the L1+ disjointness check in `VersionSet` would reject that).
#[test]
fn compaction_builds_multiple_levels_and_splits_outputs() {
    // Unsplit: the exact shape below (every older version compacted away) is the one of single
    // jobs. Subcompactions cut outputs elsewhere, so a key's older version may legitimately rest
    // one level lower while the level above is within target; the split run checks only that
    // a level never holds two versions of a key (and `check` that reads see the newest).
    for options in [unsplit(), options()] {
        let strict = options.max_subcompactions == 1;
        let mut store = Store::new();
        for round in 0u8..40 {
            for k in 0u8..40 {
                store.apply(&Op::Put(k, round), &options);
            }
            store.apply(&Op::Flush, &options);
        }
        store.check();
        let current = store.versions.current();
        let populated: Vec<usize> = (1..NUM_LEVELS)
            .filter(|&l| !current.files(l).is_empty())
            .collect();
        assert!(store.compactions > 0);
        assert!(
            current.files(0).len() < options.l0_trigger,
            "L0 drained below the trigger"
        );
        let bottom = *populated.last().unwrap();
        let files = current.files(bottom);
        assert!(files.len() > 1, "outputs split at the target file size");
        // No snapshots: one version per key per level (and, unsplit, one version in total).
        let (stored, _) = stored(store.fs.as_ref(), &store.versions);
        assert_eq!(stored.len(), 40);
        let most = if strict { 1 } else { populated.len() };
        assert!(stored.values().all(|v| v.len() <= most), "strict: {strict}");
    }
}

/// Deleting everything and compacting at the bottommost level drops the tombstones as well.
#[test]
fn bottommost_compaction_drops_tombstones_and_shadowed_values() {
    let options = options();
    let mut store = Store::new();
    for k in 0u8..40 {
        store.apply(&Op::Put(k, 1), &options);
    }
    store.apply(&Op::Flush, &options);
    for k in 0u8..40 {
        store.apply(&Op::Delete(k), &options);
    }
    store.apply(&Op::Flush, &options);
    store.flush(&options);
    // l0_trigger = 2: the two flushes were compacted into the (bottommost) base level.
    store.check();
    assert!(stored(store.fs.as_ref(), &store.versions).0.is_empty());
}

struct DropGc;
impl CompactionFilter for DropGc {
    fn filter(&self, _level: usize, user_key: &[u8], _value: &[u8]) -> FilterDecision {
        if user_key.starts_with(b"gc/") {
            FilterDecision::Remove
        } else {
            FilterDecision::Keep
        }
    }
}

/// TC-STO-004 (GC filter part): the filter removes unprotected values; values a snapshot reads
/// survive.
#[test]
fn tc_sto_004_gc_filter_respects_snapshots() {
    let options = options();
    let mut store = Store::new();
    store.write(b"gc/old".to_vec(), ValueKind::Put, b"v1".to_vec());
    store.write(b"keep".to_vec(), ValueKind::Put, b"v2".to_vec());
    store.snapshots.push(store.seqno);
    store.write(b"gc/new".to_vec(), ValueKind::Put, b"v3".to_vec());
    let memtable = std::mem::take(&mut store.memtable);
    flush_memtable(
        store.fs.as_ref(),
        Path::new(DIR),
        &mut store.versions,
        &memtable,
        &options.writer,
        store.seqno,
    )
    .unwrap();
    let forced = CompactionOptions {
        l0_trigger: 1,
        ..options.clone()
    };
    let runs = compact_until_quiet(
        store.fs.as_ref(),
        &mut store.versions,
        &forced,
        &store.snapshots,
        Some(&DropGc),
    );
    assert_eq!(runs, 1);
    let (stored, _) = stored(store.fs.as_ref(), &store.versions);
    let keys: Vec<&[u8]> = stored.keys().map(Vec::as_slice).collect();
    // gc/old is read by the snapshot; gc/new is newer than every snapshot and is dropped.
    assert_eq!(keys, [b"gc/old".as_slice(), b"keep"]);
}

/// Subcompaction tests (TC-STO-004, NFR-PERF-005): options that do not split, so the stores are
/// built by single jobs and only the compaction under test is split.
fn unsplit() -> CompactionOptions {
    CompactionOptions {
        max_subcompactions: 1,
        ..options()
    }
}

/// The test shapes forced to pick the L0 compaction, split into up to `max` sub-jobs.
fn split(max: usize, parallel: bool) -> CompactionOptions {
    CompactionOptions {
        l0_trigger: 1,
        max_subcompactions: max,
        parallel_subcompactions: parallel,
        ..options()
    }
}

/// All entries of `files` in file order and all their range tombstones, sorted: what readers
/// can observe of a compaction's output, independent of where the files are cut.
type Contents = (Vec<(Vec<u8>, Vec<u8>)>, Tombstones);

fn contents(fs: &dyn FileSystem, files: &[FileMeta]) -> Contents {
    let mut entries = Vec::new();
    let mut tombstones = Tombstones::new();
    for f in files {
        let file = fs
            .open(
                &Path::new(DIR).join(sst_file_name(f.number)),
                OpenMode::Read,
            )
            .unwrap();
        let reader = SstReader::open(file, SstReaderOptions::default()).unwrap();
        tombstones.extend(
            reader
                .range_tombstones()
                .iter()
                .map(|t| (t.start.clone(), t.end.clone(), t.seqno)),
        );
        let mut it = reader.new_iterator();
        it.seek_to_first().unwrap();
        while it.valid() {
            entries.push((it.key().to_vec(), it.value().to_vec()));
            it.next().unwrap();
        }
    }
    tombstones.sort();
    (entries, tombstones)
}

fn remove_outputs(fs: &dyn FileSystem, files: &[FileMeta]) {
    for f in files {
        fs.remove_file(&Path::new(DIR).join(sst_file_name(f.number)))
            .unwrap();
    }
}

/// The pending L0 compaction of `store` (forced by `l0_trigger = 1`).
fn l0_compaction(store: &Store) -> Compaction {
    let current = store.versions.current();
    let c = pick_compaction(&current, &split(1, false), &BTreeSet::new()).unwrap();
    assert_eq!(c.level, 0, "the forced compaction is the L0 one");
    c
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// TC-STO-004 (subcompactions): splitting the L0 compaction into sub-jobs, run sequentially
    /// or on parallel threads, writes exactly the entries and range tombstones of a single job
    /// (same order, same versions, same merged operands); the installed result keeps every
    /// snapshot's view and the level invariants.
    #[test]
    fn tc_sto_004_subcompactions_equal_single_job(
        before in proptest::collection::vec(arb_op(), 20..300),
        l0 in proptest::collection::vec(arb_op(), 20..300),
        max in 2usize..9,
    ) {
        let base = unsplit();
        let mut store = Store::new();
        for op in &before {
            store.apply(op, &base);
        }
        store.flush(&base);
        for op in &l0 {
            match op {
                Op::Flush => store.flush_to_l0(&base),
                op => store.apply(op, &base),
            }
        }
        store.flush_to_l0(&base);
        let c = l0_compaction(&store);

        let single = store.run(&c, &split(1, false), &mut Vec::new()).unwrap();
        prop_assert_eq!(single.subcompactions, 1);
        let want = contents(store.fs.as_ref(), &single.files);
        remove_outputs(store.fs.as_ref(), &single.files);
        for parallel in [false, true] {
            let out = store.run(&c, &split(max, parallel), &mut Vec::new()).unwrap();
            prop_assert!(out.subcompactions <= max);
            prop_assert_eq!(&contents(store.fs.as_ref(), &out.files), &want);
            prop_assert_eq!(
                (out.entries_in, out.entries_out),
                (single.entries_in, single.entries_out)
            );
            if parallel {
                // The VersionSet checks the L1+ disjointness of all sub-jobs' outputs here.
                install_compaction(&mut store.versions, &c, &out).unwrap();
            } else {
                remove_outputs(store.fs.as_ref(), &out.files);
            }
        }
        delete_obsolete_files(store.fs.as_ref(), &store.versions, &BTreeSet::new()).unwrap();
        store.check();
        prop_assert_eq!(sst_on_disk(store.fs.as_ref()), store.versions.live_files());
    }
}

/// A level-to-level compaction of `store`: every file of the deepest non-empty level `l` above
/// another non-empty level, plus every file of the next non-empty level `l + 1`. `None` when
/// the store has fewer than two adjacent non-empty L1+ levels.
fn level_compaction(store: &Store) -> Option<Compaction> {
    let current = store.versions.current();
    let level = (1..LAST_LEVEL)
        .rev()
        .find(|&l| !current.files(l).is_empty() && !current.files(l + 1).is_empty())?;
    let inputs = [level, level + 1]
        .into_iter()
        .flat_map(|l| current.files(l).iter().map(move |f| (l, Arc::clone(f))))
        .collect();
    Some(Compaction {
        level,
        output_level: level + 1,
        inputs,
        bottommost: (level + 2..=LAST_LEVEL).all(|l| current.files(l).is_empty()),
        score: 1000,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// TC-STO-004 (subcompactions of L1+ compactions, PD-025): a level-to-level compaction split
    /// into sub-jobs, sequential or parallel, writes exactly the entries and range tombstones of
    /// a single job, and the installed result keeps every snapshot's view and the invariants.
    #[test]
    fn tc_sto_004_level_subcompactions_equal_single_job(
        ops in proptest::collection::vec(arb_op(), 200..600),
        max in 2usize..9,
    ) {
        let base = unsplit();
        let mut store = Store::new();
        for op in &ops {
            store.apply(op, &base);
        }
        store.flush(&base);
        let Some(c) = level_compaction(&store) else {
            return Ok(());
        };
        let single = store.run(&c, &unsplit(), &mut Vec::new()).unwrap();
        prop_assert_eq!(single.subcompactions, 1);
        let want = contents(store.fs.as_ref(), &single.files);
        remove_outputs(store.fs.as_ref(), &single.files);
        for parallel in [false, true] {
            let options = CompactionOptions {
                max_subcompactions: max,
                parallel_subcompactions: parallel,
                ..options()
            };
            let out = store.run(&c, &options, &mut Vec::new()).unwrap();
            prop_assert!(out.subcompactions <= max);
            prop_assert_eq!(&contents(store.fs.as_ref(), &out.files), &want);
            if parallel {
                install_compaction(&mut store.versions, &c, &out).unwrap();
            } else {
                remove_outputs(store.fs.as_ref(), &out.files);
            }
        }
        delete_obsolete_files(store.fs.as_ref(), &store.versions, &BTreeSet::new()).unwrap();
        store.check();
        prop_assert_eq!(sst_on_disk(store.fs.as_ref()), store.versions.live_files());
    }
}

/// TC-STO-004 (PD-025): a level-to-level compaction over many data blocks is really split
/// (the proptest above would pass vacuously if L1+ jobs never split).
#[test]
fn tc_sto_004_level_compactions_are_split() {
    let base = unsplit();
    let mut store = Store::new();
    for round in 0u8..6 {
        for k in 0u8..=255 {
            store.apply(&Op::Put(k, round), &base);
        }
        store.flush(&base);
    }
    let c = level_compaction(&store).expect("two adjacent non-empty L1+ levels");
    let options = CompactionOptions {
        max_subcompactions: 4,
        parallel_subcompactions: true,
        ..options()
    };
    let out = store.run(&c, &options, &mut Vec::new()).unwrap();
    assert!(out.subcompactions > 1, "got {}", out.subcompactions);
    install_compaction(&mut store.versions, &c, &out).unwrap();
    store.check();
}

/// A store whose L0 compaction has range tombstones across many data blocks and a hot merge
/// key whose operands (with a snapshot between them) span several blocks.
fn boundary_store() -> Store {
    let base = unsplit();
    let mut store = Store::new();
    for k in 0u8..40 {
        store.apply(&Op::Put(k, 1), &base);
    }
    store.flush(&base);
    store.apply(&Op::Snapshot, &base);
    for d in 0..60i8 {
        store.apply(&Op::Merge(44, d), &base);
    }
    for k in (0u8..40).step_by(2) {
        store.apply(&Op::Put(k, 2), &base);
    }
    store.flush_to_l0(&base);
    store.apply(&Op::DeleteRange(10, 30), &base);
    store.apply(&Op::DeleteRange(33, 35), &base);
    store.apply(&Op::Snapshot, &base);
    for k in (1u8..40).step_by(2) {
        store.apply(&Op::Put(k, 3), &base);
    }
    for d in 0..20i8 {
        store.apply(&Op::Merge(44, -d), &base);
    }
    store.flush_to_l0(&base);
    store
}

/// TC-STO-004 (subcompaction boundaries): range tombstones are carried whole by exactly one
/// sub-job and never cut by a boundary, and every version of the hot merge key (both snapshot
/// stripes) is resolved by one sub-job into one file; the result equals a single job's.
#[test]
fn tc_sto_004_subcompaction_boundaries_keep_range_tombstones_and_merges_whole() {
    for parallel in [false, true] {
        let mut store = boundary_store();
        let c = l0_compaction(&store);
        let single = store.run(&c, &split(1, false), &mut Vec::new()).unwrap();
        let want = contents(store.fs.as_ref(), &single.files);
        remove_outputs(store.fs.as_ref(), &single.files);
        assert_eq!(
            want.1.len(),
            2,
            "both tombstones carried (a snapshot protects them)"
        );

        let out = store.run(&c, &split(8, parallel), &mut Vec::new()).unwrap();
        assert!(out.subcompactions > 2, "split into {}", out.subcompactions);
        assert_eq!(contents(store.fs.as_ref(), &out.files), want);
        // Each tombstone lies wholly inside one output file.
        for (start, end, _) in &want.1 {
            let holders = out
                .files
                .iter()
                .filter(|f| {
                    f.smallest.user_key() <= start.as_slice()
                        && end.as_slice() <= f.largest.user_key()
                })
                .count();
            assert_eq!(holders, 1, "tombstone {start:?}..{end:?}");
        }
        let hot = user_key(44);
        let holders = out
            .files
            .iter()
            .filter(|f| {
                f.smallest.user_key() <= hot.as_slice() && hot.as_slice() <= f.largest.user_key()
            })
            .count();
        assert_eq!(holders, 1, "all versions of the merge key in one file");

        install_compaction(&mut store.versions, &c, &out).unwrap();
        delete_obsolete_files(store.fs.as_ref(), &store.versions, &BTreeSet::new()).unwrap();
        store.check();
    }
}

/// TC-STO-004 (subcompaction failure): when one sub-job fails (disk full half-way through the
/// outputs), the job fails as a whole: nothing is installed, the outputs every sub-job already
/// wrote are removed, the inputs stay live, and a retry succeeds.
#[test]
fn tc_sto_004_failed_subcompaction_installs_nothing() {
    for parallel in [false, true] {
        let mut store = boundary_store();
        let c = l0_compaction(&store);
        let options = split(4, parallel);
        let dry = store.run(&c, &options, &mut Vec::new()).unwrap();
        assert!(dry.subcompactions > 1);
        remove_outputs(store.fs.as_ref(), &dry.files);

        let used: u64 = store
            .fs
            .read_dir(Path::new(DIR))
            .unwrap()
            .iter()
            .map(|p| store.fs.open(p, OpenMode::Read).unwrap().size().unwrap())
            .sum();
        let before = store.versions.current();
        let live = store.versions.live_files();
        // Room for about half of the outputs: the first sub-jobs finish, a later one fails.
        store.fs.set_quota(Some(used + dry.bytes_out / 2));
        let mut allocated = Vec::new();
        let err = store.run(&c, &options, &mut allocated).unwrap_err();
        assert!(!err.is_corruption(), "{err}");
        assert!(
            allocated.len() > 1,
            "outputs of several sub-jobs were created"
        );
        assert_eq!(*store.versions.current(), *before, "nothing installed");
        assert_eq!(sst_on_disk(store.fs.as_ref()), live, "every output removed");

        store.fs.set_quota(None);
        let out = store.run(&c, &options, &mut Vec::new()).unwrap();
        install_compaction(&mut store.versions, &c, &out).unwrap();
        delete_obsolete_files(store.fs.as_ref(), &store.versions, &BTreeSet::new()).unwrap();
        store.check();
    }
}
