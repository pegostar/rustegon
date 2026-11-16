// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Read path integration tests (M1 T6; storage-engine.md §1, §3, §8; TC-STO-001 read part):
//! point lookups and user-key iterators over active + immutable memtables and all LSM levels,
//! at every live snapshot, with merge operands, forward/reverse scans and direction changes,
//! against a model.

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
use rustegon_sim_api::FileSystem;
use rustegon_storage::{
    MAX_SEQNO, Memtable, ReadView, SeqNo, StorageError, TableCache, ValueKind,
    compaction::{
        CompactionOptions, delete_obsolete_files, install_compaction, pick_compaction,
        run_compaction,
    },
    flush_memtable,
    merge::{MergeOperand, full_merge},
    sst::{SstReaderOptions, SstWriterOptions},
    version::VersionSet,
};

const DIR: &str = "/store";

fn options() -> CompactionOptions {
    CompactionOptions {
        l0_trigger: 3,
        level_base_bytes: 2 << 10,
        level_multiplier: 4,
        target_file_size_base: 1 << 10,
        max_target_file_size: 2 << 10,
        writer: SstWriterOptions {
            block_size: 128,
            restart_interval: 4,
            index_partition_size: 64,
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
    /// Make the active memtable immutable.
    Rotate,
    /// Flush the oldest immutable memtable, then compact until quiet.
    Flush,
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => (0u8..30, any::<u8>()).prop_map(|(k, v)| Op::Put(k, v)),
        2 => (0u8..30).prop_map(Op::Delete),
        // Keys 20..30 also receive puts/deletes: merges on top of values and tombstones.
        4 => (20u8..30, any::<i8>()).prop_map(|(k, d)| Op::Merge(k, d)),
        1 => (0u8..30, 1u8..8).prop_map(|(a, len)| Op::DeleteRange(a, a.saturating_add(len))),
        1 => Just(Op::Snapshot),
        1 => Just(Op::Rotate),
        2 => Just(Op::Flush),
    ]
}

fn user_key(k: u8) -> Vec<u8> {
    format!("user-{k:02}").into_bytes()
}

fn counter(v: i64) -> Vec<u8> {
    MergeOperand::CounterDelta(v).encode()
}

/// Versions of one key, newest first.
type Versions = Vec<(SeqNo, ValueKind, Vec<u8>)>;

/// `(start, end, seqno)` range tombstones.
type Tombstones = Vec<(Vec<u8>, Vec<u8>, SeqNo)>;

/// The model's answer at `snapshot` (merge keys hold counter encodings so merging onto a put is
/// well-typed); a version older than a visible covering range tombstone reads as deleted.
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

struct Store {
    fs: Arc<SimFileSystem>,
    versions: VersionSet,
    tables: Arc<TableCache>,
    active: Arc<Memtable>,
    /// Newest first.
    immutable: Vec<Arc<Memtable>>,
    seqno: SeqNo,
    model: BTreeMap<Vec<u8>, Versions>,
    tombstones: Tombstones,
    snapshots: Vec<SeqNo>,
}

impl Store {
    fn new() -> Self {
        let fs = Arc::new(SimFileSystem::new());
        let dyn_fs: Arc<dyn FileSystem> = fs.clone();
        let versions = VersionSet::create(Arc::clone(&dyn_fs), Path::new(DIR)).unwrap();
        let tables = Arc::new(TableCache::new(
            dyn_fs,
            DIR.into(),
            SstReaderOptions::default(),
        ));
        Self {
            fs,
            versions,
            tables,
            active: Arc::new(Memtable::new()),
            immutable: Vec::new(),
            seqno: 0,
            model: BTreeMap::new(),
            tombstones: Vec::new(),
            snapshots: Vec::new(),
        }
    }

    fn write(&mut self, key: Vec<u8>, kind: ValueKind, value: Vec<u8>) {
        self.seqno += 1;
        self.active
            .add(self.seqno, kind, &key, Bytes::from(value.clone()));
        self.model
            .entry(key)
            .or_default()
            .insert(0, (self.seqno, kind, value));
    }

    fn apply(&mut self, op: &Op, options: &CompactionOptions) {
        match *op {
            Op::Put(k, v) if k >= 20 => {
                self.write(user_key(k), ValueKind::Put, counter(i64::from(v)));
            }
            Op::Put(k, v) => {
                let value = vec![v; 1 + usize::from(v % 50)];
                self.write(user_key(k), ValueKind::Put, value);
            }
            Op::Delete(k) => self.write(user_key(k), ValueKind::Delete, Vec::new()),
            Op::Merge(k, d) => self.write(user_key(k), ValueKind::Merge, counter(i64::from(d))),
            Op::DeleteRange(a, b) => {
                self.seqno += 1;
                let (start, end) = (user_key(a), user_key(b));
                self.active.add_range_tombstone(self.seqno, &start, &end);
                self.tombstones.push((start, end, self.seqno));
            }
            Op::Snapshot => self.snapshots.push(self.seqno),
            Op::Rotate => {
                let old = std::mem::replace(&mut self.active, Arc::new(Memtable::new()));
                self.immutable.insert(0, old);
            }
            Op::Flush => self.flush_oldest(options),
        }
    }

    fn flush_oldest(&mut self, options: &CompactionOptions) {
        let Some(oldest) = self.immutable.pop() else {
            return;
        };
        // Newer memtables are not flushed yet: the flushed seqno is the largest seqno of the
        // flushed memtable (never below the recorded value).
        let flushed = oldest
            .iter()
            .map(|e| e.key().seqno())
            .chain(oldest.range_tombstones().iter().map(|t| t.seqno))
            .max()
            .unwrap_or(0)
            .max(self.versions.flushed_seqno());
        flush_memtable(
            self.fs.as_ref(),
            Path::new(DIR),
            &mut self.versions,
            &oldest,
            &options.writer,
            flushed,
        )
        .unwrap();
        loop {
            let current = self.versions.current();
            let Some(c) = pick_compaction(&current, options, &BTreeSet::default()) else {
                break;
            };
            drop(current);
            let versions = &mut self.versions;
            let out = run_compaction(
                self.fs.as_ref(),
                Path::new(DIR),
                &c,
                options,
                &self.snapshots,
                None,
                &mut || versions.new_file_number(),
            )
            .unwrap();
            install_compaction(&mut self.versions, &c, &out).unwrap();
            for (_, f) in &c.inputs {
                self.tables.evict(f.number);
            }
            delete_obsolete_files(self.fs.as_ref(), &self.versions, &BTreeSet::default()).unwrap();
        }
    }

    fn view(&self) -> ReadView {
        let mut memtables = vec![Arc::clone(&self.active)];
        memtables.extend(self.immutable.iter().cloned());
        ReadView::new(memtables, self.versions.current(), Arc::clone(&self.tables))
    }

    /// The model's visible `(key, value)` pairs at `snapshot`, in key order.
    fn expected(&self, snapshot: SeqNo) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.model
            .iter()
            .filter_map(|(k, v)| {
                read_at(k, v, &self.tombstones, snapshot).map(|value| (k.clone(), value))
            })
            .collect()
    }
}

/// `(probe key, seek backwards?, moves: true = next)`.
type Walk = (u8, bool, Vec<bool>);

fn check(store: &Store, walks: &[Walk]) -> Result<(), TestCaseError> {
    let view = store.view();
    for snapshot in store.snapshots.iter().copied().chain([MAX_SEQNO]) {
        let expected = store.expected(snapshot);
        for k in 0u8..31 {
            let key = user_key(k);
            let want = expected
                .iter()
                .find(|(ek, _)| *ek == key)
                .map(|(_, v)| v.clone());
            let got = view.get(&key, snapshot).unwrap().map(|b| b.to_vec());
            prop_assert_eq!(got, want, "get {:?} at {}", key, snapshot);
        }

        let mut it = view.iterator(snapshot).unwrap();
        it.seek_to_first().unwrap();
        let mut forward = Vec::new();
        while it.valid() {
            forward.push((it.key().to_vec(), it.value().to_vec()));
            it.next().unwrap();
        }
        prop_assert_eq!(&forward, &expected, "forward scan at {}", snapshot);

        it.seek_to_last().unwrap();
        let mut backward = Vec::new();
        while it.valid() {
            backward.push((it.key().to_vec(), it.value().to_vec()));
            it.prev().unwrap();
        }
        backward.reverse();
        prop_assert_eq!(&backward, &expected, "reverse scan at {}", snapshot);

        for (probe, backwards, moves) in walks {
            let probe = user_key(*probe);
            let mut pos = if *backwards {
                it.seek_for_prev(&probe).unwrap();
                expected
                    .partition_point(|(k, _)| *k <= probe)
                    .checked_sub(1)
            } else {
                it.seek(&probe).unwrap();
                Some(expected.partition_point(|(k, _)| *k < probe)).filter(|&p| p < expected.len())
            };
            for &step_forward in moves {
                let Some(p) = pos else {
                    break;
                };
                prop_assert_eq!(it.key(), expected[p].0.as_slice());
                prop_assert_eq!(it.value().to_vec(), expected[p].1.clone());
                if step_forward {
                    it.next().unwrap();
                    pos = Some(p + 1).filter(|&n| n < expected.len());
                } else {
                    it.prev().unwrap();
                    pos = p.checked_sub(1);
                }
            }
            if pos.is_none() {
                prop_assert!(!it.valid());
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn tc_sto_001_read_path_matches_model_at_every_snapshot(
        ops in prop::collection::vec(arb_op(), 1..400),
        walks in prop::collection::vec(
            (0u8..32, any::<bool>(), prop::collection::vec(any::<bool>(), 0..30)),
            0..4,
        ),
    ) {
        let options = options();
        let mut store = Store::new();
        for op in &ops {
            store.apply(op, &options);
        }
        check(&store, &walks)?;
        // Flush everything and check again from SSTs only.
        store.apply(&Op::Rotate, &options);
        while !store.immutable.is_empty() {
            store.apply(&Op::Flush, &options);
        }
        check(&store, &walks)?;
    }
}

/// A counter that overflows `i64` is reported at read (`RGN-1009`), by `get` and by iterators.
#[test]
fn merged_counter_overflow_is_reported_at_read() {
    let mut store = Store::new();
    store.write(user_key(1), ValueKind::Merge, counter(i64::MAX));
    store.write(user_key(1), ValueKind::Merge, counter(1));
    let view = store.view();
    assert!(matches!(
        view.get(&user_key(1), MAX_SEQNO),
        Err(StorageError::CounterOverflow)
    ));
    let mut it = view.iterator(MAX_SEQNO).unwrap();
    assert!(matches!(
        it.seek_to_first(),
        Err(StorageError::CounterOverflow)
    ));
    assert!(!it.valid());
}

/// An iterator pins its version: compaction deletes nothing it still reads.
#[test]
fn iterator_pins_files_across_compaction() {
    let options = options();
    let mut store = Store::new();
    for round in 0u8..3 {
        for k in 0u8..20 {
            store.apply(&Op::Put(k, round), &options);
        }
        store.apply(&Op::Rotate, &options);
        store.apply(&Op::Flush, &options);
    }
    let expected = store.expected(MAX_SEQNO);
    let mut it = store.view().iterator(MAX_SEQNO).unwrap();
    it.seek_to_first().unwrap();
    for round in 3u8..12 {
        for k in 0u8..20 {
            store.apply(&Op::Put(k, round), &options);
        }
        store.apply(&Op::Rotate, &options);
        store.apply(&Op::Flush, &options);
    }
    let mut seen = Vec::new();
    while it.valid() {
        seen.push((it.key().to_vec(), it.value().to_vec()));
        it.next().unwrap();
    }
    assert_eq!(seen, expected);
}
