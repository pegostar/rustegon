// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Engine integration tests (storage-engine.md §1, §3, §9; TC-STO-001 engine part): random
//! batches, snapshots, flushes, compactions and crash-reopens against a model; concurrent
//! writers, readers, flushes and compactions; orphan cleanup at open.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

use bytes::Bytes;
use proptest::prelude::*;
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_sim_api::{FileSystem, OpenMode};
use rustegon_storage::{
    BatchOp, EngineOptions, LsmEngine, SeqNo, Snapshot, WriteBatch,
    compaction::{CompactionFilter, CompactionOptions, FilterDecision},
    merge::{MergeOperand, full_merge},
    sst::SstWriterOptions,
};

const DIR: &str = "/store";

fn options() -> EngineOptions {
    EngineOptions {
        memtable_size: 2 << 10,
        compaction: CompactionOptions {
            l0_trigger: 2,
            level_base_bytes: 4 << 10,
            level_multiplier: 4,
            target_file_size_base: 2 << 10,
            max_target_file_size: 4 << 10,
            writer: SstWriterOptions {
                block_size: 256,
                ..SstWriterOptions::default()
            },
            // L0 compactions split into up to 4 sub-jobs (NFR-PERF-005), run sequentially so the
            // crash sweep enumerates a reproducible sequence of operations (`compaction/job.rs`).
            max_subcompactions: 4,
            parallel_subcompactions: false,
            ..CompactionOptions::default()
        },
        ..EngineOptions::default()
    }
}

fn open(fs: &Arc<SimFileSystem>) -> LsmEngine {
    LsmEngine::open(fs.clone(), Path::new(DIR), options()).unwrap()
}

#[derive(Debug, Clone)]
enum Write {
    Put(u8, u8),
    Delete(u8),
    Merge(u8, i8),
    DeleteRange(u8, u8),
}

#[derive(Debug, Clone)]
enum Op {
    Batch(Vec<Write>),
    Snapshot,
    Release(usize),
    Flush,
    Compact,
    /// Ingest an external SST holding these `(key, value)` puts (deduplicated by key).
    Ingest(Vec<(u8, u8)>),
    /// Drop the engine without flushing (a crash: unflushed writes are lost) and reopen.
    Reopen,
}

fn arb_write() -> impl Strategy<Value = Write> {
    prop_oneof![
        5 => (0u8..24, any::<u8>()).prop_map(|(k, v)| Write::Put(k, v)),
        2 => (0u8..24).prop_map(Write::Delete),
        3 => (16u8..24, any::<i8>()).prop_map(|(k, d)| Write::Merge(k, d)),
        1 => (0u8..24, 1u8..6).prop_map(|(a, len)| Write::DeleteRange(a, a + len)),
    ]
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        10 => prop::collection::vec(arb_write(), 1..6).prop_map(Op::Batch),
        1 => Just(Op::Snapshot),
        1 => (0usize..8).prop_map(Op::Release),
        2 => Just(Op::Flush),
        1 => Just(Op::Compact),
        1 => prop::collection::vec((0u8..24, any::<u8>()), 1..6).prop_map(Op::Ingest),
        1 => Just(Op::Reopen),
    ]
}

fn key(k: u8) -> Vec<u8> {
    format!("key-{k:02}-{}", "p".repeat(20)).into_bytes()
}

fn counter(v: i64) -> Vec<u8> {
    MergeOperand::CounterDelta(v).encode()
}

/// Model: per key, versions newest first as `(seqno, op)`; `None` value = delete.
#[derive(Default, Clone)]
struct Model {
    versions: BTreeMap<Vec<u8>, Vec<(SeqNo, Write)>>,
    /// `(start, end, seqno)`.
    tombstones: Vec<(Vec<u8>, Vec<u8>, SeqNo)>,
    /// Seqnos of ingests: durable at once, so they survive a crash above `flushed_seqno`.
    ingested: Vec<SeqNo>,
}

impl Model {
    fn read(&self, key: &[u8], snapshot: SeqNo) -> Option<Vec<u8>> {
        let cutoff = self
            .tombstones
            .iter()
            .filter(|(s, e, seq)| *seq <= snapshot && s.as_slice() <= key && key < e.as_slice())
            .map(|t| t.2)
            .max()
            .unwrap_or(0);
        let mut operands: Vec<Vec<u8>> = Vec::new();
        for (seqno, w) in self.versions.get(key)?.iter().filter(|v| v.0 <= snapshot) {
            if *seqno < cutoff {
                break;
            }
            match w {
                Write::Merge(_, d) => operands.push(counter(i64::from(*d))),
                Write::Put(k, v) => {
                    let base = put_value(*k, *v);
                    return Some(if operands.is_empty() {
                        base
                    } else {
                        full_merge(Some(&base), operands.iter().map(Vec::as_slice)).unwrap()
                    });
                }
                Write::Delete(_) => break,
                Write::DeleteRange(..) => unreachable!("kept in `tombstones`"),
            }
        }
        (!operands.is_empty())
            .then(|| full_merge(None, operands.iter().map(Vec::as_slice)).unwrap())
    }

    fn visible(&self, snapshot: SeqNo) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.versions
            .keys()
            .filter_map(|k| self.read(k, snapshot).map(|v| (k.clone(), v)))
            .collect()
    }

    /// A crash loses every write above the flushed seqno.
    fn truncate(&mut self, flushed: SeqNo) {
        let ingested = self.ingested.clone();
        for versions in self.versions.values_mut() {
            versions.retain(|v| v.0 <= flushed || ingested.contains(&v.0));
        }
        self.tombstones.retain(|t| t.2 <= flushed);
    }
}

/// Merge keys (16..24) store counters so merges onto puts are well-typed.
fn put_value(k: u8, v: u8) -> Vec<u8> {
    if k >= 16 {
        counter(i64::from(v))
    } else {
        vec![v; 30]
    }
}

fn check(engine: &LsmEngine, model: &Model, snapshots: &[Snapshot]) -> Result<(), TestCaseError> {
    let latest = engine.last_seqno();
    for (seqno, snap) in snapshots
        .iter()
        .map(|s| (s.seqno(), Some(s)))
        .chain([(latest, None)])
    {
        let expected = model.visible(seqno);
        let mut it = engine.iterator(snap).unwrap();
        it.seek_to_first().unwrap();
        let mut got = Vec::new();
        while it.valid() {
            got.push((it.key().to_vec(), it.value().to_vec()));
            it.next().unwrap();
        }
        prop_assert_eq!(&got, &expected, "scan at {}", seqno);
        for k in 0u8..24 {
            let want = model.read(&key(k), seqno);
            let got = engine.get(&key(k), snap).unwrap().map(|b| b.to_vec());
            prop_assert_eq!(got, want, "get {} at {}", k, seqno);
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// TC-STO-001 (engine part): every live snapshot and the latest state read what the model
    /// reads through batches, rotations, flushes, compactions and crash-reopens.
    #[test]
    fn tc_sto_001_engine_matches_model(ops in prop::collection::vec(arb_op(), 1..150)) {
        let fs = Arc::new(SimFileSystem::new());
        let mut engine = open(&fs);
        let mut model = Model::default();
        let mut snapshots: Vec<Snapshot> = Vec::new();
        let mut ingest_count = 0u32;
        for op in &ops {
            match op {
                Op::Batch(writes) => {
                    let mut batch = WriteBatch::new();
                    for w in writes {
                        match *w {
                            Write::Put(k, v) => batch.put(&key(k), put_value(k, v)),
                            Write::Delete(k) => batch.delete(&key(k)),
                            Write::Merge(k, d) => batch.merge(&key(k), counter(i64::from(d))),
                            Write::DeleteRange(a, b) => batch.delete_range(&key(a), &key(b)),
                        };
                    }
                    let last = engine.write(&batch).unwrap();
                    let first = last + 1 - writes.len() as u64;
                    for (w, seqno) in writes.iter().zip(first..) {
                        let k = match *w {
                            Write::Put(k, _) | Write::Delete(k) | Write::Merge(k, _) => k,
                            Write::DeleteRange(a, b) => {
                                model.tombstones.push((key(a), key(b), seqno));
                                continue;
                            }
                        };
                        model.versions.entry(key(k)).or_default().insert(0, (seqno, w.clone()));
                    }
                }
                Op::Snapshot => snapshots.push(engine.snapshot()),
                Op::Release(i) => {
                    if *i < snapshots.len() {
                        snapshots.remove(*i);
                    }
                }
                Op::Flush => engine.flush().unwrap(),
                Op::Ingest(puts) => {
                    let puts: BTreeMap<u8, u8> = puts.iter().copied().collect();
                    fs.create_dir_all(Path::new("/ext")).unwrap();
                    let path = Path::new("/ext").join(format!("{ingest_count}.sst"));
                    ingest_count += 1;
                    let mut w = rustegon_storage::sst::SstWriter::new(
                        fs.open(&path, OpenMode::CreateNew).unwrap(),
                        SstWriterOptions::default(),
                    );
                    for (&k, &v) in &puts {
                        let ik = rustegon_storage::InternalKey::new(
                            &key(k),
                            0,
                            rustegon_storage::ValueKind::Put,
                        );
                        w.add(ik.as_bytes(), &put_value(k, v)).unwrap();
                    }
                    w.finish().unwrap();
                    let seqno = engine.ingest(&[path]).unwrap();
                    model.ingested.push(seqno);
                    for (&k, &v) in &puts {
                        model.versions.entry(key(k)).or_default().insert(0, (seqno, Write::Put(k, v)));
                    }
                }
                Op::Compact => {
                    engine.compact().unwrap();
                }
                Op::Reopen => {
                    let flushed = engine.flushed_seqno();
                    snapshots.clear();
                    drop(engine);
                    model.truncate(flushed);
                    engine = open(&fs);
                    let last_ingest = model.ingested.iter().copied().max().unwrap_or(0);
                    prop_assert_eq!(engine.last_seqno(), flushed.max(last_ingest));
                }
            }
        }
        check(&engine, &model, &snapshots)?;
        engine.flush().unwrap();
        engine.compact().unwrap();
        check(&engine, &model, &snapshots)?;
    }
}

/// Writers commit `(a_i, b_i)` pairs atomically with equal values while readers check, at
/// snapshots, that both halves always agree and values never go backwards; a background thread
/// flushes and compacts throughout.
#[test]
fn concurrent_writes_reads_flushes_and_compactions_stay_consistent() {
    const WRITERS: u8 = 4;
    const ROUNDS: u32 = 300;
    let fs = Arc::new(SimFileSystem::new());
    let engine = Arc::new(open(&fs));
    let done = Arc::new(AtomicBool::new(false));

    let background = {
        let (engine, done) = (Arc::clone(&engine), Arc::clone(&done));
        thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                engine.flush().unwrap();
                engine.compact().unwrap();
            }
        })
    };
    let readers: Vec<_> = (0..2)
        .map(|_| {
            let (engine, done) = (Arc::clone(&engine), Arc::clone(&done));
            thread::spawn(move || {
                let mut last_seen = [0u32; WRITERS as usize];
                while !done.load(Ordering::Acquire) {
                    let snap = engine.snapshot();
                    for w in 0..WRITERS {
                        let a = engine.get(format!("a{w}").as_bytes(), Some(&snap)).unwrap();
                        let b = engine.get(format!("b{w}").as_bytes(), Some(&snap)).unwrap();
                        assert_eq!(a, b, "batch of writer {w} applied partially");
                        let v = a.map_or(0, |v| u32::from_le_bytes(v[..4].try_into().unwrap()));
                        assert!(v >= last_seen[w as usize], "value went backwards");
                        last_seen[w as usize] = v;
                    }
                    let mut it = engine.iterator(Some(&snap)).unwrap();
                    it.seek_to_first().unwrap();
                    let mut seen = BTreeMap::new();
                    while it.valid() {
                        seen.insert(it.key().to_vec(), it.value());
                        it.next().unwrap();
                    }
                    for w in 0..WRITERS {
                        assert_eq!(
                            seen.get(format!("a{w}").as_bytes()),
                            seen.get(format!("b{w}").as_bytes())
                        );
                    }
                }
            })
        })
        .collect();
    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let engine = Arc::clone(&engine);
            thread::spawn(move || {
                for round in 1..=ROUNDS {
                    let mut value = round.to_le_bytes().to_vec();
                    value.extend_from_slice(&[w; 60]);
                    let mut batch = WriteBatch::new();
                    batch.put(format!("a{w}").as_bytes(), value.clone());
                    batch.put(format!("b{w}").as_bytes(), value);
                    engine.write(&batch).unwrap();
                }
            })
        })
        .collect();
    for w in writers {
        w.join().unwrap();
    }
    done.store(true, Ordering::Release);
    background.join().unwrap();
    for r in readers {
        r.join().unwrap();
    }
    engine.flush().unwrap();
    for w in 0..WRITERS {
        let v = engine
            .get(format!("a{w}").as_bytes(), None)
            .unwrap()
            .unwrap();
        assert_eq!(u32::from_le_bytes(v[..4].try_into().unwrap()), ROUNDS);
    }
    assert_eq!(engine.flushed_seqno(), engine.last_seqno());
}

/// Startup recovery deletes SSTs no MANIFEST record references (§9 step D) and keeps the data.
#[test]
fn open_deletes_orphan_files_and_keeps_flushed_data() {
    let fs = Arc::new(SimFileSystem::new());
    let engine = open(&fs);
    let mut batch = WriteBatch::new();
    batch.put(b"k", b"v".to_vec());
    engine.write(&batch).unwrap();
    engine.flush().unwrap();
    drop(engine);
    let orphan = Path::new(DIR).join("999999.sst");
    let mut f = fs.open(&orphan, OpenMode::CreateNew).unwrap();
    f.append(b"partial").unwrap();
    f.sync_data().unwrap();
    drop(f);
    fs.sync_dir(Path::new(DIR)).unwrap();

    let engine = open(&fs);
    assert!(fs.open(&orphan, OpenMode::Read).is_err(), "orphan deleted");
    assert_eq!(engine.get(b"k", None).unwrap().as_deref(), Some(&b"v"[..]));
}

/// M1 T15: engine metrics reflect writes, flushes, compactions and the level shape.
#[test]
fn engine_metrics_track_activity() {
    let fs = Arc::new(SimFileSystem::new());
    let engine = open(&fs);
    let snap = engine.snapshot();
    for round in 0..6u8 {
        let mut batch = WriteBatch::new();
        for k in 0..20u8 {
            batch.put(&key(k), put_value(k, round));
        }
        engine.write(&batch).unwrap();
        engine.flush().unwrap();
    }
    drop(snap);
    let before = engine.metrics();
    assert_eq!(before.write_batches, 6);
    assert_eq!(before.flushes, 6);
    assert!(before.flush_bytes > 0);
    assert_eq!(before.snapshots, 0);
    assert_eq!(before.level_files[0], 6);
    engine.compact().unwrap();
    let after = engine.metrics();
    assert!(after.compactions > 0);
    assert!(after.compaction_read_bytes > 0 && after.compaction_write_bytes > 0);
    assert!(after.level_files[0] < 6);
    let v = engine.current_version();
    let live: u64 = v.all_files().map(|(_, f)| f.size).sum();
    assert_eq!(after.disk_used_bytes(), live);
}

/// PD-061: the background scheduler's `flush_immutable` flushes only rotated memtables — the
/// active one stays in memory, so a polling scheduler does not cut a tiny L0 file per tick —
/// and the data stays readable across it.
#[test]
fn flush_immutable_leaves_the_active_memtable() {
    let fs = Arc::new(SimFileSystem::new());
    let engine = open(&fs);
    let mut batch = WriteBatch::new();
    batch.put(&key(1), put_value(1, 1));
    engine.write(&batch).unwrap();
    assert_eq!(engine.flush_immutable().unwrap(), 0, "nothing rotated yet");
    assert_eq!(engine.metrics().flushes, 0);

    // 2 KiB memtables (`options`): this batch overflows and rotates the active memtable.
    let mut big = WriteBatch::new();
    for k in 0..100u8 {
        big.put(&key(k), vec![k; 64]);
    }
    engine.write(&big).unwrap();
    let rotated = engine.immutable_memtables();
    assert!(rotated > 0);
    let mut tail = WriteBatch::new();
    tail.put(&key(200), put_value(200, 1));
    engine.write(&tail).unwrap();

    assert_eq!(engine.flush_immutable().unwrap(), rotated);
    assert_eq!(engine.immutable_memtables(), 0);
    assert_eq!(engine.metrics().level_files[0], rotated);
    // The last write is still only in the active memtable, and readable.
    assert_eq!(engine.flush_immutable().unwrap(), 0);
    assert_eq!(
        engine.get(&key(200), None).unwrap(),
        Some(Bytes::from(put_value(200, 1)))
    );
    assert_eq!(
        engine.get(&key(7), None).unwrap(),
        Some(Bytes::from(vec![7; 64]))
    );
}

/// What the crash workload had acknowledged (durable) or attempted when it stopped.
#[derive(Default)]
struct Progress {
    model: Model,
    acked_flushed: SeqNo,
    acked_ingests: Vec<SeqNo>,
}

/// Deterministic workload for the crash campaign: batches with puts, merges, deletes and range
/// deletes (memtables rotate inside batches: 2 KiB memtables), flushes, compactions and ingests.
/// Stops at the first error (the halted file system).
// Short names mirror the model's vocabulary (k key, v value, w write, p progress).
#[allow(clippy::many_single_char_names)]
fn crash_workload(
    fs: &SimFileSystem,
    engine: &LsmEngine,
    p: &mut Progress,
    workload: u64,
) -> Result<(), String> {
    // Xorshift needs a non-zero state; the constant is an arbitrary odd 64-bit value.
    let mut x: u64 = 0x2545_F491_4F6C_DD1D ^ workload.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let small = |v: u64| u8::try_from(v).unwrap();
    let err = |e: rustegon_storage::StorageError| e.to_string();
    for round in 0..12u32 {
        let mut batch = WriteBatch::new();
        let mut writes = Vec::new();
        for _ in 0..8 {
            let k = small(next(24));
            let w = match next(10) {
                0..=4 => Write::Put(k, small(next(256))),
                5 | 6 => Write::Delete(k),
                7 | 8 => Write::Merge(16 + k % 8, i8::try_from(next(100)).unwrap() - 50),
                _ => Write::DeleteRange(k, k + 1 + small(next(4))),
            };
            match w {
                Write::Put(k, v) => batch.put(&key(k), put_value(k, v)),
                Write::Delete(k) => batch.delete(&key(k)),
                Write::Merge(k, d) => batch.merge(&key(k), counter(i64::from(d))),
                Write::DeleteRange(a, b) => batch.delete_range(&key(a), &key(b)),
            };
            writes.push(w);
        }
        let last = engine.write(&batch).map_err(err)?;
        let first = last + 1 - writes.len() as u64;
        for (w, seqno) in writes.into_iter().zip(first..) {
            match w {
                Write::DeleteRange(a, b) => p.model.tombstones.push((key(a), key(b), seqno)),
                Write::Put(k, _) | Write::Delete(k) | Write::Merge(k, _) => {
                    p.model
                        .versions
                        .entry(key(k))
                        .or_default()
                        .insert(0, (seqno, w));
                }
            }
        }
        if round % 2 == 1 {
            engine.flush().map_err(err)?;
            p.acked_flushed = engine.flushed_seqno();
        }
        if round % 3 == 2 {
            engine.compact().map_err(err)?;
        }
        if round % 4 == 3 {
            let path = Path::new("/ext").join(format!("{round}.sst"));
            let puts: BTreeMap<u8, u8> = (0..4)
                .map(|_| (small(next(16)), small(next(256))))
                .collect();
            let written = (|| -> rustegon_storage::Result<()> {
                fs.create_dir_all(Path::new("/ext"))?;
                let mut w = rustegon_storage::sst::SstWriter::new(
                    fs.open(&path, OpenMode::CreateNew)?,
                    SstWriterOptions::default(),
                );
                for (&k, &v) in &puts {
                    let ik = rustegon_storage::InternalKey::new(
                        &key(k),
                        0,
                        rustegon_storage::ValueKind::Put,
                    );
                    w.add(ik.as_bytes(), &put_value(k, v))?;
                }
                w.finish().map(drop)
            })();
            written.map_err(err)?;
            // The ingest seqno is decided before the attempt, so an in-flight ingest that became
            // durable can be recognised after the crash.
            let seqno = engine.last_seqno() + 1;
            p.model.ingested.push(seqno);
            for (&k, &v) in &puts {
                p.model
                    .versions
                    .entry(key(k))
                    .or_default()
                    .insert(0, (seqno, Write::Put(k, v)));
            }
            let got = engine.ingest(&[path]).map_err(err)?;
            assert_eq!(got, seqno);
            p.acked_ingests.push(seqno);
        }
    }
    Ok(())
}

/// Recovery check: the store opens, keeps every acknowledged flush and ingest, and holds exactly
/// the model truncated at the recovered flushed seqno (plus the ingests that are durable).
fn check_recovered(engine: &LsmEngine, p: &Progress, label: &str) {
    let flushed = engine.flushed_seqno();
    let last = engine.last_seqno();
    assert!(
        flushed >= p.acked_flushed,
        "{label}: lost an acknowledged flush"
    );
    for g in &p.acked_ingests {
        assert!(*g <= last, "{label}: lost acknowledged ingest {g}");
    }
    let mut model = p.model.clone();
    model.ingested.retain(|g| *g <= last);
    model.truncate(flushed);
    let expected = model.visible(rustegon_storage::MAX_SEQNO);
    let mut it = engine.iterator(None).unwrap();
    it.seek_to_first().unwrap();
    let mut got = Vec::new();
    while it.valid() {
        got.push((it.key().to_vec(), it.value().to_vec()));
        it.next().unwrap();
    }
    assert_eq!(got, expected, "{label}: recovered content");
    for k in 0u8..24 {
        let want = model.read(&key(k), rustegon_storage::MAX_SEQNO);
        let got = engine.get(&key(k), None).unwrap().map(|b| b.to_vec());
        assert_eq!(got, want, "{label}: get {k}");
    }
}

/// Lower bound on the crash workload's mutating operations (about 200 today: 6 flushes, 4
/// compactions, 3 ingests with their SST writes, fsyncs and MANIFEST records). Fewer means the
/// workload silently shrank and the sweep no longer reaches every kind of crash point.
const MIN_CRASH_POINTS: u64 = 120;

fn env_count(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// TC-STO-002 / TC-STO-004: the crash workloads really split L0 compactions into sub-jobs, so
/// the crash sweep below covers crashes between and inside subcompactions and around their one
/// combined MANIFEST edit. Range tombstones can veto every boundary of a compaction, so the bar
/// is "most workloads", checked over the first 16 (the campaign's workloads come from the same
/// generator).
#[test]
fn tc_sto_002_crash_workloads_exercise_subcompactions() {
    let mut split = 0;
    for workload in 0..16 {
        let fs = Arc::new(SimFileSystem::new());
        let engine = open(&fs);
        crash_workload(&fs, &engine, &mut Progress::default(), workload).unwrap();
        let m = engine.metrics();
        assert!(m.compactions > 0, "workload {workload} never compacted");
        if m.subcompactions > m.compactions {
            split += 1;
        }
    }
    assert!(
        split >= 12,
        "only {split} of 16 workloads split an L0 compaction"
    );
}

/// TC-STO-002 (full-engine campaign): crash at every mutating file-system operation of the
/// workload, in every crash mode, with `RUSTEGON_CRASH_SEEDS` crash seeds each (default 2) over
/// `RUSTEGON_CRASH_WORKLOADS` randomized workloads (default 1; the nightly long run raises
/// both), then recover and check prefix consistency and writability. Workloads are numbered
/// from `RUSTEGON_CRASH_WORKLOAD_START` (default 0), so a long run is split into disjoint shards
/// running as parallel processes (`scripts/crash-campaign.sh`); each workload number is a
/// distinct, reproducible random workload.
#[test]
fn tc_sto_002_engine_crash_at_every_operation() {
    let seeds = env_count("RUSTEGON_CRASH_SEEDS", 2);
    let start = env_count("RUSTEGON_CRASH_WORKLOAD_START", 0);
    for workload in start..start + env_count("RUSTEGON_CRASH_WORKLOADS", 1) {
        crash_campaign(workload, seeds);
    }
}

fn crash_campaign(workload: u64, seeds: u64) {
    // Count the crash points of a full run.
    let fs = Arc::new(SimFileSystem::new());
    let engine = open(&fs);
    let start = fs.op_count();
    let mut full = Progress::default();
    crash_workload(&fs, &engine, &mut full, workload).unwrap();
    let points = fs.op_count() - start;
    check_recovered(&engine, &full, "no crash");
    drop(engine);
    assert!(
        points > MIN_CRASH_POINTS,
        "workload too small to cover crash points: {points}"
    );

    for point in 0..points {
        for mode in CrashMode::ALL {
            for seed in 0..seeds {
                let label =
                    format!("workload {workload}, point {point}/{points}, {mode:?}, seed {seed}");
                let fs = Arc::new(SimFileSystem::new());
                let engine = open(&fs);
                fs.halt_after_ops(point);
                let mut p = Progress::default();
                let outcome = crash_workload(&fs, &engine, &mut p, workload);
                assert!(outcome.is_err(), "{label}: workload did not hit the halt");
                drop(engine);
                fs.crash(seed * 7919 + point + workload * 104_729, mode);
                let engine = LsmEngine::open(fs.clone(), Path::new(DIR), options())
                    .unwrap_or_else(|e| panic!("{label}: reopen failed: {e}"));
                check_recovered(&engine, &p, &label);
                // Still writable and durable.
                let mut b = WriteBatch::new();
                b.put(b"after-crash", b"ok".to_vec());
                engine.write(&b).unwrap();
                engine.flush().unwrap();
                drop(engine);
                let engine = open(&fs);
                assert_eq!(
                    engine.get(b"after-crash", None).unwrap().as_deref(),
                    Some(&b"ok"[..]),
                    "{label}"
                );
            }
        }
    }
}

/// TC-STO-002 (store creation, NFR-REL-003): crash at every mutating operation of the very
/// first open of an empty directory, in every crash mode and with several seeds, for a plaintext
/// and an encrypted store. Nothing was acknowledged yet, so the next open must yield a valid,
/// empty, writable store — never an error that needs manual cleanup (storage-engine.md §9
/// "Store creation").
#[test]
fn tc_sto_002_crash_during_store_creation_reopens() {
    use rustegon_storage::encryption::{FileKekProvider, KeyManager, SecretKey};
    let options_for = |fs: &Arc<SimFileSystem>, encrypted: bool, create_keys: bool| {
        if !encrypted {
            return options();
        }
        let kek = Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([7; 32])));
        let rng = Arc::new(rustegon_sim_api::OsRng);
        let keys = if create_keys {
            KeyManager::create(fs.clone(), Path::new("/keys"), kek, rng)
        } else {
            KeyManager::open(fs.clone(), Path::new("/keys"), kek, rng)
        };
        EngineOptions {
            encryption: Some(Arc::new(keys.unwrap())),
            ..options()
        }
    };
    let mut failures = Vec::new();
    for encrypted in [false, true] {
        let fs = Arc::new(SimFileSystem::new());
        let opts = options_for(&fs, encrypted, true);
        let start = fs.op_count();
        drop(LsmEngine::open(fs.clone(), Path::new(DIR), opts).unwrap());
        let points = fs.op_count() - start;
        assert!(points > 0, "store creation performed no mutating operation");
        for point in 0..points {
            for mode in CrashMode::ALL {
                for seed in 0..8 {
                    let label = format!(
                        "encrypted {encrypted}, point {point}/{points}, {mode:?}, seed {seed}"
                    );
                    let fs = Arc::new(SimFileSystem::new());
                    let opts = options_for(&fs, encrypted, true);
                    fs.halt_after_ops(point);
                    assert!(
                        LsmEngine::open(fs.clone(), Path::new(DIR), opts).is_err(),
                        "{label}: creation did not hit the halt"
                    );
                    fs.crash(seed * 7919 + point, mode);
                    let opts = options_for(&fs, encrypted, false);
                    let engine = match LsmEngine::open(fs.clone(), Path::new(DIR), opts) {
                        Ok(engine) => engine,
                        Err(e) => {
                            // Collected so one run lists every failing point and mode.
                            failures.push(format!("{label}: reopen failed: {e}"));
                            continue;
                        }
                    };
                    assert_eq!(engine.flushed_seqno(), 0, "{label}");
                    assert_eq!(engine.get(b"k", None).unwrap(), None, "{label}");
                    let mut b = WriteBatch::new();
                    b.put(b"k", b"v".to_vec());
                    engine.write(&b).unwrap();
                    engine.flush().unwrap();
                    drop(engine);
                    let opts = options_for(&fs, encrypted, false);
                    let engine = LsmEngine::open(fs.clone(), Path::new(DIR), opts).unwrap();
                    assert_eq!(
                        engine.get(b"k", None).unwrap().as_deref(),
                        Some(&b"v"[..]),
                        "{label}"
                    );
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// TC-STO-002 (NFR-REL-003): a directory with store files but no `CURRENT` is a committed store
/// that lost its commit point, not an unfinished creation: opening it is refused as corruption
/// and its files are kept, never recreated as an empty store (storage-engine.md §9).
#[test]
fn tc_sto_002_store_files_without_current_are_refused() {
    let fs = Arc::new(SimFileSystem::new());
    let engine = open(&fs);
    let mut b = WriteBatch::new();
    b.put(b"k", b"v".to_vec());
    engine.write(&b).unwrap();
    engine.flush().unwrap();
    drop(engine);
    fs.remove_file(&Path::new(DIR).join("CURRENT")).unwrap();
    let before = fs.read_dir(Path::new(DIR)).unwrap();
    let err = LsmEngine::open(fs.clone(), Path::new(DIR), options())
        .err()
        .expect("open without CURRENT succeeded");
    assert!(err.is_corruption(), "{err}");
    assert_eq!(fs.read_dir(Path::new(DIR)).unwrap(), before);
}

/// FR-EAR-001 through the engine (TC-STO-005 engine part): with a key manager in the options,
/// flushes, compactions, ingests and the MANIFEST are encrypted (no plaintext canary in any
/// file), the store reopens with the same KEK, and a checkpoint of it is encrypted as well and
/// opens with the same KEK through its own DEK registry (FR-BKP-003).
#[test]
fn encrypted_engine_round_trip_without_plaintext_on_disk() {
    use rustegon_storage::{
        encryption::{FileKekProvider, KeyManager, SecretKey},
        version::VersionSet,
    };
    const CANARY: &[u8] = b"CANARY-PLAINTEXT-7f3a";
    let fs = Arc::new(SimFileSystem::new());
    let kek = || Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([42; 32])));
    let keys = |create: bool| {
        let rng = Arc::new(rustegon_sim_api::OsRng);
        let manager = if create {
            KeyManager::create(fs.clone(), Path::new("/keys"), kek(), rng)
        } else {
            KeyManager::open(fs.clone(), Path::new("/keys"), kek(), rng)
        };
        Arc::new(manager.unwrap())
    };
    let encrypted = |create: bool| EngineOptions {
        encryption: Some(keys(create)),
        ..options()
    };
    let engine = LsmEngine::open(fs.clone(), Path::new(DIR), encrypted(true)).unwrap();
    for round in 0..8u8 {
        let mut batch = WriteBatch::new();
        for k in 0..24u8 {
            let mut value = CANARY.to_vec();
            value.push(round);
            batch.put(&key(k), value);
        }
        batch.delete_range(&key(20), &key(22));
        engine.write(&batch).unwrap();
        engine.flush().unwrap();
        engine.compact().unwrap();
    }
    // Ingested external files are plaintext at the source; the store copy must not be.
    fs.create_dir_all(Path::new("/ext")).unwrap();
    let ext = Path::new("/ext/1.sst");
    let mut w = rustegon_storage::sst::SstWriter::new(
        fs.open(ext, OpenMode::CreateNew).unwrap(),
        SstWriterOptions::default(),
    );
    let ik =
        rustegon_storage::InternalKey::new(b"zz-ingested", 0, rustegon_storage::ValueKind::Put);
    w.add(ik.as_bytes(), CANARY).unwrap();
    w.finish().unwrap();
    engine.ingest(&[ext.to_path_buf()]).unwrap();
    fs.remove_file(ext).unwrap();
    let expected = scan_all(&engine);
    assert!(expected.iter().any(|(k, _)| k == b"zz-ingested"));
    // FR-BKP-003: a checkpoint of the encrypted store is encrypted too (scanned below) and
    // carries its own DEK registry.
    let info = engine.checkpoint(Path::new("/cp")).unwrap();
    assert!(info.encrypted && info.file_count > 0);
    drop(engine);
    // A plaintext open of the encrypted MANIFEST is refused (RGN-4006).
    assert!(VersionSet::open(fs.clone(), Path::new(DIR)).is_err());
    assert!(VersionSet::open(fs.clone(), Path::new("/cp")).is_err());

    let dirs = [DIR, "/keys", "/cp", "/cp/keys"];
    let mut leaks = Vec::new();
    for dir in dirs {
        for path in fs.read_dir(Path::new(dir)).unwrap() {
            if dirs.iter().any(|d| path == Path::new(d)) {
                continue;
            }
            let file = fs.open(&path, OpenMode::Read).unwrap();
            let mut bytes = vec![0; usize::try_from(file.size().unwrap()).unwrap()];
            file.read_exact_at(&mut bytes, 0).unwrap();
            if bytes.windows(CANARY.len()).any(|w| w == CANARY)
                || bytes.windows(4).any(|w| w == b"key-")
            {
                leaks.push(path);
            }
        }
    }
    assert_eq!(leaks, Vec::<std::path::PathBuf>::new(), "plaintext on disk");

    let engine = LsmEngine::open(fs.clone(), Path::new(DIR), encrypted(false)).unwrap();
    assert_eq!(scan_all(&engine), expected);

    let cp_keys = KeyManager::open(
        fs.clone(),
        &rustegon_storage::checkpoint_keys_dir(Path::new("/cp")),
        kek(),
        Arc::new(rustegon_sim_api::OsRng),
    )
    .unwrap();
    let cp_options = EngineOptions {
        encryption: Some(Arc::new(cp_keys)),
        ..options()
    };
    let cp = LsmEngine::open(fs.clone(), Path::new("/cp"), cp_options).unwrap();
    assert_eq!(scan_all(&cp), expected);
}

/// Every visible `(key, value)` of `engine` in key order.
fn scan_all(engine: &LsmEngine) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut it = engine.iterator(None).unwrap();
    it.seek_to_first().unwrap();
    let mut out = Vec::new();
    while it.valid() {
        out.push((it.key().to_vec(), it.value().to_vec()));
        it.next().unwrap();
    }
    out
}

/// TC-STO-007: a checkpoint taken while writers run opens as its own store, holds every write
/// acknowledged before the call, never half a batch, and is unaffected by later source activity.
#[test]
fn tc_sto_007_checkpoint_consistent_under_concurrent_writes() {
    let fs = Arc::new(SimFileSystem::new());
    let engine = Arc::new(open(&fs));
    let done = Arc::new(AtomicBool::new(false));
    let writer = {
        let (engine, done) = (Arc::clone(&engine), Arc::clone(&done));
        thread::spawn(move || {
            let mut round = 0u32;
            while !done.load(Ordering::Acquire) {
                round += 1;
                let mut batch = WriteBatch::new();
                let value = round.to_le_bytes().to_vec();
                batch.put(b"a", value.clone()).put(b"b", value);
                engine.write(&batch).unwrap();
                if round.is_multiple_of(50) {
                    engine.compact().unwrap();
                }
            }
            round
        })
    };
    // Let the writer get going, then checkpoint mid-stream.
    while engine.last_seqno() < 400 {
        thread::yield_now();
    }
    let acked_before = engine.last_seqno();
    let info = engine.checkpoint(Path::new("/checkpoint")).unwrap();
    done.store(true, Ordering::Release);
    let rounds = writer.join().unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();

    let cp = LsmEngine::open(fs.clone(), Path::new("/checkpoint"), options()).unwrap();
    assert!(
        cp.last_seqno() >= acked_before,
        "acknowledged writes missing"
    );
    assert!(info.file_count > 0);
    assert!(
        info.seqno >= acked_before,
        "image misses acknowledged writes"
    );
    let a = cp.get(b"a", None).unwrap().unwrap();
    let b = cp.get(b"b", None).unwrap().unwrap();
    assert_eq!(a, b, "half a batch in the checkpoint");
    let at = u32::from_le_bytes(a[..4].try_into().unwrap());
    // Each batch holds 2 seqnos, so round r ends at seqno 2r.
    assert!(u64::from(at) * 2 >= acked_before && at <= rounds);
    // The source moved on; the checkpoint did not.
    let latest = engine.get(b"a", None).unwrap().unwrap();
    assert_eq!(u32::from_le_bytes(latest[..4].try_into().unwrap()), rounds);
    assert_eq!(cp.get(b"a", None).unwrap().unwrap(), a);
}

/// T14 wired into the engine: L0 growth raises the write condition, compaction clears it.
#[test]
fn engine_reports_write_condition() {
    use rustegon_storage::{StallReason, WriteCondition};
    let fs = Arc::new(SimFileSystem::new());
    let engine = open(&fs);
    assert_eq!(engine.write_condition(), WriteCondition::Normal);
    for round in 0..20u8 {
        let mut batch = WriteBatch::new();
        batch.put(&key(round), put_value(round, round));
        engine.write(&batch).unwrap();
        engine.flush().unwrap();
    }
    assert_eq!(
        engine.write_condition(),
        WriteCondition::Slowdown(StallReason::L0Files)
    );
    engine.compact().unwrap();
    assert_eq!(engine.write_condition(), WriteCondition::Normal);
}

/// `(filter instance id, user key)` of every filter call.
type Calls = Vec<(usize, Vec<u8>)>;

/// A filter that records which instance was consulted on which key; forks one instance per
/// sub-job and removes `gc/` keys.
#[derive(Default)]
struct RecordingFilter {
    id: usize,
    forks: Arc<AtomicUsize>,
    calls: Arc<Mutex<Calls>>,
}

impl CompactionFilter for RecordingFilter {
    fn filter(&self, _level: usize, user_key: &[u8], _value: &[u8]) -> FilterDecision {
        self.calls
            .lock()
            .unwrap()
            .push((self.id, user_key.to_vec()));
        if user_key.starts_with(b"gc/") {
            FilterDecision::Remove
        } else {
            FilterDecision::Keep
        }
    }

    fn for_subcompaction(&self) -> Option<Box<dyn CompactionFilter>> {
        Some(Box::new(Self {
            id: self.forks.fetch_add(1, Ordering::SeqCst) + 1,
            forks: Arc::clone(&self.forks),
            calls: Arc::clone(&self.calls),
        }))
    }
}

/// TC-STO-004 (filter wiring for the MVCC GC filter): the engine runs
/// `EngineOptions::compaction_filter` in its compactions with one fresh instance per sub-job,
/// each consulted in ascending key order, also when sub-jobs run on parallel threads.
#[test]
fn tc_sto_004_engine_forks_compaction_filter_per_subjob() {
    let filter = RecordingFilter::default();
    let (forks, calls) = (Arc::clone(&filter.forks), Arc::clone(&filter.calls));
    let mut opts = options();
    opts.compaction.parallel_subcompactions = true;
    opts.compaction_filter = Some(Arc::new(filter));
    let fs = Arc::new(SimFileSystem::new());
    let engine = LsmEngine::open(fs, Path::new(DIR), opts).unwrap();
    for round in 0..6u8 {
        let mut batch = WriteBatch::new();
        for k in 0..40u8 {
            let prefix: &[u8] = if k % 3 == 0 { b"gc/" } else { b"kv/" };
            let mut key = prefix.to_vec();
            key.extend_from_slice(&[k, round]);
            batch.put(&key, vec![round; 32]);
        }
        engine.write(&batch).unwrap();
        engine.flush().unwrap();
    }
    engine.compact().unwrap();
    assert!(
        forks.load(Ordering::SeqCst) > 1,
        "expected several sub-jobs"
    );
    let calls = calls.lock().unwrap();
    assert!(!calls.is_empty());
    assert!(
        calls.iter().all(|(id, _)| *id > 0),
        "the shared instance was used"
    );
    let mut per_instance: BTreeMap<usize, Vec<Vec<u8>>> = BTreeMap::new();
    for (id, key) in calls.iter() {
        per_instance.entry(*id).or_default().push(key.clone());
    }
    for keys in per_instance.values() {
        assert!(
            keys.windows(2).all(|w| w[0] < w[1]),
            "keys out of order within a sub-job"
        );
    }
    // Every key the filter removed is gone for readers; kept keys remain.
    let removed: Vec<&Vec<u8>> = calls
        .iter()
        .map(|(_, k)| k)
        .filter(|k| k.starts_with(b"gc/"))
        .collect();
    assert_ne!(removed.len(), 0);
    for key in removed {
        assert_eq!(engine.get(key, None).unwrap(), None);
    }
    assert!(
        engine
            .get(&[b"kv/".as_slice(), &[1, 0]].concat(), None)
            .unwrap()
            .is_some()
    );
}

#[test]
fn write_batch_ops_lists_operations_in_insertion_order() {
    // `WriteBatch::ops` is what a replicated command serialises (replication.md "Command
    // format v1"): every operation, in order, with its exact arguments.
    let mut batch = WriteBatch::new();
    batch
        .put(b"a", b"1".to_vec())
        .delete(b"b")
        .single_delete(b"c")
        .merge(b"d", b"op".to_vec())
        .delete_range(b"e", b"f");
    assert_eq!(
        batch.ops(),
        [
            BatchOp::Put(b"a".to_vec(), Bytes::from_static(b"1")),
            BatchOp::Delete(b"b".to_vec()),
            BatchOp::SingleDelete(b"c".to_vec()),
            BatchOp::Merge(b"d".to_vec(), Bytes::from_static(b"op")),
            BatchOp::DeleteRange(b"e".to_vec(), b"f".to_vec()),
        ]
    );
    assert_eq!(WriteBatch::new().ops(), []);
}
