// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Checkpoint integration tests (M1 T13; storage-engine.md §10; FR-BKP-003; TC-STO-007): a
//! checkpoint opens as a store holding exactly the source contents at capture time while the
//! source keeps flushing and compacting, survives deletion of the source, is atomic under a crash
//! at every operation, and falls back to copying where hard links are unsupported.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_sim_api::{File, FileSystem, OpenMode};
use rustegon_storage::{
    CheckpointSource, MAX_SEQNO, Memtable, ReadView, SeqNo, StorageError, TableCache, ValueKind,
    compaction::{
        CompactionOptions, delete_obsolete_files, install_compaction, pick_compaction,
        run_compaction,
    },
    create_checkpoint, flush_memtable,
    sst::{SstReaderOptions, SstWriterOptions},
    version::VersionSet,
};

const DIR: &str = "/store";
const CKPT: &str = "/checkpoints/c1";

/// Visible `(key, value)` pairs in key order.
type Entries = Vec<(Vec<u8>, Vec<u8>)>;

/// Tiny shapes so a few rounds already compact into several levels.
fn options() -> CompactionOptions {
    CompactionOptions {
        l0_trigger: 2,
        level_base_bytes: 2 << 10,
        level_multiplier: 4,
        target_file_size_base: 1 << 10,
        max_target_file_size: 2 << 10,
        writer: SstWriterOptions {
            block_size: 256,
            ..SstWriterOptions::default()
        },
        // Subcompactions split L0 compactions; sequential so the crash sweeps here see a
        // reproducible order of file-system operations (TC-STO-002, `compaction/job.rs`).
        max_subcompactions: 4,
        parallel_subcompactions: false,
        ..CompactionOptions::default()
    }
}

/// A `SimFileSystem` whose hard links fail with `kind` (ReFS/FAT, cross-device, …).
struct LinklessFs {
    sim: Arc<SimFileSystem>,
    kind: io::ErrorKind,
}

impl FileSystem for LinklessFs {
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Box<dyn File>> {
        self.sim.open(path, mode)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.sim.create_dir_all(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.sim.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.sim.remove_file(path)
    }
    fn hard_link(&self, _original: &Path, _link: &Path) -> io::Result<()> {
        Err(self.kind.into())
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.sim.read_dir(path)
    }
    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        self.sim.sync_dir(path)
    }
}

/// A source store driven by rounds of writes, each flushed and compacted until quiet.
struct Store {
    sim: Arc<SimFileSystem>,
    fs: Arc<dyn FileSystem>,
    versions: VersionSet,
    seqno: SeqNo,
    model: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Store {
    fn new(sim: Arc<SimFileSystem>, fs: Arc<dyn FileSystem>) -> Self {
        let versions = VersionSet::create(Arc::clone(&fs), Path::new(DIR)).unwrap();
        Self {
            sim,
            fs,
            versions,
            seqno: 0,
            model: BTreeMap::new(),
        }
    }

    fn sim() -> Self {
        let sim = Arc::new(SimFileSystem::new());
        Self::new(Arc::clone(&sim), sim)
    }

    /// Overwrites a sliding window of keys (deleting every fifth), flushes, compacts.
    fn round(&mut self, round: u32) {
        let memtable = Memtable::new();
        for i in 0..40u32 {
            let key = format!("key-{:03}", (round * 17 + i) % 120).into_bytes();
            self.seqno += 1;
            if i % 5 == 4 {
                memtable.add(self.seqno, ValueKind::Delete, &key, Bytes::new());
                self.model.remove(&key);
            } else {
                let value = format!("r{round}-i{i}-{}", "x".repeat(20)).into_bytes();
                memtable.add(self.seqno, ValueKind::Put, &key, Bytes::from(value.clone()));
                self.model.insert(key, value);
            }
        }
        self.put_and_flush(&memtable);
    }

    fn put_and_flush(&mut self, memtable: &Memtable) {
        let options = options();
        flush_memtable(
            self.fs.as_ref(),
            Path::new(DIR),
            &mut self.versions,
            memtable,
            &options.writer,
            self.seqno,
        )
        .unwrap();
        loop {
            let current = self.versions.current();
            let Some(c) = pick_compaction(&current, &options, &BTreeSet::default()) else {
                break;
            };
            drop(current);
            let versions = &mut self.versions;
            let out = run_compaction(
                self.fs.as_ref(),
                Path::new(DIR),
                &c,
                &options,
                &[],
                None,
                &mut || versions.new_file_number(),
            )
            .unwrap();
            install_compaction(&mut self.versions, &c, &out).unwrap();
            delete_obsolete_files(self.fs.as_ref(), &self.versions, &BTreeSet::default()).unwrap();
        }
    }
}

/// Every visible `(key, value)` of the store in `dir`, read through a fresh `VersionSet::open`
/// and `ReadView`; also checks point lookups against the scan.
fn read_store(fs: &Arc<dyn FileSystem>, dir: &str) -> Result<Entries, StorageError> {
    let versions = VersionSet::open(Arc::clone(fs), Path::new(dir))?;
    let tables = Arc::new(TableCache::new(
        Arc::clone(fs),
        dir.into(),
        SstReaderOptions::default(),
    ));
    let view = ReadView::new(Vec::new(), versions.current(), tables);
    let mut it = view.iterator(MAX_SEQNO)?;
    it.seek_to_first()?;
    let mut out = Vec::new();
    while it.valid() {
        out.push((it.key().to_vec(), it.value().to_vec()));
        it.next()?;
    }
    for (key, value) in &out {
        assert_eq!(view.get(key, MAX_SEQNO)?.as_deref(), Some(value.as_slice()));
    }
    Ok(out)
}

fn entries(model: &BTreeMap<Vec<u8>, Vec<u8>>) -> Entries {
    model.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

#[test]
fn tc_sto_007_checkpoint_matches_capture_while_source_flushes_and_compacts() {
    let mut store = Store::sim();
    for round in 0..6 {
        store.round(round);
    }
    let at_capture = entries(&store.model);
    let source = CheckpointSource::capture(&store.versions);
    let captured: Vec<_> = source.version.all_files().map(|(_, f)| f.number).collect();

    // The source keeps going before the files are linked: its compactions must not delete the
    // captured version's inputs, because the capture pins them.
    for round in 6..12 {
        store.round(round);
    }
    let current: BTreeSet<u64> = store
        .versions
        .current()
        .all_files()
        .map(|(_, f)| f.number)
        .collect();
    assert!(
        captured.iter().any(|n| !current.contains(n)),
        "workload did not compact away any captured file"
    );

    let info =
        create_checkpoint(store.fs.as_ref(), Path::new(DIR), &source, Path::new(CKPT)).unwrap();
    assert_eq!(info.seqno, source.flushed_seqno);
    assert_eq!(info.last_seqno, source.last_seqno);
    assert_eq!(info.file_count, captured.len());
    let total: u64 = source.version.all_files().map(|(_, f)| f.size).sum();
    assert_eq!((info.bytes_linked, info.bytes_copied), (total, 0));
    assert!(info.manifest_number > captured.iter().copied().max().unwrap());

    // Releasing the capture lets the source delete the files; the checkpoint keeps its links.
    drop(source);
    assert!(
        delete_obsolete_files(store.fs.as_ref(), &store.versions, &BTreeSet::default()).unwrap()
            > 0
    );
    assert_eq!(read_store(&store.fs, CKPT).unwrap(), at_capture);
    let reopened = VersionSet::open(Arc::clone(&store.fs), Path::new(CKPT)).unwrap();
    assert_eq!(reopened.flushed_seqno(), info.seqno);
    assert_eq!(reopened.last_seqno(), info.last_seqno);
    drop(reopened);

    // The source still reads its own, newer contents.
    let now = entries(&store.model);
    assert_ne!(now, at_capture);
    drop(store.versions);
    assert_eq!(read_store(&store.fs, DIR).unwrap(), now);

    // Deleting the whole source does not affect the checkpoint.
    for path in store.fs.read_dir(Path::new(DIR)).unwrap() {
        store.fs.remove_file(&path).unwrap();
    }
    store.fs.sync_dir(Path::new(DIR)).unwrap();
    store.sim.crash(0, CrashMode::Clean);
    assert_eq!(read_store(&store.fs, CKPT).unwrap(), at_capture);
}

#[test]
fn tc_sto_007_checkpoint_of_an_empty_store_opens_empty() {
    let store = Store::sim();
    let source = CheckpointSource::capture(&store.versions);
    let info =
        create_checkpoint(store.fs.as_ref(), Path::new(DIR), &source, Path::new(CKPT)).unwrap();
    assert_eq!((info.file_count, info.seqno), (0, 0));
    assert_eq!(read_store(&store.fs, CKPT).unwrap(), Entries::new());
}

#[test]
fn tc_sto_007_target_must_be_empty_and_not_the_source() {
    let mut store = Store::sim();
    store.round(0);
    let source = CheckpointSource::capture(&store.versions);
    let fs = store.fs.as_ref();
    let err = create_checkpoint(fs, Path::new(DIR), &source, Path::new(DIR)).unwrap_err();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");

    fs.create_dir_all(Path::new(CKPT)).unwrap();
    drop(
        fs.open(&Path::new(CKPT).join("stray"), OpenMode::CreateNew)
            .unwrap(),
    );
    let err = create_checkpoint(fs, Path::new(DIR), &source, Path::new(CKPT)).unwrap_err();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");

    // A completed checkpoint is not empty either: a second one into it is refused.
    let second = "/checkpoints/c2";
    create_checkpoint(fs, Path::new(DIR), &source, Path::new(second)).unwrap();
    let err = create_checkpoint(fs, Path::new(DIR), &source, Path::new(second)).unwrap_err();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
}

#[test]
fn tc_sto_007_copy_fallback_when_hard_links_are_unsupported() {
    for kind in [io::ErrorKind::Unsupported, io::ErrorKind::CrossesDevices] {
        let sim = Arc::new(SimFileSystem::new());
        let fs: Arc<dyn FileSystem> = Arc::new(LinklessFs {
            sim: Arc::clone(&sim),
            kind,
        });
        let mut store = Store::new(sim, fs);
        for round in 0..4 {
            store.round(round);
        }
        // One SST larger than the copy chunk, so the copy loop runs more than once.
        let big = Memtable::new();
        store.seqno += 1;
        // Incompressible (xorshift) bytes, so the SST really exceeds the chunk size.
        let mut x = 0x9E37_79B9_7F4A_7C15_u64;
        let value: Vec<u8> = (0..3 << 19)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect();
        big.add(
            store.seqno,
            ValueKind::Put,
            b"key-big",
            Bytes::from(value.clone()),
        );
        store.model.insert(b"key-big".to_vec(), value);
        store.put_and_flush(&big);

        let source = CheckpointSource::capture(&store.versions);
        let info =
            create_checkpoint(store.fs.as_ref(), Path::new(DIR), &source, Path::new(CKPT)).unwrap();
        let total: u64 = source.version.all_files().map(|(_, f)| f.size).sum();
        assert_eq!(
            (info.bytes_linked, info.bytes_copied),
            (0, total),
            "{kind:?}"
        );
        assert!(total > 1 << 20);

        // Copies are independent of the source files.
        drop(source);
        drop(store.versions);
        for path in store.fs.read_dir(Path::new(DIR)).unwrap() {
            store.fs.remove_file(&path).unwrap();
        }
        assert_eq!(read_store(&store.fs, CKPT).unwrap(), entries(&store.model));
    }
}

#[test]
fn tc_sto_007_other_link_errors_are_returned() {
    let sim = Arc::new(SimFileSystem::new());
    let fs: Arc<dyn FileSystem> = Arc::new(LinklessFs {
        sim: Arc::clone(&sim),
        kind: io::ErrorKind::NotFound,
    });
    let mut store = Store::new(sim, fs);
    store.round(0);
    let source = CheckpointSource::capture(&store.versions);
    let err =
        create_checkpoint(store.fs.as_ref(), Path::new(DIR), &source, Path::new(CKPT)).unwrap_err();
    assert!(
        matches!(&err, StorageError::Io(e) if e.kind() == io::ErrorKind::NotFound),
        "{err}"
    );
    assert!(read_store(&store.fs, CKPT).is_err());
}

/// A source with several levels, its contents, and the op count before the checkpoint starts.
fn crash_setup(linkless: bool) -> (Store, Entries) {
    let sim = Arc::new(SimFileSystem::new());
    let fs: Arc<dyn FileSystem> = if linkless {
        Arc::new(LinklessFs {
            sim: Arc::clone(&sim),
            kind: io::ErrorKind::Unsupported,
        })
    } else {
        sim.clone()
    };
    let mut store = Store::new(sim, fs);
    for round in 0..9 {
        store.round(round);
    }
    let expected = entries(&store.model);
    (store, expected)
}

fn checkpoint(store: &Store) -> rustegon_storage::Result<rustegon_storage::CheckpointInfo> {
    let source = CheckpointSource::capture(&store.versions);
    create_checkpoint(store.fs.as_ref(), Path::new(DIR), &source, Path::new(CKPT))
}

#[test]
fn tc_sto_007_crash_at_every_checkpoint_op_leaves_nothing_or_a_complete_checkpoint() {
    for linkless in [false, true] {
        let (store, _) = crash_setup(linkless);
        let before = store.sim.op_count();
        let info = checkpoint(&store).unwrap();
        let total = store.sim.op_count() - before;
        assert!(
            info.file_count >= 2,
            "workload too small: {}",
            info.file_count
        );

        let (mut complete, mut absent) = (0, 0);
        // `point == total`: the checkpoint completed, then power was lost; it must survive.
        for point in 0..=total {
            for (m, mode) in CrashMode::ALL.into_iter().enumerate() {
                let (store, expected) = crash_setup(linkless);
                if point < total {
                    store.sim.halt_after_ops(point);
                    assert!(checkpoint(&store).is_err(), "point {point} did not halt");
                } else {
                    checkpoint(&store).unwrap();
                }
                store.sim.crash(point * 4 + m as u64, mode);
                let ctx = format!("linkless {linkless}, point {point}, {mode:?}");
                match read_store(&store.fs, CKPT) {
                    Ok(contents) => {
                        assert_eq!(contents, expected, "{ctx}");
                        complete += 1;
                    }
                    // No CURRENT: the checkpoint was never committed and does not open.
                    Err(StorageError::Io(e)) if e.kind() == io::ErrorKind::NotFound => absent += 1,
                    Err(e) => panic!("{ctx}: unclean failure {e}"),
                }
                // The source is unaffected by the interrupted checkpoint.
                drop(store.versions);
                assert_eq!(read_store(&store.fs, DIR).unwrap(), expected, "{ctx}");
            }
        }
        assert!(
            complete > 0 && absent > 0,
            "complete {complete}, absent {absent}"
        );
    }
}
