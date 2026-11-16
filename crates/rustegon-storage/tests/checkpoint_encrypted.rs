// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Checkpoints of encrypted stores (storage-engine.md §7, §10; FR-BKP-003 local snapshots,
//! PD-064; AC-BKP-003; TC-BKP-005):
//! - the checkpoint carries its own DEK registry holding exactly the DEKs of its SSTs and
//!   MANIFEST, opens with the store KEK and reads every key; a wrong or missing KEK is
//!   `KeyUnavailable` (`RGN-4006`);
//! - it stays O(metadata): every SST is hard-linked and only the registry copy, the MANIFEST and
//!   `CURRENT` are written;
//! - a crash at every file-system operation of the checkpoint leaves either no checkpoint or a
//!   complete, openable one, and never disturbs the source.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_sim_api::{File, FileSystem, OpenMode, Rng};
use rustegon_storage::{
    CheckpointInfo, EngineOptions, LsmEngine, MAX_SEQNO, ReadView, StorageError, TableCache,
    WriteBatch, checkpoint_keys_dir,
    compaction::CompactionOptions,
    encryption::{FileKekProvider, KekProvider, KeyManager, SecretKey},
    sst::{SstReaderOptions, SstWriterOptions},
    version::{VersionSet, manifest_file_name, sst_file_name},
};

const DIR: &str = "/data/lsm";
const KEYS: &str = "/data/keys";
const CKPT: &str = "/data/checkpoints/c1";

/// Visible `(key, value)` pairs in key order.
type Entries = Vec<(Vec<u8>, Vec<u8>)>;

/// Deterministic splitmix64 RNG, so every rebuild of a crash setup writes identical bytes.
#[derive(Debug)]
struct SeededRng(AtomicU64);

impl Rng for SeededRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let mut z = self
                .0
                .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
                .wrapping_add(0x9E37_79B9_7F4A_7C15);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
    }
}

fn rng(seed: u64) -> Arc<dyn Rng> {
    Arc::new(SeededRng(AtomicU64::new(seed)))
}

fn provider(seed: u8) -> Arc<dyn KekProvider> {
    Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([seed; 32])))
}

/// Counts appended bytes and hard links, to show what a checkpoint writes (AC-BKP-003).
struct CountingFs {
    sim: Arc<SimFileSystem>,
    appended: Arc<AtomicU64>,
    links: AtomicU64,
}

struct CountingFile {
    inner: Box<dyn File>,
    appended: Arc<AtomicU64>,
}

impl File for CountingFile {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.inner.read_exact_at(buf, offset)
    }
    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.appended.fetch_add(buf.len() as u64, Ordering::Relaxed);
        self.inner.append(buf)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }
    fn size(&self) -> io::Result<u64> {
        self.inner.size()
    }
}

impl FileSystem for CountingFs {
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Box<dyn File>> {
        Ok(Box::new(CountingFile {
            inner: self.sim.open(path, mode)?,
            appended: Arc::clone(&self.appended),
        }))
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
    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        self.links.fetch_add(1, Ordering::Relaxed);
        self.sim.hard_link(original, link)
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.sim.read_dir(path)
    }
    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        self.sim.sync_dir(path)
    }
}

/// Tiny shapes so a few rounds already compact into several files and levels; sequential
/// subcompactions keep the file-system operation order reproducible for the crash sweep.
fn engine_options(keys: Arc<KeyManager>) -> EngineOptions {
    EngineOptions {
        memtable_size: 1 << 20,
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
            max_subcompactions: 4,
            parallel_subcompactions: false,
            ..CompactionOptions::default()
        },
        encryption: Some(keys),
        ..EngineOptions::default()
    }
}

/// An encrypted engine in `DIR` (registry in `KEYS`, KEK 1) after `rounds` rounds of
/// overwrites and deletes, each flushed and compacted; returns it with its expected contents.
fn build(fs: &Arc<dyn FileSystem>, rounds: u32) -> (LsmEngine, Entries) {
    let keys = KeyManager::create(Arc::clone(fs), Path::new(KEYS), provider(1), rng(7)).unwrap();
    let engine = LsmEngine::open(
        Arc::clone(fs),
        Path::new(DIR),
        engine_options(Arc::new(keys)),
    )
    .unwrap();
    let mut model = BTreeMap::new();
    for round in 0..rounds {
        let mut batch = WriteBatch::new();
        for i in 0..60u32 {
            let key = format!("key-{:03}", (round * 23 + i) % 150).into_bytes();
            if i % 7 == 6 {
                batch.delete(&key);
                model.remove(&key);
            } else {
                let value = format!("r{round}-i{i}-{}", "v".repeat(40)).into_bytes();
                batch.put(&key, value.clone());
                model.insert(key, value);
            }
        }
        engine.write(&batch).unwrap();
        engine.flush().unwrap();
        engine.compact().unwrap();
    }
    (engine, model.into_iter().collect())
}

/// Every visible `(key, value)` of the store in `dir` whose registry is in `keys_dir`, opened
/// with KEK `kek` (`None`: no encryption configured), through `VersionSet::open_with` (which,
/// unlike `LsmEngine::open`, never creates a store where `CURRENT` is missing).
fn read_store(
    fs: &Arc<dyn FileSystem>,
    dir: &Path,
    keys_dir: &Path,
    kek: Option<u8>,
) -> Result<Entries, StorageError> {
    let keys = match kek {
        Some(seed) => Some(Arc::new(KeyManager::open(
            Arc::clone(fs),
            keys_dir,
            provider(seed),
            rng(11),
        )?)),
        None => None,
    };
    let versions = VersionSet::open_with(Arc::clone(fs), dir, keys.clone())?;
    let tables = Arc::new(TableCache::new(
        Arc::clone(fs),
        dir.to_path_buf(),
        SstReaderOptions {
            encryption: keys,
            ..SstReaderOptions::default()
        },
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

fn read_checkpoint(fs: &Arc<dyn FileSystem>, kek: Option<u8>) -> Result<Entries, StorageError> {
    read_store(
        fs,
        Path::new(CKPT),
        &checkpoint_keys_dir(Path::new(CKPT)),
        kek,
    )
}

fn checkpoint(engine: &LsmEngine) -> rustegon_storage::Result<CheckpointInfo> {
    engine.checkpoint(Path::new(CKPT))
}

/// FR-BKP-003 / PD-064: the checkpoint of an encrypted store opens with the store KEK through
/// its own registry, which holds exactly the DEKs of its SSTs and MANIFEST; the copy outlives
/// the source; a wrong or missing KEK is `KeyUnavailable`.
#[test]
fn tc_bkp_005_encrypted_checkpoint_opens_with_the_kek() {
    let sim = Arc::new(SimFileSystem::new());
    let fs: Arc<dyn FileSystem> = sim.clone();
    let (engine, expected) = build(&fs, 8);
    let ssts: Vec<u64> = engine
        .current_version()
        .all_files()
        .map(|(_, f)| f.number)
        .collect();
    let info = checkpoint(&engine).unwrap();
    assert!(info.encrypted);
    assert!(
        info.file_count >= 2,
        "workload too small: {}",
        info.file_count
    );
    assert_eq!(info.bytes_copied, 0);

    // Exactly the checkpoint's DEKs: its SSTs and its MANIFEST, nothing else of the source.
    let cp_keys = KeyManager::open(
        Arc::clone(&fs),
        &checkpoint_keys_dir(Path::new(CKPT)),
        provider(1),
        rng(3),
    )
    .unwrap();
    let mut want = ssts.clone();
    want.push(info.manifest_number);
    want.sort_unstable();
    assert_eq!(cp_keys.file_numbers(), want);
    assert!(cp_keys.file_cipher(info.manifest_number).unwrap().is_some());
    drop(cp_keys);

    // Wrong KEK: refused at the registry (RGN-4006), before any data is read.
    let err = read_checkpoint(&fs, Some(2)).unwrap_err();
    assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");
    // No KEK: the encrypted MANIFEST does not open as plaintext.
    let err = read_checkpoint(&fs, None).unwrap_err();
    assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");

    // The checkpoint survives the source going on (new DEKs, forgotten DEKs) and being deleted.
    let mut batch = WriteBatch::new();
    batch.put(b"key-after", b"later".to_vec());
    engine.write(&batch).unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();
    drop(engine);
    for dir in [DIR, KEYS] {
        for path in fs.read_dir(Path::new(dir)).unwrap() {
            fs.remove_file(&path).unwrap();
        }
        fs.sync_dir(Path::new(dir)).unwrap();
    }
    sim.crash(0, CrashMode::Clean);
    assert_eq!(read_checkpoint(&fs, Some(1)).unwrap(), expected);
    // Reopened (and so rewritten: new MANIFEST, DEK of the old one forgotten) it still reads.
    assert_eq!(read_checkpoint(&fs, Some(1)).unwrap(), expected);

    // The engine opens the checkpoint as a store of its own with the same KEK.
    let keys = KeyManager::open(
        Arc::clone(&fs),
        &checkpoint_keys_dir(Path::new(CKPT)),
        provider(1),
        rng(5),
    )
    .unwrap();
    let cp = LsmEngine::open(
        Arc::clone(&fs),
        Path::new(CKPT),
        engine_options(Arc::new(keys)),
    )
    .unwrap();
    for (key, value) in &expected {
        assert_eq!(
            cp.get(key, None).unwrap().as_deref(),
            Some(value.as_slice())
        );
    }
    assert_eq!(cp.get(b"key-after", None).unwrap(), None);
}

/// AC-BKP-003: the checkpoint costs O(metadata). Every SST is hard-linked, nothing is copied,
/// and the bytes written are only the registry copy (two small rewrites), the MANIFEST and
/// `CURRENT`, independent of the data size.
#[test]
fn tc_bkp_005_checkpoint_is_o_metadata() {
    let sim = Arc::new(SimFileSystem::new());
    let appended = Arc::new(AtomicU64::new(0));
    let counting = Arc::new(CountingFs {
        sim: Arc::clone(&sim),
        appended: Arc::clone(&appended),
        links: AtomicU64::new(0),
    });
    let fs: Arc<dyn FileSystem> = counting.clone();
    let (engine, mut expected) = build(&fs, 24);
    // A few large incompressible values: data bytes grow, file count barely does, so the
    // checkpoint's writes must not grow with them.
    let mut x = 0x9E37_79B9_7F4A_7C15_u64;
    let mut batch = WriteBatch::new();
    for i in 0..4u8 {
        let value: Vec<u8> = (0..64 << 10)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect();
        let key = format!("zz-big-{i}").into_bytes();
        batch.put(&key, value.clone());
        expected.push((key, value));
    }
    engine.write(&batch).unwrap();
    engine.flush().unwrap();
    let version = engine.current_version();
    let data: u64 = version.all_files().map(|(_, f)| f.size).sum();
    let files = version.all_files().count();
    drop(version);

    appended.store(0, Ordering::Relaxed);
    counting.links.store(0, Ordering::Relaxed);
    let info = checkpoint(&engine).unwrap();
    let written = appended.load(Ordering::Relaxed);

    assert_eq!(info.file_count, files);
    assert_eq!((info.bytes_linked, info.bytes_copied), (data, 0));
    assert_eq!(counting.links.load(Ordering::Relaxed), files as u64);
    // What a checkpoint writes besides links: the registry copy (written twice, ~100 bytes per
    // DEK each time), the MANIFEST snapshot (~100 bytes per file) and CURRENT.
    let registry = sim_size(
        &sim,
        &checkpoint_keys_dir(Path::new(CKPT)).join("registry.enc"),
    );
    let manifest = sim_size(
        &sim,
        &Path::new(CKPT).join(manifest_file_name(info.manifest_number)),
    );
    let current = sim_size(&sim, &Path::new(CKPT).join("CURRENT"));
    assert!(
        written <= 2 * registry + manifest + current,
        "checkpoint wrote {written} bytes: registry {registry}, MANIFEST {manifest}, \
         CURRENT {current}"
    );
    // Per file, the registry copy and MANIFEST cost a few hundred bytes, whatever its size.
    assert!(
        written <= files as u64 * 512 + 1024,
        "checkpoint wrote {written} bytes for {files} files"
    );
    assert!(
        written * 10 < data,
        "checkpoint wrote {written} bytes for {data} bytes of SSTs"
    );
    // Linked, not copied: the checkpoint's SSTs are the source's bytes.
    for (_, f) in engine.current_version().all_files() {
        let name = sst_file_name(f.number);
        assert_eq!(
            sim_bytes(&sim, &Path::new(DIR).join(&name)),
            sim_bytes(&sim, &Path::new(CKPT).join(&name))
        );
    }
    drop(engine);
    assert_eq!(read_checkpoint(&fs, Some(1)).unwrap(), expected);
}

fn sim_bytes(sim: &SimFileSystem, path: &Path) -> Vec<u8> {
    let f = sim.open(path, OpenMode::Read).unwrap();
    let mut buf = vec![0u8; usize::try_from(f.size().unwrap()).unwrap()];
    f.read_exact_at(&mut buf, 0).unwrap();
    buf
}

fn sim_size(sim: &SimFileSystem, path: &Path) -> u64 {
    sim.open(path, OpenMode::Read).unwrap().size().unwrap()
}

/// NFR-REL-003 for checkpoints of encrypted stores: halting at every mutating operation of the
/// checkpoint, in every crash mode, leaves either no committed checkpoint (no `CURRENT`; it
/// does not open) or a complete one that opens with the KEK and holds exactly the source
/// contents; the source always reopens unchanged.
#[test]
fn tc_bkp_005_encrypted_checkpoint_survives_crash_at_every_op() {
    let setup = || {
        let sim = Arc::new(SimFileSystem::new());
        let fs: Arc<dyn FileSystem> = sim.clone();
        let (engine, expected) = build(&fs, 6);
        (sim, fs, engine, expected)
    };
    let (sim, _fs, engine, _) = setup();
    let before = sim.op_count();
    let info = checkpoint(&engine).unwrap();
    let total = sim.op_count() - before;
    assert!(
        info.file_count >= 2,
        "workload too small: {}",
        info.file_count
    );
    drop(engine);

    let (mut complete, mut absent) = (0, 0);
    // `point == total`: the checkpoint completed, then power was lost; it must survive.
    for point in 0..=total {
        for (m, mode) in CrashMode::ALL.into_iter().enumerate() {
            let (sim, fs, engine, expected) = setup();
            if point < total {
                sim.halt_after_ops(point);
                assert!(checkpoint(&engine).is_err(), "point {point} did not halt");
            } else {
                checkpoint(&engine).unwrap();
            }
            drop(engine);
            sim.crash(point * 4 + m as u64, mode);
            let ctx = format!("point {point} of {total}, {mode:?}");
            let committed = fs
                .open(&Path::new(CKPT).join("CURRENT"), OpenMode::Read)
                .is_ok();
            match read_checkpoint(&fs, Some(1)) {
                Ok(contents) => {
                    assert!(committed, "{ctx}: opened without CURRENT");
                    assert_eq!(contents, expected, "{ctx}");
                    complete += 1;
                }
                // Not committed: no CURRENT, and possibly no registry copy yet.
                Err(e) => {
                    assert!(!committed, "{ctx}: committed checkpoint does not open: {e}");
                    let clean = match &e {
                        StorageError::Io(io) => io.kind() == io::ErrorKind::NotFound,
                        StorageError::KeyUnavailable(msg) => msg.contains("not found"),
                        _ => false,
                    };
                    assert!(clean, "{ctx}: unclean failure {e}");
                    absent += 1;
                }
            }
            // The source is unaffected by the interrupted checkpoint.
            assert_eq!(
                read_store(&fs, Path::new(DIR), Path::new(KEYS), Some(1)).unwrap(),
                expected,
                "{ctx}"
            );
        }
    }
    assert!(
        complete > 0 && absent > 0,
        "complete {complete}, absent {absent}"
    );
}
