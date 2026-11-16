// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Encryption at rest integration tests (storage-engine.md §7, §9; security.md §6; FR-EAR-001
//! format part; AC-EAR-001, AC-EAR-002 for the `file` provider).
//!
//! - TC-STO-005 = TC-EAR-001: 10^4 plaintext canaries written through flush and compaction are
//!   absent from every byte of every file of the store (SSTs, MANIFEST, CURRENT, DEK
//!   registry); a plaintext control run finds them, so the scan is known to work.
//! - TC-EAR-002 (file provider part): a missing or wrong KEK, or no encryption configured for an
//!   encrypted store, refuses the open with `RGN-4006 KeyUnavailable`.
//! - Round trip of SSTs and MANIFEST across reopen, tampered ciphertext → `StorageCorruption`.
//! - Crash at every mutating operation on `SimFileSystem` (every `CrashMode`, several seeds):
//!   the DEK registry is always the acknowledged or the in-flight state, every acknowledged DEK
//!   still decrypts, and an encrypted store with flushes, compactions and reopens recovers with
//!   every live SST readable.
//! - The plaintext path is byte-identical to the format before encryption support (golden
//!   hashes taken on the pre-encryption build).
//!
//! Out of scope (later M1/M4 tasks): Raft log segments, HNSW snapshots, spill files, KEK
//! rotation and the forced-compaction DEK rotation command. Checkpoints of encrypted stores are
//! covered by `tests/checkpoint_encrypted.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use rustegon_common::{Error, ErrorCode};
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_sim_api::{FileSystem, OpenMode, Rng};
use rustegon_storage::{
    MAX_SEQNO, Memtable, ReadView, StorageError, TableCache, ValueKind,
    compaction::{
        CompactionOptions, delete_obsolete_files, install_compaction, pick_compaction,
        run_compaction,
    },
    encryption::{FileKekProvider, KekProvider, KeyManager, SecretKey},
    flush_memtable,
    sst::{SstReaderOptions, SstWriter, SstWriterOptions},
    version::{VersionSet, manifest_file_name, sst_file_name},
};

const LSM: &str = "/store/lsm";
const KEYS: &str = "/store/keys";
const KEK_FILE: &str = "/secrets/kek";
/// AC-EAR-001: 10^4 canaries (full count; the scan is linear in the store size).
const CANARIES: usize = 10_000;
/// Canaries per memtable flush.
const PER_FLUSH: usize = 2_500;
/// Bytes of a canary compared by the scan (keys are 16 bytes, values 32).
const CANARY_PROBE: usize = 16;

/// Deterministic splitmix64 RNG: simulation-style seeded randomness for keys and nonces.
#[derive(Debug)]
struct SeededRng(AtomicU64);

impl SeededRng {
    fn new(seed: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(seed)))
    }
}

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

fn write_file(fs: &dyn FileSystem, path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        fs.create_dir_all(parent).unwrap();
    }
    let mut f = fs.open(path, OpenMode::Truncate).unwrap();
    f.append(contents).unwrap();
    f.sync_data().unwrap();
}

fn read_all(fs: &dyn FileSystem, path: &Path) -> Vec<u8> {
    let f = fs.open(path, OpenMode::Read).unwrap();
    let mut buf = vec![0u8; usize::try_from(f.size().unwrap()).unwrap()];
    f.read_exact_at(&mut buf, 0).unwrap();
    buf
}

fn provider(seed: u8) -> Arc<dyn KekProvider> {
    Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([seed; 32])))
}

/// Tiny level shapes so 10^4 entries reach several levels and output files.
fn compaction_options(keys: Option<Arc<KeyManager>>) -> CompactionOptions {
    CompactionOptions {
        l0_trigger: 2,
        level_base_bytes: 64 << 10,
        level_multiplier: 4,
        target_file_size_base: 32 << 10,
        max_target_file_size: 64 << 10,
        writer: SstWriterOptions {
            block_size: 1024,
            encryption: keys,
            ..SstWriterOptions::default()
        },
        // Subcompactions split L0 compactions; sequential so the crash sweeps here see a
        // reproducible order of file-system operations (TC-STO-002, `compaction/job.rs`).
        max_subcompactions: 4,
        parallel_subcompactions: false,
        ..CompactionOptions::default()
    }
}

fn compact_until_quiet(fs: &dyn FileSystem, versions: &mut VersionSet, opts: &CompactionOptions) {
    for _ in 0..1000 {
        let current = versions.current();
        let Some(c) = pick_compaction(&current, opts, &BTreeSet::new()) else {
            return;
        };
        drop(current);
        let out = run_compaction(fs, Path::new(LSM), &c, opts, &[], None, &mut || {
            versions.new_file_number()
        })
        .unwrap();
        install_compaction(versions, &c, &out).unwrap();
        delete_obsolete_files(fs, versions, &BTreeSet::new()).unwrap();
    }
    panic!("compaction does not converge");
}

/// `CANARIES` random 16-byte keys with random 32-byte values.
fn canaries(seed: u64) -> Vec<([u8; 16], [u8; 32])> {
    let rng = SeededRng::new(seed);
    let mut unique = HashSet::new();
    let mut out = Vec::with_capacity(CANARIES);
    while out.len() < CANARIES {
        let (mut k, mut v) = ([0u8; 16], [0u8; 32]);
        rng.fill_bytes(&mut k);
        rng.fill_bytes(&mut v);
        if unique.insert(k) {
            out.push((k, v));
        }
    }
    out
}

/// Writes the canaries through flushes and compactions, reopens the store and returns it.
fn build_store(fs: &Arc<SimFileSystem>, encrypted: bool) -> (VersionSet, Option<Arc<KeyManager>>) {
    let shared: Arc<dyn FileSystem> = fs.clone();
    let keys = encrypted.then(|| {
        Arc::new(
            KeyManager::create(
                shared.clone(),
                Path::new(KEYS),
                provider(1),
                SeededRng::new(7),
            )
            .unwrap(),
        )
    });
    let mut versions =
        VersionSet::create_with(shared.clone(), Path::new(LSM), keys.clone()).unwrap();
    let opts = compaction_options(keys.clone());
    let data = canaries(42);
    let mut seqno = 0;
    for chunk in data.chunks(PER_FLUSH) {
        let mem = Memtable::new();
        for (k, v) in chunk {
            seqno += 1;
            mem.add(seqno, ValueKind::Put, k, Bytes::copy_from_slice(v));
        }
        flush_memtable(
            shared.as_ref(),
            Path::new(LSM),
            &mut versions,
            &mem,
            &opts.writer,
            seqno,
        )
        .unwrap()
        .unwrap();
        compact_until_quiet(shared.as_ref(), &mut versions, &opts);
    }
    drop(versions);
    let versions = VersionSet::open_with(shared, Path::new(LSM), keys.clone()).unwrap();
    (versions, keys)
}

fn table_cache(fs: &Arc<SimFileSystem>, keys: Option<Arc<KeyManager>>) -> Arc<TableCache> {
    Arc::new(TableCache::new(
        fs.clone(),
        PathBuf::from(LSM),
        SstReaderOptions {
            encryption: keys,
            ..SstReaderOptions::default()
        },
    ))
}

/// Every file under `/store`, as `(path, bytes)`.
fn all_files(fs: &dyn FileSystem) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for dir in [LSM, KEYS] {
        let Ok(entries) = fs.read_dir(Path::new(dir)) else {
            continue;
        };
        for path in entries {
            let bytes = read_all(fs, &path);
            out.push((path, bytes));
        }
    }
    out
}

/// Number of canary probes (16-byte prefixes of keys and values) found anywhere in `files`.
fn canary_hits(files: &[(PathBuf, Vec<u8>)], data: &[([u8; 16], [u8; 32])]) -> usize {
    let mut probes: HashSet<[u8; CANARY_PROBE]> = HashSet::new();
    for (k, v) in data {
        probes.insert(*k);
        probes.insert(v[..CANARY_PROBE].try_into().unwrap());
        probes.insert(v[CANARY_PROBE..].try_into().unwrap());
    }
    let mut hits = 0;
    for (_, bytes) in files {
        hits += bytes
            .windows(CANARY_PROBE)
            .filter(|w| probes.contains(<&[u8; CANARY_PROBE]>::try_from(*w).unwrap()))
            .count();
    }
    hits
}

/// TC-STO-005 = TC-EAR-001 (AC-EAR-001): no plaintext canary in any file of an encrypted store
/// written through flush and compaction; every canary still reads back.
#[test]
fn tc_sto_005_tc_ear_001_no_plaintext_canary_in_any_file() {
    let data = canaries(42);

    // Control: the same workload in plaintext leaves canaries on disk, so the scan works.
    let plain_fs = Arc::new(SimFileSystem::new());
    let (plain, _) = build_store(&plain_fs, false);
    assert!(plain.current().all_files().count() > 1);
    let plain_hits = canary_hits(&all_files(plain_fs.as_ref()), &data);
    assert!(
        plain_hits >= CANARIES,
        "control found only {plain_hits} canaries"
    );

    let fs = Arc::new(SimFileSystem::new());
    let (versions, keys) = build_store(&fs, true);
    let files = all_files(fs.as_ref());
    // SSTs at more than one level, the MANIFEST, CURRENT and the registry were all scanned.
    let levels: BTreeSet<usize> = versions.current().all_files().map(|(l, _)| l).collect();
    assert!(levels.len() > 1, "{levels:?}");
    assert!(files.iter().any(|(p, _)| p.ends_with("registry.enc")));
    assert!(
        files
            .iter()
            .any(|(p, _)| p.ends_with(manifest_file_name(versions.manifest_number())))
    );
    assert_eq!(
        canary_hits(&files, &data),
        0,
        "plaintext canary found on disk"
    );

    // Exactly the live files have DEKs: compaction inputs and old MANIFESTs were forgotten
    // with their files (crypto-shredding); every canary reads back through the table cache.
    let keys = keys.unwrap();
    let mut live: BTreeSet<u64> = versions
        .current()
        .all_files()
        .map(|(_, f)| f.number)
        .collect();
    live.insert(versions.manifest_number());
    assert_eq!(
        keys.file_numbers().into_iter().collect::<BTreeSet<_>>(),
        live
    );
    let view = ReadView::new(Vec::new(), versions.current(), table_cache(&fs, Some(keys)));
    for (k, v) in &data {
        assert_eq!(view.get(k, MAX_SEQNO).unwrap().as_deref(), Some(&v[..]));
    }
}

/// Writer misuse with encryption configured: `SstWriter::new` (no file number) refuses to write
/// rather than produce a plaintext file, and a file number that already has a DEK is refused.
#[test]
fn tc_ear_writer_refuses_plaintext_and_reused_file_numbers() {
    let fs: Arc<dyn FileSystem> = Arc::new(SimFileSystem::new());
    let keys = Arc::new(
        KeyManager::create(fs.clone(), Path::new(KEYS), provider(1), SeededRng::new(1)).unwrap(),
    );
    fs.create_dir_all(Path::new(LSM)).unwrap();
    let opts = SstWriterOptions {
        encryption: Some(keys.clone()),
        ..SstWriterOptions::default()
    };
    let open = |n: u64| {
        fs.open(&Path::new(LSM).join(sst_file_name(n)), OpenMode::CreateNew)
            .unwrap()
    };
    let key = rustegon_storage::InternalKey::new(b"k", 1, ValueKind::Put);
    let mut w = SstWriter::new(open(2), opts.clone());
    let err = w.add(key.as_bytes(), b"v").unwrap_err();
    assert!(err.to_string().contains("SstWriter::create"), "{err}");
    assert!(w.finish().is_err());

    let mut w = SstWriter::create(open(3), 3, opts.clone()).unwrap();
    w.add(key.as_bytes(), b"v").unwrap();
    w.finish().unwrap();
    let err = SstWriter::create(open(4), 3, opts).err().unwrap();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
    assert_eq!(keys.file_numbers(), [3]);
}

/// A plaintext store reopened with encryption: its plaintext SSTs stay readable (no DEK), the
/// new MANIFEST is encrypted, and file numbers already in the registry (a DEK registered just
/// before a crash) are never handed out again.
#[test]
fn tc_ear_plaintext_store_switches_to_encryption_at_reopen() {
    let fs = Arc::new(SimFileSystem::new());
    let shared: Arc<dyn FileSystem> = fs.clone();
    let mut versions = VersionSet::create(shared.clone(), Path::new(LSM)).unwrap();
    let mem = Memtable::new();
    mem.add(1, ValueKind::Put, b"old", Bytes::from_static(b"plain"));
    let plain_sst = flush_memtable(
        shared.as_ref(),
        Path::new(LSM),
        &mut versions,
        &mem,
        &SstWriterOptions::default(),
        1,
    )
    .unwrap()
    .unwrap()
    .number;
    drop(versions);

    let keys = Arc::new(
        KeyManager::create(
            shared.clone(),
            Path::new(KEYS),
            provider(1),
            SeededRng::new(1),
        )
        .unwrap(),
    );
    // Simulates a switch interrupted by a crash: the plaintext MANIFEST was admitted, then the
    // DEK of the new MANIFEST was registered and the file was lost.
    let plain_manifest =
        String::from_utf8(read_all(shared.as_ref(), &Path::new(LSM).join("CURRENT")))
            .unwrap()
            .trim_end()
            .trim_start_matches("MANIFEST-")
            .parse::<u64>()
            .unwrap();
    keys.admit_plaintext_manifest(plain_manifest).unwrap();
    keys.new_file_cipher(50).unwrap();
    let mut versions =
        VersionSet::open_with(shared.clone(), Path::new(LSM), Some(keys.clone())).unwrap();
    assert!(versions.manifest_number() > 50);
    assert!(versions.new_file_number() > 50);
    let view = ReadView::new(
        Vec::new(),
        versions.current(),
        table_cache(&fs, Some(keys.clone())),
    );
    assert_eq!(
        view.get(b"old", MAX_SEQNO).unwrap().as_deref(),
        Some(&b"plain"[..])
    );
    assert!(keys.file_cipher(plain_sst).unwrap().is_none());
    assert!(
        keys.file_cipher(versions.manifest_number())
            .unwrap()
            .is_some()
    );
    drop((view, versions));
    // The switch is complete: the plaintext-MANIFEST admission is gone.
    assert_eq!(keys.admitted_plaintext_manifest(), None);
    // The MANIFEST is now encrypted: a plaintext open is refused.
    kek_unavailable(VersionSet::open(shared, Path::new(LSM)).err().unwrap());
}

/// A plaintext MANIFEST swapped into an encrypted store (attacker with write access to the data
/// directory) is refused as corruption instead of redefining the store (registry v2 admission).
#[test]
fn tc_ear_swapped_in_plaintext_manifest_is_refused() {
    let fs = Arc::new(SimFileSystem::new());
    let shared: Arc<dyn FileSystem> = fs.clone();
    small_encrypted_store(&fs);
    // Any plaintext MANIFEST will do; here the one of an empty plaintext store.
    let forge = Path::new("/forge");
    drop(VersionSet::create(shared.clone(), forge).unwrap());
    let current = String::from_utf8(read_all(shared.as_ref(), &forge.join("CURRENT"))).unwrap();
    let forged = read_all(shared.as_ref(), &forge.join(current.trim_end()));
    let name = manifest_file_name(900);
    write_file(shared.as_ref(), &Path::new(LSM).join(&name), &forged);
    write_file(
        shared.as_ref(),
        &Path::new(LSM).join("CURRENT"),
        format!("{name}\n").as_bytes(),
    );
    let kek: Arc<dyn KekProvider> =
        Arc::new(FileKekProvider::open(shared.as_ref(), Path::new(KEK_FILE)).unwrap());
    let keys = Arc::new(
        KeyManager::open(shared.clone(), Path::new(KEYS), kek, SeededRng::new(4)).unwrap(),
    );
    let err = VersionSet::open_with(shared, Path::new(LSM), Some(keys.clone()))
        .err()
        .expect("a plaintext MANIFEST in an encrypted store must be refused");
    assert!(matches!(err, StorageError::Corruption(_)), "{err}");
    assert!(err.to_string().contains("has no DEK"), "{err}");
    assert_eq!(Error::from(err).code(), ErrorCode::StorageCorruption);
    assert_eq!(keys.admitted_plaintext_manifest(), None);
}

/// Plaintext store with one flushed SST holding `old → plain`, fully durable.
fn plaintext_store(fs: &Arc<SimFileSystem>) {
    let shared: Arc<dyn FileSystem> = fs.clone();
    let mut versions = VersionSet::create(shared.clone(), Path::new(LSM)).unwrap();
    let mem = Memtable::new();
    mem.add(1, ValueKind::Put, b"old", Bytes::from_static(b"plain"));
    flush_memtable(
        shared.as_ref(),
        Path::new(LSM),
        &mut versions,
        &mem,
        &SstWriterOptions::default(),
        1,
    )
    .unwrap()
    .unwrap();
}

/// Opens the store with encryption, creating the registry if it does not exist yet (what the
/// engine's caller does when `storage.encryption` is switched on).
fn open_switching(fs: &Arc<SimFileSystem>) -> Result<(VersionSet, Arc<KeyManager>), StorageError> {
    let shared: Arc<dyn FileSystem> = fs.clone();
    let keys = if KeyManager::exists(shared.as_ref(), Path::new(KEYS))? {
        KeyManager::open(
            shared.clone(),
            Path::new(KEYS),
            provider(1),
            SeededRng::new(1),
        )?
    } else {
        KeyManager::create(
            shared.clone(),
            Path::new(KEYS),
            provider(1),
            SeededRng::new(1),
        )?
    };
    let keys = Arc::new(keys);
    let versions = VersionSet::open_with(shared, Path::new(LSM), Some(keys.clone()))?;
    Ok((versions, keys))
}

/// TC-STO-002 slice for the switch to encryption: a crash at every mutating operation of the
/// first encrypted reopen of a plaintext store, in every mode, still reopens (the admission is
/// durable with the first DEK), reads the plaintext data, and ends with an encrypted MANIFEST
/// and no admission left.
#[test]
fn tc_sto_002_switch_to_encryption_survives_crash_at_every_op() {
    let total = {
        let fs = Arc::new(SimFileSystem::new());
        plaintext_store(&fs);
        let before = fs.op_count();
        open_switching(&fs).unwrap();
        fs.op_count() - before
    };
    assert!(total >= 10, "switch shrank to {total} ops");
    let mut swept = 0;
    for halt in 0..=total {
        for mode in MODES {
            for seed in 0..SEEDS {
                let fs = Arc::new(SimFileSystem::new());
                plaintext_store(&fs);
                fs.halt_after_ops(halt);
                let _ = open_switching(&fs);
                fs.crash(seed, mode);
                let (versions, keys) = open_switching(&fs).unwrap_or_else(|e| {
                    panic!("reopen after crash at op {halt} ({mode:?}, seed {seed}): {e}")
                });
                let view = ReadView::new(
                    Vec::new(),
                    versions.current(),
                    table_cache(&fs, Some(keys.clone())),
                );
                assert_eq!(
                    view.get(b"old", MAX_SEQNO).unwrap().as_deref(),
                    Some(&b"plain"[..]),
                    "op {halt} {mode:?} seed {seed}"
                );
                assert!(
                    keys.file_cipher(versions.manifest_number())
                        .unwrap()
                        .is_some()
                );
                assert_eq!(keys.admitted_plaintext_manifest(), None);
            }
        }
        swept += 1;
    }
    assert_eq!(swept, total + 1, "every crash point of the switch is swept");
}

fn kek_unavailable(err: StorageError) {
    assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");
    let code = Error::from(err).code();
    assert_eq!(code, ErrorCode::KeyUnavailable);
    assert_eq!(code.code(), 4006);
}

/// Small encrypted store with the KEK read from a key file: one flushed SST.
fn small_encrypted_store(fs: &Arc<SimFileSystem>) -> u64 {
    let shared: Arc<dyn FileSystem> = fs.clone();
    write_file(shared.as_ref(), Path::new(KEK_FILE), &[0x5A; 32]);
    let kek: Arc<dyn KekProvider> =
        Arc::new(FileKekProvider::open(shared.as_ref(), Path::new(KEK_FILE)).unwrap());
    let keys = Arc::new(
        KeyManager::create(shared.clone(), Path::new(KEYS), kek, SeededRng::new(3)).unwrap(),
    );
    let mut versions =
        VersionSet::create_with(shared.clone(), Path::new(LSM), Some(keys.clone())).unwrap();
    let mem = Memtable::new();
    for i in 0..200u64 {
        mem.add(
            i + 1,
            ValueKind::Put,
            format!("key-{i:04}").as_bytes(),
            Bytes::from(format!("value-{i}")),
        );
    }
    let opts = SstWriterOptions {
        block_size: 256,
        encryption: Some(keys),
        ..SstWriterOptions::default()
    };
    flush_memtable(
        shared.as_ref(),
        Path::new(LSM),
        &mut versions,
        &mem,
        &opts,
        200,
    )
    .unwrap()
    .unwrap()
    .number
}

/// TC-EAR-002 (file provider part, AC-EAR-002): recovery step "unwrap KEK / load DEK registry"
/// fails with RGN-4006 when the KEK is missing or wrong, and an encrypted store opened without
/// encryption fails with RGN-4006 at its first encrypted file, never with garbage.
#[test]
fn tc_ear_002_missing_or_wrong_kek_refuses_open_with_rgn_4006() {
    let fs = Arc::new(SimFileSystem::new());
    let shared: Arc<dyn FileSystem> = fs.clone();
    let sst = small_encrypted_store(&fs);

    // Right key: everything opens and reads.
    let kek: Arc<dyn KekProvider> =
        Arc::new(FileKekProvider::open(shared.as_ref(), Path::new(KEK_FILE)).unwrap());
    let keys = Arc::new(
        KeyManager::open(shared.clone(), Path::new(KEYS), kek, SeededRng::new(4)).unwrap(),
    );
    let versions =
        VersionSet::open_with(shared.clone(), Path::new(LSM), Some(keys.clone())).unwrap();
    let view = ReadView::new(Vec::new(), versions.current(), table_cache(&fs, Some(keys)));
    assert_eq!(
        view.get(b"key-0007", 1000).unwrap().as_deref(),
        Some(&b"value-7"[..])
    );
    drop((view, versions));

    // Missing key file.
    kek_unavailable(
        FileKekProvider::open(shared.as_ref(), Path::new("/secrets/absent")).unwrap_err(),
    );
    // Wrong key.
    let err = KeyManager::open(
        shared.clone(),
        Path::new(KEYS),
        provider(9),
        SeededRng::new(5),
    )
    .unwrap_err();
    kek_unavailable(err);
    // Registry deleted.
    let empty = Path::new("/elsewhere");
    shared.create_dir_all(empty).unwrap();
    kek_unavailable(
        KeyManager::open(shared.clone(), empty, provider(9), SeededRng::new(5)).unwrap_err(),
    );
    // No encryption configured: the encrypted MANIFEST and SSTs refuse to open.
    assert!(KeyManager::exists(shared.as_ref(), Path::new(KEYS)).unwrap());
    kek_unavailable(
        VersionSet::open(shared.clone(), Path::new(LSM))
            .err()
            .unwrap(),
    );
    kek_unavailable(table_cache(&fs, None).get(sst).err().unwrap());
}

/// SST and MANIFEST round trip with encryption on, across reopens with fresh MANIFESTs; the old
/// MANIFEST's DEK is dropped from the registry, and tampered ciphertext is corruption.
#[test]
fn tc_ear_encrypted_sst_and_manifest_round_trip_and_tamper_detection() {
    let fs = Arc::new(SimFileSystem::new());
    let shared: Arc<dyn FileSystem> = fs.clone();
    let sst = small_encrypted_store(&fs);
    let kek = || -> Arc<dyn KekProvider> {
        Arc::new(FileKekProvider::open(fs.as_ref(), Path::new(KEK_FILE)).unwrap())
    };
    for round in 0..3u64 {
        let keys = Arc::new(
            KeyManager::open(
                shared.clone(),
                Path::new(KEYS),
                kek(),
                SeededRng::new(10 + round),
            )
            .unwrap(),
        );
        let versions =
            VersionSet::open_with(shared.clone(), Path::new(LSM), Some(keys.clone())).unwrap();
        assert_eq!(versions.current().all_files().count(), 1);
        assert_eq!(versions.last_seqno(), 200);
        // Registry: the live SST and the current MANIFEST only.
        assert_eq!(keys.file_numbers(), [sst, versions.manifest_number()]);
        let manifest = read_all(
            shared.as_ref(),
            &Path::new(LSM).join(manifest_file_name(versions.manifest_number())),
        );
        assert!(!manifest.windows(8).any(|w| w == b"key-0000"));
        let view = ReadView::new(Vec::new(), versions.current(), table_cache(&fs, Some(keys)));
        let mut it = view.iterator(1000).unwrap();
        it.seek_to_first().unwrap();
        let mut n = 0;
        while it.valid() {
            n += 1;
            it.next().unwrap();
        }
        assert_eq!(n, 200);
    }

    // Flip one ciphertext byte inside the first data block.
    let path = Path::new(LSM).join(sst_file_name(sst));
    let mut bytes = read_all(shared.as_ref(), &path);
    bytes[3] ^= 0x01;
    shared.remove_file(&path).unwrap();
    write_file(shared.as_ref(), &path, &bytes);
    let keys = Arc::new(
        KeyManager::open(shared.clone(), Path::new(KEYS), kek(), SeededRng::new(20)).unwrap(),
    );
    let versions =
        VersionSet::open_with(shared.clone(), Path::new(LSM), Some(keys.clone())).unwrap();
    let view = ReadView::new(Vec::new(), versions.current(), table_cache(&fs, Some(keys)));
    let err = view.get(b"key-0000", 1000).unwrap_err();
    assert!(err.is_corruption(), "{err}");
    assert_eq!(Error::from(err).code(), ErrorCode::StorageCorruption);
}

/// FNV-1a 64 (dependency-free) for the golden plaintext hashes.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

/// Encryption support must leave the plaintext format byte-identical: an SST and a MANIFEST
/// written with `encryption: None` hash to the values recorded on the build before encryption
/// support (commit 11b60ac).
#[test]
fn plaintext_files_are_byte_identical_to_the_pre_encryption_format() {
    let fs = SimFileSystem::new();
    let shared: Arc<dyn FileSystem> = Arc::new(fs.clone());
    let dir = Path::new("/golden");
    let mut versions = VersionSet::create(Arc::clone(&shared), dir).unwrap();
    let mem = Memtable::new();
    for i in 0..500u64 {
        let kind = if i % 7 == 0 {
            ValueKind::Delete
        } else {
            ValueKind::Put
        };
        let value = format!("value-{i}-").repeat(usize::try_from(i % 9).unwrap());
        mem.add(
            i + 1,
            kind,
            format!("key-{i:05}").as_bytes(),
            Bytes::from(value),
        );
    }
    let opts = SstWriterOptions {
        block_size: 256,
        ..SstWriterOptions::default()
    };
    let meta = flush_memtable(shared.as_ref(), dir, &mut versions, &mem, &opts, 500)
        .unwrap()
        .unwrap();
    let sst = read_all(shared.as_ref(), &dir.join(sst_file_name(meta.number)));
    let manifest = read_all(
        shared.as_ref(),
        &dir.join(manifest_file_name(versions.manifest_number())),
    );
    assert_eq!((sst.len(), fnv1a(&sst)), (15_360, 0x5c1f_0c36_d67c_9ae5));
    assert_eq!(
        (manifest.len(), fnv1a(&manifest)),
        (84, 0x512d_87eb_fd70_05f1)
    );
}

/// Crash seeds per crash point and mode.
const SEEDS: u64 = 4;
const MODES: [CrashMode; 4] = [
    CrashMode::Clean,
    CrashMode::TornPrefix,
    CrashMode::TornZeroTail,
    CrashMode::Journaled,
];

/// What a registry workload acknowledged before the halt.
#[derive(Default)]
struct RegistryOutcome {
    created: bool,
    /// `(file numbers, sealed probe per acknowledged file)` after each acknowledged rewrite.
    acked: Vec<BTreeSet<u64>>,
    in_flight: Option<BTreeSet<u64>>,
    /// A message sealed with each acknowledged DEK (must decrypt after the crash).
    sealed: BTreeMap<u64, Vec<u8>>,
}

/// Registers DEKs 2..8 and forgets some of them, recording each acknowledged state.
fn registry_workload(fs: &Arc<SimFileSystem>) -> RegistryOutcome {
    let shared: Arc<dyn FileSystem> = fs.clone();
    let mut out = RegistryOutcome::default();
    let Ok(keys) = KeyManager::create(shared, Path::new(KEYS), provider(1), SeededRng::new(1))
    else {
        return out;
    };
    out.created = true;
    let mut state = BTreeSet::new();
    out.acked.push(state.clone());
    for step in 0..9u64 {
        let mut next = state.clone();
        let result = if step % 3 == 2 {
            let victim = *state.iter().next().unwrap();
            next.remove(&victim);
            out.in_flight = Some(next.clone());
            keys.forget(&[victim])
        } else {
            let n = 2 + step;
            next.insert(n);
            out.in_flight = Some(next.clone());
            keys.new_file_cipher(n).map(|cipher| {
                let mut msg = format!("probe-{n}").into_bytes();
                cipher.seal_in_place(0, b"", &mut msg, 0).unwrap();
                out.sealed.insert(n, msg);
            })
        };
        if result.is_err() {
            return out;
        }
        out.in_flight = None;
        state = next;
        out.acked.push(state.clone());
    }
    out
}

/// TC-STO-002 slice for the DEK registry (§7 atomic rewrite): a crash at every mutating
/// operation in every mode leaves the acknowledged or the in-flight registry, never a damaged
/// one, and every acknowledged DEK still decrypts its data.
#[test]
fn tc_sto_002_registry_rewrite_survives_crash_at_every_op() {
    let total = {
        let fs = Arc::new(SimFileSystem::new());
        let out = registry_workload(&fs);
        assert_eq!(out.acked.len(), 10);
        fs.op_count()
    };
    assert!(total >= 9 * 5, "workload shrank to {total} ops");
    for halt in 0..total {
        for mode in MODES {
            for seed in 0..SEEDS {
                let fs = Arc::new(SimFileSystem::new());
                fs.halt_after_ops(halt);
                let out = registry_workload(&fs);
                fs.crash(seed, mode);
                let ctx = format!("halt {halt} {mode:?} seed {seed}");
                let shared: Arc<dyn FileSystem> = fs.clone();
                let keys =
                    match KeyManager::open(shared, Path::new(KEYS), provider(1), SeededRng::new(2))
                    {
                        Ok(k) => k,
                        Err(e) => {
                            // Only a crash before the first registry became durable may lose it.
                            assert!(matches!(e, StorageError::KeyUnavailable(_)), "{ctx}: {e}");
                            assert!(!out.created, "{ctx}: acknowledged registry lost");
                            continue;
                        }
                    };
                assert!(out.created || out.acked.is_empty(), "{ctx}");
                let got: BTreeSet<u64> = keys.file_numbers().into_iter().collect();
                let last = out.acked.last().cloned().unwrap_or_default();
                assert!(
                    got == last || out.in_flight.as_ref() == Some(&got),
                    "{ctx}: got {got:?}, acked {last:?}, in flight {:?}",
                    out.in_flight
                );
                for (n, sealed) in &out.sealed {
                    if !got.contains(n) {
                        continue;
                    }
                    let cipher = keys.file_cipher(*n).unwrap().unwrap();
                    let mut msg = sealed.clone();
                    cipher.open_in_place(0, b"", &mut msg).unwrap();
                    assert_eq!(msg, format!("probe-{n}").into_bytes(), "{ctx}");
                }
                assert!(
                    !fs.read_dir(Path::new(KEYS))
                        .unwrap()
                        .iter()
                        .any(|p| p.ends_with("registry.enc.tmp")),
                    "{ctx}: temp file left after open"
                );
            }
        }
    }
}

/// Encrypted store workload: flushes, a compaction and a reopen. Returns whether the store was
/// created (CURRENT durable) before the halt.
fn store_workload(fs: &Arc<SimFileSystem>) -> bool {
    let shared: Arc<dyn FileSystem> = fs.clone();
    let Ok(keys) = KeyManager::create(
        shared.clone(),
        Path::new(KEYS),
        provider(1),
        SeededRng::new(1),
    ) else {
        return false;
    };
    let keys = Arc::new(keys);
    let Ok(mut versions) =
        VersionSet::create_with(shared.clone(), Path::new(LSM), Some(keys.clone()))
    else {
        return false;
    };
    let opts = CompactionOptions {
        l0_trigger: 2,
        ..compaction_options(Some(keys.clone()))
    };
    let mut seqno = 0;
    for round in 0..3u64 {
        let mem = Memtable::new();
        for i in 0..40u64 {
            seqno += 1;
            mem.add(
                seqno,
                ValueKind::Put,
                format!("k{:03}", (i * 7 + round) % 60).as_bytes(),
                Bytes::from(vec![b'v'; 40]),
            );
        }
        if flush_memtable(
            shared.as_ref(),
            Path::new(LSM),
            &mut versions,
            &mem,
            &opts.writer,
            seqno,
        )
        .is_err()
        {
            return true;
        }
        let current = versions.current();
        if let Some(c) = pick_compaction(&current, &opts, &BTreeSet::new()) {
            drop(current);
            let Ok(out) = run_compaction(
                shared.as_ref(),
                Path::new(LSM),
                &c,
                &opts,
                &[],
                None,
                &mut || versions.new_file_number(),
            ) else {
                return true;
            };
            if install_compaction(&mut versions, &c, &out).is_err()
                || delete_obsolete_files(shared.as_ref(), &versions, &BTreeSet::new()).is_err()
            {
                return true;
            }
        }
        if round == 1 {
            drop(versions);
            let Ok(v) = VersionSet::open_with(shared.clone(), Path::new(LSM), Some(keys.clone()))
            else {
                return true;
            };
            versions = v;
        }
    }
    true
}

/// TC-STO-002 slice for an encrypted store: crash at every mutating operation (flush SST + DEK
/// registration, MANIFEST append, compaction outputs, obsolete-file and DEK cleanup, reopen
/// with a fresh encrypted MANIFEST) in every mode; the store reopens with the KEK and every
/// live SST is fully readable, and the reopened store accepts a new flush.
#[test]
fn tc_sto_002_encrypted_store_recovers_after_crash_at_every_op() {
    let total = {
        let fs = Arc::new(SimFileSystem::new());
        assert!(store_workload(&fs));
        fs.op_count()
    };
    assert!(total >= 60, "workload shrank to {total} ops");
    // Every crash point (halting after the last op = the completed workload), every mode, every
    // seed: `swept` proves no point is skipped.
    let mut swept = 0;
    for halt in 0..=total {
        swept += 1;
        for mode in MODES {
            for seed in 0..SEEDS {
                let fs = Arc::new(SimFileSystem::new());
                fs.halt_after_ops(halt);
                store_workload(&fs);
                fs.crash(seed, mode);
                let ctx = format!("halt {halt} {mode:?} seed {seed}");
                let shared: Arc<dyn FileSystem> = fs.clone();
                if shared
                    .open(&Path::new(LSM).join("CURRENT"), OpenMode::Read)
                    .is_err()
                {
                    continue; // crashed before the store existed
                }
                let keys = Arc::new(
                    KeyManager::open(
                        shared.clone(),
                        Path::new(KEYS),
                        provider(1),
                        SeededRng::new(99),
                    )
                    .unwrap_or_else(|e| panic!("{ctx}: registry: {e}")),
                );
                let mut versions =
                    VersionSet::open_with(shared.clone(), Path::new(LSM), Some(keys.clone()))
                        .unwrap_or_else(|e| panic!("{ctx}: open: {e}"));
                let view = ReadView::new(
                    Vec::new(),
                    versions.current(),
                    table_cache(&fs, Some(keys.clone())),
                );
                let mut it = view
                    .iterator(MAX_SEQNO)
                    .unwrap_or_else(|e| panic!("{ctx}: {e}"));
                it.seek_to_first().unwrap_or_else(|e| panic!("{ctx}: {e}"));
                while it.valid() {
                    it.next().unwrap_or_else(|e| panic!("{ctx}: {e}"));
                }
                drop((it, view));
                let mem = Memtable::new();
                let next = versions.last_seqno() + 1;
                mem.add(next, ValueKind::Put, b"after", Bytes::from_static(b"crash"));
                let opts = SstWriterOptions {
                    encryption: Some(keys),
                    ..SstWriterOptions::default()
                };
                flush_memtable(
                    shared.as_ref(),
                    Path::new(LSM),
                    &mut versions,
                    &mem,
                    &opts,
                    next,
                )
                .unwrap_or_else(|e| panic!("{ctx}: flush after recovery: {e}"));
            }
        }
    }
    assert_eq!(
        swept,
        total + 1,
        "every crash point of the workload is swept"
    );
}
