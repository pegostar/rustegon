// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixtures and compatibility tests (implementation-rules.md §6; formats freeze
//! at M1 exit, development-phases.md §3): `rsst` v1 SSTs, MANIFEST v1 and the DEK registry
//! (v1, v2), plaintext and encrypted (storage-engine.md §4, §7, §9).
//!
//! Each fixture directory holds a complete store written by a fixed workload (LZ4 L0 files and
//! Zstd bottommost files, Ribbon filters, partitioned indexes, range tombstones, merge operands,
//! deletes, MANIFEST + `CURRENT`; encrypted ones also `keys/registry.enc`, sealed with the
//! test-only KEK below) and `expected.txt`, the store's content as `hex(key) hex(value)` lines:
//! - `rsst/1/plain/`: rsst v1 + MANIFEST v1, plaintext (current writer output);
//! - `rsst/1/encrypted/`: rsst v1 + MANIFEST v1 + registry v1 (read compatibility only);
//! - `registry/2/encrypted/`: the same store with registry v2 (current writer output). Its SSTs
//!   and MANIFEST are byte-identical to `rsst/1/encrypted/`: v2 changed only the registry body.
//!
//! - Compatibility: the current engine must read every committed fixture and return
//!   `expected.txt`. This must keep passing after any future format change (readers support old
//!   versions).
//! - Stability: the current writer must reproduce the current-version fixtures exactly; a failure
//!   means a format changed and the change needs a version bump plus new fixtures (§6), not a
//!   regeneration.
//!
//! Generate the fixtures of a new format version (existing fixture directories are never
//! overwritten): `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-storage --test formats`.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{FileSystem, OpenMode, Rng, StdFileSystem};
use rustegon_storage::{
    EngineOptions, LsmEngine, WriteBatch,
    compaction::CompactionOptions,
    encryption::{FileKekProvider, KeyManager, SecretKey},
    merge::MergeOperand,
    sst::SstWriterOptions,
};

/// Test-only KEK of the encrypted fixture (not a secret: it only protects synthetic data).
const FIXTURE_KEK: [u8; 32] = [0x5A; 32];
const STORE: &str = "/store";
const KEYS: &str = "/keys";

/// What the fixed workload writes: a plaintext or an encrypted store.
#[derive(Clone, Copy, Debug)]
enum Variant {
    Plain,
    Encrypted,
}

impl Variant {
    const ALL: [Self; 2] = [Self::Plain, Self::Encrypted];

    /// The fixture the current writer must reproduce for this variant.
    fn current(self) -> Fixture {
        match self {
            Self::Plain => Fixture::RsstV1Plain,
            Self::Encrypted => Fixture::RegistryV2Encrypted,
        }
    }
}

/// One committed fixture directory (module docs).
#[derive(Clone, Copy, Debug)]
enum Fixture {
    RsstV1Plain,
    RsstV1Encrypted,
    RegistryV2Encrypted,
}

impl Fixture {
    const ALL: [Self; 3] = [
        Self::RsstV1Plain,
        Self::RsstV1Encrypted,
        Self::RegistryV2Encrypted,
    ];

    fn variant(self) -> Variant {
        match self {
            Self::RsstV1Plain => Variant::Plain,
            Self::RsstV1Encrypted | Self::RegistryV2Encrypted => Variant::Encrypted,
        }
    }

    fn dir(self) -> PathBuf {
        let rel = match self {
            Self::RsstV1Plain => "rsst/1/plain",
            Self::RsstV1Encrypted => "rsst/1/encrypted",
            Self::RegistryV2Encrypted => "registry/2/encrypted",
        };
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/formats")
            .join(rel)
    }
}

/// Deterministic splitmix64 RNG so DEKs, registry keys and nonces are reproducible.
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

fn keys(fs: &Arc<SimFileSystem>, create: bool) -> Arc<KeyManager> {
    let kek = Arc::new(FileKekProvider::from_key(SecretKey::from_bytes(
        FIXTURE_KEK,
    )));
    let rng = Arc::new(SeededRng(AtomicU64::new(7)));
    let manager = if create {
        KeyManager::create(fs.clone(), Path::new(KEYS), kek, rng)
    } else {
        KeyManager::open(fs.clone(), Path::new(KEYS), kek, rng)
    };
    Arc::new(manager.unwrap())
}

fn options(variant: Variant, fs: &Arc<SimFileSystem>, create: bool) -> EngineOptions {
    EngineOptions {
        memtable_size: 4 << 10,
        compaction: CompactionOptions {
            l0_trigger: 2,
            level_base_bytes: 8 << 10,
            level_multiplier: 4,
            target_file_size_base: 4 << 10,
            max_target_file_size: 8 << 10,
            writer: SstWriterOptions {
                block_size: 512,
                index_partition_size: 128,
                ..SstWriterOptions::default()
            },
            // The fixture layout is that of single compaction jobs: the default subcompaction
            // count depends on the host's CPUs, so it would make the file set host-dependent.
            // Subcompactions change where outputs are cut, never the bytes of the format.
            max_subcompactions: 1,
            parallel_subcompactions: false,
            ..CompactionOptions::default()
        },
        encryption: match variant {
            Variant::Plain => None,
            Variant::Encrypted => Some(keys(fs, create)),
        },
        ..EngineOptions::default()
    }
}

/// The fixed workload: two compacted generations (Zstd at the bottommost level), then a
/// flushed L0 file (LZ4) that is left uncompacted.
fn write_store(variant: Variant) -> Arc<SimFileSystem> {
    let fs = Arc::new(SimFileSystem::new());
    let engine =
        LsmEngine::open(fs.clone(), Path::new(STORE), options(variant, &fs, true)).unwrap();
    for round in 0..3u32 {
        let mut batch = WriteBatch::new();
        for i in 0..600u32 {
            let key = format!("doc/{:04}", (i * 7 + round * 13) % 1500);
            match (i + round) % 9 {
                0 => batch.delete(key.as_bytes()),
                1 => batch.merge(
                    format!("counter/{}", i % 5).as_bytes(),
                    MergeOperand::CounterDelta(i64::from(i) - 40).encode(),
                ),
                _ => batch.put(
                    key.as_bytes(),
                    format!("r{round}-v{i}-").repeat(1 + i as usize % 6),
                ),
            };
        }
        batch.delete_range(
            format!("doc/{:04}", 40 + round * 50).as_bytes(),
            format!("doc/{:04}", 52 + round * 50).as_bytes(),
        );
        engine.write(&batch).unwrap();
        engine.flush().unwrap();
        if round < 2 {
            engine.compact().unwrap();
        }
    }
    fs
}

/// `hex(key) hex(value)` lines of the store's latest content.
fn content(engine: &LsmEngine) -> String {
    let mut it = engine.iterator(None).unwrap();
    it.seek_to_first().unwrap();
    let mut out = String::new();
    while it.valid() {
        let hex = |b: &[u8]| {
            b.iter().fold(String::new(), |mut s, x| {
                let _ = write!(s, "{x:02x}");
                s
            })
        };
        let _ = writeln!(out, "{} {}", hex(it.key()), hex(&it.value()));
        it.next().unwrap();
    }
    out
}

/// Every file of the sim store as `relative path -> bytes`.
fn files(fs: &dyn FileSystem, root: &Path, dirs: &[&str]) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for dir in dirs {
        let Ok(entries) = fs.read_dir(&root.join(dir.trim_start_matches('/'))) else {
            continue;
        };
        for path in entries {
            let file = fs.open(&path, OpenMode::Read).unwrap();
            let mut bytes = vec![0; usize::try_from(file.size().unwrap()).unwrap()];
            file.read_exact_at(&mut bytes, 0).unwrap();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.insert(format!("{}/{name}", dir.trim_start_matches('/')), bytes);
        }
    }
    out
}

fn sim_files(fs: &SimFileSystem) -> BTreeMap<String, Vec<u8>> {
    files(fs, Path::new("/"), &[STORE, KEYS])
}

fn fixture_files(fixture: Fixture) -> BTreeMap<String, Vec<u8>> {
    let mut all = files(&StdFileSystem, &fixture.dir(), &["store", "keys"]);
    all.retain(|name, _| !name.ends_with("expected.txt"));
    all
}

#[test]
fn regenerate_format_fixtures_on_request() {
    if std::env::var("RUSTEGON_WRITE_FIXTURES").as_deref() != Ok("1") {
        return;
    }
    for variant in Variant::ALL {
        let dir = variant.current().dir();
        if StdFileSystem.read_dir(&dir).is_ok() {
            // Committed fixtures are history: a changed writer needs a new version instead.
            continue;
        }
        let fs = write_store(variant);
        for (name, bytes) in sim_files(&fs) {
            let path = dir.join(&name);
            StdFileSystem
                .create_dir_all(path.parent().unwrap())
                .unwrap();
            let mut f = StdFileSystem.open(&path, OpenMode::Truncate).unwrap();
            f.append(&bytes).unwrap();
            f.sync_data().unwrap();
        }
        let engine =
            LsmEngine::open(fs.clone(), Path::new(STORE), options(variant, &fs, false)).unwrap();
        let mut f = StdFileSystem
            .open(&dir.join("expected.txt"), OpenMode::Truncate)
            .unwrap();
        f.append(content(&engine).as_bytes()).unwrap();
        f.sync_data().unwrap();
    }
}

/// Compatibility: every committed fixture opens with the current engine and reads as expected.
#[test]
fn committed_format_fixtures_still_read() {
    for fixture in Fixture::ALL {
        let variant = fixture.variant();
        let fs = Arc::new(SimFileSystem::new());
        for (name, bytes) in fixture_files(fixture) {
            let path = Path::new("/").join(&name);
            fs.create_dir_all(path.parent().unwrap()).unwrap();
            let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
            f.append(&bytes).unwrap();
            f.sync_data().unwrap();
        }
        fs.sync_dir(Path::new(STORE)).unwrap();
        let expected = {
            let f = StdFileSystem
                .open(&fixture.dir().join("expected.txt"), OpenMode::Read)
                .expect("expected.txt committed");
            let mut bytes = vec![0; usize::try_from(f.size().unwrap()).unwrap()];
            f.read_exact_at(&mut bytes, 0).unwrap();
            String::from_utf8(bytes).unwrap()
        };
        assert!(
            expected.lines().count() > 100,
            "{fixture:?}: fixture too small"
        );
        let engine =
            LsmEngine::open(fs.clone(), Path::new(STORE), options(variant, &fs, false)).unwrap();
        assert_eq!(content(&engine), expected, "{fixture:?}: fixture content");
        let v = engine.current_version();
        assert!(
            v.files(0).len() == 1 && v.all_files().count() > 2,
            "{fixture:?}: layout"
        );
    }
}

/// The plaintext fixture really exercises the codecs: its SSTs hold compressed data blocks.
#[test]
fn plain_fixture_contains_compressed_blocks() {
    use rustegon_storage::sst::{SstReader, SstReaderOptions};
    let dir = Fixture::RsstV1Plain.dir().join("store");
    let mut compressed = 0;
    for path in StdFileSystem.read_dir(&dir).unwrap() {
        if path.extension().is_some_and(|e| e == "sst") {
            let file = StdFileSystem.open(&path, OpenMode::Read).unwrap();
            let reader = SstReader::open(file, SstReaderOptions::default()).unwrap();
            compressed += reader.properties().data_compressed_blocks;
        }
    }
    assert!(compressed > 0, "fixture SSTs hold no compressed block");
}

/// Stability: the current writer reproduces the current-version fixture bytes exactly.
#[test]
fn writer_output_matches_current_format_fixtures() {
    for variant in Variant::ALL {
        let written = sim_files(&write_store(variant));
        let fixture = fixture_files(variant.current());
        assert_eq!(
            written.keys().collect::<Vec<_>>(),
            fixture.keys().collect::<Vec<_>>(),
            "{variant:?}: file set changed"
        );
        for (name, bytes) in &written {
            assert!(
                fixture[name] == *bytes,
                "{variant:?}: {name} differs from the {:?} fixture: the persisted format \
                 changed; bump the format version and add fixtures instead \
                 (implementation-rules.md §6)",
                variant.current()
            );
        }
    }
}

/// Registry v2 changed only the registry: SSTs, MANIFEST and `CURRENT` of the v2 fixture are the
/// v1 fixture's bytes, so rsst v1 and MANIFEST v1 are untouched.
#[test]
fn registry_v2_fixture_keeps_rsst_and_manifest_v1_bytes() {
    let v1 = fixture_files(Fixture::RsstV1Encrypted);
    let v2 = fixture_files(Fixture::RegistryV2Encrypted);
    let store = |m: &BTreeMap<String, Vec<u8>>| {
        m.iter()
            .filter(|(name, _)| name.starts_with("store/"))
            .map(|(n, b)| (n.clone(), b.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    assert!(!store(&v1).is_empty());
    assert_eq!(store(&v1), store(&v2));
    assert_ne!(v1["keys/registry.enc"], v2["keys/registry.enc"]);
    // Format version field after the 8-byte magic: 1 in the old fixture, 2 in the new one.
    assert_eq!(v1["keys/registry.enc"][8..12], 1u32.to_le_bytes());
    assert_eq!(v2["keys/registry.enc"][8..12], 2u32.to_le_bytes());
}
