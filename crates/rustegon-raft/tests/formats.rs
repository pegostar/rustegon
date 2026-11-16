// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixtures of the Raft log store (implementation-rules.md §6; replication.md
//! §2 "Log store format v1/v2"): `tests/fixtures/formats/rlog/<version>/` holds the segment files
//! written by a fixed workload (several groups, rollovers, hard states, an overwrite, a
//! truncation, purges that delete segments, a snapshot install, a group removal) and
//! `expected.txt`, the recovered state.
//!
//! - v1: plaintext segments.
//! - v2 (PD-057): the same workload encrypted at rest under a fixed test KEK with a seeded RNG;
//!   the fixture also holds the log's DEK registry (`registry.enc`, placed at `/keys` when
//!   loaded).
//! - Compatibility: the current store must open every committed fixture and recover
//!   `expected.txt`, also after future format changes (readers keep old versions).
//! - Stability: the current writer must reproduce the fixture bytes exactly; a failure means
//!   the format changed and needs a version bump plus new fixtures, not a regeneration.
//!
//! Generate the fixture of a new format version (existing directories are never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-raft --test formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustegon_raft::{HardState, LogBatch, LogStore, LogStoreOptions};
use rustegon_sim::{SimFileSystem, workload::rng::SimRng};
use rustegon_sim_api::{FileSystem, OpenMode, StdFileSystem};
use rustegon_storage::encryption::{FileKekProvider, KeyManager, REGISTRY_FILE_NAME, SecretKey};

const DIR: &str = "/raft-log";
const KEYS: &str = "/keys";
const SEGMENT_SIZE: u64 = 256;
/// Format versions with a committed fixture; v2 is the encrypted one.
const VERSIONS: [u32; 2] = [1, 2];

fn fixture_dir(version: u32) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/formats/rlog/{version}"))
}

fn encrypted(version: u32) -> bool {
    version == 2
}

/// Opens the store; encrypted with the fixed test KEK, DEKs drawn from a generator seeded with
/// `seed` (deterministic bytes for the stability check).
fn open(fs: &Arc<SimFileSystem>, encrypted: bool, seed: u64) -> LogStore {
    let encryption = encrypted.then(|| {
        let kek = Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([0x42; 32])));
        Arc::new(
            KeyManager::open_or_create(
                fs.clone(),
                Path::new(KEYS),
                kek,
                Arc::new(SimRng::new(seed)),
            )
            .unwrap(),
        )
    });
    LogStore::open(
        fs.clone(),
        Path::new(DIR),
        LogStoreOptions {
            segment_size: SEGMENT_SIZE,
            encryption,
            archive_floor: None,
        },
    )
    .unwrap()
}

/// The fixed workload.
fn write_store(encrypted: bool) -> Arc<SimFileSystem> {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open(&fs, encrypted, 1);
    let hs = |term, vote, commit| HardState { term, vote, commit };
    for i in 1..=12u64 {
        let mut b = LogBatch::new();
        b.append(1, i, 1 + i / 6, format!("g1-entry-{i}").into_bytes());
        if i % 2 == 0 {
            b.append(
                2,
                i / 2,
                1,
                vec![u8::try_from(i).unwrap(); usize::try_from(i).unwrap()],
            );
        }
        b.set_hard_state(1, hs(1 + i / 6, 1, i.saturating_sub(1)));
        store.write(&b).unwrap();
    }
    let mut b = LogBatch::new();
    // Conflict resolution: entries 11.. of group 1 replaced by a higher term.
    b.append(1, 11, 4, "g1-overwrite-11")
        .truncate_suffix(2, 6)
        .set_hard_state(2, hs(1, 2, 4))
        .append(3, 1, 2, "")
        .install_snapshot(4, 50, 3)
        .append(4, 51, 3, "g4-after-snapshot");
    store.write(&b).unwrap();
    let mut b = LogBatch::new();
    b.purge(1, 8).purge(2, 3).remove_group(3);
    store.write(&b).unwrap();
    let mut b = LogBatch::new();
    b.append(2, 6, 2, "g2-entry-6-term-2")
        .set_hard_state(4, hs(3, 4, 51));
    store.write(&b).unwrap();
    fs
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// The recovered state, one line per group and per entry.
fn dump(store: &LogStore) -> String {
    let mut out = String::new();
    for g in store.groups() {
        let (first, last) = (store.first_index(g), store.last_index(g));
        let hs = store.hard_state(g);
        let _ = writeln!(
            out,
            "group {g} first {first} last {last} last_term {} boundary_term {} hard_state {} {} {}",
            store.last_term(g),
            store.term(g, first - 1).unwrap(),
            hs.term,
            hs.vote,
            hs.commit
        );
        for e in store.entries(g, first, last + 1).unwrap() {
            let _ = writeln!(out, "entry {g} {} {} {}", e.index, e.term, hex(&e.payload));
        }
    }
    out
}

fn read(fs: &dyn FileSystem, path: &Path) -> Vec<u8> {
    let file = fs.open(path, OpenMode::Read).unwrap();
    let mut bytes = vec![0; usize::try_from(file.size().unwrap()).unwrap()];
    file.read_exact_at(&mut bytes, 0).unwrap();
    bytes
}

/// Every file of `dir` except `expected.txt`, by name.
fn files(fs: &dyn FileSystem, dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for path in fs.read_dir(dir).unwrap() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name == "expected.txt" {
            continue;
        }
        out.insert(name, read(fs, &path));
    }
    out
}

/// The files a fixture holds: the segments, plus the DEK registry when encrypted.
fn store_files(fs: &SimFileSystem, encrypted: bool) -> BTreeMap<String, Vec<u8>> {
    let mut out = files(fs, Path::new(DIR));
    if encrypted {
        let registry = Path::new(KEYS).join(REGISTRY_FILE_NAME);
        out.insert(REGISTRY_FILE_NAME.to_owned(), read(fs, &registry));
    }
    out
}

fn expected(version: u32) -> String {
    String::from_utf8(read(
        &StdFileSystem,
        &fixture_dir(version).join("expected.txt"),
    ))
    .expect("expected.txt committed")
}

#[test]
fn regenerate_format_fixtures_on_request() {
    if std::env::var("RUSTEGON_WRITE_FIXTURES").as_deref() != Ok("1") {
        return;
    }
    for version in VERSIONS {
        let dir = fixture_dir(version);
        if StdFileSystem.read_dir(&dir).is_ok_and(|e| !e.is_empty()) {
            // Committed fixtures are history: a changed writer needs a new version instead.
            continue;
        }
        StdFileSystem.create_dir_all(&dir).unwrap();
        let fs = write_store(encrypted(version));
        for (name, bytes) in store_files(&fs, encrypted(version)) {
            let mut f = StdFileSystem
                .open(&dir.join(name), OpenMode::Truncate)
                .unwrap();
            f.append(&bytes).unwrap();
            f.sync_data().unwrap();
        }
        let store = open(&fs, encrypted(version), 2);
        let mut f = StdFileSystem
            .open(&dir.join("expected.txt"), OpenMode::Truncate)
            .unwrap();
        f.append(dump(&store).as_bytes()).unwrap();
        f.sync_data().unwrap();
    }
}

/// Compatibility: every committed fixture opens and recovers the expected state.
#[test]
fn committed_format_fixtures_still_read() {
    for version in VERSIONS {
        let fixture = files(&StdFileSystem, &fixture_dir(version));
        assert!(
            fixture.len() >= 2,
            "v{version} fixture has {} files",
            fixture.len()
        );
        let fs = Arc::new(SimFileSystem::new());
        fs.create_dir_all(Path::new(DIR)).unwrap();
        fs.create_dir_all(Path::new(KEYS)).unwrap();
        for (name, bytes) in &fixture {
            let dir = if name == REGISTRY_FILE_NAME {
                KEYS
            } else {
                DIR
            };
            let mut f = fs
                .open(&Path::new(dir).join(name), OpenMode::CreateNew)
                .unwrap();
            f.append(bytes).unwrap();
            f.sync_data().unwrap();
        }
        fs.sync_dir(Path::new(DIR)).unwrap();
        fs.sync_dir(Path::new(KEYS)).unwrap();
        let store = open(&fs, encrypted(version), 2);
        assert!(!store.recovery_info().torn_tail);
        let expected = expected(version);
        assert!(expected.lines().count() >= 10, "fixture too small");
        assert_eq!(dump(&store), expected, "v{version}");
    }
    // Both versions hold the same logical log.
    assert_eq!(expected(1), expected(2));
}

/// Stability: the current writer reproduces every fixture's bytes exactly.
#[test]
fn writer_output_matches_current_format_fixtures() {
    for version in VERSIONS {
        let written = store_files(&write_store(encrypted(version)), encrypted(version));
        let fixture = files(&StdFileSystem, &fixture_dir(version));
        assert_eq!(
            written.keys().collect::<Vec<_>>(),
            fixture.keys().collect::<Vec<_>>(),
            "v{version} file set changed"
        );
        for (name, bytes) in &written {
            assert!(
                fixture[name] == *bytes,
                "{name} differs from the rlog v{version} fixture: the persisted format changed; \
                 bump the format version and add fixtures instead (implementation-rules.md §6)"
            );
        }
        // Segment header: magic, then the format version.
        let first = fixture.values().next().unwrap();
        assert_eq!(&first[..8], b"RGNRLOG\0");
        assert_eq!(first[8..12], version.to_le_bytes());
    }
}

/// The v2 fixture holds no entry payload in plaintext.
#[test]
fn encrypted_fixture_holds_no_plaintext_payload() {
    let fixture = files(&StdFileSystem, &fixture_dir(2));
    for needle in [
        &b"g1-entry-1"[..],
        b"g1-overwrite-11",
        b"g4-after-snapshot",
        b"g2-entry-6",
    ] {
        for (name, bytes) in &fixture {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{name} holds {:?}",
                String::from_utf8_lossy(needle)
            );
        }
    }
}
