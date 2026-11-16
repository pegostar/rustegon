// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! External SST ingestion (storage-engine.md §12; TC-STO-006 ingestion with overlapping
//! memtables).

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{FileSystem, OpenMode};
use rustegon_storage::{
    EngineOptions, InternalKey, LsmEngine, StorageError, ValueKind, WriteBatch,
    range_del::RangeTombstone,
    sst::{SstWriter, SstWriterOptions},
    version::NUM_LEVELS,
};

const DIR: &str = "/store";
const EXT: &str = "/ext";

fn engine(fs: &Arc<SimFileSystem>) -> LsmEngine {
    LsmEngine::open(fs.clone(), Path::new(DIR), EngineOptions::default()).unwrap()
}

/// Writes an external SST with `entries` (sorted by key; seqnos are irrelevant, ingestion
/// replaces them) and `tombstones`.
fn external(
    fs: &SimFileSystem,
    name: &str,
    entries: &[(&str, ValueKind, &str)],
    tombstones: &[(&str, &str)],
) -> PathBuf {
    fs.create_dir_all(Path::new(EXT)).unwrap();
    let path = Path::new(EXT).join(name);
    let mut w = SstWriter::new(
        fs.open(&path, OpenMode::CreateNew).unwrap(),
        SstWriterOptions::default(),
    );
    for (k, kind, v) in entries {
        w.add(
            InternalKey::new(k.as_bytes(), 0, *kind).as_bytes(),
            v.as_bytes(),
        )
        .unwrap();
    }
    for (s, e) in tombstones {
        w.add_range_tombstone(RangeTombstone {
            start: s.as_bytes().to_vec(),
            end: e.as_bytes().to_vec(),
            seqno: 0,
        })
        .unwrap();
    }
    w.finish().unwrap();
    path
}

fn put(engine: &LsmEngine, key: &str, value: &str) {
    let mut b = WriteBatch::new();
    b.put(key.as_bytes(), value.as_bytes().to_vec());
    engine.write(&b).unwrap();
}

fn get(engine: &LsmEngine, key: &str, snap: Option<&rustegon_storage::Snapshot>) -> Option<String> {
    engine
        .get(key.as_bytes(), snap)
        .unwrap()
        .map(|v| String::from_utf8(v.to_vec()).unwrap())
}

/// TC-STO-006: the overlapping memtable is flushed first, the ingested values become visible
/// atomically at one new seqno, and an earlier snapshot keeps reading the old values.
#[test]
fn tc_sto_006_ingest_over_overlapping_memtable() {
    let fs = Arc::new(SimFileSystem::new());
    let e = engine(&fs);
    put(&e, "a", "old-a");
    put(&e, "m", "old-m");
    let before = e.snapshot();
    let flushed_before = e.flushed_seqno();
    let file = external(
        &fs,
        "1.sst",
        &[
            ("m", ValueKind::Put, "new-m"),
            ("n", ValueKind::Put, "new-n"),
        ],
        &[],
    );
    let seqno = e.ingest(&[file]).unwrap();
    assert_eq!(seqno, before.seqno() + 1);
    assert_eq!(e.last_seqno(), seqno);
    assert!(
        e.flushed_seqno() > flushed_before,
        "overlapping memtable flushed"
    );

    assert_eq!(get(&e, "a", None).as_deref(), Some("old-a"));
    assert_eq!(get(&e, "m", None).as_deref(), Some("new-m"));
    assert_eq!(get(&e, "n", None).as_deref(), Some("new-n"));
    assert_eq!(get(&e, "m", Some(&before)).as_deref(), Some("old-m"));
    assert_eq!(get(&e, "n", Some(&before)), None);

    // Newer writes win over ingested data; everything survives a reopen.
    put(&e, "n", "newest-n");
    e.flush().unwrap();
    drop(before);
    drop(e);
    let e = engine(&fs);
    assert_eq!(get(&e, "m", None).as_deref(), Some("new-m"));
    assert_eq!(get(&e, "n", None).as_deref(), Some("newest-n"));
}

/// Without overlap the file goes to the deepest level; ingested tombstones delete older data.
#[test]
fn ingest_places_deep_and_applies_tombstones() {
    let fs = Arc::new(SimFileSystem::new());
    let e = engine(&fs);
    let first = external(&fs, "1.sst", &[("k1", ValueKind::Put, "v1")], &[]);
    e.ingest(&[first]).unwrap();
    assert_eq!(e.current_version().files(NUM_LEVELS - 1).len(), 1);

    put(&e, "k2", "v2");
    e.flush().unwrap();
    let deleting = external(
        &fs,
        "2.sst",
        &[("k3", ValueKind::Put, "v3")],
        &[("k1", "k3")],
    );
    e.ingest(&[deleting]).unwrap();
    assert_eq!(get(&e, "k1", None), None);
    assert_eq!(get(&e, "k2", None), None);
    assert_eq!(get(&e, "k3", None).as_deref(), Some("v3"));
}

#[test]
fn ingest_rejects_overlapping_duplicate_and_empty_inputs() {
    let fs = Arc::new(SimFileSystem::new());
    let e = engine(&fs);
    let a = external(
        &fs,
        "a.sst",
        &[("a", ValueKind::Put, "1"), ("c", ValueKind::Put, "1")],
        &[],
    );
    let b = external(&fs, "b.sst", &[("b", ValueKind::Put, "2")], &[]);
    assert!(matches!(
        e.ingest(&[a, b]),
        Err(StorageError::InvalidArgument(_))
    ));

    fs.create_dir_all(Path::new(EXT)).unwrap();
    let dup = Path::new(EXT).join("dup.sst");
    let mut w = SstWriter::new(
        fs.open(&dup, OpenMode::CreateNew).unwrap(),
        SstWriterOptions::default(),
    );
    w.add(InternalKey::new(b"k", 2, ValueKind::Put).as_bytes(), b"x")
        .unwrap();
    w.add(InternalKey::new(b"k", 1, ValueKind::Put).as_bytes(), b"y")
        .unwrap();
    w.finish().unwrap();
    assert!(matches!(
        e.ingest(&[dup]),
        Err(StorageError::InvalidArgument(_))
    ));

    let empty = external(&fs, "empty.sst", &[], &[]);
    assert!(matches!(
        e.ingest(&[empty]),
        Err(StorageError::InvalidArgument(_))
    ));
    // Nothing was installed and no store file leaked.
    assert_eq!(e.current_version().all_files().count(), 0);
    let leftovers = fs
        .read_dir(Path::new(DIR))
        .unwrap()
        .iter()
        .filter(|p| p.extension().is_some_and(|x| x == "sst"))
        .count();
    assert_eq!(leftovers, 0);
}
