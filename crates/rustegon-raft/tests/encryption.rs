// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Encryption at rest of the Raft log store (storage-engine.md §7, replication.md §2 "Log
//! store format v2", FR-EAR-001, PD-057).
//!
//! - TC-EAR-001 (log part): entry payloads are absent from every file of an encrypted log
//!   (segments and the DEK registry) and read back unchanged after a reopen; a plaintext control
//!   finds them, so the scan works.
//! - A payload whose ciphertext was altered (record checksum re-sealed, as an attacker would) is
//!   reported as corruption on read, never returned.
//! - TC-EAR-003 (log part): an encrypted log opened without a key, or under another KEK, is
//!   `RGN-4006`.
//! - TC-EAR-004 (log part): a plaintext log switches to encryption at a reopen: its v1 segments
//!   stay readable, new segments are v2, and once the v1 segments are deleted the admission is
//!   dropped; a plaintext segment swapped into an encrypted log is refused.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use common::{DIR, KEYS_DIR, keys, open, open_encrypted, test_kek};
use rustegon_common::{Error, ErrorCode};
use rustegon_raft::{LogBatch, LogStore, LogStoreError, LogStoreOptions};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{FileSystem as _, OpenMode};
use rustegon_storage::encryption::{FileKekProvider, KeyManager, SecretKey};

/// Small segments: rollovers and deletions happen within a few batches.
const SEGMENT_SIZE: u64 = 1024;
const GROUP: u64 = 1;

fn canary(i: u64) -> Vec<u8> {
    format!("EAR-LOG-CANARY-{i:06}-plaintext").into_bytes()
}

fn write_entries(store: &mut LogStore, from: u64, to: u64) {
    for i in from..=to {
        let mut b = LogBatch::new();
        b.append(GROUP, i, 1, canary(i));
        store.write(&b).unwrap();
    }
}

fn files_under(fs: &SimFileSystem, dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs.read_dir(dir) else {
        return out;
    };
    for path in entries {
        if fs.open(&path, OpenMode::Read).is_ok() {
            out.push(path);
        } else {
            out.extend(files_under(fs, &path));
        }
    }
    out.sort();
    out
}

fn read(fs: &SimFileSystem, path: &Path) -> Vec<u8> {
    let f = fs.open(path, OpenMode::Read).unwrap();
    let mut b = vec![0; usize::try_from(f.size().unwrap()).unwrap()];
    f.read_exact_at(&mut b, 0).unwrap();
    b
}

fn write(fs: &SimFileSystem, path: &Path, bytes: &[u8]) {
    let mut f = fs.open(path, OpenMode::Truncate).unwrap();
    f.append(bytes).unwrap();
    f.sync_data().unwrap();
}

/// Canaries `1..=n` found anywhere under `/store`.
fn canaries_on_disk(fs: &SimFileSystem, n: u64) -> usize {
    let all: Vec<Vec<u8>> = files_under(fs, Path::new("/store"))
        .iter()
        .map(|p| read(fs, p))
        .collect();
    (1..=n)
        .filter(|&i| {
            let c = canary(i);
            all.iter()
                .any(|bytes| bytes.windows(c.len()).any(|w| w == c))
        })
        .count()
}

fn assert_entries(store: &LogStore, from: u64, to: u64) {
    let entries = store.entries(GROUP, from, to + 1).unwrap();
    assert_eq!(entries.len() as u64, to + 1 - from);
    for e in entries {
        assert_eq!(e.payload, canary(e.index), "entry {}", e.index);
    }
}

fn segment_versions(fs: &SimFileSystem) -> Vec<(PathBuf, u32)> {
    files_under(fs, Path::new(DIR))
        .into_iter()
        .map(|p| {
            let b = read(fs, &p);
            let v = u32::from_le_bytes(b[8..12].try_into().unwrap());
            (p, v)
        })
        .collect()
}

#[test]
fn tc_ear_001_log_payloads_are_encrypted_and_read_back_after_reopen() {
    const N: u64 = 300;
    // Control: the plaintext log holds the canaries (the scan can see them).
    let plain = Arc::new(SimFileSystem::new());
    write_entries(&mut open(&plain, SEGMENT_SIZE).unwrap(), 1, N);
    assert_eq!(canaries_on_disk(&plain, N), usize::try_from(N).unwrap());

    let fs = Arc::new(SimFileSystem::new());
    let mut store = open_encrypted(&fs, SEGMENT_SIZE).unwrap();
    write_entries(&mut store, 1, N);
    assert!(store.segment_ids().len() > 3, "rollovers happened");
    assert_entries(&store, 1, N);
    drop(store);
    assert_eq!(
        canaries_on_disk(&fs, N),
        0,
        "a canary is on disk in plaintext"
    );
    assert!(segment_versions(&fs).iter().all(|(_, v)| *v == 2));

    let store = open_encrypted(&fs, SEGMENT_SIZE).unwrap();
    assert_entries(&store, 1, N);
}

/// An attacker who alters a payload's ciphertext and re-seals the record checksum (XXH3 is not
/// keyed) passes recovery's checksum, but the GCM tag refuses the payload on read.
#[test]
fn tc_ear_001_altered_log_payload_is_corruption_on_read() {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open_encrypted(&fs, 1 << 20).unwrap();
    write_entries(&mut store, 1, 1);
    let segment = segment_versions(&fs).last().unwrap().0.clone();
    drop(store);
    let mut bytes = read(&fs, &segment);
    // Header (32 bytes), then the segment-head snapshot record, then the entry record.
    let rec_len =
        |at: usize| 16 + u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize + 1;
    let entry_at = 32 + rec_len(32);
    let end = entry_at + rec_len(entry_at);
    assert_eq!(end, bytes.len(), "one entry record after the snapshot");
    // The last body byte before the end marker belongs to the tag.
    bytes[end - 2] ^= 0x01;
    let len_bytes: [u8; 4] = bytes[entry_at..entry_at + 4].try_into().unwrap();
    let mut h = twox_hash::XxHash3_64::new();
    std::hash::Hasher::write(&mut h, &len_bytes);
    std::hash::Hasher::write(&mut h, &bytes[entry_at + 16..end - 1]);
    let sum = std::hash::Hasher::finish(&h);
    bytes[entry_at + 8..entry_at + 16].copy_from_slice(&sum.to_le_bytes());
    write(&fs, &segment, &bytes);

    let store = open_encrypted(&fs, 1 << 20).unwrap();
    let err = store.entries(GROUP, 1, 2).unwrap_err();
    assert!(err.is_corruption(), "{err}");
    assert_eq!(Error::from(err).code(), ErrorCode::StorageCorruption);
}

#[test]
fn tc_ear_003_encrypted_log_without_or_with_another_key_is_key_unavailable() {
    let fs = Arc::new(SimFileSystem::new());
    write_entries(&mut open_encrypted(&fs, SEGMENT_SIZE).unwrap(), 1, 20);

    let err = open(&fs, SEGMENT_SIZE).err().unwrap();
    assert!(err.to_string().contains("no key-encryption key"), "{err}");
    assert_eq!(Error::from(err).code(), ErrorCode::KeyUnavailable);

    let other = Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([0x11; 32])));
    let err = KeyManager::open(
        fs.clone(),
        Path::new(KEYS_DIR),
        other,
        Arc::new(rustegon_sim::workload::rng::SimRng::new(1)),
    )
    .err()
    .unwrap();
    assert_eq!(Error::from(err).code(), ErrorCode::KeyUnavailable);
}

#[test]
fn tc_ear_004_plaintext_log_switches_to_encryption_at_reopen() {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open(&fs, SEGMENT_SIZE).unwrap();
    write_entries(&mut store, 1, 60);
    let plaintext_ids = store.segment_ids();
    assert!(plaintext_ids.len() > 1);
    drop(store);

    let keys = keys(&fs, test_kek(), 3).unwrap();
    let mut store = LogStore::open(
        fs.clone(),
        Path::new(DIR),
        LogStoreOptions {
            segment_size: SEGMENT_SIZE,
            encryption: Some(Arc::clone(&keys)),
            archive_floor: None,
        },
    )
    .unwrap();
    let newest_plaintext = *plaintext_ids.last().unwrap();
    assert_eq!(keys.admitted_plaintext_manifest(), Some(newest_plaintext));
    assert_entries(&store, 1, 60);
    write_entries(&mut store, 61, 120);
    for (path, version) in segment_versions(&fs) {
        let id: u64 = path.file_stem().unwrap().to_str().unwrap().parse().unwrap();
        assert_eq!(version, if id <= newest_plaintext { 1 } else { 2 }, "{id}");
    }
    drop(store);
    // A reopen with plaintext segments still present is accepted (they are admitted).
    let mut store = open_encrypted_with(&fs, &keys);
    assert_entries(&store, 1, 120);
    // Purging the plaintext-era entries deletes the v1 segments; the admission goes with them.
    let mut b = LogBatch::new();
    b.purge(GROUP, 60);
    store.write(&b).unwrap();
    assert!(store.segment_ids()[0] > newest_plaintext);
    assert_eq!(keys.admitted_plaintext_manifest(), None);
    assert!(segment_versions(&fs).iter().all(|(_, v)| *v == 2));
    assert_eq!(
        canaries_on_disk(&fs, 120),
        0,
        "no plaintext entry left on disk"
    );
    drop(store);
    assert_entries(&open_encrypted_with(&fs, &keys), 61, 120);
}

/// A plaintext segment swapped into an encrypted log (under an id the registry protects, or a
/// newer id than any admitted plaintext segment) is refused as corruption.
#[test]
fn tc_ear_004_plaintext_segment_swapped_into_an_encrypted_log_is_refused() {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open_encrypted(&fs, SEGMENT_SIZE).unwrap();
    write_entries(&mut store, 1, 5);
    let ids = store.segment_ids();
    drop(store);
    let last = *ids.last().unwrap();
    for (target, replace) in [(last, true), (last + 1, false)] {
        let victim = Arc::new(SimFileSystem::new());
        for (name, bytes) in files_under(&fs, Path::new("/store"))
            .into_iter()
            .map(|p| (p.clone(), read(&fs, &p)))
        {
            victim.create_dir_all(name.parent().unwrap()).unwrap();
            write(&victim, &name, &bytes);
        }
        let forged = plaintext_segment(target);
        let path = Path::new(DIR).join(format!("{target:020}.rlog"));
        if replace {
            assert!(victim.open(&path, OpenMode::Read).is_ok());
        }
        write(&victim, &path, &forged);
        let err = open_encrypted(&victim, SEGMENT_SIZE).err().unwrap();
        assert!(err.is_corruption(), "segment {target}: {err}");
        assert!(
            err.to_string().contains("plaintext raft log segment"),
            "{err}"
        );
    }
}

fn open_encrypted_with(fs: &Arc<SimFileSystem>, keys: &Arc<KeyManager>) -> LogStore {
    LogStore::open(
        fs.clone(),
        Path::new(DIR),
        LogStoreOptions {
            segment_size: SEGMENT_SIZE,
            encryption: Some(Arc::clone(keys)),
            archive_floor: None,
        },
    )
    .unwrap()
}

/// The bytes of a valid plaintext (v1) segment `id` holding one forged entry: a scratch
/// plaintext store reopened until its active segment has that id.
fn plaintext_segment(id: u64) -> Vec<u8> {
    let scratch = Arc::new(SimFileSystem::new());
    for _ in 1..id {
        drop(open(&scratch, SEGMENT_SIZE).unwrap());
    }
    let mut store = open(&scratch, SEGMENT_SIZE).unwrap();
    assert_eq!(*store.segment_ids().last().unwrap(), id);
    let mut b = LogBatch::new();
    b.append(GROUP, 1, 1, "forged");
    store.write(&b).unwrap();
    drop(store);
    read(&scratch, &Path::new(DIR).join(format!("{id:020}.rlog")))
}

#[test]
fn log_store_errors_keep_the_storage_code() {
    let err = LogStoreError::from(rustegon_storage::StorageError::KeyUnavailable("x".into()));
    assert_eq!(Error::from(err).code(), ErrorCode::KeyUnavailable);
}
