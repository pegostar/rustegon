// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Backup hooks of the Raft log store (FR-BKP-004, PD-066; replication.md §2 "Archiving sealed
//! segments"):
//! - the archive floor keeps obsolete segments above it on disk (also across a reopen) and
//!   raising it releases them;
//! - `force_roll` seals the active segment (no-op when it holds no batch), and a sealed file
//!   never changes afterwards;
//! - the standalone segment reader returns exactly the entries written, for plaintext (v1) and
//!   encrypted (v2) segments, also from an archived copy whose live segment and DEK are gone,
//!   and fails cleanly (`RGN-4006` or corruption) with a missing or wrong key or a damaged file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use common::{DIR, keys, test_kek};
use rustegon_common::{Error, ErrorCode};
use rustegon_raft::{
    LogBatch, LogStore, LogStoreError, LogStoreOptions, SegmentEntry, SegmentKey, read_segment,
};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{FileSystem as _, OpenMode};
use rustegon_storage::encryption::{FileKekProvider, SecretKey};

const SEGMENT_SIZE: u64 = 512;

fn open_with(fs: &Arc<SimFileSystem>, encrypted: bool, floor: Option<&Arc<AtomicU64>>) -> LogStore {
    let encryption = encrypted.then(|| keys(fs, test_kek(), 11).unwrap());
    LogStore::open(
        fs.clone(),
        Path::new(DIR),
        LogStoreOptions {
            segment_size: SEGMENT_SIZE,
            encryption,
            archive_floor: floor.cloned(),
        },
    )
    .unwrap()
}

fn payload(group: u64, index: u64) -> Vec<u8> {
    format!(
        "BKP-{group}-{index:05}-{}",
        "x".repeat(usize::try_from(index % 40).unwrap())
    )
    .into_bytes()
}

/// Appends entries `from..=to` of groups 1 and 2, one batch each; returns them in write order.
fn write(store: &mut LogStore, from: u64, to: u64) -> Vec<SegmentEntry> {
    let mut out = Vec::new();
    for i in from..=to {
        let mut b = LogBatch::new();
        for group in [1, 2] {
            b.append(group, i, 1, payload(group, i));
            out.push(SegmentEntry {
                group,
                index: i,
                term: 1,
                payload: payload(group, i),
            });
        }
        store.write(&b).unwrap();
    }
    out
}

fn purge_all(store: &mut LogStore, up_to: u64) {
    let mut b = LogBatch::new();
    b.purge(1, up_to).purge(2, up_to);
    store.write(&b).unwrap();
}

fn on_disk(fs: &SimFileSystem) -> Vec<PathBuf> {
    let mut v = fs.read_dir(Path::new(DIR)).unwrap();
    v.sort();
    v
}

fn read(fs: &SimFileSystem, path: &Path) -> Vec<u8> {
    let f = fs.open(path, OpenMode::Read).unwrap();
    let mut b = vec![0; usize::try_from(f.size().unwrap()).unwrap()];
    f.read_exact_at(&mut b, 0).unwrap();
    b
}

fn copy_to(fs: &SimFileSystem, from: &Path, to: &Path) {
    let bytes = read(fs, from);
    fs.create_dir_all(to.parent().unwrap()).unwrap();
    let mut f = fs.open(to, OpenMode::Truncate).unwrap();
    f.append(&bytes).unwrap();
    f.sync_data().unwrap();
}

#[test]
fn tc_bkp_004_archive_floor_keeps_segments() {
    // Control: without a floor, purging everything leaves only the active segment.
    let control = Arc::new(SimFileSystem::new());
    let mut store = open_with(&control, false, None);
    write(&mut store, 1, 40);
    purge_all(&mut store, 40);
    assert_eq!(store.segment_ids().len(), 1);

    let fs = Arc::new(SimFileSystem::new());
    let floor = Arc::new(AtomicU64::new(0));
    let mut store = open_with(&fs, false, Some(&floor));
    write(&mut store, 1, 40);
    let before = store.segment_ids();
    assert!(before.len() > 5, "rollovers happened: {before:?}");
    purge_all(&mut store, 40);
    // Every entry is obsolete, but nothing was archived: every segment stays.
    assert_eq!(store.segment_ids(), before);
    assert_eq!(on_disk(&fs).len(), before.len());
    store.delete_obsolete();
    assert_eq!(store.segment_ids(), before);

    // Archiving the first three segments releases exactly those.
    floor.store(before[2], Ordering::Release);
    store.delete_obsolete();
    assert_eq!(store.segment_ids(), before[3..].to_vec());
    assert_eq!(on_disk(&fs).len(), before.len() - 3);

    // The floor also holds across a reopen (whose open runs a deletion pass).
    drop(store);
    let mut store = open_with(&fs, false, Some(&floor));
    assert_eq!(store.segment_ids()[0], before[3]);
    assert_eq!((store.first_index(1), store.last_index(1)), (41, 40));
    // The floor only holds segments back: live entries still pin theirs as before.
    let more = write(&mut store, 41, 45);
    assert_eq!(more.len(), 10);
    floor.store(u64::MAX, Ordering::Release);
    store.delete_obsolete();
    assert!(
        store.segment_ids()[0] > before[3],
        "purged segments released"
    );
    assert_eq!(store.entries(1, 41, 46).unwrap().len(), 5);
    purge_all(&mut store, 45);
    assert_eq!(
        store.segment_ids().len(),
        1,
        "only the active segment is left"
    );
}

#[test]
fn tc_bkp_004_force_roll_seals_the_active_segment() {
    let fs = Arc::new(SimFileSystem::new());
    let floor = Arc::new(AtomicU64::new(0));
    let mut store = open_with(&fs, false, Some(&floor));
    // A fresh active segment holds no batch: nothing to seal.
    assert_eq!(store.force_roll().unwrap(), None);
    assert_eq!(store.sealed_segment_ids(), Vec::<u64>::new());

    let mut b = LogBatch::new();
    b.append(1, 1, 1, "first");
    store.write(&b).unwrap();
    let active = *store.segment_ids().last().unwrap();
    assert_eq!(store.force_roll().unwrap(), Some(active));
    assert_eq!(store.sealed_segment_ids(), vec![active]);
    assert_eq!(*store.segment_ids().last().unwrap(), active + 1);
    // The new active segment is empty again.
    assert_eq!(store.force_roll().unwrap(), None);

    let sealed = store.sealed_segments();
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].id, active);
    assert_eq!(sealed[0].entries, BTreeMap::from([(1, (1, 1))]));
    assert!(!sealed[0].encrypted);
    let bytes = read(&fs, &sealed[0].path);
    assert_eq!(bytes.len() as u64, sealed[0].size);

    // Later writes go to the new segment; the sealed file never changes.
    let mut b = LogBatch::new();
    b.append(1, 2, 1, "second");
    store.write(&b).unwrap();
    assert_eq!(read(&fs, &sealed[0].path), bytes);
    let entries = store.entries(1, 1, 3).unwrap();
    assert_eq!(entries[0].payload, b"first");
    assert_eq!(entries[1].payload, b"second");

    // After a reopen every recovered segment is sealed and keeps its entry ranges.
    drop(store);
    let store = open_with(&fs, false, Some(&floor));
    let sealed = store.sealed_segments();
    assert_eq!(sealed.len(), 2);
    assert_eq!(sealed[0].entries, BTreeMap::from([(1, (1, 1))]));
    assert_eq!(sealed[1].entries, BTreeMap::from([(1, (2, 2))]));
    assert_eq!(read(&fs, &sealed[0].path), bytes);
}

#[test]
fn tc_bkp_004_standalone_segment_reader_v1_and_v2() {
    for encrypted in [false, true] {
        let ctx = if encrypted { "v2" } else { "v1" };
        let fs = Arc::new(SimFileSystem::new());
        let floor = Arc::new(AtomicU64::new(0));
        let mut store = open_with(&fs, encrypted, Some(&floor));
        let written = write(&mut store, 1, 30);
        store.force_roll().unwrap();
        let sealed = store.sealed_segments();
        assert!(sealed.len() > 3, "{ctx}: rollovers happened");

        // "Archive" every sealed segment under another name, with its wrapped DEK.
        let mut archived = Vec::new();
        for s in &sealed {
            assert_eq!(s.encrypted, encrypted, "{ctx}");
            let to = PathBuf::from(format!("/archive/seg-{}.bin", s.id));
            copy_to(&fs, &s.path, &to);
            let key = store.segment_key(s.id);
            assert_eq!(key.is_some(), encrypted, "{ctx}");
            archived.push((s.clone(), to, key));
        }

        // Release and shred the live segments: the archive must be self-sufficient.
        floor.store(u64::MAX, Ordering::Release);
        purge_all(&mut store, 30);
        assert_eq!(store.segment_ids().len(), 1, "{ctx}");
        for (s, _, _) in &archived {
            assert!(
                store.segment_key(s.id).is_none(),
                "{ctx}: DEK of {} kept",
                s.id
            );
        }
        drop(store);

        let mut read_back = Vec::new();
        for (s, path, wrapped) in &archived {
            let key = wrapped.clone().map(|wrapped| SegmentKey {
                kek: test_kek(),
                wrapped,
            });
            let reader = read_segment(fs.as_ref(), path, key.as_ref()).unwrap();
            assert_eq!(reader.segment_id(), s.id, "{ctx}");
            assert_eq!(reader.encrypted(), encrypted, "{ctx}");
            let entries: Vec<SegmentEntry> = reader.map(Result::unwrap).collect();
            // The per-group ranges announced for the segment match its content.
            let mut ranges: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
            for e in &entries {
                let r = ranges.entry(e.group).or_insert((e.index, e.index));
                r.0 = r.0.min(e.index);
                r.1 = r.1.max(e.index);
            }
            assert_eq!(ranges, s.entries, "{ctx}: segment {}", s.id);
            read_back.extend(entries);
        }
        assert_eq!(read_back, written, "{ctx}: entries equal what was written");

        // Damage to an archived file is corruption, never a silently shorter segment.
        let (s, path, wrapped) = &archived[1];
        let key = wrapped.clone().map(|wrapped| SegmentKey {
            kek: test_kek(),
            wrapped,
        });
        let mut bytes = read(&fs, path);
        let at = bytes.len() - 20;
        bytes[at] ^= 0x01;
        let damaged = PathBuf::from("/archive/damaged.bin");
        let mut f = fs.open(&damaged, OpenMode::Truncate).unwrap();
        f.append(&bytes).unwrap();
        let err = read_segment(fs.as_ref(), &damaged, key.as_ref())
            .unwrap()
            .find_map(Result::err)
            .unwrap_or_else(|| panic!("{ctx}: damaged segment {} read", s.id));
        assert!(err.is_corruption(), "{ctx}: {err}");

        if !encrypted {
            continue;
        }
        let (_, path, wrapped) = &archived[0];
        let wrapped = wrapped.clone().unwrap();
        // No key at all: RGN-4006.
        let err = read_segment(fs.as_ref(), path, None).unwrap_err();
        assert_eq!(Error::from(err).code(), ErrorCode::KeyUnavailable);
        // The right DEK under another KEK: RGN-4006 before any decryption.
        let other = SegmentKey {
            kek: Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([0x11; 32]))),
            wrapped: wrapped.clone(),
        };
        let err = read_segment(fs.as_ref(), path, Some(&other)).unwrap_err();
        assert_eq!(Error::from(err).code(), ErrorCode::KeyUnavailable);
        // Another segment's DEK: every payload fails authentication.
        let swapped = SegmentKey {
            kek: test_kek(),
            wrapped: archived[1].2.clone().unwrap(),
        };
        let mut reader = read_segment(fs.as_ref(), path, Some(&swapped)).unwrap();
        let err: LogStoreError = reader.next_entry().unwrap_err();
        assert!(err.is_corruption(), "{err}");
        assert!(
            reader.next_entry().unwrap().is_none(),
            "the reader ends after an error"
        );
    }
}
