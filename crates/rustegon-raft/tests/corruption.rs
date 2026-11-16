// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Corruption detection of the Raft log store (storage-engine.md §9: a corrupted record outside
//! a torn final write is an error, never silently dropped; NFR-REL-003, TC-TXN-004 storage
//! half): every single-bit flip in every segment, missing segments, and torn tails that must be
//! tolerated.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{path::Path, sync::Arc};

use common::{DIR, Model, assert_matches, batch, open};
use rustegon_raft::LogStoreError;
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_sim_api::{FileSystem as _, OpenMode};

const SEGMENT_SIZE: u64 = 200;

/// A store with several segments, closed cleanly; returns the acknowledged model.
fn build() -> (Arc<SimFileSystem>, Model) {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open(&fs, SEGMENT_SIZE).unwrap();
    let mut model = Model::default();
    let mut rng = common::Rng(7);
    for i in 0..30u64 {
        // Mostly appends (kinds 0..=3) and hard states (4), with an occasional purge (6), so
        // older segments stay pinned by live entries.
        let kind = [0, 1, 2, 3, 4, 0, 1, 6][usize::try_from(i % 8).unwrap()];
        let op = common::gen_op(&model, kind, rng.next(), rng.next(), rng.next());
        let ops = [op];
        model = model.after(&ops).unwrap();
        store.write(&batch(&ops)).unwrap();
    }
    assert!(store.segment_ids().len() >= 3, "{:?}", store.segment_ids());
    (fs, model)
}

fn segments(fs: &SimFileSystem) -> Vec<std::path::PathBuf> {
    let mut paths = fs.read_dir(Path::new(DIR)).unwrap();
    paths.sort();
    paths
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

#[test]
fn tc_txn_004_every_bit_flip_is_reported_as_corruption() {
    let (fs, model) = build();
    let mut flips = 0;
    for path in segments(&fs) {
        let original = read(&fs, &path);
        for bit in 0..original.len() * 8 {
            let mut damaged = original.clone();
            damaged[bit / 8] ^= 1 << (bit % 8);
            write(&fs, &path, &damaged);
            match open(&fs, SEGMENT_SIZE) {
                Err(LogStoreError::Corruption(_)) => {}
                other => panic!(
                    "{}: bit {bit} flipped: expected corruption, got {:?}",
                    path.display(),
                    other.map(|s| s.segment_ids())
                ),
            }
            flips += 1;
        }
        write(&fs, &path, &original);
    }
    assert!(flips > 1000, "{flips}");
    // Undamaged, the store still opens with the full state.
    let store = open(&fs, SEGMENT_SIZE).unwrap();
    assert_matches(&store, &model, "after restoring every segment");
}

#[test]
fn missing_segments_are_reported_as_corruption() {
    let (fs, _) = build();
    let paths = segments(&fs);
    // A segment in the middle: the ids are no longer consecutive.
    let middle = &paths[paths.len() / 2];
    let bytes = read(&fs, middle);
    fs.remove_file(middle).unwrap();
    assert!(matches!(
        open(&fs, SEGMENT_SIZE),
        Err(LogStoreError::Corruption(_))
    ));
    write(&fs, middle, &bytes);
    // The oldest segment while it still holds live entries: entries of a group are missing.
    fs.remove_file(&paths[0]).unwrap();
    let err = open(&fs, SEGMENT_SIZE).unwrap_err();
    assert!(err.is_corruption(), "{err}");
}

#[test]
fn torn_tails_of_the_last_segment_are_cut_off() {
    let (fs, model) = build();
    // An interrupted batch: a prefix of a valid record (taken from the oldest segment, after its
    // 32-byte header), then possibly zeros.
    let older = read(&fs, &segments(&fs)[0]);
    for (kept, zeros) in [(0, 0), (5, 0), (16, 0), (40, 0), (40, 64), (0, 300)] {
        // Each open starts a new segment, so the last one changes every round.
        let last = segments(&fs).pop().unwrap();
        let original = read(&fs, &last);
        let mut torn = original.clone();
        torn.extend_from_slice(&older[32..32 + kept]);
        torn.resize(torn.len() + zeros, 0);
        write(&fs, &last, &torn);
        let store = open(&fs, SEGMENT_SIZE).unwrap();
        assert_eq!(
            store.recovery_info().torn_tail,
            kept + zeros > 0,
            "kept {kept}, zeros {zeros}"
        );
        assert_matches(&store, &model, &format!("kept {kept}, zeros {zeros}"));
        drop(store);
        // The repair is durable: a later open (the segment is no longer last) is clean.
        fs.crash(1, CrashMode::Clean);
        let store = open(&fs, SEGMENT_SIZE).unwrap();
        assert!(!store.recovery_info().torn_tail);
        assert_matches(&store, &model, "second open");
    }
}

#[test]
fn unsupported_format_version_is_reported() {
    let (fs, _) = build();
    let first = segments(&fs)[0].clone();
    let mut bytes = read(&fs, &first);
    bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
    // Re-seal the header checksum (XXH3-64 of the first 24 bytes) as a newer writer would.
    let sum = twox_hash::XxHash3_64::oneshot(&bytes[..24]);
    bytes[24..32].copy_from_slice(&sum.to_le_bytes());
    write(&fs, &first, &bytes);
    assert!(matches!(
        open(&fs, SEGMENT_SIZE),
        Err(LogStoreError::UnsupportedVersion { version: 3, .. })
    ));
}
