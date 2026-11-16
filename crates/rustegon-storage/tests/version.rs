// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MANIFEST / version set integration tests (storage-engine.md §9, §11, §13): persistence across
//! reopen, torn MANIFEST tails at every byte, missing SSTs, file pinning and obsolete files.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::BTreeSet, path::Path, sync::Arc};

use proptest::prelude::*;
use rustegon_sim_api::{FileSystem, OpenMode, StdFileSystem};
use rustegon_storage::{
    InternalKey, StorageError, ValueKind,
    version::{FileMeta, Version, VersionEdit, VersionSet, manifest_file_name, sst_file_name},
};

type Layout = Vec<(usize, u64)>;

fn fs() -> Arc<dyn FileSystem> {
    Arc::new(StdFileSystem)
}

fn layout(v: &Version) -> Layout {
    let mut out: Layout = v.all_files().map(|(l, f)| (l, f.number)).collect();
    out.sort_unstable();
    out
}

/// A file covering user keys `[lo, hi]`, created on disk as an empty placeholder (the version set
/// only checks existence).
fn sst(dir: &Path, number: u64, lo: u8, hi: u8) -> FileMeta {
    StdFileSystem
        .open(&dir.join(sst_file_name(number)), OpenMode::CreateNew)
        .unwrap();
    FileMeta {
        number,
        size: 100 * number,
        smallest: InternalKey::new(&[lo], number, ValueKind::Put),
        largest: InternalKey::new(&[hi], number, ValueKind::Put),
        smallest_seqno: number,
        largest_seqno: number,
    }
}

fn add(level: usize, f: FileMeta) -> VersionEdit {
    VersionEdit {
        added: vec![(level, f)],
        ..VersionEdit::default()
    }
}

#[derive(Debug, Clone)]
enum Op {
    /// Add an L0 file.
    Flush,
    /// Move the oldest L0 file to the first free key slot of `level`.
    Move(usize),
    /// Delete the newest file of `level`, if any.
    Drop(usize),
}

fn arb_ops() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        prop_oneof![
            3 => Just(Op::Flush),
            2 => (1usize..7).prop_map(Op::Move),
            1 => (0usize..7).prop_map(Op::Drop),
        ],
        1..25,
    )
}

/// Turns an operation into a valid edit for `vs`, or `None` if it does not apply.
fn edit_for(vs: &mut VersionSet, dir: &Path, op: &Op, slot: &mut u8) -> Option<VersionEdit> {
    let v = vs.current();
    match *op {
        Op::Flush => {
            let n = vs.new_file_number();
            let mut e = add(0, sst(dir, n, 0, 255));
            e.flushed_seqno = Some(n);
            e.last_seqno = Some(n + 10);
            Some(e)
        }
        Op::Move(level) => {
            let oldest = v.files(0).last()?;
            // Disjoint single-byte key ranges per moved file keep L1+ non-overlapping.
            let (lo, hi) = (*slot, slot.checked_add(1)?);
            *slot = slot.checked_add(2)?;
            let n = vs.new_file_number();
            Some(VersionEdit {
                deleted: vec![(0, oldest.number)],
                added: vec![(level, sst(dir, n, lo, hi))],
                ..VersionEdit::default()
            })
        }
        Op::Drop(level) => {
            let f = v.files(level).first()?;
            Some(VersionEdit {
                deleted: vec![(level, f.number)],
                ..VersionEdit::default()
            })
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Replay after reopen reproduces exactly the applied state and counters.
    #[test]
    fn version_set_reopen_restores_state(ops in arb_ops()) {
        let dir = tempfile::tempdir().unwrap();
        let mut vs = VersionSet::create(fs(), dir.path()).unwrap();
        let mut slot = 0u8;
        for op in &ops {
            if let Some(e) = edit_for(&mut vs, dir.path(), op, &mut slot) {
                vs.log_and_apply(e).unwrap();
            }
        }
        let (expected, last, flushed) = (layout(&vs.current()), vs.last_seqno(), vs.flushed_seqno());
        let used = vs.new_file_number();
        drop(vs);
        let mut reopened = VersionSet::open(fs(), dir.path()).unwrap();
        prop_assert_eq!(layout(&reopened.current()), expected);
        prop_assert_eq!((reopened.last_seqno(), reopened.flushed_seqno()), (last, flushed));
        // File numbers are never reused, even ones allocated but never recorded.
        prop_assert!(reopened.new_file_number() > used);
    }
}

/// A MANIFEST cut at any byte (crash during an append) recovers to the state after some prefix of
/// the edits, never to anything else.
#[test]
fn manifest_truncated_at_every_byte_recovers_a_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let mut vs = VersionSet::create(fs(), dir.path()).unwrap();
    let mut states = vec![layout(&vs.current())];
    let mut slot = 0u8;
    let ops = [
        Op::Flush,
        Op::Flush,
        Op::Move(1),
        Op::Flush,
        Op::Drop(0),
        Op::Move(2),
    ];
    for op in &ops {
        let e = edit_for(&mut vs, dir.path(), op, &mut slot).unwrap();
        vs.log_and_apply(e).unwrap();
        states.push(layout(&vs.current()));
    }
    let manifest_name = manifest_file_name(vs.manifest_number());
    drop(vs);
    let manifest = std::fs::read(dir.path().join(&manifest_name)).unwrap();
    let ssts: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| Path::new(n).extension().is_some_and(|e| e == "sst"))
        .collect();

    // The first record (initial snapshot) must be complete for the store to exist at all.
    let first_record_end = 12 + u32::from_le_bytes(manifest[..4].try_into().unwrap()) as usize;
    let mut recovered = BTreeSet::new();
    for cut in first_record_end..=manifest.len() {
        let trial = tempfile::tempdir().unwrap();
        std::fs::write(trial.path().join(&manifest_name), &manifest[..cut]).unwrap();
        std::fs::write(trial.path().join("CURRENT"), format!("{manifest_name}\n")).unwrap();
        for name in &ssts {
            std::fs::write(trial.path().join(name), b"").unwrap();
        }
        let vs = VersionSet::open(fs(), trial.path()).unwrap_or_else(|e| panic!("cut {cut}: {e}"));
        let got = layout(&vs.current());
        let k = states
            .iter()
            .position(|s| *s == got)
            .unwrap_or_else(|| panic!("cut {cut}: state {got:?} is not a prefix state"));
        recovered.insert(k);
    }
    // Some prefixes produce identical layouts (a drop can undo a flush); `position` maps each
    // layout to its first occurrence, so expect exactly the distinct first occurrences.
    let distinct: BTreeSet<usize> = states
        .iter()
        .map(|s| states.iter().position(|t| t == s).unwrap())
        .collect();
    assert_eq!(recovered, distinct, "every prefix state reachable");
}

#[test]
fn version_set_refuses_missing_sst_and_double_create() {
    let dir = tempfile::tempdir().unwrap();
    let mut vs = VersionSet::create(fs(), dir.path()).unwrap();
    let n = vs.new_file_number();
    vs.log_and_apply(add(0, sst(dir.path(), n, 1, 2))).unwrap();
    drop(vs);
    assert!(matches!(
        VersionSet::create(fs(), dir.path()),
        Err(StorageError::InvalidArgument(_))
    ));
    std::fs::remove_file(dir.path().join(sst_file_name(n))).unwrap();
    let err = VersionSet::open(fs(), dir.path()).err().unwrap();
    assert!(err.is_corruption(), "{err}");
}

#[test]
fn version_set_rejects_invalid_edit_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let mut vs = VersionSet::create(fs(), dir.path()).unwrap();
    let bad = VersionEdit {
        deleted: vec![(3, 999)],
        ..VersionEdit::default()
    };
    assert!(matches!(
        vs.log_and_apply(bad),
        Err(StorageError::InvalidArgument(_))
    ));
    let n = vs.new_file_number();
    vs.log_and_apply(add(0, sst(dir.path(), n, 1, 2))).unwrap();
    drop(vs);
    let vs = VersionSet::open(fs(), dir.path()).unwrap();
    assert_eq!(layout(&vs.current()), vec![(0, n)]);
}

#[test]
fn obsolete_files_respect_pinned_versions_and_in_flight_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let mut vs = VersionSet::create(fs(), dir.path()).unwrap();
    let a = vs.new_file_number();
    vs.log_and_apply(add(0, sst(dir.path(), a, 0, 9))).unwrap();
    let pinned = vs.current();
    let b = vs.new_file_number();
    vs.log_and_apply(VersionEdit {
        deleted: vec![(0, a)],
        added: vec![(1, sst(dir.path(), b, 0, 9))],
        ..VersionEdit::default()
    })
    .unwrap();
    // An output still being written and an orphan from an earlier crash.
    let in_flight = vs.new_file_number();
    sst(dir.path(), in_flight, 0, 1);
    let orphan = 9_999;
    sst(dir.path(), orphan, 0, 1);
    let names = |vs: &VersionSet| -> Vec<String> {
        vs.obsolete_files(&BTreeSet::from([in_flight]))
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    };
    assert_eq!(names(&vs), [sst_file_name(orphan)]);
    drop(pinned);
    assert_eq!(names(&vs), [sst_file_name(a), sst_file_name(orphan)]);

    // Reopen switches to a new MANIFEST and deletes the old one.
    let old_manifest = manifest_file_name(vs.manifest_number());
    drop(vs);
    let vs = VersionSet::open(fs(), dir.path()).unwrap();
    assert_ne!(manifest_file_name(vs.manifest_number()), old_manifest);
    assert!(!dir.path().join(old_manifest).exists());
    assert!(vs.manifest_number() > orphan, "numbers in use are skipped");
}
