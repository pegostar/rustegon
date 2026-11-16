// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-STO-002 (first slice): crash simulation of the version set on the simulated file system
//! (storage-engine.md §9, §13, §15; ADR-029).
//!
//! A fixed workload of flushes (SST write → fsync → directory fsync → MANIFEST edit), compactions
//! (merge everything into one L1 file, then delete the inputs) and reopens (fresh MANIFEST +
//! `CURRENT` switch) runs on `SimFileSystem`. The file system halts at every mutating operation in
//! turn — so crash points fall between and inside SST writes, MANIFEST appends and `CURRENT`
//! switches — then crashes in every [`CrashMode`] (clean, torn prefix, torn tail followed by
//! zeros, journaled namespace prefix) with several seeds each, and the store is reopened.
//!
//! Asserted after every crash:
//! - the recovered layout is the last acknowledged one or, if an edit was in flight, that edit's
//!   result (prefix consistency, no acknowledged edit lost);
//! - every referenced SST exists with its full recorded size;
//! - the recovered store accepts a new edit and survives a further reopen.
//!
//! Out of scope here (later M1 work): the full-engine crash campaign with memtable flushes,
//! compaction and Raft log replay, and the 24 h nightly run (testing-strategy.md §3).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::BTreeSet, io, path::Path, sync::Arc};

use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_sim_api::{FileSystem, OpenMode};
use rustegon_storage::{
    InternalKey, Result, StorageError, ValueKind,
    version::{FileMeta, Version, VersionEdit, VersionSet, sst_file_name},
};

/// `(level, number, size)` of every live file.
type Layout = BTreeSet<(usize, u64, u64)>;

const DIR: &str = "/store";
/// Crash seeds per crash point and mode: torn-write and journal outcomes differ per seed.
/// 16 × 4 modes keeps the sweep at a few seconds in a debug build.
const SEEDS: u64 = 16;
/// Lower bound on the workload's mutating operations: its 12 steps each do at least 4 (SST
/// create, append, fsync, directory fsync, plus the MANIFEST append and fsync). Fewer means the
/// workload silently shrank and the sweep no longer covers every kind of crash point.
const MIN_CRASH_POINTS: u64 = 50;

#[derive(Debug, Clone, Copy)]
enum Step {
    Flush,
    Compact,
    Reopen,
}

const WORKLOAD: [Step; 12] = [
    Step::Flush,
    Step::Flush,
    Step::Compact,
    Step::Flush,
    Step::Reopen,
    Step::Flush,
    Step::Flush,
    Step::Compact,
    Step::Reopen,
    Step::Flush,
    Step::Compact,
    Step::Flush,
];

fn layout(v: &Version) -> Layout {
    v.all_files().map(|(l, f)| (l, f.number, f.size)).collect()
}

/// What the workload achieved before the file system halted.
#[derive(Default)]
struct Outcome {
    created: bool,
    /// Layouts after each acknowledged edit; `[0]` is the empty store.
    acked: Vec<Layout>,
    /// Layout an in-flight edit would produce, if the halt hit inside `log_and_apply`.
    in_flight: Option<Layout>,
}

/// Writes SST `number` with `size` bytes following the flush protocol of §9.
fn write_sst(
    fs: &dyn FileSystem,
    dir: &Path,
    number: u64,
    size: u64,
    sync_dir: bool,
) -> Result<()> {
    let mut f = fs.open(&dir.join(sst_file_name(number)), OpenMode::CreateNew)?;
    f.append(&vec![0xAB; usize::try_from(size).unwrap()])?;
    f.sync_data()?;
    // The SST's name must be durable before the MANIFEST refers to it.
    if sync_dir {
        fs.sync_dir(dir)?;
    }
    Ok(())
}

fn meta(number: u64, lo: u8, hi: u8, seqnos: (u64, u64)) -> FileMeta {
    FileMeta {
        number,
        size: 64 + number * 7,
        smallest: InternalKey::new(&[lo], seqnos.1, ValueKind::Put),
        largest: InternalKey::new(&[hi], seqnos.0, ValueKind::Put),
        smallest_seqno: seqnos.0,
        largest_seqno: seqnos.1,
    }
}

/// Logs `edit`, recording it as in flight first so a halt inside the call is accounted for.
fn apply(set: &mut VersionSet, out: &mut Outcome, edit: VersionEdit) -> Result<()> {
    let before = layout(&set.current());
    let mut expected = before.clone();
    for &(l, n) in &edit.deleted {
        expected.retain(|&(el, en, _)| (el, en) != (l, n));
    }
    expected.extend(edit.added.iter().map(|(l, f)| (*l, f.number, f.size)));
    out.in_flight = Some(expected);
    set.log_and_apply(edit)?;
    out.acked.push(out.in_flight.take().unwrap());
    assert_eq!(&layout(&set.current()), out.acked.last().unwrap());
    Ok(())
}

fn run(fs: &Arc<SimFileSystem>, sync_dir: bool, out: &mut Outcome) -> Result<()> {
    let dyn_fs: Arc<dyn FileSystem> = fs.clone();
    let dir = Path::new(DIR);
    let mut set = VersionSet::create(Arc::clone(&dyn_fs), dir)?;
    out.created = true;
    out.acked.push(Layout::new());
    let mut seqno = 0u64;
    for (i, step) in (0u8..).zip(WORKLOAD) {
        match step {
            Step::Flush => {
                let number = set.new_file_number();
                let f = meta(number, b'a' + i, b'k' + i, (seqno + 1, seqno + 10));
                seqno += 10;
                write_sst(dyn_fs.as_ref(), dir, number, f.size, sync_dir)?;
                let edit = VersionEdit {
                    last_seqno: Some(seqno),
                    flushed_seqno: Some(seqno),
                    added: vec![(0, f)],
                    ..VersionEdit::default()
                };
                apply(&mut set, out, edit)?;
            }
            Step::Compact => {
                let current = set.current();
                let inputs: Vec<_> = (0..2)
                    .flat_map(|l| current.files(l).iter().map(move |f| (l, f)))
                    .collect();
                let lo = inputs
                    .iter()
                    .map(|(_, f)| f.smallest.user_key()[0])
                    .min()
                    .unwrap();
                let hi = inputs
                    .iter()
                    .map(|(_, f)| f.largest.user_key()[0])
                    .max()
                    .unwrap();
                let s0 = inputs.iter().map(|(_, f)| f.smallest_seqno).min().unwrap();
                let s1 = inputs.iter().map(|(_, f)| f.largest_seqno).max().unwrap();
                let number = set.new_file_number();
                let f = meta(number, lo, hi, (s0, s1));
                write_sst(dyn_fs.as_ref(), dir, number, f.size, sync_dir)?;
                let edit = VersionEdit {
                    deleted: inputs.iter().map(|(l, f)| (*l, f.number)).collect(),
                    added: vec![(1, f)],
                    ..VersionEdit::default()
                };
                let obsolete: Vec<_> = inputs.iter().map(|(_, f)| f.number).collect();
                drop(current);
                apply(&mut set, out, edit)?;
                // Post-compaction cleanup (§11); deletions are not fsynced, so a crash may
                // resurrect the inputs as orphans, which is harmless.
                for n in obsolete {
                    dyn_fs.remove_file(&dir.join(sst_file_name(n)))?;
                }
            }
            Step::Reopen => {
                drop(set);
                set = VersionSet::open(Arc::clone(&dyn_fs), dir)?;
                assert_eq!(&layout(&set.current()), out.acked.last().unwrap());
            }
        }
    }
    Ok(())
}

/// Checks recovery after a crash; panics with `ctx` on a violated property.
fn check_recovery(fs: &Arc<SimFileSystem>, out: &Outcome, ctx: &str) {
    let dyn_fs: Arc<dyn FileSystem> = fs.clone();
    let dir = Path::new(DIR);
    let mut set = match VersionSet::open(Arc::clone(&dyn_fs), dir) {
        Ok(set) => set,
        // Crashed before the store existed: no CURRENT yet.
        Err(StorageError::Io(e)) if !out.created && e.kind() == io::ErrorKind::NotFound => return,
        Err(e) => panic!("{ctx}: recovery failed: {e}"),
    };
    let recovered = layout(&set.current());
    let last = out.acked.last().cloned().unwrap_or_default();
    assert!(
        recovered == last || out.in_flight.as_ref() == Some(&recovered),
        "{ctx}: recovered {recovered:?}, acknowledged {last:?}, in flight {:?}",
        out.in_flight
    );
    for &(_, number, size) in &recovered {
        let f = dyn_fs
            .open(&dir.join(sst_file_name(number)), OpenMode::Read)
            .unwrap_or_else(|e| panic!("{ctx}: SST {number} missing: {e}"));
        assert_eq!(f.size().unwrap(), size, "{ctx}: SST {number} truncated");
    }

    // The recovered store stays usable: one more flush, then a clean reopen.
    let number = set.new_file_number();
    let f = meta(number, b'x', b'y', (1000, 1000));
    write_sst(dyn_fs.as_ref(), dir, number, f.size, true).unwrap();
    set.log_and_apply(VersionEdit {
        added: vec![(0, f)],
        ..VersionEdit::default()
    })
    .unwrap_or_else(|e| panic!("{ctx}: edit after recovery failed: {e}"));
    let expected = layout(&set.current());
    drop(set);
    let set = VersionSet::open(dyn_fs, dir).unwrap();
    assert_eq!(layout(&set.current()), expected, "{ctx}: second reopen");
}

/// Runs the workload to completion and returns its number of mutating operations.
fn total_ops(sync_dir: bool) -> u64 {
    let fs = Arc::new(SimFileSystem::new());
    run(&fs, sync_dir, &mut Outcome::default()).unwrap();
    fs.op_count()
}

/// Runs the workload halting after `point` operations, then crashes with `seed` in `mode`.
fn crash_at(
    point: u64,
    seed: u64,
    mode: CrashMode,
    sync_dir: bool,
) -> (Arc<SimFileSystem>, Outcome) {
    let fs = Arc::new(SimFileSystem::new());
    fs.halt_after_ops(point);
    let mut out = Outcome::default();
    let result = run(&fs, sync_dir, &mut out);
    assert!(
        result.is_err() && fs.is_halted(),
        "point {point} did not halt"
    );
    fs.crash(seed, mode);
    (fs, out)
}

#[test]
fn tc_sto_002_version_set_recovers_a_prefix_at_every_crash_point() {
    let total = total_ops(true);
    assert!(total >= MIN_CRASH_POINTS, "workload too small: {total} ops");
    for point in 0..total {
        for mode in CrashMode::ALL {
            for seed in 0..SEEDS {
                let (fs, out) = crash_at(point, seed, mode, true);
                let ctx = format!("crash point {point}, {mode:?}, seed {seed}");
                check_recovery(&fs, &out, &ctx);
            }
        }
    }
}

#[test]
fn tc_sto_002_workload_completes_and_reopens_without_crash() {
    let fs = Arc::new(SimFileSystem::new());
    let mut out = Outcome::default();
    run(&fs, true, &mut out).unwrap();
    // Only acknowledged state is guaranteed; crash dropping nothing synced must keep it all.
    fs.crash(0, CrashMode::Clean);
    check_recovery(&fs, &out, "no crash point");
}

/// Why the flush protocol fsyncs the directory after writing an SST: without it a crash can
/// keep the MANIFEST edit but lose the SST's name, and the store refuses to open (§13). Every
/// crash mode must expose it, including the torn and journaled ones.
#[test]
fn tc_sto_002_missing_sst_dir_fsync_is_detected() {
    let total = total_ops(false);
    for mode in CrashMode::ALL {
        let corrupt = (0..total).any(|point| {
            (0..SEEDS).any(|seed| {
                let (fs, out) = crash_at(point, seed, mode, false);
                out.created
                    && matches!(
                        VersionSet::open(fs, Path::new(DIR)),
                        Err(e) if e.is_corruption()
                    )
            })
        });
        assert!(
            corrupt,
            "{mode:?}: simulator failed to expose the missing directory fsync"
        );
    }
}
