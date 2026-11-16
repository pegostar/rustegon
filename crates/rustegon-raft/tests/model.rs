// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Model-based tests of the Raft log store (replication.md §2, NFR-REL-003): random batches of
//! appends, overwrites, truncations, purges, snapshot installs, group removals and hard states
//! over several interleaved groups, with reopens in between, against an in-memory model.
//! Small segments force rollovers and segment deletion.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{path::Path, sync::Arc};

use common::{GROUPS, Model, assert_matches, batch, gen_op, open};
use proptest::prelude::*;
use rustegon_raft::{HardState, LogBatch, LogStore, LogStoreError, LogStoreOptions};
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_sim_api::FileSystem as _;

/// Raw step: `None` = reopen, else up to 4 raw ops `(kind, group, a, b)`.
type RawStep = Option<Vec<(u8, u64, u64, u64)>>;

fn raw_steps() -> impl Strategy<Value = Vec<RawStep>> {
    let op = (0u8..10, 0..GROUPS, any::<u64>(), any::<u64>());
    let step = prop_oneof![
        1 => Just(None),
        12 => prop::collection::vec(op, 1..5).prop_map(Some),
    ];
    prop::collection::vec(step, 1..60)
}

fn check(steps: &[RawStep], segment_size: u64) -> Result<(), TestCaseError> {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open(&fs, segment_size).unwrap();
    let mut model = Model::default();
    for (n, step) in steps.iter().enumerate() {
        let ctx = format!("step {n}");
        let Some(raw) = step else {
            drop(store);
            // A crash that drops nothing unsynced must keep every acknowledged batch.
            fs.crash(n as u64, CrashMode::Clean);
            store = open(&fs, segment_size).unwrap();
            prop_assert!(
                !store.recovery_info().torn_tail,
                "{}: clean reopen torn",
                ctx
            );
            assert_matches(&store, &model, &ctx);
            continue;
        };
        let mut ops = Vec::new();
        let mut m = model.clone();
        for &(kind, g, a, b) in raw {
            let op = gen_op(&m, kind, g, a, b);
            if let Some(next) = m.after(std::slice::from_ref(&op)) {
                m = next;
            }
            ops.push(op);
        }
        match (model.after(&ops), store.write(&batch(&ops))) {
            (Some(next), Ok(())) => model = next,
            (None, Err(LogStoreError::InvalidArgument(_))) => {}
            (want, got) => {
                return Err(TestCaseError::fail(format!(
                    "{ctx}: ops {ops:?}: model accepts {}, store returned {got:?}",
                    want.is_some()
                )));
            }
        }
        assert_matches(&store, &model, &ctx);
    }
    // Live entries pin at most the segments they are in; all others are gone.
    let ids = store.segment_ids();
    prop_assert!(ids.windows(2).all(|w| w[1] == w[0] + 1));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn tc_txn_004_logstore_matches_model(steps in raw_steps(), small in any::<bool>()) {
        // 160 bytes: a rollover every few batches; 1 MiB: a single segment.
        check(&steps, if small { 160 } else { 1 << 20 })?;
    }
}

#[test]
fn append_read_and_reopen_round_trip() {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open(&fs, 1 << 20).unwrap();
    let mut b = LogBatch::new();
    for i in 1..=10u64 {
        b.append(7, i, 1, vec![u8::try_from(i).unwrap(); 10]);
        b.append(9, i, 2, format!("entry {i}").into_bytes());
    }
    let hs = HardState {
        term: 2,
        vote: 1,
        commit: 8,
    };
    b.set_hard_state(9, hs);
    store.write(&b).unwrap();
    assert_eq!(store.last_index(7), 10);
    assert_eq!(store.entries(9, 3, 5).unwrap()[1].payload, b"entry 4");
    drop(store);
    let store = open(&fs, 1 << 20).unwrap();
    assert_eq!(store.recovery_info().groups, 2);
    assert_eq!(store.hard_state(9), hs);
    assert_eq!(store.entries(7, 1, 11).unwrap().len(), 10);
    assert_eq!(store.term(9, 10).unwrap(), 2);
    assert!(matches!(
        store.term(9, 11),
        Err(LogStoreError::OutOfRange { last_index: 10, .. })
    ));
}

#[test]
fn invalid_operations_are_rejected_without_effect() {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open(&fs, 1 << 20).unwrap();
    let mut b = LogBatch::new();
    b.append(1, 1, 3, "a").append(1, 2, 3, "b");
    store.write(&b).unwrap();
    let cases: [&dyn Fn(&mut LogBatch); 5] = [
        &|b| {
            b.append(1, 4, 3, "gap");
        },
        &|b| {
            b.append(1, 3, 2, "term regresses");
        },
        &|b| {
            b.purge(1, 3);
        },
        &|b| {
            b.purge(1, 1).truncate_suffix(1, 1);
        },
        // A valid op followed by an invalid one: the whole batch is rejected.
        &|b| {
            b.append(1, 3, 3, "ok").append(2, 5, 1, "gap");
        },
    ];
    for (i, case) in cases.iter().enumerate() {
        let mut b = LogBatch::new();
        case(&mut b);
        let err = store.write(&b).unwrap_err();
        assert!(
            matches!(err, LogStoreError::InvalidArgument(_)),
            "case {i}: {err}"
        );
        assert_eq!(
            (store.first_index(1), store.last_index(1)),
            (1, 2),
            "case {i}"
        );
        assert_eq!(store.last_index(2), 0, "case {i}");
    }
    assert!(store.entries(1, 2, 1).is_err());
}

#[test]
fn obsolete_segments_are_deleted_oldest_first() {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open(&fs, 256).unwrap();
    for i in 1..=40u64 {
        let mut b = LogBatch::new();
        b.append(1, i, 1, vec![0xAA; 64]).append(2, i, 1, "x");
        store.write(&b).unwrap();
    }
    let before = store.segment_ids();
    assert!(before.len() > 10, "{before:?}");
    // Group 2 still pins every segment.
    let mut b = LogBatch::new();
    b.purge(1, 40);
    store.write(&b).unwrap();
    assert_eq!(store.segment_ids()[0], before[0]);
    let mut b = LogBatch::new();
    b.purge(2, 30);
    store.write(&b).unwrap();
    let after = store.segment_ids();
    assert!(
        after.len() < before.len() && after[0] > before[0],
        "{after:?}"
    );
    let on_disk = fs.read_dir(Path::new(common::DIR)).unwrap().len();
    assert_eq!(on_disk, after.len());
    // Removing the last group frees everything but the active segment.
    let mut b = LogBatch::new();
    b.remove_group(2);
    store.write(&b).unwrap();
    assert_eq!(store.segment_ids().len(), 1);
    drop(store);
    let store = open(&fs, 256).unwrap();
    assert_eq!(store.first_index(1), 41);
    assert_eq!(store.last_index(1), 40);
    assert_eq!(store.term(1, 40).unwrap(), 1);
    assert_eq!(store.last_index(2), 0);
}

#[test]
fn failed_sync_poisons_the_store_until_reopen() {
    let sim = Arc::new(SimFileSystem::new());
    let mut store = open(&sim, 1 << 20).unwrap();
    let mut b = LogBatch::new();
    b.append(1, 1, 1, "kept");
    store.write(&b).unwrap();
    sim.fail_next_syncs(1);
    let mut b = LogBatch::new();
    b.append(1, 2, 1, "unknown");
    assert!(matches!(store.write(&b), Err(LogStoreError::Io(_))));
    // Reads serve the acknowledged state only; writes are refused.
    assert_eq!(store.last_index(1), 1);
    assert!(matches!(store.write(&b), Err(LogStoreError::Poisoned)));
    drop(store);
    // The unsynced record may or may not survive a crash; either outcome is consistent.
    sim.crash(3, CrashMode::TornPrefix);
    let store = open(&sim, 1 << 20).unwrap();
    assert!(store.last_index(1) == 1 || store.last_index(1) == 2);
    assert_eq!(store.entries(1, 1, 2).unwrap()[0].payload, b"kept");
}

#[test]
fn snapshot_install_resets_the_log() {
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open(&fs, 1 << 20).unwrap();
    let mut b = LogBatch::new();
    b.append(3, 1, 1, "a")
        .set_hard_state(
            3,
            HardState {
                term: 1,
                vote: 3,
                commit: 1,
            },
        )
        .install_snapshot(3, 100, 4)
        .append(3, 101, 4, "after");
    store.write(&b).unwrap();
    drop(store);
    let store = LogStore::open(
        fs.clone(),
        Path::new(common::DIR),
        LogStoreOptions::default(),
    )
    .unwrap();
    assert_eq!((store.first_index(3), store.last_index(3)), (101, 101));
    assert_eq!(store.term(3, 100).unwrap(), 4);
    assert_eq!(store.hard_state(3).vote, 3);
    assert_eq!(store.entries(3, 101, 102).unwrap()[0].payload, b"after");
}
