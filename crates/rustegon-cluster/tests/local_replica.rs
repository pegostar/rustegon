// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Behaviour of the single-voter local replica (FR-TXN-001, TC-TXN-004; replication.md §2,
//! "Command format v1"): atomic apply with `RangeAppliedState`, MVCC reads at a timestamp,
//! replay after restart, purge only behind the engine's flush, and refusal of commands or logs
//! that cannot be applied.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{path::Path, sync::Arc};

use bytes::Bytes;
use common::{Op, RANGE, command, key, observe, open, open_in};
use rustegon_cluster::LocalReplica;
use rustegon_mvcc::{
    MvccError, RangeAppliedState, ReadOptions, Replica, ReplicaCommand, ReplicaError, Timestamp,
    VersionValue, replica::read_applied_state,
};
use rustegon_raft::LogStoreOptions;
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_storage::WriteBatch;

#[test]
fn local_replica_applies_command_and_applied_state_in_one_batch() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    assert_eq!(
        store.replica.applied_state(),
        RangeAppliedState::initial(RANGE)
    );
    let before = store.engine.last_seqno();
    let ops = [Op::Put(1, b"a".to_vec()), Op::Put(2, b"b".to_vec())];
    let state = store.replica.propose(command(&ops, 42)).unwrap();
    assert_eq!(
        (state.applied_index, state.applied_term, state.max_ts),
        (1, rustegon_cluster::LOCAL_TERM, Timestamp::new(42, 0))
    );
    // Two data ops plus the applied state: one engine batch of three seqnos.
    assert_eq!(store.engine.last_seqno(), before + 3);
    assert_eq!(read_applied_state(&store.engine, RANGE).unwrap(), state);
    assert_eq!(
        store.engine.get(&key(2), None).unwrap().as_deref(),
        Some(&b"b"[..])
    );
    assert_eq!(store.replica.applied_index(), 1);
    assert_eq!(store.replica.log_bounds(), (1, 1));
}

#[test]
fn local_replica_serves_mvcc_writes_at_their_timestamp() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    let doc = b"\x03doc";
    let ts = Timestamp::new(100, 0);
    let mut writer = store.replica.writer();
    writer
        .put_version(doc, ts, &VersionValue::Value(Bytes::from_static(b"v1")))
        .unwrap();
    store
        .replica
        .propose(ReplicaCommand::new(ts, writer.into_batch()))
        .unwrap();
    let at = |t| store.replica.get(doc, &ReadOptions::at(t)).unwrap();
    assert_eq!(at(ts).as_deref(), Some(&b"v1"[..]));
    assert_eq!(at(Timestamp::new(99, 0)), None);
    // Survives a restart through replay (the engine was never flushed).
    drop(store);
    fs.crash(0, CrashMode::Clean);
    let store = open(&fs).unwrap();
    assert_eq!(
        store
            .replica
            .get(doc, &ReadOptions::at(ts))
            .unwrap()
            .as_deref(),
        Some(&b"v1"[..])
    );
    assert_eq!(store.replica.applied_state().max_ts, ts);
}

#[test]
fn local_replica_replays_unflushed_entries_after_crash() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    let mut model = common::Model::default();
    for i in 0..5u8 {
        let ops = [Op::Put(i, vec![i])];
        model = model.after(&ops);
        store.replica.propose(command(&ops, u64::from(i))).unwrap();
        if i == 2 {
            store.engine.flush().unwrap();
        }
    }
    drop(store);
    fs.crash(1, CrashMode::TornPrefix);
    let store = open(&fs).unwrap();
    assert_eq!(observe(&store).unwrap(), model);
    // Proposals continue at the next index.
    let state = store.replica.propose(command(&[Op::Delete(0)], 9)).unwrap();
    assert_eq!(state.applied_index, 6);
}

#[test]
fn local_replica_purges_only_entries_whose_apply_is_flushed() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    for i in 0..3u8 {
        store
            .replica
            .propose(command(&[Op::Put(i, vec![i])], 1))
            .unwrap();
    }
    // Nothing flushed: nothing purged.
    assert_eq!(store.replica.purge_flushed().unwrap(), 1);
    store.engine.flush().unwrap();
    assert_eq!(store.replica.purge_flushed().unwrap(), 4);
    assert_eq!(store.replica.log_bounds(), (4, 3));
    // Entry 4 applies after the flush; a purge piggybacked on proposal 5 must keep it.
    store
        .replica
        .propose(command(&[Op::Put(9, vec![9])], 2))
        .unwrap();
    store
        .replica
        .propose(command(&[Op::Put(10, vec![10])], 3))
        .unwrap();
    assert_eq!(store.replica.log_bounds(), (4, 5));
    store.engine.flush().unwrap();
    // The purge rides along with the next proposal (no separate log write).
    store.replica.propose(command(&[Op::Delete(9)], 4)).unwrap();
    assert_eq!(store.replica.log_bounds(), (6, 6));
    drop(store);
    fs.crash(0, CrashMode::Clean);
    let store = open(&fs).unwrap();
    assert_eq!(store.engine.get(&key(9), None).unwrap(), None);
    assert_eq!(store.replica.applied_index(), 6);
}

#[test]
fn local_replica_refuses_unappliable_command_without_logging_it() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    let mut batch = WriteBatch::new();
    batch
        .put(&key(1), b"x".to_vec())
        .delete_range(&key(5), &key(2));
    let err = store
        .replica
        .propose(ReplicaCommand::new(Timestamp::MIN, batch))
        .unwrap_err();
    assert!(matches!(
        err,
        ReplicaError::Mvcc(MvccError::InvalidArgument(_))
    ));
    assert_eq!(store.replica.log_bounds(), (1, 0));
    assert_eq!(store.replica.applied_index(), 0);
    assert_eq!(store.engine.get(&key(1), None).unwrap(), None);
    // The replica stays usable.
    assert_eq!(
        store
            .replica
            .propose(command(&[Op::Put(1, b"y".to_vec())], 1))
            .unwrap()
            .applied_index,
        1
    );
}

#[test]
fn local_replica_open_rejects_engine_missing_purged_entries() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    for i in 0..3u8 {
        store
            .replica
            .propose(command(&[Op::Put(i, vec![i])], 1))
            .unwrap();
    }
    store.engine.flush().unwrap();
    store.replica.purge_flushed().unwrap();
    drop(store);
    // A different (empty) engine with the purged log: entries 1..=3 are gone from both.
    let err = open_in(&fs, "/store/other-lsm").err().unwrap();
    assert!(err.to_string().contains("log starts at 4"), "{err}");
}

#[test]
fn local_replica_open_rejects_engine_ahead_of_log() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    store
        .replica
        .propose(command(&[Op::Put(1, vec![1])], 1))
        .unwrap();
    store.engine.flush().unwrap();
    drop(store);
    // Losing the log directory while the engine kept the applied data.
    for path in fs_files(&fs, common::LOG_DIR) {
        rustegon_sim_api::FileSystem::remove_file(fs.as_ref(), &path).unwrap();
    }
    let err = open(&fs).err().unwrap();
    assert!(err.to_string().contains("but the log ends at 0"), "{err}");
}

/// FR-BKP-002, PD-066: a physically restored store has its engine (SSTs) but not the old log;
/// a log bootstrapped at the engine's applied state lets it open, and proposals continue.
#[test]
fn tc_bkp_004_bootstrap_log_reopens_and_covers() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    let mut model = common::Model::default();
    for i in 0..5u8 {
        let ops = [Op::Put(i, vec![i])];
        model = model.after(&ops);
        store
            .replica
            .propose(command(&ops, u64::from(i) + 1))
            .unwrap();
    }
    // The backup hooks pass through: the active segment holds batches, so it is sealed.
    let active = store.replica.sealed_log_segments().len();
    assert!(store.replica.force_roll_log().unwrap().is_some());
    assert_eq!(store.replica.sealed_log_segments().len(), active + 1);
    assert_eq!(store.replica.force_roll_log().unwrap(), None);
    assert!(store.replica.log_segment_key(1).is_none(), "plaintext log");
    // The restored engine: every applied command flushed to SSTs.
    store.engine.flush().unwrap();
    let applied = store.replica.applied_state();
    drop(store);
    fs.crash(0, CrashMode::Clean);

    // The restore brings no log: the replica refuses to open.
    for path in fs_files(&fs, common::LOG_DIR) {
        rustegon_sim_api::FileSystem::remove_file(fs.as_ref(), &path).unwrap();
    }
    let err = open(&fs).err().unwrap();
    assert!(err.to_string().contains("but the log ends at 0"), "{err}");
    // `open` above created an empty segment; a bootstrap refuses any existing log.
    let bootstrap = || {
        LocalReplica::bootstrap_log(
            fs.clone(),
            Path::new(common::LOG_DIR),
            LogStoreOptions::default(),
            RANGE,
            applied.applied_index,
            applied.applied_term,
        )
    };
    let err = bootstrap().unwrap_err();
    assert!(
        err.to_string().contains("already holds raft log segments"),
        "{err}"
    );
    for path in fs_files(&fs, common::LOG_DIR) {
        rustegon_sim_api::FileSystem::remove_file(fs.as_ref(), &path).unwrap();
    }
    // A term the single voter cannot continue is refused.
    let err = LocalReplica::bootstrap_log(
        fs.clone(),
        Path::new(common::LOG_DIR),
        LogStoreOptions::default(),
        RANGE,
        applied.applied_index,
        applied.applied_term + 1,
    )
    .unwrap_err();
    assert!(err.to_string().contains("single voter"), "{err}");
    bootstrap().unwrap();

    let store = open(&fs).unwrap();
    assert_eq!(observe(&store).unwrap(), model);
    assert_eq!(store.replica.applied_state(), applied);
    assert_eq!(store.replica.log_bounds(), (6, 5));
    let state = store.replica.propose(command(&[Op::Delete(0)], 9)).unwrap();
    assert_eq!(state.applied_index, 6);
    model = model.after(&[Op::Delete(0)]);
    // And it survives a crash like any other log (replay of entry 6 from the new log).
    drop(store);
    fs.crash(1, CrashMode::TornPrefix);
    let store = open(&fs).unwrap();
    assert_eq!(observe(&store).unwrap(), model);
}

fn fs_files(fs: &Arc<SimFileSystem>, dir: &str) -> Vec<std::path::PathBuf> {
    rustegon_sim_api::FileSystem::read_dir(fs.as_ref(), std::path::Path::new(dir)).unwrap()
}
