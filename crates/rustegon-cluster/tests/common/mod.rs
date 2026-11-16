// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared test support for the local replica: store layout on the simulated file system, a
//! reference model of the range's data, reproducible workloads and a full-state comparison.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::BTreeMap, error::Error, path::PathBuf, sync::Arc};

use rustegon_cluster::{LocalReplica, LocalReplicaConfig};
use rustegon_mvcc::{
    RangeAppliedState, Replica, ReplicaCommand, Timestamp, replica::read_applied_state,
};
use rustegon_raft::LogStoreOptions;
use rustegon_sim::SimFileSystem;
use rustegon_storage::{
    EngineOptions, LsmEngine, WriteBatch, compaction::CompactionOptions, sst::SstWriterOptions,
};

/// Engine directory.
pub const LSM_DIR: &str = "/store/lsm";
/// Log store directory.
pub const LOG_DIR: &str = "/store/raft-log";
/// The range under test.
pub const RANGE: u64 = 7;
/// Log segment size: rollovers every few proposals.
pub const SEGMENT_SIZE: u64 = 512;
/// Number of distinct user keys in workloads.
pub const KEYS: u8 = 12;

/// Engine options with tiny memtables and levels, so rotations, flushes and compactions happen.
pub fn engine_options() -> EngineOptions {
    EngineOptions {
        memtable_size: 1 << 10,
        compaction: CompactionOptions {
            l0_trigger: 2,
            level_base_bytes: 4 << 10,
            level_multiplier: 4,
            target_file_size_base: 2 << 10,
            max_target_file_size: 4 << 10,
            writer: SstWriterOptions {
                block_size: 256,
                ..SstWriterOptions::default()
            },
            ..CompactionOptions::default()
        },
        ..EngineOptions::default()
    }
}

/// A store: the engine and the replica on top of it.
pub struct Store {
    pub engine: Arc<LsmEngine>,
    pub replica: LocalReplica,
}

/// Opens the engine in `lsm_dir` and the replica over it (replaying the log).
pub fn open_in(fs: &Arc<SimFileSystem>, lsm_dir: &str) -> Result<Store, Box<dyn Error>> {
    let engine = Arc::new(LsmEngine::open(
        fs.clone(),
        std::path::Path::new(lsm_dir),
        engine_options(),
    )?);
    let replica = LocalReplica::open(LocalReplicaConfig {
        fs: fs.clone(),
        log_dir: PathBuf::from(LOG_DIR),
        log_options: LogStoreOptions {
            segment_size: SEGMENT_SIZE,
            encryption: None,
            archive_floor: None,
        },
        engine: Arc::clone(&engine),
        gc: None,
        range_id: RANGE,
    })?;
    Ok(Store { engine, replica })
}

/// Opens the store in the default directories.
pub fn open(fs: &Arc<SimFileSystem>) -> Result<Store, Box<dyn Error>> {
    open_in(fs, LSM_DIR)
}

/// User key number `n` (outside the range-local `0x01` namespace).
pub fn key(n: u8) -> Vec<u8> {
    vec![0x03, b'k', n]
}

/// One storage operation of a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Put(u8, Vec<u8>),
    Delete(u8),
    /// Keys `[from, to)`, `from < to`.
    DeleteRange(u8, u8),
}

/// The command applying `ops`.
pub fn command(ops: &[Op], ts: u64) -> ReplicaCommand {
    let mut batch = WriteBatch::new();
    for op in ops {
        match op {
            Op::Put(k, v) => {
                batch.put(&key(*k), v.clone());
            }
            Op::Delete(k) => {
                batch.delete(&key(*k));
            }
            Op::DeleteRange(a, b) => {
                batch.delete_range(&key(*a), &key(*b));
            }
        }
    }
    ReplicaCommand::new(Timestamp::new(ts, 0), batch)
}

/// Reference state: the user data and the applied index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Model {
    pub data: BTreeMap<Vec<u8>, Vec<u8>>,
    pub applied: u64,
}

impl Model {
    /// The state after applying one more command of `ops`.
    pub fn after(&self, ops: &[Op]) -> Self {
        let mut next = self.clone();
        for op in ops {
            match op {
                Op::Put(k, v) => {
                    next.data.insert(key(*k), v.clone());
                }
                Op::Delete(k) => {
                    next.data.remove(&key(*k));
                }
                Op::DeleteRange(a, b) => {
                    next.data.retain(|k, _| !(key(*a) <= *k && *k < key(*b)));
                }
            }
        }
        next.applied += 1;
        next
    }
}

/// The store's observable state as a model: user keys of the engine and the applied index.
/// Also checks the applied-state invariants: the persisted `RangeAppliedState` equals the
/// replica's, names the last entry of the log, and the log still holds every entry after it.
pub fn observe(store: &Store) -> Result<Model, String> {
    let mut data = BTreeMap::new();
    let mut it = store.engine.iterator(None).map_err(|e| e.to_string())?;
    it.seek(&[0x03]).map_err(|e| e.to_string())?;
    while it.valid() {
        data.insert(it.key().to_vec(), it.value().to_vec());
        it.next().map_err(|e| e.to_string())?;
    }
    let persisted: RangeAppliedState =
        read_applied_state(&store.engine, RANGE).map_err(|e| e.to_string())?;
    let state = store.replica.applied_state();
    if persisted != state {
        return Err(format!("persisted {persisted:?} != in-memory {state:?}"));
    }
    let (first, last) = store.replica.log_bounds();
    if last != state.applied_index || first > state.applied_index + 1 {
        return Err(format!("log [{first}, {last}] vs applied {state:?}"));
    }
    if state.applied_index > 0 && state.applied_term != rustegon_cluster::LOCAL_TERM {
        return Err(format!("applied term {}", state.applied_term));
    }
    Ok(Model {
        data,
        applied: state.applied_index,
    })
}

/// One workload step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Propose(Vec<Op>),
    Flush,
    Compact,
    Purge,
    /// Drop and reopen without a crash (memtables are lost: replay needed).
    Restart,
}

/// Deterministic generator (`SplitMix64`).
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Random operations of one command (1..=4 ops, so a half-applied command is observable).
pub fn random_ops(rng: &mut Rng, step: usize) -> Vec<Op> {
    let n = 1 + rng.below(4);
    (0..n)
        .map(|i| {
            let k = u8::try_from(rng.below(u64::from(KEYS))).unwrap();
            match rng.below(10) {
                0..=6 => Op::Put(k, format!("v{step}.{i}").into_bytes()),
                7 | 8 => Op::Delete(k),
                _ => {
                    let len = u8::try_from(1 + rng.below(3)).unwrap();
                    Op::DeleteRange(k, k + len)
                }
            }
        })
        .collect()
}

/// A reproducible workload of `len` steps.
pub fn workload(seed: u64, len: usize) -> Vec<Step> {
    let mut rng = Rng(seed);
    (0..len)
        .map(|i| match rng.below(100) {
            0..=69 => Step::Propose(random_ops(&mut rng, i)),
            70..=79 => Step::Flush,
            80..=84 => Step::Compact,
            85..=91 => Step::Purge,
            _ => Step::Restart,
        })
        .collect()
}
