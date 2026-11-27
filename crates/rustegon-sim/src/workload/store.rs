// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The system under test of the transaction workloads: one range served by the Raft-less
//! [`LocalReplica`] (LSM engine + local log) on a [`SimFileSystem`], and the single-range
//! [`TxnCoordinator`] over it (M2).

use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustegon_cluster::{LocalReplica, LocalReplicaConfig};
use rustegon_mvcc::{Hlc, Replica, mvcc_filter_options};
use rustegon_raft::LogStoreOptions;
use rustegon_sim_api::Clock;
use rustegon_storage::{EngineOptions, LsmEngine};
use rustegon_txn::{TxnConfig, TxnCoordinator};

use super::{clock::SimClock, rng::SimRng};
use crate::SimFileSystem;

/// Engine directory.
const LSM_DIR: &str = "/store/lsm";
/// Log store directory.
const LOG_DIR: &str = "/store/raft-log";
/// The range under test.
const RANGE: u64 = 3;

/// An open store: the replica and the coordinator serving it.
pub(super) struct Store {
    pub replica: Arc<LocalReplica>,
    pub co: TxnCoordinator,
}

impl Store {
    /// Opens (or recovers) the store on `fs`, with a fresh coordinator: its registry, timestamp
    /// cache and HLC start empty, as after a process restart.
    pub fn open(
        fs: &Arc<SimFileSystem>,
        clock: &Arc<SimClock>,
        config: TxnConfig,
        rng_seed: u64,
    ) -> Result<Self, Box<dyn Error>> {
        let engine = Arc::new(LsmEngine::open(
            fs.clone(),
            Path::new(LSM_DIR),
            // Filters on logical keys, as in `EmbeddedDb`: point reads go through them.
            mvcc_filter_options(EngineOptions {
                // Small memtables: flushes (and SST reads after recovery) happen in short runs.
                memtable_size: 256 << 10,
                ..EngineOptions::default()
            }),
        )?);
        let replica = Arc::new(LocalReplica::open(LocalReplicaConfig {
            fs: fs.clone(),
            log_dir: PathBuf::from(LOG_DIR),
            log_options: LogStoreOptions::default(),
            engine,
            gc: None,
            range_id: RANGE,
        })?);
        let clock: Arc<dyn Clock> = clock.clone();
        let hlc = Arc::new(Hlc::new(Arc::clone(&clock)));
        let as_replica: Arc<dyn Replica> = replica.clone();
        let co = TxnCoordinator::new(
            as_replica,
            hlc,
            clock,
            Arc::new(SimRng::new(rng_seed)),
            config,
        );
        Ok(Self { replica, co })
    }

    /// What the server's background jobs do (storage-engine.md §3): flush the memtable, compact,
    /// purge the flushed log prefix. Run by the driver at deterministic steps instead of on a
    /// background thread, so that file-system operation counts (crash points) are reproducible.
    pub fn maintain(&self) -> Result<(), Box<dyn Error>> {
        self.replica.engine().flush()?;
        self.replica.engine().compact()?;
        self.replica.purge_flushed()?;
        Ok(())
    }
}

/// The user key of register `n` (outside the range-local `0x01` namespace).
pub(super) fn register_key(n: u64) -> Vec<u8> {
    let mut k = vec![0x03, b'r'];
    k.extend_from_slice(&n.to_be_bytes());
    k
}
