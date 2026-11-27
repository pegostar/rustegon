// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared test support: a single-range store (engine + `LocalReplica`) on the simulated file
//! system, controllable clocks, a deterministic RNG and value helpers.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use rustegon_cluster::{LocalReplica, LocalReplicaConfig};
use rustegon_mvcc::{Hlc, Replica};
use rustegon_raft::LogStoreOptions;
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{BoxFuture, Clock, Rng, SystemClock};
use rustegon_storage::{EngineOptions, LsmEngine};
use rustegon_txn::{TxnConfig, TxnCoordinator};

/// Engine directory.
pub const LSM_DIR: &str = "/store/lsm";
/// Log store directory.
pub const LOG_DIR: &str = "/store/raft-log";
/// The range under test.
pub const RANGE: u64 = 3;
/// Start of manual clocks: 2026-01-01T00:00:00Z in nanoseconds.
pub const T0: u64 = 1_767_225_600_000_000_000;

/// A clock whose time the test sets; monotonic time equals wall time since the epoch.
#[derive(Debug)]
pub struct ManualClock {
    ns: AtomicU64,
}

impl ManualClock {
    pub fn new(ns: u64) -> Arc<Self> {
        Arc::new(Self {
            ns: AtomicU64::new(ns),
        })
    }

    pub fn advance(&self, d: Duration) {
        self.ns
            .fetch_add(u64::try_from(d.as_nanos()).unwrap(), Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn monotonic(&self) -> Duration {
        Duration::from_nanos(self.ns.load(Ordering::SeqCst))
    }

    fn wall(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.ns.load(Ordering::SeqCst))
    }

    fn sleep(&self, _duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(std::future::ready(()))
    }
}

/// Deterministic `SplitMix64` generator, usable as the coordinator's `Rng`.
#[derive(Debug)]
pub struct TestRng(Mutex<u64>);

impl TestRng {
    pub fn new(seed: u64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(seed)))
    }

    pub fn next(&self) -> u64 {
        let mut s = self.0.lock().unwrap();
        *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&self, n: u64) -> u64 {
        self.next() % n
    }
}

impl Rng for TestRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Engine options: small memtables, so that flushes and compactions run during the tests.
pub fn engine_options() -> EngineOptions {
    EngineOptions {
        memtable_size: 256 << 10,
        ..EngineOptions::default()
    }
}

/// Opens (or recovers) the store on `fs`.
pub fn open_replica(
    fs: &Arc<SimFileSystem>,
) -> Result<Arc<LocalReplica>, Box<dyn std::error::Error>> {
    let engine = Arc::new(LsmEngine::open(
        fs.clone(),
        Path::new(LSM_DIR),
        engine_options(),
    )?);
    let replica = LocalReplica::open(LocalReplicaConfig {
        fs: fs.clone(),
        log_dir: PathBuf::from(LOG_DIR),
        log_options: LogStoreOptions::default(),
        engine,
        gc: None,
        range_id: RANGE,
    })?;
    Ok(Arc::new(replica))
}

/// A coordinator over `replica` driven by `clock`.
pub fn coordinator(
    replica: Arc<dyn Replica>,
    clock: Arc<dyn Clock>,
    config: TxnConfig,
    seed: u64,
) -> TxnCoordinator {
    let hlc = Arc::new(Hlc::new(Arc::clone(&clock)));
    TxnCoordinator::new(replica, hlc, clock, TestRng::new(seed), config)
}

/// A fresh store with a manual clock.
pub fn manual(config: TxnConfig) -> (TxnCoordinator, Arc<ManualClock>) {
    let fs = Arc::new(SimFileSystem::new());
    let clock = ManualClock::new(T0);
    let replica = open_replica(&fs).unwrap();
    (coordinator(replica, clock.clone(), config, 1), clock)
}

/// A fresh store with the system clock (multi-threaded tests: waits and real time), with a
/// background maintenance thread (see [`maintain`]).
pub fn system(config: TxnConfig) -> TxnCoordinator {
    let fs = Arc::new(SimFileSystem::new());
    let replica = open_replica(&fs).unwrap();
    maintain(&replica);
    coordinator(replica, Arc::new(SystemClock::new()), config, 7)
}

/// Interval of the background maintenance.
const MAINTENANCE_INTERVAL: Duration = Duration::from_millis(20);

/// Does what the server's background jobs do (storage-engine.md §3): flush memtables, compact
/// and purge the log, every [`MAINTENANCE_INTERVAL`] until the replica is dropped. Without it,
/// every intent write and resolution of a hot key stays in the memtable as a shadowed entry
/// that each later seek of that key steps over, and long concurrent workloads slow down
/// quadratically.
pub fn maintain(replica: &Arc<LocalReplica>) {
    let weak = Arc::downgrade(replica);
    std::thread::spawn(move || {
        // A channel nobody sends on: `recv_timeout` is the pause (no `thread::sleep`, ADR-029).
        let (_tx, rx) = std::sync::mpsc::channel::<()>();
        loop {
            let _ = rx.recv_timeout(MAINTENANCE_INTERVAL);
            let Some(replica) = weak.upgrade() else {
                return;
            };
            replica.engine().flush().unwrap();
            replica.engine().compact().unwrap();
            replica.purge_flushed().unwrap();
        }
    });
}

/// User key number `n` (outside the range-local `0x01` namespace).
pub fn key(n: u8) -> Vec<u8> {
    vec![0x03, b'k', n, b'.']
}

/// Encodes an integer value.
pub fn int(v: i64) -> Bytes {
    Bytes::copy_from_slice(&v.to_be_bytes())
}

/// Decodes an integer value (absent = 0).
pub fn as_int(v: Option<&Bytes>) -> i64 {
    v.map_or(0, |b| i64::from_be_bytes(b[..8].try_into().unwrap()))
}
