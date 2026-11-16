// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared helpers of the integration tests: an engine on the simulated file system with tiny
//! memtables and levels (so a few hundred writes span memtables, L0 and deeper levels) and the
//! MVCC options installed; a manual clock.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustegon_mvcc::{GcThreshold, mvcc_engine_options};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{BoxFuture, Clock};
use rustegon_storage::{
    EngineOptions, LsmEngine, compaction::CompactionOptions, sst::SstWriterOptions,
};

pub const DIR: &str = "/store";

/// Engine options with small sizes; `parallel` runs subcompactions on threads.
pub fn options(threshold: Arc<GcThreshold>, parallel: bool) -> EngineOptions {
    mvcc_engine_options(
        EngineOptions {
            memtable_size: 2 << 10,
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
                max_subcompactions: 4,
                parallel_subcompactions: parallel,
                ..CompactionOptions::default()
            },
            ..EngineOptions::default()
        },
        threshold,
    )
}

/// A fresh engine and its GC threshold (starting at zero).
pub fn engine(parallel: bool) -> (LsmEngine, Arc<GcThreshold>) {
    let fs = Arc::new(SimFileSystem::new());
    let threshold = Arc::new(GcThreshold::default());
    let engine = LsmEngine::open(fs, Path::new(DIR), options(threshold.clone(), parallel)).unwrap();
    (engine, threshold)
}

/// A clock whose wall time the test sets (nanoseconds since the epoch).
#[derive(Debug, Default)]
pub struct ManualClock {
    wall_ns: AtomicU64,
}

impl ManualClock {
    pub fn new(wall_ns: u64) -> Arc<Self> {
        Arc::new(Self {
            wall_ns: AtomicU64::new(wall_ns),
        })
    }

    pub fn set(&self, wall_ns: u64) {
        self.wall_ns.store(wall_ns, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn monotonic(&self) -> Duration {
        Duration::from_nanos(self.wall_ns.load(Ordering::SeqCst))
    }

    fn wall(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.wall_ns.load(Ordering::SeqCst))
    }

    fn sleep(&self, _duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(std::future::ready(()))
    }
}
