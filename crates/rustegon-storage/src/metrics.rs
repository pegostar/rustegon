// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Storage metrics: the one module that names them (coding-standards.md §3.6) and the engine's
//! counters (storage-engine.md §1 `metrics()`; system-overview.md §7 mandatory families).
//!
//! The engine only counts; the server (M4) exports [`EngineMetrics::families`] at `/metrics`.
//! Names marked "mandatory" are stable API (system-overview.md §7) and must never change.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{cache::CacheStats, version::NUM_LEVELS};

/// Mandatory: number of L0 files (gauge).
pub const L0_FILES: &str = "rustegon_storage_l0_files";
/// Mandatory: bytes written by compactions (counter).
pub const COMPACTION_BYTES_TOTAL: &str = "rustegon_storage_compaction_bytes_total";
/// Mandatory: block cache hits / lookups since open (gauge, 0..1).
pub const BLOCK_CACHE_HIT_RATIO: &str = "rustegon_storage_block_cache_hit_ratio";
/// Mandatory: bytes of live SSTs (gauge).
pub const DISK_USED_BYTES: &str = "rustegon_storage_disk_used_bytes";
/// Bytes read by compactions (counter).
pub const COMPACTION_READ_BYTES_TOTAL: &str = "rustegon_storage_compaction_read_bytes_total";
/// Completed compactions (counter).
pub const COMPACTIONS_TOTAL: &str = "rustegon_storage_compactions_total";
/// Sub-jobs of completed compactions; above `COMPACTIONS_TOTAL` when L0 compactions were split
/// (counter, NFR-PERF-005).
pub const SUBCOMPACTIONS_TOTAL: &str = "rustegon_storage_subcompactions_total";
/// Completed memtable flushes that wrote a file (counter).
pub const FLUSHES_TOTAL: &str = "rustegon_storage_flushes_total";
/// Bytes written by flushes (counter).
pub const FLUSH_BYTES_TOTAL: &str = "rustegon_storage_flush_bytes_total";
/// Bytes of ingested files (counter).
pub const INGEST_BYTES_TOTAL: &str = "rustegon_storage_ingest_bytes_total";
/// Applied write batches (counter).
pub const WRITE_BATCHES_TOTAL: &str = "rustegon_storage_write_batches_total";
/// Immutable memtables waiting for flush (gauge; write-stall input, §3).
pub const IMMUTABLE_MEMTABLES: &str = "rustegon_storage_immutable_memtables";
/// Live snapshots (gauge).
pub const SNAPSHOTS: &str = "rustegon_storage_snapshots";
/// Gauge: bytes held by the block cache (PD-233: splits the node RSS in the soak).
pub const BLOCK_CACHE_USAGE_BYTES: &str = "rustegon_storage_block_cache_usage_bytes";
/// Gauge: approximate bytes of the active and immutable memtables (PD-233).
pub const MEMTABLE_BYTES: &str = "rustegon_storage_memtable_bytes";
/// Gauge: live SST files over all levels (PD-233).
pub const SST_FILES: &str = "rustegon_storage_sst_files";
/// Gauge: compactions running now (PD-233: dates compaction episodes against latency).
pub const RUNNING_COMPACTIONS: &str = "rustegon_storage_running_compactions";
/// Counter: block cache lookups that found the block (PD-233).
pub const BLOCK_CACHE_HITS_TOTAL: &str = "rustegon_storage_block_cache_hits_total";
/// Counter: block cache lookups that missed and read the file (PD-233).
pub const BLOCK_CACHE_MISSES_TOTAL: &str = "rustegon_storage_block_cache_misses_total";

/// Monotonic counters updated by the engine. `Relaxed`: each is an independent statistic, read
/// only for reporting; no other memory is published through them.
#[derive(Debug, Default)]
pub(crate) struct EngineCounters {
    pub(crate) compactions: AtomicU64,
    pub(crate) subcompactions: AtomicU64,
    pub(crate) compaction_read_bytes: AtomicU64,
    pub(crate) compaction_write_bytes: AtomicU64,
    pub(crate) flushes: AtomicU64,
    pub(crate) flush_bytes: AtomicU64,
    pub(crate) ingest_bytes: AtomicU64,
    pub(crate) write_batches: AtomicU64,
}

impl EngineCounters {
    pub(crate) fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Point-in-time engine statistics (`LsmEngine::metrics`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EngineMetrics {
    /// Files per level.
    pub level_files: [usize; NUM_LEVELS],
    /// Bytes per level.
    pub level_bytes: [u64; NUM_LEVELS],
    /// Completed compactions.
    pub compactions: u64,
    /// Sub-jobs of completed compactions (one per unsplit compaction).
    pub subcompactions: u64,
    /// Bytes read by compactions.
    pub compaction_read_bytes: u64,
    /// Bytes written by compactions.
    pub compaction_write_bytes: u64,
    /// Flushes that wrote a file.
    pub flushes: u64,
    /// Bytes written by flushes.
    pub flush_bytes: u64,
    /// Bytes of ingested files.
    pub ingest_bytes: u64,
    /// Applied write batches.
    pub write_batches: u64,
    /// Immutable memtables waiting for flush.
    pub immutable_memtables: usize,
    /// Live snapshots.
    pub snapshots: usize,
    /// Approximate bytes of the active and immutable memtables.
    pub memtable_bytes: u64,
    /// Compactions running now.
    pub running_compactions: usize,
    /// Block cache statistics, if a cache is configured.
    pub block_cache: Option<CacheStats>,
}

impl EngineMetrics {
    pub(crate) fn from_counters(counters: &EngineCounters) -> Self {
        Self {
            compactions: EngineCounters::get(&counters.compactions),
            subcompactions: EngineCounters::get(&counters.subcompactions),
            compaction_read_bytes: EngineCounters::get(&counters.compaction_read_bytes),
            compaction_write_bytes: EngineCounters::get(&counters.compaction_write_bytes),
            flushes: EngineCounters::get(&counters.flushes),
            flush_bytes: EngineCounters::get(&counters.flush_bytes),
            ingest_bytes: EngineCounters::get(&counters.ingest_bytes),
            write_batches: EngineCounters::get(&counters.write_batches),
            ..Self::default()
        }
    }

    /// Bytes of live SSTs over all levels.
    #[must_use]
    pub fn disk_used_bytes(&self) -> u64 {
        self.level_bytes.iter().sum()
    }

    /// Block cache hit ratio since open (0 without lookups or without a cache).
    #[must_use]
    pub fn block_cache_hit_ratio(&self) -> f64 {
        self.block_cache.as_ref().map_or(0.0, |c| {
            let lookups = c.hits + c.misses;
            if lookups == 0 {
                0.0
            } else {
                // Counts below 2^53 convert exactly; beyond, the ratio is still accurate.
                #[allow(clippy::cast_precision_loss)]
                let ratio = c.hits as f64 / lookups as f64;
                ratio
            }
        })
    }

    /// `(name, value)` pairs for the exporter, mandatory families first.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // gauges/counters far below 2^53 in practice
    pub fn families(&self) -> Vec<(&'static str, f64)> {
        vec![
            (L0_FILES, self.level_files[0] as f64),
            (COMPACTION_BYTES_TOTAL, self.compaction_write_bytes as f64),
            (BLOCK_CACHE_HIT_RATIO, self.block_cache_hit_ratio()),
            (DISK_USED_BYTES, self.disk_used_bytes() as f64),
            (
                COMPACTION_READ_BYTES_TOTAL,
                self.compaction_read_bytes as f64,
            ),
            (COMPACTIONS_TOTAL, self.compactions as f64),
            (SUBCOMPACTIONS_TOTAL, self.subcompactions as f64),
            (FLUSHES_TOTAL, self.flushes as f64),
            (FLUSH_BYTES_TOTAL, self.flush_bytes as f64),
            (INGEST_BYTES_TOTAL, self.ingest_bytes as f64),
            (WRITE_BATCHES_TOTAL, self.write_batches as f64),
            (IMMUTABLE_MEMTABLES, self.immutable_memtables as f64),
            (SNAPSHOTS, self.snapshots as f64),
            (
                BLOCK_CACHE_USAGE_BYTES,
                self.block_cache.as_ref().map_or(0, |c| c.usage) as f64,
            ),
            (MEMTABLE_BYTES, self.memtable_bytes as f64),
            (SST_FILES, self.level_files.iter().sum::<usize>() as f64),
            (RUNNING_COMPACTIONS, self.running_compactions as f64),
            (
                BLOCK_CACHE_HITS_TOTAL,
                self.block_cache.as_ref().map_or(0, |c| c.hits) as f64,
            ),
            (
                BLOCK_CACHE_MISSES_TOTAL,
                self.block_cache.as_ref().map_or(0, |c| c.misses) as f64,
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mandatory_families_come_first_with_stable_names() {
        let m = EngineMetrics {
            level_files: [3, 0, 0, 0, 0, 0, 1],
            level_bytes: [30, 0, 0, 0, 0, 0, 70],
            compaction_write_bytes: 5,
            block_cache: Some(CacheStats {
                hits: 3,
                misses: 1,
                usage: 0,
                rejected_oversize: 0,
            }),
            ..EngineMetrics::default()
        };
        let families = m.families();
        let names: Vec<&str> = families.iter().take(4).map(|f| f.0).collect();
        assert_eq!(
            names,
            [
                "rustegon_storage_l0_files",
                "rustegon_storage_compaction_bytes_total",
                "rustegon_storage_block_cache_hit_ratio",
                "rustegon_storage_disk_used_bytes",
            ]
        );
        assert!((families[0].1 - 3.0).abs() < f64::EPSILON);
        assert!((families[2].1 - 0.75).abs() < f64::EPSILON);
        assert!((families[3].1 - 100.0).abs() < f64::EPSILON);
        assert!(EngineMetrics::default().block_cache_hit_ratio().abs() < f64::EPSILON);
    }

    #[test]
    fn pd_233_memory_families_split_the_node_rss() {
        let m = EngineMetrics {
            level_files: [3, 0, 0, 0, 0, 0, 1],
            memtable_bytes: 9,
            running_compactions: 2,
            block_cache: Some(CacheStats {
                hits: 5,
                misses: 6,
                usage: 7,
                rejected_oversize: 0,
            }),
            ..EngineMetrics::default()
        };
        let is = |m: &EngineMetrics, name: &str, want: f64| {
            m.families()
                .iter()
                .any(|f| f.0 == name && (f.1 - want).abs() < f64::EPSILON)
        };
        assert!(is(&m, BLOCK_CACHE_USAGE_BYTES, 7.0));
        assert!(is(&m, MEMTABLE_BYTES, 9.0));
        assert!(is(&m, SST_FILES, 4.0));
        assert!(is(&m, RUNNING_COMPACTIONS, 2.0));
        assert!(is(&m, BLOCK_CACHE_HITS_TOTAL, 5.0));
        assert!(is(&m, BLOCK_CACHE_MISSES_TOTAL, 6.0));
        // Without a cache the gauge still exists, at 0, so a scraper never misses the family.
        assert!(is(&EngineMetrics::default(), BLOCK_CACHE_USAGE_BYTES, 0.0));
    }
}
