// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Storage engine microbenchmarks BM-STO-01…03 (performance-benchmarks.md §4; absolute targets,
//! no third-party baseline per ADR-003).
//!
//! Methodology notes (performance-benchmarks.md §1), and where this harness falls short of it:
//! - fixed seeds and versioned workload files (`bench/workloads/bm-sto-*.toml`);
//! - load phase excluded from the measured phase but reported;
//! - closed loop on one thread: each latency sample is one operation, so there is no coordinated
//!   omission *within* the run, but also no open-loop rate control (the server benchmarks use
//!   the open-loop generator; a storage microbenchmark measures service time);
//! - percentiles from all samples, sorted (exact; memory = 4 B per op) instead of `HdrHistogram`;
//! - "cache miss" means the engine block cache is disabled; the OS page cache is not bypassed
//!   (`O_DIRECT` is PD-007), so BM-STO-01 measures the engine path, not the device;
//! - the harness plays the server's scheduler and admission-control roles: a background thread
//!   flushes and compacts, and a write waits while the engine reports `WriteCondition::Stop`
//!   (time reported as `stall_seconds`), so L0 cannot grow without bound and distort write
//!   amplification; `Slowdown` is not acted on (no rate limiter before M4);
//! - `key_order = "random"` writes a fixed pseudo-random permutation of the keys (each key once,
//!   uniform over the key space), the usual way to measure steady-state leveled-compaction write
//!   amplification; sequential keys never overlap and barely compact.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use rustegon_sim_api::{Clock, FileSystem};
use rustegon_storage::{
    EngineOptions, LsmEngine, StorageError, WriteBatch,
    admission::{StallReason, WriteCondition},
    settings::StorageSettings,
};
use serde::{Deserialize, Serialize};

/// What a workload measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// BM-STO-01: uniform random point gets on a loaded, compacted store.
    PointGet,
    /// BM-STO-02: sequential write batches with background flush/compaction.
    WriteBatches,
    /// BM-STO-03: full forward scan of a loaded, compacted store.
    RangeScan,
}

/// Order in which keys are written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrder {
    /// Keys `0, 1, 2, …`.
    #[default]
    Sequential,
    /// A fixed pseudo-random permutation of `0..keys` (module docs).
    Random,
}

/// A workload definition (`bench/workloads/*.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    /// Benchmark id, e.g. `BM-STO-01`.
    pub id: String,
    /// What is measured.
    pub kind: Kind,
    /// Keys loaded (or written, for `write_batches`).
    pub keys: u64,
    /// Value size in bytes.
    pub value_size: usize,
    /// Operations in the measured phase (`point_get`); ignored otherwise.
    #[serde(default)]
    pub ops: u64,
    /// Puts per write batch.
    #[serde(default = "default_batch")]
    pub batch_size: u64,
    /// Block cache bytes (0 = disabled, i.e. every block read misses the engine cache).
    #[serde(default)]
    pub block_cache_size: u64,
    /// Seed of the key/value generator.
    #[serde(default)]
    pub seed: u64,
    /// Write order of the keys.
    #[serde(default)]
    pub key_order: KeyOrder,
    /// Background compaction threads; 0 (default) = the `storage.max_compactions` default
    /// `max(2, num_cpus / 4)` (storage-engine.md §3).
    #[serde(default)]
    pub compaction_threads: u64,
    /// Concurrent reader threads (`point_get`; default 1).
    #[serde(default = "default_threads")]
    pub threads: u64,
}

const fn default_threads() -> u64 {
    1
}

/// Compaction threads for `workload` (see [`Workload::compaction_threads`]).
fn compaction_threads(workload: &Workload) -> u64 {
    if workload.compaction_threads > 0 {
        return workload.compaction_threads;
    }
    let cpus = thread::available_parallelism().map_or(1, std::num::NonZero::get) as u64;
    (cpus / 4).max(2)
}

const fn default_batch() -> u64 {
    16
}

/// Latency summary in microseconds.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Latency {
    /// Samples.
    pub count: u64,
    /// Percentiles (µs).
    pub p50: f64,
    /// 95th percentile (µs).
    pub p95: f64,
    /// 99th percentile (µs).
    pub p99: f64,
    /// 99.9th percentile (µs).
    pub p999: f64,
    /// Maximum (µs).
    pub max: f64,
}

/// Result of one run (serialised into `bench/results/`).
#[derive(Debug, Clone, Serialize)]
pub struct RunResult {
    /// The workload as run.
    pub workload: Workload,
    /// Load phase duration in seconds (excluded from the measurement, reported).
    pub load_seconds: f64,
    /// Measured phase duration in seconds.
    pub measured_seconds: f64,
    /// Operations per second in the measured phase.
    pub ops_per_second: f64,
    /// Raw user bytes (keys + values) per second in the measured phase.
    pub bytes_per_second: f64,
    /// Per-operation latency (point gets) or per-batch latency (writes).
    pub latency: Option<Latency>,
    /// (flush + compaction bytes written) / user bytes written; write workloads only.
    pub write_amplification: Option<f64>,
    /// Live SST bytes / user bytes at the end (space amplification).
    pub space_amplification: f64,
    /// Time writes waited for `WriteCondition::Stop` to clear (part of the measured phase for
    /// write workloads, of the load phase otherwise).
    pub stall_seconds: f64,
    /// Batches that had to wait for `Stop` to clear.
    pub stalls: u64,
    /// `stall_seconds` split by `Stop` reason (`MemtablesFull`, `L0Files`, …): which stage
    /// (flush or L0 compaction) held writes back.
    pub stall_seconds_by_reason: BTreeMap<String, f64>,
    /// Non-empty levels at the end: shows how many levels the data passed through.
    pub levels: Vec<LevelStat>,
    /// FNV-1a 64 (hex) over the generated keys and value words in write order: identifies the
    /// dataset (performance-benchmarks.md §2 "dataset hash").
    pub dataset_hash: String,
}

/// Files and bytes of one level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LevelStat {
    /// Level number.
    pub level: usize,
    /// Live SST files.
    pub files: usize,
    /// Live SST bytes.
    pub bytes: u64,
}

fn levels(engine: &LsmEngine) -> Vec<LevelStat> {
    let m = engine.metrics();
    (0..m.level_files.len())
        .filter(|&l| m.level_files[l] > 0)
        .map(|level| LevelStat {
            level,
            files: m.level_files[level],
            bytes: m.level_bytes[level],
        })
        .collect()
}

/// Runs `workload` on a fresh store in `dir` (must not hold a store).
///
/// # Errors
/// Engine errors.
pub fn run(
    fs: &Arc<dyn FileSystem>,
    clock: &dyn Clock,
    dir: &Path,
    workload: &Workload,
) -> Result<RunResult, StorageError> {
    let settings = StorageSettings {
        block_cache_size: workload.block_cache_size,
        ..StorageSettings::default()
    };
    let engine = Arc::new(LsmEngine::open(
        Arc::clone(fs),
        dir,
        EngineOptions::from_settings(&settings),
    )?);
    let user_bytes = workload.keys * (KEY_LEN + workload.value_size) as u64;
    let secs = |d: Duration| d.as_secs_f64();

    if workload.kind == Kind::WriteBatches {
        let start = clock.monotonic();
        let mut loaded = load(&engine, clock, workload)?;
        let measured = secs(clock.monotonic().saturating_sub(start));
        let m = engine.metrics();
        return Ok(RunResult {
            workload: Workload {
                compaction_threads: compaction_threads(workload),
                ..workload.clone()
            },
            load_seconds: 0.0,
            measured_seconds: measured,
            ops_per_second: rate(workload.keys, measured),
            bytes_per_second: rate(user_bytes, measured),
            latency: Some(summarize(std::mem::take(&mut loaded.latencies))),
            write_amplification: Some(ratio(m.flush_bytes + m.compaction_write_bytes, user_bytes)),
            space_amplification: ratio(m.disk_used_bytes(), user_bytes),
            stall_seconds: secs(loaded.stalled),
            stalls: loaded.stalls,
            stall_seconds_by_reason: loaded.stall_seconds_by_reason(),
            levels: levels(&engine),
            dataset_hash: format!("{:016x}", loaded.hash),
        });
    }

    let start = clock.monotonic();
    let loaded = load(&engine, clock, workload)?;
    let load_seconds = secs(clock.monotonic().saturating_sub(start));
    let (ops, measured, latency) = match workload.kind {
        Kind::PointGet => measure_point_gets(&engine, clock, workload)?,
        Kind::RangeScan | Kind::WriteBatches => {
            let start = clock.monotonic();
            let mut it = engine.iterator(None)?;
            it.seek_to_first()?;
            let mut n = 0u64;
            while it.valid() {
                n += 1;
                it.next()?;
            }
            if n != workload.keys {
                return Err(StorageError::InvalidArgument(format!(
                    "scan saw {n} of {} keys",
                    workload.keys
                )));
            }
            (n, secs(clock.monotonic().saturating_sub(start)), None)
        }
    };
    let bytes = if workload.kind == Kind::PointGet {
        ops * (KEY_LEN + workload.value_size) as u64
    } else {
        user_bytes
    };
    Ok(RunResult {
        workload: Workload {
            compaction_threads: compaction_threads(workload),
            ..workload.clone()
        },
        load_seconds,
        measured_seconds: measured,
        ops_per_second: rate(ops, measured),
        bytes_per_second: rate(bytes, measured),
        latency,
        write_amplification: None,
        space_amplification: ratio(engine.metrics().disk_used_bytes(), user_bytes),
        stall_seconds: secs(loaded.stalled),
        stalls: loaded.stalls,
        stall_seconds_by_reason: loaded.stall_seconds_by_reason(),
        levels: levels(&engine),
        dataset_hash: format!("{:016x}", loaded.hash),
    })
}

/// BM-STO-01 measured phase: `workload.ops` gets split over `workload.threads` reader threads;
/// returns (ops, seconds, latency).
fn measure_point_gets(
    engine: &LsmEngine,
    clock: &dyn Clock,
    workload: &Workload,
) -> Result<(u64, f64, Option<Latency>), StorageError> {
    let threads = workload.threads.max(1);
    let start = clock.monotonic();
    // Each reader thread runs its share of the ops with its own key stream; latencies
    // of all threads form one distribution, throughput is total ops over wall time.
    let per_thread: Vec<Result<Vec<Duration>, StorageError>> = thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let ops = workload.ops / threads + u64::from(t < workload.ops % threads);
                scope.spawn(move || point_gets(engine, clock, workload, t, ops))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| {
                    Err(StorageError::InvalidArgument(
                        "reader thread panicked".into(),
                    ))
                })
            })
            .collect()
    });
    let measured = (clock.monotonic().saturating_sub(start)).as_secs_f64();
    let mut samples = Vec::with_capacity(usize::try_from(workload.ops).unwrap_or(0));
    for r in per_thread {
        samples.extend(r?);
    }
    Ok((workload.ops, measured, Some(summarize(samples))))
}

/// One reader thread of BM-STO-01: `ops` uniform random gets of loaded keys.
fn point_gets(
    engine: &LsmEngine,
    clock: &dyn Clock,
    workload: &Workload,
    thread: u64,
    ops: u64,
) -> Result<Vec<Duration>, StorageError> {
    let mut rng = XorShift::new(workload.seed ^ READ_SEED ^ thread.wrapping_mul(READ_SEED));
    let mut samples = Vec::with_capacity(usize::try_from(ops).unwrap_or(0));
    for _ in 0..ops {
        let k = key(rng.below(workload.keys));
        let t = clock.monotonic();
        let found = engine.get(&k, None)?;
        samples.push(clock.monotonic().saturating_sub(t));
        if found.is_none() {
            return Err(StorageError::InvalidArgument("loaded key missing".into()));
        }
    }
    Ok(samples)
}

/// Key length in bytes (`key-` + 16 hex digits).
const KEY_LEN: usize = 20;
/// Separates the read key stream from the value stream.
const READ_SEED: u64 = 0x005E_ED0F_5EED;

fn key(i: u64) -> Vec<u8> {
    format!("key-{i:016x}").into_bytes()
}

/// Bijection on `0..n`: `i -> (i * stride + offset) mod n` with `stride` coprime to `n`, so every
/// key is written exactly once in a scattered, seed-determined order.
struct Permutation {
    n: u64,
    stride: u64,
    offset: u64,
}

impl Permutation {
    /// Golden-ratio constant: an odd stride that spreads consecutive indices over the space.
    const STRIDE: u64 = 0x9E37_79B9_7F4A_7C15;

    fn new(n: u64, seed: u64) -> Self {
        let n = n.max(1);
        let mut stride = Self::STRIDE % n;
        while gcd(stride.max(1), n) != 1 {
            stride += 1;
        }
        Self {
            n,
            stride: stride.max(1),
            offset: seed % n,
        }
    }

    fn at(&self, i: u64) -> u64 {
        let v = (u128::from(i) * u128::from(self.stride) + u128::from(self.offset))
            % u128::from(self.n);
        // Lossless: below `n`.
        #[allow(clippy::cast_possible_truncation)]
        let v = v as u64;
        v
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// FNV-1a 64 offset basis and prime (Fowler, Noll, Vo).
const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

fn fnv(hash: u64, bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(hash, |h, b| (h ^ u64::from(*b)).wrapping_mul(FNV_PRIME))
}

/// What the load phase produced.
struct Loaded {
    latencies: Vec<Duration>,
    stalled: Duration,
    /// Stall time per `Stop` reason (`StallReason` debug name).
    stalled_by: BTreeMap<String, Duration>,
    stalls: u64,
    hash: u64,
}

impl Loaded {
    fn add_stall(&mut self, reason: StallReason, d: Duration) {
        self.stalled += d;
        *self.stalled_by.entry(format!("{reason:?}")).or_default() += d;
    }

    fn stall_seconds_by_reason(&self) -> BTreeMap<String, f64> {
        self.stalled_by
            .iter()
            .map(|(k, d)| (k.clone(), d.as_secs_f64()))
            .collect()
    }
}

/// Writes every key of the workload once (in `key_order`) in batches, with a background thread
/// flushing and compacting (the server's scheduler role) and waiting while the engine reports
/// `Stop` (admission control's role); returns per-batch latencies, then waits for quiescence.
fn load(
    engine: &Arc<LsmEngine>,
    clock: &dyn Clock,
    workload: &Workload,
) -> Result<Loaded, StorageError> {
    let done = Arc::new(AtomicBool::new(false));
    // The server's scheduler (storage-engine.md §3): one flush thread and
    // `storage.max_compactions` compaction threads; `compact_once` picks only compactions whose
    // inputs and output ranges are not busy, so concurrent callers run disjoint compactions.
    let mut background = vec![{
        let (engine, done) = (Arc::clone(engine), Arc::clone(&done));
        thread::spawn(move || -> Result<(), StorageError> {
            while !done.load(Ordering::Acquire) {
                if engine.immutable_memtables() > 0 {
                    engine.flush()?;
                } else {
                    thread::yield_now();
                }
            }
            Ok(())
        })
    }];
    for _ in 0..compaction_threads(workload) {
        let (engine, done) = (Arc::clone(engine), Arc::clone(&done));
        background.push(thread::spawn(move || -> Result<(), StorageError> {
            while !done.load(Ordering::Acquire) {
                if !engine.compact_once()? {
                    thread::yield_now();
                }
            }
            Ok(())
        }));
    }
    let mut rng = XorShift::new(workload.seed);
    let order = Permutation::new(workload.keys, workload.seed);
    let mut value = vec![0u8; workload.value_size];
    let mut loaded = Loaded {
        latencies: Vec::new(),
        stalled: Duration::ZERO,
        stalled_by: BTreeMap::new(),
        stalls: 0,
        hash: FNV_OFFSET,
    };
    let mut next = 0;
    let result = (|| -> Result<(), StorageError> {
        while next < workload.keys {
            let mut batch = WriteBatch::new();
            for _ in 0..workload.batch_size.min(workload.keys - next) {
                // Incompressible values (compression must not flatter throughput), generated a
                // word at a time so the generator does not dominate the measured phase.
                for chunk in value.chunks_mut(8) {
                    let word = rng.next().to_le_bytes();
                    chunk.copy_from_slice(&word[..chunk.len()]);
                }
                let k = key(match workload.key_order {
                    KeyOrder::Sequential => next,
                    KeyOrder::Random => order.at(next),
                });
                loaded.hash = fnv(fnv(loaded.hash, &k), &value);
                batch.put(&k, value.clone());
                next += 1;
            }
            // Admission control: never write into a `Stop` condition (module docs).
            if let WriteCondition::Stop(first) = engine.write_condition() {
                let mut t = clock.monotonic();
                let mut reason = first;
                // Attribute each slice of the wait to the reason reported for it.
                while let WriteCondition::Stop(now) = engine.write_condition() {
                    if now != reason {
                        let at = clock.monotonic();
                        loaded.add_stall(reason, at.saturating_sub(t));
                        (reason, t) = (now, at);
                    }
                    thread::yield_now();
                }
                loaded.add_stall(reason, clock.monotonic().saturating_sub(t));
                loaded.stalls += 1;
            }
            let t = clock.monotonic();
            engine.write(&batch)?;
            loaded.latencies.push(clock.monotonic().saturating_sub(t));
        }
        Ok(())
    })();
    done.store(true, Ordering::Release);
    let mut bg = Ok(());
    for handle in background {
        let r = handle.join().unwrap_or_else(|_| {
            Err(StorageError::InvalidArgument(
                "background thread panicked".into(),
            ))
        });
        if bg.is_ok() {
            bg = r;
        }
    }
    result?;
    bg?;
    engine.flush()?;
    drain(engine, compaction_threads(workload))?;
    Ok(loaded)
}

/// Runs compactions on `threads` threads until the store is quiescent: the measured time
/// includes paying the compaction debt (BM-STO-02 "flush + compaction included"), and the
/// server pays it with its whole compaction pool, not one thread (storage-engine.md §3), so a
/// serial `LsmEngine::compact` here would measure the harness, not the engine (PD-025).
///
/// Rounds: every thread compacts until the picker finds nothing; a thread can stop while
/// another one is still running a job whose outputs create new work, so rounds repeat until one
/// runs no compaction at all, which means the picker found nothing with nothing busy.
fn drain(engine: &Arc<LsmEngine>, threads: u64) -> Result<(), StorageError> {
    loop {
        let runs: Vec<Result<u64, StorageError>> = thread::scope(|scope| {
            let handles: Vec<_> = (0..threads.max(1))
                .map(|_| {
                    scope.spawn(|| {
                        let mut runs = 0u64;
                        while engine.compact_once()? {
                            runs += 1;
                        }
                        Ok(runs)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join().unwrap_or_else(|_| {
                        Err(StorageError::InvalidArgument(
                            "compaction thread panicked".into(),
                        ))
                    })
                })
                .collect()
        });
        let mut total = 0;
        for r in runs {
            total += r?;
        }
        if total == 0 {
            return Ok(());
        }
    }
}

/// Exact percentiles of `samples` in microseconds.
fn summarize(mut samples: Vec<Duration>) -> Latency {
    samples.sort_unstable();
    let at = |q: f64| {
        if samples.is_empty() {
            return 0.0;
        }
        // Nearest-rank percentile.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let rank = ((q * samples.len() as f64).ceil() as usize).clamp(1, samples.len());
        samples[rank - 1].as_secs_f64() * 1e6
    };
    Latency {
        count: samples.len() as u64,
        p50: at(0.50),
        p95: at(0.95),
        p99: at(0.99),
        p999: at(0.999),
        max: at(1.0),
    }
}

#[allow(clippy::cast_precision_loss)] // benchmark counts are far below 2^53
fn rate(n: u64, seconds: f64) -> f64 {
    if seconds > 0.0 {
        n as f64 / seconds
    } else {
        0.0
    }
}

#[allow(clippy::cast_precision_loss)]
fn ratio(a: u64, b: u64) -> f64 {
    if b == 0 { 0.0 } else { a as f64 / b as f64 }
}

/// Deterministic generator for keys and values (benchmark data, not security).
struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        // Any non-zero state works; the odd constant keeps seed 0 valid.
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

#[cfg(test)]
mod tests {
    use rustegon_sim::SimFileSystem;
    use rustegon_sim_api::SystemClock;

    use super::*;

    fn tiny(kind: Kind) -> Workload {
        Workload {
            id: "test".into(),
            kind,
            keys: 2_000,
            value_size: 100,
            ops: 500,
            batch_size: 16,
            block_cache_size: 0,
            seed: 7,
            key_order: KeyOrder::Sequential,
            threads: 1,
            compaction_threads: 0,
        }
    }

    #[test]
    fn concurrent_point_gets_run_all_ops() {
        let mut w = tiny(Kind::PointGet);
        w.threads = 3;
        w.ops = 1_000;
        let fs: Arc<dyn FileSystem> = Arc::new(SimFileSystem::new());
        let r = run(&fs, &SystemClock::new(), Path::new("/bench"), &w).unwrap();
        assert_eq!(r.latency.unwrap().count, 1_000);
    }

    /// Every key is written exactly once in random order too, for sizes whose gcd with the
    /// stride constant is not 1 as well.
    #[test]
    fn permutation_is_a_bijection() {
        for n in [1u64, 2, 3, 10, 97, 1000, 1 << 12, 6_700_417] {
            let p = Permutation::new(n, 42);
            let mut seen = vec![false; usize::try_from(n).unwrap()];
            for i in 0..n {
                let v = usize::try_from(p.at(i)).unwrap();
                assert!(!seen[v], "n {n}: {v} twice");
                seen[v] = true;
            }
            if n > 10 {
                // Scattered: consecutive writes are not consecutive keys.
                assert_ne!(p.at(1), (p.at(0) + 1) % n, "n {n}");
            }
        }
    }

    #[test]
    fn random_order_loads_every_key_and_reports_levels() {
        let mut w = tiny(Kind::RangeScan);
        w.key_order = KeyOrder::Random;
        let fs: Arc<dyn FileSystem> = Arc::new(SimFileSystem::new());
        let r = run(&fs, &SystemClock::new(), Path::new("/bench"), &w).unwrap();
        assert!(r.ops_per_second > 0.0);
        assert_ne!(r.levels, Vec::new());
        assert_eq!(r.dataset_hash.len(), 16);
        let seq = run(
            &fs,
            &SystemClock::new(),
            Path::new("/bench2"),
            &tiny(Kind::RangeScan),
        );
        assert_ne!(seq.unwrap().dataset_hash, r.dataset_hash);
    }

    #[test]
    fn every_workload_kind_runs_and_reports() {
        for kind in [Kind::PointGet, Kind::WriteBatches, Kind::RangeScan] {
            let fs: Arc<dyn FileSystem> = Arc::new(SimFileSystem::new());
            let r = run(&fs, &SystemClock::new(), Path::new("/bench"), &tiny(kind)).unwrap();
            assert!(
                r.ops_per_second > 0.0 && r.bytes_per_second > 0.0,
                "{kind:?}"
            );
            assert!(r.space_amplification > 0.0, "{kind:?}");
            assert_eq!(r.write_amplification.is_some(), kind == Kind::WriteBatches);
            assert_eq!(r.latency.is_some(), kind != Kind::RangeScan);
            let json = serde_json::to_string(&r).unwrap();
            assert!(json.contains("\"ops_per_second\""));
        }
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        let samples = (1..=100).map(Duration::from_micros).collect();
        let l = summarize(samples);
        assert_eq!(l.count, 100);
        assert!((l.p50 - 50.0).abs() < 1e-6 && (l.p99 - 99.0).abs() < 1e-6);
        assert!((l.max - 100.0).abs() < 1e-6);
        assert_eq!(summarize(Vec::new()), Latency::default());
    }

    #[test]
    fn workload_files_parse() {
        let w: Workload = toml::from_str(
            "id = \"BM-STO-01\"\nkind = \"point_get\"\nkeys = 10\nvalue_size = 1024\nops = 5\n",
        )
        .unwrap();
        assert_eq!(w.kind, Kind::PointGet);
        assert_eq!(w.batch_size, 16);
    }
}
