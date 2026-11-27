// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Background flush and compaction of the store (storage-engine.md §3 "the server's
//! scheduler", PD-061).
//!
//! The storage engine runs flushes and compactions on the caller's thread and never schedules
//! them itself; without this module a running node only rotated memtables (the write path does
//! that when the active one is full), so immutable memtables piled up in memory, the
//! replicated log (the WAL) was purged only by the shutdown checkpoint, and files written
//! before a switch to encryption were never rewritten.
//!
//! - **Flush loop** (one): every [`FLUSH_POLL`] — the write path has no hook to wake it, and
//!   the check is one mutex and a length — flushes the immutable memtables, oldest first,
//!   leaving the active one alone (`EmbeddedDb::flush_immutable`), then purges the log entries
//!   the flushed data covers. A flush wakes the compaction workers, since it adds an L0 file.
//! - **Compaction workers** (`max(2, num_cpus / 4)`, the `storage.max_compactions` default of
//!   storage-engine.md §3; each L0 compaction is further split into as many sub-ranges): each
//!   runs `compact_once` until the picker finds nothing, then waits for a flush or
//!   [`COMPACTION_POLL`]. Concurrent workers are safe: the picker skips files that a running
//!   compaction holds (storage-engine.md, compaction implementation).
//! - **MVCC GC loop** (one, PD-232; storage-engine.md §11): every [`GC_POLL`] advances the GC
//!   threshold to `wall clock − gc.ttl` and deletes the versions no read at or above it can see
//!   (`EmbeddedDb::collect_garbage`, held back by backup pins); compactions then drop them
//!   physically. Without it every overwritten or deleted version stayed on disk forever (first
//!   24 h soak: 6 GB for ~100 MB of live data). The physical clock is never ahead of the HLC,
//!   so the threshold is at most `HLC now − gc.ttl`; `gc.ttl ≥ 10 min` is far above
//!   `txn.max_duration` (60 s), so no read-write transaction reads below it.
//! - **Errors** (I/O, ENOSPC, corruption): logged, then the loop waits [`ERROR_BACKOFF`]
//!   before retrying (storage-engine.md §11, "retries every 10 s"); a failed flush or
//!   compaction loses nothing (the log keeps every acknowledged commit, a failed compaction's
//!   inputs stay live). A poisoned engine keeps failing and the readiness probe reports it.
//! - **Shutdown**: [`Maintenance::stop`] runs before the shutdown checkpoint. The loops stop
//!   at their next step; a compaction already running cannot be interrupted, so the stop
//!   waits for it at most [`STOP_TIMEOUT`] and then lets the process exit under it — that is
//!   crash-equivalent (the next open deletes the orphan outputs, storage-engine.md §9 D) — and
//!   the shutdown checkpoint may flush concurrently with it, which the engine allows.
//!
//! Every engine call runs on the blocking pool: no blocking in async tasks.

use std::{sync::Arc, time::Duration};

use rustegon_engine::EmbeddedDb;
use rustegon_mvcc::Timestamp;
use rustegon_sim_api::Clock;
use tokio::{
    sync::{Notify, watch},
    task::JoinHandle,
};

/// Period of the flush loop's check for immutable memtables.
pub const FLUSH_POLL: Duration = Duration::from_millis(100);
/// Longest idle wait of a compaction worker without a flush waking it (picks up compactions
/// that become due without a flush, e.g. after a snapshot was released).
pub const COMPACTION_POLL: Duration = Duration::from_secs(5);
/// Period of the MVCC GC loop: the history kept is `gc.ttl` plus at most this much.
// shortcut: each run scans the whole store (`collect_garbage` over every key), fine for one
// node's data; a per-range garbage score (storage-engine.md §11) replaces it with ranges (M6).
pub const GC_POLL: Duration = Duration::from_secs(300);
/// Wait after a failed flush or compaction before the next attempt.
pub const ERROR_BACKOFF: Duration = Duration::from_secs(10);
/// Longest wait of [`Maintenance::stop`] for a running flush or compaction.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// The running background loops of one node.
pub struct Maintenance {
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

/// What one loop iteration achieved.
enum Step {
    /// Work was done; run the next step at once.
    Busy,
    /// Nothing to do; wait for the poll period (or a wake-up).
    Idle,
    /// The step failed; wait [`ERROR_BACKOFF`].
    Failed,
}

impl Maintenance {
    /// Starts the flush loop, `workers` compaction workers (at least one) and the MVCC GC loop
    /// keeping `gc_ttl` of history, on the current tokio runtime.
    pub fn start(
        engine: &Arc<EmbeddedDb>,
        clock: &Arc<dyn Clock>,
        workers: usize,
        gc_ttl: Duration,
    ) -> Self {
        let (stop, stop_rx) = watch::channel(false);
        let flushed = Arc::new(Notify::new());
        let mut tasks = Vec::with_capacity(3 + workers.max(1));
        tasks.push(tokio::spawn(crate::slow_io::stall_probe(
            Arc::clone(clock),
            stop_rx.clone(),
        )));
        {
            let (engine, gc_clock) = (Arc::clone(engine), Arc::clone(clock));
            tasks.push(tokio::spawn(run_loop(
                "gc",
                Arc::clone(clock),
                stop_rx.clone(),
                None,
                GC_POLL,
                move || gc_step(&engine, gc_clock.as_ref(), gc_ttl),
            )));
        }
        {
            let (engine, clock, flushed) =
                (Arc::clone(engine), Arc::clone(clock), Arc::clone(&flushed));
            tasks.push(tokio::spawn(run_loop(
                "flush",
                clock,
                stop_rx.clone(),
                None,
                FLUSH_POLL,
                move || flush_step(&engine, &flushed),
            )));
        }
        for _ in 0..workers.max(1) {
            let engine = Arc::clone(engine);
            tasks.push(tokio::spawn(run_loop(
                "compaction",
                Arc::clone(clock),
                stop_rx.clone(),
                Some(Arc::clone(&flushed)),
                COMPACTION_POLL,
                move || compaction_step(&engine),
            )));
        }
        Self { stop, tasks }
    }

    /// Stops every loop (module docs, "Shutdown"); waits at most [`STOP_TIMEOUT`] in total
    /// for running steps.
    pub async fn stop(self, clock: &dyn Clock) {
        let _ = self.stop.send(true);
        let all = async {
            for task in self.tasks {
                if let Err(e) = task.await {
                    tracing::error!(error = %e, "storage maintenance task failed");
                }
            }
        };
        tokio::select! {
            () = all => tracing::debug!("storage maintenance stopped"),
            () = clock.sleep(STOP_TIMEOUT) => tracing::warn!(
                "a flush or compaction is still running at shutdown; it is abandoned \
                 (crash-equivalent, cleaned up at the next start)"
            ),
        }
    }
}

/// Flushes the waiting immutable memtables and purges the log they covered.
fn flush_step(engine: &EmbeddedDb, flushed: &Notify) -> Step {
    match engine.flush_immutable() {
        Ok(0) => Step::Idle,
        Ok(n) => {
            tracing::debug!(memtables = n, "memtables flushed");
            flushed.notify_waiters();
            // More memtables may have been rotated meanwhile; check again at once.
            Step::Busy
        }
        Err(e) => {
            // Storage and log errors carry paths and codes, never document contents.
            tracing::error!(code = %e.code(), error = %e, "background flush failed; retrying");
            Step::Failed
        }
    }
}

/// Collects the MVCC versions shadowed for longer than `ttl` (module docs, "MVCC GC loop").
fn gc_step(engine: &EmbeddedDb, clock: &dyn Clock, ttl: Duration) -> Step {
    let now = clock
        .wall()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let Some(cutoff) = now.checked_sub(ttl) else {
        // The clock is less than `ttl` past the epoch: nothing is old enough.
        return Step::Idle;
    };
    let wall = u64::try_from(cutoff.as_nanos()).unwrap_or(u64::MAX);
    match engine.collect_garbage(Timestamp::new(wall, 0)) {
        Ok(outcome) => {
            // Info, one line per GC_POLL: the duration of the full-store scan is what PD-233
            // matches against the soak's latency bursts.
            let took = clock
                .wall()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .saturating_sub(now);
            tracing::info!(
                threshold = %outcome.threshold,
                versions = outcome.versions_removed,
                took_ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
                "MVCC garbage collected"
            );
            Step::Idle
        }
        Err(e) => {
            tracing::error!(code = %e.code(), error = %e, "MVCC garbage collection failed; retrying");
            Step::Failed
        }
    }
}

/// Runs one compaction if one is due.
fn compaction_step(engine: &EmbeddedDb) -> Step {
    match engine.compact_once() {
        Ok(true) => Step::Busy,
        Ok(false) => Step::Idle,
        Err(e) => {
            tracing::error!(code = %e.code(), error = %e, "background compaction failed; retrying");
            Step::Failed
        }
    }
}

/// Runs `work` on the blocking pool until `stopping` turns true; idles `poll` (or until `wake`)
/// when there is nothing to do and [`ERROR_BACKOFF`] after a failure.
async fn run_loop<F>(
    name: &'static str,
    clock: Arc<dyn Clock>,
    mut stopping: watch::Receiver<bool>,
    wake: Option<Arc<Notify>>,
    poll: Duration,
    work: F,
) where
    F: Fn() -> Step + Send + Sync + 'static,
{
    let work = Arc::new(work);
    loop {
        if *stopping.borrow() {
            return;
        }
        // Registered before the step so a flush finishing during it is not missed.
        let woken = wake.as_ref().map(|w| Arc::clone(w).notified_owned());
        let run = Arc::clone(&work);
        let outcome = match tokio::task::spawn_blocking(move || run()).await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!(task = name, error = %e, "storage maintenance step panicked");
                Step::Failed
            }
        };
        let wait = match outcome {
            Step::Busy => continue,
            Step::Idle => poll,
            Step::Failed => ERROR_BACKOFF,
        };
        let wake_up = async move {
            match woken {
                Some(n) => n.await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = clock.sleep(wait) => {}
            () = wake_up => {}
            _ = stopping.changed() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    // The test drives a real engine on real time (bounded waits for the background loops).
    #![allow(clippy::disallowed_methods)]

    use std::time::Instant;

    use rustegon_query::Params;
    use rustegon_sim_api::{OsRng, Rng, StdFileSystem, SystemClock};
    use rustegon_storage::EngineOptions;

    use super::*;

    /// Small memtables so a few hundred KiB of writes produce many flushes and L0 files.
    fn small_options() -> EngineOptions {
        EngineOptions {
            memtable_size: 64 << 10,
            ..EngineOptions::default()
        }
    }

    async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let started = Instant::now();
        while !done() {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// PD-061: a running node flushes rotated memtables, purges the log they cover and compacts
    /// L0 while writes go on, and stops cleanly; the data stays readable after a reopen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pd_061_background_flush_purge_and_compaction() {
        let dir = tempfile::tempdir().unwrap();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let rng: Arc<dyn Rng> = Arc::new(OsRng);
        let open = || {
            Arc::new(
                EmbeddedDb::open_with_options(
                    Arc::new(StdFileSystem),
                    dir.path(),
                    Arc::clone(&clock),
                    Arc::clone(&rng),
                    small_options(),
                )
                .unwrap(),
            )
        };
        let engine = open();
        let none = Params::default();
        engine.query("shop", "CREATE DATABASE shop", &none).unwrap();
        engine
            .query("shop", "CREATE COLLECTION orders", &none)
            .unwrap();

        let maintenance = Maintenance::start(&engine, &clock, 2, Duration::from_secs(3600));
        let pad = "x".repeat(1024);
        for i in 0..1500 {
            let statement = format!("INSERT INTO orders VALUE {{_id: {i}, pad: '{pad}'}}");
            let result = engine.query("shop", statement.as_str(), &none).unwrap();
            assert_eq!(result.inserted, 1);
        }

        wait_until("the flushes to catch up", || {
            let m = engine.storage_metrics();
            m.immutable_memtables == 0 && m.flushes >= 4
        })
        .await;
        wait_until("an L0 compaction", || {
            engine.storage_metrics().compactions >= 1
        })
        .await;
        let (first, _) = engine.replica().log_bounds();
        assert!(first > 1, "the log covered by flushed memtables is purged");

        maintenance.stop(clock.as_ref()).await;
        let metrics = engine.storage_metrics();
        drop(engine);

        assert!(
            metrics.level_files.iter().skip(1).any(|&n| n > 0),
            "compaction moved data below L0: {:?}",
            metrics.level_files
        );

        let reopened = open();
        let rows = reopened.query("shop", "FROM orders", &none).unwrap().rows;
        assert_eq!(rows.len(), 1500, "every write survives the reopen");
    }

    fn wall_ns() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )
        .unwrap()
    }

    /// PD-232: the GC step moves the threshold to `now − ttl` (never past the HLC), removes the
    /// shadowed versions of an updated document and keeps its latest value readable.
    #[test]
    fn pd_232_gc_step_collects_versions_older_than_the_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let engine = EmbeddedDb::open_with_options(
            Arc::new(StdFileSystem),
            dir.path(),
            Arc::clone(&clock),
            Arc::new(OsRng),
            small_options(),
        )
        .unwrap();
        let none = Params::default();
        engine.query("shop", "CREATE DATABASE shop", &none).unwrap();
        engine
            .query("shop", "CREATE COLLECTION orders", &none)
            .unwrap();
        engine
            .query("shop", "INSERT INTO orders VALUE {_id: 1, n: 0}", &none)
            .unwrap();
        for n in 1..=20 {
            let statement = format!("UPDATE orders SET n = {n} WHERE _id = 1");
            engine.query("shop", statement.as_str(), &none).unwrap();
        }

        // A TTL of one hour: the threshold lands one hour back, below every write.
        let hour = Duration::from_secs(3600);
        let before = wall_ns();
        assert!(matches!(gc_step(&engine, clock.as_ref(), hour), Step::Idle));
        let after = wall_ns();
        let t = engine.gc_threshold().wall;
        let hour_ns = u64::try_from(hour.as_nanos()).unwrap();
        assert!(
            (before - hour_ns..=after - hour_ns).contains(&t),
            "threshold {t}"
        );

        // A zero TTL (below the setting's minimum, test only): every write is old enough; after
        // the step nothing is left for a second pass at the same threshold (the deletion itself
        // is `collect_garbage`'s, covered in rustegon-sim tests/backup.rs).
        assert!(matches!(
            gc_step(&engine, clock.as_ref(), Duration::ZERO),
            Step::Idle
        ));
        let threshold = engine.gc_threshold();
        assert!(threshold.wall >= after);
        let again = engine.collect_garbage(threshold).unwrap();
        assert_eq!(again.versions_removed, 0);
        let rows = engine
            .query("shop", "FROM orders WHERE _id = 1", &none)
            .unwrap()
            .rows;
        assert_eq!(rows.len(), 1);
        assert!(format!("{:?}", rows[0]).contains("20"), "{:?}", rows[0]);
    }
}
