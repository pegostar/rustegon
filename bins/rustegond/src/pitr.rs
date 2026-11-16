// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The PITR log archiver task of a node (FR-BKP-002, FR-BKP-004, PD-066, PD-088;
//! backup-restore.md "Point-in-time recovery").
//!
//! With `[backup.pitr] enabled = true` the node archives every sealed segment of its Raft log
//! (the WAL) to `backup.pitr.destination`, so a backup can later be rolled forward to any time
//! in the archived window (`rustegon backup restore --to-time`). The archiving itself is
//! `rustegon_backup::pitr::PitrArchiver`; this module only decides *when* it runs:
//!
//! - **Before the store opens** ([`prepare`]): the destination is checked against the backup
//!   allowlist (`RGN-4002` refuses the start, as for any request), the archiver's local state
//!   (`<store>/pitr-archive.json`: the timeline, the highest archived segment) is loaded or
//!   created, and its archive floor is handed to `EmbeddedDb::open_with_log_options`: the open
//!   itself runs a segment deletion pass, which must already keep the unarchived segments.
//! - **While serving** ([`PitrTask::start`]): every [`ARCHIVE_POLL`] (or the segment interval
//!   if shorter) one pass copies the segments sealed by size rollovers; every
//!   `backup.pitr.segment_interval_secs` the pass first closes a timestamp and seals the active
//!   segment (the RPO, PD-088). A failed pass (destination down) is logged and retried after
//!   [`ERROR_BACKOFF`]; the archiver keeps checking `max_unarchived_bytes` on every pass, so a
//!   long outage breaks PITR continuity instead of filling the disk, and writes are never
//!   blocked: the archiver only reads the log and raises the floor.
//! - **At shutdown** ([`PitrTask::stop`], after the listeners and open transactions are gone,
//!   before the shutdown checkpoint): one last pass with a roll, so a cleanly stopped node has
//!   archived everything it acknowledged. It is bounded by [`STOP_TIMEOUT`]; past it the write
//!   fence is cancelled and the pass is abandoned, which is crash-equivalent (the floor only
//!   ever rises after a durable copy, so the next start archives what is missing).
//!
//! Passes run on the blocking pool (the log store and the destinations are synchronous): no
//! blocking in async tasks. At most one pass runs at a time: the archiver is moved into the
//! blocking task and back, so it is never shared.

use std::{path::Path, sync::Arc, time::Duration};

use rustegon_backup::{
    DestinationPolicy, DestinationUrl, PitrSettings, S3Settings, open_destination,
    pitr::{ArchiverConfig, PitrArchiver, PitrMetrics, PreparedArchiver},
};
use rustegon_common::Result;
use rustegon_engine::{EmbeddedDb, embedded::CancelHandle};
use rustegon_sim_api::{Clock, FileSystem, Rng};
use rustegon_storage::encryption::KekProvider;
use tokio::{sync::watch, task::JoinHandle};

/// Longest wait between two passes without a roll: picks up segments sealed by size
/// rollovers well before the next timed roll.
pub const ARCHIVE_POLL: Duration = Duration::from_secs(10);
/// Wait after a failed pass before the next attempt.
pub const ERROR_BACKOFF: Duration = Duration::from_secs(10);
/// Longest wait of [`PitrTask::stop`] for the final pass.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// The archiver between [`prepare`] and [`PitrTask::start`].
pub struct PreparedPitr {
    archiver: PreparedArchiver,
    destination: Arc<dyn rustegon_backup::Destination>,
    settings: PitrSettings,
}

impl PreparedPitr {
    /// The store's timeline, recorded in backup manifests.
    pub fn timeline(&self) -> &str {
        self.archiver.timeline()
    }

    /// The archive floor for `LogStoreOptions::archive_floor`.
    pub fn floor(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.archiver.floor()
    }
}

/// Startup step "PITR policy" (module docs): `None` when archiving is off.
///
/// # Errors
/// `RGN-4002` for a destination outside the allowlist; an unreadable archiver state
/// (`RGN-5002`/`RGN-5007`); a destination that cannot be opened; I/O errors.
pub fn prepare(
    settings: &PitrSettings,
    policy: &DestinationPolicy,
    s3: &S3Settings,
    fs: &Arc<dyn FileSystem>,
    rng: &dyn Rng,
    store_dir: &Path,
) -> Result<Option<PreparedPitr>> {
    if !settings.enabled {
        return Ok(None);
    }
    // `PitrSettings::validate` already refused `enabled` without a destination.
    let text = settings.destination.as_deref().unwrap_or_default();
    let url = DestinationUrl::parse(text)?;
    policy.check(&url)?;
    let destination: Arc<dyn rustegon_backup::Destination> =
        Arc::from(open_destination(&url, Arc::clone(fs), s3)?);
    let archiver = PreparedArchiver::load(Arc::clone(fs), store_dir, rng)?;
    tracing::info!(
        destination = %destination.describe(),
        timeline = %archiver.timeline(),
        segment_interval_secs = settings.segment_interval_secs,
        "PITR log archiving enabled"
    );
    Ok(Some(PreparedPitr {
        archiver,
        destination,
        settings: settings.clone(),
    }))
}

/// The running archiver task.
pub struct PitrTask {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    cancel: CancelHandle,
}

impl PitrTask {
    /// Starts archiving the opened store `engine` (opened with [`PreparedPitr::floor`]) on the
    /// current tokio runtime; returns the task and its counters (for `/metrics`).
    pub fn start(
        prepared: PreparedPitr,
        engine: &Arc<EmbeddedDb>,
        clock: &Arc<dyn Clock>,
        kek: Option<Arc<dyn KekProvider>>,
    ) -> (Self, Arc<PitrMetrics>) {
        let interval = Duration::from_secs(prepared.settings.segment_interval_secs);
        let archiver = prepared.archiver.start(
            Arc::clone(engine),
            Arc::clone(clock),
            prepared.destination,
            kek,
            ArchiverConfig {
                max_unarchived_bytes: prepared.settings.max_unarchived_bytes,
                txn_max_duration: engine.txn_config().max_duration,
                ..ArchiverConfig::default()
            },
        );
        let metrics = archiver.metrics();
        let cancel = archiver.cancel_handle();
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run(archiver, Arc::clone(clock), interval, stop_rx));
        (Self { stop, task, cancel }, metrics)
    }

    /// Runs the final pass and stops (module docs, "At shutdown").
    pub async fn stop(self, clock: &dyn Clock) {
        let _ = self.stop.send(true);
        let mut task = self.task;
        tokio::select! {
            joined = &mut task => {
                if let Err(e) = joined {
                    tracing::error!(error = %e, "PITR archiver task failed");
                }
            }
            () = clock.sleep(STOP_TIMEOUT) => {
                // The pass runs on the blocking pool and cannot be interrupted, except for its
                // write fence; abandoning it is crash-equivalent (module docs).
                self.cancel.cancel();
                tracing::warn!(
                    "the final PITR archiver pass did not finish in time; it is abandoned and \
                     the next start archives the remaining segments"
                );
            }
        }
    }
}

/// One pass on the blocking pool; `None` when the pass panicked (the archiver is lost).
async fn pass_blocking(
    mut archiver: PitrArchiver,
    roll: bool,
) -> Option<(PitrArchiver, Result<rustegon_backup::pitr::PassOutcome>)> {
    match tokio::task::spawn_blocking(move || {
        let outcome = archiver.pass(roll);
        (archiver, outcome)
    })
    .await
    {
        Ok(done) => Some(done),
        Err(e) => {
            tracing::error!(error = %e, "PITR archiver pass panicked; archiving stops until restart");
            None
        }
    }
}

/// Logs a pass's outcome; `true` when it failed.
fn report(result: &Result<rustegon_backup::pitr::PassOutcome>) -> bool {
    match result {
        Ok(outcome) => {
            if outcome.archived > 0 || outcome.rolled.is_some() {
                tracing::debug!(
                    archived = outcome.archived,
                    rolled = ?outcome.rolled,
                    unarchived_bytes = outcome.unarchived_bytes,
                    "PITR archiver pass"
                );
            }
            // The archiver logs the break itself (with the segment range) and counts it.
            false
        }
        Err(e) => {
            // Destination and log errors name objects and codes, never document contents.
            tracing::error!(code = %e.code(), error = %e, "PITR archiver pass failed; retrying");
            true
        }
    }
}

/// The archiver loop (module docs).
async fn run(
    archiver: PitrArchiver,
    clock: Arc<dyn Clock>,
    interval: Duration,
    mut stopping: watch::Receiver<bool>,
) {
    let poll = interval.min(ARCHIVE_POLL);
    let mut archiver = archiver;
    // The first pass rolls at once: segments left by the previous run are archived and the
    // timeline gets a closed timestamp right after the start.
    let mut next_roll = clock.monotonic();
    loop {
        if *stopping.borrow() {
            break;
        }
        let now = clock.monotonic();
        let roll = now >= next_roll;
        if roll {
            next_roll = now + interval;
        }
        let Some((back, result)) = pass_blocking(archiver, roll).await else {
            return;
        };
        archiver = back;
        let wait = if report(&result) { ERROR_BACKOFF } else { poll };
        tokio::select! {
            () = clock.sleep(wait) => {}
            _ = stopping.changed() => {}
        }
    }
    // Final pass (module docs, "At shutdown"): everything acknowledged so far is sealed and
    // archived, with a closed timestamp, unless the destination fails.
    if let Some((_, result)) = pass_blocking(archiver, true).await
        && !report(&result)
    {
        tracing::info!("PITR archive up to date at shutdown");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    // The task test drives a real engine on real time (bounded waits for the archiver).
    #![allow(clippy::disallowed_methods)]

    use std::time::Instant;

    use rustegon_backup::{AllowedDestination, LocalDestination, pitr::load_index};
    use rustegon_common::ErrorCode;
    use rustegon_engine::embedded::LogStoreOptions;
    use rustegon_query::Params;
    use rustegon_sim_api::{OsRng, StdFileSystem, SystemClock};
    use rustegon_storage::EngineOptions;

    use super::*;

    fn settings(destination: &Path, interval: u64) -> PitrSettings {
        PitrSettings {
            enabled: true,
            destination: Some(destination.display().to_string()),
            segment_interval_secs: interval,
            ..PitrSettings::default()
        }
    }

    fn fs() -> Arc<dyn FileSystem> {
        Arc::new(StdFileSystem)
    }

    /// PD-089: archiving off prepares nothing; a destination outside the backup allowlist
    /// refuses the start before the store is touched; an allowed one keeps its timeline across
    /// restarts.
    #[test]
    fn pd_089_prepare_checks_the_allowlist_and_keeps_the_timeline() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let allowed = dir.path().join("backups");
        let policy = DestinationPolicy::new(vec![AllowedDestination::local(&allowed).unwrap()]);
        let s3 = S3Settings::default();

        let off = PitrSettings::default();
        assert!(
            prepare(&off, &policy, &s3, &fs(), &OsRng, &store)
                .unwrap()
                .is_none()
        );

        let outside = settings(&dir.path().join("elsewhere"), 300);
        let Err(err) = prepare(&outside, &policy, &s3, &fs(), &OsRng, &store) else {
            panic!("a destination outside the allowlist was accepted");
        };
        assert_eq!(err.code(), ErrorCode::PermissionDenied, "{err}");
        assert!(!store.exists(), "nothing created on a refused start");

        let ok = settings(&allowed.join("pitr-archive"), 300);
        let first = prepare(&ok, &policy, &s3, &fs(), &OsRng, &store)
            .unwrap()
            .unwrap();
        let timeline = first.timeline().to_owned();
        drop(first);
        let again = prepare(&ok, &policy, &s3, &fs(), &OsRng, &store)
            .unwrap()
            .unwrap();
        assert_eq!(again.timeline(), timeline);
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

    /// FR-BKP-002 / PD-089: the task archives on its timer while writes go on, `/metrics`
    /// counters follow, and the final pass at stop leaves the whole acknowledged log archived
    /// with a closed timestamp at or above the last commit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tc_bkp_004_archiver_task_archives_on_its_timer_and_at_stop() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let archive_dir = dir.path().join("backups");
        let policy = DestinationPolicy::new(vec![AllowedDestination::local(&archive_dir).unwrap()]);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let rng: Arc<dyn rustegon_sim_api::Rng> = Arc::new(OsRng);
        let prepared = prepare(
            &settings(&archive_dir, 1),
            &policy,
            &S3Settings::default(),
            &fs(),
            rng.as_ref(),
            &store,
        )
        .unwrap()
        .unwrap();
        let timeline = prepared.timeline().to_owned();
        let engine = Arc::new(
            EmbeddedDb::open_with_log_options(
                fs(),
                &store,
                Arc::clone(&clock),
                Arc::clone(&rng),
                EngineOptions::default(),
                None,
                LogStoreOptions {
                    archive_floor: Some(prepared.floor()),
                    ..LogStoreOptions::default()
                },
            )
            .unwrap(),
        );
        let (task, metrics) = PitrTask::start(prepared, &engine, &clock, None);
        let none = Params::default();
        engine.query("shop", "CREATE DATABASE shop", &none).unwrap();
        engine
            .query("shop", "CREATE COLLECTION orders", &none)
            .unwrap();
        for i in 0..20 {
            let statement = format!("INSERT INTO orders VALUE {{_id: {i}}}");
            engine.query("shop", statement.as_str(), &none).unwrap();
        }
        wait_until("a timed roll to archive the first writes", || {
            metrics
                .archived_segments
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        })
        .await;
        engine
            .query("shop", "INSERT INTO orders VALUE {_id: 100}", &none)
            .unwrap();
        let last = engine.replica().log_bounds().1;
        task.stop(clock.as_ref()).await;

        let dest = LocalDestination::open(fs(), &archive_dir).unwrap();
        let index = load_index(&dest, &timeline).unwrap().unwrap();
        let archived_last = index.segments.iter().filter_map(|s| s.last_index).max();
        assert!(
            archived_last >= Some(last),
            "final pass archived through {archived_last:?}, log ends at {last}"
        );
        assert!(
            index.segments.iter().any(|s| s.closed_ts.is_some()),
            "timed rolls record closed timestamps"
        );
        assert_eq!(index.breaks, []);
        assert_eq!(
            metrics
                .failed_passes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
}
