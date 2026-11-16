// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Backup primitives of the embedded store (M13a lane BD; FR-BKP-001/003/005, PD-063, PD-066,
//! PD-067; storage-engine.md §10, transaction-management.md §13).
//!
//! # Consistency point T (PD-063)
//! [`EmbeddedDb::close_timestamp`] runs the coordinator's write fence
//! (`TxnCoordinator::close_timestamp`): it picks T from the HLC, raises the timestamp cache's
//! low-water mark to T so that every later write lands above T, and waits until no transaction
//! holding an intent at or below T can still commit there. Afterwards the committed state as of
//! T is final. Writers are not stopped.
//!
//! # Consistent checkpoint
//! [`EmbeddedDb::consistent_checkpoint`] = close T, pin the GC threshold at T for the duration,
//! then `LocalReplica::checkpoint`, which flushes and captures the LSM image together with the
//! exact Raft applied state inside it. The image holds every commit at or below T and, besides,
//! whatever committed above T before the capture plus the intents and records of transactions
//! still running: it is a consistent state of the store at its seqno, **and** reading it at T
//! gives exactly the source read at T. Restoring therefore means "revert the image to T":
//! [`EmbeddedDb::open_restored`] gives the restored engine a log positioned at the image's
//! applied state, opens it, and runs [`EmbeddedDb::revert_to`]`(T)`, which
//! - aborts every intent and deletes every transaction record: each belongs to a transaction
//!   that commits above T or never (the fence guarantees it), so at T none of them is visible;
//! - deletes every committed version above T, so the newest version at or below T of each key
//!   becomes the latest — documents, catalog, indexes and index build records alike, because
//!   they are all MVCC keys.
//!
//! The result is the source as read at T, for every reader at every timestamp `>= T`.
//!
//! # GC pins (PD-067)
//! The store's MVCC GC threshold starts at the beginning of time; [`EmbeddedDb::collect_garbage`]
//! advances it and deletes what became garbage, and the compaction filter drops it physically.
//! [`PinnedSnapshot`] holds a `GcPin` at its timestamp: while it lives the threshold never
//! passes it, so a long scan at that timestamp (the logical dump, which outlives
//! `txn.max_duration`) never loses a version it can see. Dropping the snapshot releases the pin.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustegon_cluster::LocalReplica;
use rustegon_common::{Error, ErrorCode};
use rustegon_mvcc::{
    GcPin, MvccKey, Replica, ReplicaCommand, Timestamp, gc_batch_limited, key::LOCAL_PREFIX,
};
use rustegon_raft::{LogStore, LogStoreOptions};
use rustegon_sim_api::{Clock, FileSystem, OpenMode, Rng};
use rustegon_storage::{CheckpointInfo, EngineOptions, WriteBatch, encryption::KekProvider};

use super::{CancelHandle, EmbeddedDb, LOG_DIR, RANGE_ID, keys, lock::StoreLock};

/// Default bound of the write fence: twice `txn.max_duration`, so a transaction that started
/// just before the fence can still finish (or be aborted by its own limit) before the backup
/// gives up.
pub const DEFAULT_FENCE_TIMEOUT: Duration = Duration::from_secs(120);
/// Operations per command proposed by [`EmbeddedDb::revert_to`] and
/// [`EmbeddedDb::collect_garbage`]: bounds the size of one log entry and one engine batch.
const MAX_BATCH_OPS: usize = 10_000;
/// The marker of a restore in progress in the store root ([`EmbeddedDb::open_restored`]).
pub const RESTORE_MARKER: &str = "RESTORING";
/// Second byte of transaction-record keys (`0x01 'k' …`, data-model.md §3.2).
const TXN_RECORD_MARKER: u8 = b'k';

/// A cancellation test polled by the write fence (e.g. "has the client of this backup RPC gone
/// away", over the server executor's own token, M13a lane BE).
pub type CancelCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// How long the write fence may wait, and how to cancel it.
#[derive(Clone)]
pub struct FenceOptions {
    /// Give up with `RGN-5006` after this long (module docs).
    pub timeout: Duration,
    /// Give up with `RGN-5005` once cancelled (e.g. the client of a backup RPC went away).
    pub cancel: Option<CancelHandle>,
    /// Give up with `RGN-5005` once this returns `true` (polled like `cancel`).
    pub cancel_check: Option<CancelCheck>,
}

impl std::fmt::Debug for FenceOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FenceOptions")
            .field("timeout", &self.timeout)
            .field("cancel", &self.cancel)
            .field("cancel_check", &self.cancel_check.is_some())
            .finish()
    }
}

impl Default for FenceOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_FENCE_TIMEOUT,
            cancel: None,
            cancel_check: None,
        }
    }
}

/// A closed timestamp whose versions are protected from GC (module docs); the pin is released
/// when this is dropped. Belongs to the store that created it.
#[derive(Debug)]
pub struct PinnedSnapshot {
    ts: Timestamp,
    _pin: GcPin,
}

impl PinnedSnapshot {
    /// The snapshot timestamp T.
    #[must_use]
    pub fn ts(&self) -> Timestamp {
        self.ts
    }
}

/// What [`EmbeddedDb::consistent_checkpoint`] produced: the `consistency` block of the backup
/// manifest (`rustegon_backup::Consistency`) and the checkpoint's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsistentCheckpoint {
    /// Consistency timestamp T: restoring yields the store as read at T.
    pub ts: Timestamp,
    /// Last Raft log index whose command is in the image.
    pub applied_index: u64,
    /// Term of `applied_index`.
    pub applied_term: u64,
    /// Every storage write with seqno `<=` this is in the image.
    pub storage_seqno: u64,
    /// The storage checkpoint (file count, linked / copied bytes, encryption).
    pub info: CheckpointInfo,
}

impl ConsistentCheckpoint {
    /// The point [`EmbeddedDb::open_restored`] needs to restore this checkpoint.
    #[must_use]
    pub fn restore_point(&self) -> RestorePoint {
        RestorePoint {
            ts: self.ts,
            applied_index: self.applied_index,
            applied_term: self.applied_term,
        }
    }
}

/// Where a restored image stands: its applied log position and the timestamp to revert it to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestorePoint {
    /// Consistency timestamp T of the backup (manifest `consistency.timestamp`).
    pub ts: Timestamp,
    /// Manifest `consistency.applied_index`.
    pub applied_index: u64,
    /// Manifest `consistency.applied_term`.
    pub applied_term: u64,
}

/// What [`EmbeddedDb::revert_to`] removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RevertOutcome {
    /// Committed versions above the target timestamp.
    pub versions_removed: u64,
    /// Intents of transactions that had not committed (at or below the target).
    pub intents_aborted: u64,
    /// Transaction records.
    pub records_removed: u64,
}

/// What [`EmbeddedDb::collect_garbage`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcOutcome {
    /// The threshold used: the requested one, held back by the oldest pin.
    pub threshold: Timestamp,
    /// Versions deleted.
    pub versions_removed: u64,
}

impl EmbeddedDb {
    /// Closes a fresh timestamp T for writes and returns it (module docs, PD-063).
    ///
    /// # Errors
    /// `RGN-5006` after `options.timeout`, `RGN-5005` when cancelled, `RGN-5001` when a
    /// transaction's commit outcome is unknown (reopen the store first).
    pub fn close_timestamp(&self, options: &FenceOptions) -> Result<Timestamp, Error> {
        let cancel = options.cancel.clone();
        let check = options.cancel_check.clone();
        let cancelled = move || {
            cancel.as_ref().is_some_and(CancelHandle::is_cancelled)
                || check.as_ref().is_some_and(|c| c())
        };
        Ok(self.coord.close_timestamp(options.timeout, &cancelled)?)
    }

    /// Closes a fresh timestamp T ([`EmbeddedDb::close_timestamp`]) and pins the GC threshold
    /// at it: the snapshot for a logical dump ([`EmbeddedDb::scan_at`]) or a checkpoint.
    ///
    /// # Errors
    /// As [`EmbeddedDb::close_timestamp`]; `RGN-2007` if GC already passed T (only when a
    /// caller advanced the threshold into the future).
    pub fn pin_snapshot(&self, options: &FenceOptions) -> Result<PinnedSnapshot, Error> {
        let ts = self.close_timestamp(options)?;
        let pin = self.gc.pin(ts)?;
        Ok(PinnedSnapshot { ts, _pin: pin })
    }

    /// An online, consistent checkpoint of the store in the empty directory `target` (module
    /// docs; FR-BKP-001, FR-BKP-003, PD-063). Writes continue meanwhile.
    ///
    /// `target` receives the LSM image (`CURRENT`, `MANIFEST-*`, `*.rsst`) and, for an
    /// encrypted store, its DEK registry in `target/keys/registry.enc`. The store layout a
    /// restore needs is: the image without `keys/` in `<store>/lsm/`, the registry (if any) in
    /// `<store>/keys/registry.enc`, then [`EmbeddedDb::open_restored`] with
    /// [`ConsistentCheckpoint::restore_point`]. The Raft log is not part of the image.
    ///
    /// # Errors
    /// `RGN-3002` when the store refuses writes (failed apply, reopen first); as
    /// [`EmbeddedDb::pin_snapshot`]; storage errors (the partial `target` is left for the
    /// caller to remove; it never opens as a store).
    pub fn consistent_checkpoint(
        &self,
        target: &Path,
        options: &FenceOptions,
    ) -> Result<ConsistentCheckpoint, Error> {
        if !self.is_healthy() {
            return Err(unhealthy());
        }
        // Held until the image is captured: GC cannot remove a version visible at T before
        // the checkpoint has its SSTs.
        let snapshot = self.pin_snapshot(options)?;
        self.checkpoint_at(&snapshot, target)
    }

    /// [`EmbeddedDb::consistent_checkpoint`] at an existing snapshot of this store (e.g. one
    /// also used to read the source at T, or to take a checkpoint and a logical dump at the
    /// same T).
    ///
    /// # Errors
    /// As [`EmbeddedDb::consistent_checkpoint`].
    pub fn checkpoint_at(
        &self,
        snapshot: &PinnedSnapshot,
        target: &Path,
    ) -> Result<ConsistentCheckpoint, Error> {
        if !self.is_healthy() {
            return Err(unhealthy());
        }
        let cp = self.replica.checkpoint(target)?;
        Ok(ConsistentCheckpoint {
            ts: snapshot.ts(),
            applied_index: cp.applied.applied_index,
            applied_term: cp.applied.applied_term,
            storage_seqno: cp.info.seqno,
            info: cp.info,
        })
    }

    /// Reverts the store to timestamp `ts` (module docs, "Consistent checkpoint"): aborts every
    /// intent, deletes every transaction record and every committed version above `ts`, in
    /// commands of at most 10 000 operations through the replica (durable, replayed
    /// after a crash; running it again finishes an interrupted revert). Afterwards the latest
    /// state equals the state read at `ts` — provided no transaction could still commit at or
    /// below `ts` when the image was taken (a fenced `ts`, PD-063; PITR replays far enough past
    /// it, PD-066).
    ///
    /// Only for a store no client uses yet: a restore ([`EmbeddedDb::open_restored`]) or a
    /// point-in-time recovery right after its replay. Running transactions would lose their
    /// intents and their commits above `ts`.
    ///
    /// # Errors
    /// Storage and replica errors; corruption for a key without an MVCC suffix.
    pub fn revert_to(&self, ts: Timestamp) -> Result<RevertOutcome, Error> {
        let mut outcome = RevertOutcome::default();
        let mut start: Vec<u8> = Vec::new();
        loop {
            let mut batch = WriteBatch::new();
            let mut resume = None;
            {
                let mut iter = self.replica.engine().iterator(None)?;
                iter.seek(&start)?;
                while iter.valid() {
                    if batch.len() >= MAX_BATCH_OPS {
                        resume = Some(iter.key().to_vec());
                        break;
                    }
                    let raw = iter.key();
                    match MvccKey::decode(raw)? {
                        MvccKey::Meta(logical) if logical.first() == Some(&LOCAL_PREFIX) => {
                            // Range-local state (the applied state) stays; transaction
                            // records go: none of their transactions committed at <= ts.
                            if logical.get(1) == Some(&TXN_RECORD_MARKER) {
                                batch.delete(raw);
                                outcome.records_removed += 1;
                            }
                        }
                        MvccKey::Meta(_) => {
                            // An intent: deleting it is the abort resolution (write.rs).
                            batch.delete(raw);
                            outcome.intents_aborted += 1;
                        }
                        MvccKey::Version(_, version_ts) if version_ts > ts => {
                            batch.delete(raw);
                            outcome.versions_removed += 1;
                        }
                        MvccKey::Version(..) => {}
                    }
                    iter.next()?;
                }
            }
            if !batch.is_empty() {
                let cmd = ReplicaCommand::new(self.coord.hlc().now(), batch);
                self.replica.propose(cmd)?;
            }
            match resume {
                Some(key) => start = key,
                None => break,
            }
        }
        tracing::info!(
            ts = %ts,
            versions_removed = outcome.versions_removed,
            intents_aborted = outcome.intents_aborted,
            records_removed = outcome.records_removed,
            "store reverted"
        );
        Ok(outcome)
    }

    /// Opens a store restored from a [`EmbeddedDb::consistent_checkpoint`] image (FR-BKP-001,
    /// FR-BKP-005; module docs): `root` holds `lsm/` and, for an encrypted store,
    /// `keys/registry.enc`, as laid out by the restore, and no Raft log. Under the store lock,
    /// it marks the restore in progress (`RESTORING`, synced), bootstraps the log at `point`'s
    /// applied position, opens the store, moves the HLC past `point.ts` (the restored store may
    /// be opened on a host whose clock is behind the source's), reverts the store to
    /// `point.ts`, flushes, and removes the marker.
    ///
    /// Safe to run again after a crash at any step: with the marker present, a log that does
    /// not reach the image's applied position (the bootstrap batch was lost) is replaced, and a
    /// complete one is kept and replayed (it may hold part of the revert). Without the marker a
    /// store that already has a log is refused: it is not a fresh restore target, and reverting
    /// it would discard what was written since. Removing the marker is the commit point (the
    /// reverted state is flushed before it): a rerun that gets `RGN-1031` after a failure in
    /// the very last step finds a completed restore, which opens with [`EmbeddedDb::open`].
    ///
    /// # Errors
    /// `RGN-3002` if the store is in use; `RGN-1031` if it already has a Raft log and no restore
    /// is in progress; `RGN-4006` for a wrong or missing KEK; log store errors (e.g. an applied
    /// term other than the single voter's); as [`EmbeddedDb::open_with_kek`] and
    /// [`EmbeddedDb::revert_to`].
    #[allow(clippy::too_many_arguments)]
    pub fn open_restored(
        fs: Arc<dyn FileSystem>,
        root: &Path,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        options: EngineOptions,
        kek: Option<Arc<dyn KekProvider>>,
        point: RestorePoint,
    ) -> Result<(Self, RevertOutcome), Error> {
        Self::open_restored_with_replay(fs, root, clock, rng, options, kek, point, &mut |_| Ok(()))
    }

    /// [`EmbeddedDb::open_restored`] for point-in-time recovery (FR-BKP-002, PD-066): `point`
    /// holds the image's applied position and the *target* timestamp T, and `replay` runs on
    /// the opened store before the revert to T. It proposes the archived log entries that
    /// follow the image (each one through [`EmbeddedDb::replay_entry`]), so the store reaches
    /// the state after the last replayed entry and the revert then cuts it back to T.
    ///
    /// Rerunnable like `open_restored`: the replayed entries are ordinary proposals of the
    /// restored log, so a rerun reopens with them applied and `replay` must skip the entries
    /// at or below the store's applied index ([`EmbeddedDb::replay_entry`] does).
    ///
    /// # Errors
    /// As [`EmbeddedDb::open_restored`], and whatever `replay` returns.
    #[allow(clippy::too_many_arguments)]
    pub fn open_restored_with_replay(
        fs: Arc<dyn FileSystem>,
        root: &Path,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        options: EngineOptions,
        kek: Option<Arc<dyn KekProvider>>,
        point: RestorePoint,
        replay: &mut dyn FnMut(&Self) -> Result<(), Error>,
    ) -> Result<(Self, RevertOutcome), Error> {
        let store_lock = StoreLock::acquire(fs.as_ref(), root)?;
        let log_dir = root.join(LOG_DIR);
        let marker = root.join(RESTORE_MARKER);
        let in_progress = exists(fs.as_ref(), &marker)?;
        let segments = log_segments(fs.as_ref(), &log_dir)?;
        if !segments.is_empty() && !in_progress {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                format!(
                    "{} already has a Raft log and no restore in progress: it is not a fresh \
                     restore target",
                    root.display()
                ),
            ));
        }
        // The KEK is checked before anything is written (an encrypted image without it, or
        // under another key, is RGN-4006); the log of an encrypted store is encrypted from its
        // first segment on.
        let store_keys = keys::open_store_keys(&fs, root, kek.clone(), &rng)?;
        let log_options = LogStoreOptions {
            encryption: store_keys.map(|k| k.log),
            ..LogStoreOptions::default()
        };
        if !in_progress {
            write_marker(fs.as_ref(), root, &marker)?;
        }
        // With the marker, the log is this restore's own: one that does not open or does not
        // reach the image is an interrupted bootstrap (nothing else is written to it before the
        // bootstrap batch is durable) and is replaced.
        let complete = !segments.is_empty()
            && LogStore::open(Arc::clone(&fs), &log_dir, log_options.clone())
                .is_ok_and(|log| log.last_index(RANGE_ID) >= point.applied_index);
        if complete {
            // Its key manager must be gone before the store opens its own on the same registry.
            drop(log_options);
        } else {
            // Listed again: the probe above may have created a segment.
            for segment in &log_segments(fs.as_ref(), &log_dir)? {
                fs.remove_file(segment).map_err(|e| io_err(segment, &e))?;
            }
            if exists_dir(fs.as_ref(), &log_dir) {
                fs.sync_dir(&log_dir).map_err(|e| io_err(&log_dir, &e))?;
            }
            LocalReplica::bootstrap_log(
                Arc::clone(&fs),
                &log_dir,
                log_options,
                RANGE_ID,
                point.applied_index,
                point.applied_term,
            )?;
        }
        let marker_fs = Arc::clone(&fs);
        let db = Self::open_locked(
            store_lock,
            fs,
            root,
            clock,
            rng,
            options,
            kek,
            LogStoreOptions::default(),
        )?;
        replay(&db)?;
        // Every later timestamp must be above every version the image keeps (<= ts); the
        // timestamp cache's low-water mark follows, as at any start (§8).
        db.coord.hlc().update(point.ts);
        db.coord.raise_ts_cache_low_water(db.coord.hlc().now());
        let outcome = db.revert_to(point.ts)?;
        // Durable in SSTs before the marker goes: from then on the store is an ordinary one.
        db.flush()?;
        marker_fs
            .remove_file(&marker)
            .map_err(|e| io_err(&marker, &e))?;
        marker_fs.sync_dir(root).map_err(|e| io_err(root, &e))?;
        Ok((db, outcome))
    }

    /// Applies one archived log entry of this store's range during a point-in-time replay
    /// ([`EmbeddedDb::open_restored_with_replay`]; FR-BKP-002, PD-066): `payload` is the entry's
    /// `ReplicaCommand` (command format v1), proposed unchanged, so it lands at the next log
    /// index. Returns `false` without doing anything when `index` is already applied (a rerun,
    /// or an entry inside the restored image).
    ///
    /// # Errors
    /// `RGN-5002` when `index` is not the next one (a gap in the archive) or the payload does
    /// not decode; replica errors.
    pub fn replay_entry(&self, index: u64, payload: &[u8]) -> Result<bool, Error> {
        let applied = self.replica.applied_index();
        if index <= applied {
            return Ok(false);
        }
        if index != applied + 1 {
            return Err(Error::new(
                ErrorCode::StorageCorruption,
                format!(
                    "log entry {index} cannot follow applied entry {applied}: the archived log \
                     has a gap"
                ),
            ));
        }
        let cmd = ReplicaCommand::decode(payload)?;
        let state = self.replica.propose(cmd)?;
        if state.applied_index != index {
            return Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "replayed entry {index} was applied at index {}",
                    state.applied_index
                ),
            ));
        }
        Ok(true)
    }

    /// Closes a fresh timestamp (the write fence, [`EmbeddedDb::close_timestamp`]) and pins the
    /// GC threshold at the *earlier* timestamp `ts`: a snapshot to read the store as it was at
    /// `ts` (point-in-time checks of FR-BKP-002, e.g. comparing a PITR restore with its
    /// source). Every commit at or below `ts` is final once the fence returns.
    ///
    /// # Errors
    /// As [`EmbeddedDb::close_timestamp`]; `RGN-1001` when `ts` is above the closed
    /// timestamp; `RGN-2007` when GC already passed `ts`.
    pub fn pin_snapshot_at(
        &self,
        ts: Timestamp,
        options: &FenceOptions,
    ) -> Result<PinnedSnapshot, Error> {
        let closed = self.close_timestamp(options)?;
        if ts > closed {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("{ts} is above the closed timestamp {closed}"),
            ));
        }
        let pin = self.gc.pin(ts)?;
        Ok(PinnedSnapshot { ts, _pin: pin })
    }

    /// The current MVCC GC threshold (reads below it fail with `RGN-2007`).
    #[must_use]
    pub fn gc_threshold(&self) -> Timestamp {
        self.gc.get()
    }

    /// The oldest timestamp a [`PinnedSnapshot`] of this store protects, if any.
    #[must_use]
    pub fn oldest_gc_pin(&self) -> Option<Timestamp> {
        self.gc.oldest_pin()
    }

    /// MVCC garbage collection up to `threshold` (transaction-management.md §3 "GC";
    /// storage-engine.md §11): advances the GC threshold — never past the oldest
    /// [`PinnedSnapshot`] — and deletes, through the replica, every version no read at or above
    /// the resulting threshold can see; the compaction filter then drops them physically.
    ///
    /// The caller chooses `threshold` below the read timestamp of every running transaction
    /// (the scheduled GC job of a later milestone uses `now - gc.ttl`): a transaction reading
    /// below the threshold fails with the retryable `RGN-2007`.
    ///
    /// # Errors
    /// Storage and replica errors.
    pub fn collect_garbage(&self, threshold: Timestamp) -> Result<GcOutcome, Error> {
        let used = self.gc.advance(threshold);
        let end = [0xFF_u8];
        let mut start: Vec<u8> = Vec::new();
        let mut removed = 0u64;
        loop {
            let (batch, resume) =
                gc_batch_limited(self.replica.engine(), &self.gc, &start, &end, MAX_BATCH_OPS)?;
            if !batch.is_empty() {
                removed += batch.len() as u64;
                let cmd = ReplicaCommand::new(self.coord.hlc().now(), batch);
                self.replica.propose(cmd)?;
            }
            match resume {
                Some(key) => start = key,
                None => break,
            }
        }
        Ok(GcOutcome {
            threshold: used,
            versions_removed: removed,
        })
    }
}

fn unhealthy() -> Error {
    Error::new(
        ErrorCode::Unavailable,
        "the store refuses writes after a failed apply; reopen it before taking a checkpoint",
    )
}

/// The Raft log segments in `log_dir` (none when it is missing).
fn log_segments(fs: &dyn FileSystem, log_dir: &Path) -> Result<Vec<PathBuf>, Error> {
    match fs.read_dir(log_dir) {
        Ok(paths) => Ok(paths
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "rlog"))
            .collect()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(io_err(log_dir, &e)),
    }
}

/// Whether the directory `path` exists.
fn exists_dir(fs: &dyn FileSystem, path: &Path) -> bool {
    fs.read_dir(path).is_ok()
}

/// Refuses an ordinary open of a store whose restore is unfinished (`RESTORING` present):
/// its image may be only partly reverted to T, so serving it would expose versions above T
/// next to reverted ones (no atomic state), and writes to it would be discarded by the revert
/// of the rerun. Only [`EmbeddedDb::open_restored`] (the rerun of the restore) opens it.
pub(super) fn refuse_unfinished_restore(fs: &dyn FileSystem, root: &Path) -> Result<(), Error> {
    if exists(fs, &root.join(RESTORE_MARKER))? {
        return Err(Error::new(
            ErrorCode::Unavailable,
            format!(
                "{} holds an unfinished restore ({RESTORE_MARKER}); rerun the same restore command to finish it before starting the node",
                root.display()
            ),
        )
        .with_detail("reason", "restore_in_progress"));
    }
    Ok(())
}

/// Whether the file `path` exists.
fn exists(fs: &dyn FileSystem, path: &Path) -> Result<bool, Error> {
    match fs.open(path, OpenMode::Read) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_err(path, &e)),
    }
}

/// Creates the (empty) restore marker durably: the file, then its name.
fn write_marker(fs: &dyn FileSystem, root: &Path, marker: &Path) -> Result<(), Error> {
    let file = fs
        .open(marker, OpenMode::Truncate)
        .map_err(|e| io_err(marker, &e))?;
    file.sync_data().map_err(|e| io_err(marker, &e))?;
    fs.sync_dir(root).map_err(|e| io_err(root, &e))
}

fn io_err(path: &Path, e: &io::Error) -> Error {
    Error::new(ErrorCode::Internal, format!("{}: {e}", path.display()))
}
