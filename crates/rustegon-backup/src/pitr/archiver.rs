// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The log archiver (FR-BKP-004, PD-066, PD-088): copies every sealed Raft log segment of a
//! running store to the archive, then raises the log store's archive floor so the segment may
//! leave the local disk.
//!
//! # One pass ([`PitrArchiver::pass`])
//! 1. With `roll` (every `backup.pitr.segment_interval_secs`): the write fence closes a
//!    timestamp (`EmbeddedDb::close_timestamp`, bounded and cancellable), then the active segment
//!    is sealed (`force_roll_log`). The newest sealed segment then holds every entry a reader at
//!    the closed timestamp needs: it is recorded as that segment's `closed_ts` (PD-088). A
//!    failed fence only loses the `closed_ts`; the roll still happens.
//! 2. Every sealed segment above the floor, in id order: read through the standalone reader
//!    (validates every record and decrypts v2 payloads; yields the index and timestamp ranges),
//!    copied with its BLAKE3 (`segments/<id>.rlog`), its wrapped DEK (`<id>.key.json`) for v2.
//! 3. `index.json` is rewritten (atomic object) with the new segments, `closed_ts` values and
//!    continuity breaks; then the local state (`<store>/pitr-archive.json`) and the floor are
//!    raised (`Release`) and a deletion pass releases the copied segments. The floor never
//!    passes a segment whose copy and index entry are not durable, so a crash at any point
//!    loses no segment that has left the local disk; a segment copied twice is overwritten
//!    with the same bytes.
//! 4. **Bounded lag** (PD-066): if the sealed segments above the floor exceed
//!    `max_unarchived_bytes` (the destination has been failing), the floor jumps to the newest
//!    sealed segment, a [`ContinuityBreak`] is recorded (local state at once, `index.json` at the
//!    next successful write), `rustegon_backup_pitr_continuity_breaks_total` increases and an
//!    error is logged. Writes are never blocked: the archiver only ever reads the log.
//!
//! The archiver is synchronous (log store and destinations are); `rustegond` runs passes on the
//! blocking pool.

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_engine::{
    EmbeddedDb,
    embedded::{CancelHandle, FenceOptions, RANGE_ID, SealedSegment, SegmentKey, read_segment},
};
use rustegon_mvcc::{ReplicaCommand, Timestamp};
use rustegon_sim_api::{Clock, FileSystem, OpenMode, Rng};
use rustegon_storage::encryption::KekProvider;
use serde::{Deserialize, Serialize};

use super::{
    ARCHIVE_FORMAT_VERSION, ArchiveIndex, ArchivedSegment, ContinuityBreak, KeySidecar, STATE_FILE,
    hlc, index_key, load_index, segment_key, sidecar_key, to_json, valid_timeline,
};
use crate::{
    dest::Destination,
    fsutil::{ensure_dir, read_small, rfc3339_utc, write_atomic},
};

/// Largest state file accepted.
const MAX_STATE_BYTES: u64 = 16 << 20;
/// Bound of the write fence before a timed roll: shorter than a backup's, so a long
/// transaction delays a roll at most this long (the roll then happens without `closed_ts`).
pub const ARCHIVE_FENCE_TIMEOUT: Duration = Duration::from_secs(30);

/// Tunables of a [`PitrArchiver`].
#[derive(Debug, Clone)]
pub struct ArchiverConfig {
    /// `backup.pitr.max_unarchived_bytes` (module docs, step 4).
    pub max_unarchived_bytes: u64,
    /// `txn.max_duration` of the store, recorded in the index (PD-066 replay margin).
    pub txn_max_duration: Duration,
    /// Bound of the write fence before a timed roll.
    pub fence_timeout: Duration,
}

impl Default for ArchiverConfig {
    fn default() -> Self {
        Self {
            max_unarchived_bytes: crate::settings::DEFAULT_MAX_UNARCHIVED_BYTES,
            txn_max_duration: rustegon_engine::TxnConfig::default().max_duration,
            fence_timeout: ARCHIVE_FENCE_TIMEOUT,
        }
    }
}

/// The archiver's local state (`<store>/pitr-archive.json`). A reader refuses unknown fields
/// and versions, so a newer layout is never misread.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiverState {
    /// Always 1.
    version: u32,
    /// The store's timeline.
    timeline: String,
    /// Highest segment id at or below which everything is archived or given up (= the floor).
    archived_through: u64,
    /// Breaks not yet written to `index.json` (the destination was down).
    pending_breaks: Vec<ContinuityBreak>,
}

fn write_state(fs: &dyn FileSystem, path: &Path, state: &ArchiverState) -> Result<(), Error> {
    write_atomic(fs, path, &super::to_json(state)?)
}

/// Counters of an archiver, read by the server's `/metrics` (backup-restore.md, PITR).
#[derive(Debug, Default)]
pub struct PitrMetrics {
    /// Segments archived since start.
    pub archived_segments: AtomicU64,
    /// Bytes archived since start.
    pub archived_bytes: AtomicU64,
    /// Bytes of sealed segments not yet archived (after the last pass).
    pub unarchived_bytes: AtomicU64,
    /// Continuity breaks since start (module docs, step 4): the alert condition.
    pub continuity_breaks: AtomicU64,
    /// Passes that failed (destination errors) since start.
    pub failed_passes: AtomicU64,
    /// Wall time (ns) of the newest entry archived, 0 before the first.
    pub last_archived_wall_ns: AtomicU64,
}

/// The archiver before the store opens: its state is loaded (or a new timeline created and
/// persisted) and its floor initialised, to be passed to `EmbeddedDb::open_with_log_options`.
pub struct PreparedArchiver {
    fs: Arc<dyn FileSystem>,
    state_path: PathBuf,
    state: ArchiverState,
    floor: Arc<AtomicU64>,
}

impl std::fmt::Debug for PreparedArchiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedArchiver")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl PreparedArchiver {
    /// Loads `<store_dir>/pitr-archive.json`, or creates it with a fresh timeline (durably,
    /// before any backup can record the timeline).
    ///
    /// # Errors
    /// `RGN-5002` for an unreadable state file; `RGN-5007` for another version; I/O errors.
    pub fn load(fs: Arc<dyn FileSystem>, store_dir: &Path, rng: &dyn Rng) -> Result<Self, Error> {
        let state_path = store_dir.join(STATE_FILE);
        let state = if let Some(bytes) = read_small(fs.as_ref(), &state_path, MAX_STATE_BYTES)? {
            {
                let state: ArchiverState = serde_json::from_slice(&bytes).map_err(|e| {
                    Error::new(
                        ErrorCode::StorageCorruption,
                        format!("{}: {e}", state_path.display()),
                    )
                })?;
                if state.version != 1 {
                    return Err(Error::new(
                        ErrorCode::VersionIncompatible,
                        format!(
                            "{}: archiver state version {}",
                            state_path.display(),
                            state.version
                        ),
                    ));
                }
                if !valid_timeline(&state.timeline) {
                    return Err(Error::new(
                        ErrorCode::StorageCorruption,
                        format!("{}: malformed timeline", state_path.display()),
                    ));
                }
                state
            }
        } else {
            {
                let mut bytes = [0u8; 8];
                rng.fill_bytes(&mut bytes);
                let state = ArchiverState {
                    version: 1,
                    timeline: super::hex(&bytes),
                    archived_through: 0,
                    pending_breaks: Vec::new(),
                };
                ensure_dir(fs.as_ref(), store_dir)?;
                write_state(fs.as_ref(), &state_path, &state)?;
                tracing::info!(timeline = %state.timeline, "new PITR timeline");
                state
            }
        };
        let floor = Arc::new(AtomicU64::new(state.archived_through));
        Ok(Self {
            fs,
            state_path,
            state,
            floor,
        })
    }

    /// The store's timeline (recorded in backup manifests).
    #[must_use]
    pub fn timeline(&self) -> &str {
        &self.state.timeline
    }

    /// The archive floor for `LogStoreOptions::archive_floor`.
    #[must_use]
    pub fn floor(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.floor)
    }

    /// Starts archiving the opened store `db` (opened with [`PreparedArchiver::floor`]) to
    /// `dest`; `kek` is the store's KEK (needed to read encrypted segments).
    #[must_use]
    pub fn start(
        self,
        db: Arc<EmbeddedDb>,
        clock: Arc<dyn Clock>,
        dest: Arc<dyn Destination>,
        kek: Option<Arc<dyn KekProvider>>,
        config: ArchiverConfig,
    ) -> PitrArchiver {
        PitrArchiver {
            db,
            fs: self.fs,
            clock,
            dest,
            kek,
            config,
            state_path: self.state_path,
            state: self.state,
            floor: self.floor,
            index: None,
            closed: BTreeMap::new(),
            cancel: CancelHandle::new(),
            metrics: Arc::new(PitrMetrics::default()),
        }
    }
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassOutcome {
    /// Segments copied in this pass.
    pub archived: usize,
    /// Segment sealed by the timed roll, if any.
    pub rolled: Option<u64>,
    /// Bytes of sealed segments still above the floor.
    pub unarchived_bytes: u64,
    /// Whether this pass broke continuity (module docs, step 4).
    pub broke_continuity: bool,
}

/// The running archiver (module docs).
pub struct PitrArchiver {
    db: Arc<EmbeddedDb>,
    fs: Arc<dyn FileSystem>,
    clock: Arc<dyn Clock>,
    dest: Arc<dyn Destination>,
    kek: Option<Arc<dyn KekProvider>>,
    config: ArchiverConfig,
    state_path: PathBuf,
    state: ArchiverState,
    floor: Arc<AtomicU64>,
    /// The destination's index, loaded at the first successful read.
    index: Option<ArchiveIndex>,
    /// Closed timestamps of sealed segments not yet in the index (PD-088).
    closed: BTreeMap<u64, Timestamp>,
    cancel: CancelHandle,
    metrics: Arc<PitrMetrics>,
}

impl std::fmt::Debug for PitrArchiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PitrArchiver")
            .field("destination", &self.dest.describe())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// The scan of one local segment (module docs, step 2).
struct Scan {
    first_index: Option<u64>,
    last_index: Option<u64>,
    min_ts: Option<Timestamp>,
    max_ts: Option<Timestamp>,
}

/// [`io::Read`] over a sim-api file that hashes what it reads.
struct HashingReader<'a> {
    file: &'a dyn rustegon_sim_api::File,
    offset: u64,
    size: u64,
    hasher: blake3::Hasher,
}

impl io::Read for HashingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.size - self.offset;
        let n = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        if n == 0 {
            return Ok(0);
        }
        self.file.read_exact_at(&mut buf[..n], self.offset)?;
        self.hasher.update(&buf[..n]);
        self.offset += n as u64;
        Ok(n)
    }
}

impl PitrArchiver {
    /// The timeline.
    #[must_use]
    pub fn timeline(&self) -> &str {
        &self.state.timeline
    }

    /// The counters.
    #[must_use]
    pub fn metrics(&self) -> Arc<PitrMetrics> {
        Arc::clone(&self.metrics)
    }

    /// A handle that cancels a write fence in progress (shutdown).
    #[must_use]
    pub fn cancel_handle(&self) -> CancelHandle {
        self.cancel.clone()
    }

    /// The destination's index as last written (tests, diagnostics).
    #[must_use]
    pub fn index(&self) -> Option<&ArchiveIndex> {
        self.index.as_ref()
    }

    /// One pass (module docs); `roll` = seal the active segment first.
    ///
    /// # Errors
    /// The first destination or log error; the segments archived before it are recorded and
    /// the continuity check (step 4) runs regardless.
    pub fn pass(&mut self, roll: bool) -> Result<PassOutcome, Error> {
        let mut outcome = PassOutcome::default();
        let result = self.pass_inner(roll, &mut outcome);
        if result.is_err() {
            self.metrics.failed_passes.fetch_add(1, Ordering::Relaxed);
        }
        let sealed = self.db.replica().sealed_log_segments();
        let floor = self.floor.load(Ordering::Acquire);
        let mut unarchived: u64 = sealed.iter().filter(|s| s.id > floor).map(|s| s.size).sum();
        if unarchived > self.config.max_unarchived_bytes
            && let Some(newest) = sealed.iter().map(|s| s.id).max()
        {
            self.break_continuity(floor + 1, newest, "max_unarchived_bytes")?;
            outcome.broke_continuity = true;
            unarchived = 0;
        }
        self.metrics
            .unarchived_bytes
            .store(unarchived, Ordering::Relaxed);
        outcome.unarchived_bytes = unarchived;
        result.map(|()| outcome)
    }

    fn pass_inner(&mut self, roll: bool, outcome: &mut PassOutcome) -> Result<(), Error> {
        if roll {
            let options = FenceOptions {
                timeout: self.config.fence_timeout,
                cancel: Some(self.cancel.clone()),
                cancel_check: None,
            };
            let closed = match self.db.close_timestamp(&options) {
                Ok(ts) => Some(ts),
                Err(e) => {
                    tracing::warn!(code = %e.code(), error = %e, "PITR roll without a closed timestamp");
                    None
                }
            };
            outcome.rolled = self.db.replica().force_roll_log().map_err(Error::from)?;
            // Every entry up to the fence is now in a sealed segment: the newest one on disk,
            // or (idle store, the sealed ones already archived and purged) the newest archived.
            let newest = self
                .db
                .replica()
                .sealed_log_segments()
                .iter()
                .map(|s| s.id)
                .max()
                .unwrap_or(0)
                .max(self.state.archived_through);
            if let Some(ts) = closed
                && newest > 0
            {
                self.closed.insert(newest, ts);
            }
        }
        let floor = self.floor.load(Ordering::Acquire);
        let mut todo: Vec<SealedSegment> = self
            .db
            .replica()
            .sealed_log_segments()
            .into_iter()
            .filter(|s| s.id > floor)
            .collect();
        todo.sort_by_key(|s| s.id);
        if todo.is_empty() && self.closed.is_empty() && self.state.pending_breaks.is_empty() {
            return Ok(());
        }
        self.ensure_index()?;
        let mut archived_through = self.state.archived_through;
        let mut result = Ok(());
        let mut changed = false;
        for segment in &todo {
            if archived_through > 0 && segment.id > archived_through + 1 {
                // Segments vanished without being archived (archiving was off, or the local
                // log was replaced): never replay across them.
                self.record_break(archived_through + 1, segment.id - 1, "segments_missing")?;
            }
            match self.archive_segment(segment) {
                Ok(()) => {
                    archived_through = segment.id;
                    outcome.archived += 1;
                    changed = true;
                }
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        changed |= self.apply_closed();
        changed |= !self.state.pending_breaks.is_empty();
        if changed {
            self.write_index()?;
        }
        if archived_through > self.state.archived_through {
            self.raise_floor(archived_through)?;
        }
        result
    }

    /// Loads (or starts) the destination's index of this timeline.
    fn ensure_index(&mut self) -> Result<(), Error> {
        if self.index.is_none() {
            let index = load_index(self.dest.as_ref(), &self.state.timeline)?;
            if index.is_none() && self.state.archived_through > 0 {
                tracing::warn!(
                    timeline = %self.state.timeline,
                    destination = %self.dest.describe(),
                    "the PITR archive has no index for this timeline although segments were \
                     archived before (destination changed or wiped); restores cannot reach \
                     back past the segments archived from now on"
                );
            }
            self.index = Some(index.unwrap_or_else(|| ArchiveIndex {
                format_version: ARCHIVE_FORMAT_VERSION,
                timeline: self.state.timeline.clone(),
                txn_max_duration_ms:
                    u64::try_from(self.config.txn_max_duration.as_millis()).unwrap_or(u64::MAX),
                segments: Vec::new(),
                breaks: Vec::new(),
            }));
        }
        Ok(())
    }

    /// Reads, copies and indexes one sealed segment (module docs, step 2).
    fn archive_segment(&mut self, segment: &SealedSegment) -> Result<(), Error> {
        let timeline = self.state.timeline.clone();
        let key = if segment.encrypted {
            let wrapped = self
                .db
                .replica()
                .log_segment_key(segment.id)
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::KeyUnavailable,
                        format!("no DEK for encrypted log segment {}", segment.id),
                    )
                })?;
            let kek = self.kek.clone().ok_or_else(|| {
                Error::new(
                    ErrorCode::KeyUnavailable,
                    "the log is encrypted but the archiver has no KEK",
                )
            })?;
            Some(SegmentKey { kek, wrapped })
        } else {
            None
        };
        let scan = scan_segment(self.fs.as_ref(), &segment.path, key.as_ref())?;
        if let Some(key) = &key {
            let sidecar = KeySidecar {
                format_version: ARCHIVE_FORMAT_VERSION,
                segment: segment.id,
                kek_id: key.wrapped.kek_id.as_str().to_owned(),
                wrapped_dek: super::hex(&key.wrapped.bytes),
            };
            self.dest
                .put_bytes(&sidecar_key(&timeline, segment.id), &to_json(&sidecar)?)?;
        }
        let file = self
            .fs
            .open(&segment.path, OpenMode::Read)
            .map_err(|e| crate::fsutil::io_err("open", &segment.path, &e))?;
        let size = file
            .size()
            .map_err(|e| crate::fsutil::io_err("stat", &segment.path, &e))?;
        let mut reader = HashingReader {
            file: file.as_ref(),
            offset: 0,
            size,
            hasher: blake3::Hasher::new(),
        };
        self.dest
            .put_reader(&segment_key(&timeline, segment.id), size, &mut reader)?;
        let entry = ArchivedSegment {
            id: segment.id,
            size,
            blake3: reader.hasher.finalize().to_hex().to_string(),
            encrypted: segment.encrypted,
            first_index: scan.first_index,
            last_index: scan.last_index,
            min_ts: scan.min_ts.map(hlc),
            max_ts: scan.max_ts.map(hlc),
            closed_ts: self.closed.remove(&segment.id).map(hlc),
            archived_at: rfc3339_utc(self.clock.wall())?,
        };
        if let Some(ts) = scan.max_ts {
            self.metrics
                .last_archived_wall_ns
                .fetch_max(ts.wall, Ordering::Relaxed);
        }
        self.metrics
            .archived_segments
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .archived_bytes
            .fetch_add(size, Ordering::Relaxed);
        if let Some(index) = &mut self.index {
            index.segments.retain(|s| s.id != segment.id);
            index.segments.push(entry);
            index.segments.sort_by_key(|s| s.id);
        }
        Ok(())
    }

    /// Moves closed timestamps of already-indexed segments into the index; drops those of
    /// segments that will never be indexed. Returns whether the index changed.
    fn apply_closed(&mut self) -> bool {
        let Some(index) = &mut self.index else {
            return false;
        };
        let mut changed = false;
        let floor = self.state.archived_through;
        self.closed.retain(|id, ts| {
            if let Some(s) = index.segments.iter_mut().find(|s| s.id == *id) {
                if s.closed_ts.is_none_or(|c| c < hlc(*ts)) {
                    s.closed_ts = Some(hlc(*ts));
                    changed = true;
                }
                return false;
            }
            // Given up by a continuity break: never archived.
            *id > floor
        });
        changed
    }

    fn write_index(&mut self) -> Result<(), Error> {
        let Some(index) = &mut self.index else {
            return Ok(());
        };
        let pending = self.state.pending_breaks.len();
        for b in &self.state.pending_breaks {
            if !index.breaks.contains(b) {
                index.breaks.push(b.clone());
            }
        }
        self.dest
            .put_bytes(&index_key(&self.state.timeline), &to_json(&*index)?)?;
        if pending > 0 {
            self.state.pending_breaks.clear();
            write_state(self.fs.as_ref(), &self.state_path, &self.state)?;
        }
        Ok(())
    }

    /// Persists `archived_through`, then raises the floor and lets the log delete what it no
    /// longer needs (module docs, step 3).
    fn raise_floor(&mut self, archived_through: u64) -> Result<(), Error> {
        self.state.archived_through = archived_through;
        write_state(self.fs.as_ref(), &self.state_path, &self.state)?;
        self.floor.store(archived_through, Ordering::Release);
        self.db.replica().purge_flushed().map_err(Error::from)?;
        Ok(())
    }

    fn record_break(&mut self, first: u64, last: u64, reason: &str) -> Result<(), Error> {
        let at = rfc3339_utc(self.clock.wall())?;
        self.state.pending_breaks.push(ContinuityBreak {
            first_segment: first,
            last_segment: last,
            detected_at: at,
            reason: reason.to_owned(),
        });
        write_state(self.fs.as_ref(), &self.state_path, &self.state)?;
        self.metrics
            .continuity_breaks
            .fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            timeline = %self.state.timeline,
            first_segment = first,
            last_segment = last,
            reason,
            "PITR continuity broken: log segments were not archived; point-in-time restores \
             cannot cross them (take a new base backup)"
        );
        Ok(())
    }

    /// Gives up segments `first..=last` (module docs, step 4).
    fn break_continuity(&mut self, first: u64, last: u64, reason: &str) -> Result<(), Error> {
        self.record_break(first, last, reason)?;
        self.closed.retain(|id, _| *id > last);
        self.raise_floor(last)
    }
}

/// Validates a local sealed segment and collects its index and timestamp ranges.
fn scan_segment(fs: &dyn FileSystem, path: &Path, key: Option<&SegmentKey>) -> Result<Scan, Error> {
    let mut scan = Scan {
        first_index: None,
        last_index: None,
        min_ts: None,
        max_ts: None,
    };
    for entry in read_segment(fs, path, key)? {
        let entry = entry?;
        if entry.group != RANGE_ID {
            continue;
        }
        let ts = ReplicaCommand::decode(&entry.payload)?.ts;
        scan.first_index = Some(scan.first_index.map_or(entry.index, |f| f.min(entry.index)));
        scan.last_index = Some(scan.last_index.map_or(entry.index, |l| l.max(entry.index)));
        scan.min_ts = Some(scan.min_ts.map_or(ts, |m| m.min(ts)));
        scan.max_ts = Some(scan.max_ts.map_or(ts, |m| m.max(ts)));
    }
    Ok(scan)
}
