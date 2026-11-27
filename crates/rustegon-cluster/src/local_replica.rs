// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Raft-less single-voter replica of one range (M2; development-phases.md M2, FR-TXN-001,
//! TC-TXN-004): implements [`Replica`] over the node's Raft log store and LSM engine exactly as
//! the M5 Raft replica will, minus consensus.
//!
//! # Durability (ADR-009, storage-engine.md §9)
//! The LSM has no WAL; the Raft log is the write-ahead log.
//! - **Propose** = apply the entry (its operations and the new [`RangeAppliedState`] in one
//!   atomic engine batch, [`apply_command`]), then append it (and the hard state committing it)
//!   to the log store in one batch with one `fdatasync` ("Group commit" below). For a single
//!   voter, durable *is* committed (the voter is the majority). `Ok` is returned only after the
//!   sync. Until then the entry is in a memtable only, and no memtable is flushed before the
//!   entries it holds are in the log, so a crash leaves exactly what the log holds to the next
//!   open's replay.
//! - **Open** = open the log store, read `RangeAppliedState` from the engine (after a crash: the
//!   state of the last *flushed* command, because unflushed memtables are gone), and replay every
//!   entry after it, in order, through the same apply path. As the applied state travels in the
//!   same batch as the data, the engine holds exactly the commands up to it and replay neither
//!   repeats nor skips one.
//! - **Purge**: an entry may leave the log only once the engine has *flushed* the batch that
//!   applied it, otherwise a crash would lose it from both. Each apply records `(index, seqno)`
//!   of its engine batch; the engine flushes memtables in seqno order and reports the watermark
//!   as [`LsmEngine::flushed_seqno`] (persisted in its MANIFEST together with the SSTs), so every
//!   entry whose seqno is `<= flushed_seqno` is durable in SSTs and purgeable. The entries
//!   applied before an open are covered by the engine's last seqno at that open. Purges ride
//!   along in the next proposal's log batch (no extra `fsync`) or are written by
//!   [`LocalReplica::purge_flushed`]. (replication.md §2 also bounds purging by followers' match
//!   indexes; a single voter has none.)
//!
//! # Group commit (ADR-038, ADR-040)
//! Every proposal applies its command first and queues the payload in `Inner::pending`; a log
//! write takes everything pending and makes it durable in one record with one `fdatasync`.
//! - [`Replica::propose_deferred`] (ADR-038) returns without that write: the transaction layer
//!   uses it for the intents and record heartbeats of uncommitted transactions, so a
//!   transaction costs one `fsync` (its commit) instead of one per write.
//! - [`Replica::propose_unsynced`] (ADR-040) returns without it too, and
//!   [`Replica::sync_through`] waits for it later: the transaction layer applies a commit under
//!   its range latch and syncs after releasing it. `sync_through` takes the log lock, which
//!   the write in progress holds across its `fdatasync`, so it waits for that write, and then
//!   either finds its index durable or writes everything applied meanwhile: commits that
//!   arrive during one sync share the next. [`Replica::unsynced_index`] tells readers what
//!   they must wait for before their result leaves.
//! - [`Replica::propose`] is `propose_unsynced` followed by `sync_through`.
//!
//! What keeps the rules above true:
//! - the log file never holds an unsynced record (pending entries are in memory only), so the
//!   log format and its torn-tail recovery are unchanged;
//! - a crash loses the pending entries together with the memtables that hold their effects, so
//!   the engine never ends up ahead of the log: the engine's flush barrier
//!   ([`LsmEngine::set_flush_barrier`]) writes the pending entries before any memtable reaches
//!   an SST, and [`LocalReplica::checkpoint`], [`LocalReplica::force_roll_log`] and dropping the
//!   replica write them too;
//! - a log write that fails poisons the replica: the engine holds commands the log may lack,
//!   so nothing is flushed or acknowledged any more and `unsynced_index` keeps naming them;
//! - pending entries are bounded by [`MAX_PENDING_BYTES`].
//!
//! # Backup hooks (FR-BKP-002/004, PD-066)
//! Point-in-time recovery archives the log segments: [`LocalReplica::force_roll_log`],
//! [`LocalReplica::sealed_log_segments`] and [`LocalReplica::log_segment_key`] pass the log
//! store's hooks through (an archive floor travels in [`LogStoreOptions::archive_floor`]), and
//! [`LocalReplica::bootstrap_log`] gives a physically restored engine a fresh log positioned at
//! its applied state, which is what [`LocalReplica::open`]'s coverage check requires.
//!
//! # Concurrency
//! Lock order `log → inner → applied`. `inner` serialises proposals: a command is applied and
//! queued under it, so entries are applied in index order and `applied_index + 1` is always the
//! next index; no I/O happens under it. `log` serialises log writes and is held across their
//! `fdatasync`; a write takes the pending entries under `inner` and releases it before writing,
//! so proposals and reads go on while the log syncs. Only a checkpoint, a forced log roll and
//! the close hold both across a write. `applied` is a copy of the applied state for readers,
//! updated under `inner`, so [`Replica::applied_state`] never waits for an `fsync`. Reads go to
//! the engine directly and see whole batches only (the engine publishes a batch atomically).

use std::{
    collections::VecDeque,
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use rustegon_mvcc::{
    GcThreshold, MvccError, RangeAppliedState, Replica, ReplicaCommand, ReplicaError,
    replica::{apply_command, read_applied_state},
};
use rustegon_raft::{HardState, LogBatch, LogStore, LogStoreError, LogStoreOptions, SealedSegment};
use rustegon_sim_api::FileSystem;
use rustegon_storage::{LsmEngine, SeqNo, StorageError, encryption::WrappedKey};
use tracing::info;

/// Raft term of every entry of a local replica: a single voter never holds an election.
pub const LOCAL_TERM: u64 = 1;
/// Replica id the single voter votes for (itself) in the persisted hard state.
pub const LOCAL_REPLICA_ID: u64 = 1;
/// Payload bytes of applied proposals kept in memory before a proposal writes them itself
/// (module docs, "Group commit"): bounds memory and the size of one log record when a
/// transaction writes many intents before it commits.
pub const MAX_PENDING_BYTES: usize = 1 << 20;
/// Entries read from the log per replay step (bounds memory during recovery).
const REPLAY_CHUNK: u64 = 256;
/// Attempts of [`LocalReplica::checkpoint`] to capture a fully flushed engine without holding
/// the proposal lock during a flush; the last one flushes under it.
pub const CHECKPOINT_FLUSH_ATTEMPTS: u32 = 4;

/// A checkpoint of a local replica's engine and the applied state inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaCheckpoint {
    /// What the storage checkpoint holds (seqno, files, encryption).
    pub info: rustegon_storage::CheckpointInfo,
    /// The applied state of the last command in the image (index, term, `max_ts`).
    pub applied: RangeAppliedState,
}

/// Where a [`LocalReplica`] keeps its data.
pub struct LocalReplicaConfig {
    /// File system of the store.
    pub fs: Arc<dyn FileSystem>,
    /// Directory of the Raft log store (`<data_dir>/raft-log`, storage-engine.md §2).
    pub log_dir: PathBuf,
    /// Log store options.
    pub log_options: LogStoreOptions,
    /// The store's engine (opened by the caller with the MVCC options).
    pub engine: Arc<LsmEngine>,
    /// The store's GC threshold (the one installed in the engine's compaction filter).
    pub gc: Option<Arc<GcThreshold>>,
    /// The range (= Raft group id in the log store).
    pub range_id: u64,
}

impl fmt::Debug for LocalReplicaConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalReplicaConfig")
            .field("log_dir", &self.log_dir)
            .field("log_options", &self.log_options)
            .field("range_id", &self.range_id)
            .finish_non_exhaustive()
    }
}

/// State changed only by proposals and purges (module docs, "Concurrency").
struct Inner {
    /// Applied state; equals the copy in `LocalReplica::applied` and the persisted one.
    state: RangeAppliedState,
    /// `(index, engine seqno)` of applied entries not yet known to be flushed, ascending.
    unflushed: VecDeque<(u64, SeqNo)>,
    /// Largest index known to be applied and flushed (purgeable up to it).
    flushed_index: u64,
    /// `(index, payload)` of applied proposals not yet in the log, ascending and contiguous up
    /// to `state.applied_index` (module docs, "Group commit").
    pending: Vec<(u64, Vec<u8>)>,
    pending_bytes: usize,
}

/// What the replica shares with the engine's flush barrier (module docs, "Concurrency").
struct Shared {
    range_id: u64,
    /// Taken before `inner` and held across every log write with its `fdatasync`.
    log: Mutex<LogStore>,
    inner: Mutex<Inner>,
    /// Set when a log write failed after its entries were applied, or an apply failed: the
    /// engine and the log may disagree until reopen. An atomic, because health probes must not
    /// wait for I/O.
    poisoned: AtomicBool,
    /// Index up to which the log is synced.
    durable: AtomicU64,
    /// Index of the newest proposal whose observers wait for its sync
    /// ([`Replica::unsynced_index`]); stored before that proposal is applied.
    awaited: AtomicU64,
    /// Set while [`LocalReplica::checkpoint`] flushes the engine under both locks, after
    /// writing the pending entries itself: the flush barrier must not take them again then.
    /// Any other flush that skips the barrier in that window is covered too (nothing is
    /// pending and no proposal runs while `inner` is held).
    flushing_under_inner: AtomicBool,
}

impl Shared {
    fn poisoned_error(&self) -> ReplicaError {
        ReplicaError::Poisoned {
            range_id: self.range_id,
        }
    }

    // A panic while holding either lock may have left an entry applied but neither queued nor
    // logged: treat it like a failed log write.
    fn lock_log(&self) -> Result<MutexGuard<'_, LogStore>, ReplicaError> {
        self.log.lock().map_err(|_| self.poisoned_error())
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, Inner>, ReplicaError> {
        self.inner.lock().map_err(|_| self.poisoned_error())
    }

    fn check_usable(&self) -> Result<(), ReplicaError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(self.poisoned_error());
        }
        Ok(())
    }

    /// Under both locks: moves the pending entries, and a due purge, into a log batch. Returns
    /// it with the last index it makes durable; `None` when nothing is pending.
    fn take_pending(
        &self,
        engine: &LsmEngine,
        log: &LogStore,
        inner: &mut Inner,
    ) -> Result<Option<(LogBatch, u64)>, ReplicaError> {
        let group = self.range_id;
        let (Some(&(first, _)), Some(&(last, _))) = (inner.pending.first(), inner.pending.last())
        else {
            return Ok(None);
        };
        // Proposals apply in index order and every log write takes all of them, so the log
        // never runs ahead of the applied entries and never has a gap.
        let next = log.last_index(group) + 1;
        if next != first {
            self.poisoned.store(true, Ordering::Release);
            return Err(corruption(format!(
                "range {group}: next log index {next} but the oldest applied entry not in the \
                 log is {first}"
            )));
        }
        let mut batch = LogBatch::new();
        add_purge(engine, log, inner, group, &mut batch);
        for (index, payload) in inner.pending.drain(..) {
            batch.append(group, index, LOCAL_TERM, payload);
        }
        inner.pending_bytes = 0;
        batch.set_hard_state(group, hard_state(last));
        Ok(Some((batch, last)))
    }

    /// Writes a batch of [`Self::take_pending`] with one sync. On `Err` the engine holds
    /// commands the log may lack: the replica is poisoned.
    fn write(&self, log: &mut LogStore, batch: &LogBatch, last: u64) -> Result<(), ReplicaError> {
        if let Err(e) = log.write(batch) {
            self.poisoned.store(true, Ordering::Release);
            return Err(log_err(e));
        }
        self.durable.store(last, Ordering::Release);
        Ok(())
    }

    /// Writes the pending entries while both locks are held, so that no proposal is applied
    /// between the write and what the caller does next.
    fn write_pending(
        &self,
        engine: &LsmEngine,
        log: &mut LogStore,
        inner: &mut Inner,
    ) -> Result<(), ReplicaError> {
        match self.take_pending(engine, log, inner)? {
            Some((batch, last)) => self.write(log, &batch, last),
            None => Ok(()),
        }
    }

    /// The group commit (module docs): makes every proposal applied so far durable. With
    /// `index`, does nothing when that index already is.
    fn sync(&self, engine: &LsmEngine, index: Option<u64>) -> Result<(), ReplicaError> {
        let durable = |i| self.durable.load(Ordering::Acquire) >= i;
        if index.is_some_and(durable) {
            return Ok(());
        }
        // Waits for the write in progress, which may have carried `index`.
        let mut log = self.lock_log()?;
        if index.is_some_and(durable) {
            return Ok(());
        }
        self.check_usable()?;
        // `inner` is released before the write: proposals and reads go on while the log syncs.
        let taken = self.take_pending(engine, &log, &mut *self.lock_inner()?)?;
        if let Some((batch, last)) = taken {
            self.write(&mut log, &batch, last)?;
        }
        match index {
            Some(i) if !durable(i) => Err(ReplicaError::Mvcc(MvccError::InvalidArgument(format!(
                "range {}: log index {i} was never applied",
                self.range_id
            )))),
            _ => Ok(()),
        }
    }
}

/// The hard state of a single voter that committed up to `commit`.
fn hard_state(commit: u64) -> HardState {
    HardState {
        term: LOCAL_TERM,
        vote: LOCAL_REPLICA_ID,
        commit,
    }
}

/// A single-voter replica of one range (module docs).
pub struct LocalReplica {
    range_id: u64,
    engine: Arc<LsmEngine>,
    gc: Option<Arc<GcThreshold>>,
    /// Shared with the engine's flush barrier (weakly).
    shared: Arc<Shared>,
    applied: Mutex<RangeAppliedState>,
}

impl Drop for LocalReplica {
    fn drop(&mut self) {
        // The engine may outlive the replica and flush later: leave nothing applied but
        // unlogged behind. Best effort: after a failure the next open refuses an engine that is
        // ahead of its log instead of losing the difference silently.
        self.engine.set_flush_barrier(None);
        if let (Ok(mut log), Ok(mut inner)) = (self.shared.log.lock(), self.shared.inner.lock())
            && self.shared.check_usable().is_ok()
            && let Err(e) = self
                .shared
                .write_pending(&self.engine, &mut log, &mut inner)
        {
            tracing::error!(
                range_id = self.range_id,
                error = %e,
                "applied log entries lost at close"
            );
        }
    }
}

impl fmt::Debug for LocalReplica {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalReplica")
            .field("range_id", &self.range_id)
            .field("applied", &self.applied_state())
            .finish_non_exhaustive()
    }
}

fn log_err(e: LogStoreError) -> ReplicaError {
    ReplicaError::Log(e.into())
}

fn corruption(msg: String) -> ReplicaError {
    ReplicaError::Mvcc(MvccError::Corruption(msg))
}

impl LocalReplica {
    /// Opens the replica: opens the log store, reads the applied state from the engine and
    /// replays the log entries after it (module docs, "Durability").
    ///
    /// # Errors
    /// [`ReplicaError::Log`] for log store errors (including log corruption);
    /// [`MvccError::Corruption`] when the log and the engine cannot belong together (entries
    /// the engine needs were purged, the engine is ahead of the log, terms differ) or an entry
    /// does not decode; storage errors from the replay.
    pub fn open(config: LocalReplicaConfig) -> Result<Self, ReplicaError> {
        let LocalReplicaConfig {
            fs,
            log_dir,
            log_options,
            engine,
            gc,
            range_id,
        } = config;
        let log = LogStore::open(fs, &log_dir, log_options).map_err(log_err)?;
        let persisted = read_applied_state(&engine, range_id)?;
        check_log_covers(&log, &persisted)?;
        // Everything applied before this open is in the engine at seqnos <= its last seqno; it
        // becomes purgeable once that seqno is flushed (immediately after a crash, where the
        // engine holds only flushed data).
        let mut unflushed = VecDeque::new();
        unflushed.push_back((persisted.applied_index, engine.last_seqno()));
        let mut inner = Inner {
            state: persisted,
            unflushed,
            flushed_index: 0,
            pending: Vec::new(),
            pending_bytes: 0,
        };
        let replayed = replay(&engine, &log, &mut inner)?;
        info!(
            range_id,
            applied_index = inner.state.applied_index,
            replayed,
            "local replica opened"
        );
        let state = inner.state;
        let shared = Arc::new(Shared {
            range_id,
            log: Mutex::new(log),
            inner: Mutex::new(inner),
            poisoned: AtomicBool::new(false),
            // Everything applied at an open came from the log.
            durable: AtomicU64::new(state.applied_index),
            awaited: AtomicU64::new(0),
            flushing_under_inner: AtomicBool::new(false),
        });
        // shortcut: one barrier per engine, so one local replica per engine (the M2 single
        // range); ranges sharing an engine (M5) need a barrier that covers all of them.
        engine.set_flush_barrier(Some(flush_barrier(
            Arc::downgrade(&shared),
            Arc::downgrade(&engine),
        )));
        Ok(Self {
            range_id,
            engine,
            gc,
            shared,
            applied: Mutex::new(state),
        })
    }

    /// Applies `cmd` and queues its payload for the next log write (module docs, "Group
    /// commit"). `awaited`: whoever sees the command must wait for its sync.
    fn apply_pending(
        &self,
        cmd: ReplicaCommand,
        awaited: bool,
    ) -> Result<RangeAppliedState, ReplicaError> {
        // Validated and encoded before anything is applied: a refused command leaves no trace.
        let payload = cmd.encode()?;
        let (state, full) = {
            let mut inner = self.shared.lock_inner()?;
            self.shared.check_usable()?;
            let index = inner.state.applied_index + 1;
            if awaited {
                // Before the command is visible, so that whoever sees it finds it here too.
                self.shared.awaited.store(index, Ordering::Release);
            }
            let state = self.apply(&mut inner, index, cmd)?;
            inner.pending_bytes += payload.len();
            inner.pending.push((index, payload));
            (state, inner.pending_bytes >= MAX_PENDING_BYTES)
        };
        if full {
            self.shared.sync(&self.engine, None)?;
        }
        Ok(state)
    }

    /// Applies `cmd` at `index` under `inner`; a failure poisons the replica.
    fn apply(
        &self,
        inner: &mut Inner,
        index: u64,
        cmd: ReplicaCommand,
    ) -> Result<RangeAppliedState, ReplicaError> {
        match apply_command(&self.engine, &inner.state, index, LOCAL_TERM, cmd) {
            Ok((state, seqno)) => {
                inner.state = state;
                inner.unflushed.push_back((index, seqno));
                self.publish(state);
                Ok(state)
            }
            Err(e) => {
                // An engine that refuses a batch is not one to go on with: refuse writes, and
                // keep failing whoever waits for `index`, until the store is reopened.
                self.shared.poisoned.store(true, Ordering::Release);
                Err(e.into())
            }
        }
    }

    fn publish(&self, state: RangeAppliedState) {
        *self.applied.lock().unwrap_or_else(PoisonError::into_inner) = state;
    }

    /// Purges the log entries whose application the engine has flushed (module docs, "Purge");
    /// returns the first index still in the log. Call it after engine flushes; proposals also
    /// purge on the way.
    ///
    /// # Errors
    /// [`ReplicaError::Log`] when the purge cannot be written (the entries stay).
    pub fn purge_flushed(&self) -> Result<u64, ReplicaError> {
        let mut log = self.shared.lock_log()?;
        let mut batch = LogBatch::new();
        add_purge(
            &self.engine,
            &log,
            &mut *self.shared.lock_inner()?,
            self.range_id,
            &mut batch,
        );
        if batch.is_empty() {
            // Nothing new to purge, but an archive floor raised since the last write may have
            // released segments (`LogStoreOptions::archive_floor`, PD-066).
            log.delete_obsolete();
        } else {
            log.write(&batch).map_err(log_err)?;
        }
        Ok(log.first_index(self.range_id))
    }

    /// Seals the log's active segment now ([`LogStore::force_roll`]; FR-BKP-004, PD-066): the
    /// PITR timer calls it so that the archiver can copy the latest entries. Returns the id of
    /// the sealed segment, `None` if no batch was written since the last roll. Waits for a
    /// running log write (both hold the log lock across their I/O).
    ///
    /// # Errors
    /// [`ReplicaError::Log`] when the new segment cannot be created (the log store is then
    /// poisoned and proposals fail until the store is reopened).
    pub fn force_roll_log(&self) -> Result<Option<u64>, ReplicaError> {
        let mut log = self.shared.lock_log()?;
        let mut inner = self.shared.lock_inner()?;
        // The sealed segment is what the archiver copies: it must hold every applied entry.
        self.shared
            .write_pending(&self.engine, &mut log, &mut inner)?;
        log.force_roll().map_err(log_err)
    }

    /// The log's sealed segments ([`LogStore::sealed_segments`]): the files an archiver may
    /// copy. The list is a snapshot; segments at or below the archive floor may be deleted
    /// right after it is taken.
    #[must_use]
    pub fn sealed_log_segments(&self) -> Vec<SealedSegment> {
        self.log().sealed_segments()
    }

    /// The log store for a read; waits for a log write in progress.
    fn log(&self) -> MutexGuard<'_, LogStore> {
        // Reads of the log's in-memory index: a panic elsewhere does not make them wrong.
        self.shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The wrapped DEK of log segment `id` ([`LogStore::segment_key`]), to archive with an
    /// encrypted segment; `None` for a plaintext log or segment.
    #[must_use]
    pub fn log_segment_key(&self, id: u64) -> Option<WrappedKey> {
        self.log().segment_key(id)
    }

    /// Creates the log of a restored store (FR-BKP-002, PD-066): an empty log of `range_id`
    /// positioned after `(applied_index, applied_term)`, the applied state of the restored
    /// engine, so that [`LocalReplica::open`] passes its coverage check and the next proposal
    /// gets index `applied_index + 1`. A physical restore copies SSTs but not the log (the
    /// flushed engine already holds every applied command), and the old log, if any, belongs to
    /// another history: it must be removed first.
    ///
    /// The persisted hard state commits `applied_index` with the local replica's term and vote,
    /// as a proposal would have.
    ///
    /// # Errors
    /// [`ReplicaError::Log`] with an invalid-argument error when `log_dir` already holds
    /// segments (never overwrite a log) or `applied_term` is not [`LOCAL_TERM`] while
    /// `applied_index > 0` (the single voter appends at that term, which must not be below the
    /// last entry's); log store and I/O errors.
    pub fn bootstrap_log(
        fs: Arc<dyn FileSystem>,
        log_dir: &Path,
        log_options: LogStoreOptions,
        range_id: u64,
        applied_index: u64,
        applied_term: u64,
    ) -> Result<(), ReplicaError> {
        let invalid = |m: String| log_err(LogStoreError::InvalidArgument(m));
        if applied_index > 0 && applied_term != LOCAL_TERM {
            return Err(invalid(format!(
                "cannot bootstrap a local replica log at term {applied_term}: a single voter \
                 writes term {LOCAL_TERM}"
            )));
        }
        match fs.read_dir(log_dir) {
            Ok(paths) => {
                if paths
                    .iter()
                    .any(|p| p.extension().is_some_and(|e| e == "rlog"))
                {
                    return Err(invalid(format!(
                        "{} already holds raft log segments; remove the old log before \
                         bootstrapping a restored one",
                        log_dir.display()
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(log_err(e.into())),
        }
        let mut log = LogStore::open(fs, log_dir, log_options).map_err(log_err)?;
        if applied_index == 0 {
            // An empty log already continues an engine that applied nothing.
            return Ok(());
        }
        let mut batch = LogBatch::new();
        batch
            .install_snapshot(range_id, applied_index, applied_term)
            .set_hard_state(
                range_id,
                HardState {
                    term: LOCAL_TERM,
                    vote: LOCAL_REPLICA_ID,
                    commit: applied_index,
                },
            );
        // One synced batch: the bootstrapped log is either complete or absent after a crash
        // (an absent one fails `open` loudly, "the log ends at 0", and can be bootstrapped
        // again).
        log.write(&batch).map_err(log_err)
    }

    /// Creates a storage checkpoint of the engine in the empty directory `target` and returns
    /// it with the **exact** applied state it contains (FR-BKP-001/003, PD-063): the image holds
    /// precisely the commands up to `applied.applied_index`, which is what
    /// [`LocalReplica::bootstrap_log`] needs to give the restored engine a log.
    ///
    /// Why exact: the engine is flushed without blocking proposals, then — under the log lock
    /// and `inner`, so no command is being applied — the checkpoint source is captured only if
    /// every applied write
    /// is in SSTs (`flushed_seqno >= last_seqno`); the applied state read under the same lock is
    /// then the one inside the image. If commands were applied in between, the attempt is
    /// repeated; after [`CHECKPOINT_FLUSH_ATTEMPTS`] the last one flushes under the lock, which
    /// delays proposals by one flush of what was written since the previous one. The SSTs are
    /// linked (or copied) after the lock is released, while proposals continue.
    ///
    /// # Errors
    /// Storage errors (flush, MANIFEST, I/O; a non-empty `target`), a poisoned replica. A
    /// failed checkpoint may leave a partial `target` that the caller removes.
    pub fn checkpoint(&self, target: &Path) -> Result<ReplicaCheckpoint, ReplicaError> {
        let mut attempt = 1;
        loop {
            let last_try = attempt >= CHECKPOINT_FLUSH_ATTEMPTS;
            if !last_try {
                self.engine.flush().map_err(MvccError::from)?;
            }
            let captured = {
                let mut log = self.shared.lock_log()?;
                let mut inner = self.shared.lock_inner()?;
                self.shared.check_usable()?;
                // The image must not hold a command the log lacks (module docs, "Group
                // commit"); with nothing pending the barrier has nothing to do, and it could
                // not take the locks again.
                self.shared
                    .write_pending(&self.engine, &mut log, &mut inner)?;
                if last_try {
                    let flushing = &self.shared.flushing_under_inner;
                    flushing.store(true, Ordering::Release);
                    let flushed = self.engine.flush();
                    flushing.store(false, Ordering::Release);
                    flushed.map_err(MvccError::from)?;
                }
                let source = self.engine.capture_checkpoint().map_err(MvccError::from)?;
                (source.flushed_seqno >= self.engine.last_seqno()).then_some((source, inner.state))
            };
            if let Some((source, applied)) = captured {
                let info = self
                    .engine
                    .write_checkpoint(&source, target)
                    .map_err(MvccError::from)?;
                return Ok(ReplicaCheckpoint { info, applied });
            }
            if last_try {
                // A flush under the lock left writes unflushed: an engine invariant broke.
                return Err(corruption(format!(
                    "range {}: checkpoint flush left applied writes in memtables",
                    self.range_id
                )));
            }
            attempt += 1;
        }
    }

    /// Whether the replica still accepts proposals: `false` once a log write failed after its
    /// entries were applied or an apply failed (or a panic poisoned its state), until the
    /// store is reopened. The readiness probe reports such a node as unhealthy (FR-OPS-003,
    /// PD-059).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        // `Acquire` pairs with the `Release` stores at the failures; a panic under a lock
        // (lock poisoning) also counts as unhealthy, like `Shared::lock_inner`.
        !self.shared.poisoned.load(Ordering::Acquire)
            && !self.shared.inner.is_poisoned()
            && !self.shared.log.is_poisoned()
    }

    /// First and last index of the range's entries still in the log (`first > last`: empty).
    /// Applied entries not yet written are not counted.
    #[must_use]
    pub fn log_bounds(&self) -> (u64, u64) {
        let log = self.log();
        (
            log.first_index(self.range_id),
            log.last_index(self.range_id),
        )
    }
}

/// The engine's flush barrier of a local replica (module docs, "Group commit"): writes the
/// pending entries before a memtable holding their effects is flushed. It refuses to flush a
/// poisoned replica, whose log may lack applied commands.
fn flush_barrier(shared: Weak<Shared>, engine: Weak<LsmEngine>) -> rustegon_storage::FlushBarrier {
    Arc::new(move || {
        let (Some(shared), Some(engine)) = (shared.upgrade(), engine.upgrade()) else {
            return Ok(());
        };
        if shared.flushing_under_inner.load(Ordering::Acquire) {
            return Ok(());
        }
        shared.sync(&engine, None).map_err(|e| {
            StorageError::Io(std::io::Error::other(format!(
                "range {}: writing applied log entries before a flush: {e}",
                shared.range_id
            )))
        })
    })
}

/// Checks that the log can continue the engine's applied state: no entry the engine lacks was
/// purged, the engine is not ahead of the log, and the applied entry has the recorded term.
fn check_log_covers(log: &LogStore, state: &RangeAppliedState) -> Result<(), ReplicaError> {
    let group = state.range_id;
    let (first, last) = (log.first_index(group), log.last_index(group));
    if state.applied_index.saturating_add(1) < first {
        return Err(corruption(format!(
            "range {group}: log starts at {first} but the engine applied only up to {}",
            state.applied_index
        )));
    }
    if state.applied_index > last {
        return Err(corruption(format!(
            "range {group}: engine applied {} but the log ends at {last}",
            state.applied_index
        )));
    }
    if state.applied_index > 0 {
        let term = log.term(group, state.applied_index).map_err(log_err)?;
        if term != state.applied_term {
            return Err(corruption(format!(
                "range {group}: applied entry {} has term {term} in the log, {} in the engine",
                state.applied_index, state.applied_term
            )));
        }
    }
    Ok(())
}

/// Applies every logged entry after the applied state, in order; returns how many. A single
/// voter's durable entries are all committed (each was logged with the hard state committing
/// it), so replay runs to the end of the log.
fn replay(engine: &LsmEngine, log: &LogStore, inner: &mut Inner) -> Result<u64, ReplicaError> {
    let group = inner.state.range_id;
    let last = log.last_index(group);
    let mut replayed = 0;
    let mut next = inner.state.applied_index + 1;
    while next <= last {
        let hi = last.min(next + REPLAY_CHUNK - 1) + 1;
        for entry in log.entries(group, next, hi).map_err(log_err)? {
            let cmd = ReplicaCommand::decode(&entry.payload)?;
            let (state, seqno) = apply_command(engine, &inner.state, entry.index, entry.term, cmd)?;
            inner.state = state;
            inner.unflushed.push_back((entry.index, seqno));
            replayed += 1;
        }
        next = hi;
    }
    Ok(replayed)
}

/// Adds a purge of the flushed applied prefix to `batch` when it advanced (module docs).
fn add_purge(
    engine: &LsmEngine,
    log: &LogStore,
    inner: &mut Inner,
    group: u64,
    batch: &mut LogBatch,
) {
    let flushed = engine.flushed_seqno();
    while let Some(&(index, seqno)) = inner.unflushed.front() {
        if seqno > flushed {
            break;
        }
        inner.flushed_index = inner.flushed_index.max(index);
        inner.unflushed.pop_front();
    }
    if inner.flushed_index >= log.first_index(group) {
        batch.purge(group, inner.flushed_index);
    }
}

impl Replica for LocalReplica {
    fn range_id(&self) -> u64 {
        self.range_id
    }

    fn engine(&self) -> &LsmEngine {
        &self.engine
    }

    fn gc_threshold(&self) -> Option<&GcThreshold> {
        self.gc.as_deref()
    }

    fn propose(&self, cmd: ReplicaCommand) -> Result<RangeAppliedState, ReplicaError> {
        let state = self.propose_unsynced(cmd)?;
        // One fsync, shared with whatever else was applied by then: durable = committed for
        // the single voter (module docs).
        self.sync_through(state.applied_index)?;
        Ok(state)
    }

    fn propose_deferred(&self, cmd: ReplicaCommand) -> Result<RangeAppliedState, ReplicaError> {
        self.apply_pending(cmd, false)
    }

    fn propose_unsynced(&self, cmd: ReplicaCommand) -> Result<RangeAppliedState, ReplicaError> {
        self.apply_pending(cmd, true)
    }

    fn sync_through(&self, index: u64) -> Result<(), ReplicaError> {
        self.shared.sync(&self.engine, Some(index))
    }

    fn unsynced_index(&self) -> Option<u64> {
        let awaited = self.shared.awaited.load(Ordering::Acquire);
        (awaited > self.shared.durable.load(Ordering::Acquire)).then_some(awaited)
    }

    fn applied_state(&self) -> RangeAppliedState {
        *self.applied.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
