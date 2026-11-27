// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! A transaction handle: lifecycle, liveness and limits, savepoints and restarts. Reads and
//! writes are in `ops`, waiting on intents in `wait`, commit and rollback in `commit`.
//!
//! # Lifecycle (specifications/transactions.md §3)
//! `Active` → `Committed` (commit) | `Aborted` (rollback, pushed, deadlock victim, limits) |
//! `RestartRequired` (a retryable conflict, `RGN-2001`: the intents stay as locks; only
//! [`Txn::restart`] — next epoch — or [`Txn::rollback`] are accepted) | `Unknown` (`RGN-2006`).
//! After `Aborted`, every operation returns `RGN-2002` with the reason; the first operation that
//! observes a deadlock, timeout or size abort returns `RGN-2005` / `RGN-2003` / `RGN-2004`.
//!
//! # Liveness (§7, §9)
//! Every operation — including each slice spent waiting for another transaction — is a
//! heartbeat of the in-memory state that pushers consult. A transaction idle for longer than
//! `txn.liveness_timeout` is aborted (`RGN-2002`, reason `timeout_pushed`), by a pusher or by
//! itself on its next operation; read-only transactions, which hold no intents, are exempt
//! (PD-049) and bounded by their maximum duration only. [`Txn::heartbeat`] additionally refreshes the heartbeat in the
//! persisted record at most every `txn.heartbeat_interval`, for recovery after a coordinator
//! crash.

mod commit;
mod ops;
mod wait;

use std::{collections::BTreeSet, fmt, sync::Arc, time::Duration};

use rustegon_mvcc::{
    IntentResolution, SeqRange, Timestamp, TxnContext, TxnId, TxnRecord, TxnStatus as RecordStatus,
};

use crate::{
    config::{AccessMode, Isolation, TxnOptions},
    coordinator::Core,
    error::{AbortReason, Result, TxnError},
    read_set::ReadSet,
    registry::{Status, TxnShared},
};

/// Bit position of the restart count in a bumped priority (§5.3: `restart_count << 24`).
const RESTART_SHIFT: u32 = 24;
/// Largest restart count representable below the class bits (6 bits).
const MAX_RESTART_BUMP: u32 = 63;
/// Random low bits of a bumped priority (§5.3 `random_bits`).
const RANDOM_MASK: u32 = (1 << RESTART_SHIFT) - 1;

/// Where the handle is in its lifecycle (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Active,
    RestartRequired,
    Committed(Timestamp),
    Aborted(AbortReason),
    Unknown,
}

/// An interactive transaction on one range (crate docs). Not `Sync`: one thread drives it.
/// Dropping an unfinished transaction rolls it back.
pub struct Txn {
    core: Arc<Core>,
    shared: Arc<TxnShared>,
    options: TxnOptions,
    /// Read timestamp of the current epoch (READ COMMITTED: of the transaction's start; each
    /// statement reads at a fresh one).
    read_ts: Timestamp,
    epoch: u32,
    /// Sequence number of the last write; writes use 1, 2, … (0 = before any write).
    seq: u32,
    /// Sequence ranges rolled back by savepoints (sorted, disjoint).
    ignored: Vec<SeqRange>,
    savepoints: Vec<(String, u32)>,
    /// First written key: the transaction record lives there (§3).
    anchor: Option<Vec<u8>>,
    /// Every key holding (or possibly holding) one of its intents, any epoch.
    writes: BTreeSet<Vec<u8>>,
    write_bytes: u64,
    /// Refresh spans (SERIALIZABLE only).
    reads: ReadSet,
    started: Duration,
    limit: Duration,
    heartbeat_persisted: Duration,
    restarts: u32,
    phase: Phase,
}

impl fmt::Debug for Txn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Txn")
            .field("id", &self.shared.id)
            .field("isolation", &self.options.isolation)
            .field("read_ts", &self.read_ts)
            .field("epoch", &self.epoch)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl Txn {
    pub(crate) fn new(
        core: Arc<Core>,
        shared: Arc<TxnShared>,
        options: TxnOptions,
        restarts: u32,
    ) -> Self {
        let started = core.now();
        let limit = options.timeout.map_or(core.config.max_duration, |t| {
            t.min(core.config.max_duration)
        });
        Self {
            read_ts: shared.start_ts,
            core,
            shared,
            options,
            epoch: 0,
            seq: 0,
            ignored: Vec::new(),
            savepoints: Vec::new(),
            anchor: None,
            writes: BTreeSet::new(),
            write_bytes: 0,
            reads: ReadSet::default(),
            started,
            limit,
            heartbeat_persisted: started,
            restarts,
            phase: Phase::Active,
        }
    }

    /// Transaction id.
    #[must_use]
    pub fn id(&self) -> TxnId {
        self.shared.id
    }

    /// Isolation level.
    #[must_use]
    pub fn isolation(&self) -> Isolation {
        self.options.isolation
    }

    /// Read timestamp of the current epoch.
    #[must_use]
    pub fn read_ts(&self) -> Timestamp {
        self.read_ts
    }

    /// Current provisional commit timestamp (pushed by conflicts).
    #[must_use]
    pub fn write_ts(&self) -> Timestamp {
        self.shared.lock().write_ts.max(self.read_ts)
    }

    /// Current epoch (incremented by [`Txn::restart`]).
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Current numeric priority (§5.3).
    #[must_use]
    pub fn priority(&self) -> u32 {
        self.shared.lock().priority
    }

    /// Whether operations are accepted (not finished, no restart pending).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.phase == Phase::Active
    }

    /// The commit timestamp, once committed.
    #[must_use]
    pub fn commit_ts(&self) -> Option<Timestamp> {
        match self.phase {
            Phase::Committed(ts) => Some(ts),
            _ => None,
        }
    }

    /// Time left before the transaction expires unless it runs another operation or
    /// heartbeat: the smaller of what remains of its maximum duration and, for a read-write
    /// transaction, of `txn.liveness_timeout` since its last sign of life (module docs). Zero
    /// once expired or finished. Interactive clients use it to schedule heartbeats.
    #[must_use]
    pub fn expires_in(&self) -> Duration {
        if !matches!(self.phase, Phase::Active | Phase::RestartRequired) {
            return Duration::ZERO;
        }
        let now = self.core.now();
        let left = (self.started + self.limit).saturating_sub(now);
        if !self.idle_abort_applies() {
            return left;
        }
        let last = self.shared.lock().last_heartbeat;
        left.min((last + self.core.config.liveness_timeout).saturating_sub(now))
    }

    /// Why the next operation will fail as aborted, without running one (and so without
    /// counting as a sign of life): the reason of an abort decided locally or by another
    /// transaction (push, deadlock victim), or an expiry (maximum duration, idleness) not yet
    /// observed. `None` while the transaction is usable or after it committed.
    #[must_use]
    pub fn pending_abort(&self) -> Option<AbortReason> {
        match self.phase {
            Phase::Aborted(reason) => return Some(reason),
            Phase::Active | Phase::RestartRequired => {}
            Phase::Committed(_) | Phase::Unknown => return None,
        }
        let now = self.core.now();
        if now.saturating_sub(self.started) > self.limit {
            return Some(AbortReason::MaxDuration);
        }
        let st = self.shared.lock();
        match st.status {
            Status::Aborted(reason) => Some(reason),
            Status::Pending
                if self.idle_abort_applies()
                    && now.saturating_sub(st.last_heartbeat)
                        > self.core.config.liveness_timeout =>
            {
                Some(AbortReason::TimeoutPushed)
            }
            _ => None,
        }
    }

    /// Whether idleness aborts the transaction (`txn.liveness_timeout`, §5.1, §7). The idle
    /// abort exists so that the intents (locks) of a vanished client or coordinator are
    /// released: a **read-only** transaction never holds intents and nobody waits for it, so
    /// it is bounded by its maximum duration only (PD-049; server-side cursors keep such a
    /// transaction open between `GetMore` calls without heartbeats).
    fn idle_abort_applies(&self) -> bool {
        self.options.access == AccessMode::ReadWrite
    }

    /// Records a sign of life (module docs) and, at most every `txn.heartbeat_interval`,
    /// persists it in the transaction record.
    ///
    /// # Errors
    /// As any operation when the transaction is no longer active; replica errors.
    pub fn heartbeat(&mut self) -> Result<()> {
        self.check_active()?;
        let now = self.core.now();
        let Some(anchor) = self.anchor.clone() else {
            return Ok(());
        };
        if now.saturating_sub(self.heartbeat_persisted) < self.core.config.heartbeat_interval {
            return Ok(());
        }
        let core = Arc::clone(&self.core);
        let _latch = core.write_latch();
        // Under the latch, so that no pusher's ABORTED record can be overwritten: pushers of a
        // registered transaction never write its record, and its own cleanup needs the latch.
        if self.shared.lock().status != Status::Pending {
            return Ok(());
        }
        let mut writer = core.replica.writer();
        writer.put_txn_record(
            &anchor,
            &self.shared.id,
            &self.record(RecordStatus::Pending),
        );
        // A lost heartbeat only matters after a crash, where the transaction is gone anyway.
        core.propose_deferred(writer)?;
        self.heartbeat_persisted = now;
        Ok(())
    }

    /// Sets savepoint `name` at the current sequence number (§10). A name may be reused; the
    /// newest savepoint of that name wins.
    ///
    /// # Errors
    /// As any operation when the transaction is no longer active.
    pub fn savepoint(&mut self, name: &str) -> Result<()> {
        self.check_active()?;
        self.savepoints.push((name.to_owned(), self.seq));
        Ok(())
    }

    /// Rolls back every write made after savepoint `name` (their sequence numbers join
    /// `ignored_seq_ranges`, §10); the savepoint itself remains. Rolled-back writes stay intents
    /// (locks) but are invisible to the transaction and never committed.
    ///
    /// # Errors
    /// [`TxnError::InvalidArgument`] for an unknown savepoint; as any operation when the
    /// transaction is no longer active.
    pub fn rollback_to_savepoint(&mut self, name: &str) -> Result<()> {
        self.check_active()?;
        let index = self.savepoint_index(name)?;
        let since = self.savepoints[index].1;
        if self.seq > since {
            add_ignored(
                &mut self.ignored,
                SeqRange {
                    start: since + 1,
                    end: self.seq,
                },
            );
        }
        self.savepoints.truncate(index + 1);
        Ok(())
    }

    /// Releases savepoint `name` and every later one; their writes stay.
    ///
    /// # Errors
    /// [`TxnError::InvalidArgument`] for an unknown savepoint; as any operation when the
    /// transaction is no longer active.
    pub fn release_savepoint(&mut self, name: &str) -> Result<()> {
        self.check_active()?;
        let index = self.savepoint_index(name)?;
        self.savepoints.truncate(index);
        Ok(())
    }

    fn savepoint_index(&self, name: &str) -> Result<usize> {
        self.savepoints
            .iter()
            .rposition(|(n, _)| n == name)
            .ok_or_else(|| TxnError::InvalidArgument(format!("no savepoint named {name:?}")))
    }

    /// Restarts the transaction in its next epoch (§3, §5.3): a new read timestamp at least its
    /// pushed write timestamp, no reads, no savepoints, a raised priority. Its intents stay as
    /// locks and are overwritten or discarded by the new epoch (older-epoch intents never
    /// commit).
    ///
    /// # Errors
    /// The abort error if the transaction was aborted meanwhile;
    /// [`TxnError::InvalidArgument`] after commit.
    pub fn restart(&mut self) -> Result<()> {
        match self.phase {
            Phase::Active | Phase::RestartRequired => {}
            Phase::Aborted(reason) => return Err(TxnError::Aborted { reason }),
            Phase::Committed(_) | Phase::Unknown => {
                return Err(TxnError::InvalidArgument(
                    "restart of a finished transaction".into(),
                ));
            }
        }
        self.phase = Phase::Active;
        self.check_active()?;
        let (priority, restarts) = self.bumped_priority();
        let now = self.core.hlc.now();
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| TxnError::Internal("transaction epoch overflow".into()))?;
        {
            let mut st = self.shared.lock();
            st.epoch = epoch;
            st.priority = st.priority.max(priority);
            st.write_ts = st.write_ts.max(now);
            self.read_ts = st.write_ts;
        }
        self.epoch = epoch;
        self.restarts = restarts;
        self.reads.clear();
        self.savepoints.clear();
        self.ignored.clear();
        self.write_bytes = self.writes.iter().map(|k| k.len() as u64).sum();
        Ok(())
    }

    /// The priority after one more restart and the new restart count (§5.3:
    /// `max(priority, random_bits | restart_count << 24)`, under the class bits).
    pub(crate) fn bumped_priority(&self) -> (u32, u32) {
        let restarts = self.restarts.saturating_add(1);
        let random =
            u32::try_from(self.core.rng.next_u64() & u64::from(RANDOM_MASK)).unwrap_or(RANDOM_MASK);
        let bump = self.options.priority.base()
            | (restarts.min(MAX_RESTART_BUMP) << RESTART_SHIFT)
            | random;
        (self.priority().max(bump), restarts)
    }

    /// Checks that the transaction may run an operation and records the heartbeat: phase,
    /// maximum duration, abort by others, idleness (module docs).
    fn check_active(&mut self) -> Result<()> {
        match self.phase {
            Phase::Active => {}
            Phase::RestartRequired => {
                return Err(TxnError::Conflict(
                    "the transaction must be restarted or rolled back".into(),
                ));
            }
            Phase::Aborted(reason) => return Err(TxnError::Aborted { reason }),
            Phase::Committed(_) => {
                return Err(TxnError::InvalidArgument(
                    "the transaction is already committed".into(),
                ));
            }
            Phase::Unknown => {
                return Err(TxnError::InvalidArgument(
                    "the transaction's commit outcome is unknown".into(),
                ));
            }
        }
        let now = self.core.now();
        if now.saturating_sub(self.started) > self.limit {
            return Err(self.abort(AbortReason::MaxDuration));
        }
        let idle_abort = self.idle_abort_applies();
        let aborted = {
            let mut st = self.shared.lock();
            match st.status {
                Status::Aborted(reason) => Some(reason),
                Status::Pending
                    if idle_abort
                        && now.saturating_sub(st.last_heartbeat)
                            > self.core.config.liveness_timeout =>
                {
                    self.shared
                        .set_status(&mut st, Status::Aborted(AbortReason::TimeoutPushed));
                    Some(AbortReason::TimeoutPushed)
                }
                _ => {
                    st.last_heartbeat = now;
                    None
                }
            }
        };
        match aborted {
            Some(reason) => Err(self.abort(reason)),
            None => Ok(()),
        }
    }

    fn check_writable(&self) -> Result<()> {
        match self.options.access {
            AccessMode::ReadWrite => Ok(()),
            AccessMode::ReadOnly => Err(TxnError::InvalidArgument(
                "write in a read-only transaction".into(),
            )),
        }
    }

    /// Aborts (cleaning up) and returns the error the operation that observed it reports.
    fn abort(&mut self, reason: AbortReason) -> TxnError {
        let reason = self.finish_aborted(reason);
        match reason {
            AbortReason::MaxDuration => TxnError::Timeout { limit: self.limit },
            AbortReason::Deadlock => TxnError::Deadlock,
            reason => TxnError::Aborted { reason },
        }
    }

    /// Marks the transaction aborted (keeping the reason of an abort decided by someone else),
    /// removes its intents and record in one command, and unregisters it. Must not be called
    /// under the range latch. If the cleanup fails the transaction stays registered as
    /// aborted, so whoever meets its intents resolves them at once.
    fn finish_aborted(&mut self, reason: AbortReason) -> AbortReason {
        let reason = {
            let mut st = self.shared.lock();
            if let Status::Aborted(existing) = st.status {
                existing
            } else {
                self.shared.set_status(&mut st, Status::Aborted(reason));
                reason
            }
        };
        self.phase = Phase::Aborted(reason);
        self.core.stats.aborted(reason);
        match self.remove_own_intents() {
            Ok(()) => self.core.registry.remove(&self.shared.id),
            Err(e) => {
                tracing::warn!(error = %e, "transaction cleanup failed; intents resolved lazily");
            }
        }
        reason
    }

    fn remove_own_intents(&mut self) -> Result<()> {
        if self.writes.is_empty() {
            return Ok(());
        }
        let core = Arc::clone(&self.core);
        let _latch = core.write_latch();
        let mut writer = core.replica.writer();
        let abort = IntentResolution::Abort {
            txn_id: self.shared.id,
        };
        for key in &self.writes {
            writer.resolve_intent(key, &abort)?;
        }
        if let Some(anchor) = &self.anchor {
            writer.delete_txn_record(anchor, &self.shared.id);
        }
        core.propose(writer)?;
        self.writes.clear();
        Ok(())
    }

    fn finish_committed(&mut self, commit_ts: Timestamp) {
        self.phase = Phase::Committed(commit_ts);
        self.core.stats.committed();
        self.core.registry.remove(&self.shared.id);
    }

    /// The reader context of the transaction at its current sequence number.
    fn ctx(&self) -> TxnContext {
        TxnContext {
            txn_id: self.shared.id,
            epoch: self.epoch,
            seq: self.seq,
            ignored_seq_ranges: self.ignored.clone(),
        }
    }

    /// The transaction record in `status` with the current timestamps.
    fn record(&self, status: RecordStatus) -> TxnRecord {
        let (write_ts, priority) = {
            let st = self.shared.lock();
            (st.write_ts.max(self.read_ts), st.priority)
        };
        TxnRecord {
            status,
            write_ts,
            read_ts: self.read_ts,
            priority,
            heartbeat_ts: self.core.hlc.now(),
            in_flight_writes: Vec::new(),
            lock_spans: Vec::new(),
        }
    }
}

impl Drop for Txn {
    fn drop(&mut self) {
        if matches!(self.phase, Phase::Active | Phase::RestartRequired) {
            self.finish_aborted(AbortReason::Rollback);
        }
    }
}

/// Adds `range` to the sorted, disjoint `ranges`, merging overlapping and adjacent ones (the
/// `ignored_seq_ranges` invariant of `TxnMeta`).
fn add_ignored(ranges: &mut Vec<SeqRange>, range: SeqRange) {
    ranges.push(range);
    ranges.sort_unstable();
    let mut merged: Vec<SeqRange> = Vec::with_capacity(ranges.len());
    for r in ranges.drain(..) {
        match merged.last_mut() {
            Some(last) if r.start <= last.end.saturating_add(1) => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }
    *ranges = merged;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignored_ranges_stay_sorted_and_disjoint() {
        let mut r = Vec::new();
        add_ignored(&mut r, SeqRange { start: 5, end: 6 });
        add_ignored(&mut r, SeqRange { start: 2, end: 3 });
        assert_eq!(
            r,
            [SeqRange { start: 2, end: 3 }, SeqRange { start: 5, end: 6 }]
        );
        add_ignored(&mut r, SeqRange { start: 4, end: 4 });
        assert_eq!(r, [SeqRange { start: 2, end: 6 }]);
        add_ignored(&mut r, SeqRange { start: 3, end: 9 });
        assert_eq!(r, [SeqRange { start: 2, end: 9 }]);
    }
}
