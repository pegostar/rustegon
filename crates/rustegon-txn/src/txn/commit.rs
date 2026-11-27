// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! One-phase commit of a single-range transaction and rollback (transaction-management.md §4.1,
//! §6, §10).
//!
//! # Commit (1PC)
//! Under the exclusive range latch:
//! 1. `Pending → Committing` under the transaction's state mutex: from here pushers wait, so the
//!    commit timestamp (`max(read_ts, write_ts)`, including every timestamp push received) is
//!    final.
//! 2. SERIALIZABLE with `commit_ts > read_ts`: **read refresh** — every refresh span is re-read
//!    with the uncertainty window `(read_ts, commit_ts]`, which makes the MVCC reader report
//!    any version committed in that window, and any other transaction's intent at or below
//!    `commit_ts`. Either fails the refresh (`RGN-2001`, restart). On success the refreshed
//!    spans are registered in the timestamp cache at `commit_ts`: the transaction now counts as
//!    having read them there, so no later writer may slip below its commit.
//! 3. One command resolves every intent at `commit_ts` (visible provisional value per the
//!    savepoint rules; older-epoch intents are discarded) and deletes the transaction record:
//!    the record is not needed once no intent refers to it (§7). The command is atomic, so
//!    after a crash either all writes are committed or none (the remaining intents then point
//!    to a `PENDING` record and are aborted once it expires). It is applied without its log
//!    sync (`Replica::propose_unsynced`, ADR-040).
//! 4. `Committed` is published, the HLC is advanced past `commit_ts` (later transactions start
//!    above it: real-time order on a single node), and the latch is released.
//!
//! Then, without the latch, the commit waits for its log record (`Replica::sync_through`: one
//! `fsync` shared by the commits waiting at that moment) and only then is acknowledged.
//! Others may have read its writes meanwhile; their results wait for the same sync (the read
//! rule, `settle.rs`).
//!
//! A failure before the proposal reverts the state to `Pending`; a failed proposal or sync is
//! ambiguous (`RGN-2006`): the commit applies at the next replay iff it was logged.

use std::sync::Arc;

use rustegon_mvcc::{
    IntentResolution, MvccError, RangeAppliedState, ReadOptions, ResolveOutcome, Timestamp,
    TxnContext,
};

use super::{Phase, Txn};
use crate::{
    config::Isolation,
    coordinator::CommitInfo,
    error::{AbortReason, Result, TxnError},
    registry::Status,
};

/// Why a commit attempt failed.
enum CommitFailure {
    /// The transaction is no longer pending (aborted by someone).
    Inactive,
    /// The read refresh failed: restart required.
    Refresh(String),
    /// The proposal failed: outcome unknown.
    Ambiguous(rustegon_mvcc::ReplicaError),
    /// Any other error before the proposal: nothing happened.
    Other(TxnError),
}

impl Txn {
    /// Commits the transaction (§10): returns the commit timestamp.
    ///
    /// # Errors
    /// `RGN-2001` if the read refresh failed (the transaction must restart or roll back),
    /// `RGN-2002` if it was aborted, `RGN-2003` past its maximum duration, `RGN-2006` if the
    /// outcome is unknown, MVCC errors.
    pub fn commit(&mut self) -> Result<CommitInfo> {
        let result = self.commit_unsettled();
        match result {
            // A read-write commit waited for its own log record, which is newer than anything
            // the transaction read; an unknown outcome must stay one.
            Ok(_) if !self.writes.is_empty() => result,
            Err(TxnError::CommitOutcomeUnknown(_)) => result,
            // Read-only, or failed: what it read, and a conflict it reports, are observations.
            _ => self.core.settled(result),
        }
    }

    fn commit_unsettled(&mut self) -> Result<CommitInfo> {
        self.check_active()?;
        if self.writes.is_empty() {
            // Read-only: nothing to make durable; it is serialized at its read timestamp
            // (READ COMMITTED: at the last statement's).
            let commit_ts = self.write_ts();
            self.finish_committed(commit_ts);
            return Ok(CommitInfo { commit_ts });
        }
        let core = Arc::clone(&self.core);
        let outcome = {
            let _latch = core.write_latch();
            self.commit_locked()
        };
        // Group commit (ADR-040): the latch is free while the log syncs.
        let outcome = outcome.and_then(|(commit_ts, applied)| {
            self.sync_commit(applied)?;
            Ok(commit_ts)
        });
        match outcome {
            Ok(commit_ts) => {
                self.finish_committed(commit_ts);
                Ok(CommitInfo { commit_ts })
            }
            Err(CommitFailure::Inactive) => {
                self.check_active()?;
                Err(TxnError::Internal(
                    "transaction neither pending nor aborted".into(),
                ))
            }
            Err(CommitFailure::Refresh(reason)) => {
                self.phase = Phase::RestartRequired;
                self.core
                    .stats
                    .restarted(crate::stats::RestartReason::Refresh);
                Err(TxnError::Conflict(reason))
            }
            Err(CommitFailure::Ambiguous(e)) => {
                // Stays registered as `Ambiguous`: its intents must not be resolved by anyone
                // until the log decides (replay at the next open).
                self.phase = Phase::Unknown;
                Err(TxnError::CommitOutcomeUnknown(e))
            }
            Err(CommitFailure::Other(e)) => Err(e),
        }
    }

    /// Rolls the transaction back (§10): idempotent; its intents and record are removed.
    ///
    /// # Errors
    /// [`TxnError::InvalidArgument`] after a commit or with an unknown commit outcome.
    pub fn rollback(&mut self) -> Result<()> {
        let result = match self.phase {
            Phase::Active | Phase::RestartRequired => {
                self.finish_aborted(AbortReason::Rollback);
                Ok(())
            }
            Phase::Aborted(_) => Ok(()),
            Phase::Committed(_) => Err(TxnError::InvalidArgument(
                "rollback of a committed transaction".into(),
            )),
            Phase::Unknown => Err(TxnError::InvalidArgument(
                "rollback of a transaction whose commit outcome is unknown".into(),
            )),
        };
        self.core.settled(result)
    }

    /// The second half of a commit (module docs): waits, without the latch, until the commit
    /// command applied as `applied` is durable. After a failure the log decides.
    fn sync_commit(&self, applied: Option<RangeAppliedState>) -> Result<(), CommitFailure> {
        let Some(state) = applied else {
            return Ok(());
        };
        self.core
            .replica
            .sync_through(state.applied_index)
            .map_err(|e| {
                let mut st = self.shared.lock();
                self.shared.set_status(&mut st, Status::Ambiguous);
                CommitFailure::Ambiguous(e)
            })
    }

    /// Steps 1–4 of the module docs; must hold the exclusive latch. Returns the commit
    /// timestamp and the applied state of the commit command, to wait for.
    fn commit_locked(&mut self) -> Result<(Timestamp, Option<RangeAppliedState>), CommitFailure> {
        let commit_ts = {
            let mut st = self.shared.lock();
            if st.status != Status::Pending {
                return Err(CommitFailure::Inactive);
            }
            self.shared.set_status(&mut st, Status::Committing);
            st.write_ts.max(self.read_ts)
        };
        let result = self.evaluate_commit(commit_ts);
        let mut st = self.shared.lock();
        match &result {
            Ok(_) => {
                let status = Status::Committed {
                    commit_ts,
                    epoch: self.epoch,
                    ignored: self.ignored.clone(),
                };
                self.shared.set_status(&mut st, status);
                self.core.hlc.update(commit_ts);
            }
            Err(CommitFailure::Ambiguous(_)) => self.shared.set_status(&mut st, Status::Ambiguous),
            Err(_) => self.shared.set_status(&mut st, Status::Pending),
        }
        result.map(|applied| (commit_ts, applied))
    }

    fn evaluate_commit(
        &mut self,
        commit_ts: Timestamp,
    ) -> Result<Option<RangeAppliedState>, CommitFailure> {
        if self.options.isolation == Isolation::Serializable && commit_ts > self.read_ts {
            self.refresh(commit_ts)?;
            let mut cache = self.core.ts_cache();
            for key in self.reads.points() {
                cache.record_point(key, commit_ts, Some(self.shared.id));
            }
            for span in self.reads.spans() {
                cache.record_span(&span.start, &span.end, commit_ts, Some(self.shared.id));
            }
        }
        let core = Arc::clone(&self.core);
        let mut writer = core.replica.writer();
        let resolution = IntentResolution::Commit {
            txn_id: self.shared.id,
            epoch: self.epoch,
            commit_ts,
            ignored_seq_ranges: self.ignored.clone(),
        };
        for key in &self.writes {
            match writer.resolve_intent(key, &resolution) {
                Ok(ResolveOutcome::NotFound) => {
                    return Err(CommitFailure::Other(TxnError::Internal(
                        "an intent of the committing transaction is missing".into(),
                    )));
                }
                Ok(_) => {}
                Err(e) => return Err(CommitFailure::Other(e.into())),
            }
        }
        if let Some(anchor) = &self.anchor {
            writer.delete_txn_record(anchor, &self.shared.id);
        }
        core.propose_unsynced(writer)
            .map_err(CommitFailure::Ambiguous)
    }

    /// The read refresh of step 2 (module docs). Own intents are made invisible (sequence 0)
    /// so that they do not hide versions committed by others below them.
    fn refresh(&self, commit_ts: Timestamp) -> Result<(), CommitFailure> {
        let ctx = TxnContext {
            txn_id: self.shared.id,
            epoch: self.epoch,
            seq: 0,
            ignored_seq_ranges: Vec::new(),
        };
        let opts = ReadOptions {
            read_ts: self.read_ts,
            uncertainty_limit: commit_ts,
            txn: Some(&ctx),
        };
        let reader = self.core.replica.reader();
        let check = |result: Result<(), MvccError>| match result {
            Ok(()) => Ok(()),
            Err(MvccError::ReadWithinUncertainty { existing, read_ts }) => {
                Err(CommitFailure::Refresh(format!(
                    "read refresh failed: a key read at {read_ts} was written at {existing}"
                )))
            }
            Err(MvccError::IntentConflict(intents)) => Err(CommitFailure::Refresh(format!(
                "read refresh failed: {} key(s) read have pending writes",
                intents.len()
            ))),
            Err(e) => Err(CommitFailure::Other(e.into())),
        };
        for key in self.reads.points() {
            check(reader.get(key, &opts).map(|_| ()))?;
        }
        for span in self.reads.spans() {
            check(
                reader
                    .scan(&span.start, &span.end, &opts, usize::MAX)
                    .map(|_| ()),
            )?;
        }
        Ok(())
    }
}
