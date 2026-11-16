// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! What a transaction does about another transaction's intent (transaction-management.md §5.1,
//! §7): resolve it (holder finished, or pushed out of the way), read past it (timestamp push),
//! or wait for the holder.
//!
//! # Holder state
//! - **Live holder** (in the registry): the decision is taken under the holder's state mutex,
//!   so it is atomic with the holder's own commit (`Pending → Committing`): a holder is either
//!   pushed before it starts committing, or the pusher waits for the outcome.
//! - **Unregistered holder** (its coordinator is gone, e.g. it ran before a crash): the
//!   persisted `TxnRecord` decides. A missing record means aborted: a transaction writes its
//!   record with its first intent and a one-phase commit resolves every intent in the command
//!   that deletes the record, so an intent without a record can only belong to a transaction
//!   that never committed. A `PENDING` record whose heartbeat is older than
//!   `txn.liveness_timeout` is aborted by persisting `ABORTED` together with the resolution, in
//!   one command evaluated under the range latch after re-checking the record.
//!
//! # Push rules (§5.1)
//! - An expired holder (no heartbeat for `txn.liveness_timeout`) is aborted by anyone.
//! - A waiter with a strictly higher numeric priority pushes: a writer aborts the holder; a
//!   point reader pushes the holder's write timestamp above its read timestamp and reads past
//!   the intent. Equal priorities wait (deadlocks are detected, §5.2); the restart bump of §5.3
//!   makes long-retrying transactions win eventually.
//! - Scans wait instead of pushing timestamps (M2 simplification: reading past several intents
//!   of different holders would need MVCC reader support).

use std::sync::Arc;

use rustegon_mvcc::{
    Intent, IntentResolution, MvccError, MvccWriter, Timestamp, TxnId, TxnRecord,
    TxnStatus as RecordStatus,
};

use crate::{
    coordinator::Core,
    error::{AbortReason, Result, TxnError},
    registry::{Status, TxnShared},
};

/// The kind of access that met the intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// A write (or the read of a read-modify-write).
    Write,
    /// A point read at `read_ts`.
    PointRead {
        /// The reader's timestamp.
        read_ts: Timestamp,
    },
    /// A span read.
    Scan,
}

/// The decision about one conflicting intent.
#[derive(Debug)]
pub(crate) enum Decision {
    /// The holder finished on its own: its intent is resolved with this outcome (in wait-queue
    /// order).
    Finished(IntentResolution),
    /// The waiter aborted the holder: resolve now; `persist_abort` for an unregistered holder,
    /// whose record must say `ABORTED` in the same command.
    Pushed {
        /// Abort resolution of the holder.
        resolution: IntentResolution,
        /// Whether the abort must be persisted in the holder's record.
        persist_abort: bool,
    },
    /// The holder's timestamp was pushed above the reader's: read past its intent.
    ReadPast,
    /// Wait for the holder (`None`: an unregistered holder, polled).
    Wait(Option<Arc<TxnShared>>),
}

impl Core {
    /// Decides about `intent` for a waiter of numeric priority `priority` (module docs).
    ///
    /// # Errors
    /// [`TxnError::Conflict`] for a holder whose commit outcome is unknown;
    /// [`TxnError::Internal`] for records of the distributed commit protocol (M6); storage
    /// errors reading the record.
    pub(crate) fn decide(
        &self,
        intent: &Intent,
        priority: u32,
        access: Access,
    ) -> Result<Decision> {
        match self.registry.get(&intent.meta.txn_id) {
            Some(holder) => self.decide_live(holder, priority, access),
            None => self.decide_from_record(intent),
        }
    }

    fn decide_live(
        &self,
        holder: Arc<TxnShared>,
        priority: u32,
        access: Access,
    ) -> Result<Decision> {
        let txn_id = holder.id;
        let mut st = holder.lock();
        let decision = match st.status.clone() {
            Status::Committed {
                commit_ts,
                epoch,
                ignored,
            } => Decision::Finished(IntentResolution::Commit {
                txn_id,
                epoch,
                commit_ts,
                ignored_seq_ranges: ignored,
            }),
            Status::Aborted(_) => Decision::Finished(IntentResolution::Abort { txn_id }),
            Status::Ambiguous => {
                return Err(TxnError::Conflict(
                    "conflicting intent of a transaction whose commit outcome is unknown".into(),
                ));
            }
            Status::Committing => {
                drop(st);
                return Ok(Decision::Wait(Some(holder)));
            }
            Status::Pending => {
                let idle = self.now().saturating_sub(st.last_heartbeat);
                if idle > self.config.liveness_timeout {
                    holder.set_status(&mut st, Status::Aborted(AbortReason::TimeoutPushed));
                    Decision::Pushed {
                        resolution: IntentResolution::Abort { txn_id },
                        persist_abort: false,
                    }
                } else if priority > st.priority {
                    match access {
                        Access::Write => {
                            holder.set_status(&mut st, Status::Aborted(AbortReason::Conflict));
                            Decision::Pushed {
                                resolution: IntentResolution::Abort { txn_id },
                                persist_abort: false,
                            }
                        }
                        Access::PointRead { read_ts } => {
                            // Timestamp push: the holder now commits above the reader, so the
                            // reader may ignore the intent (§5.1).
                            st.write_ts = st.write_ts.max(read_ts.next());
                            Decision::ReadPast
                        }
                        Access::Scan => {
                            drop(st);
                            return Ok(Decision::Wait(Some(holder)));
                        }
                    }
                } else {
                    drop(st);
                    return Ok(Decision::Wait(Some(holder)));
                }
            }
        };
        Ok(decision)
    }

    fn decide_from_record(&self, intent: &Intent) -> Result<Decision> {
        let txn_id = intent.meta.txn_id;
        let record = self
            .replica
            .reader()
            .get_txn_record(&intent.meta.anchor_key, &txn_id)?;
        let abort = IntentResolution::Abort { txn_id };
        match record.map(|r| (r.status, self.record_expired(&r))) {
            None | Some((RecordStatus::Aborted, _)) => Ok(Decision::Finished(abort)),
            Some((RecordStatus::Pending, true)) => Ok(Decision::Pushed {
                resolution: abort,
                persist_abort: true,
            }),
            Some((RecordStatus::Pending, false)) => Ok(Decision::Wait(None)),
            Some((status @ (RecordStatus::Committed | RecordStatus::Staging), _)) => {
                // One-phase commits never persist these; they belong to the parallel commit
                // protocol and its status recovery (M6).
                Err(TxnError::Internal(format!(
                    "transaction record in status {status:?} needs status recovery (M6)"
                )))
            }
        }
    }

    /// Whether a persisted record's heartbeat is older than `txn.liveness_timeout` (HLC wall
    /// time: records carry no monotonic time).
    fn record_expired(&self, record: &TxnRecord) -> bool {
        let liveness = u64::try_from(self.config.liveness_timeout.as_nanos()).unwrap_or(u64::MAX);
        let now = self.hlc.now();
        now.wall.saturating_sub(record.heartbeat_ts.wall) > liveness
    }

    /// Must hold the write latch. Re-reads the record of `txn_id` at `anchor` and, if it is
    /// still `PENDING` and expired, stages it as `ABORTED` in `writer` (the caller proposes it
    /// together with intent resolutions). Returns the record's status as of the staged batch
    /// (`None`: no record).
    fn stage_abort_if_expired(
        &self,
        writer: &mut MvccWriter<'_>,
        anchor: &[u8],
        txn_id: &TxnId,
    ) -> Result<Option<RecordStatus>> {
        Ok(
            match self.replica.reader().get_txn_record(anchor, txn_id)? {
                Some(mut record)
                    if record.status == RecordStatus::Pending && self.record_expired(&record) =>
                {
                    record.status = RecordStatus::Aborted;
                    writer.put_txn_record(anchor, txn_id, &record);
                    Some(RecordStatus::Aborted)
                }
                other => other.map(|r| r.status),
            },
        )
    }

    /// Resolves `intent` with `resolution` in one command under the write latch. With
    /// `persist_abort`, the holder's record is re-read first and, if it is still `PENDING` and
    /// expired, rewritten as `ABORTED` in the same command; if the holder heartbeated or
    /// finished meanwhile, nothing is done (the caller decides again).
    ///
    /// # Errors
    /// MVCC and replica errors (nothing is resolved then).
    pub(crate) fn resolve(
        &self,
        intent: &Intent,
        resolution: &IntentResolution,
        persist_abort: bool,
    ) -> Result<()> {
        let _latch = self.write_latch();
        let mut writer = self.replica.writer();
        if persist_abort {
            let anchor = &intent.meta.anchor_key;
            match self.stage_abort_if_expired(&mut writer, anchor, &intent.meta.txn_id)? {
                None | Some(RecordStatus::Aborted) => {}
                Some(_) => return Ok(()),
            }
        }
        match writer.resolve_intent(&intent.key, resolution) {
            Ok(_) => {}
            Err(MvccError::InvalidArgument(msg)) => {
                return Err(TxnError::Internal(format!(
                    "intent resolution refused: {msg}"
                )));
            }
            Err(e) => return Err(e.into()),
        }
        self.propose(writer)?;
        Ok(())
    }

    /// The persisted outcome of `txn_id` when its coordinator is not in this process (module
    /// docs, "Unregistered holder"; transaction-management.md §7; PD-121): what
    /// `TransactionService.Status` answers for a transaction opened before a restart.
    ///
    /// Safety: a one-phase commit resolves every intent in the command that deletes the record,
    /// a rollback deletes it too, and committed versions do not carry the transaction id, so a
    /// **missing record proves nothing** (the transaction may have committed) and yields
    /// `None`, never an abort. Only a record proves something:
    /// - `PENDING` and expired (no heartbeat for `txn.liveness_timeout`): aborted durably here,
    ///   as a pusher meeting one of its intents would (`ABORTED` record and the resolution of
    ///   the intent at the anchor key in one command, under the write latch, after re-reading
    ///   the record), then [`OrphanStatus::Aborted`]. The re-read under the latch excludes a
    ///   concurrent commit or rollback: both delete the record under the same latch. Its other
    ///   intents are resolved lazily by whoever meets them (the record says `ABORTED`); a 1PC
    ///   record does not list them (`lock_spans` is empty).
    /// - `PENDING` not yet expired, or `STAGING`: [`OrphanStatus::InDoubt`].
    /// - `ABORTED` / `COMMITTED`: what it says.
    ///
    /// A transaction still registered in this process is not an orphan: `None` (its handle's
    /// owner answers for it). An id is never registered again once unregistered, so the check
    /// needs no latch.
    ///
    /// Cost: one scan of the transaction-record keyspace
    /// ([`rustegon_mvcc::MvccReader::find_txn_record`]).
    ///
    /// # Errors
    /// Storage, corruption and replica errors.
    pub(crate) fn orphan_status(&self, txn_id: &TxnId) -> Result<Option<OrphanStatus>> {
        if self.registry.get(txn_id).is_some() {
            return Ok(None);
        }
        let Some((anchor, record)) = self.replica.reader().find_txn_record(txn_id)? else {
            return Ok(None);
        };
        let status = match record.status {
            RecordStatus::Pending if self.record_expired(&record) => {
                let _latch = self.write_latch();
                let mut writer = self.replica.writer();
                let status = self.stage_abort_if_expired(&mut writer, &anchor, txn_id)?;
                if status == Some(RecordStatus::Aborted) && !writer.is_empty() {
                    // The anchor holds the transaction's first intent unless someone already
                    // resolved it.
                    if let Some(intent) = self.replica.reader().get_intent(&anchor)?
                        && intent.meta.txn_id == *txn_id
                    {
                        let abort = IntentResolution::Abort { txn_id: *txn_id };
                        writer
                            .resolve_intent(&anchor, &abort)
                            .map_err(|e| match e {
                                MvccError::InvalidArgument(msg) => {
                                    TxnError::Internal(format!("intent resolution refused: {msg}"))
                                }
                                e => e.into(),
                            })?;
                    }
                    self.propose(writer)?;
                }
                status
            }
            other => Some(other),
        };
        Ok(status.map(|s| match s {
            RecordStatus::Aborted => OrphanStatus::Aborted,
            RecordStatus::Committed => OrphanStatus::Committed,
            RecordStatus::Pending | RecordStatus::Staging => OrphanStatus::InDoubt,
        }))
    }
}

/// The persisted outcome of a transaction whose coordinator is gone
/// ([`crate::TxnCoordinator::orphan_status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanStatus {
    /// Its record says it is (or was just made) aborted.
    Aborted,
    /// Its record says it committed (parallel commit records only; 1PC deletes the record).
    Committed,
    /// Not decided yet: a `PENDING` record still within `txn.liveness_timeout` (it is aborted
    /// once it expires), or a `STAGING` one.
    InDoubt,
}
