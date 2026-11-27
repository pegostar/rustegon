// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Reads and writes of a transaction (transaction-management.md §3, §4.1, §5.1).
//!
//! # Reads
//! Under the shared range latch, the read is first registered in the timestamp cache, then
//! evaluated. Writers check the cache under the exclusive latch, so for any read and write of
//! the same key either the read happens first (the writer sees the cache entry and writes above
//! it) or the write does (the reader sees the intent and resolves it first): no writer slips
//! under a read. SERIALIZABLE reads are also recorded as refresh spans. READ COMMITTED reads at
//! a fresh timestamp per statement (one call = one statement).
//!
//! # Writes
//! Under the exclusive latch: the write timestamp starts at the transaction's provisional
//! commit timestamp, moves above the timestamp cache entry of the key (unless the read was the
//! transaction's own) and above the newest committed version (write-too-old), and the intent is
//! proposed — together with the `PENDING` record for the first write (anchor key, §3). SNAPSHOT
//! first refuses keys committed after its read timestamp (first-committer-wins, `RGN-2001`).
//!
//! # The read rule (ADR-040)
//! Every public operation here ends with `Core::settled`: what it returns, an error included,
//! was computed from the range, where a commit may be applied and not durable yet.

use std::sync::Arc;

use bytes::Bytes;
use rustegon_mvcc::{
    Intent, MvccError, RangeAppliedState, ReadOptions, Timestamp, TxnContext, TxnId, TxnMeta,
    TxnStatus as RecordStatus, VersionValue,
};

use super::{Phase, Txn};
use crate::{
    config::Isolation,
    conflict::Access,
    error::{AbortReason, Result, TxnError},
    registry::Status,
};

/// Result of one evaluation attempt under the latch.
pub(super) enum Step<T> {
    /// Evaluated (and proposed).
    Done(T),
    /// Blocked by other transactions' intents: wait outside the latch, then retry.
    Conflict(Vec<Intent>),
    /// The transaction is no longer pending (aborted by someone): report outside the latch.
    Inactive,
    /// The write set would exceed a limit: abort outside the latch.
    TooLarge {
        /// `"keys"` or `"bytes"`.
        what: &'static str,
        /// The limit.
        limit: u64,
    },
}

impl Txn {
    /// Reads `key` (`None`: absent or deleted). Own writes are visible.
    ///
    /// # Errors
    /// Abort, timeout and deadlock errors while waiting for conflicting intents; `RGN-2007`
    /// below the GC threshold; storage errors.
    pub fn get(&mut self, key: &[u8]) -> Result<Option<Bytes>> {
        let read = self.get_unsettled(key);
        self.core.settled(read)
    }

    fn get_unsettled(&mut self, key: &[u8]) -> Result<Option<Bytes>> {
        self.check_active()?;
        let read_ts = self.statement_read_ts();
        let mut read_past = None;
        loop {
            match self.read_point(key, read_ts, read_past) {
                Ok(value) => {
                    self.note_point_read(key);
                    return Ok(value);
                }
                Err(MvccError::IntentConflict(intents)) => {
                    read_past = self.wait_conflicts(&intents, Access::PointRead { read_ts })?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Reads the visible `(key, value)` pairs of `[start, end)`, ascending, at most `max_keys`.
    /// The whole span counts as read (timestamp cache and refresh spans), even if `max_keys`
    /// cut it short.
    ///
    /// # Errors
    /// As [`Txn::get`].
    pub fn scan(
        &mut self,
        start: &[u8],
        end: &[u8],
        max_keys: usize,
    ) -> Result<Vec<(Vec<u8>, Bytes)>> {
        let rows = self.scan_unsettled(start, end, max_keys);
        self.core.settled(rows)
    }

    fn scan_unsettled(
        &mut self,
        start: &[u8],
        end: &[u8],
        max_keys: usize,
    ) -> Result<Vec<(Vec<u8>, Bytes)>> {
        self.check_active()?;
        let read_ts = self.statement_read_ts();
        loop {
            let ctx = self.ctx();
            let opts = ReadOptions {
                read_ts,
                uncertainty_limit: read_ts,
                txn: Some(&ctx),
            };
            let result = {
                let _latch = self.core.read_latch();
                self.core
                    .ts_cache()
                    .record_span(start, end, read_ts, Some(self.shared.id));
                self.core.replica.reader().scan(start, end, &opts, max_keys)
            };
            match result {
                Ok(rows) => {
                    if self.options.isolation == Isolation::Serializable {
                        let limit = self.core.config.max_refresh_spans_bytes;
                        self.reads.add_span(start, end, limit);
                    }
                    return Ok(rows);
                }
                Err(MvccError::IntentConflict(intents)) => {
                    self.wait_conflicts(&intents, Access::Scan)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Writes `value` at `key`.
    ///
    /// # Errors
    /// `RGN-2001` (SNAPSHOT: `key` committed after the read timestamp; the transaction must
    /// restart), `RGN-2004` (write-set limits; aborted), `RGN-1001` in a read-only transaction,
    /// abort / timeout / deadlock errors while waiting, MVCC and replica errors.
    pub fn put(&mut self, key: &[u8], value: impl Into<Bytes>) -> Result<()> {
        self.write(key, &VersionValue::Value(value.into()))
    }

    /// Deletes `key` (writes a tombstone).
    ///
    /// # Errors
    /// As [`Txn::put`].
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.write(key, &VersionValue::Tombstone)
    }

    /// Writes any version value (value, tombstone or merge operand) at `key`.
    ///
    /// # Errors
    /// As [`Txn::put`].
    pub fn write(&mut self, key: &[u8], value: &VersionValue) -> Result<()> {
        let written = self.write_unsettled(key, value);
        self.core.settled(written)
    }

    fn write_unsettled(&mut self, key: &[u8], value: &VersionValue) -> Result<()> {
        self.check_active()?;
        self.check_writable()?;
        if self.options.isolation == Isolation::ReadCommitted {
            self.statement_read_ts();
        }
        loop {
            let core = Arc::clone(&self.core);
            let step = {
                let _latch = core.write_latch();
                self.write_locked(key, value)
            }?;
            if self.handle_step(step, Access::Write)?.is_some() {
                return Ok(());
            }
        }
    }

    /// Read-modify-write of one key, atomically: reads `key`, calls `f` with its value and
    /// writes what `f` returns (`None`: no write); returns the value read.
    ///
    /// Under SERIALIZABLE and SNAPSHOT this is a read and a write with their usual rules. Under
    /// READ COMMITTED it is the statement re-evaluation primitive of §4.1 ("EvalPlanQual"): the
    /// read takes the latest committed value (fresh timestamp, under the exclusive latch, so no
    /// commit can intervene before the write); a conflicting intent is waited for and `f` is
    /// re-evaluated on the value committed by then. This prevents lost updates at every level.
    /// `f` runs under the range latch: it must be short and must not use the coordinator.
    ///
    /// # Errors
    /// As [`Txn::put`]; `RGN-2008` when a READ COMMITTED statement was re-evaluated more than
    /// `rc_statement_retries` times.
    pub fn update<F>(&mut self, key: &[u8], f: F) -> Result<Option<Bytes>>
    where
        F: FnMut(Option<&Bytes>) -> Option<VersionValue>,
    {
        let read = self.update_unsettled(key, f);
        self.core.settled(read)
    }

    fn update_unsettled<F>(&mut self, key: &[u8], mut f: F) -> Result<Option<Bytes>>
    where
        F: FnMut(Option<&Bytes>) -> Option<VersionValue>,
    {
        self.check_active()?;
        self.check_writable()?;
        let mut retries = 0;
        loop {
            let core = Arc::clone(&self.core);
            let step = {
                let _latch = core.write_latch();
                self.update_locked(key, &mut f)
            }?;
            if matches!(step, Step::Conflict(_))
                && self.options.isolation == Isolation::ReadCommitted
            {
                retries += 1;
                if retries > self.core.config.rc_statement_retries {
                    return Err(TxnError::WriteTooOld { retries });
                }
            }
            if let Some(read) = self.handle_step(step, Access::Write)? {
                return Ok(read);
            }
        }
    }

    /// Single-key fast path (§6, used by [`crate::TxnCoordinator::put_single_key`]): commits
    /// `value` as a version above the timestamp cache and the newest version, without intent or
    /// record, then finishes the (implicit) transaction. As a commit, the version is applied
    /// under the latch and its log record is waited for after it (ADR-040); `Ok` and an unknown
    /// outcome need no further wait, any other error is an observation the caller settles.
    pub(crate) fn fast_path_write(
        &mut self,
        key: &[u8],
        value: &VersionValue,
    ) -> Result<Timestamp> {
        self.check_active()?;
        loop {
            let core = Arc::clone(&self.core);
            let step = {
                let _latch = core.write_latch();
                self.fast_write_locked(key, value)
            };
            let step = match step {
                Err(e @ TxnError::CommitOutcomeUnknown(_)) => {
                    self.phase = Phase::Unknown;
                    return Err(e);
                }
                other => other?,
            };
            if let Some((ts, applied)) = self.handle_step(step, Access::Write)? {
                if let Some(state) = applied
                    && let Err(e) = core.replica.sync_through(state.applied_index)
                {
                    self.phase = Phase::Unknown;
                    return Err(TxnError::CommitOutcomeUnknown(e));
                }
                self.finish_committed(ts);
                return Ok(ts);
            }
        }
    }

    /// Acts on a step outside the latch: `Some` when done, `None` to retry.
    fn handle_step<T>(&mut self, step: Step<T>, access: Access) -> Result<Option<T>> {
        match step {
            Step::Done(v) => Ok(Some(v)),
            Step::Conflict(intents) => {
                self.wait_conflicts(&intents, access)?;
                Ok(None)
            }
            Step::Inactive => {
                self.check_active()?;
                Err(TxnError::Internal(
                    "transaction neither pending nor aborted".into(),
                ))
            }
            Step::TooLarge { what, limit } => {
                self.finish_aborted(AbortReason::TooLarge);
                Err(TxnError::TooLarge { what, limit })
            }
        }
    }

    /// The read timestamp of a new statement: the epoch's for SERIALIZABLE / SNAPSHOT, a fresh
    /// one for READ COMMITTED, which also raises the provisional commit timestamp to it (a
    /// READ COMMITTED transaction never commits below a value it observed).
    fn statement_read_ts(&mut self) -> Timestamp {
        if self.options.isolation != Isolation::ReadCommitted {
            return self.read_ts;
        }
        let ts = self.core.hlc.now();
        let mut st = self.shared.lock();
        if st.status == Status::Pending {
            st.write_ts = st.write_ts.max(ts);
        }
        ts
    }

    fn note_point_read(&mut self, key: &[u8]) {
        if self.options.isolation == Isolation::Serializable {
            let limit = self.core.config.max_refresh_spans_bytes;
            self.reads.add_point(key, limit);
        }
    }

    /// One registered point read under the shared latch. `read_past`: a holder whose timestamp
    /// was pushed above `read_ts`; its intent is made invisible by reading with a context that
    /// treats it as an own intent of an older epoch (always invisible, MVCC read rule 2).
    fn read_point(
        &self,
        key: &[u8],
        read_ts: Timestamp,
        read_past: Option<TxnId>,
    ) -> std::result::Result<Option<Bytes>, MvccError> {
        let ctx = match read_past {
            None => self.ctx(),
            Some(holder) => TxnContext {
                txn_id: holder,
                epoch: u32::MAX,
                seq: 0,
                ignored_seq_ranges: Vec::new(),
            },
        };
        let opts = ReadOptions {
            read_ts,
            uncertainty_limit: read_ts,
            txn: Some(&ctx),
        };
        let _latch = self.core.read_latch();
        self.core
            .ts_cache()
            .record_point(key, read_ts, Some(self.shared.id));
        self.core.replica.get(key, &opts)
    }

    /// The write-set limits for writing `value` at `key` (§9): the new byte total, or the
    /// exceeded limit.
    fn charge_write(&self, key: &[u8], value: &VersionValue) -> std::result::Result<u64, Step<()>> {
        let config = &self.core.config;
        let keys = self.writes.len() as u64 + u64::from(!self.writes.contains(key));
        if keys > config.max_write_keys {
            return Err(Step::TooLarge {
                what: "keys",
                limit: config.max_write_keys,
            });
        }
        let len = match value {
            VersionValue::Value(v) | VersionValue::MergeOperand(v) => v.len(),
            VersionValue::Tombstone => 0,
        };
        let bytes = self.write_bytes + (key.len() + len) as u64;
        if bytes > config.max_write_bytes {
            return Err(Step::TooLarge {
                what: "bytes",
                limit: config.max_write_bytes,
            });
        }
        Ok(bytes)
    }

    /// The read part of [`Txn::update`] and the write, under the exclusive latch.
    fn update_locked<F>(&mut self, key: &[u8], f: &mut F) -> Result<Step<Option<Bytes>>>
    where
        F: FnMut(Option<&Bytes>) -> Option<VersionValue>,
    {
        if self.shared.lock().status != Status::Pending {
            return Ok(Step::Inactive);
        }
        let read_ts = self.statement_read_ts();
        let ctx = self.ctx();
        let opts = ReadOptions {
            read_ts,
            uncertainty_limit: read_ts,
            txn: Some(&ctx),
        };
        self.core
            .ts_cache()
            .record_point(key, read_ts, Some(self.shared.id));
        let current = match self.core.replica.get(key, &opts) {
            Ok(v) => v,
            Err(MvccError::IntentConflict(intents)) => return Ok(Step::Conflict(intents)),
            Err(e) => return Err(e.into()),
        };
        self.note_point_read(key);
        let Some(new) = f(current.as_ref()) else {
            return Ok(Step::Done(current));
        };
        Ok(match self.write_locked(key, &new)? {
            Step::Done(()) => Step::Done(current),
            Step::Conflict(i) => Step::Conflict(i),
            Step::Inactive => Step::Inactive,
            Step::TooLarge { what, limit } => Step::TooLarge { what, limit },
        })
    }

    /// Evaluates and proposes one intent (module docs). Must hold the exclusive latch.
    fn write_locked(&mut self, key: &[u8], value: &VersionValue) -> Result<Step<()>> {
        let floor = {
            let st = self.shared.lock();
            if st.status != Status::Pending {
                return Ok(Step::Inactive);
            }
            st.write_ts.max(self.read_ts)
        };
        let write_bytes = match self.charge_write(key, value) {
            Ok(bytes) => bytes,
            Err(step) => return Ok(step),
        };
        let cached = self.core.ts_cache().max_point(key);
        let mut ts = if cached.blocks(&self.shared.id) && cached.ts >= floor {
            cached.ts.next()
        } else {
            floor
        };
        if self.options.isolation == Isolation::Snapshot
            && let Some(intents) = self.first_committer_check(key)?
        {
            return Ok(Step::Conflict(intents));
        }
        let seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| TxnError::Internal("sequence number overflow".into()))?;
        let anchor = self.anchor.clone().unwrap_or_else(|| key.to_vec());
        let core = Arc::clone(&self.core);
        let mut writer = core.replica.writer();
        loop {
            let meta = TxnMeta {
                txn_id: self.shared.id,
                epoch: self.epoch,
                write_ts: ts,
                seq,
                anchor_key: anchor.clone(),
                ignored_seq_ranges: self.ignored.clone(),
            };
            match writer.put_intent(key, &meta, value.clone()) {
                Ok(()) => break,
                // Write-too-old (§5.1): move above the newest committed version. SERIALIZABLE
                // then needs a refresh at commit; SNAPSHOT already refused such keys above.
                Err(MvccError::WriteTooOld { existing, .. }) => ts = existing.next(),
                Err(MvccError::IntentConflict(intents)) => return Ok(Step::Conflict(intents)),
                Err(e) => return Err(e.into()),
            }
        }
        if self.anchor.is_none() {
            let mut record = self.record(RecordStatus::Pending);
            record.write_ts = record.write_ts.max(ts);
            writer.put_txn_record(&anchor, &self.shared.id, &record);
        }
        // Tracked before proposing: if the proposal fails after logging, cleanup still
        // resolves the intent (resolving a missing intent is a no-op).
        self.writes.insert(key.to_vec());
        // Before proposing and under the latch (PD-063): a timestamp fence taken after this
        // latch is released must see that this transaction may hold an intent.
        self.shared.lock().has_intents = true;
        self.anchor = Some(anchor);
        self.seq = seq;
        self.write_bytes = write_bytes;
        // An intent (and the PENDING record) needs no fsync of its own: the commit's makes it
        // durable first (ADR-038).
        core.propose_deferred(writer)?;
        {
            let mut st = self.shared.lock();
            st.write_ts = st.write_ts.max(ts);
        }
        // Every timestamp written stays below the HLC, so later transactions start above it.
        core.hlc.update(ts);
        Ok(Step::Done(()))
    }

    /// SNAPSHOT first-committer-wins (§4.1): fails with `RGN-2001` if `key` has a version
    /// committed after the read timestamp; returns conflicting intents to wait for. The read
    /// uses `(read_ts, MAX]` as its uncertainty window, so any later version is reported, and
    /// sequence 0 so that the transaction's own intent does not hide the versions below it.
    fn first_committer_check(&mut self, key: &[u8]) -> Result<Option<Vec<Intent>>> {
        let ctx = TxnContext {
            txn_id: self.shared.id,
            epoch: self.epoch,
            seq: 0,
            ignored_seq_ranges: Vec::new(),
        };
        let opts = ReadOptions {
            read_ts: self.read_ts,
            uncertainty_limit: Timestamp::MAX,
            txn: Some(&ctx),
        };
        match self.core.replica.get(key, &opts) {
            Ok(_) => Ok(None),
            Err(MvccError::IntentConflict(intents)) => Ok(Some(intents)),
            Err(MvccError::ReadWithinUncertainty { existing, read_ts }) => {
                self.phase = Phase::RestartRequired;
                self.core
                    .stats
                    .restarted(crate::stats::RestartReason::WriteConflict);
                Err(TxnError::Conflict(format!(
                    "SNAPSHOT write-write conflict: key committed at {existing} after the read \
                     timestamp {read_ts}"
                )))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Evaluates and proposes a committed version directly (single-key fast path), without its
    /// log sync. Must hold the exclusive latch. Returns the version's timestamp and the applied
    /// state to wait for.
    fn fast_write_locked(
        &mut self,
        key: &[u8],
        value: &VersionValue,
    ) -> Result<Step<(Timestamp, Option<RangeAppliedState>)>> {
        let mut ts = self.core.hlc.now();
        let cached = self.core.ts_cache().max_point(key);
        if cached.ts >= ts {
            ts = cached.ts.next();
        }
        let core = Arc::clone(&self.core);
        let mut writer = core.replica.writer();
        loop {
            match writer.put_version(key, ts, value) {
                Ok(()) => break,
                Err(MvccError::WriteTooOld { existing, .. }) => ts = existing.next(),
                Err(MvccError::IntentConflict(intents)) => return Ok(Step::Conflict(intents)),
                Err(e) => return Err(e.into()),
            }
        }
        let applied = core
            .propose_unsynced(writer)
            .map_err(TxnError::CommitOutcomeUnknown)?;
        core.hlc.update(ts);
        Ok(Step::Done((ts, applied)))
    }
}
