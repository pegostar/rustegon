// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MVCC writes (transaction-management.md §3, §5.1, §6, §10): write intents, intent resolution,
//! committed versions and transaction records, collected in one storage write batch so that a
//! command's effects apply atomically (`LsmEngine::write`; one Raft command in the cluster).
//!
//! Invariants enforced here:
//! - **At most one intent per key** (§3): writing over another transaction's intent fails with
//!   [`MvccError::IntentConflict`]; the transaction layer resolves it (push / wait) and retries.
//! - **Write-too-old** (§5.1): a write at `ts` requires every committed version of the key to be
//!   `< ts`; otherwise [`MvccError::WriteTooOld`] reports the newest one so that the caller
//!   pushes its write timestamp above it.
//! - **Above the GC threshold**: a version at `ts <= threshold` could be garbage collected as
//!   shadowed immediately; writes there fail with `RGN-2007` (gc.rs assumptions).
//! - **Idempotent replays** (§7): rewriting the same `(txn, epoch, seq, value)` is a no-op;
//!   resolving an intent that is gone (or belongs to another transaction) is a no-op.
//!
//! Evaluation happens under the key latches of the replica (crate docs), so the state read here
//! cannot change before the batch applies; writes to the same key earlier in the same batch are
//! seen through `pending`.

use std::collections::BTreeMap;

use bytes::Bytes;
use rustegon_storage::{LsmEngine, SeqNo, WriteBatch};

use crate::{
    error::{MvccError, Result},
    gc::GcThreshold,
    hlc::Timestamp,
    key::{MvccKey, meta_key, next_logical_key, txn_record_key, version_key},
    value::{Intent, IntentValue, SeqRange, TxnId, TxnMeta, TxnRecord, VersionValue},
};

/// Final outcome of a transaction, applied to one of its intents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentResolution {
    /// The transaction committed at `commit_ts` in `epoch`; `ignored_seq_ranges` are its final
    /// savepoint rollbacks.
    Commit {
        /// Committing transaction.
        txn_id: TxnId,
        /// Epoch that committed; intents of older epochs are discarded.
        epoch: u32,
        /// Commit timestamp (`>=` the intent's write timestamp).
        commit_ts: Timestamp,
        /// Rolled-back sequence ranges.
        ignored_seq_ranges: Vec<SeqRange>,
    },
    /// The transaction aborted.
    Abort {
        /// Aborted transaction.
        txn_id: TxnId,
    },
}

impl IntentResolution {
    fn txn_id(&self) -> &TxnId {
        match self {
            Self::Commit { txn_id, .. } | Self::Abort { txn_id } => txn_id,
        }
    }
}

/// What [`MvccWriter::resolve_intent`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// No intent of the transaction on the key (already resolved, or never written).
    NotFound,
    /// The intent was removed without writing a version (abort, older epoch, or every
    /// provisional value rolled back).
    Removed,
    /// The intent became a committed version at this timestamp.
    Committed(Timestamp),
}

/// Builds one atomic batch of MVCC writes against the current state of `engine`.
pub struct MvccWriter<'a> {
    engine: &'a LsmEngine,
    gc: Option<&'a GcThreshold>,
    batch: WriteBatch,
    /// Engine keys written by this batch (`None`: deleted), consulted before the engine.
    pending: BTreeMap<Vec<u8>, Option<Bytes>>,
}

impl std::fmt::Debug for MvccWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MvccWriter")
            .field("ops", &self.batch.len())
            .finish_non_exhaustive()
    }
}

impl<'a> MvccWriter<'a> {
    /// An empty batch over `engine`; writes at or below `gc`'s threshold are rejected.
    #[must_use]
    pub fn new(engine: &'a LsmEngine, gc: Option<&'a GcThreshold>) -> Self {
        Self {
            engine,
            gc,
            batch: WriteBatch::new(),
            pending: BTreeMap::new(),
        }
    }

    /// Number of storage operations in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.batch.len()
    }

    /// Whether the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }

    /// The storage batch (to be proposed through Raft or applied directly).
    #[must_use]
    pub fn into_batch(self) -> WriteBatch {
        self.batch
    }

    /// Applies the batch to the engine atomically; returns its last seqno.
    ///
    /// # Errors
    /// Storage errors (nothing is applied then).
    pub fn commit(self) -> Result<SeqNo> {
        Ok(self.engine.write(&self.batch)?)
    }

    fn get_raw(&self, key: &[u8]) -> Result<Option<Bytes>> {
        match self.pending.get(key) {
            Some(v) => Ok(v.clone()),
            None => Ok(self.engine.get(key, None)?),
        }
    }

    fn put_raw(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let value = Bytes::from(value);
        self.batch.put(&key, value.clone());
        self.pending.insert(key, Some(value));
    }

    fn delete_raw(&mut self, key: Vec<u8>) {
        self.batch.delete(&key);
        self.pending.insert(key, None);
    }

    /// Writes at `ts <= threshold` are refused: a strictly-above check, because a version at
    /// exactly the threshold may already be shadowed by GC decisions at that threshold.
    fn check_write_ts(&self, ts: Timestamp) -> Result<()> {
        match self.gc {
            Some(gc) if ts <= gc.get() => Err(MvccError::BelowGcThreshold {
                ts,
                threshold: gc.get(),
            }),
            _ => Ok(()),
        }
    }

    fn intent(&self, key: &[u8]) -> Result<Option<IntentValue>> {
        self.get_raw(&meta_key(key))?
            .map(|v| IntentValue::decode(&v))
            .transpose()
    }

    /// Timestamp of the newest committed version of `key` (tombstones included), seen through
    /// the pending writes.
    fn newest_version(&self, key: &[u8]) -> Result<Option<Timestamp>> {
        // Version keys of `key` are in [version_key(key, MAX), next_logical_key(key)) and
        // sort newest first, so the smallest live engine key is the newest version.
        let lo = version_key(key, Timestamp::MAX);
        let hi = next_logical_key(key);
        let pending = self
            .pending
            .range(lo.clone()..hi)
            .find(|(_, v)| v.is_some())
            .map(|(k, _)| k.clone());
        let prefix = meta_key(key);
        let mut iter = self.engine.iterator(None)?;
        iter.seek(&lo)?;
        let mut stored = None;
        while iter.valid() && iter.key().starts_with(&prefix) {
            // Skip versions deleted earlier in this batch.
            if !matches!(self.pending.get(iter.key()), Some(None)) {
                stored = Some(iter.key().to_vec());
                break;
            }
            iter.next()?;
        }
        let newest = match (pending, stored) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        newest
            .map(|k| match MvccKey::decode(&k)? {
                MvccKey::Version(_, ts) => Ok(ts),
                MvccKey::Meta(_) => Err(MvccError::corruption("meta entry among versions")),
            })
            .transpose()
    }

    fn check_write_too_old(&self, key: &[u8], write_ts: Timestamp) -> Result<()> {
        match self.newest_version(key)? {
            Some(existing) if existing >= write_ts => {
                Err(MvccError::WriteTooOld { write_ts, existing })
            }
            _ => Ok(()),
        }
    }

    /// Writes (or extends) the intent of `meta.txn_id` on `key` with the provisional `value`
    /// at `meta.seq` (module docs). A later sequence number of the same epoch keeps the earlier
    /// provisional value in the intent history (savepoints, §10); a newer epoch replaces the
    /// intent; the intent's write timestamp never moves backward.
    ///
    /// # Errors
    /// [`MvccError::IntentConflict`] (another transaction's intent), [`MvccError::WriteTooOld`],
    /// [`MvccError::BelowGcThreshold`], [`MvccError::InvalidArgument`] for a stale epoch or a
    /// reused sequence number with a different value; corruption and storage errors.
    pub fn put_intent(&mut self, key: &[u8], meta: &TxnMeta, value: VersionValue) -> Result<()> {
        self.check_write_ts(meta.write_ts)?;
        let mut meta = meta.clone();
        let history = match self.intent(key)? {
            None => Vec::new(),
            Some(old) if old.meta.txn_id != meta.txn_id => {
                return Err(MvccError::IntentConflict(vec![Intent {
                    key: key.to_vec(),
                    meta: old.meta,
                }]));
            }
            Some(old) if old.meta.epoch > meta.epoch => {
                return Err(MvccError::InvalidArgument(format!(
                    "write at epoch {} over intent of epoch {}",
                    meta.epoch, old.meta.epoch
                )));
            }
            // An older epoch's writes are discarded by the restart.
            Some(old) if old.meta.epoch < meta.epoch => Vec::new(),
            Some(old) => {
                let replayed = if meta.seq == old.meta.seq {
                    Some(&old.value)
                } else {
                    old.history
                        .iter()
                        .find(|(s, _)| *s == meta.seq)
                        .map(|(_, v)| v)
                };
                match replayed {
                    Some(v) if *v == value => return Ok(()),
                    Some(_) => {
                        return Err(MvccError::InvalidArgument(format!(
                            "sequence {} rewritten with a different value",
                            meta.seq
                        )));
                    }
                    None if meta.seq < old.meta.seq => {
                        return Err(MvccError::InvalidArgument(format!(
                            "sequence {} below the intent's sequence {}",
                            meta.seq, old.meta.seq
                        )));
                    }
                    None => {}
                }
                meta.write_ts = meta.write_ts.max(old.meta.write_ts);
                let mut history = old.history;
                history.push((old.meta.seq, old.value));
                history
            }
        };
        self.check_write_too_old(key, meta.write_ts)?;
        let intent = IntentValue {
            meta,
            value,
            history,
        };
        self.put_raw(meta_key(key), intent.encode());
        Ok(())
    }

    /// Resolves the intent of the transaction named in `resolution` on `key`: commit writes
    /// its visible provisional value (newest sequence not rolled back) as a version at the
    /// commit timestamp and removes the intent; abort removes it.
    ///
    /// # Errors
    /// [`MvccError::InvalidArgument`] for a commit below the intent's write timestamp or from
    /// an older epoch than the intent's; [`MvccError::BelowGcThreshold`]; corruption and storage
    /// errors. Nothing is added to the batch on error.
    pub fn resolve_intent(
        &mut self,
        key: &[u8],
        resolution: &IntentResolution,
    ) -> Result<ResolveOutcome> {
        let Some(intent) = self.intent(key)? else {
            return Ok(ResolveOutcome::NotFound);
        };
        if intent.meta.txn_id != *resolution.txn_id() {
            return Ok(ResolveOutcome::NotFound);
        }
        let commit = match resolution {
            IntentResolution::Abort { .. } => None,
            IntentResolution::Commit {
                epoch,
                commit_ts,
                ignored_seq_ranges,
                ..
            } => {
                if intent.meta.epoch > *epoch {
                    return Err(MvccError::InvalidArgument(format!(
                        "commit of epoch {epoch} over intent of epoch {}",
                        intent.meta.epoch
                    )));
                }
                if intent.meta.epoch < *epoch {
                    None
                } else {
                    if *commit_ts < intent.meta.write_ts {
                        return Err(MvccError::InvalidArgument(format!(
                            "commit at {commit_ts} below intent timestamp {}",
                            intent.meta.write_ts
                        )));
                    }
                    self.check_write_ts(*commit_ts)?;
                    intent
                        .visible(u32::MAX, ignored_seq_ranges)
                        .map(|(_, v)| (*commit_ts, v.encode()))
                }
            }
        };
        self.delete_raw(meta_key(key));
        Ok(match commit {
            Some((ts, value)) => {
                self.put_raw(version_key(key, ts), value);
                ResolveOutcome::Committed(ts)
            }
            None => ResolveOutcome::Removed,
        })
    }

    /// Writes a committed version directly (single-key fast path, §6; non-transactional
    /// writes). A deletion is [`VersionValue::Tombstone`].
    ///
    /// # Errors
    /// [`MvccError::IntentConflict`] if any intent is on the key, [`MvccError::WriteTooOld`],
    /// [`MvccError::BelowGcThreshold`]; corruption and storage errors.
    pub fn put_version(&mut self, key: &[u8], ts: Timestamp, value: &VersionValue) -> Result<()> {
        self.check_write_ts(ts)?;
        if let Some(intent) = self.intent(key)? {
            return Err(MvccError::IntentConflict(vec![Intent {
                key: key.to_vec(),
                meta: intent.meta,
            }]));
        }
        self.check_write_too_old(key, ts)?;
        self.put_raw(version_key(key, ts), value.encode());
        Ok(())
    }

    /// Writes the transaction record of `txn_id` anchored at `anchor` (unversioned, meta slot of
    /// `txn_record_key`).
    pub fn put_txn_record(&mut self, anchor: &[u8], txn_id: &TxnId, record: &TxnRecord) {
        self.put_raw(meta_key(&txn_record_key(anchor, txn_id)), record.encode());
    }

    /// Deletes the transaction record (record GC once all intents are resolved, §7).
    pub fn delete_txn_record(&mut self, anchor: &[u8], txn_id: &TxnId) {
        self.delete_raw(meta_key(&txn_record_key(anchor, txn_id)));
    }
}
