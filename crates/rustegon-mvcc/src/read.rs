// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MVCC reads at a timestamp (transaction-management.md §3 visibility rule, §4.2 uncertainty,
//! §10 savepoints).
//!
//! The value of logical key *K* for a reader at `read_ts`:
//! 1. An intent of **another** transaction with `write_ts <= uncertainty_limit` (the limit is
//!    `read_ts` without clock uncertainty) is a conflict: its outcome decides what the reader
//!    must see, so it is reported for resolution ([`MvccError::IntentConflict`]; scans collect
//!    every conflicting intent of the span). Intents above the limit are invisible.
//! 2. An intent of the reader's **own** transaction (same epoch) contributes its newest
//!    provisional value with `seq <= reader seq` not rolled back by a savepoint. Intents of an
//!    older epoch of the same transaction are discarded writes and invisible.
//! 3. Committed versions with `read_ts < ts <= uncertainty_limit` make the read uncertain
//!    ([`MvccError::ReadWithinUncertainty`]).
//! 4. Otherwise the newest version `<= read_ts` decides: a value is returned, a tombstone hides
//!    the key, merge operands accumulate down to the next base (value / tombstone / oldest
//!    version) and are folded with `rustegon_storage::merge::full_merge`.
//!
//! GC: the engine view is pinned (iterator creation) **before** the GC threshold is checked, so
//! a read that passes the check cannot miss a version GC removed (gc.rs, "threshold ordering").

use bytes::Bytes;
use rustegon_storage::{DbIterator, LsmEngine, merge::full_merge};

use crate::{
    error::{MvccError, Result},
    gc::GcThreshold,
    hlc::Timestamp,
    key::{
        LOCAL_PREFIX, MvccKey, TXN_RECORD_MARKER, meta_key, next_logical_key, txn_record_anchor,
        txn_record_key, version_key,
    },
    value::{Intent, IntentValue, SeqRange, TxnId, TxnRecord, VersionValue},
};

/// The reading transaction, for the visibility of its own intents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnContext {
    /// Transaction id.
    pub txn_id: TxnId,
    /// Current epoch.
    pub epoch: u32,
    /// Sequence number of the read: own writes with a higher sequence are not yet visible.
    pub seq: u32,
    /// Sequence ranges rolled back by savepoints.
    pub ignored_seq_ranges: Vec<SeqRange>,
}

/// Parameters of a read.
#[derive(Debug, Clone, Copy)]
pub struct ReadOptions<'a> {
    /// Read timestamp.
    pub read_ts: Timestamp,
    /// Upper end of the uncertainty interval (`>= read_ts`; equal to it when there is no clock
    /// uncertainty, e.g. single node).
    pub uncertainty_limit: Timestamp,
    /// The reading transaction, if any.
    pub txn: Option<&'a TxnContext>,
}

impl ReadOptions<'_> {
    /// A non-transactional read at `read_ts` without uncertainty.
    #[must_use]
    pub fn at(read_ts: Timestamp) -> Self {
        Self {
            read_ts,
            uncertainty_limit: read_ts,
            txn: None,
        }
    }
}

/// What resolving one logical key produced.
enum KeyOutcome {
    Value(Option<Bytes>),
    Conflict(Intent),
}

/// MVCC reader over an engine.
#[derive(Clone, Copy)]
pub struct MvccReader<'a> {
    engine: &'a LsmEngine,
    gc: Option<&'a GcThreshold>,
}

impl std::fmt::Debug for MvccReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MvccReader")
            .field("gc", &self.gc)
            .finish_non_exhaustive()
    }
}

impl<'a> MvccReader<'a> {
    /// A reader of `engine`; reads below `gc` fail with `RGN-2007`.
    #[must_use]
    pub fn new(engine: &'a LsmEngine, gc: Option<&'a GcThreshold>) -> Self {
        Self { engine, gc }
    }

    /// Pins an engine view, then checks the GC threshold (module docs).
    fn open(&self, opts: &ReadOptions<'_>) -> Result<DbIterator> {
        if opts.uncertainty_limit < opts.read_ts {
            return Err(MvccError::InvalidArgument(
                "uncertainty limit below read timestamp".into(),
            ));
        }
        let iter = self.engine.iterator(None)?;
        if let Some(gc) = self.gc {
            gc.check(opts.read_ts)?;
        }
        Ok(iter)
    }

    /// The value of `key` at `opts.read_ts` (module docs); `None` when absent or deleted.
    ///
    /// # Errors
    /// [`MvccError::IntentConflict`], [`MvccError::ReadWithinUncertainty`],
    /// [`MvccError::BelowGcThreshold`] (`RGN-2007`), corruption and storage errors (including
    /// `RGN-1009` from merging).
    pub fn get(&self, key: &[u8], opts: &ReadOptions<'_>) -> Result<Option<Bytes>> {
        let mut iter = self.open(opts)?;
        let meta = meta_key(key);
        iter.seek(&meta)?;
        // Every entry of `key` starts with `key ‖ 0x00`, and no other logical key does
        // (data-model.md §3.2).
        if !iter.valid() || !iter.key().starts_with(&meta) {
            return Ok(None);
        }
        match resolve_key(&mut iter, key, opts, false)? {
            KeyOutcome::Value(v) => Ok(v),
            KeyOutcome::Conflict(intent) => Err(MvccError::IntentConflict(vec![intent])),
        }
    }

    /// The visible `(key, value)` pairs of the logical keys in `[start, end)`, ascending, at
    /// most `max_keys` of them (continue at `next_logical_key(last key)`).
    ///
    /// # Errors
    /// As [`MvccReader::get`]; a conflict lists every conflicting intent found in the scanned
    /// part of the span. A key in the span without an MVCC suffix is corruption.
    pub fn scan(
        &self,
        start: &[u8],
        end: &[u8],
        opts: &ReadOptions<'_>,
        max_keys: usize,
    ) -> Result<Vec<(Vec<u8>, Bytes)>> {
        let mut iter = self.open(opts)?;
        let mut out = Vec::new();
        let mut conflicts = Vec::new();
        iter.seek(start)?;
        while iter.valid() && out.len() < max_keys {
            let key = MvccKey::decode(iter.key())?.logical().to_vec();
            if key.as_slice() >= end {
                break;
            }
            match resolve_key(&mut iter, &key, opts, false)? {
                KeyOutcome::Value(Some(v)) => out.push((key.clone(), v)),
                KeyOutcome::Value(None) => {}
                KeyOutcome::Conflict(intent) => conflicts.push(intent),
            }
            // Past every entry of `key` (key.rs ordering argument).
            iter.seek(&next_logical_key(&key))?;
        }
        if conflicts.is_empty() {
            Ok(out)
        } else {
            Err(MvccError::IntentConflict(conflicts))
        }
    }

    /// The committed `(key, value)` pairs of the logical keys in `[start, end)` at `read_ts`,
    /// ascending, at most `max_keys` (continue at `next_logical_key(last key)`): every intent is
    /// invisible, whoever holds it.
    ///
    /// Only correct at a **closed** timestamp: one at or below which no transaction can still
    /// commit (`TxnCoordinator::close_timestamp`, PD-063). There every intent at or below
    /// `read_ts` belongs to a transaction that will commit above it or never, so reading past
    /// it is exactly what resolving it would give, without the waits and pushes of a
    /// transactional reader — which is what lets a logical dump read for longer than
    /// `txn.max_duration` (PD-067). The GC threshold is checked as for every read; pin it first.
    ///
    /// # Errors
    /// [`MvccError::BelowGcThreshold`] (`RGN-2007`), corruption and storage errors.
    pub fn scan_committed(
        &self,
        start: &[u8],
        end: &[u8],
        read_ts: Timestamp,
        max_keys: usize,
    ) -> Result<Vec<(Vec<u8>, Bytes)>> {
        let opts = ReadOptions::at(read_ts);
        let mut iter = self.open(&opts)?;
        let mut out = Vec::new();
        iter.seek(start)?;
        while iter.valid() && out.len() < max_keys {
            let key = MvccKey::decode(iter.key())?.logical().to_vec();
            if key.as_slice() >= end {
                break;
            }
            if let KeyOutcome::Value(Some(v)) = resolve_key(&mut iter, &key, &opts, true)? {
                out.push((key.clone(), v));
            }
            iter.seek(&next_logical_key(&key))?;
        }
        Ok(out)
    }

    /// The committed value of `key` at the closed timestamp `read_ts` (see
    /// [`MvccReader::scan_committed`]).
    ///
    /// # Errors
    /// As [`MvccReader::scan_committed`].
    pub fn get_committed(&self, key: &[u8], read_ts: Timestamp) -> Result<Option<Bytes>> {
        let opts = ReadOptions::at(read_ts);
        let mut iter = self.open(&opts)?;
        let meta = meta_key(key);
        iter.seek(&meta)?;
        if !iter.valid() || !iter.key().starts_with(&meta) {
            return Ok(None);
        }
        match resolve_key(&mut iter, key, &opts, true)? {
            KeyOutcome::Value(v) => Ok(v),
            KeyOutcome::Conflict(_) => Err(MvccError::corruption(
                "committed-only read reported an intent",
            )),
        }
    }

    /// The intent on `key`, if any (any transaction).
    ///
    /// # Errors
    /// Corruption and storage errors.
    pub fn get_intent(&self, key: &[u8]) -> Result<Option<IntentValue>> {
        self.engine
            .get(&meta_key(key), None)?
            .map(|v| IntentValue::decode(&v))
            .transpose()
    }

    /// The transaction record of `txn_id` anchored at `anchor`, if any.
    ///
    /// # Errors
    /// Corruption and storage errors.
    pub fn get_txn_record(&self, anchor: &[u8], txn_id: &TxnId) -> Result<Option<TxnRecord>> {
        self.engine
            .get(&meta_key(&txn_record_key(anchor, txn_id)), None)?
            .map(|v| TxnRecord::decode(&v))
            .transpose()
    }

    /// The transaction record of `txn_id` and its anchor, found without knowing the anchor:
    /// scans the transaction-record keyspace (`0x01 'k' …`). Records exist only for
    /// transactions with intents that have not finished (a commit or rollback deletes them),
    /// plus aborted ones left by a crash, so the scan is short; it serves the rare status
    /// lookup of a transaction whose coordinator is gone (PD-121).
    ///
    /// # Errors
    /// Corruption and storage errors.
    pub fn find_txn_record(&self, txn_id: &TxnId) -> Result<Option<(Vec<u8>, TxnRecord)>> {
        let prefix = [LOCAL_PREFIX, TXN_RECORD_MARKER];
        let mut iter = self.engine.iterator(None)?;
        iter.seek(&prefix)?;
        while iter.valid() && iter.key().starts_with(&prefix) {
            if let MvccKey::Meta(logical) = MvccKey::decode(iter.key())?
                && let Some(anchor) = txn_record_anchor(logical, txn_id)
            {
                return Ok(Some((anchor, TxnRecord::decode(&iter.value())?)));
            }
            iter.next()?;
        }
        Ok(None)
    }
}

/// Applies the intent on `key` to a read (module docs, rules 1 and 2): `Some` when it decides
/// the outcome (a conflict, or an own value / tombstone); an own merge operand is pushed to
/// `operands` and `None` returned, as for an invisible intent.
fn apply_intent(
    intent: IntentValue,
    key: &[u8],
    opts: &ReadOptions<'_>,
    operands: &mut Vec<Bytes>,
) -> Result<Option<KeyOutcome>> {
    match opts.txn {
        Some(txn) if txn.txn_id == intent.meta.txn_id => {
            if intent.meta.epoch > txn.epoch {
                return Err(MvccError::InvalidArgument(format!(
                    "read at epoch {} sees own intent of later epoch {}",
                    txn.epoch, intent.meta.epoch
                )));
            }
            // An older epoch's intent holds discarded writes: invisible.
            let visible = if intent.meta.epoch == txn.epoch {
                intent.visible(txn.seq, &txn.ignored_seq_ranges)
            } else {
                None
            };
            Ok(match visible {
                Some((_, VersionValue::Value(v))) => Some(KeyOutcome::Value(Some(v.clone()))),
                Some((_, VersionValue::Tombstone)) => Some(KeyOutcome::Value(None)),
                Some((_, VersionValue::MergeOperand(op))) => {
                    operands.push(op.clone());
                    None
                }
                None => None,
            })
        }
        _ if intent.meta.write_ts <= opts.uncertainty_limit => {
            Ok(Some(KeyOutcome::Conflict(Intent {
                key: key.to_vec(),
                meta: intent.meta,
            })))
        }
        // Written above everything the reader may observe.
        _ => Ok(None),
    }
}

/// Resolves `key` (module docs). `iter` is on the first entry of `key`; it is left anywhere.
/// `committed_only`: skip the intent, whoever holds it ([`MvccReader::scan_committed`]).
fn resolve_key(
    iter: &mut DbIterator,
    key: &[u8],
    opts: &ReadOptions<'_>,
    committed_only: bool,
) -> Result<KeyOutcome> {
    // Merge operands seen so far, newest first.
    let mut operands: Vec<Bytes> = Vec::new();
    let meta = meta_key(key);
    if !committed_only && iter.key() == meta.as_slice() {
        let intent = IntentValue::decode(&iter.value())?;
        if let Some(outcome) = apply_intent(intent, key, opts, &mut operands)? {
            return Ok(outcome);
        }
    }

    // Versions newer than the uncertainty limit are irrelevant: skip them with one seek.
    iter.seek(&version_key(key, opts.uncertainty_limit))?;
    let mut base: Option<Bytes> = None;
    while iter.valid() && iter.key().starts_with(&meta) {
        let MvccKey::Version(_, ts) = MvccKey::decode(iter.key())? else {
            return Err(MvccError::corruption("second meta entry of a key"));
        };
        if ts > opts.read_ts {
            return Err(MvccError::ReadWithinUncertainty {
                read_ts: opts.read_ts,
                existing: ts,
            });
        }
        match VersionValue::decode(&iter.value())? {
            VersionValue::Value(v) => {
                base = Some(v);
                break;
            }
            VersionValue::Tombstone => break,
            VersionValue::MergeOperand(op) => operands.push(op),
        }
        iter.next()?;
    }
    if operands.is_empty() {
        return Ok(KeyOutcome::Value(base));
    }
    let merged = full_merge(base.as_deref(), operands.iter().map(Bytes::as_ref))?;
    Ok(KeyOutcome::Value(Some(Bytes::from(merged))))
}
