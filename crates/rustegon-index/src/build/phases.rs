// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transaction bodies of the build steps (one body = one transaction; see the parent module
//! docs for the invariants they rely on).

use std::{cell::RefCell, collections::BTreeMap};

use rustegon_catalog::{
    CatalogError, CatalogRead, CollectionDescriptor, Descriptor, DescriptorState, IndexDescriptor,
    IndexState, Mutation, get_descriptor,
    index::{
        codec::decode_index_descriptor,
        ops::{index_descriptor_key, mark_multikey, transition_index},
    },
    ops::KvPairs,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, value_to_json},
    keyspace::{Family, family_prefix},
    rdoc,
};
use rustegon_txn::{Txn, TxnError};

use super::{
    BuildConfig, BuildProgress, CANCELLED, MAX_OFFENDING_IDS,
    record::{BuildRecord, JobPhase, build_record_key, decode_build_record, encode_build_record},
};
use crate::{
    keygen::{PartialFilter, display_key_part, index_entries},
    maintain::{ENTRY_PREFIX_LEN, IndexError, apply_changes, plan_changes},
    scan::{index_span, prefix_end},
};

/// Outer error: transaction (retried by the coordinator); inner: request error, returned only
/// before anything was written.
pub(super) type Body<T> = Result<Result<T, Error>, TxnError>;

macro_rules! req {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Ok(Err(e.into())),
        }
    };
}

/// `_id` field name.
const ID: &str = "_id";

/// What one step did (committed with its transaction).
#[derive(Debug)]
pub(super) enum Outcome {
    /// Work done, more to do; `docs` / `bytes` processed (throttling input).
    Progress {
        progress: BuildProgress,
        docs: u64,
        bytes: u64,
    },
    /// The index became (or already was) public; the record is gone.
    Public(IndexDescriptor),
    /// The build failed: the index is now `Dropping` and the record in phase cleanup.
    Failed(Error),
    /// Cleanup done, record deleted; the failure message, if any.
    Finished(Option<String>),
    /// There is no record (finished, dropped and cleaned, or never started).
    Missing,
}

/// [`CatalogRead`] over a transaction; transaction errors are kept aside so that they reach the
/// coordinator's retry loop as such (not as an opaque catalog read error).
pub(super) struct TxnCatalog<'a> {
    txn: RefCell<&'a mut Txn>,
    failed: RefCell<Option<TxnError>>,
}

impl TxnCatalog<'_> {
    fn fail(&self, e: TxnError) -> Error {
        let err = Error::new(e.code(), e.to_string());
        *self.failed.borrow_mut() = Some(e);
        err
    }
}

impl CatalogRead for TxnCatalog<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let r = self.txn.borrow_mut().get(key);
        r.map(|v| v.map(|b| b.to_vec())).map_err(|e| self.fail(e))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<KvPairs, Error> {
        let Some(end) = prefix_end(prefix) else {
            return Err(Error::new(ErrorCode::Internal, "unbounded catalog scan"));
        };
        let r = self.txn.borrow_mut().scan(prefix, &end, usize::MAX);
        r.map(|rows| rows.into_iter().map(|(k, v)| (k, v.to_vec())).collect())
            .map_err(|e| self.fail(e))
    }
}

/// Runs a catalog operation over `txn` (outer error = transaction error).
pub(super) fn catalog<T>(
    txn: &mut Txn,
    op: impl FnOnce(&TxnCatalog<'_>) -> Result<T, CatalogError>,
) -> Body<T> {
    let reader = TxnCatalog {
        txn: RefCell::new(txn),
        failed: RefCell::new(None),
    };
    let result = op(&reader);
    if let Some(e) = reader.failed.into_inner() {
        return Err(e);
    }
    Ok(result.map_err(Error::from))
}

/// Applies catalog mutations through `txn`.
pub(super) fn apply(txn: &mut Txn, mutations: &[Mutation]) -> Result<(), TxnError> {
    for m in mutations {
        match m {
            Mutation::Put { key, value } => txn.put(key, value.clone())?,
            Mutation::Delete { key } => txn.delete(key)?,
        }
    }
    Ok(())
}

/// Scanned `(key, value)` rows.
type Rows = Vec<(Vec<u8>, bytes::Bytes)>;

/// Up to `max` rows of `[span_start, end)` strictly after `cursor` (all of them from
/// `span_start` without one).
///
/// The scan restarts *at* the cursor and drops it rather than starting at `cursor ‖ 0x00`:
/// logical keys must not be a prefix of another key followed by `0x00` (the MVCC separator,
/// data-model.md §3.2), and such a start key sorts among the cursor's own versions, which would
/// return the cursor again.
fn scan_after(
    txn: &mut Txn,
    span_start: &[u8],
    cursor: Option<&[u8]>,
    end: &[u8],
    max: usize,
) -> Result<Rows, TxnError> {
    let Some(c) = cursor else {
        return txn.scan(span_start, end, max);
    };
    let mut rows = txn.scan(c, end, max.saturating_add(1))?;
    if rows.first().is_some_and(|(k, _)| k.as_slice() == c) {
        rows.remove(0);
    } else {
        rows.truncate(max);
    }
    Ok(rows)
}

fn put_record(txn: &mut Txn, rec: &BuildRecord) -> Body<()> {
    let bytes = req!(encode_build_record(rec));
    txn.put(&rec.key(), bytes)?;
    Ok(Ok(()))
}

fn progress(ix: &IndexDescriptor, rec: &BuildRecord) -> BuildProgress {
    BuildProgress {
        state: ix.state,
        phase: rec.phase,
        docs_scanned: rec.docs_scanned,
        entries_written: rec.entries_written,
    }
}

fn id_text(id: &Value) -> String {
    value_to_json(id, JsonMode::Canonical)
}

/// `RGN-1022 IndexBuildFailed` (indexing.md §5: the report lists the offending `_id`s).
fn build_failed(ix: &IndexDescriptor, reason: &str, ids: &[String], key: Option<&str>) -> Error {
    let mut e = Error::new(
        ErrorCode::IndexBuildFailed,
        format!("index {} build failed: {reason}", ix.name),
    )
    .with_detail("index", ix.name.clone())
    .with_detail("offending_ids", format!("[{}]", ids.join(",")));
    if let Some(k) = key {
        e = e.with_detail("key", k);
    }
    e
}

/// One step of the job of index `index_id` (dispatch on record phase and index state).
pub(super) fn step_body(
    txn: &mut Txn,
    collection_id: u32,
    index_id: u32,
    config: &BuildConfig,
    filter: &dyn PartialFilter,
) -> Body<Outcome> {
    let key = build_record_key(collection_id, index_id);
    let Some(bytes) = txn.get(&key)? else {
        return Ok(Ok(Outcome::Missing));
    };
    let mut rec = req!(decode_build_record(&bytes));
    let Some(ix_bytes) = txn.get(&index_descriptor_key(collection_id, index_id))? else {
        // Nothing can be built or cleaned without the descriptor (it is never deleted, so
        // this is only reachable through corruption); drop the job.
        txn.delete(&key)?;
        return Ok(Ok(Outcome::Finished(Some(
            "index descriptor missing".into(),
        ))));
    };
    let ix = req!(decode_index_descriptor(&ix_bytes));
    if rec.phase == JobPhase::Cleanup {
        return cleanup(txn, &ix, rec, config);
    }
    let coll = match req!(catalog(txn, |r| get_descriptor(r, collection_id))?) {
        Some(Descriptor::Collection(c)) if c.state == DescriptorState::Public => c,
        _ => {
            // The collection was dropped: its whole span (indexes included) is reclaimed with
            // it, so the job just ends.
            txn.delete(&key)?;
            return Ok(Ok(Outcome::Finished(Some("collection dropped".into()))));
        }
    };
    match ix.state {
        IndexState::DeleteOnly => advance(txn, &coll, &ix, &rec, IndexState::WriteOnly),
        IndexState::WriteOnly => advance(txn, &coll, &ix, &rec, IndexState::Backfilling),
        IndexState::Backfilling => backfill_batch(txn, &coll, ix, rec, config, filter),
        IndexState::Validating => validate(txn, &coll, ix, rec, filter),
        IndexState::Public => {
            txn.delete(&key)?;
            Ok(Ok(Outcome::Public(ix)))
        }
        IndexState::Dropping => {
            // Dropped by someone else (DROP INDEX) without touching the record: clean up.
            rec.phase = JobPhase::Cleanup;
            rec.cursor = None;
            rec.error.get_or_insert_with(|| CANCELLED.to_owned());
            req!(put_record(txn, &rec)?);
            Ok(Ok(Outcome::Progress {
                progress: progress(&ix, &rec),
                docs: 0,
                bytes: 0,
            }))
        }
    }
}

/// One state transition (its own transaction: database-engine.md §2.3 requires every node to
/// run with state N before N+1 is entered; locally, writers serialize with the descriptor
/// rewrite, see the parent module docs).
fn advance(
    txn: &mut Txn,
    coll: &CollectionDescriptor,
    ix: &IndexDescriptor,
    rec: &BuildRecord,
    to: IndexState,
) -> Body<Outcome> {
    let (next, m) = req!(catalog(txn, |r| transition_index(r, coll, ix, to))?);
    apply(txn, &m)?;
    Ok(Ok(Outcome::Progress {
        progress: progress(&next, rec),
        docs: 0,
        bytes: 0,
    }))
}

/// Turns the build into a cleanup in the current transaction: index → `Dropping` (writers stop
/// maintaining it), record → phase cleanup with the failure message.
fn fail(
    txn: &mut Txn,
    coll: &CollectionDescriptor,
    ix: &IndexDescriptor,
    mut rec: BuildRecord,
    err: Error,
) -> Body<Outcome> {
    let (_, m) = req!(catalog(txn, |r| transition_index(
        r,
        coll,
        ix,
        IndexState::Dropping
    ))?);
    apply(txn, &m)?;
    rec.phase = JobPhase::Cleanup;
    rec.cursor = None;
    rec.error = Some(err.message().to_owned());
    req!(put_record(txn, &rec)?);
    Ok(Ok(Outcome::Failed(err)))
}

fn document_span(coll: &CollectionDescriptor) -> Result<(Vec<u8>, Vec<u8>), TxnError> {
    let start = family_prefix(coll.database_id, coll.id, Family::Document);
    let end =
        prefix_end(&start).ok_or_else(|| TxnError::Internal("document span without end".into()))?;
    Ok((start, end))
}

fn doc_id(doc: &Document) -> Result<Value, Error> {
    doc.get(ID)
        .cloned()
        .ok_or_else(|| Error::new(ErrorCode::StorageCorruption, "stored document without _id"))
}

/// One backfill batch (parent module docs: step 3, invariants I2 and I3).
fn backfill_batch(
    txn: &mut Txn,
    coll: &CollectionDescriptor,
    mut ix: IndexDescriptor,
    mut rec: BuildRecord,
    config: &BuildConfig,
    filter: &dyn PartialFilter,
) -> Body<Outcome> {
    let (span_start, end) = document_span(coll)?;
    let max = config.batch_docs.max(1);
    let rows = scan_after(txn, &span_start, rec.cursor.as_deref(), &end, max)?;
    let reached_end = rows.len() < max;
    let (mut docs, mut bytes, mut saw_array, mut cut) = (0u64, 0u64, false, false);
    for (key, value) in &rows {
        if docs > 0 && bytes >= config.batch_bytes {
            cut = true;
            break;
        }
        let doc = req!(rdoc::decode(value).map_err(Error::from));
        let id = req!(doc_id(&doc));
        let planned = plan_changes(std::slice::from_ref(&ix), &id, None, Some(&doc), filter);
        let changes = match planned {
            Ok(c) => c,
            Err(IndexError::Txn(e)) => return Err(e),
            // RGN-1025 / RGN-1008 / partial-filter errors of existing data fail the build.
            Err(IndexError::Rejected(e)) => return fail(txn, coll, &ix, rec, e),
        };
        match apply_changes(txn, &changes) {
            Ok(()) => {}
            Err(IndexError::Txn(e)) => return Err(e),
            Err(IndexError::Rejected(e)) if e.code() == ErrorCode::DuplicateKey => {
                let key_text = e.details().get("key").cloned();
                let err = build_failed(&ix, e.message(), &[id_text(&id)], key_text.as_deref());
                return fail(txn, coll, &ix, rec, err);
            }
            Err(IndexError::Rejected(e)) => return fail(txn, coll, &ix, rec, e),
        }
        saw_array |= !changes.newly_multikey.is_empty();
        rec.entries_written += u64::try_from(changes.put_count()).unwrap_or(u64::MAX);
        docs += 1;
        bytes += u64::try_from(value.len()).unwrap_or(u64::MAX);
        rec.cursor = Some(key.clone());
    }
    rec.docs_scanned += docs;
    if saw_array && let Some((next, m)) = req!(catalog(txn, |r| mark_multikey(r, coll, &ix))?) {
        apply(txn, &m)?;
        ix = next;
    }
    if reached_end && !cut {
        let (next, m) = req!(catalog(txn, |r| transition_index(
            r,
            coll,
            &ix,
            IndexState::Validating
        ))?);
        apply(txn, &m)?;
        ix = next;
    }
    req!(put_record(txn, &rec)?);
    Ok(Ok(Outcome::Progress {
        progress: progress(&ix, &rec),
        docs,
        bytes,
    }))
}

/// Validation (parent module docs: step 4, invariant I4): the index span must equal the entries the
/// documents produce, at this transaction's snapshot; unique collisions fail the build.
fn validate(
    txn: &mut Txn,
    coll: &CollectionDescriptor,
    mut ix: IndexDescriptor,
    rec: BuildRecord,
    filter: &dyn PartialFilter,
) -> Body<Outcome> {
    let (start, end) = document_span(coll)?;
    // Expected entries: key -> (value, owner _id text).
    let mut expected: BTreeMap<Vec<u8>, (Vec<u8>, String)> = BTreeMap::new();
    let mut offending: Vec<String> = Vec::new();
    let mut saw_array = false;
    for (_, value) in txn.scan(&start, &end, usize::MAX)? {
        let doc = req!(rdoc::decode(&value).map_err(Error::from));
        let id = req!(doc_id(&doc));
        let entries = match index_entries(&ix, &id, &doc, filter) {
            Ok(e) => e,
            Err(e) => return fail(txn, coll, &ix, rec, e),
        };
        saw_array |= entries.saw_array;
        for (k, v) in entries.entries {
            match expected.get(&k) {
                // A unique key produced by two documents (their values carry different ids).
                Some((v0, owner)) if *v0 != v => {
                    if offending.len() < MAX_OFFENDING_IDS {
                        offending.push(owner.clone());
                        offending.push(id_text(&id));
                    }
                }
                Some(_) => {}
                None => {
                    expected.insert(k, (v, id_text(&id)));
                }
            }
        }
    }
    if !offending.is_empty() {
        offending.truncate(MAX_OFFENDING_IDS);
        let err = build_failed(&ix, "duplicate key in unique index", &offending, None);
        return fail(txn, coll, &ix, rec, err);
    }
    let (ix_start, ix_end) = req!(index_span(&ix));
    let actual = txn.scan(&ix_start, &ix_end, usize::MAX)?;
    let same = actual.len() == expected.len()
        && actual
            .iter()
            .zip(&expected)
            .all(|((ka, va), (ke, (ve, _)))| ka == ke && va.as_ref() == ve.as_slice());
    if !same {
        // Unreachable while the invariants hold; refusing the index is the safe outcome.
        let reason = format!(
            "validation found {} entries, documents produce {}",
            actual.len(),
            expected.len()
        );
        // Name the first entry the documents do not produce (or the first one missing) so the
        // report points at a document.
        let extra = actual
            .iter()
            .find(|(k, _)| !expected.contains_key(k))
            .map(|(k, _)| k.clone());
        let missing = expected
            .iter()
            .find(|(k, _)| !actual.iter().any(|(ka, _)| ka == *k))
            .map(|(k, (_, id))| (k.clone(), id.clone()));
        let part = |k: &[u8]| display_key_part(&ix, k.get(ENTRY_PREFIX_LEN..).unwrap_or_default());
        let mut err = build_failed(&ix, &reason, &[], None);
        if let Some(k) = extra {
            err = err.with_detail("unexpected_entry", part(&k));
        }
        if let Some((k, id)) = missing {
            err = err
                .with_detail("missing_entry", part(&k))
                .with_detail("missing_for", id);
        }
        return fail(txn, coll, &ix, rec, err);
    }
    // The flag is set by the batches and writers; this only repairs a missed one.
    if saw_array && let Some((next, m)) = req!(catalog(txn, |r| mark_multikey(r, coll, &ix))?) {
        apply(txn, &m)?;
        ix = next;
    }
    let (public, m) = req!(catalog(txn, |r| transition_index(
        r,
        coll,
        &ix,
        IndexState::Public
    ))?);
    apply(txn, &m)?;
    txn.delete(&rec.key())?;
    Ok(Ok(Outcome::Public(public)))
}

/// One cleanup batch of a `Dropping` index: deletes up to `cleanup_batch_keys` entries after
/// the cursor; the record is deleted with the last batch.
fn cleanup(
    txn: &mut Txn,
    ix: &IndexDescriptor,
    mut rec: BuildRecord,
    config: &BuildConfig,
) -> Body<Outcome> {
    let (span_start, end) = req!(index_span(ix));
    let max = config.cleanup_batch_keys.max(1);
    let rows = scan_after(txn, &span_start, rec.cursor.as_deref(), &end, max)?;
    for (k, _) in &rows {
        txn.delete(k)?;
    }
    if rows.len() < max {
        txn.delete(&rec.key())?;
        return Ok(Ok(Outcome::Finished(rec.error)));
    }
    rec.cursor = rows.last().map(|(k, _)| k.clone());
    req!(put_record(txn, &rec)?);
    Ok(Ok(Outcome::Progress {
        progress: progress(ix, &rec),
        docs: 0,
        bytes: 0,
    }))
}
