// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Write-path index maintenance (indexing.md §4, database-engine.md §3 step 4; FR-IDX-002).
//!
//! For one changed document: `old_entries = keys(index, old)`, `new_entries = keys(index,
//! new)`; deletes for `old − new`, puts for `new − old` (and for keys whose value changed,
//! e.g. a covered field). The changes are written through the caller's [`Txn`], so index
//! entries are MVCC intents like the document: they commit or abort with it, and an index
//! read at a snapshot is consistent with the base data at that snapshot.
//!
//! Per index state (database-engine.md §2.3): `DeleteOnly` → deletes only; `WriteOnly`,
//! `Backfilling`, `Validating`, `Public` → deletes and puts; `Dropping` → nothing.
//!
//! # Unique enforcement (`RGN-1005 DuplicateKey`)
//! Each unique put is a read-modify-write of the unique key ([`Txn::update`]): if the key holds
//! an entry (committed, or an intent of this transaction) owned by another `_id`, the write is
//! refused. The read and the write go through the transaction layer's conflict rules, so two
//! concurrent transactions cannot both insert the same unique key:
//! - an uncommitted intent of another transaction on the key is waited for (or pushed), then
//!   the check sees its outcome;
//! - SERIALIZABLE: the read joins the refresh set, so a key committed by another transaction
//!   after our read timestamp fails our commit-time refresh (`RGN-2001`, retried — and the
//!   retry then sees the duplicate);
//! - SNAPSHOT: writing a key committed after the snapshot is a write-write conflict;
//! - READ COMMITTED: `update` reads the latest committed value under the range latch and
//!   re-evaluates on conflicts, so the check and the write are atomic.
//!
//! A rejection after some entries were written must not leave them behind when the caller
//! still commits (it returns a request error without aborting): the changes are applied under
//! a savepoint that is rolled back on rejection.
//!
//! # Unique deletes (online builds, FR-IDX-003)
//! While a unique index is being built, the data may still hold a duplicate the backfill has
//! not reached: document `B` may own unique key `k` while document `A` (not yet backfilled)
//! also has `k`. When `A` is then updated away from `k`, a blind delete of `k` would remove
//! `B`'s entry. A unique delete is therefore a read-modify-write that tombstones the key only
//! when it is absent or owned by the deleting document, and leaves another document's entry
//! alone. Tombstoning an absent key is deliberate: the write makes the deleting transaction
//! write-write conflict with a concurrent backfill batch that writes the (now stale) entry of
//! the old version (`crate::build` relies on this, see its module docs).

use std::collections::BTreeMap;

use bytes::Bytes;
use rustegon_catalog::IndexDescriptor;
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_mvcc::VersionValue;
use rustegon_txn::{Txn, TxnError};

use crate::{
    entry::EntryValue,
    keygen::{DocEntries, PartialFilter, display_key_part, index_entries},
};

/// Savepoint protecting a batch of index changes.
const SAVEPOINT: &str = "rustegon.index.maintenance";
/// Length of the `0x03 tenant db coll family index_id` prefix of index entry keys.
pub const ENTRY_PREFIX_LEN: usize = 15;

/// Failure of index maintenance.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    /// The write is refused (`RGN-1005`, `RGN-1008`, `RGN-1025`, partial-filter or document
    /// errors). Nothing of the batch was written (the savepoint was rolled back).
    #[error(transparent)]
    Rejected(Error),
    /// Transaction error (conflicts are retryable by the caller's retry loop).
    #[error(transparent)]
    Txn(#[from] TxnError),
}

/// A unique put and what is needed to report a duplicate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UniquePut {
    index: String,
    id_element: Vec<u8>,
    display: String,
}

/// One entry write.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Put {
    key: Vec<u8>,
    value: Vec<u8>,
    unique: Option<UniquePut>,
}

/// One entry delete; `owner` = `enc(_id)` of the deleting document for a unique entry (module
/// docs, "Unique deletes").
#[derive(Debug, Clone, PartialEq, Eq)]
struct Delete {
    key: Vec<u8>,
    owner: Option<Vec<u8>>,
}

/// Index changes of one document write, computed by [`plan_changes`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexChanges {
    deletes: Vec<Delete>,
    puts: Vec<Put>,
    /// Indexes (by id) that saw an array value for the first time: the caller sets their
    /// `multikey` flag (`rustegon_catalog::index::ops::mark_multikey`).
    pub newly_multikey: Vec<u32>,
}

impl IndexChanges {
    /// Whether there is nothing to write.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.deletes.is_empty() && self.puts.is_empty()
    }

    /// Number of entry deletes.
    #[must_use]
    pub fn delete_count(&self) -> usize {
        self.deletes.len()
    }

    /// Number of entry puts.
    #[must_use]
    pub fn put_count(&self) -> usize {
        self.puts.len()
    }
}

/// Computes the index changes of replacing `old` by `new` (`None` = absent) for the document
/// `id`, over `indexes` (normally every non-dropping index of the collection).
///
/// The old document's entries are computed leniently: a document whose entries cannot be
/// computed (e.g. two arrays in a compound index while it was in `DeleteOnly`) was never
/// indexed, so it has nothing to delete. The new document's errors reject the write.
///
/// # Errors
/// [`IndexError::Rejected`] from key generation of `new` (`RGN-1025`, `RGN-1008`, …).
pub fn plan_changes(
    indexes: &[IndexDescriptor],
    id: &Value,
    old: Option<&Document>,
    new: Option<&Document>,
    filter: &dyn PartialFilter,
) -> Result<IndexChanges, IndexError> {
    let mut changes = IndexChanges::default();
    for index in indexes {
        if !index.state.deletes_entries() {
            continue;
        }
        let old_entries = match old {
            Some(d) => index_entries(index, id, d, filter).unwrap_or_default(),
            None => DocEntries::default(),
        };
        let new_entries = match new {
            Some(d) if index.state.adds_entries() => {
                index_entries(index, id, d, filter).map_err(IndexError::Rejected)?
            }
            _ => DocEntries::default(),
        };
        if new_entries.saw_array && !index.multikey {
            changes.newly_multikey.push(index.id);
        }
        diff(
            index,
            &old_entries.entries,
            &new_entries.entries,
            &mut changes,
        );
    }
    Ok(changes)
}

fn diff(
    index: &IndexDescriptor,
    old: &BTreeMap<Vec<u8>, Vec<u8>>,
    new: &BTreeMap<Vec<u8>, Vec<u8>>,
    changes: &mut IndexChanges,
) {
    for (key, value) in old {
        if !new.contains_key(key) {
            let owner = index.unique.then(|| {
                // Same fallback as for puts: an empty owner only makes the delete skip more.
                EntryValue::decode(value)
                    .ok()
                    .and_then(|v| v.id_element)
                    .unwrap_or_default()
            });
            changes.deletes.push(Delete {
                key: key.clone(),
                owner,
            });
        }
    }
    for (key, value) in new {
        if old.get(key) == Some(value) {
            continue;
        }
        let unique = index.unique.then(|| {
            let part = key.get(ENTRY_PREFIX_LEN..).unwrap_or_default();
            UniquePut {
                index: index.name.clone(),
                // Unique entry values always carry the id (keygen); an empty fallback can only
                // make the duplicate check stricter.
                id_element: EntryValue::decode(value)
                    .ok()
                    .and_then(|v| v.id_element)
                    .unwrap_or_default(),
                display: display_key_part(index, part),
            }
        });
        changes.puts.push(Put {
            key: key.clone(),
            value: value.clone(),
            unique,
        });
    }
}

/// Outcome of one unique check inside [`Txn::update`].
enum Check {
    Ok,
    Duplicate,
    Corrupt(Error),
}

/// Writes `changes` through `txn` (module docs: deletes first, then puts; unique puts checked
/// atomically; all-or-nothing on rejection).
///
/// # Errors
/// [`IndexError::Rejected`] with `RGN-1005 DuplicateKey` (details `index`, `key`) or
/// `RGN-5002` for a corrupt unique entry; [`IndexError::Txn`] for transaction errors.
pub fn apply_changes(txn: &mut Txn, changes: &IndexChanges) -> Result<(), IndexError> {
    if changes.is_empty() {
        return Ok(());
    }
    txn.savepoint(SAVEPOINT)?;
    match write_all(txn, changes) {
        Ok(()) => {
            txn.release_savepoint(SAVEPOINT)?;
            Ok(())
        }
        Err(IndexError::Rejected(e)) => {
            txn.rollback_to_savepoint(SAVEPOINT)?;
            txn.release_savepoint(SAVEPOINT)?;
            Err(IndexError::Rejected(e))
        }
        Err(e) => Err(e),
    }
}

fn write_all(txn: &mut Txn, changes: &IndexChanges) -> Result<(), IndexError> {
    // Deletes first: a unique key moving from this document's old version to its new one, or
    // between documents of this transaction, is free again before it is re-checked.
    for del in &changes.deletes {
        let Some(owner) = &del.owner else {
            txn.delete(&del.key)?;
            continue;
        };
        // Module docs, "Unique deletes": tombstone unless another document owns the key. A
        // corrupt entry is tombstoned too (it cannot be attributed to anyone).
        txn.update(&del.key, |current| {
            let foreign = current
                .and_then(|b| EntryValue::decode(b).ok())
                .and_then(|v| v.id_element)
                .is_some_and(|id| id != *owner);
            (!foreign).then_some(VersionValue::Tombstone)
        })?;
    }
    for put in &changes.puts {
        let Some(u) = &put.unique else {
            txn.put(&put.key, put.value.clone())?;
            continue;
        };
        let value = Bytes::from(put.value.clone());
        let mut check = Check::Ok;
        // `f` may run several times (READ COMMITTED re-evaluation); it must be short (it runs
        // under the range latch), so it only compares bytes.
        txn.update(&put.key, |current| {
            check = match current.map(|b| EntryValue::decode(b)) {
                None => Check::Ok,
                Some(Ok(v)) if v.id_element.as_deref() == Some(u.id_element.as_slice()) => {
                    Check::Ok
                }
                Some(Ok(_)) => Check::Duplicate,
                Some(Err(e)) => Check::Corrupt(e),
            };
            matches!(check, Check::Ok).then(|| VersionValue::Value(value.clone()))
        })?;
        match check {
            Check::Ok => {}
            Check::Duplicate => {
                return Err(IndexError::Rejected(
                    Error::new(
                        ErrorCode::DuplicateKey,
                        format!("duplicate key {} in unique index {}", u.display, u.index),
                    )
                    .with_detail("index", u.index.clone())
                    .with_detail("key", u.display.clone()),
                ));
            }
            Check::Corrupt(e) => return Err(IndexError::Rejected(e)),
        }
    }
    Ok(())
}

/// Plans and applies the index changes of one document write: [`plan_changes`] then
/// [`apply_changes`]; returns the ids of indexes that became multikey.
///
/// # Errors
/// As both.
pub fn maintain(
    txn: &mut Txn,
    indexes: &[IndexDescriptor],
    id: &Value,
    old: Option<&Document>,
    new: Option<&Document>,
    filter: &dyn PartialFilter,
) -> Result<Vec<u32>, IndexError> {
    let changes = plan_changes(indexes, id, old, new, filter)?;
    apply_changes(txn, &changes)?;
    Ok(changes.newly_multikey)
}
