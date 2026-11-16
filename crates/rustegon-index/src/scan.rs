// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! A minimal index range read (first part of TC-IDX-001; the planner and executor of the query
//! lane replace it).
//!
//! Bounds are **prefixes of the key tuple in index key order**: `[v1]` bounds the first field,
//! `[v1, v2]` the first two, and so on (for a wildcard index the tuple is `(path string, value)`).
//! For a descending field, "lower" in key order is the *larger* value. Because every element
//! encoding is prefix-free, all entries whose first `k` elements equal a `k`-tuple share its
//! encoding as a byte prefix, so an inclusive bound covers exactly them.
//!
//! Hits flagged `truncated` (key part cut at 3 KiB, indexing.md §3) — and every hit when a
//! bound itself is longer than the kept prefix (the scan is then widened to that prefix) — may
//! not match: the caller must re-check the document.

use std::ops::Bound;

use rustegon_catalog::IndexDescriptor;
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    keyenc::encode_element,
    keyspace::{Family, ShardHash, family_prefix, hash16},
};
use rustegon_txn::Txn;

use crate::{
    entry::{EntryValue, TRUNCATED_PREFIX, decode_id_element, id_element_of_key},
    keygen::key_directions,
    maintain::{ENTRY_PREFIX_LEN, IndexError},
};

/// One index entry returned by [`scan_index`].
#[derive(Debug, Clone, PartialEq)]
pub struct IndexHit {
    /// `_id` of the document (decoded from its key encoding: numeric type not preserved).
    pub id: Value,
    /// `enc(_id)`, the identity used by document keys.
    pub id_element: Vec<u8>,
    /// The match must be re-checked against the document (module docs).
    pub truncated: bool,
    /// Covered fields, if the index has any.
    pub include: Option<Document>,
}

/// `0x03 tenant db coll ('I'|'U') index_id`: the span of every entry of `index`.
#[must_use]
pub fn index_span_prefix(index: &IndexDescriptor) -> Vec<u8> {
    let family = if index.unique {
        Family::Unique
    } else {
        Family::Index
    };
    let mut p = family_prefix(index.database_id, index.collection_id, family);
    p.extend_from_slice(&index.id.to_be_bytes());
    p
}

/// The smallest key greater than every key starting with `prefix` (`None`: all `0xFF`).
#[must_use]
pub fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

/// The document key of an `_id` element read from an index entry (data-model.md §3.2: family
/// `D`, `hash16(enc(_id))` when the shard key is hashed, then the element), without decoding
/// the element, so the identity is exactly the one the entry was written for.
#[must_use]
pub fn document_key_for_element(
    database_id: u32,
    collection_id: u32,
    shard: ShardHash,
    id_element: &[u8],
) -> Vec<u8> {
    let mut k = family_prefix(database_id, collection_id, Family::Document);
    if shard == ShardHash::Hashed {
        k.extend_from_slice(&hash16(id_element).to_be_bytes());
    }
    k.extend_from_slice(id_element);
    k
}

/// `[start, end)` of every entry of `index`.
///
/// # Errors
/// `RGN-5000 Internal` if the prefix has no successor (impossible for user namespaces).
pub fn index_span(index: &IndexDescriptor) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let start = index_span_prefix(index);
    let end = prefix_end(&start).ok_or_else(|| internal("index span without end"))?;
    Ok((start, end))
}

fn internal(msg: &str) -> Error {
    Error::new(ErrorCode::Internal, msg)
}

/// Encoded bound tuple; `true` when it was cut to the kept prefix of truncated keys.
fn encode_bound(
    index: &IndexDescriptor,
    tuple: &[Option<Value>],
) -> Result<(Vec<u8>, bool), Error> {
    let dirs = key_directions(index);
    if tuple.len() > dirs.len() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "bound has {} values, index {} has {}",
                tuple.len(),
                index.name,
                dirs.len()
            ),
        ));
    }
    let mut part = Vec::new();
    for (v, dir) in tuple.iter().zip(dirs) {
        encode_element(&mut part, v.as_ref(), dir)?;
    }
    let widened = part.len() > TRUNCATED_PREFIX;
    part.truncate(TRUNCATED_PREFIX);
    let mut key = index_span_prefix(index);
    key.extend_from_slice(&part);
    Ok((key, widened))
}

/// Reads the entries of `index` within `[lower, upper]` (module docs) at the transaction's
/// snapshot, at most `max` of them, in key order.
///
/// # Errors
/// [`IndexError::Txn`] for transaction errors; [`IndexError::Rejected`] for invalid bounds or
/// corrupt entries (`RGN-5002`).
pub fn scan_index(
    txn: &mut Txn,
    index: &IndexDescriptor,
    lower: Bound<&[Option<Value>]>,
    upper: Bound<&[Option<Value>]>,
    max: usize,
) -> Result<Vec<IndexHit>, IndexError> {
    scan_index_page(txn, index, lower, upper, None, max).map(|p| p.hits)
}

/// One page of [`scan_index_page`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IndexPage {
    /// The hits, in key order.
    pub hits: Vec<IndexHit>,
    /// Pass as `after` to read the next page; `None` when the range is exhausted.
    pub resume: Option<Vec<u8>>,
}

/// [`scan_index`] by pages (FR-QL-006 streaming): reads at most `max` entries of
/// `[lower, upper]` strictly after the raw entry key `after` (the `resume` of the previous
/// page), so a long index range is read with bounded memory.
///
/// # Errors
/// As [`scan_index`].
pub fn scan_index_page(
    txn: &mut Txn,
    index: &IndexDescriptor,
    lower: Bound<&[Option<Value>]>,
    upper: Bound<&[Option<Value>]>,
    after: Option<&[u8]>,
    max: usize,
) -> Result<IndexPage, IndexError> {
    let (span_start, span_end) = index_span(index).map_err(IndexError::Rejected)?;
    let mut widened = false;
    let start = match lower {
        Bound::Unbounded => span_start,
        Bound::Included(t) | Bound::Excluded(t) => {
            let (k, w) = encode_bound(index, t).map_err(IndexError::Rejected)?;
            widened |= w;
            if matches!(lower, Bound::Excluded(_)) && !w {
                prefix_end(&k).ok_or_else(|| IndexError::Rejected(internal("bound overflow")))?
            } else {
                k
            }
        }
    };
    let end = match upper {
        Bound::Unbounded => span_end,
        Bound::Included(t) | Bound::Excluded(t) => {
            let (k, w) = encode_bound(index, t).map_err(IndexError::Rejected)?;
            widened |= w;
            if matches!(upper, Bound::Excluded(_)) && !w {
                k
            } else {
                prefix_end(&k).ok_or_else(|| IndexError::Rejected(internal("bound overflow")))?
            }
        }
    };
    let start = match after {
        // `key ‖ 0x01`, not `key ‖ 0x00`: the MVCC layer appends `0x00 ‖ timestamp` to logical
        // keys, so a `0x00` bound falls inside the versions of `key` itself; no entry key
        // starts with `key ‖ 0x00` (entry keys are prefix-free element sequences).
        Some(k) => {
            let mut next = k.to_vec();
            next.push(1);
            next.max(start)
        }
        None => start,
    };
    if start >= end || max == 0 {
        return Ok(IndexPage::default());
    }
    let rows = txn.scan(&start, &end, max)?;
    let resume = if rows.len() < max {
        None
    } else {
        rows.last().map(|(k, _)| k.clone())
    };
    let dirs = key_directions(index);
    let hits = rows
        .iter()
        .map(|(key, value)| {
            let v = EntryValue::decode(value)?;
            let id_element = if index.unique {
                v.id_element
                    .clone()
                    .ok_or_else(|| crate::entry::corrupt("unique index entry without _id"))?
            } else {
                let after = key
                    .get(ENTRY_PREFIX_LEN..)
                    .ok_or_else(|| crate::entry::corrupt("short index key"))?;
                id_element_of_key(after, &dirs, v.truncated)?.to_vec()
            };
            Ok(IndexHit {
                id: decode_id_element(&id_element)?,
                id_element,
                truncated: v.truncated || widened,
                include: v.include,
            })
        })
        .collect::<Result<Vec<_>, Error>>()
        .map_err(IndexError::Rejected)?;
    Ok(IndexPage { hits, resume })
}
