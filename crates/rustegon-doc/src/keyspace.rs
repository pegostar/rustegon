// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Keyspace layout v1 (data-model.md §3.2, byte-exact; DEC-017, NFR-MNT-004).
//!
//! ```text
//! user   0x03 tenant(0x00) db_id(u32 BE) coll_id(u32 BE) family(u8 ASCII) …
//! system 0x02 …
//! local  0x01 'r' range_id(u64 BE) tag(u8) …  |  0x01 'k' anchor … 't' txn_id(16)
//! ```
//! Builders here cover the user namespace; the local and system namespaces belong to the range
//! and catalog crates, which use the prefix constants below. Every component that can follow a
//! complete logical key starts with a non-zero byte (family tags, `'C'`, §3.1 elements), which
//! `rustegon-mvcc`'s `0x00` separator relies on (§3.2).

use twox_hash::XxHash3_64;

use crate::{
    error::DocResult,
    keyenc::{Direction, encode_element},
    value::{Timestamp, Value},
};

/// Namespace byte of range-local keys.
pub const NS_LOCAL: u8 = 0x01;
/// Namespace byte of system keys (`/sys`: catalog, settings, sequences).
pub const NS_SYSTEM: u8 = 0x02;
/// Namespace byte of user data.
pub const NS_USER: u8 = 0x03;
/// The default (and in 1.0 only) tenant (DEC-017).
pub const DEFAULT_TENANT: u8 = 0x00;
/// Local sub-prefix of range-id-local keys (`0x01 'r'`).
pub const LOCAL_RANGE_ID: u8 = b'r';
/// Local sub-prefix of transaction records (`0x01 'k'`).
pub const LOCAL_TXN_RECORD: u8 = b'k';
/// Separator before the transaction id of a transaction-record key.
pub const LOCAL_TXN_ID_TAG: u8 = b't';
/// Suffix separating a document key from a counter name.
pub const COUNTER_SUFFIX: u8 = b'C';

/// Key families of a collection (§3.2, ASCII bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Family {
    /// `D` documents.
    Document = b'D',
    /// `C` (reserved family byte; document counters are a suffix of the document key).
    Counter = b'C',
    /// `I` non-unique secondary index entries.
    Index = b'I',
    /// `U` unique index entries.
    Unique = b'U',
    /// `F` full-text postings.
    FullText = b'F',
    /// `G` geo index entries.
    Geo = b'G',
    /// `R` revisions.
    Revision = b'R',
    /// `T` table rows.
    Table = b'T',
    /// `B` time-series buckets.
    Bucket = b'B',
    /// `M` map-reduce aggregate rows.
    MapReduce = b'M',
}

/// Whether the shard key is hashed, i.e. whether `hash16` is present (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardHash {
    /// Hashed shard key (the default for document collections, FR-SHD-002).
    Hashed,
    /// Range-sharded: no `hash16`.
    Unhashed,
}

/// `hash16` of an encoded shard key: the top two bytes of `xxh3_64` (seed 0), i.e. bytes 0–1 of
/// the hash in big-endian order (65 536 buckets).
#[must_use]
pub fn hash16(encoded_shard_key: &[u8]) -> u16 {
    // Truncation to the top 16 bits is the definition.
    #[allow(clippy::cast_possible_truncation)]
    let h = (XxHash3_64::oneshot(encoded_shard_key) >> 48) as u16;
    h
}

/// `0x03 tenant db_id coll_id family`.
#[must_use]
pub fn family_prefix(db_id: u32, coll_id: u32, family: Family) -> Vec<u8> {
    let mut k = Vec::with_capacity(16);
    k.push(NS_USER);
    k.push(DEFAULT_TENANT);
    k.extend_from_slice(&db_id.to_be_bytes());
    k.extend_from_slice(&coll_id.to_be_bytes());
    k.push(family as u8);
    k
}

/// Document key: family prefix `D`, `hash16(_id element)` if hashed, then the `_id` element.
///
/// # Errors
/// As [`crate::keyenc::encode_element`] (e.g. `counter` ids).
pub fn document_key(db_id: u32, coll_id: u32, shard: ShardHash, id: &Value) -> DocResult<Vec<u8>> {
    let mut id_enc = Vec::new();
    encode_element(&mut id_enc, Some(id), Direction::Ascending)?;
    let mut k = family_prefix(db_id, coll_id, Family::Document);
    if shard == ShardHash::Hashed {
        k.extend_from_slice(&hash16(&id_enc).to_be_bytes());
    }
    k.extend_from_slice(&id_enc);
    Ok(k)
}

/// Document counter key: document key ‖ `'C'` ‖ counter name as a string element.
#[must_use]
pub fn document_counter_key(document_key: &[u8], counter: &str) -> Vec<u8> {
    let mut k = document_key.to_vec();
    k.push(COUNTER_SUFFIX);
    // A string element never fails to encode.
    let _ = encode_element(
        &mut k,
        Some(&Value::String(counter.to_owned())),
        Direction::Ascending,
    );
    k
}

/// Non-unique secondary index entry: prefix `I` ‖ `index_id` (u32 BE) ‖ index key ‖ `_id`.
///
/// # Errors
/// As [`crate::keyenc::encode_element`].
pub fn index_entry_key(
    db_id: u32,
    coll_id: u32,
    index_id: u32,
    index_key: &[u8],
    id: &Value,
) -> DocResult<Vec<u8>> {
    let mut k = unique_index_key(db_id, coll_id, index_id, index_key);
    k[10] = Family::Index as u8;
    encode_element(&mut k, Some(id), Direction::Ascending)?;
    Ok(k)
}

/// Unique index entry: prefix `U` ‖ `index_id` (u32 BE) ‖ index key (value = `_id`).
#[must_use]
pub fn unique_index_key(db_id: u32, coll_id: u32, index_id: u32, index_key: &[u8]) -> Vec<u8> {
    let mut k = family_prefix(db_id, coll_id, Family::Unique);
    k.extend_from_slice(&index_id.to_be_bytes());
    k.extend_from_slice(index_key);
    k
}

/// Revision key: prefix `R` ‖ `_id` element ‖ revision timestamp element, descending (newest
/// first).
///
/// # Errors
/// As [`crate::keyenc::encode_element`].
pub fn revision_key(db_id: u32, coll_id: u32, id: &Value, rev: Timestamp) -> DocResult<Vec<u8>> {
    let mut k = family_prefix(db_id, coll_id, Family::Revision);
    encode_element(&mut k, Some(id), Direction::Ascending)?;
    encode_element(&mut k, Some(&Value::Timestamp(rev)), Direction::Descending)?;
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_key_layout() {
        let id = Value::Int64(1);
        let k = document_key(7, 9, ShardHash::Unhashed, &id).unwrap();
        assert_eq!(
            k,
            [
                0x03, 0x00, 0, 0, 0, 7, 0, 0, 0, 9, b'D', 0x14, 0x80, 0x01, 20
            ]
        );
        let h = document_key(7, 9, ShardHash::Hashed, &id).unwrap();
        let expected_hash = hash16(&[0x14, 0x80, 0x01, 20]).to_be_bytes();
        assert_eq!(&h[11..13], &expected_hash);
        assert_eq!(&h[13..], &k[11..]);
        let c = document_counter_key(&h, "views");
        assert_eq!(c[h.len()], b'C');
        let i = index_entry_key(7, 9, 3, &[0x20, b'x', 0, 1], &id).unwrap();
        assert_eq!(&i[10..16], &[b'I', 0, 0, 0, 3, 0x20]);
    }
}
