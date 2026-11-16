// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! System keys of the catalog under the `0x02` namespace (data-model.md §3.2; byte layout in
//! database-engine.md §2.5, catalog format v1).
//!
//! ```text
//! descriptor   0x02 'd' id(u32 BE)                         -> descriptor RDoc (catalog_format 1)
//! name index   0x02 'n' parent_id(u32 BE) name(ASCII bytes) -> id (u32 BE, 4 bytes)
//! sequence     0x02 's' seq(u8)                             -> last allocated value (u32 BE)
//! ```
//! - `parent_id` is [`ROOT_PARENT_ID`] (0) for databases and the database id for collections, so
//!   the collections of one database are one contiguous prefix scan.
//! - Names are validated ASCII without NUL ([`crate::name`]), so no name-index key is a strict
//!   prefix of another one whose next byte is `0x00`, which `rustegon-mvcc`'s `0x00` separator
//!   requires (§3.2). Descriptor and sequence keys are fixed-width per sub-namespace.
//! - The sub-namespace bytes `'d'`, `'n'`, `'s'` are owned by the catalog; other `/sys` users
//!   (settings, jobs, liveness, meta ranges, …) take other bytes when their milestones land.

use rustegon_doc::keyspace::NS_SYSTEM;

use crate::error::{CatalogError, CatalogResult};

/// Sub-namespace byte of descriptors (`/sys/descriptors`).
pub const SUB_DESCRIPTOR: u8 = b'd';
/// Sub-namespace byte of the name index (`/sys/catalog` names).
pub const SUB_NAME: u8 = b'n';
/// Sub-namespace byte of sequences.
pub const SUB_SEQUENCE: u8 = b's';
/// Sequence id of the cluster-wide descriptor id sequence (databases and collections share it).
pub const SEQ_DESCRIPTOR_ID: u8 = 0x01;
/// Parent id of database name entries. Never allocated as a descriptor id.
pub const ROOT_PARENT_ID: u32 = 0;
/// First id handed out to user objects. Ids `1..FIRST_USER_ID` are reserved for system
/// databases and collections created by later milestones with fixed ids (bootstrap does not need
/// to allocate them through the sequence).
pub const FIRST_USER_ID: u32 = 100;
/// Length of a name-index value and of a sequence value: one u32 BE.
pub const ID_VALUE_LEN: usize = 4;

/// Key of the descriptor with id `id`.
#[must_use]
pub fn descriptor_key(id: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(6);
    k.extend_from_slice(&[NS_SYSTEM, SUB_DESCRIPTOR]);
    k.extend_from_slice(&id.to_be_bytes());
    k
}

/// Prefix of every descriptor key (scan of all descriptors).
#[must_use]
pub fn descriptor_prefix() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_DESCRIPTOR]
}

/// Key of the name-index entry `name` under `parent_id` ([`ROOT_PARENT_ID`] for databases).
///
/// `name` must already be validated ([`crate::name`]); the layout relies on it being NUL-free.
#[must_use]
pub fn name_key(parent_id: u32, name: &str) -> Vec<u8> {
    let mut k = name_prefix(parent_id);
    k.extend_from_slice(name.as_bytes());
    k
}

/// Prefix of the name-index entries under `parent_id` (e.g. all collections of a database).
#[must_use]
pub fn name_prefix(parent_id: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(6);
    k.extend_from_slice(&[NS_SYSTEM, SUB_NAME]);
    k.extend_from_slice(&parent_id.to_be_bytes());
    k
}

/// Key of the descriptor id sequence.
#[must_use]
pub fn descriptor_id_sequence_key() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_SEQUENCE, SEQ_DESCRIPTOR_ID]
}

/// Encodes an id value (name-index value, sequence value).
#[must_use]
pub fn encode_id(id: u32) -> Vec<u8> {
    id.to_be_bytes().to_vec()
}

/// Decodes an id value written by [`encode_id`].
///
/// # Errors
/// [`CatalogError::Corrupt`] if the value is not exactly 4 bytes.
pub fn decode_id(value: &[u8]) -> CatalogResult<u32> {
    let bytes: [u8; ID_VALUE_LEN] = value
        .try_into()
        .map_err(|_| CatalogError::corrupt(format!("id value of {} bytes", value.len())))?;
    Ok(u32::from_be_bytes(bytes))
}

/// The name of a name-index key under `parent_id`, or `None` if `key` is not such a key.
#[must_use]
pub fn name_from_key(parent_id: u32, key: &[u8]) -> Option<&str> {
    let prefix = name_prefix(parent_id);
    key.strip_prefix(prefix.as_slice())
        .and_then(|n| std::str::from_utf8(n).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_bytes() {
        assert_eq!(descriptor_key(0x0102_0304), [0x02, b'd', 1, 2, 3, 4]);
        assert_eq!(name_key(0, "ab"), [0x02, b'n', 0, 0, 0, 0, b'a', b'b']);
        assert_eq!(descriptor_id_sequence_key(), [0x02, b's', 0x01]);
        assert_eq!(decode_id(&encode_id(7)).ok(), Some(7));
        assert!(decode_id(&[1, 2, 3]).is_err());
        assert_eq!(name_from_key(5, &name_key(5, "orders")), Some("orders"));
        assert_eq!(name_from_key(6, &name_key(5, "orders")), None);
    }
}
