// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Index entry keys and values, format 1 (indexing.md §3, data-model.md §3.2; fixtures in
//! `tests/fixtures/formats/index_entry/1/`).
//!
//! **Keys** (keyspace layout v1, DEC-017; built with `rustegon_doc::keyspace`):
//! ```text
//! non-unique  0x03 tenant db_id coll_id 'I' index_id(u32 BE) key_part ‖ enc(_id)
//! unique      0x03 tenant db_id coll_id 'U' index_id(u32 BE) key_part
//! key_part    enc(v1, dir1) ‖ … ‖ enc(vn, dirn)              (compound, key encoding v1)
//!             enc(path string, asc) ‖ enc(value, dir)        (wildcard)
//! truncated   key_part[..3072] ‖ xxh3_128(key_part) (u128 BE)  when key_part > 4096 bytes
//! ```
//! **Values**:
//! ```text
//! value  := ε                                    non-unique, nothing covered, not truncated
//!         | 0x01 flags(u8) [id] [include]
//! flags  := bit 0 truncated (the key part is cut: the reader must re-check the document)
//!           bit 1 id present  (always for unique entries: value = _id, indexing.md §3)
//!           bit 2 include present
//!           other bits zero
//! id     := enc(_id, asc)                         (self-delimiting key-encoding element)
//! include:= canonical RDoc object { "<covered path>": value, … } (missing paths omitted)
//! ```
//! The empty value keeps the common entry as small as the spec intends ("value empty or
//! covered fields", data-model.md §3). *Provisional (PD pending)*: the value layout and the
//! truncation boundaries (key part measured without the prefix and `_id`; cut at exactly
//! 3072 bytes) are not fixed by the spec.

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    keyenc::{Direction, decode_element},
    rdoc,
};
use twox_hash::XxHash3_128;

/// Version byte of a non-empty entry value.
pub const ENTRY_VALUE_FORMAT: u8 = 0x01;
/// Largest key part stored as is (system-overview §9 "Index key size 4 KiB").
pub const MAX_KEY_PART: usize = 4096;
/// Length of the kept prefix of a truncated key part (indexing.md §3: 3 KiB).
pub const TRUNCATED_PREFIX: usize = 3072;
/// Length of the hash suffix of a truncated key part (xxh3-128).
pub const TRUNCATION_HASH_LEN: usize = 16;
/// Length of a truncated key part.
pub const TRUNCATED_KEY_PART: usize = TRUNCATED_PREFIX + TRUNCATION_HASH_LEN;

const FLAG_TRUNCATED: u8 = 0x01;
const FLAG_ID: u8 = 0x02;
const FLAG_INCLUDE: u8 = 0x04;
const KNOWN_FLAGS: u8 = FLAG_TRUNCATED | FLAG_ID | FLAG_INCLUDE;

/// Decoded entry value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryValue {
    /// The key part was truncated (re-check the document).
    pub truncated: bool,
    /// `enc(_id)` (unique entries).
    pub id_element: Option<Vec<u8>>,
    /// Covered fields.
    pub include: Option<Document>,
}

impl EntryValue {
    /// Encodes the value (empty when there is nothing to store).
    ///
    /// # Errors
    /// Document codec errors for the covered-fields object (e.g. size limits).
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if !self.truncated && self.id_element.is_none() && self.include.is_none() {
            return Ok(Vec::new());
        }
        let mut flags = 0;
        if self.truncated {
            flags |= FLAG_TRUNCATED;
        }
        if self.id_element.is_some() {
            flags |= FLAG_ID;
        }
        if self.include.is_some() {
            flags |= FLAG_INCLUDE;
        }
        let mut out = vec![ENTRY_VALUE_FORMAT, flags];
        if let Some(id) = &self.id_element {
            out.extend_from_slice(id);
        }
        if let Some(inc) = &self.include {
            out.extend_from_slice(&rdoc::encode(inc)?);
        }
        Ok(out)
    }

    /// Decodes a value written by [`EntryValue::encode`].
    ///
    /// # Errors
    /// `RGN-5002 StorageCorruption` for malformed bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let Some((&version, rest)) = bytes.split_first() else {
            return Ok(Self::default());
        };
        if version != ENTRY_VALUE_FORMAT {
            return Err(corrupt(format!("index entry value format {version}")));
        }
        let Some((&flags, mut rest)) = rest.split_first() else {
            return Err(corrupt("index entry value without flags"));
        };
        if flags & !KNOWN_FLAGS != 0 || flags == 0 {
            return Err(corrupt(format!("index entry value flags {flags:#04x}")));
        }
        let mut out = Self {
            truncated: flags & FLAG_TRUNCATED != 0,
            ..Self::default()
        };
        if flags & FLAG_ID != 0 {
            let (_, n) = decode_element(rest, Direction::Ascending)
                .map_err(|e| corrupt(format!("index entry _id: {e}")))?;
            out.id_element = Some(rest[..n].to_vec());
            rest = &rest[n..];
        }
        if flags & FLAG_INCLUDE != 0 {
            out.include =
                Some(rdoc::decode(rest).map_err(|e| corrupt(format!("index entry include: {e}")))?);
            rest = &[];
        }
        if !rest.is_empty() {
            return Err(corrupt("trailing bytes in index entry value"));
        }
        Ok(out)
    }
}

/// Truncates an over-long key part: the first 3072 bytes, then xxh3-128 of the whole part
/// (big endian), so distinct long values stay distinct keys while order is kept up to the cut.
#[must_use]
pub fn truncate_key_part(part: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRUNCATED_KEY_PART);
    out.extend_from_slice(&part[..TRUNCATED_PREFIX.min(part.len())]);
    out.extend_from_slice(&XxHash3_128::oneshot(part).to_be_bytes());
    out
}

/// The `_id` element at the end of a non-unique entry key, given the bytes after the index
/// prefix (`'I' index_id`): the key part is skipped element by element (`dirs`), or by its
/// fixed length when `truncated`.
///
/// # Errors
/// `RGN-5002` for keys that do not parse.
pub fn id_element_of_key<'k>(
    after_prefix: &'k [u8],
    dirs: &[Direction],
    truncated: bool,
) -> Result<&'k [u8], Error> {
    let mut pos = 0;
    if truncated {
        pos = TRUNCATED_KEY_PART;
    } else {
        for dir in dirs {
            let rest = after_prefix
                .get(pos..)
                .ok_or_else(|| corrupt("index key shorter than its fields"))?;
            let (_, n) = decode_element(rest, *dir)
                .map_err(|e| corrupt(format!("index key element: {e}")))?;
            pos += n;
        }
    }
    let id = after_prefix
        .get(pos..)
        .ok_or_else(|| corrupt("index key without _id"))?;
    let (_, n) =
        decode_element(id, Direction::Ascending).map_err(|e| corrupt(format!("index _id: {e}")))?;
    if n != id.len() || n == 0 {
        return Err(corrupt("trailing bytes after the index _id"));
    }
    Ok(id)
}

/// A `RGN-5002 StorageCorruption` error.
pub(crate) fn corrupt(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::StorageCorruption, msg)
}

/// The value of an `_id` element.
///
/// # Errors
/// `RGN-5002` for a malformed element.
pub fn decode_id_element(id: &[u8]) -> Result<Value, Error> {
    match decode_element(id, Direction::Ascending) {
        Ok((Some(v), n)) if n == id.len() => Ok(v),
        Ok(_) => Err(corrupt("malformed _id element")),
        Err(e) => Err(corrupt(format!("_id element: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn value_round_trip() {
        let mut inc = Document::new();
        inc.insert("total", Value::Int64(5));
        let cases = [
            EntryValue::default(),
            EntryValue {
                truncated: true,
                ..EntryValue::default()
            },
            EntryValue {
                truncated: false,
                id_element: Some(vec![0x20, b'a', 0x00, 0x01]),
                include: Some(inc.clone()),
            },
            EntryValue {
                truncated: true,
                id_element: None,
                include: Some(inc),
            },
        ];
        for c in cases {
            let bytes = c.encode().unwrap();
            assert_eq!(EntryValue::decode(&bytes).unwrap(), c);
        }
        assert_eq!(EntryValue::default().encode().unwrap().len(), 0);
        for bad in [
            &[0x02, 0x01][..],
            &[0x01][..],
            &[0x01, 0x00][..],
            &[0x01, 0x08][..],
            &[0x01, 0x01, 0xAA][..],
        ] {
            assert!(EntryValue::decode(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn truncation_keeps_prefix_and_distinguishes() {
        let a = vec![7u8; 5000];
        let mut b = a.clone();
        b[4999] = 8;
        let (ta, tb) = (truncate_key_part(&a), truncate_key_part(&b));
        assert_eq!(ta.len(), TRUNCATED_KEY_PART);
        assert_eq!(ta[..TRUNCATED_PREFIX], a[..TRUNCATED_PREFIX]);
        assert_ne!(ta, tb);
    }
}
