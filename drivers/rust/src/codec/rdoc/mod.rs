// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `RDoc` v1: the binary document format (data-model.md §4 "`RDoc` v1 byte layout", FR-DOC-001,
//! FR-DOC-003, FR-DOC-004).
//!
//! Layout summary (the normative text is in data-model.md §4):
//! ```text
//! RDoc   := 0xD7 0x01 flags(u8) total_len(u32 LE) object
//! object := 0x0D varint(n) varint(fields_len) index[n] fields
//!           index entry := name_hash16(u16 LE) offset(u32 LE, from the start of `fields`)
//!           sorted by (name_hash16, name bytes); fields in insertion order
//!           field := varint(name_len) name value
//! array  := 0x0C varint(n) varint(elems_len) offset(u32 LE)[n] elements
//! ```
//! Containers carry their body length so any value can be skipped in O(1); the index makes a
//! field lookup O(log n) without decoding siblings.
//!
//! Persisted format: changes follow implementation-rules.md §6 (version bump, old readers kept,
//! fixtures under `tests/fixtures/formats/rdoc/<version>/`).

pub(crate) mod decode;
pub(crate) mod encode;

use twox_hash::XxHash3_64;

pub use self::{
    decode::{ValueRef, decode, decode_value, decode_value_ref},
    encode::{encode, encode_value, encoded_len},
};
use crate::codec::error::{DocError, DocResult};

/// First byte of every `RDoc`.
pub const MAGIC: u8 = 0xD7;
/// Format version written by this crate.
pub const VERSION: u8 = 1;
/// `flags` bit 0: the bytes are in canonical form (written by the server; checked on decode).
pub const FLAG_CANONICAL: u8 = 0x01;
/// Header length: magic, version, flags, `total_len`.
pub const HEADER_LEN: usize = 7;
/// Size of one object index entry: `name_hash16` u16 + offset u32.
pub(crate) const INDEX_ENTRY_LEN: usize = 6;
/// Size of one array offset-table entry.
pub(crate) const ARRAY_OFFSET_LEN: usize = 4;
/// The canonical float64 NaN (quiet, positive, no payload).
pub(crate) const CANONICAL_NAN_BITS: u64 = 0x7FF8_0000_0000_0000;

/// Value tags (data-model.md §2).
pub(crate) mod tag {
    pub const NULL: u8 = 0x01;
    pub const BOOL: u8 = 0x02;
    pub const INT64: u8 = 0x03;
    pub const FLOAT64: u8 = 0x04;
    pub const DECIMAL: u8 = 0x05;
    pub const STRING: u8 = 0x06;
    pub const BINARY: u8 = 0x07;
    pub const DATETIME: u8 = 0x08;
    pub const TIMESTAMP: u8 = 0x09;
    pub const OBJECT_ID: u8 = 0x0A;
    pub const UUID: u8 = 0x0B;
    pub const ARRAY: u8 = 0x0C;
    pub const OBJECT: u8 = 0x0D;
    pub const VECTOR: u8 = 0x0E;
    pub const COUNTER: u8 = 0x0F;
    pub const MIN_KEY: u8 = 0x10;
    pub const MAX_KEY: u8 = 0x11;
}

/// `name_hash16`: the low 16 bits of `xxh3_64(name)` (seed 0).
#[must_use]
pub fn name_hash16(name: &[u8]) -> u16 {
    // Truncation is the definition of the field.
    #[allow(clippy::cast_possible_truncation)]
    let h = XxHash3_64::oneshot(name) as u16;
    h
}

/// Re-encodes any valid `RDoc` (canonical or not) into canonical form.
///
/// # Errors
/// As [`decode`] and [`encode`].
pub fn canonicalize(bytes: &[u8]) -> DocResult<Vec<u8>> {
    encode(&decode(bytes)?)
}

/// Zigzag mapping of a signed integer onto an unsigned one (small magnitudes → short varints).
pub(crate) fn zigzag(v: i64) -> u64 {
    // Bit reinterpretation is the definition of zigzag.
    #[allow(clippy::cast_sign_loss)]
    let z = ((v << 1) ^ (v >> 63)) as u64;
    z
}

/// Inverse of [`zigzag`].
pub(crate) fn unzigzag(z: u64) -> i64 {
    #[allow(clippy::cast_possible_wrap)]
    let v = ((z >> 1) as i64) ^ -((z & 1) as i64);
    v
}

/// Encoded length of an unsigned LEB128 varint.
pub(crate) fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Appends a minimal unsigned LEB128 varint.
pub(crate) fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        // Low 7 bits plus the continuation bit; truncation intended.
        #[allow(clippy::cast_possible_truncation)]
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    #[allow(clippy::cast_possible_truncation)]
    out.push(v as u8);
}

/// Reads an unsigned LEB128 varint at `pos`, bounded by `end`. Returns the value and the
/// position after it. With `strict`, non-minimal encodings are rejected (canonical form).
pub(crate) fn read_varint(
    buf: &[u8],
    pos: usize,
    end: usize,
    strict: bool,
) -> DocResult<(u64, usize)> {
    // A u64 needs at most 10 groups of 7 bits; the 10th may only carry the top bit.
    const MAX_VARINT_LEN: usize = 10;
    let mut v = 0u64;
    for i in 0..MAX_VARINT_LEN {
        let p = pos + i;
        if p >= end {
            return Err(DocError::malformed(p, "truncated varint"));
        }
        let b = buf[p];
        if i == MAX_VARINT_LEN - 1 && b > 1 {
            return Err(DocError::malformed(p, "varint overflows u64"));
        }
        v |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            if strict && i > 0 && b == 0 {
                return Err(DocError::malformed(p, "non-minimal varint"));
            }
            return Ok((v, p + 1));
        }
    }
    Err(DocError::malformed(pos, "varint too long"))
}

/// Reads a varint used as a length or count and converts it to `usize`.
pub(crate) fn read_len(
    buf: &[u8],
    pos: usize,
    end: usize,
    strict: bool,
) -> DocResult<(usize, usize)> {
    let (v, next) = read_varint(buf, pos, end, strict)?;
    let v = usize::try_from(v).map_err(|_| DocError::malformed(pos, "length overflow"))?;
    Ok((v, next))
}

/// `pos + len` if it does not pass `end`.
pub(crate) fn checked_end(pos: usize, len: usize, end: usize) -> DocResult<usize> {
    pos.checked_add(len)
        .filter(|e| *e <= end)
        .ok_or_else(|| DocError::malformed(pos, "length exceeds the enclosing value"))
}

/// Reads `N` bytes at `pos` within `end`.
pub(crate) fn read_array<const N: usize>(buf: &[u8], pos: usize, end: usize) -> DocResult<[u8; N]> {
    let stop = checked_end(pos, N, end)?;
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[pos..stop]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip_and_strictness() {
        for v in [0u64, 1, 127, 128, 300, u64::from(u32::MAX), u64::MAX] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(b.len(), varint_len(v));
            assert_eq!(read_varint(&b, 0, b.len(), true).unwrap(), (v, b.len()));
        }
        // 1 encoded with a redundant continuation group.
        assert!(read_varint(&[0x81, 0x00], 0, 2, true).is_err());
        assert_eq!(read_varint(&[0x81, 0x00], 0, 2, false).unwrap(), (1, 2));
        let overflow = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
        assert!(read_varint(&overflow, 0, 10, false).is_err());
        assert!(read_varint(&[0x80], 0, 1, false).is_err());
    }

    #[test]
    fn zigzag_round_trip() {
        for v in [0i64, -1, 1, i64::MIN, i64::MAX, -64, 63] {
            assert_eq!(unzigzag(zigzag(v)), v);
        }
        assert_eq!(zigzag(-1), 1);
        assert_eq!(zigzag(1), 2);
    }

    /// The value encoding is exactly the bytes a field value has inside a document, and it
    /// round-trips (protocol.md §3 `Value.rdoc_value`; PD-053).
    #[test]
    fn fr_doc_003_value_encoding_matches_field_bytes_and_round_trips() {
        use crate::codec::{
            oid::ObjectId,
            value::{Document, Value},
        };
        let values = [
            Value::Null,
            Value::Int64(-5),
            Value::String("héllo".into()),
            Value::ObjectId(ObjectId([7; 12])),
            Value::Array(vec![Value::Bool(true), Value::Float64(1.5)]),
            Value::Object(
                Document::try_from_fields(vec![("a".to_owned(), Value::Int64(1))]).unwrap(),
            ),
        ];
        for v in values {
            let bytes = encode_value(&v).unwrap();
            assert_eq!(decode_value(&bytes).unwrap(), v);
            let doc = Document::try_from_fields(vec![("v".to_owned(), v.clone())]).unwrap();
            let encoded = encode(&doc).unwrap();
            assert!(encoded.ends_with(&bytes), "{v:?}");
            let mut trailing = bytes.clone();
            trailing.push(0x01);
            assert!(decode_value(&trailing).is_err());
        }
        assert!(decode_value(&[]).is_err());
        assert!(decode_value(&[0xEE]).is_err());
    }
}
