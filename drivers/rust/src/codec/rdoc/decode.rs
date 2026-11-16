// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `RDoc` v1 decoder (full validation) and the borrowed [`ValueRef`] used by lazy access.
//!
//! Every input is untrusted: all reads are bounds-checked against the enclosing value, lengths are
//! validated before allocation, recursion is bounded by the depth limit, and every inconsistency
//! is an error — the decoder never panics (TC-DOC-001 fuzz-style proptests).

use super::{
    ARRAY_OFFSET_LEN, CANONICAL_NAN_BITS, FLAG_CANONICAL, HEADER_LEN, INDEX_ENTRY_LEN, MAGIC,
    VERSION, checked_end, encode::check_binary, name_hash16, read_array, read_len, read_varint,
    tag, unzigzag,
};
use crate::codec::{
    decimal::Decimal128,
    error::{DocError, DocResult},
    limits::{MAX_DEPTH, MAX_DOCUMENT_SIZE, validate_field_name},
    oid::ObjectId,
    value::{Document, Timestamp, Value},
};

/// Decodes and fully validates an `RDoc`.
///
/// With `flags.canonical` set the bytes must also be canonical (minimal varints, canonical NaN
/// and decimal128 encodings); without it those variants are accepted and normalized.
///
/// # Errors
/// [`DocError::TooLarge`] if `total_len` exceeds 16 MiB, [`DocError::TooDeep`] beyond 100
/// levels, [`DocError::InvalidFieldName`] for names breaking §2.2 or duplicates,
/// [`DocError::InvalidVector`] for non-finite vectors, [`DocError::Malformed`] otherwise.
pub fn decode(bytes: &[u8]) -> DocResult<Document> {
    let strict = check_header(bytes)?;
    let d = Decoder { buf: bytes, strict };
    let end = bytes.len();
    if bytes.get(HEADER_LEN) != Some(&tag::OBJECT) {
        return Err(DocError::malformed(HEADER_LEN, "root is not an object"));
    }
    let (doc, next) = d.object(HEADER_LEN + 1, end, 1)?;
    if next != end {
        return Err(DocError::malformed(
            next,
            "trailing bytes after the root object",
        ));
    }
    Ok(doc)
}

/// Validates the header; returns whether the canonical flag is set.
pub(crate) fn check_header(bytes: &[u8]) -> DocResult<bool> {
    if bytes.len() < HEADER_LEN + 1 {
        return Err(DocError::malformed(bytes.len(), "truncated header"));
    }
    if bytes[0] != MAGIC {
        return Err(DocError::malformed(0, "bad magic"));
    }
    if bytes[1] != VERSION {
        return Err(DocError::malformed(1, "unsupported RDoc version"));
    }
    let flags = bytes[2];
    if flags & !FLAG_CANONICAL != 0 {
        return Err(DocError::malformed(2, "unknown flag bits"));
    }
    let total = u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
    let total = usize::try_from(total).unwrap_or(usize::MAX);
    if total > MAX_DOCUMENT_SIZE {
        return Err(DocError::TooLarge {
            size: u64::try_from(total).unwrap_or(u64::MAX),
            limit: u64::try_from(MAX_DOCUMENT_SIZE).unwrap_or(u64::MAX),
        });
    }
    if total != bytes.len() {
        return Err(DocError::malformed(
            3,
            "total_len does not match the input length",
        ));
    }
    Ok(flags & FLAG_CANONICAL != 0)
}

/// A borrowed, not yet decoded value: exactly the bytes of one value (tag first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueRef<'a> {
    bytes: &'a [u8],
}

impl<'a> ValueRef<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The type tag (data-model.md §2).
    #[must_use]
    pub fn type_tag(&self) -> u8 {
        self.bytes.first().copied().unwrap_or(0)
    }

    /// The raw bytes of the value, tag included.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Decodes the value (lenient about canonical form, strict about validity).
    ///
    /// # Errors
    /// As [`decode`].
    pub fn to_value(&self) -> DocResult<Value> {
        let d = Decoder {
            buf: self.bytes,
            strict: false,
        };
        let (v, next) = d.value(0, self.bytes.len(), 0)?;
        if next != self.bytes.len() {
            return Err(DocError::malformed(next, "trailing bytes after value"));
        }
        Ok(v)
    }
}

/// Decodes one value in the `RDoc` value encoding ([`super::encode_value`]): the whole input
/// must be exactly one value. Non-canonical variants are accepted and normalized, like a
/// document without the canonical flag.
///
/// # Errors
/// As [`decode`]; [`DocError::Malformed`] for trailing bytes.
pub fn decode_value(bytes: &[u8]) -> DocResult<Value> {
    ValueRef::new(bytes).to_value()
}

/// Splits off the value starting at `pos` (bounded by `end`) without decoding it.
///
/// # Errors
/// [`DocError::Malformed`] if the value's extent cannot be read or passes `end`.
pub fn decode_value_ref(buf: &[u8], pos: usize, end: usize) -> DocResult<ValueRef<'_>> {
    let stop = value_end(buf, pos, end)?;
    Ok(ValueRef::new(&buf[pos..stop]))
}

/// End position of the value starting at `pos`, in O(1) (containers carry their body length).
pub(crate) fn value_end(buf: &[u8], pos: usize, end: usize) -> DocResult<usize> {
    let t = *buf
        .get(pos)
        .filter(|_| pos < end)
        .ok_or_else(|| DocError::malformed(pos, "missing value"))?;
    let p = pos + 1;
    match t {
        tag::NULL | tag::MIN_KEY | tag::MAX_KEY => Ok(p),
        tag::BOOL => checked_end(p, 1, end),
        tag::FLOAT64 => checked_end(p, 8, end),
        tag::DECIMAL | tag::UUID => checked_end(p, 16, end),
        tag::TIMESTAMP | tag::OBJECT_ID => checked_end(p, 12, end),
        tag::INT64 | tag::DATETIME | tag::COUNTER => Ok(read_varint(buf, p, end, false)?.1),
        tag::STRING => {
            let (len, q) = read_len(buf, p, end, false)?;
            checked_end(q, len, end)
        }
        tag::BINARY => {
            let (len, q) = read_len(buf, p + 1, end, false)?;
            checked_end(q, len, end)
        }
        tag::VECTOR => {
            let (dims, q) = read_len(buf, p, end, false)?;
            checked_end(q, dims.saturating_mul(4), end)
        }
        tag::OBJECT | tag::ARRAY => {
            let h = container_header(buf, p, end, t, false)?;
            Ok(h.body_end)
        }
        _ => Err(DocError::malformed(pos, "unknown type tag")),
    }
}

/// Positions of a container's parts.
pub(crate) struct ContainerHeader {
    pub(crate) n: usize,
    pub(crate) table_at: usize,
    pub(crate) body_at: usize,
    pub(crate) body_end: usize,
}

/// Parses `varint(n) varint(body_len)` and locates the table and body (after the tag).
pub(crate) fn container_header(
    buf: &[u8],
    pos: usize,
    end: usize,
    t: u8,
    strict: bool,
) -> DocResult<ContainerHeader> {
    let entry = if t == tag::OBJECT {
        INDEX_ENTRY_LEN
    } else {
        ARRAY_OFFSET_LEN
    };
    let (n, p) = read_len(buf, pos, end, strict)?;
    let (body_len, table_at) = read_len(buf, p, end, strict)?;
    let table_len = n
        .checked_mul(entry)
        .ok_or_else(|| DocError::malformed(pos, "entry count overflow"))?;
    let body_at = checked_end(table_at, table_len, end)?;
    let body_end = checked_end(body_at, body_len, end)?;
    Ok(ContainerHeader {
        n,
        table_at,
        body_at,
        body_end,
    })
}

fn u32_at(buf: &[u8], at: usize) -> usize {
    let b = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
    usize::try_from(u32::from_le_bytes(b)).unwrap_or(usize::MAX)
}

struct Decoder<'a> {
    buf: &'a [u8],
    strict: bool,
}

impl Decoder<'_> {
    /// Decodes the value whose tag is at `pos`; `depth` is the depth of the enclosing container
    /// (containers decoded here get `depth + 1`).
    fn value(&self, pos: usize, end: usize, depth: usize) -> DocResult<(Value, usize)> {
        let ty = *self
            .buf
            .get(pos)
            .filter(|_| pos < end)
            .ok_or_else(|| DocError::malformed(pos, "missing value"))?;
        let at = pos + 1;
        Ok(match ty {
            tag::NULL => (Value::Null, at),
            tag::MIN_KEY => (Value::MinKey, at),
            tag::MAX_KEY => (Value::MaxKey, at),
            tag::BOOL => match read_array::<1>(self.buf, at, end)?[0] {
                0 => (Value::Bool(false), at + 1),
                1 => (Value::Bool(true), at + 1),
                _ => return Err(DocError::malformed(at, "bool byte not 0 or 1")),
            },
            tag::INT64 | tag::DATETIME | tag::COUNTER => {
                let (z, next) = read_varint(self.buf, at, end, self.strict)?;
                let i = unzigzag(z);
                let v = match ty {
                    tag::INT64 => Value::Int64(i),
                    tag::DATETIME => Value::DateTime(i),
                    _ => Value::Counter(i),
                };
                (v, next)
            }
            tag::FLOAT64 => {
                let bits = u64::from_le_bytes(read_array(self.buf, at, end)?);
                let f = f64::from_bits(bits);
                if self.strict && f.is_nan() && bits != CANONICAL_NAN_BITS {
                    return Err(DocError::malformed(at, "non-canonical NaN"));
                }
                (
                    Value::Float64(if f.is_nan() { f64::NAN } else { f }),
                    at + 8,
                )
            }
            tag::DECIMAL => {
                let bits = u128::from_le_bytes(read_array(self.buf, at, end)?);
                let (d, canonical) = Decimal128::from_bits(bits);
                if self.strict && !canonical {
                    return Err(DocError::malformed(at, "non-canonical decimal128"));
                }
                (Value::Decimal(d), at + 16)
            }
            tag::STRING => {
                let (s, next) = self.string(at, end)?;
                (Value::String(s.to_owned()), next)
            }
            tag::BINARY => {
                let subtype = read_array::<1>(self.buf, at, end)?[0];
                let (len, next) = read_len(self.buf, at + 1, end, self.strict)?;
                let stop = checked_end(next, len, end)?;
                check_binary(subtype, len).map_err(|_| DocError::malformed(at, "bad binary"))?;
                let data = self.buf[next..stop].to_vec();
                (Value::Binary { subtype, data }, stop)
            }
            tag::TIMESTAMP => {
                let wall = u64::from_le_bytes(read_array(self.buf, at, end)?);
                let logical = u32::from_le_bytes(read_array(self.buf, at + 8, end)?);
                (Value::Timestamp(Timestamp { wall, logical }), at + 12)
            }
            tag::OBJECT_ID => (
                Value::ObjectId(ObjectId(read_array(self.buf, at, end)?)),
                at + 12,
            ),
            tag::UUID => (Value::Uuid(read_array(self.buf, at, end)?), at + 16),
            tag::VECTOR => self.vector(at, end)?,
            tag::ARRAY => {
                let (items, next) = self.array(at, end, depth + 1)?;
                (Value::Array(items), next)
            }
            tag::OBJECT => {
                let (d, next) = self.object(at, end, depth + 1)?;
                (Value::Object(d), next)
            }
            _ => return Err(DocError::malformed(pos, "unknown type tag")),
        })
    }

    fn string(&self, p: usize, end: usize) -> DocResult<(&str, usize)> {
        let (len, q) = read_len(self.buf, p, end, self.strict)?;
        let stop = checked_end(q, len, end)?;
        let s = std::str::from_utf8(&self.buf[q..stop])
            .map_err(|_| DocError::malformed(q, "invalid UTF-8"))?;
        Ok((s, stop))
    }

    fn vector(&self, p: usize, end: usize) -> DocResult<(Value, usize)> {
        let (dims, q) = read_len(self.buf, p, end, self.strict)?;
        let stop = checked_end(q, dims.saturating_mul(4), end)?;
        let mut v = Vec::with_capacity(dims);
        for chunk in self.buf[q..stop].as_chunks::<4>().0 {
            let x = f32::from_le_bytes(*chunk);
            if !x.is_finite() {
                return Err(DocError::InvalidVector("non-finite element".into()));
            }
            v.push(x);
        }
        Ok((Value::VectorF32(v), stop))
    }

    fn check_depth(depth: usize) -> DocResult<()> {
        if depth > MAX_DEPTH {
            return Err(DocError::TooDeep { limit: MAX_DEPTH });
        }
        Ok(())
    }

    /// Decodes an object (after its tag) and checks the index against the fields: every entry
    /// must point at a field start, carry that field's name hash, and entries must be strictly
    /// increasing by (hash, name) — which also proves the names are unique and the index is a
    /// permutation of the fields.
    fn object(&self, p: usize, end: usize, depth: usize) -> DocResult<(Document, usize)> {
        Self::check_depth(depth)?;
        let h = container_header(self.buf, p, end, tag::OBJECT, self.strict)?;
        // Each field takes at least 3 bytes (name length, one name byte, tag): bound `n` before
        // allocating so a forged count cannot reserve gigabytes.
        if h.n > (h.body_end - h.body_at) / 3 {
            return Err(DocError::malformed(p, "field count exceeds the body"));
        }
        let mut fields: Vec<(String, Value)> = Vec::with_capacity(h.n);
        let mut starts: Vec<usize> = Vec::with_capacity(h.n);
        let mut q = h.body_at;
        for _ in 0..h.n {
            starts.push(q - h.body_at);
            let (name, after_name) = self.string(q, h.body_end)?;
            validate_field_name(name)?;
            let (v, next) = self.value(after_name, h.body_end, depth)?;
            fields.push((name.to_owned(), v));
            q = next;
        }
        if q != h.body_end {
            return Err(DocError::malformed(q, "object body length mismatch"));
        }
        let mut prev: Option<(u16, &str)> = None;
        for i in 0..h.n {
            let at = h.table_at + i * INDEX_ENTRY_LEN;
            let hash = u16::from_le_bytes([self.buf[at], self.buf[at + 1]]);
            let offset = u32_at(self.buf, at + 2);
            let j = starts
                .binary_search(&offset)
                .map_err(|_| DocError::malformed(at, "index offset is not a field start"))?;
            let name = fields[j].0.as_str();
            if name_hash16(name.as_bytes()) != hash {
                return Err(DocError::malformed(at, "index hash mismatch"));
            }
            if let Some(prev) = prev
                && prev >= (hash, name)
            {
                return Err(if prev == (hash, name) {
                    DocError::InvalidFieldName("duplicate field name".into())
                } else {
                    DocError::malformed(at, "index not sorted")
                });
            }
            prev = Some((hash, name));
        }
        Ok((Document::from_unique_fields(fields), h.body_end))
    }

    fn array(&self, p: usize, end: usize, depth: usize) -> DocResult<(Vec<Value>, usize)> {
        Self::check_depth(depth)?;
        let h = container_header(self.buf, p, end, tag::ARRAY, self.strict)?;
        if h.n > h.body_end - h.body_at {
            return Err(DocError::malformed(p, "element count exceeds the body"));
        }
        let mut items = Vec::with_capacity(h.n);
        let mut q = h.body_at;
        for i in 0..h.n {
            let at = h.table_at + i * ARRAY_OFFSET_LEN;
            if u32_at(self.buf, at) != q - h.body_at {
                return Err(DocError::malformed(at, "array offset mismatch"));
            }
            let (v, next) = self.value(q, h.body_end, depth)?;
            items.push(v);
            q = next;
        }
        if q != h.body_end {
            return Err(DocError::malformed(q, "array body length mismatch"));
        }
        Ok((items, h.body_end))
    }
}
