// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `RDoc` v1 encoder. Always writes canonical form (flag bit 0 set).
//!
//! Two passes: `measure` computes every container's body length (stored in pre-order) and
//! enforces the depth and size limits before anything is written, so an oversized document is
//! rejected without building a 16 MiB buffer; `write` then emits bytes in one pass, back-patching
//! each container's index/offset table, whose slots are reserved before the body.

use super::{
    ARRAY_OFFSET_LEN, CANONICAL_NAN_BITS, FLAG_CANONICAL, HEADER_LEN, INDEX_ENTRY_LEN, MAGIC,
    VERSION, name_hash16, put_varint, tag, varint_len, zigzag,
};
use crate::codec::{
    error::{DocError, DocResult},
    limits::{MAX_DEPTH, MAX_DOCUMENT_SIZE, validate_field_name},
    value::{BINARY_GENERIC, BINARY_USER_MIN, BINARY_UUID, Document, Value},
};

/// `usize` → `u64` for size arithmetic (lossless on every supported target).
fn u64_of(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Size limit as `u64`.
fn limit() -> u64 {
    u64_of(MAX_DOCUMENT_SIZE)
}

fn too_large(size: u64) -> DocError {
    DocError::TooLarge {
        size,
        limit: limit(),
    }
}

/// Exact encoded size of `doc` as an `RDoc` (header included).
///
/// # Errors
/// As [`encode`], except that it never allocates the output.
pub fn encoded_len(doc: &Document) -> DocResult<usize> {
    let mut sizes = Vec::new();
    let body = measure_object(doc, 1, &mut sizes)?;
    total_len(body)
}

fn total_len(root: u64) -> DocResult<usize> {
    let total = u64_of(HEADER_LEN).saturating_add(root);
    if total > limit() {
        return Err(too_large(total));
    }
    usize::try_from(total).map_err(|_| too_large(total))
}

/// Encodes a document as canonical `RDoc` v1.
///
/// # Errors
/// - [`DocError::TooLarge`] (`RGN-1002`) above 16 MiB encoded;
/// - [`DocError::TooDeep`] (`RGN-1003`) beyond 100 levels;
/// - [`DocError::InvalidFieldName`] (`RGN-1004`) for names breaking §2.2;
/// - [`DocError::InvalidVector`] for non-finite vector elements;
/// - [`DocError::Malformed`] for a reserved binary subtype or a UUID binary not 16 bytes long.
pub fn encode(doc: &Document) -> DocResult<Vec<u8>> {
    let mut sizes = Vec::new();
    let root = measure_object(doc, 1, &mut sizes)?;
    let total = total_len(root)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[MAGIC, VERSION, FLAG_CANONICAL]);
    let total_u32 = u32::try_from(total).map_err(|_| too_large(u64_of(total)))?;
    out.extend_from_slice(&total_u32.to_le_bytes());
    let mut w = Writer {
        out,
        sizes: &sizes,
        next: 0,
    };
    w.object(doc)?;
    debug_assert_eq!(w.out.len(), total, "measure and write disagree");
    Ok(w.out)
}

/// Encodes one value in the `RDoc` *value encoding*: the type tag and payload exactly as the
/// value is stored inside a document (data-model.md §4), without the document header. This is
/// the `rdoc_value` of the public `Value` message (protocol.md §3): document ids, query
/// parameters and option values. A container value starts at depth 1, so the nesting limit is
/// the same as for a field value one level below a document root.
///
/// # Errors
/// As [`encode`].
pub fn encode_value(v: &Value) -> DocResult<Vec<u8>> {
    let mut sizes = Vec::new();
    let size = measure_value(v, 0, &mut sizes)?;
    let mut w = Writer {
        out: Vec::with_capacity(usize::try_from(size).unwrap_or(0)),
        sizes: &sizes,
        next: 0,
    };
    w.value(v)?;
    Ok(w.out)
}

/// Encoded size of one value; pushes container body lengths in pre-order.
fn measure_value(v: &Value, depth: usize, sizes: &mut Vec<u64>) -> DocResult<u64> {
    let size = match v {
        Value::Null | Value::MinKey | Value::MaxKey => 1,
        Value::Bool(_) => 2,
        Value::Int64(i) | Value::DateTime(i) | Value::Counter(i) => {
            1 + u64_of(varint_len(zigzag(*i)))
        }
        Value::Float64(_) => 9,
        Value::Decimal(_) | Value::Uuid(_) => 17,
        Value::Timestamp(_) | Value::ObjectId(_) => 13,
        Value::String(s) => 1 + len_prefixed(s.len()),
        Value::Binary { subtype, data } => {
            check_binary(*subtype, data.len())?;
            2 + len_prefixed(data.len())
        }
        Value::VectorF32(v) => {
            if v.iter().any(|x| !x.is_finite()) {
                return Err(DocError::InvalidVector("non-finite element".into()));
            }
            1 + u64_of(varint_len(u64_of(v.len()))) + 4 * u64_of(v.len())
        }
        Value::Array(items) => measure_array(items, depth + 1, sizes)?,
        Value::Object(d) => measure_object(d, depth + 1, sizes)?,
    };
    if size > limit() {
        return Err(too_large(size));
    }
    Ok(size)
}

fn len_prefixed(n: usize) -> u64 {
    u64_of(varint_len(u64_of(n))) + u64_of(n)
}

/// Binary subtypes of data-model.md §2: 0 generic, 4 UUID (16 bytes), 0x80+ user-defined.
pub(crate) fn check_binary(subtype: u8, len: usize) -> DocResult<()> {
    const UUID_LEN: usize = 16;
    match subtype {
        BINARY_GENERIC => Ok(()),
        BINARY_UUID if len == UUID_LEN => Ok(()),
        BINARY_UUID => Err(DocError::malformed(
            0,
            "binary subtype 4 (uuid) needs 16 bytes",
        )),
        s if s >= BINARY_USER_MIN => Ok(()),
        _ => Err(DocError::malformed(0, "reserved binary subtype")),
    }
}

fn check_depth(depth: usize) -> DocResult<()> {
    if depth > MAX_DEPTH {
        return Err(DocError::TooDeep { limit: MAX_DEPTH });
    }
    Ok(())
}

fn container_size(n: usize, entry_len: usize, body: u64) -> u64 {
    1 + u64_of(varint_len(u64_of(n)))
        + u64_of(varint_len(body))
        + u64_of(entry_len).saturating_mul(u64_of(n))
        + body
}

fn measure_object(d: &Document, depth: usize, sizes: &mut Vec<u64>) -> DocResult<u64> {
    check_depth(depth)?;
    let slot = sizes.len();
    sizes.push(0);
    let mut body = 0u64;
    for (name, value) in d.iter() {
        validate_field_name(name)?;
        body = body
            .saturating_add(len_prefixed(name.len()))
            .saturating_add(measure_value(value, depth, sizes)?);
        if body > limit() {
            return Err(too_large(body));
        }
    }
    sizes[slot] = body;
    Ok(container_size(d.len(), INDEX_ENTRY_LEN, body))
}

fn measure_array(items: &[Value], depth: usize, sizes: &mut Vec<u64>) -> DocResult<u64> {
    check_depth(depth)?;
    let slot = sizes.len();
    sizes.push(0);
    let mut body = 0u64;
    for item in items {
        body = body.saturating_add(measure_value(item, depth, sizes)?);
        if body > limit() {
            return Err(too_large(body));
        }
    }
    sizes[slot] = body;
    Ok(container_size(items.len(), ARRAY_OFFSET_LEN, body))
}

struct Writer<'s> {
    out: Vec<u8>,
    /// Container body lengths in pre-order, from `measure`.
    sizes: &'s [u64],
    next: usize,
}

impl Writer<'_> {
    fn next_size(&mut self) -> DocResult<u64> {
        let s = self
            .sizes
            .get(self.next)
            .copied()
            .ok_or_else(|| DocError::malformed(0, "internal: size table exhausted"))?;
        self.next += 1;
        Ok(s)
    }

    /// Offset relative to `start` as the u32 stored in index/offset tables. Bodies are below
    /// 16 MiB (checked by `measure`), so the conversion cannot fail in practice.
    fn rel(&self, start: usize) -> DocResult<u32> {
        u32::try_from(self.out.len() - start).map_err(|_| too_large(u64_of(self.out.len())))
    }

    fn value(&mut self, v: &Value) -> DocResult<()> {
        self.out.push(v.type_tag());
        match v {
            Value::Null | Value::MinKey | Value::MaxKey => {}
            Value::Bool(b) => self.out.push(u8::from(*b)),
            Value::Int64(i) | Value::DateTime(i) | Value::Counter(i) => {
                put_varint(&mut self.out, zigzag(*i));
            }
            Value::Float64(f) => {
                let bits = if f.is_nan() {
                    CANONICAL_NAN_BITS
                } else {
                    f.to_bits()
                };
                self.out.extend_from_slice(&bits.to_le_bytes());
            }
            Value::Decimal(d) => self.out.extend_from_slice(&d.to_bits().to_le_bytes()),
            Value::String(s) => {
                put_varint(&mut self.out, u64_of(s.len()));
                self.out.extend_from_slice(s.as_bytes());
            }
            Value::Binary { subtype, data } => {
                self.out.push(*subtype);
                put_varint(&mut self.out, u64_of(data.len()));
                self.out.extend_from_slice(data);
            }
            Value::Timestamp(ts) => {
                self.out.extend_from_slice(&ts.wall.to_le_bytes());
                self.out.extend_from_slice(&ts.logical.to_le_bytes());
            }
            Value::ObjectId(id) => self.out.extend_from_slice(&id.0),
            Value::Uuid(u) => self.out.extend_from_slice(u),
            Value::VectorF32(v) => {
                put_varint(&mut self.out, u64_of(v.len()));
                for x in v {
                    self.out.extend_from_slice(&x.to_le_bytes());
                }
            }
            Value::Array(items) => {
                self.out.pop(); // `array` writes its own tag
                self.array(items)?;
            }
            Value::Object(d) => {
                self.out.pop();
                self.object(d)?;
            }
        }
        Ok(())
    }

    fn object(&mut self, d: &Document) -> DocResult<()> {
        self.out.push(tag::OBJECT);
        put_varint(&mut self.out, u64_of(d.len()));
        let body = self.next_size()?;
        put_varint(&mut self.out, body);
        let index_at = self.out.len();
        self.out.resize(index_at + INDEX_ENTRY_LEN * d.len(), 0);
        let fields_at = self.out.len();
        let mut entries: Vec<(u16, &str, u32)> = Vec::with_capacity(d.len());
        for (name, value) in d.iter() {
            let offset = self.rel(fields_at)?;
            entries.push((name_hash16(name.as_bytes()), name, offset));
            put_varint(&mut self.out, u64_of(name.len()));
            self.out.extend_from_slice(name.as_bytes());
            self.value(value)?;
        }
        // Index order (hash, name bytes) makes lookups a binary search and the bytes canonical.
        entries.sort_unstable_by(|a, b| (a.0, a.1.as_bytes()).cmp(&(b.0, b.1.as_bytes())));
        for (i, (hash, _, offset)) in entries.iter().enumerate() {
            let at = index_at + i * INDEX_ENTRY_LEN;
            self.out[at..at + 2].copy_from_slice(&hash.to_le_bytes());
            self.out[at + 2..at + INDEX_ENTRY_LEN].copy_from_slice(&offset.to_le_bytes());
        }
        debug_assert_eq!(u64_of(self.out.len() - fields_at), body);
        Ok(())
    }

    fn array(&mut self, items: &[Value]) -> DocResult<()> {
        self.out.push(tag::ARRAY);
        put_varint(&mut self.out, u64_of(items.len()));
        let body = self.next_size()?;
        put_varint(&mut self.out, body);
        let table_at = self.out.len();
        self.out
            .resize(table_at + ARRAY_OFFSET_LEN * items.len(), 0);
        let elems_at = self.out.len();
        for (i, item) in items.iter().enumerate() {
            let offset = self.rel(elems_at)?;
            let at = table_at + i * ARRAY_OFFSET_LEN;
            self.out[at..at + ARRAY_OFFSET_LEN].copy_from_slice(&offset.to_le_bytes());
            self.value(item)?;
        }
        debug_assert_eq!(u64_of(self.out.len() - elems_at), body);
        Ok(())
    }
}
