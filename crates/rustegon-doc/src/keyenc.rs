// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Order-preserving key encoding v1 (data-model.md §3.1, byte-exact; DEC-018, NFR-MNT-004).
//!
//! `cmp(a, b) == cmp(encode(a), encode(b))` for the §2.1 order ([`crate::compare`]); TC-DOC-003
//! checks it by property test. Every element is prefix-free, so composite keys are plain
//! concatenations and a descending element is its ascending bytes bit-inverted.
//!
//! Numbers are exact (see `numeric.rs`): `0x12`/`0x14` + `E` (i16 BE, sign bit flipped) + the
//! digits of `D` two per byte, `2 × pair + 1` for every pair but the last and `2 × pair` for the
//! last; negatives invert those bytes. The numeric type is not recoverable from the key:
//! [`decode_element`] returns `int64` for integers in i64 range, else `decimal128` when exact,
//! else `float64` (exact for every key produced from a float64).
//!
//! Persisted format: frozen at M2 exit; golden vectors in `tests/fixtures/formats/keyenc/1/`.

use crate::{
    compare::exact,
    decimal::{self, Decimal128},
    error::{DocError, DocResult},
    limits::MAX_DEPTH,
    numeric::{ExactNum, NumClass},
    oid::ObjectId,
    value::{Document, Timestamp, Value},
};

/// Sort direction of a key element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Ascending (bytes as encoded).
    Ascending,
    /// Descending (bytes bit-inverted).
    Descending,
}

impl Direction {
    fn mask(self) -> u8 {
        match self {
            Self::Ascending => 0x00,
            Self::Descending => 0xFF,
        }
    }
}

/// Class bytes of §3.1.
mod class {
    pub const MIN_KEY: u8 = 0x01;
    pub const MISSING: u8 = 0x02;
    pub const NULL: u8 = 0x03;
    pub const NAN: u8 = 0x10;
    pub const NEG_INF: u8 = 0x11;
    pub const NEG: u8 = 0x12;
    pub const ZERO: u8 = 0x13;
    pub const POS: u8 = 0x14;
    pub const POS_INF: u8 = 0x15;
    pub const STRING: u8 = 0x20;
    pub const OBJECT: u8 = 0x30;
    pub const ARRAY: u8 = 0x31;
    pub const BINARY: u8 = 0x40;
    pub const OBJECT_ID: u8 = 0x50;
    pub const UUID: u8 = 0x58;
    pub const FALSE: u8 = 0x60;
    pub const TRUE: u8 = 0x61;
    pub const DATETIME: u8 = 0x70;
    pub const TIMESTAMP: u8 = 0x78;
    pub const VECTOR: u8 = 0x80;
    pub const MAX_KEY: u8 = 0xFF;
}

/// Terminator of strings and field names (`0x00 0x01`); NUL inside is escaped `0x00 0xFF`.
const ESCAPE: u8 = 0x00;
const ESCAPED_NUL: u8 = 0xFF;
const STRING_END: u8 = 0x01;
/// Terminator of objects and arrays.
const CONTAINER_END: u8 = 0x00;

/// Appends the encoding of `v` (`None` = missing) in direction `dir`.
///
/// # Errors
/// [`DocError::InvalidFieldName`] (`RGN-1004`) for `counter` values and for field names that are
/// empty or contain NUL; [`DocError::TooDeep`] beyond 100 levels; [`DocError::Malformed`] for
/// binary or vector lengths above `u32::MAX`.
pub fn encode_element(out: &mut Vec<u8>, v: Option<&Value>, dir: Direction) -> DocResult<()> {
    let start = out.len();
    match v {
        None => out.push(class::MISSING),
        Some(v) => encode_value(out, v, 0)?,
    }
    if dir == Direction::Descending {
        invert(&mut out[start..]);
    }
    Ok(())
}

/// Encodes a composite key (concatenation of elements).
///
/// # Errors
/// As [`encode_element`].
pub fn encode_key(parts: &[(Option<&Value>, Direction)]) -> DocResult<Vec<u8>> {
    let mut out = Vec::new();
    for (v, dir) in parts {
        encode_element(&mut out, *v, *dir)?;
    }
    Ok(out)
}

fn invert(bytes: &mut [u8]) {
    for b in bytes {
        *b = !*b;
    }
}

fn len_u32(n: usize) -> DocResult<[u8; 4]> {
    u32::try_from(n)
        .map(u32::to_be_bytes)
        .map_err(|_| DocError::malformed(0, "length above u32::MAX is not key-encodable"))
}

fn encode_value(out: &mut Vec<u8>, v: &Value, depth: usize) -> DocResult<()> {
    match v {
        Value::MinKey => out.push(class::MIN_KEY),
        Value::MaxKey => out.push(class::MAX_KEY),
        Value::Null => out.push(class::NULL),
        Value::Counter(_) => {
            return Err(DocError::InvalidFieldName(
                "counter values are not key-encodable".into(),
            ));
        }
        Value::Int64(_) | Value::Float64(_) | Value::Decimal(_) => {
            if let Some(n) = exact(v) {
                encode_number(out, &n);
            }
        }
        Value::String(s) => {
            out.push(class::STRING);
            put_escaped(out, s.as_bytes());
        }
        Value::Object(d) => {
            check_depth(depth + 1)?;
            out.push(class::OBJECT);
            for (name, fv) in d.iter() {
                if name.is_empty() || name.contains('\0') {
                    return Err(DocError::InvalidFieldName(
                        "field name empty or with NUL is not key-encodable".into(),
                    ));
                }
                put_escaped(out, name.as_bytes());
                encode_value(out, fv, depth + 1)?;
            }
            out.push(CONTAINER_END);
        }
        Value::Array(items) => {
            check_depth(depth + 1)?;
            out.push(class::ARRAY);
            for item in items {
                encode_value(out, item, depth + 1)?;
            }
            out.push(CONTAINER_END);
        }
        Value::Binary { subtype, data } => {
            out.push(class::BINARY);
            out.extend_from_slice(&len_u32(data.len())?);
            out.push(*subtype);
            out.extend_from_slice(data);
        }
        Value::ObjectId(id) => {
            out.push(class::OBJECT_ID);
            out.extend_from_slice(&id.0);
        }
        Value::Uuid(u) => {
            out.push(class::UUID);
            out.extend_from_slice(u);
        }
        Value::Bool(b) => out.push(if *b { class::TRUE } else { class::FALSE }),
        Value::DateTime(ms) => {
            out.push(class::DATETIME);
            out.extend_from_slice(&flip_i64(*ms).to_be_bytes());
        }
        Value::Timestamp(ts) => {
            out.push(class::TIMESTAMP);
            out.extend_from_slice(&ts.wall.to_be_bytes());
            out.extend_from_slice(&ts.logical.to_be_bytes());
        }
        Value::VectorF32(xs) => {
            out.push(class::VECTOR);
            out.extend_from_slice(&len_u32(xs.len())?);
            for x in xs {
                out.extend_from_slice(&f32_key(*x).to_be_bytes());
            }
        }
    }
    Ok(())
}

fn check_depth(depth: usize) -> DocResult<()> {
    if depth > MAX_DEPTH {
        return Err(DocError::TooDeep { limit: MAX_DEPTH });
    }
    Ok(())
}

/// i64 → u64 preserving order (sign bit flipped).
fn flip_i64(v: i64) -> u64 {
    u64::from_be_bytes(v.to_be_bytes()) ^ (1 << 63)
}

/// f32 → u32 preserving `total_cmp` order: sign bit flipped for ≥ 0, all bits for < 0.
fn f32_key(x: f32) -> u32 {
    let b = x.to_bits();
    if b >> 31 == 0 { b ^ (1 << 31) } else { !b }
}

fn f32_from_key(k: u32) -> f32 {
    f32::from_bits(if k >> 31 == 1 { k ^ (1 << 31) } else { !k })
}

fn put_escaped(out: &mut Vec<u8>, bytes: &[u8]) {
    for b in bytes {
        out.push(*b);
        if *b == ESCAPE {
            out.push(ESCAPED_NUL);
        }
    }
    out.extend_from_slice(&[ESCAPE, STRING_END]);
}

fn encode_number(out: &mut Vec<u8>, n: &ExactNum) {
    match n.class {
        NumClass::NaN => out.push(class::NAN),
        NumClass::NegInf => out.push(class::NEG_INF),
        NumClass::Zero => out.push(class::ZERO),
        NumClass::PosInf => out.push(class::POS_INF),
        NumClass::Pos => {
            out.push(class::POS);
            put_magnitude(out, n);
        }
        NumClass::Neg => {
            out.push(class::NEG);
            let start = out.len();
            put_magnitude(out, n);
            invert(&mut out[start..]);
        }
    }
}

/// `E` (i16 BE, sign flipped) then digit pairs (odd bytes continue, the even byte ends).
fn put_magnitude(out: &mut Vec<u8>, n: &ExactNum) {
    // |E| ≤ 6176 for every encodable number (decimal128 bounds), so i16 always fits.
    let e = i16::try_from(n.exp).unwrap_or(if n.exp < 0 { i16::MIN } else { i16::MAX });
    out.extend_from_slice(&(u16::from_be_bytes(e.to_be_bytes()) ^ 0x8000).to_be_bytes());
    let pairs = n.digits.len().div_ceil(2);
    for i in 0..pairs {
        let hi = n.digits[2 * i];
        let lo = n.digits.get(2 * i + 1).copied().unwrap_or(0);
        let pair = hi * 10 + lo;
        out.push(if i + 1 == pairs {
            2 * pair
        } else {
            2 * pair + 1
        });
    }
}

/// Decodes one element; returns the value (`None` = missing) and the bytes consumed.
///
/// # Errors
/// [`DocError::Malformed`] for bytes that no encoder produces.
pub fn decode_element(bytes: &[u8], dir: Direction) -> DocResult<(Option<Value>, usize)> {
    let mut r = Reader {
        b: bytes,
        pos: 0,
        mask: dir.mask(),
    };
    let v = r.element(0)?;
    Ok((v, r.pos))
}

/// Decodes a composite key with the given directions; the whole input must be consumed.
///
/// # Errors
/// As [`decode_element`], plus trailing bytes.
pub fn decode_key(bytes: &[u8], dirs: &[Direction]) -> DocResult<Vec<Option<Value>>> {
    let mut pos = 0;
    let mut out = Vec::with_capacity(dirs.len());
    for dir in dirs {
        let (v, n) = decode_element(&bytes[pos..], *dir)?;
        out.push(v);
        pos += n;
    }
    if pos != bytes.len() {
        return Err(DocError::malformed(pos, "trailing key bytes"));
    }
    Ok(out)
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    mask: u8,
}

impl Reader<'_> {
    fn err(&self, reason: &str) -> DocError {
        DocError::malformed(self.pos, reason)
    }

    fn peek(&self) -> DocResult<u8> {
        self.b
            .get(self.pos)
            .map(|b| b ^ self.mask)
            .ok_or_else(|| self.err("truncated key"))
    }

    fn next(&mut self) -> DocResult<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }

    fn take<const N: usize>(&mut self) -> DocResult<[u8; N]> {
        let mut out = [0u8; N];
        for o in &mut out {
            *o = self.next()?;
        }
        Ok(out)
    }

    fn element(&mut self, depth: usize) -> DocResult<Option<Value>> {
        let c = self.next()?;
        Ok(Some(match c {
            class::MISSING if depth == 0 => return Ok(None),
            class::MIN_KEY => Value::MinKey,
            class::MAX_KEY => Value::MaxKey,
            class::NULL => Value::Null,
            class::NAN => Value::Float64(f64::NAN),
            class::NEG_INF => Value::Float64(f64::NEG_INFINITY),
            class::POS_INF => Value::Float64(f64::INFINITY),
            class::ZERO => Value::Int64(0),
            class::POS | class::NEG => self.number(c == class::NEG)?,
            class::STRING => Value::String(self.string()?),
            class::OBJECT => {
                check_depth(depth + 1)?;
                let mut fields = Vec::new();
                while self.peek()? != CONTAINER_END {
                    let name = self.string()?;
                    let v = self
                        .element(depth + 1)?
                        .ok_or_else(|| self.err("missing"))?;
                    fields.push((name, v));
                }
                self.pos += 1;
                Value::Object(Document::try_from_fields(fields)?)
            }
            class::ARRAY => {
                check_depth(depth + 1)?;
                let mut items = Vec::new();
                while self.peek()? != CONTAINER_END {
                    items.push(
                        self.element(depth + 1)?
                            .ok_or_else(|| self.err("missing"))?,
                    );
                }
                self.pos += 1;
                Value::Array(items)
            }
            class::BINARY => {
                let len = usize::try_from(u32::from_be_bytes(self.take()?)).unwrap_or(usize::MAX);
                let subtype = self.next()?;
                if len > self.b.len().saturating_sub(self.pos) {
                    return Err(self.err("truncated binary"));
                }
                let mut data = Vec::with_capacity(len);
                for _ in 0..len {
                    data.push(self.next()?);
                }
                Value::Binary { subtype, data }
            }
            class::OBJECT_ID => Value::ObjectId(ObjectId(self.take()?)),
            class::UUID => Value::Uuid(self.take()?),
            class::FALSE => Value::Bool(false),
            class::TRUE => Value::Bool(true),
            class::DATETIME => {
                let u = u64::from_be_bytes(self.take()?) ^ (1 << 63);
                Value::DateTime(i64::from_be_bytes(u.to_be_bytes()))
            }
            class::TIMESTAMP => Value::Timestamp(Timestamp {
                wall: u64::from_be_bytes(self.take()?),
                logical: u32::from_be_bytes(self.take()?),
            }),
            class::VECTOR => {
                let dims = usize::try_from(u32::from_be_bytes(self.take()?)).unwrap_or(usize::MAX);
                if dims > self.b.len().saturating_sub(self.pos) / 4 {
                    return Err(self.err("truncated vector"));
                }
                let mut xs = Vec::with_capacity(dims);
                for _ in 0..dims {
                    xs.push(f32_from_key(u32::from_be_bytes(self.take()?)));
                }
                Value::VectorF32(xs)
            }
            _ => return Err(self.err("unknown key class byte")),
        }))
    }

    fn string(&mut self) -> DocResult<String> {
        let mut bytes = Vec::new();
        loop {
            let b = self.next()?;
            if b != ESCAPE {
                bytes.push(b);
                continue;
            }
            match self.next()? {
                ESCAPED_NUL => bytes.push(0),
                STRING_END => break,
                _ => return Err(self.err("bad string escape")),
            }
        }
        String::from_utf8(bytes).map_err(|_| self.err("invalid UTF-8 in key string"))
    }

    fn number(&mut self, negative: bool) -> DocResult<Value> {
        // The magnitude of a negative number is stored inverted.
        let saved = self.mask;
        if negative {
            self.mask ^= 0xFF;
        }
        let e_raw = u16::from_be_bytes(self.take()?) ^ 0x8000;
        let exp = i32::from(i16::from_be_bytes(e_raw.to_be_bytes()));
        let mut digits = Vec::new();
        loop {
            let b = self.next()?;
            let pair = b / 2;
            if pair > 99 {
                self.mask = saved;
                return Err(self.err("bad digit pair"));
            }
            digits.push(pair / 10);
            digits.push(pair % 10);
            if b % 2 == 0 {
                break;
            }
        }
        self.mask = saved;
        if digits.last() == Some(&0) {
            digits.pop(); // padding of an odd-length D
        }
        if digits.first() == Some(&0) || digits.last() == Some(&0) {
            return Err(self.err("non-normalized number"));
        }
        let n = ExactNum {
            class: if negative {
                NumClass::Neg
            } else {
                NumClass::Pos
            },
            exp,
            digits,
        };
        Ok(number_value(&n))
    }
}

/// The most specific exact value for a decoded number (module docs).
fn number_value(n: &ExactNum) -> Value {
    let negative = n.class == NumClass::Neg;
    let len = i32::try_from(n.digits.len()).unwrap_or(i32::MAX);
    let scale = n.exp - len; // value = D (as integer) × 10^scale
    let d = n.digit_string();
    // Integers in i64 range: at most 19 digits plus scale.
    if scale >= 0 && n.exp <= 19 {
        let int: Option<i128> = format!("{d}{}", "0".repeat(scale.unsigned_abs() as usize))
            .parse::<i128>()
            .ok();
        if let Some(i) = int.and_then(|i| i64::try_from(if negative { -i } else { i }).ok()) {
            return Value::Int64(i);
        }
    }
    if n.digits.len() <= decimal::MAX_DIGITS {
        let coefficient = d.parse::<u128>().unwrap_or(0);
        if let Ok(dec) = Decimal128::new(negative, coefficient, scale) {
            return Value::Decimal(dec);
        }
    }
    let f: f64 = format!("{}0.{d}e{}", if negative { "-" } else { "" }, n.exp)
        .parse()
        .unwrap_or(f64::NAN);
    Value::Float64(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: &Value) -> Vec<u8> {
        encode_key(&[(Some(v), Direction::Ascending)]).unwrap()
    }

    #[test]
    fn numbers_known_bytes_and_cross_type_equality() {
        // 1 = 0.1 × 10^1: E = 1 → 0x8001; D = "1" → pair 10 (last) → 20.
        let one = vec![0x14, 0x80, 0x01, 20];
        assert_eq!(enc(&Value::Int64(1)), one);
        assert_eq!(enc(&Value::Float64(1.0)), one);
        assert_eq!(
            enc(&Value::Decimal(Decimal128::parse("1.00").unwrap())),
            one
        );
        // -1: magnitude inverted.
        assert_eq!(enc(&Value::Int64(-1)), vec![0x12, 0x7F, 0xFE, !20]);
        assert_eq!(enc(&Value::Float64(-0.0)), vec![class::ZERO]);
        // 123 = 0.123 × 10^3: pairs 12 (continue → 25), 30 (last → 60).
        assert_eq!(enc(&Value::Int64(123)), vec![0x14, 0x80, 0x03, 25, 60]);
        assert_eq!(
            enc(&Value::String("a\0".into())),
            vec![0x20, b'a', 0, 0xFF, 0, 1]
        );
        let desc = encode_key(&[(None, Direction::Descending)]).unwrap();
        assert_eq!(desc, vec![!class::MISSING]);
    }

    #[test]
    fn counter_not_encodable() {
        let e = encode_key(&[(Some(&Value::Counter(1)), Direction::Ascending)]).unwrap_err();
        assert_eq!(e.code().code(), 1004);
    }

    #[test]
    fn decode_picks_exact_types() {
        let cases = [
            (Value::Int64(i64::MIN), Value::Int64(i64::MIN)),
            (
                Value::Float64(2.5),
                Value::Decimal(Decimal128::parse("25E-1").unwrap()),
            ),
            (Value::Float64(0.1), Value::Float64(0.1)),
            (Value::Float64(1e300), Value::Float64(1e300)),
            (
                Value::Float64(1e22),
                Value::Decimal(Decimal128::parse("1E+22").unwrap()),
            ),
            (
                Value::Float64(f64::MIN_POSITIVE / 3.0),
                Value::Float64(f64::MIN_POSITIVE / 3.0),
            ),
        ];
        for (input, expected) in cases {
            for dir in [Direction::Ascending, Direction::Descending] {
                let k = encode_key(&[(Some(&input), dir)]).unwrap();
                let (v, n) = decode_element(&k, dir).unwrap();
                assert_eq!(n, k.len());
                assert_eq!(v, Some(expected.clone()), "{input:?}");
            }
        }
    }
}
