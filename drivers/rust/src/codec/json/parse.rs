// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! JSON / extended-JSON parser (RFC 8259 syntax; semantics in the parent module docs).
//!
//! Own recursive-descent parser instead of `serde_json`: it must see duplicate names, keep the
//! integer/float distinction and number text exactly (without `arbitrary_precision`), and stop at
//! the document depth limit before recursing further (bounded stack).

use super::datetime;
use crate::codec::{
    decimal::Decimal128,
    error::{DocError, DocResult},
    hex,
    limits::{MAX_DEPTH, validate_field_name},
    oid::ObjectId,
    rdoc::encode::check_binary,
    value::{Document, Timestamp, Value},
};

/// Parses a JSON object into a document.
///
/// # Errors
/// [`DocError::Malformed`] (`RGN-1001`) for syntax errors or a non-object top level,
/// [`DocError::InvalidFieldName`] (`RGN-1004`), [`DocError::TooDeep`] (`RGN-1003`),
/// [`DocError::InvalidVector`].
pub fn parse_document(text: &str) -> DocResult<Document> {
    match parse_value(text)? {
        Value::Object(d) => Ok(d),
        _ => Err(DocError::malformed(0, "a document must be a JSON object")),
    }
}

/// Parses any JSON value (extended-JSON wrappers included).
///
/// # Errors
/// As [`parse_document`].
pub fn parse_value(text: &str) -> DocResult<Value> {
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.pos != p.s.len() {
        return Err(p.err("trailing characters"));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

/// A JSON number with its text (needed for exact int64/float/f32 conversion).
struct Number<'a> {
    text: &'a str,
    integral: bool,
}

impl<'a> Parser<'a> {
    fn err(&self, reason: &str) -> DocError {
        DocError::malformed(self.pos, reason)
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, c: u8) -> DocResult<()> {
        self.ws();
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected '{}'", char::from(c))))
        }
    }

    fn literal(&mut self, word: &str, v: Value) -> DocResult<Value> {
        if self.s[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(v)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    /// Parses a value; `depth` is the depth of the enclosing container (0 at top level).
    fn value(&mut self, depth: usize) -> DocResult<Value> {
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => {
                let items = self.array(depth + 1)?;
                Ok(Value::Array(items))
            }
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => {
                let n = self.number()?;
                self.number_value(&n)
            }
            _ => Err(self.err("expected a value")),
        }
    }

    fn check_depth(depth: usize) -> DocResult<()> {
        if depth > MAX_DEPTH {
            return Err(DocError::TooDeep { limit: MAX_DEPTH });
        }
        Ok(())
    }

    fn array(&mut self, depth: usize) -> DocResult<Vec<Value>> {
        Self::check_depth(depth)?;
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(items);
        }
        loop {
            items.push(self.value(depth)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(items);
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> DocResult<Value> {
        Self::check_depth(depth)?;
        self.pos += 1; // '{'
        let mut fields: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(Document::new()));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected a field name"));
            }
            let name = self.string()?;
            self.eat(b':')?;
            if fields.is_empty() && name.starts_with('$') {
                // A `$` name is legal only as the single key of an extended-JSON wrapper.
                let v = self.wrapper(&name)?;
                self.eat(b'}')?;
                return Ok(v);
            }
            validate_field_name(&name)?;
            let v = self.value(depth)?;
            fields.push((name, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(Document::try_from_fields(fields)?));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn string(&mut self) -> DocResult<String> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            // Copy the run of plain characters in one step.
            let start = self.pos;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            // The input is a `&str` and runs stop only at ASCII bytes, so the run is valid UTF-8.
            out.push_str(
                std::str::from_utf8(&self.s[start..self.pos])
                    .map_err(|_| self.err("invalid UTF-8"))?,
            );
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let c = self.escape()?;
                    out.push(c);
                }
                Some(_) => return Err(self.err("control character in string")),
                None => return Err(self.err("unterminated string")),
            }
        }
    }

    fn escape(&mut self) -> DocResult<char> {
        let c = self.peek().ok_or_else(|| self.err("unterminated escape"))?;
        self.pos += 1;
        Ok(match c {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{08}',
            b'f' => '\u{0C}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let hi = self.hex4()?;
                if (0xD800..0xDC00).contains(&hi) {
                    if !self.s[self.pos..].starts_with(b"\\u") {
                        return Err(self.err("lone surrogate"));
                    }
                    self.pos += 2;
                    let lo = self.hex4()?;
                    if !(0xDC00..0xE000).contains(&lo) {
                        return Err(self.err("lone surrogate"));
                    }
                    let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                    char::from_u32(cp).ok_or_else(|| self.err("invalid code point"))?
                } else {
                    char::from_u32(hi).ok_or_else(|| self.err("lone surrogate"))?
                }
            }
            _ => return Err(self.err("invalid escape")),
        })
    }

    fn hex4(&mut self) -> DocResult<u32> {
        let digits = self
            .s
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.err("truncated \\u escape"))?;
        let text = std::str::from_utf8(digits).map_err(|_| self.err("bad \\u escape"))?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(self.err("bad \\u escape"));
        }
        self.pos += 4;
        u32::from_str_radix(text, 16).map_err(|_| self.err("bad \\u escape"))
    }

    /// Scans an RFC 8259 number: `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
    fn number(&mut self) -> DocResult<Number<'a>> {
        let start = self.pos;
        let digits = |p: &mut Self| {
            let from = p.pos;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.pos += 1;
            }
            p.pos - from
        };
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let int_start = self.pos;
        let n = digits(self);
        if n == 0 || (n > 1 && self.s[int_start] == b'0') {
            return Err(self.err("invalid number"));
        }
        let mut integral = true;
        if self.peek() == Some(b'.') {
            self.pos += 1;
            integral = false;
            if digits(self) == 0 {
                return Err(self.err("invalid number fraction"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            integral = false;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if digits(self) == 0 {
                return Err(self.err("invalid number exponent"));
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.pos])
            .map_err(|_| self.err("invalid number"))?;
        Ok(Number { text, integral })
    }

    fn number_value(&self, n: &Number<'_>) -> DocResult<Value> {
        if n.integral
            && let Ok(i) = n.text.parse::<i64>()
        {
            return Ok(Value::Int64(i));
        }
        // Rust's float parsing is correctly rounded; out-of-range magnitudes become infinite,
        // which plain JSON cannot mean, so they are rejected.
        let f: f64 = n.text.parse().map_err(|_| self.err("invalid number"))?;
        if f.is_infinite() {
            return Err(self.err("number outside the float64 range"));
        }
        Ok(Value::Float64(f))
    }

    /// String value of a wrapper (`{"$x":"…"}`).
    fn wrapper_string(&mut self) -> DocResult<String> {
        self.ws();
        if self.peek() != Some(b'"') {
            return Err(self.err("expected a string"));
        }
        self.string()
    }

    /// Parses the value of an extended-JSON wrapper whose key is `key`.
    fn wrapper(&mut self, key: &str) -> DocResult<Value> {
        let at = self.pos;
        let bad = |reason: &str| DocError::malformed(at, format!("{key}: {reason}"));
        Ok(match key {
            "$int64" => {
                let s = self.wrapper_string()?;
                Value::Int64(s.parse().map_err(|_| bad("not an int64"))?)
            }
            "$float" => {
                let s = self.wrapper_string()?;
                Value::Float64(match s.as_str() {
                    "NaN" => f64::NAN,
                    "Infinity" => f64::INFINITY,
                    "-Infinity" => f64::NEG_INFINITY,
                    _ => {
                        let mut p = Parser {
                            s: s.as_bytes(),
                            pos: 0,
                        };
                        let n = p.number().map_err(|_| bad("not a number"))?;
                        if p.pos != s.len() {
                            return Err(bad("not a number"));
                        }
                        n.text.parse().map_err(|_| bad("not a number"))?
                    }
                })
            }
            "$decimal" => Value::Decimal(Decimal128::parse(&self.wrapper_string()?)?),
            "$date" => Value::DateTime(datetime::parse(&self.wrapper_string()?)?),
            "$oid" => Value::ObjectId(ObjectId::parse_hex(&self.wrapper_string()?)?),
            "$uuid" => Value::Uuid(
                parse_uuid(&self.wrapper_string()?)
                    .ok_or_else(|| bad("expected 8-4-4-4-12 hex"))?,
            ),
            "$ts" => {
                let s = self.wrapper_string()?;
                let (w, l) = s
                    .split_once('.')
                    .ok_or_else(|| bad("expected wall.logical"))?;
                let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
                if !digits(w) || !digits(l) {
                    return Err(bad("expected wall.logical"));
                }
                Value::Timestamp(Timestamp {
                    wall: w.parse().map_err(|_| bad("wall out of range"))?,
                    logical: l.parse().map_err(|_| bad("logical out of range"))?,
                })
            }
            "$binary" => self.binary()?,
            "$vector" => self.vector()?,
            "$minKey" | "$maxKey" => {
                self.ws();
                let n = self.number()?;
                if n.text != "1" {
                    return Err(bad("expected 1"));
                }
                if key == "$minKey" {
                    Value::MinKey
                } else {
                    Value::MaxKey
                }
            }
            "$counter" => {
                return Err(DocError::InvalidFieldName(
                    "$counter is a read-only projection, not accepted as input".into(),
                ));
            }
            _ => {
                return Err(DocError::InvalidFieldName(
                    "field name starts with '$'".into(),
                ));
            }
        })
    }

    /// `{"base64":"…","subType":"hh"}` in either key order.
    fn binary(&mut self) -> DocResult<Value> {
        let at = self.pos;
        let bad = |r: &str| DocError::malformed(at, format!("$binary: {r}"));
        self.eat(b'{')?;
        let (mut data, mut subtype) = (None, None);
        for i in 0..2 {
            if i > 0 {
                self.eat(b',')?;
            }
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(bad("expected base64 and subType"));
            }
            let k = self.string()?;
            self.eat(b':')?;
            let v = self.wrapper_string()?;
            match k.as_str() {
                "base64" if data.is_none() => {
                    data = Some(hex::base64_decode(&v).ok_or_else(|| bad("invalid base64"))?);
                }
                "subType" if subtype.is_none() => {
                    let mut b = [0u8; 1];
                    hex::decode_into(&v, &mut b).ok_or_else(|| bad("subType is 2 hex digits"))?;
                    subtype = Some(b[0]);
                }
                _ => return Err(bad("expected base64 and subType")),
            }
        }
        self.eat(b'}')?;
        let (Some(data), Some(subtype)) = (data, subtype) else {
            return Err(bad("expected base64 and subType"));
        };
        check_binary(subtype, data.len())?;
        Ok(Value::Binary { subtype, data })
    }

    /// `[n, …]` of numbers, each converted to the nearest f32 (must be finite).
    fn vector(&mut self) -> DocResult<Value> {
        self.eat(b'[')?;
        let mut xs = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::VectorF32(xs));
        }
        loop {
            self.ws();
            let n = self.number()?;
            let x: f32 = n.text.parse().map_err(|_| self.err("invalid number"))?;
            if !x.is_finite() {
                return Err(DocError::InvalidVector(
                    "element outside the f32 range".into(),
                ));
            }
            xs.push(x);
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::VectorF32(xs));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }
}

/// `8-4-4-4-12` hex (either case).
fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 36 || [8, 13, 18, 23].iter().any(|i| b[*i] != b'-') {
        return None;
    }
    let compact: String = s.chars().filter(|c| *c != '-').collect();
    let mut out = [0u8; 16];
    hex::decode_into(&compact, &mut out)?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_numbers_map_to_types() {
        assert_eq!(parse_value("5").unwrap(), Value::Int64(5));
        assert_eq!(parse_value("-0").unwrap(), Value::Int64(0));
        assert_eq!(parse_value("5.0").unwrap(), Value::Float64(5.0));
        assert_eq!(parse_value("5e0").unwrap(), Value::Float64(5.0));
        assert_eq!(
            parse_value("9223372036854775807").unwrap(),
            Value::Int64(i64::MAX)
        );
        assert_eq!(
            parse_value("9223372036854775808").unwrap(),
            Value::Float64(9_223_372_036_854_775_808.0)
        );
        assert!(parse_value("1e400").is_err());
        for bad in ["01", "1.", ".5", "-", "1e", "+1", "0x1", "NaN"] {
            assert!(parse_value(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn json_strings_and_wrappers() {
        assert_eq!(
            parse_value(r#""😀é\/""#).unwrap(),
            Value::String("😀é/".into())
        );
        assert!(parse_value(r#""\ud83d""#).is_err());
        assert!(parse_value("\"a\u{1}\"").is_err());
        assert_eq!(parse_value(r#"{"$int64":"-7"}"#).unwrap(), Value::Int64(-7));
        assert_eq!(parse_value(r#"{"$minKey":1}"#).unwrap(), Value::MinKey);
        assert!(parse_value(r#"{"$int64":"1","x":1}"#).is_err());
        assert!(parse_value(r#"{"a":1,"$b":1}"#).is_err());
        assert_eq!(
            parse_value(r#"{"$binary":{"subType":"04","base64":"AAAAAAAAAAAAAAAAAAAAAA=="}}"#)
                .unwrap(),
            Value::Binary {
                subtype: 4,
                data: vec![0; 16]
            }
        );
        assert!(parse_value(r#"{"$binary":{"base64":"AA==","subType":"04"}}"#).is_err());
        assert!(parse_value(r#"{"$binary":{"base64":"AA==","subType":"05"}}"#).is_err());
        assert_eq!(parse_value(r#"{"$counter":1}"#).unwrap_err().code(), 1004);
        assert!(parse_value(r#"{"$vector":[1e39]}"#).is_err());
    }
}
