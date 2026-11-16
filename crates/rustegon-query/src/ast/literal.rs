// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Literal values of RGQL (query-language.md §2) and their JSON form (§13).
//!
//! JSON: `{"kind":"literal","value":<json>}` for `null`, booleans, integers, floats and strings
//! (the JSON number keeps the integer/float distinction: `10` is an integer, `10.0` a float), and
//! `{"kind":"literal","type":"<type>","value":"<text>"}` for the typed literals that have no
//! native JSON form (`decimal`, `datetime`, `object_id`, `uuid`, `interval`).

use std::fmt::Write as _;

use rustegon_doc::{Decimal128, ObjectId, Value, json};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::SerializeMap};

/// A literal value.
///
/// Negative numbers are literals (`-5` is `Int(-5)`, not a negation of `5`): the parser folds a
/// unary minus directly followed by a number token into the literal, so `i64::MIN` is writable.
#[derive(Debug, Clone)]
pub enum Literal {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// Integer literal (`int64`).
    Int(i64),
    /// Floating-point literal (`float64`); always finite.
    Float(f64),
    /// Decimal literal with suffix `m` (`decimal128`), e.g. `12.50m`.
    Decimal(Decimal128),
    /// String literal.
    String(String),
    /// `DATE '…'`: milliseconds since the Unix epoch, UTC (data-model §2 `datetime`).
    DateTime(i64),
    /// `OID '…'`.
    ObjectId(ObjectId),
    /// `UUID '…'`.
    Uuid([u8; 16]),
    /// `INTERVAL '…'`: the interval text, interpreted by the binder (e.g. `'7 days'`).
    Interval(String),
}

impl PartialEq for Literal {
    /// Representational equality (floats compare by bits, decimals keep their cohort member),
    /// which is what the round-trip guarantee `parse(print(ast)) == ast` needs.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Int(a), Self::Int(b)) | (Self::DateTime(a), Self::DateTime(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a.to_bits() == b.to_bits(),
            (Self::Decimal(a), Self::Decimal(b)) => a == b,
            (Self::String(a), Self::String(b)) | (Self::Interval(a), Self::Interval(b)) => a == b,
            (Self::ObjectId(a), Self::ObjectId(b)) => a == b,
            (Self::Uuid(a), Self::Uuid(b)) => a == b,
            _ => false,
        }
    }
}

/// Formats a `datetime` as ISO 8601 (`YYYY-MM-DDTHH:MM:SS.mmmZ`), reusing the document model's
/// canonical extended-JSON text so both layers print identical instants.
#[must_use]
pub fn format_datetime(ms: i64) -> String {
    let json = json::value_to_json(&Value::DateTime(ms), json::JsonMode::Canonical);
    // Canonical form is `{"$date":"<iso>"}`; the ISO text never contains quotes.
    json.split('"').nth(3).map(str::to_owned).unwrap_or(json)
}

/// Parses the text of a `DATE '…'` literal: `YYYY-MM-DD` (midnight UTC) or the full
/// `YYYY-MM-DDTHH:MM:SS[.fff]Z` form. Returns `None` when invalid.
#[must_use]
pub fn parse_datetime(text: &str) -> Option<i64> {
    let full;
    let iso = if text.len() == 10 && !text.contains('T') {
        full = format!("{text}T00:00:00Z");
        full.as_str()
    } else {
        text
    };
    // Only the characters of an ISO timestamp may reach the JSON wrapper (no quote injection).
    if !iso
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b'+' | b':' | b'.' | b'T' | b'Z'))
    {
        return None;
    }
    match json::parse_value(&format!("{{\"$date\":\"{iso}\"}}")) {
        Ok(Value::DateTime(ms)) => Some(ms),
        _ => None,
    }
}

/// Formats a UUID as lowercase `8-4-4-4-12` hex.
#[must_use]
pub fn format_uuid(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parses a UUID in `8-4-4-4-12` or plain 32-digit hex form (either case).
#[must_use]
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hyphenated = text.len() == 36;
    if hyphenated
        && text
            .char_indices()
            .any(|(i, c)| matches!(i, 8 | 13 | 18 | 23) != (c == '-'))
    {
        return None;
    }
    let digits: Vec<u8> = text.bytes().filter(|b| *b != b'-' || !hyphenated).collect();
    if digits.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in digits.chunks(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        out[i] = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

impl Serialize for Literal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::Null => map.serialize_entry("value", &())?,
            Self::Bool(b) => map.serialize_entry("value", b)?,
            Self::Int(i) => map.serialize_entry("value", i)?,
            Self::Float(f) => map.serialize_entry("value", f)?,
            Self::String(s) => map.serialize_entry("value", s)?,
            Self::Decimal(d) => {
                map.serialize_entry("type", "decimal")?;
                map.serialize_entry("value", &d.to_string())?;
            }
            Self::DateTime(ms) => {
                map.serialize_entry("type", "datetime")?;
                map.serialize_entry("value", &format_datetime(*ms))?;
            }
            Self::ObjectId(oid) => {
                map.serialize_entry("type", "object_id")?;
                map.serialize_entry("value", &oid.to_string())?;
            }
            Self::Uuid(u) => {
                map.serialize_entry("type", "uuid")?;
                map.serialize_entry("value", &format_uuid(u))?;
            }
            Self::Interval(s) => {
                map.serialize_entry("type", "interval")?;
                map.serialize_entry("value", s)?;
            }
        }
        map.end()
    }
}

/// Wire shape of a literal (see the module docs).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiteralRepr {
    #[serde(rename = "type", default)]
    ty: Option<String>,
    value: serde_json::Value,
}

impl<'de> Deserialize<'de> for Literal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = LiteralRepr::deserialize(deserializer)?;
        let text = || {
            repr.value
                .as_str()
                .ok_or_else(|| D::Error::custom("typed literal value must be a string"))
        };
        let invalid = |ty: &str| D::Error::custom(format!("invalid {ty} literal"));
        match repr.ty.as_deref() {
            None => untyped(&repr.value).ok_or_else(|| {
                D::Error::custom("literal value must be null, a boolean, a number or a string")
            }),
            Some("decimal") => Decimal128::parse(text()?)
                .map(Self::Decimal)
                .map_err(|_| invalid("decimal")),
            Some("datetime") => parse_datetime(text()?)
                .map(Self::DateTime)
                .ok_or_else(|| invalid("datetime")),
            Some("object_id") => ObjectId::parse_hex(text()?)
                .map(Self::ObjectId)
                .map_err(|_| invalid("object_id")),
            Some("uuid") => parse_uuid(text()?)
                .map(Self::Uuid)
                .ok_or_else(|| invalid("uuid")),
            Some("interval") => Ok(Self::Interval(text()?.to_owned())),
            Some(other) => Err(D::Error::custom(format!("unknown literal type `{other}`"))),
        }
    }
}

fn untyped(v: &serde_json::Value) -> Option<Literal> {
    Some(match v {
        serde_json::Value::Null => Literal::Null,
        serde_json::Value::Bool(b) => Literal::Bool(*b),
        serde_json::Value::String(s) => Literal::String(s.clone()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Literal::Int(i)
            } else if n.is_f64() {
                Literal::Float(n.as_f64()?)
            } else {
                // A u64 beyond i64: no RGQL integer literal has that value.
                return None;
            }
        }
        _ => return None,
    })
}
