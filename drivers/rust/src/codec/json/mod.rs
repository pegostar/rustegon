// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Canonical and extended JSON (data-model.md §2 column "JSON", FR-DOC-003).
//!
//! Output modes ([`JsonMode`]):
//! - **canonical**: the plain JSON form wherever it is lossless — `int64` as a number when
//!   |v| ≤ 2^53, `float64` as a number that always contains `.` or an exponent (so it parses back
//!   as `float64`) — and the `$`-wrappers otherwise. Compact, fields in stored order, minimal
//!   string escapes: the same document always gives the same bytes (AC-DOC-001).
//! - **extended**: like canonical but every `int64` is `{"$int64":"…"}` and every `float64` is
//!   `{"$float":"…"}`, for clients whose JSON parser loses the integer/float distinction.
//!
//! The parser accepts both. Plain JSON integers within i64 become `int64`; integers beyond it
//! become `float64` (nearest value, like `MongoDB` and JavaScript); numbers with a fraction or an
//! exponent become `float64`; a number beyond the float64 range is rejected. Duplicate names,
//! names breaking §2.2 (`$` prefix, NUL, empty, > 1024 bytes) and `{"$counter":…}` are rejected
//! (`RGN-1004`), nesting beyond 100 levels gives `RGN-1003`.

mod datetime;
mod parse;

use std::fmt::Write as _;

pub use self::parse::{parse_document, parse_value};
use crate::codec::{
    hex,
    value::{Document, Value},
};

/// Largest integer magnitude a JSON number carries without loss in IEEE-double parsers.
const MAX_SAFE_INTEGER: u64 = 1 << 53;

/// JSON output mode (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonMode {
    /// Plain JSON where lossless, wrappers elsewhere.
    Canonical,
    /// Every int64 and float64 wrapped.
    Extended,
}

/// Serializes a document.
#[must_use]
pub fn to_json(doc: &Document, mode: JsonMode) -> String {
    let mut out = String::new();
    write_document(&mut out, doc, mode);
    out
}

/// Serializes a value.
#[must_use]
pub fn value_to_json(v: &Value, mode: JsonMode) -> String {
    let mut out = String::new();
    write_value(&mut out, v, mode);
    out
}

fn write_document(out: &mut String, doc: &Document, mode: JsonMode) {
    out.push('{');
    for (i, (name, v)) in doc.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, name);
        out.push(':');
        write_value(out, v, mode);
    }
    out.push('}');
}

/// Shortest round-trip text of a finite float that a JSON parser reads back as a float.
fn float_text(f: f64) -> String {
    // `{:?}` is Rust's shortest round-trip representation and uses an exponent for very large
    // and small magnitudes; integral values print as `1.0`. Append `.0` defensively should a
    // representation ever lack both markers.
    let mut s = format!("{f:?}");
    if !s.contains(['.', 'e', 'E']) {
        s.push_str(".0");
    }
    s
}

fn float_special(f: f64) -> Option<&'static str> {
    if f.is_nan() {
        Some("NaN")
    } else if f.is_infinite() {
        Some(if f > 0.0 { "Infinity" } else { "-Infinity" })
    } else {
        None
    }
}

fn wrap(out: &mut String, key: &str, quoted_value: &str) {
    let _ = write!(out, "{{\"{key}\":\"{quoted_value}\"}}");
}

fn write_value(out: &mut String, v: &Value, mode: JsonMode) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int64(i) => {
            if mode == JsonMode::Canonical && i.unsigned_abs() <= MAX_SAFE_INTEGER {
                let _ = write!(out, "{i}");
            } else {
                wrap(out, "$int64", &i.to_string());
            }
        }
        Value::Float64(f) => match (float_special(*f), mode) {
            (Some(s), _) => wrap(out, "$float", s),
            (None, JsonMode::Canonical) => out.push_str(&float_text(*f)),
            (None, JsonMode::Extended) => wrap(out, "$float", &float_text(*f)),
        },
        Value::Decimal(d) => wrap(out, "$decimal", &d.to_string()),
        Value::String(s) => write_string(out, s),
        Value::Binary { subtype, data } => {
            let _ = write!(
                out,
                "{{\"$binary\":{{\"base64\":\"{}\",\"subType\":\"{subtype:02x}\"}}}}",
                hex::base64_encode(data)
            );
        }
        Value::DateTime(ms) => wrap(out, "$date", &datetime::format(*ms)),
        Value::Timestamp(ts) => wrap(out, "$ts", &format!("{}.{}", ts.wall, ts.logical)),
        Value::ObjectId(id) => wrap(out, "$oid", &id.to_string()),
        Value::Uuid(u) => wrap(out, "$uuid", &uuid_text(u)),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item, mode);
            }
            out.push(']');
        }
        Value::Object(d) => write_document(out, d, mode),
        Value::VectorF32(xs) => {
            out.push_str("{\"$vector\":[");
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(out, "{x:?}");
            }
            out.push_str("]}");
        }
        Value::Counter(c) => {
            let _ = write!(out, "{{\"$counter\":{c}}}");
        }
        Value::MinKey => out.push_str("{\"$minKey\":1}"),
        Value::MaxKey => out.push_str("{\"$maxKey\":1}"),
    }
}

/// `8-4-4-4-12` lowercase hex.
fn uuid_text(u: &[u8; 16]) -> String {
    let h = hex::encode(u);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Minimal escaping: `"`, `\` and C0 controls (short forms where JSON has them); everything
/// else, including non-ASCII, verbatim UTF-8.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decimal::Decimal128, oid::ObjectId, value::Timestamp};

    #[test]
    fn canonical_json_of_every_type() {
        let mut d = Document::new();
        d.insert("n", Value::Null);
        d.insert("b", Value::Bool(true));
        d.insert("i", Value::Int64(-5));
        d.insert("big", Value::Int64((1 << 53) + 1));
        d.insert("f", Value::Float64(1.0));
        d.insert("nan", Value::Float64(f64::NAN));
        d.insert("dec", Value::Decimal(Decimal128::parse("12.50").unwrap()));
        d.insert("s", Value::String("a\"\\\n\u{1}é".into()));
        d.insert(
            "bin",
            Value::Binary {
                subtype: 0x80,
                data: vec![1, 2, 3],
            },
        );
        d.insert("dt", Value::DateTime(0));
        d.insert(
            "ts",
            Value::Timestamp(Timestamp {
                wall: 7,
                logical: 2,
            }),
        );
        d.insert("oid", Value::ObjectId(ObjectId([0x11; 12])));
        d.insert("u", Value::Uuid([0xAB; 16]));
        d.insert(
            "a",
            Value::Array(vec![Value::Int64(1), Value::MinKey, Value::MaxKey]),
        );
        d.insert("v", Value::VectorF32(vec![0.5, -1.0]));
        d.insert("c", Value::Counter(3));
        let expected = concat!(
            r#"{"n":null,"b":true,"i":-5,"big":{"$int64":"9007199254740993"},"f":1.0,"#,
            r#""nan":{"$float":"NaN"},"dec":{"$decimal":"12.50"},"s":"a\"\\\n\u0001é","#,
            r#""bin":{"$binary":{"base64":"AQID","subType":"80"}},"#,
            r#""dt":{"$date":"1970-01-01T00:00:00.000Z"},"ts":{"$ts":"7.2"},"#,
            r#""oid":{"$oid":"111111111111111111111111"},"#,
            r#""u":{"$uuid":"abababab-abab-abab-abab-abababababab"},"#,
            r#""a":[1,{"$minKey":1},{"$maxKey":1}],"v":{"$vector":[0.5,-1.0]},"c":{"$counter":3}}"#
        );
        assert_eq!(to_json(&d, JsonMode::Canonical), expected);
        assert_eq!(
            value_to_json(&Value::Int64(1), JsonMode::Extended),
            r#"{"$int64":"1"}"#
        );
        assert_eq!(
            value_to_json(&Value::Float64(1e300), JsonMode::Extended),
            r#"{"$float":"1e300"}"#
        );
    }
}
