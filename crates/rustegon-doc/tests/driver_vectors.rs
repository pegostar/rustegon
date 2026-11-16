// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! RDoc v1 codec vectors for the drivers (FR-DRV-001/002/003, data-model.md §2 and §4, M11).
//!
//! The .NET and Java codecs must be byte-exact with the server: documents travel as RDoc v1
//! (`Document.rdoc`), ids and parameters as the value encoding (`Value.rdoc_value`, tag +
//! payload, no header). This test writes the vectors both drivers check against:
//! - `drivers/conformance/codec/values.yaml`: every value type and its edge cases as
//!   canonical extended JSON, extended-mode JSON and the hex of the value encoding, plus
//!   non-canonical value encodings with their canonical form;
//! - `drivers/conformance/codec/documents.yaml`: whole documents (canonical JSON + RDoc hex,
//!   the `name_hash16` of every field name, a hash collision, the depth limit) and
//!   non-canonical documents (flag bit 0 clear) with their canonical re-encoding;
//! - `drivers/conformance/codec/invalid.yaml`: byte strings and JSON texts that must be
//!   rejected, with the error class and catalog code the server's decoder gives.
//!
//! Every vector is produced by the real codec (`rustegon_doc::rdoc`, `rustegon_doc::json`) and
//! the expected error class is asserted, so the files cannot drift from the server. A stale
//! file fails the test; re-bless with
//! `RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-doc --test driver_vectors`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use std::{
    collections::HashMap,
    fmt::Write as _,
    path::{Path, PathBuf},
};

use rustegon_doc::{
    Document, Value,
    error::DocError,
    json::{JsonMode, parse_document, parse_value, to_json, value_to_json},
    rdoc::{self, decode, decode_value, encode, encode_value, name_hash16},
};

const BLESS_ENV: &str = "RGN_FIXTURES_BLESS";
const BLESS_COMMAND: &str = "cargo nextest run -p rustegon-doc --test driver_vectors";

fn out_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../drivers/conformance/codec")
}

fn check_or_bless(name: &str, content: &str) {
    let path = out_dir().join(name);
    if std::env::var(BLESS_ENV).is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(out_dir()).unwrap();
        std::fs::write(&path, content).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| {
            panic!(
                "{}: {e} (generate with {BLESS_ENV}=1 {BLESS_COMMAND})",
                path.display()
            )
        })
        .replace("\r\n", "\n");
    assert!(
        committed == content,
        "{} is stale; re-bless with {BLESS_ENV}=1 {BLESS_COMMAND} and review the diff",
        path.display()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A YAML 1.2 double-quoted scalar. Escapes everything outside the printable set YAML allows
/// unescaped (C0/C1 controls, DEL, BOM, line/paragraph separators), so any string survives.
fn yq(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20
                || (0x7F..=0x9F).contains(&(c as u32))
                || matches!(c, '\u{FEFF}' | '\u{2028}' | '\u{2029}') =>
            {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Int64(_) => "int64",
        Value::Float64(_) => "float64",
        Value::Decimal(_) => "decimal128",
        Value::String(_) => "string",
        Value::Binary { .. } => "binary",
        Value::DateTime(_) => "datetime",
        Value::Timestamp(_) => "timestamp",
        Value::ObjectId(_) => "objectId",
        Value::Uuid(_) => "uuid",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::VectorF32(_) => "vector_f32",
        Value::Counter(_) => "counter",
        Value::MinKey => "minKey",
        Value::MaxKey => "maxKey",
    }
}

/// Error class names used in `invalid.yaml` (one per `DocError` variant).
fn error_class(e: &DocError) -> &'static str {
    match e {
        DocError::TooLarge { .. } => "too_large",
        DocError::TooDeep { .. } => "too_deep",
        DocError::InvalidFieldName(_) => "invalid_field_name",
        DocError::InvalidVector(_) => "invalid_vector",
        DocError::Malformed { .. } => "malformed",
    }
}

const HEADER: &str = "# GENERATED by crates/rustegon-doc/tests/driver_vectors.rs - do not edit.\n# Re-bless: RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-doc --test driver_vectors\n# Format and use: drivers/conformance/README.md (section \"Codec vectors\").\n";

// ---------------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------------

/// `(name, extended JSON input)`; the canonical JSON written to the file is the codec's
/// output, which may differ from the input spelling (that difference is part of the vector).
fn value_cases() -> Vec<(&'static str, String)> {
    let s = |x: &str| x.to_owned();
    vec![
        ("null", s("null")),
        ("bool_false", s("false")),
        ("bool_true", s("true")),
        ("int64_zero", s("0")),
        ("int64_one", s("1")),
        ("int64_minus_one", s("-1")),
        ("int64_63_one_byte_zigzag_max", s("63")),
        ("int64_64_two_byte_zigzag", s("64")),
        ("int64_minus_64", s("-64")),
        ("int64_minus_65", s("-65")),
        ("int64_300", s("300")),
        ("int64_2_pow_53_plain", s("9007199254740992")),
        (
            "int64_2_pow_53_plus_1_wrapped",
            s(r#"{"$int64":"9007199254740993"}"#),
        ),
        (
            "int64_minus_2_pow_53_minus_1_wrapped",
            s(r#"{"$int64":"-9007199254740993"}"#),
        ),
        ("int64_max", s(r#"{"$int64":"9223372036854775807"}"#)),
        ("int64_min", s(r#"{"$int64":"-9223372036854775808"}"#)),
        (
            "int64_wrapper_small_value_prints_plain",
            s(r#"{"$int64":"5"}"#),
        ),
        ("float64_zero", s("0.0")),
        ("float64_negative_zero", s("-0.0")),
        ("float64_one", s("1.0")),
        ("float64_one_half", s("1.5")),
        ("float64_tenth", s("0.1")),
        ("float64_min_subnormal", s("5e-324")),
        ("float64_max", s("1.7976931348623157e308")),
        ("float64_lowest", s("-1.7976931348623157e308")),
        ("float64_1e300", s("1e300")),
        ("float64_2_pow_53", s("9007199254740992.0")),
        (
            "float64_integer_beyond_int64_parses_as_float",
            s("9223372036854775808"),
        ),
        ("float64_nan", s(r#"{"$float":"NaN"}"#)),
        ("float64_infinity", s(r#"{"$float":"Infinity"}"#)),
        ("float64_negative_infinity", s(r#"{"$float":"-Infinity"}"#)),
        ("float64_wrapper_number_string", s(r#"{"$float":"2.5"}"#)),
        ("decimal_12_50_keeps_cohort", s(r#"{"$decimal":"12.50"}"#)),
        ("decimal_zero", s(r#"{"$decimal":"0"}"#)),
        ("decimal_negative_zero", s(r#"{"$decimal":"-0"}"#)),
        ("decimal_0_1", s(r#"{"$decimal":"0.1"}"#)),
        ("decimal_1e3", s(r#"{"$decimal":"1E+3"}"#)),
        (
            "decimal_34_digits",
            s(r#"{"$decimal":"1234567890123456789012345678901234"}"#),
        ),
        ("decimal_min_positive", s(r#"{"$decimal":"1E-6176"}"#)),
        (
            "decimal_max",
            s(r#"{"$decimal":"9.999999999999999999999999999999999E+6144"}"#),
        ),
        ("decimal_negative", s(r#"{"$decimal":"-123.456"}"#)),
        ("decimal_infinity", s(r#"{"$decimal":"Infinity"}"#)),
        (
            "decimal_negative_infinity",
            s(r#"{"$decimal":"-Infinity"}"#),
        ),
        ("decimal_nan", s(r#"{"$decimal":"NaN"}"#)),
        ("string_empty", s(r#""""#)),
        ("string_ascii", s(r#""hello""#)),
        ("string_escapes", s(r#""\"\\\n\t\r\b\f\u0001\u001f""#)),
        ("string_nul_inside", s(r#""a\u0000b""#)),
        ("string_del_and_c1", s(r#""\u007f\u0080\u009f""#)),
        ("string_latin1", s(r#""héllo""#)),
        ("string_cjk", s(r#""日本語""#)),
        ("string_astral_emoji", s(r#""😀🎉""#)),
        ("string_combining", s("\"e\\u0301\"")),
        ("string_bom_and_separators", s("\"\\ufeff\\u2028\\u2029\"")),
        (
            "string_127_bytes_one_byte_length",
            format!("\"{}\"", "x".repeat(127)),
        ),
        (
            "string_128_bytes_two_byte_length",
            format!("\"{}\"", "x".repeat(128)),
        ),
        ("string_300_bytes", format!("\"{}\"", "y".repeat(300))),
        (
            "binary_generic_empty",
            s(r#"{"$binary":{"base64":"","subType":"00"}}"#),
        ),
        (
            "binary_generic",
            s(r#"{"$binary":{"base64":"AQID","subType":"00"}}"#),
        ),
        (
            "binary_uuid_subtype",
            s(r#"{"$binary":{"base64":"ASNFZ4mrze8BI0VniavN7w==","subType":"04"}}"#),
        ),
        (
            "binary_user_0x80",
            s(r#"{"$binary":{"base64":"/w==","subType":"80"}}"#),
        ),
        (
            "binary_user_0xff",
            s(r#"{"$binary":{"base64":"AAEC","subType":"ff"}}"#),
        ),
        (
            "datetime_epoch",
            s(r#"{"$date":"1970-01-01T00:00:00.000Z"}"#),
        ),
        (
            "datetime_2026",
            s(r#"{"$date":"2026-01-01T00:00:00.000Z"}"#),
        ),
        (
            "datetime_with_millis",
            s(r#"{"$date":"2026-11-09T12:34:56.789Z"}"#),
        ),
        (
            "datetime_one_ms_before_epoch",
            s(r#"{"$date":"1969-12-31T23:59:59.999Z"}"#),
        ),
        (
            "datetime_input_without_fraction",
            s(r#"{"$date":"2026-01-01T00:00:00Z"}"#),
        ),
        (
            "datetime_year_10000_expanded",
            s(r#"{"$date":"+010000-01-01T00:00:00.000Z"}"#),
        ),
        (
            "datetime_min",
            s(r#"{"$date":"-292275055-05-16T16:47:04.192Z"}"#),
        ),
        (
            "datetime_max",
            s(r#"{"$date":"+292278994-08-17T07:12:55.807Z"}"#),
        ),
        ("timestamp", s(r#"{"$ts":"1767225600000.7"}"#)),
        ("timestamp_zero", s(r#"{"$ts":"0.0"}"#)),
        ("object_id", s(r#"{"$oid":"65a1b2c3d4e5f60718293a4b"}"#)),
        (
            "object_id_uppercase_input",
            s(r#"{"$oid":"65A1B2C3D4E5F60718293A4B"}"#),
        ),
        (
            "uuid",
            s(r#"{"$uuid":"01234567-89ab-cdef-0123-456789abcdef"}"#),
        ),
        (
            "uuid_nil",
            s(r#"{"$uuid":"00000000-0000-0000-0000-000000000000"}"#),
        ),
        ("vector_f32_empty", s(r#"{"$vector":[]}"#)),
        ("vector_f32", s(r#"{"$vector":[0.5,-1.0,3.25]}"#)),
        (
            "vector_f32_negative_zero_and_tiny",
            s(r#"{"$vector":[-0.0,1e-45,3.4028235e38]}"#),
        ),
        ("min_key", s(r#"{"$minKey":1}"#)),
        ("max_key", s(r#"{"$maxKey":1}"#)),
        ("array_empty", s("[]")),
        ("array_mixed", s(r#"[1,"two",3.0,null,true]"#)),
        ("array_nested", s("[[],[[1]],[[[2,3]]]]")),
        ("array_of_documents", s(r#"[{"a":1},{"b":[{}]}]"#)),
        ("object_empty", s("{}")),
        ("object_field_order_kept", s(r#"{"z":1,"a":2,"m":3}"#)),
        (
            "object_nested",
            s(r#"{"a":{"b":{"c":{"d":[1,{"e":null}]}}}}"#),
        ),
        (
            "object_unicode_names",
            s(r#"{"ключ":1,"名前":"x","é":true}"#),
        ),
        (
            "object_dotted_and_spaced_names",
            s(r#"{"a.b":1,"c d":2,"_id":3}"#),
        ),
    ]
}

fn values_yaml() -> String {
    let mut o = String::from(HEADER);
    o.push_str("# Value encoding = type tag + payload, exactly the bytes of a field value inside a document\n# (Value.rdoc_value: ids, parameters). Every vector must encode to `hex` from `ext_json`\n# (unless decode_only) and decode from `hex` to `ext_json`.\nversion: 1\nvalues:\n");
    for (name, input) in value_cases() {
        let v = parse_value(&input).unwrap_or_else(|e| panic!("{name}: {e}"));
        let bytes = encode_value(&v).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(decode_value(&bytes).unwrap(), v, "{name}: round trip");
        let canonical = value_to_json(&v, JsonMode::Canonical);
        // The canonical JSON parses back to the same value.
        assert_eq!(
            parse_value(&canonical).unwrap(),
            v,
            "{name}: canonical JSON round trip"
        );
        let _ = write!(
            o,
            "  - name: {}\n    type: {}\n    input: {}\n    ext_json: {}\n    extended_json: {}\n    hex: {}\n",
            yq(name),
            yq(type_name(&v)),
            yq(&input),
            yq(&canonical),
            yq(&value_to_json(&v, JsonMode::Extended)),
            yq(&hex(&bytes)),
        );
    }
    // `counter` is a read-only projection: never accepted as input, but drivers decode it.
    for (name, n) in [
        ("counter_42", 42i64),
        ("counter_negative", -3),
        ("counter_max", i64::MAX),
    ] {
        let v = Value::Counter(n);
        let bytes = encode_value(&v).unwrap();
        assert_eq!(decode_value(&bytes).unwrap(), v);
        let canonical = value_to_json(&v, JsonMode::Canonical);
        assert!(
            parse_value(&canonical).is_err(),
            "counter must be refused as input"
        );
        let _ = write!(
            o,
            "  - name: {}\n    type: \"counter\"\n    decode_only: true\n    ext_json: {}\n    extended_json: {}\n    hex: {}\n",
            yq(name),
            yq(&canonical),
            yq(&value_to_json(&v, JsonMode::Extended)),
            yq(&hex(&bytes)),
        );
    }
    // Non-canonical value encodings: accepted and normalised (a value has no canonical flag).
    o.push_str("# Accepted, non-canonical value encodings: decode `hex`, re-encode -> `canonical_hex`.\nnoncanonical:\n");
    let nan_payload = 0x7FF8_0000_0000_0001u64.to_le_bytes();
    let negative_nan = 0xFFF8_0000_0000_0000u64.to_le_bytes();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("int64_one_non_minimal_varint", vec![0x03, 0x82, 0x00]),
        (
            "string_length_non_minimal_varint",
            vec![0x06, 0x81, 0x00, b'a'],
        ),
        (
            "float64_nan_with_payload",
            [&[0x04u8][..], &nan_payload].concat(),
        ),
        (
            "float64_negative_nan",
            [&[0x04u8][..], &negative_nan].concat(),
        ),
        (
            "decimal_non_canonical_coefficient_is_zero",
            [&[0x05u8][..], &noncanonical_decimal_bits().to_le_bytes()].concat(),
        ),
    ];
    for (name, bytes) in cases {
        let v = decode_value(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let canonical = encode_value(&v).unwrap();
        assert_ne!(canonical, bytes, "{name}: input must be non-canonical");
        let _ = write!(
            o,
            "  - name: {}\n    hex: {}\n    canonical_hex: {}\n    ext_json: {}\n",
            yq(name),
            yq(&hex(&bytes)),
            yq(&hex(&canonical)),
            yq(&value_to_json(&v, JsonMode::Canonical)),
        );
    }
    o
}

/// decimal128 BID bits with a coefficient of 10^34 in the small-coefficient form: not a
/// canonical encoding (IEEE 754-2008: such coefficients mean zero).
fn noncanonical_decimal_bits() -> u128 {
    const BIAS: u128 = 6176;
    let coefficient: u128 = 10u128.pow(34);
    (BIAS << 113) | coefficient
}

// ---------------------------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------------------------

/// The first two names `f<n>` whose `name_hash16` collide (deterministic search).
fn hash_collision() -> (String, String) {
    let mut seen: HashMap<u16, String> = HashMap::new();
    for n in 0u32.. {
        let name = format!("f{n}");
        let h = name_hash16(name.as_bytes());
        if let Some(prev) = seen.insert(h, name.clone()) {
            return (prev, name);
        }
    }
    unreachable!()
}

fn nested_arrays(depth: usize) -> String {
    format!("{}{}", "[".repeat(depth), "]".repeat(depth))
}

fn document_cases() -> Vec<(String, Document)> {
    let p = |s: &str| parse_document(s).unwrap_or_else(|e| panic!("{s}: {e}"));
    let (c1, c2) = hash_collision();
    let mut counter = Document::new();
    counter.insert("_id", Value::Int64(1));
    counter.insert("views", Value::Counter(42));
    let many = format!(
        "{{{}}}",
        (0..40)
            .map(|i| format!("\"f{i}\":{i}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let big_array = format!(
        "{{\"a\":[{}]}}",
        (0..200)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    vec![
        ("empty".into(), Document::new()),
        ("single_int".into(), p(r#"{"a":1}"#)),
        ("id_int".into(), p(r#"{"_id":42,"name":"x"}"#)),
        ("id_string".into(), p(r#"{"_id":"user-1","n":1}"#)),
        (
            "id_object_id".into(),
            p(r#"{"_id":{"$oid":"65a1b2c3d4e5f60718293a4b"},"n":1}"#),
        ),
        (
            "id_uuid".into(),
            p(r#"{"_id":{"$uuid":"01234567-89ab-cdef-0123-456789abcdef"}}"#),
        ),
        (
            "all_types".into(),
            p(concat!(
                r#"{"_id":{"$oid":"65a1b2c3d4e5f60718293a4b"},"null":null,"t":true,"f":false,"#,
                r#""i":-42,"big":{"$int64":"9223372036854775807"},"x":1.5,"negz":-0.0,"#,
                r#""nan":{"$float":"NaN"},"inf":{"$float":"-Infinity"},"#,
                r#""dec":{"$decimal":"12.50"},"s":"héllo","#,
                r#""bin":{"$binary":{"base64":"AQID","subType":"00"}},"#,
                r#""dt":{"$date":"2026-01-01T00:00:00.000Z"},"ts":{"$ts":"1767225600000.7"},"#,
                r#""u":{"$uuid":"01234567-89ab-cdef-0123-456789abcdef"},"#,
                r#""arr":[1,"two",3.0],"obj":{"k":"v"},"vec":{"$vector":[0.5,-1.0,3.25]},"#,
                r#""min":{"$minKey":1},"max":{"$maxKey":1}}"#
            )),
        ),
        (
            "field_order_differs_from_index_order".into(),
            p(r#"{"zeta":1,"alpha":2,"mid":3,"_id":4}"#),
        ),
        (
            "nested".into(),
            p(r#"{"a":{"b":{"c":[[],{},[{"d":[1,[2,[3]]]}]]}},"e":[{"x":1},{"y":[{}]}],"z":{}}"#),
        ),
        (
            "unicode_and_dotted_names".into(),
            p(r#"{"名前":"太郎","ключ":1,"a.b":2,"c d":3,"😀":4}"#),
        ),
        (
            "long_string_two_byte_lengths".into(),
            p(&format!(r#"{{"s":"{}"}}"#, "x".repeat(300))),
        ),
        ("many_fields".into(), p(&many)),
        ("array_200_elements".into(), p(&big_array)),
        (
            "name_hash16_collision".into(),
            p(&format!(r#"{{"{c2}":2,"{c1}":1}}"#)),
        ),
        (
            "max_depth_100".into(),
            p(&format!(r#"{{"a":{}}}"#, nested_arrays(99))),
        ),
        ("counter_decode_only".into(), counter),
    ]
}

/// Field names of a document in first-appearance order (nested objects included).
fn field_names(doc: &Document, out: &mut Vec<String>) {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(d) => field_names(d, out),
            Value::Array(items) => items.iter().for_each(|i| walk(i, out)),
            _ => {}
        }
    }
    for (name, v) in doc.iter() {
        if !out.iter().any(|n| n == name) {
            out.push(name.to_owned());
        }
        walk(v, out);
    }
}

fn header_bytes(flags: u8, body: &[u8]) -> Vec<u8> {
    let total = u32::try_from(rdoc::HEADER_LEN + body.len()).unwrap();
    let mut out = vec![rdoc::MAGIC, rdoc::VERSION, flags];
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out
}

/// An object (tag included) from raw `(name bytes, value bytes)` fields, with a correct sorted
/// index, so that a test can corrupt exactly one aspect.
fn object(fields: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut entries = Vec::new();
    for (name, value) in fields {
        entries.push((
            name_hash16(name),
            name.to_vec(),
            u32::try_from(body.len()).unwrap(),
        ));
        body.extend(varint(name.len() as u64));
        body.extend_from_slice(name);
        body.extend_from_slice(value);
    }
    entries.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    let index: Vec<(u16, u32)> = entries.iter().map(|e| (e.0, e.2)).collect();
    object_raw(fields.len() as u64, body.len() as u64, &index, &body)
}

fn object_raw(n: u64, body_len: u64, index: &[(u16, u32)], body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x0D];
    out.extend(varint(n));
    out.extend(varint(body_len));
    for (h, off) in index {
        out.extend_from_slice(&h.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
    }
    out.extend_from_slice(body);
    out
}

fn array_raw(elements: &[Vec<u8>], offsets: Option<&[u32]>) -> Vec<u8> {
    let mut body = Vec::new();
    let mut offs = Vec::new();
    for e in elements {
        offs.push(u32::try_from(body.len()).unwrap());
        body.extend_from_slice(e);
    }
    let offs = offsets.map_or(offs, <[u32]>::to_vec);
    let mut out = vec![0x0C];
    out.extend(varint(elements.len() as u64));
    out.extend(varint(body.len() as u64));
    for o in offs {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend(body);
    out
}

fn documents_yaml() -> String {
    let mut o = String::from(HEADER);
    o.push_str("# Canonical RDoc v1 documents (flags = 0x01). Encoding `ext_json` must give `hex` byte for byte\n# (unless decode_only); decoding `hex` must give `ext_json`. `name_hash16` = low 16 bits of\n# xxh3_64(name UTF-8 bytes, seed 0), stored little-endian in the index; index entries are\n# sorted by (hash, name bytes).\nversion: 1\ndocuments:\n");
    for (name, doc) in document_cases() {
        let bytes = encode(&doc).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(decode(&bytes).unwrap(), doc, "{name}: round trip");
        let json = to_json(&doc, JsonMode::Canonical);
        let decode_only = doc.iter().any(|(_, v)| matches!(v, Value::Counter(_)));
        if !decode_only {
            assert_eq!(
                parse_document(&json).unwrap(),
                doc,
                "{name}: JSON round trip"
            );
        }
        let mut names = Vec::new();
        field_names(&doc, &mut names);
        let _ = writeln!(o, "  - name: {}", yq(&name));
        if decode_only {
            o.push_str("    decode_only: true\n");
        }
        let _ = write!(
            o,
            "    ext_json: {}\n    hex: {}\n    name_hash16:\n",
            yq(&json),
            yq(&hex(&bytes))
        );
        for n in names {
            let _ = writeln!(
                o,
                "      - {{name: {}, hash: \"{:04x}\"}}",
                yq(&n),
                name_hash16(n.as_bytes())
            );
        }
    }
    // Non-canonical documents (flag bit 0 clear): accepted, re-encoding gives canonical bytes.
    o.push_str("# Accepted non-canonical documents (flags = 0x00): decode `hex`, re-encode -> `canonical_hex`.\n# The same bytes with flags = 0x01 are rejected (see invalid.yaml, *_with_canonical_flag).\nnoncanonical:\n");
    for (name, value) in noncanonical_field_values() {
        let bytes = header_bytes(0x00, &object(&[(b"a", value)]));
        let doc = decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let canonical = encode(&doc).unwrap();
        let _ = write!(
            o,
            "  - name: {}\n    hex: {}\n    canonical_hex: {}\n    ext_json: {}\n",
            yq(name),
            yq(&hex(&bytes)),
            yq(&hex(&canonical)),
            yq(&to_json(&doc, JsonMode::Canonical)),
        );
    }
    // A canonical document without the flag is accepted as well (flag only adds strictness).
    let plain = encode(&parse_document(r#"{"a":1}"#).unwrap()).unwrap();
    let mut unflagged = plain.clone();
    unflagged[2] = 0;
    assert_eq!(decode(&unflagged).unwrap(), decode(&plain).unwrap());
    let _ = write!(
        o,
        "  - name: canonical_bytes_without_flag\n    hex: {}\n    canonical_hex: {}\n    ext_json: {}\n",
        yq(&hex(&unflagged)),
        yq(&hex(&plain)),
        yq(r#"{"a":1}"#)
    );
    o
}

/// Non-canonical encodings of the value of field `a` (accepted only without the flag).
fn noncanonical_field_values() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("int64_non_minimal_varint", vec![0x03, 0x82, 0x00]),
        (
            "float64_nan_with_payload",
            [&[0x04u8][..], &0x7FF8_0000_0000_0001u64.to_le_bytes()].concat(),
        ),
        (
            "decimal_non_canonical",
            [&[0x05u8][..], &noncanonical_decimal_bits().to_le_bytes()].concat(),
        ),
    ]
}

// ---------------------------------------------------------------------------------------------
// Invalid inputs
// ---------------------------------------------------------------------------------------------

fn invalid_documents() -> Vec<(String, Vec<u8>, &'static str)> {
    let valid = encode(&parse_document(r#"{"a":1}"#).unwrap()).unwrap();
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = valid.clone();
        f(&mut b);
        b
    };
    let int1 = vec![0x03, 0x02];
    let doc = |fields: &[(&[u8], Vec<u8>)]| header_bytes(0x01, &object(fields));
    let mut too_deep = vec![0x0C, 0x00, 0x00];
    for _ in 0..99 {
        too_deep = array_raw(&[too_deep], None);
    }
    // 100 nested arrays below the root object: depth 101.
    let too_deep_doc = doc(&[(b"a", too_deep)]);
    let mut huge = vec![rdoc::MAGIC, rdoc::VERSION, 0x01];
    huge.extend_from_slice(&(16 * 1024 * 1024 + 1u32).to_le_bytes());
    huge.push(0x0D);
    let (h_a, h_b) = (name_hash16(b"a"), name_hash16(b"b"));
    let ab_body = [vec![0x01, b'a', 0x01], vec![0x01, b'b', 0x01]].concat();
    let (first, second) = if (h_a, b"a") < (h_b, b"b") {
        ((h_a, 0), (h_b, 3))
    } else {
        ((h_b, 3), (h_a, 0))
    };
    let mut cases: Vec<(String, Vec<u8>, &'static str)> = vec![
        ("empty_input".into(), vec![], "malformed"),
        (
            "truncated_header".into(),
            vec![0xD7, 0x01, 0x01],
            "malformed",
        ),
        ("bad_magic".into(), with(&|b| b[0] = 0xD8), "malformed"),
        (
            "unsupported_version_2".into(),
            with(&|b| b[1] = 0x02),
            "malformed",
        ),
        (
            "unknown_flag_bits".into(),
            with(&|b| b[2] = 0x03),
            "malformed",
        ),
        (
            "total_len_does_not_match_input".into(),
            with(&|b| b.push(0x00)),
            "malformed",
        ),
        ("total_len_above_16_mib".into(), huge, "too_large"),
        (
            "root_is_an_array".into(),
            header_bytes(0x01, &array_raw(&[], None)),
            "malformed",
        ),
        (
            "trailing_bytes_after_root".into(),
            header_bytes(
                0x01,
                &[&object(&[(b"a", int1.clone())])[..], &[0x01]].concat(),
            ),
            "malformed",
        ),
        (
            "value_truncated".into(),
            header_bytes(0x01, &object(&[(b"a", vec![0x03])])),
            "malformed",
        ),
        (
            "unknown_type_tag".into(),
            doc(&[(b"a", vec![0x12])]),
            "malformed",
        ),
        (
            "missing_tag_0x00".into(),
            doc(&[(b"a", vec![0x00])]),
            "malformed",
        ),
        (
            "bool_byte_not_0_or_1".into(),
            doc(&[(b"a", vec![0x02, 0x02])]),
            "malformed",
        ),
        (
            "invalid_utf8_string".into(),
            doc(&[(b"a", vec![0x06, 0x01, 0xFF])]),
            "malformed",
        ),
        (
            "string_length_past_value".into(),
            header_bytes(0x01, &object(&[(b"a", vec![0x06, 0x05, b'x'])])),
            "malformed",
        ),
        (
            "invalid_utf8_field_name".into(),
            doc(&[(&[0xFF], int1.clone())]),
            "malformed",
        ),
        (
            "field_name_with_nul".into(),
            doc(&[(b"a\0b", int1.clone())]),
            "invalid_field_name",
        ),
        (
            "field_name_empty".into(),
            doc(&[(b"", vec![0x03, 0x02])]),
            "invalid_field_name",
        ),
        (
            "field_name_dollar_prefix".into(),
            doc(&[(b"$a", int1.clone())]),
            "invalid_field_name",
        ),
        (
            "field_name_1025_bytes".into(),
            doc(&[(&[b'n'; 1025], int1.clone())]),
            "invalid_field_name",
        ),
        (
            "duplicate_field_names".into(),
            doc(&[(b"a", int1.clone()), (b"a", vec![0x03, 0x04])]),
            "invalid_field_name",
        ),
        (
            "index_hash_mismatch".into(),
            with(&|b| b[10] ^= 0x01),
            "malformed",
        ),
        (
            "index_not_sorted".into(),
            header_bytes(
                0x01,
                &object_raw(2, ab_body.len() as u64, &[second, first], &ab_body),
            ),
            "malformed",
        ),
        (
            "index_offset_not_a_field_start".into(),
            header_bytes(
                0x01,
                &object_raw(1, 4, &[(h_a, 1)], &[0x01, b'a', 0x03, 0x02]),
            ),
            "malformed",
        ),
        (
            "object_body_length_mismatch".into(),
            header_bytes(
                0x01,
                &object_raw(1, 5, &[(h_a, 0)], &[0x01, b'a', 0x03, 0x02, 0x01]),
            ),
            "malformed",
        ),
        (
            "field_count_exceeds_body".into(),
            header_bytes(
                0x01,
                &object_raw(200, 4, &[(h_a, 0)], &[0x01, b'a', 0x03, 0x02]),
            ),
            "malformed",
        ),
        (
            "array_offset_mismatch".into(),
            doc(&[(
                b"a",
                array_raw(&[int1.clone(), int1.clone()], Some(&[0, 3])),
            )]),
            "malformed",
        ),
        (
            "binary_reserved_subtype_0x05".into(),
            doc(&[(b"a", vec![0x07, 0x05, 0x00])]),
            "malformed",
        ),
        (
            "binary_uuid_subtype_15_bytes".into(),
            doc(&[(b"a", [vec![0x07, 0x04, 0x0F], vec![0; 15]].concat())]),
            "malformed",
        ),
        (
            "vector_with_nan".into(),
            doc(&[(
                b"a",
                [vec![0x0E, 0x01], f32::NAN.to_le_bytes().to_vec()].concat(),
            )]),
            "invalid_vector",
        ),
        (
            "vector_with_infinity".into(),
            doc(&[(
                b"a",
                [vec![0x0E, 0x01], f32::INFINITY.to_le_bytes().to_vec()].concat(),
            )]),
            "invalid_vector",
        ),
        ("depth_101".into(), too_deep_doc, "too_deep"),
    ];
    for (name, value) in noncanonical_field_values() {
        cases.push((
            format!("{name}_with_canonical_flag"),
            doc(&[(b"a", value)]),
            "malformed",
        ));
    }
    cases
}

fn invalid_values() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    vec![
        ("empty_input", vec![], "malformed"),
        ("unknown_tag_0xee", vec![0xEE], "malformed"),
        ("trailing_bytes", vec![0x01, 0x01], "malformed"),
        ("truncated_varint", vec![0x03, 0x80], "malformed"),
        (
            "varint_overflows_u64",
            [vec![0x03], vec![0xFF; 9], vec![0x02]].concat(),
            "malformed",
        ),
        ("truncated_float64", vec![0x04, 0x00, 0x00], "malformed"),
        ("truncated_object_id", vec![0x0A, 0x01, 0x02], "malformed"),
        (
            "string_length_past_end",
            vec![0x06, 0x05, b'a'],
            "malformed",
        ),
        ("bool_byte_2", vec![0x02, 0x02], "malformed"),
        (
            "binary_reserved_subtype",
            vec![0x07, 0x10, 0x00],
            "malformed",
        ),
        (
            "vector_nan",
            [vec![0x0E, 0x01], f32::NAN.to_le_bytes().to_vec()].concat(),
            "invalid_vector",
        ),
    ]
}

/// Extended-JSON texts the parsers must refuse (`RDocument.FromJson` / `RDocument.parse`).
fn invalid_json() -> Vec<(&'static str, &'static str, bool)> {
    // (name, text, is_document)
    vec![
        ("syntax_error", r#"{"a":"#, true),
        ("root_not_an_object", "[1]", true),
        ("duplicate_names", r#"{"a":1,"a":2}"#, true),
        ("dollar_prefixed_field", r#"{"$a":1}"#, true),
        ("nested_dollar_prefixed_field", r#"{"a":{"$set":1}}"#, true),
        ("field_name_with_nul", r#"{"a\u0000b":1}"#, true),
        ("field_name_empty", r#"{"":1}"#, true),
        ("counter_as_input", r#"{"c":{"$counter":1}}"#, true),
        (
            "wrapper_with_extra_key",
            r#"{"a":{"$oid":"65a1b2c3d4e5f60718293a4b","x":1}}"#,
            true,
        ),
        ("number_beyond_float64", "1e400", false),
        (
            "int64_wrapper_out_of_range",
            r#"{"$int64":"9223372036854775808"}"#,
            false,
        ),
        ("float_wrapper_lowercase_nan", r#"{"$float":"nan"}"#, false),
        (
            "decimal_35_significant_digits",
            r#"{"$decimal":"12345678901234567890123456789012345"}"#,
            false,
        ),
        ("oid_too_short", r#"{"$oid":"65a1b2"}"#, false),
        (
            "uuid_without_hyphens",
            r#"{"$uuid":"0123456789abcdef0123456789abcdef"}"#,
            false,
        ),
        (
            "date_without_z",
            r#"{"$date":"2026-01-01T00:00:00.000"}"#,
            false,
        ),
        (
            "date_four_fraction_digits",
            r#"{"$date":"2026-01-01T00:00:00.0000Z"}"#,
            false,
        ),
        (
            "binary_reserved_subtype",
            r#"{"$binary":{"base64":"AA==","subType":"05"}}"#,
            false,
        ),
        (
            "binary_uuid_subtype_wrong_length",
            r#"{"$binary":{"base64":"AA==","subType":"04"}}"#,
            false,
        ),
        (
            "binary_bad_base64",
            r#"{"$binary":{"base64":"A","subType":"00"}}"#,
            false,
        ),
        ("vector_non_finite", r#"{"$vector":[1e39]}"#, false),
    ]
}

fn invalid_yaml() -> String {
    let mut o = String::from(HEADER);
    o.push_str("# Inputs that must be rejected. `error` = error class (malformed -> RGN-1001 InvalidArgument,\n# too_large -> RGN-1002, too_deep -> RGN-1003, invalid_field_name -> RGN-1004,\n# invalid_vector -> RGN-1040); `code` = the catalog code. A driver must reject the input\n# (never panic/crash); it should report the same code.\nversion: 1\ndocuments:\n");
    for (name, bytes, expected) in invalid_documents() {
        let err = decode(&bytes).expect_err(&name);
        assert_eq!(error_class(&err), expected, "{name}: {err}");
        let _ = write!(
            o,
            "  - name: {}\n    hex: {}\n    error: {expected}\n    code: {}\n",
            yq(&name),
            yq(&hex(&bytes)),
            err.code().code()
        );
    }
    o.push_str("values:\n");
    for (name, bytes, expected) in invalid_values() {
        let err = decode_value(&bytes).expect_err(name);
        assert_eq!(error_class(&err), expected, "{name}: {err}");
        let _ = write!(
            o,
            "  - name: {}\n    hex: {}\n    error: {expected}\n    code: {}\n",
            yq(name),
            yq(&hex(&bytes)),
            err.code().code()
        );
    }
    o.push_str("# Extended-JSON texts: `kind: document` is parsed as a document, `value` as a single value.\njson:\n");
    for (name, text, is_document) in invalid_json() {
        let err = if is_document {
            parse_document(text).expect_err(name)
        } else {
            parse_value(text).expect_err(name)
        };
        let _ = write!(
            o,
            "  - name: {}\n    kind: {}\n    json: {}\n    error: {}\n    code: {}\n",
            yq(name),
            if is_document { "document" } else { "value" },
            yq(text),
            error_class(&err),
            err.code().code()
        );
    }
    o
}

/// FR-DRV-003: the codec vectors for the drivers are current (values, documents, invalid).
#[test]
fn tc_drv_conf_codec_vectors_are_current() {
    check_or_bless("values.yaml", &values_yaml());
    check_or_bless("documents.yaml", &documents_yaml());
    check_or_bless("invalid.yaml", &invalid_yaml());
}

/// The YAML quoting used by the vector files escapes exactly the non-printable characters.
#[test]
fn tc_drv_conf_yaml_quoting_escapes_non_printable_characters() {
    assert_eq!(yq("a\"b\\c"), r#""a\"b\\c""#);
    assert_eq!(
        yq("\u{0}\u{7f}\u{85}\u{feff}\u{e9}\u{1f600}"),
        "\"\\u0000\\u007f\\u0085\\ufeff\u{e9}\u{1f600}\""
    );
}
