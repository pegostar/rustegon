// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Document-model acceptance tests TC-DOC-001…007 (data-model.md §12; AC-DOC-001…003).

// Test code: casts and short names in reference implementations are deliberate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap
)]

mod common;

use std::{
    cmp::Ordering,
    collections::HashSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::{Counters, arb_document, arb_value, raw_object, raw_rdoc};
use proptest::prelude::*;
use rustegon_doc::{
    Decimal128, DocError, Document, ObjectIdGenerator, Value,
    compare::{compare, values_equal},
    json::{JsonMode, parse_document, to_json},
    keyenc::{Direction, decode_element, encode_key},
    limits::{MAX_DEPTH, MAX_DOCUMENT_SIZE},
    path::{FieldPath, RDocRef, Segment, get_path},
    rdoc::{self, canonicalize, decode, encode, encoded_len},
};
use rustegon_sim_api::{BoxFuture, Clock, Rng};

/// `cases` by default; `PROPTEST_CASES` overrides it for long runs (AC-DOC-001 asks for 10^6).
fn cfg(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------- TC-DOC-001

proptest! {
    #![proptest_config(cfg(512))]

    /// AC-DOC-001: JSON → RDoc → JSON gives byte-equal canonical JSON; RDoc → RDoc gives
    /// byte-equal canonical bytes; extended JSON round-trips too.
    #[test]
    fn tc_doc_001_json_rdoc_round_trip(doc in arb_document(Counters::Excluded)) {
        let json = to_json(&doc, JsonMode::Canonical);
        let parsed = parse_document(&json).unwrap();
        prop_assert_eq!(&parsed, &doc);
        prop_assert_eq!(to_json(&parsed, JsonMode::Canonical), json.clone());

        let ext = to_json(&doc, JsonMode::Extended);
        prop_assert_eq!(parse_document(&ext).unwrap(), doc.clone());

        let bytes = encode(&parsed).unwrap();
        prop_assert_eq!(bytes.len(), encoded_len(&parsed).unwrap());
        let back = decode(&bytes).unwrap();
        prop_assert_eq!(&back, &doc);
        prop_assert_eq!(to_json(&back, JsonMode::Canonical), json);
        prop_assert_eq!(encode(&back).unwrap(), bytes);
    }

    /// Counters are output-only in JSON but round-trip through RDoc.
    #[test]
    fn tc_doc_001_rdoc_round_trip_with_counters(doc in arb_document(Counters::Allowed)) {
        let bytes = encode(&doc).unwrap();
        prop_assert_eq!(decode(&bytes).unwrap(), doc);
    }

    /// The decoder rejects malformed input with an error and never panics: random bytes, and
    /// bit flips / truncations of valid documents. Lazy lookups on the same bytes never panic.
    #[test]
    fn tc_doc_001_decoder_never_panics(
        doc in arb_document(Counters::Allowed),
        flips in proptest::collection::vec((any::<prop::sample::Index>(), 0u8..8), 1..4),
        cut in any::<prop::sample::Index>(),
        noise in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let bytes = encode(&doc).unwrap();
        let mut flipped = bytes.clone();
        for (i, bit) in &flips {
            let i = i.index(flipped.len());
            flipped[i] ^= 1 << bit;
        }
        let truncated = &bytes[..cut.index(bytes.len())];
        let with_header = raw_rdoc(1, &noise);
        for input in [&flipped[..], truncated, &noise[..], &with_header[..]] {
            let _ = decode(input);
            if let Ok(r) = RDocRef::new(input) {
                for p in ["a", "a.0", "b.c.d", "0"] {
                    if let Ok(Some(v)) = r.get(&FieldPath::parse(p).unwrap()) {
                        let _ = v.to_value();
                    }
                }
            }
            let _ = decode_element(input, Direction::Ascending);
            let _ = decode_element(input, Direction::Descending);
            if let Ok(s) = std::str::from_utf8(input) {
                let _ = parse_document(s);
            }
        }
    }
}

#[test]
fn tc_doc_001_duplicate_field_rejected() {
    for json in [
        r#"{"a":1,"a":2}"#,
        r#"{"x":{"b":1,"c":2,"b":3}}"#,
        r#"{"x":[{"k":1,"k":1}]}"#,
    ] {
        let e = parse_document(json).unwrap_err();
        assert_eq!(e.code().code(), 1004, "{json}");
    }
    // RDoc with two fields named "a" (index entries identical).
    let root = raw_object(&[("a", vec![0x01]), ("a", vec![0x01])]);
    let e = decode(&raw_rdoc(1, &root)).unwrap_err();
    assert_eq!(e.code().code(), 1004);
    assert!(matches!(e, DocError::InvalidFieldName(_)));
}

// ---------------------------------------------------------------- TC-DOC-002

/// Exact decimal text of a number: (negative, integer digits, fraction digits), normalized.
#[derive(Debug, PartialEq, Eq)]
enum RefNum {
    NaN,
    NegInf,
    Finite(bool, String, String),
    PosInf,
}

fn normalize(neg: bool, int: &str, frac: &str) -> RefNum {
    let int = int.trim_start_matches('0').to_owned();
    let frac = frac.trim_end_matches('0').to_owned();
    let zero = int.is_empty() && frac.is_empty();
    RefNum::Finite(neg && !zero, int, frac)
}

/// Independent exact conversion: Rust's fixed-precision float formatting is exact, and 1100
/// fractional digits cover every f64 (at most 1074 binary fraction digits).
fn ref_num(v: &Value) -> RefNum {
    match v {
        Value::Int64(i) | Value::Counter(i) => normalize(*i < 0, &i.unsigned_abs().to_string(), ""),
        Value::Float64(f) if f.is_nan() => RefNum::NaN,
        Value::Float64(f) if f.is_infinite() => {
            if *f > 0.0 {
                RefNum::PosInf
            } else {
                RefNum::NegInf
            }
        }
        Value::Float64(f) => {
            let s = format!("{:.1100}", f.abs());
            let (i, fr) = s.split_once('.').unwrap();
            normalize(f.is_sign_negative(), i, fr)
        }
        Value::Decimal(Decimal128::NaN) => RefNum::NaN,
        Value::Decimal(Decimal128::Infinity { negative }) => {
            if *negative {
                RefNum::NegInf
            } else {
                RefNum::PosInf
            }
        }
        Value::Decimal(Decimal128::Finite {
            negative,
            coefficient,
            exponent,
        }) => {
            let c = coefficient.to_string();
            let e = i64::from(*exponent);
            if e >= 0 {
                normalize(*negative, &format!("{c}{}", "0".repeat(e as usize)), "")
            } else {
                let k = (-e) as usize;
                let padded = format!("{}{c}", "0".repeat(k + 1));
                let (i, fr) = padded.split_at(padded.len() - k);
                normalize(*negative, i, fr)
            }
        }
        _ => unreachable!(),
    }
}

fn ref_num_cmp(a: &RefNum, b: &RefNum) -> Ordering {
    fn rank(n: &RefNum) -> u8 {
        match n {
            RefNum::NaN => 0,
            RefNum::NegInf => 1,
            RefNum::Finite(true, ..) => 2,
            RefNum::Finite(false, i, f) if i.is_empty() && f.is_empty() => 3,
            RefNum::Finite(false, ..) => 4,
            RefNum::PosInf => 5,
        }
    }
    let r = rank(a).cmp(&rank(b));
    if r != Ordering::Equal {
        return r;
    }
    match (a, b) {
        (RefNum::Finite(neg, ia, fa), RefNum::Finite(_, ib, fb)) => {
            let mag = ia.len().cmp(&ib.len()).then(ia.cmp(ib)).then(fa.cmp(fb));
            if *neg { mag.reverse() } else { mag }
        }
        _ => Ordering::Equal,
    }
}

/// Reference comparator written directly from data-model.md §2.1.
fn ref_cmp(a: Option<&Value>, b: Option<&Value>) -> Ordering {
    fn class(v: Option<&Value>) -> u8 {
        match v {
            Some(Value::MinKey) => 0,
            None => 1,
            Some(Value::Null) => 2,
            Some(Value::Int64(_) | Value::Float64(_) | Value::Decimal(_) | Value::Counter(_)) => 3,
            Some(Value::String(_)) => 4,
            Some(Value::Object(_)) => 5,
            Some(Value::Array(_)) => 6,
            Some(Value::Binary { .. }) => 7,
            Some(Value::ObjectId(_)) => 8,
            Some(Value::Uuid(_)) => 9,
            Some(Value::Bool(_)) => 10,
            Some(Value::DateTime(_)) => 11,
            Some(Value::Timestamp(_)) => 12,
            Some(Value::VectorF32(_)) => 13,
            Some(Value::MaxKey) => 14,
        }
    }
    let c = class(a).cmp(&class(b));
    if c != Ordering::Equal {
        return c;
    }
    let (Some(a), Some(b)) = (a, b) else {
        return Ordering::Equal;
    };
    match (a, b) {
        (Value::String(x), Value::String(y)) => x.as_bytes().cmp(y.as_bytes()),
        (Value::Object(x), Value::Object(y)) => {
            for ((nx, vx), (ny, vy)) in x.iter().zip(y.iter()) {
                let o = nx
                    .as_bytes()
                    .cmp(ny.as_bytes())
                    .then_with(|| ref_cmp(Some(vx), Some(vy)));
                if o != Ordering::Equal {
                    return o;
                }
            }
            x.len().cmp(&y.len())
        }
        (Value::Array(x), Value::Array(y)) => {
            for (p, q) in x.iter().zip(y) {
                let o = ref_cmp(Some(p), Some(q));
                if o != Ordering::Equal {
                    return o;
                }
            }
            x.len().cmp(&y.len())
        }
        (
            Value::Binary {
                subtype: sa,
                data: da,
            },
            Value::Binary {
                subtype: sb,
                data: db,
            },
        ) => (da.len(), sa, da).cmp(&(db.len(), sb, db)),
        (Value::ObjectId(x), Value::ObjectId(y)) => x.0.cmp(&y.0),
        (Value::Uuid(x), Value::Uuid(y)) => x.cmp(y),
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::DateTime(x), Value::DateTime(y)) => x.cmp(y),
        (Value::Timestamp(x), Value::Timestamp(y)) => (x.wall, x.logical).cmp(&(y.wall, y.logical)),
        (Value::VectorF32(x), Value::VectorF32(y)) => {
            let kx: Vec<i64> = x.iter().map(|f| total_key(*f)).collect();
            let ky: Vec<i64> = y.iter().map(|f| total_key(*f)).collect();
            (x.len(), kx).cmp(&(y.len(), ky))
        }
        (Value::MinKey | Value::MaxKey | Value::Null, _) => Ordering::Equal,
        _ => ref_num_cmp(&ref_num(a), &ref_num(b)),
    }
}

/// IEEE 754 totalOrder key of an f32 as a signed integer.
fn total_key(f: f32) -> i64 {
    let b = i64::from(f.to_bits());
    if b >> 31 == 1 {
        -(b & 0x7FFF_FFFF) - 1
    } else {
        b
    }
}

/// Values biased towards numeric ties across types.
fn arb_tie_value() -> BoxedStrategy<Value> {
    let numeric = (-50i64..50, 0u32..3, 0usize..3).prop_map(|(i, scale, ty)| {
        // i / 2^scale is exact in all three types.
        let f = i as f64 / f64::from(1u32 << scale);
        match ty {
            0 if scale == 0 => Value::Int64(i),
            1 => Value::Decimal(Decimal128::parse(&format!("{f}")).unwrap()),
            _ => Value::Float64(f),
        }
    });
    prop_oneof![3 => numeric, 2 => arb_value(Counters::Excluded)].boxed()
}

fn arb_opt_value() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![1 => Just(None), 9 => arb_tie_value().prop_map(Some)]
}

proptest! {
    #![proptest_config(cfg(2048))]

    #[test]
    fn tc_doc_002_order_matches_reference_comparator(a in arb_opt_value(), b in arb_opt_value()) {
        let got = compare(a.as_ref(), b.as_ref());
        prop_assert_eq!(got, ref_cmp(a.as_ref(), b.as_ref()));
        prop_assert_eq!(compare(b.as_ref(), a.as_ref()), got.reverse());
        prop_assert_eq!(values_equal(a.as_ref(), b.as_ref()), got == Ordering::Equal);
    }
}

// ---------------------------------------------------------------- TC-DOC-003

fn arb_dir() -> impl Strategy<Value = Direction> {
    prop_oneof![Just(Direction::Ascending), Just(Direction::Descending)]
}

fn directed(o: Ordering, d: Direction) -> Ordering {
    if d == Direction::Descending {
        o.reverse()
    } else {
        o
    }
}

proptest! {
    #![proptest_config(cfg(2048))]

    /// cmp(a, b) == cmp(enc a, enc b) for single elements and composites in both directions;
    /// decoding gives a value equal (§2.1) to the original.
    #[test]
    fn tc_doc_003_key_order_preserving(
        a in proptest::collection::vec(arb_opt_value(), 1..3),
        b in proptest::collection::vec(arb_opt_value(), 1..3),
        dirs in proptest::collection::vec(arb_dir(), 3),
    ) {
        let n = a.len().min(b.len());
        let ka = encode_key(&a[..n].iter().zip(&dirs).map(|(v, d)| (v.as_ref(), *d)).collect::<Vec<_>>()).unwrap();
        let kb = encode_key(&b[..n].iter().zip(&dirs).map(|(v, d)| (v.as_ref(), *d)).collect::<Vec<_>>()).unwrap();
        let expected = a[..n].iter().zip(&b[..n]).zip(&dirs)
            .map(|((x, y), d)| directed(compare(x.as_ref(), y.as_ref()), *d))
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal);
        prop_assert_eq!(ka.cmp(&kb), expected);

        for (v, d) in a.iter().zip(&dirs) {
            let k = encode_key(&[(v.as_ref(), *d)]).unwrap();
            let (back, used) = decode_element(&k, *d).unwrap();
            prop_assert_eq!(used, k.len());
            prop_assert!(values_equal(back.as_ref(), v.as_ref()), "{:?} -> {:?}", v, back);
            prop_assert_eq!(encode_key(&[(back.as_ref(), *d)]).unwrap(), k);
        }
    }
}

#[test]
fn tc_doc_003_numeric_cross_type_equal() {
    let dec = |s: &str| Value::Decimal(Decimal128::parse(s).unwrap());
    let groups: Vec<Vec<Value>> = vec![
        vec![
            Value::Int64(1),
            Value::Float64(1.0),
            dec("1"),
            dec("1.00"),
            dec("0.1E+1"),
        ],
        vec![
            Value::Int64(0),
            Value::Float64(0.0),
            Value::Float64(-0.0),
            dec("0"),
            dec("-0E-5"),
        ],
        vec![Value::Int64(-250), Value::Float64(-250.0), dec("-2.5E+2")],
        vec![
            Value::Int64(1 << 53),
            Value::Float64(9_007_199_254_740_992.0),
            dec("9007199254740992"),
        ],
        vec![Value::Float64(0.5), dec("0.50"), dec("5E-1")],
        vec![Value::Float64(f64::NAN), dec("NaN")],
        vec![Value::Float64(f64::INFINITY), dec("Infinity")],
        vec![
            Value::Int64(i64::MIN),
            Value::Float64(-9_223_372_036_854_775_808.0),
            dec("-9223372036854775808"),
        ],
    ];
    for group in &groups {
        let keys: HashSet<Vec<u8>> = group
            .iter()
            .map(|v| encode_key(&[(Some(v), Direction::Ascending)]).unwrap())
            .collect();
        assert_eq!(keys.len(), 1, "{group:?}");
        for x in group {
            for y in group {
                assert!(values_equal(Some(x), Some(y)), "{x:?} = {y:?}");
            }
        }
    }
    // Neighbours that a lossy conversion would merge stay distinct and ordered.
    let ordered = [
        Value::Float64(f64::NAN),
        Value::Float64(f64::NEG_INFINITY),
        dec("-9.999999999999999999999999999999999E+6144"),
        Value::Float64(f64::MIN),
        Value::Int64(i64::MIN),
        Value::Int64(-1),
        dec("-1E-6176"),
        Value::Int64(0),
        dec("1E-6176"),
        Value::Float64(f64::from_bits(1)),
        Value::Float64(f64::MIN_POSITIVE),
        dec("0.1"),
        Value::Float64(0.1),
        Value::Float64(9_007_199_254_740_992.0),
        Value::Int64((1 << 53) + 1),
        Value::Int64(i64::MAX),
        Value::Float64(9_223_372_036_854_775_808.0),
        Value::Float64(f64::MAX),
        dec("9.999999999999999999999999999999999E+6144"),
        Value::Float64(f64::INFINITY),
    ];
    for w in ordered.windows(2) {
        let ka = encode_key(&[(Some(&w[0]), Direction::Ascending)]).unwrap();
        let kb = encode_key(&[(Some(&w[1]), Direction::Ascending)]).unwrap();
        assert!(ka < kb, "{:?} < {:?}", w[0], w[1]);
        assert_eq!(compare(Some(&w[0]), Some(&w[1])), Ordering::Less);
    }
}

// ---------------------------------------------------------------- TC-DOC-004

fn string_doc(len: usize) -> Document {
    let mut d = Document::new();
    d.insert("s", Value::String("x".repeat(len)));
    d
}

fn nested(depth: usize) -> Document {
    // `depth` counts the root object (depth 1).
    let mut v = Document::new();
    for _ in 1..depth {
        let mut outer = Document::new();
        outer.insert("a", Value::Object(v));
        v = outer;
    }
    v
}

fn nested_json(depth: usize) -> String {
    format!(
        "{}{}",
        r#"{"a":"#.repeat(depth - 1) + "{",
        "}".repeat(depth)
    )
}

#[test]
fn tc_doc_004_size_and_depth_limits() {
    // Find the string length whose document encodes to exactly 16 MiB.
    let overhead = encoded_len(&string_doc(MAX_DOCUMENT_SIZE / 2)).unwrap() - MAX_DOCUMENT_SIZE / 2;
    let len = MAX_DOCUMENT_SIZE - overhead;
    let exact = string_doc(len);
    assert_eq!(encoded_len(&exact).unwrap(), MAX_DOCUMENT_SIZE);
    let bytes = encode(&exact).unwrap();
    assert_eq!(bytes.len(), MAX_DOCUMENT_SIZE);
    assert_eq!(decode(&bytes).unwrap(), exact);
    let e = encode(&string_doc(len + 1)).unwrap_err();
    assert_eq!(e.code().code(), 1002);
    // A forged header claiming 16 MiB + 1.
    let mut forged = bytes.clone();
    forged.push(0);
    forged[3..7].copy_from_slice(&((MAX_DOCUMENT_SIZE + 1) as u32).to_le_bytes());
    assert_eq!(decode(&forged).unwrap_err().code().code(), 1002);
    // JSON input of 16 MiB + 1 encoded bytes is rejected at encode time.
    let json = to_json(&string_doc(len + 1), JsonMode::Canonical);
    assert_eq!(
        encode(&parse_document(&json).unwrap())
            .unwrap_err()
            .code()
            .code(),
        1002
    );

    // Depth: 100 ok, 101 rejected by every entry point.
    let ok = nested(MAX_DEPTH);
    let ok_bytes = encode(&ok).unwrap();
    assert_eq!(decode(&ok_bytes).unwrap(), ok);
    assert_eq!(parse_document(&nested_json(MAX_DEPTH)).unwrap(), ok);
    assert_eq!(
        encode(&nested(MAX_DEPTH + 1)).unwrap_err().code().code(),
        1003
    );
    assert_eq!(
        parse_document(&nested_json(MAX_DEPTH + 1))
            .unwrap_err()
            .code()
            .code(),
        1003
    );
    let mut raw = raw_object(&[]);
    for _ in 1..=MAX_DEPTH {
        raw = raw_object(&[("a", raw)]);
    }
    assert_eq!(decode(&raw_rdoc(1, &raw)).unwrap_err().code().code(), 1003);
    // Arrays count as levels too.
    let arr_json = format!(
        "{{\"a\":{}{}}}",
        "[".repeat(MAX_DEPTH),
        "]".repeat(MAX_DEPTH)
    );
    assert_eq!(parse_document(&arr_json).unwrap_err().code().code(), 1003);
    // Very deep input does not overflow the stack.
    let deep = "[".repeat(1_000_000);
    assert_eq!(
        rustegon_doc::json::parse_value(&deep)
            .unwrap_err()
            .code()
            .code(),
        1003
    );
}

#[test]
fn tc_doc_004_invalid_field_names() {
    let long = "n".repeat(1025);
    let ok_long = "n".repeat(1024);
    for json in [
        r#"{"":1}"#.to_owned(),
        r#"{"a\u0000b":1}"#.to_owned(),
        r#"{"$set":1}"#.to_owned(),
        r#"{"a":1,"$x":2}"#.to_owned(),
        r#"{"a":{"$bad":1}}"#.to_owned(),
        r#"{"a":[{"b":{"$where":1}}]}"#.to_owned(),
        format!(r#"{{"{long}":1}}"#),
    ] {
        let e = parse_document(&json).unwrap_err();
        assert_eq!(e.code().code(), 1004, "{json}");
    }
    assert!(parse_document(&format!(r#"{{"{ok_long}":1,"a.b":2,"_x":3}}"#)).is_ok());
    // The encoder enforces the same rules on in-memory documents.
    for name in ["", "$x", "a\0", long.as_str()] {
        let mut d = Document::new();
        d.insert(name, Value::Null);
        assert_eq!(encode(&d).unwrap_err().code().code(), 1004, "{name:?}");
    }
    // And the decoder on bytes.
    let root = raw_object(&[("$x", vec![0x01])]);
    assert_eq!(decode(&raw_rdoc(1, &root)).unwrap_err().code().code(), 1004);
    // Server-maintained names are rejected as user input (FR-DOC-005), `_expiresAt` is not.
    let d = parse_document(r#"{"_rev":"x"}"#).unwrap();
    assert_eq!(
        rustegon_doc::limits::validate_user_document(&d)
            .unwrap_err()
            .code()
            .code(),
        1004
    );
    let d =
        parse_document(r#"{"_id":1,"_expiresAt":{"$date":"2030-01-01T00:00:00.000Z"}}"#).unwrap();
    assert!(rustegon_doc::limits::validate_user_document(&d).is_ok());
}

// ---------------------------------------------------------------- TC-DOC-005

/// Every path of a value (fields and array indexes), up to `max` paths.
fn all_paths(prefix: &[Segment], v: &Value, out: &mut Vec<Vec<Segment>>) {
    let push = |seg: Segment, child: &Value, out: &mut Vec<Vec<Segment>>| {
        let mut p = prefix.to_vec();
        p.push(seg);
        out.push(p.clone());
        all_paths(&p, child, out);
    };
    match v {
        Value::Object(d) => {
            for (n, c) in d.iter() {
                push(
                    Segment {
                        name: n.to_owned(),
                        index: None,
                    },
                    c,
                    out,
                );
            }
        }
        Value::Array(items) => {
            for (i, c) in items.iter().enumerate() {
                push(
                    Segment {
                        name: i.to_string(),
                        index: Some(i),
                    },
                    c,
                    out,
                );
            }
        }
        _ => {}
    }
}

proptest! {
    #![proptest_config(cfg(512))]

    #[test]
    fn tc_doc_005_lazy_access_equals_full_decode(
        doc in arb_document(Counters::Allowed),
        extra in proptest::collection::vec("[a-c0-2]{1,2}", 1..4),
    ) {
        let bytes = encode(&doc).unwrap();
        let lazy = RDocRef::new(&bytes).unwrap();
        let mut paths = Vec::new();
        all_paths(&[], &Value::Object(doc.clone()), &mut paths);
        // Paths that may not exist, including index-like segments on objects.
        let mut extra_path: Vec<Segment> = Vec::new();
        for e in &extra {
            extra_path.push(FieldPath::parse(e).unwrap().segments()[0].clone());
            paths.push(extra_path.clone());
        }
        for segs in paths {
            let path = FieldPath::from_segments(segs);
            let expected = get_path(&doc, &path).cloned();
            let got = lazy.get(&path).unwrap().map(|r| r.to_value().unwrap());
            prop_assert_eq!(got, expected);
        }
    }
}

// ---------------------------------------------------------------- TC-DOC-006

proptest! {
    #![proptest_config(cfg(256))]

    #[test]
    fn tc_doc_006_canonical_bytes_deterministic(doc in arb_document(Counters::Allowed)) {
        let a = encode(&doc).unwrap();
        let b = encode(&doc.clone()).unwrap();
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(a[2], rdoc::FLAG_CANONICAL);
        prop_assert_eq!(canonicalize(&a).unwrap(), a.clone());
        // Rebuilding the same document field by field yields the same bytes.
        let mut rebuilt = Document::new();
        for (n, v) in doc.iter() {
            rebuilt.insert(n, v.clone());
        }
        prop_assert_eq!(encode(&rebuilt).unwrap(), a);
    }
}

#[test]
fn tc_doc_006_non_canonical_input_normalized() {
    // {"i": 1} with a non-minimal varint for the int (0x82 0x00 instead of 0x02).
    let root = raw_object(&[("i", vec![0x03, 0x82, 0x00])]);
    let non_canonical = raw_rdoc(0, &root);
    let mut canonical_doc = Document::new();
    canonical_doc.insert("i", Value::Int64(1));
    assert_eq!(decode(&non_canonical).unwrap(), canonical_doc);
    assert_eq!(
        canonicalize(&non_canonical).unwrap(),
        encode(&canonical_doc).unwrap()
    );
    assert!(
        decode(&raw_rdoc(1, &root)).is_err(),
        "canonical flag requires minimal varints"
    );

    // NaN with a payload: accepted and normalized only without the canonical flag.
    let mut nan = vec![0x04];
    nan.extend_from_slice(&0x7FF8_0000_0000_0001u64.to_le_bytes());
    let root = raw_object(&[("f", nan)]);
    assert!(decode(&raw_rdoc(1, &root)).is_err());
    let mut nan_doc = Document::new();
    nan_doc.insert("f", Value::Float64(f64::NAN));
    assert_eq!(
        canonicalize(&raw_rdoc(0, &root)).unwrap(),
        encode(&nan_doc).unwrap()
    );

    // Unknown flag bits and versions are rejected.
    let good = encode(&canonical_doc).unwrap();
    let mut bad = good.clone();
    bad[2] = 0x03;
    assert!(decode(&bad).is_err());
    let mut bad = good;
    bad[1] = 2;
    assert!(decode(&bad).is_err());

    // Same field set in a different insertion order is a different document (order preserved).
    let a = parse_document(r#"{"x":1,"y":2}"#).unwrap();
    let b = parse_document(r#"{"y":2,"x":1}"#).unwrap();
    assert_ne!(encode(&a).unwrap(), encode(&b).unwrap());
}

// ---------------------------------------------------------------- TC-DOC-007

/// Clock frozen at one instant: the worst case for uniqueness (all ids share the seconds).
struct FrozenClock(SystemTime);

impl Clock for FrozenClock {
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn wall(&self) -> SystemTime {
        self.0
    }
    fn sleep(&self, _: Duration) -> BoxFuture<'static, ()> {
        Box::pin(std::future::ready(()))
    }
}

struct CounterRng(std::sync::atomic::AtomicU64);

impl Rng for CounterRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        let n = self
            .0
            .fetch_add(0x9E37_79B9_7F4A_7C15, std::sync::atomic::Ordering::Relaxed);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (n >> ((i % 8) * 8)) as u8;
        }
    }
}

#[test]
fn tc_doc_007_object_ids_unique_under_concurrency() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 125_000; // 10^6 ids in total (AC-DOC-003)
    let at = UNIX_EPOCH + Duration::from_hours(490_896); // 2026-01-01T00:00:00Z
    let clock: Arc<dyn Clock> = Arc::new(FrozenClock(at));
    let rng = CounterRng(std::sync::atomic::AtomicU64::new(42));
    let generator = Arc::new(ObjectIdGenerator::new(clock.clone(), &rng));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let g = Arc::clone(&generator);
            std::thread::spawn(move || (0..PER_THREAD).map(|_| g.generate()).collect::<Vec<_>>())
        })
        .collect();
    let mut all = HashSet::with_capacity(THREADS * PER_THREAD);
    for h in handles {
        for id in h.join().unwrap() {
            assert_eq!(id.seconds(), 1_767_225_600);
            assert!(all.insert(id), "duplicate id {id}");
        }
    }
    assert_eq!(all.len(), THREADS * PER_THREAD);
    // A second generator (another process) gets a different random part.
    let other = ObjectIdGenerator::new(clock, &rng).generate();
    let first = generator.generate();
    assert_ne!(other.0[4..9], first.0[4..9]);
}
