// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared generators and raw-byte builders for the integration tests.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use proptest::{collection::vec, prelude::*};
use rustegon_doc::{
    Decimal128, Document, ObjectId, Timestamp, Value,
    decimal::{EXP_MAX, EXP_MIN, MAX_COEFFICIENT},
    rdoc::name_hash16,
};

/// Whether generated values may contain `counter` (not accepted by JSON input or key encoding).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Counters {
    Allowed,
    Excluded,
}

pub fn arb_i64() -> impl Strategy<Value = i64> {
    prop_oneof![
        any::<i64>(),
        prop::sample::select(vec![
            0,
            1,
            -1,
            1 << 53,
            (1 << 53) + 1,
            -(1 << 53) - 1,
            i64::MIN,
            i64::MAX,
            1000,
        ]),
        -1000i64..1000,
    ]
}

pub fn arb_f64() -> impl Strategy<Value = f64> {
    prop_oneof![
        any::<u64>().prop_map(f64::from_bits),
        prop::sample::select(vec![
            0.0,
            -0.0,
            1.0,
            0.1,
            -2.5,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MAX,
            f64::MIN,
            f64::MIN_POSITIVE,
            f64::from_bits(1),
            9_007_199_254_740_993.0,
            1e300,
            1e-300,
        ]),
        (-1000i32..1000).prop_map(f64::from),
        (-1_000_000i64..1_000_000).prop_map(|i| i as f64 / 1000.0),
    ]
}

pub fn arb_decimal() -> impl Strategy<Value = Decimal128> {
    prop_oneof![
        (any::<bool>(), 0..=MAX_COEFFICIENT, EXP_MIN..=EXP_MAX)
            .prop_map(|(n, c, e)| Decimal128::new(n, c, e).unwrap()),
        (any::<bool>(), 0u128..100_000, -8i32..8)
            .prop_map(|(n, c, e)| Decimal128::new(n, c, e).unwrap()),
        prop::sample::select(vec![
            "NaN",
            "Infinity",
            "-Infinity",
            "1E-6176",
            "9.999999999999999999999999999999999E+6144",
            "1.00",
            "-0",
            "0E+10",
        ])
        .prop_map(|s| Decimal128::parse(s).unwrap()),
    ]
}

pub fn arb_name() -> impl Strategy<Value = String> {
    "[a-zA-Z_é😀0-9][a-zA-Z0-9_ .é😀-]{0,6}"
}

fn arb_f32() -> impl Strategy<Value = f32> {
    prop_oneof![
        any::<u32>().prop_map(|b| {
            let x = f32::from_bits(b);
            if x.is_finite() { x } else { 0.5 }
        }),
        (-100i16..100).prop_map(f32::from),
    ]
}

pub fn arb_leaf(counters: Counters) -> BoxedStrategy<Value> {
    let base = prop_oneof![
        Just(Value::Null),
        Just(Value::MinKey),
        Just(Value::MaxKey),
        any::<bool>().prop_map(Value::Bool),
        arb_i64().prop_map(Value::Int64),
        arb_f64().prop_map(Value::Float64),
        arb_decimal().prop_map(Value::Decimal),
        any::<String>().prop_map(Value::String),
        "[a-c\\x00]{0,4}".prop_map(Value::String),
        (
            prop_oneof![Just(0u8), 0x80u8..=0xFF],
            vec(any::<u8>(), 0..12)
        )
            .prop_map(|(subtype, data)| Value::Binary { subtype, data }),
        any::<[u8; 16]>().prop_map(|d| Value::Binary {
            subtype: 4,
            data: d.to_vec()
        }),
        any::<i64>().prop_map(Value::DateTime),
        (any::<u64>(), any::<u32>())
            .prop_map(|(wall, logical)| Value::Timestamp(Timestamp { wall, logical })),
        any::<[u8; 12]>().prop_map(|b| Value::ObjectId(ObjectId(b))),
        any::<[u8; 16]>().prop_map(Value::Uuid),
        vec(arb_f32(), 0..5).prop_map(Value::VectorF32),
    ];
    if counters == Counters::Allowed {
        prop_oneof![9 => base, 1 => any::<i64>().prop_map(Value::Counter)].boxed()
    } else {
        base.boxed()
    }
}

/// Builds a document keeping the first occurrence of each name.
pub fn unique_doc(fields: Vec<(String, Value)>) -> Document {
    let mut seen = std::collections::HashSet::new();
    let fields = fields
        .into_iter()
        .filter(|(n, _)| seen.insert(n.clone()))
        .collect();
    Document::try_from_fields(fields).unwrap()
}

pub fn arb_value(counters: Counters) -> BoxedStrategy<Value> {
    arb_leaf(counters)
        .prop_recursive(4, 48, 6, |inner| {
            prop_oneof![
                vec(inner.clone(), 0..6).prop_map(Value::Array),
                vec((arb_name(), inner), 0..6).prop_map(|f| Value::Object(unique_doc(f))),
            ]
        })
        .boxed()
}

pub fn arb_document(counters: Counters) -> impl Strategy<Value = Document> {
    vec((arb_name(), arb_value(counters)), 0..8).prop_map(unique_doc)
}

/// Raw `RDoc` writer for hand-crafted (possibly invalid) documents.
pub fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Raw object bytes (tag included) from `(name, encoded value)` pairs; index sorted by
/// (hash, name), duplicates allowed.
pub fn raw_object(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut index: Vec<(u16, &str, u32)> = Vec::new();
    for (name, value) in fields {
        index.push((name_hash16(name.as_bytes()), name, body.len() as u32));
        varint(name.len() as u64, &mut body);
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(value);
    }
    index.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let mut out = vec![0x0D];
    varint(fields.len() as u64, &mut out);
    varint(body.len() as u64, &mut out);
    for (h, _, off) in index {
        out.extend_from_slice(&h.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
    }
    out.extend_from_slice(&body);
    out
}

/// Wraps a root object into an `RDoc` with the given flags.
pub fn raw_rdoc(flags: u8, root: &[u8]) -> Vec<u8> {
    let total = (7 + root.len()) as u32;
    let mut out = vec![0xD7, 0x01, flags];
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(root);
    out
}
