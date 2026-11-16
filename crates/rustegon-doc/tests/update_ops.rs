// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Update-operator acceptance tests TC-DOC-009…012 (FR-DOC-006, AC-DOC-005).
//!
//! Mapping (the specification names the TC range without splitting it; recorded here and in the
//! traceability report):
//! - TC-DOC-009 field operators: `SET`, `UNSET`, `RENAME`, `CURRENT DATE`, `_id` immutability,
//!   server-maintained fields, field names, conflicting paths, atomicity;
//! - TC-DOC-010 numeric and comparison operators: `INC`, `MUL`, `MIN`, `MAX`;
//! - TC-DOC-011 array insertion/removal: `PUSH` (each, position, sort, slice), `POP`,
//!   `ADD TO SET`;
//! - TC-DOC-012 `PULL … WHERE`, `pullAll` and array filters (positional segments), mixed with
//!   every other operator.
//!
//! Each TC has hand-checked examples plus a differential property test against the independent
//! reference interpreter in `update_ref`. AC-DOC-005 asks for 10^5 generated cases in total: the
//! four property tests run `UPDATE_CASES` cases each (default 25 000, i.e. 10^5 together).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod update_ref;

use proptest::{collection::vec, prelude::*, sample::select};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Decimal128, Document, Value,
    compare::{compare_values, values_equal},
    json::{JsonMode, parse_document, to_json},
    keyenc::Direction,
    path::{FieldPath, Segment},
    rdoc,
    update::{
        ElementPredicate, PopEnd, Push, PushSort, UpdateContext, UpdateOp, UpdatePath,
        UpdateSegment, apply_updates,
    },
};
use update_ref::ref_apply;

const NOW: i64 = 1_700_000_000_000;
const CTX: UpdateContext = UpdateContext { now_ms: NOW };

// ---------------------------------------------------------------- helpers

fn doc(json: &str) -> Document {
    parse_document(json).unwrap()
}

fn p(path: &str) -> UpdatePath {
    UpdatePath::parse(path).unwrap()
}

fn json(d: &Document) -> String {
    to_json(d, JsonMode::Canonical)
}

fn dec(s: &str) -> Value {
    Value::Decimal(Decimal128::parse(s).unwrap())
}

fn s(x: &str) -> Value {
    Value::String(x.into())
}

/// Applies `ops` and returns canonical JSON of the result.
fn ok(d: &str, ops: &[UpdateOp]) -> String {
    json(&apply_updates(&doc(d), ops, &CTX).unwrap())
}

/// Applies `ops`, expects an error and checks the input is unchanged; returns the code.
fn err(d: &str, ops: &[UpdateOp]) -> ErrorCode {
    let input = doc(d);
    let before = input.clone();
    let e = apply_updates(&input, ops, &CTX).unwrap_err();
    assert_eq!(input, before);
    e.code()
}

fn set(path: &str, value: Value) -> UpdateOp {
    UpdateOp::Set {
        path: p(path),
        value,
    }
}

fn push(path: &str, values: Vec<Value>) -> Push {
    Push {
        path: p(path),
        values,
        position: None,
        sort: None,
        slice: None,
    }
}

/// Element predicates used by the examples and the generators (stand-ins for `WHERE` exprs).
fn pred(kind: u8) -> ElementPredicate {
    match kind {
        0 => ElementPredicate::new(|v| {
            Ok(matches!(
                v,
                Value::Int64(_) | Value::Float64(_) | Value::Decimal(_)
            ))
        }),
        1 => ElementPredicate::new(|v| {
            Ok(
                matches!(v, Value::Int64(_) | Value::Float64(_) | Value::Decimal(_))
                    && compare_values(v, &Value::Int64(0)).is_gt(),
            )
        }),
        2 => ElementPredicate::new(|v| Ok(matches!(v, Value::String(_)))),
        3 => ElementPredicate::new(|v| {
            Ok(matches!(v, Value::Object(d)
                if values_equal(d.get("a"), Some(&Value::Int64(1)))))
        }),
        _ => ElementPredicate::new(|_| Err(Error::new(ErrorCode::UnknownFunction, "boom"))),
    }
}

// ---------------------------------------------------------------- TC-DOC-009

#[test]
fn tc_doc_009_set_creates_and_replaces_in_place() {
    let out = ok(
        r#"{"a":1,"b":{"c":2}}"#,
        &[set("b.d", Value::Int64(3)), set("a", Value::Int64(5))],
    );
    assert_eq!(out, r#"{"a":5,"b":{"c":2,"d":3}}"#);
    assert_eq!(
        ok("{}", &[set("x.y.z", s("v"))]),
        r#"{"x":{"y":{"z":"v"}}}"#
    );
    assert_eq!(
        ok(r#"{"a":[1,2]}"#, &[set("a.1", Value::Null)]),
        r#"{"a":[1,null]}"#
    );
    // Index past the end: RGN-1001 (no null padding); field in an array or scalar: RGN-1011.
    assert_eq!(
        err(r#"{"a":[1]}"#, &[set("a.1", Value::Null)]),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        err(r#"{"a":[1]}"#, &[set("a.x", Value::Null)]),
        ErrorCode::QueryTypeError
    );
    assert_eq!(
        err(r#"{"a":1}"#, &[set("a.x", Value::Null)]),
        ErrorCode::QueryTypeError
    );
    // A numeric segment on an object (or a missing intermediate) is a field name.
    assert_eq!(ok("{}", &[set("a.0", Value::Int64(1))]), r#"{"a":{"0":1}}"#);
}

#[test]
fn tc_doc_009_unset_rename_current_date() {
    let unset = |path: &str| UpdateOp::Unset { path: p(path) };
    assert_eq!(ok(r#"{"a":1,"b":2}"#, &[unset("a")]), r#"{"b":2}"#);
    assert_eq!(
        ok(r#"{"a":[1,2,3]}"#, &[unset("a.1")]),
        r#"{"a":[1,null,3]}"#
    );
    assert_eq!(
        ok(r#"{"a":1}"#, &[unset("z.y"), unset("a.q")]),
        r#"{"a":1}"#
    );

    let rename = |f: &str, t: &str| UpdateOp::Rename {
        from: p(f),
        to: p(t),
    };
    assert_eq!(
        ok(r#"{"a":1,"b":2}"#, &[rename("a", "c")]),
        r#"{"b":2,"c":1}"#
    );
    assert_eq!(ok(r#"{"a":1,"b":2}"#, &[rename("b", "a")]), r#"{"a":2}"#);
    assert_eq!(
        ok(r#"{"a":{"x":1}}"#, &[rename("a.x", "b.y")]),
        r#"{"a":{},"b":{"y":1}}"#
    );
    assert_eq!(ok(r#"{"a":1}"#, &[rename("q", "r")]), r#"{"a":1}"#);
    assert_eq!(
        err(r#"{"a":[{"x":1}]}"#, &[rename("a.0.x", "b")]),
        ErrorCode::QueryTypeError
    );
    assert_eq!(
        err(r#"{"a":1,"b":5}"#, &[rename("a", "b.c")]),
        ErrorCode::QueryTypeError
    );
    let positional = UpdateOp::Rename {
        from: UpdatePath::new(vec![
            UpdateSegment::Field(Segment {
                name: "a".into(),
                index: None,
            }),
            UpdateSegment::AllElements,
        ]),
        to: p("b"),
    };
    assert_eq!(
        err(r#"{"a":[1]}"#, &[positional]),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        err(r#"{"a":1}"#, &[rename("a", "a.b")]),
        ErrorCode::InvalidArgument
    );

    let d = apply_updates(&doc("{}"), &[UpdateOp::CurrentDate { path: p("t") }], &CTX).unwrap();
    assert_eq!(d.get("t"), Some(&Value::DateTime(NOW)));
}

#[test]
fn tc_doc_009_id_and_system_fields() {
    // AC-DOC-003: changing `_id` fails with RGN-1001; an equal value is a no-op.
    let base = r#"{"_id":1,"a":1}"#;
    assert_eq!(
        err(base, &[set("_id", Value::Int64(2))]),
        ErrorCode::InvalidArgument
    );
    assert_eq!(ok(base, &[set("_id", Value::Float64(1.0))]), base);
    for op in [
        UpdateOp::Unset { path: p("_id") },
        UpdateOp::Inc {
            path: p("_id"),
            by: Value::Int64(0),
        },
        UpdateOp::Rename {
            from: p("_id"),
            to: p("b"),
        },
        UpdateOp::Rename {
            from: p("a"),
            to: p("_id"),
        },
        set("_id.x", Value::Int64(1)),
    ] {
        assert_eq!(err(base, &[op]), ErrorCode::InvalidArgument);
    }
    // AC-DOC-004 / FR-DOC-005: server-maintained fields are not writable; `_expiresAt` is.
    for name in ["_rev", "_createdAt", "_updatedAt", "_conflict", "_origin"] {
        assert_eq!(
            err(base, &[set(name, Value::Null)]),
            ErrorCode::InvalidFieldName
        );
    }
    assert_eq!(
        ok(base, &[set("_expiresAt", Value::DateTime(5))]),
        r#"{"_id":1,"a":1,"_expiresAt":{"$date":"1970-01-01T00:00:00.005Z"}}"#
    );
    // Field names and stored values follow data-model.md §2.2 (RGN-1004).
    assert_eq!(
        err(base, &[set("a.$x", Value::Null)]),
        ErrorCode::InvalidFieldName
    );
    let bad = Value::Object(doc(r#"{"ok":1}"#));
    let mut fields = match bad {
        Value::Object(d) => d.into_fields(),
        _ => unreachable!(),
    };
    fields.push(("$x".into(), Value::Null));
    let bad = Value::Object(Document::try_from_fields(fields).unwrap());
    assert_eq!(err(base, &[set("a", bad)]), ErrorCode::InvalidFieldName);
    assert_eq!(
        err(base, &[set("a", Value::Counter(1))]),
        ErrorCode::InvalidFieldName
    );
}

#[test]
fn tc_doc_009_conflicts_and_atomicity() {
    let d = r#"{"a":{"b":1},"s":"x"}"#;
    assert_eq!(
        err(d, &[set("a", Value::Null), set("a.b", Value::Null)]),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        ok(
            d,
            &[set("a.b", Value::Int64(2)), set("a.c", Value::Int64(3))]
        ),
        r#"{"a":{"b":2,"c":3},"s":"x"}"#
    );
    let all = UpdatePath::new(vec![
        UpdateSegment::Field(Segment {
            name: "a".into(),
            index: None,
        }),
        UpdateSegment::AllElements,
    ]);
    assert_eq!(
        err(d, &[UpdateOp::Unset { path: all }, set("a.0", Value::Null)]),
        ErrorCode::InvalidArgument
    );
    // All or nothing: the first operator succeeds on the copy, the second fails, the input is
    // unchanged (checked by `err`).
    assert_eq!(
        err(
            d,
            &[
                set("a.b", Value::Int64(9)),
                UpdateOp::Inc {
                    path: p("s"),
                    by: Value::Int64(1)
                }
            ]
        ),
        ErrorCode::QueryTypeError
    );
}

// ---------------------------------------------------------------- TC-DOC-010

fn inc(path: &str, by: Value) -> UpdateOp {
    UpdateOp::Inc { path: p(path), by }
}

fn mul(path: &str, by: Value) -> UpdateOp {
    UpdateOp::Mul { path: p(path), by }
}

#[test]
fn tc_doc_010_inc_and_mul_numeric_rules() {
    assert_eq!(ok(r#"{"n":1}"#, &[inc("n", Value::Int64(2))]), r#"{"n":3}"#);
    assert_eq!(ok("{}", &[inc("n", Value::Int64(-2))]), r#"{"n":-2}"#);
    assert_eq!(
        ok(r#"{"n":1}"#, &[inc("n", Value::Float64(0.5))]),
        r#"{"n":1.5}"#
    );
    assert_eq!(
        ok(r#"{"n":{"$decimal":"1.10"}}"#, &[inc("n", Value::Int64(1))]),
        r#"{"n":{"$decimal":"2.10"}}"#
    );
    assert_eq!(
        ok(
            r#"{"n":{"$decimal":"1"}}"#,
            &[inc("n", Value::Float64(0.1))]
        ),
        r#"{"n":{"$decimal":"1.1"}}"#
    );
    // int64 overflow is an error, not a silent promotion.
    assert_eq!(
        err(r#"{"n":9223372036854775807}"#, &[inc("n", Value::Int64(1))]),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        err(
            r#"{"n":4294967296}"#,
            &[mul("n", Value::Int64(4_294_967_296))]
        ),
        ErrorCode::InvalidArgument
    );
    // Type errors (RGN-1011): non-numeric target or operand.
    assert_eq!(
        err(r#"{"n":"x"}"#, &[inc("n", Value::Int64(1))]),
        ErrorCode::QueryTypeError
    );
    assert_eq!(
        err(r#"{"n":null}"#, &[inc("n", Value::Int64(1))]),
        ErrorCode::QueryTypeError
    );
    assert_eq!(
        err(r#"{"n":1}"#, &[inc("n", s("1"))]),
        ErrorCode::QueryTypeError
    );
    // MUL on a missing field stores zero of the factor's type.
    assert_eq!(ok("{}", &[mul("n", Value::Int64(7))]), r#"{"n":0}"#);
    assert_eq!(ok("{}", &[mul("n", Value::Float64(7.0))]), r#"{"n":0.0}"#);
    assert_eq!(
        ok("{}", &[mul("n", dec("7.5"))]),
        r#"{"n":{"$decimal":"0"}}"#
    );
    assert_eq!(
        ok(r#"{"n":{"$decimal":"1.5"}}"#, &[mul("n", Value::Int64(-2))]),
        r#"{"n":{"$decimal":"-3.0"}}"#
    );
    // Decimal results round half-even to 34 digits.
    assert_eq!(
        ok(
            r#"{"n":{"$decimal":"9999999999999999999999999999999999"}}"#,
            &[inc("n", Value::Int64(1))]
        ),
        r#"{"n":{"$decimal":"1.000000000000000000000000000000000E+34"}}"#
    );
    // Floats follow IEEE 754.
    assert_eq!(
        ok(r#"{"n":1e308}"#, &[mul("n", Value::Float64(10.0))]),
        r#"{"n":{"$float":"Infinity"}}"#
    );
}

#[test]
fn tc_doc_010_min_max_total_order() {
    let min = |v: Value| UpdateOp::Min {
        path: p("n"),
        value: v,
    };
    let max = |v: Value| UpdateOp::Max {
        path: p("n"),
        value: v,
    };
    assert_eq!(
        ok(r#"{"n":5}"#, &[min(Value::Float64(2.5))]),
        r#"{"n":2.5}"#
    );
    assert_eq!(ok(r#"{"n":5}"#, &[max(Value::Float64(2.5))]), r#"{"n":5}"#);
    // Equal values keep the stored representation.
    assert_eq!(ok(r#"{"n":1}"#, &[max(Value::Float64(1.0))]), r#"{"n":1}"#);
    // Cross-type: numbers sort before strings (§2.1).
    assert_eq!(ok(r#"{"n":1}"#, &[min(s("a"))]), r#"{"n":1}"#);
    assert_eq!(ok(r#"{"n":1}"#, &[max(s("a"))]), r#"{"n":"a"}"#);
    assert_eq!(ok("{}", &[min(Value::Int64(3))]), r#"{"n":3}"#);
    assert_eq!(
        ok(r#"{"n":null}"#, &[min(Value::Int64(3))]),
        r#"{"n":null}"#
    );
}

// ---------------------------------------------------------------- TC-DOC-011

#[test]
fn tc_doc_011_push_modifiers() {
    let one = |v: i64| Value::Int64(v);
    assert_eq!(
        ok(r#"{"a":[1]}"#, &[UpdateOp::Push(push("a", vec![one(2)]))]),
        r#"{"a":[1,2]}"#
    );
    assert_eq!(
        ok("{}", &[UpdateOp::Push(push("a", vec![one(2)]))]),
        r#"{"a":[2]}"#
    );
    assert_eq!(
        err(r#"{"a":1}"#, &[UpdateOp::Push(push("a", vec![one(2)]))]),
        ErrorCode::QueryTypeError
    );
    let at = |pos: i64| {
        UpdateOp::Push(Push {
            position: Some(pos),
            ..push("a", vec![one(8), one(9)])
        })
    };
    assert_eq!(ok(r#"{"a":[1,2,3]}"#, &[at(0)]), r#"{"a":[8,9,1,2,3]}"#);
    assert_eq!(ok(r#"{"a":[1,2,3]}"#, &[at(-1)]), r#"{"a":[1,2,8,9,3]}"#);
    assert_eq!(ok(r#"{"a":[1,2,3]}"#, &[at(99)]), r#"{"a":[1,2,3,8,9]}"#);
    assert_eq!(ok(r#"{"a":[1,2,3]}"#, &[at(-99)]), r#"{"a":[8,9,1,2,3]}"#);
    // Sort then slice (query-language.md example: `PUSH items VALUE $item SLICE -100`).
    let sorted = UpdateOp::Push(Push {
        sort: Some(PushSort::Elements(Direction::Descending)),
        slice: Some(3),
        ..push("a", vec![one(5), one(0)])
    });
    assert_eq!(ok(r#"{"a":[3,1,4]}"#, &[sorted]), r#"{"a":[5,4,3]}"#);
    let last_two = UpdateOp::Push(Push {
        slice: Some(-2),
        ..push("a", vec![one(5)])
    });
    assert_eq!(ok(r#"{"a":[3,1,4]}"#, &[last_two]), r#"{"a":[4,5]}"#);
    let empty = UpdateOp::Push(Push {
        slice: Some(0),
        ..push("a", vec![one(5)])
    });
    assert_eq!(ok(r#"{"a":[3]}"#, &[empty]), r#"{"a":[]}"#);
    // Sort by field: stable, non-objects and missing fields sort as `missing` (first).
    let by_field = UpdateOp::Push(Push {
        sort: Some(PushSort::Fields(vec![(
            FieldPath::parse("k").unwrap(),
            Direction::Ascending,
        )])),
        ..push("a", vec![])
    });
    assert_eq!(
        ok(
            r#"{"a":[{"k":2,"i":1},7,{"k":1},{"k":2,"i":2},{}]}"#,
            &[by_field]
        ),
        r#"{"a":[7,{},{"k":1},{"k":2,"i":1},{"k":2,"i":2}]}"#
    );
}

#[test]
fn tc_doc_011_pop_and_add_to_set() {
    let pop = |end| UpdateOp::Pop { path: p("a"), end };
    assert_eq!(
        ok(r#"{"a":[1,2,3]}"#, &[pop(PopEnd::First)]),
        r#"{"a":[2,3]}"#
    );
    assert_eq!(
        ok(r#"{"a":[1,2,3]}"#, &[pop(PopEnd::Last)]),
        r#"{"a":[1,2]}"#
    );
    assert_eq!(ok(r#"{"a":[]}"#, &[pop(PopEnd::Last)]), r#"{"a":[]}"#);
    assert_eq!(ok("{}", &[pop(PopEnd::Last)]), "{}");
    assert_eq!(
        err(r#"{"a":"x"}"#, &[pop(PopEnd::First)]),
        ErrorCode::QueryTypeError
    );

    let add = |values| UpdateOp::AddToSet {
        path: p("a"),
        values,
    };
    // §2.1 equality: 1.0 is already present as 1; duplicates among the new values collapse.
    assert_eq!(
        ok(
            r#"{"a":[1,"x"]}"#,
            &[add(vec![Value::Float64(1.0), s("y"), s("y")])]
        ),
        r#"{"a":[1,"x","y"]}"#
    );
    assert_eq!(ok("{}", &[add(vec![s("y")])]), r#"{"a":["y"]}"#);
    assert_eq!(
        err(r#"{"a":{}}"#, &[add(vec![s("y")])]),
        ErrorCode::QueryTypeError
    );
}

// ---------------------------------------------------------------- TC-DOC-012

fn field(name: &str) -> UpdateSegment {
    UpdateSegment::Field(Segment {
        name: name.into(),
        index: None,
    })
}

#[test]
fn tc_doc_012_pull_and_pull_all() {
    let pull = |kind| UpdateOp::Pull {
        path: p("a"),
        predicate: pred(kind),
    };
    assert_eq!(ok(r#"{"a":[1,-2,"x",3]}"#, &[pull(1)]), r#"{"a":[-2,"x"]}"#);
    assert_eq!(
        ok(r#"{"a":[{"a":1},{"a":2}]}"#, &[pull(3)]),
        r#"{"a":[{"a":2}]}"#
    );
    assert_eq!(ok("{}", &[pull(1)]), "{}");
    assert_eq!(err(r#"{"a":5}"#, &[pull(1)]), ErrorCode::QueryTypeError);
    // A failing predicate aborts the update with its own error.
    assert_eq!(err(r#"{"a":[1]}"#, &[pull(9)]), ErrorCode::UnknownFunction);

    let pull_all = UpdateOp::PullAll {
        path: p("a"),
        values: vec![Value::Float64(1.0), s("x")],
    };
    assert_eq!(ok(r#"{"a":[1,2,"x",1]}"#, &[pull_all]), r#"{"a":[2]}"#);
}

#[test]
fn tc_doc_012_array_filters() {
    let all = UpdatePath::new(vec![field("a"), UpdateSegment::AllElements]);
    let positive = UpdatePath::new(vec![field("a"), UpdateSegment::Filtered(pred(1))]);
    assert_eq!(
        ok(
            r#"{"a":[1,2]}"#,
            &[UpdateOp::Inc {
                path: all.clone(),
                by: Value::Int64(10)
            }]
        ),
        r#"{"a":[11,12]}"#
    );
    assert_eq!(
        ok(
            r#"{"a":[1,-2,3]}"#,
            &[UpdateOp::Set {
                path: positive,
                value: Value::Int64(0)
            }]
        ),
        r#"{"a":[0,-2,0]}"#
    );
    // Nested: every element's field, created when missing.
    let nested = UpdatePath::new(vec![field("a"), UpdateSegment::AllElements, field("b")]);
    assert_eq!(
        ok(
            r#"{"a":[{"b":1},{}]}"#,
            &[UpdateOp::Set {
                path: nested.clone(),
                value: s("v")
            }]
        ),
        r#"{"a":[{"b":"v"},{"b":"v"}]}"#
    );
    assert_eq!(
        err(
            r#"{"a":[{"b":1},5]}"#,
            &[UpdateOp::Set {
                path: nested,
                value: s("v")
            }]
        ),
        ErrorCode::QueryTypeError
    );
    // Removing through a positional segment nulls the elements; positional needs an array.
    assert_eq!(
        ok(r#"{"a":[1,2]}"#, &[UpdateOp::Unset { path: all.clone() }]),
        r#"{"a":[null,null]}"#
    );
    assert_eq!(ok("{}", &[UpdateOp::Unset { path: all.clone() }]), "{}");
    assert_eq!(
        err(r#"{"a":{"x":1}}"#, &[UpdateOp::Unset { path: all.clone() }]),
        ErrorCode::QueryTypeError
    );
    assert_eq!(
        err(
            "{}",
            &[UpdateOp::Set {
                path: all,
                value: Value::Null
            }]
        ),
        ErrorCode::QueryTypeError
    );
    // Array operators per matched element.
    let inner = UpdatePath::new(vec![
        field("a"),
        UpdateSegment::Filtered(pred(3)),
        field("t"),
    ]);
    assert_eq!(
        ok(
            r#"{"a":[{"a":1,"t":[1]},{"a":2,"t":[1]}]}"#,
            &[UpdateOp::Push(Push {
                path: inner,
                ..push("x", vec![Value::Int64(2)])
            })]
        ),
        r#"{"a":[{"a":1,"t":[1,2]},{"a":2,"t":[1]}]}"#
    );
}

// ---------------------------------------------------------------- generators

const PREDICATES: u8 = 5;

/// Numbers whose exact decimal sums and products stay within 34 digits (the reference
/// interpreter computes decimals exactly in `i128`).
fn arb_number() -> impl Strategy<Value = Value> {
    prop_oneof![
        prop_oneof![
            4 => -3i64..3,
            1 => select(vec![i64::MAX, i64::MIN, i64::MAX - 1, 1 << 40])
        ]
        .prop_map(Value::Int64),
        select(vec![
            0.0,
            -0.0,
            0.5,
            1.5,
            -2.25,
            3.0,
            1e10,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY
        ])
        .prop_map(Value::Float64),
        prop_oneof![
            8 => (any::<bool>(), 0u128..1_000_000, -3i32..=3)
                .prop_map(|(n, c, e)| Decimal128::new(n, c, e).unwrap()),
            1 => select(vec![
                Decimal128::NaN,
                Decimal128::Infinity { negative: false },
                Decimal128::Infinity { negative: true }
            ]),
        ]
        .prop_map(Value::Decimal),
    ]
}

fn arb_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        1 => Just(Value::Null),
        1 => any::<bool>().prop_map(Value::Bool),
        3 => arb_number(),
        1 => select(vec!["x", "y", ""]).prop_map(|t| Value::String(t.into())),
        1 => (-5i64..5).prop_map(Value::DateTime),
    ]
}

fn object_of(fields: Vec<(String, Value)>) -> Document {
    let mut d = Document::new();
    for (n, v) in fields {
        if d.get(&n).is_none() {
            d.insert(n, v);
        }
    }
    d
}

fn arb_value() -> impl Strategy<Value = Value> {
    arb_leaf().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..4).prop_map(Value::Array),
            vec(
                (select(vec!["a", "b", "c"]).prop_map(String::from), inner),
                0..3
            )
            .prop_map(|f| Value::Object(object_of(f))),
        ]
    })
}

/// Operand values: mostly storable, sometimes not (RGN-1004 paths).
fn arb_operand() -> impl Strategy<Value = Value> {
    prop_oneof![
        60 => arb_value(),
        1 => Just(Value::Counter(1)),
        1 => Just(Value::Object(
            Document::try_from_fields(vec![("$x".into(), Value::Null)]).unwrap()
        )),
    ]
}

/// `MIN`/`MAX` candidates: often a small number that equals a stored value in another type
/// (`1` vs `1.0` vs `1.0` decimal), where keeping the stored representation matters.
fn arb_compare_operand() -> impl Strategy<Value = Value> {
    prop_oneof![
        2 => select(vec![
            Value::Int64(0),
            Value::Int64(1),
            Value::Int64(-1),
            Value::Float64(0.0),
            Value::Float64(-0.0),
            Value::Float64(1.0),
            Value::Decimal(Decimal128::new(false, 10, -1).unwrap()),
            Value::Decimal(Decimal128::new(true, 0, 2).unwrap()),
        ]),
        3 => arb_operand(),
    ]
}

fn arb_number_operand() -> impl Strategy<Value = Value> {
    prop_oneof![
        12 => arb_number(),
        1 => arb_leaf(),
    ]
}

fn arb_document() -> impl Strategy<Value = Document> {
    vec(
        (
            select(vec!["a", "b", "c", "_id", "_expiresAt"]).prop_map(String::from),
            prop_oneof![
                2 => arb_value(),
                1 => arb_leaf(),
                1 => vec(arb_leaf(), 0..4).prop_map(Value::Array),
                1 => vec(arb_value(), 0..4).prop_map(Value::Array),
            ],
        ),
        0..5,
    )
    .prop_map(object_of)
}

fn arb_field_segment() -> impl Strategy<Value = UpdateSegment> {
    prop_oneof![
        40 => select(vec!["a", "b", "c"]).prop_map(field),
        3 => select(vec!["_id", "_rev", "_expiresAt"]).prop_map(field),
        1 => Just(field("$x")),
        15 => (0usize..3).prop_map(|i| UpdateSegment::Field(Segment {
            name: i.to_string(),
            index: Some(i),
        })),
    ]
}

/// A path; with `positional`, segments after the first may be `$[]` or filtered.
fn arb_path(positional: bool) -> impl Strategy<Value = UpdatePath> {
    let later = if positional {
        prop_oneof![
            3 => arb_field_segment(),
            1 => Just(UpdateSegment::AllElements),
            1 => (0..PREDICATES).prop_map(|k| UpdateSegment::Filtered(pred(k % (PREDICATES - 1)))),
        ]
        .boxed()
    } else {
        arb_field_segment().boxed()
    };
    (arb_field_segment(), vec(later, 0..3)).prop_map(|(first, rest)| {
        let mut segs = vec![first];
        segs.extend(rest);
        UpdatePath::new(segs)
    })
}

fn arb_direction() -> impl Strategy<Value = Direction> {
    prop_oneof![Just(Direction::Ascending), Just(Direction::Descending)]
}

fn arb_field_ops(positional: bool) -> BoxedStrategy<UpdateOp> {
    prop_oneof![
        3 => (arb_path(positional), arb_operand()).prop_map(|(path, value)| UpdateOp::Set { path, value }),
        2 => arb_path(positional).prop_map(|path| UpdateOp::Unset { path }),
        2 => (arb_path(positional), arb_path(false)).prop_map(|(from, to)| UpdateOp::Rename { from, to }),
        1 => arb_path(positional).prop_map(|path| UpdateOp::CurrentDate { path }),
    ]
    .boxed()
}

fn arb_numeric_ops(positional: bool) -> BoxedStrategy<UpdateOp> {
    prop_oneof![
        (arb_path(positional), arb_number_operand())
            .prop_map(|(path, by)| UpdateOp::Inc { path, by }),
        (arb_path(positional), arb_number_operand())
            .prop_map(|(path, by)| UpdateOp::Mul { path, by }),
        (arb_path(positional), arb_compare_operand())
            .prop_map(|(path, value)| UpdateOp::Min { path, value }),
        (arb_path(positional), arb_compare_operand())
            .prop_map(|(path, value)| UpdateOp::Max { path, value }),
    ]
    .boxed()
}

fn arb_push_sort() -> impl Strategy<Value = PushSort> {
    prop_oneof![
        arb_direction().prop_map(PushSort::Elements),
        vec((select(vec!["a", "b", "0"]), arb_direction()), 1..3).prop_map(|keys| {
            PushSort::Fields(
                keys.into_iter()
                    .map(|(k, d)| (FieldPath::parse(k).unwrap(), d))
                    .collect(),
            )
        }),
    ]
}

fn arb_array_ops(positional: bool) -> BoxedStrategy<UpdateOp> {
    prop_oneof![
        3 => (
            arb_path(positional),
            vec(arb_operand(), 0..3),
            proptest::option::of(-4i64..5),
            proptest::option::of(arb_push_sort()),
            proptest::option::of(-4i64..5),
        )
            .prop_map(|(path, values, position, sort, slice)| UpdateOp::Push(Push {
                path,
                values,
                position,
                sort,
                slice
            })),
        1 => (arb_path(positional), prop_oneof![Just(PopEnd::First), Just(PopEnd::Last)])
            .prop_map(|(path, end)| UpdateOp::Pop { path, end }),
        2 => (arb_path(positional), vec(arb_operand(), 0..3))
            .prop_map(|(path, values)| UpdateOp::AddToSet { path, values }),
    ]
    .boxed()
}

fn arb_filter_ops() -> BoxedStrategy<UpdateOp> {
    prop_oneof![
        3 => (arb_path(true), prop_oneof![9 => 0..PREDICATES - 1, 1 => Just(PREDICATES - 1)])
            .prop_map(|(path, k)| UpdateOp::Pull { path, predicate: pred(k) }),
        2 => (arb_path(true), vec(arb_value(), 0..3))
            .prop_map(|(path, values)| UpdateOp::PullAll { path, values }),
        1 => arb_field_ops(true),
        1 => arb_numeric_ops(true),
        1 => arb_array_ops(true),
    ]
    .boxed()
}

/// Cases per differential test; 4 tests × 25 000 = 10^5 (AC-DOC-005).
fn cases() -> u32 {
    std::env::var("UPDATE_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(25_000)
}

fn cfg() -> ProptestConfig {
    ProptestConfig {
        cases: cases(),
        ..ProptestConfig::default()
    }
}

/// Engine and reference agree on the result or on the error code; successful results encode.
fn check(d: &Document, ops: &[UpdateOp]) -> Result<(), TestCaseError> {
    let got = apply_updates(d, ops, &CTX).map_err(|e| e.code());
    let want = ref_apply(d, ops, NOW);
    prop_assert_eq!(&got, &want, "ops: {:?}", ops);
    if let Ok(out) = got {
        prop_assert!(rdoc::encode(&out).is_ok());
    }
    Ok(())
}

proptest! {
    #![proptest_config(cfg())]

    /// AC-DOC-005, field operators.
    #[test]
    fn tc_doc_009_field_ops_match_reference(
        d in arb_document(),
        ops in vec(arb_field_ops(false), 1..=3),
    ) {
        check(&d, &ops)?;
    }

    /// AC-DOC-005, numeric and comparison operators.
    #[test]
    fn tc_doc_010_numeric_ops_match_reference(
        d in arb_document(),
        ops in vec(arb_numeric_ops(false), 1..=3),
    ) {
        check(&d, &ops)?;
    }

    /// AC-DOC-005, array insertion and removal operators.
    #[test]
    fn tc_doc_011_array_ops_match_reference(
        d in arb_document(),
        ops in vec(arb_array_ops(false), 1..=3),
    ) {
        check(&d, &ops)?;
    }

    /// AC-DOC-005, PULL / pullAll and array filters mixed with every operator.
    #[test]
    fn tc_doc_012_filters_and_pull_match_reference(
        d in arb_document(),
        ops in vec(arb_filter_ops(), 1..=3),
    ) {
        check(&d, &ops)?;
    }
}
