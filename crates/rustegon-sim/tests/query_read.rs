// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Read operators of the query engine through the embedded API (M3 lane F; FR-QL-001/003/008):
//! `Filter`, `Project`, `Sort`, `TopK`, `Limit`/`Offset` over every source, predicate semantics
//! (three-valued logic, multikey, fan-out), scalar functions, batching, memory limit and the
//! deadline / cancellation hook. TC-QL-009 (operator semantics), TC-QL-008 (hook part).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, atomic::AtomicBool};

use common::{DB, code, js, load, open, q, rows, rows_of, val};
use rustegon_common::ErrorCode;
use rustegon_doc::Value;
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_query::{ExecOptions, Interrupt, Params, Statement, parse_statement};
use rustegon_sim_api::{Clock, SystemClock};

fn orders() -> EmbeddedDb {
    let db = open(11);
    load(
        &db,
        "orders",
        &[
            r#"{"_id":1,"status":"paid","qty":5,"price":2.5,"tags":["a","b"],"customer":{"name":"ann","tier":1}}"#,
            r#"{"_id":2,"status":"new","qty":1,"price":10,"tags":["b"],"customer":{"name":"bob","tier":2}}"#,
            r#"{"_id":3,"status":"paid","qty":7,"tags":[],"customer":{"name":"cid","tier":1,"secret":"x"}}"#,
            r#"{"_id":4,"status":null,"qty":3,"price":1,"items":[{"sku":"x","n":2},{"sku":"y","n":0}]}"#,
            r#"{"_id":5,"qty":9,"price":4,"tags":"a","items":[{"sku":"y","n":5}]}"#,
            r#"{"_id":6,"status":"shipped","qty":5,"price":{"$decimal":"3.25"},"tags":["c",null]}"#,
        ],
    );
    db
}

fn ids(db: &EmbeddedDb, filter: &str) -> String {
    rows_of(
        db,
        &format!("FROM orders WHERE {filter} SELECT VALUE _id ORDER BY _id"),
    )
}

#[test]
fn tc_ql_009_filter_project_sort_limit_offset() {
    let db = orders();
    assert_eq!(
        rows_of(
            &db,
            "FROM orders AS o WHERE o.qty > 2 SELECT o._id, o.qty ORDER BY o.qty DESC, o._id LIMIT 3 OFFSET 1"
        ),
        r#"{"_id":3,"qty":7} {"_id":1,"qty":5} {"_id":6,"qty":5}"#
    );
    // Without LIMIT the blocking sort is used; ties are ordered by `_id`.
    assert_eq!(
        rows_of(&db, "FROM orders SELECT VALUE _id ORDER BY qty"),
        "2 4 1 6 3 5"
    );
    assert_eq!(
        rows_of(
            &db,
            "FROM orders SELECT VALUE _id ORDER BY qty DESC LIMIT 2"
        ),
        "5 3"
    );
    assert_eq!(
        rows_of(&db, "FROM orders SELECT VALUE _id ORDER BY _id OFFSET 4"),
        "5 6"
    );
    assert_eq!(rows_of(&db, "FROM orders LIMIT 0"), "");
    // ORDER BY an output alias.
    assert_eq!(
        rows_of(
            &db,
            "FROM orders SELECT qty * 10 AS t ORDER BY t DESC LIMIT 2"
        ),
        r#"{"t":90} {"t":70}"#
    );
    // Only an explicit alias is resolved: the derived name `tags` of `tags.1` does not shadow
    // the field `tags` (TC-QL-010 seed 6840335469013534960).
    assert_eq!(
        rows_of(
            &db,
            "FROM orders WHERE _id IN [1, 2, 3] SELECT _id, tags.1 ORDER BY tags DESC"
        ),
        r#"{"_id":2} {"_id":1,"tags":"b"} {"_id":3}"#
    );
}

#[test]
fn tc_ql_009_projection_shapes() {
    let db = orders();
    assert_eq!(
        rows_of(&db, "FROM orders WHERE _id = 3 SELECT customer.*, -secret"),
        r#"{"name":"cid","tier":1}"#
    );
    assert_eq!(
        rows_of(
            &db,
            "FROM orders WHERE _id = 3 SELECT -customer, -tags, -_rev, -_createdAt, -_updatedAt"
        ),
        r#"{"_id":3,"status":"paid","qty":7}"#
    );
    // `missing` omits the field, `null` is kept; SELECT VALUE of missing is null.
    assert_eq!(
        rows_of(
            &db,
            "FROM orders WHERE _id IN [4, 5] SELECT _id, status ORDER BY _id"
        ),
        r#"{"_id":4,"status":null} {"_id":5}"#
    );
    assert_eq!(
        rows_of(&db, "FROM orders WHERE _id = 5 SELECT VALUE status"),
        "null"
    );
    assert_eq!(
        rows_of(
            &db,
            "FROM orders WHERE _id = 1 SELECT customer.name, upper(status), 1 + 1"
        ),
        r#"{"name":"ann","_2":"PAID","_3":2}"#
    );
    let whole = q(&db, "FROM orders WHERE _id = 2");
    let d = &whole.documents()[0];
    assert!(d.get("_rev").is_some() && d.get("_createdAt").is_some());
}

#[test]
fn tc_ql_009_three_valued_logic_null_and_missing() {
    let db = orders();
    assert_eq!(ids(&db, "status = 'paid'"), "1 3");
    assert_eq!(ids(&db, "status != 'paid'"), "2 6");
    assert_eq!(ids(&db, "NOT (status = 'paid')"), "2 6");
    assert_eq!(ids(&db, "status IS NULL"), "4 5");
    assert_eq!(ids(&db, "status IS MISSING"), "5");
    assert_eq!(ids(&db, "status IS NOT NULL"), "1 2 3 6");
    assert_eq!(ids(&db, "status = null"), "");
    assert_eq!(ids(&db, "price > 2 OR status = 'new'"), "1 2 5 6");
    // Unknown OR true is true; unknown AND false is false; NOT unknown stays unknown.
    assert_eq!(ids(&db, "price > 100 OR qty = 7"), "3");
    assert_eq!(ids(&db, "NOT (price > 2)"), "4");
    // Cross-type comparisons follow the total order (strings sort after numbers).
    assert_eq!(ids(&db, "status > 5"), "1 2 3 6");
    assert_eq!(ids(&db, "price = 3.25"), "6");
    assert_eq!(ids(&db, "price BETWEEN 2 AND 4"), "1 5 6");
}

#[test]
fn tc_ql_009_multikey_and_fan_out() {
    let db = orders();
    assert_eq!(ids(&db, "tags = 'a'"), "1 5");
    // `!=` is "no element equals": the `null` element of 6 makes it unknown (§4.3, PD-036).
    assert_eq!(ids(&db, "tags != 'a'"), "2 3");
    assert_eq!(ids(&db, "tags == ['a', 'b']"), "1");
    assert_eq!(ids(&db, "tags = ['b']"), "2");
    assert_eq!(ids(&db, "tags IN ['c', 'z']"), "6");
    assert_eq!(ids(&db, "tags NOT IN ['a', 'b']"), "3");
    // A `null` operand is unknown before the multikey fan-out: `[] != null` is not the
    // negation of an empty `OR` (TC-QL-010 seed 6840335469013532505).
    assert_eq!(ids(&db, "tags != null"), "");
    assert_eq!(
        rows_of(
            &db,
            "FROM orders WHERE _id = 3 SELECT VALUE [tags != null, tags = to_int(status)]"
        ),
        "[null,null]"
    );
    assert_eq!(ids(&db, "tags CONTAINS 'b'"), "1 2");
    assert_eq!(ids(&db, "tags CONTAINS ALL ['a', 'b']"), "1");
    // A string left operand tests substrings: "a" contains "a".
    assert_eq!(ids(&db, "tags CONTAINS ANY ['c', 'a']"), "1 5 6");
    assert_eq!(ids(&db, "tags > 'b'"), "6");
    assert_eq!(ids(&db, "items.sku = 'y'"), "4 5");
    assert_eq!(ids(&db, "items.n > 4"), "5");
    assert_eq!(ids(&db, "items.0.sku = 'x'"), "4");
    assert_eq!(ids(&db, "items[1].n = 0"), "4");
    assert_eq!(ids(&db, "ELEM MATCH (items, sku = 'x' AND n > 1)"), "4");
    assert_eq!(
        ids(&db, "ELEM MATCH (items, items.sku = 'y' AND items.n = 2)"),
        ""
    );
    assert_eq!(ids(&db, "ANY i IN items SATISFIES i.n = 0"), "4");
    // `[]` satisfies EVERY vacuously; a `null` element makes it unknown.
    assert_eq!(ids(&db, "EVERY t IN tags SATISFIES t != 'z'"), "1 2 3");
    assert_eq!(ids(&db, "customer.name LIKE '_n%'"), "1");
    assert_eq!(ids(&db, "customer.name ILIKE 'B%'"), "2");
    assert_eq!(ids(&db, "customer.name MATCHES '^c.d$'"), "3");
}

/// `(expression, expected canonical JSON)` evaluated against document 1.
const FUNCTIONS: &[(&str, &str)] = &[
    ("type_of(qty)", r#""int64""#),
    ("type_of(nothing)", r#""missing""#),
    ("is_number(price)", "true"),
    ("to_string(qty)", r#""5""#),
    // Non-finite floats print as words (TC-QL-010 seed 6840335469013532086).
    ("to_string(to_float('NaN'))", r#""NaN""#),
    ("to_string(to_float('-inf'))", r#""-Infinity""#),
    ("to_int('42')", "42"),
    ("to_float(qty)", "5.0"),
    ("to_decimal('1.50')", r#"{"$decimal":"1.50"}"#),
    ("to_bool('TRUE')", "true"),
    // Converged conversion rules (TC-QL-010 engine differential, seed 6840335469013551997).
    ("to_int(to_date(1000))", "1000"),
    ("[to_int(' 7 '), to_float(' 2.5')]", "[7,2.5]"),
    (
        "[to_bool(to_float('NaN')), to_bool(0), to_bool(-1.5)]",
        "[false,false,true]",
    ),
    ("coalesce(nothing, null, qty)", "5"),
    ("if_null(nothing, 'x')", r#""x""#),
    ("abs(-3)", "3"),
    // A decimal stays a decimal (TC-QL-010 seed 6840335469013538815).
    ("abs(-2.50m)", r#"{"$decimal":"2.50"}"#),
    ("ceil(2.1)", "3.0"),
    ("floor(-2.1)", "-3.0"),
    ("round(2.567, 2)", "2.57"),
    ("sqrt(16)", "4.0"),
    // Outside the domain: `null` (converged with the reference, §4.3).
    (
        "[sqrt(-1), ln(0), log10(-1), ln(to_float('NaN'))]",
        "[null,null,null,null]",
    ),
    ("pow(2, 10)", "1024.0"),
    ("mod(7, 3)", "1"),
    ("greatest(1, 'a', 3)", r#""a""#),
    ("least(4, 2, nothing)", "2"),
    ("length('héllo')", "5"),
    // `length` is a string function; arrays use `size` (TC-QL-010 seed 6840335469013540751).
    ("length(tags)", "null"),
    ("lower('AbC')", r#""abc""#),
    ("trim('  x ')", r#""x""#),
    ("substr('abcdef', 2, 3)", r#""cde""#),
    ("index_of('abcdef', 'cd')", "2"),
    ("replace('aXbX', 'X', '-')", r#""a-b-""#),
    ("split('a,b', ',')", r#"["a","b"]"#),
    ("concat('a', 'b', 'c')", r#""abc""#),
    ("starts_with('rust', 'ru')", "true"),
    ("regex_extract('id=42;', 'id=([0-9]+)', 1)", r#""42""#),
    ("format('{} has {}', customer.name, qty)", r#""ann has 5""#),
    ("size(tags)", "2"),
    ("array_contains(tags, 'b')", "true"),
    ("slice([1,2,3,4], -2)", "[3,4]"),
    ("array_concat([1], [2, 3])", "[1,2,3]"),
    ("array_distinct([1, 1.0, 2])", "[1,2]"),
    ("array_sort([3, 'a', 1])", r#"[1,3,"a"]"#),
    ("array_reverse([1,2])", "[2,1]"),
    ("filter([1,2,3,4], x -> x % 2 = 0)", "[2,4]"),
    ("map([1,2], x -> x * 10)", "[10,20]"),
    ("reduce([1,2,3], 0, (acc, x) -> acc + x)", "6"),
    ("first(tags)", r#""a""#),
    ("last([])", "null"),
    ("zip([1,2], ['a','b','c'])", r#"[[1,"a"],[2,"b"]]"#),
    ("range(0, 5, 2)", "[0,2,4]"),
    ("array_to_object([['k', 1]])", r#"{"k":1}"#),
    ("object_to_array({a: 1})", r#"[{"k":"a","v":1}]"#),
    ("keys(customer)", r#"["name","tier"]"#),
    ("values({a: 1, b: 'x'})", r#"[1,"x"]"#),
    ("merge_objects({a: 1}, {b: 2, a: 3})", r#"{"a":3,"b":2}"#),
    ("get_field(customer, 'tier')", "1"),
    ("set_field({a: 1}, 'b', 2)", r#"{"a":1,"b":2}"#),
    ("unset_field({a: 1, b: 2}, 'a')", r#"{"b":2}"#),
    ("if(qty > 3, 'big', 'small')", r#""big""#),
    ("switch(status, 'new', 1, 'paid', 2, 0)", "2"),
    ("CASE WHEN qty > 10 THEN 'x' ELSE 'y' END", r#""y""#),
    ("CASE status WHEN 'paid' THEN 1 END", "1"),
    ("id()", "1"),
    (
        "date_trunc('month', DATE '2026-03-17T10:00:00Z')",
        r#"{"$date":"2026-03-01T00:00:00.000Z"}"#,
    ),
    (
        "date_add(DATE '2024-01-31', 1, 'month')",
        r#"{"$date":"2024-02-29T00:00:00.000Z"}"#,
    ),
    (
        "date_diff(DATE '2026-01-01', DATE '2026-01-08', 'day')",
        "7",
    ),
    ("extract(year FROM DATE '2026-11-06')", "2026"),
    (
        "date_format(DATE '2026-11-06T13:05:09Z', '%Y/%m/%d %H:%M:%S')",
        r#""2026/11/06 13:05:09""#,
    ),
    (
        "time_bucket('1h', DATE '2026-11-06T13:45:00Z')",
        r#"{"$date":"2026-11-06T13:00:00.000Z"}"#,
    ),
    (
        "DATE '2026-01-01' + INTERVAL '1 day'",
        r#"{"$date":"2026-01-02T00:00:00.000Z"}"#,
    ),
    ("qty / 2", "2.5"),
    ("qty / 0", "null"),
    ("price * 2", "5.0"),
    ("'a' || 'b'", r#""ab""#),
    ("[1] || [2]", "[1,2]"),
    ("-qty", "-5"),
    ("9223372036854775807 + 1", "null"),
    ("1.5m + 1", r#"{"$decimal":"2.5"}"#),
];

#[test]
fn tc_ql_009_scalar_functions_and_operators() {
    let db = orders();
    let mut failures = Vec::new();
    for (expr, expected) in FUNCTIONS {
        let got = rows_of(
            &db,
            &format!("FROM orders WHERE _id = 1 SELECT VALUE {expr}"),
        );
        if got != *expected {
            failures.push(format!("{expr}: expected {expected}, got {got}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // Invalid input yields null and counts warnings (§4.2: functions are total).
    let r = q(&db, "FROM orders SELECT VALUE qty / 0");
    assert_eq!(r.warnings, 6);
    // `now()` is the transaction timestamp, the same for every row of a statement.
    let r = q(&db, "FROM orders SELECT VALUE now()");
    assert!(r.rows.windows(2).all(|w| w[0] == w[1]));
    assert!(matches!(r.rows[0], Value::DateTime(ms) if ms > 1_700_000_000_000));
}

#[test]
fn tc_ql_009_params_are_values_never_text() {
    let db = orders();
    // AC-QL-004: a parameter that looks like RGQL is compared as a plain string.
    let p = Params::new().with("s", Value::String("paid' OR 1 = 1 --".into()));
    let r = db.query(DB, "FROM orders WHERE status = $s", &p).unwrap();
    assert_eq!(r.rows, Vec::<Value>::new());
    let p = Params::positional(vec![val("[1, 3]"), Value::Int64(2)]);
    let r = db
        .query(
            DB,
            "FROM orders WHERE _id IN $1 SELECT VALUE _id ORDER BY _id LIMIT $2",
            &p,
        )
        .unwrap();
    assert_eq!(rows(&r), ["1", "3"]);
    assert_eq!(
        code(&db, "FROM orders WHERE qty = $nope"),
        ErrorCode::QueryTypeError
    );
}

#[test]
fn tc_ql_009_structured_ast_gives_the_same_result() {
    let db = orders();
    let text = "FROM orders WHERE qty >= 5 SELECT VALUE _id ORDER BY _id";
    let json = parse_statement(text).unwrap().to_json().unwrap();
    let stmt = Statement::from_json(&json).unwrap();
    let a = db.query(DB, &stmt, &Params::new()).unwrap();
    assert_eq!(a, q(&db, text));
    assert_eq!(rows(&a), ["1", "3", "5", "6"]);
}

#[test]
fn tc_ql_009_small_batches_give_identical_results() {
    let db = orders();
    let small = ExecOptions {
        batch_rows: 2,
        batch_bytes: 64,
        ..ExecOptions::default()
    };
    for text in [
        "FROM orders SELECT VALUE _id",
        "FROM orders WHERE qty > 2 ORDER BY price DESC LIMIT 3",
        "FROM orders WHERE _id IN [1, 2, 3, 4, 5] OFFSET 1",
        "FROM orders WHERE status != 'x' SELECT status",
    ] {
        let a = db.query_with(DB, text, &Params::new(), &small).unwrap();
        assert_eq!(a.rows, q(&db, text).rows, "{text}");
    }
}

#[test]
fn tc_ql_009_sort_memory_limit_is_rgn_5004() {
    let db = orders();
    let tiny = ExecOptions {
        memory_limit: 100,
        ..ExecOptions::default()
    };
    let err = db
        .query_with(DB, "FROM orders ORDER BY qty", &Params::new(), &tiny)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    // TopK keeps only `k` rows: within the limit.
    let big = ExecOptions {
        memory_limit: 4096,
        ..ExecOptions::default()
    };
    db.query_with(DB, "FROM orders ORDER BY qty LIMIT 1", &Params::new(), &big)
        .unwrap();
}

#[test]
fn tc_ql_008_deadline_and_cancel_hooks() {
    let db = orders();
    let flag = Arc::new(AtomicBool::new(true));
    let cancelled = ExecOptions {
        interrupt: Interrupt::none().with_cancel(flag),
        ..ExecOptions::default()
    };
    let err = db
        .query_with(DB, "FROM orders", &Params::new(), &cancelled)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Cancelled);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let past = ExecOptions {
        interrupt: Interrupt::none().with_deadline(Arc::clone(&clock), clock.monotonic()),
        ..ExecOptions::default()
    };
    let err = db
        .query_with(DB, "FROM orders", &Params::new(), &past)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
    assert_eq!(
        code(&db, "FROM orders OPTIONS (max_time_ms = 0)"),
        ErrorCode::DeadlineExceeded
    );
    q(&db, "FROM orders OPTIONS (max_time_ms = 60000)");
    assert_eq!(js(&Value::Int64(1)), "1");
}
