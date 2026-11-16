// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-QL-009: golden semantics of the reference interpreter (`rustegon-query::reference`,
//! query-engine.md §11) on the edge cases of query-language.md §4 and data-model §2.1/§2.3:
//! `null` vs `missing`, cross-type numeric equality, multikey arrays, the cross-type total order,
//! three-valued logic, operators, functions, projections and writes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustegon_common::ErrorCode;
use rustegon_doc::{
    Value,
    json::{JsonMode, parse_document, value_to_json},
};
use rustegon_query::{
    parse_statement,
    reference::{Params, Reference, is_unsupported},
};

fn store(docs: &[&str]) -> Reference {
    let mut r = Reference::new();
    r.load("t", docs.iter().map(|d| parse_document(d).unwrap()));
    r
}

fn run(r: &mut Reference, text: &str, params: &Params) -> Result<Vec<Value>, ErrorCode> {
    let stmt = parse_statement(text).unwrap_or_else(|e| panic!("{text}: {e}"));
    r.execute(&stmt, params)
        .map(|o| o.rows)
        .map_err(|e| e.code())
}

/// Rows of `text` as canonical JSON.
fn q(r: &mut Reference, text: &str) -> String {
    let rows = run(r, text, &Params::new()).unwrap_or_else(|e| panic!("{text}: {e}"));
    value_to_json(&Value::Array(rows), JsonMode::Canonical)
}

fn err(r: &mut Reference, text: &str) -> ErrorCode {
    run(r, text, &Params::new()).expect_err(text)
}

fn ids(r: &mut Reference, filter: &str) -> String {
    q(
        r,
        &format!("FROM t WHERE {filter} SELECT VALUE _id ORDER BY _id"),
    )
}

#[test]
fn tc_ql_009_null_and_missing_three_valued() {
    let mut r = store(&[
        r#"{"_id":1,"a":null}"#,
        r#"{"_id":2}"#,
        r#"{"_id":3,"a":1}"#,
    ]);
    assert_eq!(ids(&mut r, "a IS NULL"), "[1,2]");
    assert_eq!(ids(&mut r, "a IS MISSING"), "[2]");
    assert_eq!(ids(&mut r, "a IS NOT NULL"), "[3]");
    assert_eq!(ids(&mut r, "a IS NOT MISSING"), "[1,3]");
    // Comparisons with null/missing are unknown, and so is their negation.
    assert_eq!(ids(&mut r, "a = null"), "[]");
    assert_eq!(ids(&mut r, "a != 1"), "[]");
    assert_eq!(ids(&mut r, "NOT (a = 1)"), "[]");
    assert_eq!(ids(&mut r, "(a = 1) IS NULL"), "[1,2]");
    assert_eq!(ids(&mut r, "a = 1 OR true"), "[1,2,3]");
    assert_eq!(ids(&mut r, "a = 1 AND false"), "[]");
    assert_eq!(
        q(&mut r, "FROM t SELECT VALUE type_of(a) ORDER BY _id"),
        r#"["null","missing","int64"]"#
    );
    // A missing projected value omits the field; SELECT VALUE turns it into null.
    assert_eq!(
        q(&mut r, "FROM t SELECT a + 1 AS b ORDER BY _id"),
        r#"[{"b":null},{},{"b":2}]"#
    );
}

#[test]
fn tc_ql_009_numeric_equality_across_types() {
    let mut r = store(&[
        r#"{"_id":1,"a":1}"#,
        r#"{"_id":2,"a":1.0}"#,
        r#"{"_id":3,"a":{"$decimal":"1.00"}}"#,
        r#"{"_id":4,"a":2}"#,
        r#"{"_id":5,"a":"1"}"#,
        r#"{"_id":6,"a":{"$float":"NaN"}}"#,
    ]);
    assert_eq!(ids(&mut r, "a = 1"), "[1,2,3]");
    assert_eq!(ids(&mut r, "a == 1.0"), "[1,2,3]");
    assert_eq!(ids(&mut r, "a = 1.00m"), "[1,2,3]");
    // The §2.1 total order, not type bracketing: strings sort after every number, NaN lowest.
    assert_eq!(ids(&mut r, "a > 1"), "[4,5]");
    assert_eq!(ids(&mut r, "a < 1"), "[6]");
    assert_eq!(ids(&mut r, "a BETWEEN 1 AND 2"), "[1,2,3,4]");
    assert_eq!(ids(&mut r, "a IN [2, '1']"), "[4,5]");
}

#[test]
fn tc_ql_009_arrays_are_multikey_except_whole_equality() {
    let mut r = store(&[
        r#"{"_id":1,"tags":["a","b"]}"#,
        r#"{"_id":2,"tags":"a"}"#,
        r#"{"_id":3,"tags":[]}"#,
        r#"{"_id":4,"tags":[["a"]]}"#,
        r#"{"_id":5,"tags":["c",null]}"#,
    ]);
    assert_eq!(ids(&mut r, "tags = 'a'"), "[1,2]");
    assert_eq!(ids(&mut r, "tags == ['a', 'b']"), "[1]");
    // Symmetric multikey: the scalar 'a' equals an element of the array literal; two arrays
    // compare as whole values ([['a']] is not ['a']).
    assert_eq!(ids(&mut r, "tags = ['a']"), "[2]");
    assert_eq!(ids(&mut r, "tags = [['a']]"), "[4]");
    // `!=` is NOT(=): no element equals; a null element keeps it unknown.
    assert_eq!(ids(&mut r, "tags != 'a'"), "[3,4]");
    assert_eq!(ids(&mut r, "tags < 'b'"), "[1,2]");
    assert_eq!(ids(&mut r, "tags CONTAINS 'c'"), "[5]");
    assert_eq!(ids(&mut r, "tags CONTAINS ALL ['a', 'b']"), "[1]");
    assert_eq!(ids(&mut r, "tags CONTAINS ANY ['b', 'c']"), "[1,5]");
    assert_eq!(ids(&mut r, "ANY x IN tags SATISFIES x = 'b'"), "[1]");
    // The bound variable is multikey too: [['a']] has the element ['a'], and ['a'] = 'a'.
    assert_eq!(ids(&mut r, "EVERY x IN tags SATISFIES x = 'a'"), "[3,4]");
    assert_eq!(ids(&mut r, "size(tags) = 2"), "[1,5]");
}

#[test]
fn tc_ql_009_order_by_follows_the_total_order_and_ties_use_id() {
    let mut r = store(&[
        r#"{"_id":1,"v":true}"#,
        r#"{"_id":2,"v":"s"}"#,
        r#"{"_id":3}"#,
        r#"{"_id":4,"v":[1]}"#,
        r#"{"_id":5,"v":{"k":1}}"#,
        r#"{"_id":6,"v":null}"#,
        r#"{"_id":7,"v":{"$date":"2026-01-01T00:00:00.000Z"}}"#,
        r#"{"_id":8,"v":{"$oid":"000000000000000000000001"}}"#,
        r#"{"_id":9,"v":-1.5}"#,
        r#"{"_id":10,"v":{"$decimal":"-1.5"}}"#,
    ]);
    // missing < null < numbers < string < object < array < objectId < bool < datetime;
    // the equal numbers 9 and 10 keep `_id` order.
    assert_eq!(
        q(&mut r, "FROM t SELECT VALUE _id ORDER BY v"),
        "[3,6,9,10,2,5,4,8,1,7]"
    );
    assert_eq!(
        q(&mut r, "FROM t SELECT VALUE _id ORDER BY v DESC"),
        "[7,1,8,4,5,2,9,10,6,3]"
    );
    assert_eq!(
        q(
            &mut r,
            "FROM t SELECT VALUE _id ORDER BY v LIMIT 3 OFFSET 2"
        ),
        "[9,10,2]"
    );
}

#[test]
fn tc_ql_009_paths_fan_out_over_arrays_and_alias() {
    let mut r = store(&[
        r#"{"_id":1,"items":[{"sku":"s1","qty":2},{"sku":"s2"},7]}"#,
        r#"{"_id":2,"items":[{"sku":"s3","qty":0}],"c":{"y":{"z":1}}}"#,
    ]);
    assert_eq!(
        q(&mut r, "FROM t SELECT VALUE items.qty ORDER BY _id"),
        "[[2],[0]]"
    );
    assert_eq!(ids(&mut r, "items.sku = 's2'"), "[1]");
    assert_eq!(
        ids(&mut r, "ELEM MATCH (items, sku = 's1' AND qty > 1)"),
        "[1]"
    );
    assert_eq!(
        ids(&mut r, "ELEM MATCH (items, sku = 's2' AND qty > 1)"),
        "[]"
    );
    assert_eq!(
        q(&mut r, "FROM t AS o WHERE o.c.y.z = 1 SELECT VALUE o._id"),
        "[2]"
    );
    assert_eq!(
        q(&mut r, "FROM t SELECT VALUE items.0.sku ORDER BY _id"),
        r#"["s1","s3"]"#
    );
    assert_eq!(
        q(&mut r, "FROM t SELECT VALUE items[1] ORDER BY _id"),
        r#"[{"sku":"s2"},null]"#
    );
}

#[test]
fn tc_ql_009_arithmetic_promotion_and_totality() {
    let mut r = store(&[r#"{"_id":1}"#]);
    let v = |r: &mut Reference, e: &str| q(r, &format!("FROM t SELECT VALUE {e}"));
    assert_eq!(v(&mut r, "7 / 2"), "[3.5]");
    assert_eq!(v(&mut r, "7 % -2"), "[1]");
    assert_eq!(v(&mut r, "1 + 1.5"), "[2.5]");
    assert_eq!(v(&mut r, "1 + 1.5m"), r#"[{"$decimal":"2.5"}]"#);
    assert_eq!(v(&mut r, "2.50m * 2"), r#"[{"$decimal":"5.00"}]"#);
    assert_eq!(v(&mut r, "9223372036854775807 + 1"), "[null]");
    assert_eq!(v(&mut r, "1 / 0"), "[null]");
    assert_eq!(v(&mut r, "'a' + 1"), "[null]");
    assert_eq!(v(&mut r, "'a' || 'b'"), r#"["ab"]"#);
    assert_eq!(v(&mut r, "[1] || [2]"), "[[1,2]]");
    assert_eq!(v(&mut r, "-(1)"), "[-1]");
    assert_eq!(
        v(&mut r, "DATE '2026-01-02' - INTERVAL '1 day'"),
        r#"[{"$date":"2026-01-01T00:00:00.000Z"}]"#
    );
}

#[test]
fn tc_ql_009_string_predicates() {
    let mut r = store(&[
        r#"{"_id":1,"b":"abc"}"#,
        r#"{"_id":2,"b":"ABC"}"#,
        r#"{"_id":3,"b":"100%"}"#,
        r#"{"_id":4,"b":5}"#,
    ]);
    assert_eq!(ids(&mut r, "b LIKE 'a%'"), "[1]");
    assert_eq!(ids(&mut r, "b ILIKE 'a_c'"), "[1,2]");
    assert_eq!(ids(&mut r, r"b LIKE '100\\%'"), "[3]");
    assert_eq!(ids(&mut r, "b MATCHES '^[A-Z]'"), "[2]");
    assert_eq!(ids(&mut r, "(b LIKE '%') IS NULL"), "[4]");
    assert_eq!(ids(&mut r, "b CONTAINS 'bc'"), "[1]");
    assert_eq!(ids(&mut r, "starts_with(lower(b), 'ab')"), "[1,2]");
}

#[test]
fn tc_ql_009_functions_case_and_projection() {
    let mut r = store(&[r#"{"_id":1,"b":" Hi ","c":{"x":1,"y":2},"n":-2.5}"#]);
    let v = |r: &mut Reference, e: &str| q(r, &format!("FROM t SELECT VALUE {e}"));
    assert_eq!(
        v(&mut r, "[trim(b), length(b), substr('hello', 1, 3)]"),
        r#"[["Hi",4,"ell"]]"#
    );
    assert_eq!(
        v(&mut r, "[abs(n), round(n), floor(n), to_int(n)]"),
        "[[2.5,-3.0,-3.0,-2]]"
    );
    assert_eq!(
        v(&mut r, "[coalesce(nope, null, 3), if_null(nope, 'd')]"),
        r#"[[3,"d"]]"#
    );
    assert_eq!(
        v(&mut r, "CASE WHEN n > 0 THEN 'pos' ELSE 'neg' END"),
        r#"["neg"]"#
    );
    assert_eq!(v(&mut r, "CASE n WHEN -2.5 THEN 'x' END"), r#"["x"]"#);
    assert_eq!(v(&mut r, "filter([1, 2, 3], x -> x > 1)"), "[[2,3]]");
    assert_eq!(v(&mut r, "reduce([1, 2, 3], 0, (a, x) -> a + x)"), "[6]");
    assert_eq!(
        q(&mut r, "FROM t SELECT c.x, n * 2 AS d, n + 1, c.*"),
        r#"[{"x":1,"d":-5.0,"_3":-1.5,"y":2}]"#
    );
    assert_eq!(
        q(&mut r, "FROM t SELECT -b, -c.x"),
        r#"[{"_id":1,"c":{"y":2},"n":-2.5}]"#
    );
    assert_eq!(
        err(&mut r, "FROM t SELECT VALUE no_such_fn(1)"),
        ErrorCode::UnknownFunction
    );
    assert_eq!(
        err(&mut r, "FROM t SELECT VALUE lower()"),
        ErrorCode::QueryTypeError
    );
    assert_eq!(err(&mut r, "FROM t LIMIT 'x'"), ErrorCode::QueryTypeError);
    assert_eq!(err(&mut r, "FROM t LIMIT -1"), ErrorCode::InvalidArgument);
    assert_eq!(
        err(&mut r, "FROM t WHERE a = $missing_param"),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn tc_ql_009_parameters_bind_by_name_and_position() {
    let mut r = store(&[r#"{"_id":1,"a":"x'; DROP"}"#, r#"{"_id":2,"a":2}"#]);
    let mut p = Params::new();
    p.insert("v".into(), Value::String("x'; DROP".into()));
    p.insert("1".into(), Value::Int64(2));
    let rows = run(
        &mut r,
        "FROM t WHERE a = $v OR a = $1 SELECT VALUE _id ORDER BY _id",
        &p,
    );
    assert_eq!(rows, Ok(vec![Value::Int64(1), Value::Int64(2)]));
}

#[test]
fn tc_ql_009_unsupported_features_are_flagged() {
    let mut r = store(&[r#"{"_id":1}"#]);
    for text in [
        "FROM t GROUP BY a",
        "FROM t SELECT VALUE count(*)",
        "FROM t |> LIMIT 1",
        "FROM t WHERE search(b, 'x')",
        "CREATE COLLECTION x",
    ] {
        let stmt = parse_statement(text).unwrap();
        let e = r.execute(&stmt, &Params::new()).expect_err(text);
        assert!(is_unsupported(&e), "{text}: {e}");
    }
}

#[test]
fn tc_ql_009_insert_upsert_delete() {
    let mut r = store(&[r#"{"_id":1,"a":1}"#]);
    assert_eq!(
        err(&mut r, "INSERT INTO t VALUE {_id: 1.0}"),
        ErrorCode::DuplicateKey
    );
    assert_eq!(
        err(&mut r, "INSERT INTO t VALUE {_rev: 1}"),
        ErrorCode::InvalidFieldName
    );
    assert_eq!(
        err(&mut r, "INSERT INTO t VALUE 5"),
        ErrorCode::QueryTypeError
    );
    // Atomic: the duplicate in the second row rolls back the first.
    assert_eq!(
        err(&mut r, "INSERT INTO t VALUES {_id: 2}, {_id: 2}"),
        ErrorCode::DuplicateKey
    );
    assert_eq!(q(&mut r, "FROM t SELECT VALUE _id"), "[1]");
    assert_eq!(
        q(
            &mut r,
            "INSERT INTO t VALUES {_id: 1}, {_id: 3} ON CONFLICT DO NOTHING RETURNING NEW"
        ),
        r#"[{"_id":3}]"#
    );
    assert_eq!(
        q(
            &mut r,
            "INSERT INTO t VALUE {_id: 1} ON CONFLICT DO UPDATE INC a BY 1 RETURNING NEW"
        ),
        r#"[{"_id":1,"a":2}]"#
    );
    assert_eq!(
        q(&mut r, "UPSERT INTO t VALUE {_id: 3, z: 1} RETURNING OLD"),
        r#"[{"_id":3}]"#
    );
    assert_eq!(
        q(&mut r, "UPSERT INTO t VALUE {_id: 4} RETURNING NEW"),
        r#"[{"_id":4}]"#
    );
    assert_eq!(
        q(&mut r, "INSERT INTO t VALUE {b: 1} RETURNING NEW b"),
        r#"[{"b":1}]"#
    );
    assert_eq!(err(&mut r, "DELETE FROM t"), ErrorCode::QueryTooComplex);
    assert_eq!(
        q(
            &mut r,
            "DELETE FROM t WHERE _id >= 1 LIMIT 2 RETURNING OLD _id"
        ),
        r#"[{"_id":1},{"_id":3}]"#
    );
    assert_eq!(
        q(&mut r, "FROM t WHERE is_number(_id) SELECT VALUE _id"),
        "[4]"
    );
}

#[test]
fn tc_ql_009_update_operators_and_array_filters() {
    let doc = r#"{"_id":1,"n":1,"tags":["a","b","a"],"items":[{"sku":"s1","qty":1},{"sku":"s2","qty":5}]}"#;
    let mut r = store(&[doc]);
    let upd =
        |r: &mut Reference, ops: &str| q(r, &format!("UPDATE t {ops} WHERE _id = 1 RETURNING NEW"));
    assert_eq!(
        upd(&mut r, "SET m = n + 1 INC n BY 2.5"),
        r#"[{"_id":1,"n":3.5,"tags":["a","b","a"],"items":[{"sku":"s1","qty":1},{"sku":"s2","qty":5}],"m":2}]"#
    );
    assert_eq!(
        upd(
            &mut r,
            "PULL tags WHERE tags = 'a' PULL items WHERE qty > 2"
        ),
        r#"[{"_id":1,"n":3.5,"tags":["b"],"items":[{"sku":"s1","qty":1}],"m":2}]"#
    );
    assert_eq!(
        upd(
            &mut r,
            "PUSH tags VALUE 'z' POSITION 0 SET items[x -> x.qty >= 1].qty = 0 UNSET m"
        ),
        r#"[{"_id":1,"n":3.5,"tags":["z","b"],"items":[{"sku":"s1","qty":0}]}]"#
    );
    assert_eq!(
        upd(&mut r, "RENAME n TO k POP tags FIRST"),
        r#"[{"_id":1,"tags":["b"],"items":[{"sku":"s1","qty":0}],"k":3.5}]"#
    );
    assert_eq!(upd(&mut r, "REPLACE WITH {v: 1}"), r#"[{"_id":1,"v":1}]"#);
    assert_eq!(
        err(&mut r, "UPDATE t REPLACE WITH {_id: 2} WHERE _id = 1"),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        err(&mut r, "UPDATE t SET a = 1, a.b = 2 WHERE _id = 1"),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        err(&mut r, "UPDATE t INC v BY 'x' WHERE _id = 1"),
        ErrorCode::QueryTypeError
    );
    assert_eq!(
        err(&mut r, "UPDATE t SET v = 2"),
        ErrorCode::QueryTooComplex
    );
    let stmt =
        parse_statement("UPDATE t SET v = 2 OPTIONS (allow_full_scan_write = true)").unwrap();
    assert_eq!(r.execute(&stmt, &Params::new()).unwrap().affected, Some(1));
}

/// A `null` operand makes a comparison unknown before the multikey fan-out, so `[] = null` /
/// `[] != null` are unknown (TC-QL-010 engine differential, seed 6840335469013532505).
#[test]
fn tc_ql_009_null_operand_is_unknown_before_multikey() {
    let mut r = store(&[r#"{"_id": 1, "tags": []}"#]);
    assert_eq!(
        q(
            &mut r,
            "FROM t SELECT VALUE [tags = null, tags != null, tags < null]"
        ),
        "[[null,null,null]]"
    );
    assert_eq!(
        q(&mut r, "FROM t WHERE tags != null SELECT VALUE _id"),
        "[]"
    );
}

/// Conversions: a date `to_int` is its epoch milliseconds, strings are trimmed, `to_bool` is
/// case-insensitive and `NaN` converts like zero (TC-QL-010 engine differential, seed
/// 6840335469013551997).
#[test]
fn tc_ql_009_conversion_rules() {
    let mut r = store(&[r#"{"_id": 1, "d": {"$date": "1970-01-01T00:00:01.000Z"}}"#]);
    assert_eq!(
        q(
            &mut r,
            "FROM t SELECT VALUE [to_int(d), to_float(d), to_int(' 7 '), to_float(' 2.5'), \
             to_bool('TRUE'), to_bool(to_float('NaN')), to_bool(-1.5)]"
        ),
        "[[1000,null,7,2.5,true,false,true]]"
    );
    assert_eq!(
        q(&mut r, "FROM t WHERE to_int(d) < FALSE SELECT VALUE _id"),
        "[1]"
    );
}

/// `ORDER BY name` resolves explicit `AS` aliases only, never the derived name of an unaliased
/// item (TC-QL-010 engine differential, seed 6840335469013534960).
#[test]
fn tc_ql_009_order_by_resolves_explicit_aliases_only() {
    let mut r = store(&[
        r#"{"_id": 1, "tags": ["a", "b"]}"#,
        r#"{"_id": 2, "tags": ["b"]}"#,
    ]);
    assert_eq!(
        q(&mut r, "FROM t SELECT _id, tags.1 ORDER BY tags DESC"),
        r#"[{"_id":2},{"_id":1,"tags":"b"}]"#
    );
    assert_eq!(
        q(
            &mut r,
            "FROM t SELECT _id, tags.1 AS tags ORDER BY tags DESC"
        ),
        r#"[{"_id":1,"tags":"b"},{"_id":2}]"#
    );
}

/// `UPSERT … ON` converged with the engine (query-language.md §4.3): one match is replaced
/// keeping its `_id`; a `missing` / `null` key or several matches are `RGN-1001`.
#[test]
fn tc_ql_009_upsert_on_key_rules() {
    let mut r = store(&[r#"{"_id": 1, "k": "a"}"#, r#"{"_id": 2, "k": "b"}"#]);
    q(&mut r, "UPSERT INTO t VALUE {k: 'a', x: 1} ON k");
    assert_eq!(
        q(&mut r, "FROM t WHERE k = 'a' SELECT _id, x"),
        r#"[{"_id":1,"x":1}]"#
    );
    for bad in [
        "UPSERT INTO t VALUE {x: 1} ON k",
        "UPSERT INTO t VALUE {k: null} ON k",
    ] {
        assert_eq!(err(&mut r, bad), ErrorCode::InvalidArgument, "{bad}");
    }
    q(&mut r, "INSERT INTO t VALUE {_id: 3, k: 'b'}");
    assert_eq!(
        err(&mut r, "UPSERT INTO t VALUE {k: 'b'} ON k"),
        ErrorCode::InvalidArgument
    );
}
