// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `EXPLAIN` / `EXPLAIN ANALYZE` through the embedded API (TC-QL-006, AC-QL-006, FR-QL-005):
//! the explain format 1 schema (query-language.md §5.1) checked against golden fixtures
//! (`tests/fixtures/explain/*.json`, frozen clock so timings are `0.0`; re-record with
//! `RGQL_BLESS=1` and review), actual rows equal to the real result, timings from the
//! simulated clock, and `EXPLAIN ANALYZE` of writes leaving the data unchanged.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{path::PathBuf, sync::Arc, time::Duration};

use common::{DB, TestClock, js, load, open_on, q, rows_of};
use rustegon_doc::{Document, Value};
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_query::{ExecOptions, Params, stats::StatsConfig};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::Clock;

fn store(clock: &Arc<TestClock>) -> EmbeddedDb {
    let db = open_on(
        Arc::new(SimFileSystem::new()),
        Arc::clone(clock) as Arc<dyn Clock>,
        6,
        true,
    );
    q(&db, "CREATE INDEX by_status ON t (status)");
    let docs: Vec<String> = (1..=20)
        .map(|i| {
            let status = ["new", "paid", "shipped"][i % 3];
            format!(
                r#"{{"_id":{i},"status":"{status}","qty":{},"tag":"t{}"}}"#,
                i % 7,
                i % 4
            )
        })
        .collect();
    let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
    load(&db, "t", &refs);
    db
}

fn explain_with(db: &EmbeddedDb, text: &str, clock: &Arc<TestClock>) -> Document {
    let opts = ExecOptions {
        clock: Some(Arc::clone(clock) as Arc<dyn Clock>),
        ..ExecOptions::default()
    };
    let r = db.query_with(DB, text, &Params::new(), &opts).unwrap();
    assert_eq!(r.rows.len(), 1, "{text}");
    match &r.rows[0] {
        Value::Object(d) => d.clone(),
        other => panic!("{other:?}"),
    }
}

fn pretty(d: &Document) -> String {
    let v: serde_json::Value = serde_json::from_str(&js(&Value::Object(d.clone()))).unwrap();
    let mut s = serde_json::to_string_pretty(&v).unwrap();
    s.push('\n');
    s
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/explain")
        .join(format!("{name}.json"))
}

fn check_golden(name: &str, actual: &str) {
    let path = fixture(name);
    if std::env::var("RGQL_BLESS").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (bless with RGQL_BLESS=1)", path.display()))
        .replace("\r\n", "\n");
    assert_eq!(actual, expected, "golden {name} differs");
}

fn node(d: &Document) -> &Document {
    match d.get("plan") {
        Some(Value::Object(p)) => p,
        other => panic!("{other:?}"),
    }
}

fn children(n: &Document) -> Vec<&Document> {
    match n.get("children") {
        Some(Value::Array(c)) => c
            .iter()
            .map(|v| match v {
                Value::Object(d) => d,
                other => panic!("{other:?}"),
            })
            .collect(),
        other => panic!("{other:?}"),
    }
}

/// Every node of the tree, root first (single-input operators: a chain).
fn chain(d: &Document) -> Vec<&Document> {
    let mut out = vec![node(d)];
    while let Some(c) = children(out[out.len() - 1]).first().copied() {
        out.push(c);
    }
    out
}

fn int(n: &Document, f: &str) -> i64 {
    match n.get(f) {
        Some(Value::Int64(i)) => *i,
        other => panic!("{f}: {other:?}"),
    }
}

fn float(n: &Document, f: &str) -> f64 {
    match n.get(f) {
        Some(Value::Float64(x)) => *x,
        other => panic!("{f}: {other:?}"),
    }
}

fn string(n: &Document, f: &str) -> String {
    match n.get(f) {
        Some(Value::String(s)) => s.clone(),
        other => panic!("{f}: {other:?}"),
    }
}

const SCHEMA_TOP: &[&str] = &[
    "explain_format",
    "statement",
    "analyze",
    "indexes_used",
    "est_cost",
    "plan",
    "execution",
    "logical",
    "physical",
];
const SCHEMA_NODE: &[&str] = &["op", "detail", "index", "est_rows", "children"];
const SCHEMA_ACTUAL: &[&str] = &["actual_rows", "batches", "time_ms"];

fn assert_schema(d: &Document, analyze: bool) {
    let keys: Vec<&str> = d.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, SCHEMA_TOP);
    assert_eq!(int(d, "explain_format"), 1);
    assert_eq!(d.get("analyze"), Some(&Value::Bool(analyze)));
    for n in chain(d) {
        let mut expected: Vec<&str> = SCHEMA_NODE[..4].to_vec();
        if analyze {
            expected.extend_from_slice(SCHEMA_ACTUAL);
        }
        expected.push("children");
        let keys: Vec<&str> = n.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, expected, "{n:?}");
        // `null` for rule-based plans (no statistics), a float with the cost-based optimizer.
        assert!(matches!(
            n.get("est_rows"),
            Some(Value::Null | Value::Float64(_))
        ));
    }
    assert!(matches!(
        d.get("est_cost"),
        Some(Value::Null | Value::Float64(_))
    ));
    match d.get("execution") {
        Some(Value::Null) => assert!(!analyze),
        Some(Value::Object(e)) => {
            assert!(analyze);
            let keys: Vec<&str> = e.iter().map(|(k, _)| k).collect();
            assert_eq!(keys, ["rows", "affected", "time_ms", "warnings"]);
        }
        other => panic!("{other:?}"),
    }
}

const GOLDEN: &[(&str, &str)] = &[
    (
        "index_topk_project",
        "EXPLAIN ANALYZE FROM t WHERE status = 'paid' AND qty > 1 SELECT _id, qty ORDER BY qty DESC LIMIT 3",
    ),
    (
        "collscan_sort_offset",
        "EXPLAIN ANALYZE FROM t WHERE tag = 't1' ORDER BY qty OFFSET 1",
    ),
    (
        "plan_only",
        "EXPLAIN FROM t WHERE _id IN [3, 4, 99] SELECT VALUE qty",
    ),
    (
        "delete_analyze",
        "EXPLAIN ANALYZE DELETE FROM t WHERE status = 'new'",
    ),
    (
        "update_plan_only",
        "EXPLAIN UPDATE t SET qty = qty + 1 WHERE tag = 't2'",
    ),
];

#[test]
fn tc_ql_006_explain_golden_format_1() {
    let clock = TestClock::new(Duration::from_micros(1));
    let db = store(&clock);
    // Frozen clock: every timing is exactly 0.0, so the fixtures are deterministic.
    clock.set_tick(Duration::ZERO);
    for (name, text) in GOLDEN {
        let d = explain_with(&db, text, &clock);
        assert_schema(&d, text.contains("ANALYZE"));
        check_golden(name, &pretty(&d));
    }
}

/// Plans chosen with statistics carry the optimizer's estimates (FR-QL-001, FR-QL-005).
const GOLDEN_ESTIMATES: &[(&str, &str)] = &[
    (
        "estimates_index_topk",
        "EXPLAIN ANALYZE FROM t WHERE status = 'paid' AND qty > 1 SELECT _id, qty ORDER BY qty DESC LIMIT 3",
    ),
    (
        "estimates_update",
        "EXPLAIN UPDATE t SET qty = qty + 1 WHERE tag = 't2'",
    ),
];

#[test]
fn tc_ql_006_explain_estimates_after_analyze() {
    let clock = TestClock::new(Duration::from_micros(1));
    let db = store(&clock);
    let full = StatsConfig {
        sample_size: None,
        ..StatsConfig::default()
    };
    db.analyze(DB, "t", &full).unwrap();
    clock.set_tick(Duration::ZERO);
    for (name, text) in GOLDEN_ESTIMATES {
        let d = explain_with(&db, text, &clock);
        assert_schema(&d, text.contains("ANALYZE"));
        assert!(float(&d, "est_cost") > 0.0, "{text}");
        for n in chain(&d) {
            assert!(float(n, "est_rows") >= 0.0, "{text}: {n:?}");
        }
        check_golden(name, &pretty(&d));
    }
    // Estimates never grow towards the root of a read (filters and limits only cut).
    let d = explain_with(
        &db,
        "EXPLAIN FROM t WHERE tag = 't1' SELECT _id ORDER BY qty LIMIT 2 OFFSET 1",
        &clock,
    );
    let nodes = chain(&d);
    for w in nodes.windows(2) {
        assert!(float(w[0], "est_rows") <= float(w[1], "est_rows"), "{d:?}");
    }
    assert!(float(nodes[0], "est_rows") <= 2.0);
}

#[test]
fn tc_ql_006_analyze_actual_rows_match_the_result() {
    let clock = TestClock::new(Duration::from_micros(1));
    let db = store(&clock);
    let cases = [
        "FROM t WHERE status = 'paid' AND qty > 1 SELECT _id, qty ORDER BY qty DESC LIMIT 3",
        "FROM t WHERE tag = 't1' ORDER BY qty OFFSET 1",
        "FROM t WHERE qty >= 2 SELECT VALUE _id",
        "FROM t WHERE status IN ['new', 'shipped'] ORDER BY _id LIMIT 4",
        "FROM t WHERE _id IN [3, 4, 99]",
        "FROM t WHERE false",
    ];
    for text in cases {
        let real = q(&db, text).rows.len();
        let d = explain_with(&db, &format!("EXPLAIN ANALYZE {text}"), &clock);
        assert_schema(&d, true);
        let nodes = chain(&d);
        assert_eq!(
            int(nodes[0], "actual_rows"),
            i64::try_from(real).unwrap(),
            "{text}"
        );
        let Some(Value::Object(e)) = d.get("execution") else {
            panic!()
        };
        assert_eq!(int(e, "rows"), i64::try_from(real).unwrap(), "{text}");
        // Row counts never grow towards the root (single-input operators that filter or cut).
        for w in nodes.windows(2) {
            assert!(
                int(w[0], "actual_rows") <= int(w[1], "actual_rows"),
                "{text}: {} > {}",
                string(w[0], "op"),
                string(w[1], "op")
            );
        }
        // Inclusive timings on the simulated clock: a parent includes its input's time.
        for w in nodes.windows(2) {
            assert!(float(w[0], "time_ms") >= float(w[1], "time_ms"), "{text}");
        }
        assert!(float(e, "time_ms") >= float(nodes[0], "time_ms"), "{text}");
    }
    // The index is reported where it is used.
    let d = explain_with(&db, "EXPLAIN ANALYZE FROM t WHERE status = 'paid'", &clock);
    assert_eq!(js(d.get("indexes_used").unwrap()), r#"["by_status"]"#);
    let src = *chain(&d).last().unwrap();
    assert_eq!(string(src, "op"), "IndexScan");
    assert_eq!(string(src, "index"), "by_status");
    assert!(float(src, "time_ms") > 0.0, "the simulated clock advances");
}

#[test]
fn tc_ql_006_analyze_of_writes_changes_nothing() {
    let clock = TestClock::new(Duration::from_micros(1));
    let db = store(&clock);
    let before = rows_of(&db, "FROM t ORDER BY _id");
    let d = explain_with(
        &db,
        "EXPLAIN ANALYZE DELETE FROM t WHERE status = 'new'",
        &clock,
    );
    let Some(Value::Object(e)) = d.get("execution") else {
        panic!()
    };
    let n_new = q(&db, "FROM t WHERE status = 'new'").rows.len();
    assert_eq!(int(e, "affected"), i64::try_from(n_new).unwrap());
    assert_eq!(string(node(&d), "op"), "Delete");
    assert_eq!(int(node(&d), "actual_rows"), i64::try_from(n_new).unwrap());
    let d = explain_with(
        &db,
        "EXPLAIN ANALYZE UPDATE t SET qty = qty + 100 WHERE tag = 't2' RETURNING NEW _id",
        &clock,
    );
    let Some(Value::Object(e)) = d.get("execution") else {
        panic!()
    };
    assert_eq!(int(e, "affected"), int(e, "rows"));
    assert!(int(e, "affected") > 0);
    assert_eq!(rows_of(&db, "FROM t ORDER BY _id"), before);
    // Inside an explicit transaction too: only the explained statement is undone.
    db.transaction(|s| {
        s.query(
            DB,
            "INSERT INTO t VALUE {_id: 100, status: 'new'}",
            &Params::new(),
        )?;
        s.query(
            DB,
            "EXPLAIN ANALYZE DELETE FROM t WHERE status = 'new'",
            &Params::new(),
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        rows_of(&db, "FROM t WHERE _id = 100 SELECT VALUE status"),
        r#""new""#
    );
}

#[test]
fn tc_ql_006_explain_errors() {
    let clock = TestClock::new(Duration::from_micros(1));
    let db = store(&clock);
    // Errors of the explained statement surface as such (no plan row).
    let e = db
        .query(DB, "EXPLAIN ANALYZE FROM t WHERE nope(1)", &Params::new())
        .unwrap_err();
    assert_eq!(e.code(), rustegon_common::ErrorCode::UnknownFunction);
    let e = db
        .query(
            DB,
            "EXPLAIN ANALYZE FROM t OPTIONS (max_time_ms = 0)",
            &Params::new(),
        )
        .unwrap_err();
    assert_eq!(e.code(), rustegon_common::ErrorCode::DeadlineExceeded);
}
