// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Access paths of the query engine (M3 lane F): TC-IDX-001 in full (results with the planner's
//! index choice equal results with a forced collection scan, on randomized documents, queries
//! and writes; AC-IDX-001 at test scale), TC-IDX-006 (hidden indexes are maintained but chosen
//! only when forced), the re-check of truncated keys (TC-IDX-005 query side), and the error
//! codes of the binder (query-engine.md §2, query-language.md §14).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use common::{DB, code, js, load, open, plan, q, rows_of};
use rustegon_common::ErrorCode;
use rustegon_doc::Value;
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_query::{ExecOptions, Params, bind::IndexHint};
use rustegon_sim::workload::rng::SimRng;

/// Seeds of the randomized run; `RUSTEGON_IDX001_SEEDS=n` runs seeds `1..=n` (longer runs).
fn seeds() -> Vec<u64> {
    let n = std::env::var("RUSTEGON_IDX001_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    (1..=n).collect()
}
const DOCS: u64 = 120;
const QUERIES: usize = 150;

fn pick<'a>(r: &SimRng, items: &[&'a str]) -> &'a str {
    items[r.index(items.len())]
}

fn scalar(r: &SimRng) -> &'static str {
    pick(
        r,
        &[
            "null", "0", "1", "2", "2.5", "3", "4.0", "'x'", "'y'", "true", "{z: 1}",
        ],
    )
}

fn rand_doc(r: &SimRng, id: u64) -> String {
    let mut f = vec![format!("_id: {id}")];
    if !r.chance(150) {
        f.push(format!("a: {}", scalar(r)));
    }
    if !r.chance(200) {
        f.push(format!("b: {}", r.below(5)));
    }
    if r.chance(500) {
        f.push(format!("c: {}", r.below(4)));
    }
    match r.below(4) {
        0 => {}
        1 => f.push(format!("tags: {}", pick(r, &["'p'", "'q'", "1"]))),
        _ => {
            let n = r.below(4);
            let elems: Vec<&str> = (0..n)
                .map(|_| pick(r, &["'p'", "'q'", "'r'", "1", "null"]))
                .collect();
            f.push(format!("tags: [{}]", elems.join(", ")));
        }
    }
    f.push(format!("k: {}", r.below(2)));
    if r.chance(700) {
        let color = pick(r, &["'red'", "'blue'", "'green'"]);
        f.push(format!("attrs: {{color: {color}, size: {}}}", r.below(6)));
    }
    format!("{{{}}}", f.join(", "))
}

fn atom(r: &SimRng) -> String {
    let v = scalar(r);
    let n = r.below(5);
    match r.below(19) {
        0 => format!("a = {v}"),
        1 => format!("a > {v}"),
        2 => format!("a <= {v}"),
        3 => format!("a IN [{v}, {}]", scalar(r)),
        4 => "a IS NULL".to_owned(),
        5 => format!("b = {n}"),
        6 => format!("b > {n}"),
        7 => format!("b < {n}"),
        8 => format!("tags = {}", pick(r, &["'p'", "'q'", "1"])),
        9 => format!("tags > {}", pick(r, &["'p'", "0"])),
        10 => "tags IN ['q', 'r']".to_owned(),
        11 => format!("c = {}", r.below(4)),
        12 => format!("c > {}", r.below(4)),
        13 => "k = 1".to_owned(),
        14 => format!("attrs.color = {}", pick(r, &["'red'", "'blue'"])),
        15 => format!("attrs.size >= {n}"),
        16 => format!("_id = {}", r.below(DOCS)),
        17 => format!("_id IN [{}, {}, 1000]", r.below(DOCS), r.below(DOCS)),
        _ => format!("NOT (a = {v})"),
    }
}

fn rand_query(r: &SimRng) -> (String, bool) {
    let n = 1 + r.below(3);
    let mut atoms: Vec<String> = (0..n).map(|_| atom(r)).collect();
    if r.chance(150) {
        let a = atoms.pop().unwrap_or_else(|| atom(r));
        atoms.push(format!("({a} OR {})", atom(r)));
    }
    let filter = atoms.join(" AND ");
    if r.chance(400) {
        let order = pick(r, &["a", "b DESC", "a, b DESC", "attrs.size"]);
        let limit = if r.chance(500) {
            format!(" LIMIT {}", 1 + r.below(10))
        } else {
            String::new()
        };
        (
            format!("FROM t WHERE {filter} SELECT _id, a, b ORDER BY {order}{limit}"),
            true,
        )
    } else {
        (format!("FROM t WHERE {filter} SELECT VALUE _id"), false)
    }
}

fn run_rows(db: &EmbeddedDb, text: &str, opts: &ExecOptions) -> Vec<String> {
    db.query_with(DB, text, &Params::new(), opts)
        .unwrap_or_else(|e| panic!("{text}: {e}"))
        .rows
        .iter()
        .map(js)
        .collect()
}

fn setup(seed: u64) -> (EmbeddedDb, SimRng) {
    let db = open(seed);
    for ddl in [
        "CREATE INDEX ia ON t (a)",
        "CREATE INDEX iab ON t (a ASC, b DESC)",
        "CREATE INDEX ib ON t (b) WITH (`include` = ['b', 'a'])",
        "CREATE INDEX itags ON t (tags)",
        "CREATE INDEX ic ON t (c) WITH (sparse = true)",
        "CREATE INDEX ik ON t (b) WITH (partial = 'k = 1')",
        "CREATE INDEX iw ON t (`attrs.**`)",
        "CREATE INDEX isize ON t (attrs.size DESC)",
    ] {
        q(&db, ddl);
    }
    let r = SimRng::new(seed * 7919);
    for id in 0..DOCS {
        q(&db, &format!("INSERT INTO t VALUE {}", rand_doc(&r, id)));
    }
    (db, r)
}

#[test]
fn tc_idx_001_planner_results_equal_collection_scan_randomized() {
    let scan = ExecOptions {
        index_override: Some(IndexHint::CollectionScan),
        ..ExecOptions::default()
    };
    let auto = ExecOptions::default();
    let (mut indexed, mut total) = (0, 0);
    for seed in seeds() {
        let (db, r) = setup(seed);
        for round in 0..2 {
            for _ in 0..QUERIES {
                let (text, ordered) = rand_query(&r);
                let mut a = run_rows(&db, &text, &auto);
                let mut b = run_rows(&db, &text, &scan);
                if !ordered {
                    a.sort();
                    b.sort();
                }
                assert_eq!(a, b, "seed {seed} round {round}: {text}");
                total += 1;
                let p = plan(&db, &text);
                if p.contains("IndexScan") || p.contains("PrimaryGet") {
                    indexed += 1;
                }
            }
            // Random writes between the rounds exercise index maintenance by the query path.
            for _ in 0..40 {
                let id = r.below(DOCS);
                let stmt = match r.below(4) {
                    0 => format!("DELETE FROM t WHERE _id = {id}"),
                    1 => format!("UPSERT INTO t VALUE {}", rand_doc(&r, id)),
                    2 => format!(
                        "UPDATE t SET a = {}, tags = ['r', 'p'] WHERE _id = {id}",
                        scalar(&r)
                    ),
                    _ => format!("UPDATE t UNSET a INC b BY 1 WHERE b = {}", r.below(5)),
                };
                q(&db, &stmt);
            }
        }
    }
    // The planner must actually exercise the index paths in a good share of the queries.
    assert!(
        indexed * 3 >= total,
        "only {indexed} of {total} queries used an index"
    );
}

#[test]
fn tc_idx_006_hidden_index_is_maintained_but_chosen_only_when_forced() {
    let db = open(61);
    q(&db, "CREATE INDEX hid ON t (h) WITH (hidden = true)");
    load(&db, "t", &[r#"{"_id":1,"h":1}"#, r#"{"_id":2,"h":2}"#]);
    q(&db, "UPDATE t SET h = 3 WHERE _id = 2");
    let text = "FROM t WHERE h = 3 SELECT VALUE _id";
    assert!(!plan(&db, text).contains("hid"));
    let forced = "FROM t WHERE h = 3 SELECT VALUE _id OPTIONS (index = 'hid')";
    assert!(plan(&db, forced).contains("IndexScan shop.t.hid"));
    assert_eq!(rows_of(&db, text), "2");
    assert_eq!(rows_of(&db, forced), "2");
    assert_eq!(
        rows_of(&db, "FROM t WHERE h = 2 OPTIONS (index = 'hid')"),
        ""
    );
}

#[test]
fn tc_idx_005_truncated_keys_are_rechecked() {
    let db = open(62);
    q(&db, "CREATE INDEX i_s ON t (s)");
    let long = "a".repeat(5000);
    let p = Params::new()
        .with("x", Value::String(format!("{long}x")))
        .with("y", Value::String(format!("{long}y")));
    db.query(
        DB,
        "INSERT INTO t VALUES {_id: 1, s: $x}, {_id: 2, s: $y}",
        &p,
    )
    .unwrap();
    let r = db
        .query(DB, "FROM t WHERE s = $x SELECT VALUE _id", &p)
        .unwrap();
    assert_eq!(r.rows, vec![Value::Int64(1)]);
    let r = db.query(DB, "EXPLAIN FROM t WHERE s = $y", &p).unwrap();
    assert!(js(&r.rows[0]).contains("IndexScan"));
    let r = db
        .query(DB, "FROM t WHERE s > $x SELECT VALUE _id", &p)
        .unwrap();
    assert_eq!(r.rows, vec![Value::Int64(2)]);
}

#[test]
fn tc_idx_001_sort_elimination_and_covered_results_match() {
    let db = open(63);
    q(
        &db,
        "CREATE INDEX st ON t (status ASC, at DESC) WITH (`include` = ['status', 'n'])",
    );
    for i in 0..30 {
        let status = ["a", "b", "c"][i % 3];
        q(
            &db,
            &format!(
                "INSERT INTO t VALUE {{_id: {i}, status: '{status}', at: {}, n: {}}}",
                i % 7,
                i % 4
            ),
        );
    }
    let scan = ExecOptions {
        index_override: Some(IndexHint::CollectionScan),
        ..ExecOptions::default()
    };
    for text in [
        "FROM t WHERE status = 'b' SELECT _id, at ORDER BY at DESC LIMIT 4",
        "FROM t WHERE status = 'b' SELECT _id, at ORDER BY at DESC",
        "FROM t WHERE status = 'a' AND at < 5 SELECT _id ORDER BY at DESC",
        "FROM t WHERE status IN ['a', 'c'] SELECT status, n",
        "FROM t WHERE status = 'c' SELECT status, n",
    ] {
        let mut a = run_rows(&db, text, &ExecOptions::default());
        let mut b = run_rows(&db, text, &scan);
        if !text.contains("ORDER BY") {
            a.sort();
            b.sort();
        }
        assert_eq!(a, b, "{text}");
    }
    assert!(
        plan(&db, "FROM t WHERE status = 'b' SELECT _id ORDER BY at DESC").contains("IndexOrder")
    );
    assert!(plan(&db, "FROM t WHERE status = 'c' SELECT status, n").contains("covered"));
}

#[test]
fn tc_ql_011_error_codes() {
    let db = open(64);
    load(&db, "t", &[r#"{"_id":1}"#]);
    let cases = [
        ("FROM t WHERE", ErrorCode::QuerySyntaxError),
        ("FROM t WHERE nope(1)", ErrorCode::UnknownFunction),
        ("FROM t WHERE lower(1, 2) = 'a'", ErrorCode::QueryTypeError),
        ("FROM t WHERE a LIKE 5", ErrorCode::QueryTypeError),
        ("FROM t LIMIT 'x'", ErrorCode::QueryTypeError),
        ("FROM nowhere.t", ErrorCode::NotFound),
        ("FROM missing_coll", ErrorCode::NotFound),
        ("FROM t OPTIONS (index = 'none')", ErrorCode::IndexNotFound),
        ("FROM t GROUP BY a", ErrorCode::InvalidArgument),
        (
            "FROM t LOOKUP u ON a = b INTO x",
            ErrorCode::InvalidArgument,
        ),
        ("FROM t |> LIMIT 1", ErrorCode::InvalidArgument),
        ("FROM t WHERE search(a, 'x')", ErrorCode::InvalidArgument),
        (
            "FROM t AS OF SYSTEM TIME '-10s'",
            ErrorCode::InvalidArgument,
        ),
        ("BEGIN", ErrorCode::InvalidArgument),
        ("DELETE FROM t", ErrorCode::QueryTooComplex),
        (
            "INSERT INTO t VALUE {a: 1} USING TTL 5",
            ErrorCode::InvalidArgument,
        ),
        (
            "FROM t OPTIONS (max_time_ms = 'soon')",
            ErrorCode::InvalidArgument,
        ),
    ];
    let mut failures = Vec::new();
    for (text, expected) in cases {
        let got = db
            .query(DB, text, &Params::new())
            .map(|_| ())
            .map_err(|e| e.code());
        if got != Err(expected) {
            failures.push(format!("{text}: expected {expected}, got {got:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(code(&db, "FROM t WHERE a = $1"), ErrorCode::QueryTypeError);
}
