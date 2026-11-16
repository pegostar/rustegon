// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Cost-based access paths and index usage counters through the embedded API (M3 wave 3
//! lane J; FR-QL-001 optimizer, FR-IDX-004; *Provisional (PD-040)*):
//! - plan choice after `analyze` on skewed data, statistics-cache refresh, fallback without
//!   statistics;
//! - the property that the cost-based choice never changes results: randomized queries on
//!   skewed data with (possibly stale) statistics return the same rows as a forced collection
//!   scan (TC-IDX-001 style, lane F);
//! - FR-IDX-004 usage counters (lookups, scans, entries read, last use) fed by the executor and
//!   exposed with the index sizes by `EmbeddedDb::index_stats` (TC-IDX-007 usage part).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use common::{DB, js, open, plan, q};
use rustegon_common::ErrorCode;
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_query::{ExecOptions, Optimizer, Params, bind::IndexHint, stats::StatsConfig};
use rustegon_sim::workload::rng::SimRng;

/// Rows of the skewed collection: 1 KiB documents, so a scan costs ~40 pages.
const ROWS: u64 = 600;

fn pad() -> String {
    "x".repeat(1000)
}

/// `s` = `'a'` in 90 % of the rows, a unique `'r<i>'` otherwise; `n` unique; `b` 7 values;
/// `c` 4 values; `k` 2 values; `tags` a multikey array.
fn skewed_doc(i: u64, pad: &str) -> String {
    let s = if i.is_multiple_of(10) {
        format!("'r{i}'")
    } else {
        "'a'".to_owned()
    };
    let tags = ["['p']", "['p', 'q']", "['q', 'r']", "[]", "'p'"][usize::try_from(i % 5).unwrap()];
    format!(
        "{{_id: {i}, s: {s}, n: {i}, b: {}, c: {}, k: {}, tags: {tags}, pad: '{pad}'}}",
        i % 7,
        i % 4,
        i % 2
    )
}

fn load_skewed(db: &EmbeddedDb) {
    let pad = pad();
    let ids: Vec<u64> = (0..ROWS).collect();
    for chunk in ids.chunks(100) {
        let rows: Vec<String> = chunk.iter().map(|i| skewed_doc(*i, &pad)).collect();
        q(db, &format!("INSERT INTO t VALUES {}", rows.join(", ")));
    }
}

fn analyze(db: &EmbeddedDb) {
    let full = StatsConfig {
        sample_size: None,
        ..StatsConfig::default()
    };
    db.analyze(DB, "t", &full).unwrap();
}

fn explain_with(db: &EmbeddedDb, text: &str, opts: &ExecOptions) -> String {
    let r = db
        .query_with(DB, &format!("EXPLAIN {text}"), &Params::new(), opts)
        .unwrap_or_else(|e| panic!("{text}: {e}"));
    let s = js(&r.rows[0]);
    let start = s.find("\"physical\"").unwrap();
    s[start..].to_owned()
}

#[test]
fn tc_ql_001_cbo_plan_choice_after_analyze_and_cache_refresh() {
    let db = open(91);
    q(&db, "CREATE INDEX i_s ON t (s)");
    q(&db, "CREATE INDEX i_n ON t (n)");
    load_skewed(&db);
    let mcv = "FROM t WHERE s = 'a' SELECT VALUE _id";
    let rare = "FROM t WHERE s = 'r10' SELECT VALUE _id";
    // No statistics yet: the rule-based choice takes the index for both.
    assert!(plan(&db, mcv).contains("IndexScan shop.t.i_s"));
    assert!(plan(&db, rare).contains("IndexScan shop.t.i_s"));
    // `analyze` refreshes the (already loaded) cache write-through.
    analyze(&db);
    assert!(plan(&db, mcv).starts_with("Project") && plan(&db, mcv).contains("CollectionScan"));
    assert!(plan(&db, rare).contains("IndexScan shop.t.i_s"));
    assert!(plan(&db, "FROM t WHERE n > 595").contains("IndexScan shop.t.i_n"));
    assert!(plan(&db, "FROM t WHERE n > 10").contains("CollectionScan"));
    // The rule-based optimizer can still be selected per statement.
    let rule = ExecOptions {
        optimizer: Optimizer::RuleBased,
        ..ExecOptions::default()
    };
    assert!(explain_with(&db, mcv, &rule).contains("IndexScan shop.t.i_s"));
    // Reloading reads the stored record again; explicit transactions use the same cache.
    db.reload_statistics();
    assert!(plan(&db, mcv).contains("CollectionScan"));
    let in_txn = db
        .transaction(|s| s.query(DB, format!("EXPLAIN {mcv}").as_str(), &Params::new()))
        .unwrap();
    assert!(js(&in_txn.rows[0]).contains("CollectionScan"));
    // Same rows whatever the plan.
    let auto = db.query(DB, mcv, &Params::new()).unwrap();
    let forced = db
        .query(
            DB,
            "FROM t WHERE s = 'a' SELECT VALUE _id OPTIONS (index = 'i_s')",
            &Params::new(),
        )
        .unwrap();
    let (mut a, mut b) = (auto.rows.clone(), forced.rows.clone());
    a.sort_by_key(js);
    b.sort_by_key(js);
    assert_eq!(a, b);
    assert_eq!(a.len(), 540);
}

fn pick<'a>(r: &SimRng, items: &[&'a str]) -> &'a str {
    items[r.index(items.len())]
}

fn atom(r: &SimRng) -> String {
    let n = r.below(ROWS + 20);
    match r.below(14) {
        0 => "s = 'a'".to_owned(),
        1 => format!("s = 'r{}'", r.below(ROWS / 10) * 10),
        2 => format!("s IN ['a', 'r{}']", r.below(ROWS / 10) * 10),
        3 => format!("n > {n}"),
        4 => format!("n <= {n}"),
        5 => format!("n >= {n} AND n < {}", n + r.below(40)),
        6 => format!("b = {}", r.below(8)),
        7 => format!("c = {}", r.below(4)),
        8 => format!("k = {}", r.below(2)),
        9 => format!("tags = {}", pick(r, &["'p'", "'q'", "'r'"])),
        10 => "tags IN ['q', 'r']".to_owned(),
        11 => format!("_id = {n}"),
        12 => format!("NOT (b = {})", r.below(7)),
        _ => format!("(c = {} OR n < {n})", r.below(4)),
    }
}

fn rand_query(r: &SimRng) -> (String, bool) {
    let atoms: Vec<String> = (0..=r.below(2)).map(|_| atom(r)).collect();
    let filter = atoms.join(" AND ");
    let select = pick(r, &["SELECT VALUE _id", "SELECT c, n", "SELECT _id, s, n"]);
    if r.chance(400) {
        let order = pick(r, &["n", "n DESC", "s, n", "c"]);
        let limit = if r.chance(600) {
            format!(" LIMIT {}", 1 + r.below(20))
        } else {
            String::new()
        };
        // `ORDER BY c` alone leaves ties: break them by `_id` so the order is total.
        (
            format!("FROM t WHERE {filter} {select} ORDER BY {order}, _id{limit}"),
            true,
        )
    } else {
        (format!("FROM t WHERE {filter} {select}"), false)
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

/// The cost-based choice never changes results (property, randomized; statistics go stale
/// between rounds through random writes).
#[test]
fn tc_ql_001_cbo_results_equal_collection_scan_randomized() {
    let seeds: u64 = std::env::var("RUSTEGON_CBO_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let scan = ExecOptions {
        index_override: Some(IndexHint::CollectionScan),
        ..ExecOptions::default()
    };
    let rule = ExecOptions {
        optimizer: Optimizer::RuleBased,
        ..ExecOptions::default()
    };
    let auto = ExecOptions::default();
    let (mut total, mut indexed, mut scanned, mut differs) = (0, 0, 0, 0);
    for seed in 1..=seeds {
        let db = open(900 + seed);
        for ddl in [
            "CREATE INDEX i_s ON t (s)",
            "CREATE INDEX i_n ON t (n)",
            "CREATE INDEX ib ON t (b)",
            "CREATE INDEX isn ON t (s ASC, n DESC)",
            "CREATE INDEX itags ON t (tags)",
            "CREATE INDEX ik ON t (b) WITH (partial = 'k = 1')",
            "CREATE INDEX cov ON t (c) WITH (`include` = ['c', 'n'])",
        ] {
            q(&db, ddl);
        }
        load_skewed(&db);
        analyze(&db);
        let r = SimRng::new(seed * 104_729);
        for round in 0..2 {
            for _ in 0..60 {
                let (text, ordered) = rand_query(&r);
                let mut a = run_rows(&db, &text, &auto);
                let mut b = run_rows(&db, &text, &scan);
                if !ordered {
                    a.sort();
                    b.sort();
                }
                assert_eq!(a, b, "seed {seed} round {round}: {text}");
                total += 1;
                let p = explain_with(&db, &text, &auto);
                if p.contains("IndexScan") || p.contains("PrimaryGet") {
                    indexed += 1;
                } else if p.contains("CollectionScan") {
                    scanned += 1;
                }
                if p != explain_with(&db, &text, &rule) {
                    differs += 1;
                }
            }
            // Writes make the statistics stale (they are not re-analyzed): still correct.
            for _ in 0..30 {
                let id = r.below(ROWS);
                let stmt = match r.below(3) {
                    0 => format!("DELETE FROM t WHERE _id = {id}"),
                    1 => format!("UPDATE t SET s = 'a', b = {} WHERE _id = {id}", r.below(7)),
                    _ => format!("UPSERT INTO t VALUE {}", skewed_doc(id + 7, "y")),
                };
                q(&db, &stmt);
            }
        }
    }
    // Both kinds of access paths are chosen, and the costs override the rules sometimes.
    assert!(
        indexed * 5 >= total,
        "only {indexed} of {total} used an index"
    );
    assert!(scanned * 5 >= total, "only {scanned} of {total} scanned");
    assert!(
        differs > 0,
        "the cost model never changed a rule-based plan"
    );
}

#[test]
fn tc_idx_004_usage_counters_fed_by_the_executor() {
    let db = open(93);
    q(&db, "CREATE INDEX ia ON t (a)");
    q(&db, "CREATE INDEX itags ON t (tags)");
    q(
        &db,
        "INSERT INTO t VALUES {_id: 1, a: 1, tags: ['p', 'q']}, {_id: 2, a: 1, tags: 'p'}, \
         {_id: 3, a: 2}, {_id: 4, a: 3, tags: ['r']}",
    );
    let usage = |name: &str| db.index_stats(DB, "t", name).unwrap().usage;
    let fresh = db.index_stats(DB, "t", "ia").unwrap();
    assert_eq!((fresh.entries, fresh.bytes), (None, None));
    assert_eq!(fresh.usage.ops(), 0);
    assert_eq!(fresh.usage.last_used_ms, None);

    // Point lookup on the full key: 2 entries.
    q(&db, "FROM t WHERE a = 1");
    let u = usage("ia");
    assert_eq!((u.lookups, u.scans, u.rows), (1, 0, 2));
    assert!(u.last_used_ms.is_some());
    // `IN`: every range is a point, still one lookup.
    q(&db, "FROM t WHERE a IN [1, 2, 9]");
    let u = usage("ia");
    assert_eq!((u.lookups, u.scans, u.rows), (2, 0, 5));
    // A range is a scan.
    q(&db, "FROM t WHERE a > 1");
    let u = usage("ia");
    assert_eq!((u.lookups, u.scans, u.rows), (2, 1, 7));
    // EXPLAIN, collection scans and other indexes do not count.
    q(&db, "EXPLAIN FROM t WHERE a = 1");
    q(&db, "FROM t WHERE z = 1");
    q(&db, "FROM t WHERE a = 1 OPTIONS (index = 'itags')");
    assert_eq!(usage("ia").ops(), 3);
    // The row source of a write counts.
    q(&db, "UPDATE t SET x = 1 WHERE a = 3");
    let u = usage("ia");
    assert_eq!((u.lookups, u.ops(), u.rows), (3, 4, 8));
    // Multikey: entries read before deduplication (doc 1 matches through two elements).
    q(&db, "FROM t WHERE tags IN ['p', 'q']");
    let t = usage("itags");
    assert_eq!((t.lookups, t.scans, t.rows), (1, 0, 3));
    assert_eq!(usage("ia").ops(), 4);

    // Sizes come from `analyze` and match the index span.
    analyze(&db);
    let st = db.index_stats(DB, "t", "ia").unwrap();
    let spans = db.index_spans(DB, "t").unwrap();
    let entries = spans
        .iter()
        .find(|(d, _)| d.name == "ia")
        .map(|(_, n)| *n as u64);
    assert_eq!(st.entries, entries);
    assert!(st.bytes.unwrap() > 0);
    assert_eq!(st.usage.ops(), 4);

    // Dropping forgets the counters; a new index of the same name starts from zero.
    q(&db, "DROP INDEX t.ia");
    assert_eq!(
        db.index_stats(DB, "t", "ia").unwrap_err().code(),
        ErrorCode::IndexNotFound
    );
    q(&db, "CREATE INDEX ia ON t (a)");
    let again = db.index_stats(DB, "t", "ia").unwrap();
    assert_eq!(again.usage.ops(), 0);
    assert_eq!(again.entries, None);
    assert_eq!(
        db.index_stats(DB, "nope", "ia").unwrap_err().code(),
        ErrorCode::NotFound
    );
}
