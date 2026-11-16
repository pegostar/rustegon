// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Cost-based access-path choice (M3 wave 3 lane J; FR-QL-001 optimizer, query-engine.md §3,
//! *Provisional (PD-040)*): plan choice on skewed statistics (MCV-heavy value → scan, rare value
//! → index, range selectivity, sort elimination vs cost, covered and partial indexes), the
//! fallback to the rule-based chooser, and the estimates exposed for EXPLAIN.
//!
//! Statistics are built with the real [`StatsCollector`] over generated documents (full scan,
//! so MCV fractions are exact); the catalog is an in-memory fixture.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustegon_catalog::{
    CollectionDescriptor, CollectionKind, CollectionOptions, DatabaseDescriptor, DatabaseOptions,
    DescriptorState, IndexDescriptor, IndexField, IndexKind, IndexOrigin, IndexScope, IndexState,
    ShardKey, ShardStrategy,
};
use rustegon_doc::{Document, Value};
use rustegon_query::{
    ExecResult, Params,
    bind::{Binder, BoundQuery, BoundStatement, CatalogView},
    parse_statement,
    plan::{
        AccessPath, CostBasedChooser, OrderStrategy, PhysicalPlan, RuleBasedChooser, plan_query,
    },
    stats::{CollectionStats, CostConfig, StatsCollector, StatsConfig},
};

const ROWS: i64 = 5000;
/// Encoded size given to the collector per document (250 B: ~77 pages of 16 KiB in total).
const DOC_BYTES: usize = 250;
const COLL_ID: u32 = 10;

fn ix(id: u32, name: &str, field: &str) -> IndexDescriptor {
    IndexDescriptor {
        id,
        database_id: 1,
        collection_id: COLL_ID,
        name: name.to_owned(),
        kind: IndexKind::Secondary,
        fields: vec![IndexField::asc(field)],
        unique: false,
        sparse: false,
        partial: None,
        hidden: false,
        scope: IndexScope::Global,
        state: IndexState::Public,
        origin: IndexOrigin::Manual,
        version: 1,
        include: Vec::new(),
        multikey: false,
        created_at_ms: 0,
    }
}

fn indexes() -> Vec<IndexDescriptor> {
    let mut partial = ix(103, "ik", "b");
    partial.partial = Some("k = 1".into());
    let mut cov = ix(104, "cov", "c");
    cov.include = vec!["c".into(), "n".into()];
    vec![
        ix(100, "by_status", "status"),
        ix(101, "by_n", "n"),
        ix(102, "ib", "b"),
        partial,
        cov,
    ]
}

struct Fixture;

impl CatalogView for Fixture {
    fn database(&mut self, name: &str) -> ExecResult<Option<DatabaseDescriptor>> {
        Ok((name == "shop").then(|| DatabaseDescriptor {
            id: 1,
            name: "shop".into(),
            version: 1,
            state: DescriptorState::Public,
            options: DatabaseOptions::default(),
        }))
    }

    fn collection(
        &mut self,
        _db: &DatabaseDescriptor,
        name: &str,
    ) -> ExecResult<Option<CollectionDescriptor>> {
        Ok((name == "t").then(|| CollectionDescriptor {
            id: COLL_ID,
            database_id: 1,
            name: "t".into(),
            kind: CollectionKind::Document,
            version: 1,
            state: DescriptorState::Public,
            shard_key: ShardKey {
                strategy: ShardStrategy::Hashed,
                fields: vec!["_id".into()],
            },
            options: CollectionOptions::default(),
        }))
    }

    fn indexes(&mut self, _coll: &CollectionDescriptor) -> ExecResult<Vec<IndexDescriptor>> {
        Ok(indexes())
    }
}

/// Skewed data: `status` is `'a'` in 90 % of the rows and a unique `'s<i>'` otherwise; `n` is
/// uniform and unique; `b` has 1000 values of 5 rows; `c` 4 values of 25 %; `k` 2 values.
fn stats() -> CollectionStats {
    let paths: Vec<String> = indexes().iter().map(|i| i.fields[0].path.clone()).collect();
    let config = StatsConfig {
        sample_size: None,
        ..StatsConfig::default()
    };
    let mut c = StatsCollector::new(config, 1, COLL_ID, &paths);
    for i in 0..ROWS {
        let mut d = Document::new();
        d.insert("_id", Value::Int64(i));
        let status = if i % 10 == 0 {
            format!("s{i}")
        } else {
            "a".to_owned()
        };
        d.insert("status", Value::String(status));
        d.insert("n", Value::Int64(i));
        d.insert("b", Value::Int64(i % 1000));
        d.insert("c", Value::Int64(i % 4));
        d.insert("k", Value::Int64(i % 2));
        c.add_document(&d, DOC_BYTES);
    }
    c.finish(0)
}

fn bind(text: &str) -> BoundQuery {
    let stmt = parse_statement(text).unwrap();
    let p = Params::new();
    let mut catalog = Fixture;
    let mut binder = Binder {
        catalog: &mut catalog,
        session_db: "shop",
        params: &p,
    };
    match binder.bind(&stmt).unwrap() {
        BoundStatement::Query(q) => q,
        other => panic!("{other:?}"),
    }
}

fn cbo(stats: Option<&CollectionStats>, text: &str) -> PhysicalPlan {
    plan_query(
        &bind(text),
        &CostBasedChooser::new(stats, CostConfig::default()),
    )
    .unwrap()
}

/// `"scan"` or the chosen index's name.
fn access(p: &PhysicalPlan) -> String {
    match &p.access {
        AccessPath::CollectionScan => "scan".into(),
        AccessPath::IndexScan { index, .. } => index.name.clone(),
        other => format!("{other:?}"),
    }
}

#[test]
fn tc_ql_001_cbo_mcv_heavy_value_scans_rare_value_uses_index() {
    let s = stats();
    assert_eq!(
        access(&cbo(Some(&s), "FROM t WHERE status = 'a' SELECT VALUE _id")),
        "scan"
    );
    assert_eq!(
        access(&cbo(
            Some(&s),
            "FROM t WHERE status = 's10' SELECT VALUE _id"
        )),
        "by_status"
    );
    // The rule-based chooser takes the index for both.
    let rule = plan_query(
        &bind("FROM t WHERE status = 'a' SELECT VALUE _id"),
        &RuleBasedChooser,
    )
    .unwrap();
    assert_eq!(access(&rule), "by_status");
}

#[test]
fn tc_ql_001_cbo_range_selectivity() {
    let s = stats();
    assert_eq!(access(&cbo(Some(&s), "FROM t WHERE n > 4990")), "by_n");
    assert_eq!(
        access(&cbo(Some(&s), "FROM t WHERE n >= 1000 AND n < 1010")),
        "by_n"
    );
    assert_eq!(access(&cbo(Some(&s), "FROM t WHERE n > 100")), "scan");
    assert_eq!(access(&cbo(Some(&s), "FROM t WHERE n < 4000")), "scan");
}

#[test]
fn tc_ql_001_cbo_sort_elimination_vs_cost() {
    let s = stats();
    // A small LIMIT stops the ordered index scan after a few fetches: cheaper than scan + TopK.
    let p = cbo(Some(&s), "FROM t ORDER BY n LIMIT 5");
    assert_eq!(access(&p), "by_n");
    assert!(matches!(p.order, OrderStrategy::IndexOrder(_)), "{p:?}");
    // Without a LIMIT every row is fetched randomly: scan + sort is cheaper.
    let p = cbo(Some(&s), "FROM t ORDER BY n");
    assert_eq!(access(&p), "scan");
    assert!(matches!(p.order, OrderStrategy::Sort(_)), "{p:?}");
    // The rules always prefer the sort-satisfying index.
    let rule = plan_query(&bind("FROM t ORDER BY n"), &RuleBasedChooser).unwrap();
    assert_eq!(access(&rule), "by_n");
}

#[test]
fn tc_ql_001_cbo_covered_index_beats_scan_when_fetching_does_not() {
    let s = stats();
    let p = cbo(Some(&s), "FROM t WHERE c = 1 SELECT c, n");
    assert_eq!(access(&p), "cov");
    assert!(matches!(
        p.access,
        AccessPath::IndexScan { fetch: false, .. }
    ));
    // Same 25 % predicate, but `_id` is not covered: 1250 random fetches lose to the scan.
    assert_eq!(
        access(&cbo(Some(&s), "FROM t WHERE c = 1 SELECT VALUE _id")),
        "scan"
    );
}

#[test]
fn tc_ql_001_cbo_partial_index_only_when_applicable_and_then_preferred() {
    let s = stats();
    // The partial index holds only `k = 1` rows: fewer entries than the full index on `b`.
    assert_eq!(access(&cbo(Some(&s), "FROM t WHERE k = 1 AND b = 3")), "ik");
    // Not implied by the query: never chosen, whatever the cost.
    assert_eq!(access(&cbo(Some(&s), "FROM t WHERE b = 3")), "ib");
    assert_eq!(access(&cbo(Some(&s), "FROM t WHERE k = 0 AND b = 3")), "ib");
}

#[test]
fn tc_ql_001_cbo_falls_back_to_rules_without_usable_stats() {
    let s = stats();
    let mut empty = s.clone();
    empty.row_count = 0;
    let mut other = s.clone();
    other.collection_id = COLL_ID + 1;
    let texts = [
        "FROM t WHERE status = 'a' SELECT VALUE _id",
        "FROM t WHERE n > 100",
        "FROM t ORDER BY n",
        "FROM t WHERE c = 1 SELECT VALUE _id",
        "FROM t WHERE k = 1 AND b = 3",
        "FROM t WHERE _id = 3",
    ];
    for text in texts {
        let rule = plan_query(&bind(text), &RuleBasedChooser).unwrap();
        for st in [None, Some(&empty), Some(&other)] {
            let p = cbo(st, text);
            assert_eq!(p, rule, "{text}");
            assert!(p.estimate.is_none());
        }
    }
    // A forced index wins over the cost model, and is still estimated.
    let p = cbo(
        Some(&s),
        "FROM t WHERE status = 'a' OPTIONS (index = 'by_status')",
    );
    assert_eq!(access(&p), "by_status");
    assert!(p.estimate.is_some());
}

#[test]
fn tc_ql_006_cbo_estimates_for_explain() {
    let s = stats();
    let p = cbo(Some(&s), "FROM t WHERE status = 'a' SELECT VALUE _id");
    let e = p.estimate.unwrap();
    // Full-scan statistics: the MCV fraction is exact (4500 rows).
    assert!((e.filter_rows - 4500.0).abs() < 1.0, "{e:?}");
    assert!((e.est_rows - 4500.0).abs() < 1.0, "{e:?}");
    assert!((e.access_rows - 5000.0).abs() < 1e-9, "{e:?}");
    assert!(e.est_cost > 0.0);
    assert!((CostConfig::default().cost(&e.inputs) - e.est_cost).abs() < 1e-9);

    let p = cbo(Some(&s), "FROM t WHERE status = 'a' LIMIT 10 OFFSET 2");
    let e = p.estimate.unwrap();
    assert!((e.est_rows - 10.0).abs() < 1e-9, "{e:?}");

    let p = cbo(Some(&s), "FROM t WHERE false");
    let e = p.estimate.unwrap();
    assert!(matches!(p.access, AccessPath::Empty));
    assert!(e.est_rows.abs() < 1e-9 && e.est_cost.abs() < 1e-9, "{e:?}");

    let p = cbo(Some(&s), "FROM t WHERE _id IN [1, 2, 3]");
    assert!(matches!(p.access, AccessPath::PrimaryGet { .. }));
    assert!((p.estimate.unwrap().access_rows - 3.0).abs() < 1e-9);
}
