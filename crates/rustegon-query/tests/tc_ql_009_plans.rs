// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Golden plan tests (query-engine.md §11): binder, rule rewrites and access-path choice for a
//! fixed in-memory catalog. Each case of `tests/golden/plans.rgql` is bound and planned; the
//! logical and physical plans (or the bind error) are compared with the recorded sections.
//! Re-record with `RGQL_BLESS=1` and review the diff.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::golden;
use rustegon_catalog::{
    CollectionDescriptor, CollectionKind, CollectionOptions, DatabaseDescriptor, DatabaseOptions,
    DescriptorState, IndexDescriptor, IndexField, IndexKind, IndexOrigin, IndexScope, IndexState,
    ShardKey, ShardStrategy,
};
use rustegon_doc::Value;
use rustegon_query::{
    ExecResult, Params,
    bind::{Binder, BoundStatement, CatalogView, IndexHint},
    parse_statement,
    plan::{LogicalPlan, RuleBasedChooser, plan_query},
};

/// The catalog of the golden cases: database `shop` with
/// - `orders` (hashed `_id`): `by_status (status)`, `status_created (status ASC, createdAt
///   DESC)`, `tags (tags)` multikey, `sparse_x (x)` sparse, `paid_total (total)` partial
///   `status = 'paid'`, `hidden_h (h)` hidden, `attrs (attrs.**)` wildcard, `cov (sku)
///   include [sku, qty]`, `building (b)` not yet public;
/// - `events` (range-sharded `_id`), no index.
struct Fixture;

fn ix(id: u32, name: &str, fields: Vec<IndexField>) -> IndexDescriptor {
    IndexDescriptor {
        id,
        database_id: 1,
        collection_id: 10,
        name: name.to_owned(),
        kind: IndexKind::Secondary,
        fields,
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
    let mut tags = ix(102, "tags", vec![IndexField::asc("tags")]);
    tags.multikey = true;
    let mut sparse = ix(103, "sparse_x", vec![IndexField::asc("x")]);
    sparse.sparse = true;
    let mut paid = ix(104, "paid_total", vec![IndexField::asc("total")]);
    paid.partial = Some("status = 'paid'".into());
    let mut hidden = ix(105, "hidden_h", vec![IndexField::asc("h")]);
    hidden.hidden = true;
    let mut cov = ix(107, "cov", vec![IndexField::asc("sku")]);
    cov.include = vec!["sku".into(), "qty".into()];
    let mut building = ix(108, "building", vec![IndexField::asc("b")]);
    building.state = IndexState::Backfilling;
    vec![
        ix(100, "by_status", vec![IndexField::asc("status")]),
        ix(
            101,
            "status_created",
            vec![IndexField::asc("status"), IndexField::desc("createdAt")],
        ),
        tags,
        sparse,
        paid,
        hidden,
        ix(106, "attrs", vec![IndexField::asc("attrs.**")]),
        cov,
        building,
    ]
}

fn collection(id: u32, name: &str, strategy: ShardStrategy) -> CollectionDescriptor {
    CollectionDescriptor {
        id,
        database_id: 1,
        name: name.to_owned(),
        kind: CollectionKind::Document,
        version: 1,
        state: DescriptorState::Public,
        shard_key: ShardKey {
            strategy,
            fields: vec!["_id".into()],
        },
        options: CollectionOptions::default(),
    }
}

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
        Ok(match name {
            "orders" => Some(collection(10, "orders", ShardStrategy::Hashed)),
            "events" => Some(collection(11, "events", ShardStrategy::Range)),
            _ => None,
        })
    }

    fn indexes(&mut self, coll: &CollectionDescriptor) -> ExecResult<Vec<IndexDescriptor>> {
        Ok(if coll.id == 10 { indexes() } else { Vec::new() })
    }
}

fn params() -> Params {
    Params::new()
        .with("min", Value::Int64(10))
        .with("ids", Value::Array(vec![Value::Int64(3), Value::Int64(1)]))
        .with("s", Value::String("paid".into()))
}

fn produce(input: &str, tags: &[String]) -> Vec<(String, String)> {
    let stmt = match parse_statement(input) {
        Ok(s) => s,
        Err(e) => return vec![("error".into(), e.to_string())],
    };
    let p = params();
    let mut catalog = Fixture;
    let mut binder = Binder {
        catalog: &mut catalog,
        session_db: "shop",
        params: &p,
    };
    let bound = match binder.bind(&stmt) {
        Ok(b) => b,
        Err(e) => return vec![("error".into(), e.into_error().to_string())],
    };
    let mut query = match bound {
        BoundStatement::Query(q) => q,
        BoundStatement::Update(u) => u.source,
        BoundStatement::Delete(d) => d.source,
        other => return vec![("bound".into(), format!("{other:?}"))],
    };
    if tags.iter().any(|t| t == "collscan") {
        query.options.index = IndexHint::CollectionScan;
    }
    let physical = plan_query(&query, &RuleBasedChooser).unwrap();
    vec![
        ("logical".into(), LogicalPlan::of(&query).render()),
        ("physical".into(), physical.render()),
    ]
}

#[test]
fn tc_ql_009_plan_golden_corpus() {
    let cases = golden::load("plans.rgql");
    assert!(
        cases.len() >= 40,
        "golden corpus too small: {}",
        cases.len()
    );
    let produced: Vec<_> = cases.iter().map(|c| produce(&c.input, &c.tags)).collect();
    let failures = golden::check("plans.rgql", &cases, &produced);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
