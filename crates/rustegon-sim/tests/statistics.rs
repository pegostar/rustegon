// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The statistics job end to end through the embedded API on `SimFileSystem` (M3 wave 2
//! lane G; query-engine.md §2, §2.1, §8): TC-STAT-006 (*Provisional (PD pending)* id) and the
//! size part of TC-IDX-007 (FR-IDX-004, AC-IDX-004: index entries and bytes match the actual
//! index contents).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cast_precision_loss)]

use std::{ops::Bound, path::Path, sync::Arc};

use rustegon_catalog::{DatabaseOptions, IndexField, IndexSpec};
use rustegon_common::ErrorCode;
use rustegon_doc::{Document, Value};
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_query::stats::{Predicate, StatsConfig, estimate_rows};
use rustegon_sim::{SimFileSystem, workload::rng::SimRng};
use rustegon_sim_api::SystemClock;

const DB: &str = "shop";
const COLL: &str = "orders";

fn open() -> EmbeddedDb {
    let db = EmbeddedDb::open(
        Arc::new(SimFileSystem::new()),
        Path::new("/store"),
        Arc::new(SystemClock::new()),
        Arc::new(SimRng::new(11)),
    )
    .unwrap();
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    db
}

fn doc(fields: Vec<(&str, Value)>) -> Document {
    Document::try_from_fields(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect()).unwrap()
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

fn order(i: i64) -> Document {
    let status = match i % 10 {
        0..=5 => "done",
        6..=8 => "new",
        _ => "void",
    };
    let mut fields = vec![
        ("_id", Value::Int64(i)),
        ("status", s(status)),
        ("total", Value::Int64(i * 3 % 1000)),
    ];
    if i % 4 != 0 {
        let tags = (0..i % 3)
            .map(|t| s(&format!("t{}", (i + t) % 5)))
            .collect();
        fields.push(("tags", Value::Array(tags)));
    }
    doc(fields)
}

#[test]
fn tc_stat_006_analyze_end_to_end_and_tc_idx_007_index_sizes() {
    let db = open();
    let by_status = db
        .create_index(
            DB,
            COLL,
            &IndexSpec::new("by_status", vec![IndexField::asc("status")]),
        )
        .unwrap();
    let by_tags = db
        .create_index(
            DB,
            COLL,
            &IndexSpec::new("by_tags", vec![IndexField::asc("tags")]),
        )
        .unwrap();
    for i in 0..300 {
        db.insert(DB, COLL, &order(i)).unwrap();
    }
    // Missing collection → RGN-1030.
    let err = db.analyze(DB, "nope", &StatsConfig::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert!(db.collection_stats(DB, COLL).unwrap().is_none());

    let first = db.analyze(DB, COLL, &StatsConfig::default()).unwrap();
    assert!(first.previous.is_none());
    assert!(
        first.invalidate_plans,
        "no statistics before: plans must be (re)built"
    );
    let stats = &first.stats;
    assert_eq!(stats.row_count, 300);
    assert_eq!(stats.sample_rows, 300);
    assert!(stats.avg_doc_size() > 20.0);
    // Indexed paths first, then discovered top-level fields (system fields skipped).
    let paths: Vec<&str> = stats.fields.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["status", "tags", "_id", "total"]);
    let st = stats.field("status").unwrap();
    assert!(st.indexed);
    assert_eq!(st.ndv, 3);
    let tags = stats.field("tags").unwrap();
    assert_eq!(tags.rows_missing, 75);
    assert_eq!(tags.rows_array, 225);

    // Stored record == returned statistics.
    assert_eq!(db.collection_stats(DB, COLL).unwrap().as_ref(), Some(stats));

    // TC-IDX-007 (sizes): entries equal the actual index contents.
    let actual = |name: &str| {
        db.index_scan(DB, COLL, name, Bound::Unbounded, Bound::Unbounded)
            .unwrap()
            .len() as u64
    };
    for (ix, name) in [(&by_status, "by_status"), (&by_tags, "by_tags")] {
        let size = stats.indexes.iter().find(|s| s.index_id == ix.id).unwrap();
        assert_eq!(size.entries, actual(name), "{name}");
        assert!(
            size.bytes >= size.entries * 10,
            "{name}: {} bytes",
            size.bytes
        );
    }

    // Estimates from the stored statistics vs the truth.
    let truth = (0..300).filter(|i| (6..=8).contains(&(i % 10))).count() as f64;
    let est = estimate_rows(
        stats,
        &Predicate::Eq {
            path: "status".into(),
            value: s("new"),
        },
    );
    assert!(
        (est - truth).abs() < 1e-9,
        "full-sample MCV is exact: {est} vs {truth}"
    );

    // Unchanged data: no invalidation; > 20 % more rows: invalidation.
    let again = db.analyze(DB, COLL, &StatsConfig::default()).unwrap();
    assert_eq!(again.previous.as_ref().map(|p| p.row_count), Some(300));
    assert!(!again.invalidate_plans);
    for i in 300..400 {
        db.insert(DB, COLL, &order(i)).unwrap();
    }
    let grown = db.analyze(DB, COLL, &StatsConfig::default()).unwrap();
    assert_eq!(grown.stats.row_count, 400);
    assert!(grown.invalidate_plans);

    // Invalid settings are rejected before any work.
    let bad = StatsConfig {
        histogram_buckets: 0,
        ..StatsConfig::default()
    };
    assert_eq!(
        db.analyze(DB, COLL, &bad).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}
