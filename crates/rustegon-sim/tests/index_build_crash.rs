// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Crash atomicity of the online index build (FR-IDX-003; AC-IDX-003, TC-IDX-003 crash part).
//!
//! A build interleaved with writes runs on `SimFileSystem`, which halts at every mutating
//! file-system operation in turn and then crashes in every [`CrashMode`] (pattern of
//! `rustegon-txn/tests/crash.rs`). After reopening (clock far ahead, so interrupted
//! transactions' records have expired) the unfinished builds are resumed from their checkpoints
//! and the result must be:
//! - scenario `plain`: no index (crash before the DDL committed) or a public index equal to the
//!   documents;
//! - scenario `unique_failure` (existing data holds a duplicate): no live index, and no entry
//!   left in the dropped index's span — whether the crash hit the build, its failure or its
//!   cleanup.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{path::Path, sync::Arc, time::Duration};

use rustegon_catalog::{DatabaseOptions, IndexField, IndexSpec};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_index::{BuildConfig, BuildStep};
use rustegon_sim::{
    CrashMode, SimFileSystem,
    workload::{
        clock::SimClock,
        index_build::{COLL, DB, INDEX, Model, check_no_orphans, user_part, verify_index},
        rng::SimRng,
    },
};

const T0: Duration = Duration::from_secs(1_000_000);
const IDS: i64 = 8;

fn open_at(fs: &Arc<SimFileSystem>, start: Duration) -> Result<EmbeddedDb, Error> {
    EmbeddedDb::open(
        Arc::clone(fs) as Arc<dyn rustegon_sim_api::FileSystem>,
        Path::new("/store"),
        Arc::new(SimClock::new(
            start,
            Duration::from_micros(10),
            Duration::from_micros(10),
        )),
        Arc::new(SimRng::new(start.as_secs())),
    )
}

fn doc(id: i64, a: Value, u: i64) -> Document {
    Document::try_from_fields(vec![
        ("_id".to_owned(), Value::Int64(id)),
        ("a".to_owned(), a),
        ("u".to_owned(), Value::Int64(u)),
    ])
    .unwrap()
}

fn arr(v: &[i64]) -> Value {
    Value::Array(v.iter().map(|i| Value::Int64(*i)).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Plain,
    UniqueFailure,
}

/// The store with its database and documents, before any crash point matters.
fn bootstrapped(scenario: Scenario) -> Arc<SimFileSystem> {
    let fs = Arc::new(SimFileSystem::new());
    let db = open_at(&fs, T0).unwrap();
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    for id in 0..5 {
        // Unique scenario: u = 1 twice (documents 1 and 4), never changed by the writes.
        let u = if scenario == Scenario::UniqueFailure && id == 4 {
            1
        } else {
            id
        };
        let a = if id % 2 == 0 {
            Value::Int64(id)
        } else {
            arr(&[id, 9])
        };
        db.insert(DB, COLL, &doc(id, a, u)).unwrap();
    }
    drop(db);
    fs
}

/// The build with writes between its steps; returns early with the first error (the halted
/// file system makes every later operation fail).
fn run(fs: &Arc<SimFileSystem>, scenario: Scenario) -> Result<(), Error> {
    let db = open_at(fs, T0 + Duration::from_secs(60))?;
    let (field, unique) = match scenario {
        Scenario::Plain => ("a", false),
        Scenario::UniqueFailure => ("u", true),
    };
    let mut spec = IndexSpec::new(INDEX, vec![IndexField::asc(field)]);
    spec.unique = unique;
    let config = BuildConfig {
        batch_docs: 2,
        cleanup_batch_keys: 1,
        ..BuildConfig::default()
    };
    let mut build = db.start_index_build(DB, COLL, &spec, &config)?;
    let mut i = 0i64;
    loop {
        // One write between steps: insert, replace (array ↔ scalar), delete.
        match i % 3 {
            0 => {
                db.insert(DB, COLL, &doc(5 + i % 3, arr(&[i, i + 1]), 100 + i))
                    .map(|_| ())
                    .or_else(|e| {
                        if e.code() == ErrorCode::DuplicateKey {
                            Ok(())
                        } else {
                            Err(e)
                        }
                    })?;
            }
            1 => {
                let d = doc(0, Value::Int64(i), 200 + i);
                db.replace(DB, COLL, &Value::Int64(0), &d).map(|_| ())?;
            }
            _ => {
                db.delete(DB, COLL, &Value::Int64(2)).map(|_| ())?;
            }
        }
        i += 1;
        match db.step_index_build(&mut build)? {
            BuildStep::Continue { .. } => {}
            BuildStep::Public(_) | BuildStep::Abandoned(_) => return Ok(()),
        }
    }
}

fn check(fs: &Arc<SimFileSystem>, scenario: Scenario, ctx: &str) {
    let db = open_at(fs, T0 + Duration::from_secs(7200))
        .unwrap_or_else(|e| panic!("{ctx}: reopen failed: {e}"));
    let results = db
        .resume_index_builds(&BuildConfig::default())
        .unwrap_or_else(|e| panic!("{ctx}: resume failed: {e}"));
    let mut model = Model::new();
    for id in 0..IDS {
        if let Some(d) = db.get(DB, COLL, &Value::Int64(id)).unwrap() {
            model.insert(id, user_part(&d));
        }
    }
    let live = db.list_indexes(DB, COLL).unwrap();
    match scenario {
        Scenario::Plain => {
            assert!(results.iter().all(Result::is_ok), "{ctx}: {results:?}");
            if live.is_empty() {
                check_no_orphans(&db).unwrap_or_else(|e| panic!("{ctx}: {e}"));
            } else {
                verify_index(&db, "a", false, &model, true)
                    .unwrap_or_else(|e| panic!("{ctx}: {e}"));
            }
        }
        Scenario::UniqueFailure => {
            for r in &results {
                let e = r.as_ref().expect_err(ctx);
                assert_eq!(e.code(), ErrorCode::IndexBuildFailed, "{ctx}: {e}");
            }
            assert!(live.is_empty(), "{ctx}: {live:?}");
            check_no_orphans(&db).unwrap_or_else(|e| panic!("{ctx}: {e}"));
        }
    }
}

fn crash_every_point(scenario: Scenario) {
    let fs = bootstrapped(scenario);
    let start = fs.op_count();
    run(&fs, scenario).unwrap();
    let total = fs.op_count() - start;
    assert!(total > 20, "only {total} crash points");
    eprintln!(
        "{scenario:?}: {total} crash points x {} modes",
        CrashMode::ALL.len()
    );
    for point in 0..total {
        for mode in CrashMode::ALL {
            let fs = bootstrapped(scenario);
            fs.halt_after_ops(point);
            let result = run(&fs, scenario);
            assert!(fs.is_halted(), "point {point} did not halt ({result:?})");
            fs.crash(point, mode);
            check(
                &fs,
                scenario,
                &format!("{scenario:?} point {point}/{total} {mode:?}"),
            );
        }
    }
}

#[test]
fn tc_idx_003_crash_at_every_fs_op_during_build_resumes_to_equivalence() {
    crash_every_point(Scenario::Plain);
}

#[test]
fn tc_idx_003_crash_at_every_fs_op_during_failing_unique_build_cleans_up() {
    crash_every_point(Scenario::UniqueFailure);
}
