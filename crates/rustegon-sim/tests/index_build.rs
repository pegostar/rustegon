// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Online index build job through the embedded API (FR-IDX-003; TC-IDX-002, TC-IDX-003 per
//! indexing.md §11 — unique enforcement under concurrent inserts — plus the abort/cancel
//! atomicity of AC-IDX-003; the crash part is in `index_build_crash.rs`).
//!
//! The final state is always checked with `verify_index` / `check_no_orphans` of the
//! `index_build` workload: index scan == filtered collection scan, entry counts per document,
//! multikey flag, unique values distinct, no entry left in a dropped index.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::{
    collections::BTreeSet,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rustegon_catalog::{
    CollectionSpec, DatabaseOptions, IndexField, IndexSpec, IndexState, ShardKey, ShardStrategy,
};
use rustegon_common::ErrorCode;
use rustegon_doc::{Document, Value};
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_index::{BuildConfig, BuildStep, IndexBuild};
use rustegon_sim::{
    CrashMode, SimFileSystem,
    workload::{
        clock::SimClock,
        index_build::{
            COLL, DB, INDEX, IndexBuildConfig, Model, check_no_orphans, is_array, rand_doc,
            run_index_build, user_part, verify_index,
        },
        rng::SimRng,
    },
};
use rustegon_sim_api::SystemClock;

/// A store on the simulated clock. The tests drive one thread without the workload's
/// scheduler steps, so the clock never switches to its stall tick (time would otherwise race
/// ahead of the transactions' heartbeats).
fn open_at(fs: &Arc<SimFileSystem>, start: Duration, seed: u64) -> EmbeddedDb {
    EmbeddedDb::open(
        Arc::clone(fs) as Arc<dyn rustegon_sim_api::FileSystem>,
        Path::new("/store"),
        Arc::new(SimClock::new(
            start,
            Duration::from_micros(10),
            Duration::from_micros(10),
        )),
        Arc::new(SimRng::new(seed)),
    )
    .unwrap()
}

fn fresh(seed: u64) -> (Arc<SimFileSystem>, EmbeddedDb) {
    let fs = Arc::new(SimFileSystem::new());
    let db = open_at(&fs, Duration::from_secs(1_000_000), seed);
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    (fs, db)
}

fn int(i: i64) -> Value {
    Value::Int64(i)
}

fn with_id(id: i64, d: &Document) -> Document {
    let mut d = d.clone();
    d.insert("_id", int(id));
    d
}

fn doc(fields: Vec<(&str, Value)>) -> Document {
    Document::try_from_fields(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect()).unwrap()
}

/// Inserts `n` random documents (ids `0..n`) and returns the model.
fn populate(db: &EmbeddedDb, r: &SimRng, n: i64, unique_u: bool) -> Model {
    let mut model = Model::new();
    for id in 0..n {
        let d = if unique_u {
            doc(vec![("a", int(id % 3)), ("u", int(id))])
        } else {
            rand_doc(r, 8, true)
        };
        let stored = db.insert(DB, COLL, &with_id(id, &d)).unwrap();
        model.insert(id, user_part(&stored));
    }
    model
}

/// One random write on ids `0..space`, applied to `model` when it commits.
fn random_write(db: &EmbeddedDb, r: &SimRng, model: &mut Model, space: u64) {
    let id = i64::try_from(r.below(space)).unwrap();
    let d = rand_doc(r, 8, true);
    let result = if model.contains_key(&id) {
        if r.chance(300) {
            db.delete(DB, COLL, &int(id)).map(|_| None)
        } else {
            db.replace(DB, COLL, &int(id), &d).map(Some)
        }
    } else {
        db.insert(DB, COLL, &with_id(id, &d)).map(Some)
    };
    match result.unwrap() {
        Some(stored) => model.insert(id, user_part(&stored)),
        None => model.remove(&id),
    };
}

fn spec_a() -> IndexSpec {
    IndexSpec::new(INDEX, vec![IndexField::asc("a")])
}

fn small_batches(batch_docs: usize) -> BuildConfig {
    BuildConfig {
        batch_docs,
        cleanup_batch_keys: 2,
        ..BuildConfig::default()
    }
}

/// Steps `build` to its end, retrying steps that lost to concurrent writers too often.
fn drive(db: &EmbeddedDb, build: &mut IndexBuild) -> Result<(), rustegon_common::Error> {
    let mut errors = 0;
    loop {
        match db.step_index_build(build) {
            Ok(BuildStep::Continue { .. }) => {}
            Ok(BuildStep::Public(_)) => return Ok(()),
            Ok(BuildStep::Abandoned(e)) => return Err(e),
            Err(e) => {
                errors += 1;
                assert!(errors < 100, "step keeps failing: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// TC-IDX-002: the job's phases, checkpoints, throttling and resumption.

#[test]
fn tc_idx_002_build_walks_every_state_in_batches() {
    let (_fs, db) = fresh(1);
    let model = populate(&db, &SimRng::new(1), 10, false);
    let config = BuildConfig {
        batch_docs: 3,
        max_docs_per_sec: 100,
        ..BuildConfig::default()
    };
    let mut build = db.start_index_build(DB, COLL, &spec_a(), &config).unwrap();
    assert_eq!(
        db.list_indexes(DB, COLL).unwrap()[0].state,
        IndexState::DeleteOnly
    );
    let mut states = Vec::new();
    let mut backfill_pauses = Vec::new();
    loop {
        match db.step_index_build(&mut build).unwrap() {
            BuildStep::Continue { progress, pause } => {
                if progress.docs_scanned > states.last().map_or(0, |(_, d)| *d) {
                    backfill_pauses.push(pause);
                }
                states.push((progress.state, progress.docs_scanned));
            }
            BuildStep::Public(ix) => {
                assert_eq!(ix.state, IndexState::Public);
                break;
            }
            BuildStep::Abandoned(e) => panic!("{e}"),
        }
    }
    // DeleteOnly → WriteOnly → Backfilling ×3 (3+3+3 docs) → the batch reaching the end moves
    // to Validating → Public.
    let walked: Vec<IndexState> = states.iter().map(|(s, _)| *s).collect();
    assert_eq!(
        walked,
        [
            IndexState::WriteOnly,
            IndexState::Backfilling,
            IndexState::Backfilling,
            IndexState::Backfilling,
            IndexState::Backfilling,
            IndexState::Validating,
        ],
        "{states:?}"
    );
    assert_eq!(states.last().unwrap().1, 10);
    // Throttling: 3 documents at 100 docs/s owe 30 ms.
    assert_eq!(backfill_pauses[0], Duration::from_millis(30));
    let ever = model.values().any(|d| is_array(d, "a"));
    verify_index(&db, "a", false, &model, ever).unwrap();
    // The job record is gone.
    assert!(db.pending_index_builds(&config).unwrap().is_empty());
}

#[test]
fn tc_idx_002_resume_after_reopen_continues_from_checkpoint() {
    let (fs, db) = fresh(2);
    let model = populate(&db, &SimRng::new(2), 20, false);
    let config = small_batches(2);
    let mut build = db.start_index_build(DB, COLL, &spec_a(), &config).unwrap();
    let mut scanned = 0;
    while scanned < 6 {
        if let BuildStep::Continue { progress, .. } = db.step_index_build(&mut build).unwrap() {
            scanned = progress.docs_scanned;
        }
    }
    drop(db);
    fs.crash(7, CrashMode::Clean);
    let db = open_at(&fs, Duration::from_secs(2_000_000), 3);
    let mut pending = db.pending_index_builds(&config).unwrap();
    assert_eq!(pending.len(), 1);
    let mut build = pending.pop().unwrap();
    match db.step_index_build(&mut build).unwrap() {
        BuildStep::Continue { progress, .. } => {
            assert_eq!(progress.state, IndexState::Backfilling);
            assert_eq!(
                progress.docs_scanned,
                scanned + 2,
                "resumed from the checkpoint"
            );
        }
        other => panic!("{other:?}"),
    }
    let results = db.resume_index_builds(&config).unwrap();
    assert!(matches!(results.as_slice(), [Ok(_)]), "{results:?}");
    verify_index(&db, "a", false, &model, true).unwrap();
}

#[test]
fn tc_idx_002_deterministic_writes_between_every_step() {
    // Phases (state before the next step) in which writes happened, over all seeds.
    let mut written_in = BTreeSet::new();
    for seed in 0..40u64 {
        let (_fs, db) = fresh(seed);
        let r = SimRng::new(seed);
        let mut model = populate(&db, &r, 25, false);
        let config = small_batches(1 + usize::try_from(seed % 4).unwrap());
        let mut build = db.start_index_build(DB, COLL, &spec_a(), &config).unwrap();
        let mut ever = model.values().any(|d| is_array(d, "a"));
        let mut state = IndexState::DeleteOnly;
        loop {
            for _ in 0..r.below(4) {
                random_write(&db, &r, &mut model, 40);
                ever |= model.values().any(|d| is_array(d, "a"));
                written_in.insert(format!("{state:?}"));
            }
            match db.step_index_build(&mut build).unwrap() {
                BuildStep::Continue { progress, .. } => state = progress.state,
                BuildStep::Public(_) => break,
                BuildStep::Abandoned(e) => panic!("seed {seed}: {e}"),
            }
        }
        for _ in 0..10 {
            random_write(&db, &r, &mut model, 40);
            ever |= model.values().any(|d| is_array(d, "a"));
        }
        verify_index(&db, "a", false, &model, ever).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
    }
    assert_eq!(
        written_in.into_iter().collect::<Vec<_>>(),
        ["Backfilling", "DeleteOnly", "Validating", "WriteOnly"],
    );
}

#[test]
fn tc_idx_002_concurrent_writer_threads_during_build() {
    const THREADS: i64 = 4;
    const IDS_PER_THREAD: i64 = 15;
    let fs = Arc::new(SimFileSystem::new());
    let db = Arc::new(
        EmbeddedDb::open(
            fs,
            Path::new("/store"),
            Arc::new(SystemClock::new()),
            Arc::new(SimRng::new(5)),
        )
        .unwrap(),
    );
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    let mut model = populate(&db, &SimRng::new(5), THREADS * IDS_PER_THREAD, false);
    let done = Arc::new(AtomicBool::new(false));
    let writers: Vec<_> = (0..THREADS)
        .map(|t| {
            let db = Arc::clone(&db);
            let done = Arc::clone(&done);
            // Each thread owns its ids, so its part of the model is exact.
            let mut own: Model = model
                .iter()
                .filter(|(id, _)| **id / IDS_PER_THREAD == t)
                .map(|(id, d)| (*id, d.clone()))
                .collect();
            std::thread::spawn(move || {
                let r = SimRng::new(100 + u64::try_from(t).unwrap());
                let mut extra = 0;
                while !done.load(Ordering::SeqCst) || extra < 20 {
                    if done.load(Ordering::SeqCst) {
                        extra += 1;
                    }
                    let id = t * IDS_PER_THREAD
                        + i64::try_from(r.below(u64::try_from(IDS_PER_THREAD).unwrap())).unwrap();
                    let d = rand_doc(&r, 8, true);
                    let res = if own.contains_key(&id) && r.chance(300) {
                        db.delete(DB, COLL, &int(id)).map(|_| None)
                    } else if own.contains_key(&id) {
                        db.replace(DB, COLL, &int(id), &d).map(Some)
                    } else {
                        db.insert(DB, COLL, &with_id(id, &d)).map(Some)
                    };
                    match res {
                        Ok(Some(s)) => {
                            own.insert(id, user_part(&s));
                        }
                        Ok(None) => {
                            own.remove(&id);
                        }
                        // Lost too many conflicts: nothing committed, the model stays.
                        Err(e) => assert!(e.retryable(), "{e}"),
                    }
                }
                own
            })
        })
        .collect();
    let mut build = db
        .start_index_build(DB, COLL, &spec_a(), &small_batches(4))
        .unwrap();
    drive(&db, &mut build).unwrap();
    done.store(true, Ordering::SeqCst);
    model.clear();
    for w in writers {
        model.extend(w.join().unwrap());
    }
    verify_index(&db, "a", false, &model, true).unwrap();
}

// ---------------------------------------------------------------------------------------------
// TC-IDX-003 (indexing.md §11): unique enforcement under concurrent inserts during a build.

#[test]
fn tc_idx_003_unique_build_fails_on_duplicate_inserted_during_write_only() {
    let (_fs, db) = fresh(6);
    populate(&db, &SimRng::new(6), 8, true);
    let spec = IndexSpec::new(INDEX, vec![IndexField::asc("u")]).unique();
    let mut build = db
        .start_index_build(DB, COLL, &spec, &small_batches(1))
        .unwrap();
    assert!(matches!(
        db.step_index_build(&mut build).unwrap(),
        BuildStep::Continue { .. }
    ));
    // WriteOnly: u = 3 is owned by document 3, which the backfill has not reached; the writer
    // finds no entry and commits a real duplicate.
    db.insert(DB, COLL, &doc(vec![("_id", int(100)), ("u", int(3))]))
        .unwrap();
    let err = drive(&db, &mut build).unwrap_err();
    assert_eq!(err.code(), ErrorCode::IndexBuildFailed, "{err}");
    let offending = err.details().get("offending_ids").unwrap();
    assert!(
        offending.contains('3') || offending.contains("100"),
        "{offending}"
    );
    assert_eq!(db.list_indexes(DB, COLL).unwrap(), Vec::new());
    check_no_orphans(&db).unwrap();
    // Once the duplicate is gone the index builds, and then rejects duplicates.
    db.delete(DB, COLL, &int(100)).unwrap();
    db.create_index(DB, COLL, &spec).unwrap();
    let dup = db
        .insert(DB, COLL, &doc(vec![("_id", int(101)), ("u", int(3))]))
        .unwrap_err();
    assert_eq!(dup.code(), ErrorCode::DuplicateKey);
}

#[test]
fn tc_idx_003_unique_delete_never_removes_another_documents_entry() {
    let (_fs, db) = fresh(7);
    // Range shard key on `_id`: documents are backfilled in `_id` order, so the test controls
    // which document the cursor has passed.
    let mut spec = CollectionSpec::document(COLL);
    spec.shard_key = ShardKey {
        strategy: ShardStrategy::Range,
        fields: vec!["_id".into()],
    };
    db.create_collection(DB, &spec).unwrap();
    let mut model = populate(&db, &SimRng::new(7), 8, true);
    let spec = IndexSpec::new(INDEX, vec![IndexField::asc("u")]).unique();
    let mut build = db
        .start_index_build(DB, COLL, &spec, &small_batches(1))
        .unwrap();
    db.step_index_build(&mut build).unwrap(); // → WriteOnly
    // Document -5 takes u = 7 while document 7 (not backfilled yet) still has it.
    let s = db
        .insert(DB, COLL, &doc(vec![("_id", int(-5)), ("u", int(7))]))
        .unwrap();
    model.insert(-5, user_part(&s));
    db.step_index_build(&mut build).unwrap(); // → Backfilling
    db.step_index_build(&mut build).unwrap(); // batch 1: document -5 (cursor passes it)
    // Document 7 moves away from u = 7: its writer must not delete the entry of document -5,
    // which the backfill will never revisit.
    let s = db
        .replace(DB, COLL, &int(7), &doc(vec![("a", int(0)), ("u", int(77))]))
        .unwrap();
    model.insert(7, user_part(&s));
    drive(&db, &mut build).unwrap();
    verify_index(&db, "u", true, &model, false).unwrap();
}
#[test]
fn tc_idx_003_concurrent_conflicting_inserts_fail_build_or_never_duplicate() {
    for round in 0..6u64 {
        let fs = Arc::new(SimFileSystem::new());
        let db = Arc::new(
            EmbeddedDb::open(
                fs,
                Path::new("/store"),
                Arc::new(SystemClock::new()),
                Arc::new(SimRng::new(round)),
            )
            .unwrap(),
        );
        db.create_database(DB, &DatabaseOptions::default()).unwrap();
        let mut model = populate(&db, &SimRng::new(round), 40, true);
        let threads: Vec<_> = (0..3i64)
            .map(|t| {
                let db = Arc::clone(&db);
                std::thread::spawn(move || {
                    let r = SimRng::new(round * 10 + u64::try_from(t).unwrap());
                    let mut won = Model::new();
                    for i in 0..30 {
                        let id = 1000 + t * 100 + i;
                        // Values 40..80 collide between threads, 0..40 with existing documents.
                        let u = int(i64::try_from(r.below(80)).unwrap());
                        match db.insert(DB, COLL, &doc(vec![("_id", int(id)), ("u", u)])) {
                            Ok(s) => {
                                won.insert(id, user_part(&s));
                            }
                            Err(e) => {
                                assert!(
                                    e.code() == ErrorCode::DuplicateKey || e.retryable(),
                                    "{e}"
                                );
                            }
                        }
                    }
                    won
                })
            })
            .collect();
        let mut build = db
            .start_index_build(
                DB,
                COLL,
                &IndexSpec::new(INDEX, vec![IndexField::asc("u")]).unique(),
                &small_batches(3),
            )
            .unwrap();
        let outcome = drive(&db, &mut build);
        for t in threads {
            model.extend(t.join().unwrap());
        }
        match outcome {
            Ok(()) => verify_index(&db, "u", true, &model, false)
                .unwrap_or_else(|e| panic!("round {round}: {e}")),
            Err(e) => {
                assert_eq!(e.code(), ErrorCode::IndexBuildFailed, "round {round}: {e}");
                check_no_orphans(&db).unwrap();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Abort / cancel atomicity (AC-IDX-003) and DROP INDEX during a build.

#[test]
fn tc_idx_003_cancel_in_every_phase_leaves_no_entries() {
    for steps_before in 0..8 {
        let (_fs, db) = fresh(8);
        let model = populate(&db, &SimRng::new(8), 12, false);
        let mut build = db
            .start_index_build(DB, COLL, &spec_a(), &small_batches(3))
            .unwrap();
        let mut finished = false;
        for _ in 0..steps_before {
            if matches!(
                db.step_index_build(&mut build).unwrap(),
                BuildStep::Public(_)
            ) {
                finished = true;
                break;
            }
        }
        if finished {
            // Nothing left to cancel once public.
            let err = db.cancel_index_build(DB, COLL, INDEX).unwrap_err();
            assert_eq!(err.code(), ErrorCode::SchemaChangeInProgress);
            continue;
        }
        let mut cleanup = db.cancel_index_build(DB, COLL, INDEX).unwrap();
        assert_eq!(db.list_indexes(DB, COLL).unwrap(), Vec::new());
        let err = drive(&db, &mut cleanup).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled, "{err}");
        // The original handle finds the job gone.
        assert!(matches!(
            db.step_index_build(&mut build).unwrap(),
            BuildStep::Abandoned(_)
        ));
        check_no_orphans(&db).unwrap();
        // The name is free and a new build succeeds.
        db.create_index(DB, COLL, &spec_a()).unwrap();
        verify_index(&db, "a", false, &model, true).unwrap();
    }
}

#[test]
fn tc_idx_003_drop_index_during_build_stops_the_job() {
    let (_fs, db) = fresh(9);
    populate(&db, &SimRng::new(9), 12, false);
    let mut build = db
        .start_index_build(DB, COLL, &spec_a(), &small_batches(2))
        .unwrap();
    for _ in 0..4 {
        db.step_index_build(&mut build).unwrap();
    }
    db.drop_index(DB, COLL, INDEX).unwrap();
    match db.step_index_build(&mut build).unwrap() {
        BuildStep::Abandoned(e) => assert_eq!(e.code(), ErrorCode::IndexNotFound, "{e}"),
        other => panic!("{other:?}"),
    }
    check_no_orphans(&db).unwrap();
    assert!(
        db.pending_index_builds(&BuildConfig::default())
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------------------------
// The seeded simulation workload (also run by `cargo run -p rustegon-sim -- --workload all`).

#[test]
fn tc_idx_002_simulation_workload_seeds() {
    let mut public = 0;
    for seed in 1..=40 {
        let report =
            run_index_build(&IndexBuildConfig::new(seed)).unwrap_or_else(|f| panic!("{f}"));
        public += u32::from(report.public);
    }
    assert!(public > 0, "no seed built its index");
}

#[test]
fn tc_idx_002_simulation_workload_is_reproducible() {
    let a = run_index_build(&IndexBuildConfig::new(42)).unwrap();
    let b = run_index_build(&IndexBuildConfig::new(42)).unwrap();
    assert_eq!(a, b);
}
