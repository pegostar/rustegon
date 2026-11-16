// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Engine primitives of single-node backup and restore (M13a lane BD) on the simulated file
//! system:
//! - TC-BKP-001 (engine part, PD-063): a consistent checkpoint taken while transactions race the
//!   write fence, restored with `EmbeddedDb::open_restored`, equals the source read at T —
//!   deterministic interleavings, concurrent transfer workloads, and crashes during the
//!   checkpoint and during the restore;
//! - TC-BKP-013 (engine part, PD-067): scans at a pinned snapshot (not bounded by
//!   `txn.max_duration`, protected from GC) and the bulk import;
//! - TC-BKP-014 (PD-068): the store lock.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    time::Duration,
};

use rustegon_catalog::{CollectionOptions, CollectionSpec, DatabaseOptions, IndexField, IndexSpec};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, value_to_json},
};
use rustegon_engine::{
    TxnOptions,
    embedded::{
        EmbeddedDb, FenceOptions, ImportOptions, LOCK_FILE, PinnedSnapshot, ScanOptions, StoreLock,
    },
};
use rustegon_sim::{
    CrashMode, SimFileSystem,
    workload::{clock::SimClock, rng::SimRng},
};
use rustegon_sim_api::{FileSystem, SystemClock};
use rustegon_storage::EngineOptions;

const DB: &str = "shop";
const COLL: &str = "acct";
const T0: Duration = Duration::from_secs(1_700_000_000);
const SOURCE: &str = "/source";
const CHECKPOINT: &str = "/checkpoint";
const RESTORED: &str = "/restored";

fn clock_at(start: Duration) -> Arc<SimClock> {
    Arc::new(SimClock::new(
        start,
        Duration::from_micros(10),
        Duration::from_micros(10),
    ))
}

/// Small memtables, so the checkpoints hold several SSTs.
fn options() -> EngineOptions {
    EngineOptions {
        memtable_size: 32 << 10,
        ..EngineOptions::default()
    }
}

fn open_with(
    fs: &Arc<SimFileSystem>,
    root: &str,
    clock: Arc<dyn rustegon_sim_api::Clock>,
    seed: u64,
) -> Result<EmbeddedDb, Error> {
    EmbeddedDb::open_with_options(
        Arc::clone(fs) as Arc<dyn FileSystem>,
        Path::new(root),
        clock,
        Arc::new(SimRng::new(seed)),
        options(),
    )
}

fn doc(id: i64, bal: i64) -> Document {
    Document::try_from_fields(vec![
        ("_id".to_owned(), Value::Int64(id)),
        ("bal".to_owned(), Value::Int64(bal)),
        ("g".to_owned(), Value::Int64(id % 3)),
    ])
    .unwrap()
}

fn bal(d: &Document) -> i64 {
    match d.get("bal") {
        Some(Value::Int64(b)) => *b,
        other => panic!("bal: {other:?}"),
    }
}

/// Database `shop`, collection `acct` with `n` accounts of balance 100 and an index on `g`.
fn populate(db: &EmbeddedDb, n: i64) {
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    for id in 0..n {
        db.insert(DB, COLL, &doc(id, 100)).unwrap();
    }
    db.create_index(
        DB,
        COLL,
        &IndexSpec::new("by_g", vec![IndexField::asc("g")]),
    )
    .unwrap();
}

/// Every collection of every database at `snapshot`: canonical JSON of each document, in
/// key order, plus the index definitions.
fn dump(db: &Arc<EmbeddedDb>, snapshot: &Arc<PinnedSnapshot>) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for d in db.databases_at(snapshot).unwrap() {
        for c in db.collections_at(snapshot, &d.name).unwrap() {
            let mut rows = Vec::new();
            let scan = db
                .scan_at(snapshot, &d.name, &c.name, ScanOptions::default())
                .unwrap();
            for batch in scan {
                for doc in batch.unwrap() {
                    rows.push(value_to_json(&Value::Object(doc), JsonMode::Canonical));
                }
            }
            let mut indexes: Vec<String> = db
                .indexes_at(snapshot, &d.name, &c.name)
                .unwrap()
                .into_iter()
                .map(|i| format!("{}:{:?}", i.name, i.fields))
                .collect();
            indexes.sort();
            rows.push(format!("indexes {indexes:?}"));
            out.insert(format!("{}.{}", d.name, c.name), rows);
        }
    }
    out
}

/// The restore of the backup layer: the image without `keys/` into `<root>/lsm`, its DEK
/// registry (encrypted stores) into `<root>/keys/registry.enc` (hard links: the simulated
/// file system shares the immutable files).
fn install(fs: &SimFileSystem, checkpoint: &str, root: &str) {
    let lsm = Path::new(root).join("lsm");
    fs.create_dir_all(&lsm).unwrap();
    for path in fs.read_dir(Path::new(checkpoint)).unwrap() {
        let name = path.file_name().unwrap().to_owned();
        if name == "keys" {
            let keys = Path::new(root).join("keys");
            fs.create_dir_all(&keys).unwrap();
            fs.hard_link(&path.join("registry.enc"), &keys.join("registry.enc"))
                .unwrap();
            fs.sync_dir(&keys).unwrap();
        } else {
            fs.hard_link(&path, &lsm.join(name)).unwrap();
        }
    }
    fs.sync_dir(&lsm).unwrap();
}

fn restore(
    fs: &Arc<SimFileSystem>,
    cp: &rustegon_engine::embedded::ConsistentCheckpoint,
    start: Duration,
) -> (Arc<EmbeddedDb>, rustegon_engine::embedded::RevertOutcome) {
    install(fs, CHECKPOINT, RESTORED);
    let (db, outcome) = EmbeddedDb::open_restored(
        Arc::clone(fs) as Arc<dyn FileSystem>,
        Path::new(RESTORED),
        clock_at(start),
        Arc::new(SimRng::new(99)),
        options(),
        None,
        cp.restore_point(),
    )
    .unwrap();
    (Arc::new(db), outcome)
}

fn pin(db: &EmbeddedDb) -> Arc<PinnedSnapshot> {
    Arc::new(db.pin_snapshot(&FenceOptions::default()).unwrap())
}

/// Deterministic interleavings around the fence: A holds an intent below T and commits after
/// the fence started (in the image, at <= T); B writes after the fence (above T, excluded); C
/// holds an intent below T, is pushed above it by a later write and is still running at the
/// checkpoint (its intents are in the image and aborted by the restore); a single-key insert
/// after T is excluded.
#[test]
fn tc_bkp_001_restored_checkpoint_equals_source_at_t_with_transactions_racing_the_fence() {
    let fs = Arc::new(SimFileSystem::new());
    let db = Arc::new(open_with(&fs, SOURCE, clock_at(T0), 1).unwrap());
    populate(&db, 10);
    let opts = TxnOptions::default();
    let txn_a = db.begin(&opts);
    txn_a
        .replace(DB, COLL, &Value::Int64(1), &doc(1, 90))
        .unwrap();
    let txn_c = db.begin(&opts);
    txn_c
        .replace(DB, COLL, &Value::Int64(2), &doc(2, 80))
        .unwrap();
    let txn_b = db.begin(&opts);
    assert!(txn_b.get(DB, COLL, &Value::Int64(3)).unwrap().is_some());

    let (tx, rx) = mpsc::channel();
    let fencing = Arc::clone(&db);
    std::thread::spawn(move || {
        let _ = tx.send(fencing.pin_snapshot(&FenceOptions::default()));
    });
    // Let the fence raise the low-water mark and start waiting for A and C.
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(300)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    txn_b
        .replace(DB, COLL, &Value::Int64(3), &doc(3, 70))
        .unwrap();
    txn_c
        .replace(DB, COLL, &Value::Int64(4), &doc(4, 60))
        .unwrap();
    let a_ts = txn_a.commit().unwrap().commit_ts;
    let snapshot = Arc::new(rx.recv_timeout(Duration::from_secs(60)).unwrap().unwrap());
    let ts = snapshot.ts();
    assert!(a_ts <= ts);

    let cp = db.checkpoint_at(&snapshot, Path::new(CHECKPOINT)).unwrap();
    assert_eq!(cp.ts, ts);
    assert!(cp.applied_index > 0 && cp.applied_term == 1);
    // After the checkpoint: B and C commit above T, one more insert.
    assert!(txn_b.commit().unwrap().commit_ts > ts);
    assert!(txn_c.commit().unwrap().commit_ts > ts);
    db.insert(DB, COLL, &doc(100, 1)).unwrap();

    let expected = dump(&db, &snapshot);
    let balances: Vec<i64> = expected[&format!("{DB}.{COLL}")]
        .iter()
        .filter(|r| r.starts_with('{'))
        .map(|r| {
            let v = rustegon_doc::json::parse_value(r).unwrap();
            let Value::Object(d) = v else { panic!() };
            bal(&d)
        })
        .collect();
    assert_eq!(balances.len(), 10, "{expected:?}");
    assert_eq!(
        balances.iter().sum::<i64>(),
        990,
        "only A's update is at or below T"
    );

    let (restored, outcome) = restore(&fs, &cp, T0 + Duration::from_secs(3600));
    // C's two intents and B's one were in the image, with their records.
    assert!(outcome.intents_aborted >= 3, "{outcome:?}");
    assert!(outcome.records_removed >= 2, "{outcome:?}");
    let now = pin(&restored);
    assert!(now.ts() > ts);
    assert_eq!(dump(&restored, &now), expected);
    drop(now);
    // The restored store is writable and consistent with its index.
    restored.insert(DB, COLL, &doc(200, 5)).unwrap();
    let r = restored
        .query(
            DB,
            "FROM acct WHERE g = 2 SELECT VALUE _id OPTIONS (index = 'by_g')",
            &rustegon_query::Params::new(),
        )
        .unwrap();
    let mut ids: Vec<String> = r
        .rows
        .iter()
        .map(|v| value_to_json(v, JsonMode::Canonical))
        .collect();
    ids.sort();
    assert_eq!(ids, ["2", "200", "5", "8"]);
    // A finished restore is an ordinary store: restoring "again" over it would revert what was
    // written since, and is refused.
    drop(restored);
    let err = EmbeddedDb::open_restored(
        Arc::clone(&fs) as Arc<dyn FileSystem>,
        Path::new(RESTORED),
        clock_at(T0 + Duration::from_secs(7200)),
        Arc::new(SimRng::new(98)),
        options(),
        None,
        cp.restore_point(),
    )
    .err()
    .unwrap();
    assert_eq!(err.code(), ErrorCode::AlreadyExists, "{err}");
}

/// An encrypted store: the checkpoint carries its own DEK registry (BA1); the restore needs the
/// store KEK (refused without it, before anything is written) and yields the source at T.
#[test]
fn tc_bkp_001_encrypted_checkpoint_restores_to_t_with_the_kek() {
    use rustegon_storage::encryption::{FileKekProvider, KekProvider, SecretKey};
    let kek = || -> Arc<dyn KekProvider> {
        Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([7; 32])))
    };
    let fs = Arc::new(SimFileSystem::new());
    let db = Arc::new(
        EmbeddedDb::open_with_kek(
            Arc::clone(&fs) as Arc<dyn FileSystem>,
            Path::new(SOURCE),
            clock_at(T0),
            Arc::new(SimRng::new(20)),
            options(),
            Some(kek()),
        )
        .unwrap(),
    );
    populate(&db, 10);
    let snapshot = pin(&db);
    let cp = db.checkpoint_at(&snapshot, Path::new(CHECKPOINT)).unwrap();
    assert!(cp.info.encrypted);
    for id in 0..10 {
        db.replace(DB, COLL, &Value::Int64(id), &doc(id, 1))
            .unwrap();
    }
    let expected = dump(&db, &snapshot);
    install(&fs, CHECKPOINT, RESTORED);
    let open = |kek: Option<Arc<dyn KekProvider>>| {
        EmbeddedDb::open_restored(
            Arc::clone(&fs) as Arc<dyn FileSystem>,
            Path::new(RESTORED),
            clock_at(T0 + Duration::from_secs(3600)),
            Arc::new(SimRng::new(21)),
            options(),
            kek,
            cp.restore_point(),
        )
    };
    let err = open(None).err().unwrap();
    assert_eq!(err.code(), ErrorCode::KeyUnavailable, "{err}");
    assert!(fs.read_dir(&Path::new(RESTORED).join("raft-log")).is_err());
    let (restored, _) = open(Some(kek())).unwrap();
    let restored = Arc::new(restored);
    assert!(restored.is_encrypted());
    let now = pin(&restored);
    assert_eq!(dump(&restored, &now), expected);
}

/// Concurrent transfers (sum invariant) while three checkpoints are taken: every restore equals
/// the source read at its T and conserves the total.
#[test]
fn tc_bkp_001_checkpoints_under_concurrent_transfers_restore_to_t() {
    const ACCOUNTS: i64 = 8;
    const WRITERS: u64 = 4;
    let fs = Arc::new(SimFileSystem::new());
    let db = Arc::new(open_with(&fs, SOURCE, Arc::new(SystemClock::new()), 2).unwrap());
    populate(&db, ACCOUNTS);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut writers = Vec::new();
    for w in 0..WRITERS {
        let db = Arc::clone(&db);
        let stop = Arc::clone(&stop);
        writers.push(std::thread::spawn(move || {
            let rng = SimRng::new(w + 10);
            let mut committed = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let from = i64::try_from(rng.below(ACCOUNTS as u64)).unwrap();
                let to =
                    (from + 1 + i64::try_from(rng.below(ACCOUNTS as u64 - 1)).unwrap()) % ACCOUNTS;
                let t = db.begin(&TxnOptions::default());
                let transfer = (|| -> Result<(), Error> {
                    let a = t.get(DB, COLL, &Value::Int64(from))?.unwrap();
                    let b = t.get(DB, COLL, &Value::Int64(to))?.unwrap();
                    t.replace(DB, COLL, &Value::Int64(from), &doc(from, bal(&a) - 1))?;
                    t.replace(DB, COLL, &Value::Int64(to), &doc(to, bal(&b) + 1))?;
                    t.commit()?;
                    Ok(())
                })();
                match transfer {
                    Ok(()) => committed += 1,
                    Err(e) if e.retryable() => {
                        let _ = t.rollback();
                    }
                    Err(e) => panic!("transfer: {e}"),
                }
            }
            committed
        }));
    }
    let mut checkpoints = Vec::new();
    for i in 0..3 {
        // Let the writers run between checkpoints.
        let (_tx, rx) = mpsc::channel::<()>();
        let _ = rx.recv_timeout(Duration::from_millis(150));
        let snapshot = pin(&db);
        let dir = format!("{CHECKPOINT}-{i}");
        let cp = db.checkpoint_at(&snapshot, Path::new(&dir)).unwrap();
        let expected = dump(&db, &snapshot);
        checkpoints.push((dir, cp, expected));
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let committed: u64 = writers.into_iter().map(|w| w.join().unwrap()).sum();
    assert!(committed > 0, "no transfer committed");
    for (i, (dir, cp, expected)) in checkpoints.into_iter().enumerate() {
        let root = format!("{RESTORED}-{i}");
        install(&fs, &dir, &root);
        let (restored, _) = EmbeddedDb::open_restored(
            Arc::clone(&fs) as Arc<dyn FileSystem>,
            Path::new(&root),
            Arc::new(SystemClock::new()),
            Arc::new(SimRng::new(50 + i as u64)),
            options(),
            None,
            cp.restore_point(),
        )
        .unwrap();
        let restored = Arc::new(restored);
        let now = pin(&restored);
        let got = dump(&restored, &now);
        assert_eq!(got, expected, "checkpoint {i}");
        let total: i64 = got[&format!("{DB}.{COLL}")]
            .iter()
            .filter(|r| r.starts_with('{'))
            .map(|r| {
                let Value::Object(d) = rustegon_doc::json::parse_value(r).unwrap() else {
                    panic!()
                };
                bal(&d)
            })
            .sum();
        assert_eq!(total, 100 * ACCOUNTS, "checkpoint {i}");
    }
}

/// The crash tests' store: a snapshot T, the expected content at T, and a transaction still
/// running with an intent above T (in the image; the restore aborts it). The checkpoints are
/// taken at that snapshot: a fresh fence would wait for the open transaction.
struct Fixture {
    db: Arc<EmbeddedDb>,
    snapshot: Arc<PinnedSnapshot>,
    expected: BTreeMap<String, Vec<String>>,
    open: rustegon_engine::Transaction,
}

fn crash_fixture(fs: &Arc<SimFileSystem>) -> Fixture {
    let db = Arc::new(open_with(fs, SOURCE, clock_at(T0), 3).unwrap());
    populate(&db, 12);
    let snapshot = pin(&db);
    let expected = dump(&db, &snapshot);
    let open = db.begin(&TxnOptions::default());
    open.replace(DB, COLL, &Value::Int64(0), &doc(0, 1))
        .unwrap();
    Fixture {
        db,
        snapshot,
        expected,
        open,
    }
}

/// A crash at every file system operation of a checkpoint (sampled, every crash mode in turn)
/// never harms the source store; a checkpoint interrupted before its `CURRENT` never opens, and
/// one that completed restores to T.
#[test]
fn tc_bkp_001_crash_during_checkpoint_keeps_the_source_and_never_yields_a_partial_image() {
    // The number of mutating operations of one checkpoint.
    let total = {
        let fs = Arc::new(SimFileSystem::new());
        let f = crash_fixture(&fs);
        let before = fs.op_count();
        f.db.checkpoint_at(&f.snapshot, Path::new(CHECKPOINT))
            .unwrap();
        fs.op_count() - before
    };
    assert!(total > 5, "{total}");
    eprintln!("checkpoint ops: {total}");
    for n in crash_points(total) {
        let mode = CrashMode::ALL[usize::try_from(n).unwrap() % CrashMode::ALL.len()];
        let fs = Arc::new(SimFileSystem::new());
        let f = crash_fixture(&fs);
        fs.halt_after_ops(n);
        let result = f.db.checkpoint_at(&f.snapshot, Path::new(CHECKPOINT));
        fs.crash(n, mode);
        // The dead process's handles: dropping them fails quietly on stale files.
        drop(f.open);
        drop(f.snapshot);
        drop(f.db);
        // The source reopens with its content at T (the open transaction never committed).
        let later = T0 + Duration::from_secs(3600);
        let source = Arc::new(open_with(&fs, SOURCE, clock_at(later), 4).unwrap());
        let now = pin(&source);
        assert_eq!(
            dump(&source, &now),
            f.expected,
            "source after op {n} {mode:?}"
        );
        drop(now);
        drop(source);
        match result {
            Ok(cp) if n == total => {
                // Complete and durable (every step synced): restores to T.
                let (restored, _) = restore(&fs, &cp, later);
                let now = pin(&restored);
                assert_eq!(dump(&restored, &now), f.expected, "op {n} {mode:?}");
            }
            _ => {
                // Interrupted: the directory never opens as a store with data (no CURRENT;
                // `open` of an absent or empty directory creates an empty store).
                if let Ok(engine) = rustegon_storage::LsmEngine::open(
                    Arc::clone(&fs) as Arc<dyn FileSystem>,
                    Path::new(CHECKPOINT),
                    options(),
                ) {
                    assert_eq!(engine.current_version().all_files().count(), 0, "op {n}");
                }
            }
        }
    }
}

/// A crash at every operation of `open_restored` (sampled: log bootstrap, revert, flush):
/// running it again always completes the restore.
#[test]
fn tc_bkp_001_crash_during_restore_is_resumable() {
    let later = T0 + Duration::from_secs(3600);
    let prepared = |fs: &Arc<SimFileSystem>| {
        let f = crash_fixture(fs);
        let cp =
            f.db.checkpoint_at(&f.snapshot, Path::new(CHECKPOINT))
                .unwrap();
        drop(f.open);
        drop(f.snapshot);
        drop(f.db);
        install(fs, CHECKPOINT, RESTORED);
        (cp, f.expected)
    };
    let total = {
        let fs = Arc::new(SimFileSystem::new());
        let (cp, expected) = prepared(&fs);
        let before = fs.op_count();
        let restored = restore_on(&fs, &cp, later).unwrap();
        let ops = fs.op_count() - before;
        let now = pin(&restored);
        assert_eq!(dump(&restored, &now), expected);
        ops
    };
    eprintln!("restore ops: {total}");
    for n in crash_points(total).filter(|&n| n < total) {
        let mode = CrashMode::ALL[usize::try_from(n).unwrap() % CrashMode::ALL.len()];
        let fs = Arc::new(SimFileSystem::new());
        let (cp, expected) = prepared(&fs);
        fs.halt_after_ops(n);
        assert!(restore_on(&fs, &cp, later).is_err(), "op {n}");
        fs.crash(n, mode);
        let again = later + Duration::from_secs(60);
        let restored = match restore_on(&fs, &cp, again) {
            Ok(db) => db,
            // The marker removal (the last step) survived: the earlier attempt had completed,
            // and the store opens as an ordinary one.
            Err(e) if e.code() == ErrorCode::AlreadyExists && n + 2 >= total => {
                Arc::new(open_with(&fs, RESTORED, clock_at(again), 8).unwrap())
            }
            Err(e) => panic!("op {n} {mode:?}: {e}"),
        };
        let now = pin(&restored);
        assert_eq!(dump(&restored, &now), expected, "op {n} {mode:?}");
    }
}

/// The crash points of a sweep over `total` operations: every one up to [`MAX_CRASH_POINTS`],
/// else evenly spaced ones plus the first and last few (the commit points of a checkpoint and
/// a restore are near the end).
fn crash_points(total: u64) -> impl Iterator<Item = u64> {
    let stride = total.div_ceil(MAX_CRASH_POINTS).max(1);
    (0..=total).filter(move |n| n % stride == 0 || *n < 4 || total - n < 8)
}

/// Bound of a crash sweep (each point rebuilds a store, a checkpoint and a restore).
const MAX_CRASH_POINTS: u64 = 400;

fn restore_on(
    fs: &Arc<SimFileSystem>,
    cp: &rustegon_engine::embedded::ConsistentCheckpoint,
    start: Duration,
) -> Result<Arc<EmbeddedDb>, Error> {
    EmbeddedDb::open_restored(
        Arc::clone(fs) as Arc<dyn FileSystem>,
        Path::new(RESTORED),
        clock_at(start),
        Arc::new(SimRng::new(7)),
        options(),
        None,
        cp.restore_point(),
    )
    .map(|(db, _)| Arc::new(db))
}

/// A scan at a pinned snapshot sees exactly the state at T, in bounded batches, however long
/// it runs (here: past `txn.max_duration` and with writes in between), and never waits for
/// running transactions.
#[test]
fn tc_bkp_013_scan_at_reads_t_beyond_max_duration_without_blocking_writers() {
    let fs = Arc::new(SimFileSystem::new());
    let clock = clock_at(T0);
    let db = Arc::new(open_with(&fs, SOURCE, clock.clone(), 5).unwrap());
    populate(&db, 25);
    let snapshot = pin(&db);
    let mut scan = db
        .scan_at(
            &snapshot,
            DB,
            COLL,
            ScanOptions {
                batch_docs: 4,
                batch_bytes: 1 << 20,
            },
        )
        .unwrap();
    let mut seen = Vec::new();
    let first = scan.next_batch().unwrap().unwrap();
    assert_eq!(first.len(), 4);
    seen.extend(first);
    // Writes after T, including an open transaction holding intents on unread documents.
    for id in 0..25 {
        db.replace(DB, COLL, &Value::Int64(id), &doc(id, 7))
            .unwrap();
    }
    db.delete(DB, COLL, &Value::Int64(24)).unwrap();
    let open = db.begin(&TxnOptions::default());
    for id in 10..15 {
        open.replace(DB, COLL, &Value::Int64(id), &doc(id, 8))
            .unwrap();
    }
    // Two hours later: far beyond txn.max_duration.
    clock.advance(Duration::from_secs(7200));
    while let Some(batch) = scan.next_batch().unwrap() {
        assert!(batch.len() <= 4);
        seen.extend(batch);
    }
    assert_eq!(seen.len(), 25);
    assert!(seen.iter().all(|d| bal(d) == 100));
    assert_eq!(scan.returned(), 25);
    // A byte bound cuts batches too (at least one document each).
    let tiny = db
        .scan_at(
            &snapshot,
            DB,
            COLL,
            ScanOptions {
                batch_docs: 100,
                batch_bytes: 1,
            },
        )
        .unwrap();
    assert_eq!(
        tiny.map(|b| b.unwrap().len()).collect::<Vec<_>>(),
        vec![1; 25]
    );
    open.rollback().unwrap();
    // A collection created after T does not exist at T.
    db.insert(DB, "later", &doc(1, 1)).unwrap();
    let err = db
        .scan_at(&snapshot, DB, "later", ScanOptions::default())
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
}

/// GC never removes a version visible at a pinned snapshot; once the pin is released, GC
/// proceeds past it.
#[test]
fn tc_bkp_013_gc_pin_protects_versions_until_released() {
    let fs = Arc::new(SimFileSystem::new());
    let db = Arc::new(open_with(&fs, SOURCE, clock_at(T0), 6).unwrap());
    populate(&db, 10);
    let snapshot = pin(&db);
    let t = snapshot.ts();
    for round in 1..=3 {
        for id in 0..10 {
            db.replace(DB, COLL, &Value::Int64(id), &doc(id, 100 + round))
                .unwrap();
        }
    }
    let now = pin(&db);
    let latest = now.ts();
    drop(now);
    // GC up to "now" is held back at T by the pin.
    let gc = db.collect_garbage(latest).unwrap();
    assert_eq!(gc.threshold, t);
    assert_eq!(db.oldest_gc_pin(), Some(t));
    db.flush().unwrap();
    while db.compact_once().unwrap() {}
    let docs: Vec<Document> = db
        .scan_at(&snapshot, DB, COLL, ScanOptions::default())
        .unwrap()
        .flat_map(Result::unwrap)
        .collect();
    assert_eq!(docs.len(), 10);
    assert!(
        docs.iter().all(|d| bal(d) == 100),
        "a version visible at T was collected"
    );
    // Released: GC moves past T and removes the shadowed versions.
    drop(snapshot);
    assert_eq!(db.oldest_gc_pin(), None);
    let gc = db.collect_garbage(latest).unwrap();
    assert_eq!(gc.threshold, latest);
    assert!(gc.versions_removed >= 30, "{gc:?}");
    assert_eq!(db.gc_threshold(), latest);
    // The latest state is untouched.
    for id in 0..10 {
        let d = db.get(DB, COLL, &Value::Int64(id)).unwrap().unwrap();
        assert_eq!(bal(&d), 103);
    }
}

/// Import keeps `_id`, `_createdAt`, `_updatedAt`, regenerates `_rev`, skips validators, keeps
/// indexes consistent, is batched, and refuses a non-empty target unless asked to drop it.
#[test]
fn tc_bkp_013_import_round_trip_keeps_system_fields_and_skips_validators() {
    let fs = Arc::new(SimFileSystem::new());
    let db = Arc::new(open_with(&fs, SOURCE, clock_at(T0), 8).unwrap());
    populate(&db, 30);
    // A validator added later: some stored documents violate it.
    let validator = CollectionOptions {
        validator: Some(r#"{"$jsonSchema":{"properties":{"bal":{"minimum":1000}}}}"#.into()),
        ..CollectionOptions::default()
    };
    db.set_collection_options(DB, COLL, &validator).unwrap();
    let snapshot = pin(&db);
    let source: Vec<Document> = db
        .scan_at(&snapshot, DB, COLL, ScanOptions::default())
        .unwrap()
        .flat_map(Result::unwrap)
        .collect();
    assert_eq!(source.len(), 30);

    let target = "restored";
    db.create_database(target, &DatabaseOptions::default())
        .unwrap();
    // Order of PD-067: collection without validator, import, validator, indexes.
    let spec = CollectionSpec::document(COLL);
    db.prepare_import_target(target, &spec, false).unwrap();
    let outcome = db
        .import_documents(
            target,
            COLL,
            source.clone(),
            &ImportOptions {
                batch_docs: 7,
                batch_bytes: 1 << 20,
            },
        )
        .unwrap();
    assert_eq!(outcome.documents, 30);
    assert_eq!(outcome.transactions, 5);
    db.set_collection_options(target, COLL, &validator).unwrap();
    db.create_index(
        target,
        COLL,
        &IndexSpec::new("by_g", vec![IndexField::asc("g")]),
    )
    .unwrap();
    for src in &source {
        let id = src.get("_id").unwrap();
        let got = db.get(target, COLL, id).unwrap().unwrap();
        for field in ["_id", "bal", "g", "_createdAt", "_updatedAt"] {
            assert_eq!(got.get(field), src.get(field), "{field}");
        }
        assert_ne!(got.get("_rev"), src.get("_rev"), "_rev is regenerated");
        assert!(got.get("_rev").is_some());
    }
    // The imported data still violates the validator, which now applies to new writes only.
    let err = db.insert(target, COLL, &doc(99, 1)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);

    // A non-empty target is refused, then dropped on request; a duplicate _id is refused.
    let err = db.prepare_import_target(target, &spec, false).unwrap_err();
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    db.prepare_import_target(target, &spec, true).unwrap();
    assert_eq!(db.list_indexes(target, COLL).unwrap().len(), 0);
    let twice = vec![source[0].clone(), source[0].clone()];
    let err = db
        .import_documents(target, COLL, twice, &ImportOptions::default())
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DuplicateKey);
    let mut no_id = source[1].clone();
    no_id.remove("_id");
    let err = db
        .import_documents(target, COLL, vec![no_id], &ImportOptions::default())
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

/// Two opens of one store in one process: the second is refused with RGN-3002 until the first
/// is dropped; an offline restore is refused while the store is open; a crash releases it.
#[test]
fn tc_bkp_014_store_lock_refuses_a_second_open() {
    let fs = Arc::new(SimFileSystem::new());
    let first = open_with(&fs, SOURCE, clock_at(T0), 9).unwrap();
    let err = open_with(&fs, SOURCE, clock_at(T0), 10).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.to_string().contains("in use"), "{err}");
    assert!(StoreLock::is_held(fs.as_ref(), Path::new(SOURCE)).unwrap());
    assert!(StoreLock::acquire(fs.as_ref(), Path::new(SOURCE)).is_err());
    let err = EmbeddedDb::open_restored(
        Arc::clone(&fs) as Arc<dyn FileSystem>,
        Path::new(SOURCE),
        clock_at(T0),
        Arc::new(SimRng::new(1)),
        options(),
        None,
        rustegon_engine::embedded::RestorePoint {
            ts: rustegon_mvcc::Timestamp::MIN,
            applied_index: 0,
            applied_term: 0,
        },
    )
    .err()
    .unwrap();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    // Another store of the same file system is independent.
    let other = open_with(&fs, "/other", clock_at(T0), 11).unwrap();
    drop(other);
    drop(first);
    assert!(!StoreLock::is_held(fs.as_ref(), Path::new(SOURCE)).unwrap());
    assert!(!StoreLock::is_held(fs.as_ref(), Path::new("/absent")).unwrap());
    let second = open_with(&fs, SOURCE, clock_at(T0 + Duration::from_secs(10)), 12).unwrap();
    // The process dies: its lock goes with it.
    fs.crash(1, CrashMode::Clean);
    let third = open_with(&fs, SOURCE, clock_at(T0 + Duration::from_secs(20)), 13).unwrap();
    drop(second);
    assert!(StoreLock::is_held(fs.as_ref(), Path::new(SOURCE)).unwrap());
    drop(third);
    let _ = (LOCK_FILE, PathBuf::new());
}
