// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! End-to-end tests of the embedded test API (M2): `_id` generation and immutability
//! (TC-DOC-007, FR-DOC-002), server-maintained system fields (TC-DOC-008, FR-DOC-005) and
//! implicit collection creation (TC-SCH-001, FR-SCH-001), through the transaction coordinator
//! on the local replica over the simulated file system.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::HashSet,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustegon_catalog::DatabaseOptions;
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, ObjectIdGenerator, Value};
use rustegon_engine::embedded::{CREATED_AT, EmbeddedDb, ID, REV, UPDATED_AT};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{BoxFuture, Clock, Rng, SystemClock};

/// 2026-01-01T00:00:00Z in nanoseconds.
const T0: u64 = 1_767_225_600_000_000_000;
const ROOT: &str = "/store";

#[derive(Debug)]
struct ManualClock(AtomicU64);

impl ManualClock {
    fn advance(&self, d: Duration) {
        self.0
            .fetch_add(u64::try_from(d.as_nanos()).unwrap(), Ordering::SeqCst);
    }

    fn millis(&self) -> i64 {
        i64::try_from(self.0.load(Ordering::SeqCst) / 1_000_000).unwrap()
    }
}

impl Clock for ManualClock {
    fn monotonic(&self) -> Duration {
        Duration::from_nanos(self.0.load(Ordering::SeqCst))
    }

    fn wall(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.0.load(Ordering::SeqCst))
    }

    fn sleep(&self, _duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(std::future::ready(()))
    }
}

/// Seeded `SplitMix64`.
#[derive(Debug)]
struct SeededRng(Mutex<u64>);

impl Rng for SeededRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        let mut s = self.0.lock().unwrap();
        for chunk in buf.chunks_mut(8) {
            *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            let v = (z ^ (z >> 31)).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

fn rng(seed: u64) -> Arc<SeededRng> {
    Arc::new(SeededRng(Mutex::new(seed)))
}

fn open(fs: &Arc<SimFileSystem>, clock: Arc<dyn Clock>) -> EmbeddedDb {
    EmbeddedDb::open(fs.clone(), Path::new(ROOT), clock, rng(42)).unwrap()
}

/// A fresh store on a manual clock, with database `shop` (default options).
fn manual() -> (EmbeddedDb, Arc<ManualClock>, Arc<SimFileSystem>) {
    let fs = Arc::new(SimFileSystem::new());
    let clock = Arc::new(ManualClock(AtomicU64::new(T0)));
    let db = open(&fs, clock.clone());
    db.create_database("shop", &DatabaseOptions::default())
        .unwrap();
    (db, clock, fs)
}

fn doc(fields: &[(&str, Value)]) -> Document {
    Document::try_from_fields(
        fields
            .iter()
            .map(|(n, v)| ((*n).to_owned(), v.clone()))
            .collect(),
    )
    .unwrap()
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

fn code(e: &Error) -> u16 {
    e.code().code()
}

fn rev(d: &Document) -> String {
    match d.get(REV) {
        Some(Value::String(r)) => r.clone(),
        other => panic!("_rev missing or not a string: {other:?}"),
    }
}

// ---- TC-DOC-007: _id generation and immutability (FR-DOC-002, AC-DOC-003) ----

#[test]
fn tc_doc_007_id_generated_when_absent() {
    let (db, clock, _fs) = manual();
    let stored = db
        .insert("shop", "orders", &doc(&[("item", s("pen"))]))
        .unwrap();
    let Some(Value::ObjectId(oid)) = stored.get(ID) else {
        panic!("generated objectId expected: {stored:?}");
    };
    assert_eq!(stored.fields()[0].0, ID, "_id is stored first");
    assert_eq!(i64::from(oid.seconds()), clock.millis() / 1000);
    let id = Value::ObjectId(*oid);
    assert_eq!(db.get("shop", "orders", &id).unwrap(), Some(stored));
}

#[test]
fn tc_doc_007_user_id_kept_and_duplicate_rejected() {
    let (db, _clock, _fs) = manual();
    let stored = db
        .insert(
            "shop",
            "orders",
            &doc(&[("item", s("a")), (ID, Value::Int64(7))]),
        )
        .unwrap();
    assert_eq!(stored.fields()[0], (ID.to_owned(), Value::Int64(7)));
    assert_eq!(stored.get("item"), Some(&s("a")));
    let err = db
        .insert("shop", "orders", &doc(&[(ID, Value::Int64(7))]))
        .unwrap_err();
    assert_eq!(code(&err), 1005, "{err}");
    let got = db.get("shop", "orders", &Value::Int64(7)).unwrap();
    assert_eq!(got, Some(stored), "the duplicate wrote nothing");
}

#[test]
fn tc_doc_007_replace_changing_id_rejected_rgn_1001() {
    let (db, _clock, _fs) = manual();
    let id = s("k1");
    let original = db
        .insert(
            "shop",
            "orders",
            &doc(&[(ID, id.clone()), ("n", Value::Int64(1))]),
        )
        .unwrap();
    let err = db
        .replace(
            "shop",
            "orders",
            &id,
            &doc(&[(ID, s("k2")), ("n", Value::Int64(2))]),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(code(&err), 1001);
    assert_eq!(db.get("shop", "orders", &id).unwrap(), Some(original));
    assert_eq!(db.get("shop", "orders", &s("k2")).unwrap(), None);

    // Repeating the same `_id`, or omitting it, is not a change.
    let same = db
        .replace(
            "shop",
            "orders",
            &id,
            &doc(&[(ID, id.clone()), ("n", Value::Int64(3))]),
        )
        .unwrap();
    assert_eq!(same.get(ID), Some(&id));
    let omitted = db
        .replace("shop", "orders", &id, &doc(&[("n", Value::Int64(4))]))
        .unwrap();
    assert_eq!(omitted.fields()[0], (ID.to_owned(), id.clone()));
    assert_eq!(omitted.get("n"), Some(&Value::Int64(4)));
}

#[test]
fn tc_doc_007_concurrent_inserts_get_unique_ids() {
    // End to end: concurrent inserts without `_id` through the transaction layer.
    const THREADS: usize = 4;
    const PER_THREAD: usize = 200;
    let fs = Arc::new(SimFileSystem::new());
    let db = Arc::new(open(&fs, Arc::new(SystemClock::new())));
    db.create_database("shop", &DatabaseOptions::default())
        .unwrap();
    db.insert("shop", "events", &Document::new()).unwrap();
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                (0..PER_THREAD)
                    .map(|_| {
                        let d = db.insert("shop", "events", &Document::new()).unwrap();
                        d.get(ID).cloned().unwrap()
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let ids: Vec<Value> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let distinct: HashSet<String> = ids.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(distinct.len(), THREADS * PER_THREAD);
    for id in &ids {
        assert!(db.get("shop", "events", id).unwrap().is_some());
    }
}

#[test]
fn tc_doc_007_one_million_concurrent_ids_unique() {
    // AC-DOC-003 volume: 10^6 ids from one generator shared by 8 threads (the generator is
    // the only source of uniqueness on the insert path).
    const THREADS: usize = 8;
    const PER_THREAD: usize = 125_000;
    let clock = Arc::new(ManualClock(AtomicU64::new(T0)));
    let generator = Arc::new(ObjectIdGenerator::new(clock, rng(7).as_ref()));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let g = Arc::clone(&generator);
            std::thread::spawn(move || (0..PER_THREAD).map(|_| g.generate()).collect::<Vec<_>>())
        })
        .collect();
    let mut all = HashSet::with_capacity(THREADS * PER_THREAD);
    for h in handles {
        for id in h.join().unwrap() {
            assert!(all.insert(id), "duplicate objectId {id}");
        }
    }
    assert_eq!(all.len(), THREADS * PER_THREAD);
}

// ---- TC-DOC-008: system fields (FR-DOC-005, AC-DOC-004) ----

#[test]
fn tc_doc_008_system_fields_set_on_insert() {
    let (db, clock, _fs) = manual();
    let stored = db
        .insert(
            "shop",
            "orders",
            &doc(&[(ID, Value::Int64(1)), ("a", Value::Bool(true))]),
        )
        .unwrap();
    let names: Vec<&str> = stored.iter().map(|(n, _)| n).collect();
    assert_eq!(names, [ID, "a", REV, CREATED_AT, UPDATED_AT]);
    assert_eq!(rev(&stored).len(), 23);
    assert_eq!(
        stored.get(CREATED_AT),
        Some(&Value::DateTime(clock.millis()))
    );
    assert_eq!(stored.get(CREATED_AT), stored.get(UPDATED_AT));
}

#[test]
fn tc_doc_008_replace_advances_rev_and_updated_at_keeps_created_at() {
    let (db, clock, _fs) = manual();
    let id = Value::Int64(1);
    let first = db
        .insert(
            "shop",
            "orders",
            &doc(&[(ID, id.clone()), ("v", Value::Int64(1))]),
        )
        .unwrap();
    clock.advance(Duration::from_secs(5));
    let second = db
        .replace("shop", "orders", &id, &doc(&[("v", Value::Int64(2))]))
        .unwrap();
    assert!(rev(&second) > rev(&first), "_rev advances");
    assert_eq!(second.get(CREATED_AT), first.get(CREATED_AT));
    assert_eq!(
        second.get(UPDATED_AT),
        Some(&Value::DateTime(clock.millis()))
    );
    assert_eq!(db.get("shop", "orders", &id).unwrap(), Some(second.clone()));

    // Without the wall clock moving, `_rev` still strictly increases (HLC logical part).
    let mut last = rev(&second);
    for v in 3..10 {
        let next = db
            .replace("shop", "orders", &id, &doc(&[("v", Value::Int64(v))]))
            .unwrap();
        assert!(rev(&next) > last, "_rev strictly increasing");
        assert_eq!(next.get(CREATED_AT), first.get(CREATED_AT));
        last = rev(&next);
    }
}

#[test]
fn tc_doc_008_client_system_fields_rejected_rgn_1004() {
    let (db, _clock, _fs) = manual();
    let id = Value::Int64(1);
    let original = db
        .insert("shop", "orders", &doc(&[(ID, id.clone())]))
        .unwrap();
    for field in [REV, CREATED_AT, UPDATED_AT, "_conflict", "_origin"] {
        let bad = doc(&[(ID, Value::Int64(2)), (field, s("x"))]);
        let err = db.insert("shop", "orders", &bad).unwrap_err();
        assert_eq!(code(&err), 1004, "insert {field}: {err}");
        let err = db
            .replace("shop", "orders", &id, &doc(&[(field, Value::DateTime(0))]))
            .unwrap_err();
        assert_eq!(code(&err), 1004, "replace {field}: {err}");
    }
    assert_eq!(db.get("shop", "orders", &Value::Int64(2)).unwrap(), None);
    assert_eq!(db.get("shop", "orders", &id).unwrap(), Some(original));
}

#[test]
fn tc_doc_008_expires_at_writable() {
    let (db, _clock, _fs) = manual();
    let id = Value::Int64(1);
    let stored = db
        .insert(
            "shop",
            "orders",
            &doc(&[(ID, id.clone()), ("_expiresAt", Value::DateTime(9))]),
        )
        .unwrap();
    assert_eq!(stored.get("_expiresAt"), Some(&Value::DateTime(9)));
    let replaced = db
        .replace(
            "shop",
            "orders",
            &id,
            &doc(&[("_expiresAt", Value::DateTime(10))]),
        )
        .unwrap();
    assert_eq!(replaced.get("_expiresAt"), Some(&Value::DateTime(10)));
}

#[test]
fn tc_doc_008_system_fields_survive_reopen() {
    let (db, clock, fs) = manual();
    let id = Value::Int64(1);
    let stored = db
        .insert("shop", "orders", &doc(&[(ID, id.clone())]))
        .unwrap();
    drop(db);
    // The embedded store does not persist an HLC bound: a restart happens later in time.
    clock.advance(Duration::from_secs(60));
    let db = open(&fs, clock);
    assert_eq!(db.get("shop", "orders", &id).unwrap(), Some(stored));
}

// ---- TC-SCH-001: implicit collection creation (FR-SCH-001, AC-SCH-001, PD-027) ----

#[test]
fn tc_sch_001_first_insert_creates_collection_heterogeneous_docs() {
    let (db, _clock, _fs) = manual();
    assert_eq!(db.get("shop", "logs", &Value::Int64(1)).unwrap(), None);
    let a = db
        .insert(
            "shop",
            "logs",
            &doc(&[(ID, Value::Int64(1)), ("msg", s("x"))]),
        )
        .unwrap();
    let b = db
        .insert(
            "shop",
            "logs",
            &doc(&[
                (ID, Value::Int64(2)),
                ("level", Value::Int64(3)),
                ("tags", Value::Null),
            ]),
        )
        .unwrap();
    assert_eq!(db.get("shop", "logs", &Value::Int64(1)).unwrap(), Some(a));
    assert_eq!(db.get("shop", "logs", &Value::Int64(2)).unwrap(), Some(b));
}

#[test]
fn tc_sch_001_implicit_creation_disabled_rgn_1030() {
    let (db, _clock, _fs) = manual();
    db.create_database(
        "strict",
        &DatabaseOptions {
            implicit_collection_creation: false,
        },
    )
    .unwrap();
    let err = db
        .insert("strict", "logs", &doc(&[(ID, Value::Int64(1))]))
        .unwrap_err();
    assert_eq!(code(&err), 1030, "{err}");
    assert_eq!(db.get("strict", "logs", &Value::Int64(1)).unwrap(), None);
}

#[test]
fn tc_sch_001_missing_database_rgn_1030() {
    let (db, _clock, _fs) = manual();
    let id = Value::Int64(1);
    let errs = [
        db.insert("nodb", "c", &Document::new()).unwrap_err(),
        db.get("nodb", "c", &id).unwrap_err(),
        db.replace("nodb", "c", &id, &Document::new()).unwrap_err(),
        db.delete("nodb", "c", &id).unwrap_err(),
    ];
    for err in errs {
        assert_eq!(code(&err), 1030, "{err}");
    }
    // Databases are never created implicitly (PD-027): the failed insert left none behind.
    db.create_database("nodb", &DatabaseOptions::default())
        .unwrap();
    assert_eq!(
        code(
            &db.create_database("nodb", &DatabaseOptions::default())
                .unwrap_err()
        ),
        1031
    );
}

#[test]
fn tc_sch_001_concurrent_first_inserts_create_one_collection() {
    // Both transactions create the collection; serializable isolation makes one of them retry
    // and find the other's collection instead of creating a duplicate.
    let fs = Arc::new(SimFileSystem::new());
    let db = Arc::new(open(&fs, Arc::new(SystemClock::new())));
    db.create_database("shop", &DatabaseOptions::default())
        .unwrap();
    let handles: Vec<_> = (0..4i64)
        .map(|i| {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                db.insert("shop", "fresh", &doc(&[(ID, Value::Int64(i))]))
                    .unwrap()
            })
        })
        .collect();
    let stored: Vec<Document> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (i, d) in (0..4i64).zip(stored) {
        assert_eq!(db.get("shop", "fresh", &Value::Int64(i)).unwrap(), Some(d));
    }
}

// ---- delete ----

#[test]
fn embedded_delete_returns_document_then_none() {
    let (db, _clock, _fs) = manual();
    let id = Value::Int64(1);
    let stored = db
        .insert("shop", "orders", &doc(&[(ID, id.clone())]))
        .unwrap();
    let first_rev = rev(&stored);
    assert_eq!(db.delete("shop", "orders", &id).unwrap(), Some(stored));
    assert_eq!(db.get("shop", "orders", &id).unwrap(), None);
    assert_eq!(db.delete("shop", "orders", &id).unwrap(), None);
    assert_eq!(db.delete("shop", "missing", &id).unwrap(), None);
    assert_eq!(
        code(
            &db.replace("shop", "orders", &id, &Document::new())
                .unwrap_err()
        ),
        1030
    );
    // Re-insert after delete: a fresh document with a newer revision.
    let again = db
        .insert("shop", "orders", &doc(&[(ID, id.clone())]))
        .unwrap();
    assert!(rev(&again) > first_rev);
}
