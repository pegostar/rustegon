// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Logical dump and restore (M13a lane BG; FR-BKP-007, PD-067, PD-084, PD-085), TC-BKP-013:
//! - round trip dump → restore into an empty store: per-collection count and checksum, document
//!   equality without `_rev`, system fields kept, validators and indexes restored;
//! - consistency at T under concurrent writes, a dump longer than `txn.max_duration`
//!   (simulated time);
//! - corrupted, truncated, out-of-order and newer-format streams refused, with the partial
//!   restore undone; `--drop` and scope filters; cancellation;
//! - the format v1 fixture (implementation-rules.md §6);
//! - the whole path through gRPC with a `BackupBackend` over the real engine.
//!
//! The engine runs on the simulated file system and clock of `rustegon-sim`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use common::{Harness, authed, base_flags, bearer, code_of};
use rustegon_backup::HlcTimestamp;
use rustegon_catalog::{
    CollectionOptions, CollectionSpec, DatabaseOptions, IndexField, IndexSpec, ShardKey,
    ShardStrategy, ValidationAction, ValidationLevel,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, parse_document, to_json},
};
use rustegon_engine::{
    EmbeddedDb,
    embedded::{FenceOptions, ImportOptions, ScanOptions},
};
use rustegon_proto::v1::{
    DumpRequest, LogicalRestoreOptions as PbOptions, LogicalRestoreRequest,
    backup_service_client::BackupServiceClient, dump_response, logical_restore_request,
};
use rustegon_server::{
    CancelToken,
    services::{
        backup::{
            BackupBackend, DumpChunk, DumpScope, DumpSink, DumpSource, DumpSummary,
            LogicalRestoreOptions, LogicalRestoreSummary,
        },
        backup_logical::{
            CancelCheck, DUMP_FORMAT_VERSION, DUMP_MANIFEST, DumpManifest, DumpOptions, dump,
            dump_with, logical_restore, logical_restore_with,
        },
    },
};
use rustegon_sim::{
    SimFileSystem,
    workload::{clock::SimClock, rng::SimRng},
};
use rustegon_sim_api::FileSystem;
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;

const T0: Duration = Duration::from_secs(1_700_000_000);

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn clock() -> Arc<SimClock> {
    Arc::new(SimClock::new(
        T0,
        Duration::from_micros(10),
        Duration::from_micros(10),
    ))
}

fn open_at(
    fs: &Arc<SimFileSystem>,
    root: &str,
    clock: Arc<SimClock>,
    seed: u64,
) -> Arc<EmbeddedDb> {
    Arc::new(
        EmbeddedDb::open(
            Arc::clone(fs) as Arc<dyn FileSystem>,
            Path::new(root),
            clock,
            Arc::new(SimRng::new(seed)),
        )
        .unwrap(),
    )
}

/// A fresh store on its own simulated file system.
fn store(seed: u64) -> (Arc<EmbeddedDb>, Arc<SimClock>) {
    let fs = Arc::new(SimFileSystem::new());
    let clock = clock();
    (open_at(&fs, "/store", Arc::clone(&clock), seed), clock)
}

struct Never;

impl CancelCheck for Never {
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Cancelled once it has been asked `after` times.
struct CancelAfter {
    left: AtomicUsize,
}

impl CancelAfter {
    fn new(after: usize) -> Self {
        Self {
            left: AtomicUsize::new(after),
        }
    }
}

impl CancelCheck for CancelAfter {
    fn check(&self) -> Result<(), Error> {
        let left = self.left.load(Ordering::SeqCst);
        if left == 0 {
            return Err(Error::new(ErrorCode::Cancelled, "cancelled by the test"));
        }
        self.left.store(left - 1, Ordering::SeqCst);
        Ok(())
    }
}

type Hook = Box<dyn FnMut(&DumpChunk) + Send>;
/// Dump files in stream order: path and content.
type Files = Vec<(String, Vec<u8>)>;

/// A sink keeping every chunk, with an optional hook run after each one (writes racing the
/// dump, clock jumps).
#[derive(Default)]
struct MemSink {
    started: Option<HlcTimestamp>,
    chunks: Vec<DumpChunk>,
    hook: Option<Hook>,
}

impl DumpSink for MemSink {
    fn started(&mut self, timestamp: HlcTimestamp) -> Result<(), Error> {
        assert!(self.started.is_none(), "started twice");
        assert!(self.chunks.is_empty(), "started after a chunk");
        self.started = Some(timestamp);
        Ok(())
    }

    fn chunk(&mut self, chunk: DumpChunk) -> Result<(), Error> {
        assert!(self.started.is_some(), "chunk before started");
        if let Some(hook) = &mut self.hook {
            hook(&chunk);
        }
        self.chunks.push(chunk);
        Ok(())
    }
}

struct MemSource(VecDeque<DumpChunk>);

impl DumpSource for MemSource {
    fn next_chunk(&mut self) -> Result<Option<DumpChunk>, Error> {
        Ok(self.0.pop_front())
    }
}

/// Checks the chunk order rules (files contiguous, never reopened, path order, `dump.json`
/// last, chunk size bound) and returns the files in stream order.
fn assemble(chunks: &[DumpChunk], max_chunk: usize) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut open = false;
    for c in chunks {
        assert!(c.data.len() <= max_chunk, "chunk of {} bytes", c.data.len());
        match files.last_mut() {
            Some((path, data)) if open && *path == c.path => data.extend_from_slice(&c.data),
            _ => {
                assert!(!open, "file {} interleaved", c.path);
                assert!(
                    files.iter().all(|(p, _)| *p != c.path),
                    "file {} reopened",
                    c.path
                );
                files.push((c.path.clone(), c.data.clone()));
            }
        }
        open = !c.end_of_file;
    }
    assert!(!open, "the stream ends inside a file");
    let (last, _) = files.last().expect("empty dump");
    assert_eq!(last, DUMP_MANIFEST, "dump.json is not last");
    let paths: Vec<&String> = files[..files.len() - 1].iter().map(|(p, _)| p).collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "files are not in path order");
    files
}

/// Chunks of `files` in the given order (as `rustegon restore` sends them).
fn chunks_of(files: &[(String, Vec<u8>)], chunk: usize) -> Vec<DumpChunk> {
    let mut out = Vec::new();
    for (path, data) in files {
        if data.is_empty() {
            out.push(DumpChunk {
                path: path.clone(),
                data: Vec::new(),
                end_of_file: true,
            });
            continue;
        }
        let pieces: Vec<&[u8]> = data.chunks(chunk).collect();
        for (i, piece) in pieces.iter().enumerate() {
            out.push(DumpChunk {
                path: path.clone(),
                data: piece.to_vec(),
                end_of_file: i + 1 == pieces.len(),
            });
        }
    }
    out
}

fn run_dump(db: &Arc<EmbeddedDb>, scope: &DumpScope, chunk_bytes: usize) -> (MemSink, DumpSummary) {
    let mut sink = MemSink::default();
    let options = DumpOptions {
        chunk_bytes,
        ..DumpOptions::default()
    };
    let summary = dump_with(db, scope, &mut sink, &Never, &options).unwrap();
    (sink, summary)
}

fn dump_files(db: &Arc<EmbeddedDb>) -> Vec<(String, Vec<u8>)> {
    let (sink, _) = run_dump(db, &DumpScope::default(), 1 << 20);
    assemble(&sink.chunks, 1 << 20)
}

fn manifest_of(files: &[(String, Vec<u8>)]) -> DumpManifest {
    let (_, bytes) = files.iter().find(|(p, _)| p == DUMP_MANIFEST).unwrap();
    DumpManifest::parse(bytes).unwrap()
}

fn restore(
    db: &Arc<EmbeddedDb>,
    files: &[(String, Vec<u8>)],
    options: &LogicalRestoreOptions,
) -> Result<LogicalRestoreSummary, Error> {
    let mut source = MemSource(chunks_of(files, 4096).into());
    logical_restore(db, options, &mut source, &Never)
}

fn doc(text: &str) -> Document {
    parse_document(text).unwrap()
}

/// Every document of `db.coll` (latest state), keyed by the canonical JSON of `_id`.
fn read_all(db: &Arc<EmbeddedDb>, database: &str, coll: &str) -> BTreeMap<String, Document> {
    let snapshot = Arc::new(db.pin_snapshot(&FenceOptions::default()).unwrap());
    db.scan_at(&snapshot, database, coll, ScanOptions::default())
        .unwrap()
        .flat_map(Result::unwrap)
        .map(|d| {
            let id = rustegon_doc::json::value_to_json(d.get("_id").unwrap(), JsonMode::Canonical);
            (id, d)
        })
        .collect()
}

fn without_rev(d: &Document) -> String {
    let mut d = d.clone();
    d.remove("_rev");
    to_json(&d, JsonMode::Canonical)
}

/// The source of the round trip: two databases, typed values, validators (one violated by
/// stored data), indexes, a dotted name, two names differing only by case, an empty
/// collection.
fn populate(db: &EmbeddedDb) {
    db.create_database("shop", &DatabaseOptions::default())
        .unwrap();
    db.create_database(
        "crm",
        &DatabaseOptions {
            implicit_collection_creation: false,
        },
    )
    .unwrap();
    for i in 0..60i64 {
        let text = format!(
            r#"{{"_id":{i},"bal":{bal},"g":"group-{g}","code":"c{i}","f":{f},"big":{{"$int64":"9007199254740993"}},"dec":{{"$decimal":"12.50"}},"when":{{"$date":"2026-01-0{d}T00:00:00.000Z"}},"bin":{{"$binary":{{"base64":"AAEC","subType":"00"}}}},"oid":{{"$oid":"0123456789abcdef01234567"}},"tags":["a",{i},null,true],"sub":{{"x":{{"y":"é\n\"q\""}}}}}}"#,
            bal = i * 10 - 100,
            g = i % 4,
            f = f64::from(u8::try_from(i).unwrap()) / 4.0 + 0.5,
            d = i % 9 + 1,
        );
        db.insert("shop", "acct", &doc(&text)).unwrap();
    }
    // Updates: `_updatedAt` differs from `_createdAt` for some documents.
    for i in 0..10i64 {
        db.replace(
            "shop",
            "acct",
            &Value::Int64(i),
            &doc(&format!(
                r#"{{"bal":{},"g":"group-x","code":"c{i}"}}"#,
                i + 1000
            )),
        )
        .unwrap();
    }
    // A validator added after documents that violate it (negative balances).
    let validator = CollectionOptions {
        validator: Some(r#"{"$jsonSchema":{"properties":{"bal":{"minimum":0}}}}"#.into()),
        validation_level: ValidationLevel::Moderate,
        validation_action: ValidationAction::Error,
    };
    db.set_collection_options("shop", "acct", &validator)
        .unwrap();
    db.create_index(
        "shop",
        "acct",
        &IndexSpec::new("by_g", vec![IndexField::asc("g"), IndexField::desc("bal")]),
    )
    .unwrap();
    db.create_index(
        "shop",
        "acct",
        &IndexSpec::new("u_code", vec![IndexField::asc("code")]).unique(),
    )
    .unwrap();
    db.create_index(
        "shop",
        "acct",
        &IndexSpec::new("tags", vec![IndexField::asc("tags")]).sparse(),
    )
    .unwrap();
    // Range-sharded collection with objectId ids.
    db.create_collection(
        "shop",
        &CollectionSpec {
            shard_key: ShardKey {
                strategy: ShardStrategy::Range,
                fields: vec!["_id".into()],
            },
            ..CollectionSpec::document("orders.2026")
        },
    )
    .unwrap();
    for i in 0..5 {
        db.insert("shop", "orders.2026", &doc(&format!(r#"{{"n":{i}}}"#)))
            .unwrap();
    }
    db.create_collection("shop", &CollectionSpec::document("empty"))
        .unwrap();
    for (coll, n) in [("people", 7), ("People", 3)] {
        db.create_collection("crm", &CollectionSpec::document(coll))
            .unwrap();
        for i in 0..n {
            db.insert(
                "crm",
                coll,
                &doc(&format!(r#"{{"_id":"p{i}","name":"{coll}-{i}"}}"#)),
            )
            .unwrap();
        }
    }
}

const COLLECTIONS: [(&str, &str); 5] = [
    ("crm", "People"),
    ("crm", "people"),
    ("shop", "acct"),
    ("shop", "empty"),
    ("shop", "orders.2026"),
];

/// The restored store equals the source for every collection: documents without `_rev`
/// (system fields kept), a regenerated `_rev`, options, shard key, indexes.
fn assert_same(source: &Arc<EmbeddedDb>, target: &Arc<EmbeddedDb>, collections: &[(&str, &str)]) {
    for (d, c) in collections {
        let a = read_all(source, d, c);
        let b = read_all(target, d, c);
        assert_eq!(a.len(), b.len(), "{d}.{c} count");
        for (id, src) in &a {
            let got = b.get(id).unwrap_or_else(|| panic!("{d}.{c} {id} missing"));
            assert_eq!(without_rev(src), without_rev(got), "{d}.{c} {id}");
            assert!(got.get("_rev").is_some());
            assert_ne!(got.get("_rev"), src.get("_rev"), "_rev is regenerated");
        }
        let sc = source.collection(d, c).unwrap().unwrap();
        let tc = target.collection(d, c).unwrap().unwrap();
        assert_eq!(sc.options, tc.options, "{d}.{c} options");
        assert_eq!(sc.shard_key, tc.shard_key, "{d}.{c} shard key");
        let strip = |v: Vec<rustegon_catalog::IndexDescriptor>| {
            v.into_iter()
                .map(|i| {
                    (
                        i.name, i.fields, i.unique, i.sparse, i.partial, i.hidden, i.include,
                        i.origin,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            strip(source.list_indexes(d, c).unwrap()),
            strip(target.list_indexes(d, c).unwrap()),
            "{d}.{c} indexes"
        );
    }
}

fn names(db: &Arc<EmbeddedDb>) -> Vec<String> {
    let mut out = Vec::new();
    for d in db.list_databases().unwrap() {
        out.push(d.name.clone());
        for c in db.list_collections(&d.name).unwrap() {
            out.push(format!("{}.{}", d.name, c.name));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------------------------

/// TC-BKP-013 / AC-BKP-006: dump → restore into an empty store gives equal collections.
#[test]
fn tc_bkp_013_round_trip_restores_equal_collections_validators_and_indexes() {
    let (source, _) = store(1);
    populate(&source);
    // Small chunks: files span many chunks, lines cross chunk boundaries.
    let (sink, summary) = run_dump(&source, &DumpScope::default(), 777);
    assert_eq!(summary.collections, 5);
    assert_eq!(summary.documents, 60 + 5 + 7 + 3);
    let files = assemble(&sink.chunks, 777);
    let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        [
            "crm.database.json",
            "crm/People.metadata.json",
            "crm/People.ndjson",
            "crm/case-1/people.metadata.json",
            "crm/case-1/people.ndjson",
            "shop.database.json",
            "shop/acct.metadata.json",
            "shop/acct.ndjson",
            "shop/empty.metadata.json",
            "shop/empty.ndjson",
            "shop/orders.2026.metadata.json",
            "shop/orders.2026.ndjson",
            "dump.json",
        ]
    );
    let manifest = manifest_of(&files);
    assert_eq!(manifest.format_version, DUMP_FORMAT_VERSION);
    assert_eq!(Some(manifest.timestamp), sink.started);
    assert_eq!(manifest.files.len(), files.len() - 1);
    // Data lines are canonical extended JSON of the stored documents, `_rev` included.
    let (_, acct) = files.iter().find(|(p, _)| p == "shop/acct.ndjson").unwrap();
    let text = std::str::from_utf8(acct).unwrap();
    assert_eq!(text.lines().count(), 60);
    assert!(
        text.contains(r#""big":{"$int64":"9007199254740993"}"#),
        "{text}"
    );
    assert!(text.contains(r#""_rev":"#));

    let (target, _) = store(2);
    let restored = restore(&target, &files, &LogicalRestoreOptions::default()).unwrap();
    assert_eq!(restored.source_timestamp, manifest.timestamp);
    let by_name: BTreeMap<String, (u64, u32)> = restored
        .collections
        .iter()
        .map(|c| {
            (
                format!("{}.{}", c.database, c.collection),
                (c.documents, c.indexes),
            )
        })
        .collect();
    assert_eq!(by_name["shop.acct"], (60, 3));
    assert_eq!(by_name["crm.people"], (7, 0));
    assert_eq!(by_name["shop.empty"], (0, 0));
    assert_same(&source, &target, &COLLECTIONS);
    assert!(
        !target
            .database("crm")
            .unwrap()
            .unwrap()
            .options
            .implicit_collection_creation,
        "database options restored"
    );
    // Per-collection count and equality checksum of a dump of the restored store match.
    let again = manifest_of(&dump_files(&target));
    let sums = |m: &DumpManifest| {
        m.databases
            .iter()
            .flat_map(|d| {
                d.collections.iter().map(|c| {
                    (
                        d.name.clone(),
                        c.name.clone(),
                        c.documents,
                        c.checksum.clone(),
                    )
                })
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(sums(&manifest), sums(&again));
    // The validator applies again to new writes; the unique index is enforced.
    let err = target
        .insert("shop", "acct", &doc(r#"{"_id":1000,"bal":-5}"#))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);
    let err = target
        .insert("shop", "acct", &doc(r#"{"_id":1001,"bal":5,"code":"c3"}"#))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DuplicateKey, "{err}");
}

/// Scope filters on both sides: a dump of selected objects, a restore of a subset.
#[test]
fn tc_bkp_013_scope_filters_select_databases_and_collections() {
    let (source, _) = store(3);
    populate(&source);
    let scope = DumpScope {
        databases: vec!["crm".into()],
        collections: vec![("shop".into(), "empty".into())],
    };
    let (sink, summary) = run_dump(&source, &scope, 1 << 20);
    assert_eq!(summary.collections, 3);
    let files = assemble(&sink.chunks, 1 << 20);
    assert!(files.iter().all(|(p, _)| !p.starts_with("shop/acct")));
    // Missing objects in a dump scope.
    for bad in [
        DumpScope {
            databases: vec!["nope".into()],
            collections: vec![],
        },
        DumpScope {
            databases: vec![],
            collections: vec![("shop".into(), "nope".into())],
        },
    ] {
        let mut sink = MemSink::default();
        let err = dump(&source, &bad, &mut sink, &Never).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound, "{bad:?}");
    }

    let all = dump_files(&source);
    let (target, _) = store(4);
    let options = LogicalRestoreOptions {
        drop_existing: false,
        scope: DumpScope {
            databases: vec![],
            collections: vec![("crm".into(), "people".into())],
        },
    };
    let restored = restore(&target, &all, &options).unwrap();
    assert_eq!(restored.collections.len(), 1);
    assert_eq!(names(&target), ["crm", "crm.people"]);
    assert_same(&source, &target, &[("crm", "people")]);
    // A scope naming something the dump does not hold: RGN-1030, nothing left behind.
    let (target, _) = store(5);
    let options = LogicalRestoreOptions {
        drop_existing: false,
        scope: DumpScope {
            databases: vec!["shop".into(), "ghost".into()],
            collections: vec![],
        },
    };
    let err = restore(&target, &all, &options).unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(
        err.details().get("cleanup").map(String::as_str),
        Some("done")
    );
    assert!(names(&target).is_empty(), "{:?}", names(&target));
}

// ---------------------------------------------------------------------------------------------
// Consistency and duration
// ---------------------------------------------------------------------------------------------

/// The dump sees exactly T: writes made while it streams (after T was announced) are absent,
/// across collections; transfers racing it on another thread keep the total invariant.
#[test]
fn tc_bkp_013_dump_is_consistent_at_t_under_concurrent_writes() {
    let (db, _) = store(6);
    db.create_database("bank", &DatabaseOptions::default())
        .unwrap();
    for coll in ["a", "b"] {
        for i in 0..40i64 {
            db.insert("bank", coll, &doc(&format!(r#"{{"_id":{i},"bal":100}}"#)))
                .unwrap();
        }
    }
    let before_a = read_all(&db, "bank", "a");
    let before_b = read_all(&db, "bank", "b");
    // Deterministic racing writes: after every chunk, change both collections.
    let writer = Arc::clone(&db);
    let mut round = 0i64;
    let mut sink = MemSink {
        hook: Some(Box::new(move |_| {
            round += 1;
            // Replace pre-T documents 0..20, insert new ones, delete pre-T documents 20..40
            // of `b` once each.
            for coll in ["a", "b"] {
                writer
                    .replace(
                        "bank",
                        coll,
                        &Value::Int64(round % 20),
                        &doc(&format!(r#"{{"bal":{}}}"#, 1000 + round)),
                    )
                    .unwrap();
                writer
                    .insert(
                        "bank",
                        coll,
                        &doc(&format!(r#"{{"_id":{},"bal":1}}"#, 100 + round)),
                    )
                    .unwrap();
            }
            if round < 20 {
                writer
                    .delete("bank", "b", &Value::Int64(20 + round))
                    .unwrap();
            }
        })),
        ..MemSink::default()
    };
    let options = DumpOptions {
        chunk_bytes: 64,
        scan: ScanOptions {
            batch_docs: 3,
            batch_bytes: 1 << 20,
        },
        ..DumpOptions::default()
    };
    dump_with(&db, &DumpScope::default(), &mut sink, &Never, &options).unwrap();
    let files = assemble(&sink.chunks, 64);
    let lines = |path: &str| -> BTreeMap<String, String> {
        let (_, data) = files.iter().find(|(p, _)| p == path).unwrap();
        std::str::from_utf8(data)
            .unwrap()
            .lines()
            .map(|l| {
                let d = doc(l);
                let id =
                    rustegon_doc::json::value_to_json(d.get("_id").unwrap(), JsonMode::Canonical);
                (id, to_json(&d, JsonMode::Canonical))
            })
            .collect()
    };
    let expect = |m: &BTreeMap<String, Document>| -> BTreeMap<String, String> {
        m.iter()
            .map(|(k, d)| (k.clone(), to_json(d, JsonMode::Canonical)))
            .collect()
    };
    assert_eq!(lines("bank/a.ndjson"), expect(&before_a));
    assert_eq!(lines("bank/b.ndjson"), expect(&before_b));

    // Transfers on another thread while dumping: every dump sees a consistent total.
    let (db, _) = store(7);
    db.create_database("bank", &DatabaseOptions::default())
        .unwrap();
    for i in 0..20i64 {
        db.insert("bank", "acct", &doc(&format!(r#"{{"_id":{i},"bal":100}}"#)))
            .unwrap();
    }
    let stop = Arc::new(AtomicBool::new(false));
    let committed = Arc::new(AtomicUsize::new(0));
    let worker = {
        let db = Arc::clone(&db);
        let stop = Arc::clone(&stop);
        let committed = Arc::clone(&committed);
        std::thread::spawn(move || {
            let mut n = 0i64;
            while !stop.load(Ordering::SeqCst) {
                let (from, to) = (n % 20, (n * 7 + 3) % 20);
                n += 1;
                if from == to {
                    continue;
                }
                let txn = db.begin(&rustegon_engine::TxnOptions::default());
                let read = |id: i64| -> Option<i64> {
                    match txn.get("bank", "acct", &Value::Int64(id)) {
                        Ok(Some(d)) => match d.get("bal") {
                            Some(Value::Int64(b)) => Some(*b),
                            _ => None,
                        },
                        _ => None,
                    }
                };
                let (Some(a), Some(b)) = (read(from), read(to)) else {
                    let _ = txn.rollback();
                    continue;
                };
                let ok = txn
                    .replace(
                        "bank",
                        "acct",
                        &Value::Int64(from),
                        &doc(&format!(r#"{{"bal":{}}}"#, a - 5)),
                    )
                    .and_then(|_| {
                        txn.replace(
                            "bank",
                            "acct",
                            &Value::Int64(to),
                            &doc(&format!(r#"{{"bal":{}}}"#, b + 5)),
                        )
                    })
                    .is_ok();
                if ok && txn.commit().is_ok() {
                    committed.fetch_add(1, Ordering::SeqCst);
                } else {
                    let _ = txn.rollback();
                }
            }
        })
    };
    // Let transfers run before and between the dumps.
    while committed.load(Ordering::SeqCst) < 10 {
        std::thread::yield_now();
    }
    for _ in 0..5 {
        let (sink, summary) = run_dump(&db, &DumpScope::default(), 256);
        assert_eq!(summary.documents, 20);
        let files = assemble(&sink.chunks, 256);
        let (_, data) = files.iter().find(|(p, _)| p == "bank/acct.ndjson").unwrap();
        let total: i64 = std::str::from_utf8(data)
            .unwrap()
            .lines()
            .map(|l| match doc(l).get("bal") {
                Some(Value::Int64(b)) => *b,
                other => panic!("{other:?}"),
            })
            .sum();
        assert_eq!(total, 2000, "the dump saw a partial transfer");
    }
    stop.store(true, Ordering::SeqCst);
    worker.join().unwrap();
    // The store's latest state agrees, and the transfers did run during the dumps.
    let latest: i64 = read_all(&db, "bank", "acct")
        .values()
        .map(|d| match d.get("bal") {
            Some(Value::Int64(b)) => *b,
            other => panic!("{other:?}"),
        })
        .sum();
    assert_eq!(latest, 2000);
    assert!(committed.load(Ordering::SeqCst) >= 10);
}

/// A dump that lasts two hours of (simulated) time per chunk, far beyond `txn.max_duration`,
/// completes and holds everything at T.
#[test]
fn tc_bkp_013_dump_outlives_txn_max_duration() {
    let (db, clock) = store(8);
    db.create_database("shop", &DatabaseOptions::default())
        .unwrap();
    for i in 0..50i64 {
        db.insert(
            "shop",
            "items",
            &doc(&format!(r#"{{"_id":{i},"v":"{}"}}"#, "x".repeat(40))),
        )
        .unwrap();
    }
    let max = db.txn_config().max_duration;
    let ticking = Arc::clone(&clock);
    let mut sink = MemSink {
        hook: Some(Box::new(move |_| {
            ticking.advance(Duration::from_secs(7200));
        })),
        ..MemSink::default()
    };
    let options = DumpOptions {
        chunk_bytes: 200,
        scan: ScanOptions {
            batch_docs: 2,
            batch_bytes: 1 << 20,
        },
        ..DumpOptions::default()
    };
    let start = clock.peek();
    let summary = dump_with(&db, &DumpScope::default(), &mut sink, &Never, &options).unwrap();
    assert_eq!(summary.documents, 50);
    assert!(
        clock.peek().saturating_sub(start) > max * 10,
        "the dump did not outlive txn.max_duration"
    );
    let files = assemble(&sink.chunks, 200);
    let (target, _) = store(9);
    restore(&target, &files, &LogicalRestoreOptions::default()).unwrap();
    assert_same(&db, &target, &[("shop", "items")]);
}

// ---------------------------------------------------------------------------------------------
// Refused streams
// ---------------------------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_value)]
fn replace_file(files: &[(String, Vec<u8>)], path: &str, data: Vec<u8>) -> Files {
    files
        .iter()
        .map(|(p, d)| (p.clone(), if p == path { data.clone() } else { d.clone() }))
        .collect()
}

fn file<'a>(files: &'a [(String, Vec<u8>)], path: &str) -> &'a [u8] {
    &files.iter().find(|(p, _)| p == path).unwrap().1
}

/// Corrupted, truncated, out-of-order and newer streams are refused, and the restore leaves
/// nothing behind (PD-084).
#[test]
fn tc_bkp_013_corrupt_truncated_and_out_of_order_streams_are_refused() {
    let (source, _) = store(10);
    populate(&source);
    let files = dump_files(&source);
    let acct = file(&files, "shop/acct.ndjson").to_vec();
    let acct_text = String::from_utf8(acct.clone()).unwrap();
    let manifest = String::from_utf8(file(&files, DUMP_MANIFEST).to_vec()).unwrap();

    let mut cases: Vec<(&str, Files, ErrorCode)> = Vec::new();
    // A changed value that still parses: caught by the file hash.
    cases.push((
        "flipped value",
        replace_file(
            &files,
            "shop/acct.ndjson",
            acct_text.replacen("group-1", "group-9", 1).into_bytes(),
        ),
        ErrorCode::StorageCorruption,
    ));
    // A changed value and a manifest adjusted to its hash: caught by the collection checksum.
    {
        let changed = acct_text.replacen("group-1", "group-9", 1).into_bytes();
        let m = manifest_of(&files);
        let entry = m
            .files
            .iter()
            .find(|f| f.path == "shop/acct.ndjson")
            .unwrap();
        let forged = manifest.replace(&entry.blake3, blake3::hash(&changed).to_hex().as_str());
        let mut f = replace_file(&files, "shop/acct.ndjson", changed);
        f = replace_file(&f, DUMP_MANIFEST, forged.into_bytes());
        cases.push(("forged file hash", f, ErrorCode::StorageCorruption));
    }
    // A document count that does not match.
    {
        let m = manifest_of(&files);
        let count = m
            .databases
            .iter()
            .find(|d| d.name == "shop")
            .unwrap()
            .collections[0]
            .documents;
        assert_eq!(count, 60);
        let forged = manifest.replacen("\"documents\": 60", "\"documents\": 61", 1);
        assert_ne!(forged, manifest);
        cases.push((
            "count",
            replace_file(&files, DUMP_MANIFEST, forged.into_bytes()),
            ErrorCode::StorageCorruption,
        ));
    }
    // Truncated data file: the last line cut.
    cases.push((
        "truncated file",
        replace_file(&files, "shop/acct.ndjson", acct[..acct.len() - 10].to_vec()),
        ErrorCode::InvalidArgument,
    ));
    // Whole lines missing: the hash catches it.
    {
        let short: String = acct_text.lines().take(59).flat_map(|l| [l, "\n"]).collect();
        cases.push((
            "missing line",
            replace_file(&files, "shop/acct.ndjson", short.into_bytes()),
            ErrorCode::StorageCorruption,
        ));
    }
    // Truncated stream: no dump.json.
    cases.push((
        "no manifest",
        files[..files.len() - 1].to_vec(),
        ErrorCode::InvalidArgument,
    ));
    // A file of the dump missing from the stream.
    cases.push((
        "missing file",
        files
            .iter()
            .filter(|(p, _)| p != "shop/empty.ndjson")
            .cloned()
            .collect(),
        ErrorCode::StorageCorruption,
    ));
    // Out of order: data before metadata, database file after its collections, a file after
    // dump.json.
    {
        let mut f = files.clone();
        let i = f
            .iter()
            .position(|(p, _)| p == "shop/acct.metadata.json")
            .unwrap();
        f.swap(i, i + 1);
        cases.push(("data before metadata", f, ErrorCode::InvalidArgument));
        let mut f = files.clone();
        let db = f.remove(
            f.iter()
                .position(|(p, _)| p == "shop.database.json")
                .unwrap(),
        );
        f.insert(f.len() - 1, db);
        cases.push(("database file late", f, ErrorCode::InvalidArgument));
        let mut f = files.clone();
        let m = f.pop().unwrap();
        f.insert(0, m);
        cases.push(("manifest first", f, ErrorCode::InvalidArgument));
    }
    // A malformed document line (with a manifest that would accept it).
    cases.push((
        "malformed line",
        replace_file(&files, "shop/empty.ndjson", b"{not json}\n".to_vec()),
        ErrorCode::InvalidArgument,
    ));
    // Newer format: manifest and a metadata file.
    cases.push((
        "newer manifest",
        replace_file(
            &files,
            DUMP_MANIFEST,
            manifest
                .replacen("\"format_version\": 1", "\"format_version\": 2", 1)
                .into_bytes(),
        ),
        ErrorCode::VersionIncompatible,
    ));
    {
        let meta = String::from_utf8(file(&files, "shop/acct.metadata.json").to_vec()).unwrap();
        cases.push((
            "newer metadata",
            replace_file(
                &files,
                "shop/acct.metadata.json",
                meta.replacen("\"format_version\": 1", "\"format_version\": 2", 1)
                    .into_bytes(),
            ),
            ErrorCode::VersionIncompatible,
        ));
    }

    for (seed, (what, stream, code)) in (100u64..).zip(cases) {
        let (target, _) = store(seed);
        let err = restore(&target, &stream, &LogicalRestoreOptions::default()).unwrap_err();
        assert_eq!(err.code(), code, "{what}: {err}");
        assert_eq!(
            err.details().get("cleanup").map(String::as_str),
            Some("done"),
            "{what}"
        );
        assert!(
            names(&target).is_empty(),
            "{what}: left {:?}",
            names(&target)
        );
    }

    // Chunk-level rules: interleaved files, a reopened file, a bad path.
    let interleaved = {
        let mut c = chunks_of(&files, 64);
        let i = c.iter().position(|c| c.path == "shop/acct.ndjson").unwrap();
        let j = c
            .iter()
            .position(|c| c.path == "shop/empty.metadata.json")
            .unwrap();
        let moved = c.remove(j);
        c.insert(i + 1, moved);
        c
    };
    let mut bad_path = chunks_of(&files, 1 << 20);
    bad_path.insert(
        0,
        DumpChunk {
            path: "../escape.ndjson".into(),
            data: vec![],
            end_of_file: true,
        },
    );
    let mut unknown = chunks_of(&files, 1 << 20);
    unknown.insert(
        0,
        DumpChunk {
            path: "a.txt".into(),
            data: vec![],
            end_of_file: true,
        },
    );
    for (what, chunks) in [
        ("interleaved", interleaved),
        ("bad path", bad_path),
        ("unknown", unknown),
    ] {
        let (target, _) = store(200);
        let mut source = MemSource(chunks.into());
        let err = logical_restore(
            &target,
            &LogicalRestoreOptions::default(),
            &mut source,
            &Never,
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{what}: {err}");
        assert!(names(&target).is_empty(), "{what}");
    }
}

/// An existing target collection is refused unless `--drop`, which replaces it; a refused
/// restore leaves the existing data untouched and drops what it created before.
#[test]
fn tc_bkp_013_existing_target_needs_drop() {
    let (source, _) = store(11);
    populate(&source);
    let files = dump_files(&source);
    let (target, _) = store(12);
    target
        .create_database("shop", &DatabaseOptions::default())
        .unwrap();
    target
        .insert("shop", "orders.2026", &doc(r#"{"_id":"mine","keep":true}"#))
        .unwrap();
    let err = restore(&target, &files, &LogicalRestoreOptions::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::AlreadyExists, "{err}");
    // crm (created by the restore, before shop) is gone again; shop and its data stay.
    assert_eq!(names(&target), ["shop", "shop.orders.2026"]);
    assert!(
        target
            .get("shop", "orders.2026", &Value::String("mine".into()))
            .unwrap()
            .is_some()
    );

    let restored = restore(
        &target,
        &files,
        &LogicalRestoreOptions {
            drop_existing: true,
            scope: DumpScope::default(),
        },
    )
    .unwrap();
    assert_eq!(restored.collections.len(), 5);
    assert!(
        target
            .get("shop", "orders.2026", &Value::String("mine".into()))
            .unwrap()
            .is_none(),
        "--drop replaces the collection"
    );
    assert_same(&source, &target, &COLLECTIONS);
}

/// Cancellation stops a dump and a restore with RGN-5005; the cancelled restore is undone.
#[test]
fn tc_bkp_013_cancel_stops_dump_and_restore() {
    let (source, _) = store(13);
    populate(&source);
    for after in [0, 1, 3, 8] {
        let mut sink = MemSink::default();
        let err = dump(
            &source,
            &DumpScope::default(),
            &mut sink,
            &CancelAfter::new(after),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled, "after {after}");
    }
    let files = dump_files(&source);
    let chunks = chunks_of(&files, 512);
    for after in [0, 5, 40, chunks.len()] {
        let (target, _) = store(300 + after as u64);
        let mut src = MemSource(chunks.clone().into());
        let err = logical_restore_with(
            &target,
            &LogicalRestoreOptions::default(),
            &mut src,
            &CancelAfter::new(after),
            &ImportOptions {
                batch_docs: 7,
                batch_bytes: 1 << 20,
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled, "after {after}");
        assert!(
            names(&target).is_empty(),
            "after {after}: {:?}",
            names(&target)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Format fixture (implementation-rules.md §6)
// ---------------------------------------------------------------------------------------------

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats/dump/1")
}

/// A small deterministic source (simulated clock and RNG): the content of the v1 fixture.
fn fixture_source() -> Arc<EmbeddedDb> {
    let (db, _) = store(42);
    db.create_database("shop", &DatabaseOptions::default())
        .unwrap();
    db.create_collection(
        "shop",
        &CollectionSpec {
            options: CollectionOptions {
                validator: Some(r#"{"$jsonSchema":{"required":["name"]}}"#.into()),
                ..CollectionOptions::default()
            },
            ..CollectionSpec::document("items")
        },
    )
    .unwrap();
    for (id, name) in [(1, "pen"), (2, "ink"), (3, "pad")] {
        db.insert(
            "shop",
            "items",
            &doc(&format!(
                r#"{{"_id":{id},"name":"{name}","price":{{"$decimal":"1.50"}}}}"#
            )),
        )
        .unwrap();
    }
    db.create_index(
        "shop",
        "items",
        &IndexSpec::new("by_name", vec![IndexField::asc("name")]).unique(),
    )
    .unwrap();
    db.insert("shop", "Items", &doc(r#"{"_id":"x","n":1.5}"#))
        .unwrap();
    db
}

fn read_fixture() -> Vec<(String, Vec<u8>)> {
    let manifest_path = fixture_dir().join(DUMP_MANIFEST);
    let norm = |p: &Path| {
        let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        // CRLF checkouts must not count as a format change.
        String::from_utf8(bytes)
            .unwrap()
            .replace("\r\n", "\n")
            .into_bytes()
    };
    let manifest = DumpManifest::parse(&norm(&manifest_path)).unwrap();
    let mut files: Vec<(String, Vec<u8>)> = manifest
        .files
        .iter()
        .map(|f| (f.path.clone(), norm(&fixture_dir().join(&f.path))))
        .collect();
    files.push((DUMP_MANIFEST.into(), norm(&manifest_path)));
    files
}

/// The v1 fixture restores forever; the current writer reproduces it byte for byte (a failure
/// means the format changed: bump the version and add a fixture, never edit this one). Bless
/// with `RGN_FIXTURES_BLESS=1`.
#[test]
fn tc_bkp_013_dump_format_v1_fixture() {
    let current = dump_files(&fixture_source());
    if std::env::var("RGN_FIXTURES_BLESS").as_deref() == Ok("1") {
        for (path, data) in &current {
            let target = fixture_dir().join(path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(&target, data).unwrap();
        }
    }
    let fixture = read_fixture();
    assert_eq!(
        current.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(),
        fixture.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>()
    );
    for ((path, now), (_, then)) in current.iter().zip(&fixture) {
        assert_eq!(
            String::from_utf8_lossy(now),
            String::from_utf8_lossy(then),
            "{path} changed: dump format v1 is frozen"
        );
    }
    // Compatibility: the fixture restores into an empty store.
    let manifest = manifest_of(&fixture);
    assert_eq!(manifest.format_version, 1);
    let (target, _) = store(43);
    let restored = restore(&target, &fixture, &LogicalRestoreOptions::default()).unwrap();
    assert_eq!(restored.source_timestamp, manifest.timestamp);
    assert_eq!(names(&target), ["shop", "shop.Items", "shop.items"]);
    let items = read_all(&target, "shop", "items");
    assert_eq!(items.len(), 3);
    assert_eq!(
        items["2"].get("price"),
        Some(&rustegon_doc::json::parse_value(r#"{"$decimal":"1.50"}"#).unwrap())
    );
    let err = target
        .insert("shop", "items", &doc(r#"{"_id":9}"#))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaValidationFailed);
    let idx = target.list_indexes("shop", "items").unwrap();
    assert_eq!(idx.len(), 1);
    assert!(idx[0].unique);
}

// ---------------------------------------------------------------------------------------------
// Through BackupBackend and gRPC
// ---------------------------------------------------------------------------------------------

/// The shape of BE's backend for the logical operations: delegate to `backup_logical`.
#[derive(Default)]
struct LogicalBackend {
    db: OnceLock<Arc<EmbeddedDb>>,
    calls: Mutex<Vec<&'static str>>,
}

impl LogicalBackend {
    fn db(&self) -> Result<&Arc<EmbeddedDb>, Error> {
        self.db
            .get()
            .ok_or_else(|| Error::new(ErrorCode::Internal, "no engine"))
    }
}

impl BackupBackend for LogicalBackend {
    fn dump(
        &self,
        scope: &DumpScope,
        sink: &mut dyn DumpSink,
        cancel: &CancelToken,
    ) -> Result<DumpSummary, Error> {
        self.calls.lock().unwrap().push("dump");
        dump(self.db()?, scope, sink, cancel)
    }

    fn logical_restore(
        &self,
        options: &LogicalRestoreOptions,
        source: &mut dyn DumpSource,
        cancel: &CancelToken,
    ) -> Result<LogicalRestoreSummary, Error> {
        self.calls.lock().unwrap().push("logical_restore");
        logical_restore(self.db()?, options, source, cancel)
    }
}

/// FR-BKP-007 end to end over gRPC with the real engine: `Dump` streams format v1 (users and
/// roles of the security layer are not part of it), `LogicalRestore` imports it back.
#[tokio::test(flavor = "multi_thread")]
async fn tc_bkp_013_dump_and_restore_through_the_backup_service() {
    let backend = Arc::new(LogicalBackend::default());
    let h = Harness::start_with_backup(base_flags(), backend.clone()).await;
    assert!(backend.db.set(Arc::clone(&h.engine)).is_ok());
    let engine = Arc::clone(&h.engine);
    tokio::task::spawn_blocking(move || {
        engine
            .create_database("shop", &DatabaseOptions::default())
            .unwrap();
        for i in 0..30i64 {
            engine
                .insert(
                    "shop",
                    "items",
                    &doc(&format!(r#"{{"_id":{i},"name":"n{i}"}}"#)),
                )
                .unwrap();
        }
        engine
            .create_index(
                "shop",
                "items",
                &IndexSpec::new("by_name", vec![IndexField::asc("name")]),
            )
            .unwrap();
    })
    .await
    .unwrap();
    let before = read_all(&h.engine, "shop", "items");

    let conn = h.channel().await;
    let auth = bearer(&conn.admin_token().await);
    let mut svc = BackupServiceClient::new(conn.channel.clone());
    let mut stream = svc
        .dump(authed(
            DumpRequest {
                databases: vec![],
                collections: vec![],
            },
            &auth,
        ))
        .await
        .unwrap()
        .into_inner();
    let mut chunks = Vec::new();
    let mut started = None;
    while let Some(m) = stream.message().await.unwrap() {
        match m.item.unwrap() {
            dump_response::Item::Started(t) => started = Some(t),
            dump_response::Item::Chunk(c) => chunks.push(DumpChunk {
                path: c.path,
                data: c.data,
                end_of_file: c.end_of_file,
            }),
        }
    }
    let started = started.unwrap();
    let files = assemble(&chunks, 4 << 20);
    let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    // Only the user database: the admin user, its roles and sessions are not exported.
    assert_eq!(
        paths,
        [
            "shop.database.json",
            "shop/items.metadata.json",
            "shop/items.ndjson",
            "dump.json"
        ]
    );
    for (_, data) in &files {
        let text = String::from_utf8_lossy(data);
        assert!(
            !text.contains(common::ADMIN),
            "a security record leaked into the dump"
        );
    }
    let manifest = manifest_of(&files);
    assert_eq!(
        (started.wall_ns, started.logical),
        (manifest.timestamp.wall, manifest.timestamp.logical)
    );

    // Restore over the API: refused without --drop, accepted with it.
    let send = |drop_existing: bool| {
        let mut svc = svc.clone();
        let auth = auth.clone();
        let chunks = chunks_of(&files, 1000);
        async move {
            let (tx, rx) = mpsc::channel(8);
            let producer = tokio::spawn(async move {
                let _ = tx
                    .send(LogicalRestoreRequest {
                        item: Some(logical_restore_request::Item::Options(PbOptions {
                            drop_existing,
                            ..PbOptions::default()
                        })),
                    })
                    .await;
                for c in chunks {
                    let item =
                        logical_restore_request::Item::Chunk(rustegon_proto::v1::DumpChunk {
                            path: c.path,
                            data: c.data,
                            end_of_file: c.end_of_file,
                        });
                    if tx
                        .send(LogicalRestoreRequest { item: Some(item) })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let result = svc
                .logical_restore(authed(ReceiverStream::new(rx), &auth))
                .await;
            let _ = producer.await;
            result
        }
    };
    let err = send(false).await.unwrap_err();
    assert_eq!(code_of(&err), 1031, "{err:?}");
    let engine = Arc::clone(&h.engine);
    tokio::task::spawn_blocking(move || engine.drop_database("shop").unwrap())
        .await
        .unwrap();
    let summary = send(false).await.unwrap().into_inner();
    assert_eq!(summary.collections.len(), 1);
    assert_eq!(summary.collections[0].documents, 30);
    assert_eq!(summary.collections[0].indexes, 1);
    let after = read_all(&h.engine, "shop", "items");
    assert_eq!(
        before.values().map(without_rev).collect::<Vec<_>>(),
        after.values().map(without_rev).collect::<Vec<_>>()
    );
    let summary = send(true).await.unwrap().into_inner();
    assert_eq!(summary.collections[0].documents, 30);
    assert_eq!(
        *backend.calls.lock().unwrap(),
        [
            "dump",
            "logical_restore",
            "logical_restore",
            "logical_restore"
        ]
    );
    h.stop().await;
}
