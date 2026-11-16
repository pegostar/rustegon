// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-BKP-006: backup / list / verify / restore on a real S3-compatible store (`MinIO`), FR-BKP-006,
//! PD-065, and single-node PITR with both the base backup and the log archive on S3
//! (FR-BKP-002, PD-066, PD-088).
//!
//! The test needs a running server and is configured through the environment:
//! - `RUSTEGON_TEST_S3_ENDPOINT` (`http(s)://host:port`, required; without it the test is
//!   skipped with a message),
//! - `RUSTEGON_TEST_S3_ACCESS_KEY`, `RUSTEGON_TEST_S3_SECRET_KEY` (required with the endpoint),
//! - `RUSTEGON_TEST_S3_BUCKET` (default `rustegon-tc-bkp-006`, created if missing),
//! - `RUSTEGON_TEST_S3_CA` (PEM CA bundle for an https endpoint with a private CA).
//!
//! `scripts/ci-local.sh` (docker mode) starts a digest-pinned `MinIO` container (PD-093; the
//! bitnami entrypoint takes no `server /data` arguments) and runs it:
//! ```text
//! docker run -d --rm -p 127.0.0.1:9000:9000 -e MINIO_ROOT_USER=… -e MINIO_ROOT_PASSWORD=… \
//!   bitnamilegacy/minio@sha256:451fe6858cb770cc9d0e77ba811ce287420f781c7c1b806a386f6896471a349c
//! RUSTEGON_TEST_S3_ENDPOINT=http://127.0.0.1:9000 RUSTEGON_TEST_S3_ACCESS_KEY=… \
//!   RUSTEGON_TEST_S3_SECRET_KEY=… cargo nextest run -p rustegon-backup -E 'test(/minio/)'
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::assert_is_empty
)]
// The PITR test reads the wall clock for its targets, as `tests/pitr.rs` does.
#![allow(clippy::disallowed_methods)]

mod support;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Duration,
};

use rustegon_backup::{
    BackupId, Destination, DestinationUrl, PhysicalBackups, PhysicalConfig, PitrTarget,
    RestoreKind, RestoreRequest, S3Destination, S3Io, S3Location, S3Settings, SourceInfo,
    open_destination,
    pitr::{self, ArchiverConfig, PreparedArchiver, select_base},
    restore_data_dir_to_time,
};
use rustegon_catalog::DatabaseOptions;
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, value_to_json},
};
use rustegon_engine::{
    TxnOptions,
    embedded::{CancelCheck, EmbeddedDb, FenceOptions, LogStoreOptions, ScanOptions},
};
use rustegon_mvcc::Timestamp;
use rustegon_sim::{SimFileSystem, workload::rng::SimRng};
use rustegon_sim_api::{Clock, FileSystem, OpenMode, OsRng, Rng, StdFileSystem, SystemClock};
use rustegon_storage::{
    EngineOptions,
    encryption::{FileKekProvider, KekProvider, SecretKey},
};

struct MinioConfig {
    endpoint: String,
    bucket: String,
    settings: S3Settings,
    dir: tempfile::TempDir,
}

/// The server configuration, or `None` (test skipped) when no endpoint is configured.
fn config() -> Option<MinioConfig> {
    let Ok(endpoint) = std::env::var("RUSTEGON_TEST_S3_ENDPOINT") else {
        eprintln!(
            "SKIPPED: TC-BKP-006 needs an S3-compatible server; set RUSTEGON_TEST_S3_ENDPOINT, \
             RUSTEGON_TEST_S3_ACCESS_KEY and RUSTEGON_TEST_S3_SECRET_KEY (scripts/ci-local.sh \
             starts MinIO in docker mode)"
        );
        return None;
    };
    let key = std::env::var("RUSTEGON_TEST_S3_ACCESS_KEY").expect("RUSTEGON_TEST_S3_ACCESS_KEY");
    let secret = std::env::var("RUSTEGON_TEST_S3_SECRET_KEY").expect("RUSTEGON_TEST_S3_SECRET_KEY");
    let bucket = std::env::var("RUSTEGON_TEST_S3_BUCKET")
        .unwrap_or_else(|_| "rustegon-tc-bkp-006".to_owned());
    // Credentials go through a credentials file, the way a server is configured.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s3.json");
    let json = serde_json::json!({"access_key_id": key, "secret_access_key": secret});
    let mut f = StdFileSystem.open(&path, OpenMode::Truncate).unwrap();
    f.append(json.to_string().as_bytes()).unwrap();
    f.sync_data().unwrap();
    Some(MinioConfig {
        endpoint,
        bucket,
        settings: S3Settings {
            credentials_file: Some(path),
            ca_file: std::env::var_os("RUSTEGON_TEST_S3_CA").map(Into::into),
            part_size_mib: 5,
            ..S3Settings::default()
        },
        dir,
    })
}

/// A prefix unique to this run, with characters that need URI encoding.
fn run_prefix(name: &str) -> String {
    format!("tc bkp+006/{name}-{:016x}", OsRng.next_u64())
}

fn open(cfg: &MinioConfig, prefix: &str) -> S3Destination {
    S3Destination::open(
        &S3Location {
            bucket: cfg.bucket.clone(),
            prefix: prefix.to_owned(),
            region: Some("us-east-1".into()),
            endpoint: Some(cfg.endpoint.clone()),
        },
        &cfg.settings,
        S3Io::production(Arc::new(StdFileSystem)),
        &|_| None,
    )
    .unwrap()
}

#[test]
fn tc_bkp_006_minio_backup_round_trip_through_s3_url() {
    let Some(cfg) = config() else { return };
    let prefix = run_prefix("roundtrip");
    open(&cfg, &prefix).create_bucket().unwrap();
    // The same path the server and the CLI use: URL → open_destination.
    let url = DestinationUrl::parse(&format!(
        "s3://{}/{}?region=us-east-1&endpoint={}",
        cfg.bucket,
        prefix.replace(' ', "%20").replace('+', "%2B"),
        cfg.endpoint
    ))
    .unwrap();
    let dest = open_destination(&url, Arc::new(StdFileSystem), &cfg.settings).unwrap();
    // 12 MiB + 5 bytes with 5 MiB parts: a three-part multipart upload.
    support::round_trip(dest.as_ref(), 12 * (1 << 20) + 5, 1);
}

#[test]
fn tc_bkp_006_minio_listing_paginates_beyond_one_page() {
    let Some(cfg) = config() else { return };
    let prefix = run_prefix("list");
    let dest = open(&cfg, &prefix);
    dest.create_bucket().unwrap();
    // One more than the 1000-key page of ListObjectsV2.
    let keys: Vec<String> = (0..1001).map(|i| format!("many/k{i:05}")).collect();
    for key in &keys {
        dest.put_bytes(key, key.as_bytes()).unwrap();
    }
    assert_eq!(dest.list("many").unwrap(), keys);
    assert_eq!(dest.list_children("").unwrap(), ["many"]);
    for key in &keys {
        dest.delete(key).unwrap();
    }
    assert_eq!(dest.list("").unwrap(), Vec::<String>::new());
}

#[test]
fn tc_bkp_006_minio_wrong_credentials_are_rgn_3002_not_retryable() {
    let Some(mut cfg) = config() else { return };
    let path = cfg.dir.path().join("wrong.json");
    let mut f = StdFileSystem.open(&path, OpenMode::Truncate).unwrap();
    f.append(br#"{"access_key_id":"nobody","secret_access_key":"wrong-secret"}"#)
        .unwrap();
    drop(f);
    cfg.settings.credentials_file = Some(path);
    let dest = open(&cfg, &run_prefix("denied"));
    let err = dest.list("").unwrap_err();
    assert!(!err.to_string().contains("wrong-secret"), "{err}");
    let common = rustegon_common::Error::from(err);
    assert_eq!(common.code().code(), 3002, "{common}");
    assert!(!common.retryable());
}

// ---------------------------------------------------------------------------------------------
// PITR over S3 (FR-BKP-002, FR-BKP-006, PD-066, PD-088, PD-093)
// ---------------------------------------------------------------------------------------------

const STORE: &str = "/node/store";
const DB: &str = "shop";
const COLL: &str = "acct";
const ACCOUNTS: i64 = 6;
const CANARY: &str = "MINIO-PITR-PLAINTEXT-CANARY";

fn doc(id: i64, bal: i64) -> Document {
    Document::try_from_fields(vec![
        ("_id".to_owned(), Value::Int64(id)),
        ("bal".to_owned(), Value::Int64(bal)),
        ("note".to_owned(), Value::String(format!("{CANARY}-{id}"))),
    ])
    .unwrap()
}

fn bal(d: &Document) -> i64 {
    match d.get("bal") {
        Some(Value::Int64(b)) => *b,
        other => panic!("bal: {other:?}"),
    }
}

/// Every collection at `at` (else at the latest closed timestamp), canonical JSON per document.
fn state(db: &Arc<EmbeddedDb>, at: Option<Timestamp>) -> BTreeMap<String, Vec<String>> {
    let snapshot = match at {
        Some(ts) => db.pin_snapshot_at(ts, &FenceOptions::default()),
        None => db.pin_snapshot(&FenceOptions::default()),
    }
    .map(Arc::new)
    .unwrap();
    let mut out = BTreeMap::new();
    for d in db.databases_at(&snapshot).unwrap() {
        for c in db.collections_at(&snapshot, &d.name).unwrap() {
            let mut rows = Vec::new();
            for batch in db
                .scan_at(&snapshot, &d.name, &c.name, ScanOptions::default())
                .unwrap()
            {
                for doc in batch.unwrap() {
                    rows.push(value_to_json(&Value::Object(doc), JsonMode::Canonical));
                }
            }
            out.insert(format!("{}.{}", d.name, c.name), rows);
        }
    }
    out
}

fn now_ts() -> Timestamp {
    let wall = SystemClock::new()
        .wall()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    Timestamp::new(u64::try_from(wall.as_nanos()).unwrap(), 0)
}

/// One round of writes: transfers keeping the sum, an insert and a delete.
fn write_round(db: &Arc<EmbeddedDb>, round: i64) {
    for i in 0..10 {
        let (from, to) = ((round + i) % ACCOUNTS, (round + i + 1) % ACCOUNTS);
        let t = db.begin(&TxnOptions::default());
        let a = t.get(DB, COLL, &Value::Int64(from)).unwrap().unwrap();
        let b = t.get(DB, COLL, &Value::Int64(to)).unwrap().unwrap();
        t.replace(DB, COLL, &Value::Int64(from), &doc(from, bal(&a) - 1))
            .unwrap();
        t.replace(DB, COLL, &Value::Int64(to), &doc(to, bal(&b) + 1))
            .unwrap();
        t.commit().unwrap();
    }
    db.insert(DB, "log", &doc(100 + round, round)).unwrap();
    if round > 0 {
        db.delete(DB, "log", &Value::Int64(100 + round - 1))
            .unwrap();
    }
}

/// A store on the simulated file system archives its log to `MinIO`, with a base backup on the
/// same destination and writes between several targets T; every restore to a T from S3 equals
/// the source read at T. With a KEK, no object on S3 holds document plaintext.
fn pitr_round_trip(cfg: &MinioConfig, kek: Option<Arc<dyn KekProvider>>, tag: &str) {
    let dest = Arc::new(open(cfg, &run_prefix(tag)));
    dest.create_bucket().unwrap();
    let dest_dyn: Arc<dyn Destination> = Arc::clone(&dest) as Arc<dyn Destination>;
    let fs = Arc::new(SimFileSystem::new());
    let sim = || Arc::clone(&fs) as Arc<dyn FileSystem>;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let prepared = PreparedArchiver::load(sim(), Path::new(STORE), &SimRng::new(1)).unwrap();
    let db = Arc::new(
        EmbeddedDb::open_with_log_options(
            sim(),
            Path::new(STORE),
            Arc::clone(&clock),
            Arc::new(SimRng::new(2)),
            EngineOptions {
                memtable_size: 32 << 10,
                ..EngineOptions::default()
            },
            kek.clone(),
            LogStoreOptions {
                // Small segments: several are archived (sealed by size and by the timed rolls).
                segment_size: 8 << 10,
                archive_floor: Some(prepared.floor()),
                ..LogStoreOptions::default()
            },
        )
        .unwrap(),
    );
    let mut config = PhysicalConfig::new(
        PathBuf::from("/node"),
        SourceInfo {
            cluster_id: "single-node".into(),
            node_id: "node1".into(),
            server_version: "test".into(),
        },
        kek.as_ref().map(|k| k.key_id().to_string()),
    );
    config.pitr_timeline = Some(prepared.timeline().to_owned());
    let physical = PhysicalBackups::open(
        Arc::clone(&db),
        sim(),
        Arc::clone(&clock),
        Arc::new(SimRng::new(3)),
        config,
    )
    .unwrap();
    let mut archiver = prepared.start(
        Arc::clone(&db),
        Arc::clone(&clock),
        Arc::clone(&dest_dyn),
        kek.clone(),
        ArchiverConfig::default(),
    );

    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    for id in 0..ACCOUNTS {
        db.insert(DB, COLL, &doc(id, 100)).unwrap();
    }
    db.insert(DB, "log", &doc(99, 0)).unwrap();
    let never: CancelCheck = Arc::new(|| false);
    let base = physical.create_backup(dest.as_ref(), &never).unwrap();
    assert!(
        base.manifest.pitr.is_some(),
        "the base records the timeline"
    );
    let mut targets = Vec::new();
    for round in 0..4 {
        write_round(&db, round);
        // Odd rounds leave their segment open: those targets sit in a segment sealed later.
        archiver.pass(round % 2 == 0).unwrap();
        thread::sleep(Duration::from_millis(2));
        targets.push(now_ts());
        thread::sleep(Duration::from_millis(2));
    }
    write_round(&db, 4);
    // The final timed roll seals a segment closing a timestamp above every target (PD-088).
    archiver.pass(true).unwrap();
    let expected: Vec<_> = targets.iter().map(|t| state(&db, Some(*t))).collect();
    let index = pitr::load_index(dest.as_ref(), archiver.timeline())
        .unwrap()
        .unwrap();
    assert!(index.segments.len() >= 2, "{}", index.segments.len());
    assert!(index.breaks.is_empty());
    assert_eq!(index.segments.iter().all(|s| s.encrypted), kek.is_some());
    drop(archiver);
    drop(physical);
    drop(db);

    for (i, (t, want)) in targets.iter().zip(&expected).enumerate() {
        let dir = format!("/restored-{i}");
        let manifest = select_base(dest.as_ref(), *t).unwrap();
        assert_eq!(manifest.backup_id, base.manifest.backup_id);
        let id = BackupId::parse(&manifest.backup_id).unwrap();
        let report = restore_data_dir_to_time(
            &sim(),
            &(Arc::new(SystemClock::new()) as Arc<dyn Clock>),
            &(Arc::new(SimRng::new(4)) as Arc<dyn Rng>),
            &RestoreRequest {
                source: dest.as_ref(),
                id: &id,
                data_dir: Path::new(&dir),
                kind: RestoreKind::Backup,
                kek: kek.clone(),
            },
            PitrTarget {
                archive: dest.as_ref(),
                ts: *t,
            },
        )
        .unwrap_or_else(|e| panic!("{tag} target {i} ({t}): {e}"));
        assert_eq!(report.pitr.unwrap().target, *t);
        let restored = Arc::new(
            EmbeddedDb::open_with_kek(
                sim(),
                &Path::new(&dir).join("store"),
                Arc::new(SystemClock::new()),
                Arc::new(SimRng::new(5)),
                EngineOptions::default(),
                kek.clone(),
            )
            .unwrap(),
        );
        assert_eq!(&state(&restored, None), want, "{tag} target {i} ({t})");
    }
    if kek.is_some() {
        for key in dest.list("").unwrap() {
            let bytes = dest.get_bytes(&key, 1 << 30).unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains(CANARY),
                "{key} holds plaintext"
            );
        }
    }
}

/// TC-BKP-006 + TC-BKP-004 on `MinIO` (FR-BKP-002, FR-BKP-006): PITR with the base backup and
/// the log archive on S3, restored to several T, for a plaintext and an encrypted store.
#[test]
fn tc_bkp_006_minio_pitr_archive_and_restore_to_time() {
    let Some(cfg) = config() else { return };
    pitr_round_trip(&cfg, None, "pitr-plain");
    let kek: Arc<dyn KekProvider> =
        Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([0x5a; 32])));
    pitr_round_trip(&cfg, Some(kek), "pitr-kek");
}
