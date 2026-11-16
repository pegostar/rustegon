// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Single-node point-in-time recovery on the simulated file system (M13a lane BF; FR-BKP-002,
//! FR-BKP-004, TC-BKP-004, AC-BKP-002, PD-066, PD-088):
//! - TC-BKP-004: restores to random timestamps between base backups and the archive's end equal
//!   the source read at those timestamps, with concurrent transactions racing segment rolls and
//!   archiver passes (several seeds), for plaintext and encrypted (v2 segments, KEK only) stores,
//!   and with the PD-066 `T + txn.max_duration` stop rule alone;
//! - refusals: a target before the oldest backup, past the archive, across a continuity gap,
//!   without or with the wrong KEK, from a corrupt segment;
//! - destination outage beyond `max_unarchived_bytes`: writes go on, continuity breaks, a restore
//!   across the gap is refused, one after a new base backup succeeds (plaintext and encrypted);
//!   a destination that hangs mid-copy never blocks commits;
//! - crash safety: a crash at any operation of an archiver pass never loses a segment that has
//!   left the local disk and a restore to the end afterwards is exact (plaintext and encrypted);
//!   a crash at any operation of a PITR restore is resumable.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::assert_is_empty
)]
// Writer threads run on real time beside the archiver (as the BD/BE concurrency tests).
#![allow(clippy::disallowed_methods)]

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use rustegon_backup::{
    BackupError, BackupId, Destination, LocalDestination, ObjectReader, PhysicalBackups,
    PhysicalConfig, PitrTarget, RestoreKind, RestoreReport, RestoreRequest, SourceInfo,
    pitr::{
        self, ArchiveIndex, ArchiverConfig, PitrArchiver, PreparedArchiver, StopRule, load_index,
        select_base,
    },
    restore_data_dir_to_time,
};
use rustegon_catalog::DatabaseOptions;
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, value_to_json},
};
use rustegon_engine::{
    TxnOptions,
    embedded::{EmbeddedDb, FenceOptions, LogStoreOptions, PinnedSnapshot, ScanOptions},
};
use rustegon_mvcc::Timestamp;
use rustegon_sim::{
    CrashMode, SimFileSystem,
    workload::{clock::SimClock, rng::SimRng},
};
use rustegon_sim_api::{Clock, FileSystem, OpenMode, SystemClock};
use rustegon_storage::{
    EngineOptions,
    encryption::{FileKekProvider, KekProvider, SecretKey},
};

const DB: &str = "shop";
const COLL: &str = "acct";
const NODE: &str = "/node";
const STORE: &str = "/node/store";
const BACKUPS: &str = "/backups";
const ARCHIVE: &str = "/archive";
const ACCOUNTS: i64 = 8;
const CANARY: &str = "PITR-PLAINTEXT-CANARY";
/// Small log segments: rolls by size race the timed rolls and the writers.
const SEGMENT_SIZE: u64 = 8 << 10;
const T0: Duration = Duration::from_secs(1_700_000_000);

fn options() -> EngineOptions {
    EngineOptions {
        memtable_size: 32 << 10,
        ..EngineOptions::default()
    }
}

fn kek(byte: u8) -> Arc<dyn KekProvider> {
    Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([byte; 32])))
}

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

/// Every collection at `snapshot`, canonical JSON per document.
fn dump(db: &Arc<EmbeddedDb>, snapshot: &Arc<PinnedSnapshot>) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for d in db.databases_at(snapshot).unwrap() {
        for c in db.collections_at(snapshot, &d.name).unwrap() {
            let mut rows = Vec::new();
            for batch in db
                .scan_at(snapshot, &d.name, &c.name, ScanOptions::default())
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

/// The source read at `ts` (an arbitrary past timestamp, closed by the fence first).
fn state_at(db: &Arc<EmbeddedDb>, ts: Timestamp) -> BTreeMap<String, Vec<String>> {
    let snapshot = Arc::new(db.pin_snapshot_at(ts, &FenceOptions::default()).unwrap());
    dump(db, &snapshot)
}

fn latest(db: &Arc<EmbeddedDb>) -> BTreeMap<String, Vec<String>> {
    let snapshot = Arc::new(db.pin_snapshot(&FenceOptions::default()).unwrap());
    dump(db, &snapshot)
}

/// A source node: store with the archive floor, physical backups recording the timeline, and
/// the archiver.
struct Source {
    db: Arc<EmbeddedDb>,
    physical: PhysicalBackups,
    archiver: PitrArchiver,
    backups: LocalDestination,
}

fn sim(fs: &Arc<SimFileSystem>) -> Arc<dyn FileSystem> {
    Arc::clone(fs) as Arc<dyn FileSystem>
}

fn open_source(
    fs: &Arc<SimFileSystem>,
    clock: Arc<dyn Clock>,
    seed: u64,
    kek: Option<Arc<dyn KekProvider>>,
    archive: Arc<dyn Destination>,
    config: ArchiverConfig,
) -> Source {
    let prepared = PreparedArchiver::load(sim(fs), Path::new(STORE), &SimRng::new(seed)).unwrap();
    let db = Arc::new(
        EmbeddedDb::open_with_log_options(
            sim(fs),
            Path::new(STORE),
            Arc::clone(&clock),
            Arc::new(SimRng::new(seed + 1000)),
            options(),
            kek.clone(),
            LogStoreOptions {
                segment_size: SEGMENT_SIZE,
                archive_floor: Some(prepared.floor()),
                ..LogStoreOptions::default()
            },
        )
        .unwrap(),
    );
    let mut config_b = PhysicalConfig::new(
        PathBuf::from(NODE),
        SourceInfo {
            cluster_id: "single-node".into(),
            node_id: "node1".into(),
            server_version: "test".into(),
        },
        kek.as_ref().map(|k| k.key_id().to_string()),
    );
    config_b.pitr_timeline = Some(prepared.timeline().to_owned());
    let physical = PhysicalBackups::open(
        Arc::clone(&db),
        sim(fs),
        Arc::clone(&clock),
        Arc::new(SimRng::new(seed + 2000)),
        config_b,
    )
    .unwrap();
    let archiver = prepared.start(Arc::clone(&db), clock, archive, kek, config);
    Source {
        db,
        physical,
        archiver,
        backups: LocalDestination::open(sim(fs), BACKUPS).unwrap(),
    }
}

fn local_archive(fs: &Arc<SimFileSystem>) -> Arc<dyn Destination> {
    Arc::new(LocalDestination::open(sim(fs), ARCHIVE).unwrap())
}

impl Source {
    fn backup(&self) -> Timestamp {
        let never: rustegon_engine::embedded::CancelCheck = Arc::new(|| false);
        let created = self.physical.create_backup(&self.backups, &never).unwrap();
        let t = created.manifest.consistency.timestamp;
        Timestamp::new(t.wall, t.logical)
    }
}

fn populate(db: &EmbeddedDb) {
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    for id in 0..ACCOUNTS {
        db.insert(DB, COLL, &doc(id, 100)).unwrap();
    }
    db.insert(DB, "log", &doc(0, 0)).unwrap();
}

/// One transfer between two random accounts (sum invariant); retryable failures are skipped.
fn transfer(db: &Arc<EmbeddedDb>, rng: &SimRng) {
    let from = i64::try_from(rng.below(ACCOUNTS as u64)).unwrap();
    let to = (from + 1 + i64::try_from(rng.below(ACCOUNTS as u64 - 1)).unwrap()) % ACCOUNTS;
    let t = db.begin(&TxnOptions::default());
    let result = (|| -> Result<(), Error> {
        let a = t.get(DB, COLL, &Value::Int64(from))?.unwrap();
        let b = t.get(DB, COLL, &Value::Int64(to))?.unwrap();
        t.replace(DB, COLL, &Value::Int64(from), &doc(from, bal(&a) - 1))?;
        t.replace(DB, COLL, &Value::Int64(to), &doc(to, bal(&b) + 1))?;
        t.commit()?;
        Ok(())
    })();
    match result {
        Ok(()) => {}
        Err(e) if e.retryable() => {
            let _ = t.rollback();
        }
        Err(e) => panic!("transfer: {e}"),
    }
}

/// Writer threads: transfers plus inserts of new documents, until stopped.
struct Writers {
    stop: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<u64>>,
}

impl Writers {
    fn start(db: &Arc<EmbeddedDb>, seed: u64, n: u64) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let handles = (0..n)
            .map(|w| {
                let (db, stop) = (Arc::clone(db), Arc::clone(&stop));
                thread::spawn(move || {
                    let rng = SimRng::new(seed * 100 + w);
                    let mut ops = 0u64;
                    // At least 8 operations per writer: on a slow host (arm64 under QEMU) the
                    // wall-clock pauses of a run can end before the writers did any real work.
                    while !stop.load(Ordering::Relaxed) || ops < 8 {
                        if rng.below(4) == 0 {
                            let id = i64::try_from(1000 + w * 1_000_000 + ops).unwrap();
                            db.insert(DB, "log", &doc(id, 0)).unwrap();
                        } else {
                            transfer(&db, &rng);
                        }
                        ops += 1;
                    }
                    ops
                })
            })
            .collect();
        Self { stop, handles }
    }

    fn stop(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.handles.into_iter().map(|h| h.join().unwrap()).sum()
    }
}

/// Archiver passes with timed rolls in a loop, racing the writers, until stopped.
fn archiver_loop(
    mut archiver: PitrArchiver,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<PitrArchiver> {
    thread::spawn(move || {
        let mut i = 0u64;
        while !stop.load(Ordering::Relaxed) {
            archiver.pass(i.is_multiple_of(2)).unwrap();
            i += 1;
            thread::sleep(Duration::from_millis(3));
        }
        archiver
    })
}

fn now_ts() -> Timestamp {
    let wall = SystemClock::new()
        .wall()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    Timestamp::new(u64::try_from(wall.as_nanos()).unwrap(), 0)
}

fn pitr_restore(
    fs: &Arc<SimFileSystem>,
    backups: &dyn Destination,
    archive: &dyn Destination,
    target: Timestamp,
    data_dir: &str,
    kek: Option<Arc<dyn KekProvider>>,
) -> Result<RestoreReport, Error> {
    let manifest = select_base(backups, target)?;
    let id = BackupId::parse(&manifest.backup_id).unwrap();
    restore_data_dir_to_time(
        &sim(fs),
        &(Arc::new(SystemClock::new()) as Arc<dyn Clock>),
        &(Arc::new(SimRng::new(77)) as Arc<dyn rustegon_sim_api::Rng>),
        &RestoreRequest {
            source: backups,
            id: &id,
            data_dir: Path::new(data_dir),
            kind: RestoreKind::Backup,
            kek,
        },
        PitrTarget {
            archive,
            ts: target,
        },
    )
}

fn restored(
    fs: &Arc<SimFileSystem>,
    data_dir: &str,
    kek: Option<Arc<dyn KekProvider>>,
) -> BTreeMap<String, Vec<String>> {
    let db = Arc::new(
        EmbeddedDb::open_with_kek(
            sim(fs),
            &Path::new(data_dir).join("store"),
            Arc::new(SystemClock::new()),
            Arc::new(SimRng::new(5)),
            options(),
            kek,
        )
        .unwrap(),
    );
    latest(&db)
}

fn sum_of(state: &BTreeMap<String, Vec<String>>) -> i64 {
    state[&format!("{DB}.{COLL}")]
        .iter()
        .map(|r| {
            let Value::Object(d) = rustegon_doc::json::parse_value(r).unwrap() else {
                panic!()
            };
            bal(&d)
        })
        .sum()
}

fn index_of(archive: &dyn Destination, timeline: &str) -> ArchiveIndex {
    load_index(archive, timeline).unwrap().unwrap()
}

/// TC-BKP-004 core: writers race segment rolls and archiver passes; two base backups; restores
/// to random timestamps equal the source read there.
fn run_random_targets(seed: u64, kek: Option<Arc<dyn KekProvider>>) {
    let fs = Arc::new(SimFileSystem::new());
    let archive = local_archive(&fs);
    let source = open_source(
        &fs,
        Arc::new(SystemClock::new()),
        seed,
        kek.clone(),
        Arc::clone(&archive),
        ArchiverConfig::default(),
    );
    populate(&source.db);
    let rng = SimRng::new(seed);
    let timeline = source.archiver.timeline().to_owned();
    let (db, physical, backups) = (Arc::clone(&source.db), source.physical, source.backups);
    let stop = Arc::new(AtomicBool::new(false));
    let archiver = archiver_loop(source.archiver, Arc::clone(&stop));
    let writers = Writers::start(&db, seed, 3);
    let pause = |rng: &SimRng| thread::sleep(Duration::from_millis(5 + rng.below(25)));

    pause(&rng);
    let never: rustegon_engine::embedded::CancelCheck = Arc::new(|| false);
    let t_b1 = {
        let m = physical.create_backup(&backups, &never).unwrap().manifest;
        assert_eq!(m.pitr.as_ref().unwrap().timeline, timeline);
        Timestamp::new(
            m.consistency.timestamp.wall,
            m.consistency.timestamp.logical,
        )
    };
    let mut targets = vec![t_b1];
    for i in 0..6 {
        pause(&rng);
        targets.push(now_ts());
        if i == 2 {
            physical.create_backup(&backups, &never).unwrap();
        }
    }
    pause(&rng);
    let ops = writers.stop();
    assert!(ops > 20, "too few writes: {ops}");
    stop.store(true, Ordering::Relaxed);
    let mut archiver = archiver.join().unwrap();
    // The final timed roll closes a timestamp above every target.
    archiver.pass(true).unwrap();
    let index = index_of(archive.as_ref(), &timeline);
    assert!(
        index.segments.len() > 3,
        "few segments: {}",
        index.segments.len()
    );
    assert!(index.breaks.is_empty());
    assert_eq!(
        index.segments.iter().all(|s| s.encrypted),
        kek.is_some(),
        "segment format follows the store's encryption"
    );
    let expected: Vec<_> = targets.iter().map(|t| state_at(&db, *t)).collect();
    drop(physical);
    drop(archiver);
    drop(db);

    let mut replayed = 0;
    for (i, (t, want)) in targets.iter().zip(&expected).enumerate() {
        let dir = format!("/restored-{i}");
        let report = pitr_restore(&fs, &backups, archive.as_ref(), *t, &dir, kek.clone())
            .unwrap_or_else(|e| panic!("seed {seed} target {i} ({t}): {e}"));
        let pitr = report.pitr.unwrap();
        assert_eq!(pitr.target, *t);
        replayed += pitr.entries;
        let got = restored(&fs, &dir, kek.clone());
        assert_eq!(&got, want, "seed {seed} target {i} ({t}, {:?})", pitr.stop);
        assert_eq!(sum_of(&got), 100 * ACCOUNTS, "seed {seed} target {i}");
        // Nothing of the restore is left besides the store.
        let mut names: Vec<String> = fs
            .read_dir(Path::new(&dir))
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["store"], "seed {seed} target {i}");
    }
    assert!(
        replayed > 0,
        "seed {seed}: no restore replayed archived entries"
    );
    if kek.is_some() {
        // Archived v2 segments never hold the plaintext of documents.
        for key in archive.list(pitr::PITR_DIR).unwrap() {
            let bytes = archive.get_bytes(&key, 1 << 30).unwrap();
            let hay = String::from_utf8_lossy(&bytes);
            assert!(!hay.contains(CANARY), "{key} holds plaintext");
        }
    }
}

#[test]
fn tc_bkp_004_pitr_to_random_timestamps_equals_source_with_racing_transactions() {
    for seed in 1..=4 {
        run_random_targets(seed, None);
    }
}

#[test]
fn tc_bkp_004_encrypted_pitr_to_random_timestamps_over_seeds() {
    for seed in 21..=23 {
        run_random_targets(seed, Some(kek(u8::try_from(seed).unwrap())));
    }
}

#[test]
fn tc_bkp_004_encrypted_archive_restores_only_with_the_kek() {
    run_random_targets(11, Some(kek(7)));

    // Refusals before anything is written: no KEK, another KEK.
    let fs = Arc::new(SimFileSystem::new());
    let archive = local_archive(&fs);
    let mut source = open_source(
        &fs,
        Arc::new(SystemClock::new()),
        12,
        Some(kek(7)),
        Arc::clone(&archive),
        ArchiverConfig::default(),
    );
    populate(&source.db);
    source.backup();
    for i in 0..30 {
        source
            .db
            .replace(
                DB,
                COLL,
                &Value::Int64(i % ACCOUNTS),
                &doc(i % ACCOUNTS, 100),
            )
            .unwrap();
    }
    let t = now_ts();
    source.archiver.pass(true).unwrap();
    let backups = LocalDestination::open(sim(&fs), BACKUPS).unwrap();
    for (key, why) in [(None, "no KEK"), (Some(kek(8)), "another KEK")] {
        let err = pitr_restore(&fs, &backups, archive.as_ref(), t, "/r-kek", key).unwrap_err();
        assert_eq!(err.code(), ErrorCode::KeyUnavailable, "{why}: {err}");
        assert!(
            fs.read_dir(Path::new("/r-kek")).is_err(),
            "{why}: nothing written"
        );
    }
    let want = state_at(&source.db, t);
    drop(source);
    pitr_restore(&fs, &backups, archive.as_ref(), t, "/r-kek", Some(kek(7))).unwrap();
    assert_eq!(restored(&fs, "/r-kek", Some(kek(7))), want);
}

/// PD-066 rule alone: without closed timestamps (size rolls only, no timed roll), the replay
/// stops at the first entry evaluated after `T + txn.max_duration`.
#[test]
fn tc_bkp_004_replay_stops_at_t_plus_max_duration_without_closed_timestamps() {
    let fs = Arc::new(SimFileSystem::new());
    let clock = Arc::new(SimClock::new(
        T0,
        Duration::from_micros(10),
        Duration::from_micros(10),
    ));
    let archive = local_archive(&fs);
    let mut source = open_source(
        &fs,
        Arc::clone(&clock) as Arc<dyn Clock>,
        21,
        None,
        Arc::clone(&archive),
        ArchiverConfig::default(),
    );
    populate(&source.db);
    source.backup();
    let rng = SimRng::new(21);
    for _ in 0..40 {
        transfer(&source.db, &rng);
    }
    let t = Timestamp::new(u64::try_from(clock.peek().as_nanos()).unwrap(), 0);
    for _ in 0..40 {
        transfer(&source.db, &rng);
    }
    // Before the margin has passed, T is beyond the archive (no closed timestamp either).
    source.db.replica().force_roll_log().unwrap();
    source.archiver.pass(false).unwrap();
    let backups = LocalDestination::open(sim(&fs), BACKUPS).unwrap();
    let err = pitr_restore(&fs, &backups, archive.as_ref(), t, "/early", None).unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");
    assert!(err.message().contains("beyond"), "{err}");

    clock.advance(Duration::from_secs(61));
    for _ in 0..20 {
        transfer(&source.db, &rng);
    }
    source.db.replica().force_roll_log().unwrap();
    source.archiver.pass(false).unwrap();
    let want = state_at(&source.db, t);
    let ts_rule = index_of(archive.as_ref(), source.archiver.timeline());
    assert!(ts_rule.segments.iter().all(|s| s.closed_ts.is_none()));
    drop(source);
    let report = pitr_restore(&fs, &backups, archive.as_ref(), t, "/late", None).unwrap();
    assert_eq!(report.pitr.unwrap().stop, StopRule::MaxDuration);
    assert_eq!(restored(&fs, "/late", None), want);
}

#[test]
fn tc_bkp_004_refuses_targets_outside_the_window_and_corrupt_segments() {
    let fs = Arc::new(SimFileSystem::new());
    let archive = local_archive(&fs);
    let mut source = open_source(
        &fs,
        Arc::new(SystemClock::new()),
        31,
        None,
        Arc::clone(&archive),
        ArchiverConfig::default(),
    );
    populate(&source.db);
    let before = now_ts();
    thread::sleep(Duration::from_millis(2));
    source.backup();
    let rng = SimRng::new(31);
    for _ in 0..60 {
        transfer(&source.db, &rng);
    }
    let t = now_ts();
    source.archiver.pass(true).unwrap();
    let backups = LocalDestination::open(sim(&fs), BACKUPS).unwrap();

    let err = pitr_restore(&fs, &backups, archive.as_ref(), before, "/r", None).unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");
    assert!(err.message().contains("before the oldest"), "{err}");

    let far = Timestamp::new(t.wall + 3_600_000_000_000, 0);
    let err = pitr_restore(&fs, &backups, archive.as_ref(), far, "/r", None).unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");
    assert!(err.message().contains("beyond"), "{err}");
    assert!(
        fs.read_dir(Path::new("/r")).is_err(),
        "refusals write nothing"
    );

    // A damaged segment copy is refused while downloading; once repaired, the rerun completes.
    let timeline = source.archiver.timeline().to_owned();
    let want = state_at(&source.db, t);
    drop(source);
    let index = index_of(archive.as_ref(), &timeline);
    let seg = index
        .segments
        .iter()
        .rfind(|s| s.last_index.is_some())
        .unwrap();
    let path = Path::new(ARCHIVE)
        .join("pitr")
        .join(&timeline)
        .join("segments")
        .join(format!("{:020}.rlog", seg.id));
    let original = read(&fs, &path);
    let mut damaged = original.clone();
    let mid = damaged.len() / 2;
    damaged[mid] ^= 0x40;
    write(&fs, &path, &damaged);
    let err = pitr_restore(&fs, &backups, archive.as_ref(), t, "/r", None).unwrap_err();
    assert_eq!(err.code(), ErrorCode::StorageCorruption, "{err}");
    write(&fs, &path, &original);
    let report = pitr_restore(&fs, &backups, archive.as_ref(), t, "/r", None).unwrap();
    assert!(report.resumed);
    assert_eq!(restored(&fs, "/r", None), want);
}

fn read(fs: &SimFileSystem, path: &Path) -> Vec<u8> {
    let f = fs.open(path, OpenMode::Read).unwrap();
    let mut b = vec![0; usize::try_from(f.size().unwrap()).unwrap()];
    f.read_exact_at(&mut b, 0).unwrap();
    b
}

fn write(fs: &SimFileSystem, path: &Path, bytes: &[u8]) {
    let mut f = fs.open(path, OpenMode::Truncate).unwrap();
    f.append(bytes).unwrap();
    f.sync_data().unwrap();
}

/// A destination that fails every call while `down` is set.
struct Flaky {
    inner: LocalDestination,
    down: Arc<AtomicBool>,
}

impl Flaky {
    fn check(&self, op: &'static str, key: &str) -> Result<(), BackupError> {
        if self.down.load(Ordering::Relaxed) {
            return Err(BackupError::Destination {
                destination: self.inner.describe(),
                op,
                key: key.to_owned(),
                source: io::Error::new(io::ErrorKind::ConnectionRefused, "destination down"),
            });
        }
        Ok(())
    }
}

impl Destination for Flaky {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn put_reader(
        &self,
        key: &str,
        size: u64,
        reader: &mut dyn io::Read,
    ) -> Result<(), BackupError> {
        self.check("put", key)?;
        self.inner.put_reader(key, size, reader)
    }
    fn open(&self, key: &str) -> Result<Box<dyn ObjectReader>, BackupError> {
        self.check("get", key)?;
        self.inner.open(key)
    }
    fn size(&self, key: &str) -> Result<Option<u64>, BackupError> {
        self.check("head", key)?;
        self.inner.size(key)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>, BackupError> {
        self.check("list", prefix)?;
        self.inner.list(prefix)
    }
    fn list_children(&self, prefix: &str) -> Result<Vec<String>, BackupError> {
        self.check("list", prefix)?;
        self.inner.list_children(prefix)
    }
    fn delete(&self, key: &str) -> Result<(), BackupError> {
        self.check("delete", key)?;
        self.inner.delete(key)
    }
}

/// Destination down beyond `max_unarchived_bytes`: writes never block, continuity breaks (index
/// records it once the destination is back), a restore across the gap is refused, one before
/// the gap and one from a new base backup after it succeed.
#[test]
fn tc_bkp_004_destination_outage_breaks_continuity_without_blocking_writes() {
    outage(None);
}

#[test]
fn tc_bkp_004_encrypted_destination_outage_breaks_continuity_without_blocking_writes() {
    outage(Some(kek(9)));
}

fn outage(kek: Option<Arc<dyn KekProvider>>) {
    let fs = Arc::new(SimFileSystem::new());
    let down = Arc::new(AtomicBool::new(false));
    let archive: Arc<dyn Destination> = Arc::new(Flaky {
        inner: LocalDestination::open(sim(&fs), ARCHIVE).unwrap(),
        down: Arc::clone(&down),
    });
    let mut source = open_source(
        &fs,
        Arc::new(SystemClock::new()),
        41,
        kek.clone(),
        Arc::clone(&archive),
        ArchiverConfig {
            max_unarchived_bytes: 4 * SEGMENT_SIZE,
            ..ArchiverConfig::default()
        },
    );
    populate(&source.db);
    source.backup();
    let rng = SimRng::new(41);
    for _ in 0..30 {
        transfer(&source.db, &rng);
    }
    let before_gap = now_ts();
    source.archiver.pass(true).unwrap();

    down.store(true, Ordering::Relaxed);
    let metrics = source.archiver.metrics();
    let mut broke = false;
    for round in 0..40 {
        // Every write succeeds while the destination is down.
        for _ in 0..10 {
            transfer(&source.db, &rng);
        }
        source.db.flush().unwrap();
        let outcome = source.archiver.pass(round % 3 == 0);
        assert!(outcome.is_err(), "the destination is down");
        if metrics.continuity_breaks.load(Ordering::Relaxed) > 0 {
            broke = true;
            break;
        }
    }
    assert!(broke, "continuity never broke");
    assert!(metrics.failed_passes.load(Ordering::Relaxed) > 0);
    // The held segments were released: the local log is back under the bound.
    source.db.replica().purge_flushed().unwrap();
    let held: u64 = source
        .db
        .replica()
        .sealed_log_segments()
        .iter()
        .map(|s| s.size)
        .sum();
    assert!(held <= 8 * SEGMENT_SIZE, "held {held}");

    for _ in 0..20 {
        transfer(&source.db, &rng);
    }
    let after_gap = now_ts();
    down.store(false, Ordering::Relaxed);
    source.archiver.pass(true).unwrap();
    let timeline = source.archiver.timeline().to_owned();
    let index = index_of(archive.as_ref(), &timeline);
    assert_eq!(index.breaks.len(), 1, "{:?}", index.breaks);
    assert_eq!(index.breaks[0].reason, "max_unarchived_bytes");

    let backups = LocalDestination::open(sim(&fs), BACKUPS).unwrap();
    let err = pitr_restore(
        &fs,
        &backups,
        archive.as_ref(),
        after_gap,
        "/across",
        kek.clone(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::StorageCorruption, "{err}");
    assert!(err.message().contains("gap"), "{err}");
    assert!(err.message().contains("max_unarchived_bytes"), "{err}");

    // Before the gap: fine. After a new base backup: fine.
    let want_before = state_at(&source.db, before_gap);
    source.backup();
    for _ in 0..20 {
        transfer(&source.db, &rng);
    }
    let after_backup = now_ts();
    source.archiver.pass(true).unwrap();
    let want_after = state_at(&source.db, after_backup);
    drop(source);
    pitr_restore(
        &fs,
        &backups,
        archive.as_ref(),
        before_gap,
        "/before",
        kek.clone(),
    )
    .unwrap();
    assert_eq!(restored(&fs, "/before", kek.clone()), want_before);
    pitr_restore(
        &fs,
        &backups,
        archive.as_ref(),
        after_backup,
        "/after",
        kek.clone(),
    )
    .unwrap();
    assert_eq!(restored(&fs, "/after", kek), want_after);
}

/// A destination whose writes hang until released (a stalled network mount or S3 endpoint).
struct Hanging {
    inner: LocalDestination,
    gate: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    entered: Arc<AtomicBool>,
}

impl Destination for Hanging {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn put_reader(
        &self,
        key: &str,
        size: u64,
        reader: &mut dyn io::Read,
    ) -> Result<(), BackupError> {
        self.entered.store(true, Ordering::Release);
        let (open, cv) = &*self.gate;
        let mut released = open.lock().unwrap();
        while !*released {
            released = cv.wait(released).unwrap();
        }
        drop(released);
        self.inner.put_reader(key, size, reader)
    }
    fn open(&self, key: &str) -> Result<Box<dyn ObjectReader>, BackupError> {
        self.inner.open(key)
    }
    fn size(&self, key: &str) -> Result<Option<u64>, BackupError> {
        self.inner.size(key)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>, BackupError> {
        self.inner.list(prefix)
    }
    fn list_children(&self, prefix: &str) -> Result<Vec<String>, BackupError> {
        self.inner.list_children(prefix)
    }
    fn delete(&self, key: &str) -> Result<(), BackupError> {
        self.inner.delete(key)
    }
}

/// FR-BKP-004 / PD-066 "never block writes": while an archiver pass is stuck in a destination
/// write, transactions keep committing (and size rolls keep sealing segments); once the
/// destination recovers the pass completes and a restore to a point inside the stall is exact.
#[test]
fn tc_bkp_004_hanging_destination_never_blocks_commits() {
    let fs = Arc::new(SimFileSystem::new());
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let entered = Arc::new(AtomicBool::new(false));
    let archive: Arc<dyn Destination> = Arc::new(Hanging {
        inner: LocalDestination::open(sim(&fs), ARCHIVE).unwrap(),
        gate: Arc::clone(&gate),
        entered: Arc::clone(&entered),
    });
    let source = open_source(
        &fs,
        Arc::new(SystemClock::new()),
        71,
        None,
        Arc::clone(&archive),
        ArchiverConfig::default(),
    );
    populate(&source.db);
    source.backup();
    let rng = SimRng::new(71);
    for _ in 0..30 {
        transfer(&source.db, &rng);
    }
    let db = Arc::clone(&source.db);
    let mut archiver = source.archiver;
    let pass = thread::spawn(move || {
        let outcome = archiver.pass(true);
        (archiver, outcome)
    });
    while !entered.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(1));
    }
    // The pass now waits inside the destination: commits must go on regardless.
    let before = db.replica().log_bounds().1;
    for _ in 0..200 {
        transfer(&db, &rng);
    }
    assert!(!pass.is_finished(), "the destination still hangs");
    let committed = db.replica().log_bounds().1 - before;
    assert!(committed >= 100, "commits during the stall: {committed}");
    let t = now_ts();
    for _ in 0..20 {
        transfer(&db, &rng);
    }
    {
        let (open, cv) = &*gate;
        *open.lock().unwrap() = true;
        cv.notify_all();
    }
    let (mut archiver, outcome) = pass.join().unwrap();
    outcome.unwrap();
    archiver.pass(true).unwrap();
    let want = state_at(&db, t);
    drop(archiver);
    drop(db);
    drop(source.physical);
    pitr_restore(&fs, &source.backups, archive.as_ref(), t, "/stall", None).unwrap();
    assert_eq!(restored(&fs, "/stall", None), want);
}

/// A deterministic source for the crash sweeps (one thread, simulated clock).
fn crash_source(
    fs: &Arc<SimFileSystem>,
    clock: &Arc<SimClock>,
    kek: Option<Arc<dyn KekProvider>>,
) -> Source {
    let mut source = open_source(
        fs,
        Arc::clone(clock) as Arc<dyn Clock>,
        51,
        kek,
        local_archive(fs),
        ArchiverConfig::default(),
    );
    populate(&source.db);
    source.backup();
    let rng = SimRng::new(51);
    for _ in 0..30 {
        transfer(&source.db, &rng);
    }
    source.archiver.pass(true).unwrap();
    for _ in 0..30 {
        transfer(&source.db, &rng);
    }
    source.db.flush().unwrap();
    source
}

fn segment_ids_on_disk(fs: &SimFileSystem) -> Vec<u64> {
    fs.read_dir(&Path::new(STORE).join("raft-log"))
        .unwrap()
        .iter()
        .filter_map(|p| {
            let name = p.file_name()?.to_str()?;
            name.strip_suffix(".rlog")?.parse().ok()
        })
        .collect()
}

/// A crash at every operation of an archiver pass (all crash modes in turn): every segment id
/// of the log is still on the local disk or archived with a matching copy, and archiving
/// resumes after the restart.
#[test]
fn tc_bkp_004_crash_during_archiving_never_loses_a_segment() {
    crash_sweep_archiving(None);
}

/// [`tc_bkp_004_crash_during_archiving_never_loses_a_segment`] on an encrypted store: the
/// wrapped-DEK sidecars are part of every pass, so a crash can also fall between a segment copy
/// and its sidecar.
#[test]
fn tc_bkp_004_crash_during_archiving_an_encrypted_store_never_loses_a_segment() {
    crash_sweep_archiving(Some(kek(5)));
}

fn crash_sweep_archiving(kek: Option<Arc<dyn KekProvider>>) {
    let total = {
        let fs = Arc::new(SimFileSystem::new());
        let clock = Arc::new(SimClock::new(
            T0,
            Duration::from_micros(10),
            Duration::from_micros(10),
        ));
        let mut source = crash_source(&fs, &clock, kek.clone());
        let before = fs.op_count();
        source.archiver.pass(true).unwrap();
        fs.op_count() - before
    };
    assert!(total > 10, "{total}");
    for n in 0..total {
        let mode = CrashMode::ALL[usize::try_from(n).unwrap() % CrashMode::ALL.len()];
        let fs = Arc::new(SimFileSystem::new());
        let clock = Arc::new(SimClock::new(
            T0,
            Duration::from_micros(10),
            Duration::from_micros(10),
        ));
        let mut source = crash_source(&fs, &clock, kek.clone());
        let timeline = source.archiver.timeline().to_owned();
        fs.halt_after_ops(n);
        let _ = source.archiver.pass(true);
        fs.crash(n, mode);
        drop(source);

        // Restart: the floor comes back from the state file.
        clock.advance(Duration::from_secs(10));
        let mut source = open_source(
            &fs,
            Arc::clone(&clock) as Arc<dyn Clock>,
            51,
            kek.clone(),
            local_archive(&fs),
            ArchiverConfig::default(),
        );
        assert_eq!(source.archiver.timeline(), timeline, "op {n}");
        let archive = local_archive(&fs);
        let index = load_index(archive.as_ref(), &timeline).unwrap().unwrap();
        let local = segment_ids_on_disk(&fs);
        let max = local.iter().copied().max().unwrap();
        for id in 1..=max {
            if local.contains(&id) {
                continue;
            }
            let seg = index
                .segments
                .iter()
                .find(|s| s.id == id)
                .unwrap_or_else(|| panic!("op {n} {mode:?}: segment {id} lost"));
            let key = format!("pitr/{timeline}/segments/{id:020}.rlog");
            assert_eq!(
                archive.size(&key).unwrap(),
                Some(seg.size),
                "op {n} segment {id}"
            );
            if seg.encrypted {
                let sidecar = format!("pitr/{timeline}/segments/{id:020}.key.json");
                assert!(
                    archive.size(&sidecar).unwrap().is_some(),
                    "op {n} {mode:?}: segment {id} indexed without its key"
                );
            }
        }
        // Archiving resumes and a restore to the end works.
        source.archiver.pass(true).unwrap();
        let t = Timestamp::new(u64::try_from(clock.peek().as_nanos()).unwrap(), 0);
        source.archiver.pass(true).unwrap();
        let want = state_at(&source.db, t);
        drop(source);
        let backups = LocalDestination::open(sim(&fs), BACKUPS).unwrap();
        pitr_restore(&fs, &backups, archive.as_ref(), t, "/r", kek.clone())
            .unwrap_or_else(|e| panic!("op {n} {mode:?}: {e}"));
        assert_eq!(restored(&fs, "/r", kek.clone()), want, "op {n} {mode:?}");
    }
}

/// A crash at sampled operations of a PITR restore: rerunning the same command completes it.
#[test]
fn tc_bkp_004_crash_during_pitr_restore_is_resumable() {
    let prepared = |fs: &Arc<SimFileSystem>| {
        let clock = Arc::new(SimClock::new(
            T0,
            Duration::from_micros(10),
            Duration::from_micros(10),
        ));
        let mut source = crash_source(fs, &clock, None);
        let t = Timestamp::new(u64::try_from(clock.peek().as_nanos()).unwrap(), 0);
        let rng = SimRng::new(52);
        for _ in 0..10 {
            transfer(&source.db, &rng);
        }
        source.archiver.pass(true).unwrap();
        let want = state_at(&source.db, t);
        (t, want)
    };
    let backups = |fs: &Arc<SimFileSystem>| LocalDestination::open(sim(fs), BACKUPS).unwrap();
    let total = {
        let fs = Arc::new(SimFileSystem::new());
        let (t, want) = prepared(&fs);
        let before = fs.op_count();
        let archive = local_archive(&fs);
        pitr_restore(&fs, &backups(&fs), archive.as_ref(), t, "/r", None).unwrap();
        let ops = fs.op_count() - before;
        assert_eq!(restored(&fs, "/r", None), want);
        ops
    };
    eprintln!("PITR restore ops: {total}");
    let stride = total.div_ceil(120).max(1);
    for n in (0..total).filter(|n| n % stride == 0 || total - n < 8) {
        let mode = CrashMode::ALL[usize::try_from(n).unwrap() % CrashMode::ALL.len()];
        let fs = Arc::new(SimFileSystem::new());
        let (t, want) = prepared(&fs);
        let archive = local_archive(&fs);
        fs.halt_after_ops(n);
        // The last operation syncs the journal's removal: the restore is complete before it.
        assert!(
            pitr_restore(&fs, &backups(&fs), archive.as_ref(), t, "/r", None).is_err()
                || n + 1 == total,
            "op {n}"
        );
        fs.crash(n, mode);
        let archive = local_archive(&fs);
        pitr_restore(&fs, &backups(&fs), archive.as_ref(), t, "/r", None)
            .unwrap_or_else(|e| panic!("op {n} {mode:?}: {e}"));
        assert_eq!(restored(&fs, "/r", None), want, "op {n} {mode:?}");
    }
}

/// The archive floor keeps sealed segments until they are archived; a segment interval roll
/// on an idle store does nothing.
#[test]
fn fr_bkp_004_floor_holds_segments_until_archived() {
    let fs = Arc::new(SimFileSystem::new());
    let mut source = open_source(
        &fs,
        Arc::new(SystemClock::new()),
        61,
        None,
        local_archive(&fs),
        ArchiverConfig::default(),
    );
    populate(&source.db);
    let rng = SimRng::new(61);
    for _ in 0..60 {
        transfer(&source.db, &rng);
    }
    source.db.flush().unwrap();
    source.db.replica().purge_flushed().unwrap();
    let held = source.db.replica().sealed_log_segments().len();
    assert!(held > 2, "segments held by the floor: {held}");
    let outcome = source.archiver.pass(true).unwrap();
    assert!(outcome.archived >= held, "{outcome:?}");
    assert_eq!(outcome.unarchived_bytes, 0);
    source.db.flush().unwrap();
    source.db.replica().purge_flushed().unwrap();
    assert!(source.db.replica().sealed_log_segments().len() < held);
    // Idle: nothing to roll, nothing archived.
    let idle = source.archiver.pass(true).unwrap();
    assert_eq!((idle.archived, idle.rolled), (0, None));
}
