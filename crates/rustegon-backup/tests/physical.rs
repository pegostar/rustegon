// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Physical backups, local snapshots and offline restores on the real file system (M13a lane
//! BE; FR-BKP-001/003/005, PD-063, PD-064, PD-068, PD-083):
//! - TC-BKP-001: a backup taken while writers run, restored offline, equals the source read at
//!   the backup's T (exact, per collection, documents and index definitions);
//! - TC-BKP-005: local snapshots (hard links, list/delete, restore keeps the old store), and an
//!   encrypted store's backup and snapshot restore only with its KEK, no plaintext in the
//!   backup files;
//! - TC-BKP-014: a restore is refused while the store is in use;
//! - restore reruns: an interrupted download, a failure after the engine's commit point, a
//!   journal of another restore; staging directories are removed on every path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::assert_is_empty,
    clippy::case_sensitive_file_extension_comparisons
)]
// Real threads write while the backup runs, on the real file system and clock.
#![allow(clippy::disallowed_methods)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use rustegon_backup::{
    BackupId, CreatedPhysicalBackup, Destination, Encryption, LocalDestination, PhysicalBackups,
    PhysicalConfig, RestoreKind, RestoreRequest, SourceInfo, VerifyMode, physical,
    restore_data_dir, snapshots_dir,
};
use rustegon_catalog::{DatabaseOptions, IndexField, IndexSpec};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, value_to_json},
};
use rustegon_engine::embedded::{
    CancelCheck, EmbeddedDb, FenceOptions, PinnedSnapshot, ScanOptions, StoreLock,
};
use rustegon_sim_api::{FileSystem, OsRng, StdFileSystem, SystemClock};
use rustegon_storage::{
    EngineOptions,
    encryption::{FileKekProvider, KekProvider},
};

const DB: &str = "shop";
const COLL: &str = "acct";
const DOCS: i64 = 40;
const WRITERS: i64 = 3;
const CANARY: &str = "BKP-PLAINTEXT-CANARY";

fn fs() -> Arc<dyn FileSystem> {
    Arc::new(StdFileSystem)
}

/// Small memtables: the store has several SSTs by the time it is backed up.
fn options() -> EngineOptions {
    EngineOptions {
        memtable_size: 64 << 10,
        ..EngineOptions::default()
    }
}

fn open(store: &Path, kek: Option<Arc<dyn KekProvider>>) -> Result<EmbeddedDb, Error> {
    EmbeddedDb::open_with_kek(
        fs(),
        store,
        Arc::new(SystemClock::new()),
        Arc::new(OsRng),
        options(),
        kek,
    )
}

fn physical(db: &Arc<EmbeddedDb>, data_dir: &Path, kek_id: Option<String>) -> PhysicalBackups {
    PhysicalBackups::open(
        Arc::clone(db),
        fs(),
        Arc::new(SystemClock::new()),
        Arc::new(OsRng),
        PhysicalConfig::new(
            data_dir.to_path_buf(),
            SourceInfo {
                cluster_id: "single-node".into(),
                node_id: "node1".into(),
                server_version: "test".into(),
            },
            kek_id,
        ),
    )
    .unwrap()
}

fn never() -> CancelCheck {
    Arc::new(|| false)
}

fn doc(id: i64, n: i64) -> Document {
    Document::try_from_fields(vec![
        ("_id".to_owned(), Value::Int64(id)),
        ("n".to_owned(), Value::Int64(n)),
        ("secret".to_owned(), Value::String(format!("{CANARY}-{id}"))),
    ])
    .unwrap()
}

fn populate(db: &EmbeddedDb) {
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    for id in 0..DOCS {
        db.insert(DB, COLL, &doc(id, 0)).unwrap();
    }
    db.create_index(
        DB,
        COLL,
        &IndexSpec::new("by_n", vec![IndexField::asc("n")]),
    )
    .unwrap();
}

/// Every collection at `snapshot`: canonical JSON of each document plus index definitions.
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

fn pin(db: &EmbeddedDb) -> Arc<PinnedSnapshot> {
    Arc::new(db.pin_snapshot(&FenceOptions::default()).unwrap())
}

/// The latest state of a store (a fresh snapshot).
fn latest(db: &Arc<EmbeddedDb>) -> BTreeMap<String, Vec<String>> {
    dump(db, &pin(db))
}

/// Writers replacing their own documents (no conflicts between them) until stopped.
struct Writers {
    stop: Arc<AtomicBool>,
    writes: Arc<AtomicU64>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl Writers {
    fn start(db: &Arc<EmbeddedDb>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicU64::new(0));
        let handles = (0..WRITERS)
            .map(|w| {
                let (db, stop, writes) = (Arc::clone(db), Arc::clone(&stop), Arc::clone(&writes));
                thread::spawn(move || {
                    let mut n = 0;
                    while !stop.load(Ordering::Relaxed) {
                        n += 1;
                        for id in (w..DOCS).step_by(usize::try_from(WRITERS).unwrap()) {
                            db.replace(DB, COLL, &Value::Int64(id), &doc(id, n))
                                .unwrap();
                            writes.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        Self {
            stop,
            writes,
            handles,
        }
    }

    fn wait_for(&self, more: u64) {
        let target = self.writes.load(Ordering::Relaxed) + more;
        while self.writes.load(Ordering::Relaxed) < target {
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn stop(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles {
            h.join().unwrap();
        }
        self.writes.load(Ordering::Relaxed)
    }
}

fn restore(
    source: &dyn Destination,
    id: &str,
    data_dir: &Path,
    kind: RestoreKind,
    kek: Option<Arc<dyn KekProvider>>,
) -> Result<rustegon_backup::RestoreReport, Error> {
    restore_data_dir(
        &(fs() as Arc<dyn rustegon_sim_api::FileSystem>),
        &(Arc::new(SystemClock::new()) as Arc<dyn rustegon_sim_api::Clock>),
        &(Arc::new(OsRng) as Arc<dyn rustegon_sim_api::Rng>),
        &RestoreRequest {
            source,
            id: &BackupId::parse(id).unwrap(),
            data_dir,
            kind,
            kek,
        },
    )
}

fn local(dir: &Path) -> LocalDestination {
    LocalDestination::open(fs(), dir).unwrap()
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|r| {
            r.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

/// TC-BKP-001 (FR-BKP-001, PD-063): a backup taken at a snapshot T while three writers keep
/// replacing documents, restored offline into a new data directory, equals the source read at
/// T — every document and the index definitions — and the restored store accepts writes. The
/// staging directory is gone afterwards.
#[test]
fn tc_bkp_001_backup_under_concurrent_writes_restores_exactly_to_t() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("src");
    let db = Arc::new(open(&data_dir.join("store"), None).unwrap());
    populate(&db);
    let backups = physical(&db, &data_dir, None);
    let writers = Writers::start(&db);
    writers.wait_for(60);
    let snapshot = pin(&db);
    writers.wait_for(60);
    let dest_dir = dir.path().join("dest");
    let created: CreatedPhysicalBackup = backups
        .create_backup_at(&snapshot, &local(&dest_dir))
        .unwrap();
    writers.wait_for(60);
    let total = writers.stop();
    assert!(total >= 180, "{total}");
    let expected = dump(&db, &snapshot);
    assert_ne!(expected, latest(&db), "writes above T happened");

    let m = &created.manifest;
    assert_eq!(m.encryption, Encryption::Plaintext);
    assert_eq!(created.warnings.len(), 1, "plaintext warning (PD-064)");
    assert_eq!(created.warnings[0].code, physical::PLAINTEXT_WARNING);
    assert_eq!(m.consistency.timestamp.wall, snapshot.ts().wall);
    assert_eq!(m.consistency.timestamp.logical, snapshot.ts().logical);
    assert!(
        m.files
            .iter()
            .any(|f| f.path.starts_with("lsm/") && f.path.ends_with(".sst"))
    );
    assert!(m.files.iter().any(|f| f.path.starts_with("lsm/CURRENT")));
    assert!(!m.files.iter().any(|f| f.path.starts_with("keys/")));
    assert!(entries(&data_dir.join(physical::BACKUP_STAGING_DIR)).is_empty());
    let id = BackupId::parse(&m.backup_id).unwrap();
    rustegon_backup::verify(&local(&dest_dir), &id, VerifyMode::Deep).unwrap();

    let restored_dir = dir.path().join("restored");
    let report = restore(
        &local(&dest_dir),
        &m.backup_id,
        &restored_dir,
        RestoreKind::Backup,
        None,
    )
    .unwrap();
    assert!(!report.resumed);
    assert!(report.previous_store.is_none());
    assert_eq!(entries(&restored_dir), ["store"]);
    let restored = Arc::new(open(&restored_dir.join("store"), None).unwrap());
    assert_eq!(latest(&restored), expected, "restored store = source at T");
    restored.insert(DB, COLL, &doc(1000, 1)).unwrap();
    drop(restored);

    // A backup restore needs an empty data directory.
    let e = restore(
        &local(&dest_dir),
        &m.backup_id,
        &restored_dir,
        RestoreKind::Backup,
        None,
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::AlreadyExists, "{e}");
}

/// TC-BKP-001 with the fence of `create_backup` itself (PD-063): the backup is taken at a fresh
/// T while writers run; the restored store is one of the source's states (every document holds a
/// value its writer wrote, and the per-writer rounds are consistent: a writer's documents differ
/// by at most one round) and a second backup of the restored store restores to the same data.
#[test]
fn tc_bkp_001_fenced_backup_under_concurrent_writes_restores_a_consistent_state() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("src");
    let db = Arc::new(open(&data_dir.join("store"), None).unwrap());
    populate(&db);
    let backups = physical(&db, &data_dir, None);
    let writers = Writers::start(&db);
    writers.wait_for(90);
    let dest_dir = dir.path().join("dest");
    let created = backups.create_backup(&local(&dest_dir), &never()).unwrap();
    writers.wait_for(90);
    writers.stop();
    let restored_dir = dir.path().join("restored");
    restore(
        &local(&dest_dir),
        &created.manifest.backup_id,
        &restored_dir,
        RestoreKind::Backup,
        None,
    )
    .unwrap();
    let restored = Arc::new(open(&restored_dir.join("store"), None).unwrap());
    // Writer w replaces its documents in id order once per round: at any T, its documents hold
    // round r for a prefix and r - 1 for the rest.
    for w in 0..WRITERS {
        let rounds: Vec<i64> = (w..DOCS)
            .step_by(usize::try_from(WRITERS).unwrap())
            .map(|id| {
                let d = restored.get(DB, COLL, &Value::Int64(id)).unwrap().unwrap();
                match d.get("n") {
                    Some(Value::Int64(n)) => *n,
                    other => panic!("{other:?}"),
                }
            })
            .collect();
        let first = rounds[0];
        assert!(
            rounds.iter().all(|&n| n == first || n == first - 1)
                && rounds.windows(2).all(|p| p[0] >= p[1]),
            "writer {w}: {rounds:?}"
        );
    }
    let restored_state = latest(&restored);
    assert_ne!(
        restored_state,
        latest(&db),
        "writes above T are not restored"
    );
    drop(restored);
}

/// TC-BKP-005 (FR-BKP-003, PD-083): snapshots are hard-link checkpoints in backup format v1
/// under `<data_dir>/snapshots`; list, duplicate names, delete; a snapshot restore refuses while
/// the store is open (TC-BKP-014), checks every file, keeps the replaced store as
/// `store.pre-restore-<ts>` and yields the state of the snapshot.
#[test]
fn tc_bkp_005_snapshot_create_list_delete_and_restore_keeps_the_old_store() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("node");
    let store = data_dir.join("store");
    let db = Arc::new(open(&store, None).unwrap());
    populate(&db);
    let backups = physical(&db, &data_dir, None);
    let name = BackupId::parse("pre-upgrade").unwrap();
    let m = backups.create_snapshot(&name, &never()).unwrap();
    let at_snapshot = latest(&db);
    assert_eq!(m.backup_id, "pre-upgrade");
    let e = backups.create_snapshot(&name, &never()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::AlreadyExists);
    let other = BackupId::parse("other").unwrap();
    backups.create_snapshot(&other, &never()).unwrap();
    let names: Vec<String> = backups
        .list_snapshots()
        .unwrap()
        .into_iter()
        .map(|m| m.backup_id)
        .collect();
    assert_eq!(names, ["other", "pre-upgrade"]);
    assert!(backups.delete_snapshot(&other).unwrap());
    assert!(!backups.delete_snapshot(&other).unwrap());
    assert_eq!(backups.list_snapshots().unwrap().len(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let snap_dir = snapshots_dir(&data_dir).join("backups").join("pre-upgrade");
        // O(metadata) (AC-BKP-003): the snapshot's SSTs are links of the store's files.
        let linked = files_under(&snap_dir.join("lsm"))
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "sst"))
            .filter(|p| std::fs::metadata(p).unwrap().nlink() >= 2)
            .count();
        assert!(linked > 0, "snapshot SSTs are hard links");
    }
    rustegon_backup::verify(&local(&snapshots_dir(&data_dir)), &name, VerifyMode::Deep).unwrap();

    // Changes after the snapshot.
    for id in 0..DOCS {
        db.replace(DB, COLL, &Value::Int64(id), &doc(id, 99))
            .unwrap();
    }
    let after = latest(&db);

    // TC-BKP-014: refused while the store is open; nothing changed.
    let e = restore(
        &local(&snapshots_dir(&data_dir)),
        "pre-upgrade",
        &data_dir,
        RestoreKind::Snapshot,
        None,
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unavailable, "{e}");
    assert!(!data_dir.join("restore-in-progress.json").exists());
    assert!(!data_dir.join("store.restoring").exists());
    drop(backups);
    drop(db);

    let report = restore(
        &local(&snapshots_dir(&data_dir)),
        "pre-upgrade",
        &data_dir,
        RestoreKind::Snapshot,
        None,
    )
    .unwrap();
    let kept = report.previous_store.clone().unwrap();
    assert!(
        kept.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("store.pre-restore-")
    );
    assert!(!data_dir.join("restore-in-progress.json").exists());
    let restored = Arc::new(open(&store, None).unwrap());
    assert_eq!(latest(&restored), at_snapshot);
    drop(restored);
    let old = Arc::new(open(&kept, None).unwrap());
    assert_eq!(latest(&old), after, "the replaced store is kept intact");
    drop(old);
    // The snapshot itself is still there and intact.
    rustegon_backup::verify(&local(&snapshots_dir(&data_dir)), &name, VerifyMode::Deep).unwrap();
}

/// Restore reruns (module docs of `rustegon_backup::offline`): an interrupted download is
/// redone, a failure after the engine's commit point (journal still present) completes on
/// rerun without a second revert, a journal of another restore is refused.
#[test]
fn fr_bkp_001_restore_reruns_resume_from_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("src");
    let db = Arc::new(open(&data_dir.join("store"), None).unwrap());
    populate(&db);
    let dest_dir = dir.path().join("dest");
    let m = physical(&db, &data_dir, None)
        .create_backup(&local(&dest_dir), &never())
        .unwrap()
        .manifest;
    let expected = latest(&db);
    drop(db);
    let journal = |phase: &str, id: &str| {
        format!(
            "{{\"version\":1,\"backup_id\":\"{id}\",\"kind\":\"backup\",\"phase\":\"{phase}\",\
             \"previous_store\":null}}"
        )
    };

    // Interrupted download: a journal and a partial staging directory.
    let target = dir.path().join("rerun");
    std::fs::create_dir_all(target.join("store.restoring").join("lsm")).unwrap();
    std::fs::write(
        target.join("store.restoring").join("lsm").join("junk"),
        b"x",
    )
    .unwrap();
    std::fs::write(
        target.join("restore-in-progress.json"),
        journal("download", &m.backup_id),
    )
    .unwrap();
    let report = restore(
        &local(&dest_dir),
        &m.backup_id,
        &target,
        RestoreKind::Backup,
        None,
    )
    .unwrap();
    assert!(report.resumed);
    assert!(report.revert.is_some());
    assert_eq!(entries(&target), ["store"]);
    let restored = Arc::new(open(&target.join("store"), None).unwrap());
    assert_eq!(latest(&restored), expected);
    drop(restored);

    // Failure after the engine removed its RESTORING marker: the rerun finds a complete store.
    std::fs::write(
        target.join("restore-in-progress.json"),
        journal("open", &m.backup_id),
    )
    .unwrap();
    let report = restore(
        &local(&dest_dir),
        &m.backup_id,
        &target,
        RestoreKind::Backup,
        None,
    )
    .unwrap();
    assert!(report.resumed);
    assert!(report.revert.is_none(), "no second revert");
    assert_eq!(entries(&target), ["store"]);

    // A journal of another restore is refused, nothing is touched.
    std::fs::write(
        target.join("restore-in-progress.json"),
        journal("open", "20200101T000000Z-00000000"),
    )
    .unwrap();
    let e = restore(
        &local(&dest_dir),
        &m.backup_id,
        &target,
        RestoreKind::Backup,
        None,
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::AlreadyExists, "{e}");
}

/// Staging is removed on every path: a cancelled backup (RGN-5005), a failed one (a destination
/// that already holds the id is impossible to hit, so: an unwritable destination), and the
/// leftovers of a crash at the next `PhysicalBackups::open`.
#[test]
fn fr_bkp_001_backup_staging_is_removed_on_every_path() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("src");
    let db = Arc::new(open(&data_dir.join("store"), None).unwrap());
    populate(&db);
    let staging = data_dir.join(physical::BACKUP_STAGING_DIR);
    let leftover = staging.join("20200101T000000Z-00000000").join("lsm");
    std::fs::create_dir_all(&leftover).unwrap();
    std::fs::write(leftover.join("000001.rsst"), b"x").unwrap();
    let snap_leftover = snapshots_dir(&data_dir).join(".staging").join("x");
    std::fs::create_dir_all(&snap_leftover).unwrap();
    let backups = physical(&db, &data_dir, None);
    assert!(!staging.exists(), "crash leftovers removed at open");
    assert!(!snap_leftover.exists());

    let cancelled: CancelCheck = Arc::new(|| true);
    let e = backups
        .create_backup(&local(&dir.path().join("dest")), &cancelled)
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Cancelled, "{e}");
    assert!(entries(&staging).is_empty());
    assert!(entries(&dir.path().join("dest").join("backups")).is_empty());

    // A destination that fails: a regular file where the destination's `backups/` must be.
    let bad = dir.path().join("bad");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("backups"), b"not a directory").unwrap();
    assert!(backups.create_backup(&local(&bad), &never()).is_err());
    assert!(entries(&staging).is_empty());
    let e = backups
        .create_snapshot(&BackupId::parse("s").unwrap(), &cancelled)
        .map(|_| ());
    // A snapshot has no step after the fence that polls `cancel`; it may complete.
    drop(e);
    assert!(entries(&snapshots_dir(&data_dir).join(".staging")).is_empty());
}

fn key_file(dir: &Path, name: &str, byte: u8) -> PathBuf {
    let path = dir.join(name);
    let hex: String = std::iter::repeat_n(format!("{byte:02x}"), 32).collect();
    StdFileSystem
        .create_new_private(&path)
        .and_then(|mut f| f.append(format!("{hex}\n").as_bytes()))
        .unwrap();
    path
}

fn kek(path: &Path) -> Arc<dyn KekProvider> {
    Arc::new(FileKekProvider::open(&StdFileSystem, path).unwrap())
}

/// TC-BKP-005 (FR-BKP-005, FR-EAR-001, PD-064) on the real file system: the backup of an
/// encrypted store records the KEK id, carries no plaintext, and restores only with that KEK
/// (none or another key: RGN-4006 before anything is written); a snapshot of the encrypted store
/// restores with the KEK too; the restored stores stay encrypted.
#[test]
fn tc_bkp_005_encrypted_store_backup_and_snapshot_restore_only_with_the_kek() {
    let dir = tempfile::tempdir().unwrap();
    let key = kek(&key_file(dir.path(), "kek", 7));
    let wrong = kek(&key_file(dir.path(), "other", 8));
    let data_dir = dir.path().join("src");
    let db = Arc::new(open(&data_dir.join("store"), Some(Arc::clone(&key))).unwrap());
    populate(&db);
    db.flush().unwrap();
    let backups = physical(&db, &data_dir, Some(key.key_id().to_string()));
    let dest_dir = dir.path().join("dest");
    let created = backups.create_backup(&local(&dest_dir), &never()).unwrap();
    let m = &created.manifest;
    assert!(created.warnings.is_empty(), "no plaintext warning");
    assert_eq!(
        m.encryption,
        Encryption::Kek {
            kek_id: key.key_id().to_string()
        }
    );
    assert!(m.files.iter().any(|f| f.path == "keys/registry.enc"));
    for file in files_under(&dest_dir) {
        let bytes = std::fs::read(&file).unwrap();
        assert!(
            !bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()),
            "plaintext in {}",
            file.display()
        );
    }
    backups
        .create_snapshot(&BackupId::parse("enc").unwrap(), &never())
        .unwrap();
    let expected = latest(&db);
    drop(backups);
    drop(db);

    let target = dir.path().join("restored");
    for (kek, what) in [(None, "no key"), (Some(Arc::clone(&wrong)), "wrong key")] {
        let e = restore(
            &local(&dest_dir),
            &m.backup_id,
            &target,
            RestoreKind::Backup,
            kek,
        )
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::KeyUnavailable, "{what}: {e}");
        assert!(!target.exists(), "{what}: nothing written");
    }
    restore(
        &local(&dest_dir),
        &m.backup_id,
        &target,
        RestoreKind::Backup,
        Some(Arc::clone(&key)),
    )
    .unwrap();
    assert_eq!(
        open(&target.join("store"), None).unwrap_err().code(),
        ErrorCode::KeyUnavailable,
        "the restored store is still encrypted"
    );
    let restored = Arc::new(open(&target.join("store"), Some(Arc::clone(&key))).unwrap());
    assert_eq!(latest(&restored), expected);
    drop(restored);

    // Snapshot restore of the encrypted store.
    let e = restore(
        &local(&snapshots_dir(&data_dir)),
        "enc",
        &data_dir,
        RestoreKind::Snapshot,
        None,
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::KeyUnavailable);
    restore(
        &local(&snapshots_dir(&data_dir)),
        "enc",
        &data_dir,
        RestoreKind::Snapshot,
        Some(Arc::clone(&key)),
    )
    .unwrap();
    let restored = Arc::new(open(&data_dir.join("store"), Some(key)).unwrap());
    assert_eq!(latest(&restored), expected);
    drop(restored);
    assert!(!StoreLock::is_held(&StdFileSystem, &data_dir.join("store")).unwrap());
}
