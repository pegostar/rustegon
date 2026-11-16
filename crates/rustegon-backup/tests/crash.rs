// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Crash-during-backup campaign on the simulated file system (M13a lane BH1; FR-BKP-001,
//! FR-BKP-003, FR-BKP-005, AC-BKP-003, TC-BKP-001, TC-BKP-005 crash variants).
//!
//! Every operation below is run once to count its mutating file-system operations, then once
//! per crash point: the file system halts after `n` operations (the process dies there), loses
//! power in one of the [`CrashMode`]s (all of them in turn, seeded by `n`), and the node is
//! started again. After every crash:
//! - (a) the live store opens and holds exactly the committed state from before the operation
//!   (nothing lost, nothing partial);
//! - (b) a backup or snapshot that did not complete is never listed and `verify` refuses it; one
//!   that is listed verifies deep; one whose call returned `Ok` survived the crash;
//! - (c) staging directories, restore journals and download directories are gone, or the rerun
//!   of the same command resumes and finishes from them; a store whose restore is unfinished is
//!   refused by an ordinary open (`RGN-3002`), and a second restore by the journal (`RGN-1031`);
//! - (d) on an encrypted store no file anywhere holds the plaintext of a document.
//!
//! Operations: online physical backup (`PhysicalBackups::create_backup`: fence, hard-link
//! checkpoint into staging, DEK registry move, `write_backup`, manifest, `COMPLETE`, cleanup),
//! snapshot create and delete, and the offline restore (`restore_data_dir`) of a backup into a
//! new data directory and of a snapshot over the current store (journal, download, swap with
//! `store.pre-restore-*`, engine open and revert). Plaintext and encrypted stores. The PITR
//! archiver and the point-in-time restore are swept in `tests/pitr.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustegon_backup::{
    BACKUPS_DIR, BackupId, Destination, LocalDestination, PhysicalBackups, PhysicalConfig,
    RestoreKind, RestoreRequest, SourceInfo, VerifyMode, list,
    offline::{JOURNAL_FILE, PRE_RESTORE_PREFIX, RESTORING_DIR},
    physical::BACKUP_STAGING_DIR,
    restore_data_dir, snapshots_dir, verify,
};
use rustegon_catalog::{DatabaseOptions, IndexField, IndexSpec};
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, value_to_json},
};
use rustegon_engine::embedded::{
    CancelCheck, EmbeddedDb, FenceOptions, RESTORE_MARKER, ScanOptions,
};
use rustegon_sim::{
    CrashMode, SimFileSystem,
    workload::{clock::SimClock, rng::SimRng},
};
use rustegon_sim_api::{Clock, FileSystem, OpenMode};
use rustegon_storage::{
    EngineOptions,
    encryption::{FileKekProvider, KekProvider, SecretKey},
};

const DB: &str = "shop";
const COLL: &str = "acct";
const NODE: &str = "/node";
const STORE: &str = "/node/store";
const BACKUPS: &str = "/backups";
const SNAPSHOT: &str = "snap-1";
const CANARY: &str = "CRASH-PLAINTEXT-CANARY";
const T0: Duration = Duration::from_secs(1_700_000_000);

type State = BTreeMap<String, Vec<String>>;

fn options() -> EngineOptions {
    EngineOptions {
        memtable_size: 16 << 10,
        ..EngineOptions::default()
    }
}

fn kek() -> Arc<dyn KekProvider> {
    Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([7; 32])))
}

fn sim(fs: &Arc<SimFileSystem>) -> Arc<dyn FileSystem> {
    Arc::clone(fs) as Arc<dyn FileSystem>
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

/// One simulated machine: its file system and clock survive crashes, the processes do not.
struct World {
    fs: Arc<SimFileSystem>,
    clock: Arc<SimClock>,
    kek: Option<Arc<dyn KekProvider>>,
}

/// A running node: the store and its backup service.
struct Node {
    db: Arc<EmbeddedDb>,
    physical: PhysicalBackups,
}

impl World {
    fn new(kek: Option<Arc<dyn KekProvider>>) -> Self {
        Self {
            fs: Arc::new(SimFileSystem::new()),
            clock: Arc::new(SimClock::new(
                T0,
                Duration::from_micros(10),
                Duration::from_micros(10),
            )),
            kek,
        }
    }

    fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock) as Arc<dyn Clock>
    }

    fn open_store(&self, store: &Path) -> EmbeddedDb {
        EmbeddedDb::open_with_kek(
            sim(&self.fs),
            store,
            self.clock(),
            Arc::new(SimRng::new(11)),
            options(),
            self.kek.clone(),
        )
        .unwrap_or_else(|e| panic!("open {}: {e}", store.display()))
    }

    /// Starts the node; `PhysicalBackups::open` removes staging leftovers like `rustegond`.
    fn start(&self) -> Node {
        let db = Arc::new(self.open_store(Path::new(STORE)));
        let physical = PhysicalBackups::open(
            Arc::clone(&db),
            sim(&self.fs),
            self.clock(),
            Arc::new(SimRng::new(12)),
            PhysicalConfig::new(
                PathBuf::from(NODE),
                SourceInfo {
                    cluster_id: "single-node".into(),
                    node_id: "node1".into(),
                    server_version: "test".into(),
                },
                self.kek.as_ref().map(|k| k.key_id().to_string()),
            ),
        )
        .unwrap();
        Node { db, physical }
    }

    fn backups(&self) -> LocalDestination {
        LocalDestination::open(sim(&self.fs), BACKUPS).unwrap()
    }

    fn snapshots(&self) -> LocalDestination {
        LocalDestination::open(sim(&self.fs), snapshots_dir(Path::new(NODE))).unwrap()
    }

    /// Power loss at the current halt point, then the clock moves on (a reboot takes time).
    fn crash(&self, n: u64) -> CrashMode {
        let mode = CrashMode::ALL[usize::try_from(n).unwrap() % CrashMode::ALL.len()];
        self.fs.crash(n, mode);
        self.clock.advance(Duration::from_secs(5));
        mode
    }

    fn exists(&self, path: &Path) -> bool {
        self.fs.read_dir(path).is_ok()
            || self
                .fs
                .read_dir(path.parent().unwrap())
                .is_ok_and(|e| e.iter().any(|p| p == path))
    }

    /// Invariant (d): no file anywhere holds a document's plaintext.
    fn assert_no_plaintext(&self, ctx: &str) {
        if self.kek.is_none() {
            return;
        }
        let mut stack = vec![PathBuf::from("/")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = self.fs.read_dir(&dir) else {
                continue;
            };
            for p in entries {
                if self.fs.read_dir(&p).is_ok() {
                    stack.push(p);
                    continue;
                }
                let file = self.fs.open(&p, OpenMode::Read).unwrap();
                let size = file.size().unwrap();
                let mut buf = vec![0u8; usize::try_from(size).unwrap()];
                file.read_exact_at(&mut buf, 0).unwrap();
                assert!(
                    !String::from_utf8_lossy(&buf).contains(CANARY),
                    "{ctx}: {} holds plaintext",
                    p.display()
                );
            }
        }
    }
}

/// Every collection of the store's latest state: canonical JSON per document, index names.
fn state(db: &Arc<EmbeddedDb>) -> State {
    let snapshot = Arc::new(db.pin_snapshot(&FenceOptions::default()).unwrap());
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
            let mut indexes: Vec<String> = db
                .indexes_at(&snapshot, &d.name, &c.name)
                .unwrap()
                .into_iter()
                .map(|i| i.name)
                .collect();
            indexes.sort();
            rows.push(format!("indexes {indexes:?}"));
            out.insert(format!("{}.{}", d.name, c.name), rows);
        }
    }
    out
}

/// A store with several SSTs, an index, and recent writes still only in the log and memtable.
fn populate(db: &EmbeddedDb) {
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    for id in 0..60 {
        db.insert(DB, COLL, &doc(id, 0)).unwrap();
    }
    db.create_index(
        DB,
        COLL,
        &IndexSpec::new("by_n", vec![IndexField::asc("n")]),
    )
    .unwrap();
    db.flush().unwrap();
    write_round(db, 1);
}

/// Replaces every tenth document: committed writes that are not flushed yet.
fn write_round(db: &EmbeddedDb, n: i64) {
    for id in (0..60).step_by(10) {
        db.replace(DB, COLL, &Value::Int64(id), &doc(id, n))
            .unwrap();
    }
}

/// The ids of every backup directory at `dest`, complete or not.
fn backup_dirs(dest: &LocalDestination) -> Vec<String> {
    dest.list_children(BACKUPS_DIR).unwrap()
}

/// Invariant (b) for one destination: listed backups verify deep; any other backup directory
/// is refused by `verify`.
fn check_destination(dest: &LocalDestination, ctx: &str) -> Vec<String> {
    let listed: Vec<String> = list(dest)
        .unwrap()
        .iter()
        .map(|b| b.id().to_owned())
        .collect();
    for name in backup_dirs(dest) {
        let id = BackupId::parse(&name).unwrap();
        let verified = verify(dest, &id, VerifyMode::Deep);
        if listed.contains(&name) {
            verified.unwrap_or_else(|e| panic!("{ctx}: listed {name} fails verify: {e}"));
        } else {
            assert!(verified.is_err(), "{ctx}: incomplete {name} passes verify");
        }
    }
    listed
}

/// Restores backup `id` of `source` into `data_dir` and returns the restored store's state.
fn restore_and_read(
    world: &World,
    source: &dyn Destination,
    id: &str,
    data_dir: &str,
    kind: RestoreKind,
) -> State {
    run_restore(world, source, id, data_dir, kind).unwrap();
    let db = Arc::new(world.open_store(&Path::new(data_dir).join("store")));
    state(&db)
}

fn run_restore(
    world: &World,
    source: &dyn Destination,
    id: &str,
    data_dir: &str,
    kind: RestoreKind,
) -> Result<rustegon_backup::RestoreReport, rustegon_common::Error> {
    restore_data_dir(
        &sim(&world.fs),
        &world.clock(),
        &(Arc::new(SimRng::new(13)) as Arc<dyn rustegon_sim_api::Rng>),
        &RestoreRequest {
            source,
            id: &BackupId::parse(id).unwrap(),
            data_dir: Path::new(data_dir),
            kind,
            kek: world.kek.clone(),
        },
    )
}

/// Counts the mutating file-system operations of `op` on a fresh world built by `setup`.
fn count_ops<S>(
    kek: Option<&Arc<dyn KekProvider>>,
    setup: impl Fn(&World) -> S,
    op: impl Fn(&World, &S),
) -> u64 {
    let world = World::new(kek.cloned());
    let s = setup(&world);
    let before = world.fs.op_count();
    op(&world, &s);
    world.fs.op_count() - before
}

// --- online physical backup -------------------------------------------------------------------

/// TC-BKP-001 crash variant (FR-BKP-001): a crash at every file-system operation of an online
/// backup — fence, staging checkpoint (hard links), DEK registry move, file uploads, manifest,
/// `COMPLETE`, staging cleanup — keeps the store's committed state, never leaves a backup that
/// is listed without verifying, and the next start removes the staging tree; a fresh backup
/// afterwards restores the full state.
#[test]
fn tc_bkp_001_crash_during_online_backup_keeps_the_store_and_no_partial_backup() {
    crash_sweep_backup(None);
}

/// [`tc_bkp_001_crash_during_online_backup_keeps_the_store_and_no_partial_backup`] on an
/// encrypted store: also no plaintext anywhere after any crash.
#[test]
fn tc_bkp_001_crash_during_online_backup_of_an_encrypted_store() {
    crash_sweep_backup(Some(kek()));
}

fn crash_sweep_backup(kek: Option<Arc<dyn KekProvider>>) {
    let setup = |w: &World| {
        let node = w.start();
        populate(&node.db);
        let want = state(&node.db);
        (node, want)
    };
    let setup = |w: &World| {
        let s = setup(w);
        w.backups();
        s
    };
    let total = count_ops(kek.as_ref(), setup, |w, (node, _)| {
        node.physical.create_backup(&w.backups(), &never()).unwrap();
    });
    assert!(total > 20, "backup ops: {total}");
    for n in 0..=total {
        let world = World::new(kek.clone());
        let (node, want) = setup(&world);
        let backups = world.backups();
        world.fs.halt_after_ops(n);
        let result = node.physical.create_backup(&backups, &never());
        // The last operations remove the staging tree, best effort: the backup is complete
        // before them, and the next start removes what is left.
        assert!(result.is_ok() || n < total, "op {n}");
        let mode = world.crash(n);
        drop(node);
        let ctx = format!("op {n}/{total} {mode:?}");

        let node = world.start();
        assert_eq!(state(&node.db), want, "{ctx}: store changed");
        assert!(
            !world.exists(&Path::new(NODE).join(BACKUP_STAGING_DIR)),
            "{ctx}: staging left after the restart"
        );
        let listed = check_destination(&world.backups(), &ctx);
        match &result {
            Ok(created) => assert_eq!(
                listed,
                std::slice::from_ref(&created.manifest.backup_id),
                "{ctx}"
            ),
            Err(_) => assert!(listed.is_empty(), "{ctx}: {listed:?}"),
        }
        world.assert_no_plaintext(&ctx);

        // The node keeps working: new writes, and a fresh backup restores all of them. A full
        // restore per crash point is the expensive part, so it runs on a sample.
        write_round(&node.db, 2);
        let want = state(&node.db);
        let created = node
            .physical
            .create_backup(&world.backups(), &never())
            .unwrap();
        drop(node);
        if n % 7 == 0 || n + 3 > total {
            let got = restore_and_read(
                &world,
                &world.backups(),
                &created.manifest.backup_id,
                "/restored",
                RestoreKind::Backup,
            );
            assert_eq!(got, want, "{ctx}: fresh backup after the crash");
            world.assert_no_plaintext(&ctx);
        }
    }
}

// --- snapshots ---------------------------------------------------------------------------------

/// TC-BKP-005 crash variant (FR-BKP-003, AC-BKP-003): a crash at every operation of a snapshot
/// creation keeps the store, leaves the snapshot absent or complete (deep verify), removes the
/// staging tree at the next start, and the same name can be created afterwards (or already
/// exists, complete); the snapshot restores the state it was taken at.
#[test]
fn tc_bkp_005_crash_during_snapshot_create_leaves_it_absent_or_complete() {
    crash_sweep_snapshot_create(None);
}

/// [`tc_bkp_005_crash_during_snapshot_create_leaves_it_absent_or_complete`] on an encrypted
/// store.
#[test]
fn tc_bkp_005_crash_during_snapshot_create_of_an_encrypted_store() {
    crash_sweep_snapshot_create(Some(kek()));
}

fn crash_sweep_snapshot_create(kek: Option<Arc<dyn KekProvider>>) {
    let name = BackupId::parse(SNAPSHOT).unwrap();
    let setup = |w: &World| {
        let node = w.start();
        populate(&node.db);
        let want = state(&node.db);
        (node, want)
    };
    let total = count_ops(kek.as_ref(), setup, |_, (node, _)| {
        node.physical.create_snapshot(&name, &never()).unwrap();
    });
    assert!(total > 20, "snapshot ops: {total}");
    for n in 0..=total {
        let world = World::new(kek.clone());
        let (node, want) = setup(&world);
        world.fs.halt_after_ops(n);
        let result = node.physical.create_snapshot(&name, &never());
        assert_eq!(result.is_ok(), n >= total, "op {n}");
        let mode = world.crash(n);
        drop(node);
        let ctx = format!("op {n}/{total} {mode:?}");

        let node = world.start();
        assert_eq!(state(&node.db), want, "{ctx}: store changed");
        assert!(
            !world.exists(
                &snapshots_dir(Path::new(NODE))
                    .join(".staging")
                    .join(SNAPSHOT)
            ),
            "{ctx}: snapshot staging left after the restart"
        );
        let listed = check_destination(&world.snapshots(), &ctx);
        let api: Vec<String> = node
            .physical
            .list_snapshots()
            .unwrap()
            .into_iter()
            .map(|m| m.backup_id)
            .collect();
        assert_eq!(api, listed, "{ctx}");
        if result.is_ok() {
            assert_eq!(listed, [SNAPSHOT], "{ctx}: a created snapshot was lost");
        }
        world.assert_no_plaintext(&ctx);
        // Creating the name again: refused only when the complete snapshot is there.
        match node.physical.create_snapshot(&name, &never()) {
            Ok(_) => assert!(listed.is_empty(), "{ctx}"),
            Err(e) => {
                assert_eq!(
                    e.code(),
                    rustegon_common::ErrorCode::AlreadyExists,
                    "{ctx}: {e}"
                );
                assert_eq!(listed, [SNAPSHOT], "{ctx}");
            }
        }
        drop(node);
        if n % 7 == 0 || n + 3 > total {
            let got = restore_and_read(
                &world,
                &world.snapshots(),
                SNAPSHOT,
                NODE,
                RestoreKind::Snapshot,
            );
            assert_eq!(got, want, "{ctx}: snapshot restore");
        }
    }
}

/// TC-BKP-005 crash variant (FR-BKP-003): a crash at every operation of a snapshot deletion
/// leaves it complete (deep verify, still restorable) or no longer listed; deleting again
/// finishes the deletion and removes the whole tree; the store is untouched.
#[test]
fn tc_bkp_005_crash_during_snapshot_delete_leaves_it_complete_or_gone() {
    for kek in [None, Some(kek())] {
        crash_sweep_snapshot_delete(kek);
    }
}

fn crash_sweep_snapshot_delete(kek: Option<Arc<dyn KekProvider>>) {
    let name = BackupId::parse(SNAPSHOT).unwrap();
    let setup = |w: &World| {
        let node = w.start();
        populate(&node.db);
        node.physical.create_snapshot(&name, &never()).unwrap();
        write_round(&node.db, 3);
        let want = state(&node.db);
        (node, want)
    };
    let total = count_ops(kek.as_ref(), setup, |_, (node, _)| {
        assert!(node.physical.delete_snapshot(&name).unwrap());
    });
    assert!(total > 5, "delete ops: {total}");
    let dir = snapshots_dir(Path::new(NODE))
        .join(BACKUPS_DIR)
        .join(SNAPSHOT);
    for n in 0..=total {
        let world = World::new(kek.clone());
        let (node, want) = setup(&world);
        world.fs.halt_after_ops(n);
        let result = node.physical.delete_snapshot(&name);
        let mode = world.crash(n);
        drop(node);
        let ctx = format!("op {n}/{total} {mode:?}");

        let node = world.start();
        assert_eq!(state(&node.db), want, "{ctx}: store changed");
        let listed = check_destination(&world.snapshots(), &ctx);
        if result.is_ok() {
            assert!(listed.is_empty(), "{ctx}: a deleted snapshot came back");
        }
        if listed.is_empty() {
            // Half deleted: never restorable, and a delete finishes it.
            assert!(
                run_restore(
                    &world,
                    &world.snapshots(),
                    SNAPSHOT,
                    "/other",
                    RestoreKind::Snapshot
                )
                .is_err(),
                "{ctx}: an incomplete snapshot was restored"
            );
        }
        let deleted = node.physical.delete_snapshot(&name).unwrap();
        assert_eq!(deleted, !listed.is_empty(), "{ctx}");
        assert!(!world.exists(&dir), "{ctx}: snapshot tree left");
        assert!(node.physical.list_snapshots().unwrap().is_empty(), "{ctx}");
    }
}

// --- offline restore ---------------------------------------------------------------------------

/// FR-BKP-001 / TC-BKP-001 crash variant: a crash at every operation of an offline restore of a
/// backup into a new data directory (journal, download, swap, engine open with revert to T,
/// journal removal). Rerunning the same command always completes it with the exact state at T
/// and nothing of the restore left besides the store; a restore of another backup is refused
/// while the journal is there.
#[test]
fn tc_bkp_001_crash_during_backup_restore_is_resumable() {
    for kek in [None, Some(kek())] {
        crash_sweep_restore(kek, RestoreKind::Backup);
    }
}

/// FR-BKP-005 / TC-BKP-005 crash variant: a crash at every operation of a snapshot restore over
/// the live store. The rerun completes it with the snapshot's state, and the replaced store is
/// kept as `store.pre-restore-*` with every write committed after the snapshot: a crash in the
/// swap never loses the current store.
#[test]
fn tc_bkp_005_crash_during_snapshot_restore_never_loses_the_current_store() {
    for kek in [None, Some(kek())] {
        crash_sweep_restore(kek, RestoreKind::Snapshot);
    }
}

fn crash_sweep_restore(kek: Option<Arc<dyn KekProvider>>, kind: RestoreKind) {
    let name = BackupId::parse(SNAPSHOT).unwrap();
    // The backup (or snapshot) holds state `at_t`; the live store moves on to `current`.
    let setup = |w: &World| {
        let node = w.start();
        populate(&node.db);
        let at_t = state(&node.db);
        let id = match kind {
            RestoreKind::Backup => {
                node.physical
                    .create_backup(&w.backups(), &never())
                    .unwrap()
                    .manifest
                    .backup_id
            }
            RestoreKind::Snapshot => {
                node.physical
                    .create_snapshot(&name, &never())
                    .unwrap()
                    .backup_id
            }
        };
        // A second complete backup (snapshot): restoring it over an unfinished restore of the
        // first must be refused.
        let other = match kind {
            RestoreKind::Backup => {
                node.physical
                    .create_backup(&w.backups(), &never())
                    .unwrap()
                    .manifest
                    .backup_id
            }
            RestoreKind::Snapshot => {
                node.physical
                    .create_snapshot(&BackupId::parse("snap-2").unwrap(), &never())
                    .unwrap()
                    .backup_id
            }
        };
        write_round(&node.db, 4);
        let current = state(&node.db);
        drop(node);
        (id, other, at_t, current)
    };
    let (data_dir, source): (&str, fn(&World) -> LocalDestination) = match kind {
        RestoreKind::Backup => ("/restored", World::backups),
        RestoreKind::Snapshot => (NODE, World::snapshots),
    };
    let total = count_ops(kek.as_ref(), setup, |w, (id, _, _, _)| {
        run_restore(w, &source(w), id, data_dir, kind).unwrap();
    });
    assert!(total > 20, "restore ops: {total}");
    let mut refused_opens = 0;
    for n in 0..=total {
        let world = World::new(kek.clone());
        let (id, other, at_t, current) = setup(&world);
        world.fs.halt_after_ops(n);
        let result = run_restore(&world, &source(&world), &id, data_dir, kind);
        // The last operation syncs the journal's removal: the restore is complete before it.
        assert!(result.is_ok() || n < total, "op {n}");
        let mode = world.crash(n);
        let ctx = format!("op {n}/{total} {mode:?}");
        world.assert_no_plaintext(&ctx);

        // The journal makes a different restore refuse instead of mixing the two.
        let journal = Path::new(data_dir).join(JOURNAL_FILE);
        if world.exists(&journal) {
            let refused = run_restore(&world, &source(&world), &other, data_dir, kind)
                .expect_err("a second restore over an unfinished one");
            assert_eq!(
                refused.code(),
                rustegon_common::ErrorCode::AlreadyExists,
                "{ctx}: {refused}"
            );
        }
        // A store whose revert is unfinished is never served by an ordinary open (a started
        // node): it may hold versions above T next to reverted ones.
        let store = Path::new(data_dir).join("store");
        if world.exists(&store.join(RESTORE_MARKER)) {
            let refused = EmbeddedDb::open_with_kek(
                sim(&world.fs),
                &store,
                world.clock(),
                Arc::new(SimRng::new(14)),
                options(),
                world.kek.clone(),
            )
            .err()
            .unwrap_or_else(|| panic!("{ctx}: a store with an unfinished restore opened"));
            assert_eq!(
                refused.code(),
                rustegon_common::ErrorCode::Unavailable,
                "{ctx}: {refused}"
            );
            refused_opens += 1;
        }
        // A journal that a crash brought back after a successful run only costs a rerun that
        // reopens the finished store.
        if result.is_err() || world.exists(&journal) {
            run_restore(&world, &source(&world), &id, data_dir, kind)
                .unwrap_or_else(|e| panic!("{ctx}: rerun: {e}"));
        }
        let db = Arc::new(world.open_store(&Path::new(data_dir).join("store")));
        assert_eq!(state(&db), at_t, "{ctx}: restored state");
        drop(db);
        // Only the store (and, for a snapshot restore, the kept store and the snapshots).
        let mut names: Vec<String> = world
            .fs
            .read_dir(Path::new(data_dir))
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .filter(|n| n != "snapshots")
            .collect();
        names.sort();
        assert!(
            !names
                .iter()
                .any(|n| n == RESTORING_DIR || n == JOURNAL_FILE),
            "{ctx}: leftovers {names:?}"
        );
        if kind == RestoreKind::Snapshot {
            let kept: Vec<&String> = names
                .iter()
                .filter(|n| n.starts_with(PRE_RESTORE_PREFIX))
                .collect();
            assert_eq!(kept.len(), 1, "{ctx}: {names:?}");
            let old = Arc::new(world.open_store(&Path::new(data_dir).join(kept[0])));
            assert_eq!(
                state(&old),
                current,
                "{ctx}: the replaced store lost writes"
            );
        } else {
            assert_eq!(names, ["store"], "{ctx}");
        }
        world.assert_no_plaintext(&ctx);
    }
    assert!(
        refused_opens > 0,
        "no crash point fell inside the engine's revert"
    );
}
