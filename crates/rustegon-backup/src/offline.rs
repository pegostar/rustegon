// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Offline physical restore of a data directory from a backup or a local snapshot (FR-BKP-001,
//! FR-BKP-003, FR-BKP-005; PD-062, PD-063, PD-068, PD-083; M13a lane BE). Runs with the node
//! stopped, in the `rustegon` CLI.
//!
//! # Recipe
//! 1. **Checks.** The store must not be in use (`<data_dir>/store/LOCK` held → `RGN-3002`,
//!    PD-068); the backup must be complete and readable; an encrypted backup needs the KEK the
//!    manifest names (`RGN-4006` before anything is written). A backup restore needs an empty
//!    or absent data directory (`RGN-1031`); a snapshot restore keeps the current store.
//! 2. **Journal.** `<data_dir>/restore-in-progress.json` (written atomically) records the
//!    backup id and the name the current store will be kept under. Every later step is
//!    idempotent and the journal says where a rerun resumes.
//! 3. **Download** into `<data_dir>/store.restoring` with [`crate::restore_files`]: every file is
//!    checked against its size and BLAKE3 before it is renamed into place, so nothing that does
//!    not match the manifest is ever swapped in. A partial download is wiped and redone.
//! 4. **Swap.** The current store (snapshot restore) is renamed to `store.pre-restore-<ts>`,
//!    then `store.restoring` to `store`, then the data directory is synced.
//! 5. **Open.** `EmbeddedDb::open_restored` with the manifest's `{T, applied_index,
//!    applied_term}`: Raft log bootstrap at the image's applied state, HLC past T, revert to T
//!    (abort every intent and transaction record, delete every version above T), flush. It is
//!    resumable itself (`RESTORING` marker). Its last step removes the marker; if a rerun then
//!    gets `RGN-1031` ("already has a Raft log and no restore in progress"), the previous run
//!    completed it, and the store is opened normally to check it.
//! 6. The journal is removed: the data directory is an ordinary one and `rustegond` starts on
//!    it (configured with the same KEK for an encrypted backup).
//!
//! The lock is checked at the start and again right before the swap; it is not held across the
//! swap itself because a held lock file keeps its directory from being renamed on Windows. The
//! window in between is a few renames long; the documentation tells operators to stop the node
//! (or keep it from restarting) during a restore.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_engine::{
    EmbeddedDb,
    embedded::{LOCK_FILE, RestorePoint, RevertOutcome, StoreLock},
};
use rustegon_mvcc::Timestamp;
use rustegon_sim_api::{Clock, FileSystem, Rng};
use rustegon_storage::{EngineOptions, encryption::KekProvider};
use serde::{Deserialize, Serialize};

use crate::{
    dest::Destination,
    fsutil::{
        compact_utc, dir_exists, io_err, list_dir, read_small, remove_tree, sync_dir, write_atomic,
    },
    id::BackupId,
    manifest::{Encryption, HlcTimestamp, Manifest},
    pitr::{self, PitrReport},
    restore::restore_files,
    verify::load_manifest,
};

/// The store directory under a data directory (as `rustegond` lays it out).
pub const STORE_DIR: &str = "store";
/// Download target of a restore in progress.
pub const RESTORING_DIR: &str = "store.restoring";
/// Prefix of the name a snapshot restore keeps the replaced store under.
pub const PRE_RESTORE_PREFIX: &str = "store.pre-restore-";
/// The restore journal (module docs, step 2).
pub const JOURNAL_FILE: &str = "restore-in-progress.json";
/// Largest journal accepted (it is a few hundred bytes).
const MAX_JOURNAL_BYTES: u64 = 64 << 10;

/// What is restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreKind {
    /// A backup into an empty or absent data directory (`rustegon backup restore`).
    Backup,
    /// A local snapshot over the current store, which is kept (`rustegon snapshot restore`).
    Snapshot,
}

/// A restore request.
pub struct RestoreRequest<'a> {
    /// Where the backup is (a destination, or `<data_dir>/snapshots` for a snapshot).
    pub source: &'a dyn Destination,
    /// Backup id or snapshot name.
    pub id: &'a BackupId,
    /// The data directory to restore.
    pub data_dir: &'a Path,
    /// Backup or snapshot semantics (module docs).
    pub kind: RestoreKind,
    /// The KEK for an encrypted backup (the one `rustegond` will be configured with).
    pub kek: Option<Arc<dyn KekProvider>>,
}

/// What a restore did.
#[derive(Debug, Clone)]
pub struct RestoreReport {
    /// The restored backup's manifest.
    pub manifest: Manifest,
    /// The replaced store's new path (snapshot restore with an existing store).
    pub previous_store: Option<PathBuf>,
    /// What the revert to T removed; `None` when a rerun found the revert already done.
    pub revert: Option<RevertOutcome>,
    /// Whether this run resumed an interrupted one.
    pub resumed: bool,
    /// What a point-in-time restore replayed; `None` for a plain restore, or when a rerun found
    /// the replay and revert already done.
    pub pitr: Option<PitrReport>,
}

/// Restore phases recorded in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Download,
    Swap,
    Open,
}

/// The journal (module docs, step 2). Persisted only for the duration of a restore; a reader
/// refuses fields it does not know, so a journal of another version is never misread.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    /// Always 1.
    version: u32,
    backup_id: String,
    kind: String,
    phase: Phase,
    /// File name (in the data directory) the current store is kept under, if any.
    previous_store: Option<String>,
    /// Target of a point-in-time restore (FR-BKP-002); absent for a plain restore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<HlcTimestamp>,
}

fn kind_text(kind: RestoreKind) -> &'static str {
    match kind {
        RestoreKind::Backup => "backup",
        RestoreKind::Snapshot => "snapshot",
    }
}

fn read_journal(fs: &dyn FileSystem, data_dir: &Path) -> Result<Option<Journal>, Error> {
    let path = data_dir.join(JOURNAL_FILE);
    let Some(bytes) = read_small(fs, &path, MAX_JOURNAL_BYTES)? else {
        return Ok(None);
    };
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|e| {
        Error::new(
            ErrorCode::StorageCorruption,
            format!("{}: unreadable restore journal: {e}", path.display()),
        )
    })?;
    if journal.version != 1 {
        return Err(Error::new(
            ErrorCode::VersionIncompatible,
            format!(
                "{}: restore journal version {}",
                path.display(),
                journal.version
            ),
        ));
    }
    Ok(Some(journal))
}

fn write_journal(fs: &dyn FileSystem, data_dir: &Path, journal: &Journal) -> Result<(), Error> {
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("restore journal: {e}")))?;
    write_atomic(fs, &data_dir.join(JOURNAL_FILE), &bytes)
}

fn refuse_if_in_use(fs: &dyn FileSystem, store: &Path) -> Result<(), Error> {
    if StoreLock::is_held(fs, store)? {
        return Err(Error::new(
            ErrorCode::Unavailable,
            format!(
                "the store in {} is in use (a running rustegond?); stop the node before \
                 restoring",
                store.display()
            ),
        )
        .with_detail("lock", store.join(LOCK_FILE).display().to_string()));
    }
    Ok(())
}

/// Checks that `kek` can open a backup encrypted as `encryption` (`RGN-4006` otherwise).
fn check_kek(encryption: &Encryption, kek: Option<&Arc<dyn KekProvider>>) -> Result<(), Error> {
    if let Encryption::Kek { kek_id } = encryption {
        match kek {
            None => {
                return Err(Error::new(
                    ErrorCode::KeyUnavailable,
                    format!(
                        "the backup is encrypted under KEK {kek_id}; give the key file or \
                         variable of that KEK"
                    ),
                ));
            }
            Some(k) if k.key_id().as_str() != kek_id => {
                return Err(Error::new(
                    ErrorCode::KeyUnavailable,
                    format!(
                        "the backup is encrypted under KEK {kek_id}, the given key is {}",
                        k.key_id()
                    ),
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Restores a data directory (module docs).
///
/// # Errors
/// `RGN-3002` when the store is in use; `RGN-1031` for a non-empty data directory (backup
/// restore) or a journal of another restore; `RGN-1030`/`RGN-5002`/`RGN-5007` for a missing,
/// corrupt or newer backup; `RGN-4006` for a missing or wrong KEK; engine and I/O errors. Every
/// failure can be retried with the same command once its cause is fixed.
pub fn restore_data_dir(
    fs: &Arc<dyn FileSystem>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn Rng>,
    request: &RestoreRequest<'_>,
) -> Result<RestoreReport, Error> {
    restore_inner(fs, clock, rng, request, None)
}

/// A point-in-time target (FR-BKP-002): roll the backup forward to `ts` with the log archive
/// at `archive` (module docs of [`crate::pitr`]).
#[derive(Clone, Copy)]
pub struct PitrTarget<'a> {
    /// Destination holding `pitr/<timeline>/` (`backup.pitr.destination` of the source).
    pub archive: &'a dyn Destination,
    /// The target T.
    pub ts: Timestamp,
}

/// [`restore_data_dir`] of a backup (kind [`RestoreKind::Backup`]) rolled forward to
/// `target.ts` (FR-BKP-002, PD-066, PD-088): the same journal, download and swap, plus the
/// archived segments downloaded and checked next to the store (`pitr-replay/`), replayed from
/// the image's applied index by the open, which then reverts to T. Every refusal of
/// [`crate::pitr`] happens before anything is written; reruns resume from the journal as for a
/// plain restore (the journal records T, so a rerun with another T is refused).
///
/// # Errors
/// As [`restore_data_dir`]; `RGN-1001` for a target before the backup; `RGN-1030` for a target
/// past the archive; `RGN-5002` for a continuity gap or a corrupt segment; `RGN-4006` for a
/// missing or wrong KEK of an archived segment.
pub fn restore_data_dir_to_time(
    fs: &Arc<dyn FileSystem>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn Rng>,
    request: &RestoreRequest<'_>,
    target: PitrTarget<'_>,
) -> Result<RestoreReport, Error> {
    if request.kind != RestoreKind::Backup {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "a point-in-time restore starts from a backup, not a snapshot",
        ));
    }
    restore_inner(fs, clock, rng, request, Some(target))
}

fn restore_inner(
    fs: &Arc<dyn FileSystem>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn Rng>,
    request: &RestoreRequest<'_>,
    target: Option<PitrTarget<'_>>,
) -> Result<RestoreReport, Error> {
    let fsr = fs.as_ref();
    let data_dir = request.data_dir;
    let store = data_dir.join(STORE_DIR);
    let staging = data_dir.join(RESTORING_DIR);
    let replay_dir = data_dir.join(pitr::REPLAY_DIR);
    refuse_if_in_use(fsr, &store)?;
    let manifest = load_manifest(request.source, request.id)?;
    check_kek(&manifest.encryption, request.kek.as_ref())?;
    let plan = target
        .map(|t| pitr::plan(t.archive, &manifest, t.ts, request.kek.as_ref()))
        .transpose()?;
    let journal_target = plan.as_ref().map(|p| HlcTimestamp {
        wall: p.target.wall,
        logical: p.target.logical,
    });

    let (mut journal, resumed) = match read_journal(fsr, data_dir)? {
        Some(journal) => (check_journal(journal, request, journal_target)?, true),
        None => (
            start_journal(fsr, clock.as_ref(), request, journal_target)?,
            false,
        ),
    };

    if journal.phase == Phase::Download {
        // A partial download from an interrupted run is not trusted: start it over.
        remove_tree(fsr, &staging)?;
        restore_files(request.source, request.id, Arc::clone(fs), &staging)?;
        if let (Some(plan), Some(t)) = (&plan, &target) {
            remove_tree(fsr, &replay_dir)?;
            pitr::download(t.archive, plan, fsr, &replay_dir)?;
        }
        sync_dir(fsr, data_dir)?;
        journal.phase = Phase::Swap;
        write_journal(fsr, data_dir, &journal)?;
    }
    if journal.phase == Phase::Swap {
        swap(fsr, data_dir, &journal)?;
        journal.phase = Phase::Open;
        write_journal(fsr, data_dir, &journal)?;
    }
    let replay = plan.as_ref().map(|p| (p, replay_dir.as_path()));
    let (revert, pitr_report) =
        open_and_revert(fs, clock, rng, request, &manifest, resumed, replay)?;
    if plan.is_some() {
        remove_tree(fsr, &replay_dir)?;
    }

    let journal_path = data_dir.join(JOURNAL_FILE);
    fs.remove_file(&journal_path)
        .map_err(|e| io_err("remove", &journal_path, &e))?;
    // The restore is complete once the journal is gone from the live namespace: if this sync
    // fails and a crash brings the journal back, a rerun finds the finished store and only
    // reopens it. Failing here would report a completed restore as failed, and the rerun would
    // then refuse the (now non-empty) data directory of a backup restore.
    if let Err(e) = sync_dir(fsr, data_dir) {
        tracing::warn!(data_dir = %data_dir.display(), error = %e, "restore complete, but the removal of its journal may not be durable; a rerun of the same command only reopens the store");
    }
    tracing::info!(
        backup_id = %request.id,
        kind = kind_text(request.kind),
        data_dir = %data_dir.display(),
        resumed,
        "restore complete"
    );
    Ok(RestoreReport {
        previous_store: journal.previous_store.map(|n| data_dir.join(n)),
        manifest,
        revert,
        resumed,
        pitr: pitr_report,
    })
}

/// A rerun must be the same restore as the one its journal records.
fn check_journal(
    journal: Journal,
    request: &RestoreRequest<'_>,
    target: Option<HlcTimestamp>,
) -> Result<Journal, Error> {
    if journal.backup_id != request.id.as_str()
        || journal.kind != kind_text(request.kind)
        || journal.target != target
    {
        return Err(Error::new(
            ErrorCode::AlreadyExists,
            format!(
                "{} holds an unfinished {} restore of {}; rerun that restore (or remove \
                 {JOURNAL_FILE} and the {RESTORING_DIR} directory to abandon it)",
                request.data_dir.display(),
                journal.kind,
                journal.backup_id
            ),
        ));
    }
    Ok(journal)
}

/// Checks the target of a fresh restore and writes its journal (module docs, steps 1–2).
fn start_journal(
    fs: &dyn FileSystem,
    clock: &dyn Clock,
    request: &RestoreRequest<'_>,
    target: Option<HlcTimestamp>,
) -> Result<Journal, Error> {
    let data_dir = request.data_dir;
    let previous_store = match request.kind {
        RestoreKind::Backup => {
            // A journal temp file is what a crash before the first journal write leaves.
            let leftover = format!("{JOURNAL_FILE}~tmp");
            if list_dir(fs, data_dir)?.is_some_and(|e| {
                e.iter()
                    .any(|p| p.file_name().and_then(|n| n.to_str()) != Some(leftover.as_str()))
            }) {
                return Err(Error::new(
                    ErrorCode::AlreadyExists,
                    format!(
                        "{} is not empty: a backup restores into an empty or new data directory",
                        data_dir.display()
                    ),
                ));
            }
            None
        }
        RestoreKind::Snapshot if dir_exists(fs, &data_dir.join(STORE_DIR))? => Some(format!(
            "{PRE_RESTORE_PREFIX}{}",
            compact_utc(clock.wall())?
        )),
        RestoreKind::Snapshot => None,
    };
    if let Some(name) = &previous_store
        && dir_exists(fs, &data_dir.join(name))?
    {
        return Err(Error::new(
            ErrorCode::AlreadyExists,
            format!(
                "{} already exists; retry in a second",
                data_dir.join(name).display()
            ),
        ));
    }
    fs.create_dir_all(data_dir)
        .map_err(|e| io_err("create directory", data_dir, &e))?;
    let journal = Journal {
        version: 1,
        backup_id: request.id.to_string(),
        kind: kind_text(request.kind).to_owned(),
        phase: Phase::Download,
        previous_store,
        target,
    };
    write_journal(fs, data_dir, &journal)?;
    Ok(journal)
}

/// Step 4: keep the current store (if any), move the download into place. Idempotent: once
/// the download is in place there is nothing left to do.
fn swap(fs: &dyn FileSystem, data_dir: &Path, journal: &Journal) -> Result<(), Error> {
    let store = data_dir.join(STORE_DIR);
    let staging = data_dir.join(RESTORING_DIR);
    refuse_if_in_use(fs, &store)?;
    if !dir_exists(fs, &staging)? {
        return Ok(());
    }
    if dir_exists(fs, &store)? {
        let Some(name) = &journal.previous_store else {
            // A store appeared since the restore started (a node was started on the
            // directory): never replace it without keeping it.
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                format!(
                    "{} appeared during the restore; stop whatever created it and remove it, \
                     then rerun",
                    store.display()
                ),
            ));
        };
        let keep = data_dir.join(name);
        fs.rename(&store, &keep)
            .map_err(|e| io_err("rename", &store, &e))?;
    }
    fs.rename(&staging, &store)
        .map_err(|e| io_err("rename", &staging, &e))?;
    sync_dir(fs, data_dir)
}

/// Step 5: `EmbeddedDb::open_restored` (bootstrap, revert to T, flush); on a rerun after its
/// commit point, a plain open that checks the completed store.
/// With `replay`, a point-in-time restore: the target replaces the backup's T and the
/// downloaded segments are replayed before the revert.
fn open_and_revert(
    fs: &Arc<dyn FileSystem>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn Rng>,
    request: &RestoreRequest<'_>,
    manifest: &Manifest,
    resumed: bool,
    replay: Option<(&pitr::ReplayPlan, &Path)>,
) -> Result<(Option<RevertOutcome>, Option<PitrReport>), Error> {
    let store = request.data_dir.join(STORE_DIR);
    let point = RestorePoint {
        ts: replay.map_or_else(
            || {
                Timestamp::new(
                    manifest.consistency.timestamp.wall,
                    manifest.consistency.timestamp.logical,
                )
            },
            |(plan, _)| plan.target,
        ),
        applied_index: manifest.consistency.applied_index,
        applied_term: manifest.consistency.applied_term,
    };
    let mut report = None;
    let mut run_replay = |db: &EmbeddedDb| -> Result<(), Error> {
        if let Some((plan, dir)) = replay {
            report = Some(pitr::replay(
                db,
                fs.as_ref(),
                dir,
                plan,
                request.kek.as_ref(),
            )?);
        }
        Ok(())
    };
    let opened = EmbeddedDb::open_restored_with_replay(
        Arc::clone(fs),
        &store,
        Arc::clone(clock),
        Arc::clone(rng),
        EngineOptions::default(),
        request.kek.clone(),
        point,
        &mut run_replay,
    );
    match opened {
        Ok((db, outcome)) => {
            db.flush()?;
            drop(db);
            Ok((Some(outcome), report))
        }
        // Only on a rerun: the previous run removed the `RESTORING` marker (its commit point)
        // and failed after it. The store is complete; opening it checks that it really is.
        Err(e) if resumed && e.code() == ErrorCode::AlreadyExists => {
            let db = EmbeddedDb::open_with_kek(
                Arc::clone(fs),
                &store,
                Arc::clone(clock),
                Arc::clone(rng),
                EngineOptions::default(),
                request.kek.clone(),
            )?;
            drop(db);
            Ok((None, None))
        }
        Err(e) => Err(e),
    }
}
