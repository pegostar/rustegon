// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Online restore of the node (FR-BKP-001, ADR-037).
//!
//! `BackupService.RestoreBackup` verifies the backup while the node serves and then hands it to
//! [`Scheduler`]. From there:
//! 1. **Accepted.** The scheduler writes `<data_dir>/online-restore.json` (destination and
//!    backup id, never credentials) and wakes the serving loop. From this point the restore
//!    happens even if the process is stopped or killed: every start of `rustegond` first runs
//!    the pending restore ([`run_pending`]).
//! 2. **Stop serving.** The node runs its ordinary graceful shutdown (readiness 503, listeners
//!    drained, open transactions rolled back, memtables flushed, store closed) without leaving
//!    the process: a Windows service stays `RUNNING`, a container keeps its PID 1.
//! 3. **Restore** ([`run_pending`]): `restore_data_dir` with `RestoreKind::Replace` — the
//!    backup is downloaded and checked next to the store, the current store is kept as
//!    `store.pre-restore-<ts>`, the image is swapped in and reverted to its T. The step is
//!    journaled and resumable (crash safety of `rustegon_backup::offline`).
//! 4. **Outcome.** `<data_dir>/restore-status.json` records it for `GetRestoreStatus`, and the
//!    node serves again. A restore that fails before its swap is abandoned: the node serves its
//!    previous store, unchanged, and the status says why. One that fails after its swap stops
//!    the process with the error; the next start resumes it (the journal and the pending record
//!    stay), since serving either store at that point would hide the failure.
//!
//! Configuration, certificates, the cursor token key, logs, the audit log and the backups in
//! the data directory are not part of a backup's image and stay as they are.

use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use rustegon_backup::{
    BackupId, DestinationUrl, Encryption, RestoreKind, RestoreRequest, abandon_unswapped_restore,
    open_destination, restore_data_dir,
};
use rustegon_common::{
    Error, ErrorCode, Result,
    settings::{Config, NodeSettings, Sources},
};
use rustegon_engine::embedded::StoreLock;
use rustegon_server::services::backup::{RestoreOutcome, RestoreScheduler, ScheduledRestore};
use rustegon_sim_api::{Clock, FileSystem, OpenMode, OsRng, Rng, StdFileSystem, SystemClock};
use rustegon_storage::settings::StorageSettings;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// The accepted restore that has not finished yet (module docs, step 1).
pub const PENDING_FILE: &str = "online-restore.json";
/// The outcome of the last online restore (module docs, step 4).
pub const STATUS_FILE: &str = "restore-status.json";
/// Longest wait for the previous serving period to release the store (a blocking task such as
/// an index build step may outlive the runtime's shutdown by a few seconds).
const LOCK_WAIT: Duration = Duration::from_secs(60);
/// Poll period of that wait.
const LOCK_POLL: Duration = Duration::from_millis(100);
/// Largest accepted pending or status file (they are a few hundred bytes).
const MAX_RECORD_BYTES: u64 = 64 << 10;

/// `online-restore.json`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    /// Always 1.
    version: u32,
    destination: String,
    backup_id: String,
}

/// `restore-status.json`.
#[derive(Debug, Serialize, Deserialize)]
struct Status {
    /// Always 1.
    version: u32,
    /// `completed` or `failed`.
    state: String,
    backup_id: String,
    finished_at_unix_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_store: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

/// The node's [`RestoreScheduler`] (module docs, step 1).
pub struct Scheduler {
    fs: Arc<dyn FileSystem>,
    data_dir: PathBuf,
    /// The node's KEK id: an encrypted backup is accepted only under the same KEK.
    kek_id: Option<String>,
    wake: Mutex<Option<oneshot::Sender<ScheduledRestore>>>,
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("data_dir", &self.data_dir)
            .finish_non_exhaustive()
    }
}

/// A scheduler for one serving period and the receiver the serving loop waits on.
pub fn scheduler(
    fs: Arc<dyn FileSystem>,
    data_dir: PathBuf,
    kek_id: Option<String>,
) -> (Arc<Scheduler>, oneshot::Receiver<ScheduledRestore>) {
    let (tx, rx) = oneshot::channel();
    (
        Arc::new(Scheduler {
            fs,
            data_dir,
            kek_id,
            wake: Mutex::new(Some(tx)),
        }),
        rx,
    )
}

impl RestoreScheduler for Scheduler {
    fn schedule(&self, restore: ScheduledRestore) -> Result<()> {
        if let Encryption::Kek { kek_id } = &restore.manifest.encryption
            && self.kek_id.as_deref() != Some(kek_id.as_str())
        {
            return Err(Error::new(
                ErrorCode::KeyUnavailable,
                format!(
                    "the backup is encrypted under KEK {kek_id}; this node is configured with {}",
                    self.kek_id.as_deref().unwrap_or("no encryption key")
                ),
            ));
        }
        let mut wake = self
            .wake
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "restore scheduler lock poisoned"))?;
        let Some(tx) = wake.take() else {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                "an online restore is already scheduled on this node",
            ));
        };
        // Durable before the node is told: from here a stop or a crash still restores.
        let pending = Pending {
            version: 1,
            destination: restore.destination.to_string(),
            backup_id: restore.backup_id.to_string(),
        };
        if let Err(e) = write_record(self.fs.as_ref(), &self.data_dir, PENDING_FILE, &pending) {
            *wake = Some(tx);
            return Err(e);
        }
        tracing::warn!(
            backup_id = %restore.backup_id,
            destination = %restore.destination,
            "online restore accepted; the node stops serving to restore the backup"
        );
        // The receiver lives as long as the serving loop; once it is gone the pending record
        // makes the next start restore.
        let _ = tx.send(restore);
        Ok(())
    }

    fn status(&self) -> Result<RestoreOutcome> {
        let Some(status) = read_record::<Status>(self.fs.as_ref(), &self.data_dir, STATUS_FILE)?
        else {
            return Ok(RestoreOutcome::None);
        };
        Ok(if status.state == "completed" {
            RestoreOutcome::Completed {
                backup_id: status.backup_id,
                finished_at_unix_ms: status.finished_at_unix_ms,
                previous_store: status.previous_store.unwrap_or_default(),
            }
        } else {
            let code = status
                .error_code
                .and_then(ErrorCode::from_code)
                .unwrap_or(ErrorCode::Internal);
            RestoreOutcome::Failed {
                backup_id: status.backup_id,
                finished_at_unix_ms: status.finished_at_unix_ms,
                error: Error::new(code, status.error_message.unwrap_or_default()),
            }
        })
    }
}

/// Runs the pending online restore of the node, if there is one (module docs, steps 3–4):
/// between two serving periods and at every start, before the store is opened. Blocking.
///
/// Returns whether a restore completed: the node then revokes the sessions the backup brought
/// back before it serves.
///
/// # Errors
/// A restore that failed after its swap (module docs); errors reading the pending record or the
/// configuration. A restore that failed before its swap is not an error: it is recorded and the
/// node serves its previous store.
pub fn run_pending(config: &Config, sources: &Sources) -> Result<bool> {
    let node: NodeSettings = config.section()?;
    let data_dir = node.data_dir;
    let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
    let Some(pending) = read_record::<Pending>(fs.as_ref(), &data_dir, PENDING_FILE)? else {
        return Ok(false);
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let rng: Arc<dyn Rng> = Arc::new(OsRng);
    tracing::warn!(
        backup_id = %pending.backup_id,
        destination = %pending.destination,
        "running the online restore"
    );
    match restore(config, sources, &fs, &clock, &rng, &data_dir, &pending) {
        Ok(previous_store) => {
            finish(
                fs.as_ref(),
                &data_dir,
                clock.as_ref(),
                &pending,
                Ok(previous_store),
            )?;
            tracing::warn!(backup_id = %pending.backup_id, "online restore complete");
            Ok(true)
        }
        Err(e) => match abandon_unswapped_restore(fs.as_ref(), &data_dir) {
            Ok(_) => {
                tracing::error!(backup_id = %pending.backup_id, error = %e, "online restore failed before its swap; the node serves its previous store");
                finish(fs.as_ref(), &data_dir, clock.as_ref(), &pending, Err(&e))?;
                Ok(false)
            }
            Err(swapped) => {
                tracing::error!(backup_id = %pending.backup_id, error = %e, state = %swapped, "online restore failed after its swap; the next start resumes it");
                Err(e)
            }
        },
    }
}

/// The restore itself; returns the directory name the replaced store is kept under.
fn restore(
    config: &Config,
    sources: &Sources,
    fs: &Arc<dyn FileSystem>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn Rng>,
    data_dir: &Path,
    pending: &Pending,
) -> Result<Option<String>> {
    let storage: StorageSettings = config.section()?;
    let backup: rustegon_backup::BackupSettings = config.section()?;
    let mut sources = sources.clone();
    let kek = crate::node::encryption_key(&storage, fs.as_ref(), &mut sources)?;
    let url = DestinationUrl::parse(&pending.destination)?;
    let id = BackupId::parse(&pending.backup_id)?;
    wait_for_store(fs.as_ref(), clock.as_ref(), &data_dir.join("store"))?;
    let source = open_destination(&url, Arc::clone(fs), &backup.s3)?;
    let report = restore_data_dir(
        fs,
        clock,
        rng,
        &RestoreRequest {
            source: source.as_ref(),
            id: &id,
            data_dir,
            kind: RestoreKind::Replace,
            kek,
        },
    )?;
    Ok(report
        .previous_store
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())))
}

/// Waits until no process holds the store (module docs of the constants).
fn wait_for_store(fs: &dyn FileSystem, clock: &dyn Clock, store: &Path) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|e| Error::new(ErrorCode::Internal, "cannot start a timer").with_source(e))?;
    let mut waited = Duration::ZERO;
    while StoreLock::is_held(fs, store)? {
        if waited >= LOCK_WAIT {
            return Err(Error::new(
                ErrorCode::Unavailable,
                format!(
                    "the store {} is still in use {}s after the node stopped serving",
                    store.display(),
                    LOCK_WAIT.as_secs()
                ),
            ));
        }
        runtime.block_on(clock.sleep(LOCK_POLL));
        waited += LOCK_POLL;
    }
    Ok(())
}

/// Records the outcome and removes the pending record (module docs, step 4). The pending record
/// goes first: a crash in between loses only the status line, never repeats a restore.
fn finish(
    fs: &dyn FileSystem,
    data_dir: &Path,
    clock: &dyn Clock,
    pending: &Pending,
    outcome: std::result::Result<Option<String>, &Error>,
) -> Result<()> {
    let path = data_dir.join(PENDING_FILE);
    fs.remove_file(&path)
        .map_err(|e| io_error("remove", &path, &e))?;
    sync(fs, data_dir)?;
    let finished_at_unix_ms = clock
        .wall()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let status = match outcome {
        Ok(previous_store) => Status {
            version: 1,
            state: "completed".into(),
            backup_id: pending.backup_id.clone(),
            finished_at_unix_ms,
            previous_store,
            error_code: None,
            error_message: None,
        },
        Err(e) => Status {
            version: 1,
            state: "failed".into(),
            backup_id: pending.backup_id.clone(),
            finished_at_unix_ms,
            previous_store: None,
            error_code: Some(e.code().code()),
            error_message: Some(e.message().to_owned()),
        },
    };
    write_record(fs, data_dir, STATUS_FILE, &status)
}

fn io_error(op: &str, path: &Path, e: &io::Error) -> Error {
    Error::new(ErrorCode::Internal, format!("{op} {}: {e}", path.display()))
}

fn sync(fs: &dyn FileSystem, dir: &Path) -> Result<()> {
    fs.sync_dir(dir).map_err(|e| io_error("sync", dir, &e))
}

/// Writes `value` as `<dir>/<name>` atomically (temp file, fsync, rename, directory fsync).
fn write_record<T: Serialize>(
    fs: &dyn FileSystem,
    dir: &Path,
    name: &str,
    value: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("{name}: {e}")))?;
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}~tmp"));
    let mut file = fs
        .open(&tmp, OpenMode::Truncate)
        .map_err(|e| io_error("create", &tmp, &e))?;
    file.append(&bytes)
        .and_then(|()| file.sync_data())
        .map_err(|e| io_error("write", &tmp, &e))?;
    drop(file);
    fs.rename(&tmp, &path)
        .map_err(|e| io_error("rename", &tmp, &e))?;
    sync(fs, dir)
}

/// Reads `<dir>/<name>`, or `None` when it does not exist.
fn read_record<T: for<'de> Deserialize<'de>>(
    fs: &dyn FileSystem,
    dir: &Path,
    name: &str,
) -> Result<Option<T>> {
    let path = dir.join(name);
    let file = match fs.open(&path, OpenMode::Read) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("open", &path, &e)),
    };
    let size = file.size().map_err(|e| io_error("stat", &path, &e))?;
    if size > MAX_RECORD_BYTES {
        return Err(Error::new(
            ErrorCode::StorageCorruption,
            format!("{} is too large", path.display()),
        ));
    }
    let mut bytes = vec![0u8; usize::try_from(size).unwrap_or(0)];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|e| io_error("read", &path, &e))?;
    serde_json::from_slice(&bytes).map(Some).map_err(|e| {
        Error::new(
            ErrorCode::StorageCorruption,
            format!("{}: {e}", path.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    use rustegon_backup::{Consistency, HlcTimestamp, Manifest, SourceInfo};

    use super::*;

    fn manifest(encryption: Encryption) -> Manifest {
        Manifest {
            format_version: 1,
            backup_id: "20261109T101500Z-3fa85f64".into(),
            created_at: "2026-11-09T10:15:00Z".into(),
            consistency: Consistency {
                timestamp: HlcTimestamp {
                    wall: 1,
                    logical: 0,
                },
                applied_index: 1,
                applied_term: 1,
                storage_seqno: 1,
            },
            source: SourceInfo {
                cluster_id: "single-node".into(),
                node_id: "node1".into(),
                server_version: "0.1.0".into(),
            },
            encryption,
            files: Vec::new(),
            pitr: None,
        }
    }

    fn restore(encryption: Encryption) -> ScheduledRestore {
        ScheduledRestore {
            destination: DestinationUrl::parse("/backups").unwrap(),
            backup_id: BackupId::parse("20261109T101500Z-3fa85f64").unwrap(),
            manifest: manifest(encryption),
        }
    }

    /// ADR-037: the scheduler accepts one restore, writes the pending record before waking the
    /// node, refuses a second one and an encrypted backup under another KEK.
    #[test]
    fn fr_bkp_001_scheduler_records_one_restore_and_checks_the_kek() {
        let dir = tempfile::tempdir().unwrap();
        let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
        let (s, mut rx) = scheduler(Arc::clone(&fs), dir.path().to_path_buf(), Some("k1".into()));
        let other = Encryption::Kek {
            kek_id: "k2".into(),
        };
        assert_eq!(
            s.schedule(restore(other)).unwrap_err().code(),
            ErrorCode::KeyUnavailable
        );
        assert!(!dir.path().join(PENDING_FILE).exists());
        s.schedule(restore(Encryption::Kek {
            kek_id: "k1".into(),
        }))
        .unwrap();
        assert!(dir.path().join(PENDING_FILE).exists());
        assert_eq!(
            rx.try_recv().unwrap().backup_id.as_str(),
            "20261109T101500Z-3fa85f64"
        );
        assert_eq!(
            s.schedule(restore(Encryption::Plaintext))
                .unwrap_err()
                .code(),
            ErrorCode::AlreadyExists
        );
        assert!(matches!(s.status().unwrap(), RestoreOutcome::None));
    }

    /// The status record round-trips both outcomes, and the pending record is gone after each.
    #[test]
    fn fr_bkp_001_status_records_completed_and_failed_restores() {
        let dir = tempfile::tempdir().unwrap();
        let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
        let clock = SystemClock::new();
        let pending = Pending {
            version: 1,
            destination: "/b".into(),
            backup_id: "20261109T101500Z-3fa85f64".into(),
        };
        let (s, _rx) = scheduler(Arc::clone(&fs), dir.path().to_path_buf(), None);
        write_record(fs.as_ref(), dir.path(), PENDING_FILE, &pending).unwrap();
        finish(
            fs.as_ref(),
            dir.path(),
            &clock,
            &pending,
            Ok(Some("store.pre-restore-x".into())),
        )
        .unwrap();
        assert!(!dir.path().join(PENDING_FILE).exists());
        assert!(matches!(
            s.status().unwrap(),
            RestoreOutcome::Completed { previous_store, .. } if previous_store == "store.pre-restore-x"
        ));
        write_record(fs.as_ref(), dir.path(), PENDING_FILE, &pending).unwrap();
        let err = Error::new(ErrorCode::StorageCorruption, "bad file");
        finish(fs.as_ref(), dir.path(), &clock, &pending, Err(&err)).unwrap();
        assert!(!dir.path().join(PENDING_FILE).exists());
        match s.status().unwrap() {
            RestoreOutcome::Failed { error, .. } => {
                assert_eq!(error.code(), ErrorCode::StorageCorruption);
                assert_eq!(error.message(), "bad file");
            }
            other => panic!("{other:?}"),
        }
    }
}
