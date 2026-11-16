// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Online physical backups and local snapshots of a running node (FR-BKP-001, FR-BKP-003;
//! PD-063, PD-064, PD-083; M13a lane BE), on the engine's backup primitives (lane BD).
//!
//! # Backup
//! [`PhysicalBackups::create_backup`]:
//! 1. `EmbeddedDb::consistent_checkpoint` into a staging directory
//!    `<data_dir>/backup-staging/<id>/lsm` — the write fence closes T (PD-063), the image is a
//!    hard-link checkpoint, so staging costs metadata, not a copy of the store; the staging
//!    directory must be on the store's file system for the links, hence under the data dir;
//! 2. the checkpoint's DEK registry (`lsm/keys/registry.enc`, encrypted stores) is moved to
//!    `keys/registry.enc`, which turns the staging tree into the backup format v1 file tree;
//! 3. [`crate::write_backup`] uploads it with the manifest (`consistency` from the checkpoint,
//!    `encryption` = the store KEK id, PD-064) and `COMPLETE` last;
//! 4. the staging directory is removed on every path (success, failure, cancellation), and
//!    leftovers of a crash are removed by [`PhysicalBackups::open`] at the next start.
//!
//! # Snapshots (PD-083)
//! A snapshot named `n` is a backup in format v1 inside the data directory:
//! `<data_dir>/snapshots/backups/<n>/{lsm/…, keys/registry.enc, manifest.json, COMPLETE}`, so
//! `<data_dir>/snapshots` is an ordinary local destination: list, verify and the offline restore
//! read snapshots with the same code as backups. The difference is how the files get there:
//! they are the checkpoint's hard links (no copy), hashed in place for the manifest. Creation is
//! staged in `<data_dir>/snapshots/.staging/<n>` and renamed into place after `COMPLETE` is
//! durable, so a snapshot is either absent or complete; deletion removes `COMPLETE` first, so a
//! half-deleted snapshot is incomplete (never listed, never restored) and is finished by the
//! next delete of the same name.

use std::{
    io::Read as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_engine::{
    EmbeddedDb,
    embedded::{
        CancelCheck, ConsistentCheckpoint, DEFAULT_FENCE_TIMEOUT, FenceOptions, PinnedSnapshot,
    },
};
use rustegon_sim_api::{Clock, FileSystem, OpenMode, Rng};

use crate::{
    BACKUPS_DIR, COMPLETE_FILE, MANIFEST_FILE,
    dest::{Destination, FileReader, local::LocalDestination},
    fsutil::{
        dir_exists, ensure_dir, io_err, list_dir, remove_tree, rfc3339_utc, sync_dir, write_atomic,
    },
    id::BackupId,
    manifest::{
        Consistency, Encryption, FileEntry, HlcTimestamp, MANIFEST_FORMAT_VERSION, Manifest,
        PitrLink, SourceInfo,
    },
    verify::{ListedBackup, list},
    writer::{BackupMetadata, NewBackup, complete_marker, staged_files, write_backup},
};

/// Directory under the data dir holding the staging trees of running backups.
pub const BACKUP_STAGING_DIR: &str = "backup-staging";
/// Directory under the data dir holding the local snapshots (a local destination root).
pub const SNAPSHOTS_DIR: &str = "snapshots";
/// Directory under [`SNAPSHOTS_DIR`] holding snapshots being created.
const SNAPSHOT_STAGING_DIR: &str = ".staging";
/// The LSM part of a backup tree (format v1).
pub const LSM_DIR: &str = "lsm";
/// The key part of a backup tree (format v1).
pub const KEYS_DIR: &str = "keys";
/// Warning code of a plaintext backup (PD-064).
pub const PLAINTEXT_WARNING: &str = "plaintext_backup";

/// The local snapshot destination of a data directory: `<data_dir>/snapshots`.
#[must_use]
pub fn snapshots_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(SNAPSHOTS_DIR)
}

/// Settings of [`PhysicalBackups`].
#[derive(Debug, Clone)]
pub struct PhysicalConfig {
    /// The node's data directory (the store is `<data_dir>/store`; staging and snapshots live
    /// next to it, on the same file system, so checkpoints can hard-link).
    pub data_dir: PathBuf,
    /// Recorded in every manifest.
    pub source: SourceInfo,
    /// The store KEK id for an encrypted store (manifest `encryption.kek_id`, PD-064).
    pub kek_id: Option<String>,
    /// Bound of the write fence (default 120 s).
    pub fence_timeout: Duration,
    /// The store's PITR timeline (`rustegond` with `[backup.pitr]` enabled): recorded in every
    /// manifest so a point-in-time restore finds the archive that continues the backup.
    pub pitr_timeline: Option<String>,
}

impl PhysicalConfig {
    /// A configuration with the default fence timeout.
    #[must_use]
    pub fn new(data_dir: PathBuf, source: SourceInfo, kek_id: Option<String>) -> Self {
        Self {
            data_dir,
            source,
            kek_id,
            fence_timeout: DEFAULT_FENCE_TIMEOUT,
            pitr_timeline: None,
        }
    }
}

/// A non-fatal condition of a backup, reported to the caller (`Warning` on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupWarning {
    /// Stable code.
    pub code: &'static str,
    /// Human-readable text.
    pub message: String,
}

/// What [`PhysicalBackups::create_backup`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedPhysicalBackup {
    /// The manifest as written to the destination.
    pub manifest: Manifest,
    /// Non-fatal conditions (a plaintext backup, PD-064).
    pub warnings: Vec<BackupWarning>,
}

/// Online backups and snapshots of one open store (module docs).
pub struct PhysicalBackups {
    db: Arc<EmbeddedDb>,
    fs: Arc<dyn FileSystem>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    config: PhysicalConfig,
    /// Serialises snapshot creation and deletion: both work on fixed names.
    snapshots: Mutex<()>,
}

impl std::fmt::Debug for PhysicalBackups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhysicalBackups")
            .field("data_dir", &self.config.data_dir)
            .finish_non_exhaustive()
    }
}

/// Converts the checkpoint's position into the manifest block (PD-063).
fn consistency_of(cp: &ConsistentCheckpoint) -> Consistency {
    Consistency {
        timestamp: HlcTimestamp {
            wall: cp.ts.wall,
            logical: cp.ts.logical,
        },
        applied_index: cp.applied_index,
        applied_term: cp.applied_term,
        storage_seqno: cp.storage_seqno,
    }
}

fn cancelled() -> Error {
    Error::new(ErrorCode::Cancelled, "the backup was cancelled")
}

impl PhysicalBackups {
    /// Physical backups of `db` (module docs); removes the staging leftovers of a crash.
    ///
    /// # Errors
    /// I/O errors removing leftovers.
    pub fn open(
        db: Arc<EmbeddedDb>,
        fs: Arc<dyn FileSystem>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        config: PhysicalConfig,
    ) -> Result<Self, Error> {
        // Nothing else uses these directories: a leftover is a backup or snapshot that never
        // completed (the process died), and its hard links would pin deleted SSTs on disk.
        remove_tree(fs.as_ref(), &config.data_dir.join(BACKUP_STAGING_DIR))?;
        remove_tree(
            fs.as_ref(),
            &snapshots_dir(&config.data_dir).join(SNAPSHOT_STAGING_DIR),
        )?;
        Ok(Self {
            db,
            fs,
            clock,
            rng,
            config,
            snapshots: Mutex::new(()),
        })
    }

    /// The encryption block of the manifest (PD-064).
    fn pitr_link(&self) -> Option<PitrLink> {
        self.config
            .pitr_timeline
            .clone()
            .map(|timeline| PitrLink { timeline })
    }

    fn encryption(&self, encrypted: bool) -> Result<Encryption, Error> {
        match (encrypted, &self.config.kek_id) {
            (false, _) => Ok(Encryption::Plaintext),
            (true, Some(kek_id)) => Ok(Encryption::Kek {
                kek_id: kek_id.clone(),
            }),
            (true, None) => Err(Error::new(
                ErrorCode::Internal,
                "the store is encrypted but the backup service has no KEK id",
            )),
        }
    }

    /// Fenced checkpoint of the store into `staging` laid out as a backup tree (module docs,
    /// steps 1–2), at `snapshot` when given (else at a freshly closed T). `staging` must not
    /// exist.
    fn stage(
        &self,
        staging: &Path,
        snapshot: Option<&PinnedSnapshot>,
        cancel: &CancelCheck,
    ) -> Result<ConsistentCheckpoint, Error> {
        let fs = self.fs.as_ref();
        if let Some(parent) = staging.parent() {
            ensure_dir(fs, parent)?;
        }
        let lsm = staging.join(LSM_DIR);
        let options = FenceOptions {
            timeout: self.config.fence_timeout,
            cancel: None,
            cancel_check: Some(Arc::clone(cancel)),
        };
        let cp = match snapshot {
            Some(snapshot) => self.db.checkpoint_at(snapshot, &lsm)?,
            None => self.db.consistent_checkpoint(&lsm, &options)?,
        };
        // The checkpoint keeps its DEK registry beside its SSTs (`lsm/keys/`); a backup and a
        // store keep it at `keys/` beside `lsm/` (backup format v1, store layout).
        let cp_keys = rustegon_storage::checkpoint_keys_dir(&lsm);
        if let Some(entries) = list_dir(fs, &cp_keys)? {
            let keys = staging.join(KEYS_DIR);
            ensure_dir(fs, &keys)?;
            for entry in entries {
                let Some(name) = entry.file_name() else {
                    continue;
                };
                let to = keys.join(name);
                fs.rename(&entry, &to)
                    .map_err(|e| io_err("rename", &entry, &e))?;
            }
            sync_dir(fs, &keys)?;
            fs.remove_dir(&cp_keys)
                .map_err(|e| io_err("remove directory", &cp_keys, &e))?;
            sync_dir(fs, &lsm)?;
        }
        Ok(cp)
    }

    /// Takes an online backup to `dest` (module docs). `cancel` is polled during the fence and
    /// between steps.
    ///
    /// # Errors
    /// Fence errors (`RGN-5006` timeout, `RGN-5005` cancelled), `RGN-3002` for an unhealthy
    /// store or an unreachable destination, storage and destination errors.
    pub fn create_backup(
        &self,
        dest: &dyn Destination,
        cancel: &CancelCheck,
    ) -> Result<CreatedPhysicalBackup, Error> {
        self.create_backup_inner(dest, None, cancel)
    }

    /// [`Self::create_backup`] at an existing snapshot of this store
    /// (`EmbeddedDb::pin_snapshot`): T is the snapshot's, so a physical backup and a logical
    /// dump (or a test reading the source) can share one consistency point.
    ///
    /// # Errors
    /// As [`Self::create_backup`].
    pub fn create_backup_at(
        &self,
        snapshot: &PinnedSnapshot,
        dest: &dyn Destination,
    ) -> Result<CreatedPhysicalBackup, Error> {
        let never: CancelCheck = Arc::new(|| false);
        self.create_backup_inner(dest, Some(snapshot), &never)
    }

    fn create_backup_inner(
        &self,
        dest: &dyn Destination,
        snapshot: Option<&PinnedSnapshot>,
        cancel: &CancelCheck,
    ) -> Result<CreatedPhysicalBackup, Error> {
        let now = self.clock.wall();
        let id = BackupId::generate(now, self.rng.as_ref())?;
        let staging = self
            .config
            .data_dir
            .join(BACKUP_STAGING_DIR)
            .join(id.as_str());
        let result = self.backup_from_staging(dest, snapshot, cancel, &id, now, &staging);
        // Every path cleans up: the staging tree holds hard links to SSTs the store may delete
        // after compaction, which would otherwise keep their space allocated.
        if let Err(e) = remove_tree(self.fs.as_ref(), &staging) {
            tracing::warn!(staging = %staging.display(), error = %e, "cannot remove a backup staging directory; it is removed at the next start");
        }
        result
    }

    fn backup_from_staging(
        &self,
        dest: &dyn Destination,
        snapshot: Option<&PinnedSnapshot>,
        cancel: &CancelCheck,
        id: &BackupId,
        now: std::time::SystemTime,
        staging: &Path,
    ) -> Result<CreatedPhysicalBackup, Error> {
        let cp = self.stage(staging, snapshot, cancel)?;
        if cancel() {
            return Err(cancelled());
        }
        let encryption = self.encryption(cp.info.encrypted)?;
        let backup = NewBackup {
            id: id.clone(),
            created_at: now,
            metadata: BackupMetadata {
                consistency: consistency_of(&cp),
                source: self.config.source.clone(),
                encryption,
                pitr: self.pitr_link(),
            },
        };
        let manifest = write_backup(dest, self.fs.as_ref(), staging, &backup)?;
        let mut warnings = Vec::new();
        if manifest.encryption == Encryption::Plaintext {
            warnings.push(BackupWarning {
                code: PLAINTEXT_WARNING,
                message: "the store is not encrypted at rest, so this backup is stored in \
                          plaintext; protect the destination accordingly (PD-064)"
                    .to_owned(),
            });
        }
        Ok(CreatedPhysicalBackup { manifest, warnings })
    }

    /// The snapshot destination `<data_dir>/snapshots` (created if missing).
    fn snapshot_destination(&self) -> Result<LocalDestination, Error> {
        Ok(LocalDestination::open(
            Arc::clone(&self.fs),
            snapshots_dir(&self.config.data_dir),
        )?)
    }

    fn lock_snapshots(&self) -> std::sync::MutexGuard<'_, ()> {
        // A panic while holding the guard leaves nothing to repair in memory.
        self.snapshots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Creates the local snapshot `name` (module docs, PD-083) and returns its manifest.
    ///
    /// # Errors
    /// `RGN-1031` when a snapshot of that name exists; as [`Self::create_backup`].
    pub fn create_snapshot(
        &self,
        name: &BackupId,
        cancel: &CancelCheck,
    ) -> Result<Manifest, Error> {
        let _guard = self.lock_snapshots();
        let fs = self.fs.as_ref();
        let root = snapshots_dir(&self.config.data_dir);
        let final_dir = root.join(BACKUPS_DIR).join(name.as_str());
        if dir_exists(fs, &final_dir)? {
            if self.is_complete_snapshot(name)? {
                return Err(Error::new(
                    ErrorCode::AlreadyExists,
                    format!("snapshot {name} already exists"),
                ));
            }
            // An incomplete leftover of an interrupted delete: finish it.
            remove_tree(fs, &final_dir)?;
        }
        let staging = root.join(SNAPSHOT_STAGING_DIR).join(name.as_str());
        remove_tree(fs, &staging)?;
        let now = self.clock.wall();
        let result = self.snapshot_into(&staging, &final_dir, name, now, cancel);
        if result.is_err()
            && let Err(e) = remove_tree(fs, &staging)
        {
            tracing::warn!(staging = %staging.display(), error = %e, "cannot remove a snapshot staging directory; it is removed at the next start");
        }
        result
    }

    fn snapshot_into(
        &self,
        staging: &Path,
        final_dir: &Path,
        name: &BackupId,
        now: std::time::SystemTime,
        cancel: &CancelCheck,
    ) -> Result<Manifest, Error> {
        let fs = self.fs.as_ref();
        let cp = self.stage(staging, None, cancel)?;
        let manifest = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            backup_id: name.to_string(),
            created_at: rfc3339_utc(now)?,
            consistency: consistency_of(&cp),
            source: self.config.source.clone(),
            encryption: self.encryption(cp.info.encrypted)?,
            files: hash_tree(fs, staging)?,
            pitr: self.pitr_link(),
        };
        let json = manifest.to_json()?;
        write_atomic(fs, &staging.join(MANIFEST_FILE), &json)?;
        write_atomic(
            fs,
            &staging.join(COMPLETE_FILE),
            complete_marker(&json).as_bytes(),
        )?;
        // Publication: the complete tree appears under its name in one rename.
        let parent = final_dir
            .parent()
            .ok_or_else(|| Error::new(ErrorCode::Internal, "snapshot directory has no parent"))?;
        ensure_dir(fs, parent)?;
        fs.rename(staging, final_dir)
            .map_err(|e| io_err("rename", staging, &e))?;
        sync_dir(fs, parent)?;
        if let Some(staging_parent) = staging.parent() {
            sync_dir(fs, staging_parent)?;
        }
        tracing::info!(
            snapshot = %name,
            files = manifest.files.len(),
            bytes = manifest.total_bytes(),
            "snapshot created"
        );
        Ok(manifest)
    }

    fn is_complete_snapshot(&self, name: &BackupId) -> Result<bool, Error> {
        let dest = self.snapshot_destination()?;
        let key = format!("{BACKUPS_DIR}/{name}/{COMPLETE_FILE}");
        Ok(dest.exists(&key)?)
    }

    /// The complete local snapshots, sorted by name; unreadable ones are logged and skipped.
    ///
    /// # Errors
    /// I/O errors listing the snapshot directory.
    pub fn list_snapshots(&self) -> Result<Vec<Manifest>, Error> {
        let root = snapshots_dir(&self.config.data_dir);
        if !dir_exists(self.fs.as_ref(), &root)? {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in list(&self.snapshot_destination()?)? {
            match entry {
                ListedBackup::Complete(m) => out.push(m),
                ListedBackup::Unreadable { id, error } => {
                    tracing::warn!(snapshot = %id, error = %error, "unreadable snapshot skipped");
                }
            }
        }
        out.sort_by(|a, b| a.backup_id.cmp(&b.backup_id));
        Ok(out)
    }

    /// Deletes the snapshot `name`; `false` when no snapshot of that name exists.
    ///
    /// # Errors
    /// I/O errors.
    pub fn delete_snapshot(&self, name: &BackupId) -> Result<bool, Error> {
        let _guard = self.lock_snapshots();
        let fs = self.fs.as_ref();
        let dir = snapshots_dir(&self.config.data_dir)
            .join(BACKUPS_DIR)
            .join(name.as_str());
        if !dir_exists(fs, &dir)? {
            return Ok(false);
        }
        let existed = self.is_complete_snapshot(name)?;
        // `COMPLETE` first and durably: from here on the snapshot no longer exists for list,
        // verify and restore, whatever part of the tree a crash leaves behind.
        let marker = dir.join(COMPLETE_FILE);
        if existed {
            fs.remove_file(&marker)
                .map_err(|e| io_err("remove", &marker, &e))?;
            sync_dir(fs, &dir)?;
        }
        remove_tree(fs, &dir)?;
        if let Some(parent) = dir.parent() {
            sync_dir(fs, parent)?;
        }
        Ok(existed)
    }
}

/// Size and BLAKE3 of every file of a staged tree, sorted by path (manifest `files`).
fn hash_tree(fs: &dyn FileSystem, dir: &Path) -> Result<Vec<FileEntry>, Error> {
    let mut entries = Vec::new();
    for (key, path) in staged_files(fs, dir)? {
        let file = fs
            .open(&path, OpenMode::Read)
            .map_err(|e| io_err("open", &path, &e))?;
        let size = file.size().map_err(|e| io_err("stat", &path, &e))?;
        let mut reader = FileReader::new(file.as_ref(), size);
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| io_err("read", &path, &e))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        entries.push(FileEntry {
            path: key,
            size,
            blake3: hasher.finalize().to_hex().to_string(),
        });
    }
    Ok(entries)
}
