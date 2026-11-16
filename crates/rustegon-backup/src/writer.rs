// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Writing a backup from a staged directory (FR-BKP-001 single-node scope, PD-064).
//!
//! # Staged directory
//! The caller (the engine's backup fence + checkpoint, PD-063) prepares a directory whose tree
//! *is* the backup's file tree: `lsm/*.sst` plus the checkpoint's `MANIFEST-*`/`CURRENT`, and
//! `keys/registry.enc` for an encrypted store. Every file is uploaded under the same relative
//! path; `manifest.json` and `COMPLETE` are reserved for this module.
//!
//! # Commit protocol
//! Files first (hashed with BLAKE3 while they stream, so each is read once), then
//! `manifest.json`, then `COMPLETE` last. Every put is atomic and durable before the next starts
//! ([`Destination::put_reader`]), so `COMPLETE` exists only if everything it vouches for does:
//! a crash or error at any point leaves a backup without `COMPLETE`, which list/verify/restore
//! ignore (TC-BKP-009 crash sweep). `COMPLETE` holds the BLAKE3 of `manifest.json`, binding the
//! marker to the exact manifest it completes.

use std::{
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use rustegon_sim_api::{FileSystem, OpenMode};

use crate::{
    COMPLETE_FILE, KEY_REGISTRY_FILE, MANIFEST_FILE,
    dest::{Destination, FileReader, join_key, validate_key},
    error::{BackupError, Result},
    id::{BackupId, UtcTime},
    manifest::{
        Consistency, Encryption, FileEntry, MANIFEST_FORMAT_VERSION, Manifest, PitrLink, SourceInfo,
    },
};

/// What the caller knows about the image it staged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupMetadata {
    /// Consistency point of the image (PD-063).
    pub consistency: Consistency,
    /// Source cluster/node.
    pub source: SourceInfo,
    /// Encryption scope; [`Encryption::Kek`] requires `keys/registry.enc` in the staged
    /// directory, [`Encryption::Plaintext`] forbids it.
    pub encryption: Encryption,
    /// The PITR timeline that continues the image, if the store archives its log.
    pub pitr: Option<PitrLink>,
}

/// A backup about to be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBackup {
    /// Its id (see [`BackupId::generate`]).
    pub id: BackupId,
    /// Creation time recorded in the manifest.
    pub created_at: SystemTime,
    /// Image metadata.
    pub metadata: BackupMetadata,
}

/// Key prefix of backup `id`: `backups/<id>`.
#[must_use]
pub fn backup_prefix(id: &BackupId) -> String {
    join_key(&[crate::BACKUPS_DIR, id.as_str()])
}

/// The contents of `COMPLETE` for a manifest (`blake3:<hex>\n`).
pub(crate) fn complete_marker(manifest_json: &[u8]) -> String {
    format!("blake3:{}\n", blake3::hash(manifest_json).to_hex())
}

/// Uploads the staged directory `staged_dir` of `fs` as backup `backup.id` to `dest` and returns
/// its manifest (module docs).
///
/// On error nothing is marked complete; already uploaded objects are deleted on a best-effort
/// basis (if the destination is down they remain, are ignored as incomplete and are left to
/// retention).
///
/// # Errors
/// [`BackupError::BackupExists`] if the destination already has objects under this id;
/// [`BackupError::InvalidArgument`] for staged names outside the key alphabet, reserved names,
/// or a key registry that does not match `encryption`; [`BackupError::Local`] when the staged
/// directory cannot be read; [`BackupError::Destination`] when the destination fails.
pub fn write_backup(
    dest: &dyn Destination,
    fs: &dyn FileSystem,
    staged_dir: &Path,
    backup: &NewBackup,
) -> Result<Manifest> {
    let files = staged_files(fs, staged_dir)?;
    check_key_registry(&files, &backup.metadata.encryption)?;
    let prefix = backup_prefix(&backup.id);
    if !dest.list(&prefix)?.is_empty() {
        return Err(BackupError::BackupExists {
            id: backup.id.to_string(),
            destination: dest.describe(),
        });
    }
    let created_at = UtcTime::from_system_time(backup.created_at)?.rfc3339();
    let mut uploaded = Vec::with_capacity(files.len() + 1);
    let result = upload(dest, fs, &prefix, &files, &mut uploaded).and_then(|entries| {
        let manifest = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            backup_id: backup.id.to_string(),
            created_at,
            consistency: backup.metadata.consistency,
            source: backup.metadata.source.clone(),
            encryption: backup.metadata.encryption.clone(),
            files: entries,
            pitr: backup.metadata.pitr.clone(),
        };
        let json = manifest.to_json()?;
        let manifest_key = join_key(&[&prefix, MANIFEST_FILE]);
        uploaded.push(manifest_key.clone());
        dest.put_bytes(&manifest_key, &json)?;
        // The commit point: from here on the backup is visible to list/verify/restore.
        dest.put_bytes(
            &join_key(&[&prefix, COMPLETE_FILE]),
            complete_marker(&json).as_bytes(),
        )?;
        Ok(manifest)
    });
    match result {
        Ok(manifest) => {
            if manifest.encryption == Encryption::Plaintext {
                tracing::warn!(
                    backup_id = %backup.id,
                    "backup of an unencrypted store is stored in plaintext"
                );
            }
            tracing::info!(
                backup_id = %backup.id,
                files = manifest.files.len(),
                bytes = manifest.total_bytes(),
                "backup complete"
            );
            Ok(manifest)
        }
        Err(err) => {
            for key in &uploaded {
                let _ = dest.delete(key);
            }
            Err(err)
        }
    }
}

/// Streams every staged file to the destination, recording each key in `uploaded` before its
/// put starts (a failed put may leave an object behind on some destinations).
fn upload(
    dest: &dyn Destination,
    fs: &dyn FileSystem,
    prefix: &str,
    files: &[(String, PathBuf)],
    uploaded: &mut Vec<String>,
) -> Result<Vec<FileEntry>> {
    let mut entries = Vec::with_capacity(files.len());
    for (rel, path) in files {
        let file = fs
            .open(path, OpenMode::Read)
            .map_err(|e| BackupError::local("open", path, e))?;
        let size = file
            .size()
            .map_err(|e| BackupError::local("stat", path, e))?;
        let mut reader = SourceReader {
            inner: FileReader::new(file.as_ref(), size),
            hasher: blake3::Hasher::new(),
            error: None,
        };
        let key = join_key(&[prefix, rel]);
        uploaded.push(key.clone());
        if let Err(err) = dest.put_reader(&key, size, &mut reader) {
            // A failed read of the staged file is a local problem, not a destination outage.
            return Err(match reader.error.take() {
                Some(source) => BackupError::local("read", path, source),
                None => err,
            });
        }
        entries.push(FileEntry {
            path: rel.clone(),
            size,
            blake3: reader.hasher.finalize().to_hex().to_string(),
        });
    }
    Ok(entries)
}

/// Hashing reader over a staged file that remembers its own read error.
struct SourceReader<'a> {
    inner: FileReader<'a>,
    hasher: blake3::Hasher,
    error: Option<io::Error>,
}

impl io::Read for SourceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Ok(n) => {
                self.hasher.update(&buf[..n]);
                Ok(n)
            }
            Err(e) => {
                let kind = e.kind();
                self.error = Some(e);
                Err(io::Error::new(kind, "reading the staged file failed"))
            }
        }
    }
}

/// Every file below `dir` as (relative key, path), sorted by key.
pub(crate) fn staged_files(fs: &dyn FileSystem, dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    walk(fs, dir, "", &mut out)?;
    out.sort();
    for (key, _) in &out {
        if matches!(key.as_str(), MANIFEST_FILE | COMPLETE_FILE) {
            return Err(BackupError::InvalidArgument(format!(
                "staged directory contains the reserved name {key:?}"
            )));
        }
    }
    Ok(out)
}

fn walk(
    fs: &dyn FileSystem,
    dir: &Path,
    prefix: &str,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let entries = fs
        .read_dir(dir)
        .map_err(|e| BackupError::local("list", dir, e))?;
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            BackupError::InvalidArgument(format!("staged name {} is not UTF-8", path.display()))
        })?;
        let key = join_key(&[prefix, name]);
        validate_key(&key)?;
        // The sim-api file system has no stat; a path that lists is a directory.
        if fs.read_dir(&path).is_ok() {
            walk(fs, &path, &key, out)?;
        } else {
            out.push((key, path));
        }
    }
    Ok(())
}

fn check_key_registry(files: &[(String, PathBuf)], encryption: &Encryption) -> Result<()> {
    let has_registry = files.iter().any(|(k, _)| k == KEY_REGISTRY_FILE);
    let has_keys_dir = files.iter().any(|(k, _)| k.starts_with("keys/"));
    match encryption {
        Encryption::Kek { .. } if !has_registry => Err(BackupError::InvalidArgument(format!(
            "encrypted backup without {KEY_REGISTRY_FILE}"
        ))),
        Encryption::Plaintext if has_keys_dir => Err(BackupError::InvalidArgument(
            "plaintext backup with a keys/ directory".into(),
        )),
        _ => Ok(()),
    }
}
