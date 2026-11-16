// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Listing and verifying backups (FR-BKP-004/-006 single-node scope, TC-BKP-010, PD-064).
//!
//! A backup exists for these functions only once its `COMPLETE` marker does; a backup directory
//! without it is an interrupted or failed write and is invisible (not listed, `RGN-1030` on
//! verify/restore). A complete backup that does not match its manifest is corrupt (`RGN-5002`).

use crate::{
    BACKUPS_DIR, COMPLETE_FILE, MANIFEST_FILE,
    dest::{Destination, hash_object, join_key},
    error::{BackupError, Result},
    id::BackupId,
    manifest::{MAX_MANIFEST_BYTES, Manifest},
    writer::{backup_prefix, complete_marker},
};

/// Largest `COMPLETE` marker read (bytes); the v1 marker is 72.
const MAX_MARKER_BYTES: u64 = 1024;

/// How thoroughly [`verify`] checks the files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Every file listed in the manifest exists with the recorded size (metadata only).
    Shallow,
    /// Also reads every file and compares its BLAKE3 hash (`--deep`).
    Deep,
}

/// Result of a successful [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// The verified manifest.
    pub manifest: Manifest,
    /// Files checked.
    pub files_checked: usize,
    /// Bytes read and hashed (0 for [`VerifyMode::Shallow`]).
    pub bytes_hashed: u64,
}

/// One entry of [`list`].
#[derive(Debug)]
pub enum ListedBackup {
    /// A complete backup with a readable manifest.
    Complete(Manifest),
    /// A complete backup whose manifest cannot be used (corrupt, or a newer format).
    Unreadable {
        /// The backup id.
        id: BackupId,
        /// Why the manifest cannot be used.
        error: BackupError,
    },
}

impl ListedBackup {
    /// The backup id (as recorded by the directory name).
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Complete(m) => &m.backup_id,
            Self::Unreadable { id, .. } => id.as_str(),
        }
    }
}

/// Lists the complete backups at `dest`, oldest first (generated ids sort chronologically).
/// Directories without `COMPLETE` and names that are not backup ids are skipped; a complete
/// backup whose manifest cannot be read is reported as [`ListedBackup::Unreadable`] instead of
/// failing the whole listing.
///
/// # Errors
/// [`BackupError::Destination`] when the destination cannot be listed or read.
pub fn list(dest: &dyn Destination) -> Result<Vec<ListedBackup>> {
    let mut out = Vec::new();
    for name in dest.list_children(BACKUPS_DIR)? {
        let Ok(id) = BackupId::parse(&name) else {
            continue;
        };
        if !dest.exists(&join_key(&[&backup_prefix(&id), COMPLETE_FILE]))? {
            continue;
        }
        match load_manifest(dest, &id) {
            Ok(manifest) => out.push(ListedBackup::Complete(manifest)),
            Err(e @ BackupError::Destination { .. }) => return Err(e),
            Err(error) => out.push(ListedBackup::Unreadable { id, error }),
        }
    }
    Ok(out)
}

/// Reads and validates the manifest of the complete backup `id`.
///
/// Checks, in order: `COMPLETE` exists (else `RGN-1030`), `manifest.json` exists and parses
/// with a supported format version (`RGN-5007` for a newer one), it names this backup, and
/// `COMPLETE` holds its hash.
///
/// # Errors
/// [`BackupError::BackupNotFound`], [`BackupError::UnsupportedFormat`],
/// [`BackupError::Corrupt`], [`BackupError::Destination`].
pub fn load_manifest(dest: &dyn Destination, id: &BackupId) -> Result<Manifest> {
    let prefix = backup_prefix(id);
    let marker = match dest.get_bytes(&join_key(&[&prefix, COMPLETE_FILE]), MAX_MARKER_BYTES) {
        Ok(marker) => marker,
        Err(BackupError::ObjectNotFound { .. }) => {
            return Err(BackupError::BackupNotFound {
                id: id.to_string(),
                destination: dest.describe(),
            });
        }
        Err(BackupError::InvalidArgument(reason)) => {
            return Err(BackupError::corrupt(id.as_str(), COMPLETE_FILE, reason));
        }
        Err(e) => return Err(e),
    };
    let json = match dest.get_bytes(&join_key(&[&prefix, MANIFEST_FILE]), MAX_MANIFEST_BYTES) {
        Ok(json) => json,
        Err(BackupError::ObjectNotFound { .. }) => {
            return Err(BackupError::corrupt(id.as_str(), MANIFEST_FILE, "missing"));
        }
        Err(BackupError::InvalidArgument(reason)) => {
            return Err(BackupError::corrupt(id.as_str(), MANIFEST_FILE, reason));
        }
        Err(e) => return Err(e),
    };
    // The version check comes first so a newer backup reports RGN-5007, not a marker mismatch
    // that a newer marker format would also cause.
    let manifest = Manifest::from_json(id.as_str(), &json)?;
    if manifest.backup_id != id.as_str() {
        return Err(BackupError::corrupt(
            id.as_str(),
            MANIFEST_FILE,
            format!("names backup {:?}", manifest.backup_id),
        ));
    }
    if marker != complete_marker(&json).as_bytes() {
        return Err(BackupError::corrupt(
            id.as_str(),
            COMPLETE_FILE,
            "does not match manifest.json",
        ));
    }
    Ok(manifest)
}

/// Verifies backup `id` (`rustegon backup verify [--deep]`, TC-BKP-010).
///
/// # Errors
/// As [`load_manifest`], plus [`BackupError::Corrupt`] for a missing file, a size mismatch
/// (truncated or extended file) or, in [`VerifyMode::Deep`], a checksum mismatch.
pub fn verify(dest: &dyn Destination, id: &BackupId, mode: VerifyMode) -> Result<VerifyReport> {
    let manifest = load_manifest(dest, id)?;
    let prefix = backup_prefix(id);
    let mut bytes_hashed = 0;
    for file in &manifest.files {
        let key = join_key(&[&prefix, &file.path]);
        let corrupt = |reason: String| BackupError::corrupt(id.as_str(), &file.path, reason);
        let reader = match dest.open(&key) {
            Ok(reader) => reader,
            Err(BackupError::ObjectNotFound { .. }) => return Err(corrupt("missing".into())),
            Err(e) => return Err(e),
        };
        if reader.size() != file.size {
            return Err(corrupt(format!(
                "size {} but the manifest records {} (truncated or overwritten)",
                reader.size(),
                file.size
            )));
        }
        if mode == VerifyMode::Deep {
            let hash = hash_object(reader.as_ref(), |_| Ok(()))?;
            if hash != file.blake3 {
                return Err(corrupt("BLAKE3 checksum mismatch".into()));
            }
            bytes_hashed += file.size;
        }
    }
    Ok(VerifyReport {
        files_checked: manifest.files.len(),
        manifest,
        bytes_hashed,
    })
}
