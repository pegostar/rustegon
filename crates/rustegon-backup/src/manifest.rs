// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The backup manifest, format v1 (PD-064, docs/deployment/backup-restore.md "Backup format v1").
//!
//! `manifest.json` is versioned JSON. The reader looks at `format_version` before anything else,
//! so a manifest of a newer format fails with RGN-5007 even when its structure changed, instead of
//! surfacing as a parse error (RGN-5002). Unknown fields are ignored: a v1 reader keeps reading a
//! manifest that a later v1 writer extended with optional fields; anything a reader must
//! understand to restore correctly bumps the version.
//!
//! 64-bit counters (HLC wall nanoseconds, seqno, Raft index) are JSON numbers; `serde_json` reads
//! and writes them exactly. Tools that parse JSON numbers as doubles must not be used to edit a
//! manifest.

use serde::{Deserialize, Serialize};

use crate::{
    dest::validate_key,
    error::{BackupError, Result},
    id::BackupId,
};

/// Current (and newest readable) manifest format version.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// Largest manifest the reader accepts (bytes): guards the allocation when reading an untrusted
/// destination. 64 MiB holds the entries of about half a million files.
pub const MAX_MANIFEST_BYTES: u64 = 64 << 20;

/// An HLC timestamp (same components as `rustegon_mvcc::Timestamp`, kept as plain data so the
/// format does not depend on that crate's types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HlcTimestamp {
    /// Physical component, nanoseconds since the Unix epoch.
    pub wall: u64,
    /// Logical component.
    pub logical: u32,
}

/// The consistency point of the backup (PD-063): restoring yields the source as read at
/// `timestamp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consistency {
    /// Consistency timestamp T.
    pub timestamp: HlcTimestamp,
    /// Last applied Raft log index included in the image.
    pub applied_index: u64,
    /// Term of `applied_index`.
    pub applied_term: u64,
    /// Every storage write with seqno <= this value is in the image (checkpoint seqno).
    pub storage_seqno: u64,
}

/// Where the backup was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    /// Cluster identifier (opaque).
    pub cluster_id: String,
    /// Node identifier (opaque).
    pub node_id: String,
    /// Version of the server that took the backup.
    pub server_version: String,
}

/// How the backed-up files are protected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Encryption {
    /// The source store is not encrypted; the backup is plaintext.
    Plaintext,
    /// The SSTs are encrypted as in the source store, and `keys/registry.enc` holds the DEK
    /// registry wrapped by the KEK `kek_id` (PD-064: backup KEK = store KEK in M13a).
    Kek {
        /// Identifier of the KEK needed to restore.
        kek_id: String,
    },
}

/// One file of the backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the backup directory, `/`-separated (e.g. `lsm/000012.sst`).
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// BLAKE3 hash of the contents, 64 lowercase hex digits.
    pub blake3: String,
}

/// The point-in-time recovery archive a backup can be rolled forward with (FR-BKP-002,
/// PD-066; backup-restore.md "Point-in-time recovery"): the log timeline of the store the
/// backup was taken from. Its archived segments continue the image after
/// `consistency.applied_index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PitrLink {
    /// Timeline id (16 lowercase hex digits): `pitr/<timeline>/` at the archive destination.
    pub timeline: String,
}

/// The backup manifest (format v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version, [`MANIFEST_FORMAT_VERSION`] when written by this build.
    pub format_version: u32,
    /// Backup id (equal to the backup's directory name).
    pub backup_id: String,
    /// Creation time, RFC 3339 UTC (`2026-11-09T10:15:00Z`).
    pub created_at: String,
    /// Consistency point.
    pub consistency: Consistency,
    /// Source cluster and node.
    pub source: SourceInfo,
    /// Encryption scope.
    pub encryption: Encryption,
    /// Every file of the backup, sorted by path.
    pub files: Vec<FileEntry>,
    /// The PITR timeline whose archive continues this backup (optional field of format 1:
    /// absent when the store had no PITR archiving; older readers ignore it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pitr: Option<PitrLink>,
}

/// The format-version probe: only the field that decides how to read the rest.
#[derive(Deserialize)]
struct VersionProbe {
    format_version: u64,
}

impl Manifest {
    /// Total size of the backup's files (bytes).
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    /// The backup id, validated.
    ///
    /// # Errors
    /// [`BackupError::InvalidArgument`] when the recorded id is not a valid id.
    pub fn id(&self) -> Result<BackupId> {
        BackupId::parse(&self.backup_id)
    }

    /// Serialises the manifest (pretty-printed JSON, newline-terminated).
    ///
    /// # Errors
    /// [`BackupError::Internal`] if serialisation fails (it cannot for these types).
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut out = serde_json::to_vec_pretty(self)
            .map_err(|e| BackupError::Internal(format!("manifest serialisation: {e}")))?;
        out.push(b'\n');
        Ok(out)
    }

    /// Parses and validates a manifest of backup `id` (the id is used in error messages only).
    ///
    /// Validation: the format version first (newer → RGN-5007), then structure, then every file
    /// path is a safe relative key (no `..`, absolute paths or drive letters: restore joins them
    /// onto a local directory), unique, and every hash is 64 hex digits.
    ///
    /// # Errors
    /// [`BackupError::UnsupportedFormat`] for a newer format; [`BackupError::Corrupt`] for
    /// anything else that is wrong.
    pub fn from_json(id: &str, bytes: &[u8]) -> Result<Self> {
        let corrupt = |reason: String| BackupError::corrupt(id, crate::MANIFEST_FILE, reason);
        let probe: VersionProbe =
            serde_json::from_slice(bytes).map_err(|e| corrupt(format!("unreadable: {e}")))?;
        if probe.format_version > u64::from(MANIFEST_FORMAT_VERSION) {
            return Err(BackupError::UnsupportedFormat {
                found: probe.format_version,
                supported: MANIFEST_FORMAT_VERSION,
            });
        }
        if probe.format_version == 0 {
            return Err(corrupt("format_version 0 does not exist".into()));
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|e| corrupt(format!("invalid: {e}")))?;
        manifest.validate().map_err(corrupt)?;
        Ok(manifest)
    }

    fn validate(&self) -> std::result::Result<(), String> {
        BackupId::parse(&self.backup_id).map_err(|e| e.to_string())?;
        let mut seen = std::collections::BTreeSet::new();
        for file in &self.files {
            validate_key(&file.path).map_err(|e| e.to_string())?;
            if matches!(
                file.path.as_str(),
                crate::MANIFEST_FILE | crate::COMPLETE_FILE
            ) {
                return Err(format!("reserved file name {:?} listed", file.path));
            }
            if !seen.insert(file.path.as_str()) {
                return Err(format!("file {:?} listed twice", file.path));
            }
            let hex_ok = file.blake3.len() == 64
                && file
                    .blake3
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !hex_ok {
                return Err(format!(
                    "file {:?}: malformed blake3 {:?}",
                    file.path, file.blake3
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustegon_common::ErrorCode;

    use super::*;

    fn sample() -> Manifest {
        Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            backup_id: "20261109T101500Z-3fa85f64".into(),
            created_at: "2026-11-09T10:15:00Z".into(),
            consistency: Consistency {
                timestamp: HlcTimestamp {
                    wall: 1_794_219_300_000_000_000,
                    logical: 3,
                },
                applied_index: 42,
                applied_term: 1,
                storage_seqno: 1234,
            },
            source: SourceInfo {
                cluster_id: "c".into(),
                node_id: "1".into(),
                server_version: "0.1.0".into(),
            },
            encryption: Encryption::Kek {
                kek_id: "file:/etc/kek".into(),
            },
            files: vec![FileEntry {
                path: "lsm/000001.rsst".into(),
                size: 10,
                blake3: "0".repeat(64),
            }],
            pitr: None,
        }
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let m = sample();
        let bytes = m.to_json().unwrap();
        assert_eq!(Manifest::from_json("x", &bytes).unwrap(), m);
    }

    #[test]
    fn tc_bkp_010_newer_manifest_format_is_refused() {
        // A future format may change everything but the version field.
        let bytes = br#"{"format_version": 2, "something": "else"}"#;
        let err = Manifest::from_json("x", bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::VersionIncompatible);
    }

    #[test]
    fn manifest_with_unsafe_or_duplicate_paths_is_corrupt() {
        for path in [
            "../x",
            "/abs",
            "C:/x",
            "a//b",
            "a\\b",
            "COMPLETE",
            "manifest.json",
        ] {
            let mut m = sample();
            m.files[0].path = path.into();
            let err = Manifest::from_json("x", &m.to_json().unwrap()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::StorageCorruption, "{path}");
        }
        let mut m = sample();
        m.files.push(m.files[0].clone());
        let err = Manifest::from_json("x", &m.to_json().unwrap()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::StorageCorruption);
        let mut m = sample();
        m.files[0].blake3 = "XYZ".into();
        assert!(Manifest::from_json("x", &m.to_json().unwrap()).is_err());
        assert!(Manifest::from_json("x", b"not json").is_err());
    }
}
