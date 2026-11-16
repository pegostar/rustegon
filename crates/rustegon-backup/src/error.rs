// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Errors of the backup crate and their mapping onto the error catalog (PD-064, protocol.md §7).

use std::io;

use rustegon_common::{Error, ErrorCode};

/// Result alias using [`BackupError`].
pub type Result<T, E = BackupError> = std::result::Result<T, E>;

/// Everything that can go wrong while writing, listing, verifying or restoring a backup.
///
/// The variants follow the PD-064 error table: a missing backup or one without `COMPLETE` is
/// `RGN-1030`, any checksum/size/structure mismatch of a complete backup is `RGN-5002`, a newer
/// manifest format is `RGN-5007`, a non-empty restore target is `RGN-1031`, an unreachable
/// destination is `RGN-3002`, a missing KEK is `RGN-4006`.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// No complete backup with this id exists at the destination (absent, or no `COMPLETE`).
    #[error("backup {id} not found (absent or incomplete) at {destination}")]
    BackupNotFound {
        /// The requested backup id.
        id: String,
        /// The destination that was searched.
        destination: String,
    },
    /// An object that must exist is missing at the destination.
    #[error("object {key} not found at {destination}")]
    ObjectNotFound {
        /// Destination key.
        key: String,
        /// The destination that was read.
        destination: String,
    },
    /// A complete backup does not match its manifest (missing/truncated/corrupt file, broken
    /// manifest or `COMPLETE` marker).
    #[error("backup {id} is corrupt: {path}: {reason}")]
    Corrupt {
        /// The backup id.
        id: String,
        /// The file of the backup (relative path) that failed the check.
        path: String,
        /// What did not match.
        reason: String,
    },
    /// The manifest was written by a newer format than this build reads.
    #[error("backup manifest format {found} is newer than the supported format {supported}")]
    UnsupportedFormat {
        /// Format version found in the manifest.
        found: u64,
        /// Newest format version this build reads.
        supported: u32,
    },
    /// The key encryption key that wraps the backup's DEK registry is not available.
    #[error("backup key encryption key {kek_id} is unavailable")]
    KeyUnavailable {
        /// KEK identifier recorded in the manifest.
        kek_id: String,
    },
    /// The restore target directory already contains entries.
    #[error("restore target {path} is not empty")]
    TargetNotEmpty {
        /// Target directory.
        path: String,
    },
    /// The destination already holds objects under the new backup's id.
    #[error("backup {id} already exists at {destination}")]
    BackupExists {
        /// The backup id.
        id: String,
        /// The destination.
        destination: String,
    },
    /// An I/O operation on the destination failed (destination down, permissions, network).
    #[error("destination {destination}: {op} {key} failed: {source}")]
    Destination {
        /// The destination.
        destination: String,
        /// Operation (`put`, `get`, `list`, ...).
        op: &'static str,
        /// Key the operation was about.
        key: String,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// The destination URL or path cannot be parsed.
    #[error("invalid backup destination {url:?}: {reason}")]
    InvalidDestination {
        /// The URL as given.
        url: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The destination kind is recognised but not available in this build.
    #[error("backup destination scheme {scheme:?} is not yet supported")]
    UnsupportedDestination {
        /// URL scheme, e.g. `s3`.
        scheme: String,
    },
    /// An argument is invalid (backup id, destination key, staged file name).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// A local file system operation (staged directory, restore target) failed.
    #[error("{op} {path} failed: {source}")]
    Local {
        /// Operation.
        op: &'static str,
        /// Local path.
        path: String,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// An internal invariant does not hold (e.g. a manifest cannot be serialised).
    #[error("internal error: {0}")]
    Internal(String),
}

impl BackupError {
    /// The catalog code of this error (PD-064 table).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::BackupNotFound { .. } | Self::ObjectNotFound { .. } => ErrorCode::NotFound,
            Self::Corrupt { .. } => ErrorCode::StorageCorruption,
            Self::UnsupportedFormat { .. } => ErrorCode::VersionIncompatible,
            Self::KeyUnavailable { .. } => ErrorCode::KeyUnavailable,
            Self::TargetNotEmpty { .. } | Self::BackupExists { .. } => ErrorCode::AlreadyExists,
            Self::Destination { source, .. } | Self::Local { source, .. }
                if source.kind() == io::ErrorKind::StorageFull =>
            {
                ErrorCode::DiskFull
            }
            Self::Destination { .. } => ErrorCode::Unavailable,
            // The catalog has no "unimplemented" code: an unsupported destination is an
            // argument this build cannot serve.
            Self::InvalidDestination { .. }
            | Self::UnsupportedDestination { .. }
            | Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::Local { .. } | Self::Internal(_) => ErrorCode::Internal,
        }
    }

    pub(crate) fn local(op: &'static str, path: &std::path::Path, source: io::Error) -> Self {
        Self::Local {
            op,
            path: path.display().to_string(),
            source,
        }
    }

    pub(crate) fn corrupt(id: &str, path: &str, reason: impl Into<String>) -> Self {
        Self::Corrupt {
            id: id.to_owned(),
            path: path.to_owned(),
            reason: reason.into(),
        }
    }
}

impl From<BackupError> for Error {
    fn from(err: BackupError) -> Self {
        // A destination outage may clear up; everything else needs a different request or an
        // operator. A destination that answered "permission denied", "not found" or "bad
        // request" (an S3 403/404/400, a read-only share) stays RGN-3002 but will not heal by
        // retrying.
        let permanent = matches!(
            &err,
            BackupError::Destination { source, .. } if matches!(
                source.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::NotFound
                    | io::ErrorKind::InvalidInput
                    | io::ErrorKind::InvalidData
                    | io::ErrorKind::ReadOnlyFilesystem
            )
        );
        let retryable = matches!(err.code(), ErrorCode::Unavailable) && !permanent;
        Error::new(err.code(), err.to_string())
            .with_retryable(retryable)
            .with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_error_codes_follow_pd_064_table() {
        let io_err = || io::Error::other("down");
        let cases = [
            (
                BackupError::BackupNotFound {
                    id: "x".into(),
                    destination: "d".into(),
                },
                1030,
            ),
            (BackupError::corrupt("x", "lsm/1.rsst", "checksum"), 5002),
            (
                BackupError::UnsupportedFormat {
                    found: 2,
                    supported: 1,
                },
                5007,
            ),
            (BackupError::KeyUnavailable { kek_id: "k".into() }, 4006),
            (BackupError::TargetNotEmpty { path: "/t".into() }, 1031),
            (
                BackupError::Destination {
                    destination: "d".into(),
                    op: "put",
                    key: "k".into(),
                    source: io_err(),
                },
                3002,
            ),
        ];
        for (err, code) in cases {
            assert_eq!(err.code().code(), code, "{err}");
            let common = Error::from(err);
            assert_eq!(common.code().code(), code);
            assert_eq!(common.retryable(), code == 3002);
        }
        // A destination that refuses the request is still RGN-3002 but not retryable.
        let denied = Error::from(BackupError::Destination {
            destination: "s3://b".into(),
            op: "put",
            key: "k".into(),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "HTTP 403: AccessDenied"),
        });
        assert_eq!(denied.code().code(), 3002);
        assert!(!denied.retryable());
    }
}
