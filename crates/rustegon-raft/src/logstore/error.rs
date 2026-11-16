// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Log store error type (coding-standards.md §3.2).
//!
//! Corruption is a distinct kind: storage-engine.md §9 quarantines the replica (cluster mode) or
//! refuses to start (single node) instead of retrying.

use std::io;

use rustegon_common::{Error, ErrorCode};
use rustegon_storage::StorageError;

/// Result alias for log store operations.
pub type Result<T, E = LogStoreError> = std::result::Result<T, E>;

/// Errors raised by the Raft log store.
#[derive(Debug, thiserror::Error)]
pub enum LogStoreError {
    /// Persisted log data failed validation (checksum, magic, structure, missing segment).
    #[error("raft log corruption: {0}")]
    Corruption(String),
    /// A segment was written by a newer, unknown format version.
    #[error("raft log segment {segment} has unsupported format version {version}")]
    UnsupportedVersion {
        /// Segment id.
        segment: u64,
        /// Format version found in the segment header.
        version: u32,
    },
    /// The caller violated an API contract (e.g. an append that leaves a gap).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// A read asked for entries that are purged or not yet written.
    #[error("group {group}: index {index} outside the stored log [{first_index}, {last_index}]")]
    OutOfRange {
        /// Raft group id.
        group: u64,
        /// Requested index.
        index: u64,
        /// First stored index of the group.
        first_index: u64,
        /// Last stored index of the group.
        last_index: u64,
    },
    /// An earlier write failed after reaching the file: the on-disk state is unknown, so the
    /// store accepts no further writes and must be reopened (recovery decides what survived).
    #[error("raft log store is unusable after a failed write; reopen it")]
    Poisoned,
    /// An I/O error from the file system.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// An encryption-at-rest error (PD-057): the KEK or a segment's DEK is unavailable
    /// (`RGN-4006`), a payload failed authentication (corruption), or the DEK registry could
    /// not be updated. Keeps the storage error's catalog code.
    #[error(transparent)]
    Encryption(#[from] StorageError),
}

impl LogStoreError {
    /// Shorthand for [`LogStoreError::Corruption`].
    pub(crate) fn corruption(reason: impl Into<String>) -> Self {
        Self::Corruption(reason.into())
    }

    /// Shorthand for [`LogStoreError::InvalidArgument`].
    pub(crate) fn invalid(reason: impl Into<String>) -> Self {
        Self::InvalidArgument(reason.into())
    }

    /// Whether the error indicates corrupt persisted data.
    #[must_use]
    pub fn is_corruption(&self) -> bool {
        match self {
            Self::Corruption(_) => true,
            Self::Encryption(e) => e.is_corruption(),
            _ => false,
        }
    }
}

impl From<LogStoreError> for Error {
    fn from(err: LogStoreError) -> Self {
        let err = match err {
            LogStoreError::Encryption(e) => return Error::from(e),
            other => other,
        };
        let code = match &err {
            LogStoreError::Corruption(_) | LogStoreError::UnsupportedVersion { .. } => {
                ErrorCode::StorageCorruption
            }
            LogStoreError::InvalidArgument(_) | LogStoreError::OutOfRange { .. } => {
                ErrorCode::InvalidArgument
            }
            LogStoreError::Io(e) if e.kind() == io::ErrorKind::StorageFull => ErrorCode::DiskFull,
            LogStoreError::Poisoned | LogStoreError::Io(_) | LogStoreError::Encryption(_) => {
                ErrorCode::Internal
            }
        };
        Error::new(code, err.to_string()).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_store_errors_map_to_catalog_codes() {
        let cases = [
            (
                LogStoreError::corruption("bad record"),
                ErrorCode::StorageCorruption,
            ),
            (
                LogStoreError::UnsupportedVersion {
                    segment: 1,
                    version: 9,
                },
                ErrorCode::StorageCorruption,
            ),
            (LogStoreError::invalid("gap"), ErrorCode::InvalidArgument),
            (
                LogStoreError::Io(io::ErrorKind::StorageFull.into()),
                ErrorCode::DiskFull,
            ),
            (LogStoreError::Poisoned, ErrorCode::Internal),
        ];
        for (err, code) in cases {
            assert_eq!(Error::from(err).code(), code);
        }
    }
}
