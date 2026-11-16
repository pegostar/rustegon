// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MVCC error type (coding-standards.md §3.2) and its mapping onto the error catalog
//! (`proto/errors.yaml`).

use rustegon_common::{Error, ErrorCode};
use rustegon_storage::StorageError;

use crate::{hlc::Timestamp, value::Intent};

/// Result alias for MVCC operations.
pub type Result<T, E = MvccError> = std::result::Result<T, E>;

/// Errors raised by the MVCC layer.
#[derive(Debug, thiserror::Error)]
pub enum MvccError {
    /// An error of the storage engine.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// A persisted MVCC key or value failed validation (format version, length, tag).
    #[error("MVCC corruption: {0}")]
    Corruption(String),
    /// The caller violated an API contract (e.g. commit below the intent timestamp).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Intents of other transactions must be resolved (pushed, waited on or cleaned up) before
    /// the operation can proceed (transaction-management.md §5.1). Sorted by key.
    #[error("{} conflicting write intent(s)", .0.len())]
    IntentConflict(Vec<Intent>),
    /// A committed version at or above the write timestamp exists: the writer must move its
    /// timestamp above `existing` (§5.1 "write-too-old"; `RGN-2008`).
    #[error("write too old: committed version at {existing} >= write timestamp {write_ts}")]
    WriteTooOld {
        /// Requested write timestamp.
        write_ts: Timestamp,
        /// Newest committed version of the key.
        existing: Timestamp,
    },
    /// A committed version lies in `(read_ts, uncertainty_limit]`: the reader cannot tell
    /// whether it happened before it and must restart above `existing` (§4.2).
    #[error("read within uncertainty interval: version at {existing} > read timestamp {read_ts}")]
    ReadWithinUncertainty {
        /// The reader's timestamp.
        read_ts: Timestamp,
        /// Timestamp of the uncertain version.
        existing: Timestamp,
    },
    /// The operation's timestamp is below the GC threshold: versions it might need may have
    /// been removed (`RGN-2007`, FR-TXN / TC-TXN-036).
    #[error("timestamp {ts} is below the GC threshold {threshold}")]
    BelowGcThreshold {
        /// Requested read (or write) timestamp.
        ts: Timestamp,
        /// Current GC threshold.
        threshold: Timestamp,
    },
}

impl MvccError {
    /// Shorthand for [`MvccError::Corruption`].
    pub(crate) fn corruption(reason: impl Into<String>) -> Self {
        Self::Corruption(reason.into())
    }

    /// The catalog code the error maps to.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Storage(e) => storage_code(e),
            Self::Corruption(_) => ErrorCode::StorageCorruption,
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            // An intent conflict surfaces to clients only when the transaction layer gives up
            // resolving it; an uncertainty restart is transparent there (§1.1). Leaked, both
            // are retryable conflicts.
            Self::IntentConflict(_) | Self::ReadWithinUncertainty { .. } => {
                ErrorCode::TransactionConflict
            }
            Self::WriteTooOld { .. } => ErrorCode::WriteTooOld,
            Self::BelowGcThreshold { .. } => ErrorCode::ReadTimestampTooOld,
        }
    }
}

/// The catalog code of a storage error (its own mapping, without consuming it).
fn storage_code(e: &StorageError) -> ErrorCode {
    match e {
        StorageError::Corruption(_) => ErrorCode::StorageCorruption,
        StorageError::InvalidArgument(_) => ErrorCode::InvalidArgument,
        StorageError::CounterOverflow => ErrorCode::CounterOverflow,
        StorageError::KeyUnavailable(_) => ErrorCode::KeyUnavailable,
        StorageError::Io(io) if io.kind() == std::io::ErrorKind::StorageFull => ErrorCode::DiskFull,
        StorageError::Io(_) => ErrorCode::Internal,
    }
}

impl From<MvccError> for Error {
    fn from(err: MvccError) -> Self {
        match err {
            MvccError::Storage(e) => e.into(),
            other => Error::new(other.code(), other.to_string()).with_source(other),
        }
    }
}
