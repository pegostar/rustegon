// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Storage error type (coding-standards.md §3.2).
//!
//! Corruption is a distinct kind because it needs different handling than ordinary I/O failures
//! (storage-engine.md §13: replica quarantine in cluster mode, `RGN-5002` to the caller).

use std::io;

use rustegon_common::{Error, ErrorCode};

/// Result alias for storage operations.
pub type Result<T, E = StorageError> = std::result::Result<T, E>;

/// Errors raised by the storage engine.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Persisted data failed validation (checksum, magic, structure).
    #[error("storage corruption: {0}")]
    Corruption(String),
    /// The caller violated an API contract (e.g. keys added out of order).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// A merged counter/statistic left the `i64` range (storage-engine.md §8, data-model.md §10).
    #[error("merged value out of i64 range")]
    CounterOverflow,
    /// Key material needed to read or write encrypted files is unavailable: the KEK cannot be
    /// read or does not match the one the store was written with, the DEK registry is missing,
    /// or an encrypted file is opened without encryption configured (storage-engine.md §7, §9:
    /// the node refuses to start with `RGN-4006`). The message never contains key material.
    #[error("encryption key unavailable: {0}")]
    KeyUnavailable(String),
    /// An I/O error from the file system.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl StorageError {
    /// Shorthand for [`StorageError::Corruption`].
    pub(crate) fn corruption(reason: impl Into<String>) -> Self {
        Self::Corruption(reason.into())
    }

    /// Shorthand for [`StorageError::KeyUnavailable`].
    pub(crate) fn key_unavailable(reason: impl Into<String>) -> Self {
        Self::KeyUnavailable(reason.into())
    }

    /// Whether the error indicates corrupt persisted data.
    #[must_use]
    pub fn is_corruption(&self) -> bool {
        matches!(self, Self::Corruption(_))
    }
}

impl From<StorageError> for Error {
    fn from(err: StorageError) -> Self {
        let code = match &err {
            StorageError::Corruption(_) => ErrorCode::StorageCorruption,
            StorageError::InvalidArgument(_) => ErrorCode::InvalidArgument,
            StorageError::CounterOverflow => ErrorCode::CounterOverflow,
            StorageError::KeyUnavailable(_) => ErrorCode::KeyUnavailable,
            StorageError::Io(e) if e.kind() == io::ErrorKind::StorageFull => ErrorCode::DiskFull,
            StorageError::Io(_) => ErrorCode::Internal,
        };
        Error::new(code, err.to_string()).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_error_maps_to_catalog_codes() {
        let cases = [
            (
                StorageError::corruption("bad block"),
                ErrorCode::StorageCorruption,
            ),
            (
                StorageError::InvalidArgument("x".into()),
                ErrorCode::InvalidArgument,
            ),
            (StorageError::CounterOverflow, ErrorCode::CounterOverflow),
            (
                StorageError::KeyUnavailable("no KEK".into()),
                ErrorCode::KeyUnavailable,
            ),
            (
                io::Error::from(io::ErrorKind::StorageFull).into(),
                ErrorCode::DiskFull,
            ),
            (io::Error::other("eio").into(), ErrorCode::Internal),
        ];
        for (err, code) in cases {
            assert_eq!(Error::from(err).code(), code);
        }
    }
}
