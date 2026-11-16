// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Errors of the catalog and their mapping onto the common error catalog (proto/errors.yaml).

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::DocError;

/// The kind of catalog object an error is about (used in messages and error details).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// A database.
    Database,
    /// A collection (document, table or time-series).
    Collection,
}

impl ObjectKind {
    /// Lower-case name used in messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Collection => "collection",
        }
    }
}

/// Error of a catalog operation.
///
/// Names are user input, not document contents, so they may appear in messages (they are also
/// what the client needs to see to fix the request).
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// The object does not exist (`RGN-1030 NotFound`), including a missing collection when
    /// `implicitCollectionCreation` is false (FR-SCH-001, AC-SCH-001).
    #[error("{} not found: {name}{}", kind.as_str(), hint.map_or(String::new(), |h| format!(" ({h})")))]
    NotFound {
        /// What was looked up.
        kind: ObjectKind,
        /// The name that was looked up.
        name: String,
        /// Optional explanation (e.g. implicit creation disabled).
        hint: Option<&'static str>,
    },
    /// An object with this name already exists (`RGN-1031 AlreadyExists`).
    #[error("{} already exists: {name}", kind.as_str())]
    AlreadyExists {
        /// What was created.
        kind: ObjectKind,
        /// The conflicting name.
        name: String,
    },
    /// A name breaks the rules of system-overview.md §9 (`RGN-1001 InvalidArgument`; the catalog
    /// has no dedicated "invalid name" code).
    #[error("invalid {} name: {reason}", kind.as_str())]
    InvalidName {
        /// What was named.
        kind: ObjectKind,
        /// Which rule is broken.
        reason: &'static str,
    },
    /// Any other invalid request argument (`RGN-1001 InvalidArgument`).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The descriptor id sequence is exhausted (`RGN-5004 ResourceExhausted`): ids are never
    /// reused (database-engine.md §1), so this is final for the cluster.
    #[error("descriptor id space exhausted")]
    IdsExhausted,
    /// A stored catalog entry cannot be decoded (`RGN-5002 StorageCorruption`). Distinct from
    /// invalid input so that it alerts (coding-standards.md §3.2).
    #[error("corrupt catalog entry: {0}")]
    Corrupt(String),
    /// Encoding a descriptor failed in the document codec.
    #[error(transparent)]
    Doc(#[from] DocError),
    /// The caller's [`crate::CatalogRead`] implementation failed (propagated unchanged).
    #[error(transparent)]
    Read(Error),
    /// No non-dropping index of that name on the collection (`RGN-1021 IndexNotFound`).
    #[error("index not found: {name} on collection {collection}")]
    IndexNotFound {
        /// Collection name.
        collection: String,
        /// Index name.
        name: String,
    },
    /// A non-dropping index of that name exists (`RGN-1020 IndexAlreadyExists`).
    #[error("index already exists: {name}")]
    IndexAlreadyExists {
        /// Index name.
        name: String,
    },
    /// The collection already has the maximum number of indexes (`RGN-1023`, FR-IDX-005).
    #[error("collection {collection} already has {limit} indexes")]
    IndexLimitExceeded {
        /// Collection name.
        collection: String,
        /// The limit.
        limit: usize,
    },
    /// The object changed state concurrently (`RGN-1033 SchemaChangeInProgress`, retryable).
    #[error("schema change in progress: {0}")]
    SchemaChangeInProgress(String),
}

/// Result alias of this crate.
pub type CatalogResult<T> = Result<T, CatalogError>;

impl CatalogError {
    /// The catalog code this error maps to (proto/errors.yaml).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::NotFound { .. } => ErrorCode::NotFound,
            Self::AlreadyExists { .. } => ErrorCode::AlreadyExists,
            Self::InvalidName { .. } | Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::IdsExhausted => ErrorCode::ResourceExhausted,
            Self::Corrupt(_) => ErrorCode::StorageCorruption,
            Self::Doc(e) => e.code(),
            Self::Read(e) => e.code(),
            Self::IndexNotFound { .. } => ErrorCode::IndexNotFound,
            Self::IndexAlreadyExists { .. } => ErrorCode::IndexAlreadyExists,
            Self::IndexLimitExceeded { .. } => ErrorCode::IndexLimitExceeded,
            Self::SchemaChangeInProgress(_) => ErrorCode::SchemaChangeInProgress,
        }
    }

    /// Builds a [`CatalogError::Corrupt`].
    pub(crate) fn corrupt(reason: impl Into<String>) -> Self {
        Self::Corrupt(reason.into())
    }
}

impl From<CatalogError> for Error {
    fn from(e: CatalogError) -> Self {
        match e {
            // Keep the caller's error intact (details, retryability, source).
            CatalogError::Read(inner) => inner,
            other => {
                let code = other.code();
                let mut err = Error::new(code, other.to_string());
                match &other {
                    CatalogError::NotFound { kind, name, .. }
                    | CatalogError::AlreadyExists { kind, name } => {
                        err = err
                            .with_detail("kind", kind.as_str())
                            .with_detail("name", name.clone());
                    }
                    CatalogError::IndexNotFound { name, .. }
                    | CatalogError::IndexAlreadyExists { name } => {
                        err = err
                            .with_detail("kind", "index")
                            .with_detail("name", name.clone());
                    }
                    CatalogError::SchemaChangeInProgress(_) => err = err.with_retryable(true),
                    _ => {}
                }
                err
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_match_catalog() {
        let nf = CatalogError::NotFound {
            kind: ObjectKind::Collection,
            name: "c".into(),
            hint: None,
        };
        assert_eq!(nf.code(), ErrorCode::NotFound);
        assert_eq!(nf.code().code(), 1030);
        let ae = CatalogError::AlreadyExists {
            kind: ObjectKind::Database,
            name: "d".into(),
        };
        assert_eq!(ae.code().code(), 1031);
        let common: Error = ae.into();
        assert_eq!(
            common.details().get("kind").map(String::as_str),
            Some("database")
        );
        assert_eq!(
            CatalogError::IdsExhausted.code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            CatalogError::corrupt("x").code(),
            ErrorCode::StorageCorruption
        );
    }
}
