// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Errors of the document model and their mapping onto the common error catalog.

use rustegon_common::{Error, ErrorCode};

/// Error of a document-model operation (parsing, encoding, decoding, key encoding).
///
/// Messages never contain document values (coding-standards.md §3.6): they name the problem and,
/// at most, a byte offset or a limit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocError {
    /// The encoded document exceeds the 16 MiB limit (FR-DOC-004, `RGN-1002`).
    #[error("document too large: {size} bytes exceed the limit of {limit} bytes")]
    TooLarge {
        /// Encoded size (or a lower bound of it once the limit is crossed).
        size: u64,
        /// The limit in bytes.
        limit: u64,
    },
    /// Nesting deeper than 100 levels (FR-DOC-004, `RGN-1003`).
    #[error("nesting too deep: more than {limit} levels")]
    TooDeep {
        /// The depth limit.
        limit: usize,
    },
    /// A field name breaks the rules of data-model.md §2.2, is duplicated within an object, or a
    /// value cannot be accepted where it appears (e.g. `counter` as input) (`RGN-1004`).
    #[error("invalid field name: {0}")]
    InvalidFieldName(String),
    /// A `vector_f32` element is not finite (`RGN-1040` `InvalidVector`).
    #[error("invalid vector: {0}")]
    InvalidVector(String),
    /// Malformed input: JSON syntax, extended-JSON wrapper, `RDoc` bytes or key bytes (`RGN-1001`).
    #[error("invalid input at byte {offset}: {reason}")]
    Malformed {
        /// Byte offset of the problem within the input.
        offset: usize,
        /// What is wrong.
        reason: String,
    },
}

/// Result alias of this crate.
pub type DocResult<T> = Result<T, DocError>;

impl DocError {
    /// Builds a [`DocError::Malformed`].
    pub(crate) fn malformed(offset: usize, reason: impl Into<String>) -> Self {
        Self::Malformed {
            offset,
            reason: reason.into(),
        }
    }

    /// The catalog code this error maps to (proto/errors.yaml).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge { .. } => ErrorCode::DocumentTooLarge,
            Self::TooDeep { .. } => ErrorCode::NestingTooDeep,
            Self::InvalidFieldName(_) => ErrorCode::InvalidFieldName,
            Self::InvalidVector(_) => ErrorCode::InvalidVector,
            Self::Malformed { .. } => ErrorCode::InvalidArgument,
        }
    }
}

impl From<DocError> for Error {
    fn from(e: DocError) -> Self {
        Error::new(e.code(), e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_error_codes_match_catalog() {
        assert_eq!(DocError::TooLarge { size: 2, limit: 1 }.code().code(), 1002);
        assert_eq!(DocError::TooDeep { limit: 100 }.code().code(), 1003);
        assert_eq!(
            DocError::InvalidFieldName(String::new()).code().code(),
            1004
        );
        assert_eq!(DocError::malformed(0, "x").code().code(), 1001);
        let common: Error = DocError::TooDeep { limit: 100 }.into();
        assert_eq!(common.code(), ErrorCode::NestingTooDeep);
    }
}
