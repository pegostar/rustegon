// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Errors of the `RDoc` codec and the extended-JSON parser, with their catalog codes
//! (proto/errors.yaml; `drivers/conformance/codec/invalid.yaml` names the classes).

/// Error of a codec operation (parsing, encoding, decoding).
///
/// Messages never contain document values (coding-standards.md §3.6): they name the problem and,
/// at most, a byte offset or a limit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocError {
    /// The encoded document exceeds the 16 MiB limit (`RGN-1002`).
    #[error("document too large: {size} bytes exceed the limit of {limit} bytes")]
    TooLarge {
        /// Encoded size (or a lower bound of it once the limit is crossed).
        size: u64,
        /// The limit in bytes.
        limit: u64,
    },
    /// Nesting deeper than 100 levels (`RGN-1003`).
    #[error("nesting too deep: more than {limit} levels")]
    TooDeep {
        /// The depth limit.
        limit: usize,
    },
    /// A field name breaks the rules of data-model.md §2.2, is duplicated within an object, or a
    /// value cannot be accepted where it appears (e.g. `counter` as input) (`RGN-1004`).
    #[error("invalid field name: {0}")]
    InvalidFieldName(String),
    /// A `vector_f32` element is not finite (`RGN-1040`).
    #[error("invalid vector: {0}")]
    InvalidVector(String),
    /// Malformed input: JSON syntax, extended-JSON wrapper or `RDoc` bytes (`RGN-1001`).
    #[error("invalid input at byte {offset}: {reason}")]
    Malformed {
        /// Byte offset of the problem within the input.
        offset: usize,
        /// What is wrong.
        reason: String,
    },
}

/// Result alias of the codec.
pub type DocResult<T> = Result<T, DocError>;

impl DocError {
    /// Builds a [`DocError::Malformed`].
    pub(crate) fn malformed(offset: usize, reason: impl Into<String>) -> Self {
        Self::Malformed {
            offset,
            reason: reason.into(),
        }
    }

    /// The catalog code (`RGN-<code>`) this error maps to.
    #[must_use]
    pub fn code(&self) -> u32 {
        match self {
            Self::Malformed { .. } => 1001,
            Self::TooLarge { .. } => 1002,
            Self::TooDeep { .. } => 1003,
            Self::InvalidFieldName(_) => 1004,
            Self::InvalidVector(_) => 1040,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_error_codes_match_catalog() {
        assert_eq!(DocError::TooLarge { size: 2, limit: 1 }.code(), 1002);
        assert_eq!(DocError::TooDeep { limit: 100 }.code(), 1003);
        assert_eq!(DocError::InvalidFieldName(String::new()).code(), 1004);
        assert_eq!(DocError::malformed(0, "x").code(), 1001);
        assert_eq!(DocError::InvalidVector(String::new()).code(), 1040);
    }
}
