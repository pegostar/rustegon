// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Parser errors: `RGN-1010 QuerySyntaxError {line, column, found, expected[]}` and
//! `RGN-1013 QueryTooComplex` (query-language.md §14, proto/errors.yaml).

use std::fmt;

use rustegon_common::{Error, ErrorCode};

/// Longest token text echoed in an error (keeps messages bounded for huge literals).
const MAX_FOUND_CHARS: usize = 32;

/// A parse error with its 1-based source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// `RGN-1010`: the text is not valid RGQL.
    Syntax {
        /// 1-based line.
        line: u32,
        /// 1-based column (Unicode scalar values).
        column: u32,
        /// The offending token, quoted, or `end of input`.
        found: String,
        /// What would have been accepted at this position (keywords upper-case,
        /// punctuation quoted, classes such as `identifier` or `expression`).
        expected: Vec<String>,
        /// Extra explanation for errors that a token list does not describe.
        hint: Option<String>,
    },
    /// `RGN-1013`: a complexity limit was exceeded (nesting depth, input size).
    TooComplex {
        /// 1-based line.
        line: u32,
        /// 1-based column.
        column: u32,
        /// Which limit.
        reason: String,
    },
}

impl ParseError {
    pub(crate) fn syntax(
        line: u32,
        column: u32,
        found: String,
        expected: Vec<String>,
        hint: Option<String>,
    ) -> Self {
        Self::Syntax {
            line,
            column,
            found,
            expected,
            hint,
        }
    }

    /// Quotes token text for [`ParseError::Syntax::found`], truncating long tokens.
    pub(crate) fn quote_found(text: &str) -> String {
        if text.chars().count() > MAX_FOUND_CHARS {
            let cut: String = text.chars().take(MAX_FOUND_CHARS).collect();
            format!("{cut:?}…")
        } else {
            format!("{text:?}")
        }
    }

    /// The error code (`QuerySyntaxError` or `QueryTooComplex`).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Syntax { .. } => ErrorCode::QuerySyntaxError,
            Self::TooComplex { .. } => ErrorCode::QueryTooComplex,
        }
    }

    /// `(line, column)` of the error.
    #[must_use]
    pub fn position(&self) -> (u32, u32) {
        match self {
            Self::Syntax { line, column, .. } | Self::TooComplex { line, column, .. } => {
                (*line, *column)
            }
        }
    }

    /// Converts into the common error with the structured details of errors.yaml
    /// (`line`, `column`, `found`, `expected` as a comma-separated list).
    #[must_use]
    pub fn into_error(self) -> Error {
        let message = self.to_string();
        let (line, column) = self.position();
        let err = Error::new(self.code(), message)
            .with_detail("line", line.to_string())
            .with_detail("column", column.to_string());
        match self {
            Self::Syntax {
                found, expected, ..
            } => err
                .with_detail("found", found)
                .with_detail("expected", expected.join(", ")),
            Self::TooComplex { reason, .. } => err.with_detail("reason", reason),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax {
                line,
                column,
                found,
                expected,
                hint,
            } => {
                write!(
                    f,
                    "syntax error at line {line}, column {column}: found {found}"
                )?;
                match expected.as_slice() {
                    [] => {}
                    [one] => write!(f, ", expected {one}")?,
                    many => write!(f, ", expected one of: {}", many.join(", "))?,
                }
                if let Some(hint) = hint {
                    write!(f, " ({hint})")?;
                }
                Ok(())
            }
            Self::TooComplex {
                line,
                column,
                reason,
            } => write!(
                f,
                "query too complex at line {line}, column {column}: {reason}"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        e.into_error()
    }
}
