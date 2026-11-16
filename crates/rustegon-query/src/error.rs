// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Errors of the binder, planner and executor (query-engine.md §2, query-language.md §14).
//!
//! The engine runs inside a caller's transaction, so it distinguishes two failure levels:
//! [`ExecError::Txn`] is a transaction error (conflict, abort, timeout) that the caller's
//! transaction runner may retry as a whole, [`ExecError::Query`] a request error returned to the
//! client as is. Keeping them apart is what lets `TxnCoordinator::run` retry conflicts that
//! happen in the middle of a query.

use rustegon_common::{Error, ErrorCode};
use rustegon_txn::TxnError;

/// An execution failure (module docs).
#[derive(Debug)]
pub enum ExecError {
    /// Transaction-level error (possibly retryable by re-running the transaction).
    Txn(TxnError),
    /// Request error (bind, type, constraint, limit, deadline …).
    Query(Error),
}

/// Result alias of the engine.
pub type ExecResult<T> = Result<T, ExecError>;

impl From<Error> for ExecError {
    fn from(e: Error) -> Self {
        Self::Query(e)
    }
}

impl From<TxnError> for ExecError {
    fn from(e: TxnError) -> Self {
        Self::Txn(e)
    }
}

impl From<rustegon_doc::DocError> for ExecError {
    fn from(e: rustegon_doc::DocError) -> Self {
        Self::Query(e.into())
    }
}

impl ExecError {
    /// The public error (a transaction error keeps its own code and message).
    #[must_use]
    pub fn into_error(self) -> Error {
        match self {
            Self::Query(e) => e,
            Self::Txn(e) => Error::new(e.code(), e.to_string()),
        }
    }

    /// The error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Query(e) => e.code(),
            Self::Txn(e) => e.code(),
        }
    }
}

/// `RGN-1011 QueryTypeError`.
#[must_use]
pub fn type_error(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::QueryTypeError, msg)
}

/// `RGN-1012 UnknownFunction`.
#[must_use]
pub fn unknown_function(name: &str) -> Error {
    Error::new(
        ErrorCode::UnknownFunction,
        format!("unknown function {name}()"),
    )
    .with_detail("function", name)
}

/// `RGN-1030 NotFound` for a database or collection named in a statement.
#[must_use]
pub fn not_found(kind: &str, name: &str) -> Error {
    Error::new(ErrorCode::NotFound, format!("{kind} not found: {name}"))
        .with_detail("kind", kind)
        .with_detail("name", name)
}

/// A construct whose execution belongs to a later milestone (aggregation, joins, search are
/// M7; wide-column and TTL are M8). *Provisional (PD pending)*: the specification names no code
/// for "valid RGQL not supported by this version"; `RGN-1001 InvalidArgument` with a `feature`
/// detail is used so that clients can tell it apart from syntax and type errors.
#[must_use]
pub fn unsupported(feature: &str, milestone: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!("{feature} is not supported by this version (planned for {milestone})"),
    )
    .with_detail("feature", feature)
    .with_detail("milestone", milestone)
    // The same marker as the reference interpreter's (query-language.md §4.3 "unsupported =
    // RGN-1001 + detail `unsupported`"), so clients and the differential harness recognise it.
    .with_detail("unsupported", feature)
}

/// `RGN-1001 InvalidArgument`.
#[must_use]
pub fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, msg)
}

/// `RGN-5001 Internal` (an engine invariant was violated).
#[must_use]
pub fn internal(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::Internal, msg)
}
