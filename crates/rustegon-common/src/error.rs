// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Common error type and the generated error code catalog (protocol.md §7).
//!
//! Library crates keep their own `thiserror` enums and convert into [`Error`] at layer
//! boundaries (coding-standards.md §3.2).

use std::{collections::BTreeMap, fmt};

include!(concat!(env!("OUT_DIR"), "/error_codes.rs"));

/// gRPC status codes (`google.rpc.Code`) used by the error catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[allow(missing_docs)] // Names are the standard gRPC codes.
pub enum GrpcCode {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

/// Whether a client may retry an operation that failed with a given code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Retryable {
    /// Never retry automatically.
    No,
    /// Safe to retry (possibly with a qualifier, see [`ErrorCode::retry_note`]).
    Yes,
    /// Depends on the concrete error; the producer sets [`Error::retryable`] explicitly.
    Conditional,
}

struct ErrorCodeInfo {
    name: &'static str,
    aliases: &'static [&'static str],
    internal: bool,
    grpc: GrpcCode,
    http: u16,
    retryable: Retryable,
    retry_note: Option<&'static str>,
}

impl ErrorCode {
    const fn info(self) -> &'static ErrorCodeInfo {
        &INFO[self.index()]
    }

    /// Numeric code (`RGN-<code>`).
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Stable name, e.g. `DuplicateKey`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.info().name
    }

    /// Alternative documented names for the same code (e.g. `ScanNotAllowed` for 1013).
    #[must_use]
    pub const fn aliases(self) -> &'static [&'static str] {
        self.info().aliases
    }

    /// `true` for codes used only between nodes; they are never returned to clients.
    #[must_use]
    pub const fn is_internal(self) -> bool {
        self.info().internal
    }

    /// gRPC status the code maps to.
    #[must_use]
    pub const fn grpc_code(self) -> GrpcCode {
        self.info().grpc
    }

    /// HTTP status the code maps to on the REST API.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        self.info().http
    }

    /// Default retry classification.
    #[must_use]
    pub const fn retryable(self) -> Retryable {
        self.info().retryable
    }

    /// Qualifier of the retry classification (e.g. `other node`, `committed=true`).
    #[must_use]
    pub const fn retry_note(self) -> Option<&'static str> {
        self.info().retry_note
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RGN-{} {}", self.code(), self.name())
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The common error carried across layer boundaries and mapped onto gRPC/REST errors.
#[derive(Debug)]
pub struct Error {
    code: ErrorCode,
    message: String,
    details: BTreeMap<String, String>,
    retryable: bool,
    source: Option<BoxError>,
}

/// Result alias using [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// Creates an error. `retryable` starts from the code's default; codes classified
    /// [`Retryable::Conditional`] start as not retryable until [`Error::with_retryable`] says so.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: BTreeMap::new(),
            retryable: matches!(code.retryable(), Retryable::Yes),
            source: None,
        }
    }

    /// Adds a structured detail (key/value), carried in `ErrorDetail.details`.
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Overrides the retry classification (for [`Retryable::Conditional`] codes).
    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Attaches the underlying cause.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<BoxError>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// The error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Human-readable message (never contains document contents or secrets).
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Structured details.
    #[must_use]
    pub fn details(&self) -> &BTreeMap<String, String> {
        &self.details
    }

    /// Whether the client may retry.
    #[must_use]
    pub fn retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_new_conditional_code_not_retryable_until_overridden() {
        let e = Error::new(ErrorCode::TransactionAborted, "aborted");
        assert!(!e.retryable());
        assert!(e.with_retryable(true).retryable());
    }

    #[test]
    fn error_display_includes_code_name_and_message() {
        let e = Error::new(ErrorCode::DuplicateKey, "dup").with_detail("index", "by_email");
        assert_eq!(e.to_string(), "RGN-1005 DuplicateKey: dup");
        assert_eq!(
            e.details().get("index").map(String::as_str),
            Some("by_email")
        );
    }

    #[test]
    fn error_source_is_preserved() {
        let io = std::io::Error::other("disk");
        let e = Error::new(ErrorCode::Internal, "write failed").with_source(io);
        let src = std::error::Error::source(&e).map(ToString::to_string);
        assert_eq!(src.as_deref(), Some("disk"));
    }
}
