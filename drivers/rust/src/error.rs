// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Errors of the driver (rust-driver.md §8, `drivers/conformance/errors-map.yaml`, PD-075).
//!
//! Every server or transport failure is an [`Error::Rustegon`] carrying the catalog code, name,
//! [`ErrorClass`] and the `retryable` / `committed` flags of the response's `ErrorDetail`.
//! Classes form the hierarchy of errors-map.yaml: [`ErrorClass::is_a`] answers "is this a
//! `QuerySyntax` error?" and also "is this a `Client` error?" for RGN-1010. Failures without an
//! `ErrorDetail` (transport errors, proxies) use the `transport` fallbacks of the same file.

use std::{collections::BTreeMap, fmt, time::Duration};

use prost::Message as _;

use crate::{codec::DocError, pb::ErrorDetail};

/// Result alias of the driver.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The language-neutral exception classes of errors-map.yaml (`classes[].id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorClass {
    /// Root of the hierarchy; also unknown codes (newer servers).
    Base,
    /// The request was invalid (1xxx codes without a more specific class).
    Client,
    /// RGQL syntax / type errors (1010–1012); a [`Client`](Self::Client) error.
    QuerySyntax,
    /// Unique-index violation (1005).
    DuplicateKey,
    /// Schema validation failed (1006).
    DocumentValidation,
    /// Serialization conflicts (2001, 2005, 2007, 2008): retry the transaction.
    TransactionConflict,
    /// The transaction was aborted (2002).
    TransactionAborted,
    /// The commit outcome is unknown (2006): resolve with [`crate::Transaction::resolve`].
    CommitOutcomeUnknown,
    /// Authentication failed or the session expired (4001, 4004, 4005, 4007).
    Authentication,
    /// Raised by the driver when the account must change its password (PD-076); an
    /// [`Authentication`](Self::Authentication) error.
    PasswordChangeRequired,
    /// Permission denied (4002).
    Authorization,
    /// The node or range is unavailable (3xxx).
    Unavailable,
    /// Rate limited (4003); see [`RustegonError::retry_after`].
    RateLimited,
    /// Deadline, transaction or write-concern timeout (5006, 2003, 3006, 1024).
    Timeout,
    /// Server-side failure (5xxx and internal codes).
    Server,
}

impl ErrorClass {
    /// Every class, in errors-map.yaml order.
    pub const ALL: [ErrorClass; 15] = [
        Self::Base,
        Self::Client,
        Self::QuerySyntax,
        Self::DuplicateKey,
        Self::DocumentValidation,
        Self::TransactionConflict,
        Self::TransactionAborted,
        Self::CommitOutcomeUnknown,
        Self::Authentication,
        Self::PasswordChangeRequired,
        Self::Authorization,
        Self::Unavailable,
        Self::RateLimited,
        Self::Timeout,
        Self::Server,
    ];

    /// The class id of errors-map.yaml (`"QuerySyntax"`, …).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Base => "Base",
            Self::Client => "Client",
            Self::QuerySyntax => "QuerySyntax",
            Self::DuplicateKey => "DuplicateKey",
            Self::DocumentValidation => "DocumentValidation",
            Self::TransactionConflict => "TransactionConflict",
            Self::TransactionAborted => "TransactionAborted",
            Self::CommitOutcomeUnknown => "CommitOutcomeUnknown",
            Self::Authentication => "Authentication",
            Self::PasswordChangeRequired => "PasswordChangeRequired",
            Self::Authorization => "Authorization",
            Self::Unavailable => "Unavailable",
            Self::RateLimited => "RateLimited",
            Self::Timeout => "Timeout",
            Self::Server => "Server",
        }
    }

    /// The parent class (`None` for [`Base`](Self::Base)).
    #[must_use]
    pub const fn parent(self) -> Option<ErrorClass> {
        match self {
            Self::Base => None,
            Self::QuerySyntax => Some(Self::Client),
            Self::PasswordChangeRequired => Some(Self::Authentication),
            _ => Some(Self::Base),
        }
    }

    /// `true` when `self` is `ancestor` or one of its descendants.
    #[must_use]
    pub fn is_a(self, ancestor: ErrorClass) -> bool {
        let mut k = Some(self);
        while let Some(c) = k {
            if c == ancestor {
                return true;
            }
            k = c.parent();
        }
        false
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A failure with a catalog code: server errors, transport fallbacks and driver-detected
/// conditions that share the catalog (codec limits, `PasswordChangeRequired`, lost commits).
#[derive(Debug, Clone)]
pub struct RustegonError {
    /// Catalog code (`RGN-<code>`).
    pub code: u32,
    /// Stable name (`"DuplicateKey"`), or `RGN-<code>` for codes unknown to this driver.
    pub name: String,
    /// Class in the errors-map.yaml hierarchy.
    pub class: ErrorClass,
    /// Whether the operation may be retried (from the response, never from the catalog).
    pub retryable: bool,
    /// For commit errors: whether the transaction is known to have committed.
    pub committed: Option<bool>,
    /// Structured details of the server (never document contents or secrets).
    pub details: BTreeMap<String, String>,
    /// W3C trace id of the failed request (empty when the server sent none).
    pub trace_id: String,
    /// Suggested wait before a retry (`RateLimited`).
    pub retry_after: Option<Duration>,
    /// Human-readable message.
    pub message: String,
    /// `false` for transport fallbacks (no `ErrorDetail`): such a failure of a commit may
    /// hide a lost reply (PD-122).
    pub(crate) has_detail: bool,
}

/// Error of a driver operation (rust-driver.md §8).
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A catalog-coded failure (server, transport fallback or driver-detected).
    Rustegon(Box<RustegonError>),
    /// Invalid argument or settings (conformance class `Argument`); detected before any I/O.
    Argument(String),
    /// Use of a closed client, session, cursor or transaction (conformance class
    /// `InvalidState`).
    InvalidState(String),
    /// An error returned by a `with_transaction` callback that is not a driver error; propagated
    /// unchanged after the rollback (transactions.md §5).
    Application(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl Error {
    /// The catalog-coded error, if this is one.
    #[must_use]
    pub fn rustegon(&self) -> Option<&RustegonError> {
        match self {
            Self::Rustegon(e) => Some(e),
            _ => None,
        }
    }

    /// The catalog code (`None` for argument, state and application errors).
    #[must_use]
    pub fn code(&self) -> Option<u32> {
        self.rustegon().map(|e| e.code)
    }

    /// The class (`None` for argument, state and application errors).
    #[must_use]
    pub fn class(&self) -> Option<ErrorClass> {
        self.rustegon().map(|e| e.class)
    }

    /// `true` when this is a catalog-coded error of `class` or of one of its descendants.
    #[must_use]
    pub fn is(&self, class: ErrorClass) -> bool {
        self.class().is_some_and(|c| c.is_a(class))
    }

    /// Whether the operation may be retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.rustegon().is_some_and(|e| e.retryable)
    }

    /// Wraps an application error (`with_transaction` callbacks).
    pub fn application(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Application(Box::new(e))
    }

    pub(crate) fn argument(msg: impl Into<String>) -> Self {
        Self::Argument(msg.into())
    }

    pub(crate) fn closed(what: &str) -> Self {
        Self::InvalidState(format!("{what} is closed"))
    }

    /// A catalog error synthesized by the driver.
    pub(crate) fn coded(code: u32, retryable: bool, message: impl Into<String>) -> Self {
        Self::Rustegon(Box::new(RustegonError {
            code,
            name: crate::codes::name_of(code),
            class: crate::codes::class_of(code),
            retryable,
            committed: None,
            details: BTreeMap::new(),
            trace_id: String::new(),
            retry_after: None,
            message: message.into(),
            has_detail: true,
        }))
    }

    /// The error of an `ErrorDetail` (server responses, bulk-write items).
    pub(crate) fn from_detail(d: &ErrorDetail, message: impl Into<String>) -> Self {
        let name = if d.name.is_empty() {
            crate::codes::name_of(d.code)
        } else {
            d.name.clone()
        };
        Self::Rustegon(Box::new(RustegonError {
            code: d.code,
            name,
            class: crate::codes::class_of(d.code),
            retryable: d.retryable,
            committed: d.committed,
            details: d
                .details
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            trace_id: d.trace_id.clone(),
            retry_after: d
                .retry_after_ms
                .map(|ms| Duration::from_millis(u64::from(ms))),
            message: message.into(),
            has_detail: true,
        }))
    }

    /// The transport fallback of errors-map.yaml for a status without `ErrorDetail`.
    pub(crate) fn from_transport(code: tonic::Code, message: impl Into<String>) -> Self {
        let (class, catalog, retryable) = crate::codes::transport_fallback(code);
        Self::Rustegon(Box::new(RustegonError {
            code: catalog,
            name: crate::codes::name_of(catalog),
            class,
            retryable,
            committed: None,
            details: BTreeMap::new(),
            trace_id: String::new(),
            retry_after: None,
            message: message.into(),
            has_detail: false,
        }))
    }

    /// Maps a gRPC status: its `ErrorDetail` when present, the transport fallback otherwise.
    pub(crate) fn from_status(status: &tonic::Status) -> Self {
        let message = if status.message().is_empty() {
            format!("{:?}", status.code())
        } else {
            status.message().to_owned()
        };
        match error_detail_of(status) {
            Some(d) => Self::from_detail(&d, message),
            None => Self::from_transport(status.code(), message),
        }
    }

    pub(crate) fn rustegon_mut(&mut self) -> Option<&mut RustegonError> {
        match self {
            Self::Rustegon(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DocError> for Error {
    /// Codec errors of user documents carry their catalog code (1001–1004, 1040) and class
    /// `Client`, as the server would report them.
    fn from(e: DocError) -> Self {
        Self::coded(e.code(), false, e.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rustegon(e) => write!(f, "RGN-{} {}: {}", e.code, e.name, e.message),
            Self::Argument(m) => write!(f, "invalid argument: {m}"),
            Self::InvalidState(m) => write!(f, "invalid state: {m}"),
            Self::Application(e) => write!(f, "application error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Application(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// `google.rpc.Status` as packed in `grpc-status-details-bin` (protocol.md §7).
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct RpcStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(message, repeated, tag = "3")]
    pub details: Vec<Any>,
}

/// `google.protobuf.Any`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Any {
    #[prost(string, tag = "1")]
    pub type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

/// Type URL of `ErrorDetail` inside `google.rpc.Status.details`.
pub(crate) const ERROR_DETAIL_TYPE_URL: &str = "type.googleapis.com/rustegon.v1.ErrorDetail";

/// The `ErrorDetail` of a status, if the server attached one.
pub(crate) fn error_detail_of(status: &tonic::Status) -> Option<ErrorDetail> {
    let rpc = RpcStatus::decode(status.details()).ok()?;
    rpc.details
        .iter()
        .find(|a| a.type_url == ERROR_DETAIL_TYPE_URL)
        .and_then(|a| ErrorDetail::decode(a.value.as_slice()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_drv_rs_004_class_hierarchy() {
        assert!(ErrorClass::QuerySyntax.is_a(ErrorClass::Client));
        assert!(ErrorClass::QuerySyntax.is_a(ErrorClass::Base));
        assert!(!ErrorClass::QuerySyntax.is_a(ErrorClass::Server));
        assert!(ErrorClass::PasswordChangeRequired.is_a(ErrorClass::Authentication));
        let e = Error::coded(1010, false, "x");
        assert!(e.is(ErrorClass::Client) && e.is(ErrorClass::QuerySyntax));
        assert_eq!(e.code(), Some(1010));
    }

    #[test]
    fn tc_drv_rs_004_status_with_detail() {
        let d = ErrorDetail {
            code: 1005,
            name: "DuplicateKey".into(),
            retryable: false,
            committed: None,
            details: std::collections::HashMap::new(),
            trace_id: "abc".into(),
            retry_after_ms: Some(5),
        };
        let rpc = RpcStatus {
            code: 6,
            message: "dup".into(),
            details: vec![Any {
                type_url: ERROR_DETAIL_TYPE_URL.into(),
                value: d.encode_to_vec(),
            }],
        };
        let st = tonic::Status::with_details(
            tonic::Code::AlreadyExists,
            "dup",
            rpc.encode_to_vec().into(),
        );
        let e = Error::from_status(&st);
        let r = e.rustegon().unwrap();
        assert_eq!(
            (r.code, r.class, r.trace_id.as_str()),
            (1005, ErrorClass::DuplicateKey, "abc")
        );
        assert_eq!(r.retry_after, Some(Duration::from_millis(5)));
        let t = Error::from_status(&tonic::Status::unavailable("down"));
        assert_eq!(t.code(), Some(3002));
        assert!(t.is_retryable());
    }
}
