// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Errors of the authentication modules.
//!
//! Every way a credential can be wrong (unknown user, wrong password, disabled user, bad proof,
//! nonce or channel-binding mismatch, unknown/expired API key, address not allowed …) is
//! reported as the single [`AuthnError::AuthenticationFailed`] whose message is the fixed
//! [`AUTHENTICATION_FAILED`] (AC-SEC-002 "wrong credentials fail generically"): distinguishing
//! them on the wire would let a client enumerate user names or API key ids. The precise reason
//! ([`FailureReason`]) is kept for the audit log only.

use rustegon_common::{Error, ErrorCode};

/// The only message sent to a client whose credentials were rejected.
pub const AUTHENTICATION_FAILED: &str = "authentication failed";

/// Why an authentication failed (audit detail, never sent to the client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// Unknown, disabled or password-less user, or wrong password / proof / API key secret.
    BadCredentials,
    /// The client-final nonce does not equal the combined nonce of the server-first message.
    NonceMismatch,
    /// Channel binding missing, downgraded or different from the TLS exporter.
    ChannelBinding,
    /// A SCRAM message, API key string or certificate could not be parsed.
    Malformed,
    /// API key expired.
    Expired,
    /// Client address outside the API key allowlist.
    AddressNotAllowed,
}

/// Error of the authentication modules.
#[derive(Debug, thiserror::Error)]
pub enum AuthnError {
    /// Credentials rejected (module docs). `RGN-4001`.
    #[error("authentication failed")]
    AuthenticationFailed(FailureReason),
    /// The session token is unknown, expired or revoked: re-authenticate. `RGN-4005`.
    #[error("session expired")]
    SessionExpired,
    /// Invalid input of an administrative call (bad user name, weak password, roles outside
    /// the user's roles, out-of-range parameters). `RGN-1001`.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The user or API key exists already.
    #[error("{0} already exists")]
    AlreadyExists(String),
    /// The user or API key does not exist.
    #[error("{0} not found")]
    NotFound(String),
    /// The operation's precondition does not hold (e.g. bootstrap on a store that has users).
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
    /// A persisted record could not be decoded. `RGN-5002`.
    #[error("corrupt security record: {0}")]
    Corrupt(String),
    /// Error of the underlying store or transaction, propagated with its own code (retryable
    /// conflicts must reach the transaction retry loop unchanged).
    #[error(transparent)]
    Store(#[from] Error),
}

/// Result alias of the authentication modules.
pub type AuthnResult<T> = Result<T, AuthnError>;

impl AuthnError {
    /// Shorthand for a generic authentication failure.
    #[must_use]
    pub const fn failed(reason: FailureReason) -> Self {
        Self::AuthenticationFailed(reason)
    }

    /// The protocol error code (protocol.md §7).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::AuthenticationFailed(_) => ErrorCode::Unauthenticated,
            Self::SessionExpired => ErrorCode::SessionExpired,
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::AlreadyExists(_) => ErrorCode::AlreadyExists,
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::PreconditionFailed(_) => ErrorCode::PreconditionFailed,
            Self::Corrupt(_) => ErrorCode::StorageCorruption,
            Self::Store(e) => e.code(),
        }
    }

    pub(crate) fn corrupt(what: &str, msg: impl std::fmt::Display) -> Self {
        Self::Corrupt(format!("{what}: {msg}"))
    }
}

impl From<AuthnError> for Error {
    fn from(e: AuthnError) -> Self {
        match e {
            AuthnError::Store(inner) => inner,
            // The display of `AuthenticationFailed` is the fixed generic message; the reason
            // stays out of the client-visible error on purpose (module docs).
            other => Error::new(other.code(), other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_sec_002_failures_are_generic_and_map_to_unauthenticated() {
        for reason in [
            FailureReason::BadCredentials,
            FailureReason::NonceMismatch,
            FailureReason::ChannelBinding,
            FailureReason::Malformed,
            FailureReason::Expired,
            FailureReason::AddressNotAllowed,
        ] {
            let e: Error = AuthnError::failed(reason).into();
            assert_eq!(e.code(), ErrorCode::Unauthenticated);
            assert_eq!(e.message(), AUTHENTICATION_FAILED);
        }
        let e: Error = AuthnError::SessionExpired.into();
        assert_eq!(e.code(), ErrorCode::SessionExpired);
    }
}
