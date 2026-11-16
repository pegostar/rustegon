// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transaction errors (coding-standards.md §3.2) and their mapping onto the error catalog
//! (`proto/errors.yaml`, specifications/transactions.md §4).

use std::time::Duration;

use rustegon_common::{Error, ErrorCode, Retryable};
use rustegon_mvcc::{MvccError, ReplicaError};

/// Result alias for transaction operations.
pub type Result<T, E = TxnError> = std::result::Result<T, E>;

/// Why a transaction was aborted (the `reason` detail of `RGN-2002`, transactions.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbortReason {
    /// The client rolled the transaction back.
    Rollback,
    /// A higher-priority transaction pushed it (abort push, transaction-management.md §5.1).
    Conflict,
    /// It was chosen as the victim of a deadlock (§5.2).
    Deadlock,
    /// Its heartbeat expired (`txn.liveness_timeout`): idle client or dead coordinator (§7).
    TimeoutPushed,
    /// It exceeded its maximum duration (`txn.max_duration`, `RGN-2003`).
    MaxDuration,
    /// Its write set exceeded the limits (`RGN-2004`).
    TooLarge,
}

impl AbortReason {
    /// The stable `reason` string of `RGN-2002` (transactions.md §4).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rollback => "rollback",
            Self::Conflict => "conflict",
            Self::Deadlock => "deadlock",
            Self::TimeoutPushed => "timeout_pushed",
            Self::MaxDuration => "max_duration",
            Self::TooLarge => "too_large",
        }
    }

    /// Whether restarting the whole transaction may succeed (transactions.md §4: retry if
    /// `reason ∈ {conflict, deadlock, coordinator_lost, timeout_pushed}`).
    #[must_use]
    pub fn retryable(self) -> bool {
        matches!(self, Self::Conflict | Self::Deadlock | Self::TimeoutPushed)
    }
}

impl std::fmt::Display for AbortReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors of transaction operations.
#[derive(Debug, thiserror::Error)]
pub enum TxnError {
    /// A serialization conflict (failed read refresh, SNAPSHOT first-committer-wins, an
    /// unresolvable intent): the transaction must restart (`RGN-2001`, retryable). The
    /// transaction keeps its intents and accepts only [`crate::Txn::restart`] or
    /// [`crate::Txn::rollback`].
    #[error("transaction conflict: {0}")]
    Conflict(String),
    /// The transaction is aborted (`RGN-2002`); every further operation fails the same way.
    #[error("transaction aborted: {reason}")]
    Aborted {
        /// Why it was aborted.
        reason: AbortReason,
    },
    /// The transaction exceeded its maximum duration and was aborted (`RGN-2003`).
    #[error("transaction exceeded its maximum duration of {limit:?}")]
    Timeout {
        /// The limit that applied.
        limit: Duration,
    },
    /// The transaction's write set exceeded a limit and it was aborted (`RGN-2004`).
    #[error("transaction too large: {what} limit of {limit} exceeded")]
    TooLarge {
        /// `"keys"` or `"bytes"`.
        what: &'static str,
        /// The limit.
        limit: u64,
    },
    /// The transaction was the victim of a deadlock and was aborted (`RGN-2005`).
    #[error("deadlock detected")]
    Deadlock,
    /// The commit proposal failed after it may have been logged: the outcome is decided by the
    /// log (it applies on the next replay iff it was logged) (`RGN-2006`).
    #[error("commit outcome unknown: {0}")]
    CommitOutcomeUnknown(#[source] ReplicaError),
    /// A READ COMMITTED statement was re-evaluated too often (`RGN-2008`).
    #[error("statement re-evaluated {retries} times without success")]
    WriteTooOld {
        /// Re-evaluations performed.
        retries: u32,
    },
    /// The caller violated the API contract (unknown savepoint, write in a read-only
    /// transaction, use after commit).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// An internal invariant does not hold (a bug or corrupt data).
    #[error("internal error: {0}")]
    Internal(String),
    /// Closing a timestamp ([`crate::TxnCoordinator::close_timestamp`], PD-063) did not finish
    /// before its deadline: a transaction with writes at or below it was still running
    /// (`RGN-5006`). Nothing changed except the raised timestamp-cache low-water mark.
    #[error(
        "closing timestamp {ts} timed out after {waited:?}: {blockers} writing transaction(s) at or below it still running"
    )]
    CloseTimedOut {
        /// The timestamp being closed.
        ts: rustegon_mvcc::Timestamp,
        /// How long the caller waited.
        waited: Duration,
        /// Transactions still blocking it.
        blockers: usize,
    },
    /// The caller cancelled the operation (`RGN-5005`).
    #[error("cancelled")]
    Cancelled,
    /// An MVCC error (e.g. `RGN-2007` below the GC threshold, corruption, storage).
    #[error(transparent)]
    Mvcc(#[from] MvccError),
    /// A replica error outside commit (the operation had no effect, or its intent is cleaned up
    /// with the transaction).
    #[error(transparent)]
    Replica(#[from] ReplicaError),
}

impl TxnError {
    /// The catalog code the error maps to.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Conflict(_) => ErrorCode::TransactionConflict,
            Self::Aborted { .. } => ErrorCode::TransactionAborted,
            Self::Timeout { .. } => ErrorCode::TransactionTimeout,
            Self::TooLarge { .. } => ErrorCode::TransactionTooLarge,
            Self::Deadlock => ErrorCode::DeadlockDetected,
            Self::CommitOutcomeUnknown(_) => ErrorCode::CommitOutcomeUnknown,
            Self::WriteTooOld { .. } => ErrorCode::WriteTooOld,
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::Internal(_) => ErrorCode::Internal,
            Self::CloseTimedOut { .. } => ErrorCode::DeadlineExceeded,
            Self::Cancelled => ErrorCode::Cancelled,
            Self::Mvcc(e) => e.code(),
            Self::Replica(e) => e.code(),
        }
    }

    /// Whether restarting the transaction may succeed (transactions.md §4).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Aborted { reason } => reason.retryable(),
            // Special: resolve through TxnStatus, never re-run blindly (transactions.md §5).
            Self::CommitOutcomeUnknown(_) => false,
            other => matches!(other.code().retryable(), Retryable::Yes),
        }
    }
}

impl From<TxnError> for Error {
    fn from(err: TxnError) -> Self {
        let retryable = err.is_retryable();
        let code = err.code();
        let reason = match &err {
            TxnError::Aborted { reason } => Some(reason.as_str()),
            _ => None,
        };
        let mut out = Error::new(code, err.to_string()).with_retryable(retryable);
        if let Some(reason) = reason {
            out = out.with_detail("reason", reason);
        }
        out.with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txn_errors_map_to_catalog_codes_and_retry_classes() {
        let cases: [(TxnError, u16, bool); 7] = [
            (TxnError::Conflict("x".into()), 2001, true),
            (
                TxnError::Aborted {
                    reason: AbortReason::Deadlock,
                },
                2002,
                true,
            ),
            (
                TxnError::Aborted {
                    reason: AbortReason::Rollback,
                },
                2002,
                false,
            ),
            (
                TxnError::Timeout {
                    limit: Duration::from_secs(1),
                },
                2003,
                false,
            ),
            (
                TxnError::TooLarge {
                    what: "keys",
                    limit: 1,
                },
                2004,
                false,
            ),
            (TxnError::Deadlock, 2005, true),
            (TxnError::WriteTooOld { retries: 3 }, 2008, true),
        ];
        for (err, code, retryable) in cases {
            assert_eq!(err.code().code(), code, "{err}");
            assert_eq!(err.is_retryable(), retryable, "{err}");
            let common: Error = err.into();
            assert_eq!(common.code().code(), code);
            assert_eq!(common.retryable(), retryable);
        }
    }

    #[test]
    fn aborted_error_carries_reason_detail() {
        let e: Error = TxnError::Aborted {
            reason: AbortReason::TimeoutPushed,
        }
        .into();
        assert_eq!(
            e.details().get("reason").map(String::as_str),
            Some("timeout_pushed")
        );
    }
}
