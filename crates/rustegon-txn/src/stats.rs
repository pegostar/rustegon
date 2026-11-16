// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transaction outcome counters of one coordinator, exported by the server at `/metrics` as the
//! mandatory families `rustegon_txn_commits_total`, `rustegon_txn_aborts_total{reason}` and
//! `rustegon_txn_restarts_total{reason}` (system-overview.md §7; PD-059).
//!
//! Every transaction of the coordinator is counted once when it ends: committed (read-only
//! ones included) or aborted with its final [`AbortReason`] (client rollbacks and dropped
//! transactions are `rollback`). A restart is counted when an operation leaves the transaction
//! needing a restart (a refresh failure at commit or a SNAPSHOT write-write conflict); the
//! retry loop of [`crate::TxnCoordinator::run`] then restarts it.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::AbortReason;

/// Every abort reason, in the order of [`TxnStatsSnapshot::aborts`].
pub const ABORT_REASONS: [AbortReason; 6] = [
    AbortReason::Rollback,
    AbortReason::Conflict,
    AbortReason::Deadlock,
    AbortReason::TimeoutPushed,
    AbortReason::MaxDuration,
    AbortReason::TooLarge,
];

/// Why a transaction had to restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartReason {
    /// The commit-time read refresh found a newer write (transaction-management.md §10).
    Refresh,
    /// A SNAPSHOT write met a newer committed version of the key.
    WriteConflict,
}

impl RestartReason {
    /// Every reason, in the order of [`TxnStatsSnapshot::restarts`].
    pub const ALL: [Self; 2] = [Self::Refresh, Self::WriteConflict];

    /// The `reason` label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refresh => "refresh",
            Self::WriteConflict => "write_conflict",
        }
    }
}

/// Live counters (module docs). `Relaxed`: independent statistics, read only for reporting.
#[derive(Debug, Default)]
pub(crate) struct TxnStats {
    commits: AtomicU64,
    aborts: [AtomicU64; ABORT_REASONS.len()],
    restarts: [AtomicU64; RestartReason::ALL.len()],
}

impl TxnStats {
    pub(crate) fn committed(&self) {
        self.commits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn aborted(&self, reason: AbortReason) {
        if let Some(i) = ABORT_REASONS.iter().position(|r| *r == reason) {
            self.aborts[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn restarted(&self, reason: RestartReason) {
        if let Some(i) = RestartReason::ALL.iter().position(|r| *r == reason) {
            self.restarts[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn snapshot(&self) -> TxnStatsSnapshot {
        TxnStatsSnapshot {
            commits: self.commits.load(Ordering::Relaxed),
            aborts: std::array::from_fn(|i| self.aborts[i].load(Ordering::Relaxed)),
            restarts: std::array::from_fn(|i| self.restarts[i].load(Ordering::Relaxed)),
        }
    }
}

/// Point-in-time copy of the counters ([`crate::TxnCoordinator::stats`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxnStatsSnapshot {
    /// Committed transactions.
    pub commits: u64,
    /// Aborted transactions per reason, indexed like [`ABORT_REASONS`].
    pub aborts: [u64; ABORT_REASONS.len()],
    /// Restarts per reason, indexed like [`RestartReason::ALL`].
    pub restarts: [u64; RestartReason::ALL.len()],
}

impl TxnStatsSnapshot {
    /// `(reason, count)` of every abort reason.
    pub fn aborts_by_reason(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        ABORT_REASONS
            .iter()
            .zip(self.aborts)
            .map(|(r, n)| (r.as_str(), n))
    }

    /// `(reason, count)` of every restart reason.
    pub fn restarts_by_reason(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        RestartReason::ALL
            .iter()
            .zip(self.restarts)
            .map(|(r, n)| (r.as_str(), n))
    }
}
