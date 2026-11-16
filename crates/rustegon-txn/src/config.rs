// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Coordinator configuration (transaction-management.md §9) and per-transaction options
//! (specifications/transactions.md §2).

use std::time::Duration;

/// `txn.liveness_timeout`: a transaction whose coordinator has not heartbeated for this long is
/// abortable by anyone who meets one of its intents (§9).
pub const DEFAULT_LIVENESS_TIMEOUT: Duration = Duration::from_secs(5);
/// `txn.heartbeat_interval`: how often a live transaction refreshes the heartbeat persisted in
/// its record (§9).
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
/// `txn.max_duration`: hard cap on a transaction's lifetime (§9, `RGN-2003`).
pub const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(60);
/// `txn.max_write_bytes`: 64 MiB of written keys and values (§9, `RGN-2004`).
pub const DEFAULT_MAX_WRITE_BYTES: u64 = 64 << 20;
/// `txn.max_write_keys`: distinct keys written (§9, `RGN-2004`).
pub const DEFAULT_MAX_WRITE_KEYS: u64 = 100_000;
/// `txn.max_refresh_spans_bytes`: 4 MiB of tracked read spans; above, they are condensed (§9).
pub const DEFAULT_MAX_REFRESH_SPANS_BYTES: usize = 4 << 20;
/// Entries the range's timestamp cache keeps before it evicts the oldest half into its
/// low-water mark (memory bound; eviction only causes extra pushes, never anomalies).
pub const DEFAULT_TS_CACHE_CAPACITY: usize = 100_000;
/// How long a waiter sleeps between re-evaluating its push decision and the deadlock check;
/// bounds the detection latency far below the 1 s of FR-TXN-008 (§5.2 runs the local detector
/// every 100 ms).
pub const DEFAULT_WAIT_SLICE: Duration = Duration::from_millis(2);
/// Re-evaluations of one READ COMMITTED statement before `RGN-2008` (transactions.md §4).
pub const DEFAULT_RC_STATEMENT_RETRIES: u32 = 100;

/// Coordinator settings (transaction-management.md §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnConfig {
    /// `txn.liveness_timeout`.
    pub liveness_timeout: Duration,
    /// `txn.heartbeat_interval`.
    pub heartbeat_interval: Duration,
    /// `txn.max_duration` (server maximum; a transaction's own timeout may be shorter).
    pub max_duration: Duration,
    /// `txn.max_write_bytes`.
    pub max_write_bytes: u64,
    /// `txn.max_write_keys`.
    pub max_write_keys: u64,
    /// `txn.max_refresh_spans_bytes`.
    pub max_refresh_spans_bytes: usize,
    /// Timestamp cache capacity in entries.
    pub ts_cache_capacity: usize,
    /// Wait-loop slice.
    pub wait_slice: Duration,
    /// READ COMMITTED statement re-evaluations before `RGN-2008`.
    pub rc_statement_retries: u32,
}

impl Default for TxnConfig {
    fn default() -> Self {
        Self {
            liveness_timeout: DEFAULT_LIVENESS_TIMEOUT,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            max_duration: DEFAULT_MAX_DURATION,
            max_write_bytes: DEFAULT_MAX_WRITE_BYTES,
            max_write_keys: DEFAULT_MAX_WRITE_KEYS,
            max_refresh_spans_bytes: DEFAULT_MAX_REFRESH_SPANS_BYTES,
            ts_cache_capacity: DEFAULT_TS_CACHE_CAPACITY,
            wait_slice: DEFAULT_WAIT_SLICE,
            rc_statement_retries: DEFAULT_RC_STATEMENT_RETRIES,
        }
    }
}

/// Isolation level (transaction-management.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Isolation {
    /// Serializable: read refresh at commit when the write timestamp moved (default).
    #[default]
    Serializable,
    /// Snapshot isolation: first-committer-wins; write skew possible.
    Snapshot,
    /// Read committed: a fresh read timestamp per statement; statement re-evaluation on
    /// write-write conflicts.
    ReadCommitted,
}

/// User priority class (transaction-management.md §5.1: `HIGH > NORMAL > LOW`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub enum Priority {
    /// Low priority.
    Low,
    /// Normal priority (default).
    #[default]
    Normal,
    /// High priority.
    High,
}

impl Priority {
    /// Bit position of the class in the numeric priority: the class dominates every restart
    /// bump (§5.3 puts the restart count at bit 24 and random bits below it).
    const CLASS_SHIFT: u32 = 30;

    /// The numeric priority of a fresh transaction of this class.
    #[must_use]
    pub fn base(self) -> u32 {
        let class: u32 = match self {
            Self::Low => 1,
            Self::Normal => 2,
            Self::High => 3,
        };
        class << Self::CLASS_SHIFT
    }
}

/// Whether a transaction may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AccessMode {
    /// Reads and writes (default).
    #[default]
    ReadWrite,
    /// Reads only; writes fail with `RGN-1001`.
    ReadOnly,
}

/// Options of one transaction (transactions.md §2, the subset served by a single range).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxnOptions {
    /// Isolation level.
    pub isolation: Isolation,
    /// Priority class.
    pub priority: Priority,
    /// Read-only or read-write.
    pub access: AccessMode,
    /// The transaction's own timeout (`timeout_ms`); capped by `txn.max_duration`.
    pub timeout: Option<Duration>,
}

impl TxnOptions {
    /// Default options with `isolation`.
    #[must_use]
    pub fn with_isolation(isolation: Isolation) -> Self {
        Self {
            isolation,
            ..Self::default()
        }
    }
}
