// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Recorded transaction histories: the input of the checker.
//!
//! A history is the client-side view of a workload run: every transaction a client issued,
//! the operations it performed with the results it observed, and how it ended. Two workloads
//! from Elle (Kingsbury & Alvaro 2020, §4) are supported and may share one history:
//! - **list-append**: [`Op::Append`] / [`Op::ReadList`]. Every key holds a list; appends add a
//!   unique element at its end, reads return the whole list. Because a read reveals the full
//!   prefix of the key's version order, dependencies can be inferred precisely.
//! - **rw-register**: [`Op::Write`] / [`Op::ReadRegister`]. Every key holds one value; writes
//!   store a unique value. A read reveals only the latest value, so far less can be inferred.
//!
//! The two workloads use separate key spaces: list key 1 and register key 1 are different
//! objects. Within a workload, every written value must be unique per key (the generator's
//! duty); a duplicate is reported as [`super::Anomaly::DuplicateWrite`].

use std::{collections::HashSet, fmt};

/// Client-assigned transaction identifier, unique within a history.
pub type TxnId = u64;
/// Key of a list (list-append) or register (rw-register).
pub type Key = u64;
/// Element appended to a list or value written to a register.
pub type Value = u64;

/// How a transaction ended, as observed by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Committed: the client received a commit acknowledgement.
    Ok,
    /// Definitely aborted: none of its writes may ever become visible.
    Fail,
    /// Indeterminate (timeout, lost connection): it may or may not have committed. Its read
    /// results are unknown and ignored; its writes count as committed once a committed
    /// transaction observes one of them.
    Info,
}

/// Result of a register read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterRead {
    /// The result is unknown (the transaction did not complete); the read is ignored.
    Unknown,
    /// The register held its initial state: no value has ever been written.
    Nil,
    /// The register held this value.
    Value(Value),
}

/// One operation of a transaction, in program order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// list-append: append `value` to the list stored at `key`.
    Append {
        /// List key.
        key: Key,
        /// Appended element (unique per key across the history).
        value: Value,
    },
    /// list-append: read the whole list stored at `key`.
    ReadList {
        /// List key.
        key: Key,
        /// Observed list (oldest element first); `None` when the result is unknown.
        value: Option<Vec<Value>>,
    },
    /// rw-register: overwrite the register at `key` with `value`.
    Write {
        /// Register key.
        key: Key,
        /// Written value (unique per key across the history).
        value: Value,
    },
    /// rw-register: read the register at `key`.
    ReadRegister {
        /// Register key.
        key: Key,
        /// Observed value.
        value: RegisterRead,
    },
}

impl Op {
    /// Shorthand for [`Op::Append`].
    #[must_use]
    pub fn append(key: Key, value: Value) -> Self {
        Self::Append { key, value }
    }

    /// Shorthand for an [`Op::ReadList`] with a known result.
    #[must_use]
    pub fn read_list(key: Key, value: &[Value]) -> Self {
        Self::ReadList {
            key,
            value: Some(value.to_vec()),
        }
    }

    /// Shorthand for [`Op::Write`].
    #[must_use]
    pub fn write(key: Key, value: Value) -> Self {
        Self::Write { key, value }
    }

    /// Shorthand for an [`Op::ReadRegister`] with a known result (`None` = initial nil).
    #[must_use]
    pub fn read_register(key: Key, value: Option<Value>) -> Self {
        let value = value.map_or(RegisterRead::Nil, RegisterRead::Value);
        Self::ReadRegister { key, value }
    }
}

/// Real-time interval of a transaction on a single global clock (any unit), used for
/// strict-serializability checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealTime {
    /// When the client invoked the transaction (before its first operation was sent).
    pub start: u64,
    /// When the client received the outcome; `None` if it never did. Ignored for
    /// [`Outcome::Info`] transactions, which may take effect at any later time.
    pub end: Option<u64>,
}

/// One transaction of a history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Txn {
    /// Unique identifier, used in anomaly reports.
    pub id: TxnId,
    /// How the transaction ended.
    pub outcome: Outcome,
    /// Operations in program order, with their observed results.
    pub ops: Vec<Op>,
    /// Real-time interval, if recorded.
    pub time: Option<RealTime>,
}

impl Txn {
    /// Creates a transaction without real-time information.
    #[must_use]
    pub fn new(id: TxnId, outcome: Outcome, ops: Vec<Op>) -> Self {
        Self {
            id,
            outcome,
            ops,
            time: None,
        }
    }

    /// Sets the real-time interval `[start, end]`.
    #[must_use]
    pub fn with_time(mut self, start: u64, end: Option<u64>) -> Self {
        self.time = Some(RealTime { start, end });
        self
    }
}

/// A complete recorded history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    /// All transactions, in any order.
    pub txns: Vec<Txn>,
}

impl History {
    /// Creates a history from its transactions.
    #[must_use]
    pub fn new(txns: Vec<Txn>) -> Self {
        Self { txns }
    }

    /// Checks the structural well-formedness the analysis relies on.
    ///
    /// # Errors
    /// [`HistoryError`] if two transactions share an id or an interval ends before it starts.
    pub fn validate(&self) -> Result<(), HistoryError> {
        let mut ids = HashSet::with_capacity(self.txns.len());
        for txn in &self.txns {
            if !ids.insert(txn.id) {
                return Err(HistoryError::DuplicateTxnId(txn.id));
            }
            if let Some(RealTime {
                start,
                end: Some(end),
            }) = txn.time
                && end < start
            {
                return Err(HistoryError::InvalidInterval(txn.id));
            }
        }
        Ok(())
    }
}

/// A history the checker cannot analyse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryError {
    /// Two transactions have the same id.
    DuplicateTxnId(TxnId),
    /// The transaction's real-time interval ends before it starts.
    InvalidInterval(TxnId),
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateTxnId(id) => write!(f, "duplicate transaction id {id}"),
            Self::InvalidInterval(id) => write!(f, "transaction {id} ends before it starts"),
        }
    }
}

impl std::error::Error for HistoryError {}
