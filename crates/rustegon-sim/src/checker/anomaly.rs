// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Anomaly vocabulary and the consistency models that forbid each anomaly.
//!
//! Names follow Adya's thesis (1999) as used by Elle: G0 (dirty write: cycle of write-write
//! dependencies), G1a (aborted read), G1b (intermediate read), G1c (circular information flow:
//! cycle of ww/wr dependencies), G-single (cycle with exactly one anti-dependency: read skew,
//! non-repeatable read, lost update) and G2-item (cycle with two or more anti-dependencies:
//! write skew). `*-realtime` variants are cycles that need at least one real-time edge and
//! are therefore only violations of strict serializability.

use super::history::{Key, TxnId, Value};

/// Kind of a dependency edge between two transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Write-write: `from` installed a version of a key, `to` installed a later one.
    Ww,
    /// Write-read: `to` read a version `from` installed.
    Wr,
    /// Read-write (anti-dependency): `from` read a version, `to` installed a later one.
    Rw,
    /// Real time: `from` completed before `to` started.
    Rt,
}

/// One edge of an explaining cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CycleStep {
    /// Source transaction.
    pub from: TxnId,
    /// Target transaction.
    pub to: TxnId,
    /// Why `from` must precede `to`.
    pub edge: EdgeKind,
}

/// Fieldless classification of an [`Anomaly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AnomalyKind {
    /// Cycle of ww edges only.
    G0,
    /// A committed transaction read a value written by an aborted one.
    G1a,
    /// A committed transaction read a non-final value of another transaction.
    G1b,
    /// Cycle of ww/wr edges with at least one wr.
    G1c,
    /// Cycle with exactly one rw edge.
    GSingle,
    /// Cycle with two or more rw edges.
    G2Item,
    /// [`Self::G0`] that needs a real-time edge.
    G0Realtime,
    /// [`Self::G1c`] that needs a real-time edge.
    G1cRealtime,
    /// [`Self::GSingle`] that needs a real-time edge.
    GSingleRealtime,
    /// [`Self::G2Item`] that needs a real-time edge.
    G2ItemRealtime,
    /// Two committed transactions read the same version of a key and both overwrote it.
    LostUpdate,
    /// A transaction read a key twice and saw different versions not caused by itself.
    NonRepeatableRead,
    /// A transaction did not observe its own prior writes.
    Internal,
    /// Two reads of one list are not prefixes of each other.
    IncompatibleOrder,
    /// A list read contains the same element twice.
    DuplicateElements,
    /// The same value was written to a key twice (generator bug, history unusable).
    DuplicateWrite,
    /// A read returned a value nobody wrote.
    GarbageRead,
}

impl AnomalyKind {
    /// Returns `true` for the dependency-cycle kinds.
    #[must_use]
    pub fn is_cycle(self) -> bool {
        matches!(
            self,
            Self::G0
                | Self::G1c
                | Self::GSingle
                | Self::G2Item
                | Self::G0Realtime
                | Self::G1cRealtime
                | Self::GSingleRealtime
                | Self::G2ItemRealtime
        )
    }
}

/// One detected anomaly with the evidence that explains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anomaly {
    /// A dependency cycle; `steps` is closed (`steps.last().to == steps[0].from`) and is the
    /// shortest cycle of its kind the search found in its strongly connected component.
    Cycle {
        /// One of the cycle kinds ([`AnomalyKind::is_cycle`]).
        kind: AnomalyKind,
        /// The edges of the cycle, in order.
        steps: Vec<CycleStep>,
    },
    /// G1a.
    AbortedRead {
        /// Key read.
        key: Key,
        /// Value written by the aborted transaction.
        value: Value,
        /// Committed reader.
        reader: TxnId,
        /// Aborted writer.
        writer: TxnId,
    },
    /// G1b.
    IntermediateRead {
        /// Key read.
        key: Key,
        /// Intermediate value observed.
        value: Value,
        /// Committed reader.
        reader: TxnId,
        /// Writer that later overwrote `value` within the same transaction.
        writer: TxnId,
    },
    /// Lost update.
    LostUpdate {
        /// Key involved.
        key: Key,
        /// The committed transactions that read the same version and all wrote the key.
        txns: Vec<TxnId>,
    },
    /// Non-repeatable read within one transaction.
    NonRepeatableRead {
        /// Key read twice.
        key: Key,
        /// The reading transaction.
        txn: TxnId,
    },
    /// Internal inconsistency.
    Internal {
        /// Key involved.
        key: Key,
        /// The inconsistent transaction.
        txn: TxnId,
        /// Human-readable description of the expectation that failed.
        detail: String,
    },
    /// Incompatible version orders.
    IncompatibleOrder {
        /// List key.
        key: Key,
        /// The reference (longest) read.
        left: Vec<Value>,
        /// A read that is not a prefix of `left`.
        right: Vec<Value>,
    },
    /// Duplicate list elements.
    DuplicateElements {
        /// List key.
        key: Key,
        /// Reading transaction.
        txn: TxnId,
        /// The repeated element.
        value: Value,
    },
    /// Duplicate write of the same value.
    DuplicateWrite {
        /// Key written.
        key: Key,
        /// Value written twice.
        value: Value,
        /// The two writers (equal if one transaction wrote it twice).
        txns: [TxnId; 2],
    },
    /// Read of a value nobody wrote.
    GarbageRead {
        /// Key read.
        key: Key,
        /// Unknown value.
        value: Value,
        /// Reading transaction.
        reader: TxnId,
    },
}

impl Anomaly {
    /// Returns the classification of this anomaly.
    #[must_use]
    pub fn kind(&self) -> AnomalyKind {
        match self {
            Self::Cycle { kind, .. } => *kind,
            Self::AbortedRead { .. } => AnomalyKind::G1a,
            Self::IntermediateRead { .. } => AnomalyKind::G1b,
            Self::LostUpdate { .. } => AnomalyKind::LostUpdate,
            Self::NonRepeatableRead { .. } => AnomalyKind::NonRepeatableRead,
            Self::Internal { .. } => AnomalyKind::Internal,
            Self::IncompatibleOrder { .. } => AnomalyKind::IncompatibleOrder,
            Self::DuplicateElements { .. } => AnomalyKind::DuplicateElements,
            Self::DuplicateWrite { .. } => AnomalyKind::DuplicateWrite,
            Self::GarbageRead { .. } => AnomalyKind::GarbageRead,
        }
    }
}

/// Consistency model a history is checked against (transaction-management.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsistencyModel {
    /// READ COMMITTED: forbids G0, G1a, G1b, G1c.
    ReadCommitted,
    /// SNAPSHOT: additionally forbids G-single (read skew, non-repeatable read), lost update.
    Snapshot,
    /// SERIALIZABLE: additionally forbids G2-item (write skew).
    Serializable,
    /// Strict serializability: additionally forbids every cycle through real-time edges.
    StrictSerializable,
}

impl ConsistencyModel {
    /// All models, weakest first.
    pub const ALL: [Self; 4] = [
        Self::ReadCommitted,
        Self::Snapshot,
        Self::Serializable,
        Self::StrictSerializable,
    ];

    /// Returns `true` if a history exhibiting `kind` violates this model.
    ///
    /// Matrix of transaction-management.md §4.2. Two deliberate choices:
    /// - Lost update is forbidden from SNAPSHOT up only. The §4.2 claim that READ COMMITTED
    ///   prevents it refers to statement re-evaluation of read-modify-write statements; the
    ///   workloads here issue blind appends/writes after a separate read, which READ COMMITTED
    ///   legitimately orders after a concurrent writer.
    /// - The integrity kinds (internal, incompatible order, duplicates, garbage) mean the
    ///   database (or the history) is broken; every model forbids them.
    #[must_use]
    pub fn forbids(self, kind: AnomalyKind) -> bool {
        use AnomalyKind as K;
        match kind {
            K::G0
            | K::G1a
            | K::G1b
            | K::G1c
            | K::Internal
            | K::IncompatibleOrder
            | K::DuplicateElements
            | K::DuplicateWrite
            | K::GarbageRead => true,
            K::GSingle | K::LostUpdate | K::NonRepeatableRead => self != Self::ReadCommitted,
            K::G2Item => matches!(self, Self::Serializable | Self::StrictSerializable),
            K::G0Realtime | K::G1cRealtime | K::GSingleRealtime | K::G2ItemRealtime => {
                self == Self::StrictSerializable
            }
        }
    }

    /// Returns `true` if checking this model needs real-time edges.
    #[must_use]
    pub fn uses_real_time(self) -> bool {
        self == Self::StrictSerializable
    }
}
