// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The replica contract of a range (replication.md §3, "Command format v1"; FR-TXN-001,
//! TC-TXN-004): the transaction layer evaluates requests into an MVCC write batch, proposes it
//! as a [`ReplicaCommand`] and reads through the replica's engine. The M2 single-voter
//! `LocalReplica` (`rustegon-cluster`) and the M5 Raft replica implement the same trait, so the
//! transaction layer does not change when replication arrives.
//!
//! Placement: the trait lives here, below `rustegon-cluster` (which implements it) and
//! `rustegon-txn` (which uses it), because it is expressed in MVCC terms (writer, reader, GC
//! threshold, `RangeAppliedState`) and the crate graph (repository-structure.md) lets both
//! depend on `rustegon-mvcc` while `rustegon-raft` stays a pure log/consensus crate.
//!
//! **Synchronous by design.** [`Replica::propose`] blocks the calling thread until the command
//! is durable and applied, like the engine and the log store it drives (all synchronous over the
//! `rustegon-sim-api` file system). Callers in an async context run it on the I/O pool
//! (coding-standards.md §3.3 "no blocking in async"); deterministic simulation drives it
//! directly. A Raft implementation blocks the same way until its entry is committed and applied.
//!
//! **Apply path** ([`apply_command`]): the command's operations and the new
//! [`RangeAppliedState`] go to the engine in one atomic batch — the invariant that makes log
//! replay after a crash exact (storage-engine.md §9).

mod applied;
mod codec;
mod command;

use bytes::Bytes;
use rustegon_common::{Error, ErrorCode};
use rustegon_storage::{LsmEngine, SeqNo};

pub use self::{
    applied::{
        APPLIED_STATE_ENCODED_LEN, APPLIED_STATE_FORMAT_VERSION, APPLIED_STATE_TAG,
        LOCAL_RANGE_ID_MARKER, RangeAppliedState,
    },
    command::{COMMAND_FORMAT_VERSION, ReplicaCommand},
};
use crate::{
    error::{MvccError, Result},
    gc::GcThreshold,
    read::{MvccReader, ReadOptions},
    write::MvccWriter,
};

/// Errors of a replica operation.
#[derive(Debug, thiserror::Error)]
pub enum ReplicaError {
    /// An MVCC or storage error (including corrupt commands or applied state).
    #[error(transparent)]
    Mvcc(#[from] MvccError),
    /// An error of the replicated log (the implementation converts it at this boundary).
    #[error("replica log: {0}")]
    Log(#[source] Error),
    /// A command was logged but could not be applied: the engine and the log may disagree until
    /// the replica is reopened, whose replay applies the logged command again.
    #[error("range {range_id}: replica unusable after a failed apply; reopen it")]
    Poisoned {
        /// Range of the replica.
        range_id: u64,
    },
}

impl ReplicaError {
    /// The catalog code the error maps to.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Mvcc(e) => e.code(),
            Self::Log(e) => e.code(),
            Self::Poisoned { .. } => ErrorCode::Internal,
        }
    }
}

impl From<ReplicaError> for Error {
    fn from(err: ReplicaError) -> Self {
        match err {
            ReplicaError::Mvcc(e) => e.into(),
            ReplicaError::Log(e) => e,
            other @ ReplicaError::Poisoned { .. } => {
                Error::new(other.code(), other.to_string()).with_source(other)
            }
        }
    }
}

/// A range's replica as seen by the transaction layer (module docs).
///
/// Concurrency: implementations are `Sync`; proposals are serialised internally in log order.
/// Evaluation ([`Replica::writer`]) happens outside, under the key latches of the concurrency
/// manager, so the state a batch was evaluated against cannot change before it applies.
pub trait Replica: Send + Sync {
    /// The range this replica serves.
    fn range_id(&self) -> u64;

    /// The engine holding the range's data (shared by all ranges of the store).
    fn engine(&self) -> &LsmEngine;

    /// The store's MVCC GC threshold, if GC is enabled.
    fn gc_threshold(&self) -> Option<&GcThreshold>;

    /// Proposes `cmd` and blocks until it is committed (durable in the log) and applied to the
    /// engine together with the new applied state; returns that state. `Ok` is the
    /// acknowledgement: the command then survives any crash. On `Err` the command may or may not
    /// have been logged; if it was, it is applied at the latest by the replay of the next open
    /// (never partially).
    ///
    /// # Errors
    /// [`MvccError::InvalidArgument`] for a command that cannot be logged (nothing happened);
    /// [`ReplicaError::Log`] for log failures; storage errors; [`ReplicaError::Poisoned`] once
    /// an apply failed (every later proposal fails until reopened).
    fn propose(&self, cmd: ReplicaCommand) -> Result<RangeAppliedState, ReplicaError>;

    /// The applied state of the last applied command (in memory, equal to the persisted one).
    fn applied_state(&self) -> RangeAppliedState;

    /// Index of the last applied log entry.
    fn applied_index(&self) -> u64 {
        self.applied_state().applied_index
    }

    /// A writer that evaluates a batch against the current engine state (to be proposed).
    fn writer(&self) -> MvccWriter<'_> {
        MvccWriter::new(self.engine(), self.gc_threshold())
    }

    /// A reader of the replica's data. Each read pins an engine snapshot first, so it sees
    /// every command applied before it started and no part of any later one.
    fn reader(&self) -> MvccReader<'_> {
        MvccReader::new(self.engine(), self.gc_threshold())
    }

    /// The value of logical key `key` at `opts.read_ts` (see [`MvccReader::get`]).
    ///
    /// # Errors
    /// As [`MvccReader::get`].
    fn get(&self, key: &[u8], opts: &ReadOptions<'_>) -> Result<Option<Bytes>> {
        self.reader().get(key, opts)
    }
}

/// Reads the persisted applied state of `range_id` (the initial state when absent).
///
/// # Errors
/// Storage errors; [`MvccError::Corruption`] for an undecodable value or one of another range.
pub fn read_applied_state(engine: &LsmEngine, range_id: u64) -> Result<RangeAppliedState> {
    match engine.get(&RangeAppliedState::engine_key(range_id), None)? {
        None => Ok(RangeAppliedState::initial(range_id)),
        Some(bytes) => {
            let state = RangeAppliedState::decode(&bytes)?;
            if state.range_id != range_id {
                return Err(MvccError::Corruption(format!(
                    "applied state of range {range_id} names range {}",
                    state.range_id
                )));
            }
            Ok(state)
        }
    }
}

/// The apply path shared by every [`Replica`] implementation: applies committed entry
/// `(index, term)` holding `cmd` on top of `state`. The command's operations and the advanced
/// [`RangeAppliedState`] are written in **one** engine batch, so a crash keeps both or neither
/// (module docs). Returns the new state and the batch's last engine seqno (the caller keeps the
/// log entry until the engine's `flushed_seqno` reaches it).
///
/// # Errors
/// [`MvccError::InvalidArgument`] if `index` does not directly follow `state` (nothing is
/// written); storage errors (nothing is applied then).
pub fn apply_command(
    engine: &LsmEngine,
    state: &RangeAppliedState,
    index: u64,
    term: u64,
    cmd: ReplicaCommand,
) -> Result<(RangeAppliedState, SeqNo)> {
    let next = state.advance(index, term, cmd.ts)?;
    let mut batch = cmd.batch;
    // Last in the batch: no command operation can overwrite it (the key is range-local).
    batch.put(&RangeAppliedState::engine_key(next.range_id), next.encode());
    let seqno = engine.write(&batch)?;
    Ok((next, seqno))
}
