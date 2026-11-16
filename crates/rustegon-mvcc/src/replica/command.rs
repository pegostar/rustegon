// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Replicated command and its log encoding, format v1 (replication.md "Command format v1";
//! persisted in the Raft log, so it changes only per implementation-rules.md §6).
//!
//! A command is an **evaluated** write batch (replication.md §3: the proposal is the batch, not
//! the request), so every replica — and every replay after a crash — applies exactly the same
//! storage operations, with no re-evaluation and no dependence on the state it is applied to.
//!
//! Layout (all integers big endian, `bytes` = `len u32 ‖ bytes`):
//! `version u8 (= 1) ‖ ts (wall u64 ‖ logical u32) ‖ op_count u32 ‖ op*`, op = `tag u8 ‖ …`:
//! 1 Put `key bytes ‖ value bytes`; 2 Delete `key bytes`; 3 `SingleDelete` `key bytes`;
//! 4 Merge `key bytes ‖ operand bytes`; 5 `DeleteRange` `start bytes ‖ end bytes` (`start < end`).

use bytes::Bytes;
use rustegon_storage::{BatchOp, WriteBatch};

use super::codec::{Reader, put_bytes, put_u32, put_u64};
use crate::{
    error::{MvccError, Result},
    hlc::Timestamp,
};

/// Format version of the command encoding.
pub const COMMAND_FORMAT_VERSION: u8 = 1;

/// Op tags of format v1.
const TAG_PUT: u8 = 1;
const TAG_DELETE: u8 = 2;
const TAG_SINGLE_DELETE: u8 = 3;
const TAG_MERGE: u8 = 4;
const TAG_DELETE_RANGE: u8 = 5;
/// Smallest encoded op: tag + one empty `bytes`.
const MIN_OP_LEN: usize = 1 + 4;

/// A command proposed to a range's replica: the storage batch produced by
/// [`MvccWriter`](crate::MvccWriter) plus metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicaCommand {
    /// HLC timestamp at which the leaseholder evaluated the batch. Applying a command tracks the
    /// largest one in [`RangeAppliedState::max_ts`](super::RangeAppliedState::max_ts) (the
    /// replica's time lag, replication.md §7); it does not order application (the log does).
    pub ts: Timestamp,
    /// The storage operations, applied atomically together with the range's applied state.
    pub batch: WriteBatch,
}

impl ReplicaCommand {
    /// A command applying `batch`, evaluated at `ts`.
    #[must_use]
    pub fn new(ts: Timestamp, batch: WriteBatch) -> Self {
        Self { ts, batch }
    }

    /// Encodes the command in format v1 (module docs).
    ///
    /// # Errors
    /// [`MvccError::InvalidArgument`] if the command cannot be applied (a range delete with
    /// `start >= end`, which the engine would refuse after the command was already logged) or
    /// cannot be encoded (a byte string or op count of 4 GiB or more).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let ops = self.batch.ops();
        let count = u32::try_from(ops.len())
            .map_err(|_| MvccError::InvalidArgument("command with 4 Gi ops or more".into()))?;
        let mut out = Vec::with_capacity(1 + Timestamp::ENCODED_LEN + 4 + 32 * ops.len());
        out.push(COMMAND_FORMAT_VERSION);
        put_u64(&mut out, self.ts.wall);
        put_u32(&mut out, self.ts.logical);
        put_u32(&mut out, count);
        for op in ops {
            match op {
                BatchOp::Put(k, v) => {
                    out.push(TAG_PUT);
                    put_bytes(&mut out, k)?;
                    put_bytes(&mut out, v)?;
                }
                BatchOp::Delete(k) => {
                    out.push(TAG_DELETE);
                    put_bytes(&mut out, k)?;
                }
                BatchOp::SingleDelete(k) => {
                    out.push(TAG_SINGLE_DELETE);
                    put_bytes(&mut out, k)?;
                }
                BatchOp::Merge(k, v) => {
                    out.push(TAG_MERGE);
                    put_bytes(&mut out, k)?;
                    put_bytes(&mut out, v)?;
                }
                BatchOp::DeleteRange(start, end) => {
                    // Validated before logging: an entry the engine refuses would stop the
                    // replica's apply loop for good (every replay would fail the same way).
                    if start >= end {
                        return Err(MvccError::InvalidArgument(
                            "delete_range needs start < end".into(),
                        ));
                    }
                    out.push(TAG_DELETE_RANGE);
                    put_bytes(&mut out, start)?;
                    put_bytes(&mut out, end)?;
                }
            }
        }
        Ok(out)
    }

    /// Decodes a format v1 command.
    ///
    /// # Errors
    /// [`MvccError::Corruption`] for an unknown version or tag, truncation, trailing bytes, an
    /// impossible count or a range delete with `start >= end`. Never panics.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, "replica command");
        let version = r.u8()?;
        if version != COMMAND_FORMAT_VERSION {
            return Err(r.corruption(&format!("unknown format version {version}")));
        }
        let ts = r.ts()?;
        let count = r.count(MIN_OP_LEN)?;
        let mut batch = WriteBatch::new();
        for _ in 0..count {
            match r.u8()? {
                TAG_PUT => {
                    let k = r.bytes()?;
                    batch.put(k, Bytes::copy_from_slice(r.bytes()?));
                }
                TAG_DELETE => {
                    batch.delete(r.bytes()?);
                }
                TAG_SINGLE_DELETE => {
                    batch.single_delete(r.bytes()?);
                }
                TAG_MERGE => {
                    let k = r.bytes()?;
                    batch.merge(k, Bytes::copy_from_slice(r.bytes()?));
                }
                TAG_DELETE_RANGE => {
                    let (start, end) = (r.bytes()?, r.bytes()?);
                    if start >= end {
                        return Err(r.corruption("delete_range with start >= end"));
                    }
                    batch.delete_range(start, end);
                }
                tag => return Err(r.corruption(&format!("unknown op tag {tag}"))),
            }
        }
        r.finish()?;
        Ok(Self { ts, batch })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn sample() -> ReplicaCommand {
        let mut batch = WriteBatch::new();
        batch
            .put(b"k1", b"v1".to_vec())
            .delete(b"k2")
            .single_delete(b"k3")
            .merge(b"k4", b"\x01".to_vec())
            .delete_range(b"a", b"b");
        ReplicaCommand::new(Timestamp::new(7, 3), batch)
    }

    #[test]
    fn command_round_trips_every_op_kind() {
        let cmd = sample();
        assert_eq!(ReplicaCommand::decode(&cmd.encode().unwrap()).unwrap(), cmd);
        let empty = ReplicaCommand::default();
        assert_eq!(
            empty.encode().unwrap(),
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            ReplicaCommand::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );
    }

    #[test]
    fn command_with_inverted_delete_range_is_refused_before_logging() {
        let mut batch = WriteBatch::new();
        batch.delete_range(b"b", b"a");
        let err = ReplicaCommand::new(Timestamp::MIN, batch).encode();
        assert!(matches!(err, Err(MvccError::InvalidArgument(_))));
    }

    #[test]
    fn command_decoder_rejects_damage() {
        let bytes = sample().encode().unwrap();
        for cut in 0..bytes.len() {
            assert!(ReplicaCommand::decode(&bytes[..cut]).is_err(), "cut {cut}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ReplicaCommand::decode(&trailing).is_err());
        let mut version = bytes.clone();
        version[0] = 2;
        assert!(ReplicaCommand::decode(&version).is_err());
        let mut tag = bytes;
        tag[17] = 9;
        assert!(ReplicaCommand::decode(&tag).is_err());
    }
}
