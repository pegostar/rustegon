// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `RangeAppliedState` v1: how far a range's replica has applied its log (replication.md §3,
//! "Command format v1"; storage-engine.md §9 recovery).
//!
//! It is written **in the same storage write batch** as the operations of the command it
//! records. The LSM applies a batch atomically and recovers a prefix of whole batches (no WAL:
//! after a crash it holds exactly the flushed batches), so the persisted applied state always
//! names the last command whose operations are in the engine — replay restarts right after it
//! and never applies a command twice or skips one (storage-engine.md §9: "replay is exact").
//!
//! Key: the meta slot (`‖ 0x00`, [`meta_key`]) of the range-id-local logical key
//! `0x01 'r' range_id(u64 BE) 'a'` (data-model.md §3.2); unversioned, never garbage collected
//! (the GC filter keeps every `0x01` key).
//!
//! Value: `version u8 (= 1) ‖ range_id u64 ‖ applied_index u64 ‖ applied_term u64 ‖
//! max_ts (wall u64 ‖ logical u32)`, big endian, 37 bytes.

use super::codec::{Reader, put_u32, put_u64};
use crate::{
    error::{MvccError, Result},
    hlc::Timestamp,
    key::{LOCAL_PREFIX, meta_key},
};

/// Format version of the `RangeAppliedState` encoding.
pub const APPLIED_STATE_FORMAT_VERSION: u8 = 1;
/// Second byte of range-id-local keys (`0x01 'r'`, data-model.md §3.2).
pub const LOCAL_RANGE_ID_MARKER: u8 = b'r';
/// Range-id-local tag of the applied state (data-model.md §3.2).
pub const APPLIED_STATE_TAG: u8 = b'a';
/// Encoded size of a v1 `RangeAppliedState`.
pub const APPLIED_STATE_ENCODED_LEN: usize = 1 + 3 * 8 + Timestamp::ENCODED_LEN;

/// The applied position of a range's replica (module docs).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RangeAppliedState {
    /// Range (= Raft group) the state belongs to.
    pub range_id: u64,
    /// Index of the last applied log entry (0: nothing applied).
    pub applied_index: u64,
    /// Term of the entry at `applied_index` (0 when nothing is applied).
    pub applied_term: u64,
    /// Largest evaluation timestamp of the commands applied so far (replication lag, §7).
    pub max_ts: Timestamp,
}

impl RangeAppliedState {
    /// The state of a range that applied nothing yet.
    #[must_use]
    pub fn initial(range_id: u64) -> Self {
        Self {
            range_id,
            ..Self::default()
        }
    }

    /// The logical key `0x01 'r' range_id 'a'` (data-model.md §3.2).
    #[must_use]
    pub fn logical_key(range_id: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(11);
        out.push(LOCAL_PREFIX);
        out.push(LOCAL_RANGE_ID_MARKER);
        out.extend_from_slice(&range_id.to_be_bytes());
        out.push(APPLIED_STATE_TAG);
        out
    }

    /// The engine key: the meta slot of [`RangeAppliedState::logical_key`].
    #[must_use]
    pub fn engine_key(range_id: u64) -> Vec<u8> {
        meta_key(&Self::logical_key(range_id))
    }

    /// Encodes the state (module docs).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(APPLIED_STATE_ENCODED_LEN);
        out.push(APPLIED_STATE_FORMAT_VERSION);
        put_u64(&mut out, self.range_id);
        put_u64(&mut out, self.applied_index);
        put_u64(&mut out, self.applied_term);
        put_u64(&mut out, self.max_ts.wall);
        put_u32(&mut out, self.max_ts.logical);
        out
    }

    /// Decodes a v1 state.
    ///
    /// # Errors
    /// [`MvccError::Corruption`] for an unknown version, truncation or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, "range applied state");
        let version = r.u8()?;
        if version != APPLIED_STATE_FORMAT_VERSION {
            return Err(r.corruption(&format!("unknown format version {version}")));
        }
        let state = Self {
            range_id: r.u64()?,
            applied_index: r.u64()?,
            applied_term: r.u64()?,
            max_ts: r.ts()?,
        };
        r.finish()?;
        Ok(state)
    }

    /// The state after applying entry `(index, term)` whose command was evaluated at `ts`.
    ///
    /// # Errors
    /// [`MvccError::InvalidArgument`] unless `index` is exactly `applied_index + 1` and `term`
    /// does not go backwards: the apply path must never skip, repeat or reorder entries.
    pub fn advance(&self, index: u64, term: u64, ts: Timestamp) -> Result<Self> {
        if Some(index) != self.applied_index.checked_add(1) || term < self.applied_term {
            return Err(MvccError::InvalidArgument(format!(
                "range {}: entry ({index}, term {term}) does not follow applied ({}, term {})",
                self.range_id, self.applied_index, self.applied_term
            )));
        }
        Ok(Self {
            range_id: self.range_id,
            applied_index: index,
            applied_term: term,
            max_ts: self.max_ts.max(ts),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn applied_state_round_trips_and_has_fixed_size() {
        let s = RangeAppliedState {
            range_id: 9,
            applied_index: 12,
            applied_term: 3,
            max_ts: Timestamp::new(5, 6),
        };
        let bytes = s.encode();
        assert_eq!(bytes.len(), APPLIED_STATE_ENCODED_LEN);
        assert_eq!(RangeAppliedState::decode(&bytes).unwrap(), s);
        for cut in 0..bytes.len() {
            assert!(RangeAppliedState::decode(&bytes[..cut]).is_err());
        }
        let mut long = bytes.clone();
        long.push(0);
        assert!(RangeAppliedState::decode(&long).is_err());
    }

    #[test]
    fn applied_state_key_is_range_local_meta_slot() {
        assert_eq!(
            RangeAppliedState::engine_key(0x0102),
            [0x01, b'r', 0, 0, 0, 0, 0, 0, 0x01, 0x02, b'a', 0x00]
        );
    }

    #[test]
    fn advance_requires_the_next_index_and_monotonic_term() {
        let s = RangeAppliedState::initial(1);
        let s1 = s.advance(1, 1, Timestamp::new(9, 0)).unwrap();
        assert_eq!((s1.applied_index, s1.applied_term), (1, 1));
        let s2 = s1.advance(2, 1, Timestamp::new(3, 0)).unwrap();
        assert_eq!(s2.max_ts, Timestamp::new(9, 0));
        assert!(s2.advance(2, 1, Timestamp::MIN).is_err());
        assert!(s2.advance(4, 1, Timestamp::MIN).is_err());
        assert!(s2.advance(3, 0, Timestamp::MIN).is_err());
    }
}
