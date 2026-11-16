// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixtures of the replica layer, v1 (implementation-rules.md §6;
//! replication.md "Command format v1"): the replicated command stored in Raft log entries and
//! the `RangeAppliedState` stored in the engine.
//!
//! - Stability: the current encoders reproduce every v1 fixture byte for byte; a failure means
//!   a format changed and needs a version bump plus new fixtures, not a regeneration.
//! - Compatibility: the current decoders read every committed fixture back into the sample.
//! - Robustness: decoders reject arbitrary and damaged bytes with an error, never a panic.
//!
//! Write missing fixtures (existing ones are never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-mvcc --test replica_formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use proptest::prelude::*;
use rustegon_mvcc::{RangeAppliedState, ReplicaCommand, Timestamp};
use rustegon_storage::WriteBatch;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats/replica/1")
}

fn sample_command() -> ReplicaCommand {
    let mut batch = WriteBatch::new();
    batch
        .put(b"\x03put", b"value".to_vec())
        .delete(b"\x03del")
        .single_delete(b"\x03sdel")
        .merge(b"\x03merge", b"\x01\x01\x06".to_vec())
        .delete_range(b"\x03a", b"\x03b");
    ReplicaCommand::new(Timestamp::new(0x0102_0304_0506_0708, 0x090A_0B0C), batch)
}

fn sample_state() -> RangeAppliedState {
    RangeAppliedState {
        range_id: 0x0A0B,
        applied_index: 0x0102_0304,
        applied_term: 7,
        max_ts: Timestamp::new(1_762_300_000_123_456_789, 42),
    }
}

/// One fixture: file name, the current encoding of its sample, and a decoder check.
struct Case {
    name: &'static str,
    bytes: Vec<u8>,
    decodes: fn(&[u8]) -> bool,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "command.bin",
            bytes: sample_command().encode().unwrap(),
            decodes: |b| ReplicaCommand::decode(b).unwrap() == sample_command(),
        },
        Case {
            name: "range_applied_state.bin",
            bytes: sample_state().encode(),
            decodes: |b| RangeAppliedState::decode(b).unwrap() == sample_state(),
        },
        Case {
            name: "range_applied_state_key.bin",
            bytes: RangeAppliedState::engine_key(0x0A0B),
            decodes: |b| b == RangeAppliedState::engine_key(0x0A0B).as_slice(),
        },
    ]
}

#[test]
fn replica_v1_fixtures_are_stable_and_readable() {
    let write = std::env::var_os("RUSTEGON_WRITE_FIXTURES").is_some();
    for case in cases() {
        let path = dir().join(case.name);
        if !path.exists() && write {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(&path, &case.bytes).unwrap();
        }
        let fixture = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("fixture {} missing ({e})", path.display()));
        assert_eq!(fixture, case.bytes, "{}: encoder output changed", case.name);
        assert!((case.decodes)(&fixture), "{}: decoder mismatch", case.name);
    }
}

#[test]
fn replica_v1_bytes_are_as_specified() {
    // replication.md "Command format v1": version ‖ ts ‖ op_count ‖ ops.
    let mut batch = WriteBatch::new();
    batch.put(b"k", b"v".to_vec());
    let cmd = ReplicaCommand::new(Timestamp::new(1, 2), batch)
        .encode()
        .unwrap();
    let mut expect = vec![0x01];
    expect.extend_from_slice(&1u64.to_be_bytes());
    expect.extend_from_slice(&2u32.to_be_bytes());
    expect.extend_from_slice(&1u32.to_be_bytes());
    expect.push(1);
    expect.extend_from_slice(&[0, 0, 0, 1, b'k', 0, 0, 0, 1, b'v']);
    assert_eq!(cmd, expect);
    // Key: meta slot of 0x01 'r' range_id(u64 BE) 'a'.
    let mut key = vec![0x01, b'r'];
    key.extend_from_slice(&5u64.to_be_bytes());
    key.extend_from_slice(&[b'a', 0x00]);
    assert_eq!(RangeAppliedState::engine_key(5), key);
}

proptest! {
    #[test]
    fn replica_decoders_never_panic_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = ReplicaCommand::decode(&bytes);
        let _ = RangeAppliedState::decode(&bytes);
    }

    /// Truncations are always rejected (both formats are length-checked); bit flips never panic.
    #[test]
    fn replica_decoders_reject_damaged_encodings(which in 0usize..2, cut in any::<prop::sample::Index>(), flip in any::<prop::sample::Index>(), bit in 0u8..8) {
        let case = &cases()[which];
        let len = case.bytes.len();
        let truncated = &case.bytes[..cut.index(len)];
        prop_assert!(ReplicaCommand::decode(truncated).is_err() || which != 0);
        prop_assert!(RangeAppliedState::decode(truncated).is_err() || which != 1);
        let mut flipped = case.bytes.clone();
        flipped[flip.index(len)] ^= 1 << bit;
        let _ = ReplicaCommand::decode(&flipped);
        let _ = RangeAppliedState::decode(&flipped);
    }
}
