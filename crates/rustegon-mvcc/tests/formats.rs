// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixtures of the MVCC layer, v1 (implementation-rules.md §6; frozen at M2
//! exit, DEC-018): key layout, version values, `TxnMeta`, intents, `TxnRecord`, transaction
//! record keys and the HLC bound file (transaction-management.md §3).
//!
//! - Stability: the current encoders reproduce every v1 fixture byte for byte; a failure means
//!   a format changed and needs a version bump plus new fixtures, not a regeneration.
//! - Compatibility: the current decoders read every committed fixture back into the sample.
//! - Robustness: decoders reject arbitrary and damaged bytes with an error, never a panic.
//!
//! Write missing fixtures (existing ones are never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-mvcc --test formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use bytes::Bytes;
use proptest::prelude::*;
use rustegon_mvcc::{
    IntentValue, MvccKey, SeqRange, Timestamp, TxnMeta, TxnRecord, TxnStatus, VersionValue,
    hlc::{decode_bound, encode_bound},
    meta_key, txn_record_key,
    value::{InFlightWrite, Span},
    version_key,
};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats/mvcc/1")
}

fn sample_meta() -> TxnMeta {
    TxnMeta {
        txn_id: *b"0123456789abcdef",
        epoch: 3,
        write_ts: Timestamp::new(1_762_300_000_123_456_789, 42),
        seq: 17,
        anchor_key: b"\x03\x00anchor".to_vec(),
        ignored_seq_ranges: vec![SeqRange { start: 4, end: 6 }, SeqRange { start: 9, end: 9 }],
    }
}

fn sample_intent() -> IntentValue {
    IntentValue {
        meta: sample_meta(),
        value: VersionValue::Value(Bytes::from_static(b"provisional")),
        history: vec![
            (2, VersionValue::Value(Bytes::from_static(b"first"))),
            (5, VersionValue::Tombstone),
            (
                9,
                VersionValue::MergeOperand(Bytes::from_static(b"\x01\x01\x06")),
            ),
        ],
    }
}

fn sample_record() -> TxnRecord {
    TxnRecord {
        status: TxnStatus::Staging,
        write_ts: Timestamp::new(1_762_300_000_200_000_000, 1),
        read_ts: Timestamp::new(1_762_300_000_100_000_000, 0),
        priority: 0x0102_0304,
        heartbeat_ts: Timestamp::new(1_762_300_000_150_000_000, 7),
        in_flight_writes: vec![
            InFlightWrite {
                key: b"k1".to_vec(),
                seq: 3,
            },
            InFlightWrite {
                key: b"k2".to_vec(),
                seq: 4,
            },
        ],
        lock_spans: vec![
            Span {
                start: b"a".to_vec(),
                end: b"m".to_vec(),
            },
            Span {
                start: b"x".to_vec(),
                end: Vec::new(),
            },
        ],
    }
}

/// One fixture: file name, the current encoding of its sample, and a decoder check.
struct Case {
    name: &'static str,
    bytes: Vec<u8>,
    decodes: fn(&[u8]) -> bool,
}

fn cases() -> Vec<Case> {
    let ts = Timestamp::new(0x0102_0304_0506_0708, 0x090A_0B0C);
    vec![
        Case {
            name: "meta_key.bin",
            bytes: meta_key(b"doc\x01key"),
            decodes: |b| MvccKey::decode(b).unwrap() == MvccKey::Meta(b"doc\x01key"),
        },
        Case {
            name: "version_key.bin",
            bytes: version_key(b"doc\x01key", ts),
            decodes: |b| {
                let ts = Timestamp::new(0x0102_0304_0506_0708, 0x090A_0B0C);
                MvccKey::decode(b).unwrap() == MvccKey::Version(b"doc\x01key", ts)
            },
        },
        Case {
            name: "version_value_value.bin",
            bytes: VersionValue::Value(Bytes::from_static(b"rdoc")).encode(),
            decodes: |b| {
                VersionValue::decode(b).unwrap() == VersionValue::Value(Bytes::from_static(b"rdoc"))
            },
        },
        Case {
            name: "version_value_tombstone.bin",
            bytes: VersionValue::Tombstone.encode(),
            decodes: |b| VersionValue::decode(b).unwrap() == VersionValue::Tombstone,
        },
        Case {
            name: "version_value_merge.bin",
            bytes: VersionValue::MergeOperand(Bytes::from_static(b"\x01\x01\x06")).encode(),
            decodes: |b| {
                VersionValue::decode(b).unwrap()
                    == VersionValue::MergeOperand(Bytes::from_static(b"\x01\x01\x06"))
            },
        },
        Case {
            name: "txn_meta.bin",
            bytes: sample_meta().encode(),
            decodes: |b| TxnMeta::decode(b).unwrap() == sample_meta(),
        },
        Case {
            name: "intent.bin",
            bytes: sample_intent().encode(),
            decodes: |b| IntentValue::decode(b).unwrap() == sample_intent(),
        },
        Case {
            name: "txn_record.bin",
            bytes: sample_record().encode(),
            decodes: |b| TxnRecord::decode(b).unwrap() == sample_record(),
        },
        Case {
            name: "txn_record_key.bin",
            bytes: meta_key(&txn_record_key(b"\x03\x00anchor", b"0123456789abcdef")),
            decodes: |b| {
                MvccKey::decode(b).unwrap()
                    == MvccKey::Meta(&txn_record_key(b"\x03\x00anchor", b"0123456789abcdef"))
            },
        },
        Case {
            name: "hlc_bound.bin",
            bytes: encode_bound(1_762_300_001_000_000_000).to_vec(),
            decodes: |b| decode_bound(b).unwrap() == 1_762_300_001_000_000_000,
        },
    ]
}

#[test]
fn mvcc_v1_fixtures_are_stable_and_readable() {
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
fn mvcc_v1_version_key_bytes_are_as_specified() {
    // transaction-management.md §3: K ‖ 0x00 ‖ inverted(wall BE ‖ logical BE) ‖ 0x0D.
    let key = version_key(b"K", Timestamp::new(1, 2));
    let mut expect = vec![b'K', 0x00];
    expect.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]);
    expect.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFD]);
    expect.push(0x0D);
    assert_eq!(key, expect);
    assert_eq!(VersionValue::Tombstone.encode(), [0x01, 0x02]);
}

fn decode_all(bytes: &[u8]) {
    let _ = MvccKey::decode(bytes);
    let _ = VersionValue::decode(bytes);
    let _ = TxnMeta::decode(bytes);
    let _ = IntentValue::decode(bytes);
    let _ = TxnRecord::decode(bytes);
    let _ = decode_bound(bytes);
}

proptest! {
    #[test]
    fn mvcc_decoders_never_panic_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        decode_all(&bytes);
    }

    /// Truncated or bit-flipped valid encodings are rejected (or decode to something), never
    /// panic; truncations of length-checked formats are always rejected.
    #[test]
    fn mvcc_decoders_reject_damaged_encodings(which in 0usize..10, cut in any::<prop::sample::Index>(), flip in any::<prop::sample::Index>(), bit in 0u8..8) {
        let case = &cases()[which];
        let len = case.bytes.len();
        let truncated = &case.bytes[..cut.index(len)];
        decode_all(truncated);
        let accepted = match case.name {
            "version_value_tombstone.bin" => Some(VersionValue::decode(truncated).is_ok()),
            "txn_meta.bin" => Some(TxnMeta::decode(truncated).is_ok()),
            "intent.bin" => Some(IntentValue::decode(truncated).is_ok()),
            "txn_record.bin" => Some(TxnRecord::decode(truncated).is_ok()),
            "hlc_bound.bin" => Some(decode_bound(truncated).is_ok()),
            // Keys and payload-carrying version values have valid shorter forms.
            _ => None,
        };
        prop_assert_ne!(accepted, Some(true), "{} truncated to {}", case.name, truncated.len());
        let mut flipped = case.bytes.clone();
        flipped[flip.index(len)] ^= 1 << bit;
        decode_all(&flipped);
    }
}
