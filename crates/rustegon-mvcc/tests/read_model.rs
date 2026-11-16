// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MVCC reader vs a model (transaction-management.md §3 visibility rule; TC-TXN-031): random
//! committed versions (values, tombstones, merge operands), intents of several transactions
//! with savepoint histories, written through `MvccWriter` across memtables, flushes and
//! compactions; random point reads and scans at random timestamps, with and without a reading
//! transaction, compared with a `BTreeMap` model.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;

use bytes::Bytes;
use proptest::prelude::*;
use rustegon_mvcc::{
    MvccError, MvccReader, MvccWriter, ReadOptions, SeqRange, Timestamp, TxnContext, TxnMeta,
    VersionValue,
};
use rustegon_storage::merge::MergeOperand;

/// Logical keys; some are prefixes of others (never continued with `0x00`, data-model §3.2).
const KEYS: [&[u8]; 6] = [b"a", b"ab", b"abc", b"b", b"c", b"cd"];

#[derive(Debug, Clone)]
enum Val {
    Value(u8),
    Tombstone,
    Merge(i8),
}

impl Val {
    /// The stored version: counter keys hold counter values and operands, plain keys bytes.
    fn version(&self, counter: bool) -> VersionValue {
        match (self, counter) {
            (Self::Value(v), false) => VersionValue::Value(Bytes::from(vec![*v; 3])),
            (Self::Value(v), true) => {
                VersionValue::Value(MergeOperand::CounterDelta(i64::from(*v)).encode().into())
            }
            (Self::Merge(d), true) => VersionValue::MergeOperand(
                MergeOperand::CounterDelta(i64::from(*d)).encode().into(),
            ),
            // Plain keys never get merge operands (storage-engine.md §8: the document layer
            // emits them only for counter keys).
            (Self::Merge(d), false) => {
                VersionValue::Value(Bytes::from(vec![d.to_ne_bytes()[0]; 2]))
            }
            (Self::Tombstone, _) => VersionValue::Tombstone,
        }
    }
}

#[derive(Debug, Clone)]
struct IntentGen {
    txn: u8,
    epoch: u32,
    /// Added to the newest committed wall time.
    ts_delta: u64,
    /// Provisional values at ascending sequence numbers.
    writes: Vec<(u32, Val)>,
}

#[derive(Debug, Clone)]
struct KeyGen {
    counter: bool,
    versions: BTreeMap<(u64, u32), Val>,
    intent: Option<IntentGen>,
}

#[derive(Debug, Clone)]
struct ReaderGen {
    txn: u8,
    epoch: u32,
    seq: u32,
    ignored: Option<(u32, u32)>,
}

#[derive(Debug, Clone)]
enum Query {
    Get(usize),
    Scan(usize, usize),
}

fn val() -> impl Strategy<Value = Val> {
    prop_oneof![
        (0u8..=255).prop_map(Val::Value),
        Just(Val::Tombstone),
        (-50i8..50).prop_map(Val::Merge),
    ]
}

fn key_gen() -> impl Strategy<Value = KeyGen> {
    let intent = (
        0u8..3,
        0u32..2,
        0u64..4,
        prop::collection::btree_map(1u32..8, val(), 1..4),
    )
        .prop_map(|(txn, epoch, ts_delta, writes)| IntentGen {
            txn,
            epoch,
            ts_delta,
            writes: writes.into_iter().collect(),
        });
    (
        any::<bool>(),
        prop::collection::btree_map((1u64..30, 0u32..2), val(), 0..6),
        prop::option::of(intent),
    )
        .prop_map(|(counter, versions, intent)| KeyGen {
            counter,
            versions,
            intent,
        })
}

fn reader_gen() -> impl Strategy<Value = Option<ReaderGen>> {
    prop::option::of(
        (
            0u8..3,
            0u32..2,
            0u32..9,
            prop::option::of((1u32..8, 0u32..4)),
        )
            .prop_map(|(txn, epoch, seq, ignored)| ReaderGen {
                txn,
                epoch,
                seq,
                ignored: ignored.map(|(s, len)| (s, s + len)),
            }),
    )
}

fn query() -> impl Strategy<Value = Query> {
    prop_oneof![
        (0..KEYS.len()).prop_map(Query::Get),
        (0..=KEYS.len(), 0..=KEYS.len()).prop_map(|(a, b)| Query::Scan(a.min(b), a.max(b))),
    ]
}

fn txn_id(txn: u8) -> [u8; 16] {
    [txn + 1; 16]
}

fn intent_ts(k: &KeyGen, i: &IntentGen) -> Timestamp {
    let newest = k.versions.keys().next_back().map_or(0, |(w, _)| *w);
    Timestamp::new(newest + 1 + i.ts_delta, 0)
}

/// What a read of one key should produce.
#[derive(Debug, PartialEq, Eq)]
enum Expect {
    Value(Option<Bytes>),
    Conflict,
    Invalid,
}

fn sum_counter(base: Option<&VersionValue>, operands: &[VersionValue]) -> Bytes {
    let decode = |v: &VersionValue| match v {
        VersionValue::Value(b) | VersionValue::MergeOperand(b) => match MergeOperand::decode(b) {
            Ok(MergeOperand::CounterDelta(d)) => d,
            other => panic!("not a counter: {other:?}"),
        },
        VersionValue::Tombstone => 0,
    };
    let total: i64 = base.map_or(0, decode) + operands.iter().map(decode).sum::<i64>();
    Bytes::from(MergeOperand::CounterDelta(total).encode())
}

/// The model of the visibility rule (read.rs module docs).
fn model(k: &KeyGen, read_ts: Timestamp, reader: Option<&ReaderGen>) -> Expect {
    let mut operands = Vec::new();
    if let Some(i) = &k.intent {
        match reader {
            Some(r) if r.txn == i.txn => {
                if i.epoch > r.epoch {
                    return Expect::Invalid;
                }
                if i.epoch == r.epoch {
                    let ignored = |s: u32| r.ignored.is_some_and(|(a, b)| a <= s && s <= b);
                    let visible = i
                        .writes
                        .iter()
                        .rev()
                        .find(|(s, _)| *s <= r.seq && !ignored(*s));
                    match visible.map(|(_, v)| v.version(k.counter)) {
                        Some(VersionValue::Value(v)) => return Expect::Value(Some(v)),
                        Some(VersionValue::Tombstone) => return Expect::Value(None),
                        Some(op @ VersionValue::MergeOperand(_)) => operands.push(op),
                        None => {}
                    }
                }
            }
            _ if intent_ts(k, i) <= read_ts => return Expect::Conflict,
            _ => {}
        }
    }
    let mut base = None;
    for (&(w, l), v) in k.versions.iter().rev() {
        if Timestamp::new(w, l) > read_ts {
            continue;
        }
        match v.version(k.counter) {
            VersionValue::MergeOperand(op) => operands.push(VersionValue::MergeOperand(op)),
            VersionValue::Tombstone => break,
            value @ VersionValue::Value(_) => {
                base = Some(value);
                break;
            }
        }
    }
    if operands.is_empty() {
        return Expect::Value(match base {
            Some(VersionValue::Value(v)) => Some(v),
            _ => None,
        });
    }
    Expect::Value(Some(sum_counter(base.as_ref(), &operands)))
}

fn outcome(r: Result<Option<Bytes>, MvccError>) -> Expect {
    match r {
        Ok(v) => Expect::Value(v),
        Err(MvccError::IntentConflict(_)) => Expect::Conflict,
        Err(MvccError::InvalidArgument(_)) => Expect::Invalid,
        Err(e) => panic!("unexpected error {e}"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn tc_txn_031_mvcc_reader_matches_model(
        keys in prop::collection::vec(key_gen(), KEYS.len()),
        flush_after in prop::collection::vec(any::<bool>(), KEYS.len()),
        compact in any::<bool>(),
        queries in prop::collection::vec((1u64..40, 0u32..2, reader_gen(), query()), 1..24),
    ) {
        let (engine, _) = common::engine(false);
        for ((key, k), flush) in KEYS.iter().zip(&keys).zip(&flush_after) {
            let mut w = MvccWriter::new(&engine, None);
            for (&(wall, logical), v) in &k.versions {
                w.put_version(key, Timestamp::new(wall, logical), &v.version(k.counter))
                    .unwrap();
            }
            w.commit().unwrap();
            if let Some(i) = &k.intent {
                // One batch per sequence number, as a transaction writes them.
                for (seq, v) in &i.writes {
                    let mut w = MvccWriter::new(&engine, None);
                    let meta = TxnMeta {
                        txn_id: txn_id(i.txn),
                        epoch: i.epoch,
                        write_ts: intent_ts(k, i),
                        seq: *seq,
                        anchor_key: b"anchor".to_vec(),
                        ignored_seq_ranges: Vec::new(),
                    };
                    w.put_intent(key, &meta, v.version(k.counter)).unwrap();
                    w.commit().unwrap();
                }
            }
            if *flush {
                engine.flush().unwrap();
            }
        }
        if compact {
            engine.flush().unwrap();
            engine.compact().unwrap();
        }

        let reader = MvccReader::new(&engine, None);
        for (wall, logical, rg, q) in &queries {
            let read_ts = Timestamp::new(*wall, *logical);
            let ctx = rg.as_ref().map(|r| TxnContext {
                txn_id: txn_id(r.txn),
                epoch: r.epoch,
                seq: r.seq,
                ignored_seq_ranges: r
                    .ignored
                    .map(|(start, end)| SeqRange { start, end })
                    .into_iter()
                    .collect(),
            });
            let opts = ReadOptions { txn: ctx.as_ref(), ..ReadOptions::at(read_ts) };
            match *q {
                Query::Get(i) => {
                    let got = outcome(reader.get(KEYS[i], &opts));
                    prop_assert_eq!(got, model(&keys[i], read_ts, rg.as_ref()), "get {:?}", i);
                }
                Query::Scan(a, b) => {
                    let end: &[u8] = if b == KEYS.len() { b"\xFF" } else { KEYS[b] };
                    // KEYS is sorted, so [KEYS[a], KEYS[b]) holds exactly the indices a..b.
                    let expected: Vec<(usize, Expect)> = (a..b)
                        .map(|i| (i, model(&keys[i], read_ts, rg.as_ref())))
                        .collect();
                    let start: &[u8] = if a == KEYS.len() { b"\xFF" } else { KEYS[a] };
                    let got = reader.scan(start, end, &opts, usize::MAX);
                    if expected.iter().any(|(_, e)| *e == Expect::Invalid) {
                        prop_assert!(matches!(got, Err(MvccError::InvalidArgument(_))));
                    } else if expected.iter().any(|(_, e)| *e == Expect::Conflict) {
                        let Err(MvccError::IntentConflict(intents)) = got else {
                            panic!("expected conflicts, got {got:?}");
                        };
                        let keys_got: Vec<Vec<u8>> = intents.into_iter().map(|i| i.key).collect();
                        let keys_want: Vec<Vec<u8>> = expected
                            .iter()
                            .filter(|(_, e)| *e == Expect::Conflict)
                            .map(|(i, _)| KEYS[*i].to_vec())
                            .collect();
                        prop_assert_eq!(keys_got, keys_want);
                    } else {
                        let want: Vec<(Vec<u8>, Bytes)> = expected
                            .into_iter()
                            .filter_map(|(i, e)| match e {
                                Expect::Value(Some(v)) => Some((KEYS[i].to_vec(), v)),
                                _ => None,
                            })
                            .collect();
                        prop_assert_eq!(got.unwrap(), want);
                    }
                }
            }
        }
    }
}
