// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Intent and version writes, resolution and transaction records (transaction-management.md
//! §3, §5.1, §6, §7, §10; FR-TXN-001, TC-TXN-007 savepoints at the MVCC level, TC-TXN-031).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytes::Bytes;
use rustegon_common::ErrorCode;
use rustegon_mvcc::{
    IntentResolution, MvccError, MvccReader, MvccWriter, ReadOptions, ResolveOutcome, SeqRange,
    Timestamp, TxnContext, TxnMeta, TxnRecord, TxnStatus, VersionValue, meta_key,
    value::{InFlightWrite, Span},
};

fn ts(wall: u64) -> Timestamp {
    Timestamp::new(wall, 0)
}

fn v(s: &str) -> VersionValue {
    VersionValue::Value(Bytes::copy_from_slice(s.as_bytes()))
}

fn meta(txn: u8, epoch: u32, wall: u64, seq: u32) -> TxnMeta {
    TxnMeta {
        txn_id: [txn; 16],
        epoch,
        write_ts: ts(wall),
        seq,
        anchor_key: b"anchor".to_vec(),
        ignored_seq_ranges: Vec::new(),
    }
}

fn commit(txn: u8, epoch: u32, wall: u64, ignored: Vec<SeqRange>) -> IntentResolution {
    IntentResolution::Commit {
        txn_id: [txn; 16],
        epoch,
        commit_ts: ts(wall),
        ignored_seq_ranges: ignored,
    }
}

fn read(engine: &rustegon_storage::LsmEngine, key: &[u8], wall: u64) -> Option<Bytes> {
    MvccReader::new(engine, None)
        .get(key, &ReadOptions::at(ts(wall)))
        .unwrap()
}

#[test]
fn tc_txn_031_intent_blocks_other_writers_and_readers() {
    let (engine, _) = common::engine(false);
    let mut w = MvccWriter::new(&engine, None);
    w.put_intent(b"k", &meta(1, 0, 10, 1), v("one")).unwrap();
    // Same batch: the second writer sees the pending intent.
    assert!(matches!(
        w.put_intent(b"k", &meta(2, 0, 11, 1), v("two")),
        Err(MvccError::IntentConflict(_))
    ));
    assert!(matches!(
        w.put_version(b"k", ts(12), &v("x")),
        Err(MvccError::IntentConflict(_))
    ));
    w.commit().unwrap();
    let reader = MvccReader::new(&engine, None);
    // Below the intent: invisible. At or above: a conflict naming the intent.
    assert_eq!(reader.get(b"k", &ReadOptions::at(ts(9))).unwrap(), None);
    let Err(MvccError::IntentConflict(intents)) = reader.get(b"k", &ReadOptions::at(ts(10))) else {
        panic!("expected a conflict");
    };
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].key, b"k");
    assert_eq!(intents[0].meta.txn_id, [1; 16]);
    // Clock uncertainty: an intent in (read_ts, limit] conflicts too.
    let opts = ReadOptions {
        uncertainty_limit: ts(10),
        ..ReadOptions::at(ts(8))
    };
    assert!(matches!(
        reader.get(b"k", &opts),
        Err(MvccError::IntentConflict(_))
    ));
}

#[test]
fn tc_txn_031_write_too_old_and_uncertainty() {
    let (engine, _) = common::engine(false);
    let mut w = MvccWriter::new(&engine, None);
    w.put_version(b"k", ts(10), &v("a")).unwrap();
    // Seen through the pending writes of the same batch.
    let err = w.put_version(b"k", ts(10), &v("b")).unwrap_err();
    assert!(matches!(err, MvccError::WriteTooOld { existing, .. } if existing == ts(10)));
    assert_eq!(err.code(), ErrorCode::WriteTooOld);
    w.commit().unwrap();
    let mut w = MvccWriter::new(&engine, None);
    assert!(matches!(
        w.put_intent(b"k", &meta(1, 0, 9, 1), v("i")),
        Err(MvccError::WriteTooOld { .. })
    ));
    w.put_version(b"k", ts(11), &VersionValue::Tombstone)
        .unwrap();
    w.commit().unwrap();
    assert_eq!(read(&engine, b"k", 10).unwrap(), "a");
    assert_eq!(read(&engine, b"k", 11), None);
    let opts = ReadOptions {
        uncertainty_limit: ts(11),
        ..ReadOptions::at(ts(10))
    };
    assert!(matches!(
        MvccReader::new(&engine, None).get(b"k", &opts),
        Err(MvccError::ReadWithinUncertainty { existing, .. }) if existing == ts(11)
    ));
}

#[test]
fn tc_txn_031_resolve_commit_and_abort() {
    let (engine, _) = common::engine(false);
    let mut w = MvccWriter::new(&engine, None);
    w.put_version(b"a", ts(5), &v("old")).unwrap();
    w.put_intent(b"a", &meta(1, 0, 10, 1), v("new")).unwrap();
    w.put_intent(b"b", &meta(1, 0, 10, 2), v("bee")).unwrap();
    w.commit().unwrap();
    let mut w = MvccWriter::new(&engine, None);
    // Commit pushed to 12 (timestamp push, §5.1).
    assert_eq!(
        w.resolve_intent(b"a", &commit(1, 0, 12, vec![])).unwrap(),
        ResolveOutcome::Committed(ts(12))
    );
    assert_eq!(
        w.resolve_intent(b"b", &IntentResolution::Abort { txn_id: [1; 16] })
            .unwrap(),
        ResolveOutcome::Removed
    );
    // Another transaction's resolution does not touch anything.
    assert_eq!(
        w.resolve_intent(b"a", &commit(2, 0, 12, vec![])).unwrap(),
        ResolveOutcome::NotFound
    );
    w.commit().unwrap();
    assert_eq!(read(&engine, b"a", 11).unwrap(), "old");
    assert_eq!(read(&engine, b"a", 12).unwrap(), "new");
    assert_eq!(read(&engine, b"b", 20), None);
    // Idempotent: resolving again finds nothing.
    let mut w = MvccWriter::new(&engine, None);
    assert_eq!(
        w.resolve_intent(b"a", &commit(1, 0, 12, vec![])).unwrap(),
        ResolveOutcome::NotFound
    );
    // Commit below the intent timestamp is a caller bug.
    w.put_intent(b"c", &meta(3, 0, 20, 1), v("c")).unwrap();
    assert!(matches!(
        w.resolve_intent(b"c", &commit(3, 0, 19, vec![])),
        Err(MvccError::InvalidArgument(_))
    ));
}

#[test]
fn tc_txn_007_savepoints_in_intent_history() {
    let (engine, _) = common::engine(false);
    for (seq, val) in [(1, "s1"), (2, "s2"), (3, "s3")] {
        let mut w = MvccWriter::new(&engine, None);
        w.put_intent(b"k", &meta(1, 0, 10, seq), v(val)).unwrap();
        w.commit().unwrap();
    }
    // Replay of an already written sequence is a no-op; a different value is refused.
    let mut w = MvccWriter::new(&engine, None);
    w.put_intent(b"k", &meta(1, 0, 10, 2), v("s2")).unwrap();
    assert!(w.is_empty());
    assert!(matches!(
        w.put_intent(b"k", &meta(1, 0, 10, 2), v("other")),
        Err(MvccError::InvalidArgument(_))
    ));
    let reader = MvccReader::new(&engine, None);
    let own = |seq, ignored: Vec<SeqRange>| TxnContext {
        txn_id: [1; 16],
        epoch: 0,
        seq,
        ignored_seq_ranges: ignored,
    };
    let get = |ctx: &TxnContext| {
        let opts = ReadOptions {
            txn: Some(ctx),
            ..ReadOptions::at(ts(10))
        };
        reader.get(b"k", &opts).unwrap()
    };
    assert_eq!(get(&own(3, vec![])).unwrap(), "s3");
    assert_eq!(get(&own(2, vec![])).unwrap(), "s2");
    assert_eq!(
        get(&own(9, vec![SeqRange { start: 2, end: 3 }])).unwrap(),
        "s1"
    );
    assert_eq!(get(&own(0, vec![])), None);
    // Commit with the final rollbacks: seq 3 rolled back → "s2" committed.
    let mut w = MvccWriter::new(&engine, None);
    w.resolve_intent(b"k", &commit(1, 0, 10, vec![SeqRange { start: 3, end: 3 }]))
        .unwrap();
    w.commit().unwrap();
    assert_eq!(read(&engine, b"k", 10).unwrap(), "s2");
    // Everything rolled back: the intent disappears without a version.
    let mut w = MvccWriter::new(&engine, None);
    w.put_intent(b"z", &meta(1, 0, 20, 4), v("gone")).unwrap();
    assert_eq!(
        w.resolve_intent(b"z", &commit(1, 0, 20, vec![SeqRange { start: 0, end: 9 }]))
            .unwrap(),
        ResolveOutcome::Removed
    );
    w.commit().unwrap();
    assert_eq!(read(&engine, b"z", 30), None);
}

#[test]
fn tc_txn_031_epochs() {
    let (engine, _) = common::engine(false);
    let mut w = MvccWriter::new(&engine, None);
    w.put_intent(b"k", &meta(1, 0, 10, 5), v("e0")).unwrap();
    w.commit().unwrap();
    // The epoch-1 reader ignores the epoch-0 intent (discarded writes).
    let ctx = TxnContext {
        txn_id: [1; 16],
        epoch: 1,
        seq: 9,
        ignored_seq_ranges: vec![],
    };
    let opts = ReadOptions {
        txn: Some(&ctx),
        ..ReadOptions::at(ts(10))
    };
    assert_eq!(
        MvccReader::new(&engine, None).get(b"k", &opts).unwrap(),
        None
    );
    // Committing epoch 1 removes an epoch-0 intent without a version.
    let mut w = MvccWriter::new(&engine, None);
    assert_eq!(
        w.resolve_intent(b"k", &commit(1, 1, 10, vec![])).unwrap(),
        ResolveOutcome::Removed
    );
    // A new epoch's write replaces the intent (history dropped); a stale epoch is refused.
    w.put_intent(b"k", &meta(1, 1, 10, 1), v("e1")).unwrap();
    assert!(matches!(
        w.put_intent(b"k", &meta(1, 0, 10, 6), v("stale")),
        Err(MvccError::InvalidArgument(_))
    ));
    w.commit().unwrap();
    let intent = MvccReader::new(&engine, None)
        .get_intent(b"k")
        .unwrap()
        .unwrap();
    assert_eq!(intent.meta.epoch, 1);
    assert_eq!(intent.history, []);
}

#[test]
fn tc_txn_031_txn_record_round_trip() {
    let (engine, _) = common::engine(false);
    let record = TxnRecord {
        status: TxnStatus::Staging,
        write_ts: ts(20),
        read_ts: ts(10),
        priority: 7,
        heartbeat_ts: ts(15),
        in_flight_writes: vec![InFlightWrite {
            key: b"k".to_vec(),
            seq: 3,
        }],
        lock_spans: vec![Span {
            start: b"a".to_vec(),
            end: b"c".to_vec(),
        }],
    };
    let mut w = MvccWriter::new(&engine, None);
    w.put_txn_record(b"k", &[4; 16], &record);
    w.commit().unwrap();
    let reader = MvccReader::new(&engine, None);
    assert_eq!(reader.get_txn_record(b"k", &[4; 16]).unwrap(), Some(record));
    assert_eq!(reader.get_txn_record(b"k", &[5; 16]).unwrap(), None);
    let mut w = MvccWriter::new(&engine, None);
    w.delete_txn_record(b"k", &[4; 16]);
    w.commit().unwrap();
    assert_eq!(reader.get_txn_record(b"k", &[4; 16]).unwrap(), None);
}

/// PD-233: a point read (and the write path's search for the newest version) opens only the
/// files that may hold its key. Versions spread over several files must all be seen, and a
/// range tombstone must hide the key even from a file with no entry of that key, whose filter
/// therefore excludes it.
#[test]
fn tc_txn_031_point_read_spans_files_and_honours_range_tombstones() {
    let (engine, _) = common::engine(false);
    let put = |key: &[u8], wall: u64, s: &str| {
        let mut w = MvccWriter::new(&engine, None);
        w.put_version(key, ts(wall), &v(s)).unwrap();
        w.commit().unwrap();
    };
    put(b"b", 5, "b5");
    put(b"d", 5, "d5");
    engine.flush().unwrap();
    put(b"b", 7, "b7");
    engine.flush().unwrap();
    put(b"b", 9, "b9");
    assert_eq!(read(&engine, b"b", 6).unwrap(), "b5");
    assert_eq!(read(&engine, b"b", 8).unwrap(), "b7");
    assert_eq!(read(&engine, b"b", 9).unwrap(), "b9");
    assert_eq!(read(&engine, b"b", 4), None);
    assert_eq!(read(&engine, b"c", 9), None);
    assert_eq!(read(&engine, b"d", 9).unwrap(), "d5");

    // A third file: another key and a range tombstone over every entry of `d`.
    put(b"a", 8, "a8");
    let mut batch = rustegon_storage::WriteBatch::new();
    batch.delete_range(&meta_key(b"d"), &meta_key(b"e"));
    engine.write(&batch).unwrap();
    engine.flush().unwrap();
    assert_eq!(read(&engine, b"d", 9), None);
    assert_eq!(read(&engine, b"a", 9).unwrap(), "a8");
    assert_eq!(read(&engine, b"b", 9).unwrap(), "b9");

    // The newest version of `b` is in the memtable, older ones in two files.
    let mut w = MvccWriter::new(&engine, None);
    assert!(matches!(
        w.put_version(b"b", ts(9), &v("late")),
        Err(MvccError::WriteTooOld { existing, .. }) if existing == ts(9)
    ));
    // `d` is gone, so nothing is newer than a write at 3.
    w.put_version(b"d", ts(3), &v("d3")).unwrap();
    w.commit().unwrap();
    assert_eq!(read(&engine, b"d", 9).unwrap(), "d3");
}

#[test]
fn tc_txn_031_scan_limit_and_counters() {
    let (engine, _) = common::engine(false);
    let op = |d: i64| {
        VersionValue::MergeOperand(
            rustegon_storage::merge::MergeOperand::CounterDelta(d)
                .encode()
                .into(),
        )
    };
    let mut w = MvccWriter::new(&engine, None);
    for (i, key) in [b"a", b"b", b"c", b"d"].iter().enumerate() {
        w.put_version(*key, ts(1), &v(&i.to_string())).unwrap();
    }
    w.put_version(b"n", ts(1), &op(5)).unwrap();
    w.put_version(b"n", ts(2), &op(-2)).unwrap();
    w.commit().unwrap();
    let reader = MvccReader::new(&engine, None);
    let page = reader.scan(b"a", b"z", &ReadOptions::at(ts(5)), 2).unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[1].0, b"b");
    let n = reader.get(b"n", &ReadOptions::at(ts(5))).unwrap().unwrap();
    assert_eq!(
        rustegon_storage::merge::MergeOperand::decode(&n).unwrap(),
        rustegon_storage::merge::MergeOperand::CounterDelta(3)
    );
}
