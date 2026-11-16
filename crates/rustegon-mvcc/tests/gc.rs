// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MVCC garbage collection (transaction-management.md §3 "GC", storage-engine.md §3, §11;
//! TC-TXN-036): reads below the threshold fail with `RGN-2007`; the compaction filter and the
//! GC batch never change a read at or above the threshold, and they do remove garbage.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{collections::BTreeMap, path::Path, sync::Arc};

use bytes::Bytes;
use proptest::prelude::*;
use rustegon_common::{Error, ErrorCode};
use rustegon_mvcc::{
    GcThreshold, MvccError, MvccReader, MvccWriter, ReadOptions, Timestamp, TxnMeta, VersionValue,
    gc_batch, key::MvccKey,
};
use rustegon_sim::SimFileSystem;
use rustegon_storage::{EngineOptions, LsmEngine, merge::MergeOperand};

fn ts(wall: u64) -> Timestamp {
    Timestamp::new(wall, 0)
}

/// Every compaction trigger at one L0 file, so each flush pushes data through a compaction
/// (and therefore through the GC filter); subcompactions on parallel threads.
fn gc_engine() -> (LsmEngine, Arc<GcThreshold>) {
    let threshold = Arc::new(GcThreshold::default());
    let mut options: EngineOptions = common::options(threshold.clone(), true);
    options.compaction.l0_trigger = 1;
    let fs = Arc::new(SimFileSystem::new());
    let engine = LsmEngine::open(fs, Path::new(common::DIR), options).unwrap();
    (engine, threshold)
}

/// All engine keys (the physical MVCC entries that are still live).
fn raw_keys(engine: &LsmEngine) -> Vec<Vec<u8>> {
    let mut it = engine.iterator(None).unwrap();
    it.seek_to_first().unwrap();
    let mut out = Vec::new();
    while it.valid() {
        out.push(it.key().to_vec());
        it.next().unwrap();
    }
    out
}

fn versions_of(engine: &LsmEngine, key: &[u8]) -> Vec<u64> {
    raw_keys(engine)
        .iter()
        .filter_map(|k| match MvccKey::decode(k).unwrap() {
            MvccKey::Version(l, t) if l == key => Some(t.wall),
            _ => None,
        })
        .collect()
}

#[test]
fn tc_txn_036_read_below_gc_threshold_rgn_2007() {
    let (engine, threshold) = common::engine(false);
    let mut w = MvccWriter::new(&engine, Some(&threshold));
    w.put_version(b"k", ts(5), &VersionValue::Value(Bytes::from_static(b"v")))
        .unwrap();
    w.commit().unwrap();
    threshold.advance(ts(10));
    let reader = MvccReader::new(&engine, Some(&threshold));
    for result in [
        reader.get(b"k", &ReadOptions::at(ts(9))).map(|_| ()),
        reader
            .scan(
                b"a",
                b"z",
                &ReadOptions::at(Timestamp::new(9, 99)),
                usize::MAX,
            )
            .map(|_| ()),
    ] {
        let err = result.unwrap_err();
        assert!(matches!(err, MvccError::BelowGcThreshold { threshold: t, .. } if t == ts(10)));
        let err = Error::from(err);
        assert_eq!(err.code(), ErrorCode::ReadTimestampTooOld);
        assert_eq!(err.code().code(), 2007);
        assert!(err.retryable());
    }
    // At the threshold the read is allowed and sees the version.
    assert!(
        reader
            .get(b"k", &ReadOptions::at(ts(10)))
            .unwrap()
            .is_some()
    );
    // Writes at or below the threshold are refused too.
    let mut w = MvccWriter::new(&engine, Some(&threshold));
    assert!(matches!(
        w.put_version(b"j", ts(10), &VersionValue::Tombstone),
        Err(MvccError::BelowGcThreshold { .. })
    ));
}

#[test]
fn tc_txn_036_gc_drops_shadowed_versions() {
    let (engine, threshold) = gc_engine();
    let value = |s: &'static [u8]| VersionValue::Value(Bytes::from_static(s));
    let mut w = MvccWriter::new(&engine, Some(&threshold));
    for wall in 1..=5 {
        w.put_version(b"a", ts(wall), &value(b"a")).unwrap();
    }
    w.put_version(b"b", ts(2), &value(b"b")).unwrap();
    w.put_version(b"b", ts(3), &VersionValue::Tombstone)
        .unwrap();
    w.put_version(b"c", ts(1), &value(b"c")).unwrap();
    w.put_version(
        b"c",
        ts(2),
        &VersionValue::MergeOperand(MergeOperand::CounterDelta(1).encode().into()),
    )
    .unwrap();
    let meta = TxnMeta {
        txn_id: [9; 16],
        epoch: 0,
        write_ts: ts(8),
        seq: 1,
        anchor_key: b"d".to_vec(),
        ignored_seq_ranges: vec![],
    };
    w.put_intent(b"d", &meta, value(b"d")).unwrap();
    w.commit().unwrap();
    threshold.advance(ts(3));
    engine.flush().unwrap();
    engine.compact().unwrap();
    // a: newest base <= 3 is @3; @2 and @1 dropped. b: the tombstone @3 is kept by the filter
    // (it cannot know nothing older survives elsewhere), @2 dropped. c: the operand needs @1.
    assert_eq!(versions_of(&engine, b"a"), [5, 4, 3]);
    assert_eq!(versions_of(&engine, b"b"), [3]);
    assert_eq!(versions_of(&engine, b"c"), [2, 1]);
    // The explicit GC request removes the tombstone, after which nothing of b remains.
    let batch = gc_batch(&engine, &threshold, b"", b"\xFF").unwrap();
    assert_eq!(batch.len(), 1);
    engine.write(&batch).unwrap();
    engine.flush().unwrap();
    engine.compact().unwrap();
    assert_eq!(versions_of(&engine, b"b"), Vec::<u64>::new());
    // The intent's meta slot is never touched.
    let reader = MvccReader::new(&engine, Some(&threshold));
    assert!(reader.get_intent(b"d").unwrap().is_some());
    assert_eq!(
        reader.get(b"a", &ReadOptions::at(ts(3))).unwrap().unwrap(),
        Bytes::from_static(b"a")
    );
}

/// A generated version: a value byte, a tombstone or (counter keys only) an operand.
#[derive(Debug, Clone)]
enum Gen {
    Value(u8),
    Tombstone,
    Merge(i8),
}

fn gen_val() -> impl Strategy<Value = Gen> {
    prop_oneof![
        (0u8..=255).prop_map(Gen::Value),
        Just(Gen::Tombstone),
        (-9i8..9).prop_map(Gen::Merge),
    ]
}

fn version(g: &Gen, counter: bool) -> VersionValue {
    match (g, counter) {
        (Gen::Value(b), false) => VersionValue::Value(Bytes::from(vec![*b; 4])),
        (Gen::Value(b), true) => {
            VersionValue::Value(MergeOperand::CounterDelta(i64::from(*b)).encode().into())
        }
        (Gen::Merge(d), true) => {
            VersionValue::MergeOperand(MergeOperand::CounterDelta(i64::from(*d)).encode().into())
        }
        (Gen::Merge(_), false) | (Gen::Tombstone, _) => VersionValue::Tombstone,
    }
}

const KEYS: [&[u8]; 5] = [b"k1", b"k2", b"k22", b"k3", b"k4"];

/// Every read the threshold must not change: each key at every timestamp from the threshold
/// up to past the newest version, and a full scan at each of them.
fn snapshot_reads(engine: &LsmEngine, gc: &GcThreshold, from: u64) -> BTreeMap<u64, String> {
    let reader = MvccReader::new(engine, Some(gc));
    let mut out = BTreeMap::new();
    for wall in from..=42 {
        let opts = ReadOptions::at(ts(wall));
        let gets: Vec<_> = KEYS.iter().map(|k| reader.get(k, &opts).unwrap()).collect();
        let scan = reader.scan(b"", b"\xFF", &opts, usize::MAX).unwrap();
        out.insert(wall, format!("{gets:?} {scan:?}"));
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Reads at timestamps >= the threshold are identical before and after GC (filter during
    /// flushes and compactions, then the explicit GC batch), and reads below it fail.
    #[test]
    fn tc_txn_036_gc_filter_keeps_visible_versions(
        keys in prop::collection::vec(
            (any::<bool>(), prop::collection::btree_map(1u64..40, gen_val(), 0..12)),
            KEYS.len(),
        ),
        rounds in 1usize..4,
        threshold_wall in 1u64..42,
    ) {
        let (engine, threshold) = gc_engine();
        // Write the versions in `rounds` batches (each key's in ascending timestamp order),
        // flushing after each so they spread over L0 and deeper levels.
        let mut queued: Vec<Vec<(u64, VersionValue)>> = keys
            .iter()
            .map(|(counter, vs)| vs.iter().map(|(w, g)| (*w, version(g, *counter))).collect())
            .collect();
        for round in 0..rounds {
            let mut w = MvccWriter::new(&engine, Some(&threshold));
            for (key, versions) in KEYS.iter().zip(&mut queued) {
                let take = if round + 1 == rounds { versions.len() } else { versions.len() / 2 };
                for (wall, value) in versions.drain(..take) {
                    w.put_version(key, ts(wall), &value).unwrap();
                }
            }
            w.commit().unwrap();
            engine.flush().unwrap();
            engine.compact().unwrap();
        }
        let before = snapshot_reads(&engine, &threshold, threshold_wall);

        threshold.advance(ts(threshold_wall));
        // Unrelated writes make the next compactions rewrite the data with the new threshold.
        let mut w = MvccWriter::new(&engine, Some(&threshold));
        // (Outside the scanned span and above every threshold.)
        w.put_version(b"\xFF\x01", ts(100), &VersionValue::Tombstone).unwrap();
        w.commit().unwrap();
        engine.flush().unwrap();
        engine.compact().unwrap();
        let after_filter = snapshot_reads(&engine, &threshold, threshold_wall);
        prop_assert_eq!(&before, &after_filter);

        let batch = gc_batch(&engine, &threshold, b"", b"\xFF").unwrap();
        engine.write(&batch).unwrap();
        engine.flush().unwrap();
        engine.compact().unwrap();
        let after_gc = snapshot_reads(&engine, &threshold, threshold_wall);
        prop_assert_eq!(&before, &after_gc);

        // Below the threshold: RGN-2007.
        let reader = MvccReader::new(&engine, Some(&threshold));
        let below = Timestamp::new(threshold_wall - 1, u32::MAX);
        let below_gc = matches!(
            reader.get(KEYS[0], &ReadOptions::at(below)),
            Err(MvccError::BelowGcThreshold { .. })
        );
        prop_assert!(below_gc);
        // After the GC batch exactly the needed versions remain: everything above the
        // threshold, then (newest first) operands down to the newest base <= threshold, which
        // stays unless it is a tombstone.
        for (key, (counter, vs)) in KEYS.iter().zip(&keys) {
            let mut expected = Vec::new();
            for (&wall, g) in vs.iter().rev() {
                if wall > threshold_wall {
                    expected.push(wall);
                    continue;
                }
                match version(g, *counter) {
                    VersionValue::MergeOperand(_) => expected.push(wall),
                    VersionValue::Value(_) => {
                        expected.push(wall);
                        break;
                    }
                    VersionValue::Tombstone => break,
                }
            }
            prop_assert_eq!(versions_of(&engine, key), expected, "key {:?}", key);
        }
    }
}
