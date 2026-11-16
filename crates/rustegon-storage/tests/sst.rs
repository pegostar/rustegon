// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! SST writer/reader integration tests (storage-engine.md §4, §15): model-based round trip,
//! filter behaviour and TC-STO-003 corruption detection.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::BTreeMap, io, path::Path, sync::Arc};

use proptest::prelude::*;
use rustegon_sim_api::{File, FileSystem, OpenMode, StdFileSystem};
use rustegon_storage::{
    InternalKey, MAX_SEQNO, StorageError, ValueKind,
    key::{compare_internal, seek_key},
    sst::{
        FilterPolicy, FullKeyExtractor, PrefixExtractor, SstEntry, SstInfo, SstReader,
        SstReaderOptions, SstWriter, SstWriterOptions,
    },
};

/// Small blocks and partitions so that even small inputs span many data blocks and several
/// index partitions.
fn tiny_options() -> SstWriterOptions {
    SstWriterOptions {
        block_size: 128,
        restart_interval: 4,
        index_partition_size: 64,
        ..SstWriterOptions::default()
    }
}

fn write(path: &Path, entries: &[(InternalKey, Vec<u8>)], options: SstWriterOptions) -> SstInfo {
    let file = StdFileSystem.open(path, OpenMode::CreateNew).unwrap();
    let mut w = SstWriter::new(file, options);
    for (k, v) in entries {
        w.add(k.as_bytes(), v).unwrap();
    }
    w.finish().unwrap()
}

fn open(path: &Path) -> Result<SstReader, StorageError> {
    SstReader::open(
        StdFileSystem.open(path, OpenMode::Read)?,
        SstReaderOptions::default(),
    )
}

type Entries = Vec<(Vec<u8>, Vec<u8>)>;

fn scan(reader: &SstReader) -> Result<Entries, StorageError> {
    let mut it = reader.new_iterator();
    it.seek_to_first()?;
    let mut out = Vec::new();
    while it.valid() {
        out.push((it.key().to_vec(), it.value().to_vec()));
        it.next()?;
    }
    Ok(out)
}

/// Model: newest version of `user_key` with seqno <= snapshot.
fn model_get(
    entries: &BTreeMap<InternalKey, Vec<u8>>,
    user_key: &[u8],
    snapshot: u64,
) -> Option<SstEntry> {
    entries
        .iter()
        .find(|(k, _)| k.user_key() == user_key && k.seqno() <= snapshot)
        .map(|(k, v)| SstEntry {
            seqno: k.seqno(),
            kind: k.kind(),
            value: v.clone().into(),
        })
}

fn arb_kind() -> impl Strategy<Value = ValueKind> {
    prop_oneof![
        4 => Just(ValueKind::Put),
        1 => Just(ValueKind::Delete),
        1 => Just(ValueKind::Merge),
        1 => Just(ValueKind::SingleDelete),
    ]
}

fn arb_entries() -> impl Strategy<Value = BTreeMap<InternalKey, Vec<u8>>> {
    prop::collection::vec(
        (
            prop::collection::vec(b'a'..=b'e', 0..6),
            0u64..50,
            arb_kind(),
            prop::collection::vec(any::<u8>(), 0..40),
        ),
        0..300,
    )
    .prop_map(|raw| {
        raw.into_iter()
            .map(|(k, seq, kind, v)| (InternalKey::new(&k, seq, kind), v))
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Round trip against a `BTreeMap` model: full scan, seeks and snapshot point reads.
    #[test]
    fn sst_round_trip_matches_model(
        entries in arb_entries(),
        probes in prop::collection::vec((prop::collection::vec(b'a'..=b'f', 0..6), 0u64..60), 30),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000001.sst");
        let list: Vec<_> = entries.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let info = write(&path, &list, tiny_options());
        prop_assert_eq!(info.properties.entries, list.len() as u64);
        prop_assert_eq!(info.smallest.as_ref(), entries.keys().next());
        prop_assert_eq!(info.largest.as_ref(), entries.keys().next_back());

        let reader = open(&path).unwrap();
        let expected: Vec<_> =
            list.iter().map(|(k, v)| (k.as_bytes().to_vec(), v.clone())).collect();
        prop_assert_eq!(scan(&reader).unwrap(), expected);

        for (user_key, snapshot) in probes {
            prop_assert_eq!(
                reader.get(&user_key, snapshot).unwrap(),
                model_get(&entries, &user_key, snapshot)
            );
            let target = seek_key(&user_key, snapshot);
            let mut it = reader.new_iterator();
            it.seek(&target).unwrap();
            let want = entries
                .keys()
                .find(|k| compare_internal(k.as_bytes(), &target).is_ge())
                .map(|k| k.as_bytes().to_vec());
            let got = it.valid().then(|| it.key().to_vec());
            prop_assert_eq!(got, want);
        }
    }
}

#[test]
fn sst_large_file_uses_filter_and_partitioned_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("000002.sst");
    let n = 50_000u64;
    let entries: Vec<_> = (0..n)
        .map(|i| {
            let key = format!("user{i:08}");
            (
                InternalKey::new(key.as_bytes(), i + 1, ValueKind::Put),
                vec![b'v'; 100],
            )
        })
        .collect();
    let info = write(&path, &entries, SstWriterOptions::default());
    let props = &info.properties;
    assert_eq!(props.entries, n);
    assert_eq!((props.min_seqno, props.max_seqno), (1, n));
    assert!(props.data_blocks > 300, "data blocks {}", props.data_blocks);
    assert!(
        props.index_partitions > 1,
        "partitions {}",
        props.index_partitions
    );
    assert_eq!(props.filter_prefix_extractor, FullKeyExtractor.name());

    let reader = open(&path).unwrap();
    assert!(reader.has_filter());
    for i in (0..n).step_by(97) {
        let key = format!("user{i:08}");
        let got = reader.get(key.as_bytes(), MAX_SEQNO).unwrap().unwrap();
        assert_eq!((got.seqno, got.kind), (i + 1, ValueKind::Put));
        // Snapshot older than the only version: invisible.
        assert_eq!(reader.get(key.as_bytes(), i).unwrap(), None);
    }
    let passed = (0..10_000)
        .filter(|i| reader.may_contain_prefix(format!("absent{i}").as_bytes()))
        .count();
    assert!(passed < 300, "filter passed {passed} of 10000 absent keys");
    assert_eq!(scan(&reader).unwrap().len(), entries.len());
}

#[test]
fn sst_reader_with_other_extractor_ignores_filter() {
    #[derive(Debug)]
    struct FirstByte;
    impl PrefixExtractor for FirstByte {
        fn name(&self) -> &'static str {
            "test.first_byte"
        }
        fn prefix<'a>(&self, user_key: &'a [u8]) -> &'a [u8] {
            &user_key[..user_key.len().min(1)]
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("000003.sst");
    let entries = vec![(InternalKey::new(b"abc", 1, ValueKind::Put), b"x".to_vec())];
    write(&path, &entries, SstWriterOptions::default());
    let file = StdFileSystem.open(&path, OpenMode::Read).unwrap();
    let options = SstReaderOptions {
        prefix_extractor: Arc::new(FirstByte),
        ..SstReaderOptions::default()
    };
    let reader = SstReader::open(file, options).unwrap();
    assert!(!reader.has_filter());
    assert!(reader.get(b"abc", MAX_SEQNO).unwrap().is_some());
}

#[test]
fn sst_without_filter_and_empty_sst_are_readable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("000004.sst");
    let options = SstWriterOptions {
        filter: FilterPolicy::Disabled,
        ..SstWriterOptions::default()
    };
    let info = write(&path, &[], options);
    assert!(info.smallest.is_none() && info.largest.is_none());
    let reader = open(&path).unwrap();
    assert!(!reader.has_filter());
    assert_eq!(scan(&reader).unwrap(), Entries::new());
    assert_eq!(reader.get(b"k", MAX_SEQNO).unwrap(), None);
    let mut it = reader.new_iterator();
    it.seek(&seek_key(b"k", MAX_SEQNO)).unwrap();
    assert!(!it.valid());
}

#[test]
fn sst_writer_rejects_misordered_and_malformed_keys() {
    let dir = tempfile::tempdir().unwrap();
    let file = StdFileSystem
        .open(&dir.path().join("000005.sst"), OpenMode::CreateNew)
        .unwrap();
    let mut w = SstWriter::new(file, SstWriterOptions::default());
    w.add(InternalKey::new(b"b", 5, ValueKind::Put).as_bytes(), b"")
        .unwrap();
    for bad in [
        InternalKey::new(b"a", 9, ValueKind::Put),
        InternalKey::new(b"b", 5, ValueKind::Put),
        InternalKey::new(b"b", 6, ValueKind::Put),
    ] {
        let err = w.add(bad.as_bytes(), b"").unwrap_err();
        assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
    }
    assert!(matches!(
        w.add(b"short", b""),
        Err(StorageError::InvalidArgument(_))
    ));
    // An older version of the same key sorts after the newer one: accepted.
    w.add(InternalKey::new(b"b", 4, ValueKind::Delete).as_bytes(), b"")
        .unwrap();
    assert_eq!(w.finish().unwrap().properties.deletions, 1);
}

/// TC-STO-003: every single-bit flip anywhere in an SST is detected as corruption when the file
/// is opened and fully read (all bytes are covered by a block or footer checksum).
#[test]
fn tc_sto_003_every_bit_flip_in_sst_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("000006.sst");
    let entries: Vec<_> = (0..40u64)
        .map(|i| {
            (
                InternalKey::new(format!("k{i:03}").as_bytes(), i, ValueKind::Put),
                format!("value-{i}").into_bytes(),
            )
        })
        .collect();
    write(&path, &entries, tiny_options());
    let original = read_all(&path);
    // Sanity: the in-memory copy of the intact file reads back completely.
    let intact = SstReader::open(
        Box::new(MemFile(original.clone())),
        SstReaderOptions::default(),
    );
    assert_eq!(scan(&intact.unwrap()).unwrap().len(), entries.len());
    for at in 0..original.len() {
        // One bit per byte position, rotating through bit indexes to cover all of them.
        let mut bytes = original.clone();
        bytes[at] ^= 1 << (at % 8);
        let reader = SstReader::open(Box::new(MemFile(bytes)), SstReaderOptions::default());
        match reader.and_then(|r| scan(&r)) {
            Err(StorageError::Corruption(_)) => {}
            other => panic!(
                "flip at byte {at} not detected: {:?}",
                other.map(|v| v.len())
            ),
        }
    }
}

#[test]
fn tc_sto_003_truncated_and_foreign_files_are_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("000007.sst");
    let entries = vec![(InternalKey::new(b"k", 1, ValueKind::Put), b"v".to_vec())];
    write(&path, &entries, SstWriterOptions::default());
    let original = read_all(&path);
    let bad_path = dir.path().join("bad.sst");
    for len in [0, 10, original.len() / 2, original.len() - 1] {
        rewrite(&bad_path, &original[..len]);
        assert!(
            matches!(open(&bad_path), Err(StorageError::Corruption(_))),
            "truncation to {len} not detected"
        );
    }
    rewrite(&bad_path, &[0x42; 4096]);
    assert!(matches!(open(&bad_path), Err(StorageError::Corruption(_))));
}

/// In-memory file so that the exhaustive corruption test does not rewrite a disk file per flip.
struct MemFile(Vec<u8>);

impl File for MemFile {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let src = self
            .0
            .get(start..start + buf.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.extend_from_slice(buf);
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
}

fn read_all(path: &Path) -> Vec<u8> {
    let f = StdFileSystem.open(path, OpenMode::Read).unwrap();
    let mut buf = vec![0u8; usize::try_from(f.size().unwrap()).unwrap()];
    f.read_exact_at(&mut buf, 0).unwrap();
    buf
}

fn rewrite(path: &Path, bytes: &[u8]) {
    let mut f = StdFileSystem.open(path, OpenMode::Truncate).unwrap();
    f.append(bytes).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// M1 T6: reverse scan is the forward scan backwards (across data blocks and index
    /// partitions), and any interleaving of `next`/`prev` after a seek matches the model.
    #[test]
    fn sst_reverse_and_mixed_direction_match_model(
        entries in arb_entries(),
        probe in (prop::collection::vec(b'a'..=b'f', 0..6), 0u64..60),
        moves in prop::collection::vec(any::<bool>(), 0..80),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000001.sst");
        let list: Vec<_> = entries.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        write(&path, &list, tiny_options());
        let reader = open(&path).unwrap();
        let forward = scan(&reader).unwrap();

        let mut it = reader.new_iterator();
        it.seek_to_last().unwrap();
        let mut backward = Vec::new();
        while it.valid() {
            backward.push((it.key().to_vec(), it.value().to_vec()));
            it.prev().unwrap();
        }
        backward.reverse();
        prop_assert_eq!(&backward, &forward);

        let target = seek_key(&probe.0, probe.1);
        let mut pos = forward.partition_point(|(k, _)| compare_internal(k, &target).is_lt());
        it.seek(&target).unwrap();
        for step_forward in moves {
            if pos >= forward.len() {
                prop_assert!(!it.valid());
                break;
            }
            prop_assert_eq!(it.key(), forward[pos].0.as_slice());
            if step_forward {
                it.next().unwrap();
                pos += 1;
            } else if pos == 0 {
                it.prev().unwrap();
                prop_assert!(!it.valid());
                break;
            } else {
                it.prev().unwrap();
                pos -= 1;
            }
        }
    }
}

/// M1 T10: range tombstones round-trip through the range-del block, a file may hold only
/// tombstones, and the file bounds and seqno range cover them.
#[test]
fn sst_range_tombstones_round_trip_and_extend_bounds() {
    use rustegon_storage::range_del::RangeTombstone;

    let dir = tempfile::tempdir().unwrap();
    let t = |s: &str, e: &str, seqno| RangeTombstone {
        start: s.as_bytes().to_vec(),
        end: e.as_bytes().to_vec(),
        seqno,
    };
    let path = dir.path().join("000001.sst");
    let file = StdFileSystem.open(&path, OpenMode::CreateNew).unwrap();
    let mut w = SstWriter::new(file, tiny_options());
    w.add(InternalKey::new(b"m", 5, ValueKind::Put).as_bytes(), b"v")
        .unwrap();
    w.add_range_tombstone(t("q", "t", 9)).unwrap();
    w.add_range_tombstone(t("a", "c", 2)).unwrap();
    assert!(
        w.add_range_tombstone(t("x", "x", 3)).is_err(),
        "empty range"
    );
    assert!(
        w.add(
            InternalKey::new(b"n", 6, ValueKind::RangeDelete).as_bytes(),
            b"z"
        )
        .is_err(),
        "range deletes are not point entries"
    );
    let info = w.finish().unwrap();
    assert_eq!(info.smallest.as_ref().unwrap().user_key(), b"a");
    assert_eq!(info.largest.as_ref().unwrap().user_key(), b"t");
    assert_eq!(
        (info.properties.min_seqno, info.properties.max_seqno),
        (2, 9)
    );
    let reader = open(&path).unwrap();
    assert_eq!(reader.range_tombstones(), [t("a", "c", 2), t("q", "t", 9)]);
    assert_eq!(scan(&reader).unwrap().len(), 1);

    let only = dir.path().join("000002.sst");
    let file = StdFileSystem.open(&only, OpenMode::CreateNew).unwrap();
    let mut w = SstWriter::new(file, tiny_options());
    w.add_range_tombstone(t("k", "p", 4)).unwrap();
    let info = w.finish().unwrap();
    assert!(info.smallest.is_some() && info.largest.is_some());
    assert_eq!(info.properties.max_seqno, 4);
    assert_eq!(open(&only).unwrap().range_tombstones(), [t("k", "p", 4)]);
}
