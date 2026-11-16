// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Block cache integration with the SST reader (storage-engine.md §5): a cached reader returns
//! exactly what an uncached one does, hits the cache on repeated reads and stays within its
//! capacity, also when shared by concurrent readers.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{path::Path, sync::Arc};

use proptest::prelude::*;
use rustegon_common::settings::{Registry, Sources};
use rustegon_sim_api::{FileSystem, OpenMode, StdFileSystem};
use rustegon_storage::{
    BlockCache, InternalKey, MAX_SEQNO, StorageError, ValueKind,
    cache::SHARD_COUNT,
    settings::StorageSettings,
    sst::{SstReader, SstReaderOptions, SstWriter, SstWriterOptions},
};

/// Small blocks and partitions so that the file has many data blocks and index partitions.
fn tiny_options() -> SstWriterOptions {
    SstWriterOptions {
        block_size: 256,
        restart_interval: 4,
        index_partition_size: 64,
        ..SstWriterOptions::default()
    }
}

fn write(path: &Path, n: u64) {
    let file = StdFileSystem.open(path, OpenMode::CreateNew).unwrap();
    let mut w = SstWriter::new(file, tiny_options());
    for i in 0..n {
        let key = InternalKey::new(format!("k{i:06}").as_bytes(), i + 1, ValueKind::Put);
        w.add(key.as_bytes(), format!("value-{i}").as_bytes())
            .unwrap();
    }
    w.finish().unwrap();
}

fn open(path: &Path, cache: Option<Arc<BlockCache>>) -> SstReader {
    let options = SstReaderOptions {
        block_cache: cache,
        ..SstReaderOptions::default()
    };
    SstReader::open(StdFileSystem.open(path, OpenMode::Read).unwrap(), options).unwrap()
}

fn scan(reader: &SstReader) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut it = reader.new_iterator();
    it.seek_to_first().unwrap();
    let mut out = Vec::new();
    while it.valid() {
        out.push((it.key().to_vec(), it.value().to_vec()));
        it.next().unwrap();
    }
    out
}

const N: u64 = 2000;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    /// Gets and scans through a cache of any size (including one too small to hold a block,
    /// and sizes around one block per shard where eviction really happens) equal the uncached
    /// reader's results, and usage never exceeds the capacity.
    #[test]
    fn cached_reader_matches_uncached(
        capacity in prop_oneof![
            Just(0usize),
            1usize..64 << 10,
            // One to a few 256-byte blocks (plus bookkeeping) per shard.
            SHARD_COUNT * 256..SHARD_COUNT * 2048,
            Just(64usize << 20),
        ],
        probes in prop::collection::vec(0..N + 50, 1..200),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000001.sst");
        write(&path, N);
        let cache = Arc::new(BlockCache::new(capacity));
        let plain = open(&path, None);
        let cached = open(&path, Some(Arc::clone(&cache)));
        for round in 0..2 {
            for &i in &probes {
                let key = format!("k{i:06}");
                prop_assert_eq!(
                    cached.get(key.as_bytes(), MAX_SEQNO).unwrap(),
                    plain.get(key.as_bytes(), MAX_SEQNO).unwrap(),
                    "round {}", round
                );
            }
            prop_assert_eq!(scan(&cached), scan(&plain));
            prop_assert!(cache.stats().usage <= capacity);
        }
    }
}

#[test]
fn repeated_reads_hit_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("000001.sst");
    write(&path, N);
    let cache = Arc::new(BlockCache::new(64 << 20));
    let reader = open(&path, Some(Arc::clone(&cache)));
    assert!(reader.get(b"k000100", MAX_SEQNO).unwrap().is_some());
    let first = cache.stats();
    // Cold cache: the index partition and the data block were both missed.
    assert_eq!((first.hits, first.misses), (0, 2));
    assert!(first.usage > 0);
    assert!(reader.get(b"k000100", MAX_SEQNO).unwrap().is_some());
    let second = cache.stats();
    assert_eq!((second.hits, second.misses), (2, 2));
    assert_eq!(second.usage, first.usage);
}

#[test]
fn readers_of_different_files_do_not_share_entries() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a.sst"), dir.path().join("b.sst"));
    write(&a, N);
    write(&b, N / 2);
    let cache = Arc::new(BlockCache::new(64 << 20));
    let ra = open(&a, Some(Arc::clone(&cache)));
    let rb = open(&b, Some(Arc::clone(&cache)));
    // Same offsets in both files, different contents: each reader must see its own file.
    assert_eq!(scan(&ra), scan(&open(&a, None)));
    assert_eq!(scan(&rb), scan(&open(&b, None)));
    assert_eq!(scan(&ra), scan(&open(&a, None)));
}

#[test]
fn concurrent_readers_share_one_cache() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("000001.sst");
    write(&path, N);
    // Small enough to force eviction while the threads read.
    let capacity = 32 << 10;
    let cache = Arc::new(BlockCache::new(capacity));
    let reader = open(&path, Some(Arc::clone(&cache)));
    let threads: Vec<_> = (0..8u64)
        .map(|t| {
            let reader = reader.clone();
            std::thread::spawn(move || {
                for j in 0..500 {
                    let i = (t * 7919 + j * 104_729) % N;
                    let got = reader
                        .get(format!("k{i:06}").as_bytes(), MAX_SEQNO)
                        .unwrap()
                        .unwrap();
                    assert_eq!(got.value.as_ref(), format!("value-{i}").as_bytes());
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let stats = cache.stats();
    assert!(stats.usage <= capacity);
    // At least one lookup per get (the data block); index partitions add more unless the
    // reader's layout changes, so do not pin the exact count.
    assert!(stats.hits + stats.misses >= 8 * 500);
}

/// A block that fails its checksum is never inserted: every read of it re-reads the file and
/// errors again, and the cache charges nothing for it.
#[test]
fn corrupted_block_is_never_cached() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("000001.sst");
    write(&path, N);
    let mut bytes = {
        let f = StdFileSystem.open(&path, OpenMode::Read).unwrap();
        let mut buf = vec![0u8; usize::try_from(f.size().unwrap()).unwrap()];
        f.read_exact_at(&mut buf, 0).unwrap();
        buf
    };
    // Offset 10 lies in the first data block (blocks are 256 bytes), which holds k000000;
    // the pinned top-level index and filter sit at the end of the file and stay intact.
    bytes[10] ^= 0x40;
    let corrupted = dir.path().join("000002.sst");
    StdFileSystem
        .open(&corrupted, OpenMode::CreateNew)
        .unwrap()
        .append(&bytes)
        .unwrap();
    let cache = Arc::new(BlockCache::new(64 << 20));
    let reader = open(&corrupted, Some(Arc::clone(&cache)));
    let err = reader.get(b"k000000", MAX_SEQNO).unwrap_err();
    assert!(matches!(err, StorageError::Corruption(_)), "{err:?}");
    let first = cache.stats();
    let err = reader.get(b"k000000", MAX_SEQNO).unwrap_err();
    assert!(matches!(err, StorageError::Corruption(_)), "{err:?}");
    let second = cache.stats();
    // Whatever index blocks the reader looks up were cached by the first get; only the
    // corrupted data block misses again, and the repeat adds no charge. Had the block been
    // cached, the second get would hit it (no new miss) and return its contents.
    assert_eq!(second.misses, first.misses + 1);
    assert_eq!(second.usage, first.usage);
    assert_eq!(second.rejected_oversize, 0);
}

/// The smallest `block_cache_size` the configuration accepts really caches data blocks and
/// index partitions, including blocks that overshoot their target by a large last entry:
/// nothing is rejected as oversize. One byte less is a load error. Run for a block size below
/// and above the 4 KiB index partition target.
#[test]
fn minimum_configured_cache_caches_data_blocks() {
    for block_size in [1024usize, 8192] {
        check_minimum_cache(block_size);
    }
}

fn check_minimum_cache(block_size: usize) {
    // 64 shards * (2 * max(block, index partition) + 96 bytes of per-entry bookkeeping).
    let min_cache = SHARD_COUNT * (2 * block_size.max(4096) + 96);
    let mut registry = Registry::new();
    registry.register::<StorageSettings>().unwrap();
    let load = |cache_size: usize| {
        registry.load(&Sources {
            flags: vec![
                format!("storage.block_size={block_size}"),
                format!("storage.block_cache_size={cache_size}"),
            ],
            ..Sources::default()
        })
    };
    assert!(load(min_cache - 1).is_err());
    let settings: StorageSettings = load(min_cache).unwrap().section().unwrap();
    let cache = BlockCache::from_settings(&settings).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("000001.sst");
    let file = StdFileSystem.open(&path, OpenMode::CreateNew).unwrap();
    let mut w = SstWriter::new(file, SstWriterOptions::from_settings(&settings));
    // Values just under the block size: a block is cut only after its second entry, near
    // 2 x block_size.
    let value = vec![b'v'; block_size - 100];
    for i in 0..200u64 {
        let key = InternalKey::new(format!("k{i:06}").as_bytes(), i + 1, ValueKind::Put);
        w.add(key.as_bytes(), &value).unwrap();
    }
    w.finish().unwrap();

    let reader = open(&path, Some(Arc::clone(&cache)));
    for i in (0..200u64).step_by(7) {
        assert!(
            reader
                .get(format!("k{i:06}").as_bytes(), MAX_SEQNO)
                .unwrap()
                .is_some()
        );
    }
    let stats = cache.stats();
    assert!(stats.usage > 0);
    assert_eq!(stats.rejected_oversize, 0, "block_size {block_size}");
}
