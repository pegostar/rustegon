// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! SST block compression integration tests (FR-CMP-001, storage-engine.md §6, TC-CMP-001…004):
//! round trip per codec through real files, incompressible-block fallback, corruption of
//! compressed blocks and compression ratio reporting.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    io,
    path::Path,
    sync::{Arc, Mutex},
};

use proptest::prelude::*;
use rustegon_sim_api::{File, FileSystem, OpenMode, StdFileSystem};
use rustegon_storage::{
    InternalKey, StorageError, ValueKind,
    sst::{
        CompressionPolicy, DEFAULT_ZSTD_LEVEL, SstInfo, SstReader, SstReaderOptions, SstWriter,
        SstWriterOptions,
    },
};

const CODECS: [CompressionPolicy; 3] = [
    CompressionPolicy::None,
    CompressionPolicy::Lz4,
    CompressionPolicy::Zstd {
        level: DEFAULT_ZSTD_LEVEL,
    },
];

type Entries = Vec<(Vec<u8>, Vec<u8>)>;

fn options(compression: CompressionPolicy, block_size: usize) -> SstWriterOptions {
    SstWriterOptions {
        block_size,
        compression,
        ..SstWriterOptions::default()
    }
}

fn write_to(
    file: Box<dyn File>,
    entries: &[(InternalKey, Vec<u8>)],
    o: SstWriterOptions,
) -> SstInfo {
    let mut w = SstWriter::new(file, o);
    for (k, v) in entries {
        w.add(k.as_bytes(), v).unwrap();
    }
    w.finish().unwrap()
}

/// Writes into memory and returns the info and the file bytes.
fn write_mem(entries: &[(InternalKey, Vec<u8>)], o: SstWriterOptions) -> (SstInfo, Vec<u8>) {
    let shared = Arc::new(Mutex::new(Vec::new()));
    let info = write_to(Box::new(MemFile(Arc::clone(&shared))), entries, o);
    let bytes = std::mem::take(&mut *shared.lock().unwrap());
    (info, bytes)
}

fn open_mem(bytes: Vec<u8>) -> Result<SstReader, StorageError> {
    SstReader::open(
        Box::new(MemFile(Arc::new(Mutex::new(bytes)))),
        SstReaderOptions::default(),
    )
}

fn write(path: &Path, entries: &[(InternalKey, Vec<u8>)], o: SstWriterOptions) -> SstInfo {
    write_to(
        StdFileSystem.open(path, OpenMode::CreateNew).unwrap(),
        entries,
        o,
    )
}

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

fn expected(entries: &[(InternalKey, Vec<u8>)]) -> Entries {
    entries
        .iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), v.clone()))
        .collect()
}

/// Deterministic incompressible bytes (xorshift64).
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Compressible document-like values.
fn doc_entries(n: u64) -> Vec<(InternalKey, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let value =
                format!(r#"{{"_id":{i},"name":"user-{i}","tags":["a","b","c"],"active":true}}"#);
            (
                InternalKey::new(format!("doc/{i:06}").as_bytes(), i + 1, ValueKind::Put),
                value.into_bytes(),
            )
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// TC-CMP-001: every codec round-trips arbitrary content through a real file.
    #[test]
    fn tc_cmp_001_file_round_trip_per_codec(
        values in prop::collection::vec((any::<u8>(), 0usize..300, any::<bool>()), 0..120),
    ) {
        // Mix of repetitive (compressible) and noisy values.
        let entries: Vec<_> = values
            .iter()
            .enumerate()
            .map(|(i, &(byte, len, noisy))| {
                let v = if noisy { noise(i as u64 + 1, len) } else { vec![byte; len] };
                (InternalKey::new(format!("k{i:04}").as_bytes(), 1, ValueKind::Put), v)
            })
            .collect();
        for policy in CODECS {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("000001.sst");
            write(&path, &entries, options(policy, 512));
            let reader = SstReader::open(
                StdFileSystem.open(&path, OpenMode::Read).unwrap(),
                SstReaderOptions::default(),
            )
            .unwrap();
            prop_assert_eq!(scan(&reader).unwrap(), expected(&entries));
        }
    }
}

/// TC-CMP-002: incompressible blocks are stored raw while compressible blocks of the same file
/// are compressed; the mixed file reads back intact.
#[test]
fn tc_cmp_002_incompressible_blocks_fall_back_to_raw() {
    // Each value fills a block on its own; even indexes are noise.
    let entries: Vec<_> = (0..20u64)
        .map(|i| {
            let v = if i % 2 == 0 {
                noise(i + 1, 4096)
            } else {
                b"compressible ".repeat(300)
            };
            (
                InternalKey::new(format!("k{i:02}").as_bytes(), 1, ValueKind::Put),
                v,
            )
        })
        .collect();
    for policy in &CODECS[1..] {
        let (info, bytes) = write_mem(&entries, options(*policy, 1024));
        assert_eq!(info.properties.data_blocks, 20, "{policy:?}");
        assert_eq!(info.properties.data_compressed_blocks, 10, "{policy:?}");
        assert_eq!(scan(&open_mem(bytes).unwrap()).unwrap(), expected(&entries));
    }
}

/// TC-CMP-002 (incompressible-run skip, PD-025): after a long run of incompressible blocks the
/// writer stops offering every block to the codec, and compressible data that follows is
/// compressed again within 16 blocks; the file reads back exactly.
#[test]
fn tc_cmp_002_compression_resumes_after_an_incompressible_run() {
    // One value per block: 40 noise blocks, then 40 compressible ones.
    let entries: Vec<_> = (0..80u64)
        .map(|i| {
            let v = if i < 40 {
                noise(i + 1, 4096)
            } else {
                b"compressible ".repeat(300)
            };
            (
                InternalKey::new(format!("k{i:02}").as_bytes(), 1, ValueKind::Put),
                v,
            )
        })
        .collect();
    for policy in &CODECS[1..] {
        let (info, bytes) = write_mem(&entries, options(*policy, 1024));
        assert_eq!(info.properties.data_blocks, 80, "{policy:?}");
        // Blocks 40..48 are skipped (the run is long), block 48 is a probe and resets it.
        assert_eq!(info.properties.data_compressed_blocks, 32, "{policy:?}");
        assert_eq!(scan(&open_mem(bytes).unwrap()).unwrap(), expected(&entries));
    }
}

/// TC-CMP-003: every single-bit flip in a file with compressed blocks is detected as corruption
/// (checksum over the stored bytes and the codec byte), never a panic or a wrong value.
#[test]
fn tc_cmp_003_bit_flips_in_compressed_sst_are_detected() {
    let entries = doc_entries(30);
    for policy in &CODECS[1..] {
        let (info, original) = write_mem(&entries, options(*policy, 512));
        assert!(info.properties.data_compressed_blocks > 0, "{policy:?}");
        for at in 0..original.len() {
            let mut bytes = original.clone();
            bytes[at] ^= 1 << (at % 8);
            match open_mem(bytes).and_then(|r| scan(&r)) {
                Err(StorageError::Corruption(_)) => {}
                other => panic!(
                    "{policy:?}: flip at {at} undetected: {:?}",
                    other.map(|v| v.len())
                ),
            }
        }
    }
}

/// TC-CMP-004: the compression ratio is reported in the SST properties and survives reopen.
#[test]
fn tc_cmp_004_compression_ratio_is_reported() {
    let entries = doc_entries(2000);
    let mut sizes = Vec::new();
    for policy in CODECS {
        let (info, bytes) = write_mem(&entries, options(policy, 16 << 10));
        let reader = open_mem(bytes).unwrap();
        let props = reader.properties();
        assert_eq!(props, &info.properties);
        assert!(props.data_raw_bytes > 0);
        if policy == CompressionPolicy::None {
            assert_eq!(props.data_compressed_blocks, 0);
            assert!(props.data_bytes >= props.data_raw_bytes);
        } else {
            assert_eq!(
                props.data_compressed_blocks, props.data_blocks,
                "{policy:?}"
            );
            // Repetitive JSON compresses well; the ratio is reportable as raw / stored.
            assert!(
                props.data_raw_bytes > 2 * props.data_bytes,
                "{policy:?}: {props:?}"
            );
        }
        sizes.push(props.data_bytes);
    }
    // Zstd beats LZ4 beats no compression on this data.
    assert!(sizes[2] < sizes[1] && sizes[1] < sizes[0], "{sizes:?}");
}

/// In-memory file shared between the writer and the test.
struct MemFile(Arc<Mutex<Vec<u8>>>);

impl File for MemFile {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let data = self.0.lock().map_err(|_| io::Error::other("poisoned"))?;
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let src = data
            .get(start..start + buf.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?
            .extend_from_slice(buf);
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self
            .0
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?
            .len() as u64)
    }
}
