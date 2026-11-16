// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! External SST ingestion helpers (storage-engine.md §12): bulk import (ADR-023), Raft snapshot
//! application and restore hand the engine SSTs written by [`SstWriter`].
//!
//! Every entry of an ingested file gets one *global seqno* `G`, newer than everything in the
//! store, so snapshots taken before the ingest do not see it and compaction orders it correctly.
//! Hence an external file may hold at most one entry per user key.
//!
//! The file is placed at the deepest level `L` such that no file in L0..=L (nor the output of a
//! running compaction into those levels) overlaps its key range: every version above it is then
//! newer, which is the source-ordering invariant reads rely on (`read.rs`). Overlapping memtable
//! data must be flushed first (the engine does it).

use std::path::Path;

use rustegon_sim_api::{FileSystem, OpenMode};

use crate::{
    error::{Result, StorageError},
    iter::InternalIterator,
    key::{InternalKey, ParsedKey, SeqNo},
    range_del::RangeTombstone,
    sst::{SstInfo, SstReader, SstReaderOptions, SstWriter, SstWriterOptions},
    version::{NUM_LEVELS, Version},
};

/// Copies the external SST `src` to `dst` with every entry and range tombstone at `seqno`.
///
// shortcut: the data is rewritten (one sequential copy) instead of recording a global seqno in
// the MANIFEST and substituting it in the reader; upgrade when bulk-import / snapshot-apply
// benchmarks (BM-STO, M5 Raft snapshots) show the copy matters.
///
/// # Errors
/// [`StorageError::InvalidArgument`] if the file holds two entries for one user key, or no
/// entries at all; corruption and I/O errors. A partial `dst` is left for the caller to remove.
pub fn rewrite_with_seqno(
    fs: &dyn FileSystem,
    src: &Path,
    dst: &Path,
    dst_number: u64,
    seqno: SeqNo,
    writer_options: &SstWriterOptions,
    reader_options: &SstReaderOptions,
) -> Result<SstInfo> {
    // External files are plaintext (written outside the store); the copy is encrypted with a
    // fresh DEK of `dst_number` when the store is (§7).
    let reader = SstReader::open(fs.open(src, OpenMode::Read)?, reader_options.clone())?;
    let file = fs.open(dst, OpenMode::CreateNew)?;
    let mut writer = SstWriter::create(file, dst_number, writer_options.clone())?;
    let mut it = reader.new_iterator();
    it.seek_to_first()?;
    let mut previous: Option<Vec<u8>> = None;
    while it.valid() {
        let parsed = ParsedKey::parse(it.key())
            .map_err(|e| StorageError::corruption(format!("ingested key: {e}")))?;
        if previous.as_deref() == Some(parsed.user_key) {
            return Err(StorageError::InvalidArgument(format!(
                "ingested file {} holds several versions of one key",
                src.display()
            )));
        }
        writer.add(
            InternalKey::new(parsed.user_key, seqno, parsed.kind).as_bytes(),
            &it.value(),
        )?;
        previous = Some(parsed.user_key.to_vec());
        InternalIterator::next(&mut it)?;
    }
    for t in reader.range_tombstones() {
        writer.add_range_tombstone(RangeTombstone { seqno, ..t.clone() })?;
    }
    if previous.is_none() && reader.range_tombstones().is_empty() {
        return Err(StorageError::InvalidArgument(format!(
            "ingested file {} is empty",
            src.display()
        )));
    }
    writer.finish()
}

/// User-key range `[lo, hi]` (inclusive) of the files being ingested and of running compactions.
pub type KeyRange = (Vec<u8>, Vec<u8>);

/// Deepest level for a file spanning `range` (see module docs). `running` lists the output
/// level and key range of every running compaction.
#[must_use]
pub fn pick_level(version: &Version, range: &KeyRange, running: &[(usize, KeyRange)]) -> usize {
    let overlaps = |level: usize| {
        let (lo, hi) = (range.0.as_slice(), range.1.as_slice());
        version
            .files(level)
            .iter()
            .any(|f| f.smallest.user_key() <= hi && f.largest.user_key() >= lo)
            || running
                .iter()
                .any(|(l, (rlo, rhi))| *l == level && rlo.as_slice() <= hi && rhi.as_slice() >= lo)
    };
    if overlaps(0) {
        return 0;
    }
    let mut level = 0;
    for candidate in 1..NUM_LEVELS {
        if overlaps(candidate) {
            break;
        }
        level = candidate;
    }
    level
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(lo: &str, hi: &str) -> KeyRange {
        (lo.as_bytes().to_vec(), hi.as_bytes().to_vec())
    }

    #[test]
    fn ingest_goes_to_the_deepest_level_without_overlap_above() {
        let empty = Version::default();
        assert_eq!(pick_level(&empty, &range("a", "z"), &[]), NUM_LEVELS - 1);

        let v = Version::for_test_ranges(&[(3, 10, "m", "p"), (6, 10, "a", "z")]);
        assert_eq!(pick_level(&v, &range("n", "o"), &[]), 2, "stops above L3");
        assert_eq!(pick_level(&v, &range("b", "c"), &[]), 5, "L6 overlaps");

        let l0 = Version::for_test_ranges(&[(0, 10, "a", "c")]);
        assert_eq!(pick_level(&l0, &range("b", "b"), &[]), 0);

        // A running compaction writing [m, p] into L4 blocks L4 for an overlapping file.
        let running = [(4, range("m", "p"))];
        assert_eq!(pick_level(&empty, &range("o", "q"), &running), 3);
    }
}
