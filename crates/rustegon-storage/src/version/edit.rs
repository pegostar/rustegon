// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Version edits: the records of the MANIFEST (storage-engine.md §2, §9).
//!
//! Payload encoding: `EDIT_FORMAT_VERSION (u8) ‖ field*`, each field `tag (varint) ‖ value`:
//!
//! | tag | field | value |
//! |---|---|---|
//! | 1 | next file number | varint |
//! | 2 | last seqno | varint |
//! | 3 | flushed seqno | varint |
//! | 4 | deleted file | level varint ‖ number varint |
//! | 5 | added file | level ‖ number ‖ size ‖ smallest (len-prefixed) ‖ largest (len-prefixed) ‖ smallest seqno ‖ largest seqno (all varints) |
//!
//! Unknown tags are corruption, not skipped: an edit we cannot fully apply must never be
//! half-applied, because a lost "added file" would let orphan cleanup delete live data.

use crate::{
    coding::{Reader, put_varint},
    error::{Result, StorageError},
    key::{InternalKey, SeqNo},
};

/// Number of LSM levels (L0..L6, storage-engine.md §3).
pub const NUM_LEVELS: usize = 7;

const EDIT_FORMAT_VERSION: u8 = 1;
const TAG_NEXT_FILE_NUMBER: u64 = 1;
const TAG_LAST_SEQNO: u64 = 2;
const TAG_FLUSHED_SEQNO: u64 = 3;
const TAG_DELETED_FILE: u64 = 4;
const TAG_ADDED_FILE: u64 = 5;

/// Metadata of one live SST, as recorded in the MANIFEST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// File number (`<number>.sst`).
    pub number: u64,
    /// File size in bytes.
    pub size: u64,
    /// Smallest internal key in the file.
    pub smallest: InternalKey,
    /// Largest internal key in the file.
    pub largest: InternalKey,
    /// Smallest seqno in the file.
    pub smallest_seqno: SeqNo,
    /// Largest seqno in the file.
    pub largest_seqno: SeqNo,
}

/// A delta between two versions, applied atomically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionEdit {
    /// Next unused file number.
    pub next_file_number: Option<u64>,
    /// Largest seqno assigned so far.
    pub last_seqno: Option<SeqNo>,
    /// All writes with seqno <= this are in SSTs (drives Raft log truncation).
    pub flushed_seqno: Option<SeqNo>,
    /// Files removed, as `(level, number)`.
    pub deleted: Vec<(usize, u64)>,
    /// Files added, as `(level, metadata)`.
    pub added: Vec<(usize, FileMeta)>,
}

impl VersionEdit {
    /// Encodes the edit as a MANIFEST record payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![EDIT_FORMAT_VERSION];
        let scalars = [
            (TAG_NEXT_FILE_NUMBER, self.next_file_number),
            (TAG_LAST_SEQNO, self.last_seqno),
            (TAG_FLUSHED_SEQNO, self.flushed_seqno),
        ];
        for (tag, value) in scalars {
            if let Some(v) = value {
                put_varint(&mut out, tag);
                put_varint(&mut out, v);
            }
        }
        for &(level, number) in &self.deleted {
            put_varint(&mut out, TAG_DELETED_FILE);
            put_varint(&mut out, level as u64);
            put_varint(&mut out, number);
        }
        for (level, f) in &self.added {
            put_varint(&mut out, TAG_ADDED_FILE);
            put_varint(&mut out, *level as u64);
            put_varint(&mut out, f.number);
            put_varint(&mut out, f.size);
            for key in [&f.smallest, &f.largest] {
                put_varint(&mut out, key.as_bytes().len() as u64);
                out.extend_from_slice(key.as_bytes());
            }
            put_varint(&mut out, f.smallest_seqno);
            put_varint(&mut out, f.largest_seqno);
        }
        out
    }

    /// Decodes a MANIFEST record payload.
    ///
    /// # Errors
    /// [`StorageError::Corruption`] for an unknown version or tag, truncation, an invalid key or
    /// a level outside L0..L6.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let corrupt = |what: &str| StorageError::corruption(format!("version edit: {what}"));
        let mut r = Reader::new(payload);
        match r.u8() {
            Some(EDIT_FORMAT_VERSION) => {}
            Some(v) => return Err(corrupt(&format!("unsupported format version {v}"))),
            None => return Err(corrupt("empty record")),
        }
        let mut edit = Self::default();
        let varint = |r: &mut Reader<'_>| r.varint().ok_or_else(|| corrupt("truncated"));
        while !r.is_empty() {
            match varint(&mut r)? {
                TAG_NEXT_FILE_NUMBER => edit.next_file_number = Some(varint(&mut r)?),
                TAG_LAST_SEQNO => edit.last_seqno = Some(varint(&mut r)?),
                TAG_FLUSHED_SEQNO => edit.flushed_seqno = Some(varint(&mut r)?),
                TAG_DELETED_FILE => {
                    let level = decode_level(varint(&mut r)?)?;
                    edit.deleted.push((level, varint(&mut r)?));
                }
                TAG_ADDED_FILE => {
                    let level = decode_level(varint(&mut r)?)?;
                    let (number, size) = (varint(&mut r)?, varint(&mut r)?);
                    let smallest = decode_key(&mut r)?;
                    let largest = decode_key(&mut r)?;
                    let (smallest_seqno, largest_seqno) = (varint(&mut r)?, varint(&mut r)?);
                    edit.added.push((
                        level,
                        FileMeta {
                            number,
                            size,
                            smallest,
                            largest,
                            smallest_seqno,
                            largest_seqno,
                        },
                    ));
                }
                tag => return Err(corrupt(&format!("unknown tag {tag}"))),
            }
        }
        Ok(edit)
    }
}

fn decode_level(level: u64) -> Result<usize> {
    usize::try_from(level)
        .ok()
        .filter(|l| *l < NUM_LEVELS)
        .ok_or_else(|| StorageError::corruption(format!("version edit: level {level}")))
}

fn decode_key(r: &mut Reader<'_>) -> Result<InternalKey> {
    let corrupt = || StorageError::corruption("version edit: bad file key");
    let len = r
        .varint()
        .and_then(|l| usize::try_from(l).ok())
        .ok_or_else(corrupt)?;
    let bytes = r.bytes(len).ok_or_else(corrupt)?;
    InternalKey::decode(bytes).map_err(|_| corrupt())
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::key::ValueKind;

    pub(crate) fn file(number: u64, lo: &[u8], hi: &[u8]) -> FileMeta {
        FileMeta {
            number,
            size: 1000 + number,
            smallest: InternalKey::new(lo, 9, ValueKind::Put),
            largest: InternalKey::new(hi, 1, ValueKind::Delete),
            smallest_seqno: 1,
            largest_seqno: 9,
        }
    }

    fn arb_edit() -> impl Strategy<Value = VersionEdit> {
        let meta = (
            any::<u64>(),
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..8),
        )
            .prop_map(|(number, size, k)| FileMeta {
                size,
                ..file(number, &k, &k)
            });
        (
            any::<Option<u64>>(),
            any::<Option<u64>>(),
            any::<Option<u64>>(),
            prop::collection::vec((0..NUM_LEVELS, any::<u64>()), 0..4),
            prop::collection::vec((0..NUM_LEVELS, meta), 0..4),
        )
            .prop_map(
                |(next_file_number, last_seqno, flushed_seqno, deleted, added)| VersionEdit {
                    next_file_number,
                    last_seqno,
                    flushed_seqno,
                    deleted,
                    added,
                },
            )
    }

    proptest! {
        #[test]
        fn version_edit_round_trips(edit in arb_edit()) {
            prop_assert_eq!(VersionEdit::decode(&edit.encode()).unwrap(), edit);
        }

        #[test]
        fn version_edit_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = VersionEdit::decode(&bytes);
        }
    }

    #[test]
    fn version_edit_rejects_unknown_tag_level_and_version() {
        assert!(VersionEdit::decode(&[]).is_err());
        assert!(VersionEdit::decode(&[2]).is_err());
        assert!(VersionEdit::decode(&[1, 99, 0]).is_err());
        assert!(VersionEdit::decode(&[1, 4, 7, 1]).is_err());
        assert!(VersionEdit::decode(&[1, 2]).is_err());
    }
}
