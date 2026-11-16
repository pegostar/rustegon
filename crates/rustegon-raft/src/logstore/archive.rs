// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Backup hooks of the log store (FR-BKP-002/004, PD-066; replication.md §2 "Archiving sealed
//! segments"): the description of a sealed segment handed to an archiver, and a standalone
//! reader of one segment file for restore.
//!
//! The reader needs neither a [`LogStore`](super::LogStore) nor the log's key registry: an
//! archived segment outlives its live copy, whose DEK the store forgets (crypto-shredding) as
//! soon as it deletes the file. For a v2 (encrypted) segment the caller therefore supplies the
//! segment's DEK *wrapped* under the KEK ([`SegmentKey`]), exported by
//! [`LogStore::segment_key`](super::LogStore::segment_key) when the segment was archived, plus
//! the KEK provider to unwrap it. The archive is thus no weaker than the store: without the KEK
//! its segments are unreadable.
//!
//! A sealed segment is complete (every batch in it was synced before the next segment
//! existed), so unlike recovery the reader tolerates no torn tail: every invalid record is
//! corruption.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use rustegon_sim_api::{File, FileSystem, OpenMode};
use rustegon_storage::{
    StorageError,
    encryption::{FileCipher, KekProvider, TAG_LEN, WrappedKey},
};

use super::{
    error::{LogStoreError, Result},
    format::{
        DecodedOp, HeaderCheck, RECORD_HEADER_LEN, SEGMENT_HEADER_LEN, check_segment_header,
        decode_body, parse_record_header, payload_aad, payload_counter, record_is_valid,
    },
};

/// A sealed segment of a live store: final, never written again (module docs of `logstore`,
/// "Backup hooks").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSegment {
    /// Segment id (the file is `<id:020>.rlog`).
    pub id: u64,
    /// Path of the segment file.
    pub path: PathBuf,
    /// File size in bytes (all of it is valid data).
    pub size: u64,
    /// Whether the segment is format v2 (encrypted): its DEK must be archived with it
    /// ([`LogStore::segment_key`](super::LogStore::segment_key)).
    pub encrypted: bool,
    /// Per Raft group, the lowest and highest index of the entry records written to the
    /// segment. Entries replaced later (Raft conflict resolution) or purged are included: they
    /// are still in the file. A group without entries in the segment is absent.
    pub entries: BTreeMap<u64, (u64, u64)>,
}

/// The key material [`read_segment`] needs for a v2 (encrypted) segment: the segment's DEK as
/// exported by [`LogStore::segment_key`](super::LogStore::segment_key) and the KEK provider that
/// unwraps it.
#[derive(Debug, Clone)]
pub struct SegmentKey {
    /// Provider of the KEK the DEK was wrapped under.
    pub kek: Arc<dyn KekProvider>,
    /// The segment's wrapped DEK.
    pub wrapped: WrappedKey,
}

/// One entry record of a segment file, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentEntry {
    /// Raft group (range id).
    pub group: u64,
    /// Log index.
    pub index: u64,
    /// Term the entry was proposed in.
    pub term: u64,
    /// Payload, decrypted for a v2 segment.
    pub payload: Vec<u8>,
}

/// Iterator over the entry records of one segment file ([`read_segment`]).
///
/// Entries come in file order, which is log order per group. A Raft conflict may have replaced
/// entries: an entry whose index is not above the previous one of its group replaces that
/// index and everything after it. Metadata operations (hard states, purges, truncations, the
/// segment-head snapshot) are not returned. After an error the iterator ends.
pub struct SegmentReader {
    file: Box<dyn File>,
    size: u64,
    /// Offset of the next record.
    pos: u64,
    id: u64,
    cipher: Option<FileCipher>,
    records: u64,
    pending: std::collections::VecDeque<SegmentEntry>,
    buf: Vec<u8>,
    done: bool,
}

impl std::fmt::Debug for SegmentReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentReader")
            .field("id", &self.id)
            .field("encrypted", &self.cipher.is_some())
            .field("pos", &self.pos)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// Opens the segment file at `path` for reading its entries without a store (module docs).
/// The segment id is taken from the file's header (an archived copy may be renamed); `key` is
/// required for a v2 segment and ignored for a v1 one.
///
/// # Errors
/// [`LogStoreError::Corruption`] for a damaged header; [`LogStoreError::UnsupportedVersion`];
/// `RGN-4006` ([`StorageError::KeyUnavailable`]) for a v2 segment without `key` or whose DEK
/// does not unwrap under `key.kek`; I/O errors.
pub fn read_segment(
    fs: &dyn FileSystem,
    path: &std::path::Path,
    key: Option<&SegmentKey>,
) -> Result<SegmentReader> {
    let file = fs.open(path, OpenMode::Read)?;
    let size = file.size()?;
    let mut head = [0u8; SEGMENT_HEADER_LEN];
    if size < SEGMENT_HEADER_LEN as u64 {
        return Err(LogStoreError::corruption(format!(
            "{}: {size} bytes is shorter than a raft log segment header",
            path.display()
        )));
    }
    file.read_exact_at(&mut head, 0)?;
    // The id field is covered by the header checksum, which `check_segment_header` verifies.
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&head[16..24]);
    let id = u64::from_le_bytes(id_bytes);
    let encrypted = match check_segment_header(&head, id) {
        HeaderCheck::Valid { encrypted } => encrypted,
        HeaderCheck::Unsupported(version) => {
            return Err(LogStoreError::UnsupportedVersion {
                segment: id,
                version,
            });
        }
        HeaderCheck::Invalid => {
            return Err(LogStoreError::corruption(format!(
                "{}: invalid raft log segment header",
                path.display()
            )));
        }
    };
    let cipher = if encrypted {
        let key = key.ok_or_else(|| {
            StorageError::KeyUnavailable(format!(
                "raft log segment {id} is encrypted at rest but no DEK was supplied"
            ))
        })?;
        // A DEK wrapped under another KEK is `KeyUnavailable` here, before any decryption.
        let dek = key.kek.unwrap(&key.wrapped)?;
        Some(FileCipher::new(id, &dek))
    } else {
        None
    };
    Ok(SegmentReader {
        file,
        size,
        pos: SEGMENT_HEADER_LEN as u64,
        id,
        cipher,
        records: 0,
        pending: std::collections::VecDeque::new(),
        buf: Vec::new(),
        done: false,
    })
}

impl SegmentReader {
    /// Id of the segment (from its header).
    #[must_use]
    pub fn segment_id(&self) -> u64 {
        self.id
    }

    /// Whether the segment is format v2 (encrypted).
    #[must_use]
    pub fn encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    /// The next entry, `None` at the end of the segment.
    ///
    /// # Errors
    /// [`LogStoreError::Corruption`] for an invalid record or a payload that fails
    /// authentication (a damaged file, or the DEK of another segment); I/O errors.
    pub fn next_entry(&mut self) -> Result<Option<SegmentEntry>> {
        loop {
            if let Some(entry) = self.pending.pop_front() {
                return Ok(Some(entry));
            }
            if self.done {
                return Ok(None);
            }
            if self.pos >= self.size {
                self.done = true;
                if self.records == 0 {
                    return Err(LogStoreError::corruption(format!(
                        "raft log segment {} holds no record",
                        self.id
                    )));
                }
                return Ok(None);
            }
            if let Err(e) = self.read_next_record() {
                self.done = true;
                self.pending.clear();
                return Err(e);
            }
        }
    }

    /// Reads, validates and decodes the record at `self.pos` into `self.pending`.
    fn read_next_record(&mut self) -> Result<()> {
        let (id, pos) = (self.id, self.pos);
        let invalid = || {
            LogStoreError::corruption(format!(
                "raft log segment {id}: invalid record at offset {pos} (a sealed segment has no \
                 torn tail)"
            ))
        };
        let rest = self.size - pos;
        if rest < RECORD_HEADER_LEN as u64 {
            return Err(invalid());
        }
        let mut header = [0u8; RECORD_HEADER_LEN];
        self.file.read_exact_at(&mut header, pos)?;
        let body_len = parse_record_header(&header).ok_or_else(invalid)?;
        let rec_len = RECORD_HEADER_LEN + body_len + 1;
        if rec_len as u64 > rest {
            return Err(invalid());
        }
        self.buf.resize(rec_len, 0);
        self.file.read_exact_at(&mut self.buf, pos)?;
        if !record_is_valid(&self.buf) {
            return Err(invalid());
        }
        let at = |e: String| LogStoreError::corruption(format!("segment {id} offset {pos}: {e}"));
        let body = &self.buf[RECORD_HEADER_LEN..rec_len - 1];
        let ops = decode_body(body).map_err(at)?;
        if self.records == 0
            && !ops
                .iter()
                .all(|op| matches!(op, DecodedOp::SetState { .. }))
        {
            return Err(at("first record is not a metadata snapshot".to_owned()));
        }
        let body_start = pos + RECORD_HEADER_LEN as u64;
        for op in ops {
            let DecodedOp::Entry {
                group,
                index,
                term,
                payload_offset,
                payload_len,
            } = op
            else {
                continue;
            };
            let start = RECORD_HEADER_LEN + payload_offset;
            let mut payload = self.buf[start..start + payload_len as usize].to_vec();
            if let Some(cipher) = &self.cipher {
                if (payload_len as usize) < TAG_LEN {
                    return Err(at(format!(
                        "group {group} entry {index}: encrypted payload shorter than its tag"
                    )));
                }
                // Same nonce and associated data as the live store (format v2): the payload's
                // file offset and its group, index and term.
                let offset = body_start + payload_offset as u64;
                let counter = payload_counter(offset)
                    .ok_or_else(|| at(format!("offset {offset} beyond the nonce range")))?;
                cipher
                    .open_in_place(counter, &payload_aad(group, index, term), &mut payload)
                    .map_err(|e| match e {
                        StorageError::Corruption(m) => {
                            at(format!("group {group} entry {index}: {m}"))
                        }
                        other => other.into(),
                    })?;
            }
            self.pending.push_back(SegmentEntry {
                group,
                index,
                term,
                payload,
            });
        }
        self.records += 1;
        self.pos += rec_len as u64;
        Ok(())
    }
}

impl Iterator for SegmentReader {
    type Item = Result<SegmentEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().transpose()
    }
}
