// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Log store format v1: segment header, record framing and operation encoding
//! (replication.md §2, "Log store format v1"; persisted, change only per implementation-rules.md
//! §6). All integers are little-endian.
//!
//! - Segment header (32 bytes): `magic "RGNRLOG\0" ‖ format_version u32 ‖ flags u32 (0) ‖
//!   segment_id u64 ‖ XXH3-64 of the preceding 24 bytes`.
//! - Record: `body_len u32 ‖ len_check u32 ‖ checksum u64 ‖ body ‖ end marker 0xE7`, where
//!   `len_check` is the low 32 bits of XXH3-64(`body_len` bytes) and `checksum` is XXH3-64 over
//!   the `body_len` bytes followed by the body. One record = one write batch, so a batch is
//!   atomic: its record is either complete and valid or dropped as a torn tail.
//! - Body: `op_count u32 ‖ op*`, op = `tag u8 ‖ group u64 ‖ fields` (see [`Tag`]).
//!
//! Why the separate length check and the end marker: recovery must tell a torn final write
//! (tolerated) from damage to acknowledged data (an error). A torn write leaves a prefix of the
//! last record followed by nothing or by zeros. With a self-checked length, a damaged length
//! field is recognised as such instead of sending the reader past EOF; with a non-zero end
//! marker, a record whose claimed extent fits in the file but fails its checksum can only be torn
//! if its marker position holds a zero. See [`classify_invalid`].

use std::hash::Hasher as _;

use rustegon_storage::encryption::TAG_LEN;
use twox_hash::XxHash3_64;

use super::group::{GroupMeta, HardState};

/// Segment file magic.
pub(crate) const SEGMENT_MAGIC: [u8; 8] = *b"RGNRLOG\0";
/// Format version of a plaintext segment (v1; still written for stores without encryption,
/// whose bytes are unchanged by v2).
pub(crate) const FORMAT_VERSION: u32 = 1;
/// Format version of an encrypted segment (v2, PD-057): v1 framing, but every entry payload is
/// `AES-256-GCM(segment DEK, nonce = segment_id ‖ payload_offset / 16, aad = group ‖ index ‖
/// term) ‖ tag`, and `payload_len` counts the tag. Metadata ops stay plaintext.
pub(crate) const FORMAT_VERSION_ENCRYPTED: u32 = 2;
/// Segment header length in bytes.
pub(crate) const SEGMENT_HEADER_LEN: usize = 32;
/// Record header length in bytes (`body_len`, `len_check`, `checksum`).
pub(crate) const RECORD_HEADER_LEN: usize = 16;
/// Last byte of every record. Non-zero by design (module docs).
pub(crate) const RECORD_END_MARKER: u8 = 0xE7;
/// Upper bound for one record body: a write batch is about 1 MiB (group commit, replication.md
/// §2) and a segment-head snapshot about 72 bytes per group; 64 MiB leaves room for large
/// proposals while bounding what recovery allocates for a damaged length.
pub(crate) const MAX_BODY_LEN: usize = 64 << 20;
/// Bytes of `op_count` at the start of every body.
const OP_COUNT_LEN: usize = 4;

/// Operation tags of format v1. Unknown tags are corruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Tag {
    /// `index u64 ‖ term u64 ‖ payload_len u32 ‖ payload`.
    Entry = 1,
    /// `term u64 ‖ vote u64 ‖ commit u64`.
    HardState = 2,
    /// `last_index u64 ‖ last_term u64`.
    Truncate = 3,
    /// `first_index u64 ‖ boundary_term u64`.
    Purge = 4,
    /// `first_index ‖ last_index ‖ last_term ‖ boundary_term ‖ hs_term ‖ hs_vote ‖ hs_commit`
    /// (7 × u64).
    SetState = 5,
    /// No fields: the group and all its entries are gone.
    RemoveGroup = 6,
}

fn xxh3(parts: &[&[u8]]) -> u64 {
    let mut h = XxHash3_64::new();
    for p in parts {
        h.write(p);
    }
    h.finish()
}

/// The header of segment `id`, version 2 if `encrypted`, else version 1.
pub(crate) fn segment_header(id: u64, encrypted: bool) -> [u8; SEGMENT_HEADER_LEN] {
    let version = if encrypted {
        FORMAT_VERSION_ENCRYPTED
    } else {
        FORMAT_VERSION
    };
    let mut h = [0u8; SEGMENT_HEADER_LEN];
    h[..8].copy_from_slice(&SEGMENT_MAGIC);
    h[8..12].copy_from_slice(&version.to_le_bytes());
    // 12..16: flags, reserved as 0.
    h[16..24].copy_from_slice(&id.to_le_bytes());
    let sum = xxh3(&[&h[..24]]);
    h[24..].copy_from_slice(&sum.to_le_bytes());
    h
}

/// Result of checking a segment header.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeaderCheck {
    /// Intact header of this segment; `encrypted` for a v2 segment.
    Valid { encrypted: bool },
    /// Intact header of another format version.
    Unsupported(u32),
    /// Damaged, torn, or belonging to another segment.
    Invalid,
}

/// Checks `bytes` (the first bytes of the file) against the header of segment `id`.
pub(crate) fn check_segment_header(bytes: &[u8], id: u64) -> HeaderCheck {
    let Some(h) = bytes.get(..SEGMENT_HEADER_LEN) else {
        return HeaderCheck::Invalid;
    };
    if h[..8] != SEGMENT_MAGIC || read_u64(&h[24..]) != Some(xxh3(&[&h[..24]])) {
        return HeaderCheck::Invalid;
    }
    let version = read_u32(&h[8..]).unwrap_or(0);
    let encrypted = match version {
        FORMAT_VERSION => false,
        FORMAT_VERSION_ENCRYPTED => true,
        other => return HeaderCheck::Unsupported(other),
    };
    if h != segment_header(id, encrypted) {
        // Valid checksum but other flags or another segment id (misnamed file).
        return HeaderCheck::Invalid;
    }
    HeaderCheck::Valid { encrypted }
}

fn read_u32(b: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

fn read_u64(b: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
}

fn len_check(len_bytes: [u8; 4]) -> u32 {
    // Truncation intended: the low half of the hash is the check value (format v1).
    #[allow(clippy::cast_possible_truncation)]
    let low = xxh3(&[&len_bytes]) as u32;
    low
}

/// Body length claimed by a record header whose length check holds, or `None`.
pub(crate) fn parse_record_header(h: &[u8; RECORD_HEADER_LEN]) -> Option<usize> {
    let len_bytes: [u8; 4] = h[..4].try_into().ok()?;
    if read_u32(&h[4..])? != len_check(len_bytes) {
        return None;
    }
    let len = usize::try_from(u32::from_le_bytes(len_bytes)).ok()?;
    (len <= MAX_BODY_LEN).then_some(len)
}

/// Whether `rec` (header, body, marker) is a complete valid record.
pub(crate) fn record_is_valid(rec: &[u8]) -> bool {
    let Some(len_bytes) = rec.get(..4) else {
        return false;
    };
    let (Some(stored), Some(&marker)) = (read_u64(&rec[8..]), rec.last()) else {
        return false;
    };
    let body = &rec[RECORD_HEADER_LEN..rec.len() - 1];
    marker == RECORD_END_MARKER && stored == xxh3(&[len_bytes, body])
}

/// Whether the bytes of an invalid record starting at `rest[0]` (through the end of the file)
/// can be a torn final write rather than damage to acknowledged data. `zeros_from(i)` tells
/// whether every byte from `i` to the end of the file is zero.
///
/// A torn write persists a prefix of the record, then nothing or zeros (file systems that
/// extend the size before the data, sim `CrashMode::TornZeroTail`):
/// - header incomplete: torn (nothing can follow);
/// - length check fails: the prefix ended inside the length fields, so everything after the
///   header must be zero;
/// - claimed extent past EOF: torn (its real length, the rest never landed);
/// - claimed extent within the file: the record was not completely written, so its marker byte
///   is a zero from the fill, and so is everything after it. A non-zero marker means the record
///   was complete: a checksum failure there is damage, never a torn write.
pub(crate) fn classify_invalid(
    rest_len: u64,
    header: Option<&[u8; RECORD_HEADER_LEN]>,
    marker_at: impl FnOnce(u64) -> Option<u8>,
    zeros_from: impl FnOnce(u64) -> bool,
) -> bool {
    let Some(header) = header else {
        return true;
    };
    let Some(body_len) = parse_record_header(header) else {
        return zeros_from(RECORD_HEADER_LEN as u64);
    };
    let marker_pos = (RECORD_HEADER_LEN + body_len) as u64;
    if marker_pos >= rest_len {
        return true;
    }
    marker_at(marker_pos) == Some(0) && zeros_from(marker_pos + 1)
}

/// Builds one record in a reusable buffer.
pub(crate) struct RecordBuilder<'a> {
    buf: &'a mut Vec<u8>,
    count: u32,
}

impl<'a> RecordBuilder<'a> {
    /// Starts a record in `buf` (cleared).
    pub(crate) fn new(buf: &'a mut Vec<u8>) -> Self {
        buf.clear();
        buf.resize(RECORD_HEADER_LEN + OP_COUNT_LEN, 0);
        Self { buf, count: 0 }
    }

    fn op(&mut self, tag: Tag, group: u64) {
        self.count += 1;
        self.buf.push(tag as u8);
        self.buf.extend_from_slice(&group.to_le_bytes());
    }

    fn u64s(&mut self, vals: &[u64]) {
        for v in vals {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    /// Adds an entry; returns the payload's offset within the record. With `tag_room` (v2
    /// segments) the payload is followed by [`TAG_LEN`] zero bytes for the tag the store writes when it seals the payload,
    /// and `payload_len` counts them.
    pub(crate) fn entry(
        &mut self,
        group: u64,
        index: u64,
        term: u64,
        payload: &[u8],
        tag_room: bool,
    ) -> usize {
        self.op(Tag::Entry, group);
        self.u64s(&[index, term]);
        let stored = payload.len() + if tag_room { TAG_LEN } else { 0 };
        // Lossless: batch payloads are bounded by MAX_BODY_LEN in `finish`; a longer payload
        // makes the record oversized and `finish` refuses it.
        let len = u32::try_from(stored).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&len.to_le_bytes());
        let offset = self.buf.len();
        self.buf.extend_from_slice(payload);
        if tag_room {
            self.buf.extend_from_slice(&[0u8; TAG_LEN]);
        }
        offset
    }

    /// Adds a hard state.
    pub(crate) fn hard_state(&mut self, group: u64, hs: HardState) {
        self.op(Tag::HardState, group);
        self.u64s(&[hs.term, hs.vote, hs.commit]);
    }

    /// Adds a suffix truncation.
    pub(crate) fn truncate(&mut self, group: u64, last_index: u64, last_term: u64) {
        self.op(Tag::Truncate, group);
        self.u64s(&[last_index, last_term]);
    }

    /// Adds a prefix purge.
    pub(crate) fn purge(&mut self, group: u64, first_index: u64, boundary_term: u64) {
        self.op(Tag::Purge, group);
        self.u64s(&[first_index, boundary_term]);
    }

    /// Adds a full metadata record.
    pub(crate) fn set_state(&mut self, group: u64, m: &GroupMeta) {
        self.op(Tag::SetState, group);
        let hs = m.hard_state;
        self.u64s(&[
            m.first_index,
            m.last_index,
            m.last_term,
            m.boundary_term,
            hs.term,
            hs.vote,
            hs.commit,
        ]);
    }

    /// Adds a group removal.
    pub(crate) fn remove_group(&mut self, group: u64) {
        self.op(Tag::RemoveGroup, group);
    }

    /// Fills in the header and appends the end marker; returns the record length.
    ///
    /// # Errors
    /// A message if the body exceeds [`MAX_BODY_LEN`] or a payload exceeds `u32::MAX`.
    pub(crate) fn finish(self) -> Result<usize, String> {
        let body_len = self.buf.len() - RECORD_HEADER_LEN;
        if body_len > MAX_BODY_LEN {
            return Err(format!(
                "batch of {body_len} bytes exceeds the {MAX_BODY_LEN}-byte record limit"
            ));
        }
        let count_at = RECORD_HEADER_LEN;
        self.buf[count_at..count_at + OP_COUNT_LEN].copy_from_slice(&self.count.to_le_bytes());
        // Lossless: bounded by MAX_BODY_LEN.
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (body_len as u32).to_le_bytes();
        let sum = xxh3(&[&len_bytes, &self.buf[RECORD_HEADER_LEN..]]);
        self.buf[..4].copy_from_slice(&len_bytes);
        self.buf[4..8].copy_from_slice(&len_check(len_bytes).to_le_bytes());
        self.buf[8..16].copy_from_slice(&sum.to_le_bytes());
        self.buf.push(RECORD_END_MARKER);
        Ok(self.buf.len())
    }
}

/// Nonce counter of an entry payload stored at `offset` of an encrypted segment (v2):
/// `offset / 16`. Unique per segment because a segment is written once, front to back (never
/// appended to after a reopen; a torn-tail repair copies bytes, it does not re-encrypt) and two
/// payloads are at least one entry op header plus a tag (29 + 16 bytes) apart, so their
/// offsets differ by more than 16. `None` beyond 64 GiB (segments are at most ~1 GiB).
pub(crate) fn payload_counter(offset: u64) -> Option<u32> {
    u32::try_from(offset / 16).ok()
}

/// Associated data of an entry payload: binds the ciphertext to its group, index and term, so
/// a payload moved to another entry (or another group) fails authentication.
pub(crate) fn payload_aad(group: u64, index: u64, term: u64) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[..8].copy_from_slice(&group.to_le_bytes());
    aad[8..16].copy_from_slice(&index.to_le_bytes());
    aad[16..].copy_from_slice(&term.to_le_bytes());
    aad
}

/// Recomputes the checksum of the finished record `rec` after its body was changed in place
/// (payloads sealed once the record's position in the segment is known).
pub(crate) fn refresh_checksum(rec: &mut [u8]) {
    let end = rec.len().saturating_sub(1);
    if end < RECORD_HEADER_LEN {
        return;
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&rec[..4]);
    let sum = xxh3(&[&len_bytes, &rec[RECORD_HEADER_LEN..end]]);
    rec[8..16].copy_from_slice(&sum.to_le_bytes());
}

/// One decoded operation; entry payloads are referenced by their offset in the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodedOp {
    Entry {
        group: u64,
        index: u64,
        term: u64,
        payload_offset: usize,
        payload_len: u32,
    },
    HardState {
        group: u64,
        hs: HardState,
    },
    Truncate {
        group: u64,
        last_index: u64,
        last_term: u64,
    },
    Purge {
        group: u64,
        first_index: u64,
        boundary_term: u64,
    },
    SetState {
        group: u64,
        meta: GroupMeta,
    },
    RemoveGroup {
        group: u64,
    },
}

struct Cursor<'a> {
    body: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.body.len());
        let end = end.ok_or_else(|| format!("operation truncated at body offset {}", self.pos))?;
        let s = &self.body[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u64(&mut self) -> Result<u64, String> {
        read_u64(self.take(8)?).ok_or_else(|| "short u64".to_owned())
    }

    fn u32(&mut self) -> Result<u32, String> {
        read_u32(self.take(4)?).ok_or_else(|| "short u32".to_owned())
    }
}

/// Decodes a valid record's body. Errors mean a checksum-valid record with an impossible
/// structure: corruption (or a writer bug), never a torn write.
pub(crate) fn decode_body(body: &[u8]) -> Result<Vec<DecodedOp>, String> {
    let mut c = Cursor { body, pos: 0 };
    let count = c.u32()?;
    // Each op takes at least 9 bytes, which bounds the allocation for a damaged count.
    let mut ops = Vec::with_capacity((count as usize).min(body.len() / 9));
    for _ in 0..count {
        let tag = c.take(1)?[0];
        let group = c.u64()?;
        let op = match tag {
            t if t == Tag::Entry as u8 => {
                let index = c.u64()?;
                let term = c.u64()?;
                let payload_len = c.u32()?;
                let payload_offset = c.pos;
                c.take(payload_len as usize)?;
                DecodedOp::Entry {
                    group,
                    index,
                    term,
                    payload_offset,
                    payload_len,
                }
            }
            t if t == Tag::HardState as u8 => DecodedOp::HardState {
                group,
                hs: HardState {
                    term: c.u64()?,
                    vote: c.u64()?,
                    commit: c.u64()?,
                },
            },
            t if t == Tag::Truncate as u8 => DecodedOp::Truncate {
                group,
                last_index: c.u64()?,
                last_term: c.u64()?,
            },
            t if t == Tag::Purge as u8 => DecodedOp::Purge {
                group,
                first_index: c.u64()?,
                boundary_term: c.u64()?,
            },
            t if t == Tag::SetState as u8 => DecodedOp::SetState {
                group,
                meta: GroupMeta {
                    first_index: c.u64()?,
                    last_index: c.u64()?,
                    last_term: c.u64()?,
                    boundary_term: c.u64()?,
                    hard_state: HardState {
                        term: c.u64()?,
                        vote: c.u64()?,
                        commit: c.u64()?,
                    },
                },
            },
            t if t == Tag::RemoveGroup as u8 => DecodedOp::RemoveGroup { group },
            t => return Err(format!("unknown operation tag {t}")),
        };
        ops.push(op);
    }
    if c.pos != body.len() {
        return Err(format!(
            "{} trailing bytes after {count} operations",
            body.len() - c.pos
        ));
    }
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(f: impl FnOnce(&mut RecordBuilder<'_>)) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut b = RecordBuilder::new(&mut buf);
        f(&mut b);
        b.finish().unwrap();
        buf
    }

    #[test]
    fn segment_header_round_trips_and_rejects_damage() {
        for encrypted in [false, true] {
            let h = segment_header(7, encrypted);
            let valid = HeaderCheck::Valid { encrypted };
            assert_eq!(check_segment_header(&h, 7), valid);
            assert_eq!(check_segment_header(&h, 8), HeaderCheck::Invalid);
            assert_eq!(check_segment_header(&h[..31], 7), HeaderCheck::Invalid);
            for bit in 0..SEGMENT_HEADER_LEN * 8 {
                let mut d = h;
                d[bit / 8] ^= 1 << (bit % 8);
                assert!(
                    !matches!(check_segment_header(&d, 7), HeaderCheck::Valid { .. }),
                    "bit {bit}"
                );
            }
        }
        // v1 bytes are unchanged by v2 (only the version field differs).
        let (v1, v2) = (segment_header(7, false), segment_header(7, true));
        assert_eq!(v1[8..12], 1u32.to_le_bytes());
        assert_eq!(v2[8..12], 2u32.to_le_bytes());
        assert_eq!(v1[..8], v2[..8]);
        assert_eq!(v1[12..24], v2[12..24]);
        let mut v3 = v1;
        v3[8..12].copy_from_slice(&3u32.to_le_bytes());
        let sum = xxh3(&[&v3[..24]]);
        v3[24..].copy_from_slice(&sum.to_le_bytes());
        assert_eq!(check_segment_header(&v3, 7), HeaderCheck::Unsupported(3));
    }

    #[test]
    fn sealed_entries_reserve_the_tag_and_refresh_checksum_validates() {
        let mut at = 0;
        let mut rec = record(|b| at = b.entry(1, 10, 3, b"payload", true));
        assert!(record_is_valid(&rec));
        let header: [u8; RECORD_HEADER_LEN] = rec[..RECORD_HEADER_LEN].try_into().unwrap();
        let body_len = parse_record_header(&header).unwrap();
        let ops = decode_body(&rec[RECORD_HEADER_LEN..RECORD_HEADER_LEN + body_len]).unwrap();
        assert!(matches!(
            ops[0],
            DecodedOp::Entry { payload_len, .. } if payload_len as usize == 7 + TAG_LEN
        ));
        rec[at] ^= 0xFF;
        assert!(!record_is_valid(&rec));
        refresh_checksum(&mut rec);
        assert!(record_is_valid(&rec));
        assert_eq!(payload_counter(16 * u64::from(u32::MAX)), Some(u32::MAX));
        assert_eq!(payload_counter(16 * (u64::from(u32::MAX) + 1)), None);
        assert_ne!(payload_aad(1, 2, 3), payload_aad(1, 3, 2));
    }

    #[test]
    fn records_round_trip_every_operation() {
        let meta = GroupMeta {
            first_index: 5,
            last_index: 9,
            last_term: 3,
            boundary_term: 2,
            hard_state: HardState {
                term: 3,
                vote: 1,
                commit: 8,
            },
        };
        let mut payload_at = 0;
        let rec = record(|b| {
            payload_at = b.entry(1, 10, 3, b"payload", false);
            b.hard_state(1, meta.hard_state);
            b.truncate(2, 4, 1);
            b.purge(3, 6, 2);
            b.set_state(4, &meta);
            b.remove_group(5);
        });
        assert!(record_is_valid(&rec));
        let header: [u8; RECORD_HEADER_LEN] = rec[..RECORD_HEADER_LEN].try_into().unwrap();
        let body_len = parse_record_header(&header).unwrap();
        assert_eq!(rec.len(), RECORD_HEADER_LEN + body_len + 1);
        let body = &rec[RECORD_HEADER_LEN..rec.len() - 1];
        let ops = decode_body(body).unwrap();
        assert_eq!(
            ops,
            vec![
                DecodedOp::Entry {
                    group: 1,
                    index: 10,
                    term: 3,
                    payload_offset: payload_at - RECORD_HEADER_LEN,
                    payload_len: 7,
                },
                DecodedOp::HardState {
                    group: 1,
                    hs: meta.hard_state
                },
                DecodedOp::Truncate {
                    group: 2,
                    last_index: 4,
                    last_term: 1
                },
                DecodedOp::Purge {
                    group: 3,
                    first_index: 6,
                    boundary_term: 2
                },
                DecodedOp::SetState { group: 4, meta },
                DecodedOp::RemoveGroup { group: 5 },
            ]
        );
        assert_eq!(&rec[payload_at..payload_at + 7], b"payload");
        // Structure errors in an otherwise valid body.
        assert!(decode_body(&[1, 0, 0, 0, 99, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode_body(&[0, 0, 0, 0, 1]).is_err());
        assert!(decode_body(&[1, 0, 0, 0, 2]).is_err());
    }

    /// Every bit flip of a complete record is either rejected by the header check or by the
    /// checksum, and the torn-tail classifier never accepts it as torn.
    #[test]
    fn every_bit_flip_of_a_complete_record_is_damage_not_a_torn_tail() {
        let rec = record(|b| {
            b.entry(1, 1, 1, &[0u8; 40], false);
            b.hard_state(1, HardState::default());
        });
        for bit in 0..rec.len() * 8 {
            let mut d = rec.clone();
            d[bit / 8] ^= 1 << (bit % 8);
            assert!(!record_is_valid(&d) || parse_record_header(&header(&d)).is_none());
            let torn = classify_invalid(
                d.len() as u64,
                Some(&header(&d)),
                |p| d.get(usize::try_from(p).unwrap()).copied(),
                |from| d[usize::try_from(from).unwrap()..].iter().all(|&b| b == 0),
            );
            assert!(!torn, "bit {bit} classified as torn");
        }
    }

    fn header(d: &[u8]) -> [u8; RECORD_HEADER_LEN] {
        d[..RECORD_HEADER_LEN].try_into().unwrap()
    }

    /// Every torn prefix, with and without a zero fill, is classified as torn.
    #[test]
    fn every_torn_prefix_with_or_without_zero_fill_is_torn() {
        let rec = record(|b| {
            b.entry(1, 1, 1, &[0xAB; 300], false);
        });
        for kept in 0..rec.len() {
            for total in kept..=rec.len() + 4 {
                let mut d = rec[..kept].to_vec();
                d.resize(total, 0);
                let h: Option<[u8; RECORD_HEADER_LEN]> =
                    d.get(..RECORD_HEADER_LEN).map(|h| h.try_into().unwrap());
                let torn = classify_invalid(
                    d.len() as u64,
                    h.as_ref(),
                    |p| d.get(usize::try_from(p).unwrap()).copied(),
                    |from| {
                        d.get(usize::try_from(from).unwrap()..)
                            .is_none_or(|r| r.iter().all(|&b| b == 0))
                    },
                );
                assert!(torn, "kept {kept}, total {total}");
            }
        }
    }
}
