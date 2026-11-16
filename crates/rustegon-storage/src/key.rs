// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Internal key format shared by the memtable and SST files (storage-engine.md §3).
//!
//! Encoding: `user_key ‖ trailer`, trailer = `seqno << 8 | kind` as u64 little-endian.
//! Ordering: user key ascending (bytewise), then trailer **descending**, so for one user key the
//! newest version (highest seqno) comes first and a seek to `(key, snapshot_seqno)` lands on the
//! newest version visible to that snapshot. The trailer cannot be compared bytewise as part of
//! the whole encoding (a user key may be a prefix of another), hence the custom `Ord`.
//!
//! This is a persisted format (it is written into SSTs); it freezes at the end of M1
//! (development-phases.md §3) and any later change needs a version bump.

use std::{cmp::Ordering, fmt};

/// Sequence number assigned to every write; 56 bits (the low 8 bits of the trailer hold the
/// kind).
pub type SeqNo = u64;

/// Largest representable sequence number; also used as "read everything" snapshot.
pub const MAX_SEQNO: SeqNo = (1 << 56) - 1;

const TRAILER_LEN: usize = 8;

/// Kind of an entry. Values are persisted; never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ValueKind {
    /// Point tombstone.
    Delete = 0,
    /// Full value.
    Put = 1,
    /// Merge operand (counters, FTS statistics).
    Merge = 2,
    /// Tombstone for a key written exactly once (write intents); may be dropped together with
    /// the put it deletes during compaction.
    SingleDelete = 3,
    /// Start key of a range tombstone; only appears in memtable range-tombstone maps and SST
    /// range-del blocks, never among point entries (`range_del.rs`).
    RangeDelete = 4,
}

impl ValueKind {
    /// Decodes a persisted kind byte.
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Delete),
            1 => Some(Self::Put),
            2 => Some(Self::Merge),
            3 => Some(Self::SingleDelete),
            4 => Some(Self::RangeDelete),
            _ => None,
        }
    }
}

/// Error decoding an internal key from bytes (corrupt or foreign data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDecodeError {
    /// Fewer bytes than the 8-byte trailer.
    TooShort,
    /// Unknown kind byte.
    UnknownKind(u8),
}

impl fmt::Display for KeyDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("internal key shorter than its trailer"),
            Self::UnknownKind(k) => write!(f, "unknown value kind {k}"),
        }
    }
}

impl std::error::Error for KeyDecodeError {}

/// An encoded internal key. Invariant: at least 8 bytes and a valid kind byte (checked by every
/// constructor), which is why the accessors are infallible.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct InternalKey(Box<[u8]>);

impl InternalKey {
    /// Builds a key.
    ///
    /// # Panics
    /// Debug builds assert `seqno <= MAX_SEQNO`; release builds mask it to 56 bits.
    #[must_use]
    pub fn new(user_key: &[u8], seqno: SeqNo, kind: ValueKind) -> Self {
        debug_assert!(seqno <= MAX_SEQNO, "seqno {seqno} exceeds 56 bits");
        let trailer = ((seqno & MAX_SEQNO) << 8) | kind as u64;
        let mut buf = Vec::with_capacity(user_key.len() + TRAILER_LEN);
        buf.extend_from_slice(user_key);
        buf.extend_from_slice(&trailer.to_le_bytes());
        Self(buf.into_boxed_slice())
    }

    /// Decodes and validates an encoded key.
    ///
    /// # Errors
    /// [`KeyDecodeError`] if the bytes are too short or carry an unknown kind.
    pub fn decode(bytes: &[u8]) -> Result<Self, KeyDecodeError> {
        let split = bytes
            .len()
            .checked_sub(TRAILER_LEN)
            .ok_or(KeyDecodeError::TooShort)?;
        let kind = bytes[split];
        ValueKind::from_u8(kind).ok_or(KeyDecodeError::UnknownKind(kind))?;
        Ok(Self(bytes.into()))
    }

    /// Wraps encoded bytes as a *comparison target* without validating the kind byte (e.g. a
    /// [`seek_key`], whose kind is 0xFF). Ordering only uses [`compare_internal`], so such a key
    /// seeks correctly; it must never be stored or have its accessors trusted.
    pub(crate) fn seek_target(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }

    fn split(&self) -> (&[u8], u64) {
        split_encoded(&self.0)
    }

    /// The user key.
    #[must_use]
    pub fn user_key(&self) -> &[u8] {
        self.split().0
    }

    /// The sequence number.
    #[must_use]
    pub fn seqno(&self) -> SeqNo {
        self.split().1 >> 8
    }

    /// The entry kind.
    #[must_use]
    pub fn kind(&self) -> ValueKind {
        // Constructor invariant: the kind byte is valid.
        ValueKind::from_u8(self.0[self.0.len() - TRAILER_LEN]).unwrap_or(ValueKind::Delete)
    }

    /// The encoded bytes (as stored in SSTs).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Ord for InternalKey {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_internal(&self.0, &other.0)
    }
}

/// Splits encoded bytes into user key and trailer without validation. Bytes shorter than the
/// trailer (only possible for corrupt input that slipped past a checksum) are treated as a user
/// key with trailer 0 so that comparisons never panic.
fn split_encoded(bytes: &[u8]) -> (&[u8], u64) {
    match bytes.len().checked_sub(TRAILER_LEN) {
        Some(at) => {
            let (user, trailer) = bytes.split_at(at);
            let mut raw = [0u8; TRAILER_LEN];
            raw.copy_from_slice(trailer);
            (user, u64::from_le_bytes(raw))
        }
        None => (bytes, 0),
    }
}

/// Compares two encoded internal keys: user key ascending, then trailer (seqno, kind)
/// descending. Used by SST blocks, which store keys as encoded bytes.
#[must_use]
pub fn compare_internal(a: &[u8], b: &[u8]) -> Ordering {
    let (a_user, a_trailer) = split_encoded(a);
    let (b_user, b_trailer) = split_encoded(b);
    a_user.cmp(b_user).then_with(|| b_trailer.cmp(&a_trailer))
}

/// Encoded key that sorts before every version of `user_key` with `seqno <= snapshot` and after
/// every newer version: seeking to it lands on the newest version visible at `snapshot`. The kind
/// byte is 0xFF (larger than any real kind) so no real entry with the same seqno sorts before it;
/// the result is a comparison target only and is never stored.
#[must_use]
pub fn seek_key(user_key: &[u8], snapshot: SeqNo) -> Vec<u8> {
    let trailer = (snapshot.min(MAX_SEQNO) << 8) | 0xFF;
    let mut buf = Vec::with_capacity(user_key.len() + TRAILER_LEN);
    buf.extend_from_slice(user_key);
    buf.extend_from_slice(&trailer.to_le_bytes());
    buf
}

/// A validated, borrowed view of an encoded internal key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedKey<'a> {
    /// The user key.
    pub user_key: &'a [u8],
    /// The sequence number.
    pub seqno: SeqNo,
    /// The entry kind.
    pub kind: ValueKind,
}

impl<'a> ParsedKey<'a> {
    /// Parses and validates encoded bytes without copying.
    ///
    /// # Errors
    /// [`KeyDecodeError`] if the bytes are too short or carry an unknown kind.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, KeyDecodeError> {
        if bytes.len() < TRAILER_LEN {
            return Err(KeyDecodeError::TooShort);
        }
        let (user_key, trailer) = split_encoded(bytes);
        // Truncation intended: the low byte of the trailer is the kind.
        #[allow(clippy::cast_possible_truncation)]
        let kind_byte = trailer as u8;
        let kind = ValueKind::from_u8(kind_byte).ok_or(KeyDecodeError::UnknownKind(kind_byte))?;
        Ok(Self {
            user_key,
            seqno: trailer >> 8,
            kind,
        })
    }
}

impl PartialOrd for InternalKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for InternalKey {
    // Keys may contain user data; Debug is for engine diagnostics and shows them escaped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{}:{:?}",
            self.user_key().escape_ascii(),
            self.seqno(),
            self.kind()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_key_round_trips_fields() {
        let k = InternalKey::new(b"user", MAX_SEQNO, ValueKind::SingleDelete);
        assert_eq!(k.user_key(), b"user");
        assert_eq!(k.seqno(), MAX_SEQNO);
        assert_eq!(k.kind(), ValueKind::SingleDelete);
        assert_eq!(InternalKey::decode(k.as_bytes()), Ok(k));
    }

    #[test]
    fn internal_key_orders_user_key_asc_then_seqno_desc() {
        let mut keys = [
            InternalKey::new(b"ab", 1, ValueKind::Put),
            InternalKey::new(b"a", 1, ValueKind::Put),
            InternalKey::new(b"a", 9, ValueKind::Delete),
            InternalKey::new(b"", 5, ValueKind::Put),
            InternalKey::new(b"a", 9, ValueKind::Merge),
        ];
        keys.sort();
        let got: Vec<_> = keys.iter().map(|k| format!("{k:?}")).collect();
        // Same seqno: higher kind byte sorts first (trailer descending).
        assert_eq!(
            got,
            ["@5:Put", "a@9:Merge", "a@9:Delete", "a@1:Put", "ab@1:Put"]
        );
    }

    #[test]
    fn seek_key_lands_on_newest_visible_version() {
        let versions = [
            InternalKey::new(b"k", 9, ValueKind::Put),
            InternalKey::new(b"k", 5, ValueKind::SingleDelete),
            InternalKey::new(b"k", 5, ValueKind::Delete),
            InternalKey::new(b"k", 2, ValueKind::Put),
        ];
        let seek = seek_key(b"k", 5);
        let first_at_or_after = versions
            .iter()
            .find(|v| compare_internal(v.as_bytes(), &seek).is_ge());
        assert_eq!(first_at_or_after, Some(&versions[1]));
        assert!(compare_internal(&seek_key(b"k", MAX_SEQNO), versions[0].as_bytes()).is_lt());
        // Short (corrupt) input compares without panicking.
        assert!(compare_internal(b"a", b"b").is_lt());
    }

    #[test]
    fn parsed_key_matches_owned_key() {
        let k = InternalKey::new(b"doc", 77, ValueKind::Merge);
        let p = ParsedKey::parse(k.as_bytes()).unwrap();
        assert_eq!(
            (p.user_key, p.seqno, p.kind),
            (&b"doc"[..], 77, ValueKind::Merge)
        );
        assert_eq!(ParsedKey::parse(b"1234567"), Err(KeyDecodeError::TooShort));
        assert_eq!(
            ParsedKey::parse(&seek_key(b"k", 1)),
            Err(KeyDecodeError::UnknownKind(0xFF))
        );
    }

    #[test]
    fn internal_key_decode_rejects_corrupt_bytes() {
        assert_eq!(InternalKey::decode(b"short"), Err(KeyDecodeError::TooShort));
        let mut bytes = InternalKey::new(b"k", 1, ValueKind::Put)
            .as_bytes()
            .to_vec();
        let kind_at = bytes.len() - 8;
        bytes[kind_at] = 0x7f;
        assert_eq!(
            InternalKey::decode(&bytes),
            Err(KeyDecodeError::UnknownKind(0x7f))
        );
    }
}
