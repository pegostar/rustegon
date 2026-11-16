// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! MVCC key layout v1 (transaction-management.md §3 "Byte layout v1"; DEC-018).
//!
//! The engine compares keys bytewise. For a logical key *K* (data-model.md §3.2):
//! - meta / intent key = `K ‖ 0x00`;
//! - version key = `K ‖ 0x00 ‖ inverted(wall u64 BE ‖ logical u32 BE) ‖ 0x0D`.
//!
//! Ordering argument (tested in `tests`): the meta key is a strict prefix of every version key of
//! *K*, so it sorts first; inverted big-endian timestamps sort newest first; and because no
//! logical key continues another one with `0x00` (data-model.md §3.2), every longer logical key
//! `K ‖ b …` has `b ≥ 0x01 > 0x00`, so all entries of *K* precede it. The last byte tells the
//! decoder the suffix length: `0x00` → 1-byte meta suffix, `0x0D` (13 = separator + timestamp)
//! → 14-byte version suffix.

use rustegon_storage::sst::PrefixExtractor;

use crate::{
    error::{MvccError, Result},
    hlc::Timestamp,
    value::TxnId,
};

/// Separator between the logical key and the MVCC suffix; also the meta key's last byte.
pub const SEPARATOR: u8 = 0x00;
/// Last byte of a version key: the number of suffix bytes before it (separator + timestamp).
pub const VERSION_TAG: u8 = 0x0D;
/// Suffix length of a version key: separator(1) + inverted timestamp(12) + tag(1).
pub const VERSION_SUFFIX_LEN: usize = 2 + Timestamp::ENCODED_LEN;

/// A decoded MVCC key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MvccKey<'a> {
    /// The meta slot of a logical key: an intent, or a transaction record for txn record keys.
    Meta(&'a [u8]),
    /// A committed version of a logical key at a timestamp.
    Version(&'a [u8], Timestamp),
}

impl<'a> MvccKey<'a> {
    /// Decodes an engine key.
    ///
    /// # Errors
    /// [`MvccError::Corruption`] if `key` does not end in a valid MVCC suffix.
    pub fn decode(key: &'a [u8]) -> Result<Self> {
        match key.last() {
            Some(&SEPARATOR) => Ok(Self::Meta(&key[..key.len() - 1])),
            Some(&VERSION_TAG) if key.len() >= VERSION_SUFFIX_LEN => {
                let split = key.len() - VERSION_SUFFIX_LEN;
                if key[split] != SEPARATOR {
                    return Err(MvccError::corruption("MVCC version key without separator"));
                }
                let mut ts = [0; Timestamp::ENCODED_LEN];
                for (dst, src) in ts.iter_mut().zip(&key[split + 1..key.len() - 1]) {
                    *dst = !src;
                }
                Ok(Self::Version(&key[..split], Timestamp::from_be_bytes(ts)))
            }
            _ => Err(MvccError::corruption("key without MVCC suffix")),
        }
    }

    /// The logical key.
    #[must_use]
    pub fn logical(&self) -> &'a [u8] {
        match *self {
            Self::Meta(k) | Self::Version(k, _) => k,
        }
    }
}

/// `K ‖ 0x00`.
#[must_use]
pub fn meta_key(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 1);
    out.extend_from_slice(key);
    out.push(SEPARATOR);
    out
}

/// `K ‖ 0x00 ‖ inverted(ts) ‖ 0x0D`.
#[must_use]
pub fn version_key(key: &[u8], ts: Timestamp) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + VERSION_SUFFIX_LEN);
    out.extend_from_slice(key);
    out.push(SEPARATOR);
    out.extend(ts.to_be_bytes().iter().map(|b| !b));
    out.push(VERSION_TAG);
    out
}

/// The smallest engine key greater than every entry of logical key `key` (`K ‖ 0x01`): where a
/// scan continues with the next logical key (module docs, ordering argument).
#[must_use]
pub fn next_logical_key(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 1);
    out.extend_from_slice(key);
    out.push(SEPARATOR + 1);
    out
}

/// Prefix of the range-local keyspace (data-model.md §3.2); its keys are unversioned.
pub const LOCAL_PREFIX: u8 = 0x01;
/// Second byte of transaction record keys: `0x01 'k' …`.
pub(crate) const TXN_RECORD_MARKER: u8 = b'k';
/// Byte after the anchor key in a transaction record key.
const TXN_RECORD_SUFFIX: u8 = b't';

/// Logical key of a transaction record: `0x01 'k' ‖ anchor (escaped as a string element body)
/// ‖ 't' ‖ txn_id` (data-model.md §3.2). Escaping is that of string elements (§3.1): `0x00` →
/// `0x00 0xFF`, then the terminator `0x00 0x01`, so the anchor is self-delimiting. The record is
/// stored in the meta slot of this logical key ([`meta_key`]), never versioned.
#[must_use]
pub fn txn_record_key(anchor: &[u8], txn_id: &TxnId) -> Vec<u8> {
    let mut out = Vec::with_capacity(anchor.len() + 21);
    out.push(LOCAL_PREFIX);
    out.push(TXN_RECORD_MARKER);
    for &b in anchor {
        out.push(b);
        if b == 0x00 {
            out.push(0xFF);
        }
    }
    out.extend_from_slice(&[0x00, 0x01, TXN_RECORD_SUFFIX]);
    out.extend_from_slice(txn_id);
    out
}

/// The anchor of `logical` if it is the transaction record key of `txn_id`
/// ([`txn_record_key`]); `None` for any other key. Unambiguous: an escaped anchor never holds
/// `0x00 0x01` (every `0x00` is followed by `0xFF`), so the fixed-length tail
/// `0x00 0x01 't' ‖ txn_id` can only be the terminator and the id.
#[must_use]
pub fn txn_record_anchor(logical: &[u8], txn_id: &TxnId) -> Option<Vec<u8>> {
    let body = logical.strip_prefix(&[LOCAL_PREFIX, TXN_RECORD_MARKER][..])?;
    let body = body.strip_suffix(&txn_id[..])?;
    let escaped = body.strip_suffix(&[0x00, 0x01, TXN_RECORD_SUFFIX][..])?;
    let mut anchor = Vec::with_capacity(escaped.len());
    let mut bytes = escaped.iter();
    while let Some(&b) = bytes.next() {
        if b == 0x00 && bytes.next() != Some(&0xFF) {
            return None;
        }
        anchor.push(b);
    }
    Some(anchor)
}

/// Prefix extractor for the SST filters: strips the MVCC suffix so that lookups of any version
/// or the intent of *K* test the filter on *K* (§3, storage-engine.md §4). A key without a
/// valid suffix is used whole.
#[derive(Debug, Clone, Copy, Default)]
pub struct MvccPrefixExtractor;

impl PrefixExtractor for MvccPrefixExtractor {
    fn name(&self) -> &'static str {
        "rustegon.mvcc.v1"
    }

    fn prefix<'a>(&self, user_key: &'a [u8]) -> &'a [u8] {
        MvccKey::decode(user_key).map_or(user_key, |k| k.logical())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mvcc_key_round_trip() {
        let ts = Timestamp::new(0x0102_0304_0506_0708, 0x0A0B_0C0D);
        let v = version_key(b"abc", ts);
        assert_eq!(v.len(), 3 + VERSION_SUFFIX_LEN);
        assert_eq!(MvccKey::decode(&v).unwrap(), MvccKey::Version(b"abc", ts));
        assert_eq!(
            MvccKey::decode(&meta_key(b"abc")).unwrap(),
            MvccKey::Meta(b"abc")
        );
        // Empty logical key works too.
        assert_eq!(MvccKey::decode(&meta_key(b"")).unwrap(), MvccKey::Meta(b""));
        assert_eq!(
            MvccKey::decode(&version_key(b"", Timestamp::MAX)).unwrap(),
            MvccKey::Version(b"", Timestamp::MAX)
        );
    }

    #[test]
    fn mvcc_key_decoder_rejects_malformed() {
        assert!(MvccKey::decode(b"").is_err());
        assert!(MvccKey::decode(b"abc").is_err());
        assert!(MvccKey::decode(&[0x0D]).is_err());
        let mut v = version_key(b"abc", Timestamp::new(1, 2));
        let sep = v.len() - VERSION_SUFFIX_LEN;
        v[sep] = 0x07;
        assert!(MvccKey::decode(&v).is_err());
    }

    #[test]
    fn key_order_versions_newest_first() {
        let tss = [
            Timestamp::new(1, 0),
            Timestamp::new(1, 1),
            Timestamp::new(2, 0),
            Timestamp::new(u64::MAX, u32::MAX),
        ];
        for w in tss.windows(2) {
            assert!(version_key(b"k", w[1]) < version_key(b"k", w[0]));
        }
    }

    #[test]
    fn key_order_meta_before_versions() {
        for ts in [Timestamp::MIN, Timestamp::new(7, 3), Timestamp::MAX] {
            assert!(meta_key(b"k") < version_key(b"k", ts));
        }
    }

    #[test]
    fn key_order_entries_of_k_before_longer_keys() {
        // Every longer logical key continues K with a byte >= 0x01 (data-model.md §3.2).
        let longer: [&[u8]; 3] = [b"k\x01", b"k\x01\x00", b"kz"];
        for l in longer {
            for entry in [meta_key(b"k"), version_key(b"k", Timestamp::MIN)] {
                assert!(entry < meta_key(l));
                assert!(entry < version_key(l, Timestamp::MAX));
                assert!(entry < next_logical_key(b"k"));
                assert!(next_logical_key(b"k") <= meta_key(l));
            }
        }
    }

    #[test]
    fn prefix_extractor_strips_suffix() {
        let x = MvccPrefixExtractor;
        assert_eq!(x.prefix(&meta_key(b"doc")), b"doc");
        assert_eq!(x.prefix(&version_key(b"doc", Timestamp::new(9, 9))), b"doc");
        assert_eq!(x.prefix(b"raw"), b"raw");
    }

    #[test]
    fn txn_record_anchor_inverts_txn_record_key() {
        let id = [7; 16];
        for anchor in [&b""[..], b"a", b"a b", b" t", b"x "] {
            let key = txn_record_key(anchor, &id);
            assert_eq!(txn_record_anchor(&key, &id).as_deref(), Some(anchor));
            assert_eq!(txn_record_anchor(&key, &[8; 16]), None);
        }
        assert_eq!(txn_record_anchor(b"kab", &id), None);
        assert_eq!(txn_record_anchor(&meta_key(b"user"), &id), None);
    }

    #[test]
    fn txn_record_key_escapes_anchor() {
        let id = [7; 16];
        let k = txn_record_key(b"a\x00b", &id);
        let mut expect = vec![0x01, b'k', b'a', 0x00, 0xFF, b'b', 0x00, 0x01, b't'];
        expect.extend_from_slice(&id);
        assert_eq!(k, expect);
    }
}
