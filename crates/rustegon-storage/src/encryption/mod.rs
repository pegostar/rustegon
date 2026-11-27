// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Encryption at rest: envelope encryption with per-file data keys (storage-engine.md §7,
//! security.md §6, FR-EAR-001 format part).
//!
//! Key hierarchy:
//! - the **KEK** (key-encryption key) lives outside the store and is reached through a
//!   [`KekProvider`]; M1 ships the file provider ([`FileKekProvider`]), M4 adds `env`, M13 the
//!   KMS providers;
//! - every encrypted file (SST, MANIFEST) gets its own random 256-bit **DEK**, wrapped by the KEK
//!   and recorded in the DEK registry `keys/registry.enc` ([`KeyManager`]) before the file is
//!   written, so a durable file is always decryptable;
//! - data is sealed with AES-256-GCM under the file's DEK ([`FileCipher`]).
//!
//! Nonces (§7): `file_number (u64 LE) ‖ counter (u32 LE)`. SST blocks use
//! `counter = block_offset / 16`, MANIFEST records `counter = record index` (the log scheme
//! "`segment_id ‖ record_seq`" with the MANIFEST number as segment id). Uniqueness argument, per
//! DEK (nonce reuse under one GCM key is catastrophic, so this is the invariant that matters):
//! - a DEK encrypts exactly one file and is never reused: [`KeyManager::new_file_cipher`] draws a
//!   fresh random DEK and refuses a file number that already has one, and
//!   `VersionSet::open_with` moves the next file number past every registered DEK, so a number is
//!   never handed out twice after a crash;
//! - files are immutable and written once front to back, so block offsets are distinct; every
//!   encrypted block occupies at least `TAG_LEN + BLOCK_TRAILER_LEN` = 26 > 16 bytes on disk, so
//!   `offset / 16` is strictly increasing from block to block (offsets need no alignment);
//! - a MANIFEST is never appended to after it is reopened (recovery starts a new one), so record
//!   indices are distinct;
//! - counters that would not fit 32 bits (an SST beyond 64 GiB, a MANIFEST beyond 2^32 records)
//!   are refused by the writer instead of wrapping.
//!
//! Key material is held in zeroize-on-drop buffers ([`SecretKey`]; the AES key schedule inside
//! [`FileCipher`] is zeroized by `aes-gcm`'s `zeroize` feature) and never printed: every `Debug`
//! impl here redacts. Zeroization is best effort: short-lived stack copies made while keying a
//! cipher are not tracked. `mlock` (best effort, §7) is not done in M1: it needs `unsafe` platform
//! calls outside `rustegon-sim-api` and is tracked with the M4 key-provider work.
//!
//! Out of scope in M1 (later tasks): Raft log segments, HNSW snapshots, spill files and
//! checkpoints (their writers call [`KeyManager::new_file_cipher`] with their own file numbers
//! when they land), the KEK rotation CLI and DEK rotation by forced compaction (the hook is
//! [`KeyManager::forget`] plus a full compaction: rewritten files get fresh DEKs).

mod kek;
mod registry;

use std::fmt;

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit},
};
pub use kek::{FileKekProvider, KekId, KekProvider, WrappedKey};
pub use registry::{KeyManager, REGISTRY_FILE_NAME};
use rustegon_common::Redacted;
use rustegon_sim_api::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, StorageError};

/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;
/// AES-GCM nonce length in bytes (96 bits, the GCM standard size, NIST SP 800-38D).
pub const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes (full 128-bit tag; truncated tags are not used).
pub const TAG_LEN: usize = 16;

/// A 256-bit secret key (a DEK or KEK), zeroized on drop and never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Wraps raw key bytes. The caller should zeroize its own copy.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// A fresh random key from `rng` (the OS CSPRNG in production, seeded in simulation).
    #[must_use]
    pub fn generate(rng: &dyn Rng) -> Self {
        let mut key = Self([0u8; KEY_LEN]);
        rng.fill_bytes(&mut key.0);
        key
    }

    /// The key bytes. Call sites are the audit points for key use.
    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// An AES-256-GCM instance keyed with this key.
    pub(crate) fn aead(&self) -> Aes256Gcm {
        Aes256Gcm::new(&self.0.into())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({:?})", Redacted::new(()))
    }
}

/// Builds the 12-byte nonce `file_number (u64 LE) ‖ counter (u32 LE)` (module docs). Little
/// endian like every other integer in the store's formats.
#[must_use]
pub fn file_nonce(file_number: u64, counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&file_number.to_le_bytes());
    nonce[8..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Seals `buf[from..]` in place with `aead` and appends the tag.
fn seal(
    aead: &Aes256Gcm,
    nonce: [u8; NONCE_LEN],
    associated: &[u8],
    buf: &mut Vec<u8>,
    from: usize,
) -> Result<()> {
    let Some(plain) = buf.get_mut(from..) else {
        return Err(StorageError::InvalidArgument(
            "seal range outside buffer".into(),
        ));
    };
    let tag = aead
        .encrypt_inout_detached(&nonce.into(), associated, plain.into())
        // GCM refuses only messages beyond 2^36 bytes; blocks and records are far smaller.
        .map_err(|_| StorageError::InvalidArgument("message too long for AES-GCM".into()))?;
    buf.extend_from_slice(tag.as_slice());
    Ok(())
}

/// Verifies and decrypts `buf` = `ciphertext ‖ tag` in place, truncating the tag. `Err(())` on
/// a short buffer or an authentication failure; callers map it to their error kind.
fn open(
    aead: &Aes256Gcm,
    nonce: [u8; NONCE_LEN],
    associated: &[u8],
    buf: &mut Vec<u8>,
) -> std::result::Result<(), ()> {
    let body_len = buf.len().checked_sub(TAG_LEN).ok_or(())?;
    let (body, tag) = buf.split_at_mut(body_len);
    let tag: &[u8] = tag;
    let tag = tag.try_into().map_err(|_| ())?;
    aead.decrypt_inout_detached(&nonce.into(), associated, body.into(), tag)
        .map_err(|_| ())?;
    buf.truncate(body_len);
    Ok(())
}

/// The AES-256-GCM context of one encrypted file: its number (the nonce prefix) and its DEK.
pub struct FileCipher {
    file_number: u64,
    aead: Aes256Gcm,
}

impl FileCipher {
    /// A cipher for file `file_number` keyed with `dek`.
    #[must_use]
    pub fn new(file_number: u64, dek: &SecretKey) -> Self {
        Self {
            file_number,
            aead: dek.aead(),
        }
    }

    /// The file number this cipher's nonces are bound to.
    #[must_use]
    pub fn file_number(&self) -> u64 {
        self.file_number
    }

    /// Encrypts `buf[from..]` in place under nonce `counter` and appends the 16-byte tag.
    /// `aad` is authenticated but not encrypted (e.g. the block's codec byte).
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] if `from` is past the end of `buf`.
    pub fn seal_in_place(
        &self,
        counter: u32,
        aad: &[u8],
        buf: &mut Vec<u8>,
        from: usize,
    ) -> Result<()> {
        seal(
            &self.aead,
            file_nonce(self.file_number, counter),
            aad,
            buf,
            from,
        )
    }

    /// Encrypts `buf` in place under nonce `counter` and returns the 16-byte tag, for callers
    /// that reserved the tag's place themselves (Raft log entry payloads, PD-057).
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] beyond the 2^36-byte GCM message limit.
    pub fn seal_detached(&self, counter: u32, aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let tag = self
            .aead
            .encrypt_inout_detached(
                &file_nonce(self.file_number, counter).into(),
                aad,
                buf.into(),
            )
            .map_err(|_| StorageError::InvalidArgument("message too long for AES-GCM".into()))?;
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_slice());
        Ok(out)
    }

    /// Verifies and decrypts `buf` = `ciphertext ‖ tag` in place (the tag is removed).
    ///
    /// # Errors
    /// [`StorageError::Corruption`] when the tag does not verify (tampered or damaged
    /// ciphertext, wrong counter, wrong DEK) or `buf` is shorter than a tag.
    pub fn open_in_place(&self, counter: u32, aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        open(&self.aead, file_nonce(self.file_number, counter), aad, buf).map_err(|()| {
            StorageError::corruption(format!(
                "AES-GCM authentication failed in file {} (counter {counter})",
                self.file_number
            ))
        })
    }
}

impl fmt::Debug for FileCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileCipher")
            .field("file_number", &self.file_number)
            .field("dek", &Redacted::new(()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// Deterministic splitmix64 RNG for tests (simulation-style seeded randomness).
    #[derive(Debug, Default)]
    pub(crate) struct TestRng(pub(crate) AtomicU64);

    impl Rng for TestRng {
        fn fill_bytes(&self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let mut z = self
                    .0
                    .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
                    .wrapping_add(0x9E37_79B9_7F4A_7C15);
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
            }
        }
    }

    #[test]
    fn nonce_layout_is_file_number_then_counter_le() {
        let n = file_nonce(0x0102_0304_0506_0708, 0x0A0B_0C0D);
        assert_eq!(n, [8, 7, 6, 5, 4, 3, 2, 1, 0x0D, 0x0C, 0x0B, 0x0A]);
    }

    #[test]
    fn seal_open_round_trip_and_tamper_detection() {
        let rng = TestRng::default();
        let dek = SecretKey::generate(&rng);
        let cipher = FileCipher::new(7, &dek);
        let mut buf = b"head:".to_vec();
        buf.extend_from_slice(b"secret payload");
        cipher.seal_in_place(3, b"aad", &mut buf, 5).unwrap();
        assert_eq!(buf.len(), 5 + 14 + TAG_LEN);
        assert!(!buf.windows(6).any(|w| w == b"secret"));
        let sealed = buf[5..].to_vec();

        let mut ok = sealed.clone();
        cipher.open_in_place(3, b"aad", &mut ok).unwrap();
        assert_eq!(ok, b"secret payload");

        // Wrong counter, wrong AAD, wrong file number, flipped bit, short buffer: all rejected.
        let mut bad = sealed.clone();
        assert!(cipher.open_in_place(4, b"aad", &mut bad).is_err());
        let mut bad = sealed.clone();
        assert!(cipher.open_in_place(3, b"aaD", &mut bad).is_err());
        let mut bad = sealed.clone();
        assert!(
            FileCipher::new(8, &dek)
                .open_in_place(3, b"aad", &mut bad)
                .unwrap_err()
                .is_corruption()
        );
        for at in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[at] ^= 0x01;
            assert!(cipher.open_in_place(3, b"aad", &mut bad).is_err(), "{at}");
        }
        let mut short = vec![0u8; TAG_LEN - 1];
        assert!(cipher.open_in_place(3, b"aad", &mut short).is_err());
        assert!(cipher.seal_in_place(0, b"", &mut Vec::new(), 1).is_err());
    }

    #[test]
    fn debug_output_never_contains_key_bytes() {
        let key = SecretKey::from_bytes([0xAB; KEY_LEN]);
        let printed = format!("{key:?} {:?}", FileCipher::new(1, &key));
        assert!(!printed.contains("171") && !printed.to_lowercase().contains("ab, "));
        assert!(
            printed.contains(rustegon_common::redacted::REDACTED),
            "{printed}"
        );
    }
}
