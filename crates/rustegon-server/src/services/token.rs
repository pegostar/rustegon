// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Sealed continuation tokens (FR-QL-007, query-language.md §5.2, query-engine.md §7, PD-041,
//! PD-053).
//!
//! The engine's token (format 1: `rdoc(position) ‖ xxh3_64`) only detects corruption; it would
//! let a client read and forge keyset positions, and the position holds row values. The server
//! therefore never hands it out as is: it is encrypted and authenticated with AES-256-GCM.
//!
//! Sealed format 1: `0x01 ‖ nonce (12 B, random) ‖ AES-256-GCM(engine token) ‖ tag (16 B)`.
//! The associated data binds the token to its purpose and to its owner
//! (`"rustegon.v1.continuation-token" 0x00 principal`), so a token issued to one user does not
//! open for another. Any failure to open — truncation, a flipped bit, another key, another
//! owner — is `RGN-1001` (the token is invalid), indistinguishable to the client.
//!
//! **Key** (*Provisional (PD-053)*): `DataPlaneConfig::token_key` (32 bytes, meant to come from
//! the cluster secret when it exists), else a random key per process. With the random key,
//! tokens do not survive a restart (and are not valid on another node): a client then gets
//! RGN-1001 and must restart its paging from the first page. Random 96-bit nonces stay far
//! below the GCM collision bound for the number of tokens one key issues between restarts.

use std::sync::Arc;

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit},
};
use rustegon_common::{Error, ErrorCode};
use rustegon_sim_api::Rng;

/// Sealed token format version.
const FORMAT: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Domain separation of the associated data.
const PURPOSE: &[u8] = b"rustegon.v1.continuation-token";

/// Seals and opens continuation tokens with one key.
pub(crate) struct TokenSealer {
    aead: Aes256Gcm,
    rng: Arc<dyn Rng>,
}

fn invalid() -> Error {
    Error::new(ErrorCode::InvalidArgument, "invalid continuation token")
}

fn associated(owner: Option<&str>) -> Vec<u8> {
    let owner = owner.unwrap_or("").as_bytes();
    let mut aad = Vec::with_capacity(PURPOSE.len() + 1 + owner.len());
    aad.extend_from_slice(PURPOSE);
    aad.push(0);
    aad.extend_from_slice(owner);
    aad
}

impl TokenSealer {
    pub(crate) fn new(key: &[u8; 32], rng: Arc<dyn Rng>) -> Self {
        Self {
            aead: Aes256Gcm::new(&(*key).into()),
            rng,
        }
    }

    /// Seals the engine token `raw` for `owner`.
    ///
    /// # Errors
    /// RGN-5001 if AES-GCM refuses the message (only beyond 2^36 bytes).
    pub(crate) fn seal(&self, raw: &[u8], owner: Option<&str>) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill_bytes(&mut nonce);
        let mut out = Vec::with_capacity(1 + NONCE_LEN + raw.len() + TAG_LEN);
        out.push(FORMAT);
        out.extend_from_slice(&nonce);
        let body_at = out.len();
        out.extend_from_slice(raw);
        let tag = self
            .aead
            .encrypt_inout_detached(
                &nonce.into(),
                &associated(owner),
                (&mut out[body_at..]).into(),
            )
            .map_err(|_| Error::new(ErrorCode::Internal, "continuation token too long"))?;
        out.extend_from_slice(tag.as_slice());
        Ok(out)
    }

    /// Opens a sealed token issued to `owner` and returns the engine token.
    ///
    /// # Errors
    /// RGN-1001 for anything that is not a token this key sealed for `owner`.
    pub(crate) fn open(&self, sealed: &[u8], owner: Option<&str>) -> Result<Vec<u8>, Error> {
        if sealed.len() < 1 + NONCE_LEN + TAG_LEN || sealed[0] != FORMAT {
            return Err(invalid());
        }
        let nonce: [u8; NONCE_LEN] = sealed[1..=NONCE_LEN].try_into().map_err(|_| invalid())?;
        let tag_at = sealed.len() - TAG_LEN;
        let tag: [u8; TAG_LEN] = sealed[tag_at..].try_into().map_err(|_| invalid())?;
        let mut body = sealed[1 + NONCE_LEN..tag_at].to_vec();
        self.aead
            .decrypt_inout_detached(
                &nonce.into(),
                &associated(owner),
                body.as_mut_slice().into(),
                &tag.into(),
            )
            .map_err(|_| invalid())?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rustegon_sim_api::OsRng;

    use super::*;

    #[test]
    fn fr_ql_007_sealed_token_round_trips_and_rejects_tampering() {
        let tokens = TokenSealer::new(&[7; 32], Arc::new(OsRng));
        let plain = b"engine token bytes".to_vec();
        let sealed = tokens.seal(&plain, Some("alice")).unwrap();
        assert!(
            !sealed.windows(plain.len()).any(|w| w == plain.as_slice()),
            "plaintext leaked"
        );
        assert_eq!(tokens.open(&sealed, Some("alice")).unwrap(), plain);
        // Another owner, another key, any flipped bit, truncation: RGN-1001.
        assert_eq!(
            tokens.open(&sealed, Some("bob")).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        let other = TokenSealer::new(&[8; 32], Arc::new(OsRng));
        assert!(other.open(&sealed, Some("alice")).is_err());
        for i in 0..sealed.len() {
            let mut t = sealed.clone();
            t[i] ^= 0x01;
            assert!(tokens.open(&t, Some("alice")).is_err(), "bit flip at {i}");
        }
        assert!(
            tokens
                .open(&sealed[..sealed.len() - 1], Some("alice"))
                .is_err()
        );
        assert!(tokens.open(&[], None).is_err());
        // Nonces are random: sealing twice gives different tokens.
        assert_ne!(
            tokens.seal(&plain, None).unwrap(),
            tokens.seal(&plain, None).unwrap()
        );
    }
}
