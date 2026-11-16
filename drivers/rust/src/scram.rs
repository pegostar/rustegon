// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! SCRAM-SHA-256 client (RFC 5802 / RFC 7677) without channel binding (gs2 header `n,,`,
//! PD-074), with `SASLprep` (RFC 4013) of the password. The client verifies the server signature,
//! so a server that does not know the credentials cannot complete the handshake (mutual
//! authentication). Pinned by `drivers/conformance/scram/vectors.yaml` (TC-DRV-RS-003).

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Smallest iteration count accepted on the wire (RFC 7677 §4): lower is a downgrade attempt.
const MIN_ITERATIONS: u32 = 4096;
/// Largest iteration count accepted: a hostile server could otherwise make the client spin.
const MAX_ITERATIONS: u32 = 10_000_000;
/// Largest accepted server message (bounds parsing of unauthenticated input).
const MAX_MESSAGE_LEN: usize = 4096;
const NONCE_ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// 24 base62 characters ≈ 143 bits.
const NONCE_LEN: usize = 24;

/// Why a SCRAM step failed (never says more: the reason is not shown to a peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramError {
    /// The password is not valid `SASLprep` text.
    SaslPrep,
    /// Malformed or unacceptable server message.
    Malformed,
    /// The server signature does not match (or the server reported an error).
    BadServerSignature,
    /// The operating system's random generator failed.
    Random,
}

/// `SASLprep` (RFC 4013) of a password, the profile the server applies too.
pub fn saslprep(password: &str) -> Result<String, ScramError> {
    stringprep::saslprep(password)
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| ScramError::SaslPrep)
}

/// Client state before the server-first message.
pub struct ScramClient {
    password: Zeroizing<String>,
    nonce: String,
    bare: String,
}

/// Client state before the server-final message.
pub struct ScramFinal {
    server_signature: [u8; 32],
}

impl std::fmt::Debug for ScramFinal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramFinal").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ScramClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramClient").finish_non_exhaustive()
    }
}

impl ScramClient {
    /// Starts a handshake with a fresh nonce; returns the state and the client-first message.
    pub fn new(user: &str, password: &str) -> Result<(Self, String), ScramError> {
        let mut raw = [0u8; NONCE_LEN];
        crate::random::fill_secure(&mut raw).map_err(|_| ScramError::Random)?;
        let nonce: String = raw
            .iter()
            .map(|b| char::from(NONCE_ALPHABET[usize::from(*b) % NONCE_ALPHABET.len()]))
            .collect();
        Self::with_nonce(user, password, &nonce)
    }

    /// Starts a handshake with a given nonce (conformance vectors).
    pub fn with_nonce(
        user: &str,
        password: &str,
        nonce: &str,
    ) -> Result<(Self, String), ScramError> {
        // SASLprep up front: a password the server would refuse fails before any I/O.
        let prepped = Zeroizing::new(saslprep(password)?);
        let bare = format!(
            "n={},r={nonce}",
            user.replace('=', "=3D").replace(',', "=2C")
        );
        let first = format!("n,,{bare}");
        Ok((
            Self {
                password: prepped,
                nonce: nonce.to_owned(),
                bare,
            },
            first,
        ))
    }

    /// Processes the server-first message; returns the client-final message.
    pub fn server_first(self, msg: &str) -> Result<(ScramFinal, String), ScramError> {
        if msg.len() > MAX_MESSAGE_LEN {
            return Err(ScramError::Malformed);
        }
        let mut parts = msg.split(',');
        let nonce = attr(parts.next(), 'r')?;
        let salt = B64
            .decode(attr(parts.next(), 's')?)
            .map_err(|_| ScramError::Malformed)?;
        let iterations: u32 = attr(parts.next(), 'i')?
            .parse()
            .map_err(|_| ScramError::Malformed)?;
        let printable = nonce
            .bytes()
            .all(|b| (0x21..=0x7E).contains(&b) && b != b',');
        if parts.next().is_some()
            || !printable
            || nonce.len() <= self.nonce.len()
            || !nonce.starts_with(&self.nonce)
            || salt.is_empty()
            || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
        {
            return Err(ScramError::Malformed);
        }
        let salted = Zeroizing::new(pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(
            self.password.as_bytes(),
            &salt,
            iterations,
        ));
        let mut client_key = hmac(salted.as_slice(), b"Client Key");
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let server_key = hmac(salted.as_slice(), b"Server Key");
        // `c=biws` is base64("n,,"): no channel binding.
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!("{},{msg},{without_proof}", self.bare);
        let signature = hmac(&stored_key, auth_message.as_bytes());
        let mut proof: [u8; 32] = std::array::from_fn(|i| client_key[i] ^ signature[i]);
        client_key.zeroize();
        let client_final = format!("{without_proof},p={}", B64.encode(proof));
        proof.zeroize();
        Ok((
            ScramFinal {
                server_signature: hmac(&server_key, auth_message.as_bytes()),
            },
            client_final,
        ))
    }
}

impl ScramFinal {
    /// Verifies the server-final message (`v=<signature>`).
    pub fn server_final(self, msg: &str) -> Result<(), ScramError> {
        if msg.len() > MAX_MESSAGE_LEN {
            return Err(ScramError::Malformed);
        }
        let v = attr(Some(msg), 'v').map_err(|_| ScramError::BadServerSignature)?;
        let sig = B64.decode(v).map_err(|_| ScramError::BadServerSignature)?;
        if bool::from(sig.ct_eq(&self.server_signature)) {
            Ok(())
        } else {
            Err(ScramError::BadServerSignature)
        }
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    // RFC 2104 §2: HMAC accepts keys of any length, so construction cannot fail; the fallback
    // (an all-zero MAC) would only make the handshake fail, never succeed wrongly.
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) else {
        return [0; 32];
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn attr(part: Option<&str>, key: char) -> Result<&str, ScramError> {
    let part = part.ok_or(ScramError::Malformed)?;
    let mut chars = part.chars();
    if chars.next() == Some(key) && chars.next() == Some('=') {
        Ok(&part[2..])
    } else {
        Err(ScramError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_drv_rs_003_rejects_downgrades() {
        let (c, first) = ScramClient::with_nonce("u", "p", "abcdefghijklmnop").unwrap();
        assert_eq!(first, "n,,n=u,r=abcdefghijklmnop");
        assert_eq!(
            c.server_first("r=abcdefghijklmnopX,s=c2FsdA==,i=1000")
                .unwrap_err(),
            ScramError::Malformed
        );
        let (c, _) = ScramClient::with_nonce("u", "p", "abcdefghijklmnop").unwrap();
        assert!(c.server_first("r=other,s=c2FsdA==,i=4096").is_err());
    }
}
