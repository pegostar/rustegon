// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! SCRAM client state machine (drivers, CLI and tests use it; the server side is in the parent
//! module). The client verifies the server signature, so a server that does not know the
//! credentials cannot complete the handshake (mutual authentication, RFC 5802 §3).

use base64::Engine as _;
use rustegon_sim_api::Rng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{
    B64, CHANNEL_BINDING_TYPE, MAX_ITERATIONS, MIN_ITERATIONS, Mechanism, NONCE_LEN,
    TLS_EXPORTER_LEN, attr, check_len, encode_saslname, fail, hmac, salted_password, sha256,
    valid_nonce,
};
use crate::authn::{
    SecretString,
    base62::{ALPHABET, random_string},
    error::{AuthnResult, FailureReason},
};

/// The channel binding a client uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientBinding {
    /// No TLS exporter available on the client: flag `n`.
    Unsupported,
    /// The client could bind but the server did not advertise the PLUS mechanism: flag `y`
    /// (lets the server detect a stripped mechanism list).
    NotOffered,
    /// `p=tls-exporter` with the connection's exporter value (mechanism PLUS).
    TlsExporter([u8; TLS_EXPORTER_LEN]),
}

/// Client state before the server-first message.
pub struct ScramClient {
    password: SecretString,
    gs2_header: String,
    cb_data: Vec<u8>,
    client_nonce: String,
    bare: String,
}

impl std::fmt::Debug for ScramClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramClient").finish_non_exhaustive()
    }
}

/// Client state before the server-final message.
pub struct ScramClientFinal {
    server_signature: [u8; 32],
}

impl std::fmt::Debug for ScramClientFinal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramClientFinal").finish_non_exhaustive()
    }
}

impl ScramClient {
    /// Starts a handshake; returns the client state, the mechanism to request and the
    /// client-first message.
    #[must_use]
    pub fn new(
        user: &str,
        password: &SecretString,
        binding: ClientBinding,
        rng: &dyn Rng,
    ) -> (Self, Mechanism, String) {
        let nonce = random_string(rng, ALPHABET, NONCE_LEN);
        Self::with_nonce(user, password, binding, &nonce)
    }

    pub(crate) fn with_nonce(
        user: &str,
        password: &SecretString,
        binding: ClientBinding,
        nonce: &str,
    ) -> (Self, Mechanism, String) {
        let (flag, cb_data, mechanism) = match binding {
            ClientBinding::Unsupported => ("n".to_owned(), Vec::new(), Mechanism::ScramSha256),
            ClientBinding::NotOffered => ("y".to_owned(), Vec::new(), Mechanism::ScramSha256),
            ClientBinding::TlsExporter(e) => (
                format!("p={CHANNEL_BINDING_TYPE}"),
                e.to_vec(),
                Mechanism::ScramSha256Plus,
            ),
        };
        let bare = format!("n={},r={nonce}", encode_saslname(user));
        let gs2_header = format!("{flag},,");
        let msg = format!("{gs2_header}{bare}");
        (
            Self {
                password: password.clone(),
                gs2_header,
                cb_data,
                client_nonce: nonce.to_owned(),
                bare,
            },
            mechanism,
            msg,
        )
    }

    /// Processes the server-first message; returns the client-final message.
    ///
    /// # Errors
    /// Generic authentication failure: malformed message, a nonce that does not extend the
    /// client nonce, an iteration count outside [`MIN_ITERATIONS`]..=[`MAX_ITERATIONS`], or a
    /// password `SASLprep` rejects.
    pub fn server_first(self, msg: &str) -> AuthnResult<(ScramClientFinal, String)> {
        check_len(msg)?;
        let mut attrs = msg.split(',');
        let nonce = attr(attrs.next(), 'r')?;
        let salt = B64
            .decode(attr(attrs.next(), 's')?)
            .map_err(|_| fail(FailureReason::Malformed))?;
        let iterations: u32 = attr(attrs.next(), 'i')?
            .parse()
            .map_err(|_| fail(FailureReason::Malformed))?;
        if attrs.next().is_some()
            || !valid_nonce(nonce)
            || nonce.len() <= self.client_nonce.len()
            || !nonce.starts_with(&self.client_nonce)
            || salt.is_empty()
            || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
        {
            return Err(fail(FailureReason::Malformed));
        }
        let salted = salted_password(self.password.expose(), &salt, iterations)?;
        let mut client_key = hmac(salted.as_slice(), b"Client Key");
        let stored_key = sha256(&client_key);
        let server_key = hmac(salted.as_slice(), b"Server Key");
        let mut cbind = self.gs2_header.as_bytes().to_vec();
        cbind.extend_from_slice(&self.cb_data);
        let without_proof = format!("c={},r={nonce}", B64.encode(&cbind));
        let auth_message = format!("{},{msg},{without_proof}", self.bare);
        let signature = hmac(&stored_key, auth_message.as_bytes());
        let mut proof: [u8; 32] = std::array::from_fn(|i| client_key[i] ^ signature[i]);
        client_key.zeroize();
        let client_final = format!("{without_proof},p={}", B64.encode(proof));
        proof.zeroize();
        Ok((
            ScramClientFinal {
                server_signature: hmac(&server_key, auth_message.as_bytes()),
            },
            client_final,
        ))
    }
}

impl ScramClientFinal {
    /// Verifies the server-final message: proves that the server knows the credentials (mutual
    /// authentication).
    ///
    /// # Errors
    /// Generic authentication failure for `e=…`, a malformed message or a wrong signature.
    pub fn server_final(self, msg: &str) -> AuthnResult<()> {
        check_len(msg)?;
        let v = attr(Some(msg), 'v').map_err(|_| fail(FailureReason::BadCredentials))?;
        let sig = B64.decode(v).map_err(|_| fail(FailureReason::Malformed))?;
        if bool::from(sig.ct_eq(&self.server_signature)) {
            Ok(())
        } else {
            Err(fail(FailureReason::BadCredentials))
        }
    }
}
