// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! SCRAM-SHA-256 and SCRAM-SHA-256-PLUS (RFC 5802, RFC 7677, channel binding `tls-exporter`
//! RFC 9266), as sans-I/O server and client state machines (security.md §2, FR-SEC-001,
//! TC-SEC-002).
//!
//! ```text
//! client-first  gs2-header client-first-bare     gs2-header = cbind-flag "," [a=authzid] ","
//! server-first  r=<cnonce><snonce>,s=<salt b64>,i=<iterations>
//! client-final  c=<b64(gs2-header + cb-data)>,r=<nonce>,p=<b64(ClientProof)>
//! server-final  v=<b64(ServerSignature)>
//! ```
//! - Key derivation (RFC 5802 §3): `SaltedPassword = PBKDF2-HMAC-SHA256(SASLprep(password),
//!   salt, i)`, `ClientKey = HMAC(SaltedPassword, "Client Key")`, `StoredKey = SHA256(ClientKey)`,
//!   `ServerKey = HMAC(SaltedPassword, "Server Key")`. The server stores only salt, iterations,
//!   `StoredKey` and `ServerKey` ([`ScramCredentials`]): a stolen record does not reveal the
//!   password and cannot be replayed as a proof without an offline dictionary attack.
//! - Unknown users, users without a password and disabled users all go through a complete
//!   handshake (PD-047): the server-first message of an unknown user carries a salt derived from
//!   a cluster-wide secret ([`FakeSaltKey`]) and the user name — stable across attempts, like a
//!   real salt — and the configured iteration count, and the final proof check fails exactly
//!   like a wrong password. The server never runs PBKDF2 during a handshake (it holds the
//!   derived keys), so the fake path costs the same few HMACs as the real one.
//! - Every check of client-supplied secrets (`StoredKey`, nonce, channel binding) and of the
//!   server signature on the client side is constant-time (`subtle`).
//! - Strictness (PD-047): extensions (`m=` and any other attribute) are rejected, an `authzid`
//!   other than the authenticated user is rejected (no impersonation), client nonces need at
//!   least [`MIN_NONCE_LEN`] printable characters, and messages are bounded by
//!   [`MAX_MESSAGE_LEN`]. Errors are the generic [`AuthnError::AuthenticationFailed`]; the
//!   server sends no `e=` message (the wire layer maps the error to `RGN-4001`).
//!
//! The client is in `scram/client.rs`; the server, the credentials and the shared parsers stay here
//! together (slightly above the 600-line file target) because they share private helpers.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, KeyInit, Mac};
use rustegon_sim_api::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::authn::{
    base62::{ALPHABET, random_string},
    error::{AuthnError, AuthnResult, FailureReason},
};

/// SASL mechanism name without channel binding.
pub const MECHANISM: &str = "SCRAM-SHA-256";
/// SASL mechanism name with channel binding.
pub const MECHANISM_PLUS: &str = "SCRAM-SHA-256-PLUS";
/// The only supported channel binding type (RFC 9266).
pub const CHANNEL_BINDING_TYPE: &str = "tls-exporter";
/// Length in bytes of the RFC 9266 `tls-exporter` value (label `EXPORTER-Channel-Binding`).
pub const TLS_EXPORTER_LEN: usize = 32;
/// Default PBKDF2 iteration count of new credentials (security.md §2).
pub const DEFAULT_ITERATIONS: u32 = 600_000;
/// Smallest iteration count the configuration accepts (security.md §2, ⚙ ≥ 100 000).
pub const MIN_CONFIG_ITERATIONS: u32 = 100_000;
/// Smallest iteration count accepted on the wire (RFC 7677 §4: at least 4096). Lower values
/// in a server-first message are a downgrade attempt and the client refuses them.
pub const MIN_ITERATIONS: u32 = 4096;
/// Largest iteration count a client accepts: a malicious server could otherwise make the
/// client spin for minutes (about 20 s of PBKDF2 at 10 M iterations on current CPUs).
pub const MAX_ITERATIONS: u32 = 10_000_000;
/// Salt length of new credentials in bytes (security.md §2).
pub const SALT_LEN: usize = 16;
/// Smallest accepted client nonce (characters): 16 base62 characters are ~95 bits.
pub const MIN_NONCE_LEN: usize = 16;
/// Largest accepted SCRAM message in bytes (bounds parsing work on unauthenticated input).
pub const MAX_MESSAGE_LEN: usize = 4096;
/// Characters of a generated nonce: 24 base62 characters are ~143 bits.
const NONCE_LEN: usize = 24;
/// Domain separation of the fake salt derivation; `v1` versions the derivation (changing it
/// changes every unknown user's salt, which is harmless but should be deliberate).
const FAKE_SALT_DOMAIN: &[u8] = b"rustegon/scram/fake-salt/v1\0";

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    // RFC 2104 §2: HMAC accepts keys of any length (long keys are hashed), so construction
    // cannot fail.
    #[allow(clippy::expect_used)]
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn fail(reason: FailureReason) -> AuthnError {
    AuthnError::failed(reason)
}

/// Which SASL mechanism the client selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// `SCRAM-SHA-256`: cbind flag `n` or `y`.
    ScramSha256,
    /// `SCRAM-SHA-256-PLUS`: cbind flag `p=tls-exporter`.
    ScramSha256Plus,
}

impl Mechanism {
    /// Parses a SASL mechanism name.
    ///
    /// # Errors
    /// Generic authentication failure for any other name.
    pub fn parse(name: &str) -> AuthnResult<Self> {
        match name {
            MECHANISM => Ok(Self::ScramSha256),
            MECHANISM_PLUS => Ok(Self::ScramSha256Plus),
            _ => Err(fail(FailureReason::Malformed)),
        }
    }
}

/// The server-side SCRAM credentials of one user (security.md §2).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ScramCredentials {
    salt: Vec<u8>,
    #[zeroize(skip)]
    iterations: u32,
    stored_key: [u8; 32],
    server_key: [u8; 32],
}

impl std::fmt::Debug for ScramCredentials {
    // The keys are verifiers, not passwords, but `ServerKey` lets its holder impersonate the
    // server and `StoredKey` enables offline guessing: keep both out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramCredentials")
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
}

/// `SASLprep` (RFC 4013) of a password; RFC 5802 §5.1 requires it before key derivation so that
/// equivalent Unicode spellings derive the same key.
fn prep_password(password: &str) -> AuthnResult<Zeroizing<String>> {
    stringprep::saslprep(password)
        .map(|p| Zeroizing::new(p.into_owned()))
        .map_err(|_| AuthnError::InvalidArgument("password is not valid SASLprep text".into()))
}

fn salted_password(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> AuthnResult<Zeroizing<[u8; 32]>> {
    let prepped = prep_password(password)?;
    Ok(Zeroizing::new(pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(
        prepped.as_bytes(),
        salt,
        iterations,
    )))
}

impl ScramCredentials {
    /// Derives the credentials of `password` with `salt` and `iterations`.
    ///
    /// # Errors
    /// `InvalidArgument` for an empty salt, fewer than [`MIN_ITERATIONS`] iterations or a
    /// password that `SASLprep` rejects.
    pub fn derive(password: &str, salt: &[u8], iterations: u32) -> AuthnResult<Self> {
        if salt.is_empty() || iterations < MIN_ITERATIONS {
            return Err(AuthnError::InvalidArgument(format!(
                "SCRAM needs a salt and at least {MIN_ITERATIONS} iterations"
            )));
        }
        let salted = salted_password(password, salt, iterations)?;
        let mut client_key = hmac(salted.as_slice(), b"Client Key");
        let stored_key = sha256(&client_key);
        client_key.zeroize();
        Ok(Self {
            salt: salt.to_vec(),
            iterations,
            stored_key,
            server_key: hmac(salted.as_slice(), b"Server Key"),
        })
    }

    /// Derives credentials of `password` with a fresh random [`SALT_LEN`]-byte salt.
    ///
    /// # Errors
    /// As [`ScramCredentials::derive`].
    pub fn generate(password: &str, iterations: u32, rng: &dyn Rng) -> AuthnResult<Self> {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        Self::derive(password, &salt, iterations)
    }

    /// Rebuilds credentials from their persisted parts.
    #[must_use]
    pub fn from_parts(
        salt: Vec<u8>,
        iterations: u32,
        stored_key: [u8; 32],
        server_key: [u8; 32],
    ) -> Self {
        Self {
            salt,
            iterations,
            stored_key,
            server_key,
        }
    }

    /// Whether `password` matches, for the GUI's password-over-TLS login (protocol.md §3),
    /// which verifies on the server through the same SCRAM verifier. Runs PBKDF2, so it costs
    /// the full iteration count; the comparison is constant-time.
    #[must_use]
    pub fn verify_password(&self, password: &str) -> bool {
        match Self::derive(password, &self.salt, self.iterations) {
            Ok(other) => bool::from(other.stored_key.ct_eq(&self.stored_key)),
            Err(_) => false,
        }
    }

    /// The salt.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The PBKDF2 iteration count.
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// `StoredKey = SHA256(ClientKey)`.
    #[must_use]
    pub const fn stored_key(&self) -> &[u8; 32] {
        &self.stored_key
    }

    /// `ServerKey = HMAC(SaltedPassword, "Server Key")`.
    #[must_use]
    pub const fn server_key(&self) -> &[u8; 32] {
        &self.server_key
    }
}

/// The cluster-wide secret from which fake salts of unknown users are derived (module docs).
/// Every node must use the same key, or comparing two nodes' salts would reveal that a user
/// does not exist; it is stored in the system keyspace ([`crate::authn::realm`]).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FakeSaltKey([u8; 32]);

impl std::fmt::Debug for FakeSaltKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeSaltKey(‹redacted›)")
    }
}

impl FakeSaltKey {
    /// Wraps a 32-byte key.
    #[must_use]
    pub const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// A fresh random key.
    #[must_use]
    pub fn generate(rng: &dyn Rng) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        Self(key)
    }

    /// The key bytes (persistence only).
    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// The fake salt of `user`: `HMAC(key, domain || user)[..SALT_LEN]`.
    #[must_use]
    pub fn salt_for(&self, user: &str) -> [u8; SALT_LEN] {
        let mut data = FAKE_SALT_DOMAIN.to_vec();
        data.extend_from_slice(user.as_bytes());
        let mac = hmac(&self.0, &data);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&mac[..SALT_LEN]);
        salt
    }
}

/// What the server knows about the user named in the client-first message.
#[derive(Debug)]
pub enum CredentialState {
    /// Enabled user with a password.
    Usable(ScramCredentials),
    /// Disabled user with a password: the handshake runs with the real salt (so that disabling
    /// a user is not observable) and fails at the proof check.
    Disabled(ScramCredentials),
    /// Unknown user or user without a password: fake handshake.
    Unknown,
}

/// The channel binding the server's connection offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerBinding {
    /// No TLS exporter (no TLS, or TLS 1.2 without extended master secret): the server does
    /// not advertise `SCRAM-SHA-256-PLUS`.
    Unavailable,
    /// The RFC 9266 `tls-exporter` value of the connection; the server advertises the PLUS
    /// mechanism.
    TlsExporter([u8; TLS_EXPORTER_LEN]),
}

/// Server inputs that do not depend on the client.
#[derive(Debug)]
pub struct ServerContext<'a> {
    /// Channel binding of the connection.
    pub binding: ServerBinding,
    /// Key of the fake salts.
    pub fake_salt_key: &'a FakeSaltKey,
    /// Iteration count announced for unknown users: the configured default for new passwords.
    pub default_iterations: u32,
}

/// The gs2 channel-binding flag of a client-first message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CbindFlag {
    /// `n`: client does not support channel binding.
    No,
    /// `y`: client supports it but believes the server does not.
    ClientOnly,
    /// `p=tls-exporter`.
    TlsExporter,
}

/// A parsed client-first message.
#[derive(Debug)]
pub struct ClientFirst {
    mechanism: Mechanism,
    cbind: CbindFlag,
    gs2_header: String,
    user: String,
    client_nonce: String,
    bare: String,
}

fn check_len(msg: &str) -> AuthnResult<()> {
    if msg.len() > MAX_MESSAGE_LEN {
        return Err(fail(FailureReason::Malformed));
    }
    Ok(())
}

/// Decodes a SASL `saslname` (`=2C` → `,`, `=3D` → `=`, RFC 5802 §5.1).
fn decode_saslname(s: &str) -> AuthnResult<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('=') {
        out.push_str(&rest[..i]);
        match rest.get(i..i + 3) {
            Some("=2C") => out.push(','),
            Some("=3D") => out.push('='),
            _ => return Err(fail(FailureReason::Malformed)),
        }
        rest = &rest[i + 3..];
    }
    out.push_str(rest);
    if out.is_empty() {
        return Err(fail(FailureReason::Malformed));
    }
    Ok(out)
}

/// Encodes a SASL `saslname`.
fn encode_saslname(s: &str) -> String {
    s.replace('=', "=3D").replace(',', "=2C")
}

/// RFC 5802 §7: `printable = %x21-2B / %x2D-7E` (no comma).
fn valid_nonce(n: &str) -> bool {
    !n.is_empty() && n.bytes().all(|b| (0x21..=0x7E).contains(&b) && b != b',')
}

/// Splits `k=v` and checks the key.
fn attr(part: Option<&str>, key: char) -> AuthnResult<&str> {
    let part = part.ok_or_else(|| fail(FailureReason::Malformed))?;
    let mut chars = part.chars();
    if chars.next() == Some(key) && chars.next() == Some('=') {
        Ok(&part[2..])
    } else {
        Err(fail(FailureReason::Malformed))
    }
}

impl ClientFirst {
    /// Parses a client-first message for `mechanism`.
    ///
    /// # Errors
    /// Generic authentication failure: malformed message, extensions, a channel binding flag
    /// that does not match the mechanism or a channel binding type other than `tls-exporter`.
    pub fn parse(mechanism: Mechanism, msg: &str) -> AuthnResult<Self> {
        check_len(msg)?;
        let mut parts = msg.splitn(3, ',');
        let flag = parts.next().ok_or_else(|| fail(FailureReason::Malformed))?;
        let authzid = parts.next().ok_or_else(|| fail(FailureReason::Malformed))?;
        let bare = parts.next().ok_or_else(|| fail(FailureReason::Malformed))?;
        let cbind = match flag {
            "n" => CbindFlag::No,
            "y" => CbindFlag::ClientOnly,
            f if f.strip_prefix("p=") == Some(CHANNEL_BINDING_TYPE) => CbindFlag::TlsExporter,
            _ => return Err(fail(FailureReason::ChannelBinding)),
        };
        // The PLUS mechanism is exactly the channel-bound variant (RFC 5802 §6).
        let plus = cbind == CbindFlag::TlsExporter;
        if plus != (mechanism == Mechanism::ScramSha256Plus) {
            return Err(fail(FailureReason::ChannelBinding));
        }
        let mut attrs = bare.split(',');
        let user = decode_saslname(attr(attrs.next(), 'n')?)?;
        let client_nonce = attr(attrs.next(), 'r')?;
        // `m=` and any other extension: RFC 5802 §5.1 requires failing on `m`; we have no
        // extensions, so everything else is rejected too (PD-047).
        if attrs.next().is_some()
            || !valid_nonce(client_nonce)
            || client_nonce.len() < MIN_NONCE_LEN
        {
            return Err(fail(FailureReason::Malformed));
        }
        if !authzid.is_empty() {
            // Only `a=<the same user>` is accepted: acting as another identity is not a feature.
            if decode_saslname(attr(Some(authzid), 'a')?)? != user {
                return Err(fail(FailureReason::BadCredentials));
            }
        }
        Ok(Self {
            mechanism,
            cbind,
            gs2_header: format!("{flag},{authzid},"),
            user,
            client_nonce: client_nonce.to_owned(),
            bare: bare.to_owned(),
        })
    }

    /// The user name (`n=`), to look up the credentials.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The selected mechanism.
    #[must_use]
    pub const fn mechanism(&self) -> Mechanism {
        self.mechanism
    }
}

/// Server state between server-first and client-final.
pub struct ScramServer {
    first: ClientFirst,
    nonce: String,
    server_first: String,
    cb_data: Vec<u8>,
    creds: ScramCredentials,
    usable: bool,
}

impl std::fmt::Debug for ScramServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramServer")
            .field("user", &self.first.user)
            .finish_non_exhaustive()
    }
}

/// Result of a successful server handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSuccess {
    /// The authenticated user.
    pub user: String,
    /// The server-final message (`v=…`).
    pub server_final: String,
}

impl ScramServer {
    /// Checks the channel binding negotiation and builds the server-first message.
    ///
    /// # Errors
    /// Generic authentication failure on a channel-binding mismatch: `p=` without a TLS
    /// exporter, or `y` while the server supports channel binding (downgrade, RFC 5802 §6).
    pub fn start(
        first: ClientFirst,
        state: CredentialState,
        ctx: &ServerContext<'_>,
        rng: &dyn Rng,
    ) -> AuthnResult<(Self, String)> {
        let snonce = random_string(rng, ALPHABET, NONCE_LEN);
        Self::start_with_nonce(first, state, ctx, rng, &snonce)
    }

    fn start_with_nonce(
        first: ClientFirst,
        state: CredentialState,
        ctx: &ServerContext<'_>,
        rng: &dyn Rng,
        snonce: &str,
    ) -> AuthnResult<(Self, String)> {
        let cb_data = match (first.cbind, ctx.binding) {
            (CbindFlag::No, _) | (CbindFlag::ClientOnly, ServerBinding::Unavailable) => Vec::new(),
            (CbindFlag::TlsExporter, ServerBinding::TlsExporter(e)) => e.to_vec(),
            (CbindFlag::ClientOnly, ServerBinding::TlsExporter(_))
            | (CbindFlag::TlsExporter, ServerBinding::Unavailable) => {
                return Err(fail(FailureReason::ChannelBinding));
            }
        };
        let (creds, usable) = match state {
            CredentialState::Usable(c) => (c, true),
            CredentialState::Disabled(c) => (c, false),
            CredentialState::Unknown => {
                // Random keys: no proof can match them (finding one means inverting SHA-256).
                let mut stored_key = [0u8; 32];
                let mut server_key = [0u8; 32];
                rng.fill_bytes(&mut stored_key);
                rng.fill_bytes(&mut server_key);
                let salt = ctx.fake_salt_key.salt_for(&first.user).to_vec();
                let creds = ScramCredentials::from_parts(
                    salt,
                    ctx.default_iterations,
                    stored_key,
                    server_key,
                );
                (creds, false)
            }
        };
        let nonce = format!("{}{snonce}", first.client_nonce);
        let server_first = format!(
            "r={nonce},s={},i={}",
            B64.encode(&creds.salt),
            creds.iterations
        );
        let msg = server_first.clone();
        Ok((
            Self {
                first,
                nonce,
                server_first,
                cb_data,
                creds,
                usable,
            },
            msg,
        ))
    }

    /// Verifies the client-final message and returns the server-final message.
    ///
    /// # Errors
    /// Generic authentication failure: malformed message, nonce or channel binding mismatch,
    /// wrong proof, disabled or unknown user.
    pub fn finish(self, client_final: &str) -> AuthnResult<ServerSuccess> {
        check_len(client_final)?;
        let idx = client_final
            .rfind(",p=")
            .ok_or_else(|| fail(FailureReason::Malformed))?;
        let without_proof = &client_final[..idx];
        let proof: [u8; 32] = B64
            .decode(&client_final[idx + 3..])
            .ok()
            .and_then(|p| <[u8; 32]>::try_from(p).ok())
            .ok_or_else(|| fail(FailureReason::Malformed))?;
        let mut attrs = without_proof.split(',');
        let cbind_b64 = attr(attrs.next(), 'c')?;
        let nonce = attr(attrs.next(), 'r')?;
        if attrs.next().is_some() {
            return Err(fail(FailureReason::Malformed));
        }
        if !bool::from(nonce.as_bytes().ct_eq(self.nonce.as_bytes())) {
            return Err(fail(FailureReason::NonceMismatch));
        }
        // c= must be the gs2 header followed by the exporter (empty unless p=): this binds the
        // proof to this TLS connection, so a man in the middle terminating TLS cannot relay it.
        let mut expected = self.first.gs2_header.as_bytes().to_vec();
        expected.extend_from_slice(&self.cb_data);
        let presented = B64
            .decode(cbind_b64)
            .map_err(|_| fail(FailureReason::Malformed))?;
        if !bool::from(presented.ct_eq(&expected)) {
            return Err(fail(FailureReason::ChannelBinding));
        }
        let auth_message = format!("{},{},{without_proof}", self.first.bare, self.server_first);
        let signature = hmac(&self.creds.stored_key, auth_message.as_bytes());
        let mut client_key: [u8; 32] = std::array::from_fn(|i| proof[i] ^ signature[i]);
        let matches = sha256(&client_key).ct_eq(&self.creds.stored_key);
        client_key.zeroize();
        // `usable` is checked after the proof so that disabled and unknown users cost the same
        // work as a wrong password.
        if !bool::from(matches) || !self.usable {
            return Err(fail(FailureReason::BadCredentials));
        }
        let server_signature = hmac(&self.creds.server_key, auth_message.as_bytes());
        Ok(ServerSuccess {
            user: self.first.user.clone(),
            server_final: format!("v={}", B64.encode(server_signature)),
        })
    }
}

mod client;

pub use client::{ClientBinding, ScramClient, ScramClientFinal};

#[cfg(test)]
mod tests;
