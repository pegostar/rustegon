// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Authentication (security.md §2, FR-SEC-001 minus OIDC, FR-SEC-003; decisions PD-047).
//!
//! - [`scram`]: SCRAM-SHA-256 / SCRAM-SHA-256-PLUS server and client (RFC 5802, 7677, 9266).
//! - [`users`]: users and their SCRAM credentials in the system keyspace.
//! - [`apikey`]: API keys `rgn_<key_id>_<secret>` with Argon2id-hashed secrets.
//! - [`keycache`]: bounded cache of verified API key secrets (PD-051).
//! - [`x509`]: client certificate subject → user mapping, node role detection.
//! - [`session`]: session tokens (BLAKE3-hashed at rest), timeouts, revocation.
//! - [`bootstrap`]: first admin without default credentials.
//! - [`password`]: password strength policy and random password generation.
//! - [`realm`]: the cluster-wide authentication secret (fake SCRAM salts).
//! - [`settings`]: the `[auth]` configuration section.
//! - [`store`]: the transactional system-keyspace access and key layout.
//!
//! Every mechanism ends in a [`Principal`]; every rejected credential is the generic
//! `RGN-4001` ([`error`]).

pub mod apikey;
mod base62;
pub mod bootstrap;
mod codec;
pub mod error;
pub mod keycache;
pub mod password;
pub mod realm;
pub mod scram;
pub mod session;
pub mod settings;
pub mod store;
pub mod users;
pub mod x509;

pub use error::{AUTHENTICATION_FAILED, AuthnError, AuthnResult, FailureReason};
use rustegon_common::Redacted;
pub use settings::AuthnSettings;
pub use store::{MemSystemTxn, SystemTxn};
use zeroize::Zeroizing;

/// A secret string: redacted in `Debug`/`Display` and wiped from memory on drop.
pub type SecretString = Redacted<Zeroizing<String>>;

/// Wraps `s` as a [`SecretString`].
#[must_use]
pub fn secret(s: impl Into<String>) -> SecretString {
    Redacted::new(Zeroizing::new(s.into()))
}

/// How a principal authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// SCRAM-SHA-256(-PLUS) or the GUI's password login.
    Password,
    /// TLS client certificate.
    Certificate,
    /// API key with this key id.
    ApiKey(String),
    /// Session token (the method that created the session is not tracked).
    Session,
}

/// Whether the principal must change its password before doing anything else (bootstrap
/// admin with a generated password, security.md §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordChange {
    /// No restriction.
    NotRequired,
    /// Only the password change is allowed.
    Required,
}

/// An authenticated identity: the user (or `node:<CN>` for a cluster node) and the role names
/// whose privileges it holds. Role names are resolved to privileges by `crate::rbac`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// User name; `node:<CN>` for a cluster node certificate.
    pub user: String,
    /// Role names (for API keys: the key scope intersected with the user's current roles).
    pub roles: Vec<String>,
    /// How it authenticated.
    pub method: AuthMethod,
    /// Password change requirement.
    pub password_change: PasswordChange,
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use rustegon_sim_api::Rng;

    use crate::authn::{scram::MIN_ITERATIONS, settings::AuthnSettings};

    /// Settings with the RFC-minimum SCRAM iteration count, so debug-build tests stay fast.
    pub(crate) fn fast_settings() -> AuthnSettings {
        AuthnSettings {
            scram_iterations: MIN_ITERATIONS,
            ..AuthnSettings::default()
        }
    }

    /// A fixed wall-clock time (2027-01-15).
    pub(crate) fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_hours(500_000)
    }

    /// Deterministic RNG (`SplitMix64`) for reproducible tests.
    pub(crate) struct SeqRng(AtomicU64);

    impl SeqRng {
        pub(crate) fn new(seed: u64) -> Self {
            Self(AtomicU64::new(seed))
        }
    }

    impl Rng for SeqRng {
        fn fill_bytes(&self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let mut z = self.0.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
            }
        }
    }
}
