// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Crypto provider, protocol versions and the rustls time source (security.md §5, FR-TLS-001).

use std::{fmt, sync::Arc, time::UNIX_EPOCH};

use rustegon_sim_api::Clock;
use rustls::{
    SupportedProtocolVersion,
    crypto::{CryptoProvider, ring},
    pki_types::UnixTime,
    time_provider::TimeProvider,
};
use serde::{Deserialize, Serialize};

/// Lowest TLS version a listener or client accepts (`tls.min_version`, security.md §5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsMinVersion {
    /// TLS 1.3 only (default).
    #[default]
    #[serde(rename = "1.3")]
    Tls13,
    /// TLS 1.2 and 1.3, for legacy clients only.
    #[serde(rename = "1.2")]
    Tls12,
}

impl TlsMinVersion {
    /// The rustls protocol versions enabled by this setting.
    #[must_use]
    pub fn protocol_versions(self) -> &'static [&'static SupportedProtocolVersion] {
        static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
        static TLS12_AND_13: &[&SupportedProtocolVersion] =
            &[&rustls::version::TLS13, &rustls::version::TLS12];
        match self {
            Self::Tls13 => TLS13_ONLY,
            Self::Tls12 => TLS12_AND_13,
        }
    }
}

/// The crypto provider used by every Rustegon TLS endpoint.
///
/// Decision (PD-046): the `ring` provider, not rustls' default `aws-lc-rs`, because aws-lc-rs
/// needs a cmake (and on Windows NASM) C build, which breaks the plain `cargo build` promise on
/// all targets (NFR-PORT-003). Consequence: no post-quantum hybrid `X25519MLKEM768` (security.md
/// §5 marks it Provisional, "when supported"); ring does not implement ML-KEM.
///
/// Suites and groups are pinned explicitly instead of relying on the provider defaults so that
/// a rustls upgrade cannot widen them silently:
/// - cipher suites: AEAD only (AES-GCM, ChaCha20-Poly1305). TLS 1.2 suites are ECDHE only, and
///   are only negotiable when [`TlsMinVersion::Tls12`] enables TLS 1.2;
/// - key exchange: X25519, then P-256 (security.md §5). P-384 is not offered.
#[must_use]
pub fn crypto_provider() -> Arc<CryptoProvider> {
    use ring::cipher_suite as cs;
    Arc::new(CryptoProvider {
        cipher_suites: vec![
            cs::TLS13_AES_256_GCM_SHA384,
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS13_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ],
        kx_groups: vec![ring::kx_group::X25519, ring::kx_group::SECP256R1],
        ..ring::default_provider()
    })
}

/// rustls time source backed by the sim-api [`Clock`] (ADR-029), so certificate validity checks
/// during handshakes use simulated time under `rustegon-sim`.
pub struct ClockTimeProvider {
    clock: Arc<dyn Clock>,
}

impl ClockTimeProvider {
    /// Wraps a clock.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }
}

impl fmt::Debug for ClockTimeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClockTimeProvider").finish_non_exhaustive()
    }
}

impl TimeProvider for ClockTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        // A wall clock before 1970 is a broken host; `None` makes rustls fail the handshake
        // rather than validate certificates against a wrong time.
        self.clock
            .wall()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(UnixTime::since_unix_epoch)
    }
}
