// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Networking: TLS configuration and reload, listeners and peer transport.
//!
//! M4 scope (FR-TLS-001…003, security.md §5, PD-046):
//! - [`TlsContext`]: rustls server/client configurations with the pinned `ring`
//!   [`crypto_provider`] (TLS 1.3 only by default, optional TLS 1.2 minimum, AEAD suites only,
//!   X25519/P-256), mTLS for the peer listener, optional client certificates on the client port
//!   and [`peer_certificate_chain`] for X.509 authentication;
//! - [`CertAuthority`]: CA, node and client certificate generation for `rustegon init` /
//!   `rustegon cert`; node certificates carry the node role URI SAN
//!   (`rustegon_common::pki::NODE_ROLE_URI`, ADR-035), detected with [`has_node_role`] (which
//!   also accepts the legacy EKU `NODE_ROLE_OID`);
//! - [`ReloadableCert`]: hot-reloadable certificate/key with poll, trigger and expiry gauge;
//! - [`transport_security`]: the `security.tls` rule (plain text only on a single node, ADR-034).
//!
//! All file reads and writes go through the sim-api `FileSystem`, time through `Clock`
//! (ADR-029).

mod certgen;
mod config;
mod error;
mod pem;
mod provider;
mod reload;

pub use certgen::{
    CA_VALIDITY, CertAuthority, GeneratedCert, KeyAlgorithm, LEAF_VALIDITY, NOT_BEFORE_BACKDATE,
    has_node_role,
};
pub use config::{
    ClientCertPolicy, Deployment, TlsContext, TlsSettings, TransportSecurity,
    peer_certificate_chain, transport_security,
};
pub use error::TlsError;
pub use pem::{TrustAnchors, not_after_unix, parse_certificates, parse_private_key};
pub use provider::{ClockTimeProvider, TlsMinVersion, crypto_provider};
pub use reload::{CertSource, DEFAULT_RELOAD_POLL, ReloadOutcome, ReloadableCert};
// Re-exported so that listener code and tests use the exact versions this crate was built with.
pub use rustls;
pub use tokio_rustls;
