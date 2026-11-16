// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! rustls server and client configurations for the Rustegon listeners (FR-TLS-001,
//! security.md §5, protocol.md §1).
//!
//! | Endpoint | Builder | Client certificate |
//! |---|---|---|
//! | client port 7700 / HTTP 7780 | [`TlsContext::client_listener_config`] | optional (X.509 auth) or none |
//! | peer port 7710 | [`TlsContext::peer_listener_config`] | mandatory, chained to the cluster CA |
//! | outgoing peer / XDC | [`TlsContext::peer_client_config`] | always presented |
//! | drivers, CLI, tests | [`TlsContext::client_config`] | optional |
//!
//! Builders return owned configs so that callers can set ALPN (`h2`, `http/1.1`) per listener
//! before wrapping them in an `Arc`.

use std::{fmt, path::PathBuf, sync::Arc};

use rustegon_sim_api::Clock;
use rustls::{
    ClientConfig, ServerConfig, client::WebPkiServerVerifier, crypto::CryptoProvider,
    pki_types::CertificateDer, server::WebPkiClientVerifier, time_provider::TimeProvider,
};
use serde::{Deserialize, Serialize};

use crate::{
    TlsError,
    provider::{ClockTimeProvider, TlsMinVersion, crypto_provider},
    reload::{DEFAULT_RELOAD_POLL, ReloadableCert},
};

/// Shared TLS building blocks: the pinned crypto provider, the clock-backed time source and the
/// minimum protocol version. One per process.
#[derive(Clone)]
pub struct TlsContext {
    provider: Arc<CryptoProvider>,
    time: Arc<dyn TimeProvider>,
    min_version: TlsMinVersion,
}

impl fmt::Debug for TlsContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsContext")
            .field("min_version", &self.min_version)
            .finish_non_exhaustive()
    }
}

impl TlsContext {
    /// A context with the [`crypto_provider`] and certificate validity checked against `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, min_version: TlsMinVersion) -> Self {
        Self {
            provider: crypto_provider(),
            time: Arc::new(ClockTimeProvider::new(clock)),
            min_version,
        }
    }

    /// The crypto provider (also needed by [`ReloadableCert::load`]).
    #[must_use]
    pub fn provider(&self) -> Arc<CryptoProvider> {
        Arc::clone(&self.provider)
    }

    /// The configured minimum protocol version.
    #[must_use]
    pub fn min_version(&self) -> TlsMinVersion {
        self.min_version
    }

    fn server_builder(
        &self,
    ) -> Result<rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>, TlsError> {
        Ok(
            ServerConfig::builder_with_details(Arc::clone(&self.provider), Arc::clone(&self.time))
                .with_protocol_versions(self.min_version.protocol_versions())?,
        )
    }

    /// Server config for the client-facing listeners. With `client_ca`, clients may present a
    /// certificate chained to it (X.509 authentication, mapped to a user by the auth layer from
    /// [`peer_certificate_chain`]); clients without one are still accepted and authenticate by
    /// SCRAM/API key. A presented certificate that does not verify fails the handshake.
    ///
    /// # Errors
    /// [`TlsError::Rustls`] on an inconsistent protocol/suite set, [`TlsError::ClientVerifier`]
    /// when the CA bundle is unusable.
    pub fn client_listener_config(
        &self,
        cert: Arc<ReloadableCert>,
        client_ca: Option<&crate::TrustAnchors>,
    ) -> Result<ServerConfig, TlsError> {
        let builder = self.server_builder()?;
        let builder = match client_ca {
            None => builder.with_no_client_auth(),
            Some(ca) => builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder_with_provider(ca.roots(), Arc::clone(&self.provider))
                    .allow_unauthenticated()
                    .build()?,
            ),
        };
        Ok(builder.with_cert_resolver(cert))
    }

    /// Server config for the peer listener: mTLS is mandatory (FR-TLS-001); a peer without a
    /// certificate chained to `cluster_ca` is refused during the handshake. Binding the node id
    /// to the certificate fingerprint happens at join, above this layer.
    ///
    /// # Errors
    /// As [`Self::client_listener_config`].
    pub fn peer_listener_config(
        &self,
        cert: Arc<ReloadableCert>,
        cluster_ca: &crate::TrustAnchors,
    ) -> Result<ServerConfig, TlsError> {
        let verifier = WebPkiClientVerifier::builder_with_provider(
            cluster_ca.roots(),
            Arc::clone(&self.provider),
        )
        .build()?;
        Ok(self
            .server_builder()?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(cert))
    }

    /// Client config verifying the server against `server_ca`, presenting `identity` when
    /// given. The server name passed to `connect` must match a SAN of the server certificate.
    ///
    /// # Errors
    /// [`TlsError::Rustls`] on an inconsistent protocol/suite set, [`TlsError::ClientVerifier`]
    /// when the CA bundle is unusable.
    pub fn client_config(
        &self,
        server_ca: &crate::TrustAnchors,
        identity: Option<Arc<ReloadableCert>>,
    ) -> Result<ClientConfig, TlsError> {
        let verifier = WebPkiServerVerifier::builder_with_provider(
            server_ca.roots(),
            Arc::clone(&self.provider),
        )
        .build()?;
        let builder =
            ClientConfig::builder_with_details(Arc::clone(&self.provider), Arc::clone(&self.time))
                .with_protocol_versions(self.min_version.protocol_versions())?
                .with_webpki_verifier(verifier);
        Ok(match identity {
            None => builder.with_no_client_auth(),
            Some(id) => builder.with_client_cert_resolver(id),
        })
    }

    /// Client config for outgoing peer connections: verifies the peer against the cluster CA and
    /// always presents this node's (hot-reloadable) certificate.
    ///
    /// # Errors
    /// As [`Self::client_config`].
    pub fn peer_client_config(
        &self,
        cluster_ca: &crate::TrustAnchors,
        node_cert: Arc<ReloadableCert>,
    ) -> Result<ClientConfig, TlsError> {
        self.client_config(cluster_ca, Some(node_cert))
    }
}

/// The verified certificate chain the peer presented (leaf first), or `None` when it presented
/// none. Only meaningful after the handshake; rustls has already verified it against the
/// configured CA. Input for X.509 user mapping and node-id binding.
#[must_use]
pub fn peer_certificate_chain(
    conn: &rustls::ServerConnection,
) -> Option<Vec<CertificateDer<'static>>> {
    conn.peer_certificates().map(<[_]>::to_vec)
}

/// Client-certificate policy of the client-facing port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientCertPolicy {
    /// No client certificates requested (default).
    #[default]
    None,
    /// Requested and verified against `client_ca_file` when presented (X.509 auth).
    Optional,
}

/// `[tls]` settings of `rustegon.toml`. Key material is referenced by path only (security.md
/// §7); the key file content never enters the configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSettings {
    /// PEM certificate chain of this node (leaf first).
    pub cert_file: PathBuf,
    /// PEM private key of this node.
    pub key_file: PathBuf,
    /// PEM cluster CA: verifies peers (mTLS) and is offered to clients as the server's issuer.
    pub ca_file: PathBuf,
    /// CA for client certificates on the client port; defaults to `ca_file`.
    #[serde(default)]
    pub client_ca_file: Option<PathBuf>,
    /// Client-certificate policy of the client port.
    #[serde(default)]
    pub client_cert: ClientCertPolicy,
    /// `"1.3"` (default) or `"1.2"`.
    #[serde(default)]
    pub min_version: TlsMinVersion,
    /// Reload poll period in seconds (default 3600; watch and SIGHUP reload sooner).
    #[serde(default = "default_reload_secs")]
    pub reload_poll_secs: u64,
}

fn default_reload_secs() -> u64 {
    DEFAULT_RELOAD_POLL.as_secs()
}

impl TlsSettings {
    /// Checks values that serde cannot.
    ///
    /// # Errors
    /// [`TlsError::Config`] when the poll period is 0 or a path is empty.
    pub fn validate(&self) -> Result<(), TlsError> {
        if self.reload_poll_secs == 0 {
            return Err(TlsError::Config("reload_poll_secs must be > 0".into()));
        }
        for (name, path) in [
            ("cert_file", &self.cert_file),
            ("key_file", &self.key_file),
            ("ca_file", &self.ca_file),
        ] {
            if path.as_os_str().is_empty() {
                return Err(TlsError::Config(format!("{name} must not be empty")));
            }
        }
        Ok(())
    }
}

/// Whether the node runs alone or as a cluster member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deployment {
    /// One node, no peer listener.
    SingleNode,
    /// Cluster member (peer listener active).
    Cluster,
}

/// Transport security selected for the listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSecurity {
    /// TLS on every listener (`security.tls = true`; always in cluster mode).
    Tls,
    /// Plain TCP; the single-node default (`security.tls = false`, ADR-034).
    PlainText,
}

/// Selects the transport security (security.md §5, ADR-034): TLS when `security.tls = true`;
/// plain text when it is false **and** the node is a single node; refused in cluster mode,
/// where peer traffic carries Raft and data and mTLS is mandatory (FR-TLS-001).
///
/// # Errors
/// [`TlsError::InsecureRefused`] for `tls = false` in [`Deployment::Cluster`].
pub fn transport_security(
    tls: bool,
    deployment: Deployment,
) -> Result<TransportSecurity, TlsError> {
    match (tls, deployment) {
        (true, _) => Ok(TransportSecurity::Tls),
        (false, Deployment::SingleNode) => {
            tracing::warn!(
                "security.tls = false: listeners accept plain-text connections; credentials and \
                 data travel unencrypted (set security.tls = true to enable TLS)"
            );
            Ok(TransportSecurity::PlainText)
        }
        (false, Deployment::Cluster) => Err(TlsError::InsecureRefused(
            "TLS is mandatory in cluster mode: set security.tls = true",
        )),
    }
}
