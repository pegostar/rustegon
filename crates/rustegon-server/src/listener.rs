// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Accept loop, TLS policy and connection facts shared by the client listeners: gRPC on 7700
//! ([`crate::grpc::GrpcServer`]) and REST on 7780 ([`crate::rest::RestServer`]) (protocol.md §1;
//! PD-050, PD-052).
//!
//! Both listeners differ only in the HTTP protocol they speak on an accepted connection (HTTP/2
//! only for gRPC, HTTP/1.1 + HTTP/2 for REST) and in their ALPN list; everything before that is
//! here, so the security-relevant parts exist once:
//! - sockets come from the sim-api [`Network`] (ADR-029) and TLS from `rustegon-net`'s rustls
//!   configuration;
//! - plain text is only reachable through [`ListenerSecurity::plain_text`], which requires the
//!   [`TransportSecurity::PlainText`] policy (`security.tls = false` on a single node, ADR-034);
//! - the TLS handshake is bounded so idle sockets cannot pin connection tasks;
//! - shutdown stops accepting, lets in-flight requests finish for a grace period, then aborts
//!   what is left.

use std::{fmt, future::Future, net::SocketAddr, sync::Arc, time::Duration};

use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use rustegon_common::Redacted;
use rustegon_net::{
    TransportSecurity, peer_certificate_chain,
    rustls::{self, pki_types::CertificateDer},
    tokio_rustls::TlsAcceptor,
};
use rustegon_security::authn::scram::TLS_EXPORTER_LEN;
use rustegon_sim_api::{BoxFuture, Clock, Connection, Listener, Network};
use tokio::task::JoinSet;

/// Errors starting a listener.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The socket could not be bound.
    #[error("cannot bind {addr}: {source}")]
    Bind {
        /// Requested address.
        addr: SocketAddr,
        /// OS error.
        source: std::io::Error,
    },
    /// A plain-text listener was requested while the transport policy demands TLS.
    #[error("plain-text listener refused: only allowed with security.tls = false on a single node")]
    PlainTextNotAllowed,
}

/// Transport security of a listener. Plain text can only be obtained from
/// [`rustegon_net::transport_security`] returning [`TransportSecurity::PlainText`], i.e.
/// `security.tls = false` on a single node (security.md §5, ADR-034); everything else is TLS.
///
/// The same value can configure both client listeners: each one sets its own ALPN protocols
/// on a copy of the rustls configuration (`h2` for gRPC, `h2` + `http/1.1` for REST).
#[derive(Clone)]
pub struct ListenerSecurity(Option<Arc<rustls::ServerConfig>>);

impl fmt::Debug for ListenerSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "ListenerSecurity::Tls"
        } else {
            "ListenerSecurity::PlainText"
        })
    }
}

impl ListenerSecurity {
    /// TLS with a server config from [`rustegon_net::TlsContext::client_listener_config`].
    /// Any ALPN list in `config` is replaced by the listener's own (see the type docs), so a
    /// client offering only protocols the listener cannot speak is refused during the handshake
    /// instead of failing later with a protocol error.
    #[must_use]
    pub fn tls(config: rustls::ServerConfig) -> Self {
        Self(Some(Arc::new(config)))
    }

    /// Plain text (HTTP/2 prior knowledge for gRPC; HTTP/1.1 or h2c prior knowledge for REST),
    /// for development and tests.
    ///
    /// # Errors
    /// [`ServerError::PlainTextNotAllowed`] unless `policy` is
    /// [`TransportSecurity::PlainText`].
    pub fn plain_text(policy: TransportSecurity) -> Result<Self, ServerError> {
        match policy {
            TransportSecurity::PlainText => Ok(Self(None)),
            TransportSecurity::Tls => Err(ServerError::PlainTextNotAllowed),
        }
    }

    /// Whether connections are TLS.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.0.is_some()
    }

    /// The TLS acceptor advertising exactly `alpn`, `None` for plain text.
    pub(crate) fn acceptor(&self, alpn: &[&[u8]]) -> Option<TlsAcceptor> {
        self.0.as_ref().map(|config| {
            let mut config = rustls::ServerConfig::clone(config);
            config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
            TlsAcceptor::from(Arc::new(config))
        })
    }
}

/// Per-connection facts, inserted into the extensions of every request on the connection
/// (`tonic::Request::extensions` for gRPC, `http::Request::extensions` for REST). The
/// authentication layer reads the verified client certificate chain from here for X.509
/// authentication.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Whether the connection is TLS.
    pub tls: bool,
    /// The client certificate chain (leaf first), verified by rustls; `None` without one.
    pub peer_certificates: Option<Arc<Vec<CertificateDer<'static>>>>,
    /// RFC 9266 `tls-exporter` value of the connection (TLS 1.3 only), for SCRAM-SHA-256-PLUS
    /// channel binding (PD-051). Derived from the TLS secrets: redacted in `Debug`.
    pub tls_exporter: Option<Redacted<[u8; TLS_EXPORTER_LEN]>>,
}

/// RFC 9266 `tls-exporter` of a TLS 1.3 connection (label `EXPORTER-Channel-Binding`, no
/// context). TLS 1.2 gets none: its exporter is only safe with extended master secret, which
/// the channel binding cannot verify, so SCRAM-SHA-256-PLUS is not offered there (PD-051).
fn tls_exporter(conn: &rustls::ServerConnection) -> Option<Redacted<[u8; TLS_EXPORTER_LEN]>> {
    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return None;
    }
    conn.export_keying_material([0u8; TLS_EXPORTER_LEN], b"EXPORTER-Channel-Binding", None)
        .ok()
        .map(Redacted::new)
}

/// A bound socket that is not accepting yet.
pub(crate) struct Bound {
    listener: Box<dyn Listener>,
    local_addr: SocketAddr,
}

impl Bound {
    /// Binds `addr` through `network`.
    pub(crate) async fn bind(network: &dyn Network, addr: SocketAddr) -> Result<Self, ServerError> {
        let listener = network
            .bind(addr)
            .await
            .map_err(|source| ServerError::Bind { addr, source })?;
        let local_addr = listener
            .local_addr()
            .map_err(|source| ServerError::Bind { addr, source })?;
        Ok(Self {
            listener,
            local_addr,
        })
    }

    /// The bound address (resolves port 0).
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// Serves one accepted (and, with TLS, handshaken) connection until it closes. The [`Watcher`]
/// must wrap the HTTP connection so graceful shutdown can drain it.
pub(crate) type ServeConnection = Arc<
    dyn Fn(Box<dyn Connection>, ConnectionInfo, Watcher) -> BoxFuture<'static, ()> + Send + Sync,
>;

/// Settings of [`accept_loop`].
pub(crate) struct AcceptConfig {
    /// Listener name for logs (`gRPC`, `REST`).
    pub name: &'static str,
    /// TLS acceptor with the listener's ALPN list; `None` for plain text.
    pub acceptor: Option<TlsAcceptor>,
    /// Bound on the TLS handshake.
    pub tls_handshake_timeout: Duration,
    /// How long shutdown waits for in-flight requests.
    pub shutdown_grace: Duration,
    /// Time source for the handshake timeout, accept backoff and grace period.
    pub clock: Arc<dyn Clock>,
}

const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Server wall clock as Unix milliseconds (`rgn-server-time` on both front ends).
pub(crate) fn server_time_ms(clock: &dyn Clock) -> u64 {
    clock
        .wall()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Accepts connections until `shutdown` completes, then drains (see the module docs). Each
/// connection runs in its own task: TLS handshake, then `serve`.
pub(crate) async fn accept_loop<F>(
    bound: Bound,
    config: AcceptConfig,
    serve: ServeConnection,
    shutdown: F,
) where
    F: Future<Output = ()> + Send,
{
    let Bound {
        mut listener,
        local_addr,
    } = bound;
    let AcceptConfig {
        name,
        acceptor,
        tls_handshake_timeout,
        shutdown_grace,
        clock,
    } = config;
    let graceful = GracefulShutdown::new();
    let mut tasks = JoinSet::new();
    tracing::info!(addr = %local_addr, tls = acceptor.is_some(), "{name} listener started");

    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        // Reap finished connection tasks so the set does not grow with every connection.
        while tasks.try_join_next().is_some() {}
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((conn, remote_addr)) => {
                tasks.spawn(serve_connection(
                    conn,
                    remote_addr,
                    acceptor.clone(),
                    tls_handshake_timeout,
                    Arc::clone(&clock),
                    Arc::clone(&serve),
                    graceful.watcher(),
                ));
            }
            Err(e) => {
                // Usually per-connection (reset before accept) or descriptor exhaustion; the
                // short pause keeps the latter from spinning the loop.
                tracing::warn!(error = %e, "{name} accept failed");
                clock.sleep(ACCEPT_BACKOFF).await;
            }
        }
    }

    drop(listener);
    tracing::info!(addr = %local_addr, "{name} listener draining");
    tokio::select! {
        () = graceful.shutdown() => {}
        () = clock.sleep(shutdown_grace) => {
            tracing::warn!(addr = %local_addr, "{name} shutdown grace expired; closing connections");
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    tracing::info!(addr = %local_addr, "{name} listener stopped");
}

async fn serve_connection(
    conn: Box<dyn Connection>,
    remote_addr: SocketAddr,
    acceptor: Option<TlsAcceptor>,
    handshake_timeout: Duration,
    clock: Arc<dyn Clock>,
    serve: ServeConnection,
    watcher: Watcher,
) {
    let (io, info): (Box<dyn Connection>, ConnectionInfo) = match acceptor {
        None => (
            conn,
            ConnectionInfo {
                remote_addr,
                tls: false,
                peer_certificates: None,
                tls_exporter: None,
            },
        ),
        Some(acceptor) => {
            let handshake = tokio::select! {
                handshake = acceptor.accept(conn) => handshake,
                () = clock.sleep(handshake_timeout) => {
                    tracing::debug!(peer = %remote_addr, "TLS handshake timed out");
                    return;
                }
            };
            let stream = match handshake {
                Ok(stream) => stream,
                Err(e) => {
                    // Expected for port scanners and plain-text clients; not worth a warning.
                    tracing::debug!(peer = %remote_addr, error = %e, "TLS handshake failed");
                    return;
                }
            };
            let peer_certificates = peer_certificate_chain(stream.get_ref().1).map(Arc::new);
            let tls_exporter = tls_exporter(stream.get_ref().1);
            (
                Box::new(stream),
                ConnectionInfo {
                    remote_addr,
                    tls: true,
                    peer_certificates,
                    tls_exporter,
                },
            )
        }
    };
    serve(io, info, watcher).await;
}
