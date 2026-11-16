// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The REST listener (port 7780, protocol.md §1; PD-052).
//!
//! REST has its own port, as protocol.md §1 specifies, rather than sharing 7700 with gRPC by
//! content-type routing: browsers and HTTP/1.1 tooling (curl, Prometheus) need HTTP/1.1, which
//! the gRPC listener deliberately refuses (ALPN `h2` only), and the two ports can be exposed
//! and firewalled independently. The accept loop, TLS policy, handshake bound and graceful
//! drain are the gRPC listener's (`crate::listener`); only the per-connection protocol differs:
//! hyper's auto connection serves HTTP/1.1 and HTTP/2 (ALPN `h2`, `http/1.1`; plain text: HTTP/1.1
//! or h2c prior knowledge, detected from the connection preface).

use std::{
    convert::Infallible,
    fmt,
    future::Future,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{Router, routing::future::RouteFuture};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
    service::TowerToHyperService,
};
use rustegon_sim_api::{Clock, Network};

use super::{DEFAULT_MAX_BODY_BYTES, router};
use crate::{
    ConnectionInfo, ListenerSecurity, ServerError,
    listener::{AcceptConfig, Bound, ServeConnection, accept_loop},
    services::Services,
};

/// REST listener settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestServerOptions {
    /// Largest request body. Default [`DEFAULT_MAX_BODY_BYTES`] (64 MiB, like gRPC messages).
    pub max_body_bytes: usize,
    /// Bound on reading an HTTP/1.1 request head, so slow-header clients cannot hold
    /// connections open (slowloris). Default 10 s.
    pub header_read_timeout: Duration,
    /// HTTP/2 keepalive ping interval (protocol.md §5.3: 30 s).
    pub keepalive_interval: Duration,
    /// HTTP/2 keepalive acknowledgement timeout (§5.3: 10 s).
    pub keepalive_timeout: Duration,
    /// HTTP/2 concurrent streams per connection (§5.3: 256).
    pub max_concurrent_streams: u32,
    /// Bound on the TLS handshake. Default 10 s.
    pub tls_handshake_timeout: Duration,
    /// How long shutdown waits for in-flight requests. Default 30 s.
    pub shutdown_grace: Duration,
}

impl Default for RestServerOptions {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            header_read_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(10),
            max_concurrent_streams: 256,
            tls_handshake_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(30),
        }
    }
}

/// A bound, not yet serving, REST listener.
pub struct RestServer {
    bound: Bound,
    security: ListenerSecurity,
    router: Router,
    options: RestServerOptions,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for RestServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestServer")
            .field("local_addr", &self.bound.local_addr())
            .field("security", &self.security)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl RestServer {
    /// Binds `addr` through `network` and builds the router over `services`.
    ///
    /// # Errors
    /// [`ServerError::Bind`].
    pub async fn bind(
        network: &dyn Network,
        addr: SocketAddr,
        security: ListenerSecurity,
        services: &Services,
        options: RestServerOptions,
    ) -> Result<Self, ServerError> {
        let bound = Bound::bind(network, addr).await?;
        Ok(Self {
            bound,
            security,
            router: router(services, options.max_body_bytes),
            options,
            clock: Arc::clone(&services.deps().clock),
        })
    }

    /// Also serves the GUI files of `assets` under `/ui` (and redirects `/` there; ADR-027,
    /// PD-130). The GUI routes do not get the API middleware (gate, `no-store`, node headers):
    /// axum layers wrap only the routes present when they are added.
    #[must_use]
    pub fn with_gui(mut self, assets: Arc<dyn super::GuiAssets>) -> Self {
        self.router = self.router.merge(super::gui_router(assets));
        self
    }

    /// The bound address (resolves port 0).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.bound.local_addr()
    }

    /// Serves until `shutdown` completes, then drains (stop accepting, finish in-flight
    /// requests for up to [`RestServerOptions::shutdown_grace`], abort the rest).
    pub async fn serve<F>(self, shutdown: F)
    where
        F: Future<Output = ()> + Send,
    {
        let Self {
            bound,
            security,
            router,
            options,
            clock,
        } = self;
        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(options.header_read_timeout);
        builder
            .http2()
            .timer(TokioTimer::new())
            .keep_alive_interval(options.keepalive_interval)
            .keep_alive_timeout(options.keepalive_timeout)
            .max_concurrent_streams(options.max_concurrent_streams);
        let serve: ServeConnection = Arc::new(move |io, info, watcher| {
            let builder = builder.clone();
            let service = TowerToHyperService::new(ConnService {
                router: router.clone(),
                conn: info,
            });
            Box::pin(async move {
                let connection = builder.serve_connection(TokioIo::new(io), service);
                if let Err(e) = watcher.watch(connection).await {
                    tracing::debug!(error = %e, "REST connection closed with error");
                }
            })
        });
        let config = AcceptConfig {
            name: "REST",
            acceptor: security.acceptor(&[b"h2", b"http/1.1"]),
            tls_handshake_timeout: options.tls_handshake_timeout,
            shutdown_grace: options.shutdown_grace,
            clock,
        };
        accept_loop(bound, config, serve, shutdown).await;
    }
}

/// The tower service of one connection: tags requests with the [`ConnectionInfo`] (read by the
/// principal resolver for X.509 callers) and hands them to the router.
#[derive(Clone)]
struct ConnService {
    router: Router,
    conn: ConnectionInfo,
}

impl tower_service::Service<http::Request<Incoming>> for ConnService {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = RouteFuture<Infallible>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        // The router is always ready (axum routers buffer nothing).
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: http::Request<Incoming>) -> Self::Future {
        request.extensions_mut().insert(self.conn.clone());
        tower_service::Service::call(&mut self.router, request)
    }
}
