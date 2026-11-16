// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The client gRPC listener (port 7700, protocol.md §1, §5.3; PD-050).
//!
//! tonic generates the service routing, but the listener itself is ours rather than
//! `tonic::transport::Server`:
//! - sockets come from the sim-api `Network` (ADR-029) and TLS from `rustegon-net`'s rustls
//!   configuration, so tonic's TLS features (and their aws-lc build) stay off; the accept loop,
//!   TLS handshake and drain logic are shared with the REST listener (`crate::listener`);
//! - tonic's server applies its own `grpc-timeout` layer outside every service and answers an
//!   expired deadline with a bare `CANCELLED`, without our `ErrorDetail`; here deadlines are
//!   enforced by the handlers ([`crate::Executor`]) and fail with RGN-5006;
//! - the `rgn-node-id`, `rgn-server-time` and `rgn-causality-token` trailers are added by
//!   [`TrailerBody`] on every response, including errors and unknown methods;
//! - every request is counted and timed for `/metrics` from its arrival to its final status
//!   (the trailers; for a streaming RPC the end of the stream), with the RGN code read back
//!   from the status detail (PD-059).
//!
//! Each accepted connection runs in its own task: TLS handshake (ALPN `h2` only, bounded by
//! [`GrpcServerOptions::tls_handshake_timeout`]), then an HTTP/2-only hyper connection with
//! the keepalive and stream limits of protocol.md §5.3. Shutdown stops accepting, lets
//! in-flight requests finish (HTTP/2 GOAWAY) for up to [`GrpcServerOptions::shutdown_grace`],
//! then aborts what is left.

use std::{
    convert::Infallible,
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use http_body::{Body, Frame, SizeHint};
use hyper::{body::Incoming, server::conn::http2};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use rustegon_proto::v1::{
    admin_service_server::AdminServiceServer, auth_service_server::AuthServiceServer,
    backup_service_server::BackupServiceServer, document_service_server::DocumentServiceServer,
    query_service_server::QueryServiceServer, schema_service_server::SchemaServiceServer,
    session_service_server::SessionServiceServer,
    transaction_service_server::TransactionServiceServer,
};
use rustegon_sim_api::{BoxFuture, Clock, Network};
use tonic::service::Routes;

use super::{
    AdminGrpc, AuthGrpc, BackupGrpc, DocumentGrpc, QueryGrpc, SchemaGrpc, SessionGrpc,
    TransactionGrpc,
    data::DataGrpc,
    gate,
    metadata::{CAUSALITY_TOKEN, NODE_ID, ResponseTrailers, SERVER_TIME},
};
pub use crate::listener::{ConnectionInfo, ListenerSecurity, ServerError};
use crate::{
    listener::{AcceptConfig, Bound, ServeConnection, accept_loop, server_time_ms},
    metrics::{InFlight, Outcome, Route},
    services::Services,
};

/// Listener settings. Defaults follow protocol.md §5.3–§5.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcServerOptions {
    /// Largest encoded request or response message. Default 64 MiB: a `BulkWrite` may carry
    /// 48 MiB of operations (§5.4) plus envelope overhead.
    pub max_message_bytes: usize,
    /// HTTP/2 keepalive ping interval (§5.3: 30 s).
    pub keepalive_interval: Duration,
    /// Keepalive ping acknowledgement timeout (§5.3: 10 s).
    pub keepalive_timeout: Duration,
    /// Concurrent streams per connection (§5.3: 256).
    pub max_concurrent_streams: u32,
    /// Bound on the TLS handshake, so idle sockets cannot pin connection tasks. Default 10 s.
    pub tls_handshake_timeout: Duration,
    /// How long shutdown waits for in-flight requests. Default 30 s.
    pub shutdown_grace: Duration,
}

impl Default for GrpcServerOptions {
    fn default() -> Self {
        Self {
            max_message_bytes: 64 * 1024 * 1024,
            keepalive_interval: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(10),
            max_concurrent_streams: 256,
            tls_handshake_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(30),
        }
    }
}

/// A bound, not yet serving, client gRPC listener.
pub struct GrpcServer {
    bound: Bound,
    security: ListenerSecurity,
    service: RgnService,
    options: GrpcServerOptions,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for GrpcServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcServer")
            .field("local_addr", &self.bound.local_addr())
            .field("security", &self.security)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

/// The gRPC routes of every service implemented so far: `SessionService`, plus `AuthService`
/// and `AdminService` when the security layer is installed (PD-051). Services that are not
/// registered answer `UNIMPLEMENTED` through tonic's fallback route. A service added here must
/// also be listed in `gate` so its access rules are enforced.
fn routes(services: &Services, options: &GrpcServerOptions) -> Routes {
    let max = options.max_message_bytes;
    let session = SessionServiceServer::new(SessionGrpc::new(services.clone()))
        .max_decoding_message_size(max)
        .max_encoding_message_size(max);
    let mut routes = Routes::new(session);
    if services.security().is_some() {
        routes = routes
            .add_service(
                AuthServiceServer::new(AuthGrpc::new(services.clone()))
                    .max_decoding_message_size(max)
                    .max_encoding_message_size(max),
            )
            .add_service(
                AdminServiceServer::new(AdminGrpc::new(services.clone()))
                    .max_decoding_message_size(max)
                    .max_encoding_message_size(max),
            )
            // BackupService (PD-062, PD-077): with the security layer, engine or not; its
            // engine operations need a backend (`Services::with_backup_backend`).
            .add_service(
                BackupServiceServer::new(BackupGrpc::new(services.clone()))
                    .max_decoding_message_size(max)
                    .max_encoding_message_size(max),
            );
        // Data-plane services (wave 2b lane G, PD-053): only with an engine, and like every
        // authenticated service only behind the gate (`gate::DATA_PLANE`).
        if services.data().is_some() {
            let data = DataGrpc {
                services: services.clone(),
            };
            routes = routes
                .add_service(
                    QueryServiceServer::new(QueryGrpc(data.clone()))
                        .max_decoding_message_size(max)
                        .max_encoding_message_size(max),
                )
                .add_service(
                    DocumentServiceServer::new(DocumentGrpc(data.clone()))
                        .max_decoding_message_size(max)
                        .max_encoding_message_size(max),
                )
                .add_service(
                    TransactionServiceServer::new(TransactionGrpc(data.clone()))
                        .max_decoding_message_size(max)
                        .max_encoding_message_size(max),
                )
                .add_service(
                    SchemaServiceServer::new(SchemaGrpc(data))
                        .max_decoding_message_size(max)
                        .max_encoding_message_size(max),
                );
        }
    }
    routes.prepare()
}

impl GrpcServer {
    /// Binds `addr` through `network` and prepares the routes.
    ///
    /// # Errors
    /// [`ServerError::Bind`].
    pub async fn bind(
        network: &dyn Network,
        addr: SocketAddr,
        security: ListenerSecurity,
        services: &Services,
        options: GrpcServerOptions,
    ) -> Result<Self, ServerError> {
        let bound = Bound::bind(network, addr).await?;
        let clock = Arc::clone(&services.deps().clock);
        let service = RgnService {
            routes: routes(services, &options),
            services: services.clone(),
            node_id: HeaderValue::from(services.node().node_id),
            clock: Arc::clone(&clock),
            conn: None,
        };
        Ok(Self {
            bound,
            security,
            service,
            options,
            clock,
        })
    }

    /// The bound address (resolves port 0).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.bound.local_addr()
    }

    /// Serves until `shutdown` completes, then drains (see the module docs).
    pub async fn serve<F>(self, shutdown: F)
    where
        F: Future<Output = ()> + Send,
    {
        let Self {
            bound,
            security,
            service,
            options,
            clock,
        } = self;
        let mut h2 = http2::Builder::new(TokioExecutor::new());
        h2.timer(TokioTimer::new())
            .keep_alive_interval(options.keepalive_interval)
            .keep_alive_timeout(options.keepalive_timeout)
            .max_concurrent_streams(options.max_concurrent_streams);
        let serve: ServeConnection = Arc::new(move |io, info, watcher| {
            let mut service = service.clone();
            service.conn = Some(info);
            let connection =
                h2.serve_connection(TokioIo::new(io), TowerToHyperService::new(service));
            Box::pin(async move {
                if let Err(e) = watcher.watch(connection).await {
                    tracing::debug!(error = %e, "gRPC connection closed with error");
                }
            })
        });
        let config = AcceptConfig {
            name: "gRPC",
            // gRPC needs HTTP/2: a client offering only `http/1.1` fails the handshake.
            acceptor: security.acceptor(&[b"h2"]),
            tls_handshake_timeout: options.tls_handshake_timeout,
            shutdown_grace: options.shutdown_grace,
            clock,
        };
        accept_loop(bound, config, serve, shutdown).await;
    }
}

/// The tower service of one connection: tags requests with [`ConnectionInfo`], admits them
/// through the security gate (`gate`, PD-051), routes them, and wraps responses in
/// [`TrailerBody`].
#[derive(Clone)]
struct RgnService {
    routes: Routes,
    services: Services,
    node_id: HeaderValue,
    clock: Arc<dyn Clock>,
    conn: Option<ConnectionInfo>,
}

impl tower_service::Service<http::Request<Incoming>> for RgnService {
    type Response = http::Response<TrailerBody>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        tower_service::Service::<http::Request<Incoming>>::poll_ready(&mut self.routes, cx)
    }

    fn call(&mut self, mut request: http::Request<Incoming>) -> Self::Future {
        if let Some(conn) = &self.conn {
            request.extensions_mut().insert(conn.clone());
        }
        let mut routes = self.routes.clone();
        let services = self.services.clone();
        let conn = self.conn.clone();
        let node_id = self.node_id.clone();
        let clock = Arc::clone(&self.clock);
        Box::pin(async move {
            let path = request.uri().path().to_owned();
            let timer = services.metrics().start(Route::grpc(&path), &clock);
            let admitted = gate::admit(&services, &path, request.headers(), conn.as_ref()).await;
            let response = match admitted {
                Ok(ctx) => {
                    request.extensions_mut().insert(ctx);
                    // The clone was not polled for readiness; tonic's router is always ready,
                    // but the tower contract is honoured anyway.
                    std::future::poll_fn(|cx| {
                        tower_service::Service::<http::Request<Incoming>>::poll_ready(
                            &mut routes,
                            cx,
                        )
                    })
                    .await?;
                    routes.call(request).await?
                }
                Err(status) => status.into_http(),
            };
            Ok(with_trailers(response, node_id, clock.as_ref(), timer))
        })
    }
}

/// Attaches the Rustegon response trailers. A trailers-only response (an error status, which
/// gRPC sends entirely in the header block) gets them in its headers, like `grpc-status`.
fn with_trailers(
    response: http::Response<tonic::body::Body>,
    node_id: HeaderValue,
    clock: &dyn Clock,
    timer: InFlight,
) -> http::Response<TrailerBody> {
    let (mut parts, inner) = response.into_parts();
    let mut extra = HeaderMap::new();
    extra.insert(NODE_ID, node_id);
    extra.insert(SERVER_TIME, HeaderValue::from(server_time_ms(clock)));
    if let Some(token) = parts
        .extensions
        .get::<ResponseTrailers>()
        .and_then(|t| t.causality_token.as_deref())
        .and_then(|t| HeaderValue::from_str(t).ok())
    {
        extra.insert(CAUSALITY_TOKEN, token);
    }
    let (extra, timer) = if parts.headers.contains_key("grpc-status") {
        timer.finish(grpc_outcome(&parts.headers));
        parts.headers.extend(extra);
        (None, None)
    } else {
        (Some(extra), Some(timer))
    };
    http::Response::from_parts(
        parts,
        TrailerBody {
            inner,
            extra,
            timer,
        },
    )
}

/// The outcome label of a gRPC status in `headers` (trailers, or the headers of a
/// trailers-only response): the RGN code of the `ErrorDetail` when present.
fn grpc_outcome(headers: &HeaderMap) -> Outcome {
    let status = headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i32>().ok())
        // A response that ends without a status is `UNKNOWN` for the client.
        .unwrap_or(2);
    if status == 0 {
        return Outcome::Ok;
    }
    let rgn = tonic::Status::from_header_map(headers)
        .and_then(|s| rustegon_proto::status::error_detail_of(&s))
        .map(|d| d.code);
    Outcome::from_grpc(status, rgn)
}

/// Response body that appends extra fields to the gRPC trailers (or sends them as the trailer
/// frame if the inner body ends without one).
pub struct TrailerBody {
    inner: tonic::body::Body,
    extra: Option<HeaderMap>,
    /// Finished with the status in the trailers; dropped unfinished (client reset) it counts
    /// the request as cancelled.
    timer: Option<InFlight>,
}

impl Body for TrailerBody {
    type Data = Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, tonic::Status>>> {
        let this = self.get_mut();
        match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
            Some(Ok(mut frame)) => {
                if let Some(trailers) = frame.trailers_mut() {
                    if let Some(timer) = this.timer.take() {
                        timer.finish(grpc_outcome(trailers));
                    }
                    if let Some(extra) = this.extra.take() {
                        trailers.extend(extra);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            None => {
                if let Some(timer) = this.timer.take() {
                    timer.finish(grpc_outcome(&HeaderMap::new()));
                }
                Poll::Ready(this.extra.take().map(|t| Ok(Frame::trailers(t))))
            }
            Some(Err(e)) => {
                if let Some(timer) = this.timer.take() {
                    let rgn = rustegon_proto::status::error_detail_of(&e).map(|d| d.code);
                    timer.finish(Outcome::from_grpc(e.code() as i32, rgn));
                }
                Poll::Ready(Some(Err(e)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.extra.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
