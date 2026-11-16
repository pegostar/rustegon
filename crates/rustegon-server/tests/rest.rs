// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST front end (FR-API-002, FR-API-003, PD-052): routing, header rules, the error body and
//! status mapping (TC-API-005 for REST), REST/gRPC parity (TC-API-006 part), the principal
//! resolver hook and the 7780 listener over TLS (HTTP/1.1 and HTTP/2) and plain text.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use axum::{
    body::{Body, to_bytes},
    extract::FromRequest,
    response::IntoResponse,
};
use http::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustegon_common::{Error, ErrorCode};
use rustegon_net::{
    CertAuthority, CertSource, Deployment, KeyAlgorithm, ReloadableCert, TlsContext, TlsMinVersion,
    TrustAnchors, rustls::pki_types::ServerName, tokio_rustls::TlsConnector, transport_security,
};
use rustegon_proto::{
    status::error_detail_of,
    v1::{GetServerInfoRequest, PingRequest, session_service_client::SessionServiceClient},
};
use rustegon_server::{
    ConnectionInfo, Executor, ListenerSecurity,
    grpc::{GrpcServer, GrpcServerOptions},
    rest::{
        ApiError, ErrorBody, JsonBody, RestServer, RestServerOptions, RestState,
        ServerInfoResponse, csrf_token, router,
    },
    services::{NodeIdentity, Principal, PrincipalResolver, RequestContext, ServiceDeps, Services},
};
use rustegon_sim_api::{
    BoxFuture, Clock, Connection, FileSystem, Network, OsRng, StdFileSystem, SystemClock,
    TokioNetwork,
};
use serde_json::Value;
use tokio::sync::oneshot;
use tonic::{
    Request as GrpcRequest,
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
};
use tower::ServiceExt;

const NODE_ID: u64 = 7;
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const BODY_LIMIT: usize = 1024 * 1024;

/// A clock whose monotonic time jumps one hour per reading: any deadline derived from the
/// request has expired by the time the service checks it.
struct JumpingClock {
    inner: SystemClock,
    jumps: AtomicU64,
}

impl Clock for JumpingClock {
    fn monotonic(&self) -> Duration {
        let n = self.jumps.fetch_add(1, Ordering::SeqCst);
        self.inner.monotonic() + Duration::from_secs(3600 * n)
    }
    fn wall(&self) -> SystemTime {
        self.inner.wall()
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        self.inner.sleep(d)
    }
}

fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock::new())
}

fn services(clock: Arc<dyn Clock>) -> Services {
    let deps = ServiceDeps {
        executor: Executor::new(Arc::clone(&clock), 4),
        clock,
        rng: Arc::new(OsRng),
    };
    Services::new(
        deps,
        NodeIdentity {
            node_id: NODE_ID,
            features: vec!["example-flag".into()],
            client_addresses: vec!["127.0.0.1:7700".into()],
        },
    )
}

fn unix_ms_now() -> u64 {
    u64::try_from(
        SystemClock::new()
            .wall()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

async fn json_of(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn call(services: &Services, request: Request<Body>) -> Response<Body> {
    router(services, BODY_LIMIT).oneshot(request).await.unwrap()
}

fn get(path: &str) -> http::request::Builder {
    Request::builder().method(Method::GET).uri(path)
}

fn assert_node_headers(response: &Response<impl Sized>, before_ms: u64) {
    let h = response.headers();
    assert_eq!(h.get("rgn-node-id").unwrap(), "7");
    let server_ms: u64 = h
        .get("rgn-server-time")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(server_ms >= before_ms && server_ms <= unix_ms_now());
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
}

/// Parses `docs/specifications/protocol.md` §7 into `(code, http status)`.
fn protocol_http_statuses() -> Vec<(u16, u16)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/specifications/protocol.md"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let section = text
        .split("## 7. Error model")
        .nth(1)
        .unwrap()
        .split("\n## ")
        .next()
        .unwrap();
    section
        .lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let code = cells.get(1)?.parse::<u16>().ok()?;
            Some((code, cells[4].parse().unwrap()))
        })
        .collect()
}

#[tokio::test]
async fn tc_api_005_every_catalog_code_has_protocol_http_status_and_error_body() {
    let rows = protocol_http_statuses();
    assert_eq!(rows.len(), ErrorCode::ALL.len());
    for (code, http) in rows {
        let error_code = ErrorCode::from_code(code).unwrap();
        let error = Error::new(error_code, "boom").with_detail("k", "v");
        let retryable = error.retryable();
        let response = ApiError::new(error, TRACE_ID).into_response();
        assert_eq!(response.status().as_u16(), http, "RGN-{code}");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json",
            "RGN-{code}"
        );
        let body = json_of(response).await;
        let e = &body["error"];
        assert_eq!(e["code"], u32::from(code), "RGN-{code}");
        assert_eq!(e["name"], error_code.name(), "RGN-{code}");
        assert_eq!(e["message"], "boom");
        assert_eq!(e["retryable"], retryable, "RGN-{code}");
        assert_eq!(e["details"]["k"], "v");
        assert_eq!(e["traceId"], TRACE_ID);
        // `committed` is present only for outcomes known to have committed.
        if code == 3006 {
            assert_eq!(e["committed"], true);
        } else {
            assert!(e.get("committed").is_none(), "RGN-{code}");
        }
        // The body deserializes into the documented schema.
        let typed: ErrorBody = serde_json::from_value(body).unwrap();
        assert_eq!(typed.error.code, u32::from(code));
    }
}

#[tokio::test]
async fn fr_api_002_ping_and_server_info_over_the_router() {
    let services = services(system_clock());
    let before = unix_ms_now();
    let response = call(&services, get("/api/v1/ping").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_node_headers(&response, before);
    assert!(response.headers().get("rgn-causality-token").is_none());
    assert_eq!(json_of(response).await, serde_json::json!({}));

    // Session calls echo the client's causality token.
    let response = call(
        &services,
        get("/api/v1/server-info")
            .header("rgn-causality-token", "tok-42")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("rgn-causality-token").unwrap(),
        "tok-42"
    );
    let info: ServerInfoResponse = serde_json::from_value(json_of(response).await).unwrap();
    assert_eq!(info.server_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.protocol_version, "1.0");
    assert_eq!(info.features, vec!["example-flag".to_owned()]);
    assert_eq!(info.node_addresses, vec!["127.0.0.1:7700".to_owned()]);

    let response = call(
        &services,
        get("/api/v1/health/live").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_node_headers(&response, before);
    assert_eq!(json_of(response).await["status"], "live");
}

#[tokio::test]
async fn fr_api_002_malformed_headers_fail_with_rgn_1001_body() {
    let services = services(system_clock());
    let cases: [(&str, Vec<&str>); 5] = [
        ("rgn-request-id", vec!["not-a-uuid"]),
        (
            "rgn-request-id",
            vec![
                "0190a6e2-3c4d-7abc-8def-0123456789ab",
                "0190a6e2-3c4d-7abc-8def-0123456789ac",
            ],
        ),
        ("x-rgn-timeout-ms", vec!["5s"]),
        ("rgn-txn-id", vec!["two words"]),
        ("rgn-causality-token", vec![""]),
    ];
    for (name, values) in cases {
        let mut request = get("/api/v1/ping").header("traceparent", TRACEPARENT);
        for v in values {
            request = request.header(name, v);
        }
        let before = unix_ms_now();
        let response = call(&services, request.body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        assert_node_headers(&response, before);
        let body = json_of(response).await;
        assert_eq!(body["error"]["code"], 1001, "{name}");
        assert_eq!(body["error"]["name"], "InvalidArgument");
        assert_eq!(body["error"]["retryable"], false);
        assert_eq!(body["error"]["details"]["header"], name);
        assert_eq!(body["error"]["traceId"], TRACE_ID);
    }
    // Without a valid traceparent a fresh trace id is reported.
    let response = call(
        &services,
        get("/api/v1/ping")
            .header("rgn-request-id", "x")
            .header("traceparent", "bogus")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let trace = json_of(response).await["error"]["traceId"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(trace.len(), 32);
    assert_ne!(trace, TRACE_ID);
}

/// `X-RGN-Timeout-Ms` becomes the server-side deadline, as `grpc-timeout` does on gRPC.
#[tokio::test]
async fn fr_api_002_timeout_header_becomes_deadline_rgn_5006() {
    let clock: Arc<dyn Clock> = Arc::new(JumpingClock {
        inner: SystemClock::new(),
        jumps: AtomicU64::new(0),
    });
    let services = services(clock);
    let response = call(
        &services,
        get("/api/v1/ping")
            .header("x-rgn-timeout-ms", "30000")
            .header("traceparent", TRACEPARENT)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    let body = json_of(response).await;
    assert_eq!(body["error"]["code"], 5006);
    assert_eq!(body["error"]["name"], "DeadlineExceeded");
    assert_eq!(body["error"]["traceId"], TRACE_ID);
}

#[tokio::test]
async fn fr_api_002_unknown_routes_and_methods_use_the_error_body() {
    let services = services(system_clock());
    for path in ["/api/v1/nope", "/", "/api/v2/ping"] {
        let response = call(&services, get(path).body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(response.headers().get("rgn-node-id").unwrap(), "7");
        let body = json_of(response).await;
        assert_eq!(body["error"]["code"], 1030, "{path}");
        assert!(!body["error"]["message"].as_str().unwrap().contains(path));
    }
    let response = call(
        &services,
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/ping")
            .header("traceparent", TRACEPARENT)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let body = json_of(response).await;
    assert_eq!(body["error"]["code"], 1001);
    assert_eq!(body["error"]["traceId"], TRACE_ID);
}

#[derive(Debug, serde::Deserialize)]
struct Sample {
    #[allow(dead_code)]
    n: u32,
}

async fn json_body_error(request: Request<Body>) -> ApiError {
    let state = RestState::new(&services(system_clock()));
    JsonBody::<Sample>::from_request(request, &state)
        .await
        .unwrap_err()
}

#[tokio::test]
async fn fr_api_002_json_body_rejections_use_rgn_codes_without_echoing_input() {
    let post = || {
        Request::builder()
            .method(Method::POST)
            .uri("/x")
            .header("traceparent", TRACEPARENT)
    };
    let state = RestState::new(&services(system_clock()));
    let ok = JsonBody::<Sample>::from_request(
        post()
            .header("content-type", "application/json")
            .body(Body::from(r#"{"n": 3}"#))
            .unwrap(),
        &state,
    )
    .await
    .unwrap();
    assert_eq!(ok.0.n, 3);

    for (request, kind) in [
        (
            post().body(Body::from(r#"{"n": 3}"#)).unwrap(),
            "content-type",
        ),
        (
            post()
                .header("content-type", "application/json")
                .body(Body::from("{secret-value"))
                .unwrap(),
            "syntax",
        ),
        (
            post()
                .header("content-type", "application/json")
                .body(Body::from(r#"{"n": "secret-value"}"#))
                .unwrap(),
            "data",
        ),
    ] {
        let err = json_body_error(request).await;
        assert_eq!(err.error().code(), ErrorCode::InvalidArgument, "{kind}");
        assert_eq!(err.error().details().get("body").unwrap(), kind);
        assert_eq!(err.trace_id(), TRACE_ID);
        assert!(!err.error().message().contains("secret-value"));
    }

    // Over the body limit: RGN-1002 / 413. The router's `DefaultBodyLimit` makes axum wrap
    // the body in `http_body_util::Limited`; the same wrapper is applied here directly.
    let limited = post()
        .header("content-type", "application/json")
        .body(Body::new(http_body_limited(64)))
        .unwrap();
    let err = json_body_error(limited).await;
    assert_eq!(err.error().code(), ErrorCode::DocumentTooLarge);
    assert_eq!(err.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A `len`-byte body behind a 16-byte limit.
fn http_body_limited(
    len: usize,
) -> impl http_body::Body<Data = bytes::Bytes, Error = axum::BoxError> {
    http_body_util::Limited::new(Body::from(vec![b' '; len]), 16)
}

/// Records what the resolver saw and authenticates `Bearer good` only.
#[derive(Debug, Default)]
struct TestResolver {
    seen: Mutex<Vec<(Option<String>, Option<bool>)>>,
}

impl PrincipalResolver for TestResolver {
    fn resolve<'a>(
        &'a self,
        ctx: &'a RequestContext,
        conn: Option<&'a ConnectionInfo>,
    ) -> BoxFuture<'a, Result<Option<Principal>, Error>> {
        let credentials = ctx.credentials().map(|c| c.expose().clone());
        self.seen
            .lock()
            .unwrap()
            .push((credentials.clone(), conn.map(|c| c.tls)));
        Box::pin(async move {
            match credentials.as_deref() {
                None => Ok(None),
                Some("Bearer good") => Ok(Some(Principal::new("alice"))),
                Some(_) => Err(Error::new(ErrorCode::Unauthenticated, "bad credentials")),
            }
        })
    }
}

#[tokio::test]
async fn fr_api_002_principal_resolver_receives_header_and_cookie_credentials() {
    let resolver = Arc::new(TestResolver::default());
    let services = services(system_clock()).with_principal_resolver(resolver.clone());

    let ok = call(
        &services,
        get("/api/v1/ping")
            .header("cookie", "rgn_session=good")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);

    let denied = call(
        &services,
        get("/api/v1/ping")
            .header("authorization", "Bearer bad")
            .header("traceparent", TRACEPARENT)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let body = json_of(denied).await;
    assert_eq!(body["error"]["code"], 4001);
    assert_eq!(body["error"]["traceId"], TRACE_ID);

    // The probe never consults the resolver.
    let live = call(
        &services,
        get("/api/v1/health/live")
            .header("authorization", "Bearer bad")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(live.status(), StatusCode::OK);

    let seen = resolver.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            (Some("Bearer good".to_owned()), None),
            (Some("Bearer bad".to_owned()), None),
        ]
    );
}

/// The CSRF token derivation is public so the login endpoint (lane H) and the GUI agree on it.
#[test]
fn tc_sec_008_csrf_token_is_stable_hex() {
    assert_eq!(csrf_token("abc"), csrf_token("abc"));
    assert_eq!(csrf_token("abc").len(), 64);
}

// ---------------------------------------------------------------------------------------------
// Listener tests.

struct Pki {
    _dir: tempfile::TempDir,
    server_config: rustegon_net::rustls::ServerConfig,
    client_config: rustegon_net::rustls::ClientConfig,
}

fn pki() -> Pki {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
    let (ca, ca_gen) = CertAuthority::generate(
        "rustegon test CA",
        KeyAlgorithm::EcdsaP256,
        clock.as_ref(),
        &OsRng,
    )
    .unwrap();
    let anchors = TrustAnchors::from_pem(ca_gen.cert_pem.as_bytes(), "ca.pem").unwrap();
    let node = ca
        .issue_node(
            "node7",
            &["127.0.0.1".into(), "localhost".into()],
            clock.as_ref(),
            &OsRng,
        )
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (dir.path().join("node.crt"), dir.path().join("node.key"));
    node.write_files(fs.as_ref(), &cert_path, &key_path)
        .unwrap();
    let identity = ReloadableCert::load(
        CertSource::new(fs, cert_path, key_path),
        rustegon_net::crypto_provider(),
        Arc::clone(&clock),
    )
    .unwrap();
    let tls = TlsContext::new(clock, TlsMinVersion::Tls13);
    let server_config = tls.client_listener_config(identity, None).unwrap();
    let client_config = tls.client_config(&anchors, None).unwrap();
    Pki {
        _dir: dir,
        server_config,
        client_config,
    }
}

struct Running {
    addr: SocketAddr,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn stop(self) {
        let _ = self.stop.send(());
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("server did not stop")
            .unwrap();
    }
}

fn spawn_serve<F>(addr: SocketAddr, serve: impl FnOnce(oneshot::Receiver<()>) -> F) -> Running
where
    F: Future<Output = ()> + Send + 'static,
{
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(serve(stopped));
    Running { addr, stop, task }
}

async fn start_rest(security: ListenerSecurity, services: &Services) -> Running {
    let server = RestServer::bind(
        &TokioNetwork,
        "127.0.0.1:0".parse().unwrap(),
        security,
        services,
        RestServerOptions {
            shutdown_grace: Duration::from_secs(5),
            ..RestServerOptions::default()
        },
    )
    .await
    .unwrap();
    spawn_serve(server.local_addr(), |stopped| {
        server.serve(async move {
            let _ = stopped.await;
        })
    })
}

async fn start_grpc(security: ListenerSecurity, services: &Services) -> Running {
    let server = GrpcServer::bind(
        &TokioNetwork,
        "127.0.0.1:0".parse().unwrap(),
        security,
        services,
        GrpcServerOptions {
            shutdown_grace: Duration::from_secs(5),
            ..GrpcServerOptions::default()
        },
    )
    .await
    .unwrap();
    spawn_serve(server.local_addr(), |stopped| {
        server.serve(async move {
            let _ = stopped.await;
        })
    })
}

/// Opens a connection (TLS with the given ALPN list when `client` is set).
async fn dial(
    addr: SocketAddr,
    client: Option<&rustegon_net::rustls::ClientConfig>,
    alpn: &[&[u8]],
) -> std::io::Result<Box<dyn Connection>> {
    let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await?;
    let Some(client) = client else {
        return Ok(conn);
    };
    let mut config = client.clone();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), conn)
        .await?;
    Ok(Box::new(stream))
}

/// One request over HTTP/1.1 or HTTP/2 on a fresh connection.
async fn http_get(
    io: Box<dyn Connection>,
    http2: bool,
    request: Request<Body>,
) -> hyper::Result<Response<Body>> {
    let io = TokioIo::new(io);
    let response = if http2 {
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
        tokio::spawn(conn);
        sender.send_request(request).await?
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);
        sender.send_request(request).await?
    };
    Ok(response.map(Body::new))
}

fn ping_request(http2: bool) -> Request<Body> {
    let builder = get(if http2 {
        "https://localhost/api/v1/ping"
    } else {
        "/api/v1/ping"
    });
    let builder = if http2 {
        builder
    } else {
        builder.header("host", "localhost")
    };
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn fr_tls_001_rest_listener_serves_http1_and_http2_over_tls() {
    let pki = pki();
    let resolver = Arc::new(TestResolver::default());
    let services = services(system_clock()).with_principal_resolver(resolver.clone());
    let running = start_rest(ListenerSecurity::tls(pki.server_config.clone()), &services).await;

    for (alpn, http2) in [(&b"http/1.1"[..], false), (&b"h2"[..], true)] {
        let io = dial(running.addr, Some(&pki.client_config), &[alpn])
            .await
            .unwrap();
        let before = unix_ms_now();
        let response = http_get(io, http2, ping_request(http2)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.version(),
            if http2 {
                http::Version::HTTP_2
            } else {
                http::Version::HTTP_11
            }
        );
        assert_node_headers(&response, before);
        assert_eq!(json_of(response).await, serde_json::json!({}));
    }
    // The resolver sees the connection facts of the TLS listener.
    assert!(
        resolver
            .seen
            .lock()
            .unwrap()
            .iter()
            .all(|(_, tls)| *tls == Some(true))
    );

    // A plain-text client cannot talk to the TLS listener.
    let io = dial(running.addr, None, &[]).await.unwrap();
    assert!(http_get(io, false, ping_request(false)).await.is_err());
    running.stop().await;
}

#[tokio::test]
async fn fr_tls_001_rest_plain_text_only_without_tls_on_single_node() {
    let policy = transport_security(false, Deployment::SingleNode).unwrap();
    let services = services(system_clock());
    let running = start_rest(ListenerSecurity::plain_text(policy).unwrap(), &services).await;
    for http2 in [false, true] {
        // Plain HTTP/1.1, and HTTP/2 with prior knowledge (h2c).
        let io = dial(running.addr, None, &[]).await.unwrap();
        let response = http_get(io, http2, ping_request(http2)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "http2={http2}");
        assert_eq!(response.headers().get("rgn-node-id").unwrap(), "7");
    }
    running.stop().await;
    assert!(
        ListenerSecurity::plain_text(transport_security(true, Deployment::SingleNode).unwrap())
            .is_err()
    );
}

/// Whether `e` is the peer closing the connection under a request still being written.
fn is_connection_reset(e: &hyper::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset};
    std::error::Error::source(e)
        .and_then(|s| s.downcast_ref::<std::io::Error>())
        .is_some_and(|io| matches!(io.kind(), BrokenPipe | ConnectionAborted | ConnectionReset))
}

/// A `POST /api/v1/auth/login` whose JSON body is about `len` bytes and lacks the required
/// members, so a 400 `data` answer proves the server read and parsed the whole body.
fn large_login_request(http2: bool, len: usize) -> Request<Body> {
    let body = format!("{{\"pad\":\"{}\"}}", "p".repeat(len));
    let builder = Request::builder().method(Method::POST);
    let builder = if http2 {
        builder.uri("https://localhost/api/v1/auth/login")
    } else {
        builder
            .uri("/api/v1/auth/login")
            .header("host", "localhost")
    };
    builder
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// FR-API-002: multi-megabyte request bodies from an independent client (hyper, HTTP/1.1 and
/// HTTP/2 over TLS) are read to the end, and a body over the listener's limit is refused with
/// RGN-1002 / 413 (protocol.md §4) instead of stalling. Server side of the "REST large request
/// stall" investigation (PD-105): the stall was the hand-written test client never flushing
/// its TLS stream.
#[tokio::test]
async fn fr_api_002_large_request_bodies_complete_over_tls() {
    let pki = pki();
    let services = services(system_clock());
    let limited = RestServer::bind(
        &TokioNetwork,
        "127.0.0.1:0".parse().unwrap(),
        ListenerSecurity::tls(pki.server_config.clone()),
        &services,
        RestServerOptions {
            max_body_bytes: 8 * 1024 * 1024,
            shutdown_grace: Duration::from_secs(5),
            ..RestServerOptions::default()
        },
    )
    .await
    .unwrap();
    let running = spawn_serve(limited.local_addr(), |stopped| {
        limited.serve(async move {
            let _ = stopped.await;
        })
    });
    for (alpn, http2) in [(&b"http/1.1"[..], false), (&b"h2"[..], true)] {
        for (len, status, code) in [
            (4 * 1024 * 1024, StatusCode::BAD_REQUEST, 1001),
            (12 * 1024 * 1024, StatusCode::PAYLOAD_TOO_LARGE, 1002),
        ] {
            let io = dial(running.addr, Some(&pki.client_config), &[alpn])
                .await
                .unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(60),
                http_get(io, http2, large_login_request(http2, len)),
            )
            .await
            .unwrap_or_else(|_| panic!("http2={http2} len={len}: no response"));
            let response = match result {
                Ok(response) => response,
                // HTTP/1.1 has no way to stop the sender but closing: hyper answers 413 and
                // closes while the client is still writing, so the client may see the reset
                // before the answer (PD-106). Not a stall, which is what this test guards.
                Err(e) if !http2 && code == 1002 && is_connection_reset(&e) => continue,
                Err(e) => panic!("http2={http2} len={len}: {e:?}"),
            };
            assert_eq!(response.status(), status, "http2={http2} len={len}");
            let body = json_of(response).await;
            assert_eq!(body["error"]["code"], code, "http2={http2} len={len}");
            if code == 1001 {
                assert_eq!(body["error"]["details"]["body"], "data");
            }
        }
    }
    running.stop().await;
}

async fn grpc_channel(addr: SocketAddr, client: &rustegon_net::rustls::ClientConfig) -> Channel {
    let client = client.clone();
    Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let client = client.clone();
            async move {
                let io = dial(addr, Some(&client), &[b"h2"]).await?;
                Ok::<_, std::io::Error>(TokioIo::new(io))
            }
        }))
        .await
        .unwrap()
}

/// TC-API-006 (part): the same operations through gRPC and REST, served from one `Services`,
/// return equal results, and the same malformed request fails identically.
#[tokio::test]
async fn tc_api_006_rest_and_grpc_return_equal_session_results_and_errors() {
    let pki = pki();
    let services = services(system_clock());
    let grpc = start_grpc(ListenerSecurity::tls(pki.server_config.clone()), &services).await;
    let rest = start_rest(ListenerSecurity::tls(pki.server_config.clone()), &services).await;
    let mut client = SessionServiceClient::new(grpc_channel(grpc.addr, &pki.client_config).await);

    // Ping.
    let grpc_ping = client.ping(PingRequest {}).await.unwrap();
    let io = dial(rest.addr, Some(&pki.client_config), &[b"h2"])
        .await
        .unwrap();
    let rest_ping = http_get(io, true, ping_request(true)).await.unwrap();
    assert_eq!(rest_ping.status(), StatusCode::OK);
    assert_eq!(
        grpc_ping.metadata().get("rgn-node-id").unwrap().as_bytes(),
        rest_ping.headers().get("rgn-node-id").unwrap().as_bytes()
    );

    // Server info: field-by-field equality.
    let grpc_info = client
        .get_server_info(GetServerInfoRequest {})
        .await
        .unwrap()
        .into_inner();
    let io = dial(rest.addr, Some(&pki.client_config), &[b"h2"])
        .await
        .unwrap();
    let response = http_get(
        io,
        true,
        get("https://localhost/api/v1/server-info")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    let rest_info: ServerInfoResponse = serde_json::from_value(json_of(response).await).unwrap();
    assert_eq!(
        (
            rest_info.server_version,
            rest_info.protocol_version,
            rest_info.features,
            rest_info.node_addresses
        ),
        (
            grpc_info.server_version,
            grpc_info.protocol_version,
            grpc_info.features,
            grpc_info.node_addresses
        )
    );

    // The same malformed header: same code, name, retry flag, details and trace id.
    let mut request = GrpcRequest::new(PingRequest {});
    request
        .metadata_mut()
        .insert("rgn-request-id", MetadataValue::from_static("not-a-uuid"));
    request
        .metadata_mut()
        .insert("traceparent", MetadataValue::from_static(TRACEPARENT));
    let status = client.ping(request).await.unwrap_err();
    let detail = error_detail_of(&status).unwrap();
    let io = dial(rest.addr, Some(&pki.client_config), &[b"h2"])
        .await
        .unwrap();
    let response = http_get(
        io,
        true,
        get("https://localhost/api/v1/ping")
            .header("rgn-request-id", "not-a-uuid")
            .header("traceparent", TRACEPARENT)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: ErrorBody = serde_json::from_value(json_of(response).await).unwrap();
    assert_eq!(body.error.code, detail.code);
    assert_eq!(body.error.name, detail.name);
    assert_eq!(body.error.message, status.message());
    assert_eq!(body.error.retryable, detail.retryable);
    assert_eq!(body.error.committed, detail.committed);
    assert_eq!(
        body.error.details,
        detail
            .details
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>()
    );
    assert_eq!(body.error.trace_id, detail.trace_id);

    grpc.stop().await;
    rest.stop().await;
}

/// gRPC and REST share one TLS configuration: the gRPC listener still refuses HTTP/1.1-only
/// clients (ALPN `h2`), while the REST listener accepts them.
#[tokio::test]
async fn fr_tls_001_shared_tls_config_keeps_per_listener_alpn() {
    let pki = pki();
    let services = services(system_clock());
    let grpc = start_grpc(ListenerSecurity::tls(pki.server_config.clone()), &services).await;
    assert!(
        dial(grpc.addr, Some(&pki.client_config), &[b"http/1.1"])
            .await
            .is_err()
    );
    let rest = start_rest(ListenerSecurity::tls(pki.server_config.clone()), &services).await;
    assert!(
        dial(rest.addr, Some(&pki.client_config), &[b"http/1.1"])
            .await
            .is_ok()
    );
    grpc.stop().await;
    rest.stop().await;
}
