// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC skeleton end to end (FR-API-001, PD-050): a tonic client talks to [`GrpcServer`] over
//! TLS on a loopback socket (sim-api `TokioNetwork`, certificates from
//! `rustegon_net::CertAuthority`). TC-API-003 part: `SessionService` round trips;
//! TC-API-005 part: request errors carry the packed `ErrorDetail` with the caller's trace id.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use hyper_util::rt::TokioIo;
use rustegon_common::ErrorCode;
use rustegon_net::{
    CertAuthority, CertSource, Deployment, KeyAlgorithm, ReloadableCert, TlsContext, TlsMinVersion,
    TransportSecurity, TrustAnchors,
    rustls::pki_types::ServerName,
    tokio_rustls::{TlsConnector, client::TlsStream},
    transport_security,
};
use rustegon_proto::{
    status::error_detail_of,
    v1::{GetServerInfoRequest, PingRequest, session_service_client::SessionServiceClient},
};
use rustegon_server::{
    Completion, Executor,
    grpc::{
        GrpcServer, GrpcServerOptions, ListenerSecurity, ServerError, context_from_metadata,
        status_of,
    },
    services::{NodeIdentity, ServiceDeps, Services},
};
use rustegon_sim_api::{
    BoxFuture, Clock, Connection, FileSystem, Network, OsRng, StdFileSystem, SystemClock,
    TokioNetwork,
};
use tokio::sync::oneshot;
use tonic::{
    Code, Request,
    metadata::{MetadataMap, MetadataValue},
    transport::{Channel, Endpoint},
};

const NODE_ID: u64 = 7;
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

/// A clock whose monotonic time jumps one hour on every reading, so any
/// deadline computed from the request expires by the next check while the client's own
/// timer (real time) is still far away.
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
    let mut client_config = tls.client_config(&anchors, None).unwrap();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    Pki {
        _dir: dir,
        server_config,
        client_config,
    }
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

struct Running {
    addr: SocketAddr,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
    _pki: Option<Pki>,
    client_config: Option<rustegon_net::rustls::ClientConfig>,
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

async fn start(security: ListenerSecurity, clock: Arc<dyn Clock>, pki: Option<Pki>) -> Running {
    let server = GrpcServer::bind(
        &TokioNetwork,
        "127.0.0.1:0".parse().unwrap(),
        security,
        &services(clock),
        GrpcServerOptions {
            shutdown_grace: Duration::from_secs(5),
            ..GrpcServerOptions::default()
        },
    )
    .await
    .unwrap();
    let addr = server.local_addr();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(server.serve(async move {
        let _ = stopped.await;
    }));
    let client_config = pki.as_ref().map(|p| p.client_config.clone());
    Running {
        addr,
        stop,
        task,
        _pki: pki,
        client_config,
    }
}

async fn start_tls(clock: Arc<dyn Clock>) -> Running {
    let pki = pki();
    let security = ListenerSecurity::tls(pki.server_config.clone());
    start(security, clock, Some(pki)).await
}

/// A tonic channel whose connector dials through the sim-api network and, with a client
/// config, performs the TLS handshake for `localhost`.
async fn channel(running: &Running) -> Channel {
    try_channel(running).await.unwrap()
}

async fn try_channel(running: &Running) -> Result<Channel, tonic::transport::Error> {
    let addr = running.addr;
    let tls = running
        .client_config
        .clone()
        .map(|c| TlsConnector::from(Arc::new(c)));
    Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let tls = tls.clone();
            async move {
                let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await?;
                let io: Box<dyn Connection> = match tls {
                    Some(tls) => {
                        let stream: TlsStream<Box<dyn Connection>> = tls
                            .connect(ServerName::try_from("localhost").unwrap(), conn)
                            .await?;
                        Box::new(stream)
                    }
                    None => conn,
                };
                Ok::<_, std::io::Error>(TokioIo::new(io))
            }
        }))
        .await
}

fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock::new())
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

fn assert_node_trailers(metadata: &MetadataMap, before_ms: u64) {
    assert_eq!(metadata.get("rgn-node-id").unwrap(), "7");
    let server_ms: u64 = metadata
        .get("rgn-server-time")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        server_ms >= before_ms && server_ms <= unix_ms_now(),
        "rgn-server-time {server_ms} outside the call window"
    );
}

#[tokio::test]
async fn tc_api_003_session_ping_and_server_info_over_tls() {
    let running = start_tls(system_clock()).await;
    let mut client = SessionServiceClient::new(channel(&running).await);

    let before = unix_ms_now();
    let ping = client.ping(PingRequest {}).await.unwrap();
    assert_node_trailers(ping.metadata(), before);
    assert!(ping.metadata().get("rgn-causality-token").is_none());

    let info = client
        .get_server_info(GetServerInfoRequest {})
        .await
        .unwrap();
    assert_node_trailers(info.metadata(), before);
    let info = info.into_inner();
    assert_eq!(info.server_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.protocol_version, "1.0");
    assert_eq!(info.features, vec!["example-flag".to_owned()]);
    assert_eq!(info.node_addresses, vec!["127.0.0.1:7700".to_owned()]);

    running.stop().await;
}

/// The trailers really travel as HTTP/2 trailers on success (not only as headers): the raw
/// response headers of a unary call must not contain them.
#[tokio::test]
async fn tc_api_003_success_trailers_are_sent_after_the_message() {
    let running = start_tls(system_clock()).await;
    let mut client = tonic::client::Grpc::new(channel(&running).await);
    client.ready().await.unwrap();
    let codec = tonic_prost::ProstCodec::<PingRequest, rustegon_proto::v1::PingResponse>::default();
    let mut request = Request::new(PingRequest {});
    request
        .metadata_mut()
        .insert("rgn-causality-token", MetadataValue::from_static("tok-42"));
    let response = client
        .server_streaming(
            request,
            http::uri::PathAndQuery::from_static("/rustegon.v1.SessionService/Ping"),
            codec,
        )
        .await
        .unwrap();
    assert!(response.metadata().get("rgn-node-id").is_none());
    let mut stream = response.into_inner();
    assert!(stream.message().await.unwrap().is_some());
    assert!(stream.message().await.unwrap().is_none());
    let trailers = stream.trailers().await.unwrap().unwrap();
    assert_eq!(trailers.get("rgn-node-id").unwrap(), "7");
    assert!(trailers.get("rgn-server-time").is_some());
    assert_eq!(trailers.get("rgn-causality-token").unwrap(), "tok-42");
    running.stop().await;
}

#[tokio::test]
async fn tc_api_005_malformed_request_id_is_rgn_1001_with_error_detail() {
    let running = start_tls(system_clock()).await;
    let mut client = SessionServiceClient::new(channel(&running).await);

    let mut request = Request::new(PingRequest {});
    let md = request.metadata_mut();
    md.insert("rgn-request-id", MetadataValue::from_static("not-a-uuid"));
    md.insert("traceparent", MetadataValue::from_static(TRACEPARENT));
    let status = client.ping(request).await.unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    let detail = error_detail_of(&status).expect("ErrorDetail");
    assert_eq!(detail.code, 1001);
    assert_eq!(detail.name, "InvalidArgument");
    assert!(!detail.retryable);
    assert_eq!(detail.trace_id, TRACE_ID);
    assert_eq!(detail.details.get("header").unwrap(), "rgn-request-id");
    // Error responses carry the node trailers too (trailers-only response).
    assert_eq!(status.metadata().get("rgn-node-id").unwrap(), "7");

    // A valid UUIDv7 and an invalid traceparent are accepted (traceparent is ignored).
    let mut request = Request::new(PingRequest {});
    let md = request.metadata_mut();
    md.insert(
        "rgn-request-id",
        MetadataValue::from_static("0190a6e2-3c4d-7abc-8def-0123456789ab"),
    );
    md.insert("traceparent", MetadataValue::from_static("bogus"));
    client.ping(request).await.unwrap();

    running.stop().await;
}

#[tokio::test]
async fn tc_api_005_repeated_or_malformed_headers_are_rgn_1001() {
    let running = start_tls(system_clock()).await;
    let mut client = SessionServiceClient::new(channel(&running).await);

    let cases: [(&str, Vec<&'static str>); 4] = [
        (
            "rgn-request-id",
            vec![
                "0190a6e2-3c4d-7abc-8def-0123456789ab",
                "0190a6e2-3c4d-7abc-8def-0123456789ac",
            ],
        ),
        ("rgn-txn-id", vec!["two words"]),
        ("rgn-causality-token", vec![""]),
        // Unparseable for the client's own timeout layer too, so only the server judges it.
        ("grpc-timeout", vec!["soon"]),
    ];
    for (name, values) in cases {
        let mut request = Request::new(PingRequest {});
        for v in values {
            request
                .metadata_mut()
                .append(name, MetadataValue::from_static(v));
        }
        let status = client.ping(request).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{name}");
        let detail = error_detail_of(&status).expect("ErrorDetail");
        assert_eq!(detail.code, 1001, "{name}");
        assert_eq!(detail.details.get("header").unwrap(), name);
        assert_eq!(detail.trace_id.len(), 32, "generated trace id");
    }
    running.stop().await;
}

/// `grpc-timeout` becomes the server-side deadline: with a server clock that jumps an hour per
/// reading, the 30 s client timeout is already exceeded when the service checks it, and the
/// client receives RGN-5006 with its `ErrorDetail` (not the bare CANCELLED of tonic's own
/// timeout layer, which this server does not install).
#[tokio::test]
async fn fr_api_001_grpc_timeout_becomes_server_deadline_rgn_5006() {
    let clock: Arc<dyn Clock> = Arc::new(JumpingClock {
        inner: SystemClock::new(),
        jumps: AtomicU64::new(0),
    });
    let running = start_tls(clock).await;
    let mut client = SessionServiceClient::new(channel(&running).await);
    let mut request = Request::new(PingRequest {});
    request.set_timeout(Duration::from_secs(30));
    request
        .metadata_mut()
        .insert("traceparent", MetadataValue::from_static(TRACEPARENT));
    let status = client.ping(request).await.unwrap_err();
    assert_eq!(status.code(), Code::DeadlineExceeded);
    let detail = error_detail_of(&status).expect("ErrorDetail");
    assert_eq!(detail.code, 5006);
    assert_eq!(detail.name, "DeadlineExceeded");
    assert_eq!(detail.trace_id, TRACE_ID);
    running.stop().await;
}

/// The deadline parsed from gRPC metadata reaches the blocking executor: a scan-like closure
/// observes the expired token, the handler returns RGN-5006, and the mapped status decodes.
#[tokio::test]
async fn fr_api_001_grpc_timeout_propagates_into_executor() {
    let clock = system_clock();
    let services = services(Arc::clone(&clock));
    let mut md = MetadataMap::new();
    md.insert("grpc-timeout", MetadataValue::from_static("40m"));
    md.insert("traceparent", MetadataValue::from_static(TRACEPARENT));
    let ctx = context_from_metadata(&md, services.deps()).unwrap();
    assert_eq!(ctx.deadline().unwrap().timeout, Duration::from_millis(40));
    let (seen_tx, seen_rx) = std::sync::mpsc::channel();
    let err = services
        .deps()
        .executor
        .run::<(), _>(&ctx, Completion::Abandon, move |token| {
            assert!(token.deadline().is_some());
            while token.check().is_ok() {
                std::thread::yield_now();
            }
            let _ = seen_tx.send(token.check().unwrap_err().code());
            Ok(())
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
    let status = status_of(&err, &ctx.trace_id_hex());
    assert_eq!(status.code(), Code::DeadlineExceeded);
    let detail = error_detail_of(&status).unwrap();
    assert_eq!((detail.code, detail.trace_id.as_str()), (5006, TRACE_ID));
    let seen = tokio::task::spawn_blocking(move || seen_rx.recv_timeout(Duration::from_secs(10)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(seen, ErrorCode::DeadlineExceeded);
}

/// Plain text is only available through the transport-security policy (single node with
/// `security.tls = false`, ADR-034), and then serves HTTP/2 prior knowledge.
#[tokio::test]
async fn fr_tls_001_plain_text_listener_only_without_tls_on_single_node() {
    assert!(matches!(
        ListenerSecurity::plain_text(transport_security(true, Deployment::SingleNode).unwrap()),
        Err(ServerError::PlainTextNotAllowed)
    ));
    assert!(transport_security(false, Deployment::Cluster).is_err());
    let policy = transport_security(false, Deployment::SingleNode).unwrap();
    assert_eq!(policy, TransportSecurity::PlainText);
    let running = start(
        ListenerSecurity::plain_text(policy).unwrap(),
        system_clock(),
        None,
    )
    .await;
    let mut client = SessionServiceClient::new(channel(&running).await);
    let ping = client.ping(PingRequest {}).await.unwrap();
    assert_eq!(ping.metadata().get("rgn-node-id").unwrap(), "7");
    running.stop().await;
}

/// A plain-text client cannot talk to the TLS listener, and services that are not registered
/// yet (wave 2b) answer UNIMPLEMENTED with the node trailers.
#[tokio::test]
async fn fr_api_001_tls_listener_refuses_plain_text_and_unregistered_services() {
    let running = start_tls(system_clock()).await;
    let plain = Running {
        addr: running.addr,
        stop: oneshot::channel().0,
        task: tokio::spawn(async {}),
        _pki: None,
        client_config: None,
    };
    let attempt = tokio::time::timeout(Duration::from_secs(10), async {
        let channel = try_channel(&plain).await.map_err(|e| e.to_string())?;
        SessionServiceClient::new(channel)
            .ping(PingRequest {})
            .await
            .map_err(|s| s.to_string())
    })
    .await
    .expect("plain-text attempt must fail promptly");
    assert!(attempt.is_err());

    let mut client = tonic::client::Grpc::new(channel(&running).await);
    client.ready().await.unwrap();
    let codec = tonic_prost::ProstCodec::<PingRequest, rustegon_proto::v1::PingResponse>::default();
    let status = client
        .unary(
            Request::new(PingRequest {}),
            http::uri::PathAndQuery::from_static("/rustegon.v1.QueryService/Explain"),
            codec,
        )
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(status.metadata().get("rgn-node-id").unwrap(), "7");
    running.stop().await;
}

/// Shutdown stops the listener: new connections are refused afterwards.
#[tokio::test]
async fn fr_api_001_graceful_shutdown_stops_accepting() {
    let running = start_tls(system_clock()).await;
    let addr = running.addr;
    let mut client = SessionServiceClient::new(channel(&running).await);
    client.ping(PingRequest {}).await.unwrap();
    drop(client);
    running.stop().await;
    assert!(TokioNetwork.connect(addr).await.is_err());
}
