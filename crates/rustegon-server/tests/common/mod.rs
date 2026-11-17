// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared harness of the security integration tests: a TLS (optionally mTLS) gRPC server over
//! a real `EmbeddedDb` with the security layer installed, certificates from
//! `rustegon_net::CertAuthority`, a SCRAM client over the `Authenticate` stream, and a raw
//! client able to call any RPC with an empty request (privilege matrix).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code,
    unreachable_pub
)]

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use hyper_util::rt::TokioIo;
use rustegon_common::settings::{Registry, Sources};
use rustegon_engine::EmbeddedDb;
use rustegon_net::{
    CertAuthority, CertSource, GeneratedCert, KeyAlgorithm, ReloadableCert, TlsContext,
    TlsMinVersion, TrustAnchors,
    rustls::{self, pki_types::ServerName},
    tokio_rustls::{TlsConnector, client::TlsStream},
};
use rustegon_proto::v1::{
    AuthMechanism, AuthSuccess, AuthenticateRequest, ClientInfo,
    auth_service_client::AuthServiceClient, authenticate_response::Step,
};
use rustegon_security::authn::{
    apikey::Argon2Cost,
    bootstrap::AdminPassword,
    scram::{ClientBinding, ScramClient, TLS_EXPORTER_LEN},
    secret,
};
use rustegon_server::{
    Executor,
    grpc::{GrpcServer, GrpcServerOptions, ListenerSecurity},
    security::{Security, SecurityConfig, register_security_settings},
    services::{DataPlaneConfig, NodeIdentity, ServiceDeps, Services},
};
use rustegon_sim_api::{
    BoxFuture, Clock, Connection, FileSystem, Network, OsRng, StdFileSystem, SystemClock,
    TokioNetwork,
};
use tokio::sync::{mpsc, oneshot};
use tonic::{
    Request, Status,
    codegen::tokio_stream::wrappers::ReceiverStream,
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
};

/// The bootstrap administrator.
pub const ADMIN: &str = "admin";
/// Its password (passes the policy; test-only, not a real secret).
pub const ADMIN_PASSWORD: &str = "q7Vz!m2Lp#9Rx4Tk";
/// A second password that passes the policy.
pub const OTHER_PASSWORD: &str = "Zr8&uW3n!Kd5Qe2p";

/// A clock whose wall and monotonic time can be moved forward (session expiry).
pub struct OffsetClock {
    inner: SystemClock,
    offset_ms: AtomicU64,
}

impl OffsetClock {
    pub fn new() -> Self {
        Self {
            inner: SystemClock::new(),
            offset_ms: AtomicU64::new(0),
        }
    }

    pub fn advance(&self, d: Duration) {
        self.offset_ms
            .fetch_add(u64::try_from(d.as_millis()).unwrap(), Ordering::SeqCst);
    }

    fn offset(&self) -> Duration {
        Duration::from_millis(self.offset_ms.load(Ordering::SeqCst))
    }
}

impl Clock for OffsetClock {
    fn monotonic(&self) -> Duration {
        self.inner.monotonic() + self.offset()
    }
    fn wall(&self) -> SystemTime {
        self.inner.wall() + self.offset()
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        self.inner.sleep(d)
    }
}

/// Certificates of one test: the CA, the server identity, client identities.
pub struct Pki {
    pub dir: tempfile::TempDir,
    pub ca: CertAuthority,
    pub anchors: TrustAnchors,
    pub tls: TlsContext,
}

impl Pki {
    pub fn new() -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let (ca, ca_gen) = CertAuthority::generate(
            "rustegon test CA",
            KeyAlgorithm::EcdsaP256,
            clock.as_ref(),
            &OsRng,
        )
        .unwrap();
        let anchors = TrustAnchors::from_pem(ca_gen.cert_pem.as_bytes(), "ca.pem").unwrap();
        Self {
            dir: tempfile::tempdir().unwrap(),
            ca,
            anchors,
            tls: TlsContext::new(clock, TlsMinVersion::Tls13),
        }
    }

    /// Writes `cert` to files and loads it as a reloadable identity.
    pub fn identity(&self, name: &str, cert: &GeneratedCert) -> Arc<ReloadableCert> {
        let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
        let cert_path = self.dir.path().join(format!("{name}.crt"));
        let key_path = self.dir.path().join(format!("{name}.key"));
        cert.write_files(fs.as_ref(), &cert_path, &key_path)
            .unwrap();
        ReloadableCert::load(
            CertSource::new(fs, cert_path, key_path),
            rustegon_net::crypto_provider(),
            Arc::new(SystemClock::new()),
        )
        .unwrap()
    }

    pub fn node_cert(&self, name: &str) -> GeneratedCert {
        self.ca
            .issue_node(
                name,
                &["127.0.0.1".into(), "localhost".into()],
                &SystemClock::new(),
                &OsRng,
            )
            .unwrap()
    }

    pub fn client_cert(&self, cn: &str) -> GeneratedCert {
        self.ca
            .issue_client(cn, &SystemClock::new(), &OsRng)
            .unwrap()
    }

    /// Server config of the client port, accepting optional client certificates.
    pub fn server_config(&self) -> rustls::ServerConfig {
        let id = self.identity("server", &self.node_cert("node7"));
        self.tls
            .client_listener_config(id, Some(&self.anchors))
            .unwrap()
    }

    /// Client config, presenting `identity` when given.
    pub fn client_config(&self, identity: Option<Arc<ReloadableCert>>) -> rustls::ClientConfig {
        let mut c = self.tls.client_config(&self.anchors, identity).unwrap();
        c.alpn_protocols = vec![b"h2".to_vec()];
        c
    }
}

/// The backup destination allowlist of the test servers: the system temporary directory.
pub fn test_backup_policy() -> rustegon_backup::DestinationPolicy {
    rustegon_backup::DestinationPolicy::new(vec![
        rustegon_backup::AllowedDestination::local(&std::env::temp_dir()).unwrap(),
    ])
}

/// A destination outside [`test_backup_policy`].
pub fn disallowed_destination() -> PathBuf {
    std::env::temp_dir()
        .parent()
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
        .join("rustegon-not-allowed")
}

/// The backup backend of a test server.
pub enum BackupSetup {
    /// A given (fake) backend.
    Backend(Arc<dyn rustegon_server::services::BackupBackend>),
    /// The engine backend over the harness's own store.
    Engine,
}

/// The process side of the online restore in tests (ADR-037): records what `RestoreBackup`
/// scheduled instead of stopping a process, and reports the last one as completed.
#[derive(Default)]
pub struct RecordingScheduler {
    pub scheduled: Mutex<Vec<rustegon_server::services::backup::ScheduledRestore>>,
}

impl rustegon_server::services::backup::RestoreScheduler for RecordingScheduler {
    fn schedule(
        &self,
        restore: rustegon_server::services::backup::ScheduledRestore,
    ) -> Result<(), rustegon_common::Error> {
        self.scheduled.lock().unwrap().push(restore);
        Ok(())
    }

    fn status(
        &self,
    ) -> Result<rustegon_server::services::backup::RestoreOutcome, rustegon_common::Error> {
        use rustegon_server::services::backup::RestoreOutcome;
        Ok(match self.scheduled.lock().unwrap().last() {
            None => RestoreOutcome::None,
            Some(r) => RestoreOutcome::Completed {
                backup_id: r.backup_id.to_string(),
                finished_at_unix_ms: 1_794_219_400_000,
                previous_store: "store.pre-restore-20261109T101640Z".into(),
            },
        })
    }
}

/// A running server with its security layer.
pub struct Harness {
    /// The restores `RestoreBackup` scheduled.
    pub restores: Arc<RecordingScheduler>,
    pub addr: SocketAddr,
    pub pki: Pki,
    pub security: Arc<Security>,
    pub services: Services,
    pub clock: Arc<OffsetClock>,
    pub data_dir: PathBuf,
    pub engine: Arc<EmbeddedDb>,
    engine_dir_guard: tempfile::TempDir,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

/// Settings flags common to the tests: the smallest SCRAM iteration count the configuration
/// accepts (debug builds), limits off unless a test turns them on.
pub fn base_flags() -> Vec<String> {
    vec![
        "auth.scram_iterations=100000".into(),
        "rate_limit.enabled=false".into(),
    ]
}

impl Harness {
    /// Starts a server with `flags` (`section.key=value`) and a bootstrapped admin.
    pub async fn start(flags: Vec<String>) -> Self {
        Self::start_with(flags, true).await
    }

    pub async fn start_with(flags: Vec<String>, bootstrap: bool) -> Self {
        Self::start_full(flags, bootstrap, Some(DataPlaneConfig::default()), None).await
    }

    /// A server with the data plane (lane G, PD-053) configured by `data` (`None`: no data
    /// plane) and, optionally, another clock for the services (deadline tests).
    pub async fn start_full(
        flags: Vec<String>,
        bootstrap: bool,
        data: Option<DataPlaneConfig>,
        service_clock: Option<Arc<dyn Clock>>,
    ) -> Self {
        Self::start_custom(flags, bootstrap, data, service_clock, None).await
    }

    /// A server with the data plane and `backend` behind `BackupService` (M13a, PD-077).
    pub async fn start_with_backup(
        flags: Vec<String>,
        backend: Arc<dyn rustegon_server::services::BackupBackend>,
    ) -> Self {
        Self::start_custom(
            flags,
            true,
            Some(DataPlaneConfig::default()),
            None,
            Some(BackupSetup::Backend(backend)),
        )
        .await
    }

    /// A server with the data plane and the engine backup backend over its own store (M13a
    /// lane BE): the store is `<engine_dir>/store`, so `<engine_dir>` plays the data directory
    /// (snapshots in `<engine_dir>/snapshots`).
    pub async fn start_with_engine_backup(flags: Vec<String>) -> Self {
        Self::start_custom(
            flags,
            true,
            Some(DataPlaneConfig::default()),
            None,
            Some(BackupSetup::Engine),
        )
        .await
    }

    /// The directory holding the store (`<this>/store`) and, with the engine backup backend,
    /// its snapshots.
    pub fn engine_dir(&self) -> &Path {
        self.engine_dir_guard.path()
    }

    // The node assembly of every server test, in startup order; splitting it would hide that order.
    #[allow(clippy::too_many_lines)]
    async fn start_custom(
        flags: Vec<String>,
        bootstrap: bool,
        data: Option<DataPlaneConfig>,
        service_clock: Option<Arc<dyn Clock>>,
        backup: Option<BackupSetup>,
    ) -> Self {
        let pki = Pki::new();
        let engine_dir = tempfile::tempdir().unwrap();
        let data_dir = engine_dir.path().join("data");
        let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
        let engine = Arc::new(
            EmbeddedDb::open(
                Arc::clone(&fs),
                &engine_dir.path().join("store"),
                Arc::new(SystemClock::new()),
                Arc::new(OsRng),
            )
            .unwrap(),
        );
        let clock = Arc::new(OffsetClock::new());
        let dyn_clock: Arc<dyn Clock> = service_clock.unwrap_or_else(|| clock.clone());
        let deps = ServiceDeps {
            executor: Executor::new(Arc::clone(&dyn_clock), 16),
            clock: dyn_clock,
            rng: Arc::new(OsRng),
        };
        let security = open_security(&engine, &data_dir, flags, &deps);
        if bootstrap {
            security
                .bootstrap_if_needed(ADMIN, AdminPassword::Provided(secret(ADMIN_PASSWORD)))
                .unwrap();
        }
        let services = Services::new(
            deps,
            NodeIdentity {
                node_id: 7,
                features: vec![],
                client_addresses: vec![],
            },
        )
        .with_security(Arc::clone(&security))
        // Every test destination is a temporary directory (PD-082 allowlist); the parent of
        // the temporary directory is the conventional "not allowed" path of the tests.
        .with_backup_destinations(test_backup_policy());
        let restores = Arc::new(RecordingScheduler::default());
        let services = services.with_restore_scheduler(Arc::clone(&restores) as _);
        let services = match data {
            Some(config) => services.with_engine(Arc::clone(&engine), config),
            None => services,
        };
        let services = match backup {
            Some(BackupSetup::Backend(backend)) => services.with_backup_backend(backend),
            Some(BackupSetup::Engine) => {
                let physical = rustegon_backup::PhysicalBackups::open(
                    Arc::clone(&engine),
                    Arc::clone(&fs),
                    Arc::new(SystemClock::new()),
                    Arc::new(OsRng),
                    rustegon_backup::PhysicalConfig::new(
                        engine_dir.path().to_path_buf(),
                        rustegon_backup::SourceInfo {
                            cluster_id: "single-node".into(),
                            node_id: "node7".into(),
                            server_version: "test".into(),
                        },
                        None,
                    ),
                )
                .unwrap();
                services.with_backup_backend(Arc::new(
                    rustegon_server::services::backup_engine::EngineBackupBackend::new(
                        Arc::clone(&engine),
                        physical,
                    ),
                ))
            }
            None => services,
        };
        let server = GrpcServer::bind(
            &TokioNetwork,
            "127.0.0.1:0".parse().unwrap(),
            ListenerSecurity::tls(pki.server_config()),
            &services,
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
        Self {
            restores,
            addr,
            pki,
            security,
            services,
            clock,
            data_dir,
            engine,
            engine_dir_guard: engine_dir,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("server did not stop")
                .unwrap();
        }
    }

    /// A channel without client certificate.
    pub async fn channel(&self) -> Conn {
        self.connect(None).await
    }

    /// A channel presenting `identity` as client certificate.
    pub async fn connect(&self, identity: Option<Arc<ReloadableCert>>) -> Conn {
        let config = Arc::new(self.pki.client_config(identity));
        let addr = self.addr;
        let exporter: Arc<Mutex<Option<[u8; TLS_EXPORTER_LEN]>>> = Arc::default();
        let seen = Arc::clone(&exporter);
        let channel = Endpoint::from_static("http://localhost")
            .connect_with_connector(tower::service_fn(move |_| {
                let tls = TlsConnector::from(Arc::clone(&config));
                let seen = Arc::clone(&seen);
                async move {
                    let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await?;
                    let stream: TlsStream<Box<dyn Connection>> = tls
                        .connect(ServerName::try_from("localhost").unwrap(), conn)
                        .await?;
                    let value = stream
                        .get_ref()
                        .1
                        .export_keying_material(
                            [0u8; TLS_EXPORTER_LEN],
                            b"EXPORTER-Channel-Binding",
                            None,
                        )
                        .ok();
                    *seen.lock().unwrap() = value;
                    let io: Box<dyn Connection> = Box::new(stream);
                    Ok::<_, std::io::Error>(TokioIo::new(io))
                }
            }))
            .await
            .unwrap();
        Conn { channel, exporter }
    }

    pub fn audit_dir(&self) -> PathBuf {
        self.data_dir.join("audit")
    }

    /// Every audit line written so far.
    pub fn audit_lines(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let mut files: Vec<_> = std::fs::read_dir(self.audit_dir())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        for f in files {
            for line in std::fs::read_to_string(f).unwrap().lines() {
                out.push(serde_json::from_str(line).unwrap());
            }
        }
        out
    }

    /// Whether an audit record of `event` with `outcome` exists.
    pub fn audited(&self, event: &str, outcome: &str) -> bool {
        self.audit_lines()
            .iter()
            .any(|l| l["event"] == event && l["outcome"] == outcome)
    }
}

/// Opens the security layer over `engine` with the test registry.
pub fn open_security(
    engine: &Arc<EmbeddedDb>,
    data_dir: &std::path::Path,
    flags: Vec<String>,
    deps: &ServiceDeps,
) -> Arc<Security> {
    let mut registry = Registry::new();
    register_security_settings(&mut registry).unwrap();
    let mut config = SecurityConfig::new(
        Arc::clone(engine),
        Arc::new(StdFileSystem),
        data_dir.to_path_buf(),
        "node7",
        Arc::new(registry),
        Sources {
            flags,
            ..Sources::default()
        },
    );
    // Debug-build tests cannot afford 64 MiB Argon2id per key; verification uses the stored
    // cost, so this only weakens the test keys.
    config.api_key_cost = Argon2Cost {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    Security::open(config, deps).unwrap()
}

/// A client connection and the TLS exporter it observed.
#[derive(Clone)]
pub struct Conn {
    pub channel: Channel,
    pub exporter: Arc<Mutex<Option<[u8; TLS_EXPORTER_LEN]>>>,
}

/// How the test client binds the SCRAM exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// `p=tls-exporter` (SCRAM-SHA-256-PLUS).
    Plus,
    /// `n` (no channel binding support).
    None,
    /// `y` (client could bind but believes the server cannot): a downgrade on TLS 1.3.
    NotOffered,
}

impl Conn {
    /// A full SCRAM login; returns the server's success after verifying `server_final`.
    pub async fn login(
        &self,
        user: &str,
        password: &str,
        binding: Binding,
    ) -> Result<AuthSuccess, Status> {
        let exporter = self.exporter.lock().unwrap().expect("TLS 1.3 exporter");
        let binding = match binding {
            Binding::Plus => ClientBinding::TlsExporter(exporter),
            Binding::None => ClientBinding::Unsupported,
            Binding::NotOffered => ClientBinding::NotOffered,
        };
        let (client, _mechanism, first) =
            ScramClient::new(user, &secret(password), binding, &OsRng);
        let (tx, rx) = mpsc::channel(2);
        tx.send(AuthenticateRequest {
            mechanism: AuthMechanism::ScramSha256 as i32,
            payload: first.into_bytes(),
            client_info: Some(ClientInfo {
                driver_name: "rustegon-test".into(),
                driver_version: "0.1.0".into(),
                application: "tests".into(),
            }),
        })
        .await
        .unwrap();
        let mut stream = AuthServiceClient::new(self.channel.clone())
            .authenticate(ReceiverStream::new(rx))
            .await?
            .into_inner();
        let Some(Step::Challenge(server_first)) = stream.message().await?.and_then(|m| m.step)
        else {
            panic!("expected a challenge");
        };
        let server_first = String::from_utf8(server_first).unwrap();
        let (fin, client_final) = tokio::task::spawn_blocking(move || {
            client
                .server_first(&server_first)
                .map_err(|e| e.to_string())
        })
        .await
        .unwrap()
        .map_err(Status::internal)?;
        tx.send(AuthenticateRequest {
            mechanism: 0,
            payload: client_final.into_bytes(),
            client_info: None,
        })
        .await
        .unwrap();
        let Some(Step::Success(success)) = stream.message().await?.and_then(|m| m.step) else {
            panic!("expected success");
        };
        fin.server_final(std::str::from_utf8(&success.server_final).unwrap())
            .expect("server signature verifies");
        Ok(success)
    }

    /// `Authenticate{X509}` with the connection's client certificate.
    pub async fn login_x509(&self) -> Result<AuthSuccess, Status> {
        let (tx, rx) = mpsc::channel(1);
        tx.send(AuthenticateRequest {
            mechanism: AuthMechanism::X509 as i32,
            payload: Vec::new(),
            client_info: None,
        })
        .await
        .unwrap();
        let mut stream = AuthServiceClient::new(self.channel.clone())
            .authenticate(ReceiverStream::new(rx))
            .await?
            .into_inner();
        match stream.message().await?.and_then(|m| m.step) {
            Some(Step::Success(s)) => Ok(s),
            other => panic!("unexpected step {other:?}"),
        }
    }

    /// Logs in as the bootstrap admin and returns the bearer token.
    pub async fn admin_token(&self) -> String {
        self.login(ADMIN, ADMIN_PASSWORD, Binding::Plus)
            .await
            .unwrap()
            .session_token
    }

    /// Calls `method` with an empty request message (valid for every request type; the empty
    /// `PingRequest`/`PingResponse` types encode nothing and ignore unknown fields) and returns
    /// the status (`Ok` on success).
    pub async fn raw_call(
        &self,
        method: &'static str,
        authorization: Option<&str>,
    ) -> Result<(), Status> {
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());
        grpc.ready()
            .await
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let mut request = Request::new(rustegon_proto::v1::PingRequest {});
        if let Some(a) = authorization {
            request
                .metadata_mut()
                .insert("authorization", MetadataValue::try_from(a).unwrap());
        }
        let codec = tonic_prost::ProstCodec::<
            rustegon_proto::v1::PingRequest,
            rustegon_proto::v1::PingResponse,
        >::default();
        grpc.unary(request, http::uri::PathAndQuery::from_static(method), codec)
            .await
            .map(|_| ())
    }
}

/// `request` with `authorization: <value>`.
pub fn authed<T>(message: T, authorization: &str) -> Request<T> {
    let mut r = Request::new(message);
    r.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(authorization).unwrap(),
    );
    r
}

/// `Bearer <token>`.
pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// The Rustegon error code of a status.
pub fn code_of(status: &Status) -> u32 {
    rustegon_proto::status::error_detail_of(status).map_or(0, |d| d.code)
}

/// Id of the backup [`seed_backup`] writes (fixed, so golden fixtures are stable).
pub const SEEDED_BACKUP_ID: &str = "20261109T101500Z-3fa85f64";

/// Writes a small plaintext backup ([`SEEDED_BACKUP_ID`], backup format v1) under
/// `<dir>/dest` with `rustegon-backup` and returns that destination directory and the manifest
/// (M13a, PD-064). Everything in it is fixed (id, time, consistency point, file contents).
pub fn seed_backup(dir: &std::path::Path) -> (PathBuf, rustegon_backup::Manifest) {
    seed_backup_as(dir, false)
}

/// [`seed_backup`], as the single file `<id>.bak` with `single_file` (ADR-037).
pub fn seed_backup_as(
    dir: &std::path::Path,
    single_file: bool,
) -> (PathBuf, rustegon_backup::Manifest) {
    use rustegon_backup::{
        BackupId, BackupMetadata, Consistency, Encryption, HlcTimestamp, LocalDestination,
        NewBackup, SourceInfo, write_backup,
    };
    use rustegon_sim_api::OpenMode;
    let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
    let stage = dir.join("stage");
    for (rel, data) in [
        ("lsm/000005.rsst", vec![7u8; 4096]),
        ("lsm/000009.rsst", b"small sst".to_vec()),
        ("lsm/MANIFEST-000002", b"version set".to_vec()),
        ("lsm/CURRENT", b"MANIFEST-000002\n".to_vec()),
    ] {
        let path = stage.join(rel);
        fs.create_dir_all(path.parent().unwrap()).unwrap();
        let mut f = fs.open(&path, OpenMode::Truncate).unwrap();
        f.append(&data).unwrap();
        f.sync_data().unwrap();
    }
    let root = dir.join("dest");
    let dest = LocalDestination::open(Arc::clone(&fs), &root).unwrap();
    let write = if single_file {
        rustegon_backup::write_bak
    } else {
        write_backup
    };
    let manifest = write(
        &dest,
        fs.as_ref(),
        &stage,
        &NewBackup {
            id: BackupId::parse(SEEDED_BACKUP_ID).unwrap(),
            created_at: SystemTime::UNIX_EPOCH + Duration::new(1_794_219_300, 0),
            metadata: BackupMetadata {
                consistency: Consistency {
                    timestamp: HlcTimestamp {
                        wall: 1_794_219_300_000_000_000,
                        logical: 1,
                    },
                    applied_index: 42,
                    applied_term: 1,
                    storage_seqno: 100,
                },
                source: SourceInfo {
                    cluster_id: "cluster-test".into(),
                    node_id: "7".into(),
                    server_version: "0.1.0".into(),
                },
                encryption: Encryption::Plaintext,
                pitr: None,
            },
        },
    )
    .unwrap();
    (root, manifest)
}
