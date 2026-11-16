// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Process-level tests of the `rustegond` server (M4 wave 2c, PD-054): the binary is started
//! on a temporary data directory with generated certificates, exercised over TLS gRPC and REST,
//! and stopped gracefully through `--stop-on-stdin-eof` (portable; SIGTERM is tested on Unix).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The server under test is a separate OS process on real time and real sockets: waiting for it
// (and holding a port it must fail to bind) cannot go through the sim-api.
#![allow(clippy::disallowed_methods)]

use std::{
    io::{BufRead as _, BufReader, Read as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use hyper_util::rt::TokioIo;
use rustegon_doc::{Document, Value, rdoc};
use rustegon_net::{
    CertAuthority, GeneratedCert, KeyAlgorithm, TlsContext, TlsMinVersion, TrustAnchors,
    rustls::{self, pki_types::ServerName},
    tokio_rustls::TlsConnector,
};
use rustegon_proto::{
    status::error_detail_of,
    v1::{
        self as pb, AuthMechanism, AuthenticateRequest, BeginRequest, CreateDatabaseRequest,
        ListDatabasesRequest, PingRequest, auth_service_client::AuthServiceClient,
        authenticate_response::Step, document_service_client::DocumentServiceClient,
        schema_service_client::SchemaServiceClient, session_service_client::SessionServiceClient,
        transaction_service_client::TransactionServiceClient,
    },
};
use rustegon_security::authn::{
    scram::{ClientBinding, ScramClient},
    secret,
};
use rustegon_sim_api::{Connection, Network, OsRng, StdFileSystem, SystemClock, TokioNetwork};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tonic::{
    Request,
    codegen::tokio_stream::wrappers::ReceiverStream,
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
};

/// Startup in a debug build includes PBKDF2 for the bootstrap admin.
const START_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_TIMEOUT: Duration = Duration::from_secs(60);
/// A password that passes the policy (test-only, not a real secret).
const PASSWORD: &str = "q7Vz!m2Lp#9Rx4Tk";

// ---------------------------------------------------------------------------------------------
// PKI and process harness
// ---------------------------------------------------------------------------------------------

struct Pki {
    ca: CertAuthority,
    anchors: TrustAnchors,
    certs_dir: PathBuf,
}

impl Pki {
    /// A CA and a node certificate for `127.0.0.1`/`localhost` in `<root>/certs`.
    fn new(root: &Path) -> Self {
        let clock = SystemClock::new();
        let (ca, ca_gen) =
            CertAuthority::generate("rustegond test CA", KeyAlgorithm::EcdsaP256, &clock, &OsRng)
                .unwrap();
        let anchors = TrustAnchors::from_pem(ca_gen.cert_pem.as_bytes(), "ca.crt").unwrap();
        let certs_dir = root.join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("ca.crt"), &ca_gen.cert_pem).unwrap();
        let pki = Self {
            ca,
            anchors,
            certs_dir,
        };
        pki.node_cert("node1")
            .write_files(
                &StdFileSystem,
                &pki.certs_dir.join("node.crt"),
                &pki.certs_dir.join("node.key"),
            )
            .unwrap();
        pki
    }

    fn node_cert(&self, name: &str) -> GeneratedCert {
        self.ca
            .issue_node(
                name,
                &["127.0.0.1".into(), "localhost".into()],
                &SystemClock::new(),
                &OsRng,
            )
            .unwrap()
    }

    /// Replaces the served node certificate and key the way an operator would: each file
    /// written next to the target and renamed over it.
    fn replace_node_cert(&self, cert: &GeneratedCert) {
        for (name, content) in [
            ("node.crt", cert.cert_pem.as_str()),
            ("node.key", cert.key_pem.expose().as_str()),
        ] {
            let tmp = self.certs_dir.join(format!("{name}.tmp"));
            std::fs::write(&tmp, content).unwrap();
            std::fs::rename(&tmp, self.certs_dir.join(name)).unwrap();
        }
    }

    fn client_config(&self, alpn: &[u8]) -> Arc<rustls::ClientConfig> {
        let tls = TlsContext::new(Arc::new(SystemClock::new()), TlsMinVersion::Tls13);
        let mut config = tls.client_config(&self.anchors, None).unwrap();
        config.alpn_protocols = vec![alpn.to_vec()];
        Arc::new(config)
    }
}

/// A test environment: data directory, certificates, and the flags of every start.
struct Env {
    root: tempfile::TempDir,
    pki: Pki,
}

impl Env {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let pki = Pki::new(root.path());
        Self { root, pki }
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn command(&self, extra: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustegond"));
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().into_owned();
            if k.starts_with("RUSTEGON_") {
                cmd.env_remove(k);
            }
        }
        cmd.arg("--stop-on-stdin-eof")
            .arg("--set")
            .arg(format!("node.data_dir={}", self.data_dir().display()))
            .arg("--set")
            .arg(format!(
                "security.certs_dir={}",
                self.pki.certs_dir.display()
            ))
            .args([
                // TLS is opt-in (ADR-034); these tests talk TLS to the node.
                "--set",
                "security.tls=true",
                "--set",
                "log.stderr=false",
                "--set",
                "listen.grpc=127.0.0.1:0",
                "--set",
                "listen.http=127.0.0.1:0",
                // The smallest iteration count the configuration accepts (debug builds).
                "--set",
                "auth.scram_iterations=100000",
                "--set",
                "listen.shutdown_grace_secs=5",
            ])
            .args(extra);
        cmd
    }

    fn start(&self, extra: &[&str]) -> Daemon {
        Daemon::spawn(self.command(extra))
    }

    /// Every JSON log line written so far.
    fn log_lines(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.data_dir().join("logs")) else {
            return out;
        };
        let mut files: Vec<_> = entries.map(|e| e.unwrap().path()).collect();
        files.sort();
        for f in files {
            for line in std::fs::read_to_string(f).unwrap().lines() {
                out.push(serde_json::from_str(line).unwrap());
            }
        }
        out
    }
}

/// A running `rustegond`.
struct Daemon {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<String>>,
    grpc: SocketAddr,
    http: SocketAddr,
}

impl Daemon {
    fn spawn(mut cmd: Command) -> Self {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout_pipe = child.stdout.take().unwrap();
        let mut stderr_pipe = child.stderr.take().unwrap();
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        let (ready_tx, ready_rx) = mpsc::channel();
        {
            let stdout = Arc::clone(&stdout);
            std::thread::spawn(move || {
                for line in BufReader::new(stdout_pipe).lines() {
                    let Ok(line) = line else { break };
                    if let Some(rest) = line.strip_prefix("rustegond ready ") {
                        let _ = ready_tx.send(rest.to_owned());
                    }
                    stdout.lock().unwrap().push(line);
                }
            });
        }
        let stderr_reader = {
            let stderr = Arc::clone(&stderr);
            std::thread::spawn(move || {
                let mut text = String::new();
                let _ = stderr_pipe.read_to_string(&mut text);
                stderr.lock().unwrap().push_str(&text);
            })
        };
        let Ok(ready) = ready_rx.recv_timeout(START_TIMEOUT) else {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stderr_reader.join();
            panic!(
                "rustegond did not become ready; stderr:\n{}",
                stderr.lock().unwrap()
            );
        };
        let addr = |key: &str| -> SocketAddr {
            ready
                .split(' ')
                .find_map(|kv| kv.strip_prefix(key))
                .unwrap()
                .parse()
                .unwrap()
        };
        Self {
            grpc: addr("grpc="),
            http: addr("http="),
            child,
            stdin,
            stdout,
            stderr,
        }
    }

    /// Closes stdin (graceful shutdown) and waits for the exit.
    fn stop(mut self) -> ExitStatus {
        drop(self.stdin.take());
        self.wait()
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "rustegond did not stop");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn stdout(&self) -> Vec<String> {
        self.stdout.lock().unwrap().clone()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Runs a failing start to its exit and returns the exit code and stderr.
fn run_to_exit(mut cmd: Command) -> (Option<i32>, String) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------------------------

async fn tls_channel(pki: &Pki, addr: SocketAddr) -> Channel {
    let config = pki.client_config(b"h2");
    Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let tls = TlsConnector::from(Arc::clone(&config));
            async move {
                let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await?;
                let stream = tls
                    .connect(ServerName::try_from("localhost").unwrap(), conn)
                    .await?;
                let io: Box<dyn Connection> = Box::new(stream);
                Ok::<_, std::io::Error>(TokioIo::new(io))
            }
        }))
        .await
        .unwrap()
}

async fn plain_channel(addr: SocketAddr) -> Result<Channel, tonic::transport::Error> {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await
}

/// The leaf certificate the server presents on a fresh TLS handshake.
async fn served_leaf(pki: &Pki, addr: SocketAddr) -> Vec<u8> {
    let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await.unwrap();
    let stream = TlsConnector::from(pki.client_config(b"h2"))
        .connect(ServerName::try_from("localhost").unwrap(), conn)
        .await
        .unwrap();
    stream.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

/// `GET path` over HTTP/1.1 on a TLS connection; returns the status line and the whole
/// response text.
async fn rest_get(pki: &Pki, addr: SocketAddr, path: &str) -> (String, String) {
    rest_call(pki, addr, "GET", path, None).await
}

/// `method path` (empty body) with an optional bearer token; as [`rest_get`].
async fn rest_call(
    pki: &Pki,
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> (String, String) {
    let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await.unwrap();
    let mut stream = TlsConnector::from(pki.client_config(b"http/1.1"))
        .connect(ServerName::try_from("localhost").unwrap(), conn)
        .await
        .unwrap();
    let auth = token.map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"));
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    // Flush: tokio-rustls may still buffer part of the request after `write_all` (PD-105).
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text.lines().next().unwrap_or_default().to_owned();
    (status, text)
}

/// SCRAM-SHA-256 login (no channel binding); returns the session token and whether the user
/// must change the password.
async fn login(channel: &Channel, user: &str, password: &str) -> (String, bool) {
    let (client, _, first) =
        ScramClient::new(user, &secret(password), ClientBinding::Unsupported, &OsRng);
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    tx.send(AuthenticateRequest {
        mechanism: AuthMechanism::ScramSha256 as i32,
        payload: first.into_bytes(),
        client_info: None,
    })
    .await
    .unwrap();
    let mut stream = AuthServiceClient::new(channel.clone())
        .authenticate(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let Some(Step::Challenge(server_first)) = stream.message().await.unwrap().and_then(|m| m.step)
    else {
        panic!("expected a SCRAM challenge");
    };
    let server_first = String::from_utf8(server_first).unwrap();
    let (fin, client_final) =
        tokio::task::spawn_blocking(move || client.server_first(&server_first).unwrap())
            .await
            .unwrap();
    tx.send(AuthenticateRequest {
        mechanism: 0,
        payload: client_final.into_bytes(),
        client_info: None,
    })
    .await
    .unwrap();
    let Some(Step::Success(success)) = stream.message().await.unwrap().and_then(|m| m.step) else {
        panic!("expected a SCRAM success");
    };
    fin.server_final(std::str::from_utf8(&success.server_final).unwrap())
        .unwrap();
    (success.session_token, success.must_change_password)
}

fn authed<T>(message: T, token: &str) -> Request<T> {
    let mut r = Request::new(message);
    r.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    r
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// FR-TLS-001 / AC-TLS-001 part: the default configuration serves gRPC and REST over TLS only;
/// a plain-text client is not served. Graceful stop exits 0.
#[test]
fn tc_tls_001_rustegond_serves_ping_over_tls_grpc_and_rest_only() {
    let env = Env::new();
    let daemon = env.start(&[]);
    runtime().block_on(async {
        let channel = tls_channel(&env.pki, daemon.grpc).await;
        let reply = SessionServiceClient::new(channel)
            .ping(PingRequest {})
            .await
            .unwrap();
        assert_eq!(
            reply
                .metadata()
                .get("rgn-node-id")
                .map(|v| v.to_str().unwrap()),
            Some("1")
        );

        let (status, response) = rest_get(&env.pki, daemon.http, "/api/v1/ping").await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert!(
            response.to_ascii_lowercase().contains("rgn-node-id: 1\r\n"),
            "{response}"
        );

        // Plain-text HTTP/2 against the TLS port: no gRPC is served.
        if let Ok(channel) = plain_channel(daemon.grpc).await {
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                SessionServiceClient::new(channel).ping(PingRequest {}),
            )
            .await;
            assert!(
                !matches!(result, Ok(Ok(_))),
                "plain text must not be served"
            );
        }
    });
    let status = daemon.stop();
    assert!(status.success(), "graceful stop exits 0: {status:?}");
    let lines = env.log_lines();
    assert!(
        lines
            .iter()
            .any(|l| l["msg"] == "rustegond ready" && l["tls"] == true)
    );
    assert!(lines.iter().any(|l| l["msg"] == "rustegond stopped"));
}

/// FR-GUI-001 / ADR-027 (PD-130): `rustegond` serves the embedded GUI under `/ui` of the REST
/// listener by default (503 "not built" when this build has no `gui/dist`), with the GUI
/// security headers; `gui.enabled = false` turns `/ui` back into an unknown path (404 RGN-1030).
#[test]
fn fr_gui_001_rustegond_serves_ui_unless_disabled() {
    let env = Env::new();
    let daemon = env.start(&[]);
    runtime().block_on(async {
        let (status, response) = rest_get(&env.pki, daemon.http, "/ui").await;
        assert!(status.starts_with("HTTP/1.1 303"), "{status}");
        assert!(
            response.to_ascii_lowercase().contains("location: /ui/\r\n"),
            "{response}"
        );
        let (status, response) = rest_get(&env.pki, daemon.http, "/ui/db/x").await;
        let lower = response.to_ascii_lowercase();
        assert!(
            (status.starts_with("HTTP/1.1 200") && lower.contains("content-type: text/html"))
                || (status.starts_with("HTTP/1.1 503")
                    && response.contains("not part of this build")),
            "{response}"
        );
        assert!(
            lower.contains("content-security-policy: default-src 'none'"),
            "{response}"
        );
        assert!(lower.contains("x-frame-options: deny\r\n"), "{response}");
    });
    assert!(daemon.stop().success());

    let daemon = env.start(&["--set", "gui.enabled=false"]);
    runtime().block_on(async {
        let (status, response) = rest_get(&env.pki, daemon.http, "/ui/").await;
        assert!(status.starts_with("HTTP/1.1 404"), "{status}");
        assert!(response.contains("\"code\":1030"), "{response}");
    });
    assert!(daemon.stop().success());
}

/// FR-TLS-001 / ADR-034: without `security.tls = true` a single node serves plain text: gRPC
/// over HTTP/2 prior knowledge, REST over HTTP/1.1, and the GUI login cookies come without
/// `Secure` (browsers would drop them on `http://`); TLS clients are refused. (The harness sets
/// `security.tls = true`; `--set` is applied in order, so the last value wins.)
#[test]
fn fr_tls_001_rustegond_plain_text_unless_tls_is_set() {
    let env = Env::new();
    let daemon = env.start(&["--set", "security.tls=false"]);
    let password = std::fs::read_to_string(env.data_dir().join("initial-admin-password")).unwrap();
    let password = password.strip_suffix('\n').unwrap().to_owned();
    runtime().block_on(async {
        let channel = plain_channel(daemon.grpc).await.unwrap();
        SessionServiceClient::new(channel)
            .ping(PingRequest {})
            .await
            .unwrap();
        let body = serde_json::json!({"user": "admin", "password": password}).to_string();
        let mut stream = tokio::net::TcpStream::connect(daemon.http).await.unwrap();
        let request = format!(
            "POST /api/v1/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: \
             application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 200"), "{text}");
        let cookies: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("set-cookie:"))
            .collect();
        assert_eq!(cookies.len(), 2, "{text}");
        for cookie in cookies {
            assert!(cookie.contains("httponly") || cookie.contains("rgn_csrf"));
            assert!(cookie.contains("samesite=strict"), "{cookie}");
            assert!(!cookie.contains("secure"), "{cookie}");
        }
        // A TLS client gets no handshake from a plain-text listener.
        let conn: Box<dyn Connection> = TokioNetwork.connect(daemon.http).await.unwrap();
        assert!(
            TlsConnector::from(env.pki.client_config(b"http/1.1"))
                .connect(ServerName::try_from("localhost").unwrap(), conn)
                .await
                .is_err()
        );
    });
    assert!(daemon.stop().success());
}

/// TC-SEC-003 / AC-SEC-003 + security.md §2.2: the first start bootstraps `admin` with a
/// generated password written to `<data_dir>/initial-admin-password` (owner-only); only the
/// path is printed, never the password (not in stdout, stderr or logs); the password works
/// (must be changed); a restart neither re-bootstraps nor touches the file.
#[test]
fn tc_sec_003_rustegond_generates_initial_password_file_once() {
    let env = Env::new();
    let file = env.data_dir().join("initial-admin-password");
    let daemon = env.start(&[]);
    let password = std::fs::read_to_string(&file).unwrap();
    let password = password.strip_suffix('\n').unwrap().to_owned();
    assert_eq!(password.len(), 24, "generated length (security.md §2.2)");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let stdout = daemon.stdout();
    assert!(
        stdout
            .iter()
            .any(|l| l.contains("initial password") && l.contains("initial-admin-password")),
        "{stdout:?}"
    );
    runtime().block_on(async {
        let channel = tls_channel(&env.pki, daemon.grpc).await;
        let (_, must_change) = login(&channel, "admin", &password).await;
        assert!(
            must_change,
            "a generated password must be changed at first login"
        );
    });
    let stdout = daemon.stdout();
    let stderr = daemon.stderr.lock().unwrap().clone();
    assert!(daemon.stop().success());
    let logs = std::fs::read_dir(env.data_dir().join("logs"))
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect::<String>();
    for (name, text) in [
        ("stdout", stdout.join("\n")),
        ("stderr", stderr),
        ("log", logs),
    ] {
        assert!(!text.contains(&password), "password leaked to {name}");
    }

    let before = std::fs::read(&file).unwrap();
    let daemon = env.start(&[]);
    assert!(
        !daemon
            .stdout()
            .iter()
            .any(|l| l.contains("initial password")),
        "no second bootstrap"
    );
    assert!(daemon.stop().success());
    assert_eq!(std::fs::read(&file).unwrap(), before, "never overwritten");
}

/// TC-SEC-003: a stale `initial-admin-password` next to an empty store refuses the start
/// instead of creating an administrator whose password cannot be handed out.
#[test]
fn tc_sec_003_rustegond_refuses_stale_initial_password_file() {
    let env = Env::new();
    std::fs::create_dir_all(env.data_dir()).unwrap();
    std::fs::write(env.data_dir().join("initial-admin-password"), "old\n").unwrap();
    let (code, stderr) = run_to_exit(env.command(&[]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("store has no user"), "{stderr}");
}

/// NFR-REL-002 + graceful shutdown: with an operator-provided admin password, data written
/// before a graceful stop is there after the restart, the store reopens, no second bootstrap
/// happens, and an open interactive transaction is rolled back at shutdown.
#[test]
fn nfr_rel_002_rustegond_restart_preserves_data_and_rolls_back_open_transactions() {
    let env = Env::new();
    let password_file = env.root.path().join("admin.pw");
    std::fs::write(&password_file, format!("{PASSWORD}\n")).unwrap();
    let pw_arg = password_file.display().to_string();
    let daemon = env.start(&["--admin-password-file", &pw_arg]);
    assert!(!env.data_dir().join("initial-admin-password").exists());
    runtime().block_on(async {
        let channel = tls_channel(&env.pki, daemon.grpc).await;
        let (token, must_change) = login(&channel, "admin", PASSWORD).await;
        assert!(!must_change);
        SchemaServiceClient::new(channel.clone())
            .create_database(authed(
                CreateDatabaseRequest {
                    name: "shop".into(),
                    ..CreateDatabaseRequest::default()
                },
                &token,
            ))
            .await
            .unwrap();
        TransactionServiceClient::new(channel)
            .begin(authed(BeginRequest::default(), &token))
            .await
            .unwrap();
    });
    assert!(daemon.stop().success());
    let released = env
        .log_lines()
        .into_iter()
        .find(|l| l["msg"] == "open transactions and cursors released")
        .expect("shutdown released the data plane");
    assert_eq!(released["transactions_rolled_back"], 1, "{released}");

    // Restart without the password file: the store keeps the admin and the database.
    let daemon = env.start(&[]);
    assert!(!env.data_dir().join("initial-admin-password").exists());
    runtime().block_on(async {
        let channel = tls_channel(&env.pki, daemon.grpc).await;
        let (token, _) = login(&channel, "admin", PASSWORD).await;
        let list = SchemaServiceClient::new(channel)
            .list_databases(authed(ListDatabasesRequest::default(), &token))
            .await
            .unwrap()
            .into_inner();
        assert!(
            list.databases.iter().any(|d| d.name == "shop"),
            "{:?}",
            list.databases
        );
    });
    assert!(daemon.stop().success());
}

/// Inserts `{_id: id}` into `shop.items` within transaction `txn`.
async fn insert_in(channel: &Channel, token: &str, txn: &str, id: i64) {
    let mut d = Document::new();
    d.insert("_id", Value::Int64(id));
    DocumentServiceClient::new(channel.clone())
        .insert(authed(
            pb::InsertRequest {
                database: "shop".into(),
                collection: "items".into(),
                documents: vec![pb::Document {
                    rdoc: rdoc::encode(&d).unwrap(),
                }],
                txn_id: Some(txn.to_owned()),
                ..pb::InsertRequest::default()
            },
            token,
        ))
        .await
        .unwrap();
}

async fn txn_status(
    txns: &mut TransactionServiceClient<Channel>,
    token: &str,
    id: &str,
) -> Result<pb::StatusResponse, tonic::Status> {
    txns.status(authed(
        pb::StatusRequest {
            txn_id: id.to_owned(),
        },
        token,
    ))
    .await
    .map(tonic::Response::into_inner)
}

/// FR-TXN-005/006, PD-121 option (a'), TC-DRV-NET-029 / TC-DRV-JAVA-030 server side: after
/// `rustegond` is killed (no graceful rollback) and restarted on the same data directory,
/// `Status` of a transaction that had uncommitted writes answers COMMITTING until
/// `txn.liveness_timeout` (5 s) has passed since its last write, then ABORTED
/// `coordinator_lost` (gRPC and REST); `Commit` of it fails with retryable RGN-2002
/// `coordinator_lost`, `Rollback` succeeds, and its writes are gone. A transaction committed
/// right before the kill is never reported ABORTED: RGN-1030 (its record went with the commit).
#[test]
#[allow(clippy::too_many_lines)] // One scenario across a crash: splitting it hides the sequence.
fn tc_txn_006_rustegond_status_after_kill_restart_reports_coordinator_lost() {
    const LIVENESS: Duration = Duration::from_secs(5);
    let env = Env::new();
    let password_file = env.root.path().join("admin.pw");
    std::fs::write(&password_file, format!("{PASSWORD}\n")).unwrap();
    let pw_arg = password_file.display().to_string();
    let mut daemon = env.start(&["--admin-password-file", &pw_arg]);
    let (committed, pending, written_at) = runtime().block_on(async {
        let channel = tls_channel(&env.pki, daemon.grpc).await;
        let (token, _) = login(&channel, "admin", PASSWORD).await;
        SchemaServiceClient::new(channel.clone())
            .create_database(authed(
                CreateDatabaseRequest {
                    name: "shop".into(),
                    ..CreateDatabaseRequest::default()
                },
                &token,
            ))
            .await
            .unwrap();
        let mut txns = TransactionServiceClient::new(channel.clone());
        let mut begin = async || {
            txns.begin(authed(BeginRequest::default(), &token))
                .await
                .unwrap()
                .into_inner()
                .txn_id
        };
        // The first insert creates the collection: commit it before the second transaction
        // writes, or that one would wait for it.
        let committed = begin().await;
        insert_in(&channel, &token, &committed, 1).await;
        TransactionServiceClient::new(channel.clone())
            .commit(authed(
                pb::CommitRequest {
                    txn_id: committed.clone(),
                },
                &token,
            ))
            .await
            .unwrap();
        let pending = begin().await;
        insert_in(&channel, &token, &pending, 2).await;
        (committed, pending, Instant::now())
    });
    // A crash: no graceful shutdown, so nothing rolls the open transaction back.
    daemon.child.kill().unwrap();
    daemon.wait();
    drop(daemon);

    let daemon = env.start(&[]);
    runtime().block_on(async {
        let channel = tls_channel(&env.pki, daemon.grpc).await;
        let (token, _) = login(&channel, "admin", PASSWORD).await;
        let mut txns = TransactionServiceClient::new(channel.clone());
        let assert_unknown = |r: Result<pb::StatusResponse, tonic::Status>| {
            let err = r.expect_err("a committed transaction must not have a state");
            assert_eq!(error_detail_of(&err).map(|d| d.code), Some(1030), "{err:?}");
        };
        // Poll the pending transaction until it is aborted; the committed one never is.
        let mut first_poll = None;
        let deadline = Instant::now() + LIVENESS + Duration::from_secs(30);
        loop {
            let polled_at = written_at.elapsed();
            let st = txn_status(&mut txns, &token, &pending).await.unwrap();
            assert_unknown(txn_status(&mut txns, &token, &committed).await);
            first_poll.get_or_insert((polled_at, st.state));
            if st.state == pb::TransactionState::Aborted as i32 {
                assert_eq!(st.abort_reason.as_deref(), Some("coordinator_lost"));
                // The record's heartbeat is its last write: never aborted before it expired.
                assert!(polled_at > LIVENESS, "aborted after only {polled_at:?}");
                break;
            }
            assert_eq!(st.state, pb::TransactionState::Committing as i32, "{st:?}");
            assert!(Instant::now() < deadline, "never aborted");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        // A first poll well within the liveness timeout must have seen COMMITTING (the restart
        // and login of a debug build take a few seconds; a slower host only skips this check).
        let (at, state) = first_poll.unwrap();
        eprintln!("first status after restart: {at:?} after the write, state {state}");
        if at + Duration::from_secs(1) < LIVENESS {
            assert_eq!(state, pb::TransactionState::Committing as i32);
        }
        // REST says the same.
        let path = |id: &str| format!("/api/v1/transactions/{id}");
        let (line, body) =
            rest_call(&env.pki, daemon.http, "GET", &path(&pending), Some(&token)).await;
        assert!(line.contains(" 200 "), "{line}\n{body}");
        assert!(
            body.contains("\"aborted\"") && body.contains("coordinator_lost"),
            "{body}"
        );
        let (line, body) = rest_call(
            &env.pki,
            daemon.http,
            "GET",
            &path(&committed),
            Some(&token),
        )
        .await;
        assert!(
            line.contains(" 404 ") && body.contains("1030"),
            "{line}\n{body}"
        );
        // Commit of the aborted one: retryable RGN-2002 coordinator_lost; Rollback succeeds.
        let err = txns
            .commit(authed(
                pb::CommitRequest {
                    txn_id: pending.clone(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        let detail = error_detail_of(&err).unwrap();
        assert_eq!(detail.code, 2002, "{err:?}");
        assert!(detail.retryable, "{detail:?}");
        let (line, body) = rest_call(
            &env.pki,
            daemon.http,
            "POST",
            &format!("{}/commit", path(&pending)),
            Some(&token),
        )
        .await;
        assert!(
            body.contains("2002") && body.contains("coordinator_lost"),
            "{line}\n{body}"
        );
        txns.rollback(authed(
            pb::RollbackRequest {
                txn_id: pending.clone(),
            },
            &token,
        ))
        .await
        .unwrap();
        // Commit of the committed one: unknown (RGN-1030), never an abort.
        let err = txns
            .commit(authed(pb::CommitRequest { txn_id: committed }, &token))
            .await
            .unwrap_err();
        assert_eq!(error_detail_of(&err).map(|d| d.code), Some(1030));
        // Data: the committed write is there, the aborted one is not.
        let mut docs = DocumentServiceClient::new(channel);
        for (id, present) in [(1, true), (2, false)] {
            let found = docs
                .get(authed(
                    pb::GetRequest {
                        database: "shop".into(),
                        collection: "items".into(),
                        id: Some(pb::Value {
                            rdoc_value: rdoc::encode_value(&Value::Int64(id)).unwrap(),
                        }),
                        ..pb::GetRequest::default()
                    },
                    &token,
                ))
                .await
                .unwrap()
                .into_inner()
                .document
                .is_some();
            assert_eq!(found, present, "document {id}");
        }
    });
    assert!(daemon.stop().success());
}

/// TC-TLS-005 / AC-TLS-003: replacing the certificate files is picked up without a restart
/// (here within seconds: `tls.watch_secs = 1`; the default 10 s meets the 1 min criterion).
#[test]
fn tc_tls_005_rustegond_reloads_replaced_certificate_without_restart() {
    let env = Env::new();
    let daemon = env.start(&["--set", "tls.watch_secs=1"]);
    runtime().block_on(async {
        let before = served_leaf(&env.pki, daemon.grpc).await;
        let replacement = env.pki.node_cert("node1-renewed");
        env.pki.replace_node_cert(&replacement);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let now_served = served_leaf(&env.pki, daemon.grpc).await;
            if now_served != before {
                // REST shares the reloadable certificate.
                assert_eq!(served_leaf(&env.pki, daemon.http).await, now_served);
                break;
            }
            assert!(Instant::now() < deadline, "certificate not reloaded");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        // Still serving after the reload.
        let channel = tls_channel(&env.pki, daemon.grpc).await;
        SessionServiceClient::new(channel)
            .ping(PingRequest {})
            .await
            .unwrap();
    });
    assert!(daemon.stop().success());
    assert!(
        env.log_lines()
            .iter()
            .any(|l| l["msg"] == "TLS certificate reloaded")
    );
}

/// TC-TLS-005 on Unix: SIGHUP reloads at once (no change check, hour-long poll).
#[cfg(unix)]
#[test]
fn tc_tls_005_rustegond_sighup_reloads_certificate() {
    let env = Env::new();
    let daemon = env.start(&["--set", "tls.watch_secs=0"]);
    runtime().block_on(async {
        let before = served_leaf(&env.pki, daemon.grpc).await;
        env.pki.replace_node_cert(&env.pki.node_cert("node1-hup"));
        let status = Command::new("kill")
            .args(["-HUP", &daemon.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let deadline = Instant::now() + Duration::from_secs(30);
        while served_leaf(&env.pki, daemon.grpc).await == before {
            assert!(Instant::now() < deadline, "SIGHUP did not reload");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    assert!(daemon.stop().success());
}

/// Graceful shutdown on SIGTERM (Unix): exit 0 and a reopenable store.
#[cfg(unix)]
#[test]
fn nfr_rel_002_rustegond_sigterm_shuts_down_gracefully() {
    let env = Env::new();
    let mut daemon = env.start(&[]);
    let status = Command::new("kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(daemon.wait().success());
    assert!(
        env.log_lines()
            .iter()
            .any(|l| l["msg"] == "shutdown requested; draining listeners"
                && l["reason"] == "SIGTERM")
    );
    let daemon = env.start(&[]);
    assert!(daemon.stop().success());
}

/// TC-OPS-001 + FR-TLS-001: startup fails with a reason, before creating a store, when the
/// TLS files are missing or the configuration asks for something the binary cannot honour.
#[test]
fn tc_ops_001_rustegond_startup_errors_name_the_reason() {
    let env = Env::new();
    std::fs::remove_file(env.pki.certs_dir.join("node.key")).unwrap();
    let (code, stderr) = run_to_exit(env.command(&[]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("node.key"), "{stderr}");
    assert!(
        !env.data_dir().join("store").exists(),
        "no store is created by a failed start"
    );

    let env = Env::new();
    let (code, stderr) = run_to_exit(env.command(&["--set", "listen.grpc=localhost:7700"]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("[listen]") && stderr.contains("not an ip:port"),
        "{stderr}"
    );

    // Encryption at rest with an unavailable key: RGN-4006 (tests/ear.rs, TC-EAR-003, PD-057).
    let env = Env::new();
    let key = env.root.path().join("kek.key");
    let (code, stderr) = run_to_exit(env.command(&[
        "--set",
        "storage.encryption=aes-256-gcm",
        "--set",
        &format!("storage.encryption_key_file={}", key.display()),
    ]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("RGN-4006") && stderr.contains("kek.key"),
        "{stderr}"
    );

    let env = Env::new();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap();
    let (code, stderr) = run_to_exit(env.command(&["--set", &format!("listen.grpc={port}")]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("cannot bind"), "{stderr}");
}

/// PD-054: the continuation-token key is created once in the data directory and reused.
#[test]
fn pd_054_rustegond_keeps_cursor_token_key_across_restarts() {
    let env = Env::new();
    let key_file = env.data_dir().join("cursor-token.key");
    assert!(env.start(&[]).stop().success());
    let first = std::fs::read(&key_file).unwrap();
    assert_eq!(first.len(), 65);
    assert!(env.start(&[]).stop().success());
    assert_eq!(std::fs::read(&key_file).unwrap(), first);
}
