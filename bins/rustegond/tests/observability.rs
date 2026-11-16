// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Process-level observability and secret-redaction tests of `rustegond` (M4 wave 3 lane O;
//! PD-059): readiness during a graceful shutdown (TC-OPS-005), `/metrics` of the real binary
//! with the certificate expiry (TC-OPS-004), and the secret canary scan over every output of
//! the process (TC-SEC-009).
//!
//! The harness is a trimmed copy of the one in `tests/server.rs` (kept separate so parallel
//! work on that file does not conflict): the binary on a temporary data directory with
//! generated certificates, stopped through `--stop-on-stdin-eof`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The server under test is a separate OS process on real time and real sockets: waiting for it
// cannot go through the sim-api.
#![allow(clippy::disallowed_methods)]

use std::{
    fmt::Write as _,
    io::{BufRead as _, BufReader, Read as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use hyper_util::rt::TokioIo;
use rustegon_net::{
    CertAuthority, KeyAlgorithm, TlsContext, TlsMinVersion, TrustAnchors,
    rustls::{self, pki_types::ServerName},
    tokio_rustls::TlsConnector,
};
use rustegon_proto::v1::{
    AuthMechanism, AuthenticateRequest, auth_service_client::AuthServiceClient,
    authenticate_response::Step,
};
use rustegon_security::authn::{
    scram::{ClientBinding, ScramClient},
    secret,
};
use rustegon_sim_api::{Connection, Network, OsRng, StdFileSystem, SystemClock, TokioNetwork};
use serde_json::{Value as Json, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tonic::{
    codegen::tokio_stream::wrappers::ReceiverStream,
    transport::{Channel, Endpoint},
};

const START_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------------------------
// PKI and process harness
// ---------------------------------------------------------------------------------------------

struct Pki {
    anchors: TrustAnchors,
    certs_dir: PathBuf,
}

impl Pki {
    fn new(root: &Path) -> Self {
        let clock = SystemClock::new();
        let (ca, ca_gen) =
            CertAuthority::generate("rustegond test CA", KeyAlgorithm::EcdsaP256, &clock, &OsRng)
                .unwrap();
        let anchors = TrustAnchors::from_pem(ca_gen.cert_pem.as_bytes(), "ca.crt").unwrap();
        let certs_dir = root.join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("ca.crt"), &ca_gen.cert_pem).unwrap();
        ca.issue_node(
            "node1",
            &["127.0.0.1".into(), "localhost".into()],
            &clock,
            &OsRng,
        )
        .unwrap()
        .write_files(
            &StdFileSystem,
            &certs_dir.join("node.crt"),
            &certs_dir.join("node.key"),
        )
        .unwrap();
        Self { anchors, certs_dir }
    }

    fn client_config(&self, alpn: &[u8]) -> Arc<rustls::ClientConfig> {
        let tls = TlsContext::new(Arc::new(SystemClock::new()), TlsMinVersion::Tls13);
        let mut config = tls.client_config(&self.anchors, None).unwrap();
        config.alpn_protocols = vec![alpn.to_vec()];
        Arc::new(config)
    }
}

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

    fn start(&self, extra: &[&str]) -> Daemon {
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
                "listen.grpc=127.0.0.1:0",
                "--set",
                "listen.http=127.0.0.1:0",
                "--set",
                "auth.scram_iterations=100000",
                "--set",
                "listen.shutdown_grace_secs=5",
            ])
            .args(extra);
        Daemon::spawn(cmd)
    }

    /// The text of every file under `<data_dir>/<sub>` (recursively).
    fn files_text(&self, sub: &str) -> Vec<(PathBuf, String)> {
        fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries {
                let path = e.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    let bytes = std::fs::read(&path).unwrap();
                    out.push((path, String::from_utf8_lossy(&bytes).into_owned()));
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.data_dir().join(sub), &mut out);
        out
    }
}

struct Daemon {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<String>>,
    stderr_reader: Option<std::thread::JoinHandle<()>>,
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
                let mut buf = Vec::new();
                let _ = stderr_pipe.read_to_end(&mut buf);
                stderr
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf));
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
            stderr_reader: Some(stderr_reader),
        }
    }

    /// Closes stdin (graceful shutdown) without waiting.
    fn request_stop(&mut self) {
        drop(self.stdin.take());
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                if let Some(reader) = self.stderr_reader.take() {
                    let _ = reader.join();
                }
                return status;
            }
            assert!(Instant::now() < deadline, "rustegond did not stop");
            std::thread::sleep(Duration::from_millis(50));
        }
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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------------------------

/// One HTTP/1.1 exchange on a fresh TLS connection.
struct Http {
    status: u16,
    head: String,
    body: String,
}

impl Http {
    fn json(&self) -> Json {
        serde_json::from_str(&self.body).unwrap_or(Json::Null)
    }

    fn code(&self) -> u64 {
        self.json()["error"]["code"].as_u64().unwrap_or(0)
    }

    /// Value of the `Set-Cookie` header setting `name`.
    fn cookie(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if !k.eq_ignore_ascii_case("set-cookie") {
                return None;
            }
            let pair = v.trim().split(';').next()?;
            let (n, value) = pair.split_once('=')?;
            (n == name).then(|| value.to_owned())
        })
    }
}

/// Decodes a `Transfer-Encoding: chunked` body.
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(eol) = raw.windows(2).position(|w| w == b"\r\n") else {
            return out;
        };
        let size_text = std::str::from_utf8(&raw[..eol]).unwrap();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16).unwrap();
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&raw[eol + 2..eol + 2 + size]);
        raw = &raw[eol + 2 + size + 2..];
    }
}

async fn http(
    pki: &Pki,
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Json>,
) -> Http {
    let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await.unwrap();
    let mut stream = TlsConnector::from(pki.client_config(b"http/1.1"))
        .connect(ServerName::try_from("localhost").unwrap(), conn)
        .await
        .unwrap();
    let body = body.map(Json::to_string).unwrap_or_default();
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (k, v) in headers {
        let _ = write!(request, "{k}: {v}\r\n");
    }
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    let _ = write!(request, "Content-Length: {}\r\n\r\n{body}", body.len());
    stream.write_all(request.as_bytes()).await.unwrap();
    // Flush: tokio-rustls may still buffer part of the request after `write_all` (PD-105).
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    // A TLS close without close_notify is fine here: the response is complete by then.
    let _ = stream.read_to_end(&mut response).await;
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no response head");
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    let raw_body = &response[split + 4..];
    let chunked = head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    let body = if chunked {
        dechunk(raw_body)
    } else {
        raw_body.to_vec()
    };
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Http {
        status,
        head,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

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

/// SCRAM-SHA-256 over gRPC; the session token, or `None` when the server refused the proof.
async fn scram_login(channel: &Channel, user: &str, password: &str) -> Option<String> {
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
        .ok()?
        .into_inner();
    let Some(Step::Challenge(server_first)) = stream.message().await.ok()?.and_then(|m| m.step)
    else {
        return None;
    };
    let server_first = String::from_utf8(server_first).unwrap();
    let (_fin, client_final) =
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
    match stream.message().await.ok()?.and_then(|m| m.step) {
        Some(Step::Success(s)) => Some(s.session_token),
        _ => None,
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// TC-OPS-005 / AC-OPS-003 (process part): `/api/v1/health/ready` is 200 once `rustegond`
/// reports ready; after a shutdown request it answers 503 `draining` for
/// `listen.drain_delay_secs` while liveness stays 200, then the node stops gracefully.
#[test]
fn tc_ops_005_rustegond_readiness_turns_503_while_draining() {
    let env = Env::new();
    let mut daemon = env.start(&["--set", "listen.drain_delay_secs=10"]);
    let rt = runtime();
    rt.block_on(async {
        let ready = http(
            &env.pki,
            daemon.http,
            "GET",
            "/api/v1/health/ready",
            &[],
            None,
        )
        .await;
        assert_eq!(ready.status, 200, "{}", ready.body);
        assert_eq!(ready.json()["status"], "ready");
    });
    let requested = Instant::now();
    daemon.request_stop();
    rt.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let ready = http(
                &env.pki,
                daemon.http,
                "GET",
                "/api/v1/health/ready",
                &[],
                None,
            )
            .await;
            if ready.status == 503 {
                assert_eq!(ready.json()["status"], "draining");
                let live = http(
                    &env.pki,
                    daemon.http,
                    "GET",
                    "/api/v1/health/live",
                    &[],
                    None,
                )
                .await;
                assert_eq!(live.status, 200, "still live while draining");
                break;
            }
            assert!(Instant::now() < deadline, "readiness never turned 503");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    assert!(daemon.wait().success());
    assert!(
        requested.elapsed() >= Duration::from_secs(9),
        "the drain delay was honoured"
    );
}

/// TC-OPS-004 (process part): the binary exports the certificate expiry of its node
/// certificate and marks itself ready in `/metrics` (admin session; full family list in
/// `rustegon-server/tests/observability.rs`).
#[test]
fn tc_ops_004_rustegond_metrics_include_certificate_expiry() {
    let env = Env::new();
    let password = "Mv8#tQ2!xL5pW9zR";
    let pw_file = env.root.path().join("admin.pw");
    std::fs::write(&pw_file, password).unwrap();
    let pw_arg = pw_file.display().to_string();
    let mut daemon = env.start(&["--admin-password-file", &pw_arg]);
    runtime().block_on(async {
        let channel = tls_channel(&env.pki, daemon.grpc).await;
        let token = scram_login(&channel, "admin", password).await.unwrap();
        let metrics = http(
            &env.pki,
            daemon.http,
            "GET",
            "/metrics",
            &[("Authorization", &bearer(&token))],
            None,
        )
        .await;
        assert_eq!(metrics.status, 200, "{}", metrics.body);
        assert!(metrics.body.ends_with("# EOF\n"));
        assert!(
            metrics.body.contains("rustegon_ready 1\n"),
            "{}",
            metrics.body
        );
        let expiry: i64 = metrics
            .body
            .lines()
            .find_map(|l| l.strip_prefix("rustegon_cert_expiry_seconds{cert=\"node\"} "))
            .expect("cert expiry exported")
            .parse()
            .unwrap();
        assert!(expiry > 86_400, "a fresh node certificate: {expiry}");
        // Anonymous scrapes are refused.
        let anonymous = http(&env.pki, daemon.http, "GET", "/metrics", &[], None).await;
        assert_eq!(anonymous.code(), 4001);
    });
    daemon.request_stop();
    assert!(daemon.wait().success());
}

/// TC-SEC-009 / AC-OPS-002 (secret redaction): with every log channel at `trace`, logins and
/// administrative operations carrying secrets — SCRAM over gRPC, password login over REST
/// (cookie and token delivery), wrong passwords, users created with passwords, own and
/// administrative password changes, API key creation and use, forged API keys and session
/// tokens, a cookie-authenticated request with its CSRF token — leave none of their secrets in
/// any log file, audit file, stdout, stderr or `/metrics` exposition.
#[test]
// One end-to-end scenario: splitting it would hide which step produced a leak.
#[allow(clippy::too_many_lines)]
fn tc_sec_009_secret_canaries_never_reach_logs_audit_stdout_stderr_or_metrics() {
    let env = Env::new();
    let admin_pw = "Cq7!vR2#mZ9xLp4W";
    let pw_file = env.root.path().join("admin.pw");
    std::fs::write(&pw_file, format!("{admin_pw}\n")).unwrap();
    let pw_arg = pw_file.display().to_string();
    let mut daemon = env.start(&[
        "--admin-password-file",
        &pw_arg,
        "--set",
        "log.level=trace",
        "--set",
        "log.stderr=true",
        // Every login and forged credential below must reach authentication, not the limiter.
        "--set",
        "rate_limit.enabled=false",
    ]);
    let mut canaries: Vec<(&'static str, String)> = vec![("admin password", admin_pw.into())];
    let mut expositions = Vec::new();
    let mut key_id = String::new();
    runtime().block_on(async {
        let pki = &env.pki;
        let rest = daemon.http;
        let channel = tls_channel(pki, daemon.grpc).await;

        // SCRAM over gRPC: success and a wrong password.
        let t_scram = scram_login(&channel, "admin", admin_pw).await.unwrap();
        canaries.push(("SCRAM session token", t_scram.clone()));
        let wrong_scram = "Wx3!kP8#rT6vNq2Z";
        assert!(scram_login(&channel, "admin", wrong_scram).await.is_none());
        canaries.push(("wrong SCRAM password", wrong_scram.into()));

        // Password login over REST: cookie delivery (session cookie + CSRF token) and a wrong
        // password.
        let cookie_login = http(
            pki,
            rest,
            "POST",
            "/api/v1/auth/login",
            &[],
            Some(&json!({"user": "admin", "password": admin_pw})),
        )
        .await;
        assert_eq!(cookie_login.status, 200, "{}", cookie_login.body);
        let session_cookie = cookie_login.cookie("rgn_session").unwrap();
        let csrf = cookie_login.json()["csrfToken"].as_str().unwrap().to_owned();
        canaries.push(("session cookie", session_cookie.clone()));
        canaries.push(("CSRF token", csrf.clone()));
        let wrong_rest = "Hb5#nY7!cJ3wQx8M";
        let refused = http(
            pki,
            rest,
            "POST",
            "/api/v1/auth/login",
            &[],
            Some(&json!({"user": "admin", "password": wrong_rest, "delivery": "token"})),
        )
        .await;
        assert_eq!(refused.code(), 4001);
        canaries.push(("wrong REST password", wrong_rest.into()));

        // Users created with passwords: one through the cookie session (with CSRF), one with
        // the bearer token.
        let alice_pw = "Ad4!sG9#fK2qVb7Z";
        let cookie_header = format!("rgn_session={session_cookie}");
        let created = http(
            pki,
            rest,
            "POST",
            "/api/v1/users",
            &[("Cookie", &cookie_header), ("X-RGN-CSRF", &csrf)],
            Some(&json!({"name": "alice", "password": alice_pw, "roles": []})),
        )
        .await;
        assert_eq!(created.status, 200, "{}", created.body);
        canaries.push(("alice password", alice_pw.into()));
        let scraper_pw = "Sp6#eM3!uH8rTz4C";
        let created = http(
            pki,
            rest,
            "POST",
            "/api/v1/users",
            &[("Authorization", &bearer(&t_scram))],
            Some(&json!({
                "name": "scraper",
                "password": scraper_pw,
                "roles": [{"role": "monitor"}],
            })),
        )
        .await;
        assert_eq!(created.status, 200, "{}", created.body);
        canaries.push(("scraper password", scraper_pw.into()));

        // Own password change over REST (token delivery login first).
        let alice_login = http(
            pki,
            rest,
            "POST",
            "/api/v1/auth/login",
            &[],
            Some(&json!({"user": "alice", "password": alice_pw, "delivery": "token"})),
        )
        .await;
        let t_alice = alice_login.json()["sessionToken"]
            .as_str()
            .unwrap()
            .to_owned();
        canaries.push(("alice session token", t_alice.clone()));
        let alice_pw2 = "Nf2#wB8!pL5kXc9D";
        let changed = http(
            pki,
            rest,
            "POST",
            "/api/v1/auth/password",
            &[("Authorization", &bearer(&t_alice))],
            Some(&json!({"currentPassword": alice_pw, "newPassword": alice_pw2})),
        )
        .await;
        assert_eq!(changed.status, 200, "{}", changed.body);
        canaries.push(("alice new password", alice_pw2.into()));
        let t_alice2 = scram_login(&channel, "alice", alice_pw2).await.unwrap();
        canaries.push(("alice SCRAM token", t_alice2));

        // Administrative password reset.
        let alice_pw3 = "Rg9!dQ4#hV7mYs2E";
        let admin_reset = http(
            pki,
            rest,
            "PATCH",
            "/api/v1/users/alice",
            &[("Authorization", &bearer(&t_scram))],
            Some(&json!({"password": alice_pw3})),
        )
        .await;
        assert_eq!(admin_reset.status, 200, "{}", admin_reset.body);
        canaries.push(("alice reset password", alice_pw3.into()));

        // API key: created for the monitor user, used to scrape, then forged.
        let key = http(
            pki,
            rest,
            "POST",
            "/api/v1/api-keys",
            &[("Authorization", &bearer(&t_scram))],
            Some(&json!({"user": "scraper", "description": "prometheus", "roles": [{"role": "monitor"}]})),
        )
        .await;
        assert_eq!(key.status, 200, "{}", key.body);
        let full_key = key.json()["secret"].as_str().unwrap().to_owned();
        let (key_prefix, key_secret) = full_key.rsplit_once('_').unwrap();
        key_id = key_prefix.trim_start_matches("rgn_").to_owned();
        canaries.push(("API key", full_key.clone()));
        canaries.push(("API key secret part", key_secret.to_owned()));
        let scraped = http(
            pki,
            rest,
            "GET",
            "/metrics",
            &[("Authorization", &format!("ApiKey {full_key}"))],
            None,
        )
        .await;
        assert_eq!(scraped.status, 200, "{}", scraped.body);
        expositions.push(scraped.body);
        let forged_secret: String = key_secret
            .chars()
            .rev()
            .map(|c| if c == 'A' { 'B' } else { c })
            .collect();
        let forged_key = format!("{key_prefix}_{forged_secret}");
        let forged = http(
            pki,
            rest,
            "GET",
            "/metrics",
            &[("Authorization", &format!("ApiKey {forged_key}"))],
            None,
        )
        .await;
        assert_eq!(forged.code(), 4001);
        canaries.push(("forged API key", forged_key));
        let bogus_key = "rgn_ZZZZZZZZZZZZ_Q9x2Lm7Vb4Nc8Kd3Hf6Gs1Jt5Pw0Ry";
        let bogus = http(
            pki,
            rest,
            "GET",
            "/api/v1/auth/me",
            &[("Authorization", &format!("ApiKey {bogus_key}"))],
            None,
        )
        .await;
        assert_eq!(bogus.code(), 4001);
        canaries.push(("unknown API key", bogus_key.into()));
        let forged_token = "Zq0Xw9Vu8Ts7Rq6Po5Nm4Lk3Ji2Hg1Fe0Dc9Ba8Zy7";
        let forged = http(
            pki,
            rest,
            "GET",
            "/api/v1/auth/me",
            &[("Authorization", &bearer(forged_token))],
            None,
        )
        .await;
        // An unknown session token reads as expired (RGN-4005) or rejected (RGN-4001).
        assert!(matches!(forged.code(), 4001 | 4005), "{}", forged.body);
        canaries.push(("forged session token", forged_token.into()));

        // The admin changes its own password last (it revokes its sessions).
        let admin_pw2 = "Te3#zK8!qN6vBx2U";
        let changed = http(
            pki,
            rest,
            "POST",
            "/api/v1/auth/password",
            &[("Cookie", &cookie_header), ("X-RGN-CSRF", &csrf)],
            Some(&json!({"currentPassword": admin_pw, "newPassword": admin_pw2})),
        )
        .await;
        assert_eq!(changed.status, 200, "{}", changed.body);
        canaries.push(("admin new password", admin_pw2.into()));

        // A last scrape after every operation.
        let scraped = http(
            pki,
            rest,
            "GET",
            "/metrics",
            &[("Authorization", &format!("ApiKey {full_key}"))],
            None,
        )
        .await;
        assert_eq!(scraped.status, 200, "{}", scraped.body);
        assert!(scraped.body.contains("rustegon_auth_failures_total"));
        expositions.push(scraped.body);
    });
    daemon.request_stop();
    assert!(daemon.wait().success());

    let mut sources: Vec<(String, String)> = Vec::new();
    for (path, text) in env.files_text("logs") {
        sources.push((format!("log {}", path.display()), text));
    }
    let audit = env.files_text("audit");
    for (path, text) in &audit {
        sources.push((format!("audit {}", path.display()), text.clone()));
    }
    sources.push(("stdout".into(), daemon.stdout.lock().unwrap().join("\n")));
    sources.push(("stderr".into(), daemon.stderr.lock().unwrap().clone()));
    for (i, text) in expositions.into_iter().enumerate() {
        sources.push((format!("/metrics scrape {i}"), text));
    }

    // The scan covers real output: trace logging ran and the failures were audited.
    let log_bytes: usize = sources
        .iter()
        .filter(|(n, _)| n.starts_with("log "))
        .map(|(_, t)| t.len())
        .sum();
    assert!(
        log_bytes > 10_000,
        "trace logs were written ({log_bytes} B)"
    );
    let audit_text: String = audit.iter().map(|(_, t)| t.as_str()).collect();
    assert!(audit_text.contains("\"login_failure\""));
    assert!(audit_text.contains("\"api_key_change\""));
    assert!(audit_text.contains("\"user_change\""));
    // The key's public id is audited (its use and creation), its secret is not.
    assert!(
        key_id.len() >= 8 && audit_text.contains(&key_id),
        "{key_id}"
    );
    assert!(
        !daemon.stderr.lock().unwrap().is_empty(),
        "stderr logging on"
    );

    let mut leaks = Vec::new();
    for (what, canary) in &canaries {
        assert!(canary.len() >= 16, "{what}: canary too short to be unique");
        for (source, text) in &sources {
            if text.contains(canary.as_str()) {
                leaks.push(format!("{what} found in {source}"));
            }
        }
    }
    assert!(leaks.is_empty(), "secret leaks:\n{}", leaks.join("\n"));
}
