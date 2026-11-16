// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Encryption at rest end to end through the `rustegond` process (M4 wave 3 lane M, PD-057;
//! FR-EAR-001/002, AC-EAR-001/002).
//!
//! - TC-EAR-001: 10⁴ distinct plaintext canaries written through the REST API into a store with
//!   `storage.encryption = aes-256-gcm`; the process is killed (the data is then only in the
//!   encrypted Raft log), every file under the data directory is byte-scanned; the node restarts
//!   (log replay decrypts), an index on the canary field is built and queried, the node stops
//!   gracefully (shutdown checkpoint: memtables to encrypted SSTs), and every file is scanned
//!   again. No canary may appear in any file: store, logs, audit log, key files.
//! - TC-EAR-002: the `file` and `env` KEK providers each wrap and unwrap through a full
//!   start/write/restart/read cycle, and the same key moves between them.
//! - TC-EAR-003: a missing, malformed or wrong key (file or environment variable), an
//!   encrypted store started without encryption, and (Unix) a group-readable key file refuse
//!   the start with `RGN-4006` and a reason that names the file or variable but never the key.
//! - TC-EAR-004: a plaintext store restarted with encryption switches to it: old data stays
//!   readable (still plaintext until compaction rewrites it; the node warns and the scan finds
//!   exactly those canaries, which also shows the scan sees the real layout), new data is not
//!   on disk in plaintext.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The server under test is a separate OS process on real time and real sockets.
#![allow(clippy::disallowed_methods)]

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    io::{BufRead as _, BufReader, Read as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use rustegon_net::{
    CertAuthority, KeyAlgorithm, TlsContext, TlsMinVersion, TrustAnchors,
    rustls::{self, pki_types::ServerName},
    tokio_rustls::TlsConnector,
};
use rustegon_sim_api::{
    Connection, FileSystem as _, Network, OsRng, StdFileSystem, SystemClock, TokioNetwork,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Startup in a debug build includes PBKDF2 for the bootstrap admin.
const START_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_TIMEOUT: Duration = Duration::from_secs(120);
/// A password that passes the policy (test-only, not a real secret).
const PASSWORD: &str = "q7Vz!m2Lp#9Rx4Tk";
/// AC-EAR-001: 10⁴ canaries.
const CANARIES: usize = 10_000;
/// Documents per REST insert call.
const PER_CALL: usize = 500;
/// The test KEK (32 bytes of 0x07) as the file provider reads it (64 hex digits) and as the env
/// provider reads it (base64). Test-only values.
const KEK_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";
const KEK_B64: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
/// Another key (32 bytes of 0x08), for the wrong-key cases.
const OTHER_KEK_HEX: &str = "0808080808080808080808080808080808080808080808080808080808080808";
const OTHER_KEK_B64: &str = "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=";
const CANARY_PREFIX: &str = "EAR-PROCESS-CANARY-";

fn canary(i: usize) -> String {
    format!("{CANARY_PREFIX}{i:05}-x")
}

// ---------------------------------------------------------------------------------------------
// Harness (a trimmed copy of `tests/server.rs`: TLS PKI, process control)
// ---------------------------------------------------------------------------------------------

struct Env {
    root: tempfile::TempDir,
    certs_dir: PathBuf,
    client: Arc<rustls::ClientConfig>,
    password_file: PathBuf,
}

impl Env {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let clock = SystemClock::new();
        let (ca, ca_gen) = CertAuthority::generate(
            "rustegond EAR test CA",
            KeyAlgorithm::EcdsaP256,
            &clock,
            &OsRng,
        )
        .unwrap();
        let anchors = TrustAnchors::from_pem(ca_gen.cert_pem.as_bytes(), "ca.crt").unwrap();
        let certs_dir = root.path().join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
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
        let tls = TlsContext::new(Arc::new(SystemClock::new()), TlsMinVersion::Tls13);
        let mut client = tls.client_config(&anchors, None).unwrap();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let password_file = root.path().join("admin.pw");
        std::fs::write(&password_file, format!("{PASSWORD}\n")).unwrap();
        Self {
            root,
            certs_dir,
            client: Arc::new(client),
            password_file,
        }
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    /// Writes an owner-only key file (Unix refuses anything else) outside the data directory.
    fn key_file(&self, name: &str, hex: &str) -> PathBuf {
        let path = self.root.path().join(name);
        let _ = std::fs::remove_file(&path);
        StdFileSystem
            .create_new_private(&path)
            .and_then(|mut f| f.append(format!("{hex}\n").as_bytes()))
            .unwrap();
        path
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
            .arg("--admin-password-file")
            .arg(&self.password_file)
            .arg("--set")
            .arg(format!("node.data_dir={}", self.data_dir().display()))
            .arg("--set")
            .arg(format!("security.certs_dir={}", self.certs_dir.display()))
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
                "--set",
                "auth.scram_iterations=100000",
                "--set",
                "listen.shutdown_grace_secs=5",
                // The smallest memtable: rotations happen during the test.
                "--set",
                "storage.memtable_size=1048576",
            ])
            .args(extra);
        cmd
    }

    fn file_args(key: &Path) -> Vec<String> {
        vec![
            "--set".into(),
            "storage.encryption=aes-256-gcm".into(),
            "--set".into(),
            format!("storage.encryption_key_file={}", key.display()),
        ]
    }

    fn env_args() -> Vec<String> {
        vec![
            "--set".into(),
            "storage.encryption=aes-256-gcm".into(),
            "--set".into(),
            "storage.encryption_key_provider=env".into(),
        ]
    }

    /// Every JSON log line written so far.
    fn log_lines(&self) -> Vec<Value> {
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

fn strings(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

struct Daemon {
    child: Child,
    stdin: Option<ChildStdin>,
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
        let stderr = Arc::new(Mutex::new(String::new()));
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout_pipe).lines() {
                let Ok(line) = line else { break };
                if let Some(rest) = line.strip_prefix("rustegond ready ") {
                    let _ = ready_tx.send(rest.to_owned());
                }
            }
        });
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
        let http = ready
            .split(' ')
            .find_map(|kv| kv.strip_prefix("http="))
            .unwrap()
            .parse()
            .unwrap();
        Self { child, stdin, http }
    }

    /// Graceful stop (stdin EOF): drain, shutdown checkpoint, exit 0.
    fn stop(mut self) {
        drop(self.stdin.take());
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "graceful stop exits 0: {status:?}");
                return;
            }
            assert!(Instant::now() < deadline, "rustegond did not stop");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Hard kill (a crash): acknowledged writes are only in the Raft log.
    fn kill(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
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
// REST client (HTTP/1.1 over TLS, one connection per request)
// ---------------------------------------------------------------------------------------------

struct Api {
    client: Arc<rustls::ClientConfig>,
    addr: SocketAddr,
    token: Option<String>,
}

impl Api {
    async fn login(env: &Env, daemon: &Daemon) -> Self {
        let mut api = Self {
            client: Arc::clone(&env.client),
            addr: daemon.http,
            token: None,
        };
        let (status, body) = api
            .call(
                "POST",
                "/api/v1/auth/login",
                Some(&json!({"user": "admin", "password": PASSWORD, "delivery": "token"})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        api.token = Some(body["sessionToken"].as_str().unwrap().to_owned());
        api
    }

    async fn call(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
        let conn: Box<dyn Connection> = TokioNetwork.connect(self.addr).await.unwrap();
        let mut stream = TlsConnector::from(Arc::clone(&self.client))
            .connect(ServerName::try_from("localhost").unwrap(), conn)
            .await
            .unwrap();
        let payload = body.map(Value::to_string).unwrap_or_default();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        );
        if let Some(token) = &self.token {
            let _ = write!(request, "Authorization: Bearer {token}\r\n");
        }
        request.push_str("\r\n");
        request.push_str(&payload);
        stream.write_all(request.as_bytes()).await.unwrap();
        // Flush: tokio-rustls may still buffer part of the request after `write_all` (PD-105).
        stream.flush().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let split = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("HTTP response head");
        let head = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
        let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
        let mut body = response[split + 4..].to_vec();
        if head.contains("transfer-encoding: chunked") {
            body = dechunk(&body);
        }
        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("{e}: {body:?}"))
        };
        (status, value)
    }

    async fn ok(&self, method: &str, path: &str, body: Option<&Value>) -> Value {
        let (status, value) = self.call(method, path, body).await;
        assert!(
            (200..300).contains(&status),
            "{method} {path}: {status} {value}"
        );
        value
    }

    async fn query(&self, rgql: &str) -> Value {
        self.ok(
            "POST",
            "/api/v1/databases/vault/query",
            Some(&json!({"rgql": rgql, "options": {"batchSize": 1000}})),
        )
        .await
    }

    /// Inserts canaries `range` into `vault.secrets`.
    async fn insert(&self, range: std::ops::Range<usize>) {
        let ids: Vec<usize> = range.collect();
        for chunk in ids.chunks(PER_CALL) {
            let documents: Vec<Value> = chunk
                .iter()
                .map(|&i| json!({"_id": i, "secret": canary(i), "n": i}))
                .collect();
            self.ok(
                "POST",
                "/api/v1/databases/vault/collections/secrets/documents",
                Some(&json!({ "documents": documents })),
            )
            .await;
        }
    }

    async fn secret(&self, i: usize) -> Value {
        self.ok(
            "GET",
            &format!("/api/v1/databases/vault/collections/secrets/documents/{i}"),
            None,
        )
        .await
    }
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(eol) = body.windows(2).position(|w| w == b"\r\n") else {
            return out;
        };
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..eol]).unwrap().trim(), 16).unwrap();
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&body[eol + 2..eol + 2 + size]);
        body = &body[eol + 2 + size + 2..];
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// Byte scan
// ---------------------------------------------------------------------------------------------

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// Every canary number found in plaintext in any file under `dir`, with the files holding
/// them. One pass per file: each occurrence of the shared prefix is decoded to its number.
fn scan(dir: &Path) -> (BTreeSet<usize>, BTreeSet<PathBuf>, usize) {
    let prefix = CANARY_PREFIX.as_bytes();
    let mut found = BTreeSet::new();
    let mut holders = BTreeSet::new();
    let files = files_under(dir);
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        for (at, _) in bytes
            .windows(prefix.len())
            .enumerate()
            .filter(|(_, w)| *w == prefix)
        {
            let digits = bytes.get(at + prefix.len()..at + prefix.len() + 5);
            if let Some(n) = digits
                .and_then(|d| std::str::from_utf8(d).ok())
                .and_then(|d| d.parse::<usize>().ok())
            {
                found.insert(n);
                holders.insert(path.clone());
            }
        }
    }
    (found, holders, files.len())
}

fn assert_no_canary(dir: &Path, when: &str) -> usize {
    let (found, holders, files) = scan(dir);
    assert!(
        found.is_empty(),
        "{when}: {} canaries in plaintext, in {holders:?}",
        found.len()
    );
    files
}

fn count_with_extension(dir: &Path, ext: &str) -> usize {
    files_under(dir)
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == ext))
        .count()
}

/// Format version field of every Raft log segment.
fn segment_versions(data_dir: &Path) -> Vec<u32> {
    files_under(&data_dir.join("store/raft-log"))
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "rlog"))
        .map(|p| {
            let b = std::fs::read(p).unwrap();
            u32::from_le_bytes(b[8..12].try_into().unwrap())
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// TC-EAR-001 / AC-EAR-001 (module docs).
#[test]
fn tc_ear_001_rustegond_leaves_no_plaintext_canary_in_any_file() {
    let env = Env::new();
    let key = env.key_file("kek.key", KEK_HEX);
    let args = Env::file_args(&key);
    let rt = runtime();

    let daemon = Daemon::spawn(env.command(&strings(&args)));
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        api.ok("POST", "/api/v1/databases", Some(&json!({"name": "vault"})))
            .await;
        api.insert(0..CANARIES).await;
        assert_eq!(api.secret(4242).await["document"]["secret"], canary(4242));
    });
    // Crash: everything acknowledged is only in the (encrypted) Raft log.
    daemon.kill();
    let files = assert_no_canary(&env.data_dir(), "after a crash");
    assert!(files > 5, "scanned {files} files");
    let versions = segment_versions(&env.data_dir());
    assert!(
        !versions.is_empty() && versions.iter().all(|&v| v == 2),
        "{versions:?}"
    );

    // Restart: replay decrypts the log; build an index over the canaries and query it.
    let daemon = Daemon::spawn(env.command(&strings(&args)));
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        assert_eq!(api.secret(9_999).await["document"]["secret"], canary(9_999));
        api.query("CREATE INDEX by_secret ON secrets (secret)")
            .await;
        let progress = "/api/v1/databases/vault/collections/secrets/indexes/by_secret/progress";
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let state = api.ok("GET", progress, None).await["state"].clone();
            if state == "ready" {
                break;
            }
            assert_ne!(state, "failed");
            assert!(Instant::now() < deadline, "index build did not finish");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let hit = api
            .query(&format!("FROM secrets WHERE secret = '{}'", canary(1234)))
            .await;
        assert!(hit.to_string().contains(&canary(1234)), "{hit}");
        let sorted = api.query("FROM secrets ORDER BY secret DESC LIMIT 3").await;
        assert!(sorted.to_string().contains(&canary(9_999)), "{sorted}");
        let range = api.query("FROM secrets WHERE n >= 9990 ORDER BY n").await;
        for i in 9990..10_000 {
            assert!(range.to_string().contains(&canary(i)), "{i}: {range}");
        }
        // A second batch after the restart: new log segments, then SSTs at the stop.
        api.ok(
            "POST",
            "/api/v1/databases/vault/collections/secrets/documents",
            Some(&json!({"documents": [{"_id": "late", "secret": canary(10_000 - 1) + "-late"}]})),
        )
        .await;
    });
    // Graceful stop: the shutdown checkpoint writes the memtables into SSTs.
    daemon.stop();
    assert!(
        env.log_lines()
            .iter()
            .any(|l| l["msg"] == "memtables flushed"),
        "shutdown checkpoint ran"
    );
    let sst = count_with_extension(&env.data_dir().join("store/lsm"), "sst");
    assert!(sst > 0, "the stop wrote SSTs");
    assert_no_canary(&env.data_dir(), "after a graceful stop");
    assert!(env.data_dir().join("store/keys/registry.enc").exists());
    assert!(
        env.data_dir()
            .join("store/keys/raft-log/registry.enc")
            .exists()
    );
    // The key never lands in the data directory or the logs.
    for path in files_under(&env.data_dir()) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes
                .windows(KEK_HEX.len())
                .any(|w| w == KEK_HEX.as_bytes()),
            "{path:?} holds the KEK"
        );
    }
    let opened = env
        .log_lines()
        .into_iter()
        .rfind(|l| l["msg"] == "store opened")
        .unwrap();
    assert_eq!(opened["encrypted"], true, "{opened}");
}

/// TC-EAR-002 (both providers through the process) and TC-EAR-003 for the `env` provider.
#[test]
fn tc_ear_002_rustegond_env_and_file_providers_wrap_and_unwrap_the_same_key() {
    let env = Env::new();
    let rt = runtime();
    let env_args = Env::env_args();

    // env provider: first start creates the encrypted store.
    let mut cmd = env.command(&strings(&env_args));
    cmd.env("RUSTEGON_KEK", KEK_B64);
    let daemon = Daemon::spawn(cmd);
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        api.ok("POST", "/api/v1/databases", Some(&json!({"name": "vault"})))
            .await;
        api.insert(0..50).await;
    });
    daemon.stop();
    assert_no_canary(&env.data_dir(), "env provider");

    // The same key from a file unwraps the env-wrapped DEKs (shared KEK id, PD-057).
    let key = env.key_file("kek.key", KEK_HEX);
    let daemon = Daemon::spawn(env.command(&strings(&Env::file_args(&key))));
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        assert_eq!(api.secret(7).await["document"]["secret"], canary(7));
        api.insert(50..60).await;
    });
    daemon.stop();

    // And back to env: the file-wrapped DEKs unwrap too.
    let mut cmd = env.command(&strings(&env_args));
    cmd.env("RUSTEGON_KEK", KEK_B64);
    let daemon = Daemon::spawn(cmd);
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        assert_eq!(api.secret(55).await["document"]["secret"], canary(55));
    });
    daemon.stop();
    assert_no_canary(&env.data_dir(), "after both providers");

    // TC-EAR-003, env provider: unset, malformed or wrong value → RGN-4006, value not echoed.
    let (code, stderr) = run_to_exit(env.command(&strings(&env_args)));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("RGN-4006")
            && stderr.contains("RUSTEGON_KEK")
            && stderr.contains("not set"),
        "{stderr}"
    );
    for value in [OTHER_KEK_B64, "not-a-key"] {
        let mut cmd = env.command(&strings(&env_args));
        cmd.env("RUSTEGON_KEK", value);
        let (code, stderr) = run_to_exit(cmd);
        assert_eq!(code, Some(2), "{stderr}");
        assert!(stderr.contains("RGN-4006"), "{stderr}");
        assert!(!stderr.contains(value), "the value is echoed: {stderr}");
    }
    // A custom variable name.
    let mut args = env_args.clone();
    args.extend([
        "--set".into(),
        "storage.encryption_key_env=APP_DB_KEK".into(),
    ]);
    let mut cmd = env.command(&strings(&args));
    cmd.env("APP_DB_KEK", KEK_B64);
    let daemon = Daemon::spawn(cmd);
    daemon.stop();
    let logs = env
        .log_lines()
        .iter()
        .map(Value::to_string)
        .collect::<String>();
    assert!(
        !logs.contains(KEK_B64) && !logs.contains(KEK_HEX),
        "the key reached the log"
    );
}

/// TC-EAR-003 / AC-EAR-002: an unavailable key refuses the start with RGN-4006 and a reason.
#[test]
fn tc_ear_003_rustegond_refuses_to_start_without_its_key() {
    // Missing key file: refused before the data directory is created.
    let env = Env::new();
    let missing = env.root.path().join("absent.key");
    let (code, stderr) = run_to_exit(env.command(&strings(&Env::file_args(&missing))));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("RGN-4006")
            && stderr.contains("absent.key")
            && stderr.contains("not found"),
        "{stderr}"
    );
    assert!(
        !env.data_dir().join("store").exists(),
        "no store is created by a failed start"
    );

    // Malformed key file.
    let bad = env.key_file("bad.key", "zz");
    let (code, stderr) = run_to_exit(env.command(&strings(&Env::file_args(&bad))));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("RGN-4006") && stderr.contains("256-bit"),
        "{stderr}"
    );

    // An encrypted store: started with another key, or without encryption.
    let key = env.key_file("kek.key", KEK_HEX);
    let daemon = Daemon::spawn(env.command(&strings(&Env::file_args(&key))));
    daemon.stop();
    let other = env.key_file("other.key", OTHER_KEK_HEX);
    let (code, stderr) = run_to_exit(env.command(&strings(&Env::file_args(&other))));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("RGN-4006"), "{stderr}");
    assert!(
        !stderr.contains(OTHER_KEK_HEX) && !stderr.contains(KEK_HEX),
        "{stderr}"
    );
    let (code, stderr) = run_to_exit(env.command(&[]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("RGN-4006") && stderr.contains("encrypted at rest"),
        "{stderr}"
    );
    // The refused starts changed nothing: the right key still opens the store.
    Daemon::spawn(env.command(&strings(&Env::file_args(&key)))).stop();

    // Unix: a key file group or others can read is refused (security.md §6).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (code, stderr) = run_to_exit(env.command(&strings(&Env::file_args(&key))));
        assert_eq!(code, Some(2), "{stderr}");
        assert!(
            stderr.contains("RGN-4006") && stderr.contains("chmod 600"),
            "{stderr}"
        );
    }
}

/// TC-EAR-004: a plaintext store switches to encryption at a restart (module docs).
#[test]
fn tc_ear_004_rustegond_switches_a_plaintext_store_to_encryption() {
    const BEFORE: std::ops::Range<usize> = 0..200;
    const AFTER: std::ops::Range<usize> = 200..400;
    let env = Env::new();
    let rt = runtime();
    let daemon = Daemon::spawn(env.command(&[]));
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        api.ok("POST", "/api/v1/databases", Some(&json!({"name": "vault"})))
            .await;
        api.insert(BEFORE).await;
    });
    daemon.stop();
    // Control: the plaintext store holds the canaries where the scan looks.
    let (found, _, _) = scan(&env.data_dir());
    assert_eq!(
        found.len(),
        BEFORE.len(),
        "the scan sees the plaintext layout"
    );

    let key = env.key_file("kek.key", KEK_HEX);
    let args = Env::file_args(&key);
    let daemon = Daemon::spawn(env.command(&strings(&args)));
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        assert_eq!(
            api.secret(BEFORE.start + 3).await["document"]["secret"],
            canary(BEFORE.start + 3)
        );
        api.insert(AFTER).await;
    });
    daemon.stop();
    let warned = env
        .log_lines()
        .into_iter()
        .find(|l| l["level"] == "WARN" && l["plaintext_files"].as_u64().is_some_and(|n| n > 0));
    assert!(
        warned.is_some(),
        "the node warns about pre-switch plaintext files"
    );
    let (found, holders, _) = scan(&env.data_dir());
    assert!(
        found.iter().all(|i| BEFORE.contains(i)),
        "post-switch canaries in plaintext: {:?} in {holders:?}",
        found
            .iter()
            .filter(|i| AFTER.contains(i))
            .collect::<Vec<_>>()
    );
    assert!(
        holders
            .iter()
            .all(|p| p.extension().is_some_and(|e| e == "sst")),
        "pre-switch data remains only in pre-switch SSTs: {holders:?}"
    );

    // Encrypted from now on: no start without the key; with it everything reads back.
    let (code, stderr) = run_to_exit(env.command(&[]));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("RGN-4006"), "{stderr}");
    let daemon = Daemon::spawn(env.command(&strings(&args)));
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        assert_eq!(api.secret(5).await["document"]["secret"], canary(5));
        assert_eq!(api.secret(305).await["document"]["secret"], canary(305));
    });
    daemon.stop();
}
