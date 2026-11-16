// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared harness of the process-level CLI tests (`tests/cli.rs`, `tests/e2e_backup.rs`): a
//! temporary node directory initialised by `rustegon init`, a real `rustegond` started on it,
//! the `rustegon` CLI run against it over TLS, and a small HTTPS client for the REST API and
//! `/metrics` (PD-058).
//!
//! `rustegond` is another package's binary, which Cargo does not build for these test targets
//! (`CARGO_BIN_EXE_*` covers the own package only); the harness runs `cargo build -p rustegond`
//! once per test process into its own target directory `<target>/cli-harness` (see
//! [`rustegond`]; a no-op once it is up to date).

// Each test binary includes this module and uses a different subset of it.
#![allow(dead_code)]

use std::{
    fmt::Write as _,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::{Duration, Instant},
};

use rustegon_net::{
    TlsContext, TlsMinVersion, TrustAnchors,
    rustls::{self, pki_types::ServerName},
};
use rustegon_sim_api::SystemClock;

/// Startup in a debug build includes PBKDF2 for the bootstrap admin.
pub const START_TIMEOUT: Duration = Duration::from_secs(180);
pub const STOP_TIMEOUT: Duration = Duration::from_secs(60);
/// A password that passes the policy (test-only, not a real secret).
pub const ADMIN_PASSWORD: &str = "q7Vz!m2Lp#9Rx4Tk";

// ---------------------------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------------------------

/// Path of the `rustegond` binary, built on first use.
///
/// The build goes to a dedicated target directory (`<target>/cli-harness`): a plain
/// `cargo build -p rustegond` resolves features differently from the test build (dev-dependency
/// features are unified only when test targets are built, resolver 2), so in the shared target
/// directory it rebuilt and re-uplifted `target/<profile>/rustegond` while `rustegond`'s own
/// integration tests were executing it — "access denied" on Windows, a swapped binary elsewhere.
/// Every CLI test process asks for the same build here; cargo's directory lock serialises the
/// first build and the later calls are fresh no-ops that write nothing.
pub fn rustegond() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let cli = PathBuf::from(env!("CARGO_BIN_EXE_rustegon"));
        let profile_dir = cli.parent().unwrap().to_path_buf();
        let profile_dir_name = profile_dir.file_name().unwrap().to_owned();
        let target_dir = profile_dir.parent().unwrap().join("cli-harness");
        let profile = match profile_dir_name.to_str() {
            Some("debug") | None => "dev".to_owned(),
            Some(other) => other.to_owned(),
        };
        let status = Command::new(env!("CARGO"))
            .args([
                "build",
                "-p",
                "rustegond",
                "--bin",
                "rustegond",
                "--profile",
            ])
            .arg(&profile)
            .arg("--target-dir")
            .arg(&target_dir)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .unwrap();
        assert!(status.success(), "cargo build -p rustegond failed");
        target_dir
            .join(profile_dir_name)
            .join(format!("rustegond{}", std::env::consts::EXE_SUFFIX))
    })
}

/// A command without inherited `RUSTEGON_*` variables.
pub fn clean(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().into_owned();
        if k.starts_with("RUSTEGON_") {
            cmd.env_remove(k);
        }
    }
    cmd
}

/// Output of a finished CLI run.
pub struct Run {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn ok(self) -> Self {
        assert_eq!(
            self.code,
            Some(0),
            "stdout:\n{}\nstderr:\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    pub fn failed(self) -> Self {
        assert_eq!(
            self.code,
            Some(1),
            "stdout:\n{}\nstderr:\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    pub fn text(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

impl From<Output> for Run {
    fn from(o: Output) -> Self {
        Self {
            code: o.status.code(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }
}

/// Runs `rustegon args…` with `env` and stdin closed.
pub fn cli(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = clean(Path::new(env!("CARGO_BIN_EXE_rustegon")));
    cmd.args(args).stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap().into()
}

/// A temporary node directory and every CLI output seen so far (for the secret checks).
pub struct Env {
    pub root: tempfile::TempDir,
    transcript: Mutex<String>,
}

impl Env {
    pub fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            transcript: Mutex::new(String::new()),
        }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    pub fn data_dir(&self) -> PathBuf {
        self.path("data")
    }

    pub fn ca(&self) -> String {
        self.data_dir()
            .join("certs")
            .join("ca.crt")
            .display()
            .to_string()
    }

    pub fn config(&self) -> String {
        self.data_dir().join("rustegon.toml").display().to_string()
    }

    pub fn write(&self, rel: &str, content: &str) -> String {
        let p = self.path(rel);
        std::fs::write(&p, content).unwrap();
        p.display().to_string()
    }

    /// Appends `text` to the node's configuration file.
    pub fn append_config(&self, text: &str) {
        let mut config = std::fs::OpenOptions::new()
            .append(true)
            .open(self.config())
            .unwrap();
        config.write_all(text.as_bytes()).unwrap();
    }

    pub fn cli(&self, args: &[&str], env: &[(&str, &str)]) -> Run {
        let run = cli(args, env);
        self.record(&run.text());
        run
    }

    /// Adds output of a process to the transcript checked by [`Self::assert_never_printed`].
    pub fn record(&self, text: &str) {
        self.transcript.lock().unwrap().push_str(text);
    }

    /// `rustegon init` on the data directory, ephemeral ports, plus `extra`.
    pub fn init(&self, extra: &[&str]) -> Run {
        let data = self.data_dir().display().to_string();
        let mut args = vec![
            "init",
            "--data-dir",
            &data,
            "--grpc-port",
            "0",
            "--http-port",
            "0",
            "--non-interactive",
            // TLS is opt-in (ADR-034); the harness talks TLS (`conn` passes `--ca`).
            "--tls",
        ];
        args.extend_from_slice(extra);
        self.cli(&args, &[])
    }

    pub fn start(&self, extra: &[&str]) -> Daemon {
        let mut cmd = clean(rustegond());
        cmd.arg("--stop-on-stdin-eof")
            .arg("--config")
            .arg(self.config())
            .args([
                "--set",
                "log.stderr=false",
                // The smallest iteration count the configuration accepts (debug builds).
                "--set",
                "auth.scram_iterations=100000",
                "--set",
                "listen.shutdown_grace_secs=5",
                // Every CLI call is a fresh SCRAM login from 127.0.0.1: the scenarios exceed the
                // default 10/min burst 20 per IP (security.md §8) and failed with RGN-4003 when
                // they ran fast enough. A rate of 0 disables the bucket (PD-048); the limiter
                // itself is covered by TC-SEC-005 (`rustegon-security/tests/ratelimit.rs`).
                "--set",
                "rate_limit.auth_per_ip_per_min=0",
                "--set",
                "rate_limit.session_per_user_per_min=0",
            ])
            .args(extra);
        Daemon::spawn(cmd)
    }

    /// Asserts that no CLI output so far contains `secret`.
    pub fn assert_never_printed(&self, secret: &str) {
        let transcript = self.transcript.lock().unwrap();
        assert!(
            !transcript.contains(secret),
            "a secret was printed by the CLI"
        );
    }
}

/// A running `rustegond`.
pub struct Daemon {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<String>>,
    stderr_reader: Option<std::thread::JoinHandle<()>>,
    pub grpc_port: String,
    pub http_port: u16,
}

impl Daemon {
    pub fn spawn(mut cmd: Command) -> Self {
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
        let port_of = |key: &str| {
            ready
                .split(' ')
                .find_map(|kv| kv.strip_prefix(key))
                .unwrap()
                .rsplit(':')
                .next()
                .unwrap()
                .to_owned()
        };
        Self {
            child,
            stdin,
            stdout,
            stderr,
            stderr_reader: Some(stderr_reader),
            grpc_port: port_of("grpc="),
            http_port: port_of("http=").parse().unwrap(),
        }
    }

    pub fn stdout(&self) -> Vec<String> {
        self.stdout.lock().unwrap().clone()
    }

    /// Closes stdin (graceful shutdown) and waits for exit 0; returns everything the process
    /// wrote to stdout and stderr (for the secret checks).
    pub fn stop(mut self) -> String {
        drop(self.stdin.take());
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "rustegond exit: {status:?}");
                break;
            }
            assert!(Instant::now() < deadline, "rustegond did not stop");
            std::thread::sleep(Duration::from_millis(50));
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
        format!(
            "{}\n{}",
            self.stdout().join("\n"),
            self.stderr.lock().unwrap()
        )
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

/// Connection arguments for the node (TLS with the CA written by init, IP SAN).
pub fn conn<'a>(env: &'a Env, daemon: &'a Daemon, ca: &'a str) -> Vec<&'a str> {
    let _ = env;
    vec![
        "--host",
        "127.0.0.1",
        "--port",
        &daemon.grpc_port,
        "--ca",
        ca,
    ]
}

pub fn with<'a>(base: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
    let mut v = base.to_vec();
    v.extend_from_slice(extra);
    v
}

/// Nanoseconds since the Unix epoch on this machine's clock (the node's HLC follows it).
pub fn now_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// The PITR timelines archived under a destination directory.
pub fn timelines(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root.join("pitr"))
        .map(|d| {
            d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Every regular file under `dir` (recursively) with its bytes.
pub fn files_under(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries {
            let path = e.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.push((path, bytes));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The files under `dir` whose bytes contain `needle`.
pub fn files_containing(dir: &Path, needle: &str) -> Vec<PathBuf> {
    files_under(dir)
        .into_iter()
        .filter(|(_, bytes)| bytes.windows(needle.len()).any(|w| w == needle.as_bytes()))
        .map(|(p, _)| p)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// HTTPS (REST API and /metrics)
// ---------------------------------------------------------------------------------------------

/// One HTTP/1.1 response.
pub struct Http {
    pub status: u16,
    pub body: String,
}

impl Http {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }

    pub fn ok(self) -> Self {
        assert!(
            (200..300).contains(&self.status),
            "{}: {}",
            self.status,
            self.body
        );
        self
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

/// One request on a fresh TLS connection to the node's REST listener, verified against the CA
/// written by `rustegon init`.
pub fn https(
    ca: &str,
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&serde_json::Value>,
) -> Http {
    let anchors = TrustAnchors::from_pem(&std::fs::read(ca).unwrap(), ca).unwrap();
    let tls = TlsContext::new(Arc::new(SystemClock::new()), TlsMinVersion::Tls13);
    let mut config = tls.client_config(&anchors, None).unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn = rustls::ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("localhost".to_owned()).unwrap(),
    )
    .unwrap();
    let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut stream = rustls::StreamOwned::new(conn, sock);
    let body = body.map(serde_json::Value::to_string).unwrap_or_default();
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(t) = token {
        let _ = write!(request, "Authorization: Bearer {t}\r\n");
    }
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    let _ = write!(request, "Content-Length: {}\r\n\r\n{body}", body.len());
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    // A TLS close without close_notify is fine here: the response is complete by then.
    let _ = stream.read_to_end(&mut response);
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no response head");
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    let raw_body = &response[split + 4..];
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(raw_body)
    } else {
        raw_body.to_vec()
    };
    Http {
        status: head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// Password login over REST with token delivery; the session token.
pub fn rest_login(ca: &str, daemon: &Daemon, user: &str, password: &str) -> String {
    let r = https(
        ca,
        daemon.http_port,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({"user": user, "password": password, "delivery": "token"})),
    )
    .ok();
    r.json()["sessionToken"].as_str().unwrap().to_owned()
}
