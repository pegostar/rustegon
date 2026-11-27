// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Online restore of a live `rustegond` (FR-BKP-001, ADR-037; TC-BKP-016):
//! - a backup taken through `POST /api/v1/backups` is one `<id>.nbck` file; after more writes and
//!   a new user, `POST /api/v1/backups/{id}/restore` makes the same process stop serving,
//!   restore and serve again: every document is back to its backed-up value, the user created
//!   later is gone (users and roles come from the backup), the replaced store is kept, and
//!   `GET /api/v1/restore-status` reports the restore;
//! - a restore accepted before a stop or a crash runs at the next start (the pending record);
//!   one that fails before its swap leaves the node serving its previous store, unchanged, with
//!   the failure in the status.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    dead_code
)]
// The server under test is a separate OS process on real time and real sockets.
#![allow(clippy::disallowed_methods)]

use std::{
    fmt::Write as _,
    io::{BufRead as _, BufReader, Read as _},
    net::SocketAddr,
    path::PathBuf,
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

const START_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_TIMEOUT: Duration = Duration::from_secs(120);
/// A password that passes the policy (test-only, not a real secret).
const PASSWORD: &str = "q7Vz!m2Lp#9Rx4Tk";
/// Test-only KEK (32 bytes of 0x07).
const KEK_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";
const DOCS: i64 = 24;
const WRITERS: i64 = 3;

// ---------------------------------------------------------------------------------------------
// Harness (a trimmed copy of `tests/ear.rs`)
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
            "rustegond backup test CA",
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

    fn key_file(&self) -> PathBuf {
        let path = self.root.path().join("kek.key");
        StdFileSystem
            .create_new_private(&path)
            .and_then(|mut f| f.append(format!("{KEK_HEX}\n").as_bytes()))
            .unwrap();
        path
    }

    fn command(&self, extra: &[String]) -> Command {
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
                "--set",
                "rate_limit.enabled=false",
                "--set",
                "storage.memtable_size=1048576",
            ])
            .args(extra);
        cmd
    }
}

struct Daemon {
    child: Child,
    stdin: Option<ChildStdin>,
    http: SocketAddr,
    /// Every `rustegond ready` line: a serving period after an online restore prints another.
    ready: mpsc::Receiver<String>,
    stderr: Arc<Mutex<String>>,
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
        Self {
            child,
            stdin,
            http: http_of(&ready),
            ready: ready_rx,
            stderr,
        }
    }

    /// Waits for the next serving period (after an online restore) and follows its address.
    fn wait_ready_again(&mut self) {
        let ready = self.ready.recv_timeout(START_TIMEOUT).unwrap_or_else(|_| {
            panic!(
                "rustegond did not serve again; stderr:\n{}",
                self.stderr.lock().unwrap()
            )
        });
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "the process must not exit"
        );
        self.http = http_of(&ready);
    }

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
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn http_of(ready: &str) -> SocketAddr {
    ready
        .split(' ')
        .find_map(|kv| kv.strip_prefix("http="))
        .unwrap()
        .parse()
        .unwrap()
}

#[derive(Clone)]
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

const DOCS_PATH: &str = "/api/v1/databases/shop/collections/acct/documents";

async fn populate(api: &Api) {
    api.ok("POST", "/api/v1/databases", Some(&json!({"name": "shop"})))
        .await;
    let documents: Vec<Value> = (0..DOCS).map(|i| json!({"_id": i, "n": 0})).collect();
    api.ok("POST", DOCS_PATH, Some(&json!({ "documents": documents })))
        .await;
}

/// Sets `n` of every document.
async fn write_all(api: &Api, n: i64) {
    for id in 0..DOCS {
        api.ok(
            "PUT",
            &format!("{DOCS_PATH}/{id}"),
            Some(&json!({"_id": id, "n": n})),
        )
        .await;
    }
}

/// `n` of every document.
async fn values(api: &Api) -> Vec<i64> {
    let mut out = Vec::new();
    for id in 0..DOCS {
        let body = api.ok("GET", &format!("{DOCS_PATH}/{id}"), None).await;
        out.push(
            body["document"]["n"]
                .as_i64()
                .unwrap_or_else(|| panic!("{body}")),
        );
    }
    out
}

fn all(n: i64) -> Vec<i64> {
    vec![n; usize::try_from(DOCS).unwrap()]
}

fn backups_dir(env: &Env) -> String {
    env.data_dir().join("backups").display().to_string()
}

fn names_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// TC-BKP-016 end to end (module docs, first point).
#[test]
fn tc_bkp_016_online_restore_replaces_the_node_without_stopping_the_process() {
    let env = Env::new();
    let rt = runtime();
    let mut daemon = Daemon::spawn(env.command(&[]));
    let id = rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        populate(&api).await;
        let status = api.ok("GET", "/api/v1/restore-status", None).await;
        assert_eq!(status["state"], "none", "{status}");
        let created = api
            .ok(
                "POST",
                "/api/v1/backups",
                Some(&json!({ "destination": backups_dir(&env) })),
            )
            .await;
        let id = created["backup"]["backupId"].as_str().unwrap().to_owned();
        assert_eq!(
            names_in(&env.data_dir().join("backups")),
            [format!("{id}.nbck")],
            "one file per backup"
        );
        // After the backup: other values and a new user.
        write_all(&api, 99).await;
        api.ok(
            "POST",
            "/api/v1/users",
            Some(&json!({"name": "late", "password": PASSWORD, "roles": []})),
        )
        .await;
        let accepted = api
            .ok(
                "POST",
                &format!("/api/v1/backups/{id}/restore"),
                Some(&json!({ "destination": backups_dir(&env) })),
            )
            .await;
        assert_eq!(accepted["backup"]["backupId"], id.as_str());
        (id, api)
    });
    let (id, old) = id;

    daemon.wait_ready_again();
    rt.block_on(async {
        // The session used before (stored in the backup too) does not come back.
        let old = Api {
            addr: daemon.http,
            ..old
        };
        let (code, body) = old.call("GET", "/api/v1/restore-status", None).await;
        assert_eq!(code, 401, "a session of the backup is revoked: {body}");
        let api = Api::login(&env, &daemon).await;
        assert_eq!(values(&api).await, all(0));
        let (code, body) = api.call("GET", "/api/v1/users/late", None).await;
        assert_eq!(
            code, 404,
            "the user created after the backup is gone: {body}"
        );
        let status = api.ok("GET", "/api/v1/restore-status", None).await;
        assert_eq!(status["state"], "completed", "{status}");
        assert_eq!(status["backupId"], id.as_str());
        let kept = status["previousStore"].as_str().unwrap().to_owned();
        assert!(kept.starts_with("store.pre-restore-"), "{kept}");
        assert!(env.data_dir().join(&kept).is_dir());
        // The node writes again after the restore.
        write_all(&api, 5).await;
        assert_eq!(values(&api).await, all(5));
    });
    assert!(!env.data_dir().join("online-restore.json").exists());
    assert!(
        env.data_dir()
            .join("backups")
            .join(format!("{id}.nbck"))
            .is_file(),
        "the backup itself is untouched"
    );
    daemon.stop();
}

/// TC-BKP-016 (module docs, second point): the pending record makes a start restore first;
/// a pending restore of a backup that does not exist fails before its swap, and the node serves
/// its store unchanged with the failure in the status.
#[test]
fn tc_bkp_016_pending_restore_runs_at_start_and_a_failed_one_keeps_the_store() {
    let env = Env::new();
    let rt = runtime();
    let daemon = Daemon::spawn(env.command(&[]));
    let id = rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        populate(&api).await;
        let created = api
            .ok(
                "POST",
                "/api/v1/backups",
                Some(&json!({ "destination": backups_dir(&env) })),
            )
            .await;
        write_all(&api, 7).await;
        created["backup"]["backupId"].as_str().unwrap().to_owned()
    });
    daemon.stop();

    let pending = |backup_id: &str| {
        std::fs::write(
            env.data_dir().join("online-restore.json"),
            json!({"version": 1, "destination": backups_dir(&env), "backup_id": backup_id})
                .to_string(),
        )
        .unwrap();
    };
    // Accepted, then the process went away: the next start restores before serving.
    pending(&id);
    let daemon = Daemon::spawn(env.command(&[]));
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        assert_eq!(values(&api).await, all(0));
        let status = api.ok("GET", "/api/v1/restore-status", None).await;
        assert_eq!(status["state"], "completed", "{status}");
        write_all(&api, 3).await;
    });
    daemon.stop();

    // A pending restore that cannot run: the store is kept and served.
    pending("20261109T101500Z-00000000");
    let daemon = Daemon::spawn(env.command(&[]));
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        assert_eq!(values(&api).await, all(3));
        let status = api.ok("GET", "/api/v1/restore-status", None).await;
        assert_eq!(status["state"], "failed", "{status}");
        assert_eq!(status["error"]["code"], 1030, "{status}");
    });
    assert!(!env.data_dir().join("online-restore.json").exists());
    assert!(!env.data_dir().join("restore-in-progress.json").exists());
    daemon.stop();
}

/// PD-230: a static setting changed through the API goes to the configuration file, shows as
/// pending, and takes effect with `POST /node/restart` without the process ending; a change
/// that keeps the node from starting falls back to the previous configuration and says why.
#[test]
fn tc_ops_002_restart_applies_static_settings_and_falls_back_on_a_bad_one() {
    let env = Env::new();
    let config = env.root.path().join("rustegon.toml");
    std::fs::write(&config, "# written by the test\n").unwrap();
    let rt = runtime();
    let mut daemon = Daemon::spawn(env.command(&["--config".into(), config.display().to_string()]));
    let api = rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        let changed = api
            .ok(
                "PATCH",
                "/api/v1/settings",
                Some(&json!({"values": {"lockout.max_failures": "4"}})),
            )
            .await;
        let s = &changed["settings"][0];
        assert_eq!(
            (s["value"].as_str(), s["pendingValue"].as_str()),
            (Some("10"), Some("4")),
            "{s}"
        );
        // A setting a --set flag owns cannot be changed here.
        let (code, body) = api
            .call(
                "PATCH",
                "/api/v1/settings",
                Some(&json!({"values": {"listen.shutdown_grace_secs": "7"}})),
            )
            .await;
        assert_eq!(code, 400, "{body}");
        let restarting = api.ok("POST", "/api/v1/node/restart", None).await;
        assert_eq!(restarting["restarting"], true);
        api
    });
    daemon.wait_ready_again();
    let api = rt.block_on(async {
        // Sessions are in the store: the same token works after the restart.
        let api = Api { addr: daemon.http, ..api };
        let got = api
            .ok("GET", "/api/v1/settings?names=lockout.max_failures", None)
            .await;
        let s = &got["settings"][0];
        assert_eq!(s["value"], "4", "{got}");
        assert!(s.get("pendingValue").is_none(), "{got}");
        assert!(got.get("lastRestartError").is_none(), "{got}");

        // A file where the audit directory should be: valid for the registry, fatal at start.
        api.ok(
            "PATCH",
            "/api/v1/settings",
            Some(&json!({"values": {"audit.dir": serde_json::to_string(&config.display().to_string()).unwrap()}})),
        )
        .await;
        api.ok("POST", "/api/v1/node/restart", None).await;
        api
    });
    daemon.wait_ready_again();
    rt.block_on(async {
        let api = Api {
            addr: daemon.http,
            ..api
        };
        let got = api
            .ok("GET", "/api/v1/settings?names=audit.dir", None)
            .await;
        let error = got["lastRestartError"].as_str().unwrap_or_default();
        assert!(error.contains("changed configuration"), "{got}");
        assert!(
            got["settings"][0].get("pendingValue").is_some(),
            "still pending: {got}"
        );
        // The node still serves with the previous configuration.
        let lockout = api
            .ok("GET", "/api/v1/settings?names=lockout.max_failures", None)
            .await;
        assert_eq!(lockout["settings"][0]["value"], "4");
    });
    assert!(
        std::fs::read_to_string(&config)
            .unwrap()
            .contains("# written by the test")
    );
    daemon.stop();
}
