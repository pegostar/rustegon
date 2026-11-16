// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Online physical backup of a live `rustegond` process and its offline restore (M13a lane BE;
//! FR-BKP-001, FR-BKP-005, PD-063, PD-064, PD-082):
//! - TC-BKP-001: writers keep replacing documents through the REST API while `POST
//!   /api/v1/backups` takes a backup to the node's default `<data_dir>/backups`; the node stops;
//!   the backup is restored offline (`rustegon_backup::restore_data_dir`) into a new data
//!   directory. Every document of the restored store holds a value its writer wrote, with the
//!   `_rev` the API returned for it; every write acknowledged before the backup request was sent
//!   is in it, no write sent after the backup response is (the cut is a consistent point T in
//!   between), and per writer the documents form one round boundary (writes are in id order).
//!   The exact "equals the source read at T" comparison is
//!   `rustegon-backup/tests/physical.rs` (TC-BKP-001, a pinned T on the engine).
//! - TC-BKP-005 / FR-BKP-005: a node with encryption at rest records its KEK id in the backup;
//!   the offline restore refuses without the key and succeeds with it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
// The server under test is a separate OS process on real time and real sockets.
#![allow(clippy::disallowed_methods)]

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io::{BufRead as _, BufReader, Read as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use rustegon_backup::{BackupId, LocalDestination, RestoreKind, RestoreRequest, restore_data_dir};
use rustegon_common::ErrorCode;
use rustegon_doc::Value as DocValue;
use rustegon_engine::EmbeddedDb;
use rustegon_net::{
    CertAuthority, KeyAlgorithm, TlsContext, TlsMinVersion, TrustAnchors,
    rustls::{self, pki_types::ServerName},
    tokio_rustls::TlsConnector,
};
use rustegon_sim_api::{
    Connection, FileSystem as _, Network, OsRng, StdFileSystem, SystemClock, TokioNetwork,
};
use rustegon_storage::{
    EngineOptions,
    encryption::{FileKekProvider, KekProvider},
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

fn restore(
    data_dir: &Path,
    backup_id: &str,
    into: &Path,
    kek: Option<Arc<dyn KekProvider>>,
) -> Result<(), rustegon_common::Error> {
    let source = LocalDestination::open(Arc::new(StdFileSystem), data_dir.join("backups")).unwrap();
    restore_data_dir(
        &(Arc::new(StdFileSystem) as Arc<dyn rustegon_sim_api::FileSystem>),
        &(Arc::new(SystemClock::new()) as Arc<dyn rustegon_sim_api::Clock>),
        &(Arc::new(OsRng) as Arc<dyn rustegon_sim_api::Rng>),
        &RestoreRequest {
            source: &source,
            id: &BackupId::parse(backup_id).unwrap(),
            data_dir: into,
            kind: RestoreKind::Backup,
            kek,
        },
    )
    .map(|_| ())
}

fn open_restored(into: &Path, kek: Option<Arc<dyn KekProvider>>) -> EmbeddedDb {
    EmbeddedDb::open_with_kek(
        Arc::new(StdFileSystem),
        &into.join("store"),
        Arc::new(SystemClock::new()),
        Arc::new(OsRng),
        EngineOptions::default(),
        kek,
    )
    .unwrap()
}

/// Phases of the test relative to the backup request (module docs).
const BEFORE: u8 = 0;
const DURING: u8 = 1;
const AFTER: u8 = 2;

/// One acknowledged write: value, `_rev`, phase when sent and when acknowledged.
#[derive(Debug, Clone)]
struct Write {
    n: i64,
    rev: String,
    sent: u8,
    acked: u8,
}

/// TC-BKP-001 end to end (module docs).
#[test]
fn tc_bkp_001_backup_of_a_live_rustegond_under_rest_writes_restores_a_consistent_cut() {
    let env = Env::new();
    let rt = runtime();
    let daemon = Daemon::spawn(env.command(&[]));
    let phase = Arc::new(AtomicU8::new(BEFORE));
    let stop = Arc::new(AtomicBool::new(false));
    let (backup_id, log) = rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        populate(&api).await;
        let log: Arc<Mutex<BTreeMap<i64, Vec<Write>>>> = Arc::default();
        let mut tasks = Vec::new();
        for w in 0..WRITERS {
            let (api, phase, stop, log) = (
                api.clone(),
                Arc::clone(&phase),
                Arc::clone(&stop),
                Arc::clone(&log),
            );
            tasks.push(tokio::spawn(async move {
                let mut n = 0;
                let mut rounds_after = 0;
                // Stops only after a few complete rounds once the backup returned.
                while !(stop.load(Ordering::SeqCst) && rounds_after >= 2) {
                    n += 1;
                    if phase.load(Ordering::SeqCst) == AFTER {
                        rounds_after += 1;
                    }
                    for id in (w..DOCS).step_by(usize::try_from(WRITERS).unwrap()) {
                        let sent = phase.load(Ordering::SeqCst);
                        let body = api
                            .ok(
                                "PUT",
                                &format!("{DOCS_PATH}/{id}"),
                                Some(&json!({"_id": id, "n": n})),
                            )
                            .await;
                        let acked = phase.load(Ordering::SeqCst);
                        let rev = body["result"]["rev"].as_str().unwrap().to_owned();
                        log.lock().unwrap().entry(id).or_default().push(Write {
                            n,
                            rev,
                            sent,
                            acked,
                        });
                    }
                }
            }));
        }
        // Let the writers run, then take the backup while they keep going.
        while log.lock().unwrap().values().map(Vec::len).sum::<usize>() < 60 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let dest = env.data_dir().join("backups").display().to_string();
        phase.store(DURING, Ordering::SeqCst);
        let created = api
            .ok(
                "POST",
                "/api/v1/backups",
                Some(&json!({ "destination": dest })),
            )
            .await;
        phase.store(AFTER, Ordering::SeqCst);
        stop.store(true, Ordering::SeqCst);
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(created["backup"]["encryption"], "plaintext");
        assert_eq!(created["warnings"][0]["kind"], "plaintext_backup");
        // PD-082: outside the allowlist is refused even for the admin.
        let outside = env.root.path().join("outside").display().to_string();
        let (status, body) = api
            .call(
                "POST",
                "/api/v1/backups",
                Some(&json!({ "destination": outside })),
            )
            .await;
        assert_eq!(status, 403, "{body}");
        let id = created["backup"]["backupId"].as_str().unwrap().to_owned();
        let log = log.lock().unwrap().clone();
        (id, log)
    });
    daemon.stop();

    let into = env.root.path().join("restored");
    restore(&env.data_dir(), &backup_id, &into, None).unwrap();
    let db = open_restored(&into, None);
    let mut boundaries = 0;
    for w in 0..WRITERS {
        let mut rounds = Vec::new();
        for id in (w..DOCS).step_by(usize::try_from(WRITERS).unwrap()) {
            let doc = db
                .get("shop", "acct", &DocValue::Int64(id))
                .unwrap()
                .unwrap();
            let Some(DocValue::Int64(n)) = doc.get("n") else {
                panic!("{doc:?}");
            };
            let writes = &log[&id];
            // Every write acknowledged before the backup was requested is in the image...
            let floor = writes
                .iter()
                .filter(|x| x.acked == BEFORE)
                .map(|x| x.n)
                .max()
                .unwrap_or(0);
            // ...and none sent after the backup returned.
            let ceiling = writes
                .iter()
                .filter(|x| x.sent == AFTER)
                .map(|x| x.n)
                .min()
                .unwrap();
            assert!(
                floor <= *n && *n < ceiling,
                "doc {id}: n={n}, floor={floor}, ceiling={ceiling}"
            );
            if *n > 0 {
                let rev = &writes.iter().find(|x| x.n == *n).unwrap().rev;
                assert_eq!(
                    doc.get("_rev"),
                    Some(&DocValue::String(rev.clone())),
                    "doc {id}: the restored version is the one the API acknowledged"
                );
            }
            rounds.push(*n);
        }
        // Writer w replaces its documents in id order: one round boundary at most.
        assert!(
            rounds.windows(2).all(|p| p[0] == p[1] || p[0] == p[1] + 1),
            "writer {w}: {rounds:?}"
        );
        boundaries += rounds.windows(2).filter(|p| p[0] != p[1]).count();
    }
    // Diagnostic only: how often the cut fell inside a round.
    eprintln!("round boundaries inside the cut: {boundaries}");
    drop(db);
}

/// TC-BKP-005 / FR-BKP-005 through the process: the backup of an encrypted node records the
/// node's KEK id (PD-064), and the offline restore needs that key.
#[test]
fn tc_bkp_005_backup_of_an_encrypted_rustegond_restores_only_with_its_kek() {
    let env = Env::new();
    let key = env.key_file();
    let rt = runtime();
    let daemon = Daemon::spawn(env.command(&[
        "--set".into(),
        "storage.encryption=aes-256-gcm".into(),
        "--set".into(),
        format!("storage.encryption_key_file={}", key.display()),
    ]));
    let kek: Arc<dyn KekProvider> = Arc::new(FileKekProvider::open(&StdFileSystem, &key).unwrap());
    let backup_id = rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        populate(&api).await;
        let dest = env.data_dir().join("backups").display().to_string();
        let created = api
            .ok(
                "POST",
                "/api/v1/backups",
                Some(&json!({ "destination": dest })),
            )
            .await;
        assert_eq!(created["backup"]["encryption"], "kek");
        assert_eq!(created["backup"]["kekId"], kek.key_id().as_str());
        assert_eq!(created["warnings"], json!([]));
        created["backup"]["backupId"].as_str().unwrap().to_owned()
    });
    daemon.stop();
    let into = env.root.path().join("restored");
    let e = restore(&env.data_dir(), &backup_id, &into, None).unwrap_err();
    assert_eq!(e.code(), ErrorCode::KeyUnavailable, "{e}");
    restore(&env.data_dir(), &backup_id, &into, Some(Arc::clone(&kek))).unwrap();
    let db = open_restored(&into, Some(kek));
    for id in 0..DOCS {
        assert!(
            db.get("shop", "acct", &DocValue::Int64(id))
                .unwrap()
                .is_some()
        );
    }
}
