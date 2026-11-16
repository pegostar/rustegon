// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Real-process kill tests of the backup paths (M13a lane BH1; FR-BKP-001/002/003/004/005,
//! AC-BKP-002, AC-BKP-003, TC-BKP-001/004/005 crash variants). The process is hard-killed
//! (`Child::kill`: SIGKILL / `TerminateProcess`, no shutdown code runs) while the file system
//! shows the operation in progress, then restarted:
//! - online backup with REST writers running: every acknowledged write is in the restarted
//!   store, an interrupted backup is never listed and fails `verify`, its staging tree is gone,
//!   and a fresh backup restores the final state offline;
//! - snapshot creation (encrypted node): the snapshot is absent or complete (deep verify), the
//!   name can be created again, and the snapshot restores;
//! - PITR archiving with writers: the archive keeps continuity across the kills and a
//!   point-in-time restore to the end equals the final state;
//! - offline restore: the restoring process (this test binary re-executed as a helper running
//!   `restore_data_dir`, the function behind `rustegon backup restore`) is killed while it
//!   downloads and after the swap; `rustegond` refuses the half-restored data directory
//!   (RGN-3002), and the rerun completes it with the backup's exact state.
//!
//! The deterministic sweeps over every crash point are `rustegon-backup/tests/crash.rs`,
//! `rustegon-backup/tests/pitr.rs` and `rustegon-server/tests/backup_logical_crash.rs`.

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
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use rustegon_backup::{
    BackupId, Destination, LocalDestination, PitrTarget, RestoreKind, RestoreRequest, VerifyMode,
    list,
    pitr::{load_index, select_base},
    restore_data_dir, restore_data_dir_to_time, verify,
};
use rustegon_doc::Value as DocValue;
use rustegon_engine::EmbeddedDb;
use rustegon_mvcc::Timestamp;
use rustegon_net::{
    CertAuthority, KeyAlgorithm, TlsContext, TlsMinVersion, TrustAnchors,
    rustls::{self, pki_types::ServerName},
    tokio_rustls::TlsConnector,
};
use rustegon_sim_api::{
    Clock as _, Connection, FileSystem as _, Network, OsRng, StdFileSystem, SystemClock,
    TokioNetwork,
};
use rustegon_storage::{
    EngineOptions,
    encryption::{FileKekProvider, KekProvider},
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const START_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a test waits for an operation to show up on disk before giving up on a kill.
const WATCH_TIMEOUT: Duration = Duration::from_secs(30);
/// A password that passes the policy (test-only, not a real secret).
const PASSWORD: &str = "q7Vz!m2Lp#9Rx4Tk";
/// Test-only KEK (32 bytes of 0x07).
const KEK_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";
/// Documents rewritten by the writers.
const DOCS: i64 = 24;
const WRITERS: i64 = 3;
const DOCS_PATH: &str = "/api/v1/databases/shop/collections/acct/documents";
const BULK_PATH: &str = "/api/v1/databases/shop/collections/bulk/documents";
/// The re-executed restore helper reads its job from these variables.
const HELPER_ENV: &str = "RGN_BH1_RESTORE_HELPER";

// ---------------------------------------------------------------------------------------------
// Harness (a trimmed copy of `tests/backup.rs` with hard kills and fallible calls)
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
            "rustegond backup crash test CA",
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

    fn backups(&self) -> PathBuf {
        self.data_dir().join("backups")
    }

    fn key_file(&self) -> PathBuf {
        let path = self.root.path().join("kek.key");
        if !path.exists() {
            StdFileSystem
                .create_new_private(&path)
                .and_then(|mut f| f.append(format!("{KEK_HEX}\n").as_bytes()))
                .unwrap();
        }
        path
    }

    fn encryption_args(&self) -> Vec<String> {
        vec![
            "--set".into(),
            "storage.encryption=aes-256-gcm".into(),
            "--set".into(),
            format!("storage.encryption_key_file={}", self.key_file().display()),
        ]
    }

    /// `rustegond` on `data_dir` (default: the env's).
    fn command_on(&self, data_dir: &Path, extra: &[String]) -> Command {
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
            .arg(format!("node.data_dir={}", data_dir.display()))
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

    fn command(&self, extra: &[String]) -> Command {
        self.command_on(&self.data_dir(), extra)
    }

    fn kek(&self) -> Arc<dyn KekProvider> {
        Arc::new(FileKekProvider::open(&StdFileSystem, &self.key_file()).unwrap())
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

    /// Hard kill: no shutdown code runs, like a power cut of the process.
    fn kill(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
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

/// Runs `rustegond` expecting it to refuse to start; returns its stderr.
fn refused_start(mut cmd: Command) -> String {
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "rustegond started: {stderr}");
    stderr
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
        let body = api
            .ok(
                "POST",
                "/api/v1/auth/login",
                Some(&json!({"user": "admin", "password": PASSWORD, "delivery": "token"})),
            )
            .await;
        api.token = Some(body["sessionToken"].as_str().unwrap().to_owned());
        api
    }

    /// One request; `None` when the connection breaks (the server was killed).
    async fn try_call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Option<(u16, Value)> {
        let conn: Box<dyn Connection> = TokioNetwork.connect(self.addr).await.ok()?;
        let mut stream = TlsConnector::from(Arc::clone(&self.client))
            .connect(ServerName::try_from("localhost").unwrap(), conn)
            .await
            .ok()?;
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
        stream.write_all(request.as_bytes()).await.ok()?;
        // tokio-rustls can still hold encrypted records after `write_all` when the socket was
        // full, and reading does not send them: without this flush a large request stalls,
        // the server waiting for the rest of the body and this client for the answer (PD-105).
        stream.flush().await.ok()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.ok()?;
        let split = response.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
        let status: u16 = head.split(' ').nth(1)?.parse().ok()?;
        let mut body = response[split + 4..].to_vec();
        if head.contains("transfer-encoding: chunked") {
            body = dechunk(&body)?;
        }
        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).ok()?
        };
        Some((status, value))
    }

    async fn call(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
        self.try_call(method, path, body)
            .await
            .unwrap_or_else(|| panic!("{method} {path}: connection failed"))
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

fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = body.windows(2).position(|w| w == b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..eol]).ok()?.trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(eol + 2..eol + 2 + size)?);
        body = body.get(eol + 2 + size + 2..)?;
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The rewritten documents plus a bulk collection large enough (about 16 MiB in several SSTs)
/// that a backup, a snapshot hash or a restore download lasts long enough to be killed in.
/// Sent in requests of about 400 KB.
async fn populate(api: &Api) {
    api.ok("POST", "/api/v1/databases", Some(&json!({"name": "shop"})))
        .await;
    let documents: Vec<Value> = (0..DOCS).map(|i| json!({"_id": i, "n": 0})).collect();
    api.ok("POST", DOCS_PATH, Some(&json!({ "documents": documents })))
        .await;
    let pad = "p".repeat(2000);
    for batch in 0..40 {
        let documents: Vec<Value> = (0..200)
            .map(|i| json!({"_id": batch * 200 + i, "pad": pad}))
            .collect();
        api.ok("POST", BULK_PATH, Some(&json!({ "documents": documents })))
            .await;
    }
}

/// `n` of every rewritten document, read through the API.
async fn read_ns(api: &Api) -> BTreeMap<i64, i64> {
    let mut out = BTreeMap::new();
    for id in 0..DOCS {
        let body = api.ok("GET", &format!("{DOCS_PATH}/{id}"), None).await;
        out.insert(
            id,
            body["document"]["n"]
                .as_i64()
                .unwrap_or_else(|| panic!("{body}")),
        );
    }
    out
}

/// `n` of every rewritten document of an offline store.
fn store_ns(db: &EmbeddedDb) -> BTreeMap<i64, i64> {
    (0..DOCS)
        .map(|id| {
            let doc = db
                .get("shop", "acct", &DocValue::Int64(id))
                .unwrap()
                .unwrap();
            let Some(DocValue::Int64(n)) = doc.get("n") else {
                panic!("{doc:?}");
            };
            (id, *n)
        })
        .collect()
}

fn open_store(store: &Path, kek: Option<Arc<dyn KekProvider>>) -> EmbeddedDb {
    EmbeddedDb::open_with_kek(
        Arc::new(StdFileSystem),
        store,
        Arc::new(SystemClock::new()),
        Arc::new(OsRng),
        EngineOptions::default(),
        kek,
    )
    .unwrap()
}

/// Per document: the highest `n` acknowledged and the highest `n` sent.
#[derive(Default, Clone, Copy, Debug)]
struct Acked {
    acked: i64,
    sent: i64,
}

/// REST writers replacing their own documents (`n` increasing) until stopped or the server is
/// gone; a write counts only when its response arrived.
struct Writers {
    stop: Arc<AtomicBool>,
    log: Arc<Mutex<BTreeMap<i64, Acked>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Writers {
    fn start(api: &Api, first_n: i64) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let log: Arc<Mutex<BTreeMap<i64, Acked>>> = Arc::default();
        let tasks = (0..WRITERS)
            .map(|w| {
                let (api, stop, log) = (api.clone(), Arc::clone(&stop), Arc::clone(&log));
                tokio::spawn(async move {
                    let mut n = first_n;
                    while !stop.load(Ordering::SeqCst) {
                        n += 1;
                        for id in (w..DOCS).step_by(usize::try_from(WRITERS).unwrap()) {
                            log.lock().unwrap().entry(id).or_default().sent = n;
                            let path = format!("{DOCS_PATH}/{id}");
                            let body = json!({"_id": id, "n": n});
                            match api.try_call("PUT", &path, Some(&body)).await {
                                Some((200, _)) => {
                                    log.lock().unwrap().entry(id).or_default().acked = n;
                                }
                                Some((status, body)) => panic!("PUT {path}: {status} {body}"),
                                // The server was killed: this write is in doubt, stop.
                                None => return,
                            }
                        }
                    }
                })
            })
            .collect();
        Self { stop, log, tasks }
    }

    async fn wait_for(&self, writes: i64) {
        while self
            .log
            .lock()
            .unwrap()
            .values()
            .map(|a| a.acked)
            .sum::<i64>()
            < writes
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn stop(self) -> BTreeMap<i64, Acked> {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.tasks {
            t.await.unwrap();
        }
        self.log.lock().unwrap().clone()
    }
}

/// Every acknowledged write survived; nothing that was never sent appeared.
fn assert_writes_survived(ns: &BTreeMap<i64, i64>, log: &BTreeMap<i64, Acked>, ctx: &str) {
    for (id, a) in log {
        let n = ns[id];
        assert!(
            a.acked <= n && n <= a.sent,
            "{ctx}: doc {id} n={n}, acknowledged {}, sent {}",
            a.acked,
            a.sent
        );
    }
}

/// Polls until `cond` holds (true) or the operation ended without it (false).
fn watch(mut cond: impl FnMut() -> bool, done: &AtomicBool) -> bool {
    let deadline = Instant::now() + WATCH_TIMEOUT;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        if done.load(Ordering::SeqCst) {
            return cond();
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    false
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|r| r.filter_map(Result::ok).map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// Invariant (b) for a local destination: listed backups verify deep, others fail `verify`.
fn check_destination(root: &Path, ctx: &str) -> Vec<String> {
    let dest = LocalDestination::open(Arc::new(StdFileSystem), root).unwrap();
    let listed: Vec<String> = list(&dest)
        .unwrap()
        .iter()
        .map(|b| b.id().to_owned())
        .collect();
    for dir in entries(&root.join("backups")) {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let id = BackupId::parse(&name).unwrap();
        let verified = verify(&dest, &id, VerifyMode::Deep);
        if listed.contains(&name) {
            verified.unwrap_or_else(|e| panic!("{ctx}: listed {name} fails verify: {e}"));
        } else {
            assert!(verified.is_err(), "{ctx}: incomplete {name} passes verify");
        }
    }
    listed
}

fn restore(
    source_root: &Path,
    id: &str,
    data_dir: &Path,
    kind: RestoreKind,
    kek: Option<Arc<dyn KekProvider>>,
) -> Result<(), rustegon_common::Error> {
    let source = LocalDestination::open(Arc::new(StdFileSystem), source_root).unwrap();
    restore_data_dir(
        &(Arc::new(StdFileSystem) as Arc<dyn rustegon_sim_api::FileSystem>),
        &(Arc::new(SystemClock::new()) as Arc<dyn rustegon_sim_api::Clock>),
        &(Arc::new(OsRng) as Arc<dyn rustegon_sim_api::Rng>),
        &RestoreRequest {
            source: &source,
            id: &BackupId::parse(id).unwrap(),
            data_dir,
            kind,
            kek,
        },
    )
    .map(|_| ())
}

// ---------------------------------------------------------------------------------------------
// Online backup
// ---------------------------------------------------------------------------------------------

/// Where a kill lands in an online backup, as seen on disk.
#[derive(Debug, Clone, Copy)]
enum BackupPhase {
    /// The checkpoint is being staged or uploaded (`backup-staging/<id>` exists).
    Staging,
    /// The upload has started (`backups/<id>/` exists, no `COMPLETE` yet).
    Upload,
}

/// TC-BKP-001 crash variant (FR-BKP-001): `rustegond` is killed during an online backup while
/// REST writers run, once while the checkpoint is staged and once during the upload. After
/// each restart every acknowledged write is there, the interrupted backup is not listed and
/// fails `verify`, and the staging tree is gone; finally a fresh backup restores the final
/// state offline.
#[test]
fn tc_bkp_001_kill_rustegond_during_online_backup_with_writers() {
    let env = Env::new();
    let rt = runtime();
    // Writers are spawned outside `block_on` and keep running while the test kills.
    let _rt = rt.enter();
    let mut daemon = Daemon::spawn(env.command(&[]));
    rt.block_on(async { populate(&Api::login(&env, &daemon).await).await });
    let mut first_n = 0;
    let mut hits = 0;
    for phase in [
        BackupPhase::Staging,
        BackupPhase::Upload,
        BackupPhase::Staging,
    ] {
        let api = rt.block_on(Api::login(&env, &daemon));
        let writers = Writers::start(&api, first_n);
        rt.block_on(writers.wait_for(30));
        let done = Arc::new(AtomicBool::new(false));
        let request = {
            let (api, done) = (api.clone(), Arc::clone(&done));
            let dest = env.backups().display().to_string();
            rt.spawn(async move {
                let r = api
                    .try_call(
                        "POST",
                        "/api/v1/backups",
                        Some(&json!({ "destination": dest })),
                    )
                    .await;
                done.store(true, Ordering::SeqCst);
                r
            })
        };
        let staging = env.data_dir().join("backup-staging");
        let backups = env.backups().join("backups");
        let before: Vec<PathBuf> = entries(&backups);
        let seen = watch(
            || match phase {
                BackupPhase::Staging => !entries(&staging).is_empty(),
                BackupPhase::Upload => entries(&backups)
                    .iter()
                    .any(|d| !before.contains(d) && !d.join("COMPLETE").exists()),
            },
            &done,
        );
        daemon.kill();
        let response = rt.block_on(request).unwrap();
        let log = rt.block_on(writers.stop());
        let ctx = format!("{phase:?}");
        if seen && response.is_none() {
            hits += 1;
        }
        eprintln!("{ctx}: in progress at the kill: {seen}, response: {response:?}");

        daemon = Daemon::spawn(env.command(&[]));
        assert!(
            entries(&staging).is_empty(),
            "{ctx}: staging left after the restart"
        );
        let listed = check_destination(&env.backups(), &ctx);
        if let Some((200, body)) = &response {
            let id = body["backup"]["backupId"].as_str().unwrap();
            assert!(
                listed.iter().any(|l| l == id),
                "{ctx}: an acknowledged backup was lost"
            );
        }
        let api = rt.block_on(Api::login(&env, &daemon));
        let ns = rt.block_on(read_ns(&api));
        assert_writes_survived(&ns, &log, &ctx);
        first_n = log.values().map(|a| a.sent).max().unwrap_or(0) + 1;
    }
    assert!(hits > 0, "no kill landed inside a backup");

    // A fresh backup after the kills restores the final state.
    let (id, want) = rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        let dest = env.backups().display().to_string();
        let created = api
            .ok(
                "POST",
                "/api/v1/backups",
                Some(&json!({ "destination": dest })),
            )
            .await;
        let id = created["backup"]["backupId"].as_str().unwrap().to_owned();
        (id, read_ns(&api).await)
    });
    daemon.stop();
    let into = env.root.path().join("restored");
    restore(&env.backups(), &id, &into, RestoreKind::Backup, None).unwrap();
    assert_eq!(store_ns(&open_store(&into.join("store"), None)), want);
}

// ---------------------------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------------------------

/// TC-BKP-005 crash variant (FR-BKP-003, AC-BKP-003): an encrypted `rustegond` is killed while
/// it creates a snapshot (staging tree on disk). After the restart the snapshot is absent or
/// complete (deep verify), the staging tree is gone, the name can be created again (or is
/// taken by the complete snapshot), and the snapshot restores offline with the KEK.
#[test]
fn tc_bkp_005_kill_rustegond_during_snapshot_creation() {
    let env = Env::new();
    let rt = runtime();
    let enc = env.encryption_args();
    let mut daemon = Daemon::spawn(env.command(&enc));
    rt.block_on(async { populate(&Api::login(&env, &daemon).await).await });
    let snapshots = env.data_dir().join("snapshots");
    let mut hits = 0;
    for round in 0..2 {
        let name = format!("snap-{round}");
        let api = rt.block_on(Api::login(&env, &daemon));
        let done = Arc::new(AtomicBool::new(false));
        let request = {
            let (api, done, name) = (api.clone(), Arc::clone(&done), name.clone());
            rt.spawn(async move {
                let r = api
                    .try_call("POST", "/api/v1/snapshots", Some(&json!({ "name": name })))
                    .await;
                done.store(true, Ordering::SeqCst);
                r
            })
        };
        let staging = snapshots.join(".staging").join(&name);
        let seen = watch(|| staging.exists(), &done);
        daemon.kill();
        let response = rt.block_on(request).unwrap();
        if seen && response.is_none() {
            hits += 1;
        }
        let ctx = format!("{name}: in progress {seen}, response {response:?}");
        eprintln!("{ctx}");

        daemon = Daemon::spawn(env.command(&enc));
        assert!(!staging.exists(), "{ctx}: staging left after the restart");
        let listed = check_destination(&snapshots, &ctx);
        if matches!(response, Some((200, _))) {
            assert!(
                listed.contains(&name),
                "{ctx}: an acknowledged snapshot was lost"
            );
        }
        let api = rt.block_on(Api::login(&env, &daemon));
        let (status, body) =
            rt.block_on(api.call("POST", "/api/v1/snapshots", Some(&json!({ "name": name }))));
        if listed.contains(&name) {
            assert_eq!(status, 409, "{ctx}: {body}");
        } else {
            assert_eq!(status, 200, "{ctx}: {body}");
        }
    }
    assert!(hits > 0, "no kill landed inside a snapshot creation");
    let want = rt.block_on(async { read_ns(&Api::login(&env, &daemon).await).await });
    daemon.stop();
    restore(
        &snapshots,
        "snap-1",
        &env.data_dir(),
        RestoreKind::Snapshot,
        Some(env.kek()),
    )
    .unwrap();
    assert_eq!(
        store_ns(&open_store(&env.data_dir().join("store"), Some(env.kek()))),
        want
    );
}

// ---------------------------------------------------------------------------------------------
// PITR archiving
// ---------------------------------------------------------------------------------------------

fn pitr_config(env: &Env) -> Vec<String> {
    let path = env.root.path().join("pitr.toml");
    // A literal TOML string: Windows paths keep their backslashes.
    std::fs::write(
        &path,
        format!(
            "[backup.pitr]\nenabled = true\ndestination = '{}'\nsegment_interval_secs = 1\n",
            env.backups().display()
        ),
    )
    .unwrap();
    vec!["--config".into(), path.display().to_string()]
}

fn now_ts() -> Timestamp {
    let wall = SystemClock::new()
        .wall()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    Timestamp::new(u64::try_from(wall.as_nanos()).unwrap(), 0)
}

/// All archived segment files (any timeline).
fn archived_files(env: &Env) -> Vec<PathBuf> {
    entries(&env.backups().join("pitr"))
        .iter()
        .flat_map(|tl| entries(&tl.join("segments")))
        .collect()
}

/// TC-BKP-004 crash variant (FR-BKP-002, FR-BKP-004, AC-BKP-002): `rustegond` with PITR
/// archiving (1 s segments) and REST writers is killed twice while an archiver pass copies
/// segments. After each restart acknowledged writes are there and archiving resumes; at the
/// end the archive has no continuity break and a point-in-time restore to the end equals the
/// final state.
#[test]
fn tc_bkp_004_kill_rustegond_during_pitr_archiving() {
    let env = Env::new();
    let rt = runtime();
    // Writers are spawned outside `block_on` and keep running while the test kills.
    let _rt = rt.enter();
    let config = pitr_config(&env);
    let mut daemon = Daemon::spawn(env.command(&config));
    rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        populate(&api).await;
        let dest = env.backups().display().to_string();
        api.ok(
            "POST",
            "/api/v1/backups",
            Some(&json!({ "destination": dest })),
        )
        .await;
    });
    let mut first_n = 0;
    let mut hits = 0;
    for round in 0..2 {
        let api = rt.block_on(Api::login(&env, &daemon));
        let writers = Writers::start(&api, first_n);
        rt.block_on(writers.wait_for(30));
        // Kill as soon as a pass adds a file to the archive (a segment copy in progress or
        // just renamed into place, its index entry not yet written).
        let before = archived_files(&env).len();
        let never = AtomicBool::new(false);
        let seen = watch(|| archived_files(&env).len() > before, &never);
        daemon.kill();
        hits += usize::from(seen);
        let log = rt.block_on(writers.stop());
        let ctx = format!("round {round}: pass seen {seen}");
        eprintln!("{ctx}");
        daemon = Daemon::spawn(env.command(&config));
        let api = rt.block_on(Api::login(&env, &daemon));
        assert_writes_survived(&rt.block_on(read_ns(&api)), &log, &ctx);
        first_n = log.values().map(|a| a.sent).max().unwrap_or(0) + 1;
    }
    assert!(hits > 0, "no kill landed during archiving");

    // More writes after the last restart, then the target T after the last acknowledged one.
    let want = rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        let writers = Writers::start(&api, first_n);
        writers.wait_for(30).await;
        writers.stop().await;
        read_ns(&api).await
    });
    std::thread::sleep(Duration::from_millis(20));
    let t = now_ts();
    std::thread::sleep(Duration::from_millis(20));
    // The graceful stop's final pass seals and archives the end of the log.
    daemon.stop();

    let dest = LocalDestination::open(Arc::new(StdFileSystem), env.backups()).unwrap();
    let base = select_base(&dest, t).unwrap();
    let timeline = &base.pitr.as_ref().unwrap().timeline;
    let index = load_index(&dest, timeline).unwrap().unwrap();
    assert!(
        index.breaks.is_empty(),
        "continuity broken: {:?}",
        index.breaks
    );
    for seg in &index.segments {
        let key = format!("pitr/{timeline}/segments/{:020}.rlog", seg.id);
        assert_eq!(
            dest.size(&key).unwrap(),
            Some(seg.size),
            "segment {}",
            seg.id
        );
    }
    let into = env.root.path().join("pitr-restored");
    restore_data_dir_to_time(
        &(Arc::new(StdFileSystem) as Arc<dyn rustegon_sim_api::FileSystem>),
        &(Arc::new(SystemClock::new()) as Arc<dyn rustegon_sim_api::Clock>),
        &(Arc::new(OsRng) as Arc<dyn rustegon_sim_api::Rng>),
        &RestoreRequest {
            source: &dest,
            id: &BackupId::parse(&base.backup_id).unwrap(),
            data_dir: &into,
            kind: RestoreKind::Backup,
            kek: None,
        },
        PitrTarget {
            archive: &dest,
            ts: t,
        },
    )
    .unwrap();
    assert_eq!(store_ns(&open_store(&into.join("store"), None)), want);
}

// ---------------------------------------------------------------------------------------------
// Offline restore
// ---------------------------------------------------------------------------------------------

/// Helper process for [`tc_bkp_001_kill_offline_restore_and_rerun`]: when started with
/// [`HELPER_ENV`] = `<backups root>|<backup id>|<data dir>`, runs the offline restore (the code
/// of `rustegon backup restore`) and exits; otherwise does nothing.
#[test]
fn restore_helper_process() {
    let Ok(job) = std::env::var(HELPER_ENV) else {
        return;
    };
    let parts: Vec<&str> = job.split('|').collect();
    restore(
        Path::new(parts[0]),
        parts[1],
        Path::new(parts[2]),
        RestoreKind::Backup,
        None,
    )
    .unwrap();
}

fn spawn_restore(root: &Path, id: &str, into: &Path) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "restore_helper_process", "--nocapture"])
        .env(
            HELPER_ENV,
            format!("{}|{id}|{}", root.display(), into.display()),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// FR-BKP-001 / TC-BKP-001 crash variant: the offline restore process is killed while it
/// downloads (`store.restoring` on disk) and again after the swap (`store` in place, revert
/// running or done). Each time `rustegond` refuses the data directory (RGN-3002) instead of
/// serving or re-creating a half-restored store; the rerun of the same restore completes it
/// with the backup's exact state, and the node then starts on it.
#[test]
fn tc_bkp_001_kill_offline_restore_and_rerun() {
    let env = Env::new();
    let rt = runtime();
    let daemon = Daemon::spawn(env.command(&[]));
    let (id, want) = rt.block_on(async {
        let api = Api::login(&env, &daemon).await;
        populate(&api).await;
        let writers = Writers::start(&api, 0);
        writers.wait_for(30).await;
        writers.stop().await;
        let dest = env.backups().display().to_string();
        let created = api
            .ok(
                "POST",
                "/api/v1/backups",
                Some(&json!({ "destination": dest })),
            )
            .await;
        let id = created["backup"]["backupId"].as_str().unwrap().to_owned();
        (id, read_ns(&api).await)
    });
    daemon.stop();

    let into = env.root.path().join("restored");
    let mut refusals = 0;
    for marker in ["store.restoring", "store"] {
        let mut child = spawn_restore(&env.backups(), &id, &into);
        let exited = AtomicBool::new(false);
        let seen = watch(
            || {
                if child.try_wait().unwrap().is_some() {
                    exited.store(true, Ordering::SeqCst);
                }
                into.join(marker).exists()
            },
            &exited,
        );
        let _ = child.kill();
        child.wait().unwrap();
        let journal = into.join("restore-in-progress.json").exists();
        eprintln!("kill at {marker}: seen {seen}, journal left {journal}");
        if journal {
            // A started node would serve or re-create a half-restored store: refused.
            let stderr = refused_start(env.command_on(&into, &[]));
            assert!(
                stderr.contains("RGN-3002") && stderr.contains("restore"),
                "{stderr}"
            );
            refusals += 1;
        }
    }
    assert!(refusals > 0, "no kill interrupted the restore");
    let status = spawn_restore(&env.backups(), &id, &into).wait().unwrap();
    assert!(status.success(), "the rerun failed");
    assert!(!into.join("restore-in-progress.json").exists());
    assert_eq!(store_ns(&open_store(&into.join("store"), None)), want);
    // The finished data directory is an ordinary one.
    let daemon = Daemon::spawn(env.command_on(&into, &[]));
    let got = rt.block_on(async { read_ns(&Api::login(&env, &daemon).await).await });
    daemon.stop();
    assert_eq!(got, want);
}
