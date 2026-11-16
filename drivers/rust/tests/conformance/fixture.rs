// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! A single-node `rustegond` for integration tests (PD-072, TC-DRV-RS-008): `rustegon init` into
//! a fresh temporary directory, then `rustegond --stop-on-stdin-eof`, which prints
//! `rustegond ready grpc=… http=…` and stops gracefully when stdin closes — also when this test
//! process exits, so no node outlives the run. Binaries come from `RUSTEGON_BIN_DIR` (default
//! `<repo>/target/debug`).
//!
//! The process is driven with `std::process` (not Tokio) so one node can serve tests running on
//! different Tokio runtimes.

use std::{
    io::{BufRead as _, BufReader},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex, Weak, mpsc},
    time::Duration,
};

/// The first administrator created by the first start (PD-054).
pub const ADMIN_USER: &str = "admin";
/// CN of the client certificate issued by `init --client-user`; it logs in as `x509:CN=<name>`.
pub const CLIENT_CERT_USER: &str = "conf_x509";
const READY: &str = "rustegond ready ";

pub struct Server {
    root: PathBuf,
    tls: bool,
    pub grpc: String,
    pub admin_password: String,
    child: Mutex<Option<(Child, ChildStdin)>>,
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

/// The repository root (directory with `Cargo.toml` and `proto/`).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The binary directory, or why there is none.
pub fn find_binaries() -> Result<PathBuf, String> {
    let dir = std::env::var_os("RUSTEGON_BIN_DIR")
        .map_or_else(|| repo_root().join("target").join("debug"), PathBuf::from);
    for n in ["rustegon", "rustegond"] {
        if !dir.join(exe(n)).is_file() {
            return Err(format!(
                "{} not found in {} (build with `cargo build -p rustegond -p rustegon-cli` or set RUSTEGON_BIN_DIR)",
                exe(n),
                dir.display()
            ));
        }
    }
    Ok(dir)
}

/// A process that sees only the flags given here, not an operator's `RUSTEGON_*` environment.
fn command(path: &Path) -> Command {
    let mut c = Command::new(path);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("RUSTEGON_")
        {
            c.env_remove(k);
        }
    }
    c
}

fn random_password() -> String {
    // 24 uniform base62 characters pass the password policy (as the server's own generator).
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut raw = [0u8; 24];
    getrandom::fill(&mut raw).expect("os random");
    raw.iter()
        .map(|b| char::from(ALPHABET[usize::from(*b) % 62]))
        .collect()
}

impl Server {
    /// Initializes and starts a node: TLS (`init --tls --client-user`) or plain text (the
    /// ADR-034 default of a single node).
    pub fn start(bin_dir: &Path, tls: bool) -> Result<Self, String> {
        let mut tag = [0u8; 6];
        getrandom::fill(&mut tag).map_err(|e| e.to_string())?;
        // Under the test target directory, not the system temp; removed when the node stops
        // (a killed test process can leave one behind there, never in the system temp).
        let root = nodes_dir().join(rustegon::codec::to_hex(&tag));
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let s = Self {
            root,
            tls,
            grpc: String::new(),
            admin_password: random_password(),
            child: Mutex::new(None),
        };
        std::fs::write(s.password_file(), &s.admin_password).map_err(|e| e.to_string())?;
        let mut init = command(&bin_dir.join(exe("rustegon")));
        init.args(["init", "--data-dir"])
            .arg(s.data_dir())
            .args([
                "--grpc-port",
                "0",
                "--http-port",
                "0",
                "--admin-password-file",
            ])
            .arg(s.password_file())
            .arg("--non-interactive");
        if tls {
            init.args(["--tls", "--client-user", CLIENT_CERT_USER]);
        }
        let out = init
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("rustegon init: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "rustegon init failed: {}\n{}{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let mut s = s;
        let line = s.launch(bin_dir, &[])?;
        for kv in line.split_whitespace() {
            if let Some(v) = kv.strip_prefix("grpc=") {
                s.grpc = v.to_owned();
            }
        }
        Ok(s)
    }

    fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }

    fn password_file(&self) -> PathBuf {
        self.root.join("admin.pw")
    }

    pub fn tls(&self) -> bool {
        self.tls
    }

    pub fn ca_file(&self) -> PathBuf {
        self.data_dir().join("certs").join("ca.crt")
    }

    pub fn client_cert_file(&self) -> PathBuf {
        self.data_dir()
            .join("certs")
            .join(format!("client-{CLIENT_CERT_USER}"))
            .join("client.crt")
    }

    pub fn client_key_file(&self) -> PathBuf {
        self.data_dir()
            .join("certs")
            .join(format!("client-{CLIENT_CERT_USER}"))
            .join("client.key")
    }

    fn launch(&self, bin_dir: &Path, extra: &[&str]) -> Result<String, String> {
        let mut c = command(&bin_dir.join(exe("rustegond")));
        c.arg("--config")
            .arg(self.data_dir().join("rustegon.toml"))
            .arg("--admin-password-file")
            .arg(self.password_file())
            .arg("--stop-on-stdin-eof")
            // The smallest iteration count the configuration accepts: fast logins in debug builds.
            .args([
                "--set",
                "auth.scram_iterations=100000",
                "--set",
                "log.stderr=false",
            ])
            // One node serves every test of a run: the suite logs in (and fails logins on
            // purpose) far more often than the default rate limits allow. 0 = unlimited (PD-098).
            .args([
                "--set",
                "rate_limit.auth_per_ip_per_min=0",
                "--set",
                "rate_limit.auth_per_user_per_min=0",
                "--set",
                "rate_limit.session_per_user_per_min=0",
                "--set",
                "rate_limit.admin_per_user_per_min=0",
            ]);
        if self.tls {
            // Client certificates are requested (and verified) when presented, for X.509.
            c.args(["--set", "tls.client_cert=optional"]);
        }
        c.args(extra);
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("rustegond: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut sent = false;
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if !sent && let Some(rest) = line.strip_prefix(READY) {
                    let _ = tx.send(rest.to_owned());
                    sent = true;
                }
            }
        });
        match rx.recv_timeout(Duration::from_secs(120)) {
            Ok(line) => {
                *self.child.lock().unwrap() = Some((child, stdin));
                Ok(line)
            }
            Err(_) => {
                let _ = child.kill();
                Err("rustegond did not become ready".into())
            }
        }
    }

    /// Stops the node (stdin EOF, killed after 30 s) and removes its directory.
    pub fn stop(&self) {
        if let Some((mut child, stdin)) = self.child.lock().unwrap().take() {
            drop(stdin);
            for _ in 0..300 {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        // A file still held open (antivirus, slow handle release) may leave the directory.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `<target>/tmp/rustegon-nodes`: the data directories of the test nodes.
fn nodes_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("rustegon-nodes")
}

/// The TLS node shared by the tests running at the same time, or why there is none (skip; fail
/// under `CI=true`). The node stops and its directory is removed when the last test using it
/// drops its handle (with nextest, at the end of each test process).
pub fn shared_tls() -> Result<Arc<Server>, String> {
    static NODE: Mutex<Weak<Server>> = Mutex::new(Weak::new());
    let mut slot = NODE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(s) = slot.upgrade() {
        return Ok(s);
    }
    let s = Arc::new(Server::start(&find_binaries()?, true)?);
    *slot = Arc::downgrade(&s);
    Ok(s)
}

/// `Err(reason)` → skip the test (or panic under `CI=true`).
pub fn skip_or_fail(reason: &str) {
    assert!(
        std::env::var("CI").as_deref() != Ok("true"),
        "no server: {reason}"
    );
    eprintln!("SKIPPED: no server: {reason}");
}
