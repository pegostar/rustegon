// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegon init`: prepares a single node (FR-TLS-002, FR-SEC-003, FR-INS-004, security.md
//! §2.2/§5/§6, PD-058, PD-151).
//!
//! On a terminal (or with `--interactive`) `init` is the FR-INS-004 wizard: it asks for every
//! setting that no flag gave (data directory, configuration file, listen address and ports,
//! administrator password, TLS on or off and then generate or import, encryption at rest),
//! prints a summary and writes nothing before the operator confirms it. With
//! `--non-interactive`, or when stdin is not a terminal, it never asks: flags and defaults only.
//!
//! TLS is opt-in on a single node (ADR-034): `--tls`, implied by the `--import-*` flags and by
//! `--client-user`; the wizard asks, default No. Without it no CA or certificate is written and
//! the node serves plain text.
//!
//! It writes, and refuses to run when any of them already exists (no partial overwrite of an
//! initialized node):
//! - TLS, generated: `<data_dir>/ca/ca.crt`, `ca.key` (the cluster CA, 10 years; kept out of the
//!   directory the server reads so that it can be moved offline) and `<data_dir>/certs/ca.crt`,
//!   `node.crt`, `node.key` (1 year, SAN = `localhost`, `127.0.0.1`, `::1`, the listen address
//!   unless unspecified, and `--host`);
//! - TLS, imported (`--import-ca-cert`, `--import-cert`, `--import-key`): the three PEM files,
//!   validated as the server validates them (parse, unexpired leaf, key matching the leaf),
//!   copied into `<data_dir>/certs` (the key owner-only);
//! - optionally `<data_dir>/certs/client-<user>/` with a client certificate (`--client-user`,
//!   generated CA only);
//! - encryption at rest (`--encryption file:<path>`): a new owner-only KEK file of 64 hex digits
//!   (security.md §6), never overwritten;
//! - the configuration file (default `<data_dir>/rustegon.toml`): `node.data_dir`, `[listen]`,
//!   with TLS `security.tls = true` and `security.certs_dir`, and, with encryption, `storage.encryption` /
//!   `storage.encryption_key_file`; every path absolute so the file works from any directory.
//!
//! **First administrator.** The store and its users belong to `rustegond`, which runs the one
//! bootstrap implementation (PD-054) on its first start; `init` decides only where the
//! password comes from (PD-058):
//! - `--admin-password-file` / `RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE`: policy-checked now, then
//!   passed to `rustegond --admin-password-file` (printed as the next step);
//! - the wizard: asked twice without echo on a terminal, policy-checked, written owner-only to
//!   `<data_dir>/admin-password` and passed the same way (delete it after the first start);
//! - otherwise `rustegond` generates the password on its first start into
//!   `<data_dir>/initial-admin-password` (owner-only, `must_change_password`) and prints only
//!   that path. No password is ever printed by `init`;
//! - `--turnkey` (ADR-036, the MSI/DEB/RPM first install): `security.turnkey_admin = true`, so
//!   the first start creates `admin` with the documented password `admin`, flagged
//!   `must_change_password` and accepted only while every listener is on loopback (the server
//!   refuses to start otherwise). Never asks; refuses a non-loopback `--listen` and an admin
//!   password file; prints a warning.

use std::{
    fmt::{Display, Write as _},
    io::{self, BufRead, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::UNIX_EPOCH,
};

use crate::{
    cert::{self, CA_CERT, CaAlgorithm},
    output::{CliError, CliResult, err, fail, io_err, out},
    secrets,
};
use clap::Args;
use rustegon_net::{
    TrustAnchors, crypto_provider, not_after_unix, parse_certificates, parse_private_key,
    rustls::sign::CertifiedKey,
};
use rustegon_security::authn::{
    SecretString,
    bootstrap::{DEFAULT_ADMIN_USER, TURNKEY_ADMIN_PASSWORD},
    password::{GENERATED_LENGTH, check_strength},
    secret,
};
use rustegon_sim_api::{Clock as _, OsRng, Rng as _, SystemClock};
use zeroize::Zeroizing;

/// Environment variable naming the first admin's password file (as for `rustegond`).
pub const ADMIN_PASSWORD_FILE_ENV: &str = "RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE";
/// File holding a password entered in the wizard.
pub const PROMPTED_PASSWORD_FILE: &str = "admin-password";
/// Name of the configuration file written by default.
pub const CONFIG_FILE: &str = "rustegon.toml";
/// Default data directory.
const DEFAULT_DATA_DIR: &str = "rustegon-data";
/// Default gRPC and REST ports (protocol.md §1).
const DEFAULT_GRPC_PORT: u16 = 7700;
const DEFAULT_HTTP_PORT: u16 = 7780;
/// Largest PEM file accepted for import.
const MAX_PEM_FILE: u64 = 1 << 20;
/// KEK length of the `file` provider (security.md §6: 32 bytes, written as 64 hex digits).
const KEK_BYTES: usize = 32;

/// `rustegon init`.
///
/// Settings the wizard asks for are `Option`s without a clap default, so that "not given" is
/// distinguishable from "given with the default value"; the defaults are applied by the
/// accessors below and are the M4 defaults (backward compatible).
#[derive(Debug, Clone, Args)]
// Independent command-line switches, not a state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct InitArgs {
    /// Data directory of the node [default: rustegon-data].
    #[arg(long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,
    /// Configuration file to write (default `<data_dir>/rustegon.toml`).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Listen address of the client listeners [default: 127.0.0.1].
    #[arg(long, value_name = "IP")]
    pub listen: Option<IpAddr>,
    /// gRPC port (protocol.md §1; 0 = any free port) [default: 7700].
    #[arg(long)]
    pub grpc_port: Option<u16>,
    /// REST port (protocol.md §1; 0 = any free port) [default: 7780].
    #[arg(long)]
    pub http_port: Option<u16>,
    /// Enable TLS on the client listeners: generate a CA and node certificate (or import them
    /// with `--import-*`) and write `security.tls = true`. Without it the node serves plain
    /// text (ADR-034).
    #[arg(long)]
    pub tls: bool,
    /// Additional node address for the certificate SAN (DNS name or IP; repeatable).
    #[arg(long = "host", value_name = "HOST")]
    pub hosts: Vec<String>,
    /// Common name of the node certificate.
    #[arg(long, default_value = "node1")]
    pub node_name: String,
    /// Key algorithm of the CA.
    #[arg(long, value_enum, default_value_t)]
    pub ca_algorithm: CaAlgorithm,
    /// Also issue a client certificate for this user (X.509 login as `x509:CN=<user>`).
    #[arg(long, value_name = "USER")]
    pub client_user: Option<String>,
    /// File with the first administrator's password (else
    /// `RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE`, else asked by the wizard, else generated by
    /// `rustegond` at its first start).
    #[arg(long, value_name = "PATH")]
    pub admin_password_file: Option<PathBuf>,
    /// Import an existing CA certificate (PEM) instead of generating a CA; requires
    /// `--import-cert` and `--import-key`.
    #[arg(
        long,
        value_name = "PATH",
        requires_all = ["import_cert", "import_key"],
        conflicts_with = "client_user"
    )]
    pub import_ca_cert: Option<PathBuf>,
    /// Import an existing node certificate chain (PEM, leaf first).
    #[arg(long, value_name = "PATH", requires_all = ["import_ca_cert", "import_key"])]
    pub import_cert: Option<PathBuf>,
    /// Import the private key (PEM) of `--import-cert`.
    #[arg(long, value_name = "PATH", requires_all = ["import_ca_cert", "import_cert"])]
    pub import_key: Option<PathBuf>,
    /// Encryption at rest: `none`, or `file:<path>` to create a new KEK file there and enable
    /// `aes-256-gcm` [default without the wizard: none].
    #[arg(long, value_name = "none|file:PATH")]
    pub encryption: Option<Encryption>,
    /// Run the wizard even when stdin is not a terminal (answers are read line by line from
    /// stdin, for scripted set-ups).
    #[arg(long, conflicts_with = "non_interactive")]
    pub interactive: bool,
    /// Never ask: flags and defaults only.
    #[arg(long)]
    pub non_interactive: bool,
    /// Turnkey install (ADR-036, used by the MSI, DEB and RPM): the first start creates the
    /// local administrator `admin` with the password `admin`, which must be changed at first
    /// login and is accepted only while every listener is on loopback. Implies
    /// `--non-interactive`.
    #[arg(long, conflicts_with_all = ["admin_password_file", "interactive"])]
    pub turnkey: bool,
    /// Directory of the log files (`log.dir`; default `<data_dir>/logs`).
    #[arg(long, value_name = "DIR")]
    pub log_dir: Option<PathBuf>,
}

impl InitArgs {
    fn data_dir(&self) -> &Path {
        self.data_dir
            .as_deref()
            .unwrap_or(Path::new(DEFAULT_DATA_DIR))
    }

    fn listen(&self) -> IpAddr {
        self.listen.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    fn grpc_port(&self) -> u16 {
        self.grpc_port.unwrap_or(DEFAULT_GRPC_PORT)
    }

    fn http_port(&self) -> u16 {
        self.http_port.unwrap_or(DEFAULT_HTTP_PORT)
    }

    /// Whether TLS is on: `--tls`, or a flag that needs certificates.
    fn tls_on(&self) -> bool {
        self.tls || self.import_ca_cert.is_some() || self.client_user.is_some()
    }

    /// The key file to create, if encryption at rest is enabled.
    fn kek_file(&self) -> Option<&Path> {
        match &self.encryption {
            Some(Encryption::File(path)) => Some(path),
            _ => None,
        }
    }
}

/// `--encryption`: storage encryption at rest (security.md §6, PD-057).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encryption {
    /// Plaintext store (`storage.encryption = "none"`).
    None,
    /// `aes-256-gcm` with a new KEK file at this path (`file` provider).
    File(PathBuf),
}

impl FromStr for Encryption {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "none" {
            return Ok(Self::None);
        }
        match s.strip_prefix("file:") {
            Some(path) if !path.is_empty() => Ok(Self::File(path.into())),
            _ => Err("expected `none` or `file:<path>`".into()),
        }
    }
}

/// Line-based question/answer channel of the wizard (FR-INS-004).
///
/// Generic over the reader and writer so that tests drive the wizard with scripted answers
/// and no terminal. Questions go to `output` (stderr in the binary: stdout carries only the
/// result lines). Secrets are read without echo only on a real terminal (`terminal`);
/// otherwise they are one input line like any other answer, and never written back.
pub struct Prompter<R, W> {
    input: R,
    output: W,
    terminal: bool,
}

impl<R: BufRead, W: Write> Prompter<R, W> {
    /// A prompter reading answers from `input` and writing questions to `output`.
    pub fn new(input: R, output: W, terminal: bool) -> Self {
        Self {
            input,
            output,
            terminal,
        }
    }

    fn write(&mut self, text: &str) -> CliResult<()> {
        self.output
            .write_all(text.as_bytes())
            .and_then(|()| self.output.flush())
            .map_err(|e| io_err("terminal", &e))
    }

    fn say(&mut self, line: &str) -> CliResult<()> {
        self.write(&format!("{line}\n"))
    }

    /// One input line without its line ending; the end of the input aborts the wizard.
    fn read_line(&mut self) -> CliResult<Zeroizing<String>> {
        let mut line = Zeroizing::new(String::new());
        let n = self
            .input
            .read_line(&mut line)
            .map_err(|e| io_err("stdin", &e))?;
        if n == 0 {
            return fail(
                "init aborted: the input ended before the wizard finished; nothing was written",
            );
        }
        let len = line.trim_end_matches(['\r', '\n']).len();
        line.truncate(len);
        Ok(line)
    }

    /// Asks `question`; an empty answer takes `default`. Without a default the question is
    /// repeated until the answer is not empty.
    fn ask(&mut self, question: &str, default: &str) -> CliResult<String> {
        loop {
            if default.is_empty() {
                self.write(&format!("{question}: "))?;
            } else {
                self.write(&format!("{question} [{default}]: "))?;
            }
            let answer = self.read_line()?;
            let answer = answer.trim();
            if !answer.is_empty() {
                return Ok(answer.to_owned());
            }
            if !default.is_empty() {
                return Ok(default.to_owned());
            }
        }
    }

    /// Asks until the answer parses.
    fn ask_parsed<T>(&mut self, question: &str, default: &str) -> CliResult<T>
    where
        T: FromStr,
        T::Err: Display,
    {
        loop {
            let answer = self.ask(question, default)?;
            match answer.parse() {
                Ok(value) => return Ok(value),
                Err(e) => self.say(&format!("  invalid answer `{answer}`: {e}"))?,
            }
        }
    }

    /// A yes/no question.
    fn confirm(&mut self, question: &str, default: bool) -> CliResult<bool> {
        let hint = if default { "Y/n" } else { "y/N" };
        loop {
            let answer = self.ask(question, hint)?.to_ascii_lowercase();
            match answer.as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ if answer == hint.to_ascii_lowercase() => return Ok(default),
                _ => self.say("  answer y or n")?,
            }
        }
    }

    /// A secret: without echo on a terminal, else one input line.
    fn secret(&mut self, label: &str) -> CliResult<SecretString> {
        let value = if self.terminal {
            Zeroizing::new(rpassword::prompt_password(label).map_err(|e| io_err("terminal", &e))?)
        } else {
            self.write(label)?;
            self.read_line()?
        };
        Ok(secret(value.as_str()))
    }
}

/// How the first administrator gets its password.
enum AdminSecret {
    /// An operator file, already checked.
    File(PathBuf),
    /// A password entered in the wizard, to be written to `<data_dir>/admin-password`.
    Prompted(SecretString),
    /// Generated by `rustegond` at its first start.
    Generated,
    /// The turnkey `admin`/`admin` account (ADR-036), created by `rustegond` at its first start.
    Turnkey,
}

/// Where the node certificate comes from.
enum Tls {
    /// No TLS: plain-text listeners (the single-node default, ADR-034).
    Off,
    /// A new CA and node certificate.
    Generate,
    /// Validated PEM files, copied as read (no second read between check and copy).
    Import {
        ca: Zeroizing<Vec<u8>>,
        cert: Zeroizing<Vec<u8>>,
        key: Zeroizing<Vec<u8>>,
        not_after_unix: i64,
    },
}

fn absolute(path: &Path) -> CliResult<PathBuf> {
    std::path::absolute(path).map_err(|e| io_err(path.display(), &e))
}

fn check_policy(password: &SecretString, source: &str) -> CliResult<()> {
    check_strength(password.expose(), DEFAULT_ADMIN_USER)
        .map_err(|e| CliError(format!("{source}: {e}")))
}

fn admin_secret<R: BufRead, W: Write>(
    args: &InitArgs,
    prompter: Option<&mut Prompter<R, W>>,
) -> CliResult<AdminSecret> {
    if args.turnkey {
        return Ok(AdminSecret::Turnkey);
    }
    let file = args
        .admin_password_file
        .clone()
        .or_else(|| std::env::var_os(ADMIN_PASSWORD_FILE_ENV).map(PathBuf::from));
    if let Some(file) = file {
        let password = secrets::read_secret_file(&file)?;
        check_policy(&password, &file.display().to_string())?;
        return Ok(AdminSecret::File(absolute(&file)?));
    }
    let Some(p) = prompter else {
        return Ok(AdminSecret::Generated);
    };
    p.say(&format!(
        "Password of the first administrator `{DEFAULT_ADMIN_USER}`: at least 12 characters, \
         checked with the server's policy (empty: `rustegond` generates one at its first start)."
    ))?;
    loop {
        let password = p.secret("Password: ")?;
        if password.expose().is_empty() {
            return Ok(AdminSecret::Generated);
        }
        // The server's own estimator (security.md §2, PD-047): a password `init` accepts is
        // one the bootstrap accepts.
        if let Err(e) = check_policy(&password, "password") {
            p.say(&format!("  {e}"))?;
            continue;
        }
        let again = p.secret("Repeat: ")?;
        if again.expose() != password.expose() {
            p.say("  the passwords do not match")?;
            continue;
        }
        return Ok(AdminSecret::Prompted(password));
    }
}

/// Default KEK path: `secrets/kek.key` beside the configuration file (the layout of
/// linux.md §1 and windows.md §1).
fn default_kek_file(args: &InitArgs) -> CliResult<PathBuf> {
    let config = Layout::new(args)?.config;
    Ok(config
        .parent()
        .unwrap_or(Path::new(""))
        .join("secrets")
        .join("kek.key"))
}

/// The wizard: fills every setting that no flag gave (FR-INS-004). The administrator password
/// is asked later by [`admin_secret`], after the checks that need no secret.
fn ask_missing<R: BufRead, W: Write>(args: &mut InitArgs, p: &mut Prompter<R, W>) -> CliResult<()> {
    p.say("rustegon init: press Enter to take the value in brackets; nothing is written before the final confirmation.")?;
    if args.data_dir.is_none() {
        args.data_dir = Some(p.ask("Data directory", DEFAULT_DATA_DIR)?.into());
    }
    if args.config.is_none() {
        let default = absolute(args.data_dir())?.join(CONFIG_FILE);
        args.config = Some(
            p.ask("Configuration file", &default.display().to_string())?
                .into(),
        );
    }
    // An initialized node is refused before any further question.
    refuse_existing(&Layout::new(args)?)?;
    if args.listen.is_none() {
        args.listen = Some(p.ask_parsed(
            "Listen address (IP; 0.0.0.0 = every interface)",
            &Ipv4Addr::LOCALHOST.to_string(),
        )?);
    }
    if args.grpc_port.is_none() {
        args.grpc_port = Some(p.ask_parsed("gRPC port", &DEFAULT_GRPC_PORT.to_string())?);
    }
    if args.http_port.is_none() {
        args.http_port = Some(p.ask_parsed("REST and GUI port", &DEFAULT_HTTP_PORT.to_string())?);
    }
    if !args.tls_on() {
        args.tls = p.confirm(
            "Enable TLS on the client listeners? (No = plain text; TLS is always on in cluster \
             mode)",
            false,
        )?;
    }
    if args.tls_on() && args.import_cert.is_none() {
        let import = loop {
            let answer = p.ask(
                "TLS: generate a new CA and node certificate, or import existing PEM files? \
                 (generate/import)",
                "generate",
            )?;
            match answer.to_ascii_lowercase().as_str() {
                "generate" | "g" => break false,
                "import" | "i" => break true,
                _ => p.say("  answer generate or import")?,
            }
        };
        if import {
            args.import_ca_cert = Some(p.ask("CA certificate file (PEM)", "")?.into());
            args.import_cert = Some(p.ask("Node certificate file (PEM, leaf first)", "")?.into());
            args.import_key = Some(p.ask("Node private key file (PEM)", "")?.into());
        } else if args.hosts.is_empty() {
            let hosts = p.ask(
                "Extra host names or IPs for the node certificate, comma separated (- for none)",
                "-",
            )?;
            args.hosts = hosts
                .split(',')
                .map(str::trim)
                .filter(|h| !h.is_empty() && *h != "-")
                .map(str::to_owned)
                .collect();
        }
    }
    if args.encryption.is_none() {
        // Default on, as windows.md §2 step 4.
        args.encryption = Some(
            if p.confirm("Encrypt data at rest with a new key file?", true)? {
                let default = default_kek_file(args)?;
                Encryption::File(
                p.ask(
                    "Key file to create (keep a copy offline: without it the data cannot be read)",
                    &default.display().to_string(),
                )?
                .into(),
            )
            } else {
                Encryption::None
            },
        );
    }
    Ok(())
}

/// Reads and validates the PEM files to import with the server's own checks
/// (`rustegon-net`: the CA parses as a trust anchor; the chain parses, its leaf has not
/// expired and the key matches the leaf's public key, as `ReloadableCert` checks at start).
///
/// shortcut: the leaf is not verified against the imported CA (a wrong CA makes clients fail
/// the handshake, not the server start); upgrade when `rustegon-net` exposes a chain check.
fn read_import(ca: &Path, cert: &Path, key: &Path) -> CliResult<Tls> {
    let ca_pem = secrets::read_file(ca, MAX_PEM_FILE)?;
    TrustAnchors::from_pem(&ca_pem, ca).map_err(|e| CliError(format!("CA certificate: {e}")))?;
    let cert_pem = secrets::read_file(cert, MAX_PEM_FILE)?;
    let key_pem = secrets::read_file(key, MAX_PEM_FILE)?;
    let chain = parse_certificates(&cert_pem, cert)
        .map_err(|e| CliError(format!("node certificate: {e}")))?;
    let private =
        parse_private_key(&key_pem, key).map_err(|e| CliError(format!("node private key: {e}")))?;
    let not_after = match chain.first() {
        Some(leaf) => {
            not_after_unix(leaf).map_err(|e| CliError(format!("node certificate: {e}")))?
        }
        None => return fail(format!("{}: no certificate", cert.display())),
    };
    let now = SystemClock::new()
        .wall()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    if not_after <= now {
        return fail(format!(
            "{}: the node certificate has expired ({})",
            cert.display(),
            cert::utc_text(not_after)
        ));
    }
    CertifiedKey::from_der(chain, private.expose().clone_key(), &crypto_provider()).map_err(
        |e| {
            CliError(format!(
                "{} does not belong to {}: {e}",
                key.display(),
                cert.display()
            ))
        },
    )?;
    Ok(Tls::Import {
        ca: ca_pem,
        cert: cert_pem,
        key: key_pem,
        not_after_unix: not_after,
    })
}

/// Writes a new KEK file: 32 bytes from the OS CSPRNG as 64 hex digits and a newline,
/// owner-only, never overwriting (security.md §6, PD-151).
fn write_kek(path: &Path) -> CliResult<()> {
    let mut key = Zeroizing::new([0u8; KEK_BYTES]);
    OsRng.fill_bytes(&mut *key);
    // Capacity set up front: no reallocation leaves an unzeroized copy of the digits behind.
    let mut text = Zeroizing::new(String::with_capacity(KEK_BYTES * 2 + 1));
    for b in key.iter() {
        let _ = write!(text, "{b:02x}");
    }
    text.push('\n');
    secrets::write_private_bytes(path, text.as_bytes())
}

/// SAN entries of the node certificate: loopback names, the listen address and `--host`,
/// without duplicates, in a stable order.
fn node_hosts(args: &InitArgs) -> Vec<String> {
    let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    if !args.listen().is_unspecified() {
        hosts.push(args.listen().to_string());
    }
    hosts.extend(args.hosts.iter().cloned());
    let mut seen = std::collections::BTreeSet::new();
    hosts.retain(|h| seen.insert(h.clone()));
    hosts
}

/// The configuration file content.
fn config_text(
    data_dir: &Path,
    certs_dir: Option<&Path>,
    grpc: SocketAddr,
    http: SocketAddr,
    kek_file: Option<&Path>,
    log_dir: Option<&Path>,
    turnkey: bool,
) -> String {
    let path = |p: &Path| toml::Value::String(p.display().to_string());
    let mut node = toml::Table::new();
    node.insert("data_dir".into(), path(data_dir));
    let mut listen = toml::Table::new();
    listen.insert("grpc".into(), toml::Value::String(grpc.to_string()));
    listen.insert("http".into(), toml::Value::String(http.to_string()));
    let mut root = toml::Table::new();
    root.insert("node".into(), toml::Value::Table(node));
    root.insert("listen".into(), toml::Value::Table(listen));
    let mut security = toml::Table::new();
    if let Some(certs_dir) = certs_dir {
        security.insert("tls".into(), toml::Value::Boolean(true));
        security.insert("certs_dir".into(), path(certs_dir));
    }
    if turnkey {
        security.insert("turnkey_admin".into(), toml::Value::Boolean(true));
    }
    if !security.is_empty() {
        root.insert("security".into(), toml::Value::Table(security));
    }
    if let Some(dir) = log_dir {
        let mut log = toml::Table::new();
        log.insert("dir".into(), path(dir));
        root.insert("log".into(), toml::Value::Table(log));
    }
    if let Some(kek) = kek_file {
        // The `file` provider is the default `storage.encryption_key_provider`.
        let mut storage = toml::Table::new();
        storage.insert(
            "encryption".into(),
            toml::Value::String(rustegon_storage::settings::ENCRYPTION_AES_256_GCM.into()),
        );
        storage.insert("encryption_key_file".into(), path(kek));
        root.insert("storage".into(), toml::Value::Table(storage));
    }
    format!(
        "# Written by `rustegon init` (PD-058). Every other setting has its default; see\n\
         # `rustegond --config <this file> --print-config`.\n\n{root}"
    )
}

/// Paths `init` would create, in creation order of their checks.
struct Layout {
    data_dir: PathBuf,
    config: PathBuf,
    ca_dir: PathBuf,
    certs_dir: PathBuf,
    client_dir: Option<PathBuf>,
    prompted_password: PathBuf,
    kek_file: Option<PathBuf>,
}

impl Layout {
    fn new(args: &InitArgs) -> CliResult<Self> {
        let data_dir = absolute(args.data_dir())?;
        let config = match &args.config {
            Some(c) => absolute(c)?,
            None => data_dir.join(CONFIG_FILE),
        };
        let certs_dir = data_dir.join("certs");
        Ok(Self {
            config,
            ca_dir: data_dir.join("ca"),
            client_dir: args
                .client_user
                .as_ref()
                .map(|u| certs_dir.join(format!("client-{u}"))),
            certs_dir,
            prompted_password: data_dir.join(PROMPTED_PASSWORD_FILE),
            kek_file: args.kek_file().map(absolute).transpose()?,
            data_dir,
        })
    }

    /// Everything that marks an initialized (or partially initialized) node, and an existing
    /// key file (a KEK is never overwritten: the data it protects would become unreadable).
    fn existing(&self) -> Vec<PathBuf> {
        let mut candidates = vec![
            self.config.clone(),
            self.ca_dir.clone(),
            self.certs_dir.clone(),
            self.prompted_password.clone(),
            // Written by `rustegond`: a node that already ran.
            self.data_dir.join("store"),
            self.data_dir.join("initial-admin-password"),
        ];
        candidates.extend(self.client_dir.clone());
        candidates.extend(self.kek_file.clone());
        candidates.into_iter().filter(|p| p.exists()).collect()
    }
}

fn refuse_existing(layout: &Layout) -> CliResult<()> {
    let existing = layout.existing();
    if existing.is_empty() {
        return Ok(());
    }
    let list = existing
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    fail(format!(
        "refusing to initialize: already present: {list} (init never overwrites; use a new \
         --data-dir or remove these files)"
    ))
}

/// What the wizard shows before asking for the confirmation (paths, never a secret).
fn summary(
    args: &InitArgs,
    layout: &Layout,
    tls: &Tls,
    admin: &AdminSecret,
    grpc: SocketAddr,
    http: SocketAddr,
) -> Vec<String> {
    let mut lines = vec![
        "Summary:".to_owned(),
        format!("  data directory      {}", layout.data_dir.display()),
        format!("  configuration file  {}", layout.config.display()),
        format!("  listen              gRPC {grpc}, REST/GUI {http}"),
    ];
    lines.push(match admin {
        AdminSecret::File(f) => format!("  admin password      from {}", f.display()),
        AdminSecret::Prompted(_) => format!(
            "  admin password      entered now, stored owner-only in {} for the first start",
            layout.prompted_password.display()
        ),
        AdminSecret::Generated => format!(
            "  admin password      generated by rustegond at its first start into {}",
            layout.data_dir.join("initial-admin-password").display()
        ),
        AdminSecret::Turnkey => {
            "  admin password      turnkey `admin`, to be changed at first login".to_owned()
        }
    });
    lines.push(match tls {
        Tls::Off => "  TLS                 off: plain-text listeners (no certificates)".to_owned(),
        Tls::Generate => format!(
            "  TLS                 new CA in {}, node certificate for {}",
            layout.ca_dir.display(),
            node_hosts(args).join(", ")
        ),
        Tls::Import { .. } => format!(
            "  TLS                 imported PEM files copied into {}",
            layout.certs_dir.display()
        ),
    });
    lines.push(match &layout.kek_file {
        Some(kek) => format!(
            "  encryption at rest  aes-256-gcm, new key file {} (back it up separately)",
            kek.display()
        ),
        None => "  encryption at rest  off".to_owned(),
    });
    lines
}

/// Runs `rustegon init`: the wizard on a terminal or with `--interactive`, flags only
/// otherwise.
///
/// # Errors
/// An existing installation, an invalid password file or TLS import, a cancelled wizard, any
/// I/O or generation failure.
pub fn run(args: &InitArgs) -> CliResult<()> {
    let terminal = secrets::interactive();
    if !args.turnkey && (args.interactive || (!args.non_interactive && terminal)) {
        let mut prompter = Prompter::new(io::stdin().lock(), io::stderr(), terminal);
        run_with(args, Some(&mut prompter))
    } else {
        run_with::<io::Empty, io::Sink>(args, None)
    }
}

/// [`run`] with the wizard's channel (`None`: never ask).
fn run_with<R: BufRead, W: Write>(
    args: &InitArgs,
    mut prompter: Option<&mut Prompter<R, W>>,
) -> CliResult<()> {
    let mut args = args.clone();
    if let Some(p) = prompter.as_deref_mut() {
        ask_missing(&mut args, p)?;
    }
    let args = args;
    let layout = Layout::new(&args)?;
    refuse_existing(&layout)?;
    if let Some(user) = &args.client_user
        && (user.is_empty() || user.contains(['/', '\\']))
    {
        return fail("--client-user must be a non-empty name without path separators");
    }
    if args.grpc_port() != 0 && args.grpc_port() == args.http_port() {
        return fail("--grpc-port and --http-port must differ");
    }
    if args.turnkey && !args.listen().is_loopback() {
        // rustegond would refuse to start with the turnkey password exposed (ADR-036).
        return fail(
            "--turnkey needs a loopback --listen address (127.0.0.1 or ::1): the turnkey \
             password is accepted only on loopback",
        );
    }
    // Everything that can fail on input is checked before the first file is written.
    let tls = match (&args.import_ca_cert, &args.import_cert, &args.import_key) {
        (Some(ca), Some(cert), Some(key)) => {
            if args.client_user.is_some() {
                return fail(
                    "--client-user needs the CA key: it cannot be used with an imported CA",
                );
            }
            read_import(ca, cert, key)?
        }
        (None, None, None) if args.tls_on() => Tls::Generate,
        (None, None, None) => Tls::Off,
        _ => return fail("--import-ca-cert, --import-cert and --import-key go together"),
    };
    let admin = admin_secret(&args, prompter.as_deref_mut())?;
    let grpc = SocketAddr::new(args.listen(), args.grpc_port());
    let http = SocketAddr::new(args.listen(), args.http_port());
    if let Some(p) = prompter {
        for line in summary(&args, &layout, &tls, &admin, grpc, http) {
            p.say(&line)?;
        }
        if !p.confirm("Write these files?", true)? {
            return fail("init cancelled; nothing was written");
        }
    }
    write_node(&args, &layout, &tls, &admin, grpc, http)
}

/// Creates every file of the plan and prints the result and the next steps.
fn write_node(
    args: &InitArgs,
    layout: &Layout,
    tls: &Tls,
    admin: &AdminSecret,
    grpc: SocketAddr,
    http: SocketAddr,
) -> CliResult<()> {
    let hosts = node_hosts(args);
    let mut reports = Vec::new();
    match tls {
        Tls::Off => {}
        Tls::Generate => {
            cert::create_dir(&layout.ca_dir)?;
            let ca_gen =
                cert::write_new_ca(&layout.ca_dir, "Rustegon CA", args.ca_algorithm.into())?;
            let ca = cert::load_ca(&layout.ca_dir)?;
            cert::create_dir(&layout.certs_dir)?;
            cert::write_new(&layout.certs_dir.join(CA_CERT), ca.cert_pem().as_bytes())?;
            let node = cert::issue_node(&ca, &args.node_name, &hosts)?;
            cert::write_pair(&node, &layout.certs_dir, "node")?;
            reports.push(("CA", layout.ca_dir.join(CA_CERT), ca_gen.not_after_unix));
            reports.push((
                "node",
                layout.certs_dir.join("node.crt"),
                node.not_after_unix,
            ));
            if let (Some(user), Some(dir)) = (&args.client_user, &layout.client_dir) {
                cert::create_dir(dir)?;
                let c = ca
                    .issue_client(user, &SystemClock::new(), &OsRng)
                    .map_err(|e| CliError(format!("client certificate: {e}")))?;
                cert::write_pair(&c, dir, "client")?;
                cert::write_new(&dir.join(CA_CERT), ca.cert_pem().as_bytes())?;
                reports.push(("client", dir.join("client.crt"), c.not_after_unix));
            }
        }
        Tls::Import {
            ca,
            cert: node_cert,
            key,
            not_after_unix,
        } => {
            cert::create_dir(&layout.certs_dir)?;
            cert::write_new(&layout.certs_dir.join(CA_CERT), ca)?;
            cert::write_new(&layout.certs_dir.join("node.crt"), node_cert)?;
            secrets::write_private_bytes(&layout.certs_dir.join("node.key"), key)?;
            reports.push(("node", layout.certs_dir.join("node.crt"), *not_after_unix));
        }
    }
    if let Some(kek) = &layout.kek_file {
        if let Some(dir) = kek.parent().filter(|d| !d.as_os_str().is_empty()) {
            cert::create_dir(dir)?;
        }
        write_kek(kek)?;
    }
    let password_file = match admin {
        AdminSecret::File(f) => Some(f.clone()),
        AdminSecret::Prompted(password) => {
            cert::create_dir(&layout.data_dir)?;
            secrets::write_private(&layout.prompted_password, password)?;
            Some(layout.prompted_password.clone())
        }
        AdminSecret::Generated | AdminSecret::Turnkey => None,
    };
    if let Some(dir) = layout.config.parent().filter(|d| !d.as_os_str().is_empty()) {
        cert::create_dir(dir)?;
    }
    cert::write_new(
        &layout.config,
        config_text(
            &layout.data_dir,
            (!matches!(tls, Tls::Off)).then_some(layout.certs_dir.as_path()),
            grpc,
            http,
            layout.kek_file.as_deref(),
            args.log_dir
                .as_deref()
                .map(absolute)
                .transpose()?
                .as_deref(),
            matches!(admin, AdminSecret::Turnkey),
        )
        .as_bytes(),
    )?;

    out(&format!(
        "initialized {} (configuration {})",
        layout.data_dir.display(),
        layout.config.display()
    ))?;
    for (kind, path, not_after) in reports {
        cert::report_cert(kind, &path, not_after)?;
    }
    if matches!(tls, Tls::Generate) {
        out(&format!("node certificate addresses: {}", hosts.join(", ")))?;
    }
    if let Some(kek) = &layout.kek_file {
        out(&format!(
            "encryption at rest: aes-256-gcm with the key file {} (owner-only; keep a copy \
             offline: without it the data cannot be read)",
            kek.display()
        ))?;
    }
    if matches!(admin, AdminSecret::Turnkey) {
        return turnkey_next_steps(layout, http);
    }
    next_steps(layout, tls, password_file.as_deref())
}

/// The turnkey install's warning (stderr) and next step (ADR-036).
fn turnkey_next_steps(layout: &Layout, http: SocketAddr) -> CliResult<()> {
    err(&format!(
        "warning: turnkey install: the first start creates the administrator \
         `{DEFAULT_ADMIN_USER}` with the publicly known password `{TURNKEY_ADMIN_PASSWORD}`; it \
         must be changed at first login, and rustegond refuses to start with a listener off \
         loopback until it is (ADR-036)"
    ));
    out(&format!(
        "next: start the service, or rustegond --config {}",
        layout.config.display()
    ))?;
    out(&format!(
        "then open http://localhost:{}/ui/, sign in as {DEFAULT_ADMIN_USER} / \
         {TURNKEY_ADMIN_PASSWORD}; you will be asked to change the password",
        http.port()
    ))
}

/// Prints where the CA key is and how to start and connect (paths only, never a secret).
fn next_steps(layout: &Layout, tls: &Tls, password_file: Option<&Path>) -> CliResult<()> {
    if matches!(tls, Tls::Generate) {
        out(&format!(
            "CA signing key: {} (owner-only; move it offline, `rustegon cert create-node --ca \
             {}` needs it)",
            layout.ca_dir.join(cert::CA_KEY).display(),
            layout.ca_dir.display()
        ))?;
    }
    let start = format!("rustegond --config {}", layout.config.display());
    if let Some(f) = password_file {
        out(&format!(
            "next: {start} --admin-password-file {}",
            f.display()
        ))?;
        out(&format!(
            "the first start creates the administrator `{DEFAULT_ADMIN_USER}` with that \
             password; the file is not needed afterwards"
        ))?;
    } else {
        out(&format!("next: {start}"))?;
        out(&format!(
            "the first start creates the administrator `{DEFAULT_ADMIN_USER}` with a generated \
             {GENERATED_LENGTH}-character password in {} (owner-only; change it at first login \
             with `rustegon user passwd`)",
            layout.data_dir.join("initial-admin-password").display()
        ))?;
    }
    if matches!(tls, Tls::Off) {
        out(&format!(
            "TLS is off: the listeners accept plain text (enable it with `rustegon init --tls` on \
             a new data directory, or set security.tls = true with certificates in {})",
            layout.certs_dir.display()
        ))?;
        return out(&format!(
            "connect: rustegon shell --user {DEFAULT_ADMIN_USER}"
        ));
    }
    out(&format!(
        "connect: rustegon shell --ca {} --user {DEFAULT_ADMIN_USER}",
        layout.certs_dir.join(CA_CERT).display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompter(script: &str) -> Prompter<&[u8], Vec<u8>> {
        Prompter::new(script.as_bytes(), Vec::new(), false)
    }

    #[test]
    fn fr_tls_002_config_text_parses_back_with_absolute_paths() {
        let text = config_text(
            Path::new("/var/lib/rustegon"),
            Some(Path::new("/var/lib/rustegon/certs")),
            "127.0.0.1:7700".parse().unwrap_or_else(|_| unreachable!()),
            "[::1]:7780".parse().unwrap_or_else(|_| unreachable!()),
            None,
            None,
            false,
        );
        let parsed: toml::Table = text.parse().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            parsed["node"]["data_dir"].as_str(),
            Some("/var/lib/rustegon")
        );
        assert_eq!(parsed["listen"]["http"].as_str(), Some("[::1]:7780"));
        assert_eq!(parsed["security"]["tls"].as_bool(), Some(true));
        assert_eq!(
            parsed["security"]["certs_dir"].as_str(),
            Some("/var/lib/rustegon/certs")
        );
        assert!(parsed.get("storage").is_none());
    }

    /// ADR-034: without TLS the file has no `[security]` section (plain text is the default).
    #[test]
    fn fr_tls_001_config_text_without_tls_has_no_security_section() {
        let text = config_text(
            Path::new("/d"),
            None,
            "127.0.0.1:7700".parse().unwrap_or_else(|_| unreachable!()),
            "127.0.0.1:7780".parse().unwrap_or_else(|_| unreachable!()),
            None,
            None,
            false,
        );
        let parsed: toml::Table = text.parse().unwrap_or_else(|e| panic!("{e}"));
        assert!(parsed.get("security").is_none(), "{text}");
        let args = |tls, client: Option<&str>, import: Option<&str>| InitArgs {
            tls,
            client_user: client.map(str::to_owned),
            import_ca_cert: import.map(PathBuf::from),
            ..test_args()
        };
        assert!(!args(false, None, None).tls_on());
        assert!(args(true, None, None).tls_on());
        assert!(args(false, Some("app"), None).tls_on());
        assert!(args(false, None, Some("ca.crt")).tls_on());
    }

    #[test]
    fn fr_ins_004_config_text_enables_encryption_with_the_key_file() {
        let text = config_text(
            Path::new("/d"),
            Some(Path::new("/d/certs")),
            "127.0.0.1:7700".parse().unwrap_or_else(|_| unreachable!()),
            "127.0.0.1:7780".parse().unwrap_or_else(|_| unreachable!()),
            Some(Path::new("/etc/rustegon/secrets/kek.key")),
            None,
            false,
        );
        let parsed: toml::Table = text.parse().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            parsed["storage"]["encryption"].as_str(),
            Some("aes-256-gcm")
        );
        assert_eq!(
            parsed["storage"]["encryption_key_file"].as_str(),
            Some("/etc/rustegon/secrets/kek.key")
        );
    }

    #[test]
    fn fr_ins_004_encryption_flag_syntax() {
        assert_eq!("none".parse::<Encryption>(), Ok(Encryption::None));
        assert_eq!(
            "file:/k".parse::<Encryption>(),
            Ok(Encryption::File("/k".into()))
        );
        for bad in ["", "file:", "aes", "env:X"] {
            assert!(bad.parse::<Encryption>().is_err(), "{bad}");
        }
    }

    #[test]
    fn fr_ins_004_prompter_defaults_reasks_and_eof() {
        let mut p = prompter("\n70x0\n7701\nmaybe\nn\n\n");
        assert_eq!(p.ask("Data directory", "d").ok(), Some("d".to_owned()));
        assert_eq!(p.ask_parsed::<u16>("gRPC port", "7700").ok(), Some(7701));
        assert_eq!(p.confirm("Encrypt?", true).ok(), Some(false));
        assert_eq!(p.confirm("Write?", true).ok(), Some(true));
        // The end of the input aborts instead of looping.
        assert!(p.ask("More", "").is_err());
        let shown = String::from_utf8_lossy(&p.output).into_owned();
        assert!(shown.contains("invalid answer `70x0`"), "{shown}");
        assert!(shown.contains("answer y or n"), "{shown}");
    }

    #[test]
    fn fr_ins_004_wizard_password_is_policy_checked_confirmed_and_never_echoed() {
        let weak = "password1234";
        let good = "q7Vz!m2Lp#9Rx4Tk";
        let script = format!("{weak}\n{good}\nmistyped-{good}\n{good}\n{good}\n");
        let mut p = prompter(&script);
        let args = InitArgs {
            admin_password_file: None,
            ..test_args()
        };
        let admin = admin_secret(&args, Some(&mut p));
        assert!(
            matches!(&admin, Ok(AdminSecret::Prompted(pw)) if pw.expose().as_str() == good),
            "weak and mismatched answers are asked again"
        );
        let shown = String::from_utf8_lossy(&p.output).into_owned();
        assert!(shown.contains("do not match"), "{shown}");
        assert!(!shown.contains(weak) && !shown.contains(good), "{shown}");
        // Empty: generated by rustegond.
        let mut p = prompter("\n");
        assert!(matches!(
            admin_secret(&args, Some(&mut p)),
            Ok(AdminSecret::Generated)
        ));
    }

    #[test]
    fn fr_ins_004_kek_file_is_64_hex_digits_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("kek.key");
        write_kek(&path).unwrap_or_else(|e| panic!("{e}"));
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e}"));
        let digits = text.strip_suffix('\n').unwrap_or_default();
        assert_eq!(digits.len(), 64);
        assert!(digits.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(write_kek(&path).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e}")),
            text
        );
    }

    fn test_args() -> InitArgs {
        InitArgs {
            data_dir: None,
            config: None,
            listen: None,
            grpc_port: None,
            http_port: None,
            tls: false,
            hosts: Vec::new(),
            node_name: "node1".into(),
            ca_algorithm: CaAlgorithm::default(),
            client_user: None,
            admin_password_file: None,
            import_ca_cert: None,
            import_cert: None,
            import_key: None,
            encryption: None,
            interactive: false,
            non_interactive: false,
            turnkey: false,
            log_dir: None,
        }
    }

    /// TC-SEC-021 (ADR-036): `--turnkey` writes `security.turnkey_admin` (and `log.dir` when
    /// given) and nothing else that changes security; it refuses a non-loopback listener and
    /// never runs the wizard's password question.
    #[test]
    fn tc_sec_021_turnkey_config_and_loopback_only() {
        let text = config_text(
            Path::new("/var/lib/rustegon"),
            None,
            "127.0.0.1:7700".parse().unwrap_or_else(|_| unreachable!()),
            "127.0.0.1:7780".parse().unwrap_or_else(|_| unreachable!()),
            None,
            Some(Path::new("/var/log/rustegon")),
            true,
        );
        let parsed: toml::Table = text.parse().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed["security"]["turnkey_admin"].as_bool(), Some(true));
        assert!(parsed["security"].get("tls").is_none(), "{text}");
        assert_eq!(parsed["log"]["dir"].as_str(), Some("/var/log/rustegon"));
        assert!(!text.contains("password"), "{text}");

        let args = InitArgs {
            turnkey: true,
            ..test_args()
        };
        let mut p = prompter("");
        assert!(matches!(
            admin_secret(&args, Some(&mut p)),
            Ok(AdminSecret::Turnkey)
        ));
        assert!(p.output.is_empty(), "no question asked");
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let exposed = InitArgs {
            turnkey: true,
            data_dir: Some(dir.path().join("d")),
            listen: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            ..test_args()
        };
        let e = run_with::<io::Empty, io::Sink>(&exposed, None)
            .err()
            .unwrap_or_else(|| panic!("a non-loopback turnkey init must fail"));
        assert!(e.0.contains("loopback"), "{}", e.0);
        assert!(!dir.path().join("d").exists(), "nothing written");
    }
}
