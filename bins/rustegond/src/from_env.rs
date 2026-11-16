// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegond --config-from-env`: the container start of docker.md (FR-INS-003, PD-148).
//!
//! - Configuration: the image defaults (`node.data_dir = /var/lib/rustegon`, both client
//!   listeners on `0.0.0.0`, and `security.certs_dir = /etc/rustegon/certs` when a node
//!   certificate is mounted there) sit *under* the optional `/etc/rustegon/rustegon.toml` (or
//!   `--config`), which sits under `RUSTEGON__SECTION__KEY` and `--set` as usual. They are
//!   merged into the file layer, so the precedence of `Registry::load` stays the only one.
//! - `RUSTEGON_MODE`: `single-node` (default); `cluster` is refused until cluster deployments
//!   exist (R3).
//! - `RUSTEGON_AUTO_INIT` (default `true`): the first start initializes the data directory
//!   (store, first administrator, as `rustegond` always does). `false` refuses a data directory
//!   that has never been started, so a forgotten volume mount cannot silently create a new,
//!   empty node.
//! - `RUSTEGON_AUTO_TLS` (default `true`): when TLS is on (`RUSTEGON__SECURITY__TLS=true`,
//!   ADR-034; plain text is the default) and none of the node certificate, key and CA file
//!   exists, a CA (`<data_dir>/ca/`) and a node certificate (the default `<data_dir>/certs/`
//!   layout of `rustegon init`) are generated. Partial files are never completed: the TLS setup
//!   then fails naming the missing file.
//!
//! The first administrator's password comes from `RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE` or is
//! generated into `<data_dir>/initial-admin-password` by the normal bootstrap (PD-054).

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use rustegon_common::{
    Error, ErrorCode, Result,
    settings::{Config, NodeSettings},
};
use rustegon_net::{CertAuthority, KeyAlgorithm};
use rustegon_sim_api::{FileSystem, OpenMode, OsRng, StdFileSystem, SystemClock};

use crate::config::{SecuritySettings, TlsFileSettings};

/// Deployment mode variable (docker.md §2).
pub const MODE_ENV: &str = "RUSTEGON_MODE";
/// First-start initialization switch.
pub const AUTO_INIT_ENV: &str = "RUSTEGON_AUTO_INIT";
/// Certificate generation switch.
pub const AUTO_TLS_ENV: &str = "RUSTEGON_AUTO_TLS";
/// Address clients use for this node; added to the generated certificate.
pub const ADVERTISE_ENV: &str = "RUSTEGON_ADVERTISE_ADDR";
/// Optional configuration file of the image.
pub const CONFIG_FILE: &str = "/etc/rustegon/rustegon.toml";
/// Mount point of operator certificates.
pub const MOUNTED_CERTS_DIR: &str = "/etc/rustegon/certs";
/// Data volume of the image.
pub const DATA_DIR: &str = "/var/lib/rustegon";

/// What the start does besides loading the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// `RUSTEGON_AUTO_INIT`.
    pub auto_init: bool,
    /// `RUSTEGON_AUTO_TLS`.
    pub auto_tls: bool,
    /// Extra SAN entries of a generated node certificate (advertise address, host name).
    pub hosts: Vec<String>,
}

fn invalid(message: String) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

fn var<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
    // The last occurrence wins, as for `RUSTEGON__*` in `Registry::load`.
    env.iter()
        .rev()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

fn flag(env: &[(String, String)], name: &str) -> Result<bool> {
    match var(env, name).map(str::to_ascii_lowercase).as_deref() {
        None | Some("true" | "1" | "yes") => Ok(true),
        Some("false" | "0" | "no") => Ok(false),
        Some(other) => Err(invalid(format!(
            "{name} = {other:?}: expected true or false"
        ))),
    }
}

/// Host part of an advertise address (`host`, `host:port`, `ip:port`, `[v6]:port`).
fn host_of(addr: &str) -> String {
    if let Ok(socket) = addr.parse::<SocketAddr>() {
        return socket.ip().to_string();
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host.into(),
        _ => addr.into(),
    }
}

/// Reads the mode switches and returns the file layer with the image defaults merged under
/// `file` (module docs). `mounted_certs`: a node certificate exists in [`MOUNTED_CERTS_DIR`].
///
/// # Errors
/// `RGN-1001` for an unsupported mode, an invalid switch or an unparsable file.
pub fn layer(
    env: &[(String, String)],
    file: Option<&str>,
    mounted_certs: bool,
) -> Result<(String, Plan)> {
    match var(env, MODE_ENV) {
        None | Some("single-node") => {}
        Some("cluster") => {
            return Err(invalid(format!(
                "{MODE_ENV}=cluster is not supported yet (cluster deployments arrive with R3); \
                 use single-node"
            )));
        }
        Some(other) => {
            return Err(invalid(format!(
                "{MODE_ENV} = {other:?}: expected single-node"
            )));
        }
    }
    let mut hosts = Vec::new();
    if let Some(addr) = var(env, ADVERTISE_ENV) {
        hosts.push(host_of(addr));
    }
    // Docker sets HOSTNAME to the container's host name, which other containers dial; only a
    // plain DNS name is added (anything else would fail the certificate generation).
    if let Some(name) = var(env, "HOSTNAME").filter(|h| {
        h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    }) {
        hosts.push(name.to_owned());
    }
    let plan = Plan {
        auto_init: flag(env, AUTO_INIT_ENV)?,
        auto_tls: flag(env, AUTO_TLS_ENV)?,
        hosts,
    };

    let mut table: toml::Table = toml::from_str(file.unwrap_or_default())
        .map_err(|e| invalid(format!("config file: {e}")))?;
    let mut defaults = vec![
        ("node", "data_dir", DATA_DIR),
        ("listen", "grpc", "0.0.0.0:7700"),
        ("listen", "http", "0.0.0.0:7780"),
    ];
    if mounted_certs {
        defaults.push(("security", "certs_dir", MOUNTED_CERTS_DIR));
    }
    for (section, key, value) in defaults {
        let entry = table
            .entry(section)
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        // A non-table section is left alone: `Registry::load` reports it with its reason.
        if let toml::Value::Table(entries) = entry {
            entries
                .entry(key)
                .or_insert_with(|| toml::Value::String(value.into()));
        }
    }
    let text = toml::to_string(&table)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("config layer: {e}")))?;
    Ok((text, plan))
}

/// Whether `path` names an existing file or directory.
fn exists(fs: &dyn FileSystem, path: &Path) -> Result<bool> {
    let result = fs
        .open(path, OpenMode::Read)
        .map(drop)
        .or_else(|_| fs.read_dir(path).map(drop));
    match result {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::new(
            ErrorCode::Internal,
            format!("{}: {e}", path.display()),
        )),
    }
}

/// The checks and certificate generation of the plan; runs after logging is up and before the
/// node opens anything (module docs).
///
/// # Errors
/// A data directory that was never started with auto-init off; generation and I/O failures.
pub fn prepare(config: &Config, plan: &Plan) -> Result<()> {
    let fs = StdFileSystem;
    let node: NodeSettings = config.section()?;
    let security: SecuritySettings = config.section()?;
    let data_dir = node.data_dir;
    if !plan.auto_init && !exists(&fs, &data_dir.join("store"))? {
        return Err(Error::new(
            ErrorCode::PreconditionFailed,
            format!(
                "{} holds no initialized node and {AUTO_INIT_ENV}=false; mount the data volume \
                 of an existing node or set {AUTO_INIT_ENV}=true",
                data_dir.display()
            ),
        ));
    }
    if !security.tls || !plan.auto_tls {
        return Ok(());
    }
    let tls = config
        .section::<TlsFileSettings>()?
        .resolve(&security.certs_dir(&data_dir))?;
    for path in [&tls.cert_file, &tls.key_file, &tls.ca_file] {
        if exists(&fs, path)? {
            return Ok(());
        }
    }
    generate(
        &fs,
        &data_dir,
        &tls.ca_file,
        &tls.cert_file,
        &tls.key_file,
        &plan.hosts,
    )
}

/// The `rustegon init` certificate layout: CA pair in `<data_dir>/ca`, CA certificate and node
/// pair at the configured paths. SAN: loopback names plus `hosts`.
fn generate(
    fs: &dyn FileSystem,
    data_dir: &Path,
    ca_file: &Path,
    cert_file: &Path,
    key_file: &Path,
    hosts: &[String],
) -> Result<()> {
    let net = |e: rustegon_net::TlsError| invalid(format!("automatic TLS: {e}"));
    let io = |path: &Path, e: std::io::Error| {
        Error::new(ErrorCode::Internal, format!("{}: {e}", path.display()))
    };
    let clock = SystemClock::new();
    let ca_dir = data_dir.join("ca");
    let mut dirs: Vec<PathBuf> = vec![ca_dir.clone()];
    dirs.extend(
        [ca_file, cert_file, key_file]
            .iter()
            .filter_map(|p| p.parent().map(Path::to_path_buf)),
    );
    for dir in &dirs {
        fs.create_dir_all(dir).map_err(|e| io(dir, e))?;
    }
    let (ca, ca_gen) =
        CertAuthority::generate("Rustegon CA", KeyAlgorithm::EcdsaP256, &clock, &OsRng)
            .map_err(net)?;
    ca_gen
        .write_files(fs, &ca_dir.join("ca.crt"), &ca_dir.join("ca.key"))
        .map_err(net)?;
    let mut sans: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    for host in hosts {
        if !sans.contains(host) {
            sans.push(host.clone());
        }
    }
    let node = ca.issue_node("node1", &sans, &clock, &OsRng).map_err(net)?;
    // The CA certificate is written last: it is what clients fetch (`rustegon cert export-ca`).
    node.write_files(fs, cert_file, key_file).map_err(net)?;
    let mut file = fs
        .open(ca_file, OpenMode::CreateNew)
        .map_err(|e| io(ca_file, e))?;
    file.append(ca.cert_pem().as_bytes())
        .and_then(|()| file.sync_data())
        .map_err(|e| io(ca_file, e))?;
    tracing::info!(
        ca = %ca_file.display(),
        node_cert = %cert_file.display(),
        addresses = %sans.join(", "),
        "generated a CA and a node certificate (RUSTEGON_AUTO_TLS)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn load(text: &str, extra_env: &[(&str, &str)]) -> Config {
        crate::config::registry()
            .unwrap()
            .load(&rustegon_common::settings::Sources {
                file: Some(text.to_owned()),
                env: env(extra_env),
                flags: Vec::new(),
            })
            .unwrap()
    }

    #[test]
    fn fr_ins_003_image_defaults_sit_under_file_and_env() {
        let (text, plan) = layer(&[], None, false).unwrap();
        assert_eq!(
            plan,
            Plan {
                auto_init: true,
                auto_tls: true,
                hosts: Vec::new()
            }
        );
        let config = load(&text, &[]);
        let node: NodeSettings = config.section().unwrap();
        assert_eq!(node.data_dir, Path::new(DATA_DIR));
        let listen: crate::config::ListenSettings = config.section().unwrap();
        assert_eq!(listen.http, "0.0.0.0:7780");
        assert_eq!(listen.grpc, "0.0.0.0:7700");
        let security: SecuritySettings = config.section().unwrap();
        assert_eq!(security.certs_dir, None);

        // A file value beats the image default; an env value beats the file.
        let (text, _) = layer(
            &[],
            Some("[listen]\nhttp = \"127.0.0.1:9000\"\n[log]\nlevel = \"debug\"\n"),
            true,
        )
        .unwrap();
        let config = load(&text, &[("RUSTEGON__NODE__DATA_DIR", "/data")]);
        let listen: crate::config::ListenSettings = config.section().unwrap();
        assert_eq!(listen.http, "127.0.0.1:9000");
        assert_eq!(listen.grpc, "0.0.0.0:7700");
        let node: NodeSettings = config.section().unwrap();
        assert_eq!(node.data_dir, Path::new("/data"));
        let security: SecuritySettings = config.section().unwrap();
        assert_eq!(
            security.certs_dir.as_deref(),
            Some(Path::new(MOUNTED_CERTS_DIR))
        );
    }

    #[test]
    fn fr_ins_003_mode_and_switches_are_validated() {
        let err = layer(&env(&[(MODE_ENV, "cluster")]), None, false).unwrap_err();
        assert!(err.message().contains("R3"), "{err}");
        let err = layer(&env(&[(MODE_ENV, "multi")]), None, false).unwrap_err();
        assert!(err.message().contains("expected single-node"), "{err}");
        let err = layer(&env(&[(AUTO_TLS_ENV, "maybe")]), None, false).unwrap_err();
        assert!(err.message().contains("expected true or false"), "{err}");
        let (_, plan) = layer(
            &env(&[
                (MODE_ENV, "single-node"),
                (AUTO_INIT_ENV, "false"),
                (AUTO_TLS_ENV, "FALSE"),
                (ADVERTISE_ENV, "db.example.com:7700"),
                ("HOSTNAME", "3f2a9c1d0b7e"),
            ]),
            None,
            false,
        )
        .unwrap();
        assert!(!plan.auto_init && !plan.auto_tls);
        assert_eq!(plan.hosts, ["db.example.com", "3f2a9c1d0b7e"]);
        let (_, plan) = layer(&env(&[("HOSTNAME", "bad host/x")]), None, false).unwrap();
        assert_eq!(plan.hosts, Vec::<String>::new());
    }

    #[test]
    fn fr_ins_003_advertise_host_part() {
        assert_eq!(host_of("10.0.0.5:7700"), "10.0.0.5");
        assert_eq!(host_of("[::1]:7700"), "::1");
        assert_eq!(host_of("db"), "db");
        assert_eq!(host_of("db:7700"), "db");
        assert_eq!(host_of("fe80::1"), "fe80::1");
    }

    #[test]
    fn fr_ins_003_auto_tls_generates_once_with_tls_on_and_auto_init_off_refuses_a_new_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let data_text = data.display().to_string();
        let (text, plan) = layer(&env(&[(AUTO_INIT_ENV, "false")]), None, false).unwrap();
        let config = load(&text, &[("RUSTEGON__NODE__DATA_DIR", &data_text)]);
        let err = prepare(&config, &plan).unwrap_err();
        assert!(err.message().contains("RUSTEGON_AUTO_INIT=false"), "{err}");

        // Plain text by default (ADR-034): nothing is generated.
        let (text, plan) = layer(&[], None, false).unwrap();
        let config = load(&text, &[("RUSTEGON__NODE__DATA_DIR", &data_text)]);
        prepare(&config, &plan).unwrap();
        assert!(!data.join("certs").exists() && !data.join("ca").exists());

        let config = load(
            &text,
            &[
                ("RUSTEGON__NODE__DATA_DIR", &data_text),
                ("RUSTEGON__SECURITY__TLS", "true"),
            ],
        );
        prepare(&config, &plan).unwrap();
        for f in [
            "ca/ca.crt",
            "ca/ca.key",
            "certs/ca.crt",
            "certs/node.crt",
            "certs/node.key",
        ] {
            assert!(data.join(f).is_file(), "{f} missing");
        }
        let ca = std::fs::read(data.join("certs/ca.crt")).unwrap();
        assert_eq!(ca, std::fs::read(data.join("ca/ca.crt")).unwrap());
        // A second start keeps the existing certificates.
        prepare(&config, &plan).unwrap();
        assert_eq!(ca, std::fs::read(data.join("certs/ca.crt")).unwrap());
    }
}
