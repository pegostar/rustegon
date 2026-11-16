// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegon health` and the local CA lookup shared with `rustegon cert export-ca`
//! (FR-INS-003, docker.md §1, PD-149).
//!
//! `health` is the image's `HEALTHCHECK`: `GET /api/v1/health/ready` (`--ready`) or
//! `/api/v1/health/live` on the REST port; exit 0 on HTTP 200, 1 otherwise. Plain HTTP by
//! default, like the node (ADR-034); HTTPS, the server verified against the local CA, when TLS
//! is on: `--tls`, or `RUSTEGON__SECURITY__TLS` set to true (the variable the containerized
//! node reads, so the check follows the node), or `--ca`. Its defaults suit a container
//! (`127.0.0.1`, the port of `RUSTEGON__LISTEN__HTTP` or 7780, the CA of [`local_ca`]), so the
//! Dockerfile calls it without arguments.

use std::{
    net::{SocketAddr, ToSocketAddrs as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Args;
use rustegon_net::{
    TlsContext, TlsMinVersion, TrustAnchors, rustls::pki_types::ServerName,
    tokio_rustls::TlsConnector,
};
use rustegon_sim_api::{Connection, Network as _, StdFileSystem, SystemClock, TokioNetwork};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::output::{CliError, CliResult, fail, io_err, out};

/// Variable of the REST listener address (`listen.http`), whose port `health` defaults to.
const LISTEN_HTTP_ENV: &str = "RUSTEGON__LISTEN__HTTP";
/// Variable of the data directory (`node.data_dir`).
const DATA_DIR_ENV: &str = "RUSTEGON__NODE__DATA_DIR";
/// Largest response read (the health bodies are a few bytes).
const MAX_RESPONSE: u64 = 64 * 1024;

/// `rustegon health`.
#[derive(Debug, Args)]
pub struct HealthArgs {
    /// Check readiness (`/api/v1/health/ready`) instead of liveness.
    #[arg(long)]
    pub ready: bool,
    /// Node address.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// REST port (default: the port of `RUSTEGON__LISTEN__HTTP`, else 7780).
    #[arg(long)]
    pub port: Option<u16>,
    /// Use HTTPS (default: the value of `RUSTEGON__SECURITY__TLS`, else plain HTTP).
    #[arg(long, env = "RUSTEGON__SECURITY__TLS", value_parser = clap::builder::BoolishValueParser::new())]
    pub tls: bool,
    /// CA certificate verifying the node; implies `--tls` (default: `RUSTEGON_CA`, else the
    /// container's `/etc/rustegon/certs/ca.crt` or `<data_dir>/certs/ca.crt`).
    #[arg(long, env = "RUSTEGON_CA", value_name = "PATH")]
    pub ca: Option<PathBuf>,
}

/// The CA certificate of the local node: `/etc/rustegon/certs/ca.crt` when certificates are
/// mounted, else `<data_dir>/certs/ca.crt` (`RUSTEGON__NODE__DATA_DIR`, default
/// `/var/lib/rustegon`), the layouts `rustegond --config-from-env` serves.
///
/// # Errors
/// Neither file exists.
pub fn local_ca() -> CliResult<PathBuf> {
    let data_dir = std::env::var_os(DATA_DIR_ENV)
        .map_or_else(|| PathBuf::from("/var/lib/rustegon"), PathBuf::from);
    let candidates = [
        PathBuf::from("/etc/rustegon/certs/ca.crt"),
        data_dir.join("certs").join("ca.crt"),
    ];
    match candidates.iter().find(|p| p.is_file()) {
        Some(p) => Ok(p.clone()),
        None => fail(format!(
            "no local CA certificate ({} or {}); use --ca",
            candidates[0].display(),
            candidates[1].display()
        )),
    }
}

/// The port of an `ip:port` value, if it is one.
fn port_of(listen: &str) -> Option<u16> {
    listen.parse::<SocketAddr>().ok().map(|a| a.port())
}

/// Runs `rustegon health`.
///
/// # Errors
/// Any connection, TLS or HTTP failure, or a status other than 200 (exit code 1).
pub fn run(args: &HealthArgs) -> CliResult<()> {
    let port = args
        .port
        .or_else(|| {
            std::env::var(LISTEN_HTTP_ENV)
                .ok()
                .as_deref()
                .and_then(port_of)
        })
        .unwrap_or(7780);
    let ca = match &args.ca {
        Some(ca) => Some(ca.clone()),
        None if args.tls => Some(local_ca()?),
        None => None,
    };
    let path = if args.ready {
        "/api/v1/health/ready"
    } else {
        "/api/v1/health/live"
    };
    let target = format!("{}:{port}", bracketed(&args.host));
    let addr = target
        .to_socket_addrs()
        .map_err(|e| io_err(&target, &e))?
        .next()
        .ok_or_else(|| CliError(format!("{target}: no address")))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| io_err("runtime", &e))?;
    let status = runtime.block_on(get(&args.host, addr, ca.as_deref(), path))?;
    if status.split(' ').nth(1) == Some("200") {
        out(&format!("{path}: {status}"))
    } else {
        fail(format!("{path}: {status}"))
    }
}

fn bracketed(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// `GET path` over HTTP/1.1, on TLS verified against `ca` when given, else plain; returns the
/// status line.
async fn get(host: &str, addr: SocketAddr, ca: Option<&Path>, path: &str) -> CliResult<String> {
    let name = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let conn: Box<dyn Connection> = TokioNetwork
        .connect(addr)
        .await
        .map_err(|e| io_err(addr, &e))?;
    let mut stream: Box<dyn Connection> = match ca {
        None => conn,
        Some(ca) => {
            let anchors = TrustAnchors::load(&StdFileSystem, ca)
                .map_err(|e| CliError(format!("{}: {e}", ca.display())))?;
            let mut config = TlsContext::new(Arc::new(SystemClock::new()), TlsMinVersion::Tls13)
                .client_config(&anchors, None)
                .map_err(|e| CliError(format!("TLS: {e}")))?;
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let server_name = ServerName::try_from(name.clone())
                .map_err(|_| CliError(format!("invalid TLS server name {name:?}")))?;
            Box::new(
                TlsConnector::from(Arc::new(config))
                    .connect(server_name, conn)
                    .await
                    .map_err(|e| CliError(format!("{addr}: TLS: {e}")))?,
            )
        }
    };
    let request = format!("GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| io_err(addr, &e))?;
    // tokio-rustls may still buffer part of the request after `write_all` (PD-105).
    stream.flush().await.map_err(|e| io_err(addr, &e))?;
    let mut response = Vec::new();
    (&mut stream)
        .take(MAX_RESPONSE)
        .read_to_end(&mut response)
        .await
        .map_err(|e| io_err(addr, &e))?;
    let text = String::from_utf8_lossy(&response);
    Ok(text.lines().next().unwrap_or_default().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_ins_007_health_port_from_listen_address() {
        assert_eq!(port_of("0.0.0.0:7781"), Some(7781));
        assert_eq!(port_of("[::]:9000"), Some(9000));
        assert_eq!(port_of("localhost"), None);
        assert_eq!(bracketed("::1"), "[::1]");
        assert_eq!(bracketed("127.0.0.1"), "127.0.0.1");
    }
}
