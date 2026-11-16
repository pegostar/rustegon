// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegon cert`: CA, node and client certificates (FR-TLS-002, security.md §5, PD-046,
//! PD-058).
//!
//! File layout (the one `rustegon init` produces and `rustegond` reads by default):
//! - CA directory: `ca.crt`, `ca.key` (the signing key; keep it offline or at least out of the
//!   directory the server reads);
//! - node directory = `security.certs_dir`: `ca.crt`, `node.crt`, `node.key`;
//! - client directory: `ca.crt`, `client.crt`, `client.key`.
//!
//! Every file is created new: an existing file is never overwritten (renewal = issue into a new
//! directory, then move the files, which `rustegond` picks up without a restart, FR-TLS-003).
//! Private keys are created owner-only (`FileSystem::create_new_private`).

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use rustegon_common::Redacted;
use rustegon_net::{
    CertAuthority, GeneratedCert, KeyAlgorithm, has_node_role, not_after_unix, parse_certificates,
};
use rustegon_sim_api::{Clock as _, FileSystem, OpenMode, OsRng, StdFileSystem, SystemClock};

use crate::{
    output::{CliResult, fail, io_err, out},
    secrets::read_file,
};

/// Largest certificate or key file read (rustegon-net's own cap is 4 MiB; PEM files written
/// here are a few KiB).
const MAX_PEM_FILE: u64 = 1 << 20;

/// CA certificate file name.
pub const CA_CERT: &str = "ca.crt";
/// CA private key file name.
pub const CA_KEY: &str = "ca.key";

/// CA key algorithm (security.md §5).
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum CaAlgorithm {
    /// ECDSA P-256 (default).
    #[default]
    EcdsaP256,
    /// Ed25519.
    Ed25519,
}

impl From<CaAlgorithm> for KeyAlgorithm {
    fn from(a: CaAlgorithm) -> Self {
        match a {
            CaAlgorithm::EcdsaP256 => Self::EcdsaP256,
            CaAlgorithm::Ed25519 => Self::Ed25519,
        }
    }
}

/// `rustegon cert …`.
#[derive(Debug, Subcommand)]
pub enum CertCommand {
    /// Create a CA (`ca.crt`, `ca.key`, 10 years).
    CreateCa(CreateCaArgs),
    /// Issue a node certificate (`node.crt`, `node.key`, 1 year) from an existing CA.
    CreateNode(CreateNodeArgs),
    /// Issue a client certificate (`client.crt`, `client.key`, 1 year) for X.509 login.
    CreateClient(CreateClientArgs),
    /// Show the expiry and kind of certificates.
    Show(ShowArgs),
    /// Print the CA certificate (PEM) of the local node to stdout (FR-INS-003, docker.md §4).
    ExportCa(ExportCaArgs),
}

/// `cert export-ca`.
#[derive(Debug, Args)]
pub struct ExportCaArgs {
    /// CA certificate file (default: the container's `/etc/rustegon/certs/ca.crt` or
    /// `<data_dir>/certs/ca.crt`).
    #[arg(long, value_name = "PATH")]
    pub ca: Option<PathBuf>,
}

/// `cert create-ca`.
#[derive(Debug, Args)]
pub struct CreateCaArgs {
    /// Output directory (created if missing; existing files are never overwritten).
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
    /// Common name of the CA.
    #[arg(long, default_value = "Rustegon CA")]
    pub name: String,
    /// Key algorithm of the CA.
    #[arg(long, value_enum, default_value_t)]
    pub algorithm: CaAlgorithm,
}

/// `cert create-node`.
#[derive(Debug, Args)]
pub struct CreateNodeArgs {
    /// Directory holding `ca.crt` and `ca.key`.
    #[arg(long, value_name = "DIR")]
    pub ca: PathBuf,
    /// Output directory (usable as `security.certs_dir`: `ca.crt` is copied there).
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
    /// Address of the node (DNS name or IP; repeatable; at least one).
    #[arg(long = "host", value_name = "HOST", required = true)]
    pub hosts: Vec<String>,
    /// Common name of the node certificate.
    #[arg(long, default_value = "node1")]
    pub name: String,
}

/// `cert create-client`.
#[derive(Debug, Args)]
pub struct CreateClientArgs {
    /// Directory holding `ca.crt` and `ca.key`.
    #[arg(long, value_name = "DIR")]
    pub ca: PathBuf,
    /// Output directory (`ca.crt` is copied there).
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
    /// Subject CN; X.509 login maps it to the user `x509:CN=<user>`.
    #[arg(long)]
    pub user: String,
}

/// `cert show`.
#[derive(Debug, Args)]
pub struct ShowArgs {
    /// PEM certificate files.
    #[arg(required = true, value_name = "FILE")]
    pub files: Vec<PathBuf>,
}

/// Runs a `cert` subcommand.
///
/// # Errors
/// Any failure, with its reason.
pub fn run(command: CertCommand) -> CliResult<()> {
    match command {
        CertCommand::CreateCa(a) => {
            create_dir(&a.out)?;
            let ca = write_new_ca(&a.out, &a.name, a.algorithm.into())?;
            report_cert("CA", &a.out.join(CA_CERT), ca.not_after_unix)?;
            out(&format!(
                "CA key written to {} (owner-only); keep it offline",
                a.out.join(CA_KEY).display()
            ))
        }
        CertCommand::CreateNode(a) => {
            let ca = load_ca(&a.ca)?;
            create_dir(&a.out)?;
            let cert = issue_node(&ca, &a.name, &a.hosts)?;
            write_pair(&cert, &a.out, "node")?;
            write_new(&a.out.join(CA_CERT), ca.cert_pem().as_bytes())?;
            report_cert("node", &a.out.join("node.crt"), cert.not_after_unix)
        }
        CertCommand::CreateClient(a) => {
            let ca = load_ca(&a.ca)?;
            create_dir(&a.out)?;
            let cert = ca
                .issue_client(&a.user, &SystemClock::new(), &OsRng)
                .map_err(|e| crate::output::CliError(format!("client certificate: {e}")))?;
            write_pair(&cert, &a.out, "client")?;
            write_new(&a.out.join(CA_CERT), ca.cert_pem().as_bytes())?;
            report_cert("client", &a.out.join("client.crt"), cert.not_after_unix)
        }
        CertCommand::ExportCa(a) => {
            let path = match a.ca {
                Some(p) => p,
                None => crate::health::local_ca()?,
            };
            let pem = read_file(&path, MAX_PEM_FILE)?;
            // Only a certificate file is printed: never one that also holds a private key.
            parse_certificates(&pem, &path)
                .map_err(|e| crate::output::CliError(format!("{}: {e}", path.display())))?;
            if rustegon_net::parse_private_key(&pem, &path).is_ok() {
                return fail(format!(
                    "{}: holds a private key; not printed",
                    path.display()
                ));
            }
            let Ok(text) = std::str::from_utf8(&pem) else {
                return fail(format!("{}: not PEM text", path.display()));
            };
            out(text.trim_end())
        }
        CertCommand::Show(a) => {
            let mut expired = false;
            for file in &a.files {
                expired |= show(file)?;
            }
            if expired {
                return fail("at least one certificate has expired");
            }
            Ok(())
        }
    }
}

/// Creates a directory (and its parents).
///
/// # Errors
/// I/O errors.
pub fn create_dir(dir: &Path) -> CliResult<()> {
    StdFileSystem
        .create_dir_all(dir)
        .map_err(|e| io_err(dir.display(), &e))
}

/// Writes a new non-secret file (refuses to overwrite) and syncs it.
///
/// # Errors
/// I/O errors, including `AlreadyExists`.
pub fn write_new(path: &Path, content: &[u8]) -> CliResult<()> {
    let fs = StdFileSystem;
    let mut file = fs
        .open(path, OpenMode::CreateNew)
        .map_err(|e| io_err(path.display(), &e))?;
    file.append(content)
        .and_then(|()| file.sync_data())
        .map_err(|e| io_err(path.display(), &e))
}

/// Generates a CA into `dir` (`ca.crt`, owner-only `ca.key`).
///
/// # Errors
/// Generation and I/O errors.
pub fn write_new_ca(
    dir: &Path,
    common_name: &str,
    algorithm: KeyAlgorithm,
) -> CliResult<GeneratedCert> {
    let (_, generated) =
        CertAuthority::generate(common_name, algorithm, &SystemClock::new(), &OsRng)
            .map_err(|e| crate::output::CliError(format!("CA generation: {e}")))?;
    generated
        .write_files(&StdFileSystem, &dir.join(CA_CERT), &dir.join(CA_KEY))
        .map_err(|e| crate::output::CliError(e.to_string()))?;
    Ok(generated)
}

/// Loads the CA of `dir` (`ca.crt` + `ca.key`).
///
/// # Errors
/// Missing or unparsable files.
pub fn load_ca(dir: &Path) -> CliResult<CertAuthority> {
    let cert = read_file(&dir.join(CA_CERT), MAX_PEM_FILE)?;
    let key = read_file(&dir.join(CA_KEY), MAX_PEM_FILE)?;
    let (Ok(cert), Ok(key)) = (std::str::from_utf8(&cert), std::str::from_utf8(&key)) else {
        return fail(format!("{}: CA files are not PEM text", dir.display()));
    };
    CertAuthority::from_pem(cert, &Redacted::new(key.to_owned()))
        .map_err(|e| crate::output::CliError(format!("{}: {e}", dir.display())))
}

/// Issues a node certificate for `hosts`.
///
/// # Errors
/// No host, an invalid DNS name.
pub fn issue_node(ca: &CertAuthority, name: &str, hosts: &[String]) -> CliResult<GeneratedCert> {
    ca.issue_node(name, hosts, &SystemClock::new(), &OsRng)
        .map_err(|e| crate::output::CliError(format!("node certificate: {e}")))
}

/// Writes `<dir>/<stem>.crt` and owner-only `<dir>/<stem>.key`.
///
/// # Errors
/// I/O errors, including `AlreadyExists`.
pub fn write_pair(cert: &GeneratedCert, dir: &Path, stem: &str) -> CliResult<()> {
    cert.write_files(
        &StdFileSystem,
        &dir.join(format!("{stem}.crt")),
        &dir.join(format!("{stem}.key")),
    )
    .map_err(|e| crate::output::CliError(e.to_string()))
}

/// Prints `<kind> certificate <path>: expires <date> (<n> days)`.
///
/// # Errors
/// The stdout write error.
pub fn report_cert(kind: &str, path: &Path, not_after_unix: i64) -> CliResult<()> {
    out(&format!(
        "{kind} certificate {}: expires {}",
        path.display(),
        expiry_text(not_after_unix)
    ))
}

fn now_unix() -> i64 {
    SystemClock::new()
        .wall()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `2027-01-02T03:04:05Z (364 days left)` or `… (EXPIRED)`.
fn expiry_text(not_after_unix: i64) -> String {
    let left = not_after_unix.saturating_sub(now_unix());
    if left <= 0 {
        format!("{} (EXPIRED)", utc_text(not_after_unix))
    } else {
        format!("{} ({} days left)", utc_text(not_after_unix), left / 86_400)
    }
}

/// Prints every certificate of a PEM file; returns whether one has expired.
fn show(path: &Path) -> CliResult<bool> {
    let pem = read_file(path, MAX_PEM_FILE)?;
    let certs = parse_certificates(&pem, path)
        .map_err(|e| crate::output::CliError(format!("{}: {e}", path.display())))?;
    let mut expired = false;
    for (i, cert) in certs.iter().enumerate() {
        let not_after = not_after_unix(cert)
            .map_err(|e| crate::output::CliError(format!("{}: {e}", path.display())))?;
        let node = has_node_role(cert)
            .map_err(|e| crate::output::CliError(format!("{}: {e}", path.display())))?;
        expired |= not_after <= now_unix();
        let kind = if node { "node" } else { "certificate" };
        let index = if certs.len() > 1 {
            format!("[{i}]")
        } else {
            String::new()
        };
        out(&format!(
            "{}{index}: {kind}, expires {}",
            path.display(),
            expiry_text(not_after)
        ))?;
    }
    Ok(expired)
}

/// RFC 3339 UTC text of a Unix timestamp (proleptic Gregorian calendar; days-from-civil
/// inverse after H. Hinnant, valid for every `i64` day count used by X.509 dates).
pub fn utc_text(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_text_matches_known_dates() {
        assert_eq!(utc_text(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_text(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_text(1_798_761_599), "2026-12-31T23:59:59Z");
        assert_eq!(utc_text(-1), "1969-12-31T23:59:59Z");
    }
}
