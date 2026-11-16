// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegon` command-line tool (M4, PD-058):
//! - `init`: CA, node certificate and configuration of a single node, and the source of the
//!   first administrator's password (FR-TLS-002, FR-SEC-003);
//! - `cert`: create a CA, issue node and client certificates, show expiry (FR-TLS-002),
//!   print the local CA (`export-ca`, FR-INS-003);
//! - `health`: liveness/readiness of the local node, the container healthcheck (FR-INS-003);
//! - `user` / `role`: administration over gRPC with SCRAM or API-key login (FR-SEC-001/002);
//! - `shell`: RGQL REPL and script runner over gRPC (FR-QL-001, FR-TXN-001);
//! - `backup`, `snapshot`, `dump`, `restore`: single-node backup and restore (M13a, FR-BKP-*,
//!   PD-062, PD-077).
//!
//! Exit codes: 0 success, 1 failed command, 2 usage error.
//! Import/export and debug commands arrive with their milestones.

mod admin;
mod backup;
mod cert;
mod client;
mod health;
mod init;
mod output;
mod secrets;
mod shell;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// `--version`: the dev version stamped by `cargo xtask dist`
/// (`<semver>-dev.<commits>+g<sha>`, PD-154), else the crate version of a plain `cargo build`.
const VERSION: &str = match option_env!("RUSTEGON_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Rustegon command-line tool.
#[derive(Debug, Parser)]
#[command(name = "rustegon", version = VERSION, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prepare a single node: CA, node certificate, configuration, first administrator.
    Init(init::InitArgs),
    /// Certificate management.
    #[command(subcommand)]
    Cert(cert::CertCommand),
    /// User administration.
    User(admin::UserArgs),
    /// Role administration.
    Role(admin::RoleArgs),
    /// API key administration.
    Apikey(admin::ApiKeyArgs),
    /// RGQL shell.
    Shell(shell::ShellArgs),
    /// Physical backups: create, list (online), verify, restore (offline).
    Backup(backup::BackupArgs),
    /// Local snapshots: create, list, delete (online), restore (offline).
    Snapshot(backup::SnapshotArgs),
    /// Logical dump of databases/collections into a directory (online).
    Dump(backup::DumpArgs),
    /// Logical restore of a `rustegon dump` directory (online).
    Restore(backup::RestoreArgs),
    /// Check that the local node is live (or `--ready`) over HTTPS; exit 0 or 1.
    Health(health::HealthArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init(args) => init::run(&args),
        Command::Cert(command) => cert::run(command),
        Command::User(args) => admin::run_user(args),
        Command::Role(args) => admin::run_role(args),
        Command::Apikey(args) => admin::run_api_key(args),
        Command::Shell(args) => shell::run(args),
        Command::Backup(args) => backup::run_backup(args),
        Command::Snapshot(args) => backup::run_snapshot(args),
        Command::Dump(args) => backup::run_dump(&args),
        Command::Restore(args) => backup::run_restore(&args),
        Command::Health(args) => health::run(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            output::err(&format!("rustegon: {e}"));
            ExitCode::FAILURE
        }
    }
}
