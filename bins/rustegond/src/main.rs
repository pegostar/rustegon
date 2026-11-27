// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegond` server daemon.
//!
//! Loads and validates the configuration (file < env < flags; `--print-config` prints it with
//! secrets redacted and exits), initialises JSON logging, then runs a single node: engine,
//! security layer, first-admin bootstrap, gRPC (7700) and REST (7780) listeners with TLS,
//! certificate hot reload and graceful shutdown (`node`, PD-054). Peer listener and cluster
//! membership arrive with M5. With `--service` the same node runs as the Windows service
//! `Rustegon` (`service`, PD-206).

mod allocator;
mod config;
mod from_env;
mod gui;
#[cfg(feature = "heap-stats")]
mod heap_stats;
mod maintenance;
mod node;
mod pitr;
mod restore;
mod service;
mod signals;
mod slow_io;
mod tls;
mod token_key;

use std::{
    io::{self, Write as _},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
};

use clap::Parser;
use rustegon_common::{
    Error, ErrorCode, Result,
    logging::{self, LogContext, LogSettings},
    settings::{NodeSettings, Sources},
};
use rustegon_sim_api::{StdFileSystem, SystemClock};

/// Environment variable naming the first admin's password file (docker.md; read on the first
/// start only, like `--admin-password-file`).
const ADMIN_PASSWORD_FILE_ENV: &str = "RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE";

/// `--version`: the dev version stamped by `cargo xtask dist`
/// (`<semver>-dev.<commits>+g<sha>`, PD-154), else the crate version of a plain `cargo build`.
const VERSION: &str = match option_env!("RUSTEGON_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Rustegon server daemon.
#[derive(Debug, Parser)]
#[command(name = "rustegond", version = VERSION, about)]
// Independent command-line switches, not a state machine.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Args {
    /// Configuration file (`rustegon.toml`).
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Container start (docker.md): image defaults (data directory `/var/lib/rustegon`,
    /// listeners on all interfaces) under the optional `/etc/rustegon/rustegon.toml` (or
    /// `--config`), the environment and `--set`; `RUSTEGON_MODE`, `RUSTEGON_AUTO_INIT` and
    /// `RUSTEGON_AUTO_TLS` select the first-start steps (FR-INS-003, PD-148).
    #[arg(long)]
    config_from_env: bool,
    /// Override a setting (repeatable; highest precedence over env, file and defaults).
    #[arg(long = "set", value_name = "SECTION.KEY=VALUE")]
    set: Vec<String>,
    /// Print the effective configuration with secrets redacted, then exit.
    #[arg(long)]
    print_config: bool,
    /// Password of the first administrator, read from this file on the first start (else
    /// `RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE`; without either a password is generated into
    /// `<data_dir>/initial-admin-password`).
    #[arg(long, value_name = "PATH")]
    admin_password_file: Option<PathBuf>,
    /// Shut down gracefully when standard input reaches its end (for supervisors and tests
    /// that own the pipe; works on every platform).
    #[arg(long)]
    stop_on_stdin_eof: bool,
    /// Run as the Windows service `Rustegon` under the Service Control Manager (registered by
    /// the installer; Windows only). Stop, shutdown and preshutdown drain like Ctrl-C.
    #[arg(long, conflicts_with_all = ["print_config", "stop_on_stdin_eof"])]
    service: bool,
}

/// How a supervisor (the Windows SCM) drives the node besides the console signals.
#[derive(Default)]
pub(crate) struct Supervisor {
    /// Completes with the reason of a requested graceful shutdown.
    pub stop: Option<tokio::sync::oneshot::Receiver<&'static str>>,
    /// Called once when both listeners are bound.
    pub on_ready: Option<Box<dyn FnOnce() + Send>>,
}

pub(crate) fn run(args: Args, supervisor: Supervisor) -> Result<()> {
    // Startup reads happen before any engine exists; they are not part of simulated I/O.
    let read = |path: &PathBuf| {
        std::fs::read_to_string(path).map_err(|e| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("cannot read {}", path.display()),
            )
            .with_source(e)
        })
    };
    let mut file = args.config.as_ref().map(read).transpose()?;
    // Non-UTF-8 variables cannot be Rustegon settings; skip them instead of panicking.
    let env: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let plan = if args.config_from_env {
        // The image's configuration file is optional (docker.md §1).
        let default_file = PathBuf::from(from_env::CONFIG_FILE);
        if file.is_none() && default_file.is_file() {
            file = Some(read(&default_file)?);
        }
        let mounted_certs = PathBuf::from(from_env::MOUNTED_CERTS_DIR)
            .join("node.crt")
            .is_file();
        let (text, plan) = from_env::layer(&env, file.as_deref(), mounted_certs)?;
        file = Some(text);
        Some(plan)
    } else {
        None
    };
    let sources = Sources {
        file,
        env,
        flags: args.set,
    };
    let registry = Arc::new(config::registry()?);
    let config = registry.load(&sources)?;

    if args.print_config {
        let dump = config.dump_redacted()?;
        return io::stdout()
            .lock()
            .write_all(dump.as_bytes())
            .map_err(|e| Error::new(ErrorCode::Internal, "cannot write stdout").with_source(e));
    }

    let node: NodeSettings = config.section()?;
    let log: LogSettings = config.section()?;
    let log_dir = log
        .dir
        .clone()
        .unwrap_or_else(|| node.data_dir.join("logs"));
    let _guard = logging::init(
        &log,
        &log_dir,
        LogContext {
            fs: Arc::new(StdFileSystem),
            clock: Arc::new(SystemClock::new()),
            node_id: None,
        },
    )?;
    tracing::info!(
        version = VERSION,
        data_dir = %node.data_dir.display(),
        "rustegond started"
    );
    if let Some(plan) = &plan {
        from_env::prepare(&config, plan)?;
    }
    let admin_password_file = args
        .admin_password_file
        .or_else(|| std::env::var_os(ADMIN_PASSWORD_FILE_ENV).map(PathBuf::from));
    // Static settings changed in the console are written to the configuration file (PD-230);
    // in the container mode the file is composed from the environment, so they stay read-only.
    let config_file = if args.config_from_env {
        None
    } else {
        args.config.clone()
    };
    let result = node::run(
        config,
        node::Options {
            registry,
            sources,
            config_file,
            admin_password_file,
            stop_on_stdin_eof: args.stop_on_stdin_eof,
            stop: supervisor.stop,
            on_ready: supervisor.on_ready,
        },
    );
    if let Err(e) = &result {
        // Also in the log file: a service manager may discard stderr.
        tracing::error!(error = %e, "rustegond failed");
    }
    result
}

fn main() -> ExitCode {
    let args = Args::parse();
    let result = if args.service {
        service::run(args)
    } else {
        run(args, Supervisor::default())
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rustegond: {e}");
            ExitCode::from(2)
        }
    }
}
