// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegon-bench`: runs benchmark workloads and writes results with an environment manifest
//! into `bench/results/` (performance-benchmarks.md §2). Numbers are quoted only from those
//! files (implementation-rules.md §4).

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use clap::{Parser, Subcommand};
use rustegon_bench::{manifest::Manifest, storage};
use rustegon_sim_api::{Clock, FileSystem, OpenMode, StdFileSystem, SystemClock};

#[derive(Parser)]
#[command(name = "rustegon-bench", about = "Rustegon benchmark runner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Storage engine microbenchmarks (BM-STO-*).
    Storage {
        /// Workload definition (`bench/workloads/bm-sto-*.toml`).
        #[arg(long)]
        workload: PathBuf,
        /// Scratch directory for the store (must not hold one); on the device under test.
        #[arg(long)]
        dir: PathBuf,
        /// Directory receiving `<date>-<workload>-<env>.json`.
        #[arg(long, default_value = "bench/results")]
        out: PathBuf,
        /// Environment label: `REF-1N` only on reference hardware, otherwise e.g. `dev-laptop`.
        #[arg(long)]
        env: String,
        /// Commit being measured (e.g. `git rev-parse HEAD`).
        #[arg(long, default_value = "unknown")]
        commit: String,
        /// Free-form notes for the manifest (file system, disk model, power plan, ...).
        #[arg(long, default_value = "")]
        notes: String,
        /// JSON file describing the host (CPU, RAM, disk, file system, OS build, toolchain),
        /// embedded verbatim as `environment.host` (written by `scripts/bench-host.ps1`).
        #[arg(long)]
        host_file: Option<PathBuf>,
        /// Run label appended to the result file name (e.g. `r1` for repetition 1).
        #[arg(long)]
        label: Option<String>,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(path) => {
            // The output path is the result of the command: print it for scripts.
            #[allow(clippy::print_stdout)]
            {
                println!("{}", path.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("rustegon-bench: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<PathBuf, String> {
    let Command::Storage {
        workload,
        dir,
        out,
        env,
        commit,
        notes,
        host_file,
        label,
    } = cli.command;
    let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
    let text = read_to_string(fs.as_ref(), &workload)?;
    let workload: storage::Workload = toml::from_str(&text).map_err(|e| e.to_string())?;
    let clock = SystemClock::new();
    let result = storage::run(&fs, &clock, &dir, &workload).map_err(|e| e.to_string())?;
    let host = match &host_file {
        Some(path) => serde_json::from_str(&read_to_string(fs.as_ref(), path)?)
            .map_err(|e| format!("{}: {e}", path.display()))?,
        None => serde_json::Value::Null,
    };
    let mut manifest = Manifest::collect(&env, &commit, &notes, clock.wall());
    manifest.host = host;
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "environment": manifest,
        "result": result,
    }))
    .map_err(|e| e.to_string())?;
    fs.create_dir_all(&out).map_err(|e| e.to_string())?;
    let label = label
        .map(|l| format!("-{}", l.to_lowercase()))
        .unwrap_or_default();
    let path = out.join(format!(
        "{}-{}{label}-{}.json",
        manifest.date,
        workload.id.to_lowercase(),
        env.to_lowercase()
    ));
    let mut file = fs
        .open(&path, OpenMode::CreateNew)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.append(&body).map_err(|e| e.to_string())?;
    file.sync_data().map_err(|e| e.to_string())?;
    Ok(path)
}

fn read_to_string(fs: &dyn FileSystem, path: &std::path::Path) -> Result<String, String> {
    let file = fs
        .open(path, OpenMode::Read)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let size =
        usize::try_from(file.size().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let mut buf = vec![0; size];
    file.read_exact_at(&mut buf, 0).map_err(|e| e.to_string())?;
    String::from_utf8(buf).map_err(|e| e.to_string())
}
