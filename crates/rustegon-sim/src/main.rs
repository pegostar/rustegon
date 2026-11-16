// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegon-sim`: runs simulation workloads over a range of seeds (testing-strategy.md §3).
//!
//! ```text
//! cargo run -p rustegon-sim -- --seeds 200 --workload all
//! cargo run -p rustegon-sim -- --workload rw-register-faults --isolation snapshot --seed 0x2a
//! ```
//!
//! Options: `--workload rw-register | rw-register-faults | index-build | all` (default `all`;
//! `index-build` ignores the isolation and register options), `--isolation
//! serializable | snapshot | read-committed | all` (default `all`), `--seeds N` (default 20),
//! `--start-seed S` (default 1), `--seed S` (exactly one seed), `--registers N`, `--clients N`,
//! `--txns N`, `--no-io-restart` (see `RegisterConfig::io_restart`). Seeds accept decimal or `0x`
//! hex. Every failure prints its seed and the command that reproduces it; the exit status is
//! non-zero if any seed failed.

use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};

use rustegon_sim::workload::{
    ISOLATIONS, IndexBuildConfig, IndexBuildReport, RegisterConfig, RunStats, isolation_name,
    parse_isolation, run_index_build, run_rw_register,
};
use rustegon_txn::Isolation;

/// Parsed command line.
struct Args {
    faults: Vec<bool>,
    index_build: bool,
    isolations: Vec<Isolation>,
    start: u64,
    seeds: u64,
    registers: Option<u64>,
    clients: Option<usize>,
    txns: Option<usize>,
    io_restart: bool,
}

fn parse_u64(flag: &str, v: Option<String>) -> Result<u64, String> {
    let v = v.ok_or_else(|| format!("{flag} needs a value"))?;
    let parsed = match v.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => v.parse(),
    };
    parsed.map_err(|e| format!("{flag} {v}: {e}"))
}

fn parse_usize(flag: &str, v: Option<String>) -> Result<usize, String> {
    let n = parse_u64(flag, v)?;
    usize::try_from(n).map_err(|e| format!("{flag} {n}: {e}"))
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        faults: vec![false, true],
        index_build: true,
        isolations: ISOLATIONS.to_vec(),
        start: 1,
        seeds: 20,
        registers: None,
        clients: None,
        txns: None,
        io_restart: true,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--workload" => {
                (args.faults, args.index_build) = match it.next().as_deref() {
                    Some("rw-register") => (vec![false], false),
                    Some("rw-register-faults") => (vec![true], false),
                    Some("index-build") => (vec![], true),
                    Some("all") => (vec![false, true], true),
                    other => return Err(format!("unknown workload {other:?}")),
                };
            }
            "--isolation" => {
                let v = it.next().unwrap_or_default();
                args.isolations = if v == "all" {
                    ISOLATIONS.to_vec()
                } else {
                    vec![parse_isolation(&v).ok_or_else(|| format!("unknown isolation {v:?}"))?]
                };
            }
            "--seeds" => args.seeds = parse_u64(&flag, it.next())?,
            "--start-seed" => args.start = parse_u64(&flag, it.next())?,
            "--seed" => {
                args.start = parse_u64(&flag, it.next())?;
                args.seeds = 1;
            }
            "--registers" => args.registers = Some(parse_u64(&flag, it.next())?),
            "--clients" => args.clients = Some(parse_usize(&flag, it.next())?),
            "--txns" => args.txns = Some(parse_usize(&flag, it.next())?),
            "--no-io-restart" => args.io_restart = false,
            other => return Err(format!("unknown option {other:?} (see crate docs)")),
        }
    }
    Ok(args)
}

/// Runs the `index-build` workload over the seed range; returns the number of failed seeds.
fn run_index_builds(args: &Args, out: &mut impl Write) -> Result<u64, Box<dyn Error>> {
    let (mut failures, mut passed, mut public) = (0u64, 0u64, 0u64);
    let mut total = IndexBuildReport::default();
    for seed in args.start..args.start.saturating_add(args.seeds) {
        match run_index_build(&IndexBuildConfig::new(seed)) {
            Ok(r) => {
                passed += 1;
                public += u64::from(r.public);
                total.steps += r.steps;
                total.writes += r.writes;
                total.rejected += r.rejected;
                total.reopens += r.reopens;
            }
            Err(failure) => {
                failures += 1;
                writeln!(out, "FAIL {failure}")?;
            }
        }
    }
    writeln!(
        out,
        "index-build: {passed}/{} seeds passed ({public} public); steps {}, writes {}, \
         rejected {}, reopens {}",
        args.seeds, total.steps, total.writes, total.rejected, total.reopens
    )?;
    out.flush()?;
    Ok(failures)
}

fn main() -> Result<ExitCode, Box<dyn Error>> {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            writeln!(io::stderr(), "rustegon-sim: {msg}")?;
            return Ok(ExitCode::from(2));
        }
    };
    let mut out = io::stdout().lock();
    let mut failures = 0u64;
    for &faults in &args.faults {
        for &isolation in &args.isolations {
            let mut total = RunStats::default();
            let mut passed = 0u64;
            for seed in args.start..args.start.saturating_add(args.seeds) {
                let mut config = RegisterConfig::new(seed, isolation, faults);
                config.registers = args.registers.unwrap_or(config.registers);
                config.clients = args.clients.unwrap_or(config.clients);
                config.txns = args.txns.unwrap_or(config.txns);
                config.io_restart = args.io_restart;
                match run_rw_register(&config) {
                    Ok(report) => {
                        passed += 1;
                        total.add(&report.stats);
                    }
                    Err(failure) => {
                        failures += 1;
                        writeln!(out, "FAIL {failure}")?;
                    }
                }
            }
            let name = RegisterConfig::new(0, isolation, faults).workload_name();
            writeln!(
                out,
                "{name} {}: {passed}/{} seeds passed; {total:?}",
                isolation_name(isolation),
                args.seeds
            )?;
            out.flush()?;
        }
    }
    if args.index_build {
        failures += run_index_builds(&args, &mut out)?;
    }
    Ok(if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
