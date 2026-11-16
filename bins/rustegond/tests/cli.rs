// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! End-to-end tests of the `rustegond` binary: version, configuration layering, logging.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Output};

fn rustegond() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustegond"));
    // Isolate from any RUSTEGON__* variables of the developer's shell.
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("RUSTEGON__") {
            cmd.env_remove(k);
        }
    }
    cmd
}

fn run(cmd: &mut Command) -> (Output, String, String) {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.stderr.clone()).unwrap();
    (out, stdout, stderr)
}

#[test]
fn rustegond_version_prints_package_version() {
    let (out, stdout, _) = run(rustegond().arg("--version"));
    assert!(out.status.success());
    assert_eq!(
        stdout.trim(),
        format!("rustegond {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn tc_ops_001_print_config_applies_flag_env_file_precedence() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rustegon.toml");
    std::fs::write(
        &file,
        "[log]\nlevel = \"debug\"\nmax_files = 3\nstderr = false\n",
    )
    .unwrap();
    let (out, stdout, stderr) = run(rustegond()
        .arg("--config")
        .arg(&file)
        .env("RUSTEGON__LOG__LEVEL", "info")
        .env("RUSTEGON__LOG__MAX_FILES", "5")
        .args(["--set", "log.level=warn", "--print-config"]));
    assert!(out.status.success(), "{stderr}");
    assert!(
        stdout.contains("level = \"warn\""),
        "flag must win:\n{stdout}"
    );
    assert!(
        stdout.contains("max_files = 5"),
        "env must beat file:\n{stdout}"
    );
    assert!(
        stdout.contains("stderr = false"),
        "file must beat default:\n{stdout}"
    );
    assert!(
        stdout.contains("data_dir = \"rustegon-data\""),
        "default:\n{stdout}"
    );
}

#[test]
fn tc_ops_001_invalid_configuration_fails_with_reason() {
    let (out, _, stderr) = run(rustegond()
        .env("RUSTEGON__LOG__MAX_FILES", "0")
        .arg("--print-config"));
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr.contains("RGN-1001 InvalidArgument"), "{stderr}");
    assert!(
        stderr.contains("log.max_files = 0 outside 1..=10000"),
        "{stderr}"
    );

    let (out, _, stderr) = run(rustegond().args(["--set", "log.colour=red"]));
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr.contains("unknown setting log.colour"), "{stderr}");

    let (out, _, stderr) = run(rustegond().args(["--config", "does-not-exist.toml"]));
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr.contains("cannot read does-not-exist.toml"),
        "{stderr}"
    );
}

/// TC-BKP-014 (PD-068): a running node holds `<data_dir>/store/LOCK`; a second node on the
/// same data directory refuses to start with RGN-3002 instead of opening the store twice.
#[test]
fn tc_bkp_014_second_rustegond_on_the_same_data_dir_is_refused() {
    use std::io::{BufRead as _, BufReader};
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let args = |cmd: &mut Command| {
        cmd.arg("--set")
            .arg(format!("node.data_dir={}", data_dir.display()))
            .args(["--set", "log.stderr=false"])
            .arg("--stop-on-stdin-eof")
            .args([
                "--set",
                "listen.grpc=127.0.0.1:0",
                "--set",
                "listen.http=127.0.0.1:0",
            ])
            .args(["--set", "auth.scram_iterations=100000"]);
    };
    let mut first = rustegond();
    args(&mut first);
    let mut first = first
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let stdout = first.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let ready = lines
        .by_ref()
        .map_while(Result::ok)
        .any(|l| l.contains("ready"));
    assert!(ready, "the first node never became ready");
    assert!(data_dir.join("store").join("LOCK").exists());

    let mut second = rustegond();
    args(&mut second);
    let (out, _, stderr) = run(&mut second);
    // Stop the first node (stdin EOF) before asserting, so a failure does not leak it.
    drop(first.stdin.take());
    let status = first.wait().unwrap();
    assert!(!out.status.success(), "the second node started: {stderr}");
    assert!(
        stderr.contains("RGN-3002") && stderr.contains("in use"),
        "{stderr}"
    );
    assert!(status.success(), "the first node failed to stop cleanly");

    // Once the first node is gone (lock released by the OS), the store opens again.
    let mut third = rustegond();
    args(&mut third);
    let (out, _, stderr) = run(&mut third);
    assert!(out.status.success(), "{stderr}");
}

#[test]
fn tc_ops_002_startup_writes_json_log_in_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    // Plain text keeps this test free of certificates; stdin is closed by `output()`, so the
    // server stops right after becoming ready.
    let (out, _, stderr) = run(rustegond()
        .arg("--set")
        .arg(format!("node.data_dir={}", data_dir.display()))
        .args(["--set", "log.stderr=false"])
        .arg("--stop-on-stdin-eof")
        .args([
            "--set",
            "listen.grpc=127.0.0.1:0",
            "--set",
            "listen.http=127.0.0.1:0",
        ])
        .args(["--set", "auth.scram_iterations=100000"]));
    assert!(out.status.success(), "{stderr}");
    let logs: Vec<_> = std::fs::read_dir(data_dir.join("logs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(logs.len(), 1);
    let text = std::fs::read_to_string(&logs[0]).unwrap();
    let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(first["msg"], "rustegond started");
    assert_eq!(first["level"], "INFO");
    assert_eq!(first["channel"], "main");
    assert_eq!(first["version"], env!("CARGO_PKG_VERSION"));
    assert!(first["ts"].as_str().unwrap().ends_with('Z'));
}

/// FR-INS-003 (PD-148): `--config-from-env` needs no file; the image defaults apply and the
/// environment overrides them; an unsupported `RUSTEGON_MODE` fails the start with its reason.
#[test]
fn fr_ins_003_config_from_env_defaults_and_mode() {
    let (out, stdout, stderr) = run(rustegond()
        .env_remove("RUSTEGON_MODE")
        .env("RUSTEGON__LISTEN__GRPC", "127.0.0.1:7701")
        .args(["--config-from-env", "--print-config"]));
    assert!(out.status.success(), "{stderr}");
    assert!(
        stdout.contains("data_dir = \"/var/lib/rustegon\""),
        "{stdout}"
    );
    assert!(stdout.contains("http = \"0.0.0.0:7780\""), "{stdout}");
    assert!(stdout.contains("grpc = \"127.0.0.1:7701\""), "{stdout}");

    let (out, _, stderr) = run(rustegond()
        .env("RUSTEGON_MODE", "cluster")
        .args(["--config-from-env", "--print-config"]));
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr.contains("RUSTEGON_MODE=cluster"), "{stderr}");
}
