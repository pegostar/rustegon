// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Process-level test of the container start without Docker (FR-INS-003, PD-148, PD-149):
//! `rustegond --config-from-env` on an empty data directory initializes the node and, with
//! `RUSTEGON__SECURITY__TLS=true`, its TLS (auto-init, auto-TLS, admin from
//! `RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE`); `rustegon health` (the image's healthcheck) follows
//! the same variable and, like `rustegon cert export-ca`, finds the generated CA by default.
//! Without the variable the node is plain text and generates no certificate (ADR-034).
//! The image itself is tested by `scripts/docker-tests.sh` (TC-INS-007/008).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The server under test is a separate OS process on real time: waiting for it cannot go
// through the sim-api (shared harness in tests/common, as cli.rs and e2e_backup.rs).
#![allow(clippy::disallowed_methods)]

mod common;

use common::{ADMIN_PASSWORD, Daemon, Env, clean, rustegond};

/// `rustegond --config-from-env` as the image starts it, plus `extra` environment.
fn start(env: &Env, pw: &str, extra: &[(&str, &str)]) -> Daemon {
    let mut cmd = clean(rustegond());
    cmd.args([
        "--stop-on-stdin-eof",
        "--config-from-env",
        "--set",
        "log.stderr=false",
        "--set",
        "auth.scram_iterations=100000",
        "--set",
        "listen.shutdown_grace_secs=5",
    ])
    .env("RUSTEGON_MODE", "single-node")
    .env("RUSTEGON__NODE__DATA_DIR", env.data_dir())
    .env("RUSTEGON__LISTEN__GRPC", "127.0.0.1:0")
    .env("RUSTEGON__LISTEN__HTTP", "127.0.0.1:0")
    .env("RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE", pw)
    .envs(extra.iter().copied());
    Daemon::spawn(cmd)
}

/// ADR-034: the container default is plain text: no certificate is generated, the healthcheck
/// and the shell work without one.
#[test]
fn fr_ins_003_config_from_env_plain_text_by_default() {
    let env = Env::new();
    let pw = env.write("admin.pw", &format!("{ADMIN_PASSWORD}\n"));
    let data = env.data_dir().display().to_string();
    let daemon = start(&env, &pw, &[]);
    assert!(!env.data_dir().join("certs").exists() && !env.data_dir().join("ca").exists());
    let port = daemon.http_port.to_string();
    let ready = env
        .cli(
            &["health", "--ready", "--port", &port],
            &[("RUSTEGON__NODE__DATA_DIR", data.as_str())],
        )
        .ok();
    assert!(ready.stdout.contains("HTTP/1.1 200"), "{}", ready.stdout);
    let grpc = daemon.grpc_port.clone();
    env.cli(
        &[
            "user",
            "--host",
            "127.0.0.1",
            "--port",
            &grpc,
            "--user",
            "admin",
            "list",
        ],
        &[("RUSTEGON_PASSWORD", ADMIN_PASSWORD)],
    )
    .ok();
    env.record(&daemon.stop());
    env.assert_never_printed(ADMIN_PASSWORD);
}

#[test]
fn fr_ins_003_config_from_env_auto_init_tls_health_and_export_ca() {
    let env = Env::new();
    let pw = env.write("admin.pw", &format!("{ADMIN_PASSWORD}\n"));
    let data = env.data_dir().display().to_string();
    let tls_env = [("RUSTEGON__SECURITY__TLS", "true")];
    let daemon = start(&env, &pw, &tls_env);
    let ca_path = env.data_dir().join("certs").join("ca.crt");
    let ca = std::fs::read_to_string(&ca_path).unwrap();
    assert!(env.data_dir().join("ca").join("ca.key").is_file());
    // The healthcheck sees the same variables as the node inside the container.
    let data_env = [("RUSTEGON__NODE__DATA_DIR", data.as_str()), tls_env[0]];
    let port = daemon.http_port.to_string();

    let ready = env
        .cli(&["health", "--ready", "--port", &port], &data_env)
        .ok();
    assert!(
        ready.stdout.contains("/api/v1/health/ready: HTTP/1.1 200"),
        "{}",
        ready.stdout
    );
    // The port defaults to the one of RUSTEGON__LISTEN__HTTP, as inside the container.
    let listen = format!("127.0.0.1:{port}");
    let live = env
        .cli(
            &["health"],
            &[
                data_env[0],
                data_env[1],
                ("RUSTEGON__LISTEN__HTTP", listen.as_str()),
            ],
        )
        .ok();
    assert!(
        live.stdout.contains("/api/v1/health/live: HTTP/1.1 200"),
        "{}",
        live.stdout
    );

    let exported = env.cli(&["cert", "export-ca"], &data_env).ok();
    assert_eq!(exported.stdout.trim_end(), ca.trim_end());
    let key = env
        .data_dir()
        .join("certs")
        .join("node.key")
        .display()
        .to_string();
    env.cli(&["cert", "export-ca", "--ca", &key], &[]).failed();

    // The administrator got the password of the secret file.
    let grpc = daemon.grpc_port.clone();
    let ca_text = ca_path.display().to_string();
    env.cli(
        &[
            "user",
            "--host",
            "127.0.0.1",
            "--port",
            &grpc,
            "--ca",
            &ca_text,
            "--user",
            "admin",
            "list",
        ],
        &[("RUSTEGON_PASSWORD", ADMIN_PASSWORD)],
    )
    .ok();
    let output = daemon.stop();
    env.record(&output);

    // A restart keeps the generated CA; a stopped node is unhealthy (exit 1).
    let daemon = start(&env, &pw, &tls_env);
    assert_eq!(std::fs::read_to_string(&ca_path).unwrap(), ca);
    let port = daemon.http_port.to_string();
    env.record(&daemon.stop());
    let down = env
        .cli(&["health", "--ready", "--port", &port], &data_env)
        .failed();
    assert!(down.stderr.contains("rustegon:"), "{}", down.stderr);
    env.assert_never_printed(ADMIN_PASSWORD);
}
