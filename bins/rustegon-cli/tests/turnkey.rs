// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Process-level tests of the turnkey bootstrap (ADR-036; FR-SEC-003, FR-INS-001/002):
//! `rustegon init --turnkey` and a real `rustegond` started on the result (harness in
//! `tests/common/mod.rs`). The harness speaks TLS, so these nodes add `--tls`; the safeguards
//! do not depend on it (the packages' plain-text layout is covered by
//! `scripts/package-tests.sh` and the GUI e2e test).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
// The server under test is a separate OS process on real time.
#![allow(clippy::disallowed_methods)]

mod common;

use std::process::Stdio;

use common::{ADMIN_PASSWORD, Env, clean, conn, files_under, https, rustegond, with};

const TURNKEY: &str = "admin";

fn turnkey_init(env: &Env) -> common::Run {
    let data = env.data_dir().display().to_string();
    let logs = env.path("logs").display().to_string();
    env.cli(
        &[
            "init",
            "--data-dir",
            &data,
            "--grpc-port",
            "0",
            "--http-port",
            "0",
            "--tls",
            "--turnkey",
            "--log-dir",
            &logs,
        ],
        &[],
    )
}

/// TC-SEC-021 / TC-SEC-023 (ADR-036): the turnkey init warns and writes no password; the first
/// start creates `admin`/`admin` flagged must-change; until the change every operation except
/// change-password/logout/whoami is refused on REST, gRPC and the CLI; after it the old
/// password no longer works and the new one does; no log line carries the password.
#[test]
fn tc_sec_021_turnkey_admin_must_change_before_anything_else() {
    let env = Env::new();
    let init = turnkey_init(&env).ok();
    assert!(
        init.stderr.contains("warning: turnkey install"),
        "{}",
        init.stderr
    );
    assert!(
        init.stdout.contains("sign in as admin / admin"),
        "{}",
        init.stdout
    );
    assert!(!env.data_dir().join("admin-password").exists());

    let daemon = env.start(&[]);
    assert!(
        !env.data_dir().join("initial-admin-password").exists(),
        "no generated password in turnkey mode"
    );
    let ca = env.ca();

    // REST: the login says must-change; data and admin endpoints are refused; whoami is not.
    let login = https(
        &ca,
        daemon.http_port,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({"user": "admin", "password": TURNKEY, "delivery": "token"})),
    )
    .ok()
    .json();
    assert_eq!(login["mustChangePassword"], true, "{login}");
    let token = login["sessionToken"].as_str().unwrap().to_owned();
    for (method, path) in [
        ("GET", "/api/v1/databases"),
        ("GET", "/api/v1/users"),
        ("GET", "/metrics"),
    ] {
        let r = https(&ca, daemon.http_port, method, path, Some(&token), None);
        assert_eq!(r.status, 403, "{method} {path}: {}", r.body);
        assert!(r.body.contains("password_change_required"), "{}", r.body);
    }
    https(
        &ca,
        daemon.http_port,
        "GET",
        "/api/v1/auth/me",
        Some(&token),
        None,
    )
    .ok();

    // gRPC through the CLI: refused with the must-change message.
    let base = conn(&env, &daemon, &ca);
    let shell = with(
        &with(&["shell"], &base),
        &["--user", "admin", "-c", "CREATE DATABASE shop"],
    );
    let refused = env.cli(&shell, &[("RUSTEGON_PASSWORD", TURNKEY)]).failed();
    assert!(
        refused.stderr.contains("must be changed"),
        "{}",
        refused.stderr
    );
    let users = with(&with(&["user"], &base), &["--user", "admin", "list"]);
    let refused = env.cli(&users, &[("RUSTEGON_PASSWORD", TURNKEY)]).failed();
    assert!(
        refused.stderr.contains("must be changed"),
        "{}",
        refused.stderr
    );

    // The change itself: policy-checked (the turnkey password cannot be kept).
    let passwd = with(&with(&["user"], &base), &["--user", "admin", "passwd"]);
    env.cli(
        &passwd,
        &[
            ("RUSTEGON_PASSWORD", TURNKEY),
            ("RUSTEGON_NEW_PASSWORD", TURNKEY),
        ],
    )
    .failed();
    env.cli(
        &passwd,
        &[
            ("RUSTEGON_PASSWORD", TURNKEY),
            ("RUSTEGON_NEW_PASSWORD", ADMIN_PASSWORD),
        ],
    )
    .ok();
    env.cli(&shell, &[("RUSTEGON_PASSWORD", TURNKEY)]).failed();
    let done = env
        .cli(&shell, &[("RUSTEGON_PASSWORD", ADMIN_PASSWORD)])
        .ok();
    assert!(!done.stderr.contains("must be changed"), "{}", done.stderr);

    let output = daemon.stop();
    assert!(!output.contains("initial-admin-password"), "{output}");
    // TC-SEC-023: no log field named like a password carries a value, and the file logs
    // went to --log-dir.
    let logs = files_under(&env.path("logs"));
    assert!(!logs.is_empty(), "file logs under --log-dir");
    for (path, bytes) in logs {
        for line in String::from_utf8_lossy(&bytes).lines() {
            let Ok(serde_json::Value::Object(record)) = serde_json::from_str(line) else {
                continue;
            };
            let fields = record
                .get("fields")
                .and_then(|f| f.as_object())
                .unwrap_or(&record);
            for (key, value) in fields {
                assert!(
                    !(key.contains("password") && value.as_str() == Some(TURNKEY)),
                    "{}: {line}",
                    path.display()
                );
            }
            assert!(
                !line.contains("admin/admin") && !line.contains("admin / admin"),
                "{line}"
            );
        }
    }
    env.assert_never_printed(ADMIN_PASSWORD);
}

/// TC-SEC-022 (ADR-036): `rustegond` refuses to start while `admin` has the turnkey password
/// and a listener is not on loopback, on the first start (bootstrap, then refusal) and later;
/// after the password change the same configuration starts.
#[test]
fn tc_sec_022_turnkey_password_refuses_a_non_loopback_listener() {
    let env = Env::new();
    turnkey_init(&env).ok();
    let exposed = || {
        let out = clean(rustegond())
            .args(["--stop-on-stdin-eof", "--config", &env.config()])
            .args(["--set", "log.stderr=false"])
            .args(["--set", "auth.scram_iterations=100000"])
            .args(["--set", "listen.http=0.0.0.0:0"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            out.status,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (status, stderr) = exposed();
    assert_eq!(status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("turnkey bootstrap password"), "{stderr}");
    assert!(stderr.contains("0.0.0.0"), "{stderr}");

    // On loopback the node starts; the admin was created by the refused first start.
    let daemon = env.start(&[]);
    let ca = env.ca();
    let passwd = with(
        &with(&["user"], &conn(&env, &daemon, &ca)),
        &["--user", "admin", "passwd"],
    );
    env.cli(
        &passwd,
        &[
            ("RUSTEGON_PASSWORD", TURNKEY),
            ("RUSTEGON_NEW_PASSWORD", ADMIN_PASSWORD),
        ],
    )
    .ok();
    daemon.stop();
    let (status, stderr) = exposed();
    // Changed: no refusal any more (the node then runs until stdin ends, which is at once).
    assert!(!stderr.contains("turnkey"), "{stderr}");
    assert_eq!(status.code(), Some(0), "{stderr}");
}
