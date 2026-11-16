// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Process-level tests of the `rustegon init` wizard (FR-INS-004, AC-INS-004, PD-151): scripted
//! answers on stdin (`--interactive`, no terminal needed), the files it writes, and a real
//! `rustegond` started on the result (harness in `tests/common/mod.rs`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
// The server under test is a separate OS process on real time.
#![allow(clippy::disallowed_methods)]

mod common;

use std::{io::Write as _, path::Path, process::Stdio};

use common::{ADMIN_PASSWORD, Env, Run, clean, conn, files_containing};

/// `rustegon init --interactive extra…` with `answers` (one per line) on stdin.
fn wizard(env: &Env, extra: &[&str], answers: &[&str]) -> Run {
    let mut child = clean(Path::new(env!("CARGO_BIN_EXE_rustegon")))
        .arg("init")
        .arg("--interactive")
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = answers.join("\n");
    input.push('\n');
    // The wizard may stop reading early (a refusal): a broken pipe is part of the scenario.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    let run: Run = child.wait_with_output().unwrap().into();
    env.record(&run.text());
    run
}

/// Whether nothing of a node was written into the data directory.
fn assert_nothing_written(env: &Env) {
    for p in ["rustegon.toml", "ca", "certs", "admin-password", "secrets"] {
        assert!(!env.data_dir().join(p).exists(), "{p} was written");
    }
}

#[cfg(unix)]
fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "{}", path.display());
}

#[cfg(not(unix))]
fn assert_owner_only(path: &Path) {
    // Windows: the file inherits its directory's ACL (PD-046); only presence is checked.
    assert!(path.is_file(), "{}", path.display());
}

/// FR-TLS-001 / ADR-034: the wizard's default is plain text: TLS is off unless answered yes, no
/// CA or certificate is written, the summary says so, and `rustegond` started on the result
/// serves the shell and `rustegon health` without any certificate.
#[test]
fn fr_tls_001_wizard_default_is_plain_text_and_rustegond_serves_it() {
    let env = Env::new();
    let pw = env.write("admin.pw", ADMIN_PASSWORD);
    let data = env.data_dir().display().to_string();
    let init = wizard(
        &env,
        &["--admin-password-file", &pw],
        &[&data, "", "127.0.0.1", "0", "0", "", "n", ""],
    )
    .ok();
    assert!(init.stderr.contains("Enable TLS"), "{}", init.stderr);
    assert!(
        init.stderr.contains("TLS                 off"),
        "{}",
        init.stderr
    );
    assert!(init.stdout.contains("TLS is off"), "{}", init.stdout);
    assert!(!env.data_dir().join("ca").exists());
    assert!(!env.data_dir().join("certs").exists());

    let daemon = env.start(&["--admin-password-file", &pw]);
    env.cli(
        &[
            "shell",
            "--host",
            "127.0.0.1",
            "--port",
            &daemon.grpc_port,
            "--user",
            "admin",
            "-c",
            "CREATE DATABASE shop",
        ],
        &[("RUSTEGON_PASSWORD", ADMIN_PASSWORD)],
    )
    .ok();
    let port = daemon.http_port.to_string();
    let health = env.cli(&["health", "--ready", "--port", &port], &[]).ok();
    assert!(health.stdout.contains("200"), "{}", health.stdout);
    // A TLS health check against the plain-text node fails at the handshake.
    let other_ca = env.path("other-ca").display().to_string();
    env.cli(&["cert", "create-ca", "--out", &other_ca], &[])
        .ok();
    let ca_crt = env.path("other-ca").join("ca.crt").display().to_string();
    let tls = env
        .cli(&["health", "--ca", &ca_crt, "--port", &port], &[])
        .failed();
    assert!(tls.stderr.contains("TLS"), "{}", tls.stderr);
    daemon.stop();
    env.assert_never_printed(ADMIN_PASSWORD);
}

/// FR-INS-004 / AC-INS-004: the scripted wizard (TLS on and generated, password with confirmation,
/// encryption at rest on with the default key file) writes a node that `rustegond` starts with
/// encryption: a document written through the shell is not readable in any file of the data
/// directory, the KEK file is 64 hex digits and owner-only, and no password is printed.
#[test]
fn fr_ins_004_scripted_wizard_with_encryption_starts_rustegond() {
    let env = Env::new();
    let data = env.data_dir().display().to_string();
    let init = wizard(
        &env,
        &[],
        &[
            &data,          // data directory
            "",             // configuration file: <data>/rustegon.toml
            "127.0.0.1",    // listen address
            "0",            // gRPC port
            "0",            // REST port
            "y",            // TLS: on
            "",             // TLS: generate
            "",             // no extra hosts
            "",             // encryption at rest: yes
            "",             // key file: <data>/secrets/kek.key
            ADMIN_PASSWORD, // password
            ADMIN_PASSWORD, // repeat
            "y",            // write
        ],
    )
    .ok();
    assert!(init.stderr.contains("Summary:"), "{}", init.stderr);
    assert!(
        init.stdout.contains("encryption at rest: aes-256-gcm"),
        "{}",
        init.stdout
    );
    let kek = env.data_dir().join("secrets").join("kek.key");
    let key_text = std::fs::read_to_string(&kek).unwrap();
    let digits = key_text.trim_end();
    assert_eq!(digits.len(), 64);
    assert!(digits.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!init.text().contains(digits), "the KEK was printed");
    assert_owner_only(&kek);
    let password_file = env.data_dir().join("admin-password");
    assert_owner_only(&password_file);
    assert_owner_only(&env.data_dir().join("certs").join("node.key"));
    let config = std::fs::read_to_string(env.config()).unwrap();
    assert!(config.contains("aes-256-gcm"), "{config}");

    let pw = password_file.display().to_string();
    let daemon = env.start(&["--admin-password-file", &pw]);
    let ca = env.ca();
    let mut args = vec!["shell"];
    args.extend(conn(&env, &daemon, &ca));
    args.extend([
        "--user",
        "admin",
        "-c",
        "CREATE DATABASE shop; CREATE COLLECTION shop.orders; \
         INSERT INTO shop.orders VALUE {_id: 1, item: 'canary-iw-7f3a9c'}; \
         FROM shop.orders SELECT VALUE item",
    ]);
    let shell = env
        .cli(&args, &[("RUSTEGON_PASSWORD", ADMIN_PASSWORD)])
        .ok();
    assert!(
        shell.stdout.contains("canary-iw-7f3a9c"),
        "{}",
        shell.stdout
    );
    let daemon_output = daemon.stop();
    env.record(&daemon_output);
    assert_eq!(
        files_containing(&env.data_dir(), "canary-iw-7f3a9c"),
        Vec::<std::path::PathBuf>::new(),
        "plaintext document data on disk"
    );
    env.assert_never_printed(ADMIN_PASSWORD);
}

/// FR-INS-004: the wizard imports existing PEM files (CA, node certificate, key) instead of
/// generating a CA; `rustegond` serves the imported certificate and the shell verifies it
/// against the original CA. No CA directory is created and the copied key is owner-only.
#[test]
fn fr_ins_004_wizard_imports_pem_files_and_rustegond_serves_them() {
    let env = Env::new();
    let own_ca = env.path("own-ca").display().to_string();
    let own_node = env.path("own-node").display().to_string();
    env.cli(&["cert", "create-ca", "--out", &own_ca], &[]).ok();
    env.cli(
        &[
            "cert",
            "create-node",
            "--ca",
            &own_ca,
            "--out",
            &own_node,
            "--host",
            "127.0.0.1",
        ],
        &[],
    )
    .ok();
    let pw = env.write("admin.pw", ADMIN_PASSWORD);
    let data = env.data_dir().display().to_string();
    let ca_crt = env.path("own-ca").join("ca.crt").display().to_string();
    let node_crt = env.path("own-node").join("node.crt").display().to_string();
    let node_key = env.path("own-node").join("node.key").display().to_string();
    wizard(
        &env,
        &["--admin-password-file", &pw],
        &[
            &data,
            "",
            "127.0.0.1",
            "0",
            "0",
            "y", // TLS: on
            "import",
            &ca_crt,
            &node_crt,
            &node_key,
            "n", // no encryption at rest
            "",  // write (default yes)
        ],
    )
    .ok();
    assert!(!env.data_dir().join("ca").exists());
    assert_eq!(
        std::fs::read(env.data_dir().join("certs").join("node.crt")).unwrap(),
        std::fs::read(&node_crt).unwrap()
    );
    assert_owner_only(&env.data_dir().join("certs").join("node.key"));
    assert!(
        !std::fs::read_to_string(env.config())
            .unwrap()
            .contains("encryption")
    );

    let daemon = env.start(&["--admin-password-file", &pw]);
    let mut args = vec!["shell"];
    args.extend(conn(&env, &daemon, &ca_crt));
    args.extend(["--user", "admin", "-c", "CREATE DATABASE shop"]);
    env.cli(&args, &[("RUSTEGON_PASSWORD", ADMIN_PASSWORD)])
        .ok();
    daemon.stop();
    env.assert_never_printed(ADMIN_PASSWORD);
}

/// FR-INS-004: an imported key that does not belong to the imported certificate is rejected
/// before anything is written.
#[test]
fn fr_ins_004_import_rejects_a_key_of_another_certificate() {
    let env = Env::new();
    let ca = env.path("own-ca").display().to_string();
    env.cli(&["cert", "create-ca", "--out", &ca], &[]).ok();
    for n in ["a", "b"] {
        let out = env.path(n).display().to_string();
        env.cli(
            &[
                "cert",
                "create-node",
                "--ca",
                &ca,
                "--out",
                &out,
                "--host",
                "localhost",
            ],
            &[],
        )
        .ok();
    }
    let ca_crt = env.path("own-ca").join("ca.crt").display().to_string();
    let cert_a = env.path("a").join("node.crt").display().to_string();
    let key_b = env.path("b").join("node.key").display().to_string();
    let rejected = env
        .init(&[
            "--import-ca-cert",
            &ca_crt,
            "--import-cert",
            &cert_a,
            "--import-key",
            &key_b,
        ])
        .failed();
    assert!(
        rejected.stderr.contains("does not belong"),
        "{}",
        rejected.stderr
    );
    assert_nothing_written(&env);
    // Not a certificate at all.
    let rejected = env
        .init(&[
            "--import-ca-cert",
            &key_b,
            "--import-cert",
            &cert_a,
            "--import-key",
            &key_b,
        ])
        .failed();
    assert!(
        rejected.stderr.contains("CA certificate"),
        "{}",
        rejected.stderr
    );
    assert_nothing_written(&env);
}

/// FR-INS-004 / security.md §6: `--encryption file:<path>` never overwrites an existing key
/// file (the data it protects would become unreadable); nothing is written.
#[test]
fn fr_ins_004_encryption_refuses_an_existing_key_file() {
    let env = Env::new();
    let kek = env.write("kek.key", "existing key material\n");
    let flag = format!("file:{kek}");
    let refused = env.init(&["--encryption", &flag]).failed();
    assert!(
        refused.stderr.contains("already present") && refused.stderr.contains("kek.key"),
        "{}",
        refused.stderr
    );
    assert_eq!(
        std::fs::read_to_string(&kek).unwrap(),
        "existing key material\n"
    );
    assert_nothing_written(&env);

    // A new path works and is written into the configuration.
    let new_kek = env.path("keys").join("kek.key");
    let flag = format!("file:{}", new_kek.display());
    env.init(&["--encryption", &flag]).ok();
    assert_owner_only(&new_kek);
    let config = std::fs::read_to_string(env.config()).unwrap();
    assert!(config.contains("encryption_key_file"), "{config}");
}

/// FR-INS-004: the wizard asks again after a weak password (the server's policy) and writes
/// nothing when the input ends; a "no" at the final confirmation writes nothing either. The
/// rejected password is never shown.
#[test]
fn fr_ins_004_wizard_rejects_weak_passwords_and_writes_nothing_when_cancelled() {
    let env = Env::new();
    let data = env.data_dir().display().to_string();
    // TLS: default (off), so no certificate question; encryption at rest: no.
    let common = [&data as &str, "", "127.0.0.1", "0", "0", "", "n"];
    let mut answers = common.to_vec();
    answers.push("password1234");
    let weak = wizard(&env, &[], &answers).failed();
    assert!(weak.stderr.contains("password:"), "{}", weak.stderr);
    assert!(weak.stderr.contains("input ended"), "{}", weak.stderr);
    assert_nothing_written(&env);
    env.assert_never_printed("password1234");

    let mut answers = common.to_vec();
    answers.extend([ADMIN_PASSWORD, ADMIN_PASSWORD, "n"]);
    let cancelled = wizard(&env, &[], &answers).failed();
    assert!(
        cancelled.stderr.contains("cancelled"),
        "{}",
        cancelled.stderr
    );
    assert_nothing_written(&env);
    env.assert_never_printed(ADMIN_PASSWORD);
}

/// FR-INS-004 regression: `--non-interactive` never reads stdin (M4 behaviour, PD-058); the
/// import flags go together; `--interactive` and `--non-interactive` exclude each other;
/// a malformed `--encryption` is a usage error.
#[test]
fn fr_ins_004_non_interactive_never_asks_and_validates_flags() {
    let env = Env::new();
    let data = env.data_dir().display().to_string();
    let mut child = clean(Path::new(env!("CARGO_BIN_EXE_rustegon")))
        .args(["init", "--non-interactive", "--data-dir", &data])
        .args(["--grpc-port", "0", "--http-port", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child
        .stdin
        .take()
        .unwrap()
        .write_all(b"/elsewhere\n\n0.0.0.0\n");
    let run: Run = child.wait_with_output().unwrap().into();
    let run = run.ok();
    assert!(!run.stderr.contains("Summary"), "{}", run.stderr);
    let config = std::fs::read_to_string(env.config()).unwrap();
    assert!(config.contains("127.0.0.1:0"), "{config}");
    assert!(!config.contains("encryption"), "{config}");
    // TLS is opt-in (ADR-034): no `--tls`, no CA, no certificates, no `[security]`.
    assert!(!config.contains("[security]"), "{config}");
    assert!(!env.data_dir().join("ca").exists());
    assert!(!env.data_dir().join("certs").exists());

    let other = env.path("other").display().to_string();
    for bad in [
        vec!["init", "--data-dir", &other, "--import-cert", "x.crt"],
        vec!["init", "--data-dir", &other, "--encryption", "aes"],
        vec![
            "init",
            "--data-dir",
            &other,
            "--interactive",
            "--non-interactive",
        ],
    ] {
        let run = env.cli(&bad, &[]);
        assert_eq!(run.code, Some(2), "{bad:?}: {}", run.stderr);
    }
    assert!(!env.path("other").exists());
}
