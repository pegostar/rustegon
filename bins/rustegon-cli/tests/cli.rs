// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Process-level tests of the `rustegon` CLI against a real `rustegond` (PD-058):
//! `rustegon init` → `rustegond --config` → `rustegon shell`/`user`/`role`/`apikey` over TLS.
//!
//! The harness (building `rustegond`, `rustegon init`, starting and stopping the daemon) is
//! shared with `tests/e2e_backup.rs` in `tests/common/mod.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    // End-to-end scenarios read best as one sequence of CLI calls.
    clippy::too_many_lines
)]
// The server under test is a separate OS process on real time: waiting for it cannot go
// through the sim-api.
#![allow(clippy::disallowed_methods)]

mod common;

use std::time::Duration;

use common::{ADMIN_PASSWORD, Daemon, Env, cli, conn, now_ns, timelines, with};

const ALICE_PASSWORD: &str = "Wr4!nkleZ#90pQuv";
const ALICE_NEW_PASSWORD: &str = "Tm8$haloVx#27nEd";

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// TC-TLS-004 / AC-TLS-002 (FR-TLS-002): `rustegon init` produces a CA and node certificate
/// that `rustegond` serves; the shell connects over TLS verified against that CA with the
/// bootstrap admin, inserts and selects (rows as JSON on stdout) and runs interactive
/// transactions (ROLLBACK discards, COMMIT keeps). The password is never printed.
#[test]
fn tc_tls_004_init_rustegond_and_shell_over_tls_end_to_end() {
    let env = Env::new();
    let pw = env.write("admin.pw", &format!("{ADMIN_PASSWORD}\n"));
    let init = env
        .init(&["--admin-password-file", &pw, "--client-user", "app"])
        .ok();
    assert!(
        init.stdout.contains("next: rustegond --config"),
        "{}",
        init.stdout
    );
    assert!(
        init.stdout.contains("--admin-password-file"),
        "{}",
        init.stdout
    );
    let certs = env.data_dir().join("certs");
    for f in [
        certs.join("ca.crt"),
        certs.join("node.crt"),
        certs.join("node.key"),
        certs.join("client-app").join("client.crt"),
        certs.join("client-app").join("client.key"),
        env.data_dir().join("ca").join("ca.crt"),
        env.data_dir().join("ca").join("ca.key"),
    ] {
        assert!(f.is_file(), "{} missing", f.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for key in [
            certs.join("node.key"),
            env.data_dir().join("ca").join("ca.key"),
        ] {
            let mode = std::fs::metadata(&key).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", key.display());
        }
    }
    let shown = env
        .cli(
            &[
                "cert",
                "show",
                &certs.join("node.crt").display().to_string(),
            ],
            &[],
        )
        .ok();
    assert!(shown.stdout.contains("node, expires"), "{}", shown.stdout);
    assert!(shown.stdout.contains("days left"), "{}", shown.stdout);

    let daemon = env.start(&["--admin-password-file", &pw]);
    let ca = env.ca();
    let base = conn(&env, &daemon, &ca);
    let login = [("RUSTEGON_PASSWORD", ADMIN_PASSWORD)];
    let setup = with(
        &with(&["shell"], &base),
        &[
            "--user",
            "admin",
            "-c",
            "CREATE DATABASE shop; CREATE COLLECTION shop.orders; \
             INSERT INTO shop.orders VALUE {_id: 1, item: 'book'}",
        ],
    );
    env.cli(&setup, &login).ok();

    let shell = |script: &str| {
        let mut args = vec!["shell"];
        args.extend(base.iter().copied());
        args.extend(["--user", "admin", "-d", "shop", "-c", script]);
        env.cli(&args, &login)
    };
    let select = shell("FROM orders SELECT _id, item").ok();
    assert_eq!(
        select.stdout.trim(),
        r#"{"_id":1,"item":"book"}"#,
        "{}",
        select.stderr
    );

    shell(
        "BEGIN; INSERT INTO orders VALUE {_id: 2}; ROLLBACK; \
         BEGIN; INSERT INTO orders VALUE {_id: 3}; COMMIT",
    )
    .ok();
    let select = shell("FROM orders SELECT _id ORDER BY _id").ok();
    assert_eq!(
        select.stdout.lines().collect::<Vec<_>>(),
        [r#"{"_id":1}"#, r#"{"_id":3}"#],
        "{}",
        select.stderr
    );
    // A transaction left open by a script is rolled back and reported.
    let open = shell("BEGIN; INSERT INTO orders VALUE {_id: 4}").failed();
    assert!(open.stderr.contains("rolled back"), "{}", open.stderr);
    let select = shell("FROM orders WHERE _id = 4").ok();
    assert_eq!(select.stdout.trim(), "", "{}", select.stderr);
    // A failing statement stops the script with exit 1 and the server's error code.
    let bad = shell("FROM missing_collection; INSERT INTO orders VALUE {_id: 5}").failed();
    assert!(bad.stderr.contains("RGN-"), "{}", bad.stderr);
    assert_eq!(shell("FROM orders WHERE _id = 5").ok().stdout.trim(), "");

    // Another CA does not verify the node: TLS refuses.
    env.cli(
        &[
            "cert",
            "create-ca",
            "--out",
            &env.path("other-ca").display().to_string(),
        ],
        &[],
    )
    .ok();
    let other = env.path("other-ca").join("ca.crt").display().to_string();
    let mut args = vec!["shell", "--host", "127.0.0.1", "--port", &daemon.grpc_port];
    args.extend(["--ca", &other, "--user", "admin", "-c", "FROM shop.orders"]);
    let refused = env.cli(&args, &login).failed();
    assert!(!refused.stdout.contains("book"));

    // The node certificate also carries `localhost`.
    let mut args = vec![
        "shell",
        "--host",
        "127.0.0.1",
        "--tls-server-name",
        "localhost",
    ];
    args.extend(["--port", &daemon.grpc_port, "--ca", &ca, "--user", "admin"]);
    args.extend(["-c", "FROM shop.orders SELECT VALUE item"]);
    let named = env.cli(&args, &login).ok();
    assert!(named.stdout.contains("book"), "{}", named.stdout);

    daemon.stop();
    env.assert_never_printed(ADMIN_PASSWORD);
}

/// FR-SEC-001/002 through the CLI: role create/grant/list, user create/list/grant, the new
/// user's privileges enforced in the shell, self password change (old password rejected
/// afterwards), API key login, revoke and drop. No password or key is printed.
#[test]
fn fr_sec_002_cli_user_role_and_api_key_round_trip() {
    let env = Env::new();
    let pw = env.write("admin.pw", ADMIN_PASSWORD);
    env.init(&["--admin-password-file", &pw]).ok();
    let daemon = env.start(&["--admin-password-file", &pw]);
    let ca = env.ca();
    let base = conn(&env, &daemon, &ca);
    let admin_env = [("RUSTEGON_PASSWORD", ADMIN_PASSWORD)];
    let admin = |cmd: &str, rest: &[&str], extra_env: &[(&str, &str)]| {
        let mut args = vec![cmd];
        args.extend(base.iter().copied());
        args.extend(["--user", "admin"]);
        args.extend_from_slice(rest);
        let mut vars = admin_env.to_vec();
        vars.extend_from_slice(extra_env);
        env.cli(&args, &vars)
    };
    admin(
        "shell",
        &["-c", "CREATE DATABASE shop; CREATE COLLECTION shop.orders"],
        &[],
    )
    .ok();
    admin(
        "shell",
        &["-c", "INSERT INTO shop.orders VALUE {_id: 1}"],
        &[],
    )
    .ok();

    admin(
        "role",
        &["create", "shop_reader", "--privilege", "database:shop=find"],
        &[],
    )
    .ok();
    let granted = admin(
        "role",
        &[
            "grant",
            "shop_reader",
            "--privilege",
            "database:shop=insert",
        ],
        &[],
    )
    .ok();
    assert!(
        granted.stdout.contains("database:shop=find,insert"),
        "{}",
        granted.stdout
    );
    let roles = admin("role", &["list"], &[]).ok();
    assert!(
        roles.stdout.contains("shop_reader\tcustom"),
        "{}",
        roles.stdout
    );
    let revoked = admin(
        "role",
        &[
            "revoke",
            "shop_reader",
            "--privilege",
            "database:shop=insert",
        ],
        &[],
    )
    .ok();
    assert!(
        revoked.stdout.contains("database:shop=find\t")
            || revoked.stdout.trim_end().ends_with("database:shop=find"),
        "{}",
        revoked.stdout
    );

    let new_pw = [("RUSTEGON_NEW_PASSWORD", ALICE_PASSWORD)];
    admin("user", &["create", "alice"], &new_pw).ok();
    admin("user", &["grant", "alice", "--role", "shop_reader"], &[]).ok();
    let users = admin("user", &["list"], &[]).ok();
    assert!(
        users
            .stdout
            .lines()
            .any(|l| l.starts_with("alice\troles=shop_reader")),
        "{}",
        users.stdout
    );

    let alice = |password: &str, script: &str| {
        let mut args = vec!["shell"];
        args.extend(base.iter().copied());
        args.extend(["--user", "alice", "-c", script]);
        env.cli(&args, &[("RUSTEGON_PASSWORD", password)])
    };
    assert_eq!(
        alice(ALICE_PASSWORD, "FROM shop.orders SELECT _id")
            .ok()
            .stdout
            .trim(),
        r#"{"_id":1}"#
    );
    let denied = alice(ALICE_PASSWORD, "INSERT INTO shop.orders VALUE {_id: 2}").failed();
    assert!(denied.stderr.contains("RGN-"), "{}", denied.stderr);

    // Self password change: login with the current one, then only the new one works.
    let mut args = vec!["user"];
    args.extend(base.iter().copied());
    args.extend(["--user", "alice", "passwd"]);
    env.cli(
        &args,
        &[
            ("RUSTEGON_PASSWORD", ALICE_PASSWORD),
            ("RUSTEGON_NEW_PASSWORD", ALICE_NEW_PASSWORD),
        ],
    )
    .ok();
    let old = alice(ALICE_PASSWORD, "FROM shop.orders").failed();
    assert!(
        old.stderr.contains("authentication failed") || old.stderr.contains("RGN-"),
        "{}",
        old.stderr
    );
    alice(ALICE_NEW_PASSWORD, "FROM shop.orders").ok();

    // API key of admin: written to an owner-only file, used instead of a password.
    let key_file = env.path("admin.key").display().to_string();
    let created = admin(
        "apikey",
        &["create", "--secret-file", &key_file, "--description", "ci"],
        &[],
    )
    .ok();
    let key = std::fs::read_to_string(&key_file).unwrap();
    let key = key.trim_end();
    assert!(key.starts_with("rgn_"));
    assert!(!created.text().contains(key));
    let mut args = vec!["shell"];
    args.extend(base.iter().copied());
    args.extend([
        "--api-key-file",
        &key_file,
        "-c",
        "FROM shop.orders SELECT _id",
    ]);
    assert_eq!(env.cli(&args, &[]).ok().stdout.trim(), r#"{"_id":1}"#);
    let key_id = key
        .trim_start_matches("rgn_")
        .split('_')
        .next()
        .unwrap()
        .to_owned();
    let listed = admin("apikey", &["list"], &[]).ok();
    assert!(listed.stdout.contains(&key_id), "{}", listed.stdout);
    admin("apikey", &["revoke", &key_id], &[]).ok();
    env.cli(&args, &[]).failed();

    admin("user", &["revoke", "alice", "--role", "shop_reader"], &[]).ok();
    admin("user", &["drop", "alice"], &[]).ok();
    admin("role", &["drop", "shop_reader"], &[]).ok();
    let users = admin("user", &["list"], &[]).ok();
    assert!(!users.stdout.contains("alice"), "{}", users.stdout);

    daemon.stop();
    for secret in [ADMIN_PASSWORD, ALICE_PASSWORD, ALICE_NEW_PASSWORD, key] {
        env.assert_never_printed(secret);
    }
}

/// PD-058 / TC-TLS-004: `init` never overwrites an initialized node (nothing changes on the
/// second run) and rejects a weak admin password file before writing anything.
#[test]
fn tc_tls_004_init_refuses_to_overwrite_and_checks_the_password_first() {
    let env = Env::new();
    let weak = env.write("weak.pw", "password1234\n");
    let rejected = env.init(&["--admin-password-file", &weak]).failed();
    assert!(rejected.stderr.contains("password"), "{}", rejected.stderr);
    assert!(!env.data_dir().join("ca").exists(), "nothing written");
    assert!(!env.data_dir().join("rustegon.toml").exists());

    env.init(&[]).ok();
    let node_crt = env.data_dir().join("certs").join("node.crt");
    let before = std::fs::read(&node_crt).unwrap();
    let config_before = std::fs::read(env.config()).unwrap();
    let again = env.init(&[]).failed();
    assert!(
        again.stderr.contains("refusing to initialize"),
        "{}",
        again.stderr
    );
    assert_eq!(std::fs::read(&node_crt).unwrap(), before);
    assert_eq!(std::fs::read(env.config()).unwrap(), config_before);

    // `cert create-node` into an existing directory refuses too.
    let ca_dir = env.data_dir().join("ca").display().to_string();
    let certs = env.data_dir().join("certs").display().to_string();
    let refused = env
        .cli(
            &[
                "cert",
                "create-node",
                "--ca",
                &ca_dir,
                "--out",
                &certs,
                "--host",
                "n1",
            ],
            &[],
        )
        .failed();
    assert!(
        refused.stderr.contains("node.key") || refused.stderr.contains("exists"),
        "{}",
        refused.stderr
    );
    assert_eq!(std::fs::read(&node_crt).unwrap(), before);
    // Into a new directory it works and shows a node certificate.
    let fresh = env.path("n2").display().to_string();
    env.cli(
        &[
            "cert",
            "create-node",
            "--ca",
            &ca_dir,
            "--out",
            &fresh,
            "--host",
            "n2.example",
        ],
        &[],
    )
    .ok();
    let shown = env
        .cli(
            &[
                "cert",
                "show",
                &env.path("n2").join("node.crt").display().to_string(),
            ],
            &[],
        )
        .ok();
    assert!(shown.stdout.contains("node, expires"), "{}", shown.stdout);
}

/// FR-SEC-003 / security.md §2.2 with PD-058: without a password source `init` leaves the
/// generation to `rustegond` (path printed, never the password); the generated password logs
/// in with `must_change_password`, `rustegon user passwd` changes it, and the CLI never
/// prints either password.
#[test]
fn fr_sec_003_init_without_password_uses_the_generated_bootstrap() {
    let env = Env::new();
    let init = env.init(&[]).ok();
    assert!(
        init.stdout.contains("initial-admin-password"),
        "{}",
        init.stdout
    );
    let daemon = env.start(&[]);
    assert!(
        daemon
            .stdout()
            .iter()
            .any(|l| l.contains("initial-admin-password")),
        "{:?}",
        daemon.stdout()
    );
    let generated = std::fs::read_to_string(env.data_dir().join("initial-admin-password")).unwrap();
    let generated = generated.trim_end().to_owned();
    let ca = env.ca();
    let base = conn(&env, &daemon, &ca);

    // Before the change only the password change is allowed.
    let mut args = vec!["shell"];
    args.extend(base.iter().copied());
    args.extend(["--user", "admin", "-c", "CREATE DATABASE shop"]);
    let restricted = env
        .cli(&args, &[("RUSTEGON_PASSWORD", &generated)])
        .failed();
    assert!(
        restricted.stderr.contains("must be changed"),
        "{}",
        restricted.stderr
    );

    let mut passwd = vec!["user"];
    passwd.extend(base.iter().copied());
    passwd.extend(["--user", "admin", "passwd"]);
    env.cli(
        &passwd,
        &[
            ("RUSTEGON_PASSWORD", &generated),
            ("RUSTEGON_NEW_PASSWORD", ADMIN_PASSWORD),
        ],
    )
    .ok();
    let done = env
        .cli(&args, &[("RUSTEGON_PASSWORD", ADMIN_PASSWORD)])
        .ok();
    assert!(!done.stderr.contains("must be changed"), "{}", done.stderr);

    daemon.stop();
    env.assert_never_printed(&generated);
    env.assert_never_printed(ADMIN_PASSWORD);
}

/// Usage errors: `--tls-server-name` without `--ca` (TLS is on only with a CA, ADR-034); a
/// password is never read from argv (there is no such flag); no credentials is refused before
/// connecting.
#[test]
fn pd_058_connection_options_and_never_takes_passwords_from_argv() {
    let run = cli(
        &[
            "shell",
            "--port",
            "1",
            "--tls-server-name",
            "n",
            "-c",
            "FROM a.b",
        ],
        &[],
    );
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    assert!(run.stderr.contains("--ca"), "{}", run.stderr);
    let run = cli(&["shell", "--password", "secret"], &[]);
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    let run = cli(&["shell", "--port", "1", "-c", "FROM a.b"], &[]).failed();
    assert!(run.stderr.contains("no credentials"), "{}", run.stderr);
}

/// TC-BKP-001/005/009/013 end to end with the CLI against a real `rustegond` (M13a lane BE;
/// FR-BKP-001/003/004/007, PD-062, PD-068, PD-082): `backup create` to the default
/// `<data_dir>/backups` and `backup list`/`verify --deep`; a destination outside the allowlist
/// is refused (RGN-4002); `snapshot create|list`; `dump` then logical `restore --drop` puts the
/// collection back to the dump; `snapshot restore` is refused while the node runs (RGN-3002)
/// and, with the node stopped, brings back the snapshot's state (the old store kept); `backup
/// restore` fills a new data directory and refuses a non-empty one.
#[test]
fn tc_bkp_001_cli_backup_snapshot_dump_and_restore_against_rustegond() {
    let env = Env::new();
    let pw = env.write("admin.pw", &format!("{ADMIN_PASSWORD}\n"));
    env.init(&["--admin-password-file", &pw]).ok();
    let daemon = env.start(&["--admin-password-file", &pw]);
    let ca = env.ca();
    let base = conn(&env, &daemon, &ca);
    let login = [("RUSTEGON_PASSWORD", ADMIN_PASSWORD)];
    let online = |args: &[&str]| {
        let mut v: Vec<&str> = args.to_vec();
        v.extend(base.iter().copied());
        v.extend(["--user", "admin"]);
        env.cli(&v, &login)
    };
    let shell = |script: &str| {
        let mut args = vec!["shell"];
        args.extend(base.iter().copied());
        args.extend(["--user", "admin", "-c", script]);
        env.cli(&args, &login)
    };
    let ids = || {
        let out = shell("FROM shop.orders SELECT _id ORDER BY _id").ok();
        out.stdout.lines().map(str::to_owned).collect::<Vec<_>>()
    };
    shell(
        "CREATE DATABASE shop; CREATE COLLECTION shop.orders; \
         INSERT INTO shop.orders VALUE {_id: 1}; INSERT INTO shop.orders VALUE {_id: 2}",
    )
    .ok();

    let dest = env.data_dir().join("backups").display().to_string();
    let created = online(&["backup", "create", "--to", &dest]).ok();
    let id = created
        .stdout
        .strip_prefix("created ")
        .and_then(|l| l.split('\t').next())
        .unwrap_or_else(|| panic!("{}", created.stdout))
        .to_owned();
    assert!(
        created.stderr.contains("plaintext"),
        "PD-064 warning: {}",
        created.stderr
    );
    let listed = online(&["backup", "list", "--dest", &dest]).ok();
    assert!(listed.stdout.contains(&id), "{}", listed.stdout);
    env.cli(
        &["backup", "verify", "--dest", &dest, "--id", &id, "--deep"],
        &[],
    )
    .ok();
    let outside = env.path("outside").display().to_string();
    let refused = online(&["backup", "create", "--to", &outside]).failed();
    assert!(refused.stderr.contains("4002"), "{}", refused.stderr);
    assert!(!env.path("outside").exists());

    online(&["snapshot", "create", "--name", "s1"]).ok();
    let snaps = online(&["snapshot", "list"]).ok();
    assert!(snaps.stdout.starts_with("s1\t"), "{}", snaps.stdout);

    let dump_dir = env.path("dump").display().to_string();
    online(&["dump", "--out", &dump_dir]).ok();
    shell("INSERT INTO shop.orders VALUE {_id: 3}").ok();
    assert_eq!(ids().len(), 3);
    online(&["restore", "--from", &dump_dir, "--drop"]).ok();
    assert_eq!(ids(), [r#"{"_id":1}"#, r#"{"_id":2}"#], "dump state back");
    shell("INSERT INTO shop.orders VALUE {_id: 4}").ok();

    // PD-068: an offline restore never runs under a live node.
    let data = env.data_dir().display().to_string();
    let busy = env
        .cli(
            &["snapshot", "restore", "--data-dir", &data, "--name", "s1"],
            &[],
        )
        .failed();
    assert!(busy.stderr.contains("3002"), "{}", busy.stderr);
    daemon.stop();

    let restored = env
        .cli(
            &["snapshot", "restore", "--data-dir", &data, "--name", "s1"],
            &[],
        )
        .ok();
    assert!(
        restored.stdout.contains("store.pre-restore-"),
        "{}",
        restored.stdout
    );
    let into = env.path("restored").display().to_string();
    let r = env
        .cli(
            &[
                "backup", "restore", "--from", &dest, "--id", &id, "--into", &into,
            ],
            &[],
        )
        .ok();
    assert!(r.stdout.contains(&format!("restored {id}")), "{}", r.stdout);
    assert!(env.path("restored").join("store").is_dir());
    let again = env
        .cli(
            &[
                "backup", "restore", "--from", &dest, "--id", &id, "--into", &into,
            ],
            &[],
        )
        .failed();
    assert!(again.stderr.contains("1031"), "{}", again.stderr);

    // The node starts on the snapshot's state: documents 3 and 4 came later.
    let daemon = env.start(&["--admin-password-file", &pw]);
    let base2 = conn(&env, &daemon, &ca);
    let mut args = vec!["shell"];
    args.extend(base2.iter().copied());
    args.extend([
        "--user",
        "admin",
        "-c",
        "FROM shop.orders SELECT _id ORDER BY _id",
    ]);
    let after = env.cli(&args, &login).ok();
    assert_eq!(
        after.stdout.lines().collect::<Vec<_>>(),
        [r#"{"_id":1}"#, r#"{"_id":2}"#],
        "{}",
        after.stderr
    );
    daemon.stop();
}

/// TC-BKP-004 / AC-BKP-002 end to end (M13a lane BF; FR-BKP-002, FR-BKP-004, PD-066, PD-088):
/// a real `rustegond` with `[backup.pitr]` archiving its log to `<data_dir>/backups`; a backup,
/// writes before and after a point in time T; the node stops (its final archiver pass seals and
/// archives the log); `rustegon backup restore --to-time T` picks the backup, replays the
/// archive, and the node started on the restored store holds exactly the state at T, under a new
/// timeline. A target before the backup is refused (RGN-1030), as is `--archive` without
/// `--to-time` (argument error).
#[test]
fn tc_bkp_004_cli_point_in_time_restore_against_rustegond() {
    let env = Env::new();
    let pw = env.write("admin.pw", &format!("{ADMIN_PASSWORD}\n"));
    env.init(&["--admin-password-file", &pw]).ok();
    let backups = env.data_dir().join("backups");
    {
        use std::io::Write as _;
        let mut config = std::fs::OpenOptions::new()
            .append(true)
            .open(env.config())
            .unwrap();
        // A literal TOML string: Windows paths keep their backslashes.
        write!(
            config,
            "\n[backup.pitr]\nenabled = true\ndestination = '{}'\nsegment_interval_secs = 1\n",
            backups.display()
        )
        .unwrap();
    }
    let ca = env.ca();
    let login = [("RUSTEGON_PASSWORD", ADMIN_PASSWORD)];
    let shell = |daemon: &Daemon, script: &str| {
        let mut args = vec!["shell"];
        args.extend(conn(&env, daemon, &ca));
        args.extend(["--user", "admin", "-c", script]);
        env.cli(&args, &login)
    };
    let rows = |daemon: &Daemon| {
        shell(daemon, "FROM shop.orders SELECT _id, v ORDER BY _id")
            .ok()
            .stdout
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };

    let daemon = env.start(&["--admin-password-file", &pw]);
    shell(
        &daemon,
        "CREATE DATABASE shop; CREATE COLLECTION shop.orders; \
         INSERT INTO shop.orders VALUE {_id: 1, v: 'a'}",
    )
    .ok();
    let before_backup = now_ns().to_string();
    std::thread::sleep(Duration::from_millis(50));
    let dest = backups.display().to_string();
    let mut args = vec!["backup", "create", "--to", &dest];
    args.extend(conn(&env, &daemon, &ca));
    args.extend(["--user", "admin"]);
    env.cli(&args, &login).ok();
    shell(
        &daemon,
        "INSERT INTO shop.orders VALUE {_id: 2, v: 'b'}; \
         UPDATE shop.orders SET v = 'a2' WHERE _id = 1",
    )
    .ok();
    // Let a timed roll (1 s) pass so part of the history is archived while the node runs.
    std::thread::sleep(Duration::from_millis(1500));
    shell(&daemon, "INSERT INTO shop.orders VALUE {_id: 3, v: 'c'}").ok();
    std::thread::sleep(Duration::from_millis(100));
    let t = now_ns().to_string();
    std::thread::sleep(Duration::from_millis(100));
    shell(
        &daemon,
        "INSERT INTO shop.orders VALUE {_id: 4, v: 'd'}; \
         UPDATE shop.orders SET v = 'b2' WHERE _id = 2; \
         DELETE FROM shop.orders WHERE _id = 3",
    )
    .ok();
    assert_eq!(
        rows(&daemon),
        [
            r#"{"_id":1,"v":"a2"}"#,
            r#"{"_id":2,"v":"b2"}"#,
            r#"{"_id":4,"v":"d"}"#
        ]
    );
    daemon.stop();
    let old_timelines = timelines(&backups);
    assert_eq!(old_timelines.len(), 1, "{old_timelines:?}");

    let into = env.path("restored").display().to_string();
    let refused = env
        .cli(
            &[
                "backup",
                "restore",
                "--from",
                &dest,
                "--to-time",
                &before_backup,
                "--into",
                &into,
            ],
            &[],
        )
        .failed();
    assert!(refused.stderr.contains("1030"), "{}", refused.stderr);
    let usage = env.cli(
        &[
            "backup",
            "restore",
            "--from",
            &dest,
            "--id",
            "x",
            "--archive",
            &dest,
            "--into",
            &into,
        ],
        &[],
    );
    assert_eq!(usage.code, Some(2), "{}", usage.text());

    let restored = env
        .cli(
            &[
                "backup",
                "restore",
                "--from",
                &dest,
                "--to-time",
                &t,
                "--into",
                &into,
            ],
            &[],
        )
        .ok();
    assert!(
        restored
            .stdout
            .contains(&format!("rolled forward to {t}.0")),
        "{}",
        restored.stdout
    );
    let restored_store = env.path("restored").join("store");
    assert!(
        !restored_store.join("pitr-archive.json").exists(),
        "a restored store starts a new timeline"
    );
    // The node's data directory gets the restored store (the original is kept aside).
    std::fs::rename(env.data_dir().join("store"), env.path("original-store")).unwrap();
    std::fs::rename(&restored_store, env.data_dir().join("store")).unwrap();

    let daemon = env.start(&["--admin-password-file", &pw]);
    assert_eq!(
        rows(&daemon),
        [
            r#"{"_id":1,"v":"a2"}"#,
            r#"{"_id":2,"v":"b"}"#,
            r#"{"_id":3,"v":"c"}"#
        ],
        "exactly the state at T"
    );
    daemon.stop();
    let now = timelines(&backups);
    assert_eq!(
        now.len(),
        2,
        "the restored node archives under a new timeline: {now:?}"
    );
    assert!(now.contains(&old_timelines[0]));
}
