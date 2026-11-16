// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Process-level tests of the `rustegon backup|snapshot|dump|restore` argument handling and
//! of the offline commands (M13a lane BC; FR-BKP-003/004/006/007, TC-BKP-010, PD-062, PD-077).
//! No server is needed: online commands are checked up to the point where they would connect.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::Path,
    process::{Command, Output},
    sync::Arc,
    time::{Duration, SystemTime},
};

use rustegon_backup::{
    BackupId, BackupMetadata, Consistency, Encryption, HlcTimestamp, LocalDestination, NewBackup,
    SourceInfo, write_backup,
};
use rustegon_sim_api::{FileSystem, OpenMode, StdFileSystem};

const ID: &str = "20261109T101500Z-3fa85f64";

fn rustegon(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustegon"));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("RUSTEGON_") {
            cmd.env_remove(k);
        }
    }
    cmd.args(args).output().unwrap()
}

fn text(o: &Output) -> (Option<i32>, String, String) {
    (
        o.status.code(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// A plaintext backup `ID` with one 4 KiB file under `<dir>/dest`.
fn seed(dir: &Path) -> std::path::PathBuf {
    let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
    let stage = dir.join("stage");
    let sst = stage.join("lsm").join("000001.rsst");
    fs.create_dir_all(sst.parent().unwrap()).unwrap();
    let mut f = fs.open(&sst, OpenMode::Truncate).unwrap();
    f.append(&[3u8; 4096]).unwrap();
    f.sync_data().unwrap();
    let root = dir.join("dest");
    let dest = LocalDestination::open(Arc::clone(&fs), &root).unwrap();
    write_backup(
        &dest,
        fs.as_ref(),
        &stage,
        &NewBackup {
            id: BackupId::parse(ID).unwrap(),
            created_at: SystemTime::UNIX_EPOCH + Duration::new(1_794_219_300, 0),
            metadata: BackupMetadata {
                consistency: Consistency {
                    timestamp: HlcTimestamp {
                        wall: 1_794_219_300_000_000_000,
                        logical: 0,
                    },
                    applied_index: 1,
                    applied_term: 1,
                    storage_seqno: 1,
                },
                source: SourceInfo {
                    cluster_id: "c".into(),
                    node_id: "1".into(),
                    server_version: "0.1.0".into(),
                },
                encryption: Encryption::Plaintext,
                pitr: None,
            },
        },
    )
    .unwrap();
    root
}

/// TC-BKP-010 from the CLI: offline `backup verify` (shallow and deep) on a local destination,
/// and the RGN-5002 of a corrupt file.
#[test]
fn tc_bkp_010_cli_verifies_a_backup_offline() {
    let dir = tempfile::tempdir().unwrap();
    let dest = seed(dir.path());
    let d = dest.to_str().unwrap();
    let (code, out, err) = text(&rustegon(&["backup", "verify", "--dest", d, "--id", ID]));
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("verified (shallow): 1 files"), "{out}");
    let (code, out, err) = text(&rustegon(&[
        "backup", "verify", "--dest", d, "--id", ID, "--deep",
    ]));
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("4096 bytes hashed"), "{out}");
    let file = dest
        .join("backups")
        .join(ID)
        .join("lsm")
        .join("000001.rsst");
    std::fs::write(&file, [4u8; 4096]).unwrap();
    let (code, _, err) = text(&rustegon(&[
        "backup", "verify", "--dest", d, "--id", ID, "--deep",
    ]));
    assert_eq!(code, Some(1));
    assert!(err.contains("RGN-5002"), "{err}");
    // Unknown id, malformed id, missing destination (never created).
    let (code, _, err) = text(&rustegon(&[
        "backup",
        "verify",
        "--dest",
        d,
        "--id",
        "20261109T101500Z-00000000",
    ]));
    assert_eq!(code, Some(1));
    assert!(err.contains("RGN-1030"), "{err}");
    let (code, _, err) = text(&rustegon(&[
        "backup", "verify", "--dest", d, "--id", "../x",
    ]));
    assert_eq!(code, Some(1));
    assert!(err.contains("RGN-1001"), "{err}");
    let missing = dir.path().join("nowhere");
    let (code, _, _) = text(&rustegon(&[
        "backup",
        "verify",
        "--dest",
        missing.to_str().unwrap(),
        "--id",
        ID,
    ]));
    assert_eq!(code, Some(1));
    assert!(!missing.exists());
}

/// The offline restores (M13a lane BE, PD-068) refuse a non-empty data directory (RGN-1031), a
/// missing backup id (RGN-1030), an invalid snapshot name and a data directory without
/// snapshots before writing anything. Real restores against a real `rustegond` are
/// `tests/cli.rs` `tc_bkp_001_cli_backup_snapshot_dump_and_restore_against_rustegond`.
#[test]
fn fr_bkp_001_offline_restores_check_their_arguments_and_targets() {
    let dir = tempfile::tempdir().unwrap();
    let dest = seed(dir.path());
    let (code, _, err) = text(&rustegon(&[
        "backup",
        "restore",
        "--from",
        dest.to_str().unwrap(),
        "--id",
        ID,
        "--into",
        dir.path().to_str().unwrap(),
    ]));
    assert_eq!(code, Some(1));
    assert!(err.contains("1031"), "{err}");
    let target = dir.path().join("restored");
    let (code, _, err) = text(&rustegon(&[
        "backup",
        "restore",
        "--from",
        dest.to_str().unwrap(),
        "--id",
        "20200101T000000Z-00000000",
        "--into",
        target.to_str().unwrap(),
    ]));
    assert_eq!(code, Some(1));
    assert!(err.contains("1030"), "{err}");
    assert!(!target.exists(), "nothing may be written");
    let (code, _, err) = text(&rustegon(&[
        "snapshot",
        "restore",
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--name",
        "pre-upgrade",
    ]));
    assert_eq!(code, Some(1));
    assert!(err.contains("no snapshots"), "{err}");
    let (code, _, _) = text(&rustegon(&[
        "snapshot",
        "restore",
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--name",
        ".bad",
    ]));
    assert_eq!(code, Some(1));
}

/// Argument handling of the online commands: required options (usage error 2), no password or
/// key on the command line, credentials checked before connecting, dump targets checked before
/// connecting.
#[test]
fn pd_062_online_commands_check_arguments_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        &["backup", "create"][..],
        &["backup", "list"],
        &["backup", "verify", "--dest", "x"],
        &["snapshot", "create"],
        &["dump"],
        &["restore"],
        &["backup", "create", "--to", "/b", "--password", "secret"],
    ] {
        let (code, _, err) = text(&rustegon(args));
        assert_eq!(code, Some(2), "{args:?}: {err}");
    }
    // No credentials: refused before any connection attempt (port 1 would refuse anyway).
    let (code, _, err) = text(&rustegon(&[
        "backup", "create", "--to", "/b", "--port", "1",
    ]));
    assert_eq!(code, Some(1));
    assert!(err.contains("no credentials"), "{err}");
    // A non-empty dump target is refused before connecting.
    std::fs::write(dir.path().join("f"), b"x").unwrap();
    let (code, _, err) = text(&rustegon(&[
        "dump",
        "--out",
        dir.path().to_str().unwrap(),
        "--user",
        "admin",
        "--port",
        "1",
    ]));
    assert_eq!(code, Some(1));
    assert!(err.contains("not empty"), "{err}");
    // A directory without dump.json is not a dump.
    let (code, _, err) = text(&rustegon(&[
        "restore",
        "--from",
        dir.path().to_str().unwrap(),
        "--user",
        "admin",
        "--port",
        "1",
    ]));
    assert_eq!(code, Some(1));
    assert!(err.contains("dump.json"), "{err}");
}
