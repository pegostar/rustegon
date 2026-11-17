// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Single-file backups, the `.bak` (ADR-037, PD-225; FR-BKP-001, TC-BKP-015):
//! - a `.bak` is one object `<id>.bak` at the destination; listing, shallow and deep
//!   verification and restore read it like a directory backup, and every restored byte matches;
//! - a corrupt, truncated or foreign `.bak` is reported (RGN-5002), a newer one refused
//!   (RGN-5007), an existing id refused (RGN-1031);
//! - it is an ordinary tar archive (`tar -tf` lists it, where a `tar` command exists);
//! - the format fixture `fixtures/formats/bak/1/` stays readable and is reproduced byte for byte
//!   by the writer (implementation-rules.md §6). `RGN_FIXTURES_BLESS=1` rewrites it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, SystemTime},
};

use rustegon_backup::{
    BackupId, BackupMetadata, BakDestination, Consistency, Encryption, HlcTimestamp, ListedBackup,
    LocalDestination, NewBackup, SourceInfo, VerifyMode, bak_key, list, load_manifest,
    restore_files, verify, write_bak,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{FileSystem, OpenMode, Rng};

const STAGE: &str = "/stage";
const DEST: &str = "/dest";

struct SeqRng(AtomicU8);
impl Rng for SeqRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        buf.fill(self.0.fetch_add(1, Ordering::Relaxed));
    }
}

/// A fake checkpoint; the big file spans two 1 MiB transfer chunks and is not block aligned.
fn staged_contents(big: bool) -> Vec<(&'static str, Vec<u8>)> {
    let mut files = vec![
        ("lsm/000009.rsst", b"small sst".to_vec()),
        ("lsm/MANIFEST-000002", b"manifest snapshot".to_vec()),
        ("lsm/CURRENT", b"MANIFEST-000002\n".to_vec()),
        ("lsm/000010.rsst", Vec::new()),
        ("keys/registry.enc", vec![0x5a; 96]),
    ];
    if big {
        let data = (0..(1u32 << 20) + 17)
            .map(|i| u8::try_from(i * 31 % 251).unwrap())
            .collect();
        files.push(("lsm/000005.rsst", data));
    }
    files
}

fn write_file(fs: &dyn FileSystem, path: &Path, data: &[u8]) {
    fs.create_dir_all(path.parent().unwrap()).unwrap();
    let mut f = fs.open(path, OpenMode::Truncate).unwrap();
    f.append(data).unwrap();
    f.sync_data().unwrap();
}

fn read_file(fs: &dyn FileSystem, path: &Path) -> Vec<u8> {
    let f = fs.open(path, OpenMode::Read).unwrap();
    let mut buf = vec![0u8; usize::try_from(f.size().unwrap()).unwrap()];
    f.read_exact_at(&mut buf, 0).unwrap();
    buf
}

fn new_backup(secs: u64, seed: u8) -> NewBackup {
    let created_at = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
    NewBackup {
        id: BackupId::generate(created_at, &SeqRng(AtomicU8::new(seed))).unwrap(),
        created_at,
        metadata: BackupMetadata {
            consistency: Consistency {
                timestamp: HlcTimestamp {
                    wall: 1_794_219_300_000_000_000,
                    logical: 1,
                },
                applied_index: 77,
                applied_term: 2,
                storage_seqno: 1000,
            },
            source: SourceInfo {
                cluster_id: "single-node".into(),
                node_id: "node1".into(),
                server_version: "0.1.0".into(),
            },
            encryption: Encryption::Kek {
                kek_id: "file:/kek".into(),
            },
            pitr: None,
        },
    }
}

/// A sim file system with a staged checkpoint and a destination holding one `.bak`.
fn backed_up(big: bool) -> (SimFileSystem, LocalDestination, BackupId) {
    let fs = SimFileSystem::new();
    for (rel, data) in staged_contents(big) {
        write_file(&fs, &Path::new(STAGE).join(rel), &data);
    }
    let dest = LocalDestination::open(Arc::new(fs.clone()), DEST).unwrap();
    let backup = new_backup(1_794_219_300, 1);
    write_bak(&dest, &fs, Path::new(STAGE), &backup).unwrap();
    (fs, dest, backup.id)
}

fn bak_path(id: &BackupId) -> PathBuf {
    Path::new(DEST).join(bak_key(id))
}

/// Overwrites the `.bak` with `edit` applied to its bytes.
fn tamper(fs: &SimFileSystem, id: &BackupId, edit: impl FnOnce(&mut Vec<u8>)) {
    let path = bak_path(id);
    let mut bytes = read_file(fs, &path);
    edit(&mut bytes);
    write_file(fs, &path, &bytes);
}

fn code(err: impl Into<Error>) -> ErrorCode {
    err.into().code()
}

/// TC-BKP-015: one object at the destination; listed, verified (shallow and deep), its manifest
/// loaded and every file restored byte for byte, exactly as a directory backup.
#[test]
fn tc_bkp_015_bak_is_one_file_listed_verified_and_restored() {
    let (fs, dest, id) = backed_up(true);
    assert_eq!(
        rustegon_backup::Destination::list(&dest, "").unwrap(),
        [bak_key(&id)],
        "one object, no backups/ tree"
    );

    let listed = list(&dest).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(matches!(&listed[0], ListedBackup::Complete(m) if m.backup_id == id.as_str()));
    assert_eq!(load_manifest(&dest, &id).unwrap().backup_id, id.as_str());
    let shallow = verify(&dest, &id, VerifyMode::Shallow).unwrap();
    assert_eq!(shallow.files_checked, staged_contents(true).len());
    let deep = verify(&dest, &id, VerifyMode::Deep).unwrap();
    assert_eq!(deep.bytes_hashed, deep.manifest.total_bytes());

    restore_files(&dest, &id, Arc::new(fs.clone()), Path::new("/restored")).unwrap();
    for (rel, data) in staged_contents(true) {
        assert_eq!(
            read_file(&fs, &Path::new("/restored").join(rel)),
            data,
            "{rel}"
        );
    }

    // The same id again is refused, as for a directory backup.
    let again = write_bak(&dest, &fs, Path::new(STAGE), &new_backup(1_794_219_300, 1));
    assert_eq!(code(again.unwrap_err()), ErrorCode::AlreadyExists);
}

/// TC-BKP-015: damage is detected. A flipped data byte fails the deep verification and the
/// restore (never the shallow one); a damaged header, a truncated file and a `.bak` named after
/// another backup are listed as unreadable and refused with RGN-5002.
#[test]
fn tc_bkp_015_corrupt_or_truncated_bak_is_reported() {
    let (fs, dest, id) = backed_up(false);
    // The first data byte of the second entry: marker header + marker data (one block) + header.
    tamper(&fs, &id, |b| b[3 * 512] ^= 0xff);
    verify(&dest, &id, VerifyMode::Shallow).unwrap();
    let deep = verify(&dest, &id, VerifyMode::Deep).unwrap_err();
    assert_eq!(code(deep), ErrorCode::StorageCorruption);
    let restored = restore_files(&dest, &id, Arc::new(fs.clone()), Path::new("/r1"));
    assert_eq!(code(restored.unwrap_err()), ErrorCode::StorageCorruption);

    let edits: [fn(&mut Vec<u8>); 2] = [
        // A header byte: the header checksum no longer matches.
        |b| b[1024 + 5] ^= 0x01,
        // Truncated in the middle of the archive.
        |b| b.truncate(b.len() / 2),
    ];
    for edit in edits {
        let (fs, dest, id) = backed_up(false);
        tamper(&fs, &id, edit);
        let listed = list(&dest).unwrap();
        assert!(
            matches!(&listed[..], [ListedBackup::Unreadable { id: i, .. }] if i == &id),
            "{listed:?}"
        );
        assert_eq!(
            code(verify(&dest, &id, VerifyMode::Shallow).unwrap_err()),
            ErrorCode::StorageCorruption
        );
    }

    // A valid `.bak` of another backup under this id's name.
    let (fs, dest, id) = backed_up(false);
    let other = BackupId::parse("20261109T101500Z-00000000").unwrap();
    let bytes = read_file(&fs, &bak_path(&id));
    write_file(&fs, &bak_path(&other), &bytes);
    assert_eq!(
        code(load_manifest(&dest, &other).unwrap_err()),
        ErrorCode::StorageCorruption
    );
}

/// TC-BKP-015: a `.bak` whose marker announces a newer format is refused with RGN-5007 before
/// anything else of it is trusted.
#[test]
fn tc_bkp_015_newer_bak_format_is_refused_with_rgn_5007() {
    let (fs, dest, id) = backed_up(false);
    tamper(&fs, &id, |b| {
        let marker = b"\"format_version\":1";
        let at = b.windows(marker.len()).position(|w| w == marker).unwrap();
        b[at + marker.len() - 1] = b'2';
    });
    let err = BakDestination::open(&dest, &bak_key(&id)).unwrap_err();
    assert_eq!(code(err), ErrorCode::VersionIncompatible);
    assert_eq!(
        code(load_manifest(&dest, &id).unwrap_err()),
        ErrorCode::VersionIncompatible
    );
}

/// TC-BKP-015: the `.bak` is a tar archive any `tar` lists: marker first, the backup's files,
/// then `manifest.json` and `COMPLETE`. Skipped where no `tar` command exists.
#[test]
fn tc_bkp_015_bak_is_a_tar_archive() {
    let (fs, _dest, id) = backed_up(true);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(bak_key(&id));
    std::fs::write(&file, read_file(&fs, &bak_path(&id))).unwrap();
    // An external program reads the archive: real process, real file system.
    #[allow(clippy::disallowed_methods)]
    let Ok(out) = std::process::Command::new("tar")
        .arg("-tf")
        .arg(&file)
        .output()
    else {
        eprintln!("no tar command: skipped");
        return;
    };
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let names: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let prefix = format!("backups/{id}/");
    let mut want = vec!["rustegon-bak.json".to_owned()];
    let mut files: Vec<String> = staged_contents(true)
        .iter()
        .map(|(rel, _)| format!("{prefix}{rel}"))
        .collect();
    files.sort();
    want.extend(files);
    want.push(format!("{prefix}manifest.json"));
    want.push(format!("{prefix}COMPLETE"));
    assert_eq!(names, want);
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formats/bak/1/20261109T101500Z-01010101.bak")
}

/// Format stability (implementation-rules.md §6): the writer reproduces the v1 fixture byte for
/// byte, and the fixture reads back with its recorded contents. A failure means the format
/// changed: bump `BAK_FORMAT_VERSION` and add a fixture, never edit this one.
#[test]
fn tc_bkp_015_bak_v1_fixture_is_readable_and_reproduced() {
    let (fs, _dest, id) = backed_up(false);
    assert_eq!(id.as_str(), "20261109T101500Z-01010101");
    let written = read_file(&fs, &bak_path(&id));
    if std::env::var("RGN_FIXTURES_BLESS").as_deref() == Ok("1") {
        std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
        std::fs::write(fixture_path(), &written).unwrap();
    }
    let fixture = std::fs::read(fixture_path())
        .unwrap_or_else(|e| panic!("{}: {e}", fixture_path().display()));
    assert!(written == fixture, "the bak v1 writer changed its output");

    let fixture_fs = SimFileSystem::new();
    write_file(&fixture_fs, &bak_path(&id), &fixture);
    let dest = LocalDestination::open(Arc::new(fixture_fs.clone()), DEST).unwrap();
    let report = verify(&dest, &id, VerifyMode::Deep).unwrap();
    assert_eq!(report.manifest.created_at, "2026-11-09T10:15:00Z");
    assert_eq!(
        report.manifest.encryption,
        Encryption::Kek {
            kek_id: "file:/kek".into()
        }
    );
    restore_files(&dest, &id, Arc::new(fixture_fs.clone()), Path::new("/r")).unwrap();
    for (rel, data) in staged_contents(false) {
        assert_eq!(
            read_file(&fixture_fs, &Path::new("/r").join(rel)),
            data,
            "{rel}"
        );
    }
}
