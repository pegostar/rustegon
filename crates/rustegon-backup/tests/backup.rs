// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Backup write / list / verify / restore over the local destination (TC-BKP-009, TC-BKP-010;
//! FR-BKP-001, FR-BKP-004, FR-BKP-006 single-node scope; PD-064), on the simulated file system
//! (including a crash sweep over every mutating operation) and on the real one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use rustegon_backup::{
    BackupError, BackupId, BackupMetadata, Consistency, Destination, DestinationUrl, Encryption,
    HlcTimestamp, ListedBackup, LocalDestination, Manifest, NewBackup, SourceInfo, VerifyMode,
    backup_prefix, list, restore_files, verify, write_backup,
};
use rustegon_common::ErrorCode;
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_sim_api::{FileSystem, OpenMode, Rng, StdFileSystem};

const STAGE: &str = "/stage";
const DEST: &str = "/dest";

struct SeqRng(std::sync::atomic::AtomicU8);
impl Rng for SeqRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        let v = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        buf.fill(v);
    }
}

/// Files of a fake checkpoint: (relative path, contents). The big SST spans two transfer
/// chunks (1 MiB) so streaming boundaries are exercised.
fn staged_contents(encrypted: bool) -> Vec<(&'static str, Vec<u8>)> {
    let big: Vec<u8> = (0..(1u32 << 20) + 17)
        .map(|i| u8::try_from(i * 31 % 251).unwrap())
        .collect();
    let mut files = vec![
        ("lsm/000005.rsst", big),
        ("lsm/000009.rsst", b"small sst".to_vec()),
        ("lsm/MANIFEST-000002", b"manifest snapshot".to_vec()),
        ("lsm/CURRENT", b"MANIFEST-000002\n".to_vec()),
        ("lsm/000010.rsst", Vec::new()),
    ];
    if encrypted {
        files.push(("keys/registry.enc", vec![0x5a; 96]));
    }
    files
}

fn write_file(fs: &dyn FileSystem, path: &Path, data: &[u8]) {
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

fn stage(fs: &dyn FileSystem, root: &Path, encrypted: bool) {
    for (rel, data) in staged_contents(encrypted) {
        let path = root.join(rel);
        let parent = path.parent().unwrap();
        fs.create_dir_all(parent).unwrap();
        write_file(fs, &path, &data);
        fs.sync_dir(parent).unwrap();
    }
}

fn metadata(encrypted: bool) -> BackupMetadata {
    BackupMetadata {
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
            cluster_id: "cluster-a".into(),
            node_id: "1".into(),
            server_version: "0.1.0".into(),
        },
        encryption: if encrypted {
            Encryption::Kek {
                kek_id: "file:/kek".into(),
            }
        } else {
            Encryption::Plaintext
        },
        pitr: None,
    }
}

fn new_backup(rng: &dyn Rng, secs: u64, encrypted: bool) -> NewBackup {
    let created_at = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
    NewBackup {
        id: BackupId::generate(created_at, rng).unwrap(),
        created_at,
        metadata: metadata(encrypted),
    }
}

fn rng() -> SeqRng {
    SeqRng(std::sync::atomic::AtomicU8::new(1))
}

/// A sim file system with a staged checkpoint, a destination and one complete backup.
fn backed_up() -> (SimFileSystem, LocalDestination, BackupId) {
    let fs = SimFileSystem::new();
    stage(&fs, Path::new(STAGE), true);
    let dest = LocalDestination::open(Arc::new(fs.clone()), DEST).unwrap();
    let backup = new_backup(&rng(), 1_794_219_300, true);
    write_backup(&dest, &fs, Path::new(STAGE), &backup).unwrap();
    (fs, dest, backup.id)
}

fn object_path(id: &BackupId, rel: &str) -> PathBuf {
    let mut p = PathBuf::from(DEST);
    p.extend(backup_prefix(id).split('/'));
    p.extend(rel.split('/'));
    p
}

/// Asserts that `target` holds exactly the staged files.
fn assert_restored(fs: &dyn FileSystem, target: &Path, encrypted: bool) {
    for (rel, data) in staged_contents(encrypted) {
        let mut path = target.to_path_buf();
        path.extend(rel.split('/'));
        assert!(read_file(fs, &path) == data, "{rel} differs after restore");
    }
}

fn code(err: &BackupError) -> u16 {
    err.code().code()
}

#[test]
fn tc_bkp_009_local_destination_round_trip() {
    let (fs, dest, id) = backed_up();
    let listed = list(&dest).unwrap();
    assert_eq!(listed.len(), 1);
    let ListedBackup::Complete(manifest) = &listed[0] else {
        panic!("unreadable: {listed:?}");
    };
    assert_eq!(manifest.backup_id, id.as_str());
    assert_eq!(manifest.created_at, "2026-11-09T10:15:00Z");
    assert!(id.as_str().starts_with("20261109T101500Z-"));
    assert_eq!(manifest.consistency, metadata(true).consistency);
    assert_eq!(manifest.files.len(), staged_contents(true).len());
    let big = manifest
        .files
        .iter()
        .find(|f| f.path == "lsm/000005.rsst")
        .unwrap();
    assert_eq!(big.size, (1 << 20) + 17);
    assert_eq!(
        big.blake3,
        blake3::hash(&staged_contents(false)[0].1).to_hex().as_str()
    );

    let report = verify(&dest, &id, VerifyMode::Deep).unwrap();
    assert_eq!(report.files_checked, manifest.files.len());
    assert_eq!(report.bytes_hashed, manifest.total_bytes());

    let restored = restore_files(&dest, &id, Arc::new(fs.clone()), Path::new("/restore")).unwrap();
    assert_eq!(&restored, manifest);
    assert_restored(&fs, Path::new("/restore"), true);
}

#[test]
fn tc_bkp_009_local_destination_round_trip_on_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
    let staged = tmp.path().join("stage");
    stage(fs.as_ref(), &staged, false);
    // Through the URL parser, as the CLI does: a plain path and a file:// URL name the same
    // directory.
    let dest_dir = tmp.path().join("dest");
    let url = DestinationUrl::parse(dest_dir.to_str().unwrap()).unwrap();
    let dest = url.open(Arc::clone(&fs)).unwrap();
    let backup = new_backup(&rng(), 1_794_219_300, false);
    write_backup(dest.as_ref(), fs.as_ref(), &staged, &backup).unwrap();
    let file_url = format!("file:///{}", dest_dir.to_str().unwrap().replace('\\', "/"));
    let file_url = file_url.replace("file:////", "file:///");
    let dest = DestinationUrl::parse(&file_url)
        .unwrap()
        .open(Arc::clone(&fs))
        .unwrap();
    assert_eq!(list(dest.as_ref()).unwrap().len(), 1);
    verify(dest.as_ref(), &backup.id, VerifyMode::Deep).unwrap();
    let target = tmp.path().join("restore");
    restore_files(dest.as_ref(), &backup.id, Arc::clone(&fs), &target).unwrap();
    assert_restored(fs.as_ref(), &target, false);
    // No temp files left behind anywhere.
    for dir in [
        &target.join("lsm"),
        &dest_dir
            .join("backups")
            .join(backup.id.as_str())
            .join("lsm"),
    ] {
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(!name.contains('~'), "{name}");
        }
    }
}

/// Rewrites a destination object in place (the sim-api file has no positional write).
fn rewrite(fs: &SimFileSystem, path: &Path, edit: impl FnOnce(&mut Vec<u8>)) {
    let mut data = read_file(fs, path);
    edit(&mut data);
    write_file(fs, path, &data);
}

#[test]
fn tc_bkp_010_verify_detects_corrupt_file() {
    let (fs, dest, id) = backed_up();
    rewrite(&fs, &object_path(&id, "lsm/000005.rsst"), |d| {
        d[123_456] ^= 0x01;
    });
    // Same size: only the deep check can see it.
    verify(&dest, &id, VerifyMode::Shallow).unwrap();
    let err = verify(&dest, &id, VerifyMode::Deep).unwrap_err();
    assert_eq!(code(&err), 5002, "{err}");
    assert!(err.to_string().contains("lsm/000005.rsst"), "{err}");
    // Restore checks while it downloads and never commits the corrupt file under its name.
    let err = restore_files(&dest, &id, Arc::new(fs.clone()), Path::new("/restore")).unwrap_err();
    assert_eq!(code(&err), 5002, "{err}");
    let names: Vec<_> = fs.read_dir(Path::new("/restore/lsm")).unwrap_or_default();
    assert!(
        !names.iter().any(|p| p.ends_with("000005.rsst")),
        "{names:?}"
    );
}

#[test]
fn tc_bkp_010_verify_detects_missing_file() {
    let (fs, dest, id) = backed_up();
    fs.remove_file(&object_path(&id, "lsm/CURRENT")).unwrap();
    let err = verify(&dest, &id, VerifyMode::Shallow).unwrap_err();
    assert_eq!(code(&err), 5002, "{err}");
    assert!(err.to_string().contains("missing"), "{err}");
    let err = restore_files(&dest, &id, Arc::new(fs.clone()), Path::new("/restore")).unwrap_err();
    assert_eq!(code(&err), 5002, "{err}");
}

#[test]
fn tc_bkp_010_verify_detects_truncated_file() {
    let (fs, dest, id) = backed_up();
    rewrite(&fs, &object_path(&id, "lsm/000005.rsst"), |d| {
        d.truncate(4096);
    });
    let err = verify(&dest, &id, VerifyMode::Shallow).unwrap_err();
    assert_eq!(code(&err), 5002, "{err}");
    assert!(err.to_string().contains("truncated"), "{err}");
    let err = restore_files(&dest, &id, Arc::new(fs.clone()), Path::new("/restore")).unwrap_err();
    assert_eq!(code(&err), 5002, "{err}");
}

#[test]
fn tc_bkp_010_verify_detects_tampered_manifest_or_marker() {
    let (fs, dest, id) = backed_up();
    // A manifest edited after COMPLETE was written no longer matches the marker.
    rewrite(&fs, &object_path(&id, "manifest.json"), |d| {
        let text = String::from_utf8(d.clone()).unwrap();
        *d = text
            .replace("\"applied_index\": 77", "\"applied_index\": 78")
            .into_bytes();
    });
    let err = verify(&dest, &id, VerifyMode::Shallow).unwrap_err();
    assert_eq!(code(&err), 5002, "{err}");
    assert!(err.to_string().contains("COMPLETE"), "{err}");
    let listed = list(&dest).unwrap();
    assert!(matches!(&listed[..], [ListedBackup::Unreadable { error, .. }] if code(error) == 5002));
}

#[test]
fn tc_bkp_010_incomplete_backup_is_ignored() {
    let (fs, dest, incomplete) = backed_up();
    let complete = new_backup(
        &SeqRng(std::sync::atomic::AtomicU8::new(9)),
        1_794_219_400,
        true,
    );
    write_backup(&dest, &fs, Path::new(STAGE), &complete).unwrap();
    fs.remove_file(&object_path(&incomplete, "COMPLETE"))
        .unwrap();

    let ids: Vec<_> = list(&dest)
        .unwrap()
        .iter()
        .map(|b| b.id().to_owned())
        .collect();
    assert_eq!(ids, [complete.id.as_str()]);
    let err = verify(&dest, &incomplete, VerifyMode::Shallow).unwrap_err();
    assert_eq!(code(&err), 1030, "{err}");
    let err = restore_files(
        &dest,
        &incomplete,
        Arc::new(fs.clone()),
        Path::new("/restore"),
    )
    .unwrap_err();
    assert_eq!(code(&err), 1030, "{err}");
    // Nothing was created for the refused restore.
    assert!(fs.read_dir(Path::new("/restore")).is_err());
    let unknown = BackupId::parse("20200101T000000Z-00000000").unwrap();
    assert_eq!(
        code(&verify(&dest, &unknown, VerifyMode::Deep).unwrap_err()),
        1030
    );
}

#[test]
fn tc_bkp_009_restore_into_non_empty_dir_is_refused() {
    let (fs, dest, id) = backed_up();
    fs.create_dir_all(Path::new("/restore")).unwrap();
    write_file(&fs, Path::new("/restore/existing"), b"x");
    let err = restore_files(&dest, &id, Arc::new(fs.clone()), Path::new("/restore")).unwrap_err();
    assert_eq!(code(&err), 1031, "{err}");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    // An existing empty directory is fine.
    fs.create_dir_all(Path::new("/empty")).unwrap();
    restore_files(&dest, &id, Arc::new(fs.clone()), Path::new("/empty")).unwrap();
    assert_restored(&fs, Path::new("/empty"), true);
}

#[test]
fn tc_bkp_010_newer_manifest_is_refused() {
    let (fs, dest, id) = backed_up();
    rewrite(&fs, &object_path(&id, "manifest.json"), |d| {
        let text = String::from_utf8(d.clone()).unwrap();
        *d = text
            .replace("\"format_version\": 1", "\"format_version\": 2")
            .into_bytes();
    });
    let err = verify(&dest, &id, VerifyMode::Shallow).unwrap_err();
    assert_eq!(code(&err), 5007, "{err}");
    let err = restore_files(&dest, &id, Arc::new(fs.clone()), Path::new("/restore")).unwrap_err();
    assert_eq!(code(&err), 5007, "{err}");
    let listed = list(&dest).unwrap();
    assert!(matches!(&listed[..], [ListedBackup::Unreadable { error, .. }] if code(error) == 5007));
}

#[test]
fn write_backup_rejects_existing_id_and_mismatched_key_registry() {
    let (fs, dest, id) = backed_up();
    let mut again = new_backup(&rng(), 1_794_219_300, true);
    assert_eq!(again.id, id);
    let err = write_backup(&dest, &fs, Path::new(STAGE), &again).unwrap_err();
    assert_eq!(code(&err), 1031, "{err}");
    again.id = BackupId::parse("20261109T101500Z-ffffffff").unwrap();
    again.metadata.encryption = Encryption::Plaintext;
    let err = write_backup(&dest, &fs, Path::new(STAGE), &again).unwrap_err();
    assert!(matches!(err, BackupError::InvalidArgument(_)), "{err}");
    fs.remove_file(Path::new("/stage/keys/registry.enc"))
        .unwrap();
    again.metadata.encryption = Encryption::Kek { kek_id: "k".into() };
    let err = write_backup(&dest, &fs, Path::new(STAGE), &again).unwrap_err();
    assert!(matches!(err, BackupError::InvalidArgument(_)), "{err}");
    // The staged directory may not carry the reserved names.
    write_file(&fs, Path::new("/stage/COMPLETE"), b"");
    again.metadata.encryption = Encryption::Plaintext;
    let err = write_backup(&dest, &fs, Path::new(STAGE), &again).unwrap_err();
    assert!(matches!(err, BackupError::InvalidArgument(_)), "{err}");
}

#[test]
fn tc_bkp_009_failed_backup_leaves_no_complete_backup_and_cleans_up() {
    let fs = SimFileSystem::new();
    stage(&fs, Path::new(STAGE), true);
    let dest = LocalDestination::open(Arc::new(fs.clone()), DEST).unwrap();
    let backup = new_backup(&rng(), 1_794_219_300, true);
    // Room for the small first file (keys/registry.enc) but not for the big SST after it: the
    // destination fills up in the middle of the backup.
    let used: usize = staged_contents(true).iter().map(|(_, d)| d.len()).sum();
    fs.set_quota(Some(used as u64 + 1024));
    let err = write_backup(&dest, &fs, Path::new(STAGE), &backup).unwrap_err();
    assert_eq!(err.code(), ErrorCode::DiskFull, "{err}");
    fs.set_quota(None);
    assert!(list(&dest).unwrap().is_empty());
    // The file uploaded before the failure was removed again.
    assert_eq!(
        dest.list(&backup_prefix(&backup.id)).unwrap(),
        Vec::<String>::new()
    );
    // A destination I/O error (failed sync) is reported as "destination unavailable".
    fs.fail_next_syncs(1);
    let err = write_backup(&dest, &fs, Path::new(STAGE), &backup).unwrap_err();
    assert_eq!(code(&err), 3002, "{err}");
    assert!(list(&dest).unwrap().is_empty());
    // And the same backup succeeds once the destination is healthy.
    write_backup(&dest, &fs, Path::new(STAGE), &backup).unwrap();
    assert_eq!(list(&dest).unwrap().len(), 1);
}

/// One run of the crash sweep: halt the file system after `halt` mutating operations of the
/// backup, crash it, and check that the destination holds either nothing complete or exactly
/// one backup that verifies and restores byte for byte.
fn crash_run(halt: Option<u64>, seed: u64, mode: CrashMode) -> bool {
    let fs = SimFileSystem::new();
    stage(&fs, Path::new(STAGE), true);
    let backup = new_backup(&rng(), 1_794_219_300, true);
    if let Some(n) = halt {
        fs.halt_after_ops(n);
    }
    let result = LocalDestination::open(Arc::new(fs.clone()), DEST)
        .and_then(|dest| write_backup(&dest, &fs, Path::new(STAGE), &backup));
    fs.crash(seed, mode);
    let dest = LocalDestination::open(Arc::new(fs.clone()), DEST).unwrap();
    let listed = list(&dest).unwrap();
    let ctx = format!("halt {halt:?} seed {seed} mode {mode:?} result {result:?}");
    if result.is_ok() {
        assert_eq!(
            listed.len(),
            1,
            "{ctx}: a returned backup must survive the crash"
        );
    }
    assert!(listed.len() <= 1, "{ctx}");
    for entry in &listed {
        let ListedBackup::Complete(manifest) = entry else {
            panic!("{ctx}: a complete backup must be readable: {entry:?}");
        };
        assert_eq!(manifest.backup_id, backup.id.as_str(), "{ctx}");
        verify(&dest, &backup.id, VerifyMode::Deep).unwrap_or_else(|e| panic!("{ctx}: {e}"));
        restore_files(
            &dest,
            &backup.id,
            Arc::new(fs.clone()),
            Path::new("/restore"),
        )
        .unwrap_or_else(|e| panic!("{ctx}: {e}"));
        assert_restored(&fs, Path::new("/restore"), true);
    }
    // An incomplete backup is invisible to verify as well.
    if listed.is_empty() {
        let err = verify(&dest, &backup.id, VerifyMode::Shallow).unwrap_err();
        assert_eq!(code(&err), 1030, "{ctx}: {err}");
    }
    result.is_ok()
}

#[test]
fn tc_bkp_009_crash_during_backup_leaves_no_complete_backup() {
    // Count the mutating operations of a full backup, then crash after each prefix of them.
    let fs = SimFileSystem::new();
    stage(&fs, Path::new(STAGE), true);
    let before = fs.op_count();
    let dest = LocalDestination::open(Arc::new(fs.clone()), DEST).unwrap();
    write_backup(
        &dest,
        &fs,
        Path::new(STAGE),
        &new_backup(&rng(), 1_794_219_300, true),
    )
    .unwrap();
    let total = fs.op_count() - before;
    assert!(total > 20, "unexpectedly few operations: {total}");
    let mut completed = 0;
    for halt in 0..=total {
        for mode in CrashMode::ALL {
            for seed in 0..2 {
                if crash_run(Some(halt), seed, mode) {
                    completed += 1;
                }
            }
        }
    }
    // Only the run that is allowed every operation completes (4 modes x 2 seeds).
    assert_eq!(completed, 8);
    assert!(crash_run(None, 0, CrashMode::Journaled));
}

/// Manifest equality survives a JSON round trip of what `write_backup` returned (the CLI prints
/// and re-reads it).
#[test]
fn written_manifest_round_trips() {
    let (_fs, dest, id) = backed_up();
    let m = rustegon_backup::load_manifest(&dest, &id).unwrap();
    assert_eq!(
        Manifest::from_json(id.as_str(), &m.to_json().unwrap()).unwrap(),
        m
    );
}
