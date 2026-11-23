// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Compressed single-file backups (PD-227; FR-BKP-001, FR-BKP-007, TC-BKP-016):
//! - a whole-node backup is one object `<id>.nbck`; listing, shallow and deep verification and
//!   restore read it like a directory backup, every restored byte matches, and it is smaller
//!   than the data it holds; the spool is removed;
//! - a damaged `.nbck` fails the deep verification (RGN-5002);
//! - a `.dbck` holds `dumps/<id>/…` in the given order and reads back byte for byte; a `.dbck`
//!   renamed `.nbck` is not taken for a node backup;
//! - the format fixtures `fixtures/formats/{nbck,dbck}/1/` stay readable and are reproduced byte
//!   for byte (implementation-rules.md §6). `RGN_FIXTURES_BLESS=1` rewrites them.

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
    ArchiveBuilder, ArchiveKind, BackupId, BackupMetadata, BakDestination, Consistency,
    Destination, Encryption, HlcTimestamp, ListedBackup, LocalDestination, NewBackup, SourceInfo,
    VerifyMode, list, restore_files, verify, write_nbck,
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

/// A fake checkpoint; the big file spans two 1 MiB transfer chunks and compresses well.
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

/// A sim file system with a staged checkpoint and a destination holding one `.nbck`.
fn backed_up(big: bool) -> (SimFileSystem, LocalDestination, BackupId) {
    let fs = SimFileSystem::new();
    for (rel, data) in staged_contents(big) {
        write_file(&fs, &Path::new(STAGE).join(rel), &data);
    }
    let dest = LocalDestination::open(Arc::new(fs.clone()), DEST).unwrap();
    let backup = new_backup(1_794_219_300, 1);
    write_nbck(&dest, &fs, Path::new(STAGE), &backup).unwrap();
    (fs, dest, backup.id)
}

fn code(err: impl Into<Error>) -> ErrorCode {
    err.into().code()
}

/// TC-BKP-016: one compressed object, read like a directory backup.
#[test]
fn tc_bkp_016_nbck_is_one_compressed_file_listed_verified_and_restored() {
    let (fs, dest, id) = backed_up(true);
    let key = ArchiveKind::Node.key(&id);
    assert_eq!(
        dest.list("").unwrap(),
        std::slice::from_ref(&key),
        "one object"
    );
    assert!(
        fs.read_dir(Path::new("/stage.nbck-spool")).is_err(),
        "the spool is removed"
    );
    let raw: usize = staged_contents(true).iter().map(|(_, d)| d.len()).sum();
    let stored = read_file(&fs, &Path::new(DEST).join(&key)).len();
    assert!(stored * 10 < raw, "{stored} bytes stored for {raw}");

    let listed = list(&dest).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(matches!(&listed[0], ListedBackup::Complete(m) if m.backup_id == id.as_str()));
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

    let again = write_nbck(&dest, &fs, Path::new(STAGE), &new_backup(1_794_219_300, 1));
    assert_eq!(code(again.unwrap_err()), ErrorCode::AlreadyExists);
}

/// TC-BKP-016: a flipped byte inside the compressed data fails the deep verification.
#[test]
fn tc_bkp_016_damaged_nbck_fails_deep_verification() {
    let (fs, dest, id) = backed_up(true);
    let path = Path::new(DEST).join(ArchiveKind::Node.key(&id));
    let mut bytes = read_file(&fs, &path);
    // The big entry's frame is the largest part of the archive; its middle is data.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x40;
    write_file(&fs, &path, &bytes);
    let err = verify(&dest, &id, VerifyMode::Deep).unwrap_err();
    assert_eq!(code(err), ErrorCode::StorageCorruption);
}

/// A `.dbck` of a fake dump, built entry by entry as the server's dump does.
fn dbck(fs: &SimFileSystem, dest: &LocalDestination) -> (BackupId, Vec<(&'static str, Vec<u8>)>) {
    let id = BackupId::parse("20261118T101500Z-02020202").unwrap();
    let ndjson: Vec<u8> = (0..20_000)
        .flat_map(|i| format!("{{\"_id\":{i},\"name\":\"n{i}\"}}\n").into_bytes())
        .collect();
    let files = vec![
        ("shop.database.json", b"{}".to_vec()),
        ("shop/items.metadata.json", b"{\"indexes\":[]}".to_vec()),
        ("shop/items.ndjson", ndjson),
        ("dump.json", b"{\"format_version\":1}".to_vec()),
    ];
    let mut b =
        ArchiveBuilder::new(fs, Path::new("/spool/d"), ArchiveKind::Database, id.clone()).unwrap();
    for (rel, data) in &files {
        b.start(rel).unwrap();
        for chunk in data.chunks(7000) {
            b.write(chunk).unwrap();
        }
        b.finish_entry().unwrap();
    }
    b.store(dest, 1_794_996_900).unwrap();
    (id, files)
}

/// TC-BKP-016: a `.dbck` reads back entry by entry; it is never listed as a node backup.
#[test]
fn tc_bkp_016_dbck_reads_back_and_is_not_a_node_backup() {
    let fs = SimFileSystem::new();
    let dest = LocalDestination::open(Arc::new(fs.clone()), DEST).unwrap();
    let (id, files) = dbck(&fs, &dest);
    let key = ArchiveKind::Database.key(&id);
    assert_eq!(dest.list("").unwrap(), std::slice::from_ref(&key));
    assert!(fs.read_dir(Path::new("/spool/d")).is_err(), "spool removed");

    let archive = BakDestination::open(&dest, &key).unwrap();
    assert_eq!(archive.kind(), ArchiveKind::Database);
    let prefix = format!("dumps/{id}/");
    let keys = archive.list(&format!("dumps/{id}")).unwrap();
    let mut want: Vec<String> = files.iter().map(|(r, _)| format!("{prefix}{r}")).collect();
    want.sort();
    assert_eq!(keys, want);
    for (rel, data) in &files {
        let r = archive.open(&format!("{prefix}{rel}")).unwrap();
        assert_eq!(r.size(), data.len() as u64, "{rel}");
        // Front to back in uneven pieces, as a restore reads.
        let mut got = Vec::new();
        let mut off = 0u64;
        while off < r.size() {
            let n = usize::try_from((r.size() - off).min(4099)).unwrap();
            let mut buf = vec![0u8; n];
            r.read_exact_at(&mut buf, off).unwrap();
            got.extend_from_slice(&buf);
            off += n as u64;
        }
        assert_eq!(&got, data, "{rel}");
    }
    // Not a node backup, also under a node backup's name.
    assert!(list(&dest).unwrap().is_empty());
    let bytes = read_file(&fs, &Path::new(DEST).join(&key));
    write_file(
        &fs,
        &Path::new(DEST).join(ArchiveKind::Node.key(&id)),
        &bytes,
    );
    assert!(matches!(
        list(&dest).unwrap().as_slice(),
        [ListedBackup::Unreadable { .. }]
    ));
}

fn fixture(kind: ArchiveKind, id: &BackupId) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formats")
        .join(kind.extension())
        .join("1")
        .join(kind.key(id))
}

/// Byte-for-byte comparison with a fixture (bless with `RGN_FIXTURES_BLESS=1`).
fn assert_fixture(kind: ArchiveKind, id: &BackupId, written: &[u8]) -> Vec<u8> {
    let path = fixture(kind, id);
    if std::env::var("RGN_FIXTURES_BLESS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, written).unwrap();
    }
    let fixture = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert!(
        written == fixture,
        "the {} v1 writer changed its output",
        kind.extension()
    );
    fixture
}

/// Format stability (implementation-rules.md §6) of nbck v1 and dbck v1: the writers reproduce
/// the fixtures byte for byte and the fixtures read back. A failure means the format changed:
/// bump `ARCHIVE_FORMAT_VERSION` and add fixtures, never edit these.
#[test]
fn tc_bkp_016_nbck_and_dbck_v1_fixtures_are_readable_and_reproduced() {
    let (fs, _dest, id) = backed_up(false);
    assert_eq!(id.as_str(), "20261109T101500Z-01010101");
    let written = read_file(&fs, &Path::new(DEST).join(ArchiveKind::Node.key(&id)));
    let nbck = assert_fixture(ArchiveKind::Node, &id, &written);
    let fixture_fs = SimFileSystem::new();
    write_file(
        &fixture_fs,
        &Path::new(DEST).join(ArchiveKind::Node.key(&id)),
        &nbck,
    );
    let dest = LocalDestination::open(Arc::new(fixture_fs.clone()), DEST).unwrap();
    let report = verify(&dest, &id, VerifyMode::Deep).unwrap();
    assert_eq!(report.manifest.created_at, "2026-11-09T10:15:00Z");
    restore_files(&dest, &id, Arc::new(fixture_fs.clone()), Path::new("/r")).unwrap();
    for (rel, data) in staged_contents(false) {
        assert_eq!(
            read_file(&fixture_fs, &Path::new("/r").join(rel)),
            data,
            "{rel}"
        );
    }

    let fs = SimFileSystem::new();
    let dest = LocalDestination::open(Arc::new(fs.clone()), DEST).unwrap();
    let (id, files) = dbck(&fs, &dest);
    let written = read_file(&fs, &Path::new(DEST).join(ArchiveKind::Database.key(&id)));
    let dbck_bytes = assert_fixture(ArchiveKind::Database, &id, &written);
    let fixture_fs = SimFileSystem::new();
    write_file(
        &fixture_fs,
        &Path::new(DEST).join(ArchiveKind::Database.key(&id)),
        &dbck_bytes,
    );
    let dest = LocalDestination::open(Arc::new(fixture_fs), DEST).unwrap();
    let archive = BakDestination::open(&dest, &ArchiveKind::Database.key(&id)).unwrap();
    let (rel, data) = &files[0];
    let r = archive.open(&format!("dumps/{id}/{rel}")).unwrap();
    let mut buf = vec![0u8; data.len()];
    r.read_exact_at(&mut buf, 0).unwrap();
    assert_eq!(&buf, data);
}
