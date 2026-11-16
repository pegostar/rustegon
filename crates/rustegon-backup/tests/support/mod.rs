// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared helpers of the S3 tests: the fake server and a backup round trip that any
//! destination must pass (TC-BKP-006).

#![allow(dead_code)]

pub mod fake_s3;

use std::{
    path::Path,
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, SystemTime},
};

use rustegon_backup::{
    BackupError, BackupId, BackupMetadata, Consistency, Destination, Encryption, HlcTimestamp,
    NewBackup, SourceInfo, VerifyMode, backup_prefix, list, restore_files, verify, write_backup,
};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{FileSystem, OpenMode, Rng};

struct SeqRng(AtomicU8);

impl Rng for SeqRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        buf.fill(self.0.fetch_add(1, Ordering::Relaxed));
    }
}

/// Deterministic contents of `len` bytes.
pub fn pattern(len: usize, seed: u32) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let i = u32::try_from(i).unwrap();
            u8::try_from(i.wrapping_mul(31).wrapping_add(seed) % 251).unwrap()
        })
        .collect()
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

/// Staged checkpoint: one file larger than `big` bytes (multipart with a 5 MiB part size), a few
/// small ones, an empty one and the DEK registry.
fn staged(big: usize) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("lsm/000005.rsst", pattern(big, 7)),
        ("lsm/000009.rsst", b"small sst".to_vec()),
        ("lsm/MANIFEST-000002", b"manifest snapshot".to_vec()),
        ("lsm/CURRENT", b"MANIFEST-000002\n".to_vec()),
        ("lsm/000010.rsst", Vec::new()),
        ("keys/registry.enc", vec![0x5a; 96]),
    ]
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
                cluster_id: "cluster-a".into(),
                node_id: "1".into(),
                server_version: "0.1.0".into(),
            },
            encryption: Encryption::Kek {
                kek_id: "file:/kek".into(),
            },
            pitr: None,
        },
    }
}

/// Full backup cycle on `dest` (TC-BKP-006 acceptance): write (with a multipart file of `big`
/// bytes), list, shallow + deep verify, restore and compare every byte; an incomplete backup
/// is invisible; deep verify detects a corrupted object. `seed` keeps ids distinct when one
/// destination runs the cycle several times.
pub fn round_trip(dest: &dyn Destination, big: usize, seed: u8) {
    let fs = SimFileSystem::new();
    let files = staged(big);
    for (rel, data) in &files {
        write_file(&fs, &Path::new("/stage").join(rel), data);
    }
    let backup = new_backup(1_794_219_300 + u64::from(seed), seed);
    let manifest = write_backup(dest, &fs, Path::new("/stage"), &backup).unwrap();
    assert_eq!(manifest.files.len(), files.len());

    // A second id with objects but no COMPLETE: never listed, never restorable.
    let partial = new_backup(1_794_219_400 + u64::from(seed), seed.wrapping_add(100));
    let partial_prefix = backup_prefix(&partial.id);
    dest.put_bytes(&format!("{partial_prefix}/manifest.json"), b"{}")
        .unwrap();

    let listed = list(dest).unwrap();
    assert!(
        listed.iter().any(|b| b.id() == backup.id.as_str()),
        "complete backup listed"
    );
    assert!(
        !listed.iter().any(|b| b.id() == partial.id.as_str()),
        "incomplete backup ignored"
    );
    assert!(matches!(
        verify(dest, &partial.id, VerifyMode::Shallow),
        Err(BackupError::BackupNotFound { .. })
    ));

    let shallow = verify(dest, &backup.id, VerifyMode::Shallow).unwrap();
    assert_eq!(shallow.files_checked, files.len());
    let deep = verify(dest, &backup.id, VerifyMode::Deep).unwrap();
    let total: usize = files.iter().map(|(_, d)| d.len()).sum();
    assert_eq!(deep.bytes_hashed, total as u64);

    let target: std::sync::Arc<dyn FileSystem> = std::sync::Arc::new(fs.clone());
    restore_files(dest, &backup.id, target, Path::new("/restored")).unwrap();
    for (rel, data) in &files {
        assert_eq!(
            &read_file(&fs, &Path::new("/restored").join(rel)),
            data,
            "{rel} restored"
        );
    }

    // Corrupt one object in place (same size): deep verify fails with RGN-5002.
    let victim = format!("{}/lsm/000009.rsst", backup_prefix(&backup.id));
    dest.put_bytes(&victim, b"SMALL SST").unwrap();
    let err = verify(dest, &backup.id, VerifyMode::Deep).unwrap_err();
    assert_eq!(err.code().code(), 5002, "{err}");

    // Clean up so that a shared bucket does not grow across runs.
    for key in dest.list(&backup_prefix(&backup.id)).unwrap() {
        dest.delete(&key).unwrap();
    }
    for key in dest.list(&partial_prefix).unwrap() {
        dest.delete(&key).unwrap();
    }
    assert_eq!(
        dest.list(&backup_prefix(&backup.id)).unwrap(),
        Vec::<String>::new()
    );
}
