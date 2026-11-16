// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-STO-008: platform file semantics the storage engine relies on, checked against the real
//! file system through [`StdFileSystem`] (storage-engine.md §9, §10, §13).
//!
//! The same tests run on Windows and Unix because the engine needs identical behaviour on both:
//! obsolete SSTs are deleted and CURRENT is replaced while table-cache handles and iterators keep
//! the old files open. Windows-only tests cover sharing violations caused by foreign handles.

#![allow(clippy::unwrap_used)] // tests: a failed setup step should abort the test

use std::{io, path::Path};

use rustegon_sim_api::{File, FileSystem, OpenMode, StdFileSystem};

fn write_file(fs: &dyn FileSystem, path: &Path, data: &[u8]) -> Box<dyn File> {
    let mut f = fs.open(path, OpenMode::CreateNew).unwrap();
    f.append(data).unwrap();
    f.sync_data().unwrap();
    f
}

fn read_all(f: &dyn File) -> Vec<u8> {
    let mut buf = vec![0; usize::try_from(f.size().unwrap()).unwrap()];
    f.read_exact_at(&mut buf, 0).unwrap();
    buf
}

fn names(fs: &dyn FileSystem, dir: &Path) -> Vec<String> {
    let mut v: Vec<_> = fs
        .read_dir(dir)
        .unwrap()
        .into_iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    v.sort();
    v
}

#[test]
fn tc_sto_008_remove_open_file_keeps_handle_readable() {
    let dir = tempfile::tempdir().unwrap();
    let fs = StdFileSystem;
    let path = dir.path().join("000007.sst");
    drop(write_file(&fs, &path, b"immutable sst bytes"));
    let reader = fs.open(&path, OpenMode::Read).unwrap();

    // Obsolete-file deletion while the table cache still holds the reader.
    fs.remove_file(&path).unwrap();
    fs.sync_dir(dir.path()).unwrap();
    assert!(
        names(&fs, dir.path()).is_empty(),
        "name must be gone at once"
    );
    assert_eq!(read_all(reader.as_ref()), b"immutable sst bytes");
    assert_eq!(
        fs.open(&path, OpenMode::Read).err().unwrap().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn tc_sto_008_rename_over_existing_open_target() {
    let dir = tempfile::tempdir().unwrap();
    let fs = StdFileSystem;
    let (cur, tmp) = (dir.path().join("CURRENT"), dir.path().join("CURRENT.tmp"));
    drop(write_file(&fs, &cur, b"MANIFEST-000001\n"));
    let old_reader = fs.open(&cur, OpenMode::Read).unwrap();
    // The writer of the temp file is also still open, as after `sync_data` before drop.
    let tmp_writer = write_file(&fs, &tmp, b"MANIFEST-000002\n");

    fs.rename(&tmp, &cur).unwrap();
    fs.sync_dir(dir.path()).unwrap();

    assert_eq!(names(&fs, dir.path()), ["CURRENT"]);
    assert_eq!(read_all(old_reader.as_ref()), b"MANIFEST-000001\n");
    assert_eq!(read_all(tmp_writer.as_ref()), b"MANIFEST-000002\n");
    let fresh = fs.open(&cur, OpenMode::Read).unwrap();
    assert_eq!(read_all(fresh.as_ref()), b"MANIFEST-000002\n");
}

#[test]
fn tc_sto_008_truncate_reopen_while_reader_open() {
    // OpenMode::Truncate (small files rewritten whole) must not hit a sharing violation either.
    let dir = tempfile::tempdir().unwrap();
    let fs = StdFileSystem;
    let path = dir.path().join("f");
    drop(write_file(&fs, &path, b"old"));
    let reader = fs.open(&path, OpenMode::Read).unwrap();
    let mut w = fs.open(&path, OpenMode::Truncate).unwrap();
    w.append(b"new!").unwrap();
    assert_eq!(read_all(reader.as_ref()), b"new!");
}

#[test]
fn tc_sto_008_sync_dir_persists_entries_and_reports_missing_dir() {
    let dir = tempfile::tempdir().unwrap();
    let fs = StdFileSystem;
    let sub = dir.path().join("store");
    fs.create_dir_all(&sub).unwrap();
    // A directory handle is opened for every call; repeated calls with an open file inside
    // must not conflict with each other or with the open file.
    let _open = write_file(&fs, &sub.join("000001.sst"), b"x");
    fs.sync_dir(&sub).unwrap();
    fs.sync_dir(&sub).unwrap();
    fs.sync_dir(dir.path()).unwrap();
    let err = fs.sync_dir(&dir.path().join("missing")).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn tc_sto_008_hard_link_shares_data_and_outlives_original() {
    let dir = tempfile::tempdir().unwrap();
    let fs = StdFileSystem;
    let ckpt = dir.path().join("checkpoint");
    fs.create_dir_all(&ckpt).unwrap();
    let (orig, link) = (dir.path().join("000009.sst"), ckpt.join("000009.sst"));
    let reader = write_file(&fs, &orig, b"shared");

    fs.hard_link(&orig, &link).unwrap();
    fs.sync_dir(&ckpt).unwrap();
    // The live store drops the file; the checkpoint copy and open handles stay valid.
    fs.remove_file(&orig).unwrap();
    assert_eq!(read_all(reader.as_ref()), b"shared");
    let via_link = fs.open(&link, OpenMode::Read).unwrap();
    assert_eq!(read_all(via_link.as_ref()), b"shared");

    // Linking onto an existing name is an ordinary error, not "unsupported".
    let other = dir.path().join("other");
    drop(write_file(&fs, &other, b"o"));
    let err = fs.hard_link(&other, &link).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    let err = fs
        .hard_link(&dir.path().join("missing"), &ckpt.join("m"))
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

/// Windows only: a handle opened *outside* `StdFileSystem` without `FILE_SHARE_DELETE` (an
/// antivirus scanner, backup agent or editor) blocks delete and rename-over with a sharing
/// violation; the engine sees an ordinary I/O error and must retry later (orphan cleanup).
#[cfg(windows)]
#[test]
fn tc_sto_008_foreign_handle_without_share_delete_is_sharing_violation() {
    use std::os::windows::fs::OpenOptionsExt as _;

    /// `ERROR_SHARING_VIOLATION` (winerror.h).
    const ERROR_SHARING_VIOLATION: i32 = 32;
    /// `ERROR_ACCESS_DENIED` (winerror.h).
    const ERROR_ACCESS_DENIED: i32 = 5;
    /// `FILE_SHARE_READ` only (winnt.h).
    const FILE_SHARE_READ: u32 = 0x1;

    let dir = tempfile::tempdir().unwrap();
    let fs = StdFileSystem;
    let (path, tmp) = (dir.path().join("000011.sst"), dir.path().join("x.tmp"));
    drop(write_file(&fs, &path, b"locked"));
    drop(write_file(&fs, &tmp, b"replacement"));
    let foreign = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)
        .unwrap();

    let err = fs.remove_file(&path).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(ERROR_SHARING_VIOLATION), "{err}");
    // Rename-over reports ERROR_ACCESS_DENIED instead (observed on Windows 11 / NTFS): the
    // POSIX-semantics rename cannot obtain DELETE access to the target.
    let err = fs.rename(&tmp, &path).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED), "{err}");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    // Our readers still open: the foreign handle shares read access, ours only reads.
    let ours = fs.open(&path, OpenMode::Read).unwrap();
    assert_eq!(read_all(ours.as_ref()), b"locked");

    drop(foreign);
    drop(ours);
    fs.remove_file(&path).unwrap();
    fs.rename(&tmp, &path).unwrap();
    assert_eq!(names(&fs, dir.path()), ["000011.sst"]);
}

/// Windows only: conversely, our handles must not lock files against other processes that ask
/// for delete access (e.g. an operator removing a stray checkpoint while the engine reads it).
#[cfg(windows)]
#[test]
fn tc_sto_008_own_handles_allow_foreign_delete() {
    let dir = tempfile::tempdir().unwrap();
    let fs = StdFileSystem;
    let path = dir.path().join("000012.sst");
    let mut writer = fs.open(&path, OpenMode::CreateNew).unwrap();
    writer.append(b"abc").unwrap();
    let reader = fs.open(&path, OpenMode::Read).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(read_all(reader.as_ref()), b"abc");
}

/// Read-only files serve concurrent positional reads correctly (on Windows through a pool of
/// independent handles, `WinReadFile`), keep working after the name is deleted, and refuse
/// appends.
#[test]
fn tc_sto_008_concurrent_reads_of_one_open_file_are_exact() {
    let dir = tempfile::tempdir().unwrap();
    let fs = StdFileSystem;
    let path = dir.path().join("000042.sst");
    let data: Vec<u8> = (0..64 * 1024u32)
        .map(|i| i.wrapping_mul(31).to_le_bytes()[1])
        .collect();
    drop(write_file(&fs, &path, &data));
    let mut reader = fs.open(&path, OpenMode::Read).unwrap();
    // The name goes; the open reader keeps all of its handles.
    fs.remove_file(&path).unwrap();
    std::thread::scope(|scope| {
        for t in 0..16usize {
            let (reader, data) = (&reader, &data);
            scope.spawn(move || {
                for i in 0..500usize {
                    let offset = (t * 7919 + i * 104_729) % (data.len() - 512);
                    let len = 1 + (i * 37) % 511;
                    let mut buf = vec![0u8; len];
                    reader.read_exact_at(&mut buf, offset as u64).unwrap();
                    assert_eq!(buf, data[offset..offset + len], "thread {t} read {i}");
                }
            });
        }
    });
    assert_eq!(reader.size().unwrap(), data.len() as u64);
    let mut past = [0u8; 2];
    let err = reader
        .read_exact_at(&mut past, data.len() as u64 - 1)
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    #[cfg(windows)]
    assert_eq!(
        reader.append(b"x").unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    #[cfg(not(windows))]
    assert!(reader.append(b"x").is_err());
}
