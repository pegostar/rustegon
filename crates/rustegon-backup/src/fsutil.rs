// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Small directory helpers over the sim-api [`FileSystem`] shared by the physical backup,
//! snapshot and offline restore code (M13a lane BE). The trait has no `stat`: a path that lists
//! is a directory (as in `writer::walk`).

use std::{
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_sim_api::{FileSystem, OpenMode};

use crate::id::UtcTime;

/// A local I/O error as a catalog error naming the path (no file contents ever).
pub(crate) fn io_err(op: &str, path: &Path, e: &io::Error) -> Error {
    let code = if e.kind() == io::ErrorKind::StorageFull {
        ErrorCode::DiskFull
    } else {
        ErrorCode::Internal
    };
    Error::new(code, format!("{op} {}: {e}", path.display()))
}

/// The entries of `dir`, or `None` when it does not exist (or is not a directory).
pub(crate) fn list_dir(fs: &dyn FileSystem, dir: &Path) -> Result<Option<Vec<PathBuf>>, Error> {
    match fs.read_dir(dir) {
        Ok(entries) => Ok(Some(entries)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        // `read_dir` of a regular file: not a directory (the kind differs per platform).
        Err(_) if file_exists(fs, dir)? => Ok(None),
        Err(e) => Err(io_err("list", dir, &e)),
    }
}

/// Whether the directory `dir` exists.
pub(crate) fn dir_exists(fs: &dyn FileSystem, dir: &Path) -> Result<bool, Error> {
    Ok(list_dir(fs, dir)?.is_some())
}

/// Whether the regular file `path` exists.
pub(crate) fn file_exists(fs: &dyn FileSystem, path: &Path) -> Result<bool, Error> {
    if fs.read_dir(path).is_ok() {
        return Ok(false);
    }
    match fs.open(path, OpenMode::Read) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_err("open", path, &e)),
    }
}

/// Removes `dir` and everything below it; nothing to do when it is missing. Not atomic: a crash
/// leaves part of the tree, which the callers' recovery removes again (staging directories,
/// deleted snapshots whose `COMPLETE` went first).
pub(crate) fn remove_tree(fs: &dyn FileSystem, dir: &Path) -> Result<(), Error> {
    let Some(entries) = list_dir(fs, dir)? else {
        return Ok(());
    };
    for entry in entries {
        if fs.read_dir(&entry).is_ok() {
            remove_tree(fs, &entry)?;
        } else {
            match fs.remove_file(&entry) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_err("remove", &entry, &e)),
            }
        }
    }
    match fs.remove_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err("remove directory", dir, &e)),
    }
}

/// Syncs the directory `dir` (its entries become durable).
pub(crate) fn sync_dir(fs: &dyn FileSystem, dir: &Path) -> Result<(), Error> {
    fs.sync_dir(dir).map_err(|e| io_err("sync", dir, &e))
}

/// Creates `dir` and its parents unless it exists.
pub(crate) fn ensure_dir(fs: &dyn FileSystem, dir: &Path) -> Result<(), Error> {
    if dir_exists(fs, dir)? {
        return Ok(());
    }
    fs.create_dir_all(dir)
        .map_err(|e| io_err("create directory", dir, &e))
}

/// Writes `bytes` to `path` atomically and durably: `<path>~tmp`, fsync, rename, directory
/// fsync (the parent must exist).
pub(crate) fn write_atomic(fs: &dyn FileSystem, path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push("~tmp");
    let tmp = PathBuf::from(tmp);
    let mut file = fs
        .open(&tmp, OpenMode::Truncate)
        .map_err(|e| io_err("create", &tmp, &e))?;
    file.append(bytes).map_err(|e| io_err("write", &tmp, &e))?;
    file.sync_data().map_err(|e| io_err("sync", &tmp, &e))?;
    drop(file);
    fs.rename(&tmp, path)
        .map_err(|e| io_err("rename", path, &e))?;
    if let Some(parent) = path.parent() {
        sync_dir(fs, parent)?;
    }
    Ok(())
}

/// Reads a small file entirely (`limit` bytes at most); `None` when it does not exist.
pub(crate) fn read_small(
    fs: &dyn FileSystem,
    path: &Path,
    limit: u64,
) -> Result<Option<Vec<u8>>, Error> {
    let file = match fs.open(path, OpenMode::Read) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err("open", path, &e)),
    };
    let size = file.size().map_err(|e| io_err("stat", path, &e))?;
    if size > limit {
        return Err(Error::new(
            ErrorCode::StorageCorruption,
            format!("{} is larger than {limit} bytes", path.display()),
        ));
    }
    let len = usize::try_from(size).map_err(|_| {
        Error::new(
            ErrorCode::Internal,
            format!("{} does not fit in memory", path.display()),
        )
    })?;
    let mut buf = vec![0u8; len];
    file.read_exact_at(&mut buf, 0)
        .map_err(|e| io_err("read", path, &e))?;
    Ok(Some(buf))
}

/// `yyyymmddThhmmssZ` of `at` (names of kept stores, staging directories).
pub(crate) fn compact_utc(at: SystemTime) -> Result<String, Error> {
    Ok(UtcTime::from_system_time(at)
        .map_err(Error::from)?
        .compact())
}

/// RFC 3339 UTC of `at` (manifests).
pub(crate) fn rfc3339_utc(at: SystemTime) -> Result<String, Error> {
    Ok(UtcTime::from_system_time(at)
        .map_err(Error::from)?
        .rfc3339())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rustegon_sim_api::StdFileSystem;

    use super::*;

    #[test]
    fn fr_bkp_001_remove_tree_and_atomic_writes_on_the_real_file_system() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFileSystem;
        let root = dir.path().join("tree");
        ensure_dir(&fs, &root.join("a").join("b")).unwrap();
        write_atomic(&fs, &root.join("a").join("b").join("f"), b"x").unwrap();
        write_atomic(&fs, &root.join("g"), b"yz").unwrap();
        assert!(dir_exists(&fs, &root).unwrap());
        assert!(file_exists(&fs, &root.join("g")).unwrap());
        assert!(!file_exists(&fs, &root.join("a")).unwrap());
        assert!(list_dir(&fs, &root.join("g")).unwrap().is_none());
        assert_eq!(
            read_small(&fs, &root.join("g"), 10).unwrap().unwrap(),
            b"yz"
        );
        assert!(read_small(&fs, &root.join("g"), 1).is_err());
        assert!(read_small(&fs, &root.join("none"), 1).unwrap().is_none());
        remove_tree(&fs, &root).unwrap();
        assert!(!dir_exists(&fs, &root).unwrap());
        remove_tree(&fs, &root).unwrap();
    }
}
