// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! File naming in the LSM directory and the `CURRENT` pointer (storage-engine.md §2, §9).
//!
//! `CURRENT` holds `MANIFEST-<number>\n`. It is replaced atomically: write `CURRENT.tmp`, fsync
//! it, rename over `CURRENT`, fsync the directory. A crash at any point leaves either the old or
//! the new pointer, never a partial one.

use std::path::{Path, PathBuf};

use rustegon_sim_api::{FileSystem, OpenMode};

use crate::error::{Result, StorageError};

const CURRENT: &str = "CURRENT";
const CURRENT_TMP: &str = "CURRENT.tmp";
const MANIFEST_PREFIX: &str = "MANIFEST-";
const SST_SUFFIX: &str = ".sst";
/// `CURRENT` is tiny; anything larger is not ours.
const MAX_CURRENT_LEN: u64 = 64;

/// File name of SST `number`.
#[must_use]
pub fn sst_file_name(number: u64) -> String {
    format!("{number:06}{SST_SUFFIX}")
}

/// File name of MANIFEST `number`.
#[must_use]
pub fn manifest_file_name(number: u64) -> String {
    format!("{MANIFEST_PREFIX}{number:06}")
}

/// Kinds of files the engine owns in its directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// `<number>.sst`
    Sst(u64),
    /// `MANIFEST-<number>`
    Manifest(u64),
    /// `CURRENT`
    Current,
    /// `CURRENT.tmp` left by a crash during a pointer switch.
    CurrentTemp,
}

/// Classifies a file name; `None` for files the engine does not own.
#[must_use]
pub fn parse_file_name(name: &str) -> Option<FileKind> {
    match name {
        CURRENT => return Some(FileKind::Current),
        CURRENT_TMP => return Some(FileKind::CurrentTemp),
        _ => {}
    }
    let number = |digits: &str| {
        (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .then(|| digits.parse().ok())
            .flatten()
    };
    if let Some(digits) = name.strip_prefix(MANIFEST_PREFIX) {
        return number(digits).map(FileKind::Manifest);
    }
    name.strip_suffix(SST_SUFFIX)
        .and_then(number)
        .map(FileKind::Sst)
}

/// Creates `dir` (and missing ancestors) and fsyncs the parent of every directory it creates, so
/// the new entries survive a crash (§9: a name is durable only after its parent is fsynced).
/// Directories that already existed are left alone: whoever created them made them durable,
/// and syncing system directories (e.g. `C:\Users`) needs access a store does not have.
///
/// # Errors
/// I/O errors.
pub(crate) fn create_dir_durable(fs: &dyn FileSystem, dir: &Path) -> Result<()> {
    let mut created = Vec::new();
    let mut cur = dir;
    loop {
        match fs.read_dir(cur) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => created.push(cur),
            Err(e) => return Err(e.into()),
        }
        match cur.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(parent) => cur = parent,
            None => break,
        }
    }
    fs.create_dir_all(dir)?;
    // Deepest first is not required: each sync makes one new name durable.
    for new_dir in created {
        if let Some(parent) = new_dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs.sync_dir(parent)?;
        }
    }
    Ok(())
}

pub(crate) fn current_path(dir: &Path) -> PathBuf {
    dir.join(CURRENT)
}

/// Atomically points `CURRENT` at MANIFEST `number`.
pub(crate) fn set_current(fs: &dyn FileSystem, dir: &Path, number: u64) -> Result<()> {
    let tmp = dir.join(CURRENT_TMP);
    let mut f = fs.open(&tmp, OpenMode::Truncate)?;
    f.append(format!("{}\n", manifest_file_name(number)).as_bytes())?;
    f.sync_data()?;
    // Close before renaming: Windows refuses to rename a file with an open handle.
    drop(f);
    fs.rename(&tmp, &current_path(dir))?;
    fs.sync_dir(dir)?;
    Ok(())
}

/// Reads the MANIFEST number `CURRENT` points at.
pub(crate) fn read_current(fs: &dyn FileSystem, dir: &Path) -> Result<u64> {
    let f = fs.open(&current_path(dir), OpenMode::Read)?;
    let size = f.size()?;
    let bad = || StorageError::corruption("CURRENT does not name a MANIFEST");
    if size > MAX_CURRENT_LEN {
        return Err(bad());
    }
    // Lossless: bounded by MAX_CURRENT_LEN.
    #[allow(clippy::cast_possible_truncation)]
    let mut buf = vec![0u8; size as usize];
    f.read_exact_at(&mut buf, 0)?;
    let text = std::str::from_utf8(&buf).map_err(|_| bad())?;
    match text.strip_suffix('\n').and_then(parse_file_name) {
        Some(FileKind::Manifest(n)) => Ok(n),
        _ => Err(bad()),
    }
}

#[cfg(test)]
mod tests {
    use rustegon_sim_api::StdFileSystem;

    use super::*;

    /// Delegates to the simulated FS and records `sync_dir` calls.
    #[derive(Default)]
    struct Recording {
        inner: rustegon_sim::SimFileSystem,
        synced: std::sync::Mutex<Vec<PathBuf>>,
    }

    impl FileSystem for Recording {
        fn open(
            &self,
            path: &Path,
            mode: OpenMode,
        ) -> std::io::Result<Box<dyn rustegon_sim_api::File>> {
            self.inner.open(path, mode)
        }
        fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
            self.inner.create_dir_all(path)
        }
        fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            self.inner.rename(from, to)
        }
        fn remove_file(&self, path: &Path) -> std::io::Result<()> {
            self.inner.remove_file(path)
        }
        fn hard_link(&self, original: &Path, link: &Path) -> std::io::Result<()> {
            self.inner.hard_link(original, link)
        }
        fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
            self.inner.read_dir(path)
        }
        fn sync_dir(&self, path: &Path) -> std::io::Result<()> {
            self.synced.lock().unwrap().push(path.to_path_buf());
            self.inner.sync_dir(path)
        }
    }

    #[test]
    fn create_dir_durable_syncs_parents_of_created_directories_only() {
        let fs = Recording::default();
        fs.inner.create_dir_all(Path::new("/data")).unwrap();
        create_dir_durable(&fs, Path::new("/data/cp/one")).unwrap();
        let mut synced = fs.synced.lock().unwrap().clone();
        synced.sort();
        assert_eq!(synced, [PathBuf::from("/data"), PathBuf::from("/data/cp")]);
        assert_eq!(
            fs.read_dir(Path::new("/data/cp/one")).unwrap(),
            Vec::<PathBuf>::new()
        );

        fs.synced.lock().unwrap().clear();
        create_dir_durable(&fs, Path::new("/data/cp/one")).unwrap();
        assert!(
            fs.synced.lock().unwrap().is_empty(),
            "existing dirs are not re-synced"
        );
    }

    #[test]
    fn file_names_round_trip_and_foreign_names_are_ignored() {
        assert_eq!(sst_file_name(7), "000007.sst");
        assert_eq!(manifest_file_name(1_234_567), "MANIFEST-1234567");
        assert_eq!(parse_file_name("000007.sst"), Some(FileKind::Sst(7)));
        assert_eq!(
            parse_file_name("MANIFEST-000012"),
            Some(FileKind::Manifest(12))
        );
        assert_eq!(parse_file_name("CURRENT"), Some(FileKind::Current));
        assert_eq!(parse_file_name("CURRENT.tmp"), Some(FileKind::CurrentTemp));
        for foreign in [
            ".sst",
            "x.sst",
            "MANIFEST-",
            "MANIFEST-1a",
            "LOCK",
            "-1.sst",
        ] {
            assert_eq!(parse_file_name(foreign), None, "{foreign}");
        }
    }

    #[test]
    fn current_switches_atomically_and_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFileSystem;
        set_current(&fs, dir.path(), 3).unwrap();
        assert_eq!(read_current(&fs, dir.path()).unwrap(), 3);
        set_current(&fs, dir.path(), 9).unwrap();
        assert_eq!(read_current(&fs, dir.path()).unwrap(), 9);
        assert!(!dir.path().join(CURRENT_TMP).exists());

        let mut f = fs
            .open(&current_path(dir.path()), OpenMode::Truncate)
            .unwrap();
        f.append(b"000001.sst\n").unwrap();
        drop(f);
        assert!(read_current(&fs, dir.path()).unwrap_err().is_corruption());
    }
}
