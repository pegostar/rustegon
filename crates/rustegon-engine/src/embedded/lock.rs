// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The store directory lock (PD-068 (a); storage-engine.md §2, backup-restore.md "Single-node
//! scope"): `<root>/LOCK`, held exclusively by whoever uses the store — an open [`EmbeddedDb`]
//! (hence `rustegond`, whose store root is `<data_dir>/store`) or an offline tool such as a
//! physical restore — for as long as it uses it.
//!
//! Why: two engines on one store would each replay and append the same Raft log and write the
//! same LSM MANIFEST, and an offline restore under a live server would swap files under it.
//! Either corrupts the store; the lock turns both into a clear error (`RGN-3002`, retryable
//! once the other user is gone).
//!
//! The lock is the OS advisory lock of the sim-api `FileSystem::try_lock_exclusive` (`flock` /
//! `LockFileEx`), released when the holder closes it or dies, so a crash never leaves a stale
//! lock behind and nothing needs cleaning up at start. The `LOCK` file itself carries no data
//! and is never removed; on Windows the lock is mandatory, so the file cannot even be read while
//! held (a tool copying a live store directory must skip it — and should copy a checkpoint
//! instead anyway). A file system without locks (`Unsupported`, e.g. some network file
//! systems) is accepted with a warning: the lock protects against operator mistakes, not a
//! durability guarantee, and refusing to start there would make such deployments impossible.
//!
//! [`EmbeddedDb`]: super::EmbeddedDb

use std::{
    io,
    path::{Path, PathBuf},
};

use rustegon_common::{Error, ErrorCode};
use rustegon_sim_api::{FileLock, FileSystem};

/// Name of the lock file in the store root.
pub const LOCK_FILE: &str = "LOCK";

/// An exclusive hold on a store directory (module docs); released on drop.
#[derive(Debug)]
pub struct StoreLock {
    path: PathBuf,
    /// `None` when the file system cannot lock (module docs).
    lock: Option<FileLock>,
}

impl StoreLock {
    /// Takes the lock of the store in `root`, creating `root` if missing.
    ///
    /// # Errors
    /// `RGN-3002 Unavailable` when another process or another open in this process holds it;
    /// `RGN-5001 Internal` for I/O errors creating `root` or the lock file.
    pub fn acquire(fs: &dyn FileSystem, root: &Path) -> Result<Self, Error> {
        ensure_dir(fs, root)?;
        let path = root.join(LOCK_FILE);
        match fs.try_lock_exclusive(&path) {
            Ok(lock) => Ok(Self {
                path,
                lock: Some(lock),
            }),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(Error::new(
                ErrorCode::Unavailable,
                format!(
                    "the store in {} is in use: {} is held by another process (a running \
                     server, a restore) or another open in this process",
                    root.display(),
                    path.display()
                ),
            )
            .with_detail("lock", path.display().to_string())),
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                tracing::warn!(
                    lock = %path.display(),
                    "the file system cannot lock files: concurrent use of this store is not \
                     detected"
                );
                Ok(Self { path, lock: None })
            }
            Err(e) => Err(Error::new(
                ErrorCode::Internal,
                format!("cannot lock {}: {e}", path.display()),
            )),
        }
    }

    /// Whether the store in `root` is in use right now (an offline tool's pre-check; it should
    /// hold the lock with [`StoreLock::acquire`] for the whole operation instead, since the
    /// answer can change right after). `false` for a missing `root`.
    ///
    /// # Errors
    /// I/O errors other than a held lock or a missing directory.
    pub fn is_held(fs: &dyn FileSystem, root: &Path) -> Result<bool, Error> {
        match fs.read_dir(root) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!("cannot read {}: {e}", root.display()),
                ));
            }
        }
        match Self::acquire(fs, root) {
            Ok(lock) => {
                drop(lock);
                Ok(false)
            }
            Err(e) if e.code() == ErrorCode::Unavailable => Ok(true),
            Err(e) => Err(e),
        }
    }

    /// The lock file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the file system actually locked the file (module docs: `false` where it cannot).
    #[must_use]
    pub fn is_enforced(&self) -> bool {
        self.lock.is_some()
    }
}

/// Creates `dir` unless it exists (a read first: on an existing store this adds no mutating
/// file system operation).
fn ensure_dir(fs: &dyn FileSystem, dir: &Path) -> Result<(), Error> {
    match fs.read_dir(dir) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs.create_dir_all(dir).map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("cannot create {}: {e}", dir.display()),
            )
        }),
        Err(e) => Err(Error::new(
            ErrorCode::Internal,
            format!("cannot read {}: {e}", dir.display()),
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use rustegon_sim_api::{OsRng, StdFileSystem, SystemClock};

    use super::*;
    use crate::embedded::EmbeddedDb;

    fn open(root: &Path) -> Result<EmbeddedDb, Error> {
        EmbeddedDb::open(
            Arc::new(StdFileSystem),
            root,
            Arc::new(SystemClock::new()),
            Arc::new(OsRng),
        )
    }

    /// TC-BKP-014 (PD-068) on the real file system: two opens of one store in one process.
    #[test]
    fn tc_bkp_014_two_opens_of_one_store_on_the_real_file_system() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        let first = open(&root).unwrap();
        assert!(root.join(LOCK_FILE).exists());
        let err = open(&root).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable, "{err}");
        assert!(StoreLock::is_held(&StdFileSystem, &root).unwrap());
        drop(first);
        assert!(!StoreLock::is_held(&StdFileSystem, &root).unwrap());
        let lock = StoreLock::acquire(&StdFileSystem, &root).unwrap();
        assert!(lock.is_enforced());
        assert_eq!(lock.path(), root.join(LOCK_FILE));
        assert_eq!(open(&root).unwrap_err().code(), ErrorCode::Unavailable);
        drop(lock);
        drop(open(&root).unwrap());
    }
}
