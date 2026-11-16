// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Directory-backed destination: a local disk, an NFS mount or a Windows UNC share
//! (TC-BKP-009), through the sim-api [`FileSystem`] so crash tests can run it on the simulated
//! file system.
//!
//! # Atomic, durable puts
//! Each object is written to `<name>~partial` in its final directory, appended, `fsync`ed, renamed
//! over `<name>` and the directory is `fsync`ed (storage-engine.md §9 discipline). After a crash a
//! key therefore either holds its complete contents or does not exist; the only leftovers are
//! `~partial` files, which listings skip (`~` is outside the key alphabet, so no key collides with
//! a temp name) and the next put of the same key truncates. Directories are created on demand and
//! their parent is `fsync`ed once per directory, so the names of new backup directories survive a
//! crash as well.

use std::{
    collections::BTreeSet,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
};

use rustegon_sim_api::{File, FileSystem, OpenMode};

use super::{CHUNK_BYTES, Destination, ObjectReader, validate_key};
use crate::error::{BackupError, Result};

/// Suffix of in-progress objects (module docs).
const TEMP_SUFFIX: &str = "~partial";

/// A destination rooted at a directory.
pub struct LocalDestination {
    fs: Arc<dyn FileSystem>,
    root: PathBuf,
    /// Directories known to exist with a durable name, so each parent is synced only once.
    durable_dirs: Mutex<BTreeSet<PathBuf>>,
}

impl std::fmt::Debug for LocalDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalDestination")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl LocalDestination {
    /// Opens the destination rooted at `root`, creating the directory (durably) if missing.
    ///
    /// # Errors
    /// [`BackupError::Destination`] when the directory cannot be created or synced.
    pub fn open(fs: Arc<dyn FileSystem>, root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let dest = Self {
            fs,
            root,
            durable_dirs: Mutex::new(BTreeSet::new()),
        };
        // An existing root is taken as durable: it was not created by us, and syncing the parent
        // of e.g. a share root may not even be permitted.
        if dest.fs.read_dir(&dest.root).is_err() {
            dest.fs
                .create_dir_all(&dest.root)
                .map_err(|e| dest.error("create directory", "", e))?;
            if let Some(parent) = dest.root.parent().filter(|p| !p.as_os_str().is_empty()) {
                dest.fs
                    .sync_dir(parent)
                    .map_err(|e| dest.error("sync directory", "", e))?;
            }
        }
        dest.lock_dirs().insert(dest.root.clone());
        Ok(dest)
    }

    /// The root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn lock_dirs(&self) -> std::sync::MutexGuard<'_, BTreeSet<PathBuf>> {
        // The set only caches "already synced"; a poisoned lock leaves it valid.
        self.durable_dirs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn error(&self, op: &'static str, key: &str, source: io::Error) -> BackupError {
        BackupError::Destination {
            destination: self.describe(),
            op,
            key: key.to_owned(),
            source,
        }
    }

    /// Local path of a key or prefix (`""` = root). Keys are validated, so the join cannot
    /// leave the root.
    fn path_of(&self, key: &str) -> Result<PathBuf> {
        let mut path = self.root.clone();
        if !key.is_empty() {
            validate_key(key)?;
            path.extend(key.split('/'));
        }
        Ok(path)
    }

    /// Creates `dir` (below the root) with a durable name.
    fn ensure_dir(&self, dir: &Path) -> io::Result<()> {
        if self.lock_dirs().contains(dir) {
            return Ok(());
        }
        let parent = dir
            .parent()
            .ok_or_else(|| io::Error::other("directory outside the destination root"))?;
        self.ensure_dir(parent)?;
        self.fs.create_dir_all(dir)?;
        self.fs.sync_dir(parent)?;
        self.lock_dirs().insert(dir.to_path_buf());
        Ok(())
    }

    fn write_object(
        &self,
        path: &Path,
        tmp: &Path,
        size: u64,
        reader: &mut dyn io::Read,
    ) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("object without a parent directory"))?;
        self.ensure_dir(parent)?;
        let mut file = self.fs.open(tmp, OpenMode::Truncate)?;
        let chunk = usize::try_from(size).map_or(CHUNK_BYTES, |s| s.min(CHUNK_BYTES));
        let mut buf = vec![0u8; chunk];
        let mut left = size;
        while left > 0 {
            let n = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
            reader.read_exact(&mut buf[..n])?;
            file.append(&buf[..n])?;
            left -= n as u64;
        }
        let mut probe = [0u8; 1];
        if reader.read(&mut probe)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source yielded more bytes than declared",
            ));
        }
        file.sync_data()?;
        drop(file);
        self.fs.rename(tmp, path)?;
        self.fs.sync_dir(parent)
    }

    /// Recursive listing below `dir`, keys prefixed by `prefix`.
    fn walk(&self, dir: &Path, prefix: &str, out: &mut Vec<String>) -> io::Result<()> {
        for (name, path) in self.children(dir)? {
            let key = super::join_key(&[prefix, &name]);
            // The sim-api file system has no stat; a path that lists is a directory.
            match self.fs.read_dir(&path) {
                Ok(_) => self.walk(&path, &key, out)?,
                Err(_) => out.push(key),
            }
        }
        Ok(())
    }

    /// Valid entry names of `dir` (missing directory = none), without temp files.
    fn children(&self, dir: &Path) -> io::Result<Vec<(String, PathBuf)>> {
        let entries = match self.fs.read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out: Vec<(String, PathBuf)> = entries
            .into_iter()
            .filter_map(|path| {
                let name = path.file_name()?.to_str()?.to_owned();
                // Temp files and foreign names (outside the key alphabet) are not objects.
                validate_key(&name).ok()?;
                Some((name, path))
            })
            .collect();
        out.sort();
        Ok(out)
    }
}

impl Destination for LocalDestination {
    fn describe(&self) -> String {
        self.root.display().to_string()
    }

    fn put_reader(&self, key: &str, size: u64, reader: &mut dyn io::Read) -> Result<()> {
        let path = self.path_of(key)?;
        let name = path
            .file_name()
            .ok_or_else(|| BackupError::InvalidArgument(format!("key {key:?} has no name")))?;
        let mut tmp_name = name.to_os_string();
        tmp_name.push(TEMP_SUFFIX);
        let tmp = path.with_file_name(tmp_name);
        self.write_object(&path, &tmp, size, reader).map_err(|e| {
            // Best effort: a leftover temp file is skipped by listings and truncated by the next
            // put of this key.
            let _ = self.fs.remove_file(&tmp);
            self.error("put", key, e)
        })
    }

    fn open(&self, key: &str) -> Result<Box<dyn ObjectReader>> {
        let path = self.path_of(key)?;
        let file = self.fs.open(&path, OpenMode::Read).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                BackupError::ObjectNotFound {
                    key: key.to_owned(),
                    destination: self.describe(),
                }
            } else {
                self.error("open", key, e)
            }
        })?;
        let size = file.size().map_err(|e| self.error("stat", key, e))?;
        Ok(Box::new(LocalObject {
            file,
            size,
            key: key.to_owned(),
            destination: self.describe(),
        }))
    }

    fn size(&self, key: &str) -> Result<Option<u64>> {
        match self.open(key) {
            Ok(reader) => Ok(Some(reader.size())),
            Err(BackupError::ObjectNotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let dir = self.path_of(prefix)?;
        let mut out = Vec::new();
        self.walk(&dir, prefix, &mut out)
            .map_err(|e| self.error("list", prefix, e))?;
        out.sort();
        Ok(out)
    }

    fn list_children(&self, prefix: &str) -> Result<Vec<String>> {
        let dir = self.path_of(prefix)?;
        Ok(self
            .children(&dir)
            .map_err(|e| self.error("list", prefix, e))?
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_of(key)?;
        match self.fs.remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(self.error("delete", key, e)),
        }
        if let Some(parent) = path.parent() {
            self.fs
                .sync_dir(parent)
                .map_err(|e| self.error("delete", key, e))?;
        }
        Ok(())
    }
}

struct LocalObject {
    file: Box<dyn File>,
    size: u64,
    key: String,
    destination: String,
}

impl ObjectReader for LocalObject {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        self.file
            .read_exact_at(buf, offset)
            .map_err(|source| BackupError::Destination {
                destination: self.destination.clone(),
                op: "read",
                key: self.key.clone(),
                source,
            })
    }
}

#[cfg(test)]
mod tests {
    use rustegon_sim::SimFileSystem;

    use super::*;

    fn dest() -> (SimFileSystem, LocalDestination) {
        let fs = SimFileSystem::new();
        let d = LocalDestination::open(Arc::new(fs.clone()), "/dest").unwrap();
        (fs, d)
    }

    #[test]
    fn local_put_get_list_delete() {
        let (_fs, d) = dest();
        d.put_bytes("a/b/c.bin", b"hello").unwrap();
        d.put_bytes("a/top", b"x").unwrap();
        assert_eq!(d.get_bytes("a/b/c.bin", 100).unwrap(), b"hello");
        assert_eq!(d.size("a/b/c.bin").unwrap(), Some(5));
        assert_eq!(d.size("a/none").unwrap(), None);
        assert!(d.exists("a/top").unwrap());
        assert_eq!(d.list("").unwrap(), ["a/b/c.bin", "a/top"]);
        assert_eq!(d.list("a/b").unwrap(), ["a/b/c.bin"]);
        assert_eq!(d.list_children("a").unwrap(), ["b", "top"]);
        assert_eq!(d.list("zzz").unwrap(), Vec::<String>::new());
        assert!(d.get_bytes("a/b/c.bin", 4).is_err());
        let reader = d.open("a/b/c.bin").unwrap();
        let mut two = [0u8; 2];
        reader.read_exact_at(&mut two, 3).unwrap();
        assert_eq!(&two, b"lo");
        d.delete("a/top").unwrap();
        d.delete("a/top").unwrap();
        assert_eq!(d.list("").unwrap(), ["a/b/c.bin"]);
        assert!(matches!(
            d.open("a/top"),
            Err(BackupError::ObjectNotFound { .. })
        ));
    }

    #[test]
    fn local_put_with_wrong_size_stores_nothing() {
        let (_fs, d) = dest();
        let mut short: &[u8] = b"abc";
        assert!(d.put_reader("k", 4, &mut short).is_err());
        let mut long: &[u8] = b"abcde";
        assert!(d.put_reader("k", 4, &mut long).is_err());
        assert!(!d.exists("k").unwrap());
        assert_eq!(d.list("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn local_rejects_unsafe_keys() {
        let (_fs, d) = dest();
        for key in ["../x", "/x", "a//b", "a~partial"] {
            assert!(matches!(
                d.put_bytes(key, b"x"),
                Err(BackupError::InvalidArgument(_))
            ));
        }
    }

    #[test]
    fn local_temp_files_are_not_listed() {
        let (fs, d) = dest();
        fs.open(Path::new("/dest/k~partial"), OpenMode::CreateNew)
            .unwrap();
        assert_eq!(d.list("").unwrap(), Vec::<String>::new());
        d.put_bytes("k", b"v").unwrap();
        assert_eq!(d.list("").unwrap(), ["k"]);
    }
}
