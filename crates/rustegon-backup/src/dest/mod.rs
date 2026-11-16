// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Backup destinations: where backup files are stored (local/NFS directory, S3-compatible object
//! stores).
//!
//! # Model
//! A destination is a flat key → object store, as S3 is: keys are `/`-separated relative paths
//! ([`validate_key`]), objects are immutable once written and appear atomically (a reader never
//! sees a partial object). A directory-backed destination emulates that with temp file + fsync +
//! rename + directory fsync ([`local::LocalDestination`]).
//!
//! # Why synchronous
//! The trait is blocking, like [`rustegon_sim_api::FileSystem`]: backups and restores move whole
//! files and run on the I/O / blocking pool, never on an async executor thread
//! (coding-standards.md §3.3). An async object-store client implements it by blocking on its
//! runtime from that pool thread; streaming puts carry the size up front so such a client can
//! pick a single PUT or a multipart upload with fixed part sizes before reading the body.

pub mod local;
pub mod s3;

use std::{io, path::Path};

use rustegon_sim_api::{FileSystem, OpenMode};

use crate::error::{BackupError, Result};

/// Longest accepted key (bytes); S3 allows 1024.
const MAX_KEY_LEN: usize = 1024;

/// A ranged reader over one object.
pub trait ObjectReader: Send {
    /// Object size in bytes.
    fn size(&self) -> u64;

    /// Reads exactly `buf.len()` bytes at `offset` (an S3 ranged GET).
    ///
    /// # Errors
    /// [`BackupError::Destination`] on I/O errors, including reads past the end.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()>;
}

/// A backup destination (module docs). Implementations must be safe to share between threads.
pub trait Destination: Send + Sync {
    /// Human-readable location for messages (`file:///…`, `s3://bucket/prefix`); never contains
    /// credentials.
    fn describe(&self) -> String;

    /// Stores exactly `size` bytes read from `reader` under `key`, replacing an existing object.
    /// The object becomes visible only when complete and durable.
    ///
    /// # Errors
    /// [`BackupError::Destination`] on destination errors, or when `reader` yields fewer or more
    /// than `size` bytes (nothing is stored then); [`BackupError::InvalidArgument`] for an
    /// invalid key.
    fn put_reader(&self, key: &str, size: u64, reader: &mut dyn io::Read) -> Result<()>;

    /// Stores `bytes` under `key` atomically (small objects: manifest, markers).
    ///
    /// # Errors
    /// As [`Destination::put_reader`].
    fn put_bytes(&self, key: &str, bytes: &[u8]) -> Result<()> {
        let mut reader = bytes;
        self.put_reader(key, bytes.len() as u64, &mut reader)
    }

    /// Stores the local file `path` of `fs` under `key`.
    ///
    /// # Errors
    /// [`BackupError::Local`] when the file cannot be read; otherwise as
    /// [`Destination::put_reader`].
    fn put_file(&self, key: &str, fs: &dyn FileSystem, path: &Path) -> Result<()> {
        let file = fs
            .open(path, OpenMode::Read)
            .map_err(|e| BackupError::local("open", path, e))?;
        let size = file
            .size()
            .map_err(|e| BackupError::local("stat", path, e))?;
        let mut reader = FileReader::new(file.as_ref(), size);
        self.put_reader(key, size, &mut reader)
    }

    /// Opens `key` for ranged reads.
    ///
    /// # Errors
    /// [`BackupError::ObjectNotFound`] when the object does not exist;
    /// [`BackupError::Destination`] on other errors.
    fn open(&self, key: &str) -> Result<Box<dyn ObjectReader>>;

    /// Size of `key`, or `None` when it does not exist (an S3 HEAD).
    ///
    /// # Errors
    /// [`BackupError::Destination`] on destination errors.
    fn size(&self, key: &str) -> Result<Option<u64>>;

    /// Whether `key` exists.
    ///
    /// # Errors
    /// As [`Destination::size`].
    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.size(key)?.is_some())
    }

    /// Reads the whole object `key`, refusing objects larger than `limit` bytes.
    ///
    /// # Errors
    /// [`BackupError::ObjectNotFound`]; [`BackupError::InvalidArgument`] when the object is
    /// larger than `limit`; [`BackupError::Destination`].
    fn get_bytes(&self, key: &str, limit: u64) -> Result<Vec<u8>> {
        let reader = self.open(key)?;
        let size = reader.size();
        if size > limit {
            return Err(BackupError::InvalidArgument(format!(
                "object {key} has {size} bytes, more than the limit of {limit}"
            )));
        }
        let len = usize::try_from(size)
            .map_err(|_| BackupError::InvalidArgument(format!("object {key} too large")))?;
        let mut buf = vec![0u8; len];
        reader.read_exact_at(&mut buf, 0)?;
        Ok(buf)
    }

    /// Every key below `prefix` (a key or empty for the root), recursively, sorted. Objects
    /// still being written are not listed.
    ///
    /// # Errors
    /// [`BackupError::Destination`].
    fn list(&self, prefix: &str) -> Result<Vec<String>>;

    /// The names directly below `prefix` (objects and "directories", i.e. common prefixes of
    /// deeper keys, as an S3 listing with delimiter `/`), sorted, without the prefix.
    ///
    /// # Errors
    /// [`BackupError::Destination`].
    fn list_children(&self, prefix: &str) -> Result<Vec<String>>;

    /// Deletes `key`; deleting a missing object succeeds (as on S3).
    ///
    /// # Errors
    /// [`BackupError::Destination`].
    fn delete(&self, key: &str) -> Result<()>;
}

/// Checks that `key` is a safe relative key: 1–1024 bytes, `/`-separated non-empty segments of
/// `[A-Za-z0-9._-]`, no `.` or `..` segment. The narrow alphabet keeps keys valid and identical
/// on every destination (S3 keys, NTFS and POSIX names) and makes path traversal impossible when
/// a key from an untrusted manifest is joined onto a local directory; `~` stays free for the
/// local destination's temp names.
///
/// # Errors
/// [`BackupError::InvalidArgument`] when the key is not valid.
pub fn validate_key(key: &str) -> Result<()> {
    let invalid = |why: &str| Err(BackupError::InvalidArgument(format!("key {key:?}: {why}")));
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return invalid("empty or too long");
    }
    for segment in key.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return invalid("empty, `.` or `..` segment");
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return invalid("characters outside [A-Za-z0-9._-]");
        }
    }
    Ok(())
}

/// Joins key segments with `/`.
pub(crate) fn join_key(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("/")
}

/// Read size of streamed transfers: large enough to amortise per-call overhead (and to be a
/// sensible multipart part granularity), small enough to stay off the large-allocation path.
pub(crate) const CHUNK_BYTES: usize = 1 << 20;

/// [`io::Read`] over a sim-api [`rustegon_sim_api::File`] (positional reads; the trait has no
/// cursor).
pub(crate) struct FileReader<'a> {
    file: &'a dyn rustegon_sim_api::File,
    offset: u64,
    size: u64,
}

impl<'a> FileReader<'a> {
    pub(crate) fn new(file: &'a dyn rustegon_sim_api::File, size: u64) -> Self {
        Self {
            file,
            offset: 0,
            size,
        }
    }
}

impl io::Read for FileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.size - self.offset;
        let n = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        if n == 0 {
            return Ok(0);
        }
        self.file.read_exact_at(&mut buf[..n], self.offset)?;
        self.offset += n as u64;
        Ok(n)
    }
}

/// Reads object `reader` front to back in [`CHUNK_BYTES`] chunks, passing each chunk to `sink`,
/// and returns the BLAKE3 hash (hex) of the whole object.
pub(crate) fn hash_object(
    reader: &dyn ObjectReader,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<String> {
    let size = reader.size();
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; usize::try_from(size).map_or(CHUNK_BYTES, |s| s.min(CHUNK_BYTES))];
    let mut offset = 0;
    while offset < size {
        let n = usize::try_from(size - offset).map_or(buf.len(), |r| r.min(buf.len()));
        reader.read_exact_at(&mut buf[..n], offset)?;
        hasher.update(&buf[..n]);
        sink(&buf[..n])?;
        offset += n as u64;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_key_accepts_layout_keys_and_rejects_traversal() {
        for ok in [
            "backups/20261109T101500Z-3fa85f64/manifest.json",
            "lsm/000012.rsst",
            "lsm/MANIFEST-000003",
            "CURRENT",
        ] {
            validate_key(ok).unwrap();
        }
        for bad in [
            "",
            "/a",
            "a/",
            "a//b",
            "../a",
            "a/./b",
            "a\\b",
            "C:/a",
            "a~partial",
            "a b",
            "a/\u{e9}",
        ] {
            assert!(validate_key(bad).is_err(), "{bad:?}");
        }
        assert!(validate_key(&"a".repeat(1025)).is_err());
    }

    #[test]
    fn join_key_skips_empty_parts() {
        assert_eq!(join_key(&["", "backups", "id"]), "backups/id");
    }
}
