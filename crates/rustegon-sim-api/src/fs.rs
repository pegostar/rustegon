// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! File system access.
//!
//! The API is synchronous: storage I/O runs on a dedicated I/O thread pool, never on async
//! executor threads (coding-standards.md §3.3). Files are append-only for writers and read
//! positionally, which is all the LSM engine and log stores need and keeps the simulated file
//! system (crash = drop unsynced suffix) simple.

use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
};

/// How a file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Read only; the file must exist.
    Read,
    /// Create a new file for appending; fails if it already exists.
    CreateNew,
    /// Open for appending, creating the file if missing.
    Append,
    /// Create or truncate, then append (small files rewritten whole, e.g. temp files).
    Truncate,
}

/// An open file.
pub trait File: Send + Sync {
    /// Reads exactly `buf.len()` bytes at `offset`.
    ///
    /// # Errors
    /// I/O errors, including `UnexpectedEof` when the file is shorter.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;

    /// Appends `buf` at the end of the file. Not durable until [`File::sync_data`].
    ///
    /// # Errors
    /// I/O errors; the file may then contain a prefix of `buf`.
    fn append(&mut self, buf: &[u8]) -> io::Result<()>;

    /// Makes appended data durable (`fdatasync` / `FlushFileBuffers`).
    ///
    /// # Errors
    /// I/O errors. After a failed sync the durable state of the file is unknown; callers must
    /// treat the store as failed rather than retry.
    fn sync_data(&self) -> io::Result<()>;

    /// Current file size in bytes.
    ///
    /// # Errors
    /// I/O errors.
    fn size(&self) -> io::Result<u64>;
}

/// File system operations.
pub trait FileSystem: Send + Sync + 'static {
    /// Opens a file.
    ///
    /// # Errors
    /// I/O errors (not found, already exists for [`OpenMode::CreateNew`], permissions).
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Box<dyn File>>;

    /// Creates a new file for appending that only the owner may read or write, for secrets
    /// such as TLS private keys (security.md §7). Like [`OpenMode::CreateNew`], fails if the
    /// file exists.
    ///
    /// The default is plain [`OpenMode::CreateNew`]: simulated and wrapper file systems have no
    /// permission model. [`StdFileSystem`] creates the file with mode 0600 on Unix (atomically,
    /// at creation, so the secret is never readable by others in between); on Windows the file
    /// inherits the ACL of its directory, which deployments restrict to the service account
    /// (security.md §7; PD-046).
    ///
    /// # Errors
    /// I/O errors (already exists, permissions).
    fn create_new_private(&self, path: &Path) -> io::Result<Box<dyn File>> {
        self.open(path, OpenMode::CreateNew)
    }

    /// Creates a directory and its parents.
    ///
    /// # Errors
    /// I/O errors.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;

    /// Atomically renames `from` to `to`, replacing `to` if it exists, also while `to` is open
    /// by a reader of this file system (which keeps the old contents). Durable only after
    /// [`FileSystem::sync_dir`] on the parent directory.
    ///
    /// [`StdFileSystem`] also renames a directory to a name that does not exist yet (offline
    /// restores swap store directories, M13a); the simulated file system renames files only.
    ///
    /// # Errors
    /// I/O errors.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Removes a file. Handles that are still open keep reading the removed file; the name
    /// disappears at once (also on Windows, see TC-STO-008).
    ///
    /// # Errors
    /// I/O errors.
    fn remove_file(&self, path: &Path) -> io::Result<()>;

    /// Creates a hard link (checkpoints share immutable files).
    ///
    /// # Errors
    /// [`io::ErrorKind::Unsupported`] when the file system cannot link these paths (no hard-link
    /// support such as FAT/exFAT, cross-device link, per-file link limit reached); callers such as
    /// checkpoints fall back to copying. Other I/O errors (e.g. `AlreadyExists`, `NotFound`) as
    /// usual.
    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()>;

    /// Lists the entries of a directory (full paths, unordered).
    ///
    /// # Errors
    /// I/O errors.
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;

    /// Makes directory entries (creates, renames, removes) durable.
    ///
    /// # Errors
    /// I/O errors.
    fn sync_dir(&self, path: &Path) -> io::Result<()>;

    /// The Unix permission bits (`st_mode & 0o7777`) of `path`, or `None` where the file
    /// system has no such mode: Windows (access is governed by ACLs, which this trait does not
    /// inspect) and simulated or wrapper file systems. Secret readers such as the `file` KEK
    /// provider use it to refuse a key file readable by group or others (security.md §6).
    ///
    /// # Errors
    /// I/O errors (e.g. not found).
    fn permission_mode(&self, path: &Path) -> io::Result<Option<u32>> {
        let _ = path;
        Ok(None)
    }

    /// Takes an exclusive, non-blocking lock on the file `path` (created if missing, never
    /// truncated), held until the returned guard is dropped or the process dies. Used for the
    /// data directory `LOCK` file (PD-068): a second lock on the same path fails while the
    /// first is held, from this process or another one.
    ///
    /// The default returns [`io::ErrorKind::Unsupported`]: wrapper file systems of tests have
    /// no lock table, and callers decide what an unsupported lock means.
    /// [`StdFileSystem`] uses the OS advisory lock (`flock` on Unix, `LockFileEx` on Windows,
    /// through `std::fs::File::try_lock`); both are per open file, so two opens in one process
    /// exclude each other too.
    ///
    /// # Errors
    /// [`io::ErrorKind::WouldBlock`] when the lock is held; [`io::ErrorKind::Unsupported`] when
    /// the file system cannot lock; other I/O errors (e.g. the parent directory is missing).
    fn try_lock_exclusive(&self, path: &Path) -> io::Result<FileLock> {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this file system has no file locks",
        ))
    }

    /// Removes the empty directory `path` (staging directories of backups and snapshots,
    /// deleted snapshots; M13a, PD-082). Durable only after [`FileSystem::sync_dir`] on the
    /// parent.
    ///
    /// The default returns [`io::ErrorKind::Unsupported`], like
    /// [`FileSystem::try_lock_exclusive`]: wrapper file systems of tests that never remove
    /// directories need not implement it.
    ///
    /// # Errors
    /// Not found, not empty, not a directory, other I/O errors.
    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this file system cannot remove directories",
        ))
    }
}

/// An exclusive file lock taken by [`FileSystem::try_lock_exclusive`]; released on drop.
pub struct FileLock {
    /// What holds the lock (an open file, a simulated lock-table entry); dropping it unlocks.
    _holder: Box<dyn Send + Sync>,
}

impl FileLock {
    /// A lock held by `holder` until the lock is dropped (for [`FileSystem`] implementations).
    #[must_use]
    pub fn new(holder: impl Send + Sync + 'static) -> Self {
        Self {
            _holder: Box::new(holder),
        }
    }
}

impl std::fmt::Debug for FileLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileLock").finish_non_exhaustive()
    }
}

/// Production file system backed by `std::fs`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdFileSystem;

struct StdFile(std::fs::File);

impl File for StdFile {
    #[cfg(unix)]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(&self.0, buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        // `seek_read` moves the file cursor, which is harmless here: all writes use append mode,
        // so they always land at the end regardless of the cursor.
        while !buf.is_empty() {
            match std::os::windows::fs::FileExt::seek_read(&self.0, buf, offset) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.0.sync_data()
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.0.metadata()?.len())
    }
}

/// Independent handles per read-only file on Windows (`WinReadFile`). Measured reason: a handle
/// opened without `FILE_FLAG_OVERLAPPED` is a synchronous file object, and the I/O manager
/// serialises every request on one file object, so concurrent positional reads of one SST queue
/// behind each other (BM-STO-01 with 16 readers: about 2.4x the single-thread rate and p99 above
/// 600 µs, while the same build in a Linux container on the same host scales to 16 readers with
/// p99 under 75 µs; bench/results/2026-11-03-bm-sto-01-16t-*). Separate `CreateFileW` handles are
/// separate file objects and read in parallel. 8 bounds the extra handles per open SST (table
/// cache, iterators) while covering the reader concurrency of one node's hot files; std only,
/// no overlapped I/O (that needs unsafe Win32 calls, coding-standards.md §3.4).
#[cfg(windows)]
const WIN_READ_HANDLES: usize = 8;

/// A read-only file on Windows backed by [`WIN_READ_HANDLES`] handles; reads rotate over them.
/// All handles are opened up front: after a delete (allowed by `FILE_SHARE_DELETE`) the name is
/// gone and no further handle could be opened, while existing ones keep reading.
#[cfg(windows)]
struct WinReadFile {
    handles: Box<[std::fs::File]>,
    next: std::sync::atomic::AtomicUsize,
}

#[cfg(windows)]
impl WinReadFile {
    fn open(opts: &std::fs::OpenOptions, path: &Path) -> io::Result<Self> {
        let handles = (0..WIN_READ_HANDLES)
            .map(|_| opts.open(path))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            handles: handles.into_boxed_slice(),
            next: std::sync::atomic::AtomicUsize::new(0),
        })
    }
}

#[cfg(windows)]
impl File for WinReadFile {
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        // Relaxed: the counter only spreads reads over handles; any interleaving is correct
        // because every read carries its own offset.
        let i = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.handles.len();
        let file = &self.handles[i];
        while !buf.is_empty() {
            match std::os::windows::fs::FileExt::seek_read(file, buf, offset) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn append(&mut self, _buf: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file opened read-only",
        ))
    }

    fn sync_data(&self) -> io::Result<()> {
        // Same behaviour as a single read-only handle.
        self.handles[0].sync_data()
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.handles[0].metadata()?.len())
    }
}

impl FileSystem for StdFileSystem {
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Box<dyn File>> {
        let mut opts = std::fs::OpenOptions::new();
        // The engine deletes or replaces files that readers (table cache, iterators) still hold
        // open; on Windows that needs FILE_SHARE_DELETE on every handle (TC-STO-008). std's
        // default already includes it; set it explicitly so the requirement cannot regress.
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut opts, WIN_SHARE_ALL);
        match mode {
            OpenMode::Read => opts.read(true),
            OpenMode::CreateNew => opts.read(true).append(true).create_new(true),
            OpenMode::Append => opts.read(true).append(true).create(true),
            // `append` and `truncate` cannot be combined in OpenOptions; truncate first.
            OpenMode::Truncate => {
                let mut trunc = std::fs::OpenOptions::new();
                #[cfg(windows)]
                std::os::windows::fs::OpenOptionsExt::share_mode(&mut trunc, WIN_SHARE_ALL);
                trunc.write(true).create(true).truncate(true).open(path)?;
                opts.read(true).append(true)
            }
        };
        #[cfg(windows)]
        if mode == OpenMode::Read {
            return Ok(Box::new(WinReadFile::open(&opts, path)?));
        }
        Ok(Box::new(StdFile(opts.open(path)?)))
    }

    fn create_new_private(&self, path: &Path) -> io::Result<Box<dyn File>> {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).append(true).create_new(true);
        // 0600 is applied by open(2) itself (subject to umask, which can only remove bits).
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut opts, WIN_SHARE_ALL);
        Ok(Box::new(StdFile(opts.open(path)?)))
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        // std uses rename(2) on Unix. On Windows it uses SetFileInformationByHandle with
        // FileRenameInfoEx (FILE_RENAME_FLAG_REPLACE_IF_EXISTS | POSIX_SEMANTICS), falling back to
        // MoveFileExW(MOVEFILE_REPLACE_EXISTING): an atomic replace that succeeds even while the
        // target is open by a reader holding FILE_SHARE_DELETE (TC-STO-008). Durability of the
        // new name comes from `sync_dir`, not from MOVEFILE_WRITE_THROUGH (see `sync_dir`).
        std::fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        // On NTFS (Windows 10 1709+) DeleteFileW uses POSIX delete semantics: the name disappears
        // at once while open FILE_SHARE_DELETE handles keep reading, as on Unix (TC-STO-008).
        std::fs::remove_file(path)
    }

    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        std::fs::hard_link(original, link)
            .map_err(|e| normalize_hard_link_error(e, || links_supported_in(link)))
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        std::fs::read_dir(path)?
            .map(|e| e.map(|e| e.path()))
            .collect()
    }

    fn try_lock_exclusive(&self, path: &Path) -> io::Result<FileLock> {
        // Never truncated: the file carries no data, and truncating a file another process holds
        // locked would be a write under its lock. Opened for writing because LockFileEx needs a
        // handle with read or write access (std's `try_lock` on Windows) and `flock` any.
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut opts, WIN_SHARE_ALL);
        let file = opts.open(path)?;
        match file.try_lock() {
            // The lock lives as long as the handle: closing it (drop) unlocks, on both
            // platforms, and so does process death.
            Ok(()) => Ok(FileLock::new(file)),
            Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{} is locked by another process or handle", path.display()),
            )),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_dir(path)
    }

    #[cfg(unix)]
    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        std::fs::File::open(path)?.sync_all()
    }

    #[cfg(unix)]
    fn permission_mode(&self, path: &Path) -> io::Result<Option<u32>> {
        use std::os::unix::fs::PermissionsExt as _;
        // `metadata` follows symlinks: the mode that matters is the target's, which is what a
        // reader of the path gets.
        Ok(Some(std::fs::metadata(path)?.permissions().mode() & 0o7777))
    }

    #[cfg(windows)]
    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        // Decision (storage-engine.md §9, TC-STO-008): flush the directory handle, the Windows
        // counterpart of fsync on a directory fd. NTFS journals metadata changes (create, rename,
        // delete) but writes its log lazily, so without a flush a power loss can lose a rename
        // that already returned; a no-op is therefore not correct. CreateFileW opens a directory
        // only with FILE_FLAG_BACKUP_SEMANTICS, and FlushFileBuffers requires a handle with
        // GENERIC_WRITE (both per the Win32 API reference for CreateFileW / FlushFileBuffers);
        // on NTFS the flush of a directory handle writes its index and commits the log. std does
        // both without unsafe: `custom_flags` + `write(true)` open the handle and `sync_all`
        // calls FlushFileBuffers. Rejected: MOVEFILE_WRITE_THROUGH, which needs a raw Win32 call
        // (unsafe is not allowed in this crate, coding-standards.md §3.4) and covers only
        // renames, while §9 also needs new SST names durable before the MANIFEST names them.
        // Sync errors propagate; per §13 the caller treats them as fatal.
        // Evidence (PD-024; no power-loss test exists yet, so durability is documented, not
        // proven): (1) FlushFileBuffers "writes all the buffered information for a specified
        // file to the device" and needs GENERIC_WRITE
        // (learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers);
        // (2) the flush request it issues, NtFlushBuffersFileEx with flags 0, writes "file data
        // and metadata in the file cache ... and the underlying storage is synchronized to flush
        // its cache" on NTFS/ReFS/FAT/exFAT; only FLUSH_FLAGS_FILE_DATA_SYNC_ONLY is documented as
        // "not valid with volume or directory handles", so directory handles are valid targets
        // (learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntflushbuffersfileex);
        // (3) prior art: Lucene.Net `WindowsFsyncSupport` (and OpenJDK, which it follows) fsyncs
        // a directory the same way (GENERIC_WRITE + FILE_FLAG_BACKUP_SEMANTICS + FlushFileBuffers).
        // Unlike them we do not swallow ERROR_ACCESS_DENIED: a refused flush must not be reported
        // as durable.
        use std::os::windows::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .share_mode(WIN_SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?
            .sync_all()
    }
}

/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` (winnt.h): other handles may read,
/// write, delete and rename the file while it is open.
#[cfg(windows)]
const WIN_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;

/// `FILE_FLAG_BACKUP_SEMANTICS` (winbase.h): required by `CreateFileW` to open a directory handle.
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// Linux `EPERM` (errno.h).
#[cfg(target_os = "linux")]
const EPERM: i32 = 1;

/// Maps "this file system cannot hard-link these paths" failures to
/// [`io::ErrorKind::Unsupported`], keeping the OS error as the inner error.
///
/// Checkpoints (storage-engine.md §10) fall back to copying exactly on `Unsupported`, so they
/// need one kind instead of a per-platform list. Mapped: cross-device links (`EXDEV`,
/// `ERROR_NOT_SAME_DEVICE`), the per-file link limit (`EMLINK`, `ERROR_TOO_MANY_LINKS`: NTFS
/// allows 1024 names per file), file systems without hard links (Linux `EOPNOTSUPP`; Windows
/// `ERROR_INVALID_FUNCTION` from FAT/exFAT, `ERROR_NOT_SUPPORTED`). Other errors pass through.
///
/// Linux `EPERM` is ambiguous: link(2) returns it both when "the filesystem containing oldpath
/// and newpath does not support the creation of hard links" (vfat) and for genuine refusals
/// (`fs.protected_hardlinks` on a file the caller does not own, immutable or append-only files).
/// Only the first may become a copy, so `links_supported` is consulted: it reports whether the
/// target directory can hard-link at all (`links_supported_in`). If it can, the `EPERM` is a
/// real permission error and is returned unchanged (`PermissionDenied`).
fn normalize_hard_link_error(e: io::Error, links_supported: impl FnOnce() -> bool) -> io::Error {
    if e.kind() == io::ErrorKind::Unsupported {
        return e;
    }
    let by_kind = matches!(
        e.kind(),
        io::ErrorKind::CrossesDevices | io::ErrorKind::TooManyLinks
    );
    // Raw codes std does not map to a dedicated kind (errno.h / winerror.h).
    #[cfg(target_os = "linux")]
    let by_code = match e.raw_os_error() {
        Some(95) => true, // EOPNOTSUPP
        Some(EPERM) => !links_supported(),
        _ => false,
    };
    #[cfg(windows)]
    let by_code = {
        let _ = links_supported; // Windows reports "no hard links" with dedicated codes.
        matches!(e.raw_os_error(), Some(1 | 50)) // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED
    };
    #[cfg(not(any(target_os = "linux", windows)))]
    let by_code = {
        let _ = links_supported;
        false
    };
    if by_kind || by_code {
        io::Error::new(io::ErrorKind::Unsupported, e)
    } else {
        e
    }
}

/// Whether the directory of `link` supports hard links: creates a fresh file there (owned by
/// this process, so `protected_hardlinks` does not apply) and links it. Only an `EPERM` from
/// that link means "no hard links"; if the probe cannot even be set up the answer is "supported",
/// so the caller reports the original error instead of silently copying data. Runs only on the
/// error path of `hard_link`.
#[cfg(target_os = "linux")]
fn links_supported_in(link: &Path) -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    // Distinct probe names within the process; the pid separates processes.
    static PROBES: AtomicU64 = AtomicU64::new(0);
    let Some(dir) = link.parent() else {
        return true;
    };
    let n = PROBES.fetch_add(1, Ordering::Relaxed);
    let probe = dir.join(format!(".rustegon-link-probe-{}-{n}", std::process::id()));
    let probe_link = probe.with_extension("link");
    if std::fs::File::create_new(&probe).is_err() {
        return true;
    }
    let result = std::fs::hard_link(&probe, &probe_link);
    // Best effort: a leftover probe is an empty file with a recognisable name.
    let _ = std::fs::remove_file(&probe_link);
    let _ = std::fs::remove_file(&probe);
    !matches!(result, Err(e) if e.raw_os_error() == Some(EPERM))
}

#[cfg(not(target_os = "linux"))]
fn links_supported_in(_link: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn std_fs_append_sync_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFileSystem;
        let path = dir.path().join("a.log");
        let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
        f.append(b"hello ").unwrap();
        f.append(b"world").unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.size().unwrap(), 11);
        let mut buf = [0u8; 5];
        f.read_exact_at(&mut buf, 6).unwrap();
        assert_eq!(&buf, b"world");
        // Appends after a positional read still go to the end.
        f.append(b"!").unwrap();
        let r = fs.open(&path, OpenMode::Read).unwrap();
        let mut all = [0u8; 12];
        r.read_exact_at(&mut all, 0).unwrap();
        assert_eq!(&all, b"hello world!");
        let mut past_end = [0u8; 2];
        let err = r.read_exact_at(&mut past_end, 11).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// A file system without its own lock implementation: the trait default.
    struct NoLocks;
    impl FileSystem for NoLocks {
        fn open(&self, p: &Path, m: OpenMode) -> io::Result<Box<dyn File>> {
            StdFileSystem.open(p, m)
        }
        fn create_dir_all(&self, p: &Path) -> io::Result<()> {
            StdFileSystem.create_dir_all(p)
        }
        fn rename(&self, a: &Path, b: &Path) -> io::Result<()> {
            StdFileSystem.rename(a, b)
        }
        fn remove_file(&self, p: &Path) -> io::Result<()> {
            StdFileSystem.remove_file(p)
        }
        fn hard_link(&self, a: &Path, b: &Path) -> io::Result<()> {
            StdFileSystem.hard_link(a, b)
        }
        fn read_dir(&self, p: &Path) -> io::Result<Vec<PathBuf>> {
            StdFileSystem.read_dir(p)
        }
        fn sync_dir(&self, p: &Path) -> io::Result<()> {
            StdFileSystem.sync_dir(p)
        }
    }

    #[test]
    fn tc_bkp_014_std_lock_is_exclusive_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFileSystem;
        let path = dir.path().join("LOCK");
        let held = fs.try_lock_exclusive(&path).unwrap();
        // A second handle in the same process is refused (flock / LockFileEx are per handle).
        let err = fs.try_lock_exclusive(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        drop(held);
        let again = fs.try_lock_exclusive(&path).unwrap();
        drop(again);
        // The default of other file systems: unsupported.
        let err = NoLocks.try_lock_exclusive(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn std_fs_create_new_fails_if_exists_and_truncate_resets() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFileSystem;
        let path = dir.path().join("f");
        fs.open(&path, OpenMode::CreateNew)
            .unwrap()
            .append(b"abc")
            .unwrap();
        let err = fs.open(&path, OpenMode::CreateNew).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        let f = fs.open(&path, OpenMode::Truncate).unwrap();
        assert_eq!(f.size().unwrap(), 0);
        let mut a = fs.open(&path, OpenMode::Append).unwrap();
        a.append(b"xy").unwrap();
        assert_eq!(a.size().unwrap(), 2);
    }

    #[test]
    fn tc_tls_004_create_new_private_is_owner_only_and_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFileSystem;
        let path = dir.path().join("key.pem");
        fs.create_new_private(&path)
            .unwrap()
            .append(b"secret")
            .unwrap();
        let err = fs.create_new_private(&path).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
    }

    /// PD-057: `permission_mode` reports the Unix mode bits (none on Windows) and fails for a
    /// missing file.
    #[test]
    fn permission_mode_reports_unix_bits_only() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFileSystem;
        let path = dir.path().join("kek");
        fs.create_new_private(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs.permission_mode(&path).unwrap(), Some(0o600));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert_eq!(fs.permission_mode(&path).unwrap(), Some(0o640));
            assert!(fs.permission_mode(&dir.path().join("absent")).is_err());
        }
        #[cfg(not(unix))]
        assert_eq!(fs.permission_mode(&path).unwrap(), None);
    }

    #[test]
    fn std_fs_rename_replaces_and_dir_ops_work() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFileSystem;
        let sub = dir.path().join("a/b");
        fs.create_dir_all(&sub).unwrap();
        let (tmp, cur) = (sub.join("CURRENT.tmp"), sub.join("CURRENT"));
        fs.open(&cur, OpenMode::CreateNew)
            .unwrap()
            .append(b"old")
            .unwrap();
        fs.open(&tmp, OpenMode::CreateNew)
            .unwrap()
            .append(b"new!")
            .unwrap();
        fs.rename(&tmp, &cur).unwrap();
        fs.sync_dir(&sub).unwrap();
        assert_eq!(fs.open(&cur, OpenMode::Read).unwrap().size().unwrap(), 4);
        fs.hard_link(&cur, &sub.join("LINK")).unwrap();
        let mut names: Vec<_> = fs
            .read_dir(&sub)
            .unwrap()
            .into_iter()
            .filter_map(|p| p.file_name().map(ToOwned::to_owned))
            .collect();
        names.sort();
        assert_eq!(names, ["CURRENT", "LINK"]);
        fs.remove_file(&sub.join("LINK")).unwrap();
        assert_eq!(fs.read_dir(&sub).unwrap().len(), 1);
    }

    #[test]
    fn tc_sto_008_hard_link_errors_map_to_unsupported() {
        // "No hard links here": the probe of the target directory fails too.
        let unsupported = |e: io::Error| normalize_hard_link_error(e, || false).kind();
        for kind in [
            io::ErrorKind::CrossesDevices,
            io::ErrorKind::TooManyLinks,
            io::ErrorKind::Unsupported,
        ] {
            assert_eq!(unsupported(kind.into()), io::ErrorKind::Unsupported);
        }
        #[cfg(target_os = "linux")]
        let raw = [1, 18, 31, 95]; // EPERM, EXDEV, EMLINK, EOPNOTSUPP
        #[cfg(windows)]
        let raw = [1, 17, 50, 1142]; // INVALID_FUNCTION, NOT_SAME_DEVICE, NOT_SUPPORTED, TOO_MANY_LINKS
        #[cfg(any(target_os = "linux", windows))]
        for code in raw {
            let mapped = normalize_hard_link_error(io::Error::from_raw_os_error(code), || false);
            assert_eq!(mapped.kind(), io::ErrorKind::Unsupported, "code {code}");
            // The OS code survives for diagnostics: as the inner error when remapped, or on the
            // error itself when std already reports it as `Unsupported` (Linux EOPNOTSUPP).
            let inner = mapped.get_ref().and_then(|i| i.downcast_ref::<io::Error>());
            let os_code = mapped
                .raw_os_error()
                .or_else(|| inner.and_then(io::Error::raw_os_error));
            assert_eq!(os_code, Some(code));
        }
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::AlreadyExists,
            io::ErrorKind::StorageFull,
        ] {
            assert_eq!(unsupported(kind.into()), kind);
        }
    }

    /// Linux `EPERM` from link(2) becomes `Unsupported` (checkpoint copy) only when the
    /// directory cannot hard-link at all; on a file system with hard links it is a genuine
    /// permission refusal and surfaces as `PermissionDenied`, never as a silent data copy.
    #[cfg(target_os = "linux")]
    #[test]
    fn tc_sto_008_linux_eperm_is_unsupported_only_without_link_support() {
        let eperm = || io::Error::from_raw_os_error(EPERM);
        let refused = normalize_hard_link_error(eperm(), || true);
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(refused.raw_os_error(), Some(EPERM));
        let no_links = normalize_hard_link_error(eperm(), || false);
        assert_eq!(no_links.kind(), io::ErrorKind::Unsupported);
        // The probe consults the directory only for EPERM.
        let probed = std::cell::Cell::new(false);
        let exdev = normalize_hard_link_error(io::Error::from_raw_os_error(18), || {
            probed.set(true);
            false
        });
        assert_eq!(exdev.kind(), io::ErrorKind::Unsupported);
        assert!(!probed.get());
        // The real probe on a file system with hard links (the test temp dir) says "supported"
        // and leaves nothing behind.
        let dir = tempfile::tempdir().unwrap();
        assert!(links_supported_in(&dir.path().join("target.sst")));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
