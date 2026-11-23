// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Compressed single-file backups (PD-227, ADR-037): `.nbck` (a whole node) and `.dbck` (one or
//! more databases, a logical dump).
//!
//! # Format (nbck v1, dbck v1)
//! The container is the `.bak` one ([`crate::bak`]): a POSIX ustar archive, marker first, then
//! the objects of the backup in path order, the completion object last. What differs:
//! - every entry after the marker holds its object **compressed as one zstd frame** (level
//!   [`ZSTD_LEVEL`], content checksum on), so a reader can verify and restore one object at a
//!   time without unpacking the archive first, also from S3 with ranged reads;
//! - the marker records `"compression": "zstd"` and `entries`, the uncompressed size of every
//!   entry by name (the tar header holds the compressed size);
//! - `.nbck` holds `backups/<id>/…` (the v1 backup layout, `COMPLETE` last); `.dbck` holds
//!   `dumps/<id>/…` (the PD-067 dump layout, `dump.json` last).
//!
//! ```text
//! rustegon-bak.json → {"format":"rustegon-nbck","format_version":1,"backup_id":…,
//!                      "compression":"zstd","entries":{"backups/<id>/lsm/…":123,…}}
//! ```
//! The marker entry keeps the `.bak` name `rustegon-bak.json` in every form, so one reader
//! recognises all three.
//!
//! # Writing
//! [`ArchiveBuilder`] compresses each object as it arrives into a spool file on the local file
//! system (one per entry, created owner-only: they hold data), so the compressed sizes the tar
//! headers need are known before the archive is streamed to the destination in one atomic put.
//! The spool holds the compressed backup at most and is removed afterwards.

use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use rustegon_sim_api::{File, FileSystem, OpenMode};

use crate::{
    BACKUPS_DIR,
    bak::{BAK_MARKER, Part, Source, put_tar},
    dest::{Destination, FileReader, ObjectReader, join_key},
    error::{BackupError, Result},
    id::BackupId,
};

/// Directory of the dump objects inside a `.dbck`.
pub const DUMPS_DIR: &str = "dumps";
/// zstd level of `.nbck` and `.dbck` entries: the highest of the regular levels (the owner asked
/// for a high compression level; levels 20–22 need far more memory for little gain).
pub const ZSTD_LEVEL: i32 = 19;
/// zstd worker threads. Fixed, not the machine's core count, so an archive is byte-for-byte the
/// same on every host (zstd's output depends on the worker setting).
const ZSTD_WORKERS: u32 = 4;
/// Format version of `.nbck` and `.dbck` this build writes and reads.
pub const ARCHIVE_FORMAT_VERSION: u32 = 1;
/// Bytes moved per read while compressing a local file.
const COPY_BYTES: usize = 1 << 20;

/// The forms of a single-file backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// `.bak` v1 (ADR-037): uncompressed whole-node backup; read only, kept for old files.
    Bak,
    /// `.nbck`: compressed whole-node backup.
    Node,
    /// `.dbck`: compressed logical dump of databases.
    Database,
}

impl ArchiveKind {
    /// The marker's `format`.
    #[must_use]
    pub fn format(self) -> &'static str {
        match self {
            Self::Bak => "rustegon-bak",
            Self::Node => "rustegon-nbck",
            Self::Database => "rustegon-dbck",
        }
    }

    /// File extension (without the dot).
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Bak => "bak",
            Self::Node => "nbck",
            Self::Database => "dbck",
        }
    }

    /// The directory every entry after the marker lives in (`<dir>/<id>/…`).
    #[must_use]
    pub fn dir(self) -> &'static str {
        match self {
            Self::Bak | Self::Node => BACKUPS_DIR,
            Self::Database => DUMPS_DIR,
        }
    }

    /// Whether entries are zstd frames.
    #[must_use]
    pub fn compressed(self) -> bool {
        self != Self::Bak
    }

    /// The kind whose marker `format` is `format`.
    #[must_use]
    pub fn from_format(format: &str) -> Option<Self> {
        [Self::Bak, Self::Node, Self::Database]
            .into_iter()
            .find(|k| k.format() == format)
    }

    /// `<id>.<extension>`, the key of backup `id` at a destination root.
    #[must_use]
    pub fn key(self, id: &BackupId) -> String {
        format!("{id}.{}", self.extension())
    }

    /// The backup id of a root key named `<id>.<extension>`, if it is one.
    #[must_use]
    pub fn id_of(self, key: &str) -> Option<BackupId> {
        let stem = key.strip_suffix(self.extension())?.strip_suffix('.')?;
        if stem.contains('/') {
            return None;
        }
        BackupId::parse(stem).ok()
    }

    /// `<dir>/<id>`, the prefix of the entries of backup `id`.
    #[must_use]
    pub fn prefix(self, id: &BackupId) -> String {
        join_key(&[self.dir(), id.as_str()])
    }
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

/// [`io::Write`] appending to a spool file and hashing what it writes.
struct SpoolWriter {
    file: Box<dyn File>,
    path: PathBuf,
    hasher: blake3::Hasher,
    bytes: u64,
}

impl Write for SpoolWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.append(buf)?;
        self.hasher.update(buf);
        self.bytes += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The entry being written.
struct OpenEntry {
    name: String,
    encoder: zstd::stream::write::Encoder<'static, SpoolWriter>,
    size: u64,
}

/// One finished entry: name, uncompressed size, compressed spool file and its BLAKE3.
struct Finished {
    name: String,
    size: u64,
    spool: PathBuf,
    compressed: u64,
    blake3: String,
}

/// Builds one `.nbck` or `.dbck` (module docs, "Writing").
pub struct ArchiveBuilder<'a> {
    fs: &'a dyn FileSystem,
    spool_dir: PathBuf,
    kind: ArchiveKind,
    id: BackupId,
    prefix: String,
    entries: Vec<Finished>,
    open: Option<OpenEntry>,
}

impl std::fmt::Debug for ArchiveBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveBuilder")
            .field("kind", &self.kind)
            .field("id", &self.id)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

fn spool_err(op: &'static str, path: &Path, e: io::Error) -> BackupError {
    BackupError::local(op, path, e)
}

impl<'a> ArchiveBuilder<'a> {
    /// A builder of backup `id` of `kind` spooling in the directory `spool_dir` of `fs`
    /// (created; removed again when the builder is stored or dropped).
    ///
    /// # Errors
    /// [`BackupError::InvalidArgument`] for [`ArchiveKind::Bak`] (no longer written);
    /// [`BackupError::Local`] when the spool directory cannot be created.
    pub fn new(
        fs: &'a dyn FileSystem,
        spool_dir: &Path,
        kind: ArchiveKind,
        id: BackupId,
    ) -> Result<Self> {
        if !kind.compressed() {
            return Err(BackupError::InvalidArgument(
                "the .bak form is no longer written".into(),
            ));
        }
        fs.create_dir_all(spool_dir)
            .map_err(|e| spool_err("create", spool_dir, e))?;
        Ok(Self {
            fs,
            spool_dir: spool_dir.to_path_buf(),
            kind,
            prefix: kind.prefix(&id),
            id,
            entries: Vec::new(),
            open: None,
        })
    }

    /// Starts the entry `<dir>/<id>/<rel>`; entries must come in archive order.
    ///
    /// # Errors
    /// [`BackupError::Internal`] while another entry is open; [`BackupError::InvalidArgument`]
    /// for an invalid name; [`BackupError::Local`] for spool errors.
    pub fn start(&mut self, rel: &str) -> Result<()> {
        if self.open.is_some() {
            return Err(BackupError::Internal(
                "archive entry started while another is open".into(),
            ));
        }
        let name = join_key(&[&self.prefix, rel]);
        crate::dest::validate_key(&name)?;
        let spool = self.spool_dir.join(format!("{}.zst", self.entries.len()));
        let file = self
            .fs
            .create_new_private(&spool)
            .map_err(|e| spool_err("create", &spool, e))?;
        let writer = SpoolWriter {
            file,
            path: spool.clone(),
            hasher: blake3::Hasher::new(),
            bytes: 0,
        };
        let mut encoder = zstd::stream::write::Encoder::new(writer, ZSTD_LEVEL)
            .map_err(|e| spool_err("compress", &spool, e))?;
        // Each frame carries its own checksum; worker threads speed up level 19 on big files.
        encoder
            .include_checksum(true)
            .and_then(|()| encoder.multithread(ZSTD_WORKERS))
            .map_err(|e| spool_err("compress", &spool, e))?;
        self.open = Some(OpenEntry {
            name,
            encoder,
            size: 0,
        });
        Ok(())
    }

    /// Appends `data` to the open entry.
    ///
    /// # Errors
    /// [`BackupError::Internal`] without an open entry; [`BackupError::Local`].
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let open = self
            .open
            .as_mut()
            .ok_or_else(|| BackupError::Internal("no open archive entry".into()))?;
        open.encoder
            .write_all(data)
            .map_err(|e| spool_err("write", &self.spool_dir, e))?;
        open.size += data.len() as u64;
        Ok(())
    }

    /// Closes the open entry.
    ///
    /// # Errors
    /// [`BackupError::Internal`] without an open entry; [`BackupError::Local`].
    pub fn finish_entry(&mut self) -> Result<()> {
        let open = self
            .open
            .take()
            .ok_or_else(|| BackupError::Internal("no open archive entry".into()))?;
        let writer = open
            .encoder
            .finish()
            .map_err(|e| spool_err("compress", &self.spool_dir, e))?;
        self.entries.push(Finished {
            name: open.name,
            size: open.size,
            spool: writer.path,
            compressed: writer.bytes,
            blake3: writer.hasher.finalize().to_hex().to_string(),
        });
        Ok(())
    }

    /// Adds the entry `rel` holding `bytes`.
    ///
    /// # Errors
    /// As [`Self::start`].
    pub fn add_bytes(&mut self, rel: &str, bytes: &[u8]) -> Result<()> {
        self.start(rel)?;
        self.write(bytes)?;
        self.finish_entry()
    }

    /// Adds the entry `rel` holding the local file `path`; returns its size and BLAKE3 (hex) as
    /// read, for a manifest.
    ///
    /// # Errors
    /// As [`Self::start`]; [`BackupError::Local`] when `path` cannot be read.
    pub fn add_file(&mut self, rel: &str, path: &Path) -> Result<(u64, String)> {
        let file = self
            .fs
            .open(path, OpenMode::Read)
            .map_err(|e| BackupError::local("open", path, e))?;
        let size = file
            .size()
            .map_err(|e| BackupError::local("stat", path, e))?;
        let mut reader = FileReader::new(file.as_ref(), size);
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; COPY_BYTES];
        self.start(rel)?;
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| BackupError::local("read", path, e))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            self.write(&buf[..n])?;
        }
        self.finish_entry()?;
        Ok((size, hasher.finalize().to_hex().to_string()))
    }

    /// Writes the archive as `<id>.<extension>` at `dest` (one atomic put) and returns its size.
    ///
    /// # Errors
    /// [`BackupError::BackupExists`] when that key exists; [`BackupError::Internal`] with an
    /// entry still open; [`BackupError::Local`], [`BackupError::Destination`].
    pub fn store(mut self, dest: &dyn Destination, mtime: u64) -> Result<u64> {
        if self.open.is_some() {
            return Err(BackupError::Internal("archive entry left open".into()));
        }
        let key = self.kind.key(&self.id);
        if dest.exists(&key)? {
            return Err(BackupError::BackupExists {
                id: self.id.to_string(),
                destination: dest.describe(),
            });
        }
        let marker = serde_json::to_vec(&crate::bak::Marker {
            format: self.kind.format().to_owned(),
            format_version: u64::from(ARCHIVE_FORMAT_VERSION),
            backup_id: self.id.to_string(),
            compression: Some("zstd".to_owned()),
            entries: Some(
                self.entries
                    .iter()
                    .map(|e| (e.name.clone(), e.size))
                    .collect::<BTreeMap<_, _>>(),
            ),
        })
        .map_err(|e| BackupError::Internal(format!("archive marker: {e}")))?;
        let mut parts = Vec::with_capacity(self.entries.len() + 1);
        parts.push(Part::bytes(BAK_MARKER.to_owned(), marker));
        for e in &self.entries {
            parts.push(Part {
                name: e.name.clone(),
                size: e.compressed,
                source: Source::File {
                    path: e.spool.clone(),
                    blake3: e.blake3.clone(),
                },
            });
        }
        let total = put_tar(dest, &key, self.fs, &parts, mtime)?;
        self.cleanup();
        Ok(total)
    }

    fn cleanup(&mut self) {
        self.open = None;
        for e in self.entries.drain(..) {
            let _ = self.fs.remove_file(&e.spool);
        }
        // The spool of an entry left open, then the directory once empty.
        if let Ok(rest) = self.fs.read_dir(&self.spool_dir) {
            for p in rest {
                let _ = self.fs.remove_file(&p);
            }
        }
        let _ = self.fs.remove_dir(&self.spool_dir);
    }
}

impl Drop for ArchiveBuilder<'_> {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

/// [`io::Read`] over the byte range `[base, base + len)` of a shared object.
struct RawRange {
    reader: Arc<Mutex<Box<dyn ObjectReader>>>,
    base: u64,
    len: u64,
    pos: u64,
}

impl Read for RawRange {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.len - self.pos;
        let n = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        if n == 0 {
            return Ok(0);
        }
        let reader = self
            .reader
            .lock()
            .map_err(|_| io::Error::other("archive reader lock poisoned"))?;
        reader
            .read_exact_at(&mut buf[..n], self.base + self.pos)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

type Decoder = zstd::stream::read::Decoder<'static, io::BufReader<RawRange>>;

/// One compressed entry read as its uncompressed object. Reads are expected front to back
/// (verification, restore); a read before the current position restarts the frame.
pub(crate) struct ZstdEntryReader {
    reader: Arc<Mutex<Box<dyn ObjectReader>>>,
    base: u64,
    compressed: u64,
    size: u64,
    location: String,
    state: Mutex<Option<(Decoder, u64)>>,
}

impl ZstdEntryReader {
    pub(crate) fn new(
        reader: Arc<Mutex<Box<dyn ObjectReader>>>,
        base: u64,
        compressed: u64,
        size: u64,
        location: String,
    ) -> Self {
        Self {
            reader,
            base,
            compressed,
            size,
            location,
            state: Mutex::new(None),
        }
    }

    fn corrupt(&self, e: &io::Error) -> BackupError {
        BackupError::corrupt(&self.location, "", format!("compressed entry: {e}"))
    }
}

impl ObjectReader for ZstdEntryReader {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.size {
            return Err(BackupError::Destination {
                destination: self.location.clone(),
                op: "read",
                key: String::new(),
                source: io::Error::new(io::ErrorKind::UnexpectedEof, "read past the entry"),
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| BackupError::Internal("archive entry lock poisoned".into()))?;
        if state.as_ref().is_none_or(|(_, pos)| *pos > offset) {
            let raw = RawRange {
                reader: Arc::clone(&self.reader),
                base: self.base,
                len: self.compressed,
                pos: 0,
            };
            let decoder = Decoder::new(raw).map_err(|e| self.corrupt(&e))?;
            *state = Some((decoder, 0));
        }
        let Some((decoder, pos)) = state.as_mut() else {
            return Err(BackupError::Internal("no decoder".into()));
        };
        // Skip forward to `offset`, then read.
        let skip = offset - *pos;
        let skipped = io::copy(&mut decoder.by_ref().take(skip), &mut io::sink())
            .map_err(|e| self.corrupt(&e))?;
        if skipped != skip {
            return Err(self.corrupt(&io::Error::from(io::ErrorKind::UnexpectedEof)));
        }
        decoder.read_exact(buf).map_err(|e| self.corrupt(&e))?;
        *pos = offset + buf.len() as u64;
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Whole-node backups
// ---------------------------------------------------------------------------------------------

/// Writes the staged directory `staged_dir` of `fs` as the single file `<id>.nbck` at `dest` and
/// returns its manifest; the staged directory is the one [`crate::writer::write_backup`] takes.
/// The compressed entries are spooled in `<staged_dir>.nbck-spool` next to it.
///
/// # Errors
/// [`BackupError::BackupExists`] when a backup with this id exists in any form;
/// [`BackupError::InvalidArgument`] for staged names outside the key alphabet or a key registry
/// that does not match the encryption; [`BackupError::Local`]; [`BackupError::Destination`].
pub fn write_nbck(
    dest: &dyn Destination,
    fs: &dyn FileSystem,
    staged_dir: &Path,
    backup: &crate::writer::NewBackup,
) -> Result<crate::manifest::Manifest> {
    use crate::{
        COMPLETE_FILE, MANIFEST_FILE,
        manifest::{Encryption, FileEntry, MANIFEST_FORMAT_VERSION, Manifest},
        writer::{backup_prefix, check_key_registry, complete_marker, staged_files},
    };
    let files = staged_files(fs, staged_dir)?;
    check_key_registry(&files, &backup.metadata.encryption)?;
    let id = &backup.id;
    if dest.exists(&ArchiveKind::Node.key(id))?
        || dest.exists(&ArchiveKind::Bak.key(id))?
        || !dest.list(&backup_prefix(id))?.is_empty()
    {
        return Err(BackupError::BackupExists {
            id: id.to_string(),
            destination: dest.describe(),
        });
    }
    let mut spool = staged_dir.as_os_str().to_owned();
    spool.push(".nbck-spool");
    let mut builder = ArchiveBuilder::new(fs, Path::new(&spool), ArchiveKind::Node, id.clone())?;
    // One pass: each staged file is hashed for the manifest while it is compressed.
    let mut entries = Vec::with_capacity(files.len());
    for (rel, path) in &files {
        let (size, blake3) = builder.add_file(rel, path)?;
        entries.push(FileEntry {
            path: rel.clone(),
            size,
            blake3,
        });
    }
    let manifest = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        backup_id: id.to_string(),
        created_at: crate::id::UtcTime::from_system_time(backup.created_at)?.rfc3339(),
        consistency: backup.metadata.consistency,
        source: backup.metadata.source.clone(),
        encryption: backup.metadata.encryption.clone(),
        files: entries,
        pitr: backup.metadata.pitr.clone(),
    };
    let manifest_json = manifest.to_json()?;
    builder.add_bytes(MANIFEST_FILE, &manifest_json)?;
    builder.add_bytes(COMPLETE_FILE, complete_marker(&manifest_json).as_bytes())?;
    let mtime = backup
        .created_at
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let total = builder.store(dest, mtime)?;
    if manifest.encryption == Encryption::Plaintext {
        tracing::warn!(backup_id = %id, "backup of an unencrypted store is stored in plaintext");
    }
    tracing::info!(
        backup_id = %id,
        file = %ArchiveKind::Node.key(id),
        files = manifest.files.len(),
        bytes = total,
        "backup complete"
    );
    Ok(manifest)
}
