// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Single-file backups: the `.bak` file (FR-BKP-001, ADR-037, PD-225).
//!
//! # Format (bak v1)
//! A `.bak` is a POSIX ustar archive that holds exactly the objects a directory backup of
//! format v1 has at a destination, in this order:
//! ```text
//! rustegon-bak.json                     marker, first: {"format":"rustegon-bak","format_version":1,"backup_id":…}
//! backups/<id>/lsm/…, keys/registry.enc the image files, sorted by path
//! backups/<id>/manifest.json            the manifest of format v1
//! backups/<id>/COMPLETE                 last, as in a directory backup
//! ```
//! It is named `<id>.bak` at the destination root, next to the `backups/` directory of
//! directory backups. Any `tar` tool can list or extract it; extracting it into a directory
//! gives a directory destination holding the backup.
//!
//! # Why a destination
//! [`BakDestination`] exposes one `.bak` as a read-only [`Destination`] whose objects are the
//! archive's entries, so manifest loading, verification and restore read a `.bak` with the same
//! code (and the same checks) as a directory backup: [`crate::verify::open_backup`] picks the
//! form. Only writing differs ([`write_bak`]).
//!
//! # Writing
//! The archive is one object, stored with a single [`Destination::put_reader`], which is atomic
//! (a reader never sees a partial `.bak`) and streams to S3 without a local copy. Its size must
//! be known up front, and the manifest (written inside the archive) needs every file's hash, so
//! the staged files are read twice: once to hash them, once while streaming. The staged files
//! are an immutable checkpoint; the second read is hashed again and a difference fails the
//! write instead of storing a backup that does not match its manifest.
//!
//! # Why ustar written here
//! The `tar` crate is reserved to the release tooling (PD-154). The subset needed is small: a
//! 512-byte header per regular file, octal fields (base-256 for sizes of 8 GiB and more, the
//! GNU extension every `tar` reads), the name split into ustar's prefix/name fields, and two
//! zero blocks at the end.

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use rustegon_sim_api::{FileSystem, OpenMode};
use serde::{Deserialize, Serialize};

use crate::{
    COMPLETE_FILE, MANIFEST_FILE,
    dest::{Destination, FileReader, ObjectReader, join_key, validate_key},
    error::{BackupError, Result},
    id::{BackupId, UtcTime},
    manifest::{Encryption, FileEntry, MANIFEST_FORMAT_VERSION, Manifest},
    writer::{NewBackup, backup_prefix, check_key_registry, complete_marker, staged_files},
};

/// File extension of a single-file backup.
pub const BAK_EXTENSION: &str = "bak";
/// The marker entry, first in every `.bak`.
pub const BAK_MARKER: &str = "rustegon-bak.json";
/// `format` of the marker.
pub const BAK_FORMAT: &str = "rustegon-bak";
/// Newest `.bak` format this build writes and reads.
pub const BAK_FORMAT_VERSION: u32 = 1;

/// Tar block size.
const BLOCK: u64 = 512;
/// [`BLOCK`] as a buffer length.
const BLOCK_LEN: usize = 512;
/// Largest accepted marker entry.
const MAX_MARKER_BYTES: u64 = 4096;
/// Most entries a `.bak` may hold (a store has a few thousand files at most); bounds the index
/// built from an untrusted file.
const MAX_ENTRIES: usize = 1_000_000;
/// Largest size an octal ustar size field holds (11 octal digits).
const MAX_OCTAL_SIZE: u64 = 0o777_7777_7777;

/// The key of backup `id` as a `.bak` at a destination root: `<id>.bak`.
#[must_use]
pub fn bak_key(id: &BackupId) -> String {
    format!("{id}.{BAK_EXTENSION}")
}

/// The backup id of a destination key named like a `.bak` (`<id>.bak` at the root), if it is
/// one.
#[must_use]
pub fn bak_id(key: &str) -> Option<BackupId> {
    let stem = key.strip_suffix(BAK_EXTENSION)?.strip_suffix('.')?;
    if stem.contains('/') {
        return None;
    }
    BackupId::parse(stem).ok()
}

/// The marker entry (module docs).
#[derive(Debug, Serialize, Deserialize)]
struct Marker {
    format: String,
    format_version: u64,
    backup_id: String,
}

/// Writes the staged directory `staged_dir` of `fs` as the single file `<id>.bak` at `dest` and
/// returns its manifest (module docs). The staged directory is the one
/// [`crate::writer::write_backup`] takes.
///
/// # Errors
/// [`BackupError::BackupExists`] when `<id>.bak` or a directory backup with this id exists;
/// [`BackupError::InvalidArgument`] for staged names outside the key alphabet, reserved names or
/// a key registry that does not match the encryption; [`BackupError::Local`] when a staged
/// file cannot be read or changed while it was written; [`BackupError::Destination`].
pub fn write_bak(
    dest: &dyn Destination,
    fs: &dyn FileSystem,
    staged_dir: &Path,
    backup: &NewBackup,
) -> Result<Manifest> {
    let files = staged_files(fs, staged_dir)?;
    check_key_registry(&files, &backup.metadata.encryption)?;
    let key = bak_key(&backup.id);
    let prefix = backup_prefix(&backup.id);
    if dest.exists(&key)? || !dest.list(&prefix)?.is_empty() {
        return Err(BackupError::BackupExists {
            id: backup.id.to_string(),
            destination: dest.describe(),
        });
    }

    // Pass 1: hash every staged file for the manifest.
    let mut entries = Vec::with_capacity(files.len());
    for (rel, path) in &files {
        let (size, blake3) = hash_file(fs, path)?;
        entries.push(FileEntry {
            path: rel.clone(),
            size,
            blake3,
        });
    }
    let manifest = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        backup_id: backup.id.to_string(),
        created_at: UtcTime::from_system_time(backup.created_at)?.rfc3339(),
        consistency: backup.metadata.consistency,
        source: backup.metadata.source.clone(),
        encryption: backup.metadata.encryption.clone(),
        files: entries,
        pitr: backup.metadata.pitr.clone(),
    };
    let manifest_json = manifest.to_json()?;
    let complete = complete_marker(&manifest_json).into_bytes();
    let marker = serde_json::to_vec(&Marker {
        format: BAK_FORMAT.to_owned(),
        format_version: u64::from(BAK_FORMAT_VERSION),
        backup_id: backup.id.to_string(),
    })
    .map_err(|e| BackupError::Internal(format!("bak marker: {e}")))?;

    // The archive's entries in order (module docs).
    let mut parts = Vec::with_capacity(files.len() + 3);
    parts.push(Part::bytes(BAK_MARKER.to_owned(), marker));
    for ((rel, path), entry) in files.iter().zip(&manifest.files) {
        parts.push(Part {
            name: join_key(&[&prefix, rel]),
            size: entry.size,
            source: Source::File {
                path: path.clone(),
                blake3: entry.blake3.clone(),
            },
        });
    }
    parts.push(Part::bytes(
        join_key(&[&prefix, MANIFEST_FILE]),
        manifest_json,
    ));
    parts.push(Part::bytes(join_key(&[&prefix, COMPLETE_FILE]), complete));
    // Every header is built before anything is written: a name ustar cannot hold fails here.
    let mtime = backup
        .created_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let headers = parts
        .iter()
        .map(|p| header(&p.name, p.size, mtime))
        .collect::<Result<Vec<_>>>()?;
    let total = parts.iter().map(|p| BLOCK + padded(p.size)).sum::<u64>() + 2 * BLOCK;

    let mut stream = TarStream {
        fs,
        parts: &parts,
        headers: &headers,
        index: 0,
        state: State::Header,
        pending: Vec::new(),
        pending_pos: 0,
        file: None,
        error: None,
    };
    if let Err(err) = dest.put_reader(&key, total, &mut stream) {
        // The put is atomic, so nothing is visible; the delete only tidies a destination that
        // kept a partial object anyway. A local read failure is reported as such.
        let _ = dest.delete(&key);
        return Err(stream.error.take().unwrap_or(err));
    }
    if manifest.encryption == Encryption::Plaintext {
        tracing::warn!(
            backup_id = %backup.id,
            "backup of an unencrypted store is stored in plaintext"
        );
    }
    tracing::info!(
        backup_id = %backup.id,
        file = %key,
        files = manifest.files.len(),
        bytes = total,
        "backup complete"
    );
    Ok(manifest)
}

/// Size and BLAKE3 (hex) of a local file.
fn hash_file(fs: &dyn FileSystem, path: &Path) -> Result<(u64, String)> {
    let file = fs
        .open(path, OpenMode::Read)
        .map_err(|e| BackupError::local("open", path, e))?;
    let size = file
        .size()
        .map_err(|e| BackupError::local("stat", path, e))?;
    let mut reader = FileReader::new(file.as_ref(), size);
    let mut hasher = blake3::Hasher::new();
    io::copy(&mut reader, &mut hasher).map_err(|e| BackupError::local("read", path, e))?;
    Ok((size, hasher.finalize().to_hex().to_string()))
}

/// Bytes `size` occupies in the archive after padding to whole blocks.
fn padded(size: u64) -> u64 {
    size.div_ceil(BLOCK) * BLOCK
}

/// One archive entry to write.
struct Part {
    name: String,
    size: u64,
    source: Source,
}

enum Source {
    Bytes(Vec<u8>),
    /// A staged file and the hash pass 1 recorded for it.
    File {
        path: PathBuf,
        blake3: String,
    },
}

impl Part {
    fn bytes(name: String, bytes: Vec<u8>) -> Self {
        Self {
            name,
            size: bytes.len() as u64,
            source: Source::Bytes(bytes),
        }
    }
}

enum State {
    Header,
    Data { offset: u64 },
    Padding,
    Trailer,
    Done,
}

/// [`io::Read`] that produces the archive front to back (module docs, "Writing").
struct TarStream<'a> {
    fs: &'a dyn FileSystem,
    parts: &'a [Part],
    headers: &'a [[u8; BLOCK_LEN]],
    index: usize,
    state: State,
    /// Header, padding or trailer bytes not yet handed out.
    pending: Vec<u8>,
    pending_pos: usize,
    /// The open staged file of the current part and its running hash.
    file: Option<(Box<dyn rustegon_sim_api::File>, blake3::Hasher)>,
    /// The local error that stopped the stream (the destination only sees an I/O error).
    error: Option<BackupError>,
}

impl TarStream<'_> {
    fn fail(&mut self, err: BackupError) -> io::Error {
        let msg = err.to_string();
        self.error = Some(err);
        io::Error::other(msg)
    }

    fn set_pending(&mut self, bytes: Vec<u8>) {
        self.pending = bytes;
        self.pending_pos = 0;
    }

    /// Opens the staged file of part `index`, if it has one.
    fn open_part(&mut self) -> io::Result<()> {
        if let Source::File { path, .. } = &self.parts[self.index].source {
            match self.fs.open(path, OpenMode::Read) {
                Ok(f) => self.file = Some((f, blake3::Hasher::new())),
                Err(e) => {
                    let err = BackupError::local("open", path, e);
                    return Err(self.fail(err));
                }
            }
        }
        Ok(())
    }

    /// Closes the current part: its second read must hash as the first one did.
    fn close_part(&mut self) -> io::Result<()> {
        if let (Source::File { path, blake3 }, Some((_, hasher))) =
            (&self.parts[self.index].source, self.file.take())
            && hasher.finalize().to_hex().as_str() != blake3
        {
            let err = BackupError::local(
                "read",
                path,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the staged file changed while the backup was written",
                ),
            );
            return Err(self.fail(err));
        }
        Ok(())
    }

    /// Copies the next data bytes of the current part into `buf`.
    fn read_data(&mut self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let part = &self.parts[self.index];
        let n = usize::try_from(part.size - offset).map_or(buf.len(), |r| r.min(buf.len()));
        match &part.source {
            Source::Bytes(bytes) => {
                let start = usize::try_from(offset)
                    .map_err(|_| self.fail(BackupError::Internal("offset overflow".into())))?;
                buf[..n].copy_from_slice(&bytes[start..start + n]);
            }
            Source::File { path, .. } => {
                let path = path.clone();
                let Some((file, hasher)) = self.file.as_mut() else {
                    return Err(self.fail(BackupError::Internal("no open staged file".into())));
                };
                if let Err(e) = file.read_exact_at(&mut buf[..n], offset) {
                    let err = BackupError::local("read", &path, e);
                    return Err(self.fail(err));
                }
                hasher.update(&buf[..n]);
            }
        }
        self.state = State::Data {
            offset: offset + n as u64,
        };
        Ok(n)
    }
}

impl io::Read for TarStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pending_pos < self.pending.len() {
                let n = buf.len().min(self.pending.len() - self.pending_pos);
                buf[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                return Ok(n);
            }
            match self.state {
                State::Done => return Ok(0),
                State::Trailer => {
                    self.set_pending(vec![0; 2 * BLOCK_LEN]);
                    self.state = State::Done;
                }
                State::Header => {
                    let Some(header) = self.headers.get(self.index) else {
                        self.state = State::Trailer;
                        continue;
                    };
                    let header = header.to_vec();
                    self.open_part()?;
                    self.set_pending(header);
                    self.state = State::Data { offset: 0 };
                }
                State::Data { offset } if offset == self.parts[self.index].size => {
                    self.close_part()?;
                    self.state = State::Padding;
                }
                State::Data { offset } => return self.read_data(buf, offset),
                State::Padding => {
                    let size = self.parts[self.index].size;
                    let pad = usize::try_from(padded(size) - size).unwrap_or(0);
                    self.set_pending(vec![0; pad]);
                    self.index += 1;
                    self.state = State::Header;
                }
            }
        }
    }
}

/// The ustar header of a regular file (module docs).
fn header(name: &str, size: u64, mtime: u64) -> Result<[u8; BLOCK_LEN]> {
    let mut h = [0u8; BLOCK_LEN];
    let (prefix, base) = split_name(name)?;
    h[..base.len()].copy_from_slice(base.as_bytes());
    octal(&mut h[100..108], 0o644);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    if size <= MAX_OCTAL_SIZE {
        octal(&mut h[124..136], size);
    } else {
        // GNU base-256: high bit set, big-endian value in the remaining bytes.
        h[124] = 0x80;
        h[128..136].copy_from_slice(&size.to_be_bytes());
    }
    octal(&mut h[136..148], mtime.min(MAX_OCTAL_SIZE));
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    // The checksum is computed with its own field as spaces.
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    octal(&mut h[148..155], u64::from(sum));
    h[155] = b' ';
    Ok(h)
}

/// Splits `name` into ustar's prefix (≤ 155 bytes) and name (≤ 100 bytes) at a `/`.
fn split_name(name: &str) -> Result<(&str, &str)> {
    if name.len() <= 100 {
        return Ok(("", name));
    }
    let too_long = || BackupError::InvalidArgument(format!("archive name {name:?} is too long"));
    // The name part must start after the cut: the first `/` at or after len - 101.
    let start = name.len() - 101;
    let cut = name[start..]
        .find('/')
        .map(|i| start + i)
        .ok_or_else(too_long)?;
    if cut > 155 || cut + 1 == name.len() {
        return Err(too_long());
    }
    Ok((&name[..cut], &name[cut + 1..]))
}

/// Writes `value` as zero-padded octal digits followed by a NUL into `field`.
fn octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    let text = &text.as_bytes()[text.len().saturating_sub(digits)..];
    field[..digits].copy_from_slice(text);
    field[digits] = 0;
}

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

/// A `.bak` opened as a read-only destination (module docs). Opening reads every header once;
/// entry data is read on demand.
pub struct BakDestination {
    reader: Arc<Mutex<Box<dyn ObjectReader>>>,
    location: String,
    id: BackupId,
    /// Entry name → (data offset, size).
    index: BTreeMap<String, (u64, u64)>,
}

impl std::fmt::Debug for BakDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BakDestination")
            .field("location", &self.location)
            .field("id", &self.id)
            .field("entries", &self.index.len())
            .finish_non_exhaustive()
    }
}

impl BakDestination {
    /// Opens the `.bak` stored under `key` at `dest`.
    ///
    /// # Errors
    /// [`BackupError::ObjectNotFound`] when `key` does not exist; [`BackupError::Corrupt`] for a
    /// file that is not a well-formed `.bak` (bad header or checksum, truncated, unsafe or
    /// duplicate names, no marker first, entries of another backup);
    /// [`BackupError::UnsupportedFormat`] for a newer `.bak` format;
    /// [`BackupError::Destination`].
    pub fn open(dest: &dyn Destination, key: &str) -> Result<Self> {
        let reader = dest.open(key)?;
        let location = format!("{} ({key})", dest.describe());
        let (index, order) = read_index(reader.as_ref(), key)?;
        let corrupt = |path: &str, reason: String| BackupError::corrupt(key, path, reason);

        // The marker is first and names the one backup the archive may hold.
        let (marker_offset, marker_size) = match order.first() {
            Some(first) if first == BAK_MARKER => index[BAK_MARKER],
            _ => {
                return Err(corrupt(
                    BAK_MARKER,
                    format!("{BAK_MARKER} is not the first entry"),
                ));
            }
        };
        if marker_size > MAX_MARKER_BYTES {
            return Err(corrupt(BAK_MARKER, "too large".into()));
        }
        let mut bytes = vec![0u8; usize::try_from(marker_size).unwrap_or(0)];
        reader.read_exact_at(&mut bytes, marker_offset)?;
        // The version is read before the rest, so a newer format reports RGN-5007.
        let version = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("format_version").and_then(serde_json::Value::as_u64))
            .ok_or_else(|| corrupt(BAK_MARKER, "no format_version".into()))?;
        if version > u64::from(BAK_FORMAT_VERSION) {
            return Err(BackupError::UnsupportedFormat {
                found: version,
                supported: BAK_FORMAT_VERSION,
            });
        }
        let marker: Marker =
            serde_json::from_slice(&bytes).map_err(|e| corrupt(BAK_MARKER, e.to_string()))?;
        if marker.format != BAK_FORMAT {
            return Err(corrupt(BAK_MARKER, format!("format {:?}", marker.format)));
        }
        let id =
            BackupId::parse(&marker.backup_id).map_err(|e| corrupt(BAK_MARKER, e.to_string()))?;
        let prefix = format!("{}/", backup_prefix(&id));
        if let Some(stray) = order[1..].iter().find(|n| !n.starts_with(&prefix)) {
            return Err(corrupt(stray, format!("outside {prefix}")));
        }
        Ok(Self {
            reader: Arc::new(Mutex::new(reader)),
            location,
            id,
            index,
        })
    }

    /// The id of the backup the archive holds.
    #[must_use]
    pub fn backup_id(&self) -> &BackupId {
        &self.id
    }
}

/// Entry name → (data offset, size), and the names in archive order.
type Index = (BTreeMap<String, (u64, u64)>, Vec<String>);

/// Reads every header of the archive `reader` (named `key` in errors).
fn read_index(reader: &dyn ObjectReader, key: &str) -> Result<Index> {
    let size = reader.size();
    let corrupt = |path: &str, reason: String| BackupError::corrupt(key, path, reason);
    let mut index = BTreeMap::new();
    let mut order = Vec::new();
    let mut offset = 0;
    let mut block = [0u8; BLOCK_LEN];
    loop {
        if offset + BLOCK > size {
            return Err(corrupt("", "truncated: no end-of-archive block".into()));
        }
        reader.read_exact_at(&mut block, offset)?;
        if block.iter().all(|&b| b == 0) {
            return Ok((index, order));
        }
        let entry = parse_header(&block).map_err(|reason| corrupt("", reason))?;
        validate_key(&entry.name).map_err(|e| corrupt(&entry.name, e.to_string()))?;
        let data = offset + BLOCK;
        let next = data
            .checked_add(padded(entry.size))
            .filter(|&n| n <= size)
            .ok_or_else(|| corrupt(&entry.name, "truncated".into()))?;
        if index.len() >= MAX_ENTRIES {
            return Err(corrupt("", "too many entries".into()));
        }
        if index
            .insert(entry.name.clone(), (data, entry.size))
            .is_some()
        {
            return Err(corrupt(&entry.name, "duplicate entry".into()));
        }
        order.push(entry.name);
        offset = next;
    }
}

/// A parsed header.
#[derive(Debug)]
struct TarEntry {
    name: String,
    size: u64,
}

fn parse_header(h: &[u8; BLOCK_LEN]) -> std::result::Result<TarEntry, String> {
    let stored = parse_octal(&h[148..156]).ok_or("bad header checksum field")?;
    let sum: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(b)
            }
        })
        .sum();
    if stored != sum {
        return Err("header checksum mismatch".into());
    }
    if !matches!(h[156], b'0' | 0) {
        return Err(format!(
            "entry type {:?} is not a regular file",
            char::from(h[156])
        ));
    }
    let text = |field: &[u8]| -> std::result::Result<String, String> {
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        String::from_utf8(field[..end].to_vec()).map_err(|_| "name is not UTF-8".to_owned())
    };
    let base = text(&h[..100])?;
    let prefix = if &h[257..262] == b"ustar" {
        text(&h[345..500])?
    } else {
        String::new()
    };
    let name = if prefix.is_empty() {
        base
    } else {
        format!("{prefix}/{base}")
    };
    let size = if h[124] & 0x80 != 0 {
        if h[124] != 0x80 || h[125..128].iter().any(|&b| b != 0) {
            return Err("size field too large".into());
        }
        let mut be = [0u8; 8];
        be.copy_from_slice(&h[128..136]);
        u64::from_be_bytes(be)
    } else {
        parse_octal(&h[124..136]).ok_or("bad size field")?
    };
    Ok(TarEntry { name, size })
}

/// Parses an octal field (leading spaces, digits, then NUL or space).
fn parse_octal(field: &[u8]) -> Option<u64> {
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|&b| b != 0 && b != b' ')
        .collect();
    if digits.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(std::str::from_utf8(&digits).ok()?, 8).ok()
}

/// One entry of a [`BakDestination`].
struct EntryReader {
    reader: Arc<Mutex<Box<dyn ObjectReader>>>,
    base: u64,
    size: u64,
}

impl ObjectReader for EntryReader {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.size {
            return Err(BackupError::Destination {
                destination: "bak".into(),
                op: "read",
                key: String::new(),
                source: io::Error::new(io::ErrorKind::UnexpectedEof, "read past the entry"),
            });
        }
        let reader = self
            .reader
            .lock()
            .map_err(|_| BackupError::Internal("bak reader lock poisoned".into()))?;
        reader.read_exact_at(buf, self.base + offset)
    }
}

impl Destination for BakDestination {
    fn describe(&self) -> String {
        self.location.clone()
    }

    fn put_reader(&self, key: &str, _size: u64, _reader: &mut dyn io::Read) -> Result<()> {
        Err(BackupError::InvalidArgument(format!(
            "{} is read-only (put {key})",
            self.location
        )))
    }

    fn open(&self, key: &str) -> Result<Box<dyn ObjectReader>> {
        let &(base, size) = self
            .index
            .get(key)
            .ok_or_else(|| BackupError::ObjectNotFound {
                key: key.to_owned(),
                destination: self.location.clone(),
            })?;
        Ok(Box::new(EntryReader {
            reader: Arc::clone(&self.reader),
            base,
            size,
        }))
    }

    fn size(&self, key: &str) -> Result<Option<u64>> {
        Ok(self.index.get(key).map(|&(_, size)| size))
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let below = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}/")
        };
        Ok(self
            .index
            .keys()
            .filter(|k| k.starts_with(&below) && k.as_str() != BAK_MARKER)
            .cloned()
            .collect())
    }

    fn list_children(&self, prefix: &str) -> Result<Vec<String>> {
        let below = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}/")
        };
        let mut out: Vec<String> = self
            .list(prefix)?
            .iter()
            .filter_map(|k| k.strip_prefix(&below)?.split('/').next().map(str::to_owned))
            .collect();
        out.dedup();
        Ok(out)
    }

    fn delete(&self, key: &str) -> Result<()> {
        Err(BackupError::InvalidArgument(format!(
            "{} is read-only (delete {key})",
            self.location
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_names_sizes_and_checksum() {
        let long = format!("backups/{}/lsm/{}", "a".repeat(60), "b".repeat(60));
        for (name, size) in [
            ("rustegon-bak.json", 7_u64),
            ("backups/x/lsm/000012.rsst", 0),
            (long.as_str(), MAX_OCTAL_SIZE + 1),
        ] {
            let h = header(name, size, 1_700_000_000).unwrap();
            let e = parse_header(&h).unwrap();
            assert_eq!(e.name, name);
            assert_eq!(e.size, size);
        }
        let mut h = header("a", 1, 0).unwrap();
        h[0] = b'b';
        assert!(parse_header(&h).unwrap_err().contains("checksum"));
    }

    #[test]
    fn names_too_long_for_ustar_are_refused() {
        assert!(split_name(&"a".repeat(101)).is_err());
        assert!(split_name(&format!("{}/{}", "a".repeat(10), "b".repeat(101))).is_err());
    }

    #[test]
    fn bak_ids_are_recognised_only_at_the_root() {
        let id = "20261109T101500Z-3fa85f64";
        assert_eq!(bak_id(&format!("{id}.bak")).unwrap().as_str(), id);
        assert!(bak_id(&format!("x/{id}.bak")).is_none());
        assert!(bak_id(&format!("{id}.tar")).is_none());
        assert!(bak_id(".bak").is_none());
    }
}
