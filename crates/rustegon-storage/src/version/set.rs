// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Versions (the set of live SSTs per level) and the version set that persists them through the
//! MANIFEST (storage-engine.md §2, §9, §11, §13).
//!
//! Level invariants, checked whenever an edit is applied:
//! - L0 files may overlap; they are ordered newest first (largest seqno, then file number,
//!   descending) because a lookup must consult them in that order.
//! - L1..L6 files are ordered by smallest key and their *user-key* ranges are disjoint, so a
//!   lookup reads at most one file per level. Compaction must therefore never split the versions of
//!   one user key across two output files.
//!
//! Pinning: readers hold an `Arc<Version>`; the set tracks every version still referenced, and a
//! file is obsolete only when no live version contains it.
//!
//! Recovery (`open`): read `CURRENT`, replay the MANIFEST (tolerating a torn tail), check that
//! every referenced SST exists (a missing one is corruption — refuse to open, §13), then write a
//! fresh MANIFEST holding a snapshot of the recovered state and switch `CURRENT` to it. Starting
//! a new MANIFEST on every open discards any torn tail and bounds MANIFEST growth.
//!
//! Encryption (storage-engine.md §7, §9): a set opened with a [`KeyManager`] encrypts every
//! MANIFEST it starts, each under a fresh DEK registered before the file is created, and reads
//! an old MANIFEST with its DEK. A MANIFEST without a registry entry is read as plaintext only
//! when the registry admits it (`KeyManager::admit_plaintext_manifest`: a store switching to
//! encryption at a reopen); in a store that already encrypts files it is refused as corruption,
//! so a swapped-in plaintext MANIFEST cannot redefine the store. `CURRENT` stays plaintext: it holds only a file
//! name. On open the next file number is moved past every number in the DEK registry, so a
//! number whose DEK was registered just before a crash is never handed out again.
//!
//! Concurrency: `VersionSet` is not internally synchronised; the engine serialises edits behind
//! its own mutex (flush and compaction install results one at a time).

use std::{
    cmp::Reverse,
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Weak},
};

use rustegon_sim_api::{FileSystem, OpenMode};

use super::{
    edit::{FileMeta, NUM_LEVELS, VersionEdit},
    files::{
        FileKind, current_path, manifest_file_name, parse_file_name, read_current, set_current,
    },
    log::{LogWriter, read_log},
};
use crate::{
    encryption::{FileCipher, KeyManager},
    error::{Result, StorageError},
    key::SeqNo,
};

/// An immutable snapshot of the live files.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Version {
    levels: [Vec<Arc<FileMeta>>; NUM_LEVELS],
}

impl Version {
    /// Files of `level` in lookup order (see module docs); empty for levels out of range.
    #[must_use]
    pub fn files(&self, level: usize) -> &[Arc<FileMeta>] {
        self.levels.get(level).map_or(&[], Vec::as_slice)
    }

    /// Total bytes of the files in `level`.
    #[must_use]
    pub fn level_size(&self, level: usize) -> u64 {
        self.files(level).iter().map(|f| f.size).sum()
    }

    /// All files as `(level, file)`.
    pub fn all_files(&self) -> impl Iterator<Item = (usize, &Arc<FileMeta>)> {
        self.levels
            .iter()
            .enumerate()
            .flat_map(|(level, files)| files.iter().map(move |f| (level, f)))
    }

    /// Applies `edit`, returning the new version or the violated invariant.
    fn apply(&self, edit: &VersionEdit) -> Result<Self, String> {
        let mut next = self.clone();
        for &(level, number) in &edit.deleted {
            let files = next
                .levels
                .get_mut(level)
                .ok_or_else(|| format!("level {level} out of range"))?;
            let at = files
                .iter()
                .position(|f| f.number == number)
                .ok_or_else(|| format!("deleted file {number} not in L{level}"))?;
            files.remove(at);
        }
        let mut seen: BTreeSet<u64> = next.all_files().map(|(_, f)| f.number).collect();
        for (level, file) in &edit.added {
            if !seen.insert(file.number) {
                return Err(format!("file {} added twice", file.number));
            }
            if file.smallest > file.largest {
                return Err(format!("file {} has smallest > largest", file.number));
            }
            next.levels
                .get_mut(*level)
                .ok_or_else(|| format!("level {level} out of range"))?
                .push(Arc::new(file.clone()));
        }
        next.normalize()?;
        Ok(next)
    }

    /// Sorts every level and checks the L1+ disjointness invariant.
    fn normalize(&mut self) -> Result<(), String> {
        self.levels[0].sort_by_key(|f| Reverse((f.largest_seqno, f.number)));
        for (level, files) in self.levels.iter_mut().enumerate().skip(1) {
            files.sort_by(|a, b| a.smallest.cmp(&b.smallest));
            for pair in files.windows(2) {
                if pair[0].largest.user_key() >= pair[1].smallest.user_key() {
                    return Err(format!(
                        "files {} and {} overlap in L{level}",
                        pair[0].number, pair[1].number
                    ));
                }
            }
        }
        Ok(())
    }

    /// Test helper: one file per `(level, size)`, numbered from 1, all spanning user keys a..z
    /// (only valid with at most one file per L1+ level).
    #[cfg(test)]
    pub(crate) fn for_test(files: &[(usize, u64)]) -> Self {
        let ranges: Vec<_> = files.iter().map(|&(l, s)| (l, s, "a", "z")).collect();
        Self::for_test_ranges(&ranges)
    }

    /// Test helper: one file per `(level, size, smallest user key, largest user key)`.
    #[cfg(test)]
    pub(crate) fn for_test_ranges(files: &[(usize, u64, &str, &str)]) -> Self {
        use crate::key::{InternalKey, ValueKind};
        let added = files
            .iter()
            .zip(1..)
            .map(|(&(level, size, lo, hi), number)| {
                let meta = FileMeta {
                    number,
                    size,
                    smallest: InternalKey::new(lo.as_bytes(), number, ValueKind::Put),
                    largest: InternalKey::new(hi.as_bytes(), number, ValueKind::Put),
                    smallest_seqno: number,
                    largest_seqno: number,
                };
                (level, meta)
            })
            .collect();
        let edit = VersionEdit {
            added,
            ..VersionEdit::default()
        };
        match Self::default().apply(&edit) {
            Ok(v) => v,
            Err(e) => unreachable!("invalid test version: {e}"),
        }
    }

    /// An edit that recreates this version from an empty one.
    fn snapshot_edit(&self) -> VersionEdit {
        VersionEdit {
            added: self
                .all_files()
                .map(|(level, f)| (level, FileMeta::clone(f)))
                .collect(),
            ..VersionEdit::default()
        }
    }
}

/// Counters persisted alongside the version.
#[derive(Debug, Default, Clone, Copy)]
struct Counters {
    next_file_number: u64,
    last_seqno: SeqNo,
    flushed_seqno: SeqNo,
}

impl Counters {
    /// Counters only move forward; added files also advance the next file number.
    fn absorb(&mut self, edit: &VersionEdit) {
        if let Some(n) = edit.next_file_number {
            self.next_file_number = self.next_file_number.max(n);
        }
        if let Some(s) = edit.last_seqno {
            self.last_seqno = self.last_seqno.max(s);
        }
        if let Some(s) = edit.flushed_seqno {
            self.flushed_seqno = self.flushed_seqno.max(s);
        }
        for (_, f) in &edit.added {
            self.next_file_number = self.next_file_number.max(f.number.saturating_add(1));
        }
    }
}

/// Creates MANIFEST `number` in `dir` holding one durable record that recreates `version` and
/// `counters` from nothing; `CURRENT` is not touched.
fn write_snapshot(
    fs: &dyn FileSystem,
    dir: &Path,
    number: u64,
    version: &Version,
    counters: Counters,
    cipher: Option<Arc<FileCipher>>,
) -> Result<LogWriter> {
    let file = fs.open(&dir.join(manifest_file_name(number)), OpenMode::CreateNew)?;
    let mut manifest = LogWriter::new(file, cipher);
    let mut snapshot = version.snapshot_edit();
    snapshot.next_file_number = Some(counters.next_file_number);
    snapshot.last_seqno = Some(counters.last_seqno);
    snapshot.flushed_seqno = Some(counters.flushed_seqno);
    // §9 ordering: the record is fsynced here, before any caller names it in CURRENT.
    manifest.add_record(&snapshot.encode())?;
    Ok(manifest)
}

/// Writes MANIFEST `number` holding a snapshot of `version` and the given counters into `dir`
/// (another store's directory, e.g. a checkpoint, §10), then points `dir/CURRENT` at it.
/// `next_file_number` must exceed `number` and every file number in `version`. With
/// `encryption` (the target directory's own registry) the MANIFEST is encrypted under a fresh DEK
/// that is durable in that registry before the file exists (§7 ordering), as `VersionSet` does.
///
/// # Errors
/// I/O and DEK registry errors; the MANIFEST may then exist without `CURRENT`, which
/// `VersionSet::open` rejects.
#[allow(clippy::too_many_arguments)] // Flat counters mirror the MANIFEST snapshot record.
pub(crate) fn write_manifest_snapshot(
    fs: &dyn FileSystem,
    dir: &Path,
    number: u64,
    version: &Version,
    next_file_number: u64,
    last_seqno: SeqNo,
    flushed_seqno: SeqNo,
    encryption: Option<&KeyManager>,
) -> Result<()> {
    let counters = Counters {
        next_file_number,
        last_seqno,
        flushed_seqno,
    };
    let cipher = match encryption {
        Some(keys) => Some(keys.new_file_cipher(number)?),
        None => None,
    };
    // Closed before `set_current` renames in the same directory (Windows handle semantics).
    drop(write_snapshot(fs, dir, number, version, counters, cipher)?);
    set_current(fs, dir, number)
}

/// Removes what a store creation interrupted by a crash may leave in `dir`, which has no
/// `CURRENT` (storage-engine.md §9 "Store creation").
///
/// `CURRENT` is the commit point of creation: until it names MANIFEST 1, nothing can have been
/// acknowledged, so a `MANIFEST-000001` (empty, torn or complete) and the DEK registered for it
/// are leftovers and are dropped. Any SST or other MANIFEST means a store that once committed
/// and then lost `CURRENT`: that is refused as corruption, never recreated over its files (the
/// orphan cleanup of a fresh store would delete them).
///
/// # Errors
/// [`StorageError::Corruption`] for store files without `CURRENT`; I/O and DEK registry errors.
fn discard_unfinished_creation(
    fs: &dyn FileSystem,
    dir: &Path,
    encryption: Option<&KeyManager>,
) -> Result<()> {
    for path in fs.read_dir(dir)? {
        match path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(parse_file_name)
        {
            Some(FileKind::Manifest(1)) => fs.remove_file(&path)?,
            Some(FileKind::Sst(_) | FileKind::Manifest(_)) => {
                return Err(StorageError::corruption(format!(
                    "{} holds store files but no CURRENT",
                    dir.display()
                )));
            }
            // `CURRENT.tmp` is truncated by `set_current`; foreign files are not ours.
            _ => {}
        }
    }
    // After the file: a crash in between leaves only this unused entry, dropped on the next try.
    if let Some(keys) = encryption {
        keys.forget(&[1])?;
    }
    Ok(())
}

/// Owns the current version and the MANIFEST.
pub struct VersionSet {
    fs: Arc<dyn FileSystem>,
    dir: PathBuf,
    current: Arc<Version>,
    /// Versions handed out that may still be referenced (for obsolete-file detection).
    live: Vec<Weak<Version>>,
    manifest: LogWriter,
    manifest_number: u64,
    counters: Counters,
    /// Set after a failed MANIFEST write: the durable state is unknown (§13, fsync failure).
    failed: bool,
    /// The store's encryption context; `None` for a plaintext store.
    encryption: Option<Arc<KeyManager>>,
}

impl VersionSet {
    /// Creates a new, empty store in `dir` (created if missing).
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] if `dir` already holds a store; I/O errors.
    pub fn create(fs: Arc<dyn FileSystem>, dir: &Path) -> Result<Self> {
        Self::create_with(fs, dir, None)
    }

    /// Creates a new, empty store in `dir`, encrypting its MANIFESTs with `encryption` if given
    /// (module docs).
    ///
    /// # Errors
    /// As [`VersionSet::create`]; DEK registry errors.
    pub fn create_with(
        fs: Arc<dyn FileSystem>,
        dir: &Path,
        encryption: Option<Arc<KeyManager>>,
    ) -> Result<Self> {
        super::files::create_dir_durable(fs.as_ref(), dir)?;
        if fs.open(&current_path(dir), OpenMode::Read).is_ok() {
            return Err(StorageError::InvalidArgument(format!(
                "{} already contains a store",
                dir.display()
            )));
        }
        discard_unfinished_creation(fs.as_ref(), dir, encryption.as_deref())?;
        // File number 1 is the first MANIFEST; SSTs start at 2.
        let counters = Counters {
            next_file_number: 2,
            ..Counters::default()
        };
        Self::start_manifest(fs, dir, 1, Version::default(), counters, encryption)
    }

    /// Opens an existing store, recovering the last durable version.
    ///
    /// # Errors
    /// [`StorageError::Corruption`] for a damaged MANIFEST or a missing SST; I/O errors.
    pub fn open(fs: Arc<dyn FileSystem>, dir: &Path) -> Result<Self> {
        Self::open_with(fs, dir, None)
    }

    /// Opens an existing store, decrypting its MANIFEST with `encryption` if given (module
    /// docs).
    ///
    /// # Errors
    /// As [`VersionSet::open`]; [`StorageError::KeyUnavailable`] if the MANIFEST is encrypted
    /// and its DEK is unavailable (no `encryption`, or a DEK that does not unwrap).
    pub fn open_with(
        fs: Arc<dyn FileSystem>,
        dir: &Path,
        encryption: Option<Arc<KeyManager>>,
    ) -> Result<Self> {
        let old_number = read_current(fs.as_ref(), dir)?;
        let old_path = dir.join(manifest_file_name(old_number));
        let old_cipher = match &encryption {
            Some(keys) => {
                let cipher = keys.file_cipher(old_number)?;
                if cipher.is_none() {
                    // A plaintext MANIFEST in an encrypted store is legitimate only while a
                    // plaintext store switches to encryption (registry module docs); the
                    // admission becomes durable with the MANIFEST's DEK drawn below.
                    keys.admit_plaintext_manifest(old_number)?;
                }
                cipher
            }
            None => None,
        };
        let log = read_log(
            fs.open(&old_path, OpenMode::Read)?.as_ref(),
            old_cipher.as_deref(),
        )?;
        let mut version = Version::default();
        let mut counters = Counters::default();
        for record in &log.records {
            let edit = VersionEdit::decode(record)?;
            version = version
                .apply(&edit)
                .map_err(|e| StorageError::corruption(format!("MANIFEST replay: {e}")))?;
            counters.absorb(&edit);
        }

        // Every referenced SST must exist; numbers already used by any file in the directory
        // (e.g. orphans of an interrupted flush) are never handed out again.
        let mut present = BTreeSet::new();
        for path in fs.read_dir(dir)? {
            let kind = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(parse_file_name);
            let used = match kind {
                Some(FileKind::Sst(n)) => {
                    present.insert(n);
                    n
                }
                Some(FileKind::Manifest(n)) => n,
                _ => continue,
            };
            counters.next_file_number = counters.next_file_number.max(used.saturating_add(1));
        }
        if let Some(max) = encryption
            .as_ref()
            .and_then(|keys| keys.file_numbers().last().copied())
        {
            counters.next_file_number = counters.next_file_number.max(max.saturating_add(1));
        }
        if let Some((level, f)) = version
            .all_files()
            .find(|(_, f)| !present.contains(&f.number))
        {
            return Err(StorageError::corruption(format!(
                "MANIFEST references missing SST {} (L{level})",
                f.number
            )));
        }

        let new_number = counters.next_file_number;
        counters.next_file_number += 1;
        let set = Self::start_manifest(fs, dir, new_number, version, counters, encryption)?;
        // The old MANIFEST is unreferenced once CURRENT has switched; if this delete is lost to
        // a crash, `obsolete_files` reports the leftover on the next open.
        set.fs.remove_file(&old_path)?;
        // Its DEK goes after the file: a crash in between leaves a harmless unused entry.
        if let Some(keys) = &set.encryption {
            keys.forget(&[old_number])?;
        }
        Ok(set)
    }

    /// Writes MANIFEST `number` holding a snapshot of `version` and points `CURRENT` at it.
    fn start_manifest(
        fs: Arc<dyn FileSystem>,
        dir: &Path,
        number: u64,
        version: Version,
        counters: Counters,
        encryption: Option<Arc<KeyManager>>,
    ) -> Result<Self> {
        // §7 ordering: the MANIFEST's DEK is durable before the file exists.
        let cipher = match &encryption {
            Some(keys) => Some(keys.new_file_cipher(number)?),
            None => None,
        };
        let manifest = write_snapshot(fs.as_ref(), dir, number, &version, counters, cipher)?;
        set_current(fs.as_ref(), dir, number)?;
        let current = Arc::new(version);
        Ok(Self {
            live: vec![Arc::downgrade(&current)],
            current,
            fs,
            dir: dir.to_path_buf(),
            manifest,
            manifest_number: number,
            counters,
            failed: false,
            encryption,
        })
    }

    /// The directory holding the MANIFEST and the SSTs.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The store's encryption context, if the set was opened with one.
    #[must_use]
    pub fn encryption(&self) -> Option<&Arc<KeyManager>> {
        self.encryption.as_ref()
    }

    /// The current version; holding it pins its files.
    #[must_use]
    pub fn current(&self) -> Arc<Version> {
        Arc::clone(&self.current)
    }

    /// Allocates a file number for a new SST. Numbers are persisted with the next edit; a number
    /// lost to a crash is skipped on recovery because `open` scans the directory.
    pub fn new_file_number(&mut self) -> u64 {
        let n = self.counters.next_file_number;
        self.counters.next_file_number += 1;
        n
    }

    /// Largest seqno recorded.
    #[must_use]
    pub fn last_seqno(&self) -> SeqNo {
        self.counters.last_seqno
    }

    /// All writes with seqno <= this value are in SSTs.
    #[must_use]
    pub fn flushed_seqno(&self) -> SeqNo {
        self.counters.flushed_seqno
    }

    /// Number of the MANIFEST in use.
    #[must_use]
    pub fn manifest_number(&self) -> u64 {
        self.manifest_number
    }

    /// Durably records `edit` and installs the resulting version. Counters in the edit only
    /// move forward; the set fills in the next file number itself.
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] if the edit violates a level invariant (an engine bug;
    /// nothing is written) or the set failed before; I/O errors from the MANIFEST write, after
    /// which the set refuses all further edits because the durable state is unknown.
    pub fn log_and_apply(&mut self, mut edit: VersionEdit) -> Result<()> {
        if self.failed {
            return Err(StorageError::InvalidArgument(
                "version set is unusable after a failed MANIFEST write".into(),
            ));
        }
        let next = self
            .current
            .apply(&edit)
            .map_err(|e| StorageError::InvalidArgument(format!("invalid version edit: {e}")))?;
        let mut counters = self.counters;
        counters.absorb(&edit);
        edit.next_file_number = Some(counters.next_file_number);
        if let Err(e) = self.manifest.add_record(&edit.encode()) {
            self.failed = true;
            return Err(e);
        }
        self.counters = counters;
        self.current = Arc::new(next);
        self.live.retain(|v| v.strong_count() > 0);
        self.live.push(Arc::downgrade(&self.current));
        Ok(())
    }

    /// Numbers of all SSTs in any version still referenced.
    #[must_use]
    pub fn live_files(&self) -> BTreeSet<u64> {
        let mut live = BTreeSet::new();
        for version in self.live.iter().filter_map(Weak::upgrade) {
            live.extend(version.all_files().map(|(_, f)| f.number));
        }
        live.extend(self.current.all_files().map(|(_, f)| f.number));
        live
    }

    /// Files in the directory that no live version, the current MANIFEST or an in-flight output
    /// (`in_flight`: numbers allocated to SSTs still being written) refers to. The engine deletes
    /// them (startup orphan cleanup and post-compaction cleanup, §9, §11).
    ///
    /// # Errors
    /// I/O errors listing the directory.
    pub fn obsolete_files(&self, in_flight: &BTreeSet<u64>) -> Result<Vec<PathBuf>> {
        let live = self.live_files();
        let mut obsolete = Vec::new();
        for path in self.fs.read_dir(&self.dir)? {
            let kind = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(parse_file_name);
            let dead = match kind {
                Some(FileKind::Sst(n)) => !live.contains(&n) && !in_flight.contains(&n),
                Some(FileKind::Manifest(n)) => n != self.manifest_number,
                Some(FileKind::CurrentTemp) => true,
                Some(FileKind::Current) | None => false,
            };
            if dead {
                obsolete.push(path);
            }
        }
        obsolete.sort();
        Ok(obsolete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::edit::tests::file;

    fn add(level: usize, f: FileMeta) -> VersionEdit {
        VersionEdit {
            added: vec![(level, f)],
            ..VersionEdit::default()
        }
    }

    #[test]
    fn version_orders_l0_newest_first_and_l1_by_key() {
        let mut l0_old = file(2, b"a", b"z");
        l0_old.largest_seqno = 5;
        let mut l0_new = file(3, b"b", b"c");
        l0_new.largest_seqno = 50;
        let v = Version::default()
            .apply(&VersionEdit {
                added: vec![
                    (0, l0_old),
                    (0, l0_new),
                    (1, file(4, b"m", b"p")),
                    (1, file(5, b"a", b"c")),
                ],
                ..VersionEdit::default()
            })
            .unwrap();
        let numbers = |l| v.files(l).iter().map(|f| f.number).collect::<Vec<_>>();
        assert_eq!(numbers(0), [3, 2]);
        assert_eq!(numbers(1), [5, 4]);
        assert_eq!(v.level_size(1), 1004 + 1005);
        assert_eq!(v.files(NUM_LEVELS).len(), 0);
    }

    #[test]
    fn version_rejects_invariant_violations() {
        let base = Version::default()
            .apply(&add(1, file(2, b"c", b"f")))
            .unwrap();
        // User-key overlap in L1, including touching boundaries.
        assert!(base.apply(&add(1, file(3, b"e", b"g"))).is_err());
        assert!(base.apply(&add(1, file(3, b"f", b"g"))).is_err());
        assert!(base.apply(&add(1, file(3, b"g", b"h"))).is_ok());
        // Overlap is fine in L0.
        assert!(base.apply(&add(0, file(3, b"a", b"z"))).is_ok());
        // Duplicate number, unknown delete, wrong level, bad level, inverted range.
        assert!(base.apply(&add(2, file(2, b"x", b"y"))).is_err());
        let del = |level, number| VersionEdit {
            deleted: vec![(level, number)],
            ..VersionEdit::default()
        };
        assert!(base.apply(&del(1, 9)).is_err());
        assert!(base.apply(&del(2, 2)).is_err());
        assert!(base.apply(&del(1, 2)).is_ok());
        assert!(base.apply(&add(NUM_LEVELS, file(3, b"a", b"b"))).is_err());
        assert!(base.apply(&add(2, file(3, b"z", b"a"))).is_err());
    }
}
