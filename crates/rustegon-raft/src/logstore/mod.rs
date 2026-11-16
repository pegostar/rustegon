// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Per-node segmented Raft log store shared by all Raft groups (ADR-009, replication.md §2,
//! byte layout in "Log store format v1"; NFR-REL-003, TC-TXN-004).
//!
//! The LSM has no WAL: this log is the write-ahead log of every range, so an acknowledged write
//! must survive any crash (storage-engine.md §9). The design follows from that:
//!
//! - **Group commit.** [`LogStore::write`] persists one [`LogBatch`] (entries, hard states,
//!   truncations, purges of any number of groups) as a single record and issues one
//!   `fdatasync`. A batch is acknowledged (the call returns `Ok`) only after the sync, and it is
//!   atomic: recovery sees the whole record or drops it as a torn tail, never a part of it.
//! - **Segments.** Records go to the active segment `<dir>/<id:020>.rlog`; when it reaches
//!   [`LogStoreOptions::segment_size`] the next batch first rolls over to segment `id + 1`. Every
//!   segment starts with a snapshot of all groups' metadata (first/last index, terms, hard state),
//!   so the segments before it hold nothing but entries; a segment is deleted, oldest first, once
//!   none of its entries is live (all purged, truncated, replaced or of removed groups).
//! - **Recovery** ([`LogStore::open`]) replays every segment in order through the same state
//!   machine as live writes. A torn final write is tolerated only in the last segment (and is cut
//!   off by rewriting the valid prefix); any other invalid record, a missing segment or entries
//!   missing from a group's log is [`LogStoreError::Corruption`]: acknowledged entries are never
//!   silently dropped. The open always starts a fresh active segment.
//! - **Failure handling.** A write that fails after reaching the file leaves its state unknown;
//!   the store is then poisoned ([`LogStoreError::Poisoned`]) until reopened. Reads keep serving
//!   the acknowledged state, which the in-memory index only ever reflects.
//!
//! Concurrency: the store is a plain single-owner value (`&mut self` writes, `&self` reads); the
//! Raft driver serialises access (one writer thread doing group commit).
//!
//! **Encryption at rest** (storage-engine.md §7, FR-EAR-001, PD-057): with
//! [`LogStoreOptions::encryption`] every new segment is format v2: it gets a fresh DEK from the
//! log store's own registry, made durable *before* the segment file is created, and every
//! entry payload (the only user data in the log) is sealed with AES-256-GCM under it, nonce
//! `segment_id ‖ payload_offset / 16`, associated data `group ‖ index ‖ term`. Group metadata
//! (indexes, terms, hard states) stays plaintext. Payloads are decrypted on read
//! ([`LogStore::entries`]), where a failed tag is corruption. A plaintext store switching to
//! encryption keeps reading its v1 segments: the highest of them is recorded in the registry's
//! plaintext admission together with the first DEK (the mechanism the LSM uses for its last
//! plaintext MANIFEST), and in an encrypted log any other v1 segment is refused as corruption,
//! so a plaintext segment cannot be swapped in. Deleted segments' DEKs are forgotten
//! (crypto-shredding), the admission once no v1 segment is left.
//!
//! **Backup hooks** (FR-BKP-002/004, PD-066; replication.md §2 "Archiving sealed segments"):
//! the log is the WAL, so point-in-time recovery archives its segments. A segment other than
//! the active one is *sealed*: it is never written again (writes only go to the newest segment,
//! and an open always starts a new one), so a copy of it is final.
//! [`LogStore::sealed_segments`] lists them with what an archiver needs,
//! [`LogStore::force_roll`] seals the active segment on demand (a timer bounds the RPO), and
//! [`LogStoreOptions::archive_floor`] keeps every segment above the floor on disk even when its
//! entries are all obsolete, until the archiver has copied it. [`read_segment`] reads the
//! entries of one segment file standalone (no store, no registry), for restore.
//!
//! Not covered yet (later milestones): segment footers that would let recovery skip scanning
//! full segments, a byte limit for [`LogStore::entries`], and re-verifying checksums on reads
//! after recovery.

mod archive;
mod batch;
mod error;
mod format;
mod group;
mod recovery;

use std::{
    collections::BTreeMap,
    mem,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use rustegon_sim_api::{File, FileSystem, OpenMode};
use rustegon_storage::{
    StorageError,
    encryption::{FileCipher, KeyManager, TAG_LEN, WrappedKey},
};

pub use self::{
    archive::{SealedSegment, SegmentEntry, SegmentKey, SegmentReader, read_segment},
    batch::LogBatch,
    error::LogStoreError,
    group::HardState,
};
use self::{
    batch::{Resolved, Shadow, encode},
    error::Result,
    format::{RecordBuilder, payload_aad, payload_counter, refresh_checksum, segment_header},
    group::{Change, GroupMeta, GroupState, LiveCounts, Loc, apply_to},
};
use crate::settings::{DEFAULT_LOG_SEGMENT_SIZE, RaftSettings};

/// Log store tunables.
#[derive(Debug, Clone)]
pub struct LogStoreOptions {
    /// Segment size in bytes that triggers a rollover before the next batch.
    pub segment_size: u64,
    /// Encryption at rest (module docs, "Encryption"): the log store's own DEK registry (its
    /// numbers are segment ids, a space distinct from the LSM's file numbers, so the LSM's
    /// registry cannot be shared). `None` writes plaintext v1 segments.
    pub encryption: Option<Arc<KeyManager>>,
    /// Archive floor for point-in-time recovery (module docs, "Backup hooks"; PD-066): the
    /// highest segment id the archiver has durably copied. Obsolete-segment deletion never
    /// deletes a segment whose id is above the floor, however obsolete its entries are, so
    /// every segment reaches the archive before it leaves the disk. Raising the floor releases
    /// the held segments at the next deletion pass (a write, [`LogStore::force_roll`] or
    /// [`LogStore::delete_obsolete`]). The archiver owns the value and stores it with
    /// `Release` after its copy is durable; the store loads it with `Acquire`. Starts at 0
    /// (segment ids start at 1: nothing archived, nothing deletable). `None` disables the
    /// floor (no archiving): segments go as soon as nothing in them is live.
    pub archive_floor: Option<Arc<AtomicU64>>,
}

impl Default for LogStoreOptions {
    fn default() -> Self {
        Self {
            segment_size: DEFAULT_LOG_SEGMENT_SIZE,
            encryption: None,
            archive_floor: None,
        }
    }
}

impl LogStoreOptions {
    /// Options from the `[raft]` settings section.
    #[must_use]
    pub fn from_settings(settings: &RaftSettings) -> Self {
        Self {
            segment_size: settings.log_segment_size,
            ..Self::default()
        }
    }
}

/// One Raft log entry as read back from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Log index.
    pub index: u64,
    /// Term the entry was proposed in.
    pub term: u64,
    /// Opaque payload (an evaluated write batch, replication.md §3).
    pub payload: Vec<u8>,
}

/// What [`LogStore::open`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryInfo {
    /// Segments replayed.
    pub segments: usize,
    /// Whether a torn final write was cut off the last segment (an interrupted, never
    /// acknowledged batch).
    pub torn_tail: bool,
    /// Groups with state after recovery.
    pub groups: usize,
}

/// One segment file.
struct Segment {
    file: Box<dyn File>,
    /// Bytes of valid data (the file size, except for the moment between a failed append and
    /// the poisoning of the store).
    size: u64,
    /// The segment's cipher for a v2 (encrypted) segment; `None` for a plaintext v1 segment.
    cipher: Option<Arc<FileCipher>>,
    /// Per group, the lowest and highest index of the entry records written to this segment
    /// (replaced and purged ones included: they are still in the file). For archivers.
    written: BTreeMap<u64, (u64, u64)>,
}

/// Widens the `(lowest, highest)` range of `group` in `written` to cover `index`.
fn note_written(written: &mut BTreeMap<u64, (u64, u64)>, group: u64, index: u64) {
    let range = written.entry(group).or_insert((index, index));
    range.0 = range.0.min(index);
    range.1 = range.1.max(index);
}

/// The per-node Raft log store (module docs).
pub struct LogStore {
    fs: Arc<dyn FileSystem>,
    dir: PathBuf,
    options: LogStoreOptions,
    segments: BTreeMap<u64, Segment>,
    /// Id of the segment receiving writes (always the newest).
    active: u64,
    /// Size of the active segment when it was created (header and metadata snapshot): a
    /// larger size means it holds a batch, which [`LogStore::force_roll`] then seals.
    active_head_len: u64,
    groups: BTreeMap<u64, GroupState>,
    counts: LiveCounts,
    /// Reused record buffer.
    buf: Vec<u8>,
    poisoned: bool,
    recovery: RecoveryInfo,
}

impl std::fmt::Debug for LogStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogStore")
            .field("dir", &self.dir)
            .field("segments", &self.segments.keys().collect::<Vec<_>>())
            .field("active", &self.active)
            .field("groups", &self.groups.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

/// Path of segment `id` in `dir`.
fn segment_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:020}.rlog"))
}

/// Seals every entry payload of the finished record `buf`, to be appended at `base` of the
/// segment of `cipher`, then refreshes the record checksum (module docs, "Encryption").
/// `offsets` are the payloads' record offsets from `encode`, in op order; each payload is
/// followed by the room for its tag.
fn seal_payloads(
    cipher: &FileCipher,
    base: u64,
    buf: &mut [u8],
    ops: &[Resolved<'_>],
    offsets: &[usize],
) -> Result<()> {
    let mut offsets = offsets.iter();
    for op in ops {
        let Resolved::Entry {
            group,
            index,
            term,
            payload,
        } = *op
        else {
            continue;
        };
        let at = offsets.next().copied().unwrap_or_default();
        let counter = payload_counter(base + at as u64).ok_or_else(|| {
            LogStoreError::invalid("raft log segment offset beyond the 64 GiB nonce range")
        })?;
        let end = at + payload.len();
        let (Some(plain), Some(_)) = (buf.get(at..end), buf.get(end..end + TAG_LEN)) else {
            return Err(LogStoreError::invalid("entry payload outside its record"));
        };
        debug_assert_eq!(plain, payload);
        let tag =
            cipher.seal_detached(counter, &payload_aad(group, index, term), &mut buf[at..end])?;
        buf[end..end + TAG_LEN].copy_from_slice(&tag);
    }
    refresh_checksum(buf);
    Ok(())
}

/// Registry housekeeping at open, after recovery accepted the segments (module docs,
/// "Encryption"):
/// - a store switching to encryption (registry without any DEK) admits its newest plaintext
///   segment; the admission becomes durable with the DEK of the first encrypted segment;
/// - without any plaintext segment left, the admission is dropped and DEKs of segments that no
///   longer exist are forgotten (deletions whose `forget` a crash interrupted). The DEK of
///   `next_id` is kept: `create_segment` replaces it (an interrupted creation).
fn prepare_keys(keys: &KeyManager, segments: &BTreeMap<u64, Segment>, next_id: u64) -> Result<()> {
    let newest_plaintext = segments
        .iter()
        .rev()
        .find(|(_, s)| s.cipher.is_none())
        .map(|(&id, _)| id);
    let registered = keys.file_numbers();
    match newest_plaintext {
        Some(id) if registered.is_empty() => keys.admit_plaintext_manifest(id)?,
        // Recovery verified every plaintext segment against the admission.
        Some(_) => {}
        None => {
            let stale: Vec<u64> = registered
                .into_iter()
                .filter(|n| *n != next_id && !segments.contains_key(n))
                .collect();
            if !stale.is_empty() || keys.admitted_plaintext_manifest().is_some() {
                keys.forget(&stale)?;
            }
        }
    }
    Ok(())
}

impl LogStore {
    /// Opens (or creates) the log store in `dir`: recovers every group from the segments, cuts
    /// off a torn final write, and starts a fresh active segment.
    ///
    /// # Errors
    /// [`LogStoreError::Corruption`] for damaged or missing persisted data (never tolerated
    /// except a torn final write), [`LogStoreError::UnsupportedVersion`], I/O errors.
    pub fn open(fs: Arc<dyn FileSystem>, dir: &Path, options: LogStoreOptions) -> Result<Self> {
        if options.segment_size == 0 {
            return Err(LogStoreError::invalid("segment_size must be positive"));
        }
        let rec = recovery::recover(fs.as_ref(), dir, options.encryption.as_deref())?;
        if let Some(keys) = &options.encryption {
            prepare_keys(keys, &rec.segments, rec.next_id)?;
        }
        let mut store = Self {
            fs,
            dir: dir.to_path_buf(),
            options,
            segments: rec.segments,
            active: 0,
            active_head_len: 0,
            groups: rec.groups,
            counts: rec.counts,
            buf: Vec::new(),
            poisoned: false,
            recovery: rec.info,
        };
        store.create_segment(rec.next_id)?;
        store.delete_obsolete_segments();
        Ok(store)
    }

    /// What the last [`LogStore::open`] found.
    #[must_use]
    pub fn recovery_info(&self) -> &RecoveryInfo {
        &self.recovery
    }

    /// Persists `batch` with a single sync; on `Ok` every operation is durable and visible.
    ///
    /// # Errors
    /// [`LogStoreError::InvalidArgument`] if an operation violates its contract (nothing is
    /// written then); [`LogStoreError::Poisoned`] after an earlier failed write; I/O errors,
    /// after which the store is poisoned.
    pub fn write(&mut self, batch: &LogBatch) -> Result<()> {
        if self.poisoned {
            return Err(LogStoreError::Poisoned);
        }
        let ops = self.resolve(batch)?;
        if ops.is_empty() {
            return Ok(());
        }
        let mut buf = mem::take(&mut self.buf);
        // Every segment this store writes (the active one and any rollover) is encrypted iff
        // the store has a key manager: `open` always starts a new segment.
        let sealed = self.options.encryption.is_some();
        let encoded = encode(&mut buf, &ops, sealed);
        let result = encoded.and_then(|offsets| self.persist_and_apply(&mut buf, &ops, &offsets));
        self.buf = buf;
        result?;
        self.delete_obsolete_segments();
        Ok(())
    }

    /// Rolls over if needed, seals the entry payloads of an encrypted segment, appends + syncs
    /// the record in `buf`, then applies `ops`.
    fn persist_and_apply(
        &mut self,
        buf: &mut [u8],
        ops: &[Resolved<'_>],
        offsets: &[usize],
    ) -> Result<()> {
        let active_size = self.segments.get(&self.active).map_or(0, |s| s.size);
        if active_size >= self.options.segment_size {
            self.create_segment(self.active + 1)?;
        }
        let Some(seg) = self.segments.get_mut(&self.active) else {
            self.poisoned = true;
            return Err(LogStoreError::Poisoned);
        };
        let base = seg.size;
        if let Some(cipher) = &seg.cipher {
            // Nothing is written yet: a sealing failure leaves the store usable.
            seal_payloads(cipher, base, buf, ops, offsets)?;
        }
        // The batch counts only once it is synced: after a failed append or sync the file may
        // hold any prefix of the record, so the store refuses further writes (a retry could
        // follow a partial record) and leaves the decision to recovery.
        if let Err(e) = seg.file.append(buf).and_then(|()| seg.file.sync_data()) {
            self.poisoned = true;
            return Err(e.into());
        }
        seg.size += buf.len() as u64;
        let tag_len = if seg.cipher.is_some() { TAG_LEN } else { 0 };
        for op in ops {
            if let Resolved::Entry { group, index, .. } = *op {
                note_written(&mut seg.written, group, index);
            }
        }
        let mut offsets = offsets.iter();
        for op in ops {
            let (group, change) = match *op {
                Resolved::Entry {
                    group,
                    index,
                    term,
                    payload,
                } => {
                    let at = offsets.next().copied().unwrap_or_default();
                    let loc = Loc {
                        segment: self.active,
                        offset: base + at as u64,
                        // Lossless: the record builder refused longer payloads. The stored
                        // length, tag included for an encrypted segment.
                        len: u32::try_from(payload.len() + tag_len).unwrap_or(u32::MAX),
                        term,
                    };
                    (group, Some(Change::Entry { index, loc }))
                }
                Resolved::Change { group, change } => (group, Some(change)),
                Resolved::Remove { group } => (group, None),
            };
            if let Err(e) = apply_to(&mut self.groups, &mut self.counts, group, change) {
                // Resolution validated every op against the same state, so this is a bug; the
                // batch is durable, so the in-memory index no longer matches the file.
                self.poisoned = true;
                return Err(LogStoreError::corruption(format!(
                    "in-memory index rejected an acknowledged batch: {e}"
                )));
            }
        }
        Ok(())
    }

    /// Validates `batch` against the current state and turns it into persisted operations.
    fn resolve<'b>(&self, batch: &'b LogBatch) -> Result<Vec<Resolved<'b>>> {
        let mut shadows: BTreeMap<u64, Shadow> = BTreeMap::new();
        let mut out = Vec::with_capacity(batch.ops.len());
        for op in &batch.ops {
            let group = op.group();
            let committed = self.groups.get(&group);
            let s = shadows
                .entry(group)
                .or_insert_with(|| Shadow::new(committed));
            out.extend(s.resolve(group, op, committed)?);
        }
        Ok(out)
    }

    /// Creates segment `id` holding its header and a snapshot of all groups' metadata, makes it
    /// durable (data and directory entry), and makes it the active segment.
    fn create_segment(&mut self, id: u64) -> Result<()> {
        let mut record = Vec::new();
        let mut b = RecordBuilder::new(&mut record);
        for (&group, g) in &self.groups {
            b.set_state(group, &g.meta);
        }
        b.finish().map_err(LogStoreError::corruption)?;
        // The DEK is durable in the registry before the file exists, so every durable
        // encrypted segment has its key (storage-engine.md §7). A DEK left for this id by an
        // interrupted creation protects no data (its segment never got past the plaintext
        // head) and is replaced by a fresh one.
        let cipher = match self.options.encryption.as_deref() {
            Some(keys) if keys.file_numbers().contains(&id) => Some(keys.replace_file_cipher(id)),
            Some(keys) => Some(keys.new_file_cipher(id)),
            None => None,
        };
        // A failed registry rewrite leaves the old or the new registry (atomic rename); like a
        // failed segment creation, the store refuses writes until reopened.
        let cipher = cipher.transpose().inspect_err(|_| self.poisoned = true)?;
        let mut bytes = segment_header(id, cipher.is_some()).to_vec();
        bytes.extend_from_slice(&record);
        let path = segment_path(&self.dir, id);
        // The snapshot must be durable, name included, before anything is written to this
        // segment: older segments may be deleted as soon as it exists, and they would take the
        // only copy of the metadata with them.
        let created = (|| -> std::io::Result<Box<dyn File>> {
            let mut file = self.fs.open(&path, OpenMode::CreateNew)?;
            file.append(&bytes)?;
            file.sync_data()?;
            self.fs.sync_dir(&self.dir)?;
            Ok(file)
        })();
        match created {
            Ok(file) => {
                self.segments.insert(
                    id,
                    Segment {
                        file,
                        size: bytes.len() as u64,
                        cipher,
                        written: BTreeMap::new(),
                    },
                );
                self.active = id;
                self.active_head_len = bytes.len() as u64;
                Ok(())
            }
            Err(e) => {
                // A partial segment file may exist; recovery removes or repairs it.
                self.poisoned = true;
                Err(e.into())
            }
        }
    }

    /// Deletes the oldest segments while they hold no live entry. Oldest first, with a directory
    /// sync after each: the surviving segments then always form a contiguous id range, which
    /// recovery checks to detect a lost segment.
    ///
    /// The archive floor ([`LogStoreOptions::archive_floor`]) stops the pass at the first
    /// segment not yet archived: deleting it would leave a hole in the archived WAL that no
    /// later copy can fill (PD-066). Stopping (rather than skipping it) keeps contiguity.
    fn delete_obsolete_segments(&mut self) {
        // One load per pass: a floor raised meanwhile is honoured at the next pass.
        let floor = self
            .options
            .archive_floor
            .as_ref()
            .map(|f| f.load(Ordering::Acquire));
        while let Some((&oldest, _)) = self.segments.first_key_value() {
            if oldest == self.active
                || self.counts.get(&oldest).is_some_and(|&n| n > 0)
                || floor.is_some_and(|f| oldest > f)
            {
                break;
            }
            let path = segment_path(&self.dir, oldest);
            if let Err(e) = self.fs.remove_file(&path) {
                tracing::warn!(segment = oldest, error = %e, "cannot delete obsolete raft log segment");
                break;
            }
            let removed = self.segments.remove(&oldest);
            self.counts.remove(&oldest);
            if let Err(e) = self.fs.sync_dir(&self.dir) {
                // The next deletion waits for a successful sync (contiguity, above).
                tracing::warn!(segment = oldest, error = %e, "cannot sync raft log directory");
                break;
            }
            self.forget_deleted(oldest, removed.is_some_and(|s| s.cipher.is_some()));
        }
    }

    /// Registry upkeep after segment `id` was deleted (module docs, "Encryption"): its DEK is
    /// forgotten (crypto-shredding: a leftover copy of the file becomes unreadable), and the
    /// plaintext admission is dropped once no plaintext segment is left. Deletion is oldest
    /// first and plaintext segments are older than every encrypted one, so dropping the
    /// admission with an encrypted segment's DEK is always correct. A failure only leaves an
    /// unused entry, cleaned at the next open.
    fn forget_deleted(&self, id: u64, encrypted: bool) {
        let Some(keys) = self.options.encryption.as_deref() else {
            return;
        };
        let result = if encrypted {
            keys.forget(&[id])
        } else if keys.admitted_plaintext_manifest().is_some()
            && self.segments.values().all(|s| s.cipher.is_some())
        {
            keys.forget(&[])
        } else {
            Ok(())
        };
        if let Err(e) = result {
            tracing::warn!(segment = id, error = %e, "cannot drop the DEK of a deleted raft log segment");
        }
    }

    fn group(&self, group: u64) -> GroupMeta {
        self.groups
            .get(&group)
            .map_or_else(GroupMeta::default, |g| g.meta)
    }

    /// First stored index of `group` (1 for an unknown group).
    #[must_use]
    pub fn first_index(&self, group: u64) -> u64 {
        self.group(group).first_index
    }

    /// Last stored index of `group` (`first_index - 1` when its log is empty).
    #[must_use]
    pub fn last_index(&self, group: u64) -> u64 {
        self.group(group).last_index
    }

    /// Term of `last_index(group)`.
    #[must_use]
    pub fn last_term(&self, group: u64) -> u64 {
        self.group(group).last_term
    }

    /// Latest persisted hard state of `group`.
    #[must_use]
    pub fn hard_state(&self, group: u64) -> HardState {
        self.group(group).hard_state
    }

    /// Term of entry `index` of `group`; `first_index - 1` (the last purged entry or the
    /// snapshot index) is answered too.
    ///
    /// # Errors
    /// [`LogStoreError::OutOfRange`] for any other index outside the stored log.
    pub fn term(&self, group: u64, index: u64) -> Result<u64> {
        self.groups
            .get(&group)
            .and_then(|g| g.term(index))
            .or_else(|| (index == 0 && !self.groups.contains_key(&group)).then_some(0))
            .ok_or_else(|| self.out_of_range(group, index))
    }

    fn out_of_range(&self, group: u64, index: u64) -> LogStoreError {
        let m = self.group(group);
        LogStoreError::OutOfRange {
            group,
            index,
            first_index: m.first_index,
            last_index: m.last_index,
        }
    }

    /// Entries `lo..hi` of `group`.
    ///
    /// # Errors
    /// [`LogStoreError::InvalidArgument`] if `lo > hi`; [`LogStoreError::OutOfRange`] if the range
    /// is not within `first_index..=last_index`; I/O errors.
    pub fn entries(&self, group: u64, lo: u64, hi: u64) -> Result<Vec<Entry>> {
        if lo > hi {
            return Err(LogStoreError::invalid(format!("entry range {lo}..{hi}")));
        }
        let mut out = Vec::with_capacity(usize::try_from(hi - lo).unwrap_or(0).min(1 << 16));
        for index in lo..hi {
            let loc = self
                .groups
                .get(&group)
                .and_then(|g| g.loc(index))
                .ok_or_else(|| self.out_of_range(group, index))?;
            let seg = self.segments.get(&loc.segment).ok_or_else(|| {
                LogStoreError::corruption(format!(
                    "group {group} entry {index} points to missing segment {}",
                    loc.segment
                ))
            })?;
            let mut payload = vec![0u8; loc.len as usize];
            seg.file.read_exact_at(&mut payload, loc.offset)?;
            if let Some(cipher) = &seg.cipher {
                // Authenticated on every read: a damaged or substituted payload is corruption,
                // never returned (module docs, "Encryption").
                let counter = payload_counter(loc.offset).ok_or_else(|| {
                    LogStoreError::corruption(format!(
                        "group {group} entry {index}: offset {} beyond the nonce range",
                        loc.offset
                    ))
                })?;
                cipher
                    .open_in_place(counter, &payload_aad(group, index, loc.term), &mut payload)
                    .map_err(|e| match e {
                        StorageError::Corruption(m) => LogStoreError::corruption(format!(
                            "group {group} entry {index} in segment {}: {m}",
                            loc.segment
                        )),
                        other => other.into(),
                    })?;
            }
            out.push(Entry {
                index,
                term: loc.term,
                payload,
            });
        }
        Ok(out)
    }

    /// Ids of the groups with state, ascending.
    pub fn groups(&self) -> impl Iterator<Item = u64> + '_ {
        self.groups.keys().copied()
    }

    /// Ids of the segment files, ascending; the last one is active.
    #[must_use]
    pub fn segment_ids(&self) -> Vec<u64> {
        self.segments.keys().copied().collect()
    }

    /// Ids of the sealed segments (every segment but the active one), ascending: their files
    /// are final and will never be written again (module docs, "Backup hooks").
    #[must_use]
    pub fn sealed_segment_ids(&self) -> Vec<u64> {
        self.segments
            .keys()
            .copied()
            .filter(|&id| id != self.active)
            .collect()
    }

    /// The sealed segments, ascending by id, with what an archiver needs to copy each one: its
    /// path, size, format and the per-group index range of the entries written to it.
    #[must_use]
    pub fn sealed_segments(&self) -> Vec<SealedSegment> {
        self.segments
            .iter()
            .filter(|&(&id, _)| id != self.active)
            .map(|(&id, s)| SealedSegment {
                id,
                path: segment_path(&self.dir, id),
                size: s.size,
                encrypted: s.cipher.is_some(),
                entries: s.written.clone(),
            })
            .collect()
    }

    /// The wrapped DEK of segment `id` as the log's key registry holds it (FR-BKP-004,
    /// PD-066): what an archiver stores beside a copied v2 segment so that [`read_segment`] can
    /// decrypt it after the live segment and its DEK are gone. `None` for a plaintext store, a
    /// v1 segment or an unknown id. The DEK stays wrapped under the KEK (never in the clear).
    #[must_use]
    pub fn segment_key(&self, id: u64) -> Option<WrappedKey> {
        self.options.encryption.as_ref()?.wrapped_key(id)
    }

    /// Seals the active segment now by rolling over to a new one, so the entries written so far
    /// can be archived without waiting for the segment to fill (PD-066: a timer calling this
    /// every `backup.pitr.segment_interval` bounds the RPO). Returns the id of the segment just
    /// sealed, or `None` when the active segment holds no batch yet (rolling it would only
    /// produce empty segments on an idle store). Also runs a deletion pass.
    ///
    /// # Errors
    /// [`LogStoreError::Poisoned`] after an earlier failed write; I/O or key registry errors
    /// creating the new segment, after which the store is poisoned (as for a rollover in
    /// [`LogStore::write`]).
    pub fn force_roll(&mut self) -> Result<Option<u64>> {
        if self.poisoned {
            return Err(LogStoreError::Poisoned);
        }
        let sealed = self.active;
        let written = self
            .segments
            .get(&sealed)
            .is_some_and(|s| s.size > self.active_head_len);
        if !written {
            return Ok(None);
        }
        // Every batch in the active segment is already synced (write returns only after the
        // fsync), so the segment is complete the moment the next one exists.
        self.create_segment(sealed + 1)?;
        self.delete_obsolete_segments();
        Ok(Some(sealed))
    }

    /// Runs a deletion pass of obsolete segments without writing anything: after the archive
    /// floor was raised, this releases the segments it held. A poisoned store deletes nothing.
    pub fn delete_obsolete(&mut self) {
        if !self.poisoned {
            self.delete_obsolete_segments();
        }
    }
}
