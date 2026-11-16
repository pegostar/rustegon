// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Memtable flush: writes an immutable memtable to a new L0 SST and records it in the MANIFEST
//! (storage-engine.md §3, §9).
//!
//! Durability ordering (§9 fsync discipline), each step completing before the next starts:
//! 1. the SST is written and fsynced ([`SstWriter::finish`]);
//! 2. the directory is fsynced, so the SST's directory entry survives a crash. Without this a
//!    crash could keep the MANIFEST record but lose the file name, and the next open would refuse
//!    the store as corrupt (missing SST, §13);
//! 3. the version edit (new L0 file, `flushed_seqno`, `last_seqno`) is appended to the MANIFEST
//!    and fsynced ([`VersionSet::log_and_apply`]).
//!
//! Only after step 3 may the caller drop the memtable and let Raft truncate its log up to
//! `flushed_seqno`. A crash before step 3 leaves at most an unreferenced SST, which startup
//! orphan cleanup deletes; its file number is never reused because `VersionSet::open` scans the
//! directory.
//!
//! Encryption (§7): with `options.encryption` set, the SST's DEK is registered durably before
//! step 1 (`SstWriter::create`); a crash after that leaves an unused registry entry, dropped
//! with the orphan.
//!
//! Concurrency: the caller serialises flushes and compactions on the `VersionSet` (it is not
//! internally synchronised) and passes a memtable that no longer receives writes.

use std::path::Path;

use rustegon_sim_api::{File, FileSystem, OpenMode};

use crate::{
    error::{Result, StorageError},
    key::SeqNo,
    memtable::Memtable,
    sst::{SstWriter, SstWriterOptions},
    version::{FileMeta, VersionEdit, VersionSet, sst_file_name},
};

/// Level that flushes write to.
const FLUSH_LEVEL: usize = 0;

/// Flushes `memtable` to a new L0 SST in `dir` and durably installs it in `versions`.
///
/// `flushed_seqno` declares that every write with seqno <= it is now in SSTs; every entry of
/// `memtable` must have a seqno <= `flushed_seqno`. An empty memtable writes no file but still
/// advances `flushed_seqno` (through a file-less edit) when it is ahead of the recorded value.
///
/// Returns the metadata of the new file, or `None` when the memtable was empty.
///
/// In-flight output: the SST's file number is allocated here and is unreferenced until the
/// MANIFEST record is durable, so [`VersionSet::obsolete_files`] would report it while the
/// flush runs. No caller-visible number is needed for that: `versions` is borrowed mutably for
/// the whole call, so no `obsolete_files` can run on this set until the flush has either
/// installed the file or removed it. An engine that later moves the SST write outside that
/// borrow must allocate the number itself and pass it in `in_flight` until the edit is applied.
///
/// # Errors
/// [`StorageError::InvalidArgument`] if `flushed_seqno` is below the recorded
/// `versions.flushed_seqno()`, if the memtable holds a seqno above `flushed_seqno` (both checked
/// before any fsync) or if the version set refuses the edit; I/O errors. On any error the SST is
/// removed (best effort; a failed removal is logged and the orphan is deleted by startup
/// cleanup), except after a failed MANIFEST write: the record may then be durable, so the file
/// is left for the next open to keep (referenced) or report as obsolete (unreferenced). After
/// that error the set refuses further edits and its `obsolete_files` would wrongly list the
/// possibly referenced SST, so the caller must drop the set and reopen the store.
pub fn flush_memtable(
    fs: &dyn FileSystem,
    dir: &Path,
    versions: &mut VersionSet,
    memtable: &Memtable,
    options: &SstWriterOptions,
    flushed_seqno: SeqNo,
) -> Result<Option<FileMeta>> {
    // A regressing flushed seqno would be a caller bug (§9: it only moves forward, Raft truncates
    // its log up to it); reject it before allocating a file or touching the disk.
    if flushed_seqno < versions.flushed_seqno() {
        return Err(StorageError::InvalidArgument(format!(
            "flushed seqno {flushed_seqno} is below the recorded {}",
            versions.flushed_seqno()
        )));
    }
    if memtable.is_empty() {
        if flushed_seqno > versions.flushed_seqno() {
            versions.log_and_apply(VersionEdit {
                flushed_seqno: Some(flushed_seqno),
                last_seqno: Some(flushed_seqno),
                ..VersionEdit::default()
            })?;
        }
        return Ok(None);
    }

    let number = versions.new_file_number();
    let path = dir.join(sst_file_name(number));
    let file = fs.open(&path, OpenMode::CreateNew)?;
    // Best effort: a leftover is an orphan that startup cleanup deletes anyway (§9), but the
    // failure is logged so an accumulating leak is visible. Only the file number is logged.
    let remove = || {
        if let Err(e) = fs.remove_file(&path) {
            tracing::warn!(file_number = number, error = %e, "flush: failed to remove SST");
        }
    };

    let meta = match write_sst(fs, dir, file, memtable, options, number, flushed_seqno) {
        Ok(meta) => meta,
        Err(e) => {
            remove();
            return Err(e);
        }
    };
    let edit = VersionEdit {
        flushed_seqno: Some(flushed_seqno),
        last_seqno: Some(meta.largest_seqno.max(flushed_seqno)),
        added: vec![(FLUSH_LEVEL, meta.clone())],
        ..VersionEdit::default()
    };
    if let Err(e) = versions.log_and_apply(edit) {
        // An I/O error leaves the MANIFEST record possibly durable: deleting the file could turn
        // a valid store into one that references a missing SST.
        if !matches!(e, StorageError::Io(_)) {
            remove();
        }
        return Err(e);
    }
    Ok(Some(meta))
}

/// Steps 1 and 2 of the module-level ordering. The writer (and its file handle) is dropped on
/// return, so the caller can delete the file even on Windows.
fn write_sst(
    fs: &dyn FileSystem,
    dir: &Path,
    file: Box<dyn File>,
    memtable: &Memtable,
    options: &SstWriterOptions,
    number: u64,
    flushed_seqno: SeqNo,
) -> Result<FileMeta> {
    let mut writer = SstWriter::create(file, number, options.clone())?;
    // Checked during iteration, not on the finished file's properties, so a bad seqno costs no
    // SST fsync (`finish`).
    let mut max_seqno: SeqNo = 0;
    for entry in memtable.iter() {
        max_seqno = max_seqno.max(entry.key().seqno());
        writer.add(entry.key().as_bytes(), entry.value())?;
    }
    for tombstone in memtable.range_tombstones() {
        max_seqno = max_seqno.max(tombstone.seqno);
        writer.add_range_tombstone(tombstone)?;
    }
    if max_seqno > flushed_seqno {
        return Err(StorageError::InvalidArgument(format!(
            "memtable holds seqno {max_seqno} above flushed seqno {flushed_seqno}"
        )));
    }
    let info = writer.finish()?;
    let (Some(smallest), Some(largest)) = (info.smallest, info.largest) else {
        return Err(StorageError::InvalidArgument(
            "memtable was emptied during flush".into(),
        ));
    };
    fs.sync_dir(dir)?;
    Ok(FileMeta {
        number,
        size: info.file_size,
        smallest,
        largest,
        smallest_seqno: info.properties.min_seqno,
        largest_seqno: info.properties.max_seqno,
    })
}
