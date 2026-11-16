// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Checkpoints: a consistent, independently openable image of the LSM directory at one version
//! (storage-engine.md §10; FR-BKP-003 local snapshots, F29; TC-STO-007).
//!
//! # Contract with the engine
//! A checkpoint contains the SSTs of one version only; memtables are not part of it. The engine
//! flushes its memtables first when the image must include every acknowledged write (the
//! optional flush of §10), then, under its version-set lock, calls [`CheckpointSource::capture`]
//! and releases the lock; [`create_checkpoint`] runs without the lock while flushes and
//! compactions continue. The image then holds exactly the writes with seqno <=
//! [`CheckpointInfo::seqno`] (the flushed seqno): every SST of the version holds only such writes,
//! and every such write is in one of them.
//!
//! # Why the source can keep running
//! SSTs are immutable, so linking or copying them needs no coordination. The captured
//! `Arc<Version>` is what keeps them on disk: the version set counts every version still
//! referenced as live (`VersionSet::live_files`), so `delete_obsolete_files` cannot remove a
//! compaction input the checkpoint has not linked yet. The source MANIFEST is never copied (it
//! keeps growing); a fresh one is written holding a snapshot of the captured version.
//!
//! # Crash safety (§9 `fsync` discipline)
//! Order: create the target directory (and fsync its parent) → link or copy every SST (copies are
//! fsynced; linked inodes are already durable in the source) → fsync the target directory (the
//! SST names must be durable before a MANIFEST refers to them) → (encrypted) write the
//! checkpoint's DEK registry → write and fsync the MANIFEST → switch `CURRENT` (temp file, fsync,
//! rename, fsync directory). `CURRENT` is the commit point: a crash before it is durable leaves a
//! directory that `VersionSet::open` refuses (no `CURRENT`), a crash after it leaves a complete
//! checkpoint. A failed or interrupted checkpoint directory must be removed by the caller before
//! retrying, because the target must be empty.
//!
//! # Encrypted stores (§7, FR-BKP-003, PD-064)
//! The checkpoint is encrypted exactly like its source and carries its own DEK registry in
//! `<target>/`[`CHECKPOINT_KEYS_DIR`]`/registry.enc`, in the unchanged registry format, under the
//! source's KEK. It holds exactly the wrapped DEKs of the checkpoint's SSTs, copied byte for
//! byte from the source registry ([`KeyManager::export_subset`]: never unwrapped, so the
//! checkpoint opens with the store KEK and nothing else), plus a fresh DEK for the checkpoint's
//! own MANIFEST, which is encrypted like every MANIFEST of an encrypted store (a plaintext one
//! would be refused as a swapped-in MANIFEST at open). Both registry rewrites are durable
//! (temp + fsync + rename + fsync of the keys directory, whose own name is fsynced in the target)
//! before the MANIFEST is created, hence before `CURRENT`: a committed checkpoint is always
//! decryptable. Copying the registry, not linking it, is required: the source keeps rewriting
//! its registry and forgetting DEKs of files the checkpoint still holds. The pinned version keeps
//! the source from forgetting the DEKs being copied (it forgets only DEKs of files no live
//! version references). SSTs the store wrote before it switched to encryption have no DEK and
//! stay plaintext in the checkpoint, as in the source. To open the checkpoint, build its key
//! manager with `KeyManager::open(fs, &checkpoint_keys_dir(target), kek, rng)`.
//!
//! # Hard links vs copies
//! Hard links share the immutable SST inodes, so a checkpoint costs no data I/O. Where the file
//! system cannot link (Windows ReFS/FAT, Linux vfat, a target on another device, an inode at its
//! link limit, §10) each SST is copied and fsynced instead; any other link error is returned.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustegon_sim_api::{FileSystem, OpenMode};

use crate::{
    encryption::KeyManager,
    error::{Result, StorageError},
    key::SeqNo,
    version::{Version, VersionSet, create_dir_durable, sst_file_name, write_manifest_snapshot},
};

/// Read size of the copy fallback: large enough to amortise per-call overhead, small enough to
/// keep the buffer off the large-allocation path (1 MiB).
const COPY_CHUNK_BYTES: u64 = 1 << 20;

/// Subdirectory of a checkpoint of an encrypted store that holds its DEK registry (module docs,
/// "Encrypted stores"). Not a store file name, so the engine ignores it in the store directory.
pub const CHECKPOINT_KEYS_DIR: &str = "keys";

/// Directory of the DEK registry of the checkpoint in `target`, for `KeyManager::open`.
#[must_use]
pub fn checkpoint_keys_dir(target: &Path) -> PathBuf {
    target.join(CHECKPOINT_KEYS_DIR)
}

/// The state a checkpoint is made of, captured atomically from a [`VersionSet`].
///
/// Holding it pins the version's SSTs, and with them their DEKs in the source registry (module
/// docs, "Why the source can keep running").
#[derive(Debug, Clone)]
pub struct CheckpointSource {
    /// The version whose SSTs form the checkpoint.
    pub version: Arc<Version>,
    /// Largest seqno recorded by the source.
    pub last_seqno: SeqNo,
    /// All writes with seqno <= this value are in the version's SSTs.
    pub flushed_seqno: SeqNo,
    /// The source's key manager when it is encrypted at rest: the checkpoint then gets its own
    /// DEK registry copy (module docs, "Encrypted stores"); `None` for a plaintext store.
    pub encryption: Option<Arc<KeyManager>>,
}

impl CheckpointSource {
    /// Captures the current version and counters. Call it while the engine serialises version
    /// edits, so the counters belong to the captured version.
    #[must_use]
    pub fn capture(versions: &VersionSet) -> Self {
        Self {
            version: versions.current(),
            last_seqno: versions.last_seqno(),
            flushed_seqno: versions.flushed_seqno(),
            encryption: versions.encryption().cloned(),
        }
    }
}

/// What [`create_checkpoint`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointInfo {
    /// The image holds exactly the writes with seqno <= this value (the flushed seqno).
    pub seqno: SeqNo,
    /// Largest seqno recorded by the source when captured (writes above `seqno` were only in
    /// memtables and are not in the image).
    pub last_seqno: SeqNo,
    /// Number of SSTs in the checkpoint.
    pub file_count: usize,
    /// Bytes of the SSTs shared with the source through hard links.
    pub bytes_linked: u64,
    /// Bytes of the SSTs copied because the file system could not link them.
    pub bytes_copied: u64,
    /// Number of the checkpoint's MANIFEST.
    pub manifest_number: u64,
    /// Whether the checkpoint is encrypted; its DEK registry is then in
    /// [`checkpoint_keys_dir`]`(target)`.
    pub encrypted: bool,
}

/// Creates a checkpoint of `source` (SSTs in `source_dir`) in `target`, which must not exist or
/// be empty. See the module docs for the engine contract and the crash-safety order.
///
/// The DEK registry copy of an encrypted source is written through the source key manager's
/// file system (the store's), the SSTs and the MANIFEST through `fs`.
///
/// # Errors
/// [`StorageError::InvalidArgument`] if `target` is not empty or is `source_dir`; I/O errors and,
/// for an encrypted source, DEK registry errors (the partial directory is then left for the
/// caller to remove; it never opens as a store).
pub fn create_checkpoint(
    fs: &dyn FileSystem,
    source_dir: &Path,
    source: &CheckpointSource,
    target: &Path,
) -> Result<CheckpointInfo> {
    if target == source_dir {
        return Err(StorageError::InvalidArgument(
            "checkpoint target is the source directory".into(),
        ));
    }
    // Every newly created ancestor must survive a crash too, not just the target itself.
    create_dir_durable(fs, target)?;
    if !fs.read_dir(target)?.is_empty() {
        return Err(StorageError::InvalidArgument(format!(
            "checkpoint target {} is not empty",
            target.display()
        )));
    }

    let mut info = CheckpointInfo {
        seqno: source.flushed_seqno,
        last_seqno: source.last_seqno,
        file_count: 0,
        bytes_linked: 0,
        bytes_copied: 0,
        manifest_number: 0,
        encrypted: source.encryption.is_some(),
    };
    let mut max_number = 0;
    let mut numbers = Vec::new();
    for (_, file) in source.version.all_files() {
        let name = sst_file_name(file.number);
        let (from, to) = (source_dir.join(&name), target.join(&name));
        match fs.hard_link(&from, &to) {
            Ok(()) => info.bytes_linked += file.size,
            Err(e) if link_unsupported(&e) => info.bytes_copied += copy_file(fs, &from, &to)?,
            Err(e) => return Err(e.into()),
        }
        info.file_count += 1;
        max_number = max_number.max(file.number);
        numbers.push(file.number);
    }
    // §9: the SST names are durable before the MANIFEST refers to them.
    fs.sync_dir(target)?;

    // Encrypted source (module docs, "Encrypted stores"): the registry copy, with the DEKs of
    // exactly these SSTs, is durable here, before the MANIFEST/CURRENT commit point.
    // `export_subset` fsyncs `target` (the keys directory's name) and the keys directory.
    let keys = match &source.encryption {
        Some(source_keys) => {
            Some(source_keys.export_subset(&checkpoint_keys_dir(target), &numbers)?)
        }
        None => None,
    };

    // Above every SST number so the checkpoint never reuses one when it is opened and written to.
    info.manifest_number = max_number.max(1) + 1;
    // With `keys`, the MANIFEST's fresh DEK is registered (durably) before the file is created.
    write_manifest_snapshot(
        fs,
        target,
        info.manifest_number,
        &source.version,
        info.manifest_number + 1,
        source.last_seqno,
        source.flushed_seqno,
        keys.as_ref(),
    )?;
    Ok(info)
}

/// Whether a hard-link error means "this file system cannot link here" (copy instead) rather
/// than a real failure. Windows maps ReFS/FAT's `ERROR_NOT_SUPPORTED` / `ERROR_INVALID_FUNCTION`
/// to `Unsupported`/`InvalidInput` and a cross-volume link to `CrossesDevices`; Linux vfat
/// returns `EPERM` (normalized to `Unsupported` only after a probe link proves the directory
/// cannot link at all) and a cross-device link `EXDEV`.
// `StdFileSystem::hard_link` already normalizes the platform codes (EXDEV, EMLINK, EOPNOTSUPP,
// probe-confirmed vfat EPERM, ERROR_NOT_SUPPORTED, ERROR_INVALID_FUNCTION, ...) to `Unsupported`
// (rustegon-sim-api TC-STO-008), so a genuine permission or path error is reported instead of
// silently turning into a full data copy.
fn link_unsupported(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Unsupported | io::ErrorKind::CrossesDevices | io::ErrorKind::TooManyLinks
    )
}

/// Copies `from` to the new file `to` and fsyncs it; returns the bytes copied.
fn copy_file(fs: &dyn FileSystem, from: &Path, to: &Path) -> Result<u64> {
    let src = fs.open(from, OpenMode::Read)?;
    let size = src.size()?;
    let mut dst = fs.open(to, OpenMode::CreateNew)?;
    let mut buf = Vec::new();
    let mut offset = 0;
    while offset < size {
        let len = (size - offset).min(COPY_CHUNK_BYTES);
        // Lossless: bounded by COPY_CHUNK_BYTES.
        #[allow(clippy::cast_possible_truncation)]
        buf.resize(len as usize, 0);
        src.read_exact_at(&mut buf, offset)?;
        dst.append(&buf)?;
        offset += len;
    }
    dst.sync_data()?;
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_link_capability_errors_fall_back_to_copying() {
        for kind in [
            io::ErrorKind::Unsupported,
            io::ErrorKind::CrossesDevices,
            io::ErrorKind::TooManyLinks,
        ] {
            assert!(link_unsupported(&kind.into()), "{kind:?}");
        }
        // Real permission or path problems surface instead of silently copying all data
        // (platform "no hard links" codes arrive already normalized to `Unsupported`).
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::NotFound,
            io::ErrorKind::AlreadyExists,
            io::ErrorKind::StorageFull,
            io::ErrorKind::Other,
        ] {
            assert!(!link_unsupported(&kind.into()), "{kind:?}");
        }
    }
}
