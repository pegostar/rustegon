// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Downloading a backup's files into an empty directory (FR-BKP-001 restore, single-node scope;
//! PD-062: offline, in the CLI, with the server stopped).
//!
//! This is the file-level half of a restore: it reproduces the backup's tree (`lsm/…`,
//! `keys/registry.enc`) under the target with every file checked against the manifest while it
//! streams. Unwrapping the DEK registry with the KEK and bootstrapping the Raft log at the
//! manifest's applied index/term belong to the caller, which gets the [`Manifest`] for that.
//!
//! Each file is written atomically (temp name, fsync, rename, directory fsync) and renamed only
//! after its size and BLAKE3 matched, so a corrupt file never appears under its real name. A
//! failed restore leaves the files restored so far; the target is then not empty, so a retry
//! needs an empty (wiped) target again — a half-restored directory is never mistaken for a
//! finished one.

use std::{io, path::Path, sync::Arc};

use rustegon_sim_api::FileSystem;

use crate::{
    dest::{CHUNK_BYTES, Destination, ObjectReader, join_key, local::LocalDestination},
    error::{BackupError, Result},
    id::BackupId,
    manifest::{FileEntry, Manifest},
    verify::{load_manifest_in, open_backup},
    writer::backup_prefix,
};

/// Restores the files of backup `id` from `dest` into `target_dir` of `fs` and returns the
/// backup's manifest. `target_dir` must be empty or absent (it is created).
///
/// # Errors
/// [`BackupError::TargetNotEmpty`] when the target has entries; as
/// [`crate::verify::load_manifest`] for a missing, incomplete, newer or corrupt backup;
/// [`BackupError::Corrupt`] when a file is missing or does not match its size or checksum;
/// [`BackupError::Destination`] when the destination fails; [`BackupError::Local`] when the
/// target cannot be written.
pub fn restore_files(
    dest: &dyn Destination,
    id: &BackupId,
    fs: Arc<dyn FileSystem>,
    target_dir: &Path,
) -> Result<Manifest> {
    match fs.read_dir(target_dir) {
        Ok(entries) if entries.is_empty() => {}
        Ok(_) => {
            return Err(BackupError::TargetNotEmpty {
                path: target_dir.display().to_string(),
            });
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(BackupError::local("list", target_dir, e)),
    }
    let source = open_backup(dest, id)?;
    let dest = source.destination();
    let manifest = load_manifest_in(dest, id)?;
    // The target is written through the directory destination: it has exactly the atomic,
    // durable put this needs, and keys are the manifest's validated relative paths.
    let target = LocalDestination::open(fs, target_dir).map_err(|e| to_local(e, target_dir))?;
    let prefix = backup_prefix(id);
    for file in &manifest.files {
        restore_file(dest, &target, id, &join_key(&[&prefix, &file.path]), file)?;
    }
    tracing::info!(
        backup_id = %id,
        files = manifest.files.len(),
        bytes = manifest.total_bytes(),
        target = %target_dir.display(),
        "backup files restored"
    );
    Ok(manifest)
}

fn restore_file(
    dest: &dyn Destination,
    target: &LocalDestination,
    id: &BackupId,
    key: &str,
    file: &FileEntry,
) -> Result<()> {
    let corrupt = |reason: String| BackupError::corrupt(id.as_str(), &file.path, reason);
    let reader = match dest.open(key) {
        Ok(reader) => reader,
        Err(BackupError::ObjectNotFound { .. }) => return Err(corrupt("missing".into())),
        Err(e) => return Err(e),
    };
    if reader.size() != file.size {
        return Err(corrupt(format!(
            "size {} but the manifest records {}",
            reader.size(),
            file.size
        )));
    }
    let mut download = Download {
        reader: reader.as_ref(),
        entry: file,
        offset: 0,
        hasher: blake3::Hasher::new(),
        failure: None,
    };
    target
        .put_reader(&file.path, file.size, &mut download)
        .map_err(|err| match download.failure.take() {
            // The source side failed or the data did not match: report that, not the write.
            Some(Failure::Source(e)) => e,
            Some(Failure::Checksum) => corrupt("BLAKE3 checksum mismatch".into()),
            None => to_local(err, target.root()),
        })
}

/// Why a [`Download`] stopped the target write.
enum Failure {
    Source(BackupError),
    Checksum,
}

/// Pull reader from a destination object that hashes as it goes and fails the read after the
/// last byte when the hash does not match: the target put probes for one more byte before it
/// syncs and renames, so a corrupt file is never committed under its name.
struct Download<'a> {
    reader: &'a dyn ObjectReader,
    entry: &'a FileEntry,
    offset: u64,
    hasher: blake3::Hasher,
    failure: Option<Failure>,
}

impl io::Read for Download<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.entry.size - self.offset;
        if remaining == 0 {
            if self.hasher.finalize().to_hex().as_str() != self.entry.blake3 {
                self.failure = Some(Failure::Checksum);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "checksum mismatch",
                ));
            }
            return Ok(0);
        }
        let n = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()).min(CHUNK_BYTES));
        if let Err(e) = self.reader.read_exact_at(&mut buf[..n], self.offset) {
            self.failure = Some(Failure::Source(e));
            return Err(io::Error::other("reading the backup object failed"));
        }
        self.hasher.update(&buf[..n]);
        self.offset += n as u64;
        Ok(n)
    }
}

/// Errors of the target directory are local errors, not a destination outage.
fn to_local(err: BackupError, target: &Path) -> BackupError {
    match err {
        BackupError::Destination { op, source, .. } => BackupError::local(op, target, source),
        other => other,
    }
}
