// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Database backups stored as one `.dbck` file at a server-side destination (FR-BKP-007,
//! PD-226, PD-227): the GUI's "back up / restore one database". `Dump` and `LogicalRestore`
//! stream the files of a logical dump to and from the client (gRPC, `rustegon dump`); here the
//! server packs the same files into `<id>.dbck` at a destination it is allowed to use, as it
//! does for `.nbck` node backups (ADR-037, owner choice 2a), and restores from there.
//!
//! # Format
//! `<id>.dbck` (a [`BackupId`]) is the compressed single-file container of
//! [`rustegon_backup::archive`]: a ustar archive whose entries are `dumps/<id>/<path>` for every
//! file of the PD-067 dump layout, each one zstd frame, `dump.json` last. The file appears
//! atomically once complete, so a listed `.dbck` is always a whole dump.
//!
//! # Spool
//! Each dump file is compressed as it is produced into a spool file under the node's
//! `<data_dir>/dump-spool/<id>/` (created owner-only: it holds database contents); the archive
//! needs every compressed size before it is streamed to the destination. The spool holds the
//! compressed dump at most and is removed afterwards, also on failure.
//!
//! # Uploaded files
//! [`BackupService::restore_dump_upload`] restores a `.dbck` the client sends in the request
//! (the GUI's "restore from a file", PD-229): the bytes are written to an owner-only
//! `upload-<id>.dbck` in the same spool directory as they arrive (the archive is read with
//! random access, so it must be complete on disk first), then restored as a stored one and
//! removed, also on failure. At most [`MAX_UPLOAD_BYTES`] are accepted.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

pub use rustegon_backup::DUMPS_DIR;
use rustegon_backup::{
    ArchiveBuilder, ArchiveKind, BackupId, BakDestination, Destination, HlcTimestamp,
    LocalDestination, ObjectReader,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_security::audit::AuditEventKind;
use rustegon_sim_api::FileSystem;
use tokio::sync::mpsc;

use super::{
    Audited, BackupService, ChunkOrder, DUMP_CHUNK_BYTES, DumpChunk, DumpScope, DumpSink,
    DumpSource, LogicalRestoreOptions, LogicalRestoreSummary, op, open_existing,
};
use crate::{
    Completion,
    services::{
        RequestContext,
        backup_logical::{DUMP_MANIFEST, DumpManifest},
    },
};

/// Largest `dump.json` read (as `backup_logical`'s bound on JSON files).
const MAX_MANIFEST_BYTES: u64 = 64 << 20;

/// Largest `.dbck` accepted by [`BackupService::restore_dump_upload`] (64 GiB): it bounds the
/// disk an upload can fill; larger database backups are restored from a destination.
pub const MAX_UPLOAD_BYTES: u64 = 64 << 30;

/// Pieces of an uploaded `.dbck` in arrival order; an `Err` item (transport error) ends the
/// upload.
pub type UploadReceiver = mpsc::Receiver<Result<Vec<u8>, Error>>;
/// Sending half of [`upload_channel`].
pub type UploadSender = mpsc::Sender<Result<Vec<u8>, Error>>;

/// The bounded channel a transport adapter feeds an upload into (back pressure on the client).
#[must_use]
pub fn upload_channel() -> (UploadSender, UploadReceiver) {
    mpsc::channel(8)
}

/// A complete database backup at a destination.
#[derive(Debug, Clone)]
pub struct StoredDump {
    /// Its id (`<id>.dbck`).
    pub dump_id: String,
    /// Its `dump.json`.
    pub manifest: DumpManifest,
}

/// Result of [`BackupService::list_dumps`].
#[derive(Debug)]
pub struct DumpListing {
    /// Complete database backups, oldest first.
    pub dumps: Vec<StoredDump>,
    /// `.dbck` files that cannot be used: `(id, why)`.
    pub unreadable: Vec<(String, Error)>,
}

fn manifest_key(id: &BackupId) -> String {
    format!("{}/{DUMP_MANIFEST}", ArchiveKind::Database.prefix(id))
}

/// Opens `<id>.dbck` at `dest`, checking it holds database backup `id`.
fn open_dbck(dest: &dyn Destination, id: &BackupId) -> Result<BakDestination, Error> {
    let key = ArchiveKind::Database.key(id);
    let archive = BakDestination::open(dest, &key)?;
    if archive.kind() != ArchiveKind::Database || archive.backup_id() != id {
        return Err(Error::new(
            ErrorCode::StorageCorruption,
            format!(
                "{key} holds {} backup {}",
                archive.kind().extension(),
                archive.backup_id()
            ),
        ));
    }
    Ok(archive)
}

fn read_manifest(archive: &BakDestination, id: &BackupId) -> Result<DumpManifest, Error> {
    let bytes = archive.get_bytes(&manifest_key(id), MAX_MANIFEST_BYTES)?;
    DumpManifest::parse(&bytes)
}

impl BackupService {
    /// The spool directory of database backups (module docs).
    fn spool_dir(&self) -> PathBuf {
        // shortcut: without a configured spool (tests, embedders) the system temporary
        // directory is used; `rustegond` always configures `<data_dir>/dump-spool`.
        self.spool
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("rustegon-dump-spool"))
    }

    /// Lists the `.dbck` database backups at `destination` (`backup` on `cluster`, as
    /// `ListBackups`).
    ///
    /// # Errors
    /// RGN-4001/4002, RGN-1001 (destination), RGN-1030 (no such local destination), RGN-3002.
    pub async fn list_dumps(
        &self,
        ctx: &RequestContext,
        destination: &str,
    ) -> Result<DumpListing, Error> {
        let sec = self.guard(ctx, "ListBackups").await?;
        let url = self
            .destination(sec, ctx, "ListBackups", destination)
            .await?;
        let fs = Self::fs(sec);
        let s3 = Arc::clone(&self.s3);
        self.deps
            .executor
            .run(ctx, Completion::Abandon, move |_| {
                let dest = open_existing(&url, fs, &s3)?;
                let mut out = DumpListing {
                    dumps: Vec::new(),
                    unreadable: Vec::new(),
                };
                for name in dest.list_children("")? {
                    let Some(id) = ArchiveKind::Database.id_of(&name) else {
                        continue;
                    };
                    let loaded = open_dbck(dest.as_ref(), &id)
                        .and_then(|archive| read_manifest(&archive, &id));
                    match loaded {
                        Ok(manifest) => out.dumps.push(StoredDump {
                            dump_id: id.as_str().to_owned(),
                            manifest,
                        }),
                        // The destination failing fails the listing; a bad file is reported.
                        Err(e) if e.code() == ErrorCode::Unavailable => return Err(e),
                        Err(e) => out.unreadable.push((id.as_str().to_owned(), e)),
                    }
                }
                // Ids start with their UTC time: name order is creation order.
                out.dumps.sort_by(|a, b| a.dump_id.cmp(&b.dump_id));
                Ok(out)
            })
            .await
    }

    /// Dumps `scope` into a new `<id>.dbck` at `destination` (backend operation, `backup` on
    /// `cluster` as `Dump`). Audited as a `backup` event with `details.op = dump`.
    ///
    /// # Errors
    /// RGN-4001/4002/4003, RGN-1001 (destination), RGN-1030 (a named database does not exist),
    /// the backend's and the destination's errors. A failed dump stores nothing.
    pub async fn create_dump(
        &self,
        ctx: &RequestContext,
        destination: &str,
        scope: DumpScope,
    ) -> Result<StoredDump, Error> {
        let sec = self.guard(ctx, "Dump").await?;
        Self::admin_op(sec, ctx)?;
        let url = self.destination(sec, ctx, "Dump", destination).await?;
        let now = self.deps.clock.wall();
        let id = BackupId::generate(now, self.deps.rng.as_ref()).map_err(Error::from)?;
        let audited = Audited::start(
            sec,
            ctx,
            AuditEventKind::Backup,
            op::DUMP,
            format!("{url} {} {}", id.as_str(), scope.describe()),
        )
        .await?;
        let fs = Self::fs(sec);
        let s3 = Arc::clone(&self.s3);
        let backend = Arc::clone(&self.backend);
        let spool = self.spool_dir().join(id.as_str());
        let mtime = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |cancel| {
                // Opening creates a missing local destination, as for a backup.
                let dest = rustegon_backup::open_destination(&url, Arc::clone(&fs), &s3)
                    .map_err(Error::from)?;
                let builder =
                    ArchiveBuilder::new(fs.as_ref(), &spool, ArchiveKind::Database, id.clone())?;
                let mut sink = ArchiveSink {
                    builder,
                    order: ChunkOrder::default(),
                    started: false,
                    open: false,
                    manifest: Vec::new(),
                };
                // On any error the builder is dropped, which removes the spool.
                backend.dump(&scope, &mut sink, cancel)?;
                sink.finish()?;
                let manifest = DumpManifest::parse(&sink.manifest)?;
                sink.builder.store(dest.as_ref(), mtime)?;
                Ok(StoredDump {
                    dump_id: id.as_str().to_owned(),
                    manifest,
                })
            })
            .await;
        audited
            .end(ctx, &result, |d| {
                vec![
                    ("dump_id", d.dump_id.clone()),
                    ("databases", d.manifest.databases.len().to_string()),
                ]
            })
            .await;
        result
    }

    /// Restores database backup `dump_id` at `destination` into this node (backend operation,
    /// `restore` on `cluster` as `LogicalRestore`, with its rules: an existing target collection
    /// is RGN-1031 unless `drop_existing`). Audited as a `restore` event with `details.op =
    /// logical_restore`.
    ///
    /// # Errors
    /// RGN-4001/4002/4003, RGN-1001 (destination, id, malformed dump), RGN-1030 (no such
    /// `.dbck`, or a scope name the dump does not hold), RGN-1031, RGN-5002, RGN-5007.
    pub async fn restore_dump(
        &self,
        ctx: &RequestContext,
        destination: &str,
        dump_id: &str,
        options: LogicalRestoreOptions,
    ) -> Result<LogicalRestoreSummary, Error> {
        let sec = self.guard(ctx, "LogicalRestore").await?;
        Self::admin_op(sec, ctx)?;
        let url = self
            .destination(sec, ctx, "LogicalRestore", destination)
            .await?;
        let id =
            BackupId::parse(dump_id).map_err(|e| Error::from(e).with_detail("field", "dump_id"))?;
        let audited = Audited::start(
            sec,
            ctx,
            AuditEventKind::Restore,
            op::LOGICAL_RESTORE,
            format!("{url} {} {}", id.as_str(), options.scope.describe()),
        )
        .await?;
        let fs = Self::fs(sec);
        let s3 = Arc::clone(&self.s3);
        let backend = Arc::clone(&self.backend);
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |cancel| {
                let dest = open_existing(&url, fs, &s3)?;
                if !dest.exists(&ArchiveKind::Database.key(&id))? {
                    return Err(Error::new(
                        ErrorCode::NotFound,
                        format!("no database backup {} at {}", id.as_str(), dest.describe()),
                    )
                    .with_detail("field", "dump_id"));
                }
                let archive = open_dbck(dest.as_ref(), &id)?;
                let mut source = ArchiveSource::open(&archive, &id)?;
                backend.logical_restore(&options, &mut source, cancel)
            })
            .await;
        audited
            .end(ctx, &result, |s| {
                vec![("collections", s.collections.len().to_string())]
            })
            .await;
        result
    }
}

impl BackupService {
    /// Restores the `.dbck` received through `bytes` into this node (module docs, "Uploaded
    /// files"): everything it holds, existing target collections dropped first when
    /// `drop_existing` (else RGN-1031). Access and audit as [`Self::restore_dump`].
    ///
    /// # Errors
    /// RGN-4001/4002/4003; RGN-1001 (larger than [`MAX_UPLOAD_BYTES`], not a database backup);
    /// RGN-5002 (not a well-formed `.dbck`), RGN-5007, RGN-1031; the backend's errors.
    pub async fn restore_dump_upload(
        &self,
        ctx: &RequestContext,
        drop_existing: bool,
        bytes: UploadReceiver,
    ) -> Result<LogicalRestoreSummary, Error> {
        let sec = self.guard(ctx, "LogicalRestore").await?;
        Self::admin_op(sec, ctx)?;
        let audited = Audited::start(
            sec,
            ctx,
            AuditEventKind::Restore,
            op::LOGICAL_RESTORE,
            "uploaded .dbck *".to_owned(),
        )
        .await?;
        let fs = Self::fs(sec);
        let backend = Arc::clone(&self.backend);
        let spool = self.spool_dir();
        // Unique per upload; the id form keeps the name a valid destination key.
        let name = BackupId::generate(self.deps.clock.wall(), self.deps.rng.as_ref())
            .map(|id| {
                format!(
                    "upload-{}.{}",
                    id.as_str(),
                    ArchiveKind::Database.extension()
                )
            })
            .map_err(Error::from);
        let result = match name {
            Err(e) => Err(e),
            Ok(name) => {
                self.deps
                    .executor
                    .run(ctx, Completion::Await, move |cancel| {
                        let _upload = Upload::receive(fs.as_ref(), &spool, &name, bytes, cancel)?;
                        let dir = LocalDestination::open(Arc::clone(&fs), &spool)?;
                        let archive = BakDestination::open(&dir, &name)?;
                        if archive.kind() != ArchiveKind::Database {
                            return Err(Error::new(
                                ErrorCode::InvalidArgument,
                                format!(
                                    "the file is a .{} backup, not a database backup (.dbck)",
                                    archive.kind().extension()
                                ),
                            ));
                        }
                        let id = archive.backup_id().clone();
                        let mut source = ArchiveSource::open(&archive, &id)?;
                        let options = LogicalRestoreOptions {
                            drop_existing,
                            scope: DumpScope::default(),
                        };
                        backend.logical_restore(&options, &mut source, cancel)
                    })
                    .await
            }
        };
        audited
            .end(ctx, &result, |s| {
                vec![("collections", s.collections.len().to_string())]
            })
            .await;
        result
    }
}

/// An uploaded `.dbck` written to the spool; removed when dropped.
struct Upload<'a> {
    fs: &'a dyn FileSystem,
    path: PathBuf,
}

impl<'a> Upload<'a> {
    /// Writes every piece of `bytes` to the new owner-only file `<spool>/<name>`.
    fn receive(
        fs: &'a dyn FileSystem,
        spool: &Path,
        name: &str,
        mut bytes: UploadReceiver,
        cancel: &dyn crate::services::backup_logical::CancelCheck,
    ) -> Result<Self, Error> {
        let local = |op: &'static str, path: &Path, e: std::io::Error| {
            Error::from(rustegon_backup::BackupError::Local {
                op,
                path: path.display().to_string(),
                source: e,
            })
        };
        fs.create_dir_all(spool)
            .map_err(|e| local("create", spool, e))?;
        let path = spool.join(name);
        let mut file = fs
            .create_new_private(&path)
            .map_err(|e| local("create", &path, e))?;
        // From here on the file is removed on every exit.
        let upload = Self { fs, path };
        let mut size = 0u64;
        while let Some(piece) = bytes.blocking_recv() {
            cancel.check()?;
            let piece = piece?;
            size += piece.len() as u64;
            if size > MAX_UPLOAD_BYTES {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("the uploaded file is larger than {MAX_UPLOAD_BYTES} bytes"),
                ));
            }
            file.append(&piece)
                .map_err(|e| local("write", &upload.path, e))?;
        }
        file.sync_data()
            .map_err(|e| local("sync", &upload.path, e))?;
        Ok(upload)
    }
}

impl Drop for Upload<'_> {
    fn drop(&mut self) {
        let _ = self.fs.remove_file(&self.path);
    }
}

/// [`DumpSink`] compressing each dump file into the archive being built (module docs).
struct ArchiveSink<'a> {
    builder: ArchiveBuilder<'a>,
    order: ChunkOrder,
    started: bool,
    /// An archive entry is open.
    open: bool,
    /// The bytes of `dump.json`, kept to describe the stored dump.
    manifest: Vec<u8>,
}

impl ArchiveSink<'_> {
    fn finish(&self) -> Result<(), Error> {
        if !self.started {
            return Err(Error::new(
                ErrorCode::Internal,
                "the dump backend finished without announcing its timestamp",
            ));
        }
        self.order
            .finish()
            .map_err(|e| Error::new(ErrorCode::Internal, e.message().to_owned()))
    }
}

impl DumpSink for ArchiveSink<'_> {
    fn started(&mut self, _timestamp: HlcTimestamp) -> Result<(), Error> {
        if self.started {
            return Err(Error::new(
                ErrorCode::Internal,
                "the dump backend announced its timestamp twice",
            ));
        }
        self.started = true;
        Ok(())
    }

    fn chunk(&mut self, chunk: DumpChunk) -> Result<(), Error> {
        if !self.started {
            return Err(Error::new(
                ErrorCode::Internal,
                "the dump backend sent a chunk before its timestamp",
            ));
        }
        // A backend bug is an internal error, not the client's invalid argument.
        self.order
            .check(&chunk)
            .map_err(|e| Error::new(ErrorCode::Internal, e.message().to_owned()))?;
        if !self.open {
            self.builder.start(&chunk.path)?;
            self.open = true;
        }
        self.builder.write(&chunk.data)?;
        if chunk.path == DUMP_MANIFEST {
            self.manifest.extend_from_slice(&chunk.data);
        }
        if chunk.end_of_file {
            self.builder.finish_entry()?;
            self.open = false;
        }
        Ok(())
    }
}

/// [`DumpSource`] reading a `.dbck` in the order a restore expects: every file in byte order of
/// its path, `dump.json` last (backup-restore.md "Logical dump format v1").
struct ArchiveSource<'a> {
    archive: &'a BakDestination,
    prefix: String,
    files: VecDeque<String>,
    /// The file being sent: path, reader, bytes already sent.
    current: Option<(String, Box<dyn ObjectReader>, u64)>,
}

impl<'a> ArchiveSource<'a> {
    fn open(archive: &'a BakDestination, id: &BackupId) -> Result<Self, Error> {
        let dir = ArchiveKind::Database.prefix(id);
        let prefix = format!("{dir}/");
        let mut files: Vec<String> = archive
            .list(&dir)?
            .into_iter()
            .filter_map(|k| k.strip_prefix(&prefix).map(str::to_owned))
            .collect();
        if !files.iter().any(|f| f == DUMP_MANIFEST) {
            return Err(Error::new(
                ErrorCode::StorageCorruption,
                format!("database backup {} has no {DUMP_MANIFEST}", id.as_str()),
            ));
        }
        files.retain(|f| f != DUMP_MANIFEST);
        files.sort();
        files.push(DUMP_MANIFEST.to_owned());
        Ok(Self {
            archive,
            prefix,
            files: files.into(),
            current: None,
        })
    }
}

impl DumpSource for ArchiveSource<'_> {
    fn next_chunk(&mut self) -> Result<Option<DumpChunk>, Error> {
        if self.current.is_none() {
            let Some(path) = self.files.pop_front() else {
                return Ok(None);
            };
            let reader = self.archive.open(&format!("{}{path}", self.prefix))?;
            self.current = Some((path, reader, 0));
        }
        let Some((path, reader, sent)) = self.current.as_mut() else {
            return Ok(None);
        };
        let size = reader.size();
        let len = usize::try_from((size - *sent).min(DUMP_CHUNK_BYTES as u64))
            .map_err(|_| Error::new(ErrorCode::Internal, "chunk length overflow"))?;
        let mut data = vec![0u8; len];
        reader.read_exact_at(&mut data, *sent)?;
        *sent += len as u64;
        let chunk = DumpChunk {
            path: path.clone(),
            data,
            end_of_file: *sent == size,
        };
        if chunk.end_of_file {
            self.current = None;
        }
        Ok(Some(chunk))
    }
}
