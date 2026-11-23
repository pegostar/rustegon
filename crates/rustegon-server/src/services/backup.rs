// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `BackupService`: single-node backups, local snapshots and logical dump/restore (backup.proto,
//! backup-restore.md "Single-node scope"; FR-BKP-001/003/004/006/007; PD-062, PD-077).
//!
//! # Split between this service and the backend
//! The service owns everything that is the same whatever the engine does: authorization (the
//! rules of [`crate::security::RPC_ACCESS`], checked again here so REST and gRPC authorize
//! identically), the `admin_op` rate limit, argument validation, destination handling, audit
//! records (`backup` / `restore`, one at the start — written before the operation, so an
//! operation that cannot be audited does not run — and one at the end with the outcome), and the
//! streaming plumbing between async transports and the blocking engine.
//!
//! What needs the engine — the PD-063 consistency fence and checkpoint, snapshots, the scan at T
//! of a dump, the import of a logical restore — is behind [`BackupBackend`], implemented in
//! M13a wave 2 (lanes BE and BG) on lane BD's engine primitives. Until a backend is installed
//! ([`crate::services::Services::with_backup_backend`]) those operations fail with
//! [`not_implemented`]. Listing, describing and verifying backups need only `rustegon-backup`
//! and a destination, and are served for real.
//!
//! # Destinations on the server
//! A server-side destination is parsed with [`DestinationUrl`]; a local path must be absolute
//! (a relative path would silently depend on the server's working directory). Read-only
//! operations never create a missing local destination (`RGN-1030` instead): opening a
//! directory destination creates it, and a caller with `backup` must not be able to create
//! directories on the server by listing them. Every destination access runs on the executor's
//! blocking pool (destinations are synchronous by design, `rustegon_backup::dest`).
//!
//! Every server-side destination must also pass the node's allowlist
//! (`backup.allowed_destinations` plus `<data_dir>/backups`, [`DestinationPolicy`], PD-082)
//! before anything is opened: otherwise the `backup` privilege would let its holder make the
//! server read and write wherever the service account can. A refusal is RGN-4002 with
//! `details.reason = destination_not_allowed` and is audited as `privilege_denied`. A service
//! without an installed policy refuses every destination.

use std::{
    collections::BTreeSet,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::SystemTime,
};

use rustegon_backup::{
    BackupError, BackupId, Consistency, Destination, DestinationPolicy, DestinationUrl,
    HlcTimestamp, ListedBackup, Manifest, S3Settings, VerifyMode, VerifyReport, validate_key,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_security::{
    audit::{AuditEventKind, AuditOutcome},
    ratelimit::LimitClass,
};
use rustegon_sim_api::FileSystem;
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::Stream;

use super::{RequestContext, ServiceDeps, Warning, cancelled, unauthenticated};

mod server_dump;
use crate::{
    CancelToken, Completion,
    security::{Security, access_of},
};
pub use server_dump::{
    DUMPS_DIR, DumpListing, MAX_UPLOAD_BYTES, StoredDump, UploadReceiver, UploadSender,
    upload_channel,
};

/// Largest chunk of a dump file the service accepts in a logical restore (bytes). Backends
/// should send chunks of [`DUMP_CHUNK_BYTES`].
pub const MAX_DUMP_CHUNK_BYTES: usize = 4 << 20;

/// Recommended size of the chunks a backend produces in a dump (bytes): large enough to
/// amortise per-message overhead, far below the gRPC message limit.
pub const DUMP_CHUNK_BYTES: usize = 1 << 20;

/// Messages buffered between a dump backend and the response stream: the backend may run at
/// most this far ahead of a slow client (back pressure through the bounded channel).
const DUMP_BUFFER: usize = 4;

/// Chunks buffered between the request stream of a logical restore and the backend.
const RESTORE_BUFFER: usize = 4;

/// `ErrorDetail.details.reason` of [`not_implemented`].
pub const NOT_IMPLEMENTED_REASON: &str = "not_implemented";

/// The error of an operation whose engine part is not in this build yet (PD-077): RGN-5007
/// `VersionIncompatible` (gRPC `FAILED_PRECONDITION`, HTTP 400, not retryable) with
/// `details.reason = not_implemented` and `details.operation`. The catalog has no
/// "unimplemented" code; 5007 says "this server version cannot do that", which is exactly the
/// situation, and a client must not retry it.
#[must_use]
pub fn not_implemented(operation: &str) -> Error {
    Error::new(
        ErrorCode::VersionIncompatible,
        format!("{operation} is not available in this server build yet"),
    )
    .with_detail("reason", NOT_IMPLEMENTED_REASON)
    .with_detail("operation", operation)
}

// ---------------------------------------------------------------------------------------------
// Types shared with the backend
// ---------------------------------------------------------------------------------------------

/// A backup written by [`BackupBackend::create_backup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedBackup {
    /// Its manifest (as written to the destination).
    pub manifest: Manifest,
    /// Non-fatal conditions (e.g. a plaintext backup of a plaintext store, PD-064).
    pub warnings: Vec<Warning>,
}

/// A validated snapshot name: 1–64 characters `[A-Za-z0-9._-]`, not starting with `.` (the
/// rule of backup ids, so a name is always a safe directory name).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotName(String);

impl SnapshotName {
    /// Validates `name`.
    ///
    /// # Errors
    /// RGN-1001 (`details.field = name`).
    pub fn parse(name: &str) -> Result<Self, Error> {
        let ok = !name.is_empty()
            && name.len() <= 64
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if ok {
            Ok(Self(name.to_owned()))
        } else {
            Err(invalid(
                "name",
                "a snapshot name has 1 to 64 characters [A-Za-z0-9._-] and does not start with '.'",
            ))
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A local snapshot (FR-BKP-003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    /// Name.
    pub name: String,
    /// Creation time.
    pub created_at: SystemTime,
    /// Consistency point of the snapshot.
    pub consistency: Consistency,
    /// Number of files.
    pub file_count: u64,
    /// Total size of the files (bytes; shared with the store through hard links).
    pub total_bytes: u64,
}

/// What a dump or a logical restore covers. Empty lists mean "everything".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DumpScope {
    /// Databases.
    pub databases: Vec<String>,
    /// Collections as `(database, collection)`.
    pub collections: Vec<(String, String)>,
}

impl DumpScope {
    /// Validates the request lists (collections as `<db>.<coll>`).
    ///
    /// # Errors
    /// RGN-1001 for an empty name or a collection without `.`.
    pub fn parse(databases: Vec<String>, collections: &[String]) -> Result<Self, Error> {
        if databases.iter().any(String::is_empty) {
            return Err(invalid("databases", "database names must not be empty"));
        }
        let collections = collections
            .iter()
            .map(|c| match c.split_once('.') {
                Some((db, coll)) if !db.is_empty() && !coll.is_empty() => {
                    Ok((db.to_owned(), coll.to_owned()))
                }
                _ => Err(invalid(
                    "collections",
                    format!("collection {c:?} is not of the form <db>.<coll>"),
                )),
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self {
            databases,
            collections,
        })
    }

    /// Text for audit records: `*` or the comma-separated names.
    fn describe(&self) -> String {
        if self.databases.is_empty() && self.collections.is_empty() {
            return "*".to_owned();
        }
        self.databases
            .iter()
            .cloned()
            .chain(self.collections.iter().map(|(d, c)| format!("{d}.{c}")))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// One piece of one file of a logical dump (backup.proto `DumpChunk`, PD-067 layout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpChunk {
    /// File path relative to the dump directory (a valid destination key).
    pub path: String,
    /// The next bytes of the file.
    pub data: Vec<u8>,
    /// Last chunk of the file.
    pub end_of_file: bool,
}

/// One item of a dump stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpItem {
    /// First item: the snapshot timestamp T of the dump.
    Started(HlcTimestamp),
    /// A file chunk.
    Chunk(DumpChunk),
}

/// What [`BackupBackend::dump`] reports when it finished.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DumpSummary {
    /// Collections dumped.
    pub collections: u64,
    /// Documents dumped.
    pub documents: u64,
}

/// Options of a logical restore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogicalRestoreOptions {
    /// Drop existing target collections first (else an existing target is RGN-1031, PD-067).
    pub drop_existing: bool,
    /// What to restore from the dump.
    pub scope: DumpScope,
}

/// One restored collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredCollection {
    /// Database.
    pub database: String,
    /// Collection.
    pub collection: String,
    /// Documents imported.
    pub documents: u64,
    /// Indexes rebuilt.
    pub indexes: u32,
}

/// What [`BackupBackend::logical_restore`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalRestoreSummary {
    /// Snapshot timestamp of the imported dump.
    pub source_timestamp: HlcTimestamp,
    /// Restored collections.
    pub collections: Vec<RestoredCollection>,
}

/// Where a dump backend writes (implemented by the service over the response stream).
pub trait DumpSink: Send {
    /// Announces the snapshot timestamp T. Called exactly once, before the first chunk.
    ///
    /// # Errors
    /// RGN-5005 when the client went away (stop dumping), RGN-5001 when called twice.
    fn started(&mut self, timestamp: HlcTimestamp) -> Result<(), Error>;

    /// Sends one chunk (preferably [`DUMP_CHUNK_BYTES`] of data). Blocks while the client is
    /// slower than the backend (back pressure).
    ///
    /// # Errors
    /// RGN-5005 when the client went away; RGN-5001 for a chunk before [`DumpSink::started`],
    /// an invalid path or a file that was already finished.
    fn chunk(&mut self, chunk: DumpChunk) -> Result<(), Error>;
}

/// Where a logical-restore backend reads the dump from (implemented by the service over the
/// request stream). Chunks are validated before the backend sees them: valid keys, at most
/// [`MAX_DUMP_CHUNK_BYTES`], files contiguous and never reopened.
pub trait DumpSource: Send {
    /// The next chunk; `None` once the client finished sending. Blocks until a chunk arrives.
    ///
    /// # Errors
    /// RGN-1001 for a malformed stream; RGN-5005 when the client went away.
    fn next_chunk(&mut self) -> Result<Option<DumpChunk>, Error>;
}

/// The engine-side operations of the service (module docs), implemented in M13a wave 2: lane BE
/// (`create_backup`, snapshots; physical image per PD-063/PD-064) and lane BG (`dump`,
/// `logical_restore`; PD-067), on lane BD's engine primitives.
///
/// Every method is blocking and runs on the executor's blocking pool, holding one executor
/// permit for its whole duration; long operations should check `cancel` between files or
/// batches. Errors are catalog errors (`rustegon_backup::BackupError` converts with `?`). The
/// default bodies fail with [`not_implemented`], so a backend can implement a subset.
pub trait BackupBackend: Send + Sync + 'static {
    /// `CreateBackup`: fences writes at a timestamp T (PD-063), checkpoints the store, uploads
    /// the image to `dest` with `rustegon_backup::write_backup` and returns its manifest.
    ///
    /// # Errors
    /// Engine, destination and cancellation errors.
    fn create_backup(
        &self,
        dest: &dyn Destination,
        cancel: &CancelToken,
    ) -> Result<CreatedBackup, Error> {
        let _ = (dest, cancel);
        Err(not_implemented("CreateBackup"))
    }

    /// `CreateSnapshot`: a hard-link checkpoint named `name` (RGN-1031 if it exists).
    ///
    /// # Errors
    /// Engine and file system errors.
    fn create_snapshot(
        &self,
        name: &SnapshotName,
        cancel: &CancelToken,
    ) -> Result<SnapshotInfo, Error> {
        let _ = (name, cancel);
        Err(not_implemented("CreateSnapshot"))
    }

    /// `ListSnapshots`, sorted by name.
    ///
    /// # Errors
    /// File system errors.
    fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>, Error> {
        Err(not_implemented("ListSnapshots"))
    }

    /// `DeleteSnapshot`; `false` when no snapshot of that name exists.
    ///
    /// # Errors
    /// File system errors.
    fn delete_snapshot(&self, name: &SnapshotName) -> Result<bool, Error> {
        let _ = name;
        Err(not_implemented("DeleteSnapshot"))
    }

    /// `Dump`: reads `scope` at one snapshot T and writes the PD-067 layout to `sink`
    /// (`started(T)` first, `dump.json` last).
    ///
    /// # Errors
    /// Engine errors; the sink's RGN-5005 when the client went away.
    fn dump(
        &self,
        scope: &DumpScope,
        sink: &mut dyn DumpSink,
        cancel: &CancelToken,
    ) -> Result<DumpSummary, Error> {
        let _ = (scope, sink, cancel);
        Err(not_implemented("Dump"))
    }

    /// `LogicalRestore`: imports the dump read from `source` (PD-067 order: collection without
    /// validator, bulk load, validator, indexes).
    ///
    /// # Errors
    /// RGN-1031 for an existing target without `drop_existing`, RGN-5002 for a dump whose
    /// checksums do not match, engine errors, the source's errors.
    fn logical_restore(
        &self,
        options: &LogicalRestoreOptions,
        source: &mut dyn DumpSource,
        cancel: &CancelToken,
    ) -> Result<LogicalRestoreSummary, Error> {
        let _ = (options, source, cancel);
        Err(not_implemented("LogicalRestore"))
    }
}

/// The backend of a node without one: every engine operation fails with [`not_implemented`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBackupBackend;

impl BackupBackend for NoBackupBackend {}

/// An online restore accepted by [`BackupService::restore_backup`] (ADR-037): the backup was
/// found complete and deep-verified while the node served.
#[derive(Debug, Clone)]
pub struct ScheduledRestore {
    /// Where the backup is (already checked against the allowlist).
    pub destination: DestinationUrl,
    /// The backup.
    pub backup_id: BackupId,
    /// Its verified manifest.
    pub manifest: Manifest,
}

/// How the last online restore ended (`GetRestoreStatus`).
#[derive(Debug)]
pub enum RestoreOutcome {
    /// This node never ran an online restore.
    None,
    /// Restored; the node serves the backup.
    Completed {
        /// The restored backup.
        backup_id: String,
        /// When it ended (ms since the Unix epoch).
        finished_at_unix_ms: i64,
        /// Directory name of the replaced store in the data directory.
        previous_store: String,
    },
    /// Failed before its swap; the node serves its previous store.
    Failed {
        /// The backup that was not restored.
        backup_id: String,
        /// When it ended (ms since the Unix epoch).
        finished_at_unix_ms: i64,
        /// Why.
        error: Error,
    },
}

/// The process side of an online restore (ADR-037), installed by `rustegond`
/// ([`crate::services::Services::with_restore_scheduler`]): stopping the node, swapping its
/// store and serving again cannot happen inside a request, so the service hands the verified
/// restore over and returns.
pub trait RestoreScheduler: Send + Sync + 'static {
    /// Accepts `restore`: the node stops serving after the current requests and restores.
    ///
    /// # Errors
    /// RGN-1031 when a restore is already scheduled; RGN-4006 when the backup is encrypted
    /// under another KEK than the node's (the node could not open it).
    fn schedule(&self, restore: ScheduledRestore) -> Result<(), Error>;

    /// The outcome of the last online restore.
    ///
    /// # Errors
    /// I/O errors reading the recorded outcome.
    fn status(&self) -> Result<RestoreOutcome, Error>;
}

/// Result of [`BackupService::list_backups`].
#[derive(Debug)]
pub struct BackupListing {
    /// Complete backups with a readable manifest, oldest first.
    pub backups: Vec<Manifest>,
    /// Complete backups whose manifest cannot be used: `(id, why)`.
    pub unreadable: Vec<(String, Error)>,
}

// ---------------------------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------------------------

/// The backup service (module docs).
#[derive(Clone)]
pub struct BackupService {
    deps: ServiceDeps,
    security: Option<Arc<Security>>,
    backend: Arc<dyn BackupBackend>,
    policy: Arc<DestinationPolicy>,
    s3: Arc<S3Settings>,
    /// The online restore of `rustegond` (ADR-037); `None`: `RestoreBackup` is not served.
    scheduler: Option<Arc<dyn RestoreScheduler>>,
    /// Spool directory of server-side dumps (`server_dump`); `None`: a temporary directory.
    spool: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for BackupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupService").finish_non_exhaustive()
    }
}

fn invalid(field: &str, msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, msg).with_detail("field", field)
}

/// The audit operation names (`details.op`).
mod op {
    pub const CREATE_BACKUP: &str = "create_backup";
    pub const VERIFY_BACKUP: &str = "verify_backup";
    pub const CREATE_SNAPSHOT: &str = "create_snapshot";
    pub const DELETE_SNAPSHOT: &str = "delete_snapshot";
    pub const DUMP: &str = "dump";
    pub const LOGICAL_RESTORE: &str = "logical_restore";
    pub const RESTORE_BACKUP: &str = "restore_backup";
}

/// Start and end records of one audited operation.
struct Audited {
    security: Arc<Security>,
    kind: AuditEventKind,
    op: &'static str,
    target: String,
}

impl Audited {
    fn event(
        &self,
        ctx: &RequestContext,
        outcome: AuditOutcome,
        phase: &str,
    ) -> rustegon_security::audit::AuditEvent {
        let action = match self.kind {
            AuditEventKind::Restore => "restore",
            _ => "backup",
        };
        self.security
            .event(ctx, self.kind, outcome)
            .resource("cluster")
            .action(action)
            .detail("op", self.op)
            .detail("phase", phase)
            .detail("target", self.target.clone())
    }

    /// The start record, written durably before the operation runs: an operation that cannot
    /// be audited is refused (security.md §4, fail closed).
    async fn start(
        security: &Arc<Security>,
        ctx: &RequestContext,
        kind: AuditEventKind,
        op: &'static str,
        target: String,
    ) -> Result<Self, Error> {
        let audited = Self {
            security: Arc::clone(security),
            kind,
            op,
            target,
        };
        security
            .audit(audited.event(ctx, AuditOutcome::Success, "start"))
            .await?;
        Ok(audited)
    }

    /// The end record with the outcome. The operation already happened, so an audit failure
    /// is logged, not returned.
    async fn end<T>(
        &self,
        ctx: &RequestContext,
        result: &Result<T, Error>,
        details: impl FnOnce(&T) -> Vec<(&'static str, String)>,
    ) {
        let event = match result {
            Ok(value) => details(value).into_iter().fold(
                self.event(ctx, AuditOutcome::Success, "end"),
                |e, (k, v)| e.detail(k, v),
            ),
            Err(e) => self
                .event(ctx, AuditOutcome::Failure, "end")
                .detail("error_code", e.code().code().to_string()),
        };
        self.security.audit_or_log(event).await;
    }
}

impl BackupService {
    /// A service without security layer (every call fails with RGN-4001) and without backend.
    #[must_use]
    pub fn new(deps: ServiceDeps) -> Self {
        Self {
            deps,
            security: None,
            backend: Arc::new(NoBackupBackend),
            policy: Arc::new(DestinationPolicy::deny_all()),
            s3: Arc::new(S3Settings::default()),
            scheduler: None,
            spool: None,
        }
    }

    /// The same service spooling server-side dumps in `dir` (`server_dump`, PD-226).
    #[must_use]
    pub(crate) fn with_spool(mut self, dir: std::path::PathBuf) -> Self {
        self.spool = Some(dir);
        self
    }

    /// The same service with the online restore of the process installed (ADR-037).
    #[must_use]
    pub(crate) fn with_scheduler(mut self, scheduler: Arc<dyn RestoreScheduler>) -> Self {
        self.scheduler = Some(scheduler);
        self
    }

    /// The same service opening `s3://` destinations with `s3` (`[backup.s3]`).
    #[must_use]
    pub(crate) fn with_s3(mut self, s3: S3Settings) -> Self {
        self.s3 = Arc::new(s3);
        self
    }

    /// The same service with the destination allowlist `policy` (module docs).
    #[must_use]
    pub(crate) fn with_policy(mut self, policy: DestinationPolicy) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    /// The same service with the security layer installed.
    #[must_use]
    pub(crate) fn with_security(mut self, security: Arc<Security>) -> Self {
        self.security = Some(security);
        self
    }

    /// The same service over `backend`.
    #[must_use]
    pub(crate) fn with_backend(mut self, backend: Arc<dyn BackupBackend>) -> Self {
        self.backend = backend;
        self
    }

    /// The security layer after the checks the gate also makes for `rpc` (as
    /// `AdminService::guard`: every front end gets the same authorization).
    async fn guard(&self, ctx: &RequestContext, rpc: &str) -> Result<&Arc<Security>, Error> {
        let sec = self.security.as_ref().ok_or_else(unauthenticated)?;
        let method = format!("/rustegon.v1.BackupService/{rpc}");
        let rule = access_of(&method)
            .ok_or_else(|| Error::new(ErrorCode::Internal, "no access rule declared"))?;
        sec.admit(ctx, rule).await?;
        Ok(sec)
    }

    /// Charges one expensive administrative operation (backup, restore) to the caller.
    fn admin_op(sec: &Security, ctx: &RequestContext) -> Result<(), Error> {
        let user = ctx.require_principal()?.user.clone();
        let ip = ctx.peer().map(|p| p.remote_addr.ip());
        sec.rate_limit(LimitClass::AdminOp, Some(&user), ip)
    }

    /// Parses a server-side destination (module docs).
    fn parse_destination(text: &str) -> Result<DestinationUrl, Error> {
        if text.trim().is_empty() {
            return Err(invalid("destination", "a destination is required"));
        }
        let url = DestinationUrl::parse(text)
            .map_err(|e| Error::from(e).with_detail("field", "destination"))?;
        if let DestinationUrl::Local { path } = &url
            && !path.is_absolute()
        {
            return Err(invalid(
                "destination",
                "a local destination on the server must be an absolute path",
            ));
        }
        Ok(url)
    }

    /// Parses a request's destination and checks it against the allowlist (module docs); a
    /// refusal is audited as `privilege_denied`.
    async fn destination(
        &self,
        sec: &Security,
        ctx: &RequestContext,
        rpc: &str,
        text: &str,
    ) -> Result<DestinationUrl, Error> {
        let url = Self::parse_destination(text)?;
        if let Err(e) = self.policy.check(&url) {
            let event = sec
                .event(ctx, AuditEventKind::PrivilegeDenied, AuditOutcome::Denied)
                .resource("cluster")
                .action("backup")
                .detail("endpoint", format!("/rustegon.v1.BackupService/{rpc}"))
                .detail("reason", rustegon_backup::policy::NOT_ALLOWED_REASON)
                .detail("target", url.to_string());
            sec.audit_or_log(event).await;
            return Err(e);
        }
        Ok(url)
    }

    fn fs(sec: &Security) -> Arc<dyn FileSystem> {
        Arc::clone(sec.fs())
    }

    /// Lists the complete backups at `destination` (`backup` on `cluster`).
    ///
    /// # Errors
    /// RGN-4001/4002, RGN-1001 (destination), RGN-1030 (no such local destination), RGN-3002
    /// (destination unavailable).
    pub async fn list_backups(
        &self,
        ctx: &RequestContext,
        destination: &str,
    ) -> Result<BackupListing, Error> {
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
                let mut out = BackupListing {
                    backups: Vec::new(),
                    unreadable: Vec::new(),
                };
                for entry in rustegon_backup::list(dest.as_ref())? {
                    match entry {
                        ListedBackup::Complete(m) => out.backups.push(m),
                        ListedBackup::Unreadable { id, error } => {
                            out.unreadable.push((id.to_string(), Error::from(error)));
                        }
                    }
                }
                Ok(out)
            })
            .await
    }

    /// Reads the manifest of the complete backup `id` at `destination`.
    ///
    /// # Errors
    /// As [`Self::list_backups`]; RGN-1030 (absent or incomplete backup), RGN-5002 (corrupt
    /// manifest), RGN-5007 (newer format).
    pub async fn get_backup(
        &self,
        ctx: &RequestContext,
        destination: &str,
        id: &str,
    ) -> Result<Manifest, Error> {
        let sec = self.guard(ctx, "GetBackup").await?;
        let url = self.destination(sec, ctx, "GetBackup", destination).await?;
        let id = parse_backup_id(id)?;
        let fs = Self::fs(sec);
        let s3 = Arc::clone(&self.s3);
        self.deps
            .executor
            .run(ctx, Completion::Abandon, move |_| {
                let dest = open_existing(&url, fs, &s3)?;
                Ok(rustegon_backup::load_manifest(dest.as_ref(), &id)?)
            })
            .await
    }

    /// Verifies backup `id` at `destination` (TC-BKP-010). Audited as a `backup` event (a deep
    /// verification reads every file of the backup).
    ///
    /// # Errors
    /// As [`Self::get_backup`]; RGN-5002 for a missing, truncated or (deep) corrupt file;
    /// RGN-4003.
    pub async fn verify_backup(
        &self,
        ctx: &RequestContext,
        destination: &str,
        id: &str,
        deep: bool,
    ) -> Result<VerifyReport, Error> {
        let sec = self.guard(ctx, "VerifyBackup").await?;
        Self::admin_op(sec, ctx)?;
        let url = self
            .destination(sec, ctx, "VerifyBackup", destination)
            .await?;
        let id = parse_backup_id(id)?;
        let audited = Audited::start(
            sec,
            ctx,
            AuditEventKind::Backup,
            op::VERIFY_BACKUP,
            format!("{url} {id}"),
        )
        .await?;
        let fs = Self::fs(sec);
        let s3 = Arc::clone(&self.s3);
        let mode = if deep {
            VerifyMode::Deep
        } else {
            VerifyMode::Shallow
        };
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |_| {
                let dest = open_existing(&url, fs, &s3)?;
                Ok(rustegon_backup::verify(dest.as_ref(), &id, mode)?)
            })
            .await;
        audited
            .end(ctx, &result, |r| {
                vec![
                    ("files_checked", r.files_checked.to_string()),
                    ("deep", deep.to_string()),
                ]
            })
            .await;
        result
    }

    /// Takes an online backup to `destination` (backend operation).
    ///
    /// # Errors
    /// RGN-4001/4002/4003, RGN-1001 (destination), the backend's errors (RGN-5007
    /// `not_implemented` without backend).
    pub async fn create_backup(
        &self,
        ctx: &RequestContext,
        destination: &str,
    ) -> Result<CreatedBackup, Error> {
        let sec = self.guard(ctx, "CreateBackup").await?;
        Self::admin_op(sec, ctx)?;
        let url = self
            .destination(sec, ctx, "CreateBackup", destination)
            .await?;
        let audited = Audited::start(
            sec,
            ctx,
            AuditEventKind::Backup,
            op::CREATE_BACKUP,
            url.to_string(),
        )
        .await?;
        let fs = Self::fs(sec);
        let s3 = Arc::clone(&self.s3);
        let backend = Arc::clone(&self.backend);
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |cancel| {
                // Opening creates a missing local destination: a backup target may be new.
                let dest = rustegon_backup::open_destination(&url, fs, &s3).map_err(Error::from)?;
                backend.create_backup(dest.as_ref(), cancel)
            })
            .await;
        audited
            .end(ctx, &result, |b| {
                vec![
                    ("backup_id", b.manifest.backup_id.clone()),
                    ("files", b.manifest.files.len().to_string()),
                ]
            })
            .await;
        result
    }

    /// Schedules an online restore of the whole node from backup `id` at `destination`
    /// (`restore` on `cluster`; ADR-037). The backup is located (`<id>.bak` or a backup
    /// directory) and deep-verified first, so a missing, incomplete or corrupt backup is refused
    /// while the node keeps serving its data; only then is it handed to the process, which stops
    /// serving right after this call returns. Audited as a `restore` event (start, then the end
    /// with `scheduled=true`); the outcome after the restart is in [`Self::restore_status`] and
    /// the node log.
    ///
    /// # Errors
    /// RGN-4001/4002/4003, RGN-1001 (destination, id), RGN-1030 (no such backup), RGN-5002
    /// (corrupt), RGN-5007 (newer format, or no scheduler in this process), RGN-4006 (another
    /// KEK), RGN-1031 (a restore is already scheduled), RGN-3002 (destination unavailable).
    pub async fn restore_backup(
        &self,
        ctx: &RequestContext,
        destination: &str,
        id: &str,
    ) -> Result<Manifest, Error> {
        let sec = self.guard(ctx, "RestoreBackup").await?;
        Self::admin_op(sec, ctx)?;
        let scheduler = self
            .scheduler
            .clone()
            .ok_or_else(|| not_implemented("RestoreBackup"))?;
        let url = self
            .destination(sec, ctx, "RestoreBackup", destination)
            .await?;
        let id = parse_backup_id(id)?;
        let audited = Audited::start(
            sec,
            ctx,
            AuditEventKind::Restore,
            op::RESTORE_BACKUP,
            format!("{url} {id}"),
        )
        .await?;
        let fs = Self::fs(sec);
        let s3 = Arc::clone(&self.s3);
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |_| {
                let dest = open_existing(&url, fs, &s3)?;
                let report = rustegon_backup::verify(dest.as_ref(), &id, VerifyMode::Deep)?;
                scheduler.schedule(ScheduledRestore {
                    destination: url,
                    backup_id: id,
                    manifest: report.manifest.clone(),
                })?;
                Ok(report.manifest)
            })
            .await;
        audited
            .end(ctx, &result, |m| {
                vec![
                    ("backup_id", m.backup_id.clone()),
                    ("scheduled", "true".to_owned()),
                ]
            })
            .await;
        result
    }

    /// The outcome of the last online restore of this node (`backup` on `cluster`).
    ///
    /// # Errors
    /// RGN-4001/4002, RGN-5007 without a scheduler, I/O errors.
    pub async fn restore_status(&self, ctx: &RequestContext) -> Result<RestoreOutcome, Error> {
        self.guard(ctx, "GetRestoreStatus").await?;
        let scheduler = self
            .scheduler
            .clone()
            .ok_or_else(|| not_implemented("GetRestoreStatus"))?;
        self.deps
            .executor
            .run(ctx, Completion::Abandon, move |_| scheduler.status())
            .await
    }

    /// Creates a local snapshot (backend operation).
    ///
    /// # Errors
    /// RGN-4001/4002/4003, RGN-1001 (name), the backend's errors.
    pub async fn create_snapshot(
        &self,
        ctx: &RequestContext,
        name: &str,
    ) -> Result<SnapshotInfo, Error> {
        let sec = self.guard(ctx, "CreateSnapshot").await?;
        Self::admin_op(sec, ctx)?;
        let name = SnapshotName::parse(name)?;
        let audited = Audited::start(
            sec,
            ctx,
            AuditEventKind::Backup,
            op::CREATE_SNAPSHOT,
            name.as_str().to_owned(),
        )
        .await?;
        let backend = Arc::clone(&self.backend);
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |cancel| {
                backend.create_snapshot(&name, cancel)
            })
            .await;
        audited.end(ctx, &result, |_| Vec::new()).await;
        result
    }

    /// Lists the local snapshots (backend operation).
    ///
    /// # Errors
    /// RGN-4001/4002, the backend's errors.
    pub async fn list_snapshots(&self, ctx: &RequestContext) -> Result<Vec<SnapshotInfo>, Error> {
        self.guard(ctx, "ListSnapshots").await?;
        let backend = Arc::clone(&self.backend);
        self.deps
            .executor
            .run(ctx, Completion::Abandon, move |_| backend.list_snapshots())
            .await
    }

    /// Deletes a local snapshot (backend operation); `false` when it did not exist.
    ///
    /// # Errors
    /// RGN-4001/4002/4003, RGN-1001 (name), the backend's errors.
    pub async fn delete_snapshot(&self, ctx: &RequestContext, name: &str) -> Result<bool, Error> {
        let sec = self.guard(ctx, "DeleteSnapshot").await?;
        Self::admin_op(sec, ctx)?;
        let name = SnapshotName::parse(name)?;
        let audited = Audited::start(
            sec,
            ctx,
            AuditEventKind::Backup,
            op::DELETE_SNAPSHOT,
            name.as_str().to_owned(),
        )
        .await?;
        let backend = Arc::clone(&self.backend);
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |_| {
                backend.delete_snapshot(&name)
            })
            .await;
        audited
            .end(ctx, &result, |deleted| {
                vec![("deleted", deleted.to_string())]
            })
            .await;
        result
    }

    /// Starts a logical dump of `scope` (backend operation). Returns once the backend produced
    /// its first item, so an operation that fails at once (bad scope, no backend) is a plain
    /// error, not a stream that fails; dropping the returned stream stops the backend at its
    /// next chunk (RGN-5005).
    ///
    /// # Errors
    /// RGN-4001/4002/4003, the backend's errors before its first item.
    pub async fn dump(&self, ctx: &RequestContext, scope: DumpScope) -> Result<DumpStream, Error> {
        let sec = self.guard(ctx, "Dump").await?;
        Self::admin_op(sec, ctx)?;
        let audited =
            Audited::start(sec, ctx, AuditEventKind::Backup, op::DUMP, scope.describe()).await?;
        let (tx, mut rx) = mpsc::channel::<Result<DumpItem, Error>>(DUMP_BUFFER);
        let backend = Arc::clone(&self.backend);
        let executor = self.deps.executor.clone();
        let task_ctx = ctx.clone();
        let sink_tx = tx.clone();
        // The backend runs on the blocking pool for as long as the dump lasts; this task waits
        // for its outcome, writes the end record and forwards a late error to the stream.
        tokio::spawn(async move {
            let result = executor
                .run(&task_ctx, Completion::Await, move |cancel| {
                    let mut sink = ChannelSink {
                        tx: sink_tx,
                        order: ChunkOrder::default(),
                        started: false,
                    };
                    let summary = backend.dump(&scope, &mut sink, cancel)?;
                    sink.finish()?;
                    Ok(summary)
                })
                .await;
            audited
                .end(&task_ctx, &result, |s| {
                    vec![
                        ("collections", s.collections.to_string()),
                        ("documents", s.documents.to_string()),
                    ]
                })
                .await;
            if let Err(e) = result {
                // The client may be gone already; then there is nobody to tell.
                let _ = tx.send(Err(e)).await;
            }
        });
        match rx.recv().await {
            Some(Ok(first)) => Ok(DumpStream {
                first: Some(first),
                rx,
            }),
            Some(Err(e)) => Err(e),
            None => Err(Error::new(
                ErrorCode::Internal,
                "the dump ended without producing anything",
            )),
        }
    }

    /// Imports a logical dump read from `chunks` (backend operation). The transport adapter
    /// feeds `chunks` from its request stream; a transport error is sent as an `Err` item and
    /// ends the restore.
    ///
    /// # Errors
    /// RGN-4001/4002/4003, RGN-1001 (scope, malformed stream), the backend's errors.
    pub async fn logical_restore(
        &self,
        ctx: &RequestContext,
        options: LogicalRestoreOptions,
        chunks: ChunkReceiver,
    ) -> Result<LogicalRestoreSummary, Error> {
        let sec = self.guard(ctx, "LogicalRestore").await?;
        Self::admin_op(sec, ctx)?;
        let audited = Audited::start(
            sec,
            ctx,
            AuditEventKind::Restore,
            op::LOGICAL_RESTORE,
            options.scope.describe(),
        )
        .await?;
        let backend = Arc::clone(&self.backend);
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |cancel| {
                let mut source = ChannelSource {
                    rx: chunks,
                    order: ChunkOrder::default(),
                };
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

/// The bounded chunk channel a transport adapter feeds into
/// [`BackupService::logical_restore`] (back pressure on the client's stream).
#[must_use]
pub fn restore_channel() -> (ChunkSender, ChunkReceiver) {
    mpsc::channel(RESTORE_BUFFER)
}

/// Sending half of [`restore_channel`].
pub type ChunkSender = mpsc::Sender<Result<DumpChunk, Error>>;
/// Receiving half of [`restore_channel`], consumed by [`BackupService::logical_restore`].
pub type ChunkReceiver = mpsc::Receiver<Result<DumpChunk, Error>>;

fn parse_backup_id(id: &str) -> Result<BackupId, Error> {
    BackupId::parse(id).map_err(|e| Error::from(e).with_detail("field", "backup_id"))
}

/// Opens `url` for reading without creating a missing local directory (module docs).
fn open_existing(
    url: &DestinationUrl,
    fs: Arc<dyn FileSystem>,
    s3: &S3Settings,
) -> Result<Box<dyn Destination>, Error> {
    if let DestinationUrl::Local { path } = url {
        match fs.read_dir(path) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(Error::new(
                    ErrorCode::NotFound,
                    format!("backup destination {url} does not exist"),
                ));
            }
            Err(e) => {
                return Err(BackupError::Destination {
                    destination: url.to_string(),
                    op: "list",
                    key: String::new(),
                    source: e,
                }
                .into());
            }
        }
    }
    Ok(rustegon_backup::open_destination(url, fs, s3)?)
}

// ---------------------------------------------------------------------------------------------
// Streaming plumbing
// ---------------------------------------------------------------------------------------------

/// Order rules of a chunk stream: valid keys, bounded size, files contiguous and never
/// reopened (backup.proto `DumpChunk`).
#[derive(Debug, Default)]
struct ChunkOrder {
    open: Option<String>,
    finished: BTreeSet<String>,
}

impl ChunkOrder {
    fn check(&mut self, chunk: &DumpChunk) -> Result<(), Error> {
        let bad = |msg: String| invalid("chunk", msg);
        validate_key(&chunk.path).map_err(|e| bad(e.to_string()))?;
        if chunk.data.len() > MAX_DUMP_CHUNK_BYTES {
            return Err(bad(format!(
                "a chunk carries at most {MAX_DUMP_CHUNK_BYTES} bytes"
            )));
        }
        if self.finished.contains(&chunk.path) {
            return Err(bad(format!("file {} was already complete", chunk.path)));
        }
        match &self.open {
            Some(open) if *open != chunk.path => {
                return Err(bad(format!(
                    "file {} started before file {open} was complete",
                    chunk.path
                )));
            }
            _ => {}
        }
        if chunk.end_of_file {
            self.open = None;
            self.finished.insert(chunk.path.clone());
        } else {
            self.open = Some(chunk.path.clone());
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), Error> {
        match &self.open {
            Some(open) => Err(invalid(
                "chunk",
                format!("the stream ended inside file {open}"),
            )),
            None => Ok(()),
        }
    }
}

/// [`DumpSink`] over the bounded channel read by [`DumpStream`].
struct ChannelSink {
    tx: mpsc::Sender<Result<DumpItem, Error>>,
    order: ChunkOrder,
    started: bool,
}

impl ChannelSink {
    fn send(&self, item: DumpItem) -> Result<(), Error> {
        // On the blocking pool: `blocking_send` waits for room (back pressure) and fails only
        // when the receiver — the response stream — was dropped.
        self.tx.blocking_send(Ok(item)).map_err(|_| cancelled())
    }

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

impl DumpSink for ChannelSink {
    fn started(&mut self, timestamp: HlcTimestamp) -> Result<(), Error> {
        if self.started {
            return Err(Error::new(
                ErrorCode::Internal,
                "the dump backend announced its timestamp twice",
            ));
        }
        self.started = true;
        self.send(DumpItem::Started(timestamp))
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
        self.send(DumpItem::Chunk(chunk))
    }
}

/// [`DumpSource`] over the channel fed by the transport adapter.
struct ChannelSource {
    rx: ChunkReceiver,
    order: ChunkOrder,
}

impl DumpSource for ChannelSource {
    fn next_chunk(&mut self) -> Result<Option<DumpChunk>, Error> {
        match self.rx.blocking_recv() {
            Some(Ok(chunk)) => {
                self.order.check(&chunk)?;
                Ok(Some(chunk))
            }
            Some(Err(e)) => Err(e),
            None => {
                self.order.finish()?;
                Ok(None)
            }
        }
    }
}

/// The items of a running dump ([`BackupService::dump`]). Dropping it stops the backend.
pub struct DumpStream {
    first: Option<DumpItem>,
    rx: mpsc::Receiver<Result<DumpItem, Error>>,
}

impl std::fmt::Debug for DumpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DumpStream").finish_non_exhaustive()
    }
}

impl Stream for DumpStream {
    type Item = Result<DumpItem, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(first) = this.first.take() {
            return Poll::Ready(Some(Ok(first)));
        }
        this.rx.poll_recv(cx)
    }
}

// ---------------------------------------------------------------------------------------------
// Wire helpers shared by gRPC and REST
// ---------------------------------------------------------------------------------------------

/// Unix milliseconds of a manifest `created_at` (`yyyy-mm-ddThh:mm:ssZ`, as written by
/// `rustegon-backup`); 0 when it does not have that form.
#[must_use]
pub fn rfc3339_unix_ms(text: &str) -> i64 {
    parse_rfc3339(text).unwrap_or(0)
}

fn parse_rfc3339(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[19] != b'Z' {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> { text.get(from..to)?.parse().ok() };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    if second > 60 {
        return None;
    }
    // Days from the civil date (H. Hinnant's algorithm), proleptic Gregorian calendar.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn fr_bkp_006_manifest_times_convert_to_unix_ms() {
        assert_eq!(rfc3339_unix_ms("1970-01-01T00:00:00Z"), 0);
        assert_eq!(rfc3339_unix_ms("2026-11-09T10:15:00Z"), 1_794_219_300_000);
        assert_eq!(rfc3339_unix_ms("2000-02-29T23:59:59Z"), 951_868_799_000);
        for bad in ["", "2026-11-09 10:15:00Z", "2026-13-09T10:15:00Z", "x"] {
            assert_eq!(rfc3339_unix_ms(bad), 0, "{bad}");
        }
    }

    #[test]
    fn fr_bkp_003_snapshot_names_follow_the_id_rule() {
        for ok in ["pre-upgrade", "a", "v1.2_x", &"n".repeat(64)] {
            assert_eq!(SnapshotName::parse(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            ".hidden",
            "a/b",
            "a b",
            "..",
            &"n".repeat(65),
            "caf\u{e9}",
        ] {
            let e = SnapshotName::parse(bad).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
        }
    }

    #[test]
    fn fr_bkp_007_dump_scope_parses_qualified_collections() {
        let s = DumpScope::parse(vec!["shop".into()], &["crm.people".into()]).unwrap();
        assert_eq!(s.collections, [("crm".to_owned(), "people".to_owned())]);
        assert_eq!(s.describe(), "shop,crm.people");
        assert_eq!(DumpScope::default().describe(), "*");
        assert!(DumpScope::parse(vec![], &["nodot".into()]).is_err());
        assert!(DumpScope::parse(vec![], &[".c".into()]).is_err());
        assert!(DumpScope::parse(vec![String::new()], &[]).is_err());
    }

    fn chunk(path: &str, end: bool) -> DumpChunk {
        DumpChunk {
            path: path.into(),
            data: vec![1, 2, 3],
            end_of_file: end,
        }
    }

    #[test]
    fn fr_bkp_007_chunk_streams_must_be_contiguous_files() {
        let mut o = ChunkOrder::default();
        o.check(&chunk("shop/a.ndjson", false)).unwrap();
        o.check(&chunk("shop/a.ndjson", true)).unwrap();
        o.check(&chunk("dump.json", true)).unwrap();
        o.finish().unwrap();
        // Reopening a finished file, interleaving, bad keys, oversize, unfinished tail.
        assert!(o.check(&chunk("shop/a.ndjson", true)).is_err());
        let mut o = ChunkOrder::default();
        o.check(&chunk("a", false)).unwrap();
        assert!(o.check(&chunk("b", true)).is_err());
        assert!(o.finish().is_err());
        let mut o = ChunkOrder::default();
        assert!(o.check(&chunk("../x", true)).is_err());
        let big = DumpChunk {
            path: "x".into(),
            data: vec![0; MAX_DUMP_CHUNK_BYTES + 1],
            end_of_file: true,
        };
        assert!(o.check(&big).is_err());
    }

    #[test]
    fn fr_bkp_001_not_implemented_is_rgn_5007_with_reason() {
        let e = not_implemented("CreateBackup");
        assert_eq!(e.code(), ErrorCode::VersionIncompatible);
        assert!(!e.retryable());
        assert_eq!(
            e.details().get("reason").map(String::as_str),
            Some(NOT_IMPLEMENTED_REASON)
        );
        let b = NoBackupBackend;
        assert_eq!(
            b.list_snapshots().unwrap_err().code(),
            ErrorCode::VersionIncompatible
        );
    }

    #[test]
    fn fr_bkp_004_server_destinations_must_be_absolute() {
        let e = BackupService::parse_destination("relative/dir").unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(BackupService::parse_destination("").is_err());
        assert!(BackupService::parse_destination("s3://bucket/prefix").is_ok());
        let e = BackupService::parse_destination("azure://x/y").unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let abs = std::env::temp_dir();
        assert!(BackupService::parse_destination(abs.to_str().unwrap()).is_ok());
    }
}
