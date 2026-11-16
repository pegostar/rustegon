// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegon backup …`, `rustegon snapshot …`, `rustegon dump`, `rustegon restore`: single-node
//! backup and restore (backup-restore.md "Single-node scope"; FR-BKP-001/003/004/006/007;
//! PD-062, PD-077).
//!
//! Execution model (PD-062):
//! - **online** (through the node's `BackupService`, connection options as for `user`):
//!   `backup create|list|get`, `snapshot create|list|delete`, `dump`, `restore`. Destinations of
//!   `backup create|list|get` are paths or URLs *as seen by the server* (absolute paths);
//! - **offline** (on files, the node stopped or on another machine): `backup verify` reads the
//!   destination directly; `backup restore` and `snapshot restore` write a data directory.
//!
//! The offline restores (`rustegon_backup::restore_data_dir`, M13a lane BE) refuse while the
//! data-dir lock is held (PD-068), check every file against the manifest before the store is
//! swapped in, revert the image to its consistency point T (PD-063) and can be rerun after any
//! failure; `snapshot restore` keeps the replaced store as `store.pre-restore-<ts>`. An
//! encrypted backup needs its KEK: `--encryption-key-file` or `--encryption-key-env`, the same
//! key the node is configured with (`storage.encryption_key_*`).
//!
//! `backup restore --to-time <T>` is a point-in-time restore (FR-BKP-002, PD-066, PD-088;
//! `rustegon_backup::restore_data_dir_to_time`): the base is the newest complete backup with a
//! PITR timeline and `T_b <= T` (or `--id`), rolled forward with the log archive at `--archive`
//! (default: the backup destination, where `backup.pitr.destination` usually points) and
//! reverted to T. T is RFC 3339 (`2026-11-10T09:30:00Z`) or an HLC timestamp
//! `<wall ns>[.<logical>]` as printed by `backup list` (`T=…`). Like the plain restore it
//! refuses a data directory in use, checks every file before the swap and can be rerun after a
//! failure (with the same T).
//! Offline commands read destinations directly with the operator's own file-system or S3
//! access; the server's `backup.allowed_destinations` applies to requests the server executes.
//!
//! `dump` writes the PD-067 layout into an empty or new directory exactly as the server streams
//! it; `restore` sends a dump directory back, every file in path order and `dump.json` last.
//! Secrets never come from argv (connection options as everywhere in the CLI).

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Args, Subcommand};
use rustegon_backup::{
    BackupId, Destination, DestinationUrl, LocalDestination, PitrTarget, RestoreKind,
    RestoreReport, RestoreRequest, S3Settings, VerifyMode, open_destination, restore_data_dir,
    restore_data_dir_to_time, snapshots_dir, validate_key,
};
use rustegon_proto::v1::{
    BackupEncryptionMode, BackupInfo, CreateBackupRequest, CreateSnapshotRequest,
    DeleteSnapshotRequest, DumpRequest, GetBackupRequest, ListBackupsRequest, ListSnapshotsRequest,
    LogicalRestoreOptions, LogicalRestoreRequest, SnapshotInfo,
    backup_service_client::BackupServiceClient, dump_response, logical_restore_request,
};
use rustegon_sim_api::{FileSystem, OpenMode, OsRng, StdFileSystem, SystemClock};
use rustegon_storage::encryption::{FileKekProvider, KekProvider};
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;

use crate::{
    client::{Client, ConnArgs},
    output::{CliError, CliResult, err, fail, io_err, out},
};

/// Name of the dump's own manifest (PD-067), sent last by `restore`.
pub const DUMP_MANIFEST: &str = "dump.json";

/// Bytes read per chunk when sending a dump (the server accepts up to 4 MiB).
const CHUNK_BYTES: usize = 1 << 20;

/// `rustegon backup …`.
#[derive(Debug, Args)]
pub struct BackupArgs {
    #[command(subcommand)]
    command: BackupCommand,
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    /// Take an online backup of the node (consistent at one timestamp; writes continue).
    Create {
        #[command(flatten)]
        conn: ConnArgs,
        /// Destination as seen by the server: absolute path, `file://…` or `s3://…`.
        #[arg(long, value_name = "DEST")]
        to: String,
    },
    /// List the complete backups at a destination (through the node).
    List {
        #[command(flatten)]
        conn: ConnArgs,
        /// Destination as seen by the server.
        #[arg(long, value_name = "DEST")]
        dest: String,
    },
    /// Show one backup and its files (through the node).
    Get {
        #[command(flatten)]
        conn: ConnArgs,
        /// Destination as seen by the server.
        #[arg(long, value_name = "DEST")]
        dest: String,
        /// Backup id.
        #[arg(long)]
        id: String,
    },
    /// Verify a backup against its manifest (offline: reads the destination directly).
    Verify {
        /// Destination: path, `s3://bucket/prefix[?region=…&endpoint=…]` or `file://…` URL.
        #[arg(long, value_name = "DEST")]
        dest: String,
        /// Backup id.
        #[arg(long)]
        id: String,
        /// Also read every file and compare its BLAKE3 hash.
        #[arg(long)]
        deep: bool,
        #[command(flatten)]
        s3: S3Args,
    },
    /// Restore a backup into an empty data directory (offline), optionally rolled forward to a
    /// point in time with the PITR log archive.
    Restore {
        /// Destination holding the backup.
        #[arg(long, value_name = "DEST")]
        from: String,
        /// Backup id (with `--to-time`: default the newest PITR backup taken at or before T).
        #[arg(long, required_unless_present = "to_time")]
        id: Option<String>,
        /// Data directory to create (must be empty or absent).
        #[arg(long, value_name = "PATH")]
        into: PathBuf,
        /// Point in time to restore to: RFC 3339 (`2026-11-10T09:30:00Z`) or an HLC timestamp
        /// `<wall ns>[.<logical>]`.
        #[arg(long, value_name = "T")]
        to_time: Option<String>,
        /// Destination holding the PITR log archive (`backup.pitr.destination`; default: the
        /// `--from` destination).
        #[arg(long, value_name = "DEST", requires = "to_time")]
        archive: Option<String>,
        #[command(flatten)]
        kek: KekArgs,
        #[command(flatten)]
        s3: S3Args,
    },
}

/// Options of an offline command reading an `s3://` destination (PD-065, PD-086). Secrets never
/// come from argv: credentials are read from a JSON file or the `AWS_ACCESS_KEY_ID` /
/// `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` environment variables.
#[derive(Debug, Args)]
struct S3Args {
    /// JSON file with `access_key_id`, `secret_access_key` and optional `session_token` (else
    /// the `AWS_*` environment variables).
    #[arg(long, value_name = "PATH")]
    s3_credentials_file: Option<PathBuf>,
    /// PEM CA bundle verifying an https S3 endpoint (else the operating-system roots).
    #[arg(long, value_name = "PATH")]
    s3_ca: Option<PathBuf>,
}

impl S3Args {
    fn settings(&self) -> S3Settings {
        S3Settings {
            credentials_file: self.s3_credentials_file.clone(),
            ca_file: self.s3_ca.clone(),
            ..S3Settings::default()
        }
    }
}

/// The KEK of an encrypted backup (offline restores).
#[derive(Debug, Args)]
struct KekArgs {
    /// File holding the KEK of an encrypted backup (as `storage.encryption_key_file`).
    #[arg(long, value_name = "PATH", conflicts_with = "encryption_key_env")]
    encryption_key_file: Option<PathBuf>,
    /// Environment variable holding the KEK in base64 (as `storage.encryption_key_env`).
    #[arg(long, value_name = "VAR")]
    encryption_key_env: Option<String>,
}

impl KekArgs {
    /// The KEK provider, if a key was given. The key itself never appears in argv.
    fn provider(&self) -> CliResult<Option<Arc<dyn KekProvider>>> {
        let provider = if let Some(path) = &self.encryption_key_file {
            FileKekProvider::open(&StdFileSystem, path)
        } else if let Some(var) = &self.encryption_key_env {
            let value = zeroize::Zeroizing::new(std::env::var(var).ok());
            FileKekProvider::from_env_value(var, value.as_deref())
        } else {
            return Ok(None);
        };
        let provider = provider.map_err(|e| rgn_err(&rustegon_common::Error::from(e)))?;
        Ok(Some(Arc::new(provider)))
    }
}

/// `rustegon snapshot …`.
#[derive(Debug, Args)]
pub struct SnapshotArgs {
    #[command(subcommand)]
    command: SnapshotCommand,
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    /// Create a local snapshot (hard-link checkpoint) of the node's store.
    Create {
        #[command(flatten)]
        conn: ConnArgs,
        /// Snapshot name.
        #[arg(long)]
        name: String,
    },
    /// List the node's local snapshots.
    List {
        #[command(flatten)]
        conn: ConnArgs,
    },
    /// Delete a local snapshot.
    Delete {
        #[command(flatten)]
        conn: ConnArgs,
        /// Snapshot name.
        #[arg(long)]
        name: String,
    },
    /// Replace the node's store with a snapshot (offline, node stopped).
    Restore {
        /// Data directory of the stopped node.
        #[arg(long, value_name = "PATH")]
        data_dir: PathBuf,
        /// Snapshot name.
        #[arg(long)]
        name: String,
        #[command(flatten)]
        kek: KekArgs,
    },
}

/// `rustegon dump`.
#[derive(Debug, Args)]
pub struct DumpArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Output directory (must be empty or absent).
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// Database to dump (repeatable; default: every database).
    #[arg(long = "database", value_name = "DB")]
    databases: Vec<String>,
    /// Collection to dump as `<db>.<coll>` (repeatable).
    #[arg(long = "collection", value_name = "DB.COLL")]
    collections: Vec<String>,
}

/// `rustegon restore` (logical).
#[derive(Debug, Args)]
pub struct RestoreArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Dump directory written by `rustegon dump`.
    #[arg(long, value_name = "PATH")]
    from: PathBuf,
    /// Drop existing target collections first (else an existing target is refused).
    #[arg(long)]
    drop: bool,
    /// Restore only this database (repeatable).
    #[arg(long = "database", value_name = "DB")]
    databases: Vec<String>,
    /// Restore only this collection, `<db>.<coll>` (repeatable).
    #[arg(long = "collection", value_name = "DB.COLL")]
    collections: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------------------------

fn hlc_text(t: Option<&rustegon_proto::v1::HlcTimestamp>) -> String {
    t.map_or_else(
        || "-".to_owned(),
        |t| format!("{}.{}", t.wall_ns, t.logical),
    )
}

fn backup_line(b: &BackupInfo) -> String {
    let encryption = match BackupEncryptionMode::try_from(b.encryption) {
        Ok(BackupEncryptionMode::Kek) => format!("kek:{}", b.kek_id.as_deref().unwrap_or("?")),
        Ok(BackupEncryptionMode::Plaintext) => "plaintext".to_owned(),
        _ => "unknown".to_owned(),
    };
    format!(
        "{}\tcreated={}\tT={}\tfiles={}\tbytes={}\tencryption={}",
        b.backup_id,
        crate::cert::utc_text(b.created_at_unix_ms.div_euclid(1000)),
        hlc_text(b.consistency.as_ref().and_then(|c| c.timestamp.as_ref())),
        b.file_count,
        b.total_bytes,
        encryption
    )
}

fn snapshot_line(s: &SnapshotInfo) -> String {
    format!(
        "{}\tcreated={}\tT={}\tfiles={}\tbytes={}",
        s.name,
        crate::cert::utc_text(s.created_at_unix_ms.div_euclid(1000)),
        hlc_text(s.consistency.as_ref().and_then(|c| c.timestamp.as_ref())),
        s.file_count,
        s.total_bytes
    )
}

fn backup_err(e: &rustegon_backup::BackupError) -> CliError {
    CliError(format!("RGN-{} {}: {e}", e.code().code(), e.code().name()))
}

fn rgn_err(e: &rustegon_common::Error) -> CliError {
    CliError(format!(
        "RGN-{} {}: {}",
        e.code().code(),
        e.code().name(),
        e.message()
    ))
}

/// Runs an offline restore (FR-BKP-001/003/005, PD-068), rolled forward to `pitr` when given
/// (FR-BKP-002), and prints what it did.
fn restore_offline(
    source: &dyn Destination,
    id: &BackupId,
    data_dir: &Path,
    kind: RestoreKind,
    kek: &KekArgs,
    pitr: Option<PitrTarget<'_>>,
) -> CliResult<()> {
    let request = RestoreRequest {
        source,
        id,
        data_dir,
        kind,
        kek: kek.provider()?,
    };
    let fs = Arc::new(StdFileSystem) as Arc<dyn rustegon_sim_api::FileSystem>;
    let clock = Arc::new(SystemClock::new()) as Arc<dyn rustegon_sim_api::Clock>;
    let rng = Arc::new(OsRng) as Arc<dyn rustegon_sim_api::Rng>;
    let report: RestoreReport = match pitr {
        Some(target) => restore_data_dir_to_time(&fs, &clock, &rng, &request, target),
        None => restore_data_dir(&fs, &clock, &rng, &request),
    }
    .map_err(|e| rgn_err(&e))?;
    if report.resumed {
        err("resumed an interrupted restore");
    }
    if let Some(previous) = &report.previous_store {
        out(&format!("previous store kept as {}", previous.display()))?;
    }
    if let Some(r) = &report.revert {
        out(&format!(
            "reverted to T: {} versions above T removed, {} pending intents aborted, {} \
             transaction records removed",
            r.versions_removed, r.intents_aborted, r.records_removed
        ))?;
    }
    let t = report.manifest.consistency.timestamp;
    out(&format!(
        "restored {} into {} (T={}.{}, {} files, {} bytes)",
        report.manifest.backup_id,
        data_dir.display(),
        t.wall,
        t.logical,
        report.manifest.files.len(),
        report.manifest.total_bytes()
    ))?;
    if let Some(p) = &report.pitr {
        out(&format!(
            "rolled forward to {}.{} (timeline {}, {} archived segments, {} log entries, stop \
             rule {:?})",
            p.target.wall, p.target.logical, p.timeline, p.segments, p.entries, p.stop
        ))?;
    }
    Ok(())
}

/// `backup restore` (module docs): plain, or point in time with `to_time`.
fn restore_backup(
    from: &str,
    id: Option<&str>,
    into: &Path,
    to_time: Option<&str>,
    archive: Option<&str>,
    kek: &KekArgs,
    s3: &S3Settings,
) -> CliResult<()> {
    let source = open_offline_with(from, s3)?;
    let Some(to_time) = to_time else {
        // clap requires `--id` without `--to-time`.
        let id = BackupId::parse(id.unwrap_or_default()).map_err(|e| backup_err(&e))?;
        return restore_offline(source.as_ref(), &id, into, RestoreKind::Backup, kek, None);
    };
    let ts = rustegon_backup::pitr::parse_target_time(to_time).map_err(|e| rgn_err(&e))?;
    let id = if let Some(id) = id {
        BackupId::parse(id).map_err(|e| backup_err(&e))?
    } else {
        let base =
            rustegon_backup::pitr::select_base(source.as_ref(), ts).map_err(|e| rgn_err(&e))?;
        BackupId::parse(&base.backup_id).map_err(|e| backup_err(&e))?
    };
    let archive = open_offline_with(archive.unwrap_or(from), s3)?;
    restore_offline(
        source.as_ref(),
        &id,
        into,
        RestoreKind::Backup,
        kek,
        Some(PitrTarget {
            archive: archive.as_ref(),
            ts,
        }),
    )
}

// ---------------------------------------------------------------------------------------------
// backup
// ---------------------------------------------------------------------------------------------

/// Runs `rustegon backup …`.
///
/// # Errors
/// Option, connection, server and file errors.
pub fn run_backup(args: BackupArgs) -> CliResult<()> {
    match args.command {
        BackupCommand::Create { conn, to } => with_client(&conn, |client| {
            let mut svc = BackupServiceClient::new(client.channel());
            let r = client
                .call(svc.create_backup(client.request(CreateBackupRequest { destination: to })))?
                .into_inner();
            for w in &r.warnings {
                err(&format!("warning: {}", w.message));
            }
            let b = r
                .backup
                .ok_or_else(|| CliError("the server returned no backup".into()))?;
            out(&format!("created {}", backup_line(&b)))
        }),
        BackupCommand::List { conn, dest } => with_client(&conn, |client| {
            let mut svc = BackupServiceClient::new(client.channel());
            let r = client
                .call(svc.list_backups(client.request(ListBackupsRequest { destination: dest })))?
                .into_inner();
            for b in &r.backups {
                out(&backup_line(b))?;
            }
            for u in &r.unreadable {
                let why = u
                    .error
                    .as_ref()
                    .map_or_else(String::new, |e| format!("RGN-{} {}", e.code, e.name));
                out(&format!("{}\tunreadable\t{why}", u.backup_id))?;
            }
            Ok(())
        }),
        // FR-BKP-001: the manifest as the server sees it (the GUI's backup detail, S22), one
        // backup line then one `path\tsize\tblake3` line per file.
        BackupCommand::Get { conn, dest, id } => with_client(&conn, |client| {
            let mut svc = BackupServiceClient::new(client.channel());
            let r = client
                .call(svc.get_backup(client.request(GetBackupRequest {
                    destination: dest,
                    backup_id: id,
                })))?
                .into_inner();
            let b = r
                .backup
                .ok_or_else(|| CliError("the server returned no backup".into()))?;
            out(&backup_line(&b))?;
            for f in &r.files {
                out(&format!("{}\t{}\t{}", f.path, f.size, f.blake3))?;
            }
            Ok(())
        }),
        BackupCommand::Verify { dest, id, deep, s3 } => {
            verify_offline(&dest, &id, deep, &s3.settings())
        }
        BackupCommand::Restore {
            from,
            id,
            into,
            to_time,
            archive,
            kek,
            s3,
        } => restore_backup(
            &from,
            id.as_deref(),
            &into,
            to_time.as_deref(),
            archive.as_deref(),
            &kek,
            &s3.settings(),
        ),
    }
}

fn with_client(conn: &ConnArgs, f: impl FnOnce(&Client) -> CliResult<()>) -> CliResult<()> {
    let client = Client::connect(conn)?;
    let result = f(&client);
    client.close();
    result
}

/// Opens a destination for reading on this machine without creating it.
fn open_offline_with(text: &str, s3: &S3Settings) -> CliResult<Box<dyn Destination>> {
    let url = DestinationUrl::parse(text).map_err(|e| backup_err(&e))?;
    if let DestinationUrl::Local { path } = &url
        && StdFileSystem.read_dir(path).is_err()
    {
        return fail(format!("{}: no such destination directory", path.display()));
    }
    open_destination(&url, Arc::new(StdFileSystem), s3).map_err(|e| backup_err(&e))
}

fn verify_offline(dest: &str, id: &str, deep: bool, s3: &S3Settings) -> CliResult<()> {
    let destination = open_offline_with(dest, s3)?;
    let id = BackupId::parse(id).map_err(|e| backup_err(&e))?;
    let mode = if deep {
        VerifyMode::Deep
    } else {
        VerifyMode::Shallow
    };
    let report =
        rustegon_backup::verify(destination.as_ref(), &id, mode).map_err(|e| backup_err(&e))?;
    out(&format!(
        "backup {id} verified ({}): {} files, {} bytes hashed",
        if deep { "deep" } else { "shallow" },
        report.files_checked,
        report.bytes_hashed
    ))
}

/// A restore or dump target must be empty or absent (PD-064, RGN-1031 semantics).
fn ensure_empty_target(fs: &dyn FileSystem, dir: &Path) -> CliResult<()> {
    match fs.read_dir(dir) {
        Ok(entries) if entries.is_empty() => Ok(()),
        Ok(_) => fail(format!("{}: not empty", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(dir.display(), &e)),
    }
}

// ---------------------------------------------------------------------------------------------
// snapshot
// ---------------------------------------------------------------------------------------------

/// Runs `rustegon snapshot …`.
///
/// # Errors
/// Option, connection and server errors.
pub fn run_snapshot(args: SnapshotArgs) -> CliResult<()> {
    match args.command {
        SnapshotCommand::Create { conn, name } => with_client(&conn, |client| {
            let mut svc = BackupServiceClient::new(client.channel());
            let s = client
                .call(svc.create_snapshot(client.request(CreateSnapshotRequest { name })))?
                .into_inner()
                .snapshot
                .ok_or_else(|| CliError("the server returned no snapshot".into()))?;
            out(&format!("created {}", snapshot_line(&s)))
        }),
        SnapshotCommand::List { conn } => with_client(&conn, |client| {
            let mut svc = BackupServiceClient::new(client.channel());
            let list = client
                .call(svc.list_snapshots(client.request(ListSnapshotsRequest {})))?
                .into_inner()
                .snapshots;
            for s in &list {
                out(&snapshot_line(s))?;
            }
            Ok(())
        }),
        SnapshotCommand::Delete { conn, name } => with_client(&conn, |client| {
            let mut svc = BackupServiceClient::new(client.channel());
            let deleted =
                client
                    .call(svc.delete_snapshot(
                        client.request(DeleteSnapshotRequest { name: name.clone() }),
                    ))?
                    .into_inner()
                    .deleted;
            if deleted {
                out(&format!("deleted snapshot {name}"))
            } else {
                fail(format!("no snapshot {name}"))
            }
        }),
        SnapshotCommand::Restore {
            data_dir,
            name,
            kek,
        } => {
            if StdFileSystem.read_dir(&data_dir).is_err() {
                return fail(format!("{}: no such data directory", data_dir.display()));
            }
            if !valid_name(&name) {
                return fail(format!("invalid snapshot name {name:?}"));
            }
            let id = BackupId::parse(&name).map_err(|e| backup_err(&e))?;
            let snapshots = snapshots_dir(&data_dir);
            if StdFileSystem.read_dir(&snapshots).is_err() {
                return fail(format!("{}: no snapshots", data_dir.display()));
            }
            let source = LocalDestination::open(Arc::new(StdFileSystem), &snapshots)
                .map_err(|e| backup_err(&e))?;
            restore_offline(&source, &id, &data_dir, RestoreKind::Snapshot, &kek, None)
        }
    }
}

/// The snapshot name rule of the server (`SnapshotName`), checked before anything else.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

// ---------------------------------------------------------------------------------------------
// dump / restore
// ---------------------------------------------------------------------------------------------

/// Writes the chunks of a dump stream into a directory (order rules of backup.proto
/// `DumpChunk`: files contiguous, never reopened, valid keys).
struct DumpWriter<'a> {
    fs: &'a dyn FileSystem,
    root: PathBuf,
    open: Option<(String, Box<dyn rustegon_sim_api::File>)>,
    finished: BTreeSet<String>,
    dirs: BTreeSet<PathBuf>,
}

impl<'a> DumpWriter<'a> {
    fn new(fs: &'a dyn FileSystem, root: &Path) -> CliResult<Self> {
        ensure_empty_target(fs, root)?;
        fs.create_dir_all(root)
            .map_err(|e| io_err(root.display(), &e))?;
        Ok(Self {
            fs,
            root: root.to_path_buf(),
            open: None,
            finished: BTreeSet::new(),
            dirs: BTreeSet::from([root.to_path_buf()]),
        })
    }

    fn chunk(&mut self, path: &str, data: &[u8], end_of_file: bool) -> CliResult<()> {
        validate_key(path).map_err(|e| CliError(format!("the server sent {e}")))?;
        if self.finished.contains(path) {
            return fail(format!("the server sent file {path} twice"));
        }
        let reuse = matches!(&self.open, Some((open, _)) if open == path);
        if !reuse {
            if let Some((open, _)) = &self.open {
                return fail(format!("the server interleaved {path} with {open}"));
            }
            let target = self.root.join(path);
            if let Some(parent) = target.parent() {
                self.fs
                    .create_dir_all(parent)
                    .map_err(|e| io_err(parent.display(), &e))?;
                self.dirs.insert(parent.to_path_buf());
            }
            let file = self
                .fs
                .open(&target, OpenMode::CreateNew)
                .map_err(|e| io_err(target.display(), &e))?;
            self.open = Some((path.to_owned(), file));
        }
        if let Some((_, file)) = &mut self.open {
            file.append(data)
                .map_err(|e| io_err(self.root.join(path).display(), &e))?;
        }
        if end_of_file && let Some((name, file)) = self.open.take() {
            file.sync_data()
                .map_err(|e| io_err(self.root.join(&name).display(), &e))?;
            self.finished.insert(name);
        }
        Ok(())
    }

    fn finish(self) -> CliResult<usize> {
        if let Some((open, _)) = &self.open {
            return fail(format!("the dump ended inside file {open}"));
        }
        if !self.finished.contains(DUMP_MANIFEST) {
            return fail(format!("the dump has no {DUMP_MANIFEST}"));
        }
        for dir in &self.dirs {
            self.fs
                .sync_dir(dir)
                .map_err(|e| io_err(dir.display(), &e))?;
        }
        Ok(self.finished.len())
    }
}

/// Runs `rustegon dump`.
///
/// # Errors
/// Option, connection, server and file errors; a partial output directory is left for
/// inspection and must be removed before retrying.
pub fn run_dump(args: &DumpArgs) -> CliResult<()> {
    let fs = StdFileSystem;
    // The target is checked before connecting, so a typo costs no server work.
    ensure_empty_target(&fs, &args.out)?;
    with_client(&args.conn, |client| {
        let mut svc = BackupServiceClient::new(client.channel());
        let mut stream = client
            .call(svc.dump(client.request(DumpRequest {
                databases: args.databases.clone(),
                collections: args.collections.clone(),
            })))?
            .into_inner();
        let mut writer = DumpWriter::new(&fs, &args.out)?;
        let mut started = None;
        // One message at a time on the client's runtime; file writes happen here, on the
        // command's own thread, never on an async worker.
        while let Some(message) = client.call(stream.message())? {
            match message.item {
                Some(dump_response::Item::Started(t)) => started = Some(t),
                Some(dump_response::Item::Chunk(c)) => {
                    if started.is_none() {
                        return fail("the server sent data before the dump timestamp");
                    }
                    writer.chunk(&c.path, &c.data, c.end_of_file)?;
                }
                None => return fail("the server sent an empty dump message"),
            }
        }
        let files = writer.finish()?;
        out(&format!(
            "dumped {files} files to {} at T={}",
            args.out.display(),
            hlc_text(started.as_ref())
        ))
    })
}

/// The files of a dump directory in sending order: every file in path order, `dump.json` last.
fn dump_files(dest: &dyn Destination) -> CliResult<Vec<String>> {
    let mut keys = dest.list("").map_err(|e| backup_err(&e))?;
    let Some(pos) = keys.iter().position(|k| k == DUMP_MANIFEST) else {
        return fail(format!("not a dump directory: no {DUMP_MANIFEST}"));
    };
    let manifest = keys.remove(pos);
    keys.push(manifest);
    Ok(keys)
}

/// Runs `rustegon restore` (logical).
///
/// # Errors
/// Option, connection, server and file errors.
pub fn run_restore(args: &RestoreArgs) -> CliResult<()> {
    let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
    if fs.read_dir(&args.from).is_err() {
        return fail(format!("{}: no such dump directory", args.from.display()));
    }
    let dir = LocalDestination::open(Arc::clone(&fs), &args.from).map_err(|e| backup_err(&e))?;
    let files = dump_files(&dir)?;
    with_client(&args.conn, |client| {
        let (tx, rx) = tokio::sync::mpsc::channel::<LogicalRestoreRequest>(4);
        let mut svc = BackupServiceClient::new(client.channel());
        let request = client.request(ReceiverStream::new(rx));
        let call = client.spawn(async move { svc.logical_restore(request).await });
        let push = |item| {
            tx.blocking_send(LogicalRestoreRequest { item: Some(item) })
                .map_err(|_| CliError("the server ended the restore early".into()))
        };
        let pushed = (|| {
            push(logical_restore_request::Item::Options(
                LogicalRestoreOptions {
                    drop_existing: args.drop,
                    databases: args.databases.clone(),
                    collections: args.collections.clone(),
                },
            ))?;
            for key in &files {
                let reader = dir.open(key).map_err(|e| backup_err(&e))?;
                let size = reader.size();
                let mut offset = 0u64;
                loop {
                    let n =
                        usize::try_from(size - offset).map_or(CHUNK_BYTES, |r| r.min(CHUNK_BYTES));
                    let mut buf = vec![0u8; n];
                    reader
                        .read_exact_at(&mut buf, offset)
                        .map_err(|e| backup_err(&e))?;
                    offset += n as u64;
                    let end_of_file = offset >= size;
                    push(logical_restore_request::Item::Chunk(
                        rustegon_proto::v1::DumpChunk {
                            path: key.clone(),
                            data: buf,
                            end_of_file,
                        },
                    ))?;
                    if end_of_file {
                        break;
                    }
                }
            }
            Ok::<(), CliError>(())
        })();
        // Closing the request stream tells the server the dump is complete.
        drop(tx);
        let response = client
            .call(call)
            .map_err(|_| CliError("the restore task failed".into()))?;
        // The server's answer explains an early end better than the local send error.
        let summary = response?.into_inner();
        pushed?;
        for c in &summary.collections {
            out(&format!(
                "restored {}.{}\tdocuments={}\tindexes={}",
                c.database, c.collection, c.documents, c.indexes
            ))?;
        }
        out(&format!(
            "restored {} collections from {} (dump T={})",
            summary.collections.len(),
            args.from.display(),
            hlc_text(summary.source_timestamp.as_ref())
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn fr_bkp_007_dump_writer_follows_the_chunk_order_rules() {
        let dir = temp();
        let root = dir.path().join("out");
        let fs = StdFileSystem;
        let mut w = DumpWriter::new(&fs, &root).unwrap_or_else(|e| panic!("{e}"));
        w.chunk("shop/a.metadata.json", b"{}", true)
            .unwrap_or_else(|e| panic!("{e}"));
        w.chunk("shop/a.ndjson", b"{\"_id\":1}\n", false)
            .unwrap_or_else(|e| panic!("{e}"));
        w.chunk("shop/a.ndjson", b"{\"_id\":2}\n", true)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(w.chunk("shop/a.ndjson", b"", true).is_err(), "reopened");
        assert!(w.chunk("../evil", b"", true).is_err(), "traversal");
        w.chunk(DUMP_MANIFEST, b"{}", true)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(w.finish().unwrap_or_else(|e| panic!("{e}")), 3);
        let data = std::fs::read(root.join("shop").join("a.ndjson")).unwrap_or_default();
        assert_eq!(data, b"{\"_id\":1}\n{\"_id\":2}\n");
        // The sending order of `restore`: path order, dump.json last.
        let dest = LocalDestination::open(Arc::new(StdFileSystem), &root)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            dump_files(&dest).unwrap_or_else(|e| panic!("{e}")),
            ["shop/a.metadata.json", "shop/a.ndjson", DUMP_MANIFEST]
        );
        // A dump needs its manifest; interleaved files and a non-empty target are refused.
        let interleaved = dir.path().join("interleaved");
        let mut w = DumpWriter::new(&fs, &interleaved).unwrap_or_else(|e| panic!("{e}"));
        w.chunk("x", b"1", false).unwrap_or_else(|e| panic!("{e}"));
        assert!(w.chunk("y", b"1", true).is_err());
        assert!(DumpWriter::new(&fs, &root).is_err());
        let without_manifest = dir.path().join("without-manifest");
        let mut w = DumpWriter::new(&fs, &without_manifest).unwrap_or_else(|e| panic!("{e}"));
        w.chunk("x", b"1", true).unwrap_or_else(|e| panic!("{e}"));
        assert!(w.finish().is_err(), "no dump.json");
    }

    #[test]
    fn fr_bkp_003_snapshot_names_match_the_server_rule() {
        assert!(valid_name("pre-upgrade"));
        assert!(!valid_name(".x"));
        assert!(!valid_name("a/b"));
        assert!(!valid_name(""));
    }
}
