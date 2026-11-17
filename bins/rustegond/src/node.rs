// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Startup, serving and graceful shutdown of a single node (M4 wave 2c, PD-054).
//!
//! Startup (blocking, before any listener exists; each step fails the start with its reason):
//! 1. transport security: TLS certificate, key and client CA loaded and validated, or plain
//!    text unless `security.tls = true` (single node, ADR-034; `crate::tls`);
//! 2. the KEK of encryption at rest when `storage.encryption` is on (`file` or `env` provider;
//!    missing, malformed or exposed key → RGN-4006, PD-057), before the data directory is
//!    touched;
//! 3. the continuation-token key file (`crate::token_key`);
//! 4. a data directory holding an unfinished offline restore (`restore-in-progress.json`) is
//!    refused with RGN-3002 (rerun the restore first); with `[backup.pitr] enabled`, the PITR
//!    log archiver is prepared first (`crate::pitr`:
//!    destination checked against the backup allowlist, timeline and archive floor loaded from
//!    `<store>/pitr-archive.json`), then the engine on the real sim-api implementations
//!    (`<data_dir>/store`), encrypted at rest under that KEK (a wrong key or an encrypted store
//!    without one → RGN-4006) and opened with the archive floor, so no unarchived log segment
//!    is deleted, not even by the open; the engine holds `<data_dir>/store/LOCK` until it is
//!    dropped at the end of the shutdown, so a second node or an offline restore on the same
//!    data directory is refused with RGN-3002 (PD-068);
//! 5. the security layer: runtime setting overrides, audit log (`<data_dir>/audit`), limiters;
//! 6. first-admin bootstrap when the store has no user (security.md §2.2): the provided
//!    password, the turnkey `admin`/`admin` account with `security.turnkey_admin` (ADR-036), or
//!    a generated one; then a store whose `admin` still has the turnkey password is refused
//!    when any client listener is not on loopback (RGN-1001 `reason = turnkey_password_exposed`,
//!    ADR-036, TC-SEC-022);
//! 7. the services with the engine backup backend (physical backups and snapshots under
//!    `<data_dir>`, the `[backup]` destination allowlist plus `<data_dir>/backups`, PD-082;
//!    manifests record the PITR timeline when archiving is on),
//!    then both listeners; `ready` is printed once both are bound, and the
//!    readiness probe (`/api/v1/health/ready`) turns 200 (PD-059); the node certificate's
//!    expiry is exported as `rustegon_cert_expiry_seconds`;
//! 8. interrupted index builds resume in the background (blocking pool), and the storage
//!    maintenance loops start: background flush + log purge and compaction
//!    (`crate::maintenance`, PD-061), and the PITR archiver task (`crate::pitr`), whose
//!    counters `/metrics` exports.
//!
//! Shutdown (SIGTERM/SIGINT, Windows console events, stdin EOF with `--stop-on-stdin-eof`,
//! or a stop/shutdown/preshutdown control of the Windows service, `crate::service`): the readiness probe turns 503 (draining) and the node keeps serving
//! for `listen.drain_delay_secs` (default 0) so load balancers stop routing to it, then it
//! stops accepting and drains both listeners for up to
//! `listen.shutdown_grace_secs`, stop the certificate reload loop, roll back open interactive
//! transactions and close open cursors, stop the storage maintenance loops (a running
//! compaction is waited for at most 5 s), run the PITR archiver's final pass (a roll, then
//! every sealed segment archived; at most 30 s), flush the engine's memtables to SSTs (a shutdown
//! checkpoint, PD-057: not needed for durability, it shortens the next replay and moves the data
//! out of the log), then drop the services, the audit log and the engine. Audit records are
//! synced one by one when written, so there is nothing left to flush there; every acknowledged
//! commit is durable in the replicated log (the WAL), so a failed checkpoint loses nothing.

use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustegon_backup::{
    BackupSettings, DestinationPolicy, PhysicalBackups, PhysicalConfig, SourceInfo,
};
use rustegon_common::{
    Error, ErrorCode, Result,
    settings::{Config, NodeSettings, Registry, Sources},
};
use rustegon_engine::{EmbeddedDb, embedded::LogStoreOptions};
use rustegon_index::BuildConfig;
use rustegon_net::ReloadableCert;
use rustegon_security::authn::{
    SecretString,
    bootstrap::{AdminPassword, DEFAULT_ADMIN_USER, has_turnkey_password, is_bootstrapped},
    secret,
    users::get_user,
};
use rustegon_server::{
    DEFAULT_MAX_IN_FLIGHT, Executor,
    grpc::{GrpcServer, GrpcServerOptions},
    rest::{RestServer, RestServerOptions},
    security::{
        BootstrapOutcome, EngineTxn, INITIAL_ADMIN_PASSWORD_FILE, Security, SecurityConfig,
        write_initial_password,
    },
    services::{
        DataPlaneConfig, NodeIdentity, ServiceDeps, Services, backup::ScheduledRestore,
        backup_engine::EngineBackupBackend,
    },
};
use rustegon_sim_api::{
    Clock, FileSystem, OpenMode, OsRng, Rng, StdFileSystem, SystemClock, TokioNetwork,
};
use rustegon_storage::{
    EngineOptions, compaction::default_max_subcompactions, encryption::KekProvider,
    settings::StorageSettings,
};
use tokio::sync::{Notify, oneshot, watch};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    config::{GuiSettings, ListenSettings, SecuritySettings, TlsFileSettings},
    maintenance::Maintenance,
    pitr::{PitrTask, PreparedPitr},
    signals::Signals,
    tls::{self, Transport},
    token_key,
};

/// Node id of a single node until cluster membership assigns ids (M5).
const SINGLE_NODE_ID: u64 = 1;
/// Name of the store directory under the data directory.
const STORE_DIR: &str = "store";
/// Default backup directory under the data directory, always allowed as a destination
/// (PD-082).
const DEFAULT_BACKUP_DIR: &str = "backups";
/// Cluster id recorded in backup manifests until cluster membership assigns one (M5).
const SINGLE_NODE_CLUSTER_ID: &str = "single-node";
/// Largest accepted admin password file (a password is at most a few hundred bytes).
const MAX_PASSWORD_FILE: u64 = 4096;
/// How long the process waits for blocking tasks (e.g. a resumed index build step) after the
/// shutdown sequence; an interrupted build resumes from its checkpoint at the next start.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Inputs of [`run`] besides the configuration.
pub struct Options {
    /// The registry the configuration was loaded with (the security layer reloads it with the
    /// persisted runtime overrides).
    pub registry: Arc<Registry>,
    /// The configuration layers (file, environment, flags).
    pub sources: Sources,
    /// The first admin's password file (`--admin-password-file` or
    /// `RUSTEGON_INITIAL_ADMIN_PASSWORD_FILE`); without one a password is generated.
    pub admin_password_file: Option<PathBuf>,
    /// Shut down when standard input reaches its end.
    pub stop_on_stdin_eof: bool,
    /// A supervisor's stop request (the Windows SCM, `crate::service`), with its reason.
    pub stop: Option<oneshot::Receiver<&'static str>>,
    /// Called once when both listeners are bound (the SCM's `RUNNING`).
    pub on_ready: Option<Box<dyn FnOnce() + Send>>,
}

/// Everything opened by the startup sequence.
struct Node {
    services: Services,
    transport: Transport,
    listen: ListenSettings,
    gui: GuiSettings,
    reload_period: Duration,
    clock: Arc<dyn Clock>,
    engine: Arc<EmbeddedDb>,
    /// The PITR archiver, started with the maintenance loops (`None`: archiving off).
    pitr: Option<(PreparedPitr, Option<Arc<dyn KekProvider>>)>,
    /// Wakes the serving loop when an online restore is accepted (ADR-037).
    restore: oneshot::Receiver<ScheduledRestore>,
}

fn io_error(what: &Path, e: &io::Error) -> Error {
    Error::new(ErrorCode::Internal, format!("{}: {e}", what.display()))
}

/// Runs the node until a shutdown is requested (module docs).
///
/// # Errors
/// Any startup failure, with its reason.
pub fn run(config: &Config, mut options: Options) -> Result<()> {
    let mut stop = if options.stop_on_stdin_eof {
        Some(crate::signals::stdin_eof().map_err(|e| {
            Error::new(ErrorCode::Internal, "cannot watch standard input").with_source(e)
        })?)
    } else {
        options.stop.take()
    };
    let mut on_ready = options.on_ready.take();
    // Every serving period opens the node from these inputs again (online restore, ADR-037).
    // The startup wipes an `env` KEK from the copy it is given, so each period gets a fresh copy
    // of the captured environment; the process environment keeps the variable anyway (PD-057).
    let sources = options.sources;
    loop {
        // An online restore accepted before a stop or a crash finishes before the node serves.
        let restored = crate::restore::run_pending(config, &sources)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("rustegond")
            .build()
            .map_err(|e| {
                Error::new(ErrorCode::Internal, "cannot start the runtime").with_source(e)
            })?;
        let result = {
            // The startup steps are blocking and run on this thread, but inside the runtime
            // context: the data plane starts its sweeper task on construction.
            let _context = runtime.enter();
            let signals = Signals::install().map_err(|e| {
                Error::new(ErrorCode::Internal, "cannot install signal handlers").with_source(e)
            })?;
            let period = Options {
                registry: Arc::clone(&options.registry),
                sources: sources.clone(),
                admin_password_file: options.admin_password_file.clone(),
                stop_on_stdin_eof: false,
                stop: None,
                on_ready: None,
            };
            open(config, period, restored).and_then(|node| {
                runtime.block_on(serve(node, signals, stop.as_mut(), on_ready.take()))
            })
        };
        // Also lets go of the engine held by blocking tasks before a restore swaps the store.
        runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
        match result? {
            Served::Stopped => return Ok(()),
            Served::Restore => tracing::info!("serving again after the online restore"),
        }
    }
}

/// How a serving period ended.
enum Served {
    /// A shutdown was requested: the process ends.
    Stopped,
    /// An online restore was accepted (ADR-037): restore, then serve again.
    Restore,
}

/// Startup steps 1–6 and the services (module docs). Blocking.
// The startup order of the module docs, top to bottom; splitting it would scatter that order.
#[allow(clippy::too_many_lines)]
/// `restored`: an online restore just replaced the store (ADR-037); its sessions are revoked
/// before the node serves.
fn open(config: &Config, options: Options, restored: bool) -> Result<Node> {
    let node: NodeSettings = config.section()?;
    let storage: StorageSettings = config.section()?;
    let listen: ListenSettings = config.section()?;
    let gui: GuiSettings = config.section()?;
    let security_settings: SecuritySettings = config.section()?;
    let tls_settings: TlsFileSettings = config.section()?;
    let backup_settings: BackupSettings = config.section()?;
    let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let rng: Arc<dyn Rng> = Arc::new(OsRng);
    let data_dir = node.data_dir;

    // Transport security before the store: a configuration error must not leave a freshly
    // created, bootstrapped store behind.
    let resolved_tls = tls_settings.resolve(&security_settings.certs_dir(&data_dir))?;
    let transport = tls::setup(security_settings.tls, &resolved_tls, &fs, &clock)?;

    // The KEK, for the same reason before the data directory is touched: a missing, malformed
    // or (Unix) group-readable key refuses the start with RGN-4006 and a reason naming the file
    // or variable, never the key (security.md §6, PD-057).
    let mut options = options;
    let kek = encryption_key(&storage, fs.as_ref(), &mut options.sources)?;
    let kek_id = kek.as_ref().map(|k| k.key_id().to_string());
    let backup_policy = backup_policy(&backup_settings, &data_dir)?;

    fs.create_dir_all(&data_dir)
        .map_err(|e| io_error(&data_dir, &e))?;
    let (token_key, created) = token_key::load_or_create(
        fs.as_ref(),
        rng.as_ref(),
        &security_settings.cursor_token_key_file(&data_dir),
    )?;
    if created {
        tracing::info!(
            path = %security_settings.cursor_token_key_file(&data_dir).display(),
            "created the cursor token key"
        );
    }

    let store_dir = data_dir.join(STORE_DIR);
    refuse_unfinished_restore(fs.as_ref(), &data_dir)?;
    let pitr = prepare_pitr(
        &backup_settings,
        &backup_policy,
        &fs,
        rng.as_ref(),
        &store_dir,
    )?;
    let engine = open_engine(
        &fs,
        &store_dir,
        &clock,
        &rng,
        &storage,
        kek.clone(),
        pitr.as_ref(),
    )?;

    let timeline = pitr.as_ref().map(|p| p.timeline().to_owned());
    let (restore_scheduler, restore) =
        crate::restore::scheduler(Arc::clone(&fs), data_dir.clone(), kek_id.clone());
    let backup_backend = backup_backend(&engine, &fs, &clock, &rng, &data_dir, kek_id, timeline)?;

    let deps = ServiceDeps {
        clock: Arc::clone(&clock),
        rng,
        executor: Executor::new(Arc::clone(&clock), DEFAULT_MAX_IN_FLIGHT),
    };
    let security = Security::open(
        SecurityConfig::new(
            Arc::clone(&engine),
            Arc::clone(&fs),
            data_dir.clone(),
            format!("node{SINGLE_NODE_ID}"),
            options.registry,
            options.sources,
        ),
        &deps,
    )?;
    bootstrap(
        &security,
        &engine,
        fs.as_ref(),
        &data_dir,
        options.admin_password_file.as_deref(),
        security_settings.turnkey_admin,
    )?;
    refuse_exposed_turnkey_password(&engine, &listen)?;
    if restored {
        let revoked = security.revoke_all_sessions()?;
        tracing::info!(revoked, "sessions restored with the backup revoked");
    }

    let data_plane = DataPlaneConfig {
        token_key: Some(*token_key),
        ..DataPlaneConfig::default()
    };
    let services = Services::new(
        deps,
        NodeIdentity {
            node_id: SINGLE_NODE_ID,
            features: Vec::new(),
            client_addresses: Vec::new(),
        },
    )
    .with_security(security)
    .with_engine(Arc::clone(&engine), data_plane)
    .with_backup_backend(backup_backend)
    .with_backup_destinations(backup_policy)
    .with_backup_s3(backup_settings.s3)
    .with_restore_scheduler(restore_scheduler);
    Ok(Node {
        services,
        transport,
        listen,
        gui,
        reload_period: tls_settings.reload_period(),
        clock,
        engine,
        pitr: pitr.map(|p| (p, kek)),
        restore,
    })
}

/// Startup step 4 (module docs): an offline restore that was interrupted (its journal is still
/// in the data directory) must be finished by rerunning it before the node starts. Between its
/// swap steps there may be no `store` at all, and the node would create an empty one that the
/// rerun then refuses to replace; with the swap done the engine refuses the store itself
/// (`RESTORING`). Both are RGN-3002.
fn refuse_unfinished_restore(fs: &dyn FileSystem, data_dir: &Path) -> Result<()> {
    let journal = data_dir.join(rustegon_backup::offline::JOURNAL_FILE);
    match fs.open(&journal, OpenMode::Read) {
        Ok(_) => Err(Error::new(
            ErrorCode::Unavailable,
            format!(
                "{} holds an unfinished offline restore ({}); rerun the same `rustegon backup restore` or `rustegon snapshot restore` command to finish it",
                data_dir.display(),
                journal.display()
            ),
        )
        .with_detail("reason", "restore_in_progress")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::new(
            ErrorCode::Unavailable,
            format!("{}: {e}", journal.display()),
        )),
    }
}

/// Startup step 4 (module docs): the engine, with the PITR archive floor when archiving is on.
fn open_engine(
    fs: &Arc<dyn FileSystem>,
    store_dir: &Path,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn Rng>,
    storage: &StorageSettings,
    kek: Option<Arc<dyn KekProvider>>,
    pitr: Option<&PreparedPitr>,
) -> Result<Arc<EmbeddedDb>> {
    let engine = Arc::new(EmbeddedDb::open_with_log_options(
        Arc::clone(fs),
        store_dir,
        Arc::clone(clock),
        Arc::clone(rng),
        EngineOptions::from_settings(storage),
        kek,
        LogStoreOptions {
            archive_floor: pitr.map(PreparedPitr::floor),
            ..LogStoreOptions::default()
        },
    )?);
    tracing::info!(
        store = %store_dir.display(),
        encrypted = engine.is_encrypted(),
        "store opened"
    );
    if let Some(n) = engine.plaintext_sst_count().filter(|&n| n > 0) {
        // Storage-engine.md §7: a store switched to encryption keeps the files written before
        // the switch until compaction rewrites them; say so at every start (PD-057).
        tracing::warn!(
            plaintext_files = n,
            "encryption at rest is on, but data files written before it was enabled are still \
             plaintext; they are encrypted as compaction rewrites them"
        );
    }
    Ok(engine)
}

/// Startup step 4, PITR part (module docs): refuses a second node on the same data directory
/// before the archiver state is touched. The engine's own lock check comes later (it needs the
/// archive floor at open); this earlier check keeps a node that is about to fail from creating
/// a timeline under a running one. Two nodes starting at the same instant on a fresh data
/// directory can still both get here; the loser fails at the engine lock, and the timeline file
/// it may have written only means a new timeline at the next start (backups taken meanwhile
/// keep pointing at the archive of the timeline they were taken under).
fn prepare_pitr(
    settings: &BackupSettings,
    policy: &DestinationPolicy,
    fs: &Arc<dyn FileSystem>,
    rng: &dyn Rng,
    store_dir: &Path,
) -> Result<Option<PreparedPitr>> {
    if !settings.pitr.enabled {
        return Ok(None);
    }
    if rustegon_engine::embedded::StoreLock::is_held(fs.as_ref(), store_dir)? {
        return Err(Error::new(
            ErrorCode::Unavailable,
            format!(
                "{}: the store is in use by another process",
                store_dir.display()
            ),
        ));
    }
    crate::pitr::prepare(&settings.pitr, policy, &settings.s3, fs, rng, store_dir)
}

/// The engine backup backend (M13a lane BE): physical backups staged and snapshots kept under
/// `data_dir`, manifests naming this node, for an encrypted store its KEK id (PD-064) and, with
/// archiving on, the PITR timeline (lane BF).
fn backup_backend(
    engine: &Arc<EmbeddedDb>,
    fs: &Arc<dyn FileSystem>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn Rng>,
    data_dir: &Path,
    kek_id: Option<String>,
    pitr_timeline: Option<String>,
) -> Result<Arc<EngineBackupBackend>> {
    let mut config = PhysicalConfig::new(
        data_dir.to_path_buf(),
        SourceInfo {
            cluster_id: SINGLE_NODE_CLUSTER_ID.to_owned(),
            node_id: format!("node{SINGLE_NODE_ID}"),
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        kek_id,
    );
    // A backup taken with archiving on names the archive that continues it (FR-BKP-002).
    config.pitr_timeline = pitr_timeline;
    // One `<id>.bak` file per backup (ADR-037).
    config.single_file = true;
    let physical = PhysicalBackups::open(
        Arc::clone(engine),
        Arc::clone(fs),
        Arc::clone(clock),
        Arc::clone(rng),
        config,
    )?;
    Ok(Arc::new(EngineBackupBackend::new(
        Arc::clone(engine),
        physical,
    )))
}

/// The backup destination allowlist (PD-082): `[backup] allowed_destinations` plus the
/// default `<data_dir>/backups`. A relative data directory (development default) is made
/// absolute first, since destinations of requests must be absolute.
fn backup_policy(settings: &BackupSettings, data_dir: &Path) -> Result<DestinationPolicy> {
    let data_dir = std::path::absolute(data_dir).map_err(|e| io_error(data_dir, &e))?;
    let policy = DestinationPolicy::from_settings(settings, &data_dir.join(DEFAULT_BACKUP_DIR))?;
    for entry in policy.entries() {
        tracing::info!(destination = %entry, "backup destination allowed");
    }
    Ok(policy)
}

/// The KEK provider of `[storage]` (security.md §6, PD-057), or `None` without encryption at
/// rest. The `env` provider reads the variable from the environment captured at startup and
/// then wipes the value from that copy (it is also re-read for runtime setting reloads, which
/// never need it). The process environment itself keeps the variable: removing it is unsound
/// once threads run, so deployments that must not expose it to same-user processes use the
/// `file` provider (docker.md, PD-057).
pub(crate) fn encryption_key(
    storage: &StorageSettings,
    fs: &dyn FileSystem,
    sources: &mut Sources,
) -> Result<Option<Arc<dyn KekProvider>>> {
    let lookup = |name: &str| {
        sources
            .env
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| Zeroizing::new(v.clone()))
    };
    let provider = storage.kek_provider(fs, &lookup)?;
    if storage.kek_from_env() {
        for (key, value) in &mut sources.env {
            if *key == storage.encryption_key_env {
                value.zeroize();
            }
        }
        sources
            .env
            .retain(|(key, _)| *key != storage.encryption_key_env);
    }
    if let Some(kek) = &provider {
        // The id is a key check value, not the key; it lets an operator tell keys apart.
        tracing::info!(provider = %storage.encryption_key_provider, kek_id = %kek.key_id(), "encryption at rest enabled");
    }
    Ok(provider)
}

/// Reads the operator's admin password file: the whole content minus one trailing line ending.
fn read_password_file(fs: &dyn FileSystem, path: &Path) -> Result<SecretString> {
    let file = fs
        .open(path, OpenMode::Read)
        .map_err(|e| io_error(path, &e))?;
    let size = file.size().map_err(|e| io_error(path, &e))?;
    if size > MAX_PASSWORD_FILE {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{}: admin password file too large", path.display()),
        ));
    }
    let len =
        usize::try_from(size).map_err(|_| io_error(path, &io::ErrorKind::InvalidData.into()))?;
    let mut raw = Zeroizing::new(vec![0u8; len]);
    file.read_exact_at(&mut raw, 0)
        .map_err(|e| io_error(path, &e))?;
    let text = std::str::from_utf8(&raw).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("{}: admin password file is not UTF-8", path.display()),
        )
    })?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    Ok(secret(text))
}

fn exists(fs: &dyn FileSystem, path: &Path) -> Result<bool> {
    match fs.open(path, OpenMode::Read) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(path, &e)),
    }
}

/// First-admin bootstrap (security.md §2.2, FR-SEC-003): runs only while the store has no
/// user. A provided password must pass the policy; otherwise a generated one is written to
/// `<data_dir>/initial-admin-password` (owner-only, never overwritten) and only its path is
/// printed and logged.
fn bootstrap(
    security: &Security,
    engine: &EmbeddedDb,
    fs: &dyn FileSystem,
    data_dir: &Path,
    password_file: Option<&Path>,
    turnkey: bool,
) -> Result<()> {
    if password_file.is_none() && turnkey {
        if let BootstrapOutcome::Created(_) =
            security.bootstrap_if_needed(DEFAULT_ADMIN_USER, AdminPassword::Turnkey)?
        {
            // The password is the documented one; it is still never logged (ADR-036).
            tracing::warn!(
                user = DEFAULT_ADMIN_USER,
                "first administrator created with the turnkey bootstrap password; it must be \
                 changed at first login and is accepted only while every listener is on loopback"
            );
        }
        return Ok(());
    }
    if let Some(path) = password_file {
        let password = read_password_file(fs, path)?;
        if let BootstrapOutcome::Created(_) =
            security.bootstrap_if_needed(DEFAULT_ADMIN_USER, AdminPassword::Provided(password))?
        {
            tracing::info!(
                user = DEFAULT_ADMIN_USER,
                "first administrator created with the provided password"
            );
        }
        return Ok(());
    }
    let file = data_dir.join(INITIAL_ADMIN_PASSWORD_FILE);
    if exists(fs, &file)? {
        // Normal on every restart. On a store without users it is a leftover: generating a new
        // password could not be written (the file is never overwritten) and the admin would be
        // unreachable, so refuse instead.
        let bootstrapped =
            engine.system_transaction(|h| is_bootstrapped(&EngineTxn(h)).map_err(Error::from))?;
        if !bootstrapped {
            return Err(Error::new(
                ErrorCode::PreconditionFailed,
                format!(
                    "{} exists but the store has no user; remove the stale file to bootstrap \
                     a new administrator",
                    file.display()
                ),
            ));
        }
        return Ok(());
    }
    let BootstrapOutcome::Created(created) =
        security.bootstrap_if_needed(DEFAULT_ADMIN_USER, AdminPassword::Generate)?
    else {
        return Ok(());
    };
    let password = created.generated_password.ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "bootstrap generated no password for the first administrator",
        )
    })?;
    // Committed before the file is written: a crash in between loses the password of a store
    // that holds nothing else yet (recover by removing the data directory, or provide
    // `--admin-password-file`). Generating it outside the bootstrap would need the policy and
    // `must_change_password` handling duplicated here (PD-054).
    let path = write_initial_password(fs, data_dir, &password)?;
    drop(password);
    tracing::info!(
        user = DEFAULT_ADMIN_USER,
        path = %path.display(),
        "first administrator created; its generated password is in the file (change it at \
         first login)"
    );
    // Printed once, path only: stdout may end up in a service journal.
    let mut out = io::stdout().lock();
    let _ = writeln!(
        out,
        "rustegond: initial password of user {DEFAULT_ADMIN_USER} written to {}",
        path.display()
    );
    let _ = out.flush();
    Ok(())
}

/// ADR-036 safeguard: while `admin` still has the turnkey bootstrap password, every client
/// listener must be on loopback, else the start is refused. Checked at every start (not only
/// the first), so editing the listen address before changing the password cannot expose it.
fn refuse_exposed_turnkey_password(engine: &EmbeddedDb, listen: &ListenSettings) -> Result<()> {
    let exposed: Vec<_> = [listen.grpc_addr()?, listen.http_addr()?]
        .into_iter()
        .filter(|a| !a.ip().is_loopback())
        .collect();
    if exposed.is_empty() {
        return Ok(());
    }
    let admin = engine
        .system_transaction(|h| get_user(&EngineTxn(h), DEFAULT_ADMIN_USER).map_err(Error::from))?;
    // PBKDF2 outside the transaction (users.rs `prepare_user`).
    if !admin.as_ref().is_some_and(has_turnkey_password) {
        return Ok(());
    }
    let list = exposed
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    Err(Error::new(
        ErrorCode::InvalidArgument,
        format!(
            "user {DEFAULT_ADMIN_USER} still has the turnkey bootstrap password and a listener \
             is not on loopback ({list}); sign in on http://localhost and change the password \
             first, or set [listen] to 127.0.0.1 (ADR-036)"
        ),
    )
    .with_detail("reason", "turnkey_password_exposed"))
}

async fn wait_stop(mut stop: watch::Receiver<bool>) {
    // A dropped sender also means stop.
    let _ = stop.wait_for(|stopped| *stopped).await;
}

/// Exports the node certificate's expiry as `rustegon_cert_expiry_seconds{cert="node"}`
/// (security.md §5; PD-059). The reloadable certificate is read at every scrape, so a renewal
/// shows at once.
fn export_cert_expiry(services: &Services, cert: &Arc<ReloadableCert>) {
    let cert = Arc::clone(cert);
    services
        .metrics()
        .register_cert("node", Arc::new(move || cert.expiry_seconds()));
}

/// First shutdown step (PD-059): the readiness probe answers 503 `draining`, and the node keeps
/// serving for `delay` so load balancers stop routing to it before the listeners close.
async fn report_draining(services: &Services, delay: Duration, clock: &dyn Clock, reason: &str) {
    services.readiness().mark_draining();
    if !delay.is_zero() {
        tracing::info!(
            reason,
            delay_secs = delay.as_secs(),
            "shutdown requested; reporting not ready before draining"
        );
        clock.sleep(delay).await;
    }
}

/// Binds the listeners, serves until shutdown, then runs the shutdown sequence.
// A linear startup/shutdown script: it reads top to bottom, and splitting it further would
// scatter the order the module docs describe.
#[allow(clippy::too_many_lines)]
async fn serve(
    node: Node,
    signals: Signals,
    stop: Option<&mut oneshot::Receiver<&'static str>>,
    on_ready: Option<Box<dyn FnOnce() + Send>>,
) -> Result<Served> {
    let Node {
        services,
        transport,
        listen,
        gui,
        reload_period,
        clock,
        engine,
        pitr,
        restore,
    } = node;
    let grace = listen.shutdown_grace();
    let tls = transport.listener.is_tls();
    let bind_error =
        |e: rustegon_server::ServerError| Error::new(ErrorCode::Internal, e.to_string());
    let grpc = GrpcServer::bind(
        &TokioNetwork,
        listen.grpc_addr()?,
        transport.listener.clone(),
        &services,
        GrpcServerOptions {
            shutdown_grace: grace,
            ..GrpcServerOptions::default()
        },
    )
    .await
    .map_err(bind_error)?;
    let rest = RestServer::bind(
        &TokioNetwork,
        listen.http_addr()?,
        transport.listener,
        &services,
        RestServerOptions {
            shutdown_grace: grace,
            ..RestServerOptions::default()
        },
    )
    .await
    .map_err(bind_error)?;
    let rest = if gui.enabled {
        if !crate::gui::is_built() {
            tracing::warn!("this build has no GUI (gui/dist was empty): /ui answers 503");
        }
        rest.with_gui(Arc::new(crate::gui::EmbeddedGui))
    } else {
        rest
    };
    let (grpc_addr, http_addr) = (grpc.local_addr(), rest.local_addr());

    if let Some(cert) = &transport.cert {
        export_cert_expiry(&services, cert);
    }
    let reload_now = Arc::new(Notify::new());
    let reload_task = match transport.cert {
        Some(cert) => tokio::spawn(tls::reload_loop(
            cert,
            Arc::clone(&clock),
            reload_period,
            Arc::clone(&reload_now),
        )),
        None => tokio::spawn(tls::plain_text_warning_loop(Arc::clone(&clock))),
    };
    spawn_index_resume(Arc::clone(&engine));
    let maintenance = Maintenance::start(&engine, &clock, default_max_subcompactions());
    let pitr = pitr.map(|(prepared, kek)| {
        let (task, metrics) = PitrTask::start(prepared, &engine, &clock, kek);
        services.metrics().register_pitr(metrics);
        task
    });
    // Kept only for the shutdown checkpoint below.
    let checkpoint_engine = engine;

    let (stop_tx, stop_rx) = watch::channel(false);
    let grpc_task = tokio::spawn(grpc.serve(wait_stop(stop_rx.clone())));
    let rest_task = tokio::spawn(rest.serve(wait_stop(stop_rx)));
    services.readiness().mark_serving();
    tracing::info!(grpc = %grpc_addr, http = %http_addr, tls, "rustegond ready");
    {
        // One machine-readable line for supervisors and tests (the ports may be ephemeral).
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "rustegond ready grpc={grpc_addr} http={http_addr}");
        let _ = out.flush();
    }
    if let Some(on_ready) = on_ready {
        on_ready();
    }

    let (reason, served) = tokio::select! {
        reason = signals.wait_for_shutdown(Arc::clone(&reload_now), stop) => {
            (reason, Served::Stopped)
        }
        // The same graceful shutdown, without leaving the process (ADR-037).
        Ok(_) = restore => ("online restore", Served::Restore),
    };
    report_draining(&services, listen.drain_delay(), clock.as_ref(), reason).await;
    tracing::info!(reason, "shutdown requested; draining listeners");
    let _ = stop_tx.send(true);
    for (name, task) in [("gRPC", grpc_task), ("REST", rest_task)] {
        if let Err(e) = task.await {
            tracing::error!(listener = name, error = %e, "listener task failed");
        }
    }
    reload_task.abort();
    if let Some(data) = services.data().cloned() {
        match tokio::task::spawn_blocking(move || data.shutdown_blocking()).await {
            Ok(summary) => tracing::info!(
                transactions_rolled_back = summary.transactions_rolled_back,
                cursors_closed = summary.cursors_closed,
                "open transactions and cursors released"
            ),
            Err(e) => tracing::error!(error = %e, "releasing transactions and cursors failed"),
        }
    }
    maintenance.stop(clock.as_ref()).await;
    if let Some(pitr) = pitr {
        pitr.stop(clock.as_ref()).await;
    }
    shutdown_checkpoint(checkpoint_engine).await;
    // Last references to the security layer (audit log) and, unless a resumed index build is
    // still running, the engine.
    drop(services);
    match served {
        Served::Stopped => tracing::info!("rustegond stopped"),
        Served::Restore => tracing::info!("stopped serving for the online restore"),
    }
    Ok(served)
}

/// Resumes interrupted index builds in the background so the node serves meanwhile.
fn spawn_index_resume(engine: Arc<EmbeddedDb>) {
    drop(tokio::task::spawn_blocking(move || {
        match engine.resume_index_builds(&BuildConfig::default()) {
            Ok(results) => {
                for result in results {
                    match result {
                        Ok(index) => {
                            tracing::info!(index = %index.name, "index build resumed and finished");
                        }
                        // Code only: a build error can quote an indexed value (duplicate key),
                        // and document contents never reach the log (PD-057). The reason is in
                        // the index's build status.
                        Err(e) => tracing::warn!(code = %e.code(), "resumed index build abandoned"),
                    }
                }
            }
            Err(e) => tracing::error!(code = %e.code(), "cannot resume interrupted index builds"),
        }
    }));
}

/// Shutdown checkpoint (module docs): memtables to SSTs, covered log entries purged. A failure
/// loses nothing (every acknowledged commit is in the log) and is only logged.
async fn shutdown_checkpoint(engine: Arc<EmbeddedDb>) {
    match tokio::task::spawn_blocking(move || engine.flush()).await {
        Ok(Ok(())) => tracing::info!("memtables flushed"),
        Ok(Err(e)) => tracing::error!(error = %e, "shutdown flush failed; the log keeps the data"),
        Err(e) => tracing::error!(error = %e, "shutdown flush task failed"),
    }
}
