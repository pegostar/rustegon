// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The data plane shared by `QueryService`, `DocumentService`, `TransactionService` and
//! `SchemaService` (M4 wave 2b lane G, PD-053): the engine handle, the transaction and cursor
//! registries, the idempotency store, the continuation-token sealer, the index-build tracker,
//! their limits, and the helpers every data service uses (implicit transactions, consistency
//! and write-concern rules of a single node, request → transaction routing).

use std::{
    fmt,
    sync::{Arc, OnceLock, Weak, atomic::AtomicUsize},
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_engine::{AccessMode, EmbeddedDb, Transaction, TxnOptions};
use rustegon_security::rbac::{Action, Resource};

use super::{
    RequestContext, ServiceDeps, cursors::CursorRegistry, idempotency::IdempotencyStore,
    schema::BuildTracker, token::TokenSealer, transactions::TxnRegistry,
};
use crate::{CancelToken, security::Security};

/// Limits and timeouts of the data plane (defaults: PD-053).
#[derive(Clone)]
pub struct DataPlaneConfig {
    /// Idle time after which an open cursor is closed (FR-QL-006: 10 min). The engine bounds a
    /// cursor's read snapshot by `txn.max_duration` (60 s) before that (PD-049, PD-053).
    pub cursor_idle_timeout: Duration,
    /// Open cursors on this node.
    pub max_cursors: usize,
    /// Open cursors of one principal (anonymous callers share one budget).
    pub max_cursors_per_principal: usize,
    /// Memory reserved for open cursors on this node (each reserves
    /// [`DataPlaneConfig::cursor_reservation_bytes`]).
    pub cursor_memory_budget: usize,
    /// Memory reserved for the open cursors of one principal.
    pub cursor_memory_per_principal: usize,
    /// Memory one idle cursor may hold between `GetMore` calls: its pending operator batch
    /// (query-language.md §5.2; the executor's default `batch_bytes`, 1 MiB).
    pub cursor_reservation_bytes: usize,
    /// Rows per batch when the client sets no `batch_size`.
    pub default_batch_rows: usize,
    /// Cap on a client's `batch_size`.
    pub max_batch_rows: usize,
    /// Active interactive transactions on this node.
    pub max_transactions: usize,
    /// Active interactive transactions of one principal.
    pub max_transactions_per_principal: usize,
    /// How long a finished (committed, aborted, unknown) transaction stays queryable by
    /// `Status`/`Commit` (commit idempotency, FR-TXN-006).
    pub finished_txn_retention: Duration,
    /// How long a write outcome is kept for `rgn-request-id` retries (protocol.md §5.1: 10 min).
    pub idempotency_retention: Duration,
    /// Idempotency records kept at most (oldest finished records are evicted first).
    pub max_idempotency_records: usize,
    /// Period of the background sweep of expired cursors, transactions and records.
    pub sweep_interval: Duration,
    /// Operations per `BulkWrite` (protocol.md §5.4).
    pub max_bulk_ops: usize,
    /// AES-256-GCM key sealing continuation tokens; `None` = a random key per process
    /// (tokens then do not survive a restart; PD-053).
    pub token_key: Option<[u8; 32]>,
}

impl fmt::Debug for DataPlaneConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataPlaneConfig")
            .field("cursor_idle_timeout", &self.cursor_idle_timeout)
            .field("max_cursors", &self.max_cursors)
            .field("max_transactions", &self.max_transactions)
            .field("token_key", &self.token_key.map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl Default for DataPlaneConfig {
    fn default() -> Self {
        Self {
            cursor_idle_timeout: Duration::from_secs(600),
            max_cursors: 4096,
            max_cursors_per_principal: 1024,
            cursor_memory_budget: 4 << 30,
            cursor_memory_per_principal: 1 << 30,
            cursor_reservation_bytes: 1 << 20,
            default_batch_rows: 1000,
            max_batch_rows: 10_000,
            max_transactions: 10_000,
            max_transactions_per_principal: 1000,
            finished_txn_retention: Duration::from_secs(600),
            idempotency_retention: Duration::from_secs(600),
            max_idempotency_records: 100_000,
            sweep_interval: Duration::from_secs(1),
            max_bulk_ops: 100_000,
            token_key: None,
        }
    }
}

/// Everything the data services share.
pub(crate) struct DataPlane {
    pub(crate) db: Arc<EmbeddedDb>,
    pub(crate) config: DataPlaneConfig,
    pub(crate) txns: TxnRegistry,
    pub(crate) cursors: CursorRegistry,
    pub(crate) idempotency: Arc<IdempotencyStore>,
    pub(crate) sealer: TokenSealer,
    pub(crate) builds: BuildTracker,
    /// `Execute` streams whose producer still holds an engine cursor.
    pub(crate) streams: AtomicUsize,
    /// The security layer, once installed (`Services::with_security`).
    security: OnceLock<Arc<Security>>,
}

impl fmt::Debug for DataPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataPlane")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DataPlane {
    pub(crate) fn new(
        deps: &ServiceDeps,
        db: Arc<EmbeddedDb>,
        config: DataPlaneConfig,
    ) -> Arc<Self> {
        let key = config.token_key.unwrap_or_else(|| {
            let mut key = [0u8; 32];
            deps.rng.fill_bytes(&mut key);
            key
        });
        let plane = Arc::new(Self {
            txns: TxnRegistry::new(Arc::clone(&deps.clock), &config),
            cursors: CursorRegistry::new(Arc::clone(&deps.clock), &config),
            idempotency: Arc::new(IdempotencyStore::new(Arc::clone(&deps.clock), &config)),
            sealer: TokenSealer::new(&key, Arc::clone(&deps.rng)),
            builds: BuildTracker::default(),
            streams: AtomicUsize::new(0),
            security: OnceLock::new(),
            db,
            config,
        });
        spawn_sweeper(deps, &plane);
        plane
    }

    /// Installs the security layer (first installation wins; `Services` installs one).
    pub(crate) fn set_security(&self, security: Arc<Security>) {
        let _ = self.security.set(security);
    }

    /// Requires an authenticated caller. Without a security layer (in-process use by tools
    /// and tests) there is no caller to check: the gRPC gate serves the data plane only with
    /// the security layer installed (PD-051, PD-053).
    ///
    /// # Errors
    /// RGN-4001.
    pub(crate) fn authenticated(&self, ctx: &RequestContext) -> Result<(), Error> {
        if self.security.get().is_some() {
            ctx.require_principal()?;
        }
        Ok(())
    }

    /// Requires every `(resource, action)` of `checks` for the caller (RGN-4002, audited by
    /// the security layer); see [`DataPlane::authenticated`] for the case without one.
    ///
    /// # Errors
    /// RGN-4001, RGN-4002.
    pub(crate) async fn authorize(
        &self,
        ctx: &RequestContext,
        checks: &[(Resource, Action)],
    ) -> Result<(), Error> {
        let Some(security) = self.security.get() else {
            return Ok(());
        };
        ctx.require_principal()?;
        for (resource, action) in checks {
            security.require(ctx, resource, *action).await?;
        }
        Ok(())
    }

    /// Whether the caller may see `resource` in a listing: it holds any action on it (or on
    /// a coarser resource). Without a security layer everything is visible.
    pub(crate) fn visible(&self, ctx: &RequestContext, resource: &Resource) -> bool {
        if self.security.get().is_none() {
            return true;
        }
        ctx.principal()
            .is_some_and(|p| Action::ALL.iter().any(|a| p.allows(resource, *a)))
    }

    /// One sweep: expired cursors, idle transactions, old idempotency records. Blocking (it
    /// rolls back expired transactions and closes cursors in the engine).
    pub(crate) fn sweep_blocking(&self) {
        self.cursors.sweep_blocking();
        self.txns.sweep_blocking();
        self.idempotency.sweep();
    }
}

/// Runs [`DataPlane::sweep_blocking`] every `sweep_interval` on the sim-api clock while the
/// data plane is alive. Without a Tokio runtime (synchronous construction in tools) nothing is
/// spawned: the registries also expire entries lazily when they are used.
fn spawn_sweeper(deps: &ServiceDeps, plane: &Arc<DataPlane>) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let weak: Weak<DataPlane> = Arc::downgrade(plane);
    let clock = Arc::clone(&deps.clock);
    let interval = plane.config.sweep_interval;
    runtime.spawn(async move {
        loop {
            clock.sleep(interval).await;
            // A weak handle: the task must not keep the engine open after the services drop.
            let Some(plane) = weak.upgrade() else {
                return;
            };
            if tokio::task::spawn_blocking(move || plane.sweep_blocking())
                .await
                .is_err()
            {
                tracing::error!("data plane sweep panicked");
            }
        }
    });
}

/// The registry owner of a request: the authenticated user, `None` for anonymous callers.
/// Wave 2b lane H fills the principal; until then every caller is anonymous and shares one
/// budget (PD-053).
pub(crate) fn owner_of(ctx: &RequestContext) -> Option<String> {
    ctx.principal().map(|p| p.user.clone())
}

/// The transaction a request runs in: the request field or the `rgn-txn-id` header; both
/// present and different is a client bug (RGN-1001).
///
/// # Errors
/// RGN-1001.
pub(crate) fn txn_id_of(
    ctx: &RequestContext,
    field: Option<&str>,
) -> Result<Option<String>, Error> {
    match (field.filter(|f| !f.is_empty()), ctx.txn_id()) {
        (Some(f), Some(h)) if f != h => Err(Error::new(
            ErrorCode::InvalidArgument,
            "txn_id and the rgn-txn-id header name different transactions",
        )),
        (Some(f), _) => Ok(Some(f.to_owned())),
        (None, h) => Ok(h.map(str::to_owned)),
    }
}

/// Transaction-level errors after which an implicit transaction is restarted: nothing was
/// committed (an aborted transaction), so running the body again is invisible to the client.
/// `RGN-2006` is never retried: its commit may have happened.
fn restartable(e: &Error) -> bool {
    e.retryable()
        && matches!(
            e.code(),
            ErrorCode::TransactionConflict
                | ErrorCode::TransactionAborted
                | ErrorCode::DeadlockDetected
                | ErrorCode::ReadTimestampTooOld
                | ErrorCode::WriteTooOld
        )
}

/// Attempts of one implicit transaction (like `rustegon_engine::embedded::MAX_ATTEMPTS`).
const IMPLICIT_ATTEMPTS: u32 = 16;

/// Runs `body` in an implicit transaction (FR-TXN-003): every operation of one call commits
/// atomically or not at all. Retries restartable transaction errors. Blocking; called inside
/// an [`crate::Executor`] closure with its token.
///
/// The deadline is checked once more right before the commit: past it, the transaction is
/// rolled back and RGN-5006 returned — nothing was written, so the error is the truth. Once
/// the commit started its real outcome is returned (protocol.md §5.2).
pub(crate) fn run_implicit<T>(
    db: &Arc<EmbeddedDb>,
    options: &TxnOptions,
    token: &CancelToken,
    mut body: impl FnMut(&Transaction) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut attempt = 1;
    loop {
        let txn = db.begin(options);
        let failed = match body(&txn) {
            Ok(value) => {
                token.check()?; // `txn` drops here: rollback.
                match txn.commit() {
                    Ok(_) => return Ok(value),
                    Err(e) => e,
                }
            }
            Err(e) => e,
        };
        drop(txn);
        if restartable(&failed) && attempt < IMPLICIT_ATTEMPTS && token.check().is_ok() {
            attempt += 1;
            continue;
        }
        return Err(failed);
    }
}

/// Options of an implicit read-only transaction (one snapshot for multi-document reads).
pub(crate) fn read_only() -> TxnOptions {
    TxnOptions {
        access: AccessMode::ReadOnly,
        ..TxnOptions::default()
    }
}

/// Read consistency requested by a client (consistency.md §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadConsistency {
    /// Not set: the operation's default (linearizable).
    #[default]
    Default,
    /// Leaseholder read.
    Linearizable,
    /// Replica read no older than the bound.
    BoundedStaleness {
        /// Staleness bound.
        max_staleness: Duration,
    },
    /// Follower read at the closed timestamp (optional bound).
    Follower {
        /// Optional staleness bound.
        max_staleness: Option<Duration>,
    },
}

/// Write concern requested by a client (consistency.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WriteConcern {
    /// Not set: the collection default (`majority`).
    #[default]
    Default,
    /// Raft quorum.
    Majority,
    /// All voters.
    All,
    /// Quorum of the local site (XDC collections).
    LocalDcMajority,
    /// Every XDC peer frontier (XDC collections).
    SyncCrossDc,
    /// Local commit only (XDC collections).
    AsyncCrossDc,
}

/// Single-node rule for read consistencies (PD-053): every level is served by the one replica
/// at its latest state, which satisfies linearizability and any staleness bound (staleness 0).
/// Only `BOUNDED_STALENESS` without its bound is invalid.
///
/// # Errors
/// RGN-1001.
pub(crate) fn check_consistency(c: ReadConsistency) -> Result<(), Error> {
    match c {
        ReadConsistency::BoundedStaleness { max_staleness } if max_staleness.is_zero() => {
            Err(Error::new(
                ErrorCode::InvalidArgument,
                "BOUNDED_STALENESS requires max_staleness_ms",
            ))
        }
        _ => Ok(()),
    }
}

/// Single-node rule for write concerns (PD-053): `MAJORITY` and `ALL` hold once the single
/// voter has synced its log, which every acknowledged commit does; the XDC concerns need an
/// XDC collection, which does not exist before M10.
///
/// # Errors
/// RGN-1001 for the XDC concerns.
pub(crate) fn check_write_concern(w: WriteConcern) -> Result<(), Error> {
    match w {
        WriteConcern::Default | WriteConcern::Majority | WriteConcern::All => Ok(()),
        WriteConcern::LocalDcMajority | WriteConcern::SyncCrossDc | WriteConcern::AsyncCrossDc => {
            Err(Error::new(
                ErrorCode::InvalidArgument,
                "this write concern applies to cross-datacenter collections only",
            )
            .with_detail("write_concern", format!("{w:?}")))
        }
    }
}
