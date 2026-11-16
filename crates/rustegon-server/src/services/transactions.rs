// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `TransactionService` and the server's transaction registry (FR-TXN-001/002/005/006/007,
//! transactions.md §3, transaction-management.md §9–§10, PD-049, PD-053).
//!
//! The registry maps the wire `txn_id` (canonical UUID text, PD-049) to the engine's
//! interactive [`Transaction`] so that `Begin`, any number of operations carrying `txn_id` /
//! `rgn-txn-id`, and `Commit`/`Rollback` can arrive as separate RPCs.
//!
//! Rules (*Provisional (PD-053)*):
//! - **Owner.** A transaction belongs to the principal that began it ([`super::data::owner_of`];
//!   `None` = anonymous until lane H authenticates). Any other caller gets RGN-1030 as if the
//!   id did not exist (ids are not secrets, but existence is not disclosed either).
//! - **Idle timeout.** `BeginRequest.idle_timeout_ms` may *shorten* the engine's liveness
//!   timeout (`txn.liveness_timeout`, 5 s); it is capped at it. The registry enforces it for
//!   read-write and read-only transactions alike (the engine exempts read-only ones, PD-049):
//!   an entry idle longer — no call in progress, no call or heartbeat since — is rolled back
//!   and later calls get RGN-2002 with reason `timeout_pushed` (retryable).
//! - **Bounds.** At most `max_transactions` active transactions per node and
//!   `max_transactions_per_principal` per principal; beyond, `Begin` fails with RGN-5004.
//! - **Finished entries** (committed, aborted, outcome unknown) stay for
//!   `finished_txn_retention` (10 min) so `Commit` stays idempotent (FR-TXN-006) and `Status`
//!   answers; afterwards the id is unknown (RGN-1030).
//! - **Commit** runs with [`Completion::Await`]: a commit that started is never reported as
//!   failed because the deadline passed. RGN-2006 leaves the transaction `Unknown`, reported by
//!   `Status` as `COMMITTING` (the single-node log decides the outcome when the store reopens).
//! - **After a restart** (PD-121 option (a'), PD-123): an id the registry does not hold at all
//!   is looked up in the store ([`rustegon_engine::EmbeddedDb::orphan_txn_status`]). Its
//!   persisted record decides: `PENDING` within `txn.liveness_timeout` → `COMMITTING`;
//!   `PENDING` expired → aborted durably, then `ABORTED` with reason `coordinator_lost`;
//!   `ABORTED` → the same. **No record → RGN-1030**, never `ABORTED`: a one-phase commit
//!   deletes the record, so a missing record may mean committed. The owner is not persisted,
//!   so any authenticated principal may ask (the privilege `Begin` needs; ids are random
//!   128-bit values). `Commit` of such an aborted id fails with RGN-2002 `coordinator_lost`
//!   (retryable); `Rollback` of it succeeds (idempotent); every other case answers as before.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_engine::{
    AccessMode, Isolation, OrphanStatus, Priority, Transaction, TransactionStatus, TxnOptions,
    format_txn_id, parse_txn_id,
};
/// Raw transaction id (16 bytes, `rustegon_engine::Transaction::id`).
type TxnId = [u8; 16];
use rustegon_sim_api::Clock;

use super::{
    RequestContext, ServiceDeps,
    data::{
        DataPlane, DataPlaneConfig, ReadConsistency, WriteConcern, check_consistency,
        check_write_concern, owner_of,
    },
};
use crate::Completion;

/// One registered transaction.
pub(crate) struct TxnEntry {
    pub(crate) txn: Arc<Transaction>,
    owner: Option<String>,
    idle_timeout: Duration,
    /// Monotonic time of the last call or heartbeat.
    last_used: Mutex<Duration>,
    /// Calls in progress: an entry is never expired under a running call.
    in_use: AtomicUsize,
    /// Rolled back by the registry for idleness (reported as `timeout_pushed`).
    idle_expired: AtomicBool,
    /// Monotonic time at which the transaction was seen finished.
    finished_at: Mutex<Option<Duration>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // The protected values are single timestamps or a map updated in one call; a panic cannot
    // leave them half-written.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TxnEntry {
    fn touch(&self, now: Duration) {
        *lock(&self.last_used) = now;
    }

    fn finished(&self) -> bool {
        lock(&self.finished_at).is_some()
    }

    fn mark_finished(&self, now: Duration) {
        let mut at = lock(&self.finished_at);
        if at.is_none() {
            *at = Some(now);
        }
    }

    /// The client-visible state (the registry's idle expiry overrides the engine's
    /// `rollback`).
    pub(crate) fn state(&self) -> TxnState {
        if self.idle_expired.load(Ordering::Acquire) {
            return TxnState::Aborted {
                reason: IDLE_REASON.to_owned(),
            };
        }
        match self.txn.status() {
            TransactionStatus::Active => TxnState::Active,
            TransactionStatus::Committed { .. } => TxnState::Committed,
            TransactionStatus::Aborted { reason } => TxnState::Aborted {
                reason: reason.to_owned(),
            },
            TransactionStatus::Unknown => TxnState::Committing,
        }
    }
}

/// The abort reason of a transaction rolled back by the registry's idle timeout: the same as
/// the engine's liveness abort (transactions.md §3), retryable.
const IDLE_REASON: &str = "timeout_pushed";

fn idle_error() -> Error {
    Error::new(
        ErrorCode::TransactionAborted,
        format!("transaction aborted: {IDLE_REASON}"),
    )
    .with_retryable(true)
    .with_detail("reason", IDLE_REASON)
}

/// The abort reason of a transaction whose coordinator was lost (a restart; transactions.md
/// §3), retryable.
const COORDINATOR_LOST: &str = "coordinator_lost";

fn coordinator_lost_error() -> Error {
    Error::new(
        ErrorCode::TransactionAborted,
        format!("transaction aborted: {COORDINATOR_LOST}"),
    )
    .with_retryable(true)
    .with_detail("reason", COORDINATOR_LOST)
}

fn not_found() -> Error {
    Error::new(ErrorCode::NotFound, "transaction not found").with_detail("kind", "transaction")
}

/// A call holding a registered transaction; releases it (and refreshes its idle clock) when
/// dropped.
pub(crate) struct TxnLease {
    entry: Arc<TxnEntry>,
    clock: Arc<dyn Clock>,
}

impl TxnLease {
    pub(crate) fn txn(&self) -> &Arc<Transaction> {
        &self.entry.txn
    }

    pub(crate) fn entry(&self) -> &Arc<TxnEntry> {
        &self.entry
    }
}

impl Drop for TxnLease {
    fn drop(&mut self) {
        self.entry.touch(self.clock.monotonic());
        self.entry.in_use.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The transaction registry (module docs).
pub(crate) struct TxnRegistry {
    map: Mutex<HashMap<TxnId, Arc<TxnEntry>>>,
    clock: Arc<dyn Clock>,
    max_global: usize,
    max_per_owner: usize,
    retention: Duration,
}

impl TxnRegistry {
    pub(crate) fn new(clock: Arc<dyn Clock>, config: &DataPlaneConfig) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            clock,
            max_global: config.max_transactions,
            max_per_owner: config.max_transactions_per_principal,
            retention: config.finished_txn_retention,
        }
    }

    fn register(
        &self,
        txn: Transaction,
        owner: Option<String>,
        idle: Duration,
    ) -> Result<TxnId, Error> {
        let id = txn.id();
        let now = self.clock.monotonic();
        let mut map = lock(&self.map);
        let active: Vec<&Arc<TxnEntry>> = map.values().filter(|e| !e.finished()).collect();
        let mine = active.iter().filter(|e| e.owner == owner).count();
        if active.len() >= self.max_global || mine >= self.max_per_owner {
            // `txn` drops here: rolled back, it never wrote.
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "too many open transactions",
            ));
        }
        map.insert(
            id,
            Arc::new(TxnEntry {
                txn: Arc::new(txn),
                owner,
                idle_timeout: idle,
                last_used: Mutex::new(now),
                in_use: AtomicUsize::new(0),
                idle_expired: AtomicBool::new(false),
                finished_at: Mutex::new(None),
            }),
        );
        Ok(id)
    }

    /// The registered transaction `txn_id` for a call of `ctx`'s principal (module docs).
    ///
    /// # Errors
    /// RGN-1001 for a malformed id, RGN-1030 for an unknown id or another owner, RGN-2002
    /// (`timeout_pushed`) once the registry expired it for idleness.
    pub(crate) fn lease(&self, ctx: &RequestContext, txn_id: &str) -> Result<TxnLease, Error> {
        let id = parse_txn_id(txn_id).map_err(|e| e.with_detail("field", "txn_id"))?;
        let entry = lock(&self.map)
            .get(&id)
            .cloned()
            .filter(|e| e.owner == owner_of(ctx))
            .ok_or_else(not_found)?;
        if entry.idle_expired.load(Ordering::Acquire) {
            return Err(idle_error());
        }
        entry.in_use.fetch_add(1, Ordering::AcqRel);
        let now = self.clock.monotonic();
        let idle_for = now.saturating_sub(*lock(&entry.last_used));
        if !entry.finished()
            && entry.in_use.load(Ordering::Acquire) == 1
            && idle_for > entry.idle_timeout
        {
            // Expired between two sweeps: same outcome as the sweep (rollback off the async
            // workers).
            entry.in_use.fetch_sub(1, Ordering::AcqRel);
            self.expire_idle(&entry);
            return Err(idle_error());
        }
        entry.touch(now);
        Ok(TxnLease {
            entry,
            clock: Arc::clone(&self.clock),
        })
    }

    /// Whether the registry holds `id` at all, for any owner (an id it holds is never looked
    /// up in the store: its owner rule applies).
    fn holds(&self, id: &TxnId) -> bool {
        lock(&self.map).contains_key(id)
    }

    fn expire_idle(&self, entry: &Arc<TxnEntry>) {
        if entry.idle_expired.swap(true, Ordering::AcqRel) {
            return;
        }
        entry.mark_finished(self.clock.monotonic());
        let txn = Arc::clone(&entry.txn);
        let rollback = move || {
            // Rollback is idempotent; it fails only for a committed or unknown transaction,
            // which the idle rule never selects (finished entries are skipped).
            if let Err(e) = txn.rollback() {
                tracing::debug!(error = %e, "rollback of an idle transaction refused");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => drop(rt.spawn_blocking(rollback)),
            Err(_) => rollback(),
        }
    }

    /// Expires idle transactions, records finished ones, forgets those past retention.
    /// Blocking (rollbacks, engine status checks).
    pub(crate) fn sweep_blocking(&self) {
        let now = self.clock.monotonic();
        let entries: Vec<Arc<TxnEntry>> = {
            let mut map = lock(&self.map);
            map.retain(|_, e| {
                lock(&e.finished_at).is_none_or(|at| now.saturating_sub(at) < self.retention)
            });
            map.values().cloned().collect()
        };
        for e in entries {
            if e.finished() || e.in_use.load(Ordering::Acquire) > 0 {
                continue;
            }
            let idle_for = now.saturating_sub(*lock(&e.last_used));
            if idle_for > e.idle_timeout {
                e.idle_expired.store(true, Ordering::Release);
                e.mark_finished(now);
                if let Err(err) = e.txn.rollback() {
                    tracing::debug!(error = %err, "rollback of an idle transaction refused");
                }
            } else if e.state() != TxnState::Active {
                // Aborted by the engine (max duration, pushed) without a call noticing.
                e.mark_finished(now);
            }
        }
    }

    pub(crate) fn mark_finished_if_done(&self, entry: &TxnEntry) {
        if entry.state() != TxnState::Active {
            entry.mark_finished(self.clock.monotonic());
        }
    }

    /// Rolls back every active registered transaction (graceful shutdown, PD-054) and returns
    /// how many were rolled back. Runs after the listeners drained, so no client can still be
    /// waiting for one; a transaction already committing is left to the engine (its rollback
    /// is refused). Blocking.
    pub(crate) fn rollback_all_blocking(&self) -> usize {
        let now = self.clock.monotonic();
        let active: Vec<Arc<TxnEntry>> = lock(&self.map)
            .values()
            .filter(|e| !e.finished())
            .cloned()
            .collect();
        let mut rolled_back = 0;
        for e in active {
            e.mark_finished(now);
            match e.txn.rollback() {
                Ok(()) => rolled_back += 1,
                Err(err) => tracing::debug!(error = %err, "shutdown rollback refused"),
            }
        }
        rolled_back
    }

    /// Active (unfinished) registered transactions (tests, diagnostics).
    pub(crate) fn active(&self) -> usize {
        lock(&self.map).values().filter(|e| !e.finished()).count()
    }
}

/// Client-visible transaction state (`TransactionService.Status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnState {
    /// Open.
    Active,
    /// Commit outcome being decided (engine `Unknown`, RGN-2006).
    Committing,
    /// Committed.
    Committed,
    /// Rolled back or aborted.
    Aborted {
        /// RGN-2002 reason (`rollback`, `conflict`, `timeout_pushed`, `killed`, …).
        reason: String,
    },
}

/// `Begin` input.
#[derive(Debug, Clone, Default)]
pub struct BeginInput {
    /// Isolation (default SERIALIZABLE).
    pub isolation: Option<Isolation>,
    /// Read-only transaction.
    pub read_only: bool,
    /// Priority (default NORMAL).
    pub priority: Option<Priority>,
    /// Read consistency (`FOLLOWER` / `BOUNDED_STALENESS` only for read-only transactions).
    pub consistency: ReadConsistency,
    /// Requested idle timeout (capped by `txn.liveness_timeout`).
    pub idle_timeout: Option<Duration>,
    /// Write concern at commit.
    pub write_concern: WriteConcern,
}

/// `Begin` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginOutput {
    /// Transaction id (canonical UUID text).
    pub txn_id: String,
    /// Heartbeat interval while idle.
    pub heartbeat_interval: Duration,
}

/// `TransactionService` (module docs).
#[derive(Debug, Clone)]
pub struct TransactionService {
    deps: ServiceDeps,
    plane: Arc<DataPlane>,
}

impl TransactionService {
    pub(crate) fn new(deps: ServiceDeps, plane: Arc<DataPlane>) -> Self {
        Self { deps, plane }
    }

    /// The caller's registered transaction (authenticated callers only; PD-051 `Authenticated`
    /// rule: a transaction belongs to its principal).
    fn lease(&self, ctx: &RequestContext, txn_id: &str) -> Result<TxnLease, Error> {
        self.plane.authenticated(ctx)?;
        self.plane.txns.lease(ctx, txn_id)
    }

    /// The persisted outcome of `txn_id` when the registry does not hold it at all (module
    /// docs, "After a restart"); `None` when the store has no record either (or the registry
    /// holds it: then RGN-1030 came from the owner rule and stays).
    async fn orphan(
        &self,
        ctx: &RequestContext,
        txn_id: &str,
    ) -> Result<Option<OrphanStatus>, Error> {
        let id = parse_txn_id(txn_id).map_err(|e| e.with_detail("field", "txn_id"))?;
        if self.plane.txns.holds(&id) {
            return Ok(None);
        }
        let db = Arc::clone(&self.plane.db);
        // Blocking (a scan, possibly an abort proposal): off the async workers. Await: an abort
        // that started completes and is durable either way.
        self.deps
            .executor
            .run(ctx, Completion::Await, move |_| db.orphan_txn_status(&id))
            .await
    }

    /// Starts a transaction.
    ///
    /// # Errors
    /// RGN-1001 (invalid consistency / write concern, follower reads on a read-write
    /// transaction), RGN-5004 (registry full), RGN-5006.
    pub async fn begin(
        &self,
        ctx: &RequestContext,
        input: BeginInput,
    ) -> Result<BeginOutput, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        self.plane.authenticated(ctx)?;
        check_consistency(input.consistency)?;
        check_write_concern(input.write_concern)?;
        if !input.read_only
            && matches!(
                input.consistency,
                ReadConsistency::Follower { .. } | ReadConsistency::BoundedStaleness { .. }
            )
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "follower and bounded-staleness reads need a read-only transaction",
            ));
        }
        let config = self.plane.db.txn_config();
        let liveness = config.liveness_timeout;
        let heartbeat_interval = config.heartbeat_interval;
        let idle = input
            .idle_timeout
            .filter(|t| !t.is_zero())
            .map_or(liveness, |t| t.min(liveness));
        let options = TxnOptions {
            isolation: input.isolation.unwrap_or_default(),
            priority: input.priority.unwrap_or_default(),
            access: if input.read_only {
                AccessMode::ReadOnly
            } else {
                AccessMode::ReadWrite
            },
            timeout: None,
        };
        let db = Arc::clone(&self.plane.db);
        // Abandon: if the deadline passes first, the returned handle is dropped (rollback of a
        // transaction that never wrote).
        let txn = self
            .deps
            .executor
            .run(ctx, Completion::Abandon, move |_| Ok(db.begin(&options)))
            .await?;
        let id = self.plane.txns.register(txn, owner_of(ctx), idle)?;
        Ok(BeginOutput {
            txn_id: format_txn_id(&id),
            heartbeat_interval,
        })
    }

    /// Commits (idempotent once committed).
    ///
    /// # Errors
    /// RGN-1030 (unknown), RGN-2001/2002 (aborted; retryable per reason), RGN-2003,
    /// RGN-2006 (outcome unknown: ask `Status`), RGN-5006 if the deadline passed before the
    /// commit started.
    pub async fn commit(&self, ctx: &RequestContext, txn_id: &str) -> Result<(), Error> {
        let lease = match self.lease(ctx, txn_id) {
            Err(e) if e.code() == ErrorCode::NotFound => {
                return match self.orphan(ctx, txn_id).await? {
                    Some(OrphanStatus::Aborted) => Err(coordinator_lost_error()),
                    Some(OrphanStatus::Committed) => Ok(()),
                    Some(OrphanStatus::InDoubt) | None => Err(e),
                };
            }
            other => other?,
        };
        let txn = Arc::clone(lease.txn());
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |_| txn.commit().map(|_| ()))
            .await;
        self.plane.txns.mark_finished_if_done(lease.entry());
        result
    }

    /// Rolls back (idempotent).
    ///
    /// # Errors
    /// RGN-1030 (unknown), RGN-1001 after a commit, RGN-2006 while the outcome is unknown.
    pub async fn rollback(&self, ctx: &RequestContext, txn_id: &str) -> Result<(), Error> {
        let lease = match self.lease(ctx, txn_id) {
            Err(e) if e.code() == ErrorCode::TransactionAborted => return Ok(()),
            Err(e) if e.code() == ErrorCode::NotFound => {
                return match self.orphan(ctx, txn_id).await? {
                    Some(OrphanStatus::Aborted) => Ok(()),
                    _ => Err(e),
                };
            }
            other => other?,
        };
        let txn = Arc::clone(lease.txn());
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |_| txn.rollback())
            .await;
        self.plane.txns.mark_finished_if_done(lease.entry());
        result
    }

    /// The state of a transaction.
    ///
    /// # Errors
    /// RGN-1001 (malformed id), RGN-1030 (unknown here and no record in the store).
    pub async fn status(&self, ctx: &RequestContext, txn_id: &str) -> Result<TxnState, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        let lease = match self.lease(ctx, txn_id) {
            Ok(lease) => lease,
            Err(e) if e.code() == ErrorCode::TransactionAborted => {
                return Ok(TxnState::Aborted {
                    reason: IDLE_REASON.to_owned(),
                });
            }
            Err(e) if e.code() == ErrorCode::NotFound => {
                return match self.orphan(ctx, txn_id).await? {
                    Some(OrphanStatus::Aborted) => Ok(TxnState::Aborted {
                        reason: COORDINATOR_LOST.to_owned(),
                    }),
                    Some(OrphanStatus::Committed) => Ok(TxnState::Committed),
                    Some(OrphanStatus::InDoubt) => Ok(TxnState::Committing),
                    None => Err(e),
                };
            }
            Err(e) => return Err(e),
        };
        // `Transaction::status` may roll back an expired transaction: off the async workers.
        let entry = Arc::clone(lease.entry());
        let state = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |_| Ok(entry.state()))
            .await?;
        self.plane.txns.mark_finished_if_done(lease.entry());
        Ok(state)
    }

    /// Keeps an idle transaction alive; returns the time until it expires without another
    /// call.
    ///
    /// # Errors
    /// RGN-1030, RGN-2002/2003 once it is no longer active.
    pub async fn heartbeat(&self, ctx: &RequestContext, txn_id: &str) -> Result<Duration, Error> {
        let lease = self.lease(ctx, txn_id)?;
        let txn = Arc::clone(lease.txn());
        let idle = lease.entry().idle_timeout;
        let result = self
            .deps
            .executor
            .run(ctx, Completion::Await, move |_| txn.heartbeat())
            .await;
        self.plane.txns.mark_finished_if_done(lease.entry());
        result.map(|engine| engine.min(idle))
    }

    /// Active registered transactions (diagnostics, tests).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.plane.txns.active()
    }
}
