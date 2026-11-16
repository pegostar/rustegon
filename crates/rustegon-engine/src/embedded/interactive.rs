// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Interactive transactions (FR-TXN-001/002/005/007, FR-TXN-009 savepoints; transactions.md
//! §1 "Interactive", §3, §4; transaction-management.md §9, §10; *Provisional (PD-049)*).
//!
//! A [`Transaction`] is the client-driven transaction of `TransactionService.Begin` →
//! statements / document operations with `txn_id` → `Commit` / `Rollback`. Unlike
//! [`EmbeddedDb::transaction`] it never re-runs anything: the client drives the statements,
//! so a retryable failure is returned as the catalog error with `retryable = true` and the
//! client restarts the whole transaction (driver `withTransaction`, transactions.md §5).
//!
//! # Rules (PD-049)
//! - **Handle.** [`EmbeddedDb::begin`] returns an owned handle (`Arc<EmbeddedDb>` inside):
//!   `Send + Sync + 'static`, so the server keeps it in its transaction registry and drives it
//!   from blocking tasks. Calls on one transaction are serialized by its mutex.
//! - **Statements.** Every statement and document operation runs under a statement savepoint:
//!   a *request* error (parse, bind, validation, duplicate key, not found, interrupt
//!   `RGN-5005`/`RGN-5006`, a write in a read-only transaction, an unknown savepoint) rolls
//!   back that statement only and the transaction stays active.
//! - **Poisoning.** A *transaction* error (`RGN-2001` conflict, `RGN-2002` pushed / expired,
//!   `RGN-2003` max duration, `RGN-2004` too large, `RGN-2005` deadlock, `RGN-2007`, `RGN-2008`,
//!   storage and log errors) aborts the transaction at once — its intents are removed, not
//!   left to expire — and is returned as is; every later call returns `RGN-2002` with the
//!   reason (`retryable` iff the reason is `conflict`, `deadlock` or `timeout_pushed`).
//!   `RGN-2006` (commit outcome unknown) leaves it [`TransactionStatus::Unknown`].
//! - **DDL** is rejected inside a transaction (`RGN-1001`, a statement error): DDL runs in its
//!   own transactions (index builds are multi-transaction jobs). `BEGIN` / `COMMIT` /
//!   `ROLLBACK` statements are rejected too (the server maps them onto the handle);
//!   `SAVEPOINT` / `ROLLBACK TO` / `RELEASE` work (FR-TXN-009).
//! - **Liveness.** A read-write transaction idle for `txn.liveness_timeout` (5 s) is aborted
//!   (`timeout_pushed`): the client calls [`Transaction::heartbeat`] while idle (every
//!   `txn.heartbeat_interval`); any statement also counts. Every transaction is bounded by
//!   `min(timeout, txn.max_duration)` (`RGN-2003`). Read-only transactions are not aborted for
//!   idleness (no intents; PD-049).
//! - **Commit** returns the commit timestamp and is idempotent once committed (FR-TXN-006);
//!   committing an aborted transaction returns `RGN-2002` with the reason (§10). **Rollback**
//!   is idempotent. **Drop** rolls an active transaction back.
//! - **Cursors** opened in the transaction ([`Transaction::open_cursor`]) read through it
//!   between calls; they are *asensitive* (rows the transaction writes after the cursor opened
//!   may or may not appear) and end with the transaction.
//! - **Remote cancel** ([`Transaction::cancel_handle`], FR-QL-008 / `KILL`): the running
//!   statement or cursor batch stops with `RGN-5005` within one operator batch and the
//!   transaction is rolled back (reason `killed`). A cancel racing with a commit that already
//!   started does not undo the commit. Per-statement cancellation without killing the
//!   transaction is the statement's own [`ExecOptions::interrupt`].
//!
//! # Concurrency
//! One mutex per transaction (`Shared::inner`) protects its [`Txn`] and status; it is taken by
//! every call on the transaction and by every batch of its cursors, and is held while the
//! transaction's operations run (they take the range latch and transaction state mutexes of
//! `rustegon-txn`, which are below it in the lock order). No code holds two transactions'
//! mutexes. [`Transaction::status`] and [`Transaction::heartbeat`] use `try_lock`: while a
//! statement runs the transaction is alive by definition, so they answer without waiting for
//! it. The cancel flag is an atomic read without the mutex.

use std::{
    sync::{
        Arc, Mutex, MutexGuard, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value, limits::validate_user_document};
use rustegon_mvcc::{Timestamp, TxnId};
use rustegon_query::{ExecError, ExecOptions, ExecResult, Params, QueryResult, Statement};
use rustegon_txn::{CommitInfo, OrphanStatus, Txn, TxnError, TxnOptions};

use super::{
    Body, EmbeddedDb, OwnedCursor,
    cursor::{CursorOptions, cursor_statement},
    ddl, get_in,
    query::{QueryInput, body, execute_in, parse},
};

/// Savepoint around one statement or document operation of an interactive transaction.
const STATEMENT_SAVEPOINT: &str = "rustegon.engine.statement";
/// Prefix of user savepoints (`SAVEPOINT name`), so they cannot collide with internal ones.
const USER_SAVEPOINT_PREFIX: &str = "user:";
/// Abort reason of a transaction cancelled remotely (transactions.md §3 "killed").
const REASON_KILLED: &str = "killed";
/// Abort reason of a transaction failed by a non-retryable error without a reason of its own
/// (storage, log, internal errors).
const REASON_ERROR: &str = "error";
/// Abort reasons after which restarting the whole transaction may succeed (transactions.md §4).
const RETRYABLE_REASONS: [&str; 4] = ["conflict", "deadlock", "coordinator_lost", "timeout_pushed"];

/// Client-visible state of an interactive transaction (transactions.md §3,
/// `TransactionService.Status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Open and accepting operations.
    Active,
    /// Committed at `commit_ts`.
    Committed {
        /// The commit timestamp.
        commit_ts: Timestamp,
    },
    /// Rolled back or aborted; `reason` is the `RGN-2002` reason (`rollback`, `conflict`,
    /// `deadlock`, `timeout_pushed`, `max_duration`, `too_large`, `killed`, `error`).
    Aborted {
        /// Why.
        reason: &'static str,
    },
    /// The commit outcome is unknown (`RGN-2006`); on a single node it is decided by the log
    /// when the store reopens.
    Unknown,
}

impl TransactionStatus {
    /// Whether this is an abort after which restarting the whole transaction may succeed.
    #[must_use]
    pub fn is_retryable_abort(&self) -> bool {
        matches!(self, Self::Aborted { reason } if RETRYABLE_REASONS.contains(reason))
    }
}

/// Cancels a transaction or cursor from another thread (FR-QL-008; module docs). Cheap to
/// clone; every clone cancels the same handle.
#[derive(Debug, Clone)]
pub struct CancelHandle {
    flag: Arc<AtomicBool>,
}

impl Default for CancelHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelHandle {
    /// A handle that is not cancelled yet (e.g. to cancel a write fence, `FenceOptions`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The flag checked by the executor's interrupt.
    pub(super) fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.flag)
    }

    /// Requests the cancellation; idempotent.
    pub fn cancel(&self) {
        // Relaxed: the flag carries no data; the executor polls it once per operator batch
        // and the owner re-reads it under the transaction mutex, which orders the rest.
        self.flag.store(true, Ordering::Relaxed);
    }

    /// Whether the cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

/// An interactive transaction (module docs).
pub struct Transaction {
    db: Arc<EmbeddedDb>,
    shared: Arc<Shared>,
    id: TxnId,
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("id", &format_txn_id(&self.id))
            .finish_non_exhaustive()
    }
}

/// A savepoint statement (FR-TXN-009).
#[derive(Debug, Clone, Copy)]
enum SavepointOp {
    Set,
    RollbackTo,
    Release,
}

/// What a transaction shares with its cursors.
pub(super) struct Shared {
    inner: Mutex<Inner>,
    cancel: CancelHandle,
}

/// The transaction and its client-visible status (protected by `Shared::inner`).
///
/// Invariant: `status == Active` iff `txn` may still commit (it is `Active` or
/// `RestartRequired` in `rustegon-txn` terms and no abort was decided here).
struct Inner {
    txn: Txn,
    status: TransactionStatus,
}

impl EmbeddedDb {
    /// Begins an interactive transaction with `options` (isolation, priority, read-only,
    /// timeout capped by `txn.max_duration`; module docs).
    #[must_use]
    pub fn begin(self: &Arc<Self>, options: &TxnOptions) -> Transaction {
        // Statistics are advisory and read outside the transaction (PD-040): load them now so
        // that the transaction's statements never wait for it.
        self.load_statistics();
        let txn = self.coord.begin(options.clone());
        let id = txn.id();
        Transaction {
            db: Arc::clone(self),
            shared: Arc::new(Shared {
                inner: Mutex::new(Inner {
                    txn,
                    status: TransactionStatus::Active,
                }),
                cancel: CancelHandle::new(),
            }),
            id,
        }
    }

    /// The outcome of transaction `id` when no handle of this process knows it, e.g. one that
    /// was open when the node stopped (`TransactionService.Status` after a restart, PD-121):
    /// decided by its persisted record ([`rustegon_txn::TxnCoordinator::orphan_status`]; an
    /// expired `PENDING` record is aborted durably first). `None` when there is no record,
    /// which may mean committed: callers must not report it as aborted. Blocking.
    ///
    /// # Errors
    /// Storage and replica errors.
    pub fn orphan_txn_status(&self, id: &TxnId) -> Result<Option<OrphanStatus>, Error> {
        Ok(self.coord.orphan_status(id)?)
    }
}

impl Transaction {
    /// The transaction id (UUID bytes; [`format_txn_id`] gives the wire text).
    #[must_use]
    pub fn id(&self) -> TxnId {
        self.id
    }

    /// Executes one RGQL statement in the transaction (module docs, "Statements").
    ///
    /// # Errors
    /// As [`EmbeddedDb::query`] (request errors roll back the statement only); `RGN-1001` for
    /// DDL and `BEGIN`/`COMMIT`/`ROLLBACK`; transaction errors abort the transaction.
    pub fn query<'a>(
        &self,
        database: &str,
        input: impl Into<QueryInput<'a>>,
        params: &Params,
    ) -> Result<QueryResult, Error> {
        self.query_with(database, input, params, &ExecOptions::default())
    }

    /// [`Transaction::query`] with executor options (batch sizes, memory limit, interrupt).
    ///
    /// # Errors
    /// As [`Transaction::query`].
    pub fn query_with<'a>(
        &self,
        database: &str,
        input: impl Into<QueryInput<'a>>,
        params: &Params,
        options: &ExecOptions,
    ) -> Result<QueryResult, Error> {
        let stmt = parse(input.into())?;
        if let Some(result) = self.control_statement(&stmt) {
            return result;
        }
        self.db.load_statistics();
        let mut opts = self.db.exec_options(options);
        opts.interrupt = opts.interrupt.with_cancel(self.shared.cancel.flag());
        self.statement(|db, txn| body(execute_in(db, txn, database, &stmt, params, &opts)))
    }

    /// Opens a cursor on the read query `input` that reads through this transaction
    /// (module docs, "Cursors").
    ///
    /// # Errors
    /// As [`EmbeddedDb::open_cursor`] (request errors leave the transaction active);
    /// transaction errors abort the transaction.
    pub fn open_cursor<'a>(
        &self,
        database: &str,
        input: impl Into<QueryInput<'a>>,
        params: &Params,
        options: &CursorOptions,
    ) -> Result<OwnedCursor, Error> {
        let stmt = cursor_statement(input.into())?;
        self.db.load_statistics();
        self.statement(|_, txn| {
            body(OwnedCursor::in_transaction(
                Arc::clone(&self.db),
                Arc::clone(&self.shared),
                txn,
                database,
                &stmt,
                params,
                options,
            ))
        })
    }

    /// Inserts `doc` into `database.collection` in the transaction; see
    /// [`EmbeddedDb::insert`].
    ///
    /// # Errors
    /// As [`EmbeddedDb::insert`] (request errors leave the transaction active); transaction
    /// errors abort the transaction.
    pub fn insert(
        &self,
        database: &str,
        collection: &str,
        doc: &Document,
    ) -> Result<Document, Error> {
        validate_user_document(doc)?;
        let id = self.db.id_for(doc);
        self.statement(|db, txn| db.insert_in(txn, database, collection, doc, &id))
    }

    /// The document `id` as the transaction sees it; see [`EmbeddedDb::get`].
    ///
    /// # Errors
    /// As [`EmbeddedDb::get`]; transaction errors abort the transaction.
    pub fn get(
        &self,
        database: &str,
        collection: &str,
        id: &Value,
    ) -> Result<Option<Document>, Error> {
        self.statement(|_, txn| get_in(txn, database, collection, id))
    }

    /// Replaces the document `id` in the transaction; see [`EmbeddedDb::replace`].
    ///
    /// # Errors
    /// As [`EmbeddedDb::replace`]; transaction errors abort the transaction.
    pub fn replace(
        &self,
        database: &str,
        collection: &str,
        id: &Value,
        doc: &Document,
    ) -> Result<Document, Error> {
        validate_user_document(doc)?;
        self.statement(|db, txn| db.replace_doc_in(txn, database, collection, id, doc))
    }

    /// Deletes the document `id` in the transaction; see [`EmbeddedDb::delete`].
    ///
    /// # Errors
    /// As [`EmbeddedDb::delete`]; transaction errors abort the transaction.
    pub fn delete(
        &self,
        database: &str,
        collection: &str,
        id: &Value,
    ) -> Result<Option<Document>, Error> {
        self.statement(|db, txn| db.delete_doc_in(txn, database, collection, id))
    }

    /// Commits (transaction-management.md §10). Idempotent once committed (returns the same
    /// timestamp).
    ///
    /// # Errors
    /// `RGN-2001` (read refresh failed; the transaction is aborted, retryable), `RGN-2002` if
    /// it was aborted (with the reason), `RGN-2003`, `RGN-2006` (outcome unknown: see
    /// [`Transaction::status`]), storage errors.
    pub fn commit(&self) -> Result<CommitInfo, Error> {
        let mut inner = self.shared.lock();
        inner.apply_cancel(&self.shared.cancel);
        match inner.status {
            TransactionStatus::Active => {}
            TransactionStatus::Committed { commit_ts } => return Ok(CommitInfo { commit_ts }),
            _ => return Err(inner.finished_error()),
        }
        match inner.txn.commit() {
            Ok(info) => {
                inner.status = TransactionStatus::Committed {
                    commit_ts: info.commit_ts,
                };
                Ok(info)
            }
            Err(t) => Err(inner.fail(t)),
        }
    }

    /// Rolls back (idempotent; transaction-management.md §10): the intents are removed at
    /// once.
    ///
    /// # Errors
    /// `RGN-1001` after a commit, `RGN-2006` while the commit outcome is unknown.
    pub fn rollback(&self) -> Result<(), Error> {
        let mut inner = self.shared.lock();
        match inner.status {
            TransactionStatus::Active => {
                inner.abort("rollback");
                Ok(())
            }
            TransactionStatus::Aborted { .. } => Ok(()),
            TransactionStatus::Committed { .. } | TransactionStatus::Unknown => {
                Err(inner.finished_error())
            }
        }
    }

    /// The client-visible state (`TransactionService.Status`). An expiry or an abort decided
    /// by another transaction is reported (and the transaction cleaned up) without waiting for
    /// the client's next call. While a statement runs, the transaction is `Active`.
    #[must_use]
    pub fn status(&self) -> TransactionStatus {
        match self.shared.try_lock() {
            Some(mut inner) => {
                inner.apply_cancel(&self.shared.cancel);
                inner.observe_abort();
                inner.status
            }
            None => TransactionStatus::Active,
        }
    }

    /// Keeps an idle transaction alive (`TransactionService.Heartbeat`) and returns the time
    /// until it expires without another heartbeat or operation (transaction-management.md §9).
    /// While a statement runs it returns `txn.liveness_timeout` without waiting for it.
    ///
    /// # Errors
    /// `RGN-2002` / `RGN-2003` if the transaction is no longer active (it is aborted then).
    pub fn heartbeat(&self) -> Result<Duration, Error> {
        let Some(mut inner) = self.shared.try_lock() else {
            return Ok(self.db.coord.config().liveness_timeout);
        };
        inner.enter(&self.shared.cancel)?;
        match inner.txn.heartbeat() {
            Ok(()) => Ok(inner.txn.expires_in()),
            Err(t) => Err(inner.fail(t)),
        }
    }

    /// A handle that cancels the transaction from another thread (module docs, "Remote
    /// cancel").
    #[must_use]
    pub fn cancel_handle(&self) -> CancelHandle {
        self.shared.cancel.clone()
    }

    /// Handles the transaction-control statements (`SAVEPOINT`, `ROLLBACK TO`, `RELEASE`) and
    /// rejects those that cannot run inside (`BEGIN`, `COMMIT`, `ROLLBACK`, DDL); `None` for
    /// an ordinary statement.
    fn control_statement(&self, stmt: &Statement) -> Option<Result<QueryResult, Error>> {
        let reject = |what: &str| {
            Some(Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("{what} cannot run inside an interactive transaction"),
            )))
        };
        if ddl::is_ddl(stmt) {
            return reject("DDL statements");
        }
        let (name, kind) = match stmt {
            Statement::Begin(_) => return reject("BEGIN"),
            Statement::Commit | Statement::Rollback => {
                return reject("COMMIT and ROLLBACK statements (use the transaction calls)");
            }
            Statement::Savepoint { name } => (name, SavepointOp::Set),
            Statement::RollbackToSavepoint { name } => (name, SavepointOp::RollbackTo),
            Statement::ReleaseSavepoint { name } => (name, SavepointOp::Release),
            _ => return None,
        };
        let full = format!("{USER_SAVEPOINT_PREFIX}{name}");
        Some(self.shared.with_active(|inner| {
            let done = match kind {
                SavepointOp::Set => inner.txn.savepoint(&full),
                SavepointOp::RollbackTo => inner.txn.rollback_to_savepoint(&full),
                SavepointOp::Release => inner.txn.release_savepoint(&full),
            };
            match done {
                Ok(()) => Ok(QueryResult::default()),
                // An unknown savepoint is the statement's error, not the transaction's.
                Err(t) if inner.statement_level(&t) => Err(Error::from(t)),
                Err(t) => Err(inner.fail(t)),
            }
        }))
    }

    /// Runs one statement or document operation under the statement savepoint and applies
    /// the error rules of the module docs.
    fn statement<T>(&self, op: impl FnOnce(&EmbeddedDb, &mut Txn) -> Body<T>) -> Result<T, Error> {
        self.shared.with_active(|inner| {
            if let Err(t) = inner.txn.savepoint(STATEMENT_SAVEPOINT) {
                return Err(inner.fail(t));
            }
            match op(self.db.as_ref(), &mut inner.txn) {
                Ok(Ok(v)) => match inner.txn.release_savepoint(STATEMENT_SAVEPOINT) {
                    Ok(()) => Ok(v),
                    Err(t) => Err(inner.fail(t)),
                },
                Ok(Err(e)) => inner.undo_statement().and(Err(e)),
                Err(t) if inner.statement_level(&t) => {
                    inner.undo_statement().and(Err(Error::from(t)))
                }
                Err(t) => Err(inner.fail(t)),
            }
        })
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        // Drop = rollback (module docs). Cursors may keep `Shared` alive: they then find the
        // transaction aborted.
        let mut inner = self.shared.lock();
        if inner.status == TransactionStatus::Active {
            inner.abort("rollback");
        }
    }
}

impl Shared {
    /// The cancel flag (for the interrupt of the transaction's cursors).
    pub(super) fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel.flag()
    }

    /// Locks the transaction. A panic while it was held may have left the [`Txn`] mid-way:
    /// the transaction is then aborted rather than trusted.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            let mut inner = poisoned.into_inner();
            inner.abort_after_panic();
            inner
        })
    }

    /// [`Shared::lock`] without waiting: `None` while another call holds the transaction.
    fn try_lock(&self) -> Option<MutexGuard<'_, Inner>> {
        match self.inner.try_lock() {
            Ok(inner) => Some(inner),
            Err(TryLockError::WouldBlock) => None,
            Err(TryLockError::Poisoned(poisoned)) => {
                let mut inner = poisoned.into_inner();
                inner.abort_after_panic();
                Some(inner)
            }
        }
    }

    /// Runs `op` on the active transaction; a remote cancel observed before or during `op`
    /// kills the transaction (module docs). Without `op` having run, fails with the
    /// transaction's finished error.
    fn with_active<T>(&self, op: impl FnOnce(&mut Inner) -> Result<T, Error>) -> Result<T, Error> {
        let mut inner = self.lock();
        inner.enter(&self.cancel)?;
        let result = op(&mut inner);
        if self.cancel.is_cancelled() && inner.status == TransactionStatus::Active {
            // The cancel arrived while `op` ran: its outcome is void, the transaction dies.
            inner.abort(REASON_KILLED);
            return result.and(Err(cancelled()));
        }
        result
    }

    /// A read of one of the transaction's cursors (no savepoint: reads leave nothing to undo).
    pub(super) fn read<T>(&self, op: impl FnOnce(&mut Txn) -> ExecResult<T>) -> Result<T, Error> {
        self.with_active(|inner| match op(&mut inner.txn) {
            Ok(v) => Ok(v),
            Err(ExecError::Query(e)) => Err(e),
            Err(ExecError::Txn(t)) if inner.statement_level(&t) => Err(Error::from(t)),
            Err(ExecError::Txn(t)) => Err(inner.fail(t)),
        })
    }
}

impl Inner {
    /// Checks that the transaction accepts an operation (after applying a pending cancel).
    fn enter(&mut self, cancel: &CancelHandle) -> Result<(), Error> {
        self.apply_cancel(cancel);
        if self.status == TransactionStatus::Active {
            Ok(())
        } else {
            Err(self.finished_error())
        }
    }

    fn apply_cancel(&mut self, cancel: &CancelHandle) {
        if cancel.is_cancelled() && self.status == TransactionStatus::Active {
            self.abort(REASON_KILLED);
        }
    }

    /// Aborts an active transaction whose expiry or abort by another transaction has not been
    /// observed by an operation yet (`Status`).
    fn observe_abort(&mut self) {
        if self.status == TransactionStatus::Active
            && let Some(reason) = self.txn.pending_abort()
        {
            self.abort(reason.as_str());
        }
    }

    /// Whether a transaction-layer error concerns only the statement that hit it: an API
    /// misuse (`RGN-1001`: write in a read-only transaction, unknown savepoint) that left the
    /// transaction active.
    fn statement_level(&self, t: &TxnError) -> bool {
        matches!(t, TxnError::InvalidArgument(_)) && self.txn.is_active()
    }

    /// Rolls back the current statement (its savepoint); a failure poisons the transaction.
    fn undo_statement(&mut self) -> Result<(), Error> {
        let undone = self
            .txn
            .rollback_to_savepoint(STATEMENT_SAVEPOINT)
            .and_then(|()| self.txn.release_savepoint(STATEMENT_SAVEPOINT));
        undone.map_err(|t| self.fail(t))
    }

    /// Poisons the transaction with the transaction error `t` (module docs) and returns `t`
    /// as the catalog error for the operation that hit it.
    fn fail(&mut self, t: TxnError) -> Error {
        if matches!(t, TxnError::CommitOutcomeUnknown(_)) {
            // Its intents must stay until the log decides (`rustegon-txn`): no rollback.
            self.status = TransactionStatus::Unknown;
        } else if self.status == TransactionStatus::Active {
            self.abort(abort_reason(&t));
        }
        Error::from(t)
    }

    /// Rolls the transaction back (removing its intents) and records `reason`.
    fn abort(&mut self, reason: &'static str) {
        if let Err(e) = self.txn.rollback() {
            // Only a committed or ambiguous transaction refuses a rollback, and those are never
            // `Active` here (struct invariant); keep the status truthful anyway.
            tracing::warn!(error = %e, "rollback of an interactive transaction refused");
            return;
        }
        self.status = TransactionStatus::Aborted { reason };
    }

    fn abort_after_panic(&mut self) {
        if self.status == TransactionStatus::Active {
            self.abort(REASON_ERROR);
        }
    }

    /// The error of an operation on a transaction that is no longer active.
    fn finished_error(&self) -> Error {
        match self.status {
            TransactionStatus::Aborted { reason } => Error::new(
                ErrorCode::TransactionAborted,
                format!("transaction aborted: {reason}"),
            )
            .with_retryable(self.status.is_retryable_abort())
            .with_detail("reason", reason),
            TransactionStatus::Committed { .. } => Error::new(
                ErrorCode::InvalidArgument,
                "the transaction is already committed",
            ),
            TransactionStatus::Unknown => Error::new(
                ErrorCode::CommitOutcomeUnknown,
                "the transaction's commit outcome is unknown",
            )
            .with_retryable(false),
            TransactionStatus::Active => Error::new(
                ErrorCode::Internal,
                "an active transaction reported as finished",
            ),
        }
    }
}

/// The `RGN-2002` reason recorded for the transaction error `t`.
fn abort_reason(t: &TxnError) -> &'static str {
    match t {
        TxnError::Conflict(_) | TxnError::WriteTooOld { .. } => "conflict",
        TxnError::Aborted { reason } => reason.as_str(),
        TxnError::Timeout { .. } => "max_duration",
        TxnError::TooLarge { .. } => "too_large",
        TxnError::Deadlock => "deadlock",
        // e.g. RGN-2007 below the GC threshold: a new transaction reads at a new timestamp.
        other if other.is_retryable() => "conflict",
        _ => REASON_ERROR,
    }
}

fn cancelled() -> Error {
    Error::new(ErrorCode::Cancelled, "transaction cancelled")
}

/// The wire text of a transaction id: the canonical lowercase hyphenated UUID form
/// (`BeginResponse.txn_id`, `rgn-txn-id`; PD-049).
#[must_use]
pub fn format_txn_id(id: &TxnId) -> String {
    let mut out = String::with_capacity(36);
    for (i, b) in id.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0F)]));
    }
    out
}

/// Parses the wire text of a transaction id ([`format_txn_id`]; hex digits of either case).
///
/// # Errors
/// `RGN-1001` if `text` is not a hyphenated UUID.
pub fn parse_txn_id(text: &str) -> Result<TxnId, Error> {
    let invalid = || Error::new(ErrorCode::InvalidArgument, "invalid transaction id");
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return Err(invalid());
    }
    let mut id = [0u8; 16];
    let mut nibbles = bytes
        .iter()
        .enumerate()
        .filter(|(i, _)| !matches!(i, 8 | 13 | 18 | 23))
        .map(|(_, c)| char::from(*c).to_digit(16));
    for slot in &mut id {
        let (Some(Some(hi)), Some(Some(lo))) = (nibbles.next(), nibbles.next()) else {
            return Err(invalid());
        };
        *slot = u8::try_from(hi << 4 | lo).map_err(|_| invalid())?;
    }
    if [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
        return Err(invalid());
    }
    Ok(id)
}

/// Lowercase hex digits.
const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txn_id_text_round_trips() {
        let id: TxnId = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x4d, 0xef, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0xff,
        ];
        let text = format_txn_id(&id);
        assert_eq!(text, "12345678-9abc-4def-8001-0203040506ff");
        assert_eq!(parse_txn_id(&text).ok(), Some(id));
        assert_eq!(parse_txn_id(&text.to_uppercase()).ok(), Some(id));
        for bad in [
            "",
            "12345678-9abc-4def-8001-0203040506f",
            "12345678-9abc-4def-8001-0203040506fg",
            "123456789abc-4def-8001-0203040506ff0",
            "12345678_9abc-4def-8001-0203040506ff",
        ] {
            assert!(parse_txn_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn retryable_abort_reasons_follow_the_spec() {
        for (reason, retryable) in [
            ("conflict", true),
            ("deadlock", true),
            ("timeout_pushed", true),
            ("rollback", false),
            ("max_duration", false),
            ("too_large", false),
            ("killed", false),
            ("error", false),
        ] {
            assert_eq!(
                TransactionStatus::Aborted { reason }.is_retryable_abort(),
                retryable,
                "{reason}"
            );
        }
    }
}
