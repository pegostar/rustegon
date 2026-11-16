// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Server-side cursors of the embedded API (FR-QL-006, FR-QL-007; query-engine.md §7, the
//! single-node part of TC-QL-007).
//!
//! [`EmbeddedDb::open_cursor`] binds and plans a read query in a **read-only transaction that
//! the cursor keeps open**: every [`Cursor::next_batch`] (`getMore`) continues the same
//! operator pipeline at the same snapshot, so the batches of one cursor form one consistent
//! result. The transaction is committed when the cursor is exhausted or closed (rolled back
//! when dropped).
//!
//! Two handles share one implementation (`CursorCore`):
//! - [`Cursor`] borrows the store (`Cursor<'db>`), for in-process callers and tests;
//! - [`OwnedCursor`] holds an `Arc<EmbeddedDb>`: it is `'static + Send`, so the server keeps it
//!   in its cursor registry between `GetMore` RPCs and drives it from blocking tasks. It is
//!   opened standalone ([`EmbeddedDb::open_owned_cursor`], its own read-only transaction) or
//!   inside an interactive transaction ([`super::Transaction::open_cursor`], reading through
//!   that transaction; PD-049).
//!
//! **Remote cancel** (FR-QL-008): [`OwnedCursor::cancel_handle`] / [`Cursor::cancel_handle`]
//! return a [`CancelHandle`] usable from any thread: the batch being produced stops with
//! `RGN-5005` within one operator batch (the flag is part of the cursor's interrupt), and the
//! cursor is closed. A cursor opened in a transaction also stops when the transaction is
//! cancelled.
//!
//! Limits of the embedded cursor (*Provisional (PD-041, PD-049)*): the open transaction is
//! bounded by `txn.max_duration` (60 s, `RGN-2003`); being read-only it is not aborted for
//! idleness (`txn.liveness_timeout` applies to read-write transactions only, PD-049), so a
//! client may pause between `GetMore` calls up to that bound. The 10 min idle timeout of
//! FR-QL-006 and `killCursors` belong to the server's registry, which needs a pinned read
//! timestamp instead of a transaction for cursors living longer than `txn.max_duration`.
//! Continuation tokens ([`CursorBatch::continuation_token`]) are not bound to the cursor:
//! [`CursorOptions::resume_token`] opens a new cursor after the token's position (also on a
//! reopened store), at a new snapshot.

use std::sync::Arc;

use rustegon_common::{Error, ErrorCode};
use rustegon_query::{
    CursorBatch, CursorLimits, ExecError, ExecOptions, Params, QueryCursor, Statement, open_cursor,
};
use rustegon_txn::{AccessMode, Txn, TxnError, TxnOptions};

use super::{
    EmbeddedDb, MAX_ATTEMPTS, ddl,
    interactive::{CancelHandle, Shared},
    query::{QueryInput, QueryTxn, parse},
};

/// Options of [`EmbeddedDb::open_cursor`].
#[derive(Debug, Clone, Default)]
pub struct CursorOptions {
    /// Batch size (rows / bytes; default 1000 rows or 4 MiB).
    pub limits: CursorLimits,
    /// Executor options (operator batches, memory limit, interrupt, clock).
    pub exec: ExecOptions,
    /// Resume after the position of this continuation token.
    pub resume_token: Option<Vec<u8>>,
}

/// An open cursor borrowing the store (module docs).
pub struct Cursor<'db> {
    db: &'db EmbeddedDb,
    core: CursorCore,
}

/// An open cursor owning a handle on the store: `'static` and `Send`, for the server's cursor
/// registry (module docs).
pub struct OwnedCursor {
    db: Arc<EmbeddedDb>,
    core: CursorCore,
}

/// Where a cursor reads from.
enum Snapshot {
    /// The cursor's own read-only transaction; `None` once committed or abandoned. Boxed: a
    /// `Txn` is a few hundred bytes, the other variant a pointer.
    Own(Option<Box<Txn>>),
    /// The interactive transaction it was opened in (reads go through it, so they see its
    /// snapshot, its own writes and join its read set).
    Shared(Arc<Shared>),
}

/// State shared by [`Cursor`] and [`OwnedCursor`].
struct CursorCore {
    snapshot: Snapshot,
    inner: QueryCursor,
    exec: ExecOptions,
    limits: CursorLimits,
    cancel: CancelHandle,
    /// Exhausted, closed or failed: further batches are empty and exhausted.
    done: bool,
}

impl std::fmt::Debug for CursorCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cursor")
            .field("inner", &self.inner)
            .field(
                "in_transaction",
                &matches!(self.snapshot, Snapshot::Shared(_)),
            )
            .field("open", &!self.done)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Cursor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.core.fmt(f)
    }
}

impl std::fmt::Debug for OwnedCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.core.fmt(f)
    }
}

fn txn_error(t: TxnError) -> Error {
    Error::from(t)
}

/// The statement of a cursor: a read query (DDL is rejected here, the binder rejects writes).
pub(super) fn cursor_statement(input: QueryInput<'_>) -> Result<Statement, Error> {
    let stmt = parse(input)?;
    if ddl::is_ddl(&stmt) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "a cursor serves read queries (FROM …) only",
        ));
    }
    Ok(stmt)
}

impl EmbeddedDb {
    /// Opens a cursor on the read query `input` (module docs).
    ///
    /// # Errors
    /// Parse and bind errors, `RGN-1001` for a statement that is not a read query or an
    /// invalid continuation token, transaction errors after the retries.
    pub fn open_cursor<'a>(
        &self,
        database: &str,
        input: impl Into<QueryInput<'a>>,
        params: &Params,
        options: &CursorOptions,
    ) -> Result<Cursor<'_>, Error> {
        let stmt = cursor_statement(input.into())?;
        let core = CursorCore::open_own(self, database, &stmt, params, options)?;
        Ok(Cursor { db: self, core })
    }

    /// [`EmbeddedDb::open_cursor`] returning an [`OwnedCursor`] (`'static + Send`) for a
    /// registry that keeps cursors between calls (module docs).
    ///
    /// # Errors
    /// As [`EmbeddedDb::open_cursor`].
    pub fn open_owned_cursor<'a>(
        self: &Arc<Self>,
        database: &str,
        input: impl Into<QueryInput<'a>>,
        params: &Params,
        options: &CursorOptions,
    ) -> Result<OwnedCursor, Error> {
        let stmt = cursor_statement(input.into())?;
        let core = CursorCore::open_own(self, database, &stmt, params, options)?;
        Ok(OwnedCursor {
            db: Arc::clone(self),
            core,
        })
    }
}

impl OwnedCursor {
    /// A cursor reading through the interactive transaction `shared` (opened by
    /// [`super::Transaction::open_cursor`], which holds its lock while opening).
    pub(super) fn in_transaction(
        db: Arc<EmbeddedDb>,
        shared: Arc<Shared>,
        txn: &mut Txn,
        database: &str,
        stmt: &Statement,
        params: &Params,
        options: &CursorOptions,
    ) -> Result<Self, ExecError> {
        let cancel = CancelHandle::new();
        let mut exec = db.exec_options(&options.exec);
        // The cursor stops when it is cancelled and when its transaction is.
        exec.interrupt = exec
            .interrupt
            .with_cancel(cancel.flag())
            .with_cancel(shared.cancel_flag());
        let inner = {
            let mut store = QueryTxn { db: &db, txn };
            open_cursor(
                &mut store,
                database,
                stmt,
                params,
                &exec,
                options.resume_token.as_deref(),
            )?
        };
        let core = CursorCore {
            snapshot: Snapshot::Shared(shared),
            inner,
            exec,
            limits: options.limits,
            cancel,
            done: false,
        };
        Ok(Self { db, core })
    }

    /// The next batch (`getMore`); see [`Cursor::next_batch`]. A cursor opened in a
    /// transaction fails with the transaction's error once it is no longer active (committed,
    /// rolled back, aborted): its batches belong to that transaction.
    ///
    /// # Errors
    /// As [`Cursor::next_batch`]; for a cursor in a transaction, `RGN-2002` (aborted, with the
    /// reason), `RGN-1001` (the transaction committed) and the errors that abort it.
    pub fn next_batch(&mut self) -> Result<CursorBatch, Error> {
        self.core.next_batch(&self.db)
    }

    /// Reads every remaining batch into one vector (tests, small results).
    ///
    /// # Errors
    /// As [`OwnedCursor::next_batch`].
    pub fn collect_rows(&mut self) -> Result<Vec<rustegon_doc::Value>, Error> {
        self.core.collect_rows(&self.db)
    }

    /// Rows returned so far (including those before the resumed token).
    #[must_use]
    pub fn returned(&self) -> u64 {
        self.core.inner.returned()
    }

    /// Changes the batch size of the following batches (`GetMore.batch_size`, PD-053). The
    /// operator pipeline is unchanged; only how many rows one batch returns.
    pub fn set_limits(&mut self, limits: CursorLimits) {
        self.core.limits = limits;
    }

    /// Whether the cursor ended (exhausted, closed or failed): a registry can drop it.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.core.done
    }

    /// A handle that cancels the cursor from another thread (module docs, FR-QL-008).
    #[must_use]
    pub fn cancel_handle(&self) -> CancelHandle {
        self.core.cancel.clone()
    }

    /// Closes the cursor (`killCursors`): commits its own read-only transaction; a cursor in
    /// a transaction just stops (the transaction stays open).
    ///
    /// # Errors
    /// Transaction errors of the commit.
    pub fn close(mut self) -> Result<(), Error> {
        self.core.finish()
    }
}

impl Cursor<'_> {
    /// The next batch (`getMore`); after the last batch (`exhausted`) the transaction is
    /// committed and further calls return empty exhausted batches.
    ///
    /// # Errors
    /// `RGN-5005` / `RGN-5006` (interrupt), `RGN-5004`, transaction errors (`RGN-2003` once the
    /// transaction outlives `txn.max_duration`). After an error the cursor is closed: resume
    /// with the last continuation token.
    pub fn next_batch(&mut self) -> Result<CursorBatch, Error> {
        self.core.next_batch(self.db)
    }

    /// Reads every remaining batch into one vector (tests, small results).
    ///
    /// # Errors
    /// As [`Cursor::next_batch`].
    pub fn collect_rows(&mut self) -> Result<Vec<rustegon_doc::Value>, Error> {
        self.core.collect_rows(self.db)
    }

    /// Rows returned so far (including those before the resumed token).
    #[must_use]
    pub fn returned(&self) -> u64 {
        self.core.inner.returned()
    }

    /// A handle that cancels the cursor from another thread (module docs, FR-QL-008).
    #[must_use]
    pub fn cancel_handle(&self) -> CancelHandle {
        self.core.cancel.clone()
    }

    /// Closes the cursor (`killCursors`): commits its read-only transaction.
    ///
    /// # Errors
    /// Transaction errors of the commit.
    pub fn close(mut self) -> Result<(), Error> {
        self.core.finish()
    }
}

impl CursorCore {
    /// Opens a cursor in its own read-only transaction, retrying retryable conflicts of the
    /// open (nothing has been returned to the client yet, so a retry is invisible).
    fn open_own(
        db: &EmbeddedDb,
        database: &str,
        stmt: &Statement,
        params: &Params,
        options: &CursorOptions,
    ) -> Result<Self, Error> {
        let cancel = CancelHandle::new();
        let mut exec = db.exec_options(&options.exec);
        exec.interrupt = exec.interrupt.with_cancel(cancel.flag());
        let txn_options = TxnOptions {
            access: AccessMode::ReadOnly,
            ..TxnOptions::default()
        };
        let mut attempt = 1;
        loop {
            let mut txn = db.coord.begin(txn_options.clone());
            let opened = {
                let mut store = QueryTxn { db, txn: &mut txn };
                open_cursor(
                    &mut store,
                    database,
                    stmt,
                    params,
                    &exec,
                    options.resume_token.as_deref(),
                )
            };
            match opened {
                Ok(inner) => {
                    return Ok(Self {
                        snapshot: Snapshot::Own(Some(Box::new(txn))),
                        inner,
                        exec,
                        limits: options.limits,
                        cancel,
                        done: false,
                    });
                }
                Err(e) => {
                    // A read-only transaction holds no intents: a failed rollback leaves
                    // nothing behind, and the open error is the one to report.
                    let _rollback = txn.rollback();
                    match e {
                        ExecError::Txn(t) if t.is_retryable() && attempt < MAX_ATTEMPTS => {
                            attempt += 1;
                        }
                        ExecError::Txn(t) => return Err(txn_error(t)),
                        ExecError::Query(e) => return Err(e),
                    }
                }
            }
        }
    }

    fn next_batch(&mut self, db: &EmbeddedDb) -> Result<CursorBatch, Error> {
        if self.done {
            return Ok(CursorBatch {
                exhausted: true,
                ..CursorBatch::default()
            });
        }
        let result = match &mut self.snapshot {
            Snapshot::Own(Some(txn)) => {
                let mut store = QueryTxn { db, txn };
                self.inner
                    .next_batch(&mut store, &self.exec, &self.limits)
                    .map_err(|e| match e {
                        ExecError::Query(e) => e,
                        ExecError::Txn(t) => txn_error(t),
                    })
            }
            Snapshot::Own(None) => Ok(CursorBatch {
                exhausted: true,
                ..CursorBatch::default()
            }),
            Snapshot::Shared(shared) => {
                let (inner, exec, limits) = (&mut self.inner, &self.exec, &self.limits);
                shared.read(|txn| {
                    let mut store = QueryTxn { db, txn };
                    inner.next_batch(&mut store, exec, limits)
                })
            }
        };
        match result {
            Ok(batch) => {
                if batch.exhausted {
                    self.finish()?;
                }
                Ok(batch)
            }
            Err(e) => {
                self.abandon();
                Err(e)
            }
        }
    }

    fn collect_rows(&mut self, db: &EmbeddedDb) -> Result<Vec<rustegon_doc::Value>, Error> {
        let mut out = Vec::new();
        loop {
            let b = self.next_batch(db)?;
            out.extend(b.rows);
            if b.exhausted {
                return Ok(out);
            }
        }
    }

    /// Ends the cursor normally: commits its own transaction (a cursor in an interactive
    /// transaction leaves it to its owner).
    fn finish(&mut self) -> Result<(), Error> {
        self.done = true;
        if let Snapshot::Own(slot) = &mut self.snapshot
            && let Some(mut txn) = slot.take()
        {
            txn.commit().map_err(txn_error)?;
        }
        Ok(())
    }

    /// Ends the cursor after an error or a drop.
    fn abandon(&mut self) {
        self.done = true;
        if let Snapshot::Own(slot) = &mut self.snapshot
            && let Some(mut txn) = slot.take()
        {
            // Read-only: nothing to undo, so a failed rollback only leaves the registry entry
            // to expire; there is no caller to report it to (error path, `Drop`).
            let _rollback = txn.rollback();
        }
    }
}

impl Drop for CursorCore {
    fn drop(&mut self) {
        self.abandon();
    }
}
