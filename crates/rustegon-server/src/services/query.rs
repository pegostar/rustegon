// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `QueryService`: `Execute` (streamed batches, cursors), `GetMore`, `KillCursor`, `Explain`
//! (FR-QL-001/002/005/006/007/008, protocol.md §3, §5.2, §5.5, §6; PD-041, PD-049, PD-053).
//!
//! `Execute` of a **read query** (`FROM …`) opens an engine cursor (its own read-only snapshot,
//! or reading through the interactive transaction named by `txn_id`) and streams its batches
//! from a producer task through a bounded channel, so HTTP/2 flow control throttles the
//! engine: the producer waits on the channel and never reads ahead more than one batch. With
//! `max_batches`, the stream ends after that many batches and, unless the result is exhausted,
//! the cursor moves to the registry ([`super::cursors`]) and the last batch carries its id.
//! Dropping the stream (client cancel) cancels the cursor's batch in progress and closes it.
//!
//! **Other statements** (writes, DDL, `EXPLAIN`, `SHOW`) run once and produce one batch:
//! `RETURNING` rows, `docs_affected`. Writes run with [`Completion::Await`] (their real outcome
//! is reported) under an interrupt carrying the request deadline, so a write that misses its
//! deadline is rolled back by the engine and reported as RGN-5006 — never half-applied.
//! Outside a transaction, writes with a client `rgn-request-id` are deduplicated.
//!
//! **Rows** are documents; a non-document row (`SELECT VALUE 1`) is wrapped as
//! `{"value": row}` by the transport adapters (PD-053). **Continuation tokens** are sealed
//! ([`super::token`]) on the way out and opened on the way in.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Value,
    json::{JsonMode, value_to_json},
};
use rustegon_engine::{CancelHandle, CursorOptions, EmbeddedDb, OwnedCursor};
use rustegon_query::{
    CursorLimits, ExecOptions, Interrupt, Params, QueryResult, Statement, parse_statement,
};
use tokio::sync::mpsc;

use super::{
    RequestContext, ServiceDeps,
    cursors::close_off_thread,
    data::{
        DataPlane, ReadConsistency, WriteConcern, check_consistency, check_write_concern, owner_of,
        txn_id_of,
    },
    privileges::statement_privileges,
};
use crate::Completion;

/// A statement as RGQL text or as a structured AST (FR-QL-002).
#[derive(Debug, Clone)]
pub enum QueryText {
    /// RGQL text.
    Rgql(String),
    /// Structured statement (already validated as canonical).
    Ast(Box<Statement>),
}

/// Execution options (`ExecOptions` of protocol.md §3).
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    /// Preferred rows per batch (capped by `max_batch_rows`).
    pub batch_size: Option<u32>,
    /// Server-side time limit, covering all batches of a cursor (query-language.md §5.3).
    pub max_time: Option<Duration>,
    /// Read consistency outside transactions.
    pub consistency: ReadConsistency,
    /// Allow blocking stages to spill (accepted; no spill in M4: RGN-5004 at the memory
    /// limit).
    pub allow_disk_use: bool,
    /// End the stream after this many batches, leaving a cursor.
    pub max_batches: Option<u32>,
    /// Sealed continuation token of a previous batch.
    pub continuation_token: Option<Vec<u8>>,
    /// Write concern of data-modifying statements outside transactions.
    pub write_concern: WriteConcern,
}

/// `Execute` input.
#[derive(Debug, Clone)]
pub struct ExecuteInput {
    /// Session database for unqualified names.
    pub database: String,
    /// The statement.
    pub query: QueryText,
    /// Parameters.
    pub params: Params,
    /// Options.
    pub options: QueryOptions,
    /// Interactive transaction (field; the `rgn-txn-id` header also applies).
    pub txn_id: Option<String>,
}

/// `Explain` input.
#[derive(Debug, Clone)]
pub struct ExplainInput {
    /// Session database.
    pub database: String,
    /// The explained statement (query, update or delete).
    pub query: QueryText,
    /// Parameters.
    pub params: Params,
    /// Options (`max_time`, consistency).
    pub options: QueryOptions,
    /// `EXPLAIN ANALYZE` (executes; writes are rolled back, query-language.md §5.1).
    pub analyze: bool,
    /// Interactive transaction.
    pub txn_id: Option<String>,
}

/// Execution statistics of the last batch. `docs_examined`/`keys_examined` are not reported
/// by the engine yet (0).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryStats {
    /// Rows returned by the whole result.
    pub docs_returned: u64,
    /// Documents inserted, updated or deleted.
    pub docs_affected: u64,
    /// Server time from the start of `Execute` to this batch.
    pub execution_time_us: u64,
}

/// A non-fatal condition reported with a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// Stable kind, e.g. `EvaluationWarning`.
    pub kind: String,
    /// Message (no document contents).
    pub message: String,
    /// Details.
    pub details: BTreeMap<String, String>,
}

/// One batch of results.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResultBatch {
    /// Rows.
    pub rows: Vec<Value>,
    /// Open cursor to continue with `GetMore`.
    pub cursor_id: Option<String>,
    /// Sealed keyset token (ordered queries with more rows).
    pub continuation_token: Option<Vec<u8>>,
    /// Statistics (last batch only).
    pub stats: Option<QueryStats>,
    /// Warnings.
    pub warnings: Vec<Warning>,
}

/// State shared by a stream and its producer.
struct StreamShared {
    /// The cursor was handed to the registry: dropping the stream must not cancel it.
    detached: AtomicBool,
    cancel: Option<CancelHandle>,
}

/// The batches of one `Execute`, in order; dropping it cancels the work (module docs).
pub struct ExecuteStream {
    rx: mpsc::Receiver<Result<ResultBatch, Error>>,
    shared: Arc<StreamShared>,
}

impl std::fmt::Debug for ExecuteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecuteStream").finish_non_exhaustive()
    }
}

impl ExecuteStream {
    /// The next batch; `None` after the last.
    pub async fn next(&mut self) -> Option<Result<ResultBatch, Error>> {
        self.rx.recv().await
    }

    /// Poll form of [`ExecuteStream::next`] (transport stream adapters).
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<ResultBatch, Error>>> {
        self.rx.poll_recv(cx)
    }

    fn single(item: Result<ResultBatch, Error>) -> Self {
        let (tx, rx) = mpsc::channel(1);
        // A fresh channel of capacity 1 always accepts its first message.
        let _ = tx.try_send(item);
        Self {
            rx,
            shared: Arc::new(StreamShared {
                detached: AtomicBool::new(true),
                cancel: None,
            }),
        }
    }
}

impl Drop for ExecuteStream {
    fn drop(&mut self) {
        if !self.shared.detached.load(Ordering::Acquire)
            && let Some(cancel) = &self.shared.cancel
        {
            cancel.cancel();
        }
    }
}

/// Sets a statement's interrupt flag when the request future is dropped before the statement
/// returned (client cancel: the statement stops within one operator batch).
struct InterruptOnDrop(Option<Arc<AtomicBool>>);

impl InterruptOnDrop {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for InterruptOnDrop {
    fn drop(&mut self) {
        if let Some(flag) = self.0.take() {
            flag.store(true, Ordering::Relaxed);
        }
    }
}

/// Cancels a cursor when a `GetMore` is dropped or abandoned at its deadline.
struct CancelOnDrop(Option<CancelHandle>);

impl CancelOnDrop {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(c) = self.0.take() {
            c.cancel();
        }
    }
}

/// Whether a statement only reads (its abandonment at the deadline loses nothing).
fn read_only(stmt: &Statement) -> bool {
    matches!(
        stmt,
        Statement::Query(_) | Statement::Explain { .. } | Statement::Show { .. }
    )
}

/// Parses RGQL text.
///
/// # Errors
/// The parser's RGN-1010/1013.
pub(crate) fn statement_of(query: QueryText) -> Result<Statement, Error> {
    match query {
        QueryText::Ast(stmt) => Ok(*stmt),
        QueryText::Rgql(text) => {
            // `From` (ParseError::into_error) keeps line/column/found/expected in the details
            // (errors.yaml RGN-1010); rebuilding the error from code + message dropped them.
            parse_statement(&text).map_err(Error::from)
        }
    }
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

fn evaluation_warnings(count: u64) -> Vec<Warning> {
    if count == 0 {
        return Vec::new();
    }
    vec![Warning {
        kind: "EvaluationWarning".to_owned(),
        message: format!("{count} expression(s) returned null for invalid input"),
        details: BTreeMap::from([("count".to_owned(), count.to_string())]),
    }]
}

/// `QueryService` (module docs).
#[derive(Debug, Clone)]
pub struct QueryService {
    deps: ServiceDeps,
    plane: Arc<DataPlane>,
}

impl QueryService {
    pub(crate) fn new(deps: ServiceDeps, plane: Arc<DataPlane>) -> Self {
        Self { deps, plane }
    }

    fn interrupt(
        &self,
        ctx: &RequestContext,
        max_time: Option<Duration>,
        with_request: bool,
    ) -> Interrupt {
        let clock = Arc::clone(&self.deps.clock);
        let now = clock.monotonic();
        let mut at = max_time.map(|t| now.saturating_add(t));
        if with_request && let Some(d) = ctx.deadline() {
            at = Some(at.map_or(d.at, |a| a.min(d.at)));
        }
        match at {
            Some(at) => Interrupt::none().with_deadline(clock, at),
            None => Interrupt::none(),
        }
    }

    fn batch_rows(&self, batch_size: Option<u32>) -> usize {
        let config = &self.plane.config;
        batch_size
            .filter(|b| *b > 0)
            .map_or(config.default_batch_rows, |b| {
                usize::try_from(b).unwrap_or(usize::MAX)
            })
            .clamp(1, config.max_batch_rows.max(1))
    }

    /// Runs a statement and returns its batches (module docs).
    ///
    /// # Errors
    /// Parse/bind/execution errors of the statement, RGN-1001 (options, token, transaction
    /// id), RGN-1030 (unknown transaction), RGN-5004 (cursor registry full), RGN-5006.
    pub async fn execute(
        &self,
        ctx: &RequestContext,
        input: ExecuteInput,
    ) -> Result<ExecuteStream, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        self.plane.authenticated(ctx)?;
        check_consistency(input.options.consistency)?;
        check_write_concern(input.options.write_concern)?;
        if input.options.max_batches == Some(0) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "max_batches must be at least 1",
            ));
        }
        let txn_id = txn_id_of(ctx, input.txn_id.as_deref())?;
        let stmt = statement_of(input.query)?;
        // `Access::Statement` (PD-051): the privileges of the statement itself (PD-053).
        self.plane
            .authorize(ctx, &statement_privileges(&stmt, &input.database))
            .await?;
        if matches!(stmt, Statement::Query(_)) {
            return self
                .execute_query(
                    ctx,
                    input.database,
                    stmt,
                    input.params,
                    input.options,
                    txn_id,
                )
                .await;
        }
        if input.options.continuation_token.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "continuation tokens apply to read queries only",
            ));
        }
        let write = !read_only(&stmt);
        let in_txn = txn_id.is_some();
        let service = self.clone();
        let run_ctx = ctx.clone();
        let started = self.deps.clock.monotonic();
        let run = async move {
            service
                .run_statement(
                    &run_ctx,
                    input.database,
                    stmt,
                    input.params,
                    input.options.max_time,
                    txn_id.as_deref(),
                )
                .await
        };
        // protocol.md §5.1: non-transactional writes are deduplicated by `rgn-request-id`.
        let result = if write && !in_txn {
            self.plane
                .idempotency
                .run(ctx, "QueryService/Execute", run)
                .await
        } else {
            run.await
        }?;
        let elapsed = self.deps.clock.monotonic().saturating_sub(started);
        let rows = result.rows;
        let batch = ResultBatch {
            stats: Some(QueryStats {
                docs_returned: u64::try_from(rows.len()).unwrap_or(u64::MAX),
                docs_affected: result.inserted + result.updated + result.deleted,
                execution_time_us: micros(elapsed),
            }),
            warnings: evaluation_warnings(result.warnings),
            rows,
            ..ResultBatch::default()
        };
        Ok(ExecuteStream::single(Ok(batch)))
    }

    /// Runs one non-cursor statement (in the transaction `txn_id` or an implicit one).
    async fn run_statement(
        &self,
        ctx: &RequestContext,
        database: String,
        stmt: Statement,
        params: Params,
        max_time: Option<Duration>,
        txn_id: Option<&str>,
    ) -> Result<QueryResult, Error> {
        let write = !read_only(&stmt);
        let flag = Arc::new(AtomicBool::new(false));
        let mut options = ExecOptions {
            interrupt: self.interrupt(ctx, max_time, true),
            ..ExecOptions::default()
        };
        options.interrupt = options.interrupt.with_cancel(Arc::clone(&flag));
        let guard = InterruptOnDrop(Some(flag));
        let completion = if write {
            Completion::Await
        } else {
            Completion::Abandon
        };
        let result = if let Some(id) = txn_id {
            let lease = self.plane.txns.lease(ctx, id)?;
            let txn = Arc::clone(lease.txn());
            let r = self
                .deps
                .executor
                .run(ctx, completion, move |_| {
                    txn.query_with(&database, &stmt, &params, &options)
                })
                .await;
            self.plane.txns.mark_finished_if_done(lease.entry());
            r
        } else {
            let db = Arc::clone(&self.plane.db);
            self.deps
                .executor
                .run(ctx, completion, move |_| {
                    db.query_with(&database, &stmt, &params, &options)
                })
                .await
        };
        guard.disarm();
        result
    }

    async fn execute_query(
        &self,
        ctx: &RequestContext,
        database: String,
        stmt: Statement,
        params: Params,
        options: QueryOptions,
        txn_id: Option<String>,
    ) -> Result<ExecuteStream, Error> {
        let owner = owner_of(ctx);
        let resume_token = options
            .continuation_token
            .as_deref()
            .map(|t| self.plane.sealer.open(t, owner.as_deref()))
            .transpose()?;
        let started = self.deps.clock.monotonic();
        let cursor_options = CursorOptions {
            limits: CursorLimits {
                batch_rows: self.batch_rows(options.batch_size),
                ..CursorLimits::default()
            },
            // The request deadline bounds this call's batches through the executor; only
            // `max_time` travels with the cursor to its later GetMore calls (§5.3).
            exec: ExecOptions {
                interrupt: self.interrupt(ctx, options.max_time, false),
                ..ExecOptions::default()
            },
            resume_token,
        };
        let cursor = if let Some(id) = txn_id.as_deref() {
            let lease = self.plane.txns.lease(ctx, id)?;
            let txn = Arc::clone(lease.txn());
            let r = self
                .deps
                .executor
                .run(ctx, Completion::Abandon, move |_| {
                    txn.open_cursor(&database, &stmt, &params, &cursor_options)
                })
                .await;
            self.plane.txns.mark_finished_if_done(lease.entry());
            r?
        } else {
            let db: Arc<EmbeddedDb> = Arc::clone(&self.plane.db);
            self.deps
                .executor
                .run(ctx, Completion::Abandon, move |_| {
                    db.open_owned_cursor(&database, &stmt, &params, &cursor_options)
                })
                .await?
        };
        let shared = Arc::new(StreamShared {
            detached: AtomicBool::new(false),
            cancel: Some(cursor.cancel_handle()),
        });
        // Capacity 1: the producer reads at most one batch ahead of the client (module docs).
        let (tx, rx) = mpsc::channel(1);
        let producer = Producer {
            service: self.clone(),
            ctx: ctx.clone(),
            tx,
            shared: Arc::clone(&shared),
            max_batches: options.max_batches,
            owner,
            started,
            txn_id,
        };
        tokio::spawn(producer.run(cursor));
        Ok(ExecuteStream { rx, shared })
    }

    fn seal(&self, token: Option<Vec<u8>>, owner: Option<&str>) -> Result<Option<Vec<u8>>, Error> {
        token.map(|t| self.plane.sealer.seal(&t, owner)).transpose()
    }

    /// Runs one batch of `cursor` on the executor; the cursor comes back with the batch.
    async fn next_batch(
        &self,
        ctx: &RequestContext,
        mut cursor: OwnedCursor,
    ) -> Result<
        (
            OwnedCursor,
            Result<rustegon_query::CursorBatch, Error>,
            Duration,
        ),
        Error,
    > {
        let clock = Arc::clone(&self.deps.clock);
        self.deps
            .executor
            .run(ctx, Completion::Abandon, move |_| {
                let start = clock.monotonic();
                let batch = cursor.next_batch();
                // PD-233: the time on the executor thread, without the wait for one.
                let ran = clock.monotonic().saturating_sub(start);
                Ok((cursor, batch, ran))
            })
            .await
    }

    /// The next batch of an open cursor.
    ///
    /// # Errors
    /// RGN-1030 (unknown/expired cursor), RGN-1001 (in use), the cursor's errors (it is
    /// closed after any error), RGN-5006 (the cursor is killed).
    pub async fn get_more(
        &self,
        ctx: &RequestContext,
        cursor_id: &str,
        batch_size: Option<u32>,
    ) -> Result<ResultBatch, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        self.plane.authenticated(ctx)?;
        let owner = owner_of(ctx);
        let (entry, mut cursor) = self.plane.cursors.checkout(cursor_id, owner.as_deref())?;
        // A cursor opened in a transaction reads through it: the call keeps the transaction
        // alive (registry idle clock) and fails once the transaction is gone.
        let _lease = match entry
            .txn
            .as_deref()
            .map(|t| self.plane.txns.lease(ctx, t))
            .transpose()
        {
            Ok(lease) => lease,
            Err(e) => {
                self.plane.cursors.remove(cursor_id);
                close_off_thread(Some(cursor));
                return Err(e);
            }
        };
        if batch_size.is_some() {
            cursor.set_limits(CursorLimits {
                batch_rows: self.batch_rows(batch_size),
                ..CursorLimits::default()
            });
        }
        let kill = CancelOnDrop(Some(entry.cancel.clone()));
        let outcome = self.next_batch(ctx, cursor).await;
        let (cursor, batch) = match outcome {
            Ok((cursor, batch, _)) => (cursor, batch),
            Err(e) => {
                // Abandoned at the deadline: the batch is lost, so is the cursor.
                self.plane.cursors.remove(cursor_id);
                return Err(e);
            }
        };
        kill.disarm();
        let batch = match batch {
            Ok(b) => b,
            Err(e) => {
                self.plane.cursors.remove(cursor_id);
                close_off_thread(Some(cursor));
                return Err(e);
            }
        };
        let continuation_token = self.seal(batch.continuation_token, owner.as_deref())?;
        if batch.exhausted {
            let stats = QueryStats {
                docs_returned: cursor.returned(),
                docs_affected: 0,
                execution_time_us: micros(
                    self.deps.clock.monotonic().saturating_sub(entry.started),
                ),
            };
            self.plane.cursors.remove(cursor_id);
            close_off_thread(Some(cursor));
            return Ok(ResultBatch {
                rows: batch.rows,
                continuation_token,
                stats: Some(stats),
                ..ResultBatch::default()
            });
        }
        self.plane.cursors.put_back(&entry, cursor);
        Ok(ResultBatch {
            rows: batch.rows,
            cursor_id: Some(cursor_id.to_owned()),
            continuation_token,
            ..ResultBatch::default()
        })
    }

    /// Closes a cursor; `false` if it was unknown or already closed.
    ///
    /// # Errors
    /// RGN-5006 when the deadline already passed.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // Same async shape as every service method (PD-050).
    pub async fn kill_cursor(&self, ctx: &RequestContext, cursor_id: &str) -> Result<bool, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        self.plane.authenticated(ctx)?;
        Ok(self.plane.cursors.kill(cursor_id, owner_of(ctx).as_deref()))
    }

    /// The plan of a statement as explain-format-1 JSON (query-language.md §5.1).
    ///
    /// # Errors
    /// As [`QueryService::execute`]; RGN-1001 for statements EXPLAIN does not cover.
    pub async fn explain(
        &self,
        ctx: &RequestContext,
        input: ExplainInput,
    ) -> Result<String, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        check_consistency(input.options.consistency)?;
        let txn_id = txn_id_of(ctx, input.txn_id.as_deref())?;
        let inner = statement_of(input.query)?;
        if !matches!(
            inner,
            Statement::Query(_) | Statement::Update(_) | Statement::Delete(_)
        ) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "EXPLAIN covers queries, UPDATE and DELETE",
            ));
        }
        let stmt = Statement::Explain {
            analyze: input.analyze,
            statement: Box::new(inner),
        };
        self.plane.authenticated(ctx)?;
        self.plane
            .authorize(ctx, &statement_privileges(&stmt, &input.database))
            .await?;
        // EXPLAIN ANALYZE of a write rolls its writes back (§5.1): reads only, Abandon is safe.
        let result = self
            .run_statement(
                ctx,
                input.database,
                stmt,
                input.params,
                input.options.max_time,
                txn_id.as_deref(),
            )
            .await?;
        let row = result
            .rows
            .first()
            .ok_or_else(|| Error::new(ErrorCode::Internal, "EXPLAIN returned no row"))?;
        Ok(value_to_json(row, JsonMode::Canonical))
    }

    /// Open cursors on this node (tests, diagnostics).
    #[must_use]
    pub fn open_cursors(&self) -> usize {
        self.plane.cursors.len()
    }

    /// `Execute` streams still holding an engine cursor (tests, diagnostics).
    #[must_use]
    pub fn active_streams(&self) -> usize {
        self.plane.streams.load(Ordering::Acquire)
    }
}

/// The task streaming a cursor's batches into an [`ExecuteStream`].
struct Producer {
    service: QueryService,
    ctx: RequestContext,
    tx: mpsc::Sender<Result<ResultBatch, Error>>,
    shared: Arc<StreamShared>,
    max_batches: Option<u32>,
    owner: Option<String>,
    started: Duration,
    txn_id: Option<String>,
}

/// Logs a read query's stream that took `SLOW_QUERY` or longer when its producer ends
/// (PD-233/PD-234; the gRPC layer times `Execute` only up to the response headers):
/// `open_ms` up to the open cursor, `scan_ms` on executor threads, `queue_ms` waiting for one,
/// the rest of `duration_ms` waiting for the client to take batches.
struct ScanTimer {
    clock: Arc<dyn rustegon_sim_api::Clock>,
    trace_id: String,
    started: Duration,
    opened: Duration,
    wall: Duration,
    ran: Duration,
}

impl Drop for ScanTimer {
    fn drop(&mut self) {
        let total = self.clock.monotonic().saturating_sub(self.started);
        if total >= crate::grpc::SLOW_QUERY {
            let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
            tracing::warn!(
                target: "slow_query",
                trace_id = %self.trace_id,
                open_ms = ms(self.opened.saturating_sub(self.started)),
                scan_ms = ms(self.ran),
                queue_ms = ms(self.wall.saturating_sub(self.ran)),
                duration_ms = ms(total),
                "slow query stream"
            );
        }
    }
}

/// Counts a running producer in `DataPlane::streams`.
struct StreamCount(Arc<DataPlane>);

impl StreamCount {
    fn new(plane: &Arc<DataPlane>) -> Self {
        plane.streams.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(plane))
    }
}

impl Drop for StreamCount {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Producer {
    async fn run(self, cursor: OwnedCursor) {
        let _count = StreamCount::new(&self.service.plane);
        let mut cursor = Some(cursor);
        let mut sent: u32 = 0;
        let clock = Arc::clone(&self.service.deps.clock);
        let mut timer = ScanTimer {
            clock: Arc::clone(&clock),
            trace_id: self.ctx.trace_id_hex(),
            started: self.started,
            opened: clock.monotonic(),
            wall: Duration::ZERO,
            ran: Duration::ZERO,
        };
        while let Some(current) = cursor.take() {
            let before = clock.monotonic();
            let next = self.service.next_batch(&self.ctx, current).await;
            timer.wall += clock.monotonic().saturating_sub(before);
            let (current, batch) = match next {
                Ok((current, batch, ran)) => {
                    timer.ran += ran;
                    (current, batch)
                }
                Err(e) => {
                    // Abandoned (deadline): the closure drops the cursor; stop it early.
                    self.cancel();
                    let _ = self.tx.send(Err(e)).await;
                    return;
                }
            };
            let batch = match batch {
                Ok(b) => b,
                Err(e) => {
                    close_off_thread(Some(current));
                    let _ = self.tx.send(Err(e)).await;
                    return;
                }
            };
            sent = sent.saturating_add(1);
            let token = match self
                .service
                .seal(batch.continuation_token, self.owner.as_deref())
            {
                Ok(t) => t,
                Err(e) => {
                    close_off_thread(Some(current));
                    let _ = self.tx.send(Err(e)).await;
                    return;
                }
            };
            let mut out = ResultBatch {
                rows: batch.rows,
                continuation_token: token,
                ..ResultBatch::default()
            };
            if batch.exhausted {
                out.stats = Some(self.stats(current.returned()));
                close_off_thread(Some(current));
                let _ = self.tx.send(Ok(out)).await;
                return;
            }
            if self.max_batches.is_some_and(|m| sent >= m) {
                self.shared.detached.store(true, Ordering::Release);
                let registered = self.service.plane.cursors.register(
                    current,
                    self.owner.clone(),
                    self.started,
                    self.service.deps.rng.as_ref(),
                    self.txn_id.clone(),
                );
                let item = registered.map(|id| {
                    out.cursor_id = Some(id);
                    out
                });
                let _ = self.tx.send(item).await;
                return;
            }
            if self.tx.send(Ok(out)).await.is_err() {
                // The client cancelled the stream: kill the cursor (protocol.md §3).
                close_off_thread(Some(current));
                return;
            }
            cursor = Some(current);
        }
    }

    fn cancel(&self) {
        if let Some(c) = &self.shared.cancel {
            c.cancel();
        }
    }

    fn stats(&self, returned: u64) -> QueryStats {
        QueryStats {
            docs_returned: returned,
            docs_affected: 0,
            execution_time_us: micros(
                self.service
                    .deps
                    .clock
                    .monotonic()
                    .saturating_sub(self.started),
            ),
        }
    }
}
