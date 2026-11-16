// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The executor (query-engine.md §2 "Executor", §5, §9): batched pull iterators over a
//! [`QueryStore`] — one transaction of the caller.
//!
//! **Statement atomicity.** Every statement runs under a savepoint of the caller's
//! transaction: a request error after some writes (e.g. a duplicate key on the 5th row of an
//! `UPDATE`) rolls the statement's writes back and leaves the transaction usable. Transaction
//! errors are returned as [`ExecError::Txn`] for the caller's retry loop.
//!
//! **Batches.** Sources produce batches of at most [`ExecOptions::batch_rows`] rows (default
//! 1024) or [`ExecOptions::batch_bytes`] (default 1 MiB); index ranges are read by pages of
//! `batch_rows` entries.
//!
//! **Deadlines and cancellation** (FR-QL-008, TC-QL-008). The [`Interrupt`] (`RGN-5006`
//! deadline on the executor's [`Clock`], `RGN-5005` cancellation flag) is checked before every
//! source batch and index page, before and after an in-memory sort, before every batch drained
//! from a sort, and before every `batch_rows` written rows. The work done after a deadline passes
//! is therefore at most one batch (read or written) or one sort of rows already in memory; the
//! statement's writes are rolled back with the statement savepoint.
//! `OPTIONS (max_time_ms = n)` adds a deadline `n` ms after the statement starts (after
//! binding); a cursor's deadline covers all its batches.
//!
//! **Memory.** Blocking operators (`Sort`, `TopK`) and the row set of a write statement are
//! bounded by [`ExecOptions::memory_limit`] (per stage, default 100 MiB, database-engine.md §5);
//! beyond it the query fails with `RGN-5004` (spilling is a later feature).
//!
//! **Access paths.** Reads are planned with the cost-based chooser
//! ([`CostBasedChooser`]) over the statistics the store returns
//! ([`QueryStore::collection_stats`]); without statistics it applies the rule-based choice.
//! Every executed index access is counted in the store's [`IndexUsageRegistry`] (FR-IDX-004).

mod cursor;
mod explain;
mod project;
mod read;
mod write;

use std::{
    ops::Bound,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rustegon_catalog::{CollectionDescriptor, IndexDescriptor};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_index::IndexPage;
use rustegon_sim_api::Clock;

pub use self::{
    cursor::{
        CursorBatch, CursorLimits, DEFAULT_CURSOR_BATCH_BYTES, DEFAULT_CURSOR_BATCH_ROWS,
        QueryCursor, open_cursor,
    },
    explain::EXPLAIN_FORMAT,
    read::RowStream,
};
use crate::{
    ast::Statement,
    bind::{Binder, BoundQuery, BoundStatement, CatalogView, IndexHint},
    error::{ExecError, ExecResult},
    expr::EvalCtx,
    params::Params,
    plan::{CostBasedChooser, PhysicalPlan, plan_query},
    stats::{CollectionStats, CostConfig, IndexUsageRegistry},
};

/// Default rows per batch (query-engine.md §2).
pub const DEFAULT_BATCH_ROWS: usize = 1024;
/// Default bytes per batch (query-engine.md §2).
pub const DEFAULT_BATCH_BYTES: usize = 1 << 20;
/// Default memory limit of one blocking stage (database-engine.md §5: per-stage 100 MiB).
pub const DEFAULT_MEMORY_LIMIT: usize = 100 << 20;
/// Name of the per-statement savepoint.
pub(crate) const STATEMENT_SAVEPOINT: &str = "rustegon.query.statement";

/// Storage seen by the executor: reads and writes inside one transaction of the caller.
///
/// Writes go through the caller's single write path, which runs the collection's validators,
/// then maintains its indexes, then writes the document (FR-SCH-002, FR-IDX-002), and keeps the
/// server-maintained fields (`_rev`, `_createdAt`, `_updatedAt`).
pub trait QueryStore: CatalogView {
    /// The document whose `_id` is `id`.
    ///
    /// # Errors
    /// Transaction or decoding errors.
    fn get(&mut self, coll: &CollectionDescriptor, id: &Value) -> ExecResult<Option<Document>>;

    /// Documents with keys in `[start, end)`, ascending, at most `max`.
    ///
    /// # Errors
    /// Transaction or decoding errors.
    fn scan(
        &mut self,
        start: &[u8],
        end: &[u8],
        max: usize,
    ) -> ExecResult<Vec<(Vec<u8>, Document)>>;

    /// At most `max` index entries within `[lower, upper]` strictly after the raw entry key
    /// `after` (`rustegon_index::scan_index_page`; the page's `resume` continues the range).
    ///
    /// # Errors
    /// Transaction errors, invalid bounds.
    fn scan_index(
        &mut self,
        index: &IndexDescriptor,
        lower: Bound<&[Option<Value>]>,
        upper: Bound<&[Option<Value>]>,
        after: Option<&[u8]>,
        max: usize,
    ) -> ExecResult<IndexPage>;

    /// The document an index entry points to (`id_element` = `enc(_id)`).
    ///
    /// # Errors
    /// Transaction or decoding errors.
    fn fetch(
        &mut self,
        coll: &CollectionDescriptor,
        id_element: &[u8],
    ) -> ExecResult<Option<Document>>;

    /// Inserts a user document into `database.collection` (created implicitly when allowed)
    /// and returns the stored document.
    ///
    /// # Errors
    /// `RGN-1005` (duplicate `_id` or unique key), validator and limit errors, transaction
    /// errors.
    fn insert(&mut self, database: &str, collection: &str, doc: Document) -> ExecResult<Document>;

    /// Replaces `old` by `new` (server-maintained fields of `new` are recomputed) and returns
    /// the stored document.
    ///
    /// # Errors
    /// `RGN-1001` (`_id` changed), validator, index and limit errors, transaction errors.
    fn replace(
        &mut self,
        coll: &CollectionDescriptor,
        old: &Document,
        new: Document,
    ) -> ExecResult<Document>;

    /// Deletes `old`.
    ///
    /// # Errors
    /// Transaction errors.
    fn delete(&mut self, coll: &CollectionDescriptor, old: &Document) -> ExecResult<()>;

    /// `now()`: the transaction timestamp in ms since the Unix epoch.
    fn now_ms(&self) -> i64;

    /// Sets a savepoint of the transaction.
    ///
    /// # Errors
    /// Transaction errors.
    fn savepoint(&mut self, name: &str) -> ExecResult<()>;

    /// Rolls back to a savepoint (which remains).
    ///
    /// # Errors
    /// Transaction errors.
    fn rollback_to_savepoint(&mut self, name: &str) -> ExecResult<()>;

    /// Releases a savepoint.
    ///
    /// # Errors
    /// Transaction errors.
    fn release_savepoint(&mut self, name: &str) -> ExecResult<()>;

    /// Optimizer statistics of `coll` (`None`: never analyzed, or the store keeps none; reads
    /// are then planned by the rules). Statistics are advisory: they may be stale or come from
    /// another snapshot than the transaction's, and must not be read through the transaction
    /// (they would join its read set).
    ///
    /// # Errors
    /// Store errors (the default implementation has none).
    fn collection_stats(
        &mut self,
        _coll: &CollectionDescriptor,
    ) -> ExecResult<Option<Arc<CollectionStats>>> {
        Ok(None)
    }

    /// The node's index usage counters (FR-IDX-004), `None` if the store does not keep them.
    fn index_usage(&self) -> Option<&IndexUsageRegistry> {
        None
    }
}

/// Deadline and cancellation hook (FR-QL-008, module docs "Deadlines and cancellation").
#[derive(Clone, Default)]
pub struct Interrupt {
    deadline: Option<(Arc<dyn Clock>, Duration)>,
    /// Every flag that cancels the work (a statement's own `KILL QUERY` flag, the remote
    /// cancel of the transaction or cursor it runs in, …): any one set cancels.
    cancel: Vec<Arc<AtomicBool>>,
}

impl std::fmt::Debug for Interrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interrupt")
            .field("deadline", &self.deadline.as_ref().map(|(_, d)| *d))
            .field("cancel_flags", &self.cancel.len())
            .finish()
    }
}

impl Interrupt {
    /// No deadline, not cancellable.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Fails once `clock.monotonic()` passes `at`.
    #[must_use]
    pub fn with_deadline(mut self, clock: Arc<dyn Clock>, at: Duration) -> Self {
        self.deadline = Some(match self.deadline.take() {
            Some((c, old)) if old <= at => (c, old),
            _ => (clock, at),
        });
        self
    }

    /// Also fails once `flag` is set (`KILL QUERY`, client disconnect, remote cancel of the
    /// enclosing transaction or cursor); flags added before keep cancelling.
    #[must_use]
    pub fn with_cancel(mut self, flag: Arc<AtomicBool>) -> Self {
        if !self.cancel.iter().any(|f| Arc::ptr_eq(f, &flag)) {
            self.cancel.push(flag);
        }
        self
    }

    /// Checks the deadline and the cancellation flag.
    ///
    /// # Errors
    /// `RGN-5005 Cancelled`, `RGN-5006 DeadlineExceeded`.
    pub fn check(&self) -> Result<(), Error> {
        // Relaxed: the flag carries no data; a late observation only delays the stop by one
        // batch.
        if self.cancel.iter().any(|c| c.load(Ordering::Relaxed)) {
            return Err(Error::new(ErrorCode::Cancelled, "query cancelled"));
        }
        if let Some((clock, at)) = &self.deadline
            && clock.monotonic() >= *at
        {
            return Err(Error::new(
                ErrorCode::DeadlineExceeded,
                "query deadline exceeded",
            ));
        }
        Ok(())
    }
}

/// Executor settings.
#[derive(Clone)]
pub struct ExecOptions {
    /// Rows per batch.
    pub batch_rows: usize,
    /// Bytes per batch (approximate).
    pub batch_bytes: usize,
    /// Memory of one blocking stage (approximate bytes).
    pub memory_limit: usize,
    /// Deadline / cancellation.
    pub interrupt: Interrupt,
    /// Clock for `OPTIONS (max_time_ms = …)` (no clock: the option is not enforced).
    pub clock: Option<Arc<dyn Clock>>,
    /// Overrides the access-path hint of reads (`IndexHint::CollectionScan` for
    /// index-vs-scan equivalence tests).
    pub index_override: Option<IndexHint>,
    /// Access-path chooser of reads.
    pub optimizer: Optimizer,
    /// `query.cost.*` constants of the cost model (query-engine.md §3).
    pub cost: CostConfig,
}

/// Which access-path chooser plans reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Optimizer {
    /// Cost-based with the store's statistics; rule-based when there are none (the default).
    #[default]
    CostBased,
    /// Always rule-based (ignores statistics).
    RuleBased,
}

impl std::fmt::Debug for ExecOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecOptions")
            .field("batch_rows", &self.batch_rows)
            .field("batch_bytes", &self.batch_bytes)
            .field("memory_limit", &self.memory_limit)
            .field("interrupt", &self.interrupt)
            .field("clock", &self.clock.is_some())
            .field("index_override", &self.index_override)
            .field("optimizer", &self.optimizer)
            .field("cost", &self.cost)
            .finish()
    }
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            batch_rows: DEFAULT_BATCH_ROWS,
            batch_bytes: DEFAULT_BATCH_BYTES,
            memory_limit: DEFAULT_MEMORY_LIMIT,
            interrupt: Interrupt::none(),
            clock: None,
            index_override: None,
            optimizer: Optimizer::default(),
            cost: CostConfig::default(),
        }
    }
}

/// The result of one statement.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct QueryResult {
    /// Result rows (`RETURNING` rows for writes; one plan row for `EXPLAIN`).
    pub rows: Vec<Value>,
    /// Documents inserted (an `UPSERT` that inserted counts here).
    pub inserted: u64,
    /// Documents updated (an `UPSERT` that replaced counts here).
    pub updated: u64,
    /// Documents deleted.
    pub deleted: u64,
    /// Warnings (total functions that returned `null` for invalid input, §4.2).
    pub warnings: u64,
}

impl QueryResult {
    /// Documents written.
    #[must_use]
    pub fn affected(&self) -> u64 {
        self.inserted + self.updated + self.deleted
    }

    /// The rows that are documents (objects), in order.
    #[must_use]
    pub fn documents(&self) -> Vec<Document> {
        self.rows
            .iter()
            .filter_map(|r| match r {
                Value::Object(d) => Some(d.clone()),
                _ => None,
            })
            .collect()
    }
}

/// Per-execution context shared by the operators.
pub(crate) struct ExecCtx<'a> {
    pub store: &'a mut dyn QueryStore,
    pub eval: &'a EvalCtx,
    pub opts: &'a ExecOptions,
    pub interrupt: Interrupt,
    /// Per-operator statistics of `EXPLAIN ANALYZE`.
    pub profile: Option<read::Profile>,
}

/// Binds, plans and executes `stmt` in the store's transaction (the stable entry point used by
/// the embedded API and by differential tests).
///
/// # Errors
/// [`ExecError::Query`] for request errors (the statement's writes are rolled back),
/// [`ExecError::Txn`] for transaction errors (retry the transaction).
pub fn execute(
    store: &mut dyn QueryStore,
    session_db: &str,
    stmt: &Statement,
    params: &Params,
    opts: &ExecOptions,
) -> ExecResult<QueryResult> {
    store.savepoint(STATEMENT_SAVEPOINT)?;
    let result = run(store, session_db, stmt, params, opts);
    match &result {
        Err(ExecError::Query(_)) => {
            store.rollback_to_savepoint(STATEMENT_SAVEPOINT)?;
            store.release_savepoint(STATEMENT_SAVEPOINT)?;
        }
        Ok(_) => store.release_savepoint(STATEMENT_SAVEPOINT)?,
        // The transaction will restart (or abort): its savepoints are gone anyway.
        Err(ExecError::Txn(_)) => {}
    }
    result
}

fn run(
    store: &mut dyn QueryStore,
    session_db: &str,
    stmt: &Statement,
    params: &Params,
    opts: &ExecOptions,
) -> ExecResult<QueryResult> {
    let bound = {
        let mut binder = Binder {
            catalog: store as &mut dyn CatalogView,
            session_db,
            params,
        };
        binder.bind(stmt)?
    };
    let eval = EvalCtx::new(store.now_ms());
    let mut interrupt = opts.interrupt.clone();
    if let (Some(ms), Some(clock)) = (statement_max_time(&bound), &opts.clock) {
        let at = clock.monotonic() + Duration::from_millis(ms);
        interrupt = interrupt.with_deadline(Arc::clone(clock), at);
    }
    interrupt.check()?;
    let mut cx = ExecCtx {
        store,
        eval: &eval,
        opts,
        interrupt,
        profile: None,
    };
    let mut result = match bound {
        BoundStatement::Query(q) => {
            let plan = Arc::new(plan_read(&mut *cx.store, &q, opts)?);
            QueryResult {
                rows: read::collect(&mut cx, &plan)?,
                ..QueryResult::default()
            }
        }
        BoundStatement::Explain { analyze, statement } => QueryResult {
            rows: vec![explain::explain(&mut cx, &statement, analyze)?],
            ..QueryResult::default()
        },
        BoundStatement::Insert(i) => write::insert(&mut cx, &i)?,
        BoundStatement::Update(u) => write::update(&mut cx, &u)?,
        BoundStatement::Delete(d) => write::delete(&mut cx, &d)?,
        BoundStatement::Upsert(u) => write::upsert(&mut cx, &u)?,
    };
    result.warnings = eval.warnings();
    Ok(result)
}

pub(crate) fn statement_max_time(s: &BoundStatement) -> Option<u64> {
    match s {
        BoundStatement::Query(q) => q.options.max_time_ms,
        BoundStatement::Update(u) => u.source.options.max_time_ms,
        BoundStatement::Delete(d) => d.source.options.max_time_ms,
        BoundStatement::Explain { statement, .. } => statement_max_time(statement),
        BoundStatement::Insert(_) | BoundStatement::Upsert(_) => None,
    }
}

/// Plans a read (`SELECT`, the row source of `UPDATE` / `DELETE` / `INSERT … SELECT`): applies
/// [`ExecOptions::index_override`], then the chooser of [`ExecOptions::optimizer`] with the
/// target collection's statistics (FR-QL-001; query-engine.md §3).
///
/// # Errors
/// Store errors while reading the statistics, planning errors.
pub(crate) fn plan_read(
    store: &mut dyn QueryStore,
    q: &BoundQuery,
    opts: &ExecOptions,
) -> ExecResult<PhysicalPlan> {
    let overridden;
    let q = match &opts.index_override {
        Some(h) => {
            let mut c = q.clone();
            c.options.index = h.clone();
            overridden = c;
            &overridden
        }
        None => q,
    };
    let stats = match (opts.optimizer, &q.target.collection) {
        (Optimizer::CostBased, Some(coll)) => store.collection_stats(coll)?,
        _ => None,
    };
    let chooser = CostBasedChooser::new(stats.as_deref(), opts.cost);
    Ok(plan_query(q, &chooser)?)
}

#[cfg(test)]
mod interrupt_tests {
    use super::*;

    #[test]
    fn interrupt_cancels_on_any_of_its_flags() {
        let statement = Arc::new(AtomicBool::new(false));
        let transaction = Arc::new(AtomicBool::new(false));
        let i = Interrupt::none()
            .with_cancel(Arc::clone(&statement))
            .with_cancel(Arc::clone(&transaction))
            .with_cancel(Arc::clone(&transaction));
        assert!(i.check().is_ok());
        transaction.store(true, Ordering::Relaxed);
        assert_eq!(i.check().map_err(|e| e.code()), Err(ErrorCode::Cancelled));
        transaction.store(false, Ordering::Relaxed);
        statement.store(true, Ordering::Relaxed);
        assert_eq!(i.check().map_err(|e| e.code()), Err(ErrorCode::Cancelled));
    }
}
