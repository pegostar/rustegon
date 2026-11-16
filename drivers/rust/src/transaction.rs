// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transactions (rust-driver.md §5, transactions.md §5, retry.yaml R6).
//!
//! Manual mode: [`crate::Client::begin_transaction`], then [`Transaction::commit`] /
//! [`Transaction::rollback`]; a commit failing with RGN-2006 (or without `ErrorDetail` after it
//! was sent, PD-122) leaves the outcome unknown and [`Transaction::resolve`] asks the server.
//! Helper mode: [`crate::Client::with_transaction`] re-runs the callback on retryable errors
//! until `max_retry_time`, and resolves an unknown commit with `TransactionService.Status`, never
//! by re-running blindly.

use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    Collection, Database,
    codec::Document,
    codes,
    cursor::Cursor,
    database::{DataContext, concern_of, consistency_of},
    error::{Error, ErrorClass, Result},
    options::Action,
    pb::{
        AstIsolation, BeginRequest, CommitRequest, HeartbeatRequest, RollbackRequest,
        StatusRequest, TransactionState,
    },
    settings::{ReadConsistency, WriteConcern},
    transport::{CallSpec, Executor, OpKind, backoff_delay, may_have_reached_server, unary},
};

/// Isolation level of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Serializable (server default).
    Serializable,
    /// Snapshot isolation.
    Snapshot,
    /// Read committed.
    ReadCommitted,
}

/// Options of a transaction.
#[derive(Debug, Clone, Default)]
pub struct TransactionOptions {
    /// Isolation (server default when `None`).
    pub isolation: Option<Isolation>,
    /// Read-only transaction.
    pub read_only: bool,
    /// Read consistency of a read-only transaction.
    pub read_consistency: Option<(ReadConsistency, Option<Duration>)>,
    /// Write concern of the commit.
    pub write_concern: Option<WriteConcern>,
    /// `with_transaction`: how long to keep retrying (default 2 minutes).
    pub max_retry_time: Option<Duration>,
}

impl TransactionOptions {
    /// Default options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Isolation level.
    #[must_use]
    pub fn isolation(mut self, i: Isolation) -> Self {
        self.isolation = Some(i);
        self
    }
    /// Read-only.
    #[must_use]
    pub fn read_only(mut self, on: bool) -> Self {
        self.read_only = on;
        self
    }
    /// Retry budget of `with_transaction`.
    #[must_use]
    pub fn max_retry_time(mut self, d: Duration) -> Self {
        self.max_retry_time = Some(d);
        self
    }
    /// Write concern of the commit.
    #[must_use]
    pub fn write_concern(mut self, wc: WriteConcern) -> Self {
        self.write_concern = Some(wc);
        self
    }
}

/// Outcome reported by [`Transaction::resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionOutcome {
    /// The transaction committed.
    Committed,
    /// The transaction aborted.
    Aborted,
    /// Still unknown (committing, or the status call failed).
    Unknown,
}

impl TransactionOutcome {
    /// Lowercase name (`committed`, `aborted`, `unknown`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Aborted => "aborted",
            Self::Unknown => "unknown",
        }
    }
}

const ACTIVE: u8 = 0;
const COMMITTED: u8 = 1;
const UNKNOWN: u8 = 2;
const ENDED: u8 = 3;

struct Inner {
    exec: Arc<Executor>,
    default_db: String,
    id: String,
    state: AtomicU8,
    closed: AtomicBool,
    heartbeat: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Inner {
    fn stop_heartbeat(&self) {
        if let Ok(mut h) = self.heartbeat.lock()
            && let Some(h) = h.take()
        {
            h.abort();
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop_heartbeat();
        // The last handle of an active transaction is gone: roll it back in the background
        // (best effort; the server also aborts it after its idle timeout).
        if self.state.load(Ordering::Acquire) == ACTIVE
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            let exec = Arc::clone(&self.exec);
            let id = self.id.clone();
            rt.spawn(async move { rollback_call(&exec, id).await });
        }
    }
}

async fn rollback_call(exec: &Executor, id: String) -> Result<()> {
    unary!(
        exec,
        CallSpec::of(OpKind::NoRetry),
        transaction_service_client::TransactionServiceClient,
        rollback,
        RollbackRequest { txn_id: id }
    )
    .map(|_| ())
}

/// A transaction; cheap to clone (clones share it). Collections obtained from it run their
/// operations inside it. Dropping the last handle of an active transaction rolls it back.
#[derive(Clone)]
pub struct Transaction {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("id", &self.inner.id)
            .finish_non_exhaustive()
    }
}

impl Transaction {
    pub(crate) async fn begin(
        exec: &Arc<Executor>,
        default_db: String,
        o: &TransactionOptions,
    ) -> Result<Self> {
        exec.check_open()?;
        let req = BeginRequest {
            isolation: match o.isolation {
                None => AstIsolation::Unspecified,
                Some(Isolation::Serializable) => AstIsolation::Serializable,
                Some(Isolation::Snapshot) => AstIsolation::Snapshot,
                Some(Isolation::ReadCommitted) => AstIsolation::ReadCommitted,
            }
            .into(),
            read_only: o.read_only,
            priority: 0,
            consistency: if o.read_only {
                let (l, d) = o.read_consistency.map_or(
                    (exec.settings.read_consistency, exec.settings.max_staleness),
                    |(l, d)| (Some(l), d),
                );
                consistency_of(l, d)?
            } else {
                None
            },
            idle_timeout_ms: None,
            write_concern: concern_of(o.write_concern.or(exec.settings.write_concern)),
        };
        let r = unary!(
            exec,
            CallSpec::of(OpKind::NoRetry),
            transaction_service_client::TransactionServiceClient,
            begin,
            req
        )?;
        let t = Self {
            inner: Arc::new(Inner {
                exec: Arc::clone(exec),
                default_db,
                id: r.txn_id,
                state: AtomicU8::new(ACTIVE),
                closed: AtomicBool::new(false),
                heartbeat: Mutex::new(None),
            }),
        };
        if r.heartbeat_interval_ms > 0 {
            // The task holds only the executor and the id, so dropping the transaction is not
            // prevented by its own heartbeat.
            let exec = Arc::clone(exec);
            let id = t.inner.id.clone();
            let every = Duration::from_millis(u64::from(r.heartbeat_interval_ms));
            let h = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(every).await;
                    let _ = unary!(
                        exec,
                        CallSpec::of(OpKind::NoRetry),
                        transaction_service_client::TransactionServiceClient,
                        heartbeat,
                        HeartbeatRequest { txn_id: id.clone() }
                    );
                }
            });
            if let Ok(mut slot) = t.inner.heartbeat.lock() {
                *slot = Some(h);
            }
        }
        Ok(t)
    }

    /// The server's transaction id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.inner.id
    }

    pub(crate) fn check_active(&self) -> Result<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Error::closed("the transaction"));
        }
        self.inner.exec.check_open()
    }

    fn leave(&self, state: u8) {
        if self
            .inner
            .state
            .compare_exchange(ACTIVE, state, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.inner.stop_heartbeat();
        }
    }

    /// A database handle whose operations run in this transaction.
    #[must_use]
    pub fn database(&self, name: &str) -> Database {
        Database {
            ctx: DataContext {
                exec: Arc::clone(&self.inner.exec),
                database: name.to_owned(),
                txn: Some(self.clone()),
            },
        }
    }

    /// A collection of the default database, or `db.collection` (model `GetCollection`).
    #[must_use]
    pub fn collection(&self, name: &str) -> Collection {
        match name.split_once('.') {
            Some((db, coll)) if !db.is_empty() => self.database(db).collection(coll),
            _ => self.database(&self.inner.default_db).collection(name),
        }
    }

    /// RGQL text inside the transaction (default database).
    pub fn query(&self, rgql: &str, params: Document) -> Action<'static, Cursor> {
        let db = self.database(&self.inner.default_db);
        let rgql = rgql.to_owned();
        Action::new(move |o| async move {
            let mut a = db.query(&rgql, params);
            if let Some(b) = o.batch_size {
                a = a.batch_size(b);
            }
            if let Some(t) = o.timeout {
                a = a.timeout(t);
            }
            a.await
        })
    }

    /// Commits. RGN-2006 (or a lost reply) means the outcome is unknown: see
    /// [`resolve`](Self::resolve).
    pub async fn commit(&self) -> Result<()> {
        self.check_active()?;
        let r = unary!(
            self.inner.exec,
            CallSpec::of(OpKind::NoRetry),
            transaction_service_client::TransactionServiceClient,
            commit,
            CommitRequest {
                txn_id: self.inner.id.clone()
            }
        );
        let Err(err) = r else {
            self.leave(COMMITTED);
            return Ok(());
        };
        if err.class() == Some(ErrorClass::CommitOutcomeUnknown) {
            self.leave(UNKNOWN);
            return Err(err);
        }
        if may_have_reached_server(&err) {
            // PD-122/PD-119: the commit may have been applied before the reply was lost.
            self.leave(UNKNOWN);
            let mut u = Error::coded(
                codes::COMMIT_OUTCOME_UNKNOWN,
                false,
                format!("the commit reply was lost ({err}); the outcome is unknown"),
            );
            if let (Some(t), Some(src)) = (u.rustegon_mut(), err.rustegon()) {
                t.trace_id.clone_from(&src.trace_id);
            }
            return Err(u);
        }
        Err(err)
    }

    /// Rolls back.
    pub async fn rollback(&self) -> Result<()> {
        self.check_active()?;
        self.leave(ENDED);
        rollback_call(&self.inner.exec, self.inner.id.clone()).await
    }

    /// Asks the server for the outcome (`TransactionService.Status`).
    pub async fn resolve(&self) -> Result<TransactionOutcome> {
        let r = unary!(
            self.inner.exec,
            CallSpec::of(OpKind::NoRetry),
            transaction_service_client::TransactionServiceClient,
            status,
            StatusRequest {
                txn_id: self.inner.id.clone()
            }
        )?;
        Ok(match TransactionState::try_from(r.state) {
            Ok(TransactionState::Committed) => TransactionOutcome::Committed,
            Ok(TransactionState::Aborted) => TransactionOutcome::Aborted,
            _ => TransactionOutcome::Unknown,
        })
    }

    /// Ends the transaction: rolls back if it is still active. Idempotent; later operations
    /// fail with [`Error::InvalidState`].
    pub async fn close(&self) -> Result<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.inner.state.load(Ordering::Acquire) == ACTIVE {
            self.leave(ENDED);
            let _ = rollback_call(&self.inner.exec, self.inner.id.clone()).await;
        }
        self.inner.closed.store(true, Ordering::Release);
        self.inner.stop_heartbeat();
        Ok(())
    }

    async fn rollback_best_effort(&self) {
        if self.inner.state.load(Ordering::Acquire) == ACTIVE {
            let _ = self.rollback().await;
        }
    }
}

/// `with_transaction` (transactions.md §5, R6).
pub(crate) async fn with_transaction<T, F, Fut>(
    exec: &Arc<Executor>,
    default_db: &str,
    o: TransactionOptions,
    mut f: F,
) -> Result<T>
where
    F: FnMut(Transaction) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    exec.check_open()?;
    let deadline = Instant::now() + o.max_retry_time.unwrap_or(Duration::from_secs(120));
    let mut attempt = 0u32;
    loop {
        let retryable = match attempt_once(exec, default_db, &o, &mut f, deadline).await {
            Attempt::Done(r) => return r,
            Attempt::Retry(e) => e,
        };
        if Instant::now() >= deadline {
            return Err(retryable);
        }
        attempt += 1;
        tokio::time::sleep(clamp(backoff_delay(attempt), deadline)).await;
    }
}

enum Attempt<T> {
    Done(Result<T>),
    Retry(Error),
}

async fn attempt_once<T, F, Fut>(
    exec: &Arc<Executor>,
    default_db: &str,
    options: &TransactionOptions,
    callback: &mut F,
    deadline: Instant,
) -> Attempt<T>
where
    F: FnMut(Transaction) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let tx = match Transaction::begin(exec, default_db.to_owned(), options).await {
        Ok(t) => t,
        Err(e) => return Attempt::Done(Err(e)),
    };
    let result = callback(tx.clone()).await;
    let out = match result {
        Err(e) => {
            tx.rollback_best_effort().await;
            if e.is_retryable()
                && e.class() != Some(ErrorClass::CommitOutcomeUnknown)
                && Instant::now() < deadline
            {
                Attempt::Retry(e)
            } else {
                Attempt::Done(Err(e))
            }
        }
        Ok(v) => match tx.commit().await {
            Ok(()) => Attempt::Done(Ok(v)),
            Err(e) if e.class() == Some(ErrorClass::CommitOutcomeUnknown) => {
                match resolve(&tx, e, deadline).await {
                    Ok(true) => Attempt::Done(Ok(v)),
                    Ok(false) => {
                        let mut a = Error::coded(
                            codes::TRANSACTION_ABORTED,
                            true,
                            "the commit outcome was unknown and the transaction status reports it aborted",
                        );
                        if let Some(r) = a.rustegon_mut() {
                            r.committed = Some(false);
                        }
                        Attempt::Retry(a)
                    }
                    Err(e) => Attempt::Done(Err(e)),
                }
            }
            Err(e) => {
                tx.rollback_best_effort().await;
                if e.is_retryable() && Instant::now() < deadline {
                    Attempt::Retry(e)
                } else {
                    Attempt::Done(Err(e))
                }
            }
        },
    };
    let _ = tx.close().await;
    out
}

/// Polls `Status` until committed/aborted or the deadline (then the original RGN-2006).
async fn resolve(tx: &Transaction, unknown: Error, deadline: Instant) -> Result<bool> {
    let mut attempt = 0u32;
    loop {
        match tx.resolve().await {
            Ok(TransactionOutcome::Committed) => return Ok(true),
            Ok(TransactionOutcome::Aborted) => return Ok(false),
            // Unknown or a failed status call: keep polling (never re-run while unknown).
            Ok(TransactionOutcome::Unknown) | Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err(unknown);
        }
        attempt += 1;
        tokio::time::sleep(clamp(backoff_delay(attempt), deadline)).await;
    }
}

fn clamp(d: Duration, deadline: Instant) -> Duration {
    d.min(deadline.saturating_duration_since(Instant::now()))
}
