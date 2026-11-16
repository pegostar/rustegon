// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Interactive transactions and owned cursors of the engine, as the server drives them over
//! several RPCs (M4 wave 2a lane F; PD-049; transactions.md §1 "Interactive", §3, §4;
//! transaction-management.md §9, §10; FR-TXN-001/002/003/005/006/007/009, FR-QL-006,
//! FR-QL-008):
//! - multi-call commit / rollback / drop and visibility to other sessions (TC-TXN-001 part);
//! - isolation against concurrent writers: a conflict surfaces as a retryable catalog error,
//!   the transaction aborts as a whole, nothing is committed partially (TC-TXN-003, TC-TXN-011
//!   part: the client, not the engine, retries);
//! - statement-level errors versus errors that abort the transaction; savepoints (TC-TXN-007);
//! - maximum duration, idle abort and heartbeats (TC-TXN-008);
//! - owned cursors across calls and threads, standalone and inside a transaction (TC-QL-007
//!   part); remote cancel of transactions and cursors (TC-QL-008 part);
//! - the handles are `Send` (+ `Sync` for the transaction), checked at compile time.
//!
//! Time-dependent tests run on [`TestClock`] (manual time), so they are deterministic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use common::{DB, TestClock, load_generated, open, open_on, rows_of, val};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_engine::{
    AccessMode, CancelHandle, CursorOptions, EmbeddedDb, Isolation, OwnedCursor, Transaction,
    TransactionStatus, TxnOptions, format_txn_id, parse_txn_id,
};
use rustegon_query::{CursorLimits, ExecOptions, Params};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{BoxFuture, Clock};

// Compile-time: the server keeps these in registries and drives them from blocking tasks.
const _: () = {
    const fn send_static<T: Send + 'static>() {}
    const fn sync<T: Sync>() {}
    send_static::<Transaction>();
    sync::<Transaction>();
    send_static::<OwnedCursor>();
    send_static::<CancelHandle>();
    sync::<CancelHandle>();
    send_static::<Arc<EmbeddedDb>>();
};

fn doc(json: &str) -> Document {
    match val(json) {
        Value::Object(d) => d,
        other => panic!("not a document: {other:?}"),
    }
}

fn int(i: i64) -> Value {
    Value::Int64(i)
}

fn store() -> Arc<EmbeddedDb> {
    Arc::new(open(7))
}

/// A store on a manual clock (1 µs per reading; idle time with [`TestClock::advance`]).
fn store_on_clock() -> (Arc<EmbeddedDb>, Arc<TestClock>) {
    let clock = TestClock::new(Duration::from_micros(1));
    let db = open_on(
        Arc::new(SimFileSystem::new()),
        Arc::clone(&clock) as Arc<dyn Clock>,
        11,
        true,
    );
    (Arc::new(db), clock)
}

fn reason(e: &Error) -> Option<&str> {
    e.details().get("reason").map(String::as_str)
}

/// `n` of the document `id` in `t`, read outside any interactive transaction.
fn n_of(db: &EmbeddedDb, id: i64) -> Option<Value> {
    db.get(DB, "t", &int(id))
        .unwrap()
        .and_then(|d| d.get("n").cloned())
}

/// A read-only transaction: begun before another transaction's writes, it reads below their
/// intents and never waits for them (a later reader of an uncommitted key waits for the
/// writer, transaction-management.md §5.1).
fn reader(db: &Arc<EmbeddedDb>) -> Transaction {
    db.begin(&TxnOptions {
        access: AccessMode::ReadOnly,
        ..TxnOptions::default()
    })
}

/// An error of a transaction that is no longer active: `RGN-2002` with `reason`.
fn assert_aborted(e: &Error, why: &str, retryable: bool) {
    assert_eq!(e.code(), ErrorCode::TransactionAborted, "{e}");
    assert_eq!(reason(e), Some(why), "{e}");
    assert_eq!(e.retryable(), retryable, "{e}");
}

#[test]
fn tc_txn_001_interactive_multi_call_commit_visibility() {
    let db = store();
    db.insert(DB, "t", &doc(r#"{"_id": 1, "n": 1}"#)).unwrap();
    // A concurrent session (begun before the writes, so it never waits for their intents).
    let other = reader(&db);
    let txn = db.begin(&TxnOptions::default());
    assert_eq!(parse_txn_id(&format_txn_id(&txn.id())).unwrap(), txn.id());
    // Several calls, mixing document operations and statements.
    txn.insert(DB, "t", &doc(r#"{"_id": 2, "n": 2}"#)).unwrap();
    txn.query(DB, "UPDATE t SET n = n + 10 WHERE _id = 1", &Params::new())
        .unwrap();
    txn.replace(DB, "t", &int(2), &doc(r#"{"n": 20}"#)).unwrap();
    // The transaction reads its own writes; nobody else sees them before the commit.
    assert_eq!(
        txn.get(DB, "t", &int(1)).unwrap().unwrap().get("n"),
        Some(&int(11))
    );
    let own = txn
        .query(DB, "FROM t SELECT VALUE n ORDER BY _id", &Params::new())
        .unwrap();
    assert_eq!(own.rows, [int(11), int(20)]);
    assert_eq!(
        other.get(DB, "t", &int(1)).unwrap().unwrap().get("n"),
        Some(&int(1))
    );
    assert_eq!(other.get(DB, "t", &int(2)).unwrap(), None);
    assert_eq!(txn.status(), TransactionStatus::Active);
    let info = txn.commit().unwrap();
    assert_eq!(
        txn.status(),
        TransactionStatus::Committed {
            commit_ts: info.commit_ts
        }
    );
    // Commit is idempotent (FR-TXN-006); other operations are refused.
    assert_eq!(txn.commit().unwrap().commit_ts, info.commit_ts);
    assert_eq!(
        txn.get(DB, "t", &int(1)).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        txn.rollback().unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(n_of(&db, 1), Some(int(11)));
    assert_eq!(n_of(&db, 2), Some(int(20)));
}

#[test]
fn tc_txn_001_interactive_rollback_and_drop_discard_everything() {
    let db = store();
    db.insert(DB, "t", &doc(r#"{"_id": 1, "n": 1}"#)).unwrap();
    let txn = db.begin(&TxnOptions::default());
    txn.insert(DB, "t", &doc(r#"{"_id": 2, "n": 2}"#)).unwrap();
    txn.delete(DB, "t", &int(1)).unwrap();
    txn.rollback().unwrap();
    txn.rollback().unwrap(); // idempotent
    assert_eq!(
        txn.status(),
        TransactionStatus::Aborted { reason: "rollback" }
    );
    assert_aborted(&txn.commit().unwrap_err(), "rollback", false);
    assert_aborted(
        &txn.insert(DB, "t", &doc(r#"{"_id": 3}"#)).unwrap_err(),
        "rollback",
        false,
    );
    assert_eq!(n_of(&db, 1), Some(int(1)));
    assert_eq!(n_of(&db, 2), None);

    // Drop = rollback: the intents are gone at once, so a writer of the same document does
    // not wait for the liveness timeout.
    let txn = db.begin(&TxnOptions::default());
    txn.replace(DB, "t", &int(1), &doc(r#"{"n": 99}"#)).unwrap();
    drop(txn);
    db.replace(DB, "t", &int(1), &doc(r#"{"n": 5}"#)).unwrap();
    assert_eq!(n_of(&db, 1), Some(int(5)));
}

#[test]
fn tc_txn_003_interactive_snapshot_is_stable_against_concurrent_writers() {
    for isolation in [Isolation::Serializable, Isolation::Snapshot] {
        let db = store();
        db.insert(DB, "t", &doc(r#"{"_id": 1, "n": 1}"#)).unwrap();
        let txn = db.begin(&TxnOptions::with_isolation(isolation));
        assert_eq!(
            txn.get(DB, "t", &int(1)).unwrap().unwrap().get("n"),
            Some(&int(1))
        );
        db.replace(DB, "t", &int(1), &doc(r#"{"n": 2}"#)).unwrap();
        // Repeatable read inside the transaction (FR-TXN-002).
        assert_eq!(
            rows_of_txn(&txn, "FROM t SELECT VALUE n"),
            "1",
            "{isolation:?}"
        );
        txn.commit().unwrap();
    }
}

fn rows_of_txn(txn: &Transaction, text: &str) -> String {
    txn.query(DB, text, &Params::new())
        .unwrap()
        .rows
        .iter()
        .map(common::js)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn tc_txn_011_interactive_conflict_is_retryable_and_commits_nothing() {
    let db = store();
    db.insert(DB, "t", &doc(r#"{"_id": 1, "n": 0}"#)).unwrap();
    // Two clients read the same counter and both try to increment it (lost update).
    let a = db.begin(&TxnOptions::default());
    let b = db.begin(&TxnOptions::default());
    a.get(DB, "t", &int(1)).unwrap();
    b.get(DB, "t", &int(1)).unwrap();
    b.insert(DB, "t", &doc(r#"{"_id": 2, "n": 2}"#)).unwrap();
    a.replace(DB, "t", &int(1), &doc(r#"{"n": 1}"#)).unwrap();
    a.commit().unwrap();
    // `b` must not commit: its read of document 1 is stale. The engine does not re-run
    // anything; the conflict reaches the client as a retryable error.
    let first = b
        .replace(DB, "t", &int(1), &doc(r#"{"n": 1}"#))
        .and_then(|_| b.commit().map(|_| ()))
        .unwrap_err();
    assert!(first.retryable(), "{first}");
    assert!(
        matches!(
            first.code(),
            ErrorCode::TransactionConflict | ErrorCode::TransactionAborted
        ),
        "{first}"
    );
    // The transaction is aborted as a whole; later calls say so, retryable.
    assert!(b.status().is_retryable_abort(), "{:?}", b.status());
    assert_aborted(&b.commit().unwrap_err(), "conflict", true);
    // Nothing of `b` was committed, `a`'s increment stands.
    assert_eq!(n_of(&db, 1), Some(int(1)));
    assert_eq!(n_of(&db, 2), None);
    // The client's retry (a new transaction) succeeds.
    let retry = db.begin(&TxnOptions::default());
    retry
        .query(DB, "UPDATE t SET n = n + 1 WHERE _id = 1", &Params::new())
        .unwrap();
    retry.commit().unwrap();
    assert_eq!(n_of(&db, 1), Some(int(2)));
}

#[test]
fn tc_txn_001_interactive_statement_errors_keep_the_transaction() {
    let db = store();
    q_ok(&db, "CREATE UNIQUE INDEX by_k ON t (k)");
    let txn = db.begin(&TxnOptions::default());
    txn.insert(DB, "t", &doc(r#"{"_id": 1, "k": 1}"#)).unwrap();
    // Duplicate `_id`, unique index violation inside a multi-row statement, syntax error,
    // DDL, BEGIN/COMMIT statements, a missing document: statement errors only.
    let errors = [
        txn.insert(DB, "t", &doc(r#"{"_id": 1}"#)).unwrap_err(),
        txn.query(
            DB,
            "INSERT INTO t VALUES {_id: 2, k: 2}, {_id: 3, k: 1}",
            &Params::new(),
        )
        .unwrap_err(),
        txn.query(DB, "FROM t SELEC", &Params::new()).unwrap_err(),
        txn.query(DB, "CREATE INDEX by_x ON t (x)", &Params::new())
            .unwrap_err(),
        txn.query(DB, "COMMIT", &Params::new()).unwrap_err(),
        txn.replace(DB, "t", &int(42), &doc("{}")).unwrap_err(),
    ];
    let codes: Vec<_> = errors.iter().map(Error::code).collect();
    assert_eq!(
        codes,
        [
            ErrorCode::DuplicateKey,
            ErrorCode::DuplicateKey,
            ErrorCode::QuerySyntaxError,
            ErrorCode::InvalidArgument,
            ErrorCode::InvalidArgument,
            ErrorCode::NotFound,
        ]
    );
    assert_eq!(txn.status(), TransactionStatus::Active);
    // The failed multi-row INSERT left nothing (document 2 was rolled back with it).
    assert_eq!(
        rows_of_txn(&txn, "FROM t SELECT VALUE _id ORDER BY _id"),
        "1"
    );
    txn.commit().unwrap();
    assert_eq!(rows_of(&db, "FROM t SELECT VALUE _id ORDER BY _id"), "1");

    // A write in a read-only transaction is the statement's error.
    let ro = db.begin(&TxnOptions {
        access: AccessMode::ReadOnly,
        ..TxnOptions::default()
    });
    let e = ro.insert(DB, "t", &doc(r#"{"_id": 5}"#)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument, "{e}");
    assert_eq!(
        ro.get(DB, "t", &int(1)).unwrap().unwrap().get("k"),
        Some(&int(1))
    );
    ro.commit().unwrap();
}

fn q_ok(db: &EmbeddedDb, text: &str) {
    db.query(DB, text, &Params::new())
        .unwrap_or_else(|e| panic!("{text}: {e}"));
}

#[test]
fn tc_txn_007_interactive_savepoints() {
    let db = store();
    let txn = db.begin(&TxnOptions::default());
    let run = |text: &str| txn.query(DB, text, &Params::new());
    run("INSERT INTO t VALUE {_id: 1}").unwrap();
    run("SAVEPOINT a").unwrap();
    run("INSERT INTO t VALUE {_id: 2}").unwrap();
    run("SAVEPOINT b").unwrap();
    run("INSERT INTO t VALUE {_id: 3}").unwrap();
    run("ROLLBACK TO SAVEPOINT a").unwrap();
    assert_eq!(
        rows_of_txn(&txn, "FROM t SELECT VALUE _id ORDER BY _id"),
        "1"
    );
    // `b` went with the rollback to `a`; an unknown savepoint is a statement error.
    let e = run("ROLLBACK TO SAVEPOINT b").unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument, "{e}");
    run("INSERT INTO t VALUE {_id: 4}").unwrap();
    run("RELEASE SAVEPOINT a").unwrap();
    assert_eq!(
        run("ROLLBACK TO SAVEPOINT a").unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    txn.commit().unwrap();
    assert_eq!(rows_of(&db, "FROM t SELECT VALUE _id ORDER BY _id"), "1 4");
}

#[test]
fn tc_txn_008_interactive_max_duration() {
    let (db, clock) = store_on_clock();
    db.insert(DB, "t", &doc(r#"{"_id": 1, "n": 1}"#)).unwrap();
    let txn = db.begin(&TxnOptions {
        timeout: Some(Duration::from_secs(2)),
        ..TxnOptions::default()
    });
    txn.replace(DB, "t", &int(1), &doc(r#"{"n": 2}"#)).unwrap();
    // Heartbeats keep it from idling out but cannot extend its maximum duration.
    for _ in 0..2 {
        clock.advance(Duration::from_millis(900));
        let left = txn.heartbeat().unwrap();
        assert!(left <= Duration::from_millis(1200), "{left:?}");
    }
    clock.advance(Duration::from_millis(500));
    let e = txn.get(DB, "t", &int(1)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::TransactionTimeout, "{e}");
    assert!(!e.retryable());
    assert_eq!(
        txn.status(),
        TransactionStatus::Aborted {
            reason: "max_duration"
        }
    );
    assert_aborted(&txn.commit().unwrap_err(), "max_duration", false);
    assert_eq!(n_of(&db, 1), Some(int(1)));
}

#[test]
fn tc_txn_008_interactive_idle_abort_and_heartbeat() {
    let (db, clock) = store_on_clock();
    // Heartbeats (or statements) keep a slow client's transaction alive past 5 s.
    let slow = db.begin(&TxnOptions::default());
    slow.insert(DB, "t", &doc(r#"{"_id": 1, "n": 1}"#)).unwrap();
    for _ in 0..3 {
        clock.advance(Duration::from_secs(3));
        let left = slow.heartbeat().unwrap();
        assert!(
            left > Duration::from_millis(4900) && left <= Duration::from_secs(5),
            "{left:?}"
        );
    }
    slow.commit().unwrap();
    assert_eq!(n_of(&db, 1), Some(int(1)));

    // An idle client loses its transaction: `Status` reports it (and cleans it up) before the
    // client comes back; its next call fails retryably.
    let idle = db.begin(&TxnOptions::default());
    idle.replace(DB, "t", &int(1), &doc(r#"{"n": 2}"#)).unwrap();
    clock.advance(Duration::from_secs(6));
    assert_eq!(
        idle.status(),
        TransactionStatus::Aborted {
            reason: "timeout_pushed"
        }
    );
    assert_aborted(&idle.heartbeat().unwrap_err(), "timeout_pushed", true);
    // Its intent is gone: the next writer does not wait.
    db.replace(DB, "t", &int(1), &doc(r#"{"n": 3}"#)).unwrap();
    assert_eq!(n_of(&db, 1), Some(int(3)));

    // Without `Status`, the first call after the expiry reports it.
    let idle = db.begin(&TxnOptions::default());
    idle.get(DB, "t", &int(1)).unwrap();
    clock.advance(Duration::from_secs(6));
    assert_aborted(
        &idle.get(DB, "t", &int(1)).unwrap_err(),
        "timeout_pushed",
        true,
    );

    // A read-only transaction holds no locks: it is bounded by its maximum duration only
    // (PD-049), and its heartbeat says so.
    let ro = db.begin(&TxnOptions {
        access: AccessMode::ReadOnly,
        ..TxnOptions::default()
    });
    ro.get(DB, "t", &int(1)).unwrap();
    clock.advance(Duration::from_secs(20));
    assert_eq!(
        ro.get(DB, "t", &int(1)).unwrap().unwrap().get("n"),
        Some(&int(3))
    );
    let left = ro.heartbeat().unwrap();
    assert!(
        left > Duration::from_secs(39) && left <= Duration::from_secs(40),
        "{left:?}"
    );
    ro.commit().unwrap();
}

#[test]
fn tc_txn_001_interactive_transaction_is_driven_from_many_threads() {
    let db = store();
    q_ok(&db, "CREATE COLLECTION t");
    let other = reader(&db);
    let txn = Arc::new(db.begin(&TxnOptions::default()));
    let workers: Vec<_> = (0..4)
        .map(|w| {
            let txn = Arc::clone(&txn);
            thread::spawn(move || {
                for i in 0..25 {
                    let id = w * 100 + i;
                    txn.insert(DB, "t", &doc(&format!(r#"{{"_id": {id}}}"#)))
                        .unwrap();
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    assert_eq!(count(&rows_of_txn(&other, IDS)), 0);
    txn.commit().unwrap();
    assert_eq!(count(&rows_of(&db, IDS)), 100);
}

/// Every `_id` of `t`.
const IDS: &str = "FROM t SELECT VALUE _id";

/// Rows of a space-joined rendering.
fn count(rows: &str) -> usize {
    rows.split_whitespace().count()
}

fn cursor_options(batch_rows: usize) -> CursorOptions {
    CursorOptions {
        limits: CursorLimits {
            batch_rows,
            ..CursorLimits::default()
        },
        ..CursorOptions::default()
    }
}

fn load(db: &EmbeddedDb, n: u64) {
    load_generated(db, "t", n, 500, |i| {
        let mut d = Document::new();
        d.insert("n", Value::Int64(i64::try_from(i).unwrap()));
        d
    });
}

#[test]
fn tc_ql_007_owned_cursor_across_calls_and_threads() {
    let (db, clock) = store_on_clock();
    load(&db, 250);
    let mut cursor = db
        .open_owned_cursor(
            DB,
            "FROM t SELECT VALUE _id ORDER BY _id",
            &Params::new(),
            &cursor_options(100),
        )
        .unwrap();
    let first = cursor.next_batch().unwrap();
    assert_eq!(first.rows.len(), 100);
    // A write after the open is not seen: one snapshot for all batches.
    db.delete(DB, "t", &int(150)).unwrap();
    // The client pauses longer than the liveness timeout between two GetMore calls: the
    // cursor's read-only transaction survives (PD-049).
    clock.advance(Duration::from_secs(6));
    // The next GetMore runs on another thread (the server's blocking pool).
    let (mut cursor, second) = thread::spawn(move || {
        let b = cursor.next_batch().unwrap();
        (cursor, b)
    })
    .join()
    .unwrap();
    assert_eq!(second.rows.first(), Some(&int(100)));
    assert!(second.rows.contains(&int(150)));
    let rest = cursor.next_batch().unwrap();
    assert_eq!(rest.rows.len(), 50);
    assert!(rest.exhausted && cursor.is_closed());
    assert_eq!(cursor.returned(), 250);

    // Close (KillCursor) of a half-read cursor.
    let mut c = db
        .open_owned_cursor(
            DB,
            "FROM t SELECT VALUE _id",
            &Params::new(),
            &cursor_options(10),
        )
        .unwrap();
    c.next_batch().unwrap();
    c.close().unwrap();
}

#[test]
fn tc_ql_007_owned_cursor_inside_a_transaction() {
    let db = store();
    load(&db, 50);
    let other = reader(&db);
    let txn = db.begin(&TxnOptions::default());
    txn.query(DB, "DELETE FROM t WHERE n < 10", &Params::new())
        .unwrap();
    txn.insert(DB, "t", &doc(r#"{"_id": 1000, "n": 1000}"#))
        .unwrap();
    let text = "FROM t SELECT VALUE _id ORDER BY _id";
    let mut cursor = txn
        .open_cursor(DB, text, &Params::new(), &cursor_options(20))
        .unwrap();
    // The cursor reads through the transaction: its writes are visible, across threads.
    let (mut cursor, first) = thread::spawn(move || {
        let b = cursor.next_batch().unwrap();
        (cursor, b)
    })
    .join()
    .unwrap();
    assert_eq!(first.rows.first(), Some(&int(10)));
    // Other statements of the transaction run between two batches.
    assert_eq!(count(&rows_of_txn(&txn, IDS)), 41);
    let mut rest = cursor.collect_rows().unwrap();
    assert_eq!(rest.pop(), Some(int(1000)));
    assert_eq!(first.rows.len() + rest.len(), 40);
    // Outside the transaction nothing changed yet.
    assert_eq!(count(&rows_of_txn(&other, IDS)), 50);

    // A cursor ends with its transaction: commit closes it, rollback aborts it.
    let mut open = txn
        .open_cursor(DB, text, &Params::new(), &cursor_options(5))
        .unwrap();
    open.next_batch().unwrap();
    txn.commit().unwrap();
    let e = open.next_batch().unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument, "{e}");
    assert!(open.next_batch().unwrap().exhausted);
    assert_eq!(count(&rows_of(&db, IDS)), 41);

    let txn = db.begin(&TxnOptions::default());
    let mut open = txn
        .open_cursor(DB, text, &Params::new(), &cursor_options(5))
        .unwrap();
    drop(txn);
    assert_aborted(&open.next_batch().unwrap_err(), "rollback", false);

    // A read query is required; a bad statement is the statement's error.
    let txn = db.begin(&TxnOptions::default());
    let e = txn
        .open_cursor(DB, "FROM t SELEC", &Params::new(), &cursor_options(5))
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::QuerySyntaxError);
    assert_eq!(txn.status(), TransactionStatus::Active);
}

/// A clock that cancels `target` at its `n`-th reading (a remote cancel arriving while a
/// statement or batch runs), otherwise delegating to `inner`.
struct CancelAt {
    inner: Arc<TestClock>,
    left: AtomicU64,
    target: Mutex<Option<CancelHandle>>,
}

impl CancelAt {
    fn new(inner: &Arc<TestClock>) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::clone(inner),
            left: AtomicU64::new(u64::MAX),
            target: Mutex::new(None),
        })
    }

    fn arm(&self, target: CancelHandle, after: u64) {
        *self.target.lock().unwrap() = Some(target);
        self.left.store(after, Ordering::SeqCst);
    }

    fn fired(&self) -> bool {
        self.target
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(CancelHandle::is_cancelled)
    }
}

impl Clock for CancelAt {
    fn monotonic(&self) -> Duration {
        if self.left.fetch_sub(1, Ordering::SeqCst) == 1
            && let Some(t) = self.target.lock().unwrap().as_ref()
        {
            t.cancel();
        }
        self.inner.monotonic()
    }

    fn wall(&self) -> std::time::SystemTime {
        self.inner.wall()
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        self.inner.sleep(duration)
    }
}

/// Executor options whose interrupt reads `clock` once per operator batch: the statement
/// carries a (far) deadline, so the interrupt check reads the clock.
fn exec_on(clock: &Arc<CancelAt>) -> ExecOptions {
    ExecOptions {
        batch_rows: 50,
        clock: Some(Arc::clone(clock) as Arc<dyn Clock>),
        ..ExecOptions::default()
    }
}

const LONG_SORT: &str = "FROM t SELECT VALUE _id ORDER BY n DESC OPTIONS (max_time_ms = 100000000)";

#[test]
fn tc_ql_008_remote_cancel_of_a_running_statement_kills_the_transaction() {
    let (db, clock) = store_on_clock();
    load(&db, 2_000);
    let txn = db.begin(&TxnOptions::default());
    txn.insert(DB, "t", &doc(r#"{"_id": 5000, "n": 0}"#))
        .unwrap();
    let cancel_clock = CancelAt::new(&clock);
    cancel_clock.arm(txn.cancel_handle(), 10);
    let e = txn
        .query_with(DB, LONG_SORT, &Params::new(), &exec_on(&cancel_clock))
        .unwrap_err();
    assert!(cancel_clock.fired());
    assert_eq!(e.code(), ErrorCode::Cancelled, "{e}");
    assert_eq!(
        txn.status(),
        TransactionStatus::Aborted { reason: "killed" }
    );
    assert_aborted(&txn.commit().unwrap_err(), "killed", false);
    assert_eq!(n_of(&db, 5000), None);

    // A cancel from another thread while the transaction is idle: its next call fails.
    let txn = db.begin(&TxnOptions::default());
    txn.insert(DB, "t", &doc(r#"{"_id": 5001, "n": 0}"#))
        .unwrap();
    let handle = txn.cancel_handle();
    thread::spawn(move || handle.cancel()).join().unwrap();
    assert_aborted(&txn.get(DB, "t", &int(1)).unwrap_err(), "killed", false);
    assert_eq!(n_of(&db, 5001), None);

    // A statement's own interrupt flag cancels just that statement.
    let txn = db.begin(&TxnOptions::default());
    txn.insert(DB, "t", &doc(r#"{"_id": 5002, "n": 0}"#))
        .unwrap();
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let opts = ExecOptions {
        interrupt: rustegon_query::Interrupt::none().with_cancel(flag),
        ..ExecOptions::default()
    };
    let e = txn
        .query_with(DB, "FROM t SELECT VALUE _id", &Params::new(), &opts)
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Cancelled);
    assert_eq!(txn.status(), TransactionStatus::Active);
    txn.commit().unwrap();
    assert_eq!(n_of(&db, 5002), Some(int(0)));
}

#[test]
fn tc_ql_008_remote_cancel_of_cursors() {
    let (db, clock) = store_on_clock();
    load(&db, 2_000);
    // Between two GetMore calls, from another thread.
    let mut c = db
        .open_owned_cursor(
            DB,
            "FROM t SELECT VALUE _id",
            &Params::new(),
            &cursor_options(100),
        )
        .unwrap();
    c.next_batch().unwrap();
    let handle = c.cancel_handle();
    thread::spawn(move || handle.cancel()).join().unwrap();
    assert_eq!(c.next_batch().unwrap_err().code(), ErrorCode::Cancelled);
    assert!(c.is_closed() && c.next_batch().unwrap().exhausted);

    // While a batch is being produced (a blocking sort).
    let cancel_clock = CancelAt::new(&clock);
    let options = CursorOptions {
        exec: exec_on(&cancel_clock),
        ..cursor_options(100)
    };
    let mut c = db
        .open_owned_cursor(DB, LONG_SORT, &Params::new(), &options)
        .unwrap();
    cancel_clock.arm(c.cancel_handle(), 10);
    assert_eq!(c.next_batch().unwrap_err().code(), ErrorCode::Cancelled);
    assert!(cancel_clock.fired());

    // Cancelling a transaction stops its cursors.
    let txn = db.begin(&TxnOptions::default());
    let mut c = txn
        .open_cursor(
            DB,
            "FROM t SELECT VALUE _id",
            &Params::new(),
            &cursor_options(100),
        )
        .unwrap();
    c.next_batch().unwrap();
    txn.cancel_handle().cancel();
    assert_aborted(&c.next_batch().unwrap_err(), "killed", false);
    assert_eq!(
        txn.status(),
        TransactionStatus::Aborted { reason: "killed" }
    );
}
