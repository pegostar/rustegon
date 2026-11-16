// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Query deadlines and cancellation through the embedded API (TC-QL-008, single-node part of
//! AC-QL-008; FR-QL-008, query-language.md §5.3).
//!
//! The store runs on a [`TestClock`] whose every reading advances simulated time by a fixed
//! tick, so "work" is measured in clock readings and the bounds of AC-QL-008 are checked in
//! simulated time, deterministically. The store reads the clock about once per storage
//! operation (a document fetch: 1 reading, a document write: 3) and once per interrupt check;
//! the cost model is [`TICK`] = 250 µs per reading — pessimistic (an unoptimized build fetches
//! a document in a few µs) — with operator batches of [`BATCH`] rows:
//! - a statement over `OPTIONS (max_time_ms = n)` fails with `RGN-5006` no later than
//!   deadline + 50 ms (reads, sorts, index scans, writes — whose effects are rolled back);
//! - a cancellation (`KILL QUERY`, armed to fire mid-execution) stops the statement with
//!   `RGN-5005` within 200 ms of the kill;
//! - a cursor's deadline covers all its batches, and a cancelled cursor is closed.
//!
//! Cancelling fragments on other nodes needs the distributed executor (M4+).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use common::{DB, TestClock, load_generated, open_on, q, rows_of};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_engine::embedded::{CursorOptions, EmbeddedDb};
use rustegon_query::{CursorLimits, ExecOptions, Interrupt, Params};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::Clock;

/// Documents of the test collection.
const DOCS: u64 = 2_000;
/// Operator batch rows: `DOCS / BATCH` interrupt checks per pass over the collection.
const BATCH: usize = 50;
/// Simulated time per clock reading while measuring (module docs).
const TICK: Duration = Duration::from_micros(250);
/// AC-QL-008 bounds.
const DEADLINE_SLACK: Duration = Duration::from_millis(50);
const CANCEL_SLACK: Duration = Duration::from_millis(200);

/// A store on `clock` with `t` = `DOCS` documents `{_id, g: i % 10, n: DOCS - i}` and an
/// index on `g`, loaded with a fine tick (loading is not measured).
fn store(clock: &Arc<TestClock>) -> EmbeddedDb {
    clock.set_tick(Duration::from_micros(1));
    let db = open_on(
        Arc::new(SimFileSystem::new()),
        Arc::clone(clock) as Arc<dyn Clock>,
        8,
        true,
    );
    q(&db, "CREATE INDEX by_g ON t (g)");
    load_generated(&db, "t", DOCS, 500, |i| {
        let mut d = Document::new();
        d.insert("g", Value::Int64(i64::try_from(i % 10).unwrap()));
        d.insert("n", Value::Int64(i64::try_from(DOCS - i).unwrap()));
        d
    });
    clock.set_tick(TICK);
    db
}

fn exec(interrupt: Interrupt) -> ExecOptions {
    ExecOptions {
        batch_rows: BATCH,
        interrupt,
        ..ExecOptions::default()
    }
}

/// Runs `text`; returns its outcome and the simulated time it took.
fn timed(
    db: &EmbeddedDb,
    clock: &TestClock,
    text: &str,
    opts: &ExecOptions,
) -> (Result<u64, Error>, Duration) {
    let start = clock.peek();
    let r = db
        .query_with(DB, text, &Params::new(), opts)
        .map(|r| u64::try_from(r.rows.len()).unwrap() + r.affected());
    (r, clock.peek().saturating_sub(start))
}

/// The statements of the deadline / cancellation tests: each reads the whole collection in
/// `DOCS / BATCH` batches (collection scan, index scan, blocking sort, write).
const STATEMENTS: [&str; 4] = [
    "FROM t SELECT _id",
    "FROM t WHERE g >= 0 SELECT _id OPTIONS (index = 'by_g')",
    "FROM t SELECT _id ORDER BY n",
    "UPDATE t SET touched = true WHERE n > 0",
];

#[test]
fn tc_ql_008_deadline_exceeded_within_slack() {
    let clock = TestClock::new(TICK);
    let db = store(&clock);
    for text in STATEMENTS {
        // The UPDATE reads its rows first (~15 ms here): a later deadline interrupts the
        // writes themselves.
        let max_ms = if text.starts_with("UPDATE") { 100 } else { 2 };
        // Without a deadline the statement takes well over `max_ms` of simulated time.
        let (full, full_time) = timed(&db, &clock, text, &exec(Interrupt::none()));
        full.unwrap_or_else(|e| panic!("{text}: {e}"));
        assert!(
            full_time > Duration::from_millis(4 * max_ms),
            "{text}: the statement is too short to be interrupted ({full_time:?})"
        );
        if text.starts_with("UPDATE") {
            q(&db, "UPDATE t SET touched = false WHERE n > 0");
        }

        let with_deadline = format!("{text} OPTIONS (max_time_ms = {max_ms})");
        let with_deadline = if text.contains("OPTIONS") {
            // One OPTIONS clause per statement.
            text.replace("OPTIONS (", &format!("OPTIONS (max_time_ms = {max_ms}, "))
        } else {
            with_deadline
        };
        let (r, took) = timed(&db, &clock, &with_deadline, &exec(Interrupt::none()));
        let e = r.expect_err(&with_deadline);
        assert_eq!(
            e.code(),
            ErrorCode::DeadlineExceeded,
            "{with_deadline}: {e}"
        );
        // The deadline is set after binding, so it is at least `max_ms` after `start`: the
        // overshoot is at most `took - max_ms`.
        let overshoot = took.saturating_sub(Duration::from_millis(max_ms));
        println!("TC-QL-008 deadline: {with_deadline}: failed after {took:?}");
        assert!(
            overshoot <= DEADLINE_SLACK,
            "{with_deadline}: {overshoot:?} after the deadline"
        );
    }
    // The interrupted UPDATE wrote nothing (statement savepoint).
    assert_eq!(
        rows_of(&db, "FROM t WHERE touched = true SELECT VALUE _id LIMIT 1"),
        ""
    );
    // The caller's deadline (gateway `maxTimeMs`) behaves like the option.
    let clock_dyn = Arc::clone(&clock) as Arc<dyn Clock>;
    let max_ms = 2;
    let at = clock.peek() + Duration::from_millis(max_ms);
    let (r, took) = timed(
        &db,
        &clock,
        STATEMENTS[0],
        &exec(Interrupt::none().with_deadline(clock_dyn, at)),
    );
    assert_eq!(r.unwrap_err().code(), ErrorCode::DeadlineExceeded);
    assert!(took.saturating_sub(Duration::from_millis(max_ms)) <= DEADLINE_SLACK);
}

#[test]
fn tc_ql_008_cancel_stops_a_running_statement() {
    let clock = TestClock::new(TICK);
    let db = store(&clock);
    for text in STATEMENTS {
        // Readings of a complete run, to fire the kill a third of the way through.
        let before = clock.readings();
        timed(&db, &clock, text, &exec(Interrupt::none()))
            .0
            .unwrap_or_else(|e| panic!("{text}: {e}"));
        let readings = clock.readings() - before;
        assert!(readings >= 30, "{text}: {readings} readings");
        if text.starts_with("UPDATE") {
            q(&db, "UPDATE t SET touched = false WHERE n > 0");
        }

        clock.arm_kill_after(readings / 3);
        let opts = exec(Interrupt::none().with_cancel(Arc::clone(&clock.flag)));
        let (r, _) = timed(&db, &clock, text, &opts);
        let e = r.expect_err(text);
        assert_eq!(e.code(), ErrorCode::Cancelled, "{text}: {e}");
        let killed = clock.killed_at().expect("the kill fired");
        let after_kill = clock.peek().saturating_sub(killed);
        println!("TC-QL-008 cancel: {text}: stopped {after_kill:?} after the kill");
        assert!(after_kill <= CANCEL_SLACK, "{text}: {after_kill:?}");
        clock.flag.store(false, Ordering::SeqCst);
    }
    assert_eq!(
        rows_of(&db, "FROM t WHERE touched = true SELECT VALUE _id LIMIT 1"),
        ""
    );
    // The store stays usable after the cancellations.
    assert_eq!(rows_of(&db, "FROM t WHERE _id = 7 SELECT VALUE g"), "7");
}

fn cursor_options(interrupt: Interrupt) -> CursorOptions {
    CursorOptions {
        limits: CursorLimits {
            batch_rows: 100,
            ..CursorLimits::default()
        },
        exec: exec(interrupt),
        ..CursorOptions::default()
    }
}

#[test]
fn tc_ql_008_cursor_deadline_covers_all_batches() {
    let clock = TestClock::new(TICK);
    let db = store(&clock);
    let text = "FROM t SELECT VALUE _id ORDER BY _id OPTIONS (max_time_ms = 1000)";
    let mut c = db
        .open_cursor(DB, text, &Params::new(), &cursor_options(Interrupt::none()))
        .unwrap();
    let first = c.next_batch().unwrap();
    assert_eq!(first.rows.len(), 100);
    assert!(!first.exhausted);
    // The client is idle past the deadline: the next getMore fails.
    clock.advance(Duration::from_secs(2));
    let e = c.next_batch().unwrap_err();
    assert_eq!(e.code(), ErrorCode::DeadlineExceeded, "{e}");
    // The cursor is closed; resuming needs the last continuation token.
    let after = c.next_batch().unwrap();
    assert!(after.exhausted && after.rows.is_empty());
    let mut resumed = cursor_options(Interrupt::none());
    resumed.resume_token = first.continuation_token;
    let mut c = db.open_cursor(DB, text, &Params::new(), &resumed).unwrap();
    let rest = c.collect_rows().unwrap();
    assert_eq!(rest.len(), usize::try_from(DOCS).unwrap() - 100);
    assert_eq!(rest[0], Value::Int64(100));
}

#[test]
fn tc_ql_008_cancel_a_cursor() {
    let clock = TestClock::new(TICK);
    let db = store(&clock);
    let flag = Arc::clone(&clock.flag);
    flag.store(false, Ordering::SeqCst);
    let mut c = db
        .open_cursor(
            DB,
            "FROM t WHERE g = 3 SELECT VALUE _id",
            &Params::new(),
            &cursor_options(Interrupt::none().with_cancel(Arc::clone(&flag))),
        )
        .unwrap();
    assert_eq!(c.next_batch().unwrap().rows.len(), 100);
    // `KILL QUERY` between two getMore calls.
    flag.store(true, Ordering::SeqCst);
    let e = c.next_batch().unwrap_err();
    assert_eq!(e.code(), ErrorCode::Cancelled, "{e}");
    let after = c.next_batch().unwrap();
    assert!(after.exhausted && after.rows.is_empty());
    drop(c);

    // A kill arriving while a batch is being produced (a blocking sort reading the whole
    // collection) stops it within the slack.
    let text = "FROM t SELECT VALUE _id ORDER BY n";
    let before = clock.readings();
    let mut c = db
        .open_cursor(DB, text, &Params::new(), &cursor_options(Interrupt::none()))
        .unwrap();
    c.next_batch().unwrap();
    let readings = clock.readings() - before;
    drop(c);
    clock.arm_kill_after(readings / 2);
    let mut c = db
        .open_cursor(
            DB,
            text,
            &Params::new(),
            &cursor_options(Interrupt::none().with_cancel(Arc::clone(&flag))),
        )
        .unwrap();
    let e = c.next_batch().unwrap_err();
    assert_eq!(e.code(), ErrorCode::Cancelled, "{e}");
    let killed = clock.killed_at().expect("the kill fired");
    assert!(clock.peek().saturating_sub(killed) <= CANCEL_SLACK);
}
