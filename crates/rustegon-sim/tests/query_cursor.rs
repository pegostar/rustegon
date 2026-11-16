// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Cursors and keyset continuation tokens through the embedded API (TC-QL-007, single-node
//! part of AC-QL-007; FR-QL-006, FR-QL-007): streaming with bounded memory (measured by a
//! counting global allocator), batch limits, snapshot reads across `getMore`, and resume
//! exactness (no duplicates, no gaps) as a property, including across a reopened store.
//! Gateway failover (the rest of AC-QL-007) needs the cluster gateway (M4+).
//!
//! `RGQL_CURSOR_ROWS` sets the rows of the streaming test (default 50 000, which keeps the
//! regular test run short; AC-QL-007 asks for more than 10⁶: run with
//! `RGQL_CURSOR_ROWS=1100000`). `RGQL_CURSOR_CASES` sets the property
//! cases (default 48).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use common::{DB, js, load_generated, open, open_on, q, rows};
use proptest::prelude::*;
use rustegon_common::ErrorCode;
use rustegon_doc::{Document, Value};
use rustegon_engine::embedded::{CursorOptions, EmbeddedDb};
use rustegon_query::{CursorLimits, Params};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::SystemClock;

// ---------------------------------------------------------------------------------------------
// Counting allocator: live bytes and their peak since the last reset (the whole process; each
// nextest test runs in its own process).

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is forwarded to the system allocator with the same arguments; the
// counters do not affect allocation.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as `System.alloc`.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as `System.dealloc`.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: same contract as `System.realloc`.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                let now = LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed)
                    + (new_size - layout.size());
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn reset_peak() -> usize {
    let live = LIVE.load(Ordering::Relaxed);
    PEAK.store(live, Ordering::Relaxed);
    live
}

const MIB: f64 = 1024.0 * 1024.0;

/// Bytes as MiB for the report (precision loss above 2^52 bytes is irrelevant).
#[allow(clippy::cast_precision_loss)]
fn mib(bytes: usize) -> f64 {
    bytes as f64 / MIB
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn opts(rows: usize) -> CursorOptions {
    CursorOptions {
        limits: CursorLimits {
            batch_rows: rows,
            ..CursorLimits::default()
        },
        ..CursorOptions::default()
    }
}

// ---------------------------------------------------------------------------------------------
// Streaming with bounded memory

#[test]
fn tc_ql_007_stream_many_rows_with_bounded_memory() {
    let n = env_usize("RGQL_CURSOR_ROWS", 50_000);
    let db = open(70);
    q(&db, "CREATE INDEX by_g ON big (g)");
    // ~120 B per document.
    let pad = "x".repeat(64);
    // Small chunks keep each load transaction far below the 60 s maximum duration even under
    // emulation (linux/arm64 QEMU took > 60 s for one 20 000-row insert).
    load_generated(&db, "big", n as u64, 2_000, |i| {
        let mut d = Document::new();
        d.insert("g", Value::Int64(i64::try_from(i % 1000).unwrap()));
        d.insert("pad", Value::String(pad.clone()));
        d
    });
    let mut seen = vec![false; n];
    for (label, text) in [
        ("collection scan", "FROM big SELECT _id, g"),
        ("index scan", "FROM big WHERE g >= 0 SELECT _id, g"),
    ] {
        seen.fill(false);
        let baseline = reset_peak();
        let mut cursor = db
            .open_cursor(DB, text, &Params::new(), &opts(1000))
            .unwrap();
        let (mut count, mut batches) = (0usize, 0usize);
        loop {
            let b = cursor.next_batch().unwrap();
            assert!(b.rows.len() <= 1000);
            for r in &b.rows {
                let Value::Object(d) = r else { panic!() };
                let Some(Value::Int64(id)) = d.get("_id") else {
                    panic!()
                };
                let i = usize::try_from(*id).unwrap();
                assert!(!seen[i], "{label}: duplicate {i}");
                seen[i] = true;
            }
            count += b.rows.len();
            batches += 1;
            if b.exhausted {
                break;
            }
        }
        drop(cursor);
        let peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        println!(
            "TC-QL-007 {label}: {count} rows in {batches} batches, peak heap growth {:.1} MiB \
             (baseline {:.1} MiB)",
            mib(peak),
            mib(baseline)
        );
        assert_eq!(count, n, "{label}");
        assert!(seen.iter().all(|s| *s), "{label}: gap");
        // AC-QL-007: < 64 MiB per cursor.
        assert!(peak < 64 << 20, "{label}: peak {peak} B");
    }
}

#[test]
fn tc_ql_007_batch_limits_and_exhaustion() {
    let db = open(71);
    load_generated(&db, "t", 25, 25, |i| {
        let mut d = Document::new();
        d.insert(
            "s",
            Value::String("y".repeat(usize::try_from(i).unwrap() * 10)),
        );
        d
    });
    let mut c = db
        .open_cursor(DB, "FROM t ORDER BY _id", &Params::new(), &opts(10))
        .unwrap();
    let sizes: Vec<(usize, bool, bool)> = (0..4)
        .map(|_| {
            let b = c.next_batch().unwrap();
            (b.rows.len(), b.exhausted, b.continuation_token.is_some())
        })
        .collect();
    // The last non-empty batch knows it is the last; after it, empty exhausted batches.
    assert_eq!(
        sizes,
        [
            (10, false, true),
            (10, false, true),
            (5, true, false),
            (0, true, false)
        ]
    );
    assert_eq!(c.returned(), 25);
    // A byte budget below one row still returns one row per batch.
    let mut c = db
        .open_cursor(
            DB,
            "FROM t WHERE _id >= 20 ORDER BY _id",
            &Params::new(),
            &CursorOptions {
                limits: CursorLimits {
                    batch_rows: 100,
                    batch_bytes: 1,
                },
                ..CursorOptions::default()
            },
        )
        .unwrap();
    let mut n = 0;
    loop {
        let b = c.next_batch().unwrap();
        assert!(b.rows.len() <= 1);
        n += b.rows.len();
        if b.exhausted {
            break;
        }
    }
    assert_eq!(n, 5);
    // Unordered queries stream but have no continuation token.
    let mut c = db
        .open_cursor(DB, "FROM t", &Params::new(), &opts(10))
        .unwrap();
    let b = c.next_batch().unwrap();
    assert_eq!(b.rows.len(), 10);
    assert!(b.continuation_token.is_none());
    c.close().unwrap();
    // Cursors serve reads only.
    for text in [
        "DELETE FROM t WHERE _id = 1",
        "EXPLAIN FROM t",
        "CREATE INDEX i ON t (s)",
    ] {
        let e = db
            .open_cursor(DB, text, &Params::new(), &opts(10))
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument, "{text}");
    }
}

#[test]
fn tc_ql_007_cursor_reads_one_snapshot() {
    let db = open(72);
    load_generated(&db, "t", 30, 30, |_| Document::new());
    let mut c = db
        .open_cursor(
            DB,
            "FROM t SELECT VALUE _id ORDER BY _id",
            &Params::new(),
            &opts(10),
        )
        .unwrap();
    let first = c.next_batch().unwrap();
    // Writes between getMore calls (ahead of and behind the cursor) are not seen by it.
    q(&db, "DELETE FROM t WHERE _id = 25");
    q(&db, "INSERT INTO t VALUE {_id: 100}");
    q(&db, "DELETE FROM t WHERE _id = 3");
    let mut all = first.rows;
    all.extend(c.collect_rows().unwrap());
    let ids: Vec<String> = all.iter().map(js).collect();
    let expected: Vec<String> = (0..30).map(|i| i.to_string()).collect();
    assert_eq!(ids, expected);
}

// ---------------------------------------------------------------------------------------------
// Continuation tokens

/// Every row of `text`, read page by page: each page is a new cursor opened with the previous
/// page's token (stateless paging), `page` rows per page.
fn paged(db: &EmbeddedDb, text: &str, params: &Params, page: usize) -> Vec<Value> {
    let mut out = Vec::new();
    let mut token: Option<Vec<u8>> = None;
    loop {
        let mut o = opts(page);
        o.resume_token = token.take();
        let mut c = db.open_cursor(DB, text, params, &o).unwrap();
        let b = c.next_batch().unwrap();
        c.close().unwrap();
        out.extend(b.rows);
        if let Some(t) = b.continuation_token {
            token = Some(t);
        } else {
            assert!(b.exhausted, "{text}: no token before the end");
            return out;
        }
    }
}

#[derive(Debug, Clone)]
struct Case {
    docs: Vec<(Option<Value>, Option<Value>)>,
    order: Vec<(&'static str, bool)>,
    filter: Option<&'static str>,
    limit: Option<u64>,
    offset: u64,
    page: usize,
    index: bool,
    project: bool,
}

fn small_value() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![
        6 => (0i64..6).prop_map(|i| Some(Value::Int64(i))),
        1 => Just(Some(Value::Null)),
        1 => Just(None),
        1 => "[ab]{0,2}".prop_map(|s| Some(Value::String(s))),
        1 => (0.0f64..3.0).prop_map(|f| Some(Value::Float64((f * 2.0).round() / 2.0))),
    ]
}

fn case() -> impl Strategy<Value = Case> {
    (
        prop::collection::vec((small_value(), small_value()), 0..60),
        prop::collection::vec(
            (prop::sample::select(vec!["a", "b", "_id"]), any::<bool>()),
            1..3,
        ),
        prop::option::of(prop::sample::select(vec![
            "a >= 2",
            "b != 1",
            "a IS NOT NULL",
            "a < 4 OR b = 0",
        ])),
        prop::option::of(0u64..40),
        prop_oneof![3 => Just(0u64), 1 => 0u64..10],
        1usize..9,
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(docs, order, filter, limit, offset, page, index, project)| Case {
                docs,
                order,
                filter,
                limit,
                offset,
                page,
                index,
                project,
            },
        )
}

fn case_text(c: &Case) -> String {
    let mut t = "FROM t".to_owned();
    if let Some(f) = c.filter {
        let _ = write!(t, " WHERE {f}");
    }
    if c.project {
        t.push_str(" SELECT a");
    }
    let keys: Vec<String> = c
        .order
        .iter()
        .map(|(k, d)| format!("{k} {}", if *d { "DESC" } else { "ASC" }))
        .collect();
    let _ = write!(t, " ORDER BY {}", keys.join(", "));
    if let Some(l) = c.limit {
        let _ = write!(t, " LIMIT {l}");
    }
    if c.offset > 0 {
        let _ = write!(t, " OFFSET {}", c.offset);
    }
    t
}

fn load_case(db: &EmbeddedDb, c: &Case) {
    // The collection first: `CREATE INDEX` on a missing collection creates it implicitly, after
    // which `CREATE COLLECTION` fails with RGN-1031.
    q(db, "CREATE COLLECTION t");
    if c.index {
        q(db, "CREATE INDEX by_a ON t (a)");
    }
    let docs: Vec<Value> = c
        .docs
        .iter()
        .enumerate()
        .map(|(i, (a, b))| {
            let mut d = Document::new();
            d.insert("_id", Value::Int64(i64::try_from(i).unwrap()));
            if let Some(a) = a {
                d.insert("a", a.clone());
            }
            if let Some(b) = b {
                d.insert("b", b.clone());
            }
            Value::Object(d)
        })
        .collect();
    if !docs.is_empty() {
        let p = Params::new().with("rows", Value::Array(docs));
        db.query(DB, "INSERT INTO t VALUES $rows", &p).unwrap();
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: u32::try_from(env_usize("RGQL_CURSOR_CASES", 48)).unwrap(),
        ..ProptestConfig::default()
    })]

    /// Paging with tokens returns exactly the one-shot result (no duplicates, no gaps), for
    /// ties, `null`/`missing`/mixed-type keys, both directions, LIMIT/OFFSET, filters,
    /// projections, and index or scan plans.
    #[test]
    fn tc_ql_007_token_paging_equals_one_shot(c in case()) {
        let db = open(73);
        load_case(&db, &c);
        let text = case_text(&c);
        let once = q(&db, &text);
        let pages = paged(&db, &text, &Params::new(), c.page);
        prop_assert_eq!(rows(&once), pages.iter().map(js).collect::<Vec<_>>(), "{}", text);
    }
}

#[test]
fn tc_ql_007_tokens_resume_on_a_reopened_store() {
    let fs = Arc::new(SimFileSystem::new());
    let text = "FROM t WHERE g < 3 SELECT _id, g ORDER BY g DESC, _id LIMIT 50 OFFSET 2";
    let (expected, token, first) = {
        let db = open_on(Arc::clone(&fs), Arc::new(SystemClock::new()), 74, true);
        q(&db, "CREATE INDEX by_g ON t (g)");
        load_generated(&db, "t", 200, 200, |i| {
            let mut d = Document::new();
            d.insert("g", Value::Int64(i64::try_from(i % 5).unwrap()));
            d
        });
        let expected = rows(&q(&db, text));
        let mut c = db.open_cursor(DB, text, &Params::new(), &opts(17)).unwrap();
        let b = c.next_batch().unwrap();
        c.close().unwrap();
        (expected, b.continuation_token.unwrap(), b.rows)
    };
    // The store is closed; the token is all the client keeps.
    let db = open_on(fs, Arc::new(SystemClock::new()), 75, false);
    let mut o = opts(1000);
    o.resume_token = Some(token.clone());
    let mut c = db.open_cursor(DB, text, &Params::new(), &o).unwrap();
    let mut all = first;
    all.extend(c.collect_rows().unwrap());
    assert_eq!(all.iter().map(js).collect::<Vec<_>>(), expected);
    assert_eq!(c.returned(), 50);
    // A token only resumes its own query (text, parameters, session database).
    for other in [
        "FROM t WHERE g < 4 SELECT _id, g ORDER BY g DESC, _id LIMIT 50 OFFSET 2",
        "FROM t ORDER BY g",
    ] {
        let e = db.open_cursor(DB, other, &Params::new(), &o).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument, "{other}");
    }
    let mut bad = token.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x20;
    let mut o = opts(10);
    o.resume_token = Some(bad);
    let e = db.open_cursor(DB, text, &Params::new(), &o).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
}

#[test]
fn tc_ql_007_tokens_have_keyset_semantics_under_writes() {
    let db = open(76);
    load_generated(&db, "t", 20, 20, |i| {
        let mut d = Document::new();
        d.insert("k", Value::Int64(i64::try_from(i * 10).unwrap()));
        d
    });
    let text = "FROM t SELECT VALUE k ORDER BY k";
    let mut c = db.open_cursor(DB, text, &Params::new(), &opts(5)).unwrap();
    let b = c.next_batch().unwrap();
    c.close().unwrap();
    assert_eq!(
        b.rows.iter().map(js).collect::<Vec<_>>().join(" "),
        "0 10 20 30 40"
    );
    // Between pages: a row before the position, one after it, one removed after it.
    q(&db, "INSERT INTO t VALUE {_id: 100, k: 5}");
    q(&db, "INSERT INTO t VALUE {_id: 101, k: 55}");
    q(&db, "DELETE FROM t WHERE k = 60");
    let mut o = opts(100);
    o.resume_token = b.continuation_token;
    let mut c = db.open_cursor(DB, text, &Params::new(), &o).unwrap();
    let rest: Vec<String> = c.collect_rows().unwrap().iter().map(js).collect();
    // Exactly the rows after the position at the new snapshot: no duplicate of a returned
    // row, nothing skipped after the position.
    let expected: Vec<String> = [50, 55]
        .into_iter()
        .chain((7..20).map(|i| i * 10))
        .map(|k: i64| k.to_string())
        .collect();
    assert_eq!(rest, expected);
}
