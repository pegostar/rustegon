// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Shared helpers of the query-engine tests (`query_*.rs`): an embedded store on the simulated
//! file system and compact JSON renderings of results.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{path::Path, sync::Arc};

use rustegon_catalog::DatabaseOptions;
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Value,
    json::{JsonMode, parse_value, value_to_json},
};
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_query::{Params, QueryResult};
use rustegon_sim::{SimFileSystem, workload::rng::SimRng};
use rustegon_sim_api::SystemClock;

/// Session database of the tests.
pub const DB: &str = "shop";

/// A fresh store with database [`DB`].
pub fn open(seed: u64) -> EmbeddedDb {
    let db = EmbeddedDb::open(
        Arc::new(SimFileSystem::new()),
        Path::new("/store"),
        Arc::new(SystemClock::new()),
        Arc::new(SimRng::new(seed)),
    )
    .unwrap();
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    db
}

/// Runs `text` without parameters; panics on error.
pub fn q(db: &EmbeddedDb, text: &str) -> QueryResult {
    db.query(DB, text, &Params::new())
        .unwrap_or_else(|e| panic!("{text}: {e}"))
}

/// Runs `text` and returns its error.
pub fn q_err(db: &EmbeddedDb, text: &str) -> Error {
    match db.query(DB, text, &Params::new()) {
        Ok(r) => panic!("{text}: expected an error, got {r:?}"),
        Err(e) => e,
    }
}

/// The error code of `text`.
pub fn code(db: &EmbeddedDb, text: &str) -> ErrorCode {
    q_err(db, text).code()
}

/// Canonical JSON of a value.
pub fn js(v: &Value) -> String {
    value_to_json(v, JsonMode::Canonical)
}

/// Canonical JSON of every row.
pub fn rows(r: &QueryResult) -> Vec<String> {
    r.rows.iter().map(js).collect()
}

/// The rows of `text` as canonical JSON, joined by spaces (compact expectations).
pub fn rows_of(db: &EmbeddedDb, text: &str) -> String {
    rows(&q(db, text)).join(" ")
}

/// Parses a JSON value (test data).
pub fn val(json: &str) -> Value {
    parse_value(json).unwrap()
}

/// Inserts each JSON document of `docs` into `coll` through RGQL.
pub fn load(db: &EmbeddedDb, coll: &str, docs: &[&str]) {
    for d in docs {
        let p = Params::new().with("d", val(d));
        db.query(DB, &format!("INSERT INTO {coll} VALUE $d"), &p)
            .unwrap_or_else(|e| panic!("insert {d}: {e}"));
    }
}

/// The physical plan of `text` (EXPLAIN).
pub fn plan(db: &EmbeddedDb, text: &str) -> String {
    let r = q(db, &format!("EXPLAIN {text}"));
    match &r.rows[0] {
        Value::Object(d) => match d.get("physical") {
            Some(Value::String(s)) => s.clone(),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

/// A deterministic clock for deadline, cancellation and timing tests (TC-QL-006/008): every
/// reading advances time by a fixed `tick` (simulated work), and an armed "kill" sets a
/// cancellation flag at a given reading (a `KILL QUERY` arriving mid-execution).
pub struct TestClock {
    ns: std::sync::atomic::AtomicU64,
    tick_ns: std::sync::atomic::AtomicU64,
    readings: std::sync::atomic::AtomicU64,
    kill_at: std::sync::atomic::AtomicU64,
    killed_ns: std::sync::atomic::AtomicU64,
    /// The flag set by the armed kill.
    pub flag: Arc<std::sync::atomic::AtomicBool>,
}

impl TestClock {
    /// Starts at 1.7e9 s since the epoch (a plausible wall time for the HLC).
    pub fn new(tick: std::time::Duration) -> Arc<Self> {
        use std::sync::atomic::{AtomicBool, AtomicU64};
        Arc::new(Self {
            ns: AtomicU64::new(1_700_000_000_000_000_000),
            tick_ns: AtomicU64::new(u64::try_from(tick.as_nanos()).unwrap()),
            readings: AtomicU64::new(0),
            kill_at: AtomicU64::new(u64::MAX),
            killed_ns: AtomicU64::new(0),
            flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Current time without advancing.
    pub fn peek(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.ns.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// Changes the tick (0: frozen).
    pub fn set_tick(&self, tick: std::time::Duration) {
        self.tick_ns.store(
            u64::try_from(tick.as_nanos()).unwrap(),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    /// Jumps forward (idle time between calls).
    pub fn advance(&self, d: std::time::Duration) {
        self.ns.fetch_add(
            u64::try_from(d.as_nanos()).unwrap(),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    /// Readings so far.
    pub fn readings(&self) -> u64 {
        self.readings.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Sets [`TestClock::flag`] at the `n`-th reading from now.
    pub fn arm_kill_after(&self, n: u64) {
        use std::sync::atomic::Ordering;
        self.flag.store(false, Ordering::SeqCst);
        self.kill_at
            .store(self.readings().saturating_add(n), Ordering::SeqCst);
    }

    /// Time at which the armed kill fired.
    pub fn killed_at(&self) -> Option<std::time::Duration> {
        use std::sync::atomic::Ordering;
        self.flag
            .load(Ordering::SeqCst)
            .then(|| std::time::Duration::from_nanos(self.killed_ns.load(Ordering::SeqCst)))
    }

    fn read(&self) -> std::time::Duration {
        use std::sync::atomic::Ordering;
        let n = self.readings.fetch_add(1, Ordering::SeqCst) + 1;
        let tick = self.tick_ns.load(Ordering::SeqCst);
        let now = self.ns.fetch_add(tick, Ordering::SeqCst) + tick;
        if n == self.kill_at.load(Ordering::SeqCst) {
            self.killed_ns.store(now, Ordering::SeqCst);
            self.flag.store(true, Ordering::SeqCst);
        }
        std::time::Duration::from_nanos(now)
    }
}

impl rustegon_sim_api::Clock for TestClock {
    fn monotonic(&self) -> std::time::Duration {
        self.read()
    }

    fn wall(&self) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + self.read()
    }

    fn sleep(&self, duration: std::time::Duration) -> rustegon_sim_api::BoxFuture<'static, ()> {
        // Virtual time: sleeping is jumping.
        self.advance(duration);
        Box::pin(std::future::ready(()))
    }
}

/// A fresh store with database [`DB`] on `fs` driven by `clock`.
pub fn open_on(
    fs: Arc<SimFileSystem>,
    clock: Arc<dyn rustegon_sim_api::Clock>,
    seed: u64,
    create: bool,
) -> EmbeddedDb {
    let db = EmbeddedDb::open(fs, Path::new("/store"), clock, Arc::new(SimRng::new(seed))).unwrap();
    if create {
        db.create_database(DB, &DatabaseOptions::default()).unwrap();
    }
    db
}

/// Inserts `n` generated documents `{_id: i, …make(i)}` into `coll`, `chunk` per statement.
pub fn load_generated(
    db: &EmbeddedDb,
    coll: &str,
    n: u64,
    chunk: u64,
    make: impl Fn(u64) -> rustegon_doc::Document,
) {
    let mut i = 0;
    while i < n {
        let end = (i + chunk).min(n);
        let rows: Vec<Value> = (i..end)
            .map(|k| {
                let mut d = rustegon_doc::Document::new();
                d.insert("_id", Value::Int64(i64::try_from(k).unwrap()));
                for (name, v) in make(k).iter() {
                    d.insert(name.to_owned(), v.clone());
                }
                Value::Object(d)
            })
            .collect();
        let p = Params::new().with("rows", Value::Array(rows));
        db.query(DB, &format!("INSERT INTO {coll} VALUES $rows"), &p)
            .unwrap_or_else(|e| panic!("load {i}..{end}: {e}"));
        i = end;
    }
}
