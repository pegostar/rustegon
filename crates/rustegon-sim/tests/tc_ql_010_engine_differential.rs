// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-QL-010 / AC-QL-002: the M3 query engine (`EmbeddedDb::query`: binder, planner, index
//! access paths, executor, write path) against the reference interpreter
//! (`rustegon_query::reference`) through the differential harness of
//! `rustegon_query::testkit` (differential oracle on every statement, TLP and `NoREC` on the
//! engine). Converged evaluation rules: query-language.md §4.3 (PD-036, PD-038).
//!
//! Every case runs on a fresh embedded store whose collection carries one of several index
//! sets (none, single-field, multikey, compound, descending, sparse), so the same statements
//! are answered both by scans and by index access paths.
//!
//! Budget knobs: `RGQL_DIFF_SEED`, `RGQL_DIFF_CASES`, `RGQL_DIFF_SECONDS` (see
//! `rustegon_query::testkit::runner`); the default is small to keep `cargo nextest` fast. The
//! AC-QL-002 exit run is `RGQL_DIFF_SECONDS=3600`. A failure prints the seed and the statement.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

use std::{path::Path, sync::Arc};

use rustegon_catalog::DatabaseOptions;
use rustegon_common::Error;
use rustegon_doc::{Document, Value};
use rustegon_engine::embedded::EmbeddedDb;
use rustegon_query::{
    Params as EngineParams, Statement, parse_statement,
    testkit::{
        Output, Params, QueryEngine, Reference,
        casegen::{COLLECTION, generate},
        datagen::GenConfig,
        row_key,
        runner::{Budget, run_differential},
    },
};
use rustegon_sim::{SimFileSystem, workload::rng::SimRng};
use rustegon_sim_api::SystemClock;

/// Session database of the adapter.
const DB: &str = "diff";

/// Server-maintained fields the engine stores (FR-DOC-005) and the reference does not model.
const SYSTEM_FIELDS: &[&str] = &["_rev", "_createdAt", "_updatedAt"];

/// Index sets rotated over the cases (`CREATE INDEX` statements on [`COLLECTION`]). Compound
/// indexes pair `n` (only ever numeric: written by `INC`/`MUL` only) with a field that may
/// become an array, so no document can hit `RGN-1025` (two array-valued fields).
const INDEX_SETS: &[&[&str]] = &[
    &[],
    &[
        "CREATE INDEX ia ON t (a)",
        "CREATE INDEX ib ON t (b)",
        "CREATE INDEX itags ON t (tags)",
        "CREATE INDEX isku ON t (items.sku)",
    ],
    &[
        "CREATE INDEX inb ON t (n, b)",
        "CREATE INDEX icx ON t (c.x)",
        "CREATE INDEX iqty ON t (items.qty)",
        "CREATE INDEX itagsd ON t (tags DESC)",
    ],
    &[
        "CREATE INDEX ina ON t (n, a DESC)",
        "CREATE INDEX ibs ON t (b) WITH (sparse = true)",
        "CREATE INDEX icyz ON t (c.y.z)",
        "CREATE INDEX iflag ON t (flag)",
    ],
];

/// The embedded engine as a [`QueryEngine`].
struct Embedded {
    db: EmbeddedDb,
}

/// FNV-1a over the extended JSON of the documents (selects the index set of a case).
fn data_hash(docs: &[Document]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for d in docs {
        for b in row_key(&Value::Object(d.clone())).bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

fn open() -> EmbeddedDb {
    let db = EmbeddedDb::open(
        Arc::new(SimFileSystem::new()),
        Path::new("/store"),
        Arc::new(SystemClock::new()),
        Arc::new(SimRng::new(7)),
    )
    .unwrap();
    db.create_database(DB, &DatabaseOptions::default()).unwrap();
    db
}

/// Removes the server-maintained fields from every object inside `v`.
fn strip(v: Value) -> Value {
    match v {
        Value::Object(d) => Value::Object(strip_doc(d)),
        Value::Array(items) => Value::Array(items.into_iter().map(strip).collect()),
        other => other,
    }
}

fn strip_doc(d: Document) -> Document {
    let mut out = Document::new();
    for (name, value) in d.into_fields() {
        if !SYSTEM_FIELDS.contains(&name.as_str()) {
            out.insert(name, strip(value));
        }
    }
    out
}

fn engine_params(p: &Params) -> EngineParams {
    let mut out = EngineParams::new();
    for (name, value) in p {
        out.set(name.clone(), value.clone());
    }
    out
}

impl QueryEngine for Embedded {
    #[allow(clippy::unnecessary_literal_bound)] // The trait signature serves non-literal names.
    fn name(&self) -> &str {
        "engine"
    }

    fn reset(&mut self) -> Result<(), Error> {
        // A fresh store per case: no state leaks between cases.
        self.db = open();
        Ok(())
    }

    fn load(&mut self, collection: &str, docs: &[Document]) -> Result<(), Error> {
        // The index set is a function of the data, so `RGQL_DIFF_SEED=<seed> RGQL_DIFF_CASES=1`
        // replays a failing case with the same indexes.
        let h = data_hash(docs);
        let set = INDEX_SETS[usize::try_from(h % 4).unwrap_or(0) % INDEX_SETS.len()];
        // Half of the cases build the indexes before the data (write-path maintenance), half
        // after (online build / backfill).
        let before = (h >> 8).is_multiple_of(2);
        let create = |db: &EmbeddedDb| -> Result<(), Error> {
            for ddl in set {
                db.query(DB, *ddl, &EngineParams::new())?;
            }
            Ok(())
        };
        if before {
            create(&self.db)?;
        }
        if set.is_empty() || !before {
            // The collection must exist even without documents (reads of it are not errors).
            let _ = self.db.query(
                DB,
                &format!("CREATE COLLECTION {collection}"),
                &EngineParams::new(),
            )?;
        }
        for d in docs {
            self.db.insert(DB, collection, d)?;
        }
        if !before {
            create(&self.db)?;
        }
        Ok(())
    }

    fn run(&mut self, stmt: &Statement, params: &Params) -> Result<Output, Error> {
        let r = self.db.query(DB, stmt, &engine_params(params))?;
        let affected = (!matches!(stmt, Statement::Query(_))).then(|| r.affected());
        Ok(Output {
            rows: r.rows.into_iter().map(strip).collect(),
            affected,
        })
    }

    fn scan(&mut self, collection: &str) -> Result<Vec<Document>, Error> {
        let r = self
            .db
            .query(DB, &format!("FROM {collection}"), &EngineParams::new())?;
        Ok(r.rows
            .into_iter()
            .filter_map(|v| match strip(v) {
                Value::Object(d) => Some(d),
                _ => None,
            })
            .collect())
    }
}

#[test]
fn tc_ql_010_engine_against_reference_differential() {
    let budget = Budget::from_env(300);
    let config = GenConfig::default();
    let mut reference = Reference::new();
    let mut engine = Embedded { db: open() };
    let stats = run_differential(&budget, &config, &mut reference, &mut engine)
        .unwrap_or_else(|m| panic!("{m}"));
    println!("engine differential: {stats:?}");
    // The run must mostly compare results, not skip statements.
    assert!(stats.agreed > 3 * stats.same_error, "{stats:?}");
    assert!(stats.unsupported * 20 < stats.statements, "{stats:?}");
    if budget.max_cases >= 300 && budget.seconds.is_none() {
        assert!(stats.tlp > 0 && stats.norec > 0, "{stats:?}");
    }
}

/// Replay helper for investigating a mismatch: runs the steps before `RGQL_DEBUG_STEP` of the
/// case `RGQL_DIFF_SEED` on both engines, then the statement `RGQL_DEBUG_QUERY` (with that
/// step's parameters) on both and prints the results
/// (`cargo nextest run -p rustegon-sim --test tc_ql_010_engine_differential --run-ignored only
/// --no-capture`).
#[test]
#[ignore = "manual replay tool"]
fn tc_ql_010_engine_replay() {
    let var = |n: &str| std::env::var(n).unwrap_or_default();
    let seed: u64 = var("RGQL_DIFF_SEED").parse().unwrap();
    let step: usize = var("RGQL_DEBUG_STEP").parse().unwrap_or(0);
    let case = generate(seed, &GenConfig::default());
    let stmt = parse_statement(&var("RGQL_DEBUG_QUERY")).unwrap();
    let params = case
        .steps
        .get(step)
        .map(|s| s.params.clone())
        .unwrap_or_default();
    let mut reference = Reference::new();
    let mut engine = Embedded { db: open() };
    let engines: [&mut dyn QueryEngine; 2] = [&mut reference, &mut engine];
    for e in engines {
        e.reset().unwrap();
        e.load(COLLECTION, &case.documents).unwrap();
        for s in &case.steps[..step] {
            let _ = e.run(s.statement.as_ref().unwrap(), &s.params);
        }
        println!("== {}", e.name());
        match e.run(&stmt, &params) {
            Ok(o) => {
                for r in o.rows {
                    println!("  {}", row_key(&r));
                }
                println!("  affected {:?}", o.affected);
            }
            Err(err) => println!("  error {err}"),
        }
    }
}
