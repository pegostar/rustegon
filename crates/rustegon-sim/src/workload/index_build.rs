// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Seeded online index build workload (TC-IDX-002/003; FR-IDX-003): one build, interleaved
//! one operation at a time with document writes, cancellations and clean restarts (the build
//! then resumes from its checkpoint), all driven from one thread by a seeded scheduler on the
//! simulated file system and clock, so a seed reproduces the run.
//!
//! Checked at the end:
//! - a public index equals the documents ([`verify_index`]: per-document entry counts, point
//!   probes == filtered collection scan, multikey flag, no entry without its document; for a
//!   unique index, no duplicate value among the documents);
//! - an abandoned build failed for a legal reason (`RGN-1022` only for unique indexes,
//!   `RGN-5005` only when cancelled) and left no entries in any dropping index span.
//!
//! The reference ([`ref_values`]) is independent of `rustegon-index`: documents use only
//! integers, strings and arrays of integers, so value equality is key equality.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    ops::Bound,
    path::Path,
    sync::Arc,
    time::Duration,
};

use rustegon_catalog::{DatabaseOptions, IndexField, IndexSpec, IndexState};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_index::{BuildConfig, BuildStep, IndexBuild};

use super::{
    clock::SimClock,
    rng::{SimRng, mix},
};
use crate::{CrashMode, SimFileSystem};
use rustegon_engine::embedded::EmbeddedDb;

/// Database of the workload.
pub const DB: &str = "w";
/// Collection of the workload.
pub const COLL: &str = "c";
/// Name of the index being built.
pub const INDEX: &str = "ix";
/// Store root.
const ROOT: &str = "/store";
/// Scheduler iterations before the run is declared stuck.
const MAX_ITERATIONS: usize = 20_000;
/// Value space of `u` in unique runs.
const UNIQUE_U_SPACE: u64 = 2000;

/// The user part of the documents: `_id` → document without system fields.
pub type Model = BTreeMap<i64, Document>;

/// Settings of one run.
#[derive(Debug, Clone)]
pub struct IndexBuildConfig {
    /// Seed of every choice.
    pub seed: u64,
    /// Documents present before the build starts.
    pub initial_docs: i64,
    /// Ids used by writes (`0..id_space`).
    pub id_space: i64,
}

impl IndexBuildConfig {
    /// Default sizes for `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            initial_docs: 30,
            id_space: 50,
        }
    }
}

/// What a passing run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexBuildReport {
    /// Build steps taken.
    pub steps: u64,
    /// Committed writes.
    pub writes: u64,
    /// Writes rejected as duplicates.
    pub rejected: u64,
    /// Clean restarts mid-build.
    pub reopens: u64,
    /// The build became public.
    pub public: bool,
}

/// A failed run, with what reproduces it.
#[derive(Debug, Clone)]
pub struct IndexBuildFailure {
    /// Seed of the run.
    pub seed: u64,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for IndexBuildFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "index-build seed {:#x}: {} (reproduce: cargo run -p rustegon-sim -- --workload \
             index-build --seed {:#x})",
            self.seed, self.message, self.seed
        )
    }
}

/// Values a document has at top-level `field` for a non-sparse single-field index: missing →
/// `[None]`; a non-empty array → its distinct elements; anything else (including `[]`) → itself.
#[must_use]
pub fn ref_values(doc: &Document, field: &str) -> Vec<Option<Value>> {
    match doc.get(field) {
        None => vec![None],
        Some(Value::Array(items)) if !items.is_empty() => {
            let mut out: Vec<Option<Value>> = Vec::new();
            for v in items {
                if !out.iter().any(|o| o.as_ref() == Some(v)) {
                    out.push(Some(v.clone()));
                }
            }
            out
        }
        Some(v) => vec![Some(v.clone())],
    }
}

/// Whether `field` of `doc` is array-valued (sets the multikey flag).
#[must_use]
pub fn is_array(doc: &Document, field: &str) -> bool {
    matches!(doc.get(field), Some(Value::Array(_)))
}

fn int_of(i: i64) -> Value {
    Value::Int64(i)
}

/// A random value for field `a`: missing, a small integer, a string or an array of integers.
fn rand_a(r: &SimRng) -> Option<Value> {
    match r.below(10) {
        0 => None,
        1..=4 => Some(int_of(i64::try_from(r.below(5)).unwrap_or(0))),
        5 | 6 => Some(Value::String(["x", "y", "z"][r.index(3)].to_owned())),
        _ => {
            let n = r.below(4);
            Some(Value::Array(
                (0..n)
                    .map(|_| int_of(i64::try_from(r.below(5)).unwrap_or(0)))
                    .collect(),
            ))
        }
    }
}

/// A random document user part: `a` (see `rand_a`) and a `u` in `0..u_space`, missing in 5 %
/// of the documents when `u_may_miss` (a non-sparse unique index treats `missing` as a value,
/// so unique runs keep it present to make successful builds likely).
#[must_use]
pub fn rand_doc(r: &SimRng, u_space: u64, u_may_miss: bool) -> Document {
    let mut fields = Vec::new();
    if let Some(a) = rand_a(r) {
        fields.push(("a".to_owned(), a));
    }
    if !(u_may_miss && r.chance(50)) {
        fields.push((
            "u".to_owned(),
            int_of(i64::try_from(r.below(u_space)).unwrap_or(0)),
        ));
    }
    Document::try_from_fields(fields).unwrap_or_default()
}

/// The user part of a stored document (`a` and `u`).
#[must_use]
pub fn user_part(d: &Document) -> Document {
    let fields = d
        .iter()
        .filter(|(n, _)| matches!(*n, "a" | "u"))
        .map(|(n, v)| (n.to_owned(), v.clone()))
        .collect();
    Document::try_from_fields(fields).unwrap_or_default()
}

fn ids_of(rows: &[(rustegon_index::IndexHit, Document)]) -> Result<BTreeMap<i64, usize>, String> {
    let mut out = BTreeMap::new();
    for (_, d) in rows {
        match d.get("_id") {
            Some(Value::Int64(i)) => *out.entry(*i).or_default() += 1,
            other => return Err(format!("unexpected _id {other:?}")),
        }
    }
    Ok(out)
}

/// Checks a public index on top-level `field` against `model` (module docs). `ever_array`:
/// whether any document version indexed since the build started had an array in `field`.
///
/// # Errors
/// A description of the first discrepancy.
pub fn verify_index(
    db: &EmbeddedDb,
    field: &str,
    unique: bool,
    model: &Model,
    ever_array: bool,
) -> Result<(), String> {
    let e = |e: Error| e.to_string();
    let listed = db.list_indexes(DB, COLL).map_err(e)?;
    let [ix] = listed.as_slice() else {
        return Err(format!("expected one index, found {listed:?}"));
    };
    if ix.state != IndexState::Public {
        return Err(format!("index not public: {:?}", ix.state));
    }
    // Every entry has its document (index_scan fails otherwise) and documents match the model.
    let all = db
        .index_scan(DB, COLL, INDEX, Bound::Unbounded, Bound::Unbounded)
        .map_err(e)?;
    for (_, d) in &all {
        let Some(Value::Int64(id)) = d.get("_id") else {
            return Err("hit without integer _id".into());
        };
        if model.get(id) != Some(&user_part(d)) {
            return Err(format!("document {id} differs from the model"));
        }
    }
    let counts = ids_of(&all)?;
    let expected: BTreeMap<i64, usize> = model
        .iter()
        .map(|(id, d)| (*id, ref_values(d, field).len()))
        .collect();
    if counts != expected {
        return Err(format!(
            "entries per document {counts:?}, expected {expected:?}"
        ));
    }
    // Point probes: index range == filtered collection scan.
    let mut probes: BTreeSet<Option<String>> = BTreeSet::new();
    let mut values: Vec<Option<Value>> = vec![None];
    for d in model.values() {
        for v in ref_values(d, field) {
            let k = v.as_ref().map(|x| format!("{x:?}"));
            if probes.insert(k) {
                values.push(v);
            }
        }
    }
    for v in values {
        let t = [v.clone()];
        let hits = db
            .index_scan(DB, COLL, INDEX, Bound::Included(&t), Bound::Included(&t))
            .map_err(e)?;
        let got: BTreeSet<i64> = ids_of(&hits)?.into_keys().collect();
        let want: BTreeSet<i64> = model
            .iter()
            .filter(|(_, d)| ref_values(d, field).contains(&v))
            .map(|(id, _)| *id)
            .collect();
        if got != want {
            return Err(format!("probe {v:?}: index {got:?}, scan {want:?}"));
        }
    }
    let any_array = model.values().any(|d| is_array(d, field));
    if any_array && !ix.multikey {
        return Err("multikey flag missing".into());
    }
    if !ever_array && ix.multikey {
        return Err("multikey flag set without any array".into());
    }
    if unique {
        let mut seen = BTreeSet::new();
        for d in model.values() {
            if !seen.insert(format!("{:?}", d.get(field))) {
                return Err(format!("duplicate {field} committed: {:?}", d.get(field)));
            }
        }
    }
    check_no_orphans(db)
}

/// Every dropping index span is empty (abort/cancel atomicity) and no build is left
/// half-way (no index in a build state).
///
/// # Errors
/// A description of the first discrepancy.
pub fn check_no_orphans(db: &EmbeddedDb) -> Result<(), String> {
    for (ix, n) in db.index_spans(DB, COLL).map_err(|e| e.to_string())? {
        match ix.state {
            IndexState::Dropping if n > 0 => {
                return Err(format!("dropping index {} kept {n} entries", ix.id));
            }
            IndexState::Dropping | IndexState::Public => {}
            s => return Err(format!("index {} left in state {s:?}", ix.id)),
        }
    }
    Ok(())
}

/// The workload's store, reopened on restarts.
struct Store {
    clock: Arc<SimClock>,
    db: EmbeddedDb,
}

fn open_store(fs: &Arc<SimFileSystem>, start: Duration, seed: u64) -> Result<Store, Error> {
    let clock = Arc::new(SimClock::new(
        start,
        Duration::from_micros(10),
        Duration::from_millis(1),
    ));
    let db = EmbeddedDb::open(
        Arc::clone(fs) as Arc<dyn rustegon_sim_api::FileSystem>,
        Path::new(ROOT),
        Arc::clone(&clock) as Arc<dyn rustegon_sim_api::Clock>,
        Arc::new(SimRng::new(seed)),
    )?;
    Ok(Store { clock, db })
}

/// Applies one random write to the store and the model.
fn write(
    store: &Store,
    r: &SimRng,
    model: &mut Model,
    config: &IndexBuildConfig,
    u_space: u64,
) -> Result<bool, Error> {
    let id = i64::try_from(r.below(u64::try_from(config.id_space).unwrap_or(1))).unwrap_or(0);
    let d = rand_doc(r, u_space, u_space < UNIQUE_U_SPACE);
    let result = if model.contains_key(&id) {
        if r.chance(300) {
            store.db.delete(DB, COLL, &int_of(id)).map(|_| None)
        } else {
            store.db.replace(DB, COLL, &int_of(id), &d).map(Some)
        }
    } else {
        let mut with_id = d.clone();
        with_id.insert("_id", int_of(id));
        store.db.insert(DB, COLL, &with_id).map(Some)
    };
    match result {
        Ok(Some(stored)) => {
            model.insert(id, user_part(&stored));
            Ok(true)
        }
        Ok(None) => {
            model.remove(&id);
            Ok(true)
        }
        Err(e) if e.code() == ErrorCode::DuplicateKey => Ok(false),
        Err(e) => Err(e),
    }
}

/// Runs one seeded workload (module docs).
///
/// # Errors
/// [`IndexBuildFailure`] with the seed and the discrepancy.
pub fn run_index_build(config: &IndexBuildConfig) -> Result<IndexBuildReport, IndexBuildFailure> {
    let fail = |message: String| IndexBuildFailure {
        seed: config.seed,
        message,
    };
    let err = |e: Error| fail(e.to_string());
    let r = SimRng::new(mix(config.seed));
    let unique = r.chance(400);
    let field = if unique { "u" } else { "a" };
    // Unique runs draw `u` from a space where roughly half of the builds meet a duplicate.
    let u_space = if unique { UNIQUE_U_SPACE } else { 8 };
    let build_config = BuildConfig {
        batch_docs: usize::try_from(1 + r.below(6)).unwrap_or(1),
        cleanup_batch_keys: usize::try_from(1 + r.below(4)).unwrap_or(1),
        ..BuildConfig::default()
    };
    let fs = Arc::new(SimFileSystem::new());
    let mut store = open_store(&fs, Duration::from_secs(1_000_000), r.next()).map_err(err)?;
    store
        .db
        .create_database(DB, &DatabaseOptions::default())
        .map_err(err)?;
    let mut model = Model::new();
    let mut report = IndexBuildReport::default();
    let mut ever_array = false;
    for id in 0..config.initial_docs {
        let mut d = rand_doc(&r, u_space, !unique);
        d.insert("_id", int_of(id));
        let stored = store.db.insert(DB, COLL, &d).map_err(err)?;
        ever_array |= is_array(&stored, field);
        model.insert(id, user_part(&stored));
    }
    let mut spec = IndexSpec::new(INDEX, vec![IndexField::asc(field)]);
    spec.unique = unique;
    let mut build: IndexBuild = store
        .db
        .start_index_build(DB, COLL, &spec, &build_config)
        .map_err(err)?;
    let mut cancelled = false;
    let mut outcome: Option<Result<(), Error>> = None;
    for _ in 0..MAX_ITERATIONS {
        store.clock.begin_step();
        match r.below(100) {
            0..=44 => match store.db.step_index_build(&mut build).map_err(err)? {
                BuildStep::Continue { .. } => report.steps += 1,
                BuildStep::Public(_) => outcome = Some(Ok(())),
                BuildStep::Abandoned(e) => outcome = Some(Err(e)),
            },
            45..=95 => {
                if write(&store, &r, &mut model, config, u_space).map_err(err)? {
                    report.writes += 1;
                } else {
                    report.rejected += 1;
                }
                ever_array |= model.values().any(|d| is_array(d, field));
            }
            // Rare, so that most runs reach the end of their build.
            96 if !cancelled && r.chance(250) => match store.db.cancel_index_build(DB, COLL, INDEX)
            {
                Ok(_) => cancelled = true,
                // Already failed (dropping) or past its build: nothing to cancel.
                Err(e)
                    if matches!(
                        e.code(),
                        ErrorCode::IndexNotFound | ErrorCode::SchemaChangeInProgress
                    ) => {}
                Err(e) => return Err(err(e)),
            },
            _ => {
                let next = store.clock.peek() + Duration::from_secs(3600);
                drop(store);
                (store, build) = restart(&fs, &r, next, &build_config).map_err(fail)?;
                report.reopens += 1;
            }
        }
        if outcome.is_some() {
            break;
        }
    }
    let Some(outcome) = outcome else {
        return Err(fail("build did not finish".into()));
    };
    // Writes after the build: the index (or its absence) keeps holding.
    for _ in 0..20 {
        if write(&store, &r, &mut model, config, u_space).map_err(err)? {
            report.writes += 1;
        }
        ever_array |= model.values().any(|d| is_array(d, field));
    }
    match outcome {
        Ok(()) => {
            report.public = true;
            verify_index(&store.db, field, unique, &model, ever_array).map_err(fail)?;
        }
        Err(e) => check_abandoned(&store.db, &e, unique, cancelled).map_err(fail)?,
    }
    Ok(report)
}

/// Clean restart mid-build: reopens the store and picks up the one pending build, which
/// resumes from its checkpoint.
fn restart(
    fs: &Arc<SimFileSystem>,
    r: &SimRng,
    start: Duration,
    config: &BuildConfig,
) -> Result<(Store, IndexBuild), String> {
    fs.crash(r.next(), CrashMode::Clean);
    let store = open_store(fs, start, r.next()).map_err(|e| e.to_string())?;
    let mut pending = store
        .db
        .pending_index_builds(config)
        .map_err(|e| e.to_string())?;
    match pending.pop() {
        Some(b) if pending.is_empty() => Ok((store, b)),
        other => Err(format!(
            "expected one pending build after restart, found {}",
            usize::from(other.is_some()) + pending.len()
        )),
    }
}

/// An abandoned build failed for a legal reason and left nothing behind.
fn check_abandoned(
    db: &EmbeddedDb,
    e: &Error,
    unique: bool,
    cancelled: bool,
) -> Result<(), String> {
    let legal = match e.code() {
        ErrorCode::IndexBuildFailed => unique,
        ErrorCode::Cancelled => cancelled,
        _ => false,
    };
    if !legal {
        return Err(format!(
            "build abandoned with {e} (unique {unique}, cancelled {cancelled})"
        ));
    }
    let live = db.list_indexes(DB, COLL).map_err(|e| e.to_string())?;
    if !live.is_empty() {
        return Err(format!("abandoned build left {live:?}"));
    }
    check_no_orphans(db)
}
