// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Read operators: `Source` (primary get/scan, index scan with fetch or covered, collection
//! scan) → `Filter` → `Resume` → `Sort` | `TopK` → `Limit` → `Project`, each a batched pull
//! iterator.
//!
//! The pipeline owns its plan (`Arc`), so it can outlive one call: a cursor keeps it between
//! `getMore` calls (query-engine.md §7). Every source streams: collection and primary scans
//! resume after the last key read, index scans read their ranges by pages
//! ([`QueryStore::scan_index`](super::QueryStore::scan_index)), so memory is bounded by a batch
//! except in the blocking `Sort` (bounded by the memory limit).
//!
//! `Resume` (keyset continuation, FR-QL-007) drops the rows up to and including a [`Position`]
//! in the stream's order — `(ORDER BY keys, _id)`, the order `Sort`, `TopK` and index order all
//! produce — so a resumed query returns exactly the rows after the last one returned.
//!
//! With a [`Profile`] every operator is wrapped in an `Instrumented` operator counting its rows,
//! batches and (inclusive) time on the executor's clock (`EXPLAIN ANALYZE`, FR-QL-005).

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashSet, VecDeque},
    ops::Bound,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use rustegon_catalog::IndexDescriptor;
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    compare::compare,
    keyspace::{Family, ShardHash, document_key, family_prefix},
};
use rustegon_index::IndexHit;

use super::{ExecCtx, project::project};
use crate::{
    bind::{BoundSelect, SortKey},
    error::ExecResult,
    expr::{EvalCtx, Scope, Val, eval, eval_predicate, ops::approx_size},
    plan::{AccessPath, KeyRange, OrderStrategy, PhysicalPlan},
    stats::IndexAccess,
};

/// A row flowing through the operators: the document (or covered fields) and whether it must
/// be re-checked against the whole predicate.
pub(crate) struct Row {
    pub value: Value,
    pub recheck: bool,
}

/// A batched pull iterator (`Send`: a cursor may move between threads between calls).
pub(crate) trait Operator: Send {
    /// The next batch, `None` when exhausted.
    fn next_batch(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<Option<Vec<Row>>>;
}

/// One operator of a read pipeline (shared by the executor and `EXPLAIN`, so that profile
/// slots and plan nodes correspond one to one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Source,
    Filter,
    Resume,
    Sort,
    TopK,
    Limit,
    Project,
}

/// The stages of `plan`, innermost (the source) first.
pub(crate) fn stages(plan: &PhysicalPlan, with_projection: bool, resume: bool) -> Vec<Stage> {
    let mut out = vec![Stage::Source];
    if plan.residual.is_some() || plan.recheck.is_some() {
        out.push(Stage::Filter);
    }
    if resume {
        out.push(Stage::Resume);
    }
    match &plan.order {
        OrderStrategy::Sort(_) => out.push(Stage::Sort),
        OrderStrategy::TopK { .. } => out.push(Stage::TopK),
        OrderStrategy::None | OrderStrategy::IndexOrder(_) => {}
    }
    if plan.limit.is_some() || plan.offset > 0 {
        out.push(Stage::Limit);
    }
    if with_projection && plan.select != BoundSelect::Document {
        out.push(Stage::Project);
    }
    out
}

/// The `ORDER BY` keys of a plan (empty without `ORDER BY`).
pub(crate) fn order_keys(plan: &PhysicalPlan) -> &[SortKey] {
    match &plan.order {
        OrderStrategy::None => &[],
        OrderStrategy::IndexOrder(k)
        | OrderStrategy::Sort(k)
        | OrderStrategy::TopK { keys: k, .. } => k,
    }
}

/// Measured execution of one operator (`EXPLAIN ANALYZE`).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct OpStats {
    /// Rows returned.
    pub rows: u64,
    /// Non-empty batches returned.
    pub batches: u64,
    /// Inclusive time (operator and its inputs); `None` without an executor clock.
    pub time: Option<Duration>,
}

/// Per-operator statistics of one execution, indexed like [`stages`].
#[derive(Debug, Clone, Default)]
pub(crate) struct Profile(Arc<Mutex<Vec<OpStats>>>);

impl Profile {
    fn record(&self, slot: usize, rows: usize, time: Option<Duration>) {
        // A poisoned lock only means a panic elsewhere; the counters are still usable.
        let mut v = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if v.len() <= slot {
            v.resize(slot + 1, OpStats::default());
        }
        if let Some(s) = v.get_mut(slot) {
            if rows > 0 {
                s.rows += u64::try_from(rows).unwrap_or(u64::MAX);
                s.batches += 1;
            }
            if let Some(t) = time {
                s.time = Some(s.time.unwrap_or_default() + t);
            }
        }
    }

    /// The statistics of every slot.
    pub(crate) fn snapshot(&self) -> Vec<OpStats> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// A row's place in the stream order `(ORDER BY keys, _id)` (keyset continuation).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Position {
    /// Values of the `ORDER BY` keys (`None`: `missing`).
    pub keys: Vec<Val>,
    /// `_id` of the row.
    pub id: Val,
}

impl Position {
    /// The position of `row` for `keys`.
    pub(crate) fn of(row: &Value, keys: &[SortKey], ctx: &EvalCtx) -> Result<Self, Error> {
        let scope = Scope::new(Some(row), ctx);
        let mut vals = Vec::with_capacity(keys.len());
        for k in keys {
            vals.push(eval(&k.expr, &scope)?);
        }
        Ok(Self {
            keys: vals,
            id: row_id(row),
        })
    }
}

fn row_id(row: &Value) -> Val {
    match row {
        Value::Object(d) => d.get("_id").cloned(),
        _ => None,
    }
}

/// Stream order of two rows: keys (each in its direction), then `_id` ascending (planner docs:
/// ties are ordered by `_id` both by `Sort` and by index order).
fn order_by(a_keys: &[Val], a_id: &Val, b_keys: &[Val], b_id: &Val, desc: &[bool]) -> Ordering {
    for ((a, b), d) in a_keys.iter().zip(b_keys).zip(desc) {
        let o = compare(a.as_ref(), b.as_ref());
        if o != Ordering::Equal {
            return if *d { o.reverse() } else { o };
        }
    }
    compare(a_id.as_ref(), b_id.as_ref())
}

/// Options of a pipeline beyond its plan.
#[derive(Debug, Clone, Default)]
pub(crate) struct StreamConfig {
    /// Return only the rows after this position.
    pub resume: Option<Position>,
    /// Record per-operator statistics.
    pub profile: Option<Profile>,
}

/// The operator pipeline of a plan (without projection when `with_projection` is false).
pub struct RowStream {
    root: Box<dyn Operator>,
}

impl std::fmt::Debug for RowStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RowStream").finish_non_exhaustive()
    }
}

impl RowStream {
    pub(crate) fn new(plan: &Arc<PhysicalPlan>, with_projection: bool, cfg: StreamConfig) -> Self {
        let mut resume = cfg.resume;
        let mut op: Box<dyn Operator> = Box::new(Source::new(Arc::clone(plan)));
        for (slot, stage) in stages(plan, with_projection, resume.is_some())
            .into_iter()
            .enumerate()
        {
            op = match stage {
                Stage::Source => op,
                Stage::Filter => Box::new(FilterOp {
                    input: op,
                    plan: Arc::clone(plan),
                }),
                Stage::Resume => match resume.take() {
                    Some(after) => Box::new(ResumeOp {
                        input: op,
                        keys: order_keys(plan).to_vec(),
                        desc: order_keys(plan).iter().map(|k| k.descending).collect(),
                        after,
                    }),
                    None => op,
                },
                Stage::Sort | Stage::TopK => {
                    let k = match &plan.order {
                        OrderStrategy::TopK { k, .. } => Some(*k),
                        _ => None,
                    };
                    Box::new(SortOp::new(op, order_keys(plan), k))
                }
                Stage::Limit => Box::new(LimitOp {
                    input: op,
                    skip: plan.offset,
                    left: plan.limit,
                }),
                Stage::Project => Box::new(ProjectOp {
                    input: op,
                    plan: Arc::clone(plan),
                }),
            };
            if let Some(p) = &cfg.profile {
                op = Box::new(Instrumented {
                    input: op,
                    slot,
                    profile: p.clone(),
                });
            }
        }
        Self { root: op }
    }

    pub(crate) fn next_batch(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<Option<Vec<Row>>> {
        self.root.next_batch(cx)
    }
}

/// Runs a read plan and returns the projected rows.
pub(crate) fn collect(cx: &mut ExecCtx<'_>, plan: &Arc<PhysicalPlan>) -> ExecResult<Vec<Value>> {
    let cfg = StreamConfig {
        resume: None,
        profile: cx.profile.clone(),
    };
    let mut stream = RowStream::new(plan, true, cfg);
    let mut out = Vec::new();
    while let Some(batch) = stream.next_batch(cx)? {
        out.extend(batch.into_iter().map(|r| r.value));
    }
    Ok(out)
}

/// Runs a read plan and returns the matching documents (row source of writes), bounded by the
/// memory limit.
pub(crate) fn collect_documents(
    cx: &mut ExecCtx<'_>,
    plan: &Arc<PhysicalPlan>,
) -> ExecResult<Vec<Document>> {
    let cfg = StreamConfig {
        resume: None,
        profile: cx.profile.clone(),
    };
    let mut stream = RowStream::new(plan, false, cfg);
    let (mut out, mut bytes) = (Vec::new(), 0usize);
    while let Some(batch) = stream.next_batch(cx)? {
        for r in batch {
            bytes = bytes.saturating_add(approx_size(&r.value));
            if bytes > cx.opts.memory_limit {
                return Err(memory_exceeded("write statement").into());
            }
            if let Value::Object(d) = r.value {
                out.push(d);
            }
        }
    }
    Ok(out)
}

fn memory_exceeded(stage: &str) -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        format!("{stage} exceeded the query memory limit"),
    )
    .with_detail("stage", stage)
}

// ---------------------------------------------------------------------------------------------
// Instrumentation

struct Instrumented {
    input: Box<dyn Operator>,
    slot: usize,
    profile: Profile,
}

impl Operator for Instrumented {
    fn next_batch(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<Option<Vec<Row>>> {
        // Time comes from the executor's clock (rustegon-sim-api, ADR-029): simulated runs
        // measure simulated time.
        let clock = cx.opts.clock.clone();
        let start = clock.as_ref().map(|c| c.monotonic());
        let out = self.input.next_batch(cx);
        let time = match (clock, start) {
            (Some(c), Some(s)) => Some(c.monotonic().saturating_sub(s)),
            _ => None,
        };
        let rows = match &out {
            Ok(Some(b)) => b.len(),
            _ => 0,
        };
        self.profile.record(self.slot, rows, time);
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Source

/// Whether `r` is one full key of `index` (a point lookup for the usage counters): equal
/// inclusive bounds covering every key field (a wildcard key is `(path, value)`).
fn is_full_key_point(index: &IndexDescriptor, r: &KeyRange) -> bool {
    let fields = if index.is_wildcard() {
        2
    } else {
        index.fields.len()
    };
    matches!((&r.lower, &r.upper), (Bound::Included(lo), Bound::Included(hi)) if lo == hi && lo.len() >= fields)
}

enum SourceState {
    Start,
    Ids(VecDeque<Value>),
    Keys {
        next: Vec<u8>,
        end: Vec<u8>,
    },
    /// Index ranges read by pages: the current range, where to continue in it, the hits read
    /// but not returned yet, and the `_id`s seen when deduplicating.
    Hits {
        range: usize,
        after: Option<Vec<u8>>,
        buffer: VecDeque<IndexHit>,
        seen: HashSet<Vec<u8>>,
        /// Whether the access was already counted in the index usage counters (FR-IDX-004).
        counted: bool,
    },
    Done,
}

struct Source {
    plan: Arc<PhysicalPlan>,
    state: SourceState,
}

impl Source {
    fn new(plan: Arc<PhysicalPlan>) -> Self {
        Self {
            plan,
            state: SourceState::Start,
        }
    }

    fn start(&self) -> ExecResult<SourceState> {
        let coll = &self.plan.collection;
        let prefix = family_prefix(coll.database_id, coll.id, Family::Document);
        let end_of = |p: &[u8]| rustegon_index::scan::prefix_end(p).unwrap_or_default();
        Ok(match &self.plan.access {
            AccessPath::Empty => SourceState::Done,
            AccessPath::PrimaryGet { ids } => SourceState::Ids(ids.iter().cloned().collect()),
            AccessPath::CollectionScan => SourceState::Keys {
                end: end_of(&prefix),
                next: prefix,
            },
            AccessPath::PrimaryScan { lower, upper } => {
                let key =
                    |v: &Value| document_key(coll.database_id, coll.id, ShardHash::Unhashed, v);
                let next = match lower {
                    Bound::Unbounded => prefix.clone(),
                    Bound::Included(v) => key(v)?,
                    Bound::Excluded(v) => end_of(&key(v)?),
                };
                let end = match upper {
                    Bound::Unbounded => end_of(&prefix),
                    Bound::Included(v) => end_of(&key(v)?),
                    Bound::Excluded(v) => key(v)?,
                };
                SourceState::Keys { next, end }
            }
            AccessPath::IndexScan { .. } => SourceState::Hits {
                range: 0,
                after: None,
                buffer: VecDeque::new(),
                seen: HashSet::new(),
                counted: false,
            },
        })
    }
}

/// Refills an empty `buffer` with the next index page that has at least one new hit; `false`
/// when every range is exhausted. The interrupt is checked before every page.
///
/// FR-IDX-004: the access is counted once (lookup when every range is a full-key point, scan
/// otherwise) when its first page has been read, and every page adds the entries it read
/// (before deduplication). With paging an access may stop early (`LIMIT`, a cursor closed, a
/// deadline): it still counts, with the entries actually read.
#[allow(clippy::too_many_arguments)] // The fields of `SourceState::Hits`, borrowed separately.
fn next_hits(
    plan: &PhysicalPlan,
    cx: &mut ExecCtx<'_>,
    range: &mut usize,
    after: &mut Option<Vec<u8>>,
    buffer: &mut VecDeque<IndexHit>,
    seen: &mut HashSet<Vec<u8>>,
    counted: &mut bool,
) -> ExecResult<bool> {
    let AccessPath::IndexScan {
        index,
        ranges,
        dedupe,
        ..
    } = &plan.access
    else {
        return Ok(false);
    };
    let page_size = cx.opts.batch_rows.max(1);
    while buffer.is_empty() {
        let Some(r) = ranges.get(*range) else {
            return Ok(false);
        };
        cx.interrupt.check()?;
        let lower = r.lower.as_ref().map(Vec::as_slice);
        let upper = r.upper.as_ref().map(Vec::as_slice);
        let page = cx
            .store
            .scan_index(index, lower, upper, after.as_deref(), page_size)?;
        if let Some(usage) = cx.store.index_usage() {
            let entries = page.hits.len() as u64;
            let now = cx.store.now_ms();
            if *counted {
                usage.record_rows(index.id, entries, now);
            } else {
                let kind = if ranges.iter().all(|r| is_full_key_point(index, r)) {
                    IndexAccess::Lookup
                } else {
                    IndexAccess::Scan
                };
                usage.record(index.id, kind, entries, now);
            }
        }
        *counted = true;
        for h in page.hits {
            // The dedupe set grows with the distinct `_id`s of multikey / multi-range scans
            // only (single-range non-multikey scans never deduplicate).
            if !*dedupe || seen.insert(h.id_element.clone()) {
                buffer.push_back(h);
            }
        }
        if let Some(k) = page.resume {
            *after = Some(k);
        } else {
            *range += 1;
            *after = None;
        }
    }
    Ok(true)
}

impl Operator for Source {
    fn next_batch(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<Option<Vec<Row>>> {
        cx.interrupt.check()?;
        if matches!(self.state, SourceState::Start) {
            self.state = self.start()?;
        }
        let (max_rows, max_bytes) = (cx.opts.batch_rows.max(1), cx.opts.batch_bytes.max(1));
        let plan = Arc::clone(&self.plan);
        let coll = &plan.collection;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        match &mut self.state {
            SourceState::Start | SourceState::Done => return Ok(None),
            SourceState::Ids(ids) => {
                while out.len() < max_rows
                    && let Some(id) = ids.pop_front()
                {
                    if let Some(d) = cx.store.get(coll, &id)? {
                        out.push(Row {
                            value: Value::Object(d),
                            recheck: false,
                        });
                    }
                }
            }
            SourceState::Keys { next, end } => {
                if next >= end {
                    self.state = SourceState::Done;
                    return Ok(None);
                }
                let rows = cx.store.scan(next, end, max_rows)?;
                let (read, mut consumed) = (rows.len(), 0);
                for (key, d) in rows {
                    // Resume after the last key consumed (rows beyond the byte budget are read
                    // again next time). `key ‖ 0x01`, not `key ‖ 0x00`: the MVCC layer appends
                    // `0x00 ‖ timestamp` to logical keys, so a `0x00` bound falls inside the
                    // versions of `key` itself; no logical key starts with `key ‖ 0x00`
                    // (data-model.md §3.2), so nothing lies between `key` and `key ‖ 0x01`.
                    *next = key;
                    next.push(1);
                    consumed += 1;
                    bytes = bytes.saturating_add(approx_size_doc(&d));
                    out.push(Row {
                        value: Value::Object(d),
                        recheck: false,
                    });
                    if bytes >= max_bytes {
                        break;
                    }
                }
                if read < max_rows && consumed == read {
                    *next = end.clone();
                }
            }
            SourceState::Hits {
                range,
                after,
                buffer,
                seen,
                counted,
            } => {
                let fetch = matches!(&plan.access, AccessPath::IndexScan { fetch: true, .. });
                while out.len() < max_rows && bytes < max_bytes {
                    if buffer.is_empty()
                        && !next_hits(&plan, cx, range, after, buffer, seen, counted)?
                    {
                        break;
                    }
                    let Some(h) = buffer.pop_front() else {
                        break;
                    };
                    let value = if fetch || h.truncated {
                        let Some(d) = cx.store.fetch(coll, &h.id_element)? else {
                            return Err(Error::new(
                                ErrorCode::StorageCorruption,
                                "index entry without its document",
                            )
                            .into());
                        };
                        Value::Object(d)
                    } else {
                        covered_row(&h)
                    };
                    bytes = bytes.saturating_add(approx_size(&value));
                    out.push(Row {
                        value,
                        recheck: h.truncated,
                    });
                }
            }
        }
        if out.is_empty() && !matches!(self.state, SourceState::Keys { .. }) {
            self.state = SourceState::Done;
            return Ok(None);
        }
        Ok(Some(out))
    }
}

fn approx_size_doc(d: &Document) -> usize {
    d.iter().map(|(n, v)| n.len() + approx_size(v)).sum()
}

/// A row rebuilt from the covered fields of an index entry (top-level fields only, see the
/// planner) plus `_id` for tie-breaking.
fn covered_row(h: &IndexHit) -> Value {
    let mut d = h.include.clone().unwrap_or_default();
    d.insert("_id", h.id.clone());
    Value::Object(d)
}

// ---------------------------------------------------------------------------------------------
// Filter

struct FilterOp {
    input: Box<dyn Operator>,
    plan: Arc<PhysicalPlan>,
}

impl Operator for FilterOp {
    fn next_batch(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<Option<Vec<Row>>> {
        // Pull until a batch keeps at least one row (or the input ends), so that a selective
        // filter does not hand empty batches upstream.
        while let Some(batch) = self.input.next_batch(cx)? {
            let mut out = Vec::with_capacity(batch.len());
            for row in batch {
                let pred = if row.recheck {
                    self.plan.recheck.as_ref()
                } else {
                    self.plan.residual.as_ref()
                };
                let keep = match pred {
                    Some(p) => {
                        eval_predicate(p, &Scope::new(Some(&row.value), cx.eval))? == Some(true)
                    }
                    None => true,
                };
                if keep {
                    out.push(Row {
                        value: row.value,
                        recheck: false,
                    });
                }
            }
            if !out.is_empty() {
                return Ok(Some(out));
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------------------------
// Resume (keyset continuation)

struct ResumeOp {
    input: Box<dyn Operator>,
    keys: Vec<SortKey>,
    desc: Vec<bool>,
    after: Position,
}

impl Operator for ResumeOp {
    fn next_batch(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<Option<Vec<Row>>> {
        while let Some(batch) = self.input.next_batch(cx)? {
            let mut out = Vec::with_capacity(batch.len());
            for row in batch {
                let p = Position::of(&row.value, &self.keys, cx.eval)?;
                let after = &self.after;
                if order_by(&p.keys, &p.id, &after.keys, &after.id, &self.desc) == Ordering::Greater
                {
                    out.push(row);
                }
            }
            if !out.is_empty() {
                return Ok(Some(out));
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------
// Sort / TopK

/// A row with its evaluated sort keys; ordered by the keys, then by `_id` (ties, see the
/// planner docs).
struct Keyed {
    keys: Vec<Val>,
    id: Val,
    row: Value,
    desc: Arc<[bool]>,
}

impl Keyed {
    fn order(&self, other: &Self) -> Ordering {
        order_by(&self.keys, &self.id, &other.keys, &other.id, &self.desc)
    }
}

impl PartialEq for Keyed {
    fn eq(&self, other: &Self) -> bool {
        self.order(other) == Ordering::Equal
    }
}
impl Eq for Keyed {}
impl PartialOrd for Keyed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Keyed {
    fn cmp(&self, other: &Self) -> Ordering {
        self.order(other)
    }
}

struct SortOp {
    input: Box<dyn Operator>,
    keys: Vec<SortKey>,
    desc: Arc<[bool]>,
    /// `Some(k)`: keep only the first `k` rows (`TopK`).
    k: Option<u64>,
    sorted: Option<VecDeque<Value>>,
}

impl SortOp {
    fn new(input: Box<dyn Operator>, keys: &[SortKey], k: Option<u64>) -> Self {
        Self {
            input,
            desc: keys.iter().map(|k| k.descending).collect(),
            keys: keys.to_vec(),
            k,
            sorted: None,
        }
    }

    fn keyed(&self, row: Value, cx: &ExecCtx<'_>) -> ExecResult<Keyed> {
        let Position { keys, id } = Position::of(&row, &self.keys, cx.eval)?;
        Ok(Keyed {
            keys,
            id,
            row,
            desc: Arc::clone(&self.desc),
        })
    }

    /// Consumes the input (blocking) into sorted rows.
    fn fill(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<VecDeque<Value>> {
        let limit = cx.opts.memory_limit;
        let mut bytes = 0usize;
        let mut all: Vec<Keyed> = Vec::new();
        let mut heap: BinaryHeap<Keyed> = BinaryHeap::new();
        let k = self.k.and_then(|k| usize::try_from(k).ok());
        // The input checks the interrupt before every batch it reads.
        while let Some(batch) = self.input.next_batch(cx)? {
            for r in batch {
                let keyed = self.keyed(r.value, cx)?;
                if let Some(k) = k {
                    // TopK: a max-heap of the best `k` rows; the worst is evicted.
                    heap.push(keyed);
                    if heap.len() > k {
                        heap.pop();
                    }
                } else {
                    bytes = bytes.saturating_add(approx_size(&keyed.row));
                    if bytes > limit {
                        return Err(memory_exceeded("Sort").into());
                    }
                    all.push(keyed);
                }
            }
        }
        if k.is_some() {
            let kept: usize = heap.iter().map(|r| approx_size(&r.row)).sum();
            if kept > limit {
                return Err(memory_exceeded("TopK").into());
            }
            all = heap.into_sorted_vec();
        } else {
            cx.interrupt.check()?;
            all.sort();
        }
        // The in-memory sort itself is not interruptible; check once it is done (FR-QL-008).
        cx.interrupt.check()?;
        Ok(all.into_iter().map(|k| k.row).collect())
    }
}

impl Operator for SortOp {
    fn next_batch(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<Option<Vec<Row>>> {
        if self.sorted.is_none() {
            self.sorted = Some(self.fill(cx)?);
        }
        let max = cx.opts.batch_rows.max(1);
        let Some(sorted) = self.sorted.as_mut() else {
            return Ok(None);
        };
        if sorted.is_empty() {
            return Ok(None);
        }
        // A cursor drains the sorted rows over several calls: keep honouring the interrupt.
        cx.interrupt.check()?;
        let n = max.min(sorted.len());
        Ok(Some(
            sorted
                .drain(..n)
                .map(|value| Row {
                    value,
                    recheck: false,
                })
                .collect(),
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// Limit / Project

struct LimitOp {
    input: Box<dyn Operator>,
    skip: u64,
    left: Option<u64>,
}

impl Operator for LimitOp {
    fn next_batch(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<Option<Vec<Row>>> {
        loop {
            if self.left == Some(0) {
                // Stop pulling: the input is not read further.
                return Ok(None);
            }
            let Some(mut batch) = self.input.next_batch(cx)? else {
                return Ok(None);
            };
            let skip = usize::try_from(self.skip)
                .unwrap_or(usize::MAX)
                .min(batch.len());
            batch.drain(..skip);
            self.skip -= u64::try_from(skip).unwrap_or(0);
            if let Some(left) = self.left.as_mut() {
                let keep = usize::try_from(*left)
                    .unwrap_or(usize::MAX)
                    .min(batch.len());
                batch.truncate(keep);
                *left -= u64::try_from(keep).unwrap_or(0);
            }
            if !batch.is_empty() {
                return Ok(Some(batch));
            }
        }
    }
}

struct ProjectOp {
    input: Box<dyn Operator>,
    plan: Arc<PhysicalPlan>,
}

impl Operator for ProjectOp {
    fn next_batch(&mut self, cx: &mut ExecCtx<'_>) -> ExecResult<Option<Vec<Row>>> {
        let Some(batch) = self.input.next_batch(cx)? else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(batch.len());
        for r in batch {
            out.push(Row {
                value: project(&self.plan.select, &r.value, cx.eval)?,
                recheck: false,
            });
        }
        Ok(Some(out))
    }
}
