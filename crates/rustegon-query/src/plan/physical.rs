// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Physical plans and the rule-based access-path choice (query-engine.md §2 "Optimizer", §4).
//!
//! The planner enumerates [`Candidate`]s (collection scan, primary-key access, every usable
//! index) and asks an [`AccessPathChooser`] to pick one. M3 ships the rule-based
//! [`RuleBasedChooser`] (ESR: most equality fields, then sort satisfied by index order, then a
//! range); the cost-based [`super::cbo::CostBasedChooser`] implements the same trait with
//! statistics and falls back to the rules without them.
//!
//! Sort elimination: a single-range scan of a non-multikey index whose fields after the
//! single-value equality prefix match the `ORDER BY` keys (same directions; keys fixed by
//! equality may be dropped) returns rows in the requested order. Ties are ordered by `_id` both
//! ways (index entries end with `_id`; the `Sort` operator breaks ties by `_id`), so the result
//! is identical with and without the index. *Provisional (PD pending)*: ties broken by `_id`
//! ascending.
//!
//! Covered queries: when every field the query reads is a top-level covered field of the index
//! (`include`, stored exactly in the entry), the document is not fetched (hits flagged
//! `truncated` are fetched anyway). Key fields are never used as values: the key encoding does
//! not preserve the numeric type.

use std::{collections::BTreeSet, fmt::Write as _, ops::Bound};

use rustegon_catalog::{CollectionDescriptor, IndexDescriptor, IndexOrder};
use rustegon_doc::{Value, keyspace::ShardHash, path::FieldPath};

use super::{
    access::{
        IndexMatch, KeyRange, Sarg, SargKind, extract_sargs, match_index, match_wildcard, same_path,
    },
    logical::{render_keys, render_limit, render_select},
    rewrite::conjuncts,
};
use crate::{
    bind::{BoundProjection, BoundQuery, BoundSelect, IndexHint, SortKey},
    expr::{BExpr, Step, print::print_value, print_bexpr},
};

/// How rows are read.
#[derive(Debug, Clone, PartialEq)]
pub enum AccessPath {
    /// The predicate is never true: no rows.
    Empty,
    /// Point reads by `_id`.
    PrimaryGet {
        /// Ids (deduplicated, in key order).
        ids: Vec<Value>,
    },
    /// A range of `_id` keys (range-sharded collections only: hashed keys are not ordered).
    PrimaryScan {
        /// Lower `_id` bound.
        lower: Bound<Value>,
        /// Upper `_id` bound.
        upper: Bound<Value>,
    },
    /// Secondary index ranges.
    IndexScan {
        /// The index.
        index: IndexDescriptor,
        /// Key ranges, read in order.
        ranges: Vec<KeyRange>,
        /// A document may be hit several times (multikey / wildcard): deduplicate by `_id`.
        dedupe: bool,
        /// Read the documents (false: covered).
        fetch: bool,
    },
    /// Every document.
    CollectionScan,
}

/// Where the row order comes from.
#[derive(Debug, Clone, PartialEq)]
pub enum OrderStrategy {
    /// No `ORDER BY`.
    None,
    /// The access path already returns rows in order.
    IndexOrder(Vec<SortKey>),
    /// Blocking in-memory sort.
    Sort(Vec<SortKey>),
    /// Bounded heap of the first `k` rows.
    TopK {
        /// Keys.
        keys: Vec<SortKey>,
        /// Rows kept (`offset + limit`).
        k: u64,
    },
}

/// An executable plan of a read.
#[derive(Debug, Clone, PartialEq)]
pub struct PhysicalPlan {
    /// The collection read.
    pub collection: CollectionDescriptor,
    /// `database.collection` (display).
    pub name: String,
    /// Access path.
    pub access: AccessPath,
    /// Conjuncts the access path does not implement exactly (evaluated on every row).
    pub residual: Option<BExpr>,
    /// The whole predicate (evaluated instead of `residual` on hits that must be re-checked).
    pub recheck: Option<BExpr>,
    /// Ordering.
    pub order: OrderStrategy,
    /// Rows skipped.
    pub offset: u64,
    /// Rows returned at most.
    pub limit: Option<u64>,
    /// Output shape.
    pub select: BoundSelect,
    /// Optimizer estimates of the chosen plan (for EXPLAIN, TC-QL-006); `None` when the plan
    /// was chosen without statistics (rule-based). Advisory only: never used by the executor.
    pub estimate: Option<PlanEstimate>,
}

/// Cardinality and cost estimates of a plan (query-engine.md §3; produced by the cost-based
/// chooser, [`super::cbo`]). Rows are fractional estimates; costs are in the units of the §3
/// formula.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PlanEstimate {
    /// Rows (documents or index entries) the access path produces, before the residual filter.
    pub access_rows: f64,
    /// Rows left after the residual filter (before `ORDER BY` / `OFFSET` / `LIMIT`).
    pub filter_rows: f64,
    /// Rows the plan returns (after `OFFSET` / `LIMIT`): the root's `est_rows`.
    pub est_rows: f64,
    /// Total estimated cost of the plan: the root's `est_cost`.
    pub est_cost: f64,
    /// The cost-formula inputs behind `est_cost`.
    pub inputs: crate::stats::CostInputs,
}

/// One way of reading the rows of a query.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// The access path.
    pub access: AccessPath,
    /// Leading index fields fixed by equality (0 for scans).
    pub eq_fields: usize,
    /// A range bounds the scan.
    pub range: bool,
    /// The rows come out in `ORDER BY` order.
    pub sort_satisfied: bool,
    /// Conjuncts implemented exactly by the access path.
    pub exact: BTreeSet<usize>,
    /// Conjuncts used to bound the access path.
    pub used: BTreeSet<usize>,
}

/// Picks the access path among candidates (the cost-model hook of wave 3).
pub trait AccessPathChooser {
    /// Index of the chosen candidate; `candidates` is never empty and its last element is
    /// always the collection scan.
    fn choose(&self, query: &BoundQuery, candidates: &[Candidate]) -> usize;

    /// Estimates of the plan built from `candidate` (stored in [`PhysicalPlan::estimate`]);
    /// `None` (the default) when the chooser has no cardinality model.
    fn estimate(&self, _query: &BoundQuery, _candidate: &Candidate) -> Option<PlanEstimate> {
        None
    }
}

/// The rule-based chooser (module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleBasedChooser;

impl AccessPathChooser for RuleBasedChooser {
    fn choose(&self, query: &BoundQuery, candidates: &[Candidate]) -> usize {
        // Sort satisfaction only matters when the query orders its rows.
        let ordered = !query.order.is_empty();
        let rank = |c: &Candidate| {
            let point = matches!(c.access, AccessPath::PrimaryGet { .. } | AccessPath::Empty);
            let sorts = ordered && c.sort_satisfied;
            let useful = !c.used.is_empty() || sorts;
            (point, useful, c.eq_fields, sorts, c.range, c.exact.len())
        };
        let mut best = candidates.len().saturating_sub(1);
        for (i, c) in candidates.iter().enumerate() {
            if rank(c) > rank(&candidates[best]) {
                best = i;
            }
        }
        best
    }
}

/// The `_id` path.
pub(super) fn is_id(path: &[Step]) -> bool {
    matches!(path, [Step::Field { name, index: None }] if name == "_id")
}

/// Plans a bound read with `chooser`.
///
/// # Errors
/// `RGN-5001` if the target collection is unknown (the binder requires it for reads).
pub fn plan_query(
    q: &BoundQuery,
    chooser: &dyn AccessPathChooser,
) -> Result<PhysicalPlan, rustegon_common::Error> {
    let name = format!("{}.{}", q.target.database.name, q.target.name);
    let collection = q
        .target
        .collection
        .clone()
        .ok_or_else(|| crate::error::internal("planning a read of a missing collection"))?;
    let falsum =
        matches!(&q.filter, Some(BExpr::Const(v)) if v.as_ref() != Some(&Value::Bool(true)));
    let parts: Vec<&BExpr> = q.filter.as_ref().map(conjuncts).unwrap_or_default();
    let sargs = extract_sargs(&parts);
    let mut candidates = if falsum {
        vec![Candidate {
            access: AccessPath::Empty,
            eq_fields: 0,
            range: false,
            sort_satisfied: true,
            exact: BTreeSet::new(),
            used: BTreeSet::new(),
        }]
    } else {
        enumerate(q, &collection, &parts, &sargs)
    };
    candidates.push(Candidate {
        access: AccessPath::CollectionScan,
        eq_fields: 0,
        range: false,
        sort_satisfied: q.order.is_empty(),
        exact: BTreeSet::new(),
        used: BTreeSet::new(),
    });
    let pick = chooser.choose(q, &candidates).min(candidates.len() - 1);
    let chosen = candidates.swap_remove(pick);
    let estimate = chooser.estimate(q, &chosen);
    let mut plan = finish(q, collection, name, &parts, chosen);
    plan.estimate = estimate;
    Ok(plan)
}

fn enumerate(
    q: &BoundQuery,
    coll: &CollectionDescriptor,
    parts: &[&BExpr],
    sargs: &[Sarg],
) -> Vec<Candidate> {
    let mut out = Vec::new();
    let forced = match &q.options.index {
        IndexHint::CollectionScan => return out,
        IndexHint::Force(n) => Some(n.as_str()),
        IndexHint::Auto => None,
    };
    if forced.is_none() {
        primary_candidates(coll, sargs, &mut out);
    }
    for ix in q.target.indexes.iter().filter(|i| i.state.readable()) {
        let eligible = match forced {
            Some(n) => ix.name == n,
            None => !ix.hidden,
        };
        if eligible && let Some(c) = index_candidate(q, ix, parts, sargs) {
            out.push(c);
        }
    }
    out
}

fn primary_candidates(coll: &CollectionDescriptor, sargs: &[Sarg], out: &mut Vec<Candidate>) {
    for s in sargs.iter().filter(|s| is_id(&s.path)) {
        let ids = match &s.kind {
            SargKind::Eq(v) => vec![v.clone()],
            SargKind::In(vs) if !vs.is_empty() => vs.clone(),
            _ => continue,
        };
        out.push(Candidate {
            access: AccessPath::PrimaryGet { ids },
            eq_fields: 1,
            range: false,
            sort_satisfied: false,
            // `_id` is never an array (the write path rejects array ids), so equality on it is
            // exactly key identity.
            exact: BTreeSet::from([s.conjunct]),
            used: BTreeSet::from([s.conjunct]),
        });
    }
    if coll.shard_key.shard_hash() != ShardHash::Unhashed {
        return;
    }
    let (mut lower, mut upper) = (Bound::Unbounded, Bound::Unbounded);
    let mut used = BTreeSet::new();
    for s in sargs.iter().filter(|s| is_id(&s.path)) {
        let SargKind::Range(op, v) = &s.kind else {
            continue;
        };
        let v = v.clone();
        match op {
            crate::expr::CmpOp::Gt => lower = Bound::Excluded(v),
            crate::expr::CmpOp::Ge => lower = Bound::Included(v),
            crate::expr::CmpOp::Lt => upper = Bound::Excluded(v),
            _ => upper = Bound::Included(v),
        }
        used.insert(s.conjunct);
    }
    if !used.is_empty() {
        out.push(Candidate {
            access: AccessPath::PrimaryScan { lower, upper },
            eq_fields: 0,
            range: true,
            sort_satisfied: false,
            exact: BTreeSet::new(),
            used,
        });
    }
}

/// Whether every conjunct of `ix`'s partial predicate is a conjunct of the query.
pub(super) fn partial_implied(ix: &IndexDescriptor, parts: &[&BExpr]) -> bool {
    let Some(text) = &ix.partial else { return true };
    let Ok(pred) = crate::partial::bind_partial(text) else {
        return false;
    };
    conjuncts(&pred).iter().all(|c| parts.contains(c))
}

fn index_candidate(
    q: &BoundQuery,
    ix: &IndexDescriptor,
    parts: &[&BExpr],
    sargs: &[Sarg],
) -> Option<Candidate> {
    if !partial_implied(ix, parts) {
        return None;
    }
    let m = if ix.is_wildcard() {
        match_wildcard(ix, sargs)
    } else {
        match_index(ix, sargs)
    };
    let excludes_missing = |m: &IndexMatch| {
        m.used.iter().any(|c| {
            sargs
                .iter()
                .any(|s| s.conjunct == *c && s.kind != SargKind::IsNull)
        })
    };
    let m = match m {
        Some(m) if !ix.sparse || excludes_missing(&m) => m,
        _ => {
            // Sort-only use: the index must hold every document of the collection.
            if ix.sparse || ix.partial.is_some() || ix.is_wildcard() || q.order.is_empty() {
                return None;
            }
            IndexMatch {
                ranges: vec![KeyRange {
                    lower: Bound::Unbounded,
                    upper: Bound::Unbounded,
                }],
                eq_fields: 0,
                single_eq_fields: 0,
                range: false,
                used: BTreeSet::new(),
                exact: BTreeSet::new(),
            }
        }
    };
    let sort_satisfied = !q.order.is_empty() && sort_by_index(q, ix, &m, sargs);
    if m.used.is_empty() && !sort_satisfied {
        return None;
    }
    Some(Candidate {
        access: AccessPath::IndexScan {
            index: ix.clone(),
            dedupe: ix.multikey || ix.is_wildcard(),
            fetch: true,
            ranges: m.ranges,
        },
        eq_fields: m.eq_fields,
        range: m.range,
        sort_satisfied,
        exact: m.exact,
        used: m.used,
    })
}

/// Sort elimination (module docs).
fn sort_by_index(q: &BoundQuery, ix: &IndexDescriptor, m: &IndexMatch, sargs: &[Sarg]) -> bool {
    if ix.multikey || ix.is_wildcard() || m.ranges.len() != 1 {
        return false;
    }
    let Ok(paths) = ix
        .fields
        .iter()
        .map(|f| FieldPath::parse(&f.path))
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    // Keys fixed by a single-value equality do not affect the order.
    let fixed = |steps: &[Step]| {
        sargs.iter().any(|s| {
            matches!(s.kind, SargKind::Eq(_)) && s.path == steps && m.used.contains(&s.conjunct)
        })
    };
    let keys: Vec<&SortKey> = q
        .order
        .iter()
        .filter(|k| !k.expr.static_path().is_some_and(fixed))
        .collect();
    let mut field = m.single_eq_fields;
    for k in keys {
        let Some(steps) = k.expr.static_path() else {
            return false;
        };
        if field == ix.fields.len() {
            // Past the key fields entries are ordered by `_id` ascending: an `_id` key matches,
            // and nothing can follow it (`_id` is unique).
            return is_id(steps) && !k.descending;
        }
        let (Some(path), Some(f)) = (paths.get(field), ix.fields.get(field)) else {
            return false;
        };
        if !same_path(steps, path.segments()) || k.descending != (f.order == IndexOrder::Desc) {
            return false;
        }
        field += 1;
    }
    // Every key field must be fixed or ordered: a remaining field would order ties by itself
    // instead of by `_id` (the tie-break of the Sort operator).
    field == ix.fields.len()
}

fn finish(
    q: &BoundQuery,
    collection: CollectionDescriptor,
    name: String,
    parts: &[&BExpr],
    mut chosen: Candidate,
) -> PhysicalPlan {
    let remaining: Vec<BExpr> = parts
        .iter()
        .enumerate()
        .filter(|(i, _)| !chosen.exact.contains(i))
        .map(|(_, c)| (*c).clone())
        .collect();
    let residual = match remaining.len() {
        0 => None,
        1 => remaining.into_iter().next(),
        _ => Some(BExpr::And(remaining)),
    };
    let order = if q.order.is_empty() {
        OrderStrategy::None
    } else if chosen.sort_satisfied {
        OrderStrategy::IndexOrder(q.order.clone())
    } else if let Some(l) = q.limit {
        OrderStrategy::TopK {
            keys: q.order.clone(),
            k: l.saturating_add(q.offset),
        }
    } else {
        OrderStrategy::Sort(q.order.clone())
    };
    if let AccessPath::IndexScan { index, fetch, .. } = &mut chosen.access {
        *fetch = !covered(q, index);
    }
    PhysicalPlan {
        collection,
        name,
        access: chosen.access,
        residual,
        recheck: q.filter.clone(),
        order,
        offset: q.offset,
        limit: q.limit,
        select: q.select.clone(),
        estimate: None,
    }
}

/// Collects the top-level fields an expression reads; `false` when it reads anything else
/// (nested paths, the whole row, `id()` / `rev()`).
fn top_fields(e: &BExpr, out: &mut BTreeSet<String>) -> bool {
    let mut ok = true;
    e.walk(&mut |x| match x {
        BExpr::Field(steps) => match steps.as_slice() {
            [Step::Field { name, index: None }] => {
                out.insert(name.clone());
            }
            _ => ok = false,
        },
        BExpr::Call { func, .. } if func.reads_row() => ok = false,
        _ => {}
    });
    ok
}

pub(super) fn covered(q: &BoundQuery, ix: &IndexDescriptor) -> bool {
    if ix.include.is_empty() {
        return false;
    }
    let mut fields = BTreeSet::new();
    let mut ok = match &q.select {
        BoundSelect::Document => false,
        BoundSelect::Value(e) => top_fields(e, &mut fields),
        BoundSelect::Items(items) => items.iter().all(|p| match p {
            BoundProjection::Field { expr, .. } | BoundProjection::Wildcard(expr) => {
                top_fields(expr, &mut fields)
            }
            BoundProjection::Exclude(_) => false,
        }),
    };
    if let Some(f) = &q.filter {
        ok &= top_fields(f, &mut fields);
    }
    for k in &q.order {
        ok &= top_fields(&k.expr, &mut fields);
    }
    ok && fields.iter().all(|f| ix.include.contains(f))
}

fn render_tuple(t: &[Option<Value>]) -> String {
    let items: Vec<String> = t.iter().map(|v| print_value(v.as_ref())).collect();
    format!("({})", items.join(", "))
}

/// `[(1), (5))`-style rendering of a key range.
#[must_use]
pub fn render_range(r: &KeyRange) -> String {
    let lo = match &r.lower {
        Bound::Unbounded => "(-inf".to_owned(),
        Bound::Included(t) => format!("[{}", render_tuple(t)),
        Bound::Excluded(t) => format!("({}", render_tuple(t)),
    };
    let hi = match &r.upper {
        Bound::Unbounded => "+inf)".to_owned(),
        Bound::Included(t) => format!("{}]", render_tuple(t)),
        Bound::Excluded(t) => format!("{})", render_tuple(t)),
    };
    format!("{lo} .. {hi}")
}

impl PhysicalPlan {
    /// Indented text rendering, outermost operator first (EXPLAIN and golden tests).
    #[must_use]
    pub fn render(&self) -> String {
        let mut lines = Vec::new();
        if self.select != BoundSelect::Document {
            lines.push(format!("Project {}", render_select(&self.select)));
        }
        if self.limit.is_some() || self.offset > 0 {
            lines.push(format!("Limit {}", render_limit(self.limit, self.offset)));
        }
        match &self.order {
            OrderStrategy::None => {}
            OrderStrategy::IndexOrder(k) => lines.push(format!("IndexOrder {}", render_keys(k))),
            OrderStrategy::Sort(k) => lines.push(format!("Sort {}", render_keys(k))),
            OrderStrategy::TopK { keys, k } => {
                lines.push(format!("TopK k={k} {}", render_keys(keys)));
            }
        }
        if let Some(r) = &self.residual {
            lines.push(format!("Filter {}", print_bexpr(r)));
        }
        lines.push(self.render_access());
        let mut out = String::new();
        for (depth, l) in lines.iter().enumerate() {
            let _ = writeln!(out, "{}{l}", "  ".repeat(depth));
        }
        out.trim_end().to_owned()
    }

    fn render_access(&self) -> String {
        match &self.access {
            AccessPath::Empty => "Empty".to_owned(),
            AccessPath::CollectionScan => format!("CollectionScan {}", self.name),
            AccessPath::PrimaryGet { ids } => {
                let ids: Vec<String> = ids.iter().map(|v| print_value(Some(v))).collect();
                format!("PrimaryGet {} ids=[{}]", self.name, ids.join(", "))
            }
            AccessPath::PrimaryScan { lower, upper } => {
                let tuple = |b: &Bound<Value>| match b {
                    Bound::Unbounded => Bound::Unbounded,
                    Bound::Included(v) => Bound::Included(vec![Some(v.clone())]),
                    Bound::Excluded(v) => Bound::Excluded(vec![Some(v.clone())]),
                };
                let r = KeyRange {
                    lower: tuple(lower),
                    upper: tuple(upper),
                };
                format!("PrimaryScan {} {}", self.name, render_range(&r))
            }
            AccessPath::IndexScan {
                index,
                ranges,
                dedupe,
                fetch,
            } => {
                let rs: Vec<String> = ranges.iter().map(render_range).collect();
                let mut s = format!("IndexScan {}.{} {}", self.name, index.name, rs.join(" | "));
                if *dedupe {
                    s.push_str(" dedupe");
                }
                s.push_str(if *fetch { " fetch" } else { " covered" });
                s
            }
        }
    }
}
