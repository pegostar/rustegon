// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The cost-based access-path chooser (query-engine.md §2 "Optimizer", §3, §4; FR-QL-001,
//! *Provisional (PD-040)*).
//!
//! [`CostBasedChooser`] plugs into the same [`AccessPathChooser`] hook as the rule-based
//! chooser: the planner still enumerates the candidates (collection scan, `PrimaryGet`,
//! `PrimaryScan`, every usable index — partial, sparse and wildcard applicability is decided
//! there, so a candidate is always a *correct* way to read the rows) and the chooser only picks
//! the cheapest one. The choice therefore never changes results, only their cost.
//!
//! **Algorithm.** For every candidate, with `N` = row count of the statistics:
//! 1. *access selectivity* `s_acc`: the damped conjunction (§3; ranges on one path merged into
//!    one interval first) of the conjuncts the access
//!    path uses for its bounds, plus — for a partial index — the query conjuncts that imply
//!    its predicate (the index only holds those rows); `1` for a collection scan or a
//!    sort-only index scan; `A = N × s_acc` rows / entries (`PrimaryGet`: the number of ids);
//! 2. *filter selectivity* `s_all` of the whole `WHERE`: `R = min(N × s_all, A)`;
//! 3. *rows pulled* from the access path: when no blocking operator (`Sort` / `TopK`) sits
//!    above it and the query has a `LIMIT`, the pipeline stops after `offset + limit` output
//!    rows, i.e. after a fraction `min(1, (offset + limit) / R)` of the access rows;
//! 4. *cost inputs* (§3 formula, [`CostConfig`]): collection scan = that fraction of the
//!    collection's pages sequential + pulled rows CPU; `PrimaryScan` likewise on its `_id`
//!    range; `PrimaryGet` = one random page and one CPU row per id; index scan = all `A`
//!    entries' pages sequential (index ranges are read in full before fetching) + one random
//!    page per pulled row unless covered + `A` CPU rows; a blocking sort adds
//!    `R × log2(max(2, k))` CPU rows (`k` = rows kept: `R`, or `offset + limit` for `TopK`).
//!
//! The cheapest candidate wins; candidates whose costs are equal within a relative `1e-9`
//! are ranked by the rule-based chooser (deterministic plans for ties, e.g. two equivalent
//! indexes).
//!
//! **Fallback to the rule-based chooser** ([`RuleBasedChooser`]) when the costs would be
//! meaningless or must not be applied: no statistics for the collection, statistics of another
//! collection, statistics collected while the collection was empty (`row_count = 0`: a
//! collection that grew since would be planned as if empty), or an index forced with
//! `OPTIONS (index = '…')` (the user's choice wins; the estimate is still computed).
//!
//! **Statistics are advisory.** They may be stale or come from another snapshot than the
//! query's: they only influence which correct plan runs (query-engine.md §8).

use std::{cmp::Ordering, ops::Bound};

use rustegon_catalog::IndexDescriptor;
use rustegon_doc::{Value, compare::compare, path::FieldPath};

use super::{
    access::same_path,
    physical::{
        AccessPath, AccessPathChooser, Candidate, PlanEstimate, RuleBasedChooser, covered,
        partial_implied,
    },
    rewrite::conjuncts,
};
use crate::{
    bind::{BoundQuery, IndexHint},
    expr::{BExpr, CmpOp, IsKind, Step},
    stats::{CollectionStats, CostConfig, CostInputs, Predicate, selectivity, to_f64},
};

/// Relative cost difference under which two candidates are considered equal.
const TIE_EPSILON: f64 = 1e-9;

/// The cost-based chooser (module docs).
#[derive(Debug, Clone, Copy)]
pub struct CostBasedChooser<'s> {
    stats: Option<&'s CollectionStats>,
    config: CostConfig,
}

impl<'s> CostBasedChooser<'s> {
    /// A chooser over `stats` (the target collection's statistics, `None` if never analyzed)
    /// with the `query.cost.*` constants `config`.
    #[must_use]
    pub fn new(stats: Option<&'s CollectionStats>, config: CostConfig) -> Self {
        Self { stats, config }
    }

    /// The statistics when they may be used for `query` (module docs, fallback rule).
    fn usable(&self, query: &BoundQuery) -> Option<&'s CollectionStats> {
        let stats = self.stats?;
        let coll = query.target.collection.as_ref()?;
        (stats.row_count > 0
            && stats.collection_id == coll.id
            && stats.database_id == coll.database_id)
            .then_some(stats)
    }

    /// Estimates of `candidate` (module docs, steps 1–4).
    fn evaluate(
        &self,
        stats: &CollectionStats,
        query: &BoundQuery,
        candidate: &Candidate,
    ) -> PlanEstimate {
        let cfg = &self.config;
        let parts: Vec<&BExpr> = query.filter.as_ref().map(conjuncts).unwrap_or_default();
        let preds: Vec<Predicate> = parts.iter().map(|e| to_predicate(stats, e)).collect();
        let n = to_f64(stats.row_count);
        let total_pages = cfg.pages(to_f64(stats.total_bytes));
        let s_all = selectivity(stats, &conjunction(preds.clone()));
        let mut access_conjuncts: Vec<usize> = candidate.used.iter().copied().collect();
        if let AccessPath::IndexScan { index, .. } = &candidate.access {
            access_conjuncts.extend(partial_conjuncts(index, &parts));
            access_conjuncts.sort_unstable();
            access_conjuncts.dedup();
        }
        let s_acc = match &candidate.access {
            AccessPath::Empty => 0.0,
            AccessPath::CollectionScan => 1.0,
            _ => selectivity(
                stats,
                &conjunction(
                    access_conjuncts
                        .iter()
                        .filter_map(|i| preds.get(*i).cloned())
                        .collect(),
                ),
            ),
        };
        let access_rows = match &candidate.access {
            AccessPath::Empty => 0.0,
            AccessPath::PrimaryGet { ids } => to_f64(ids.len() as u64).min(n),
            _ => n * s_acc,
        };
        let filter_rows = (n * s_all).min(access_rows);
        let blocking = !query.order.is_empty() && !candidate.sort_satisfied;
        let wanted = query.limit.map(|l| to_f64(l.saturating_add(query.offset)));
        let fraction = match wanted {
            Some(k) if !blocking && filter_rows > 0.0 => (k / filter_rows).min(1.0),
            _ => 1.0,
        };
        let pulled = access_rows * fraction;
        let mut inputs = match &candidate.access {
            AccessPath::Empty => CostInputs::default(),
            AccessPath::CollectionScan => CostInputs {
                seq_pages: total_pages * fraction,
                rows_cpu: pulled,
                ..CostInputs::default()
            },
            AccessPath::PrimaryScan { .. } => CostInputs {
                seq_pages: (total_pages * s_acc * fraction).max(1.0),
                rows_cpu: pulled,
                ..CostInputs::default()
            },
            AccessPath::PrimaryGet { ids } => {
                let ids = to_f64(ids.len() as u64);
                CostInputs {
                    random_pages: ids,
                    rows_cpu: ids,
                    ..CostInputs::default()
                }
            }
            AccessPath::IndexScan { index, .. } => {
                let is_covered = covered(query, index);
                let mut i = cfg.index_scan(stats, index.id, s_acc, is_covered);
                if !is_covered {
                    i.random_pages = pulled;
                }
                i
            }
        };
        if blocking {
            let kept = match query.limit {
                Some(l) => to_f64(l.saturating_add(query.offset)).min(filter_rows),
                None => filter_rows,
            };
            inputs.rows_cpu += filter_rows * kept.max(2.0).log2();
        }
        let after_offset = (filter_rows - to_f64(query.offset)).max(0.0);
        let est_rows = query
            .limit
            .map_or(after_offset, |l| after_offset.min(to_f64(l)));
        PlanEstimate {
            access_rows,
            filter_rows,
            est_rows,
            est_cost: cfg.cost(&inputs),
            inputs,
        }
    }
}

impl AccessPathChooser for CostBasedChooser<'_> {
    fn choose(&self, query: &BoundQuery, candidates: &[Candidate]) -> usize {
        let Some(stats) = self.usable(query) else {
            return RuleBasedChooser.choose(query, candidates);
        };
        if matches!(query.options.index, IndexHint::Force(_)) {
            return RuleBasedChooser.choose(query, candidates);
        }
        let costs: Vec<f64> = candidates
            .iter()
            .map(|c| self.evaluate(stats, query, c).est_cost)
            .collect();
        let min = costs.iter().copied().fold(f64::INFINITY, f64::min);
        let tied: Vec<usize> = (0..candidates.len())
            .filter(|&i| costs[i] - min <= TIE_EPSILON * min.abs().max(1.0))
            .collect();
        if tied.len() == 1 {
            return tied[0];
        }
        // Rank the tied candidates by the rules. `RuleBasedChooser` defaults to the last
        // element, so the slice keeps the candidates' relative order.
        let subset: Vec<Candidate> = tied.iter().map(|&i| candidates[i].clone()).collect();
        tied[RuleBasedChooser
            .choose(query, &subset)
            .min(subset.len() - 1)]
    }

    fn estimate(&self, query: &BoundQuery, candidate: &Candidate) -> Option<PlanEstimate> {
        let stats = self.usable(query)?;
        Some(self.evaluate(stats, query, candidate))
    }
}

/// Indexes (in `parts`) of the query conjuncts that form a partial index's predicate.
fn partial_conjuncts(index: &IndexDescriptor, parts: &[&BExpr]) -> Vec<usize> {
    let Some(text) = &index.partial else {
        return Vec::new();
    };
    if !partial_implied(index, parts) {
        return Vec::new();
    }
    let Ok(pred) = crate::partial::bind_partial(text) else {
        return Vec::new();
    };
    conjuncts(&pred)
        .iter()
        .filter_map(|c| parts.iter().position(|p| p == c))
        .collect()
}

/// A conjunction whose range predicates on the same path are merged into one interval
/// (*Provisional (PD-040)*): `a >= 10 AND a < 20` is one histogram range, not two independent
/// half-lines combined by damping, which would grossly overestimate a narrow interval. For a
/// multikey path the merge may underestimate (the two bounds may hold through different
/// elements); estimates never affect results.
fn conjunction(preds: Vec<Predicate>) -> Predicate {
    let mut out: Vec<Predicate> = Vec::with_capacity(preds.len());
    for p in preds {
        let Predicate::Range { path, lower, upper } = p else {
            out.push(p);
            continue;
        };
        let existing = out.iter_mut().find_map(|q| match q {
            Predicate::Range {
                path: qp,
                lower: ql,
                upper: qu,
            } if *qp == path => Some((ql, qu)),
            _ => None,
        });
        match existing {
            Some((ql, qu)) => {
                *ql = tighter(ql, lower, true);
                *qu = tighter(qu, upper, false);
            }
            None => out.push(Predicate::Range { path, lower, upper }),
        }
    }
    Predicate::And(out)
}

/// The tighter of two bounds of one side (`lower`: the larger value; on equal values the
/// exclusive bound), in the §2.1 total order.
fn tighter(cur: &Bound<Value>, cand: Bound<Value>, lower: bool) -> Bound<Value> {
    match (cur, &cand) {
        (Bound::Unbounded, _) => cand,
        (_, Bound::Unbounded) => cur.clone(),
        (Bound::Included(a) | Bound::Excluded(a), Bound::Included(b) | Bound::Excluded(b)) => {
            match compare(Some(a), Some(b)) {
                Ordering::Equal if matches!(cand, Bound::Excluded(_)) => cand,
                Ordering::Equal => cur.clone(),
                ord if (ord == Ordering::Less) == lower => cand,
                _ => cur.clone(),
            }
        }
    }
}

/// The statistics path naming `steps` (an unknown path gets a name no statistics use, so the
/// estimator falls back to its defaults).
fn stats_path(stats: &CollectionStats, steps: &[Step]) -> String {
    stats
        .fields
        .iter()
        .find(|f| FieldPath::parse(&f.path).is_ok_and(|p| same_path(steps, p.segments())))
        .map_or_else(|| "\u{0}unknown".to_owned(), |f| f.path.clone())
}

/// Translates a bound predicate into the estimator's [`Predicate`] (query-engine.md §3). Shapes
/// the estimator does not model become [`Predicate::Other`].
pub(crate) fn to_predicate(stats: &CollectionStats, e: &BExpr) -> Predicate {
    match e {
        BExpr::Const(v) => {
            if v.as_ref() == Some(&Value::Bool(true)) {
                // An empty conjunction has selectivity 1, an empty disjunction 0.
                Predicate::And(Vec::new())
            } else {
                Predicate::Or(Vec::new())
            }
        }
        BExpr::And(items) => conjunction(items.iter().map(|x| to_predicate(stats, x)).collect()),
        BExpr::Or(items) => Predicate::Or(items.iter().map(|x| to_predicate(stats, x)).collect()),
        BExpr::Not(inner) => Predicate::Not(Box::new(to_predicate(stats, inner))),
        BExpr::Cmp { op, left, right } => {
            let (Some(steps), BExpr::Const(Some(v))) = (left.static_path(), right.as_ref()) else {
                return Predicate::Other;
            };
            let path = stats_path(stats, steps);
            let value = v.clone();
            match op {
                CmpOp::Eq | CmpOp::EqWhole => Predicate::Eq { path, value },
                CmpOp::Ne => Predicate::Not(Box::new(Predicate::Eq { path, value })),
                CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge => {
                    let (lower, upper) = match op {
                        CmpOp::Gt => (Bound::Excluded(value), Bound::Unbounded),
                        CmpOp::Ge => (Bound::Included(value), Bound::Unbounded),
                        CmpOp::Lt => (Bound::Unbounded, Bound::Excluded(value)),
                        _ => (Bound::Unbounded, Bound::Included(value)),
                    };
                    Predicate::Range { path, lower, upper }
                }
            }
        }
        BExpr::In {
            expr,
            list,
            negated,
        } => {
            let (Some(steps), BExpr::Const(Some(Value::Array(values)))) =
                (expr.static_path(), list.as_ref())
            else {
                return Predicate::Other;
            };
            let p = Predicate::In {
                path: stats_path(stats, steps),
                values: values.clone(),
            };
            if *negated {
                Predicate::Not(Box::new(p))
            } else {
                p
            }
        }
        BExpr::Is {
            expr,
            kind,
            negated,
        } => {
            let Some(steps) = expr.static_path() else {
                return Predicate::Other;
            };
            let path = stats_path(stats, steps);
            let p = match kind {
                IsKind::Null => Predicate::IsNull { path },
                IsKind::Missing => Predicate::IsMissing { path },
            };
            if *negated {
                Predicate::Not(Box::new(p))
            } else {
                p
            }
        }
        _ => Predicate::Other,
    }
}
