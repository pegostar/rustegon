// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Access-path analysis (query-engine.md §4, indexing.md §3): sargable predicates, index key
//! ranges and the ESR prefix match.
//!
//! **Bounds.** An index is matched field by field in key order: equality (`=`, `==`, `IN`)
//! predicates extend the key prefix (`IN` multiplies it into several point prefixes, at most
//! [`MAX_RANGES`]); the first field without an equality may take a range (`<`, `<=`, `>`, `>=`,
//! `IS NULL` = `[missing, null]`), after which matching stops. A descending field swaps its
//! lower and upper bound, because "lower" in key order is the larger value.
//!
//! **Exactness.** A conjunct the key range implements exactly does not need re-evaluation
//! (it leaves the residual filter); every other conjunct stays. Never exact: anything on a
//! multikey or wildcard index (a document has several entries; per-element semantics differ
//! from conjunctions of per-predicate "any element" tests), and a one-sided `<`/`<=` (the scan
//! then starts at the prefix and also sees `missing`/`null`). Multikey indexes take at most one
//! range predicate per field, since `tags > 1 AND tags < 5` may hold through two different
//! elements. Hits flagged `truncated` are always re-checked against the whole predicate.
//!
//! **Validity.** Bounds are only built from constants that are neither `null` nor arrays: an
//! array constant compares as a whole value, which no index entry of a multikey index holds.
//! A sparse index is used only when a used predicate excludes `missing`; a partial index only
//! when every conjunct of its predicate is a conjunct of the query; a wildcard index only for
//! equality on scalar constants (its entries are leaves, so ranges could miss whole objects).

use std::{cmp::Ordering, collections::BTreeSet, ops::Bound};

use rustegon_catalog::{IndexDescriptor, IndexOrder};
use rustegon_doc::{
    Value,
    compare::{compare, values_equal},
    limits::SERVER_MAINTAINED_FIELDS,
    path::{FieldPath, Segment},
};

use crate::expr::{BExpr, CmpOp, IsKind, Step};

/// Maximum number of key ranges (point prefixes) an `IN` list may expand into.
pub const MAX_RANGES: usize = 256;

/// A key range in index key order (tuples are prefixes of the key, `None` = `missing`).
#[derive(Debug, Clone, PartialEq)]
pub struct KeyRange {
    /// Lower bound.
    pub lower: Bound<Vec<Option<Value>>>,
    /// Upper bound.
    pub upper: Bound<Vec<Option<Value>>>,
}

/// What a sargable conjunct asks of one field.
#[derive(Debug, Clone, PartialEq)]
pub enum SargKind {
    /// `= v`.
    Eq(Value),
    /// `IN [v…]` (deduplicated, non-null, non-array).
    In(Vec<Value>),
    /// `< <= > >= v`.
    Range(CmpOp, Value),
    /// `IS NULL`.
    IsNull,
}

/// A sargable conjunct.
#[derive(Debug, Clone, PartialEq)]
pub struct Sarg {
    /// Field path.
    pub path: Vec<Step>,
    /// Predicate.
    pub kind: SargKind,
    /// Index of the conjunct.
    pub conjunct: usize,
}

fn usable_const(v: &Value) -> bool {
    !matches!(v, Value::Null | Value::Array(_))
}

/// The sargable conjuncts.
#[must_use]
pub fn extract_sargs(conjuncts: &[&BExpr]) -> Vec<Sarg> {
    let mut out = Vec::new();
    for (i, c) in conjuncts.iter().enumerate() {
        let (path, kind) = match c {
            BExpr::Cmp { op, left, right } => {
                let (Some(path), BExpr::Const(Some(v))) = (left.static_path(), right.as_ref())
                else {
                    continue;
                };
                if !usable_const(v) {
                    continue;
                }
                let kind = match op {
                    CmpOp::Eq | CmpOp::EqWhole => SargKind::Eq(v.clone()),
                    CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge => {
                        SargKind::Range(*op, v.clone())
                    }
                    CmpOp::Ne => continue,
                };
                (path, kind)
            }
            BExpr::In {
                expr,
                list,
                negated: false,
            } => {
                let (Some(path), BExpr::Const(Some(Value::Array(items)))) =
                    (expr.static_path(), list.as_ref())
                else {
                    continue;
                };
                if items.iter().any(|v| matches!(v, Value::Array(_))) {
                    continue;
                }
                let mut vals: Vec<Value> = Vec::new();
                for v in items.iter().filter(|v| !matches!(v, Value::Null)) {
                    if !vals.iter().any(|x| values_equal(Some(x), Some(v))) {
                        vals.push(v.clone());
                    }
                }
                vals.sort_by(|a, b| compare(Some(a), Some(b)));
                (path, SargKind::In(vals))
            }
            BExpr::Is {
                expr,
                kind: IsKind::Null,
                negated: false,
            } => match expr.static_path() {
                Some(path) => (path, SargKind::IsNull),
                None => continue,
            },
            _ => continue,
        };
        out.push(Sarg {
            path: path.to_vec(),
            kind,
            conjunct: i,
        });
    }
    out
}

/// Whether `steps` denotes the index path `segs`.
#[must_use]
pub fn same_path(steps: &[Step], segs: &[Segment]) -> bool {
    steps.len() == segs.len()
        && steps.iter().zip(segs).all(|(s, g)| match s {
            Step::Field { name, index } => *name == g.name && *index == g.index,
            Step::Dyn(_) => false,
        })
}

/// How an index serves a query.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexMatch {
    /// Key ranges, in key order.
    pub ranges: Vec<KeyRange>,
    /// Leading fields constrained by equality.
    pub eq_fields: usize,
    /// Leading fields constrained by a single-value equality (sort can skip them).
    pub single_eq_fields: usize,
    /// A range predicate was used on the next field.
    pub range: bool,
    /// Conjuncts used for bounds.
    pub used: BTreeSet<usize>,
    /// Conjuncts the ranges implement exactly.
    pub exact: BTreeSet<usize>,
}

/// One side of a range on a single field.
type Side = Bound<Option<Value>>;

/// The tighter of two bounds of the same side (`lower`: the larger value wins; on equal values
/// an exclusive bound wins).
fn tighter(cur: &Side, cand: Side, lower: bool) -> Side {
    let (a, b) = (cur, cand);
    match (a, &b) {
        (Bound::Unbounded, _) => b,
        (_, Bound::Unbounded) => a.clone(),
        (
            Bound::Included(cur_v) | Bound::Excluded(cur_v),
            Bound::Included(cand_v) | Bound::Excluded(cand_v),
        ) => match compare(cur_v.as_ref(), cand_v.as_ref()) {
            Ordering::Equal => {
                if matches!(b, Bound::Excluded(_)) {
                    b
                } else {
                    a.clone()
                }
            }
            ord if (ord == Ordering::Less) == lower => b,
            _ => a.clone(),
        },
    }
}

/// Matches a non-wildcard index against the sargable conjuncts (module docs).
#[must_use]
pub fn match_index(ix: &IndexDescriptor, sargs: &[Sarg]) -> Option<IndexMatch> {
    let paths: Vec<FieldPath> = ix
        .fields
        .iter()
        .map(|f| FieldPath::parse(&f.path))
        .collect::<Result<_, _>>()
        .ok()?;
    let exact_ok = !ix.multikey;
    let mut m = IndexMatch {
        ranges: Vec::new(),
        eq_fields: 0,
        single_eq_fields: 0,
        range: false,
        used: BTreeSet::new(),
        exact: BTreeSet::new(),
    };
    let mut prefixes: Vec<Vec<Option<Value>>> = vec![Vec::new()];
    let mut multi = false;
    let mut range: Option<(usize, Side, Side)> = None;
    for (k, path) in paths.iter().enumerate() {
        let preds: Vec<&Sarg> = sargs
            .iter()
            .filter(|s| same_path(&s.path, path.segments()))
            .collect();
        if let Some(s) = preds.iter().find(|s| matches!(s.kind, SargKind::Eq(_))) {
            let SargKind::Eq(v) = &s.kind else { continue };
            for p in &mut prefixes {
                p.push(Some(v.clone()));
            }
            m.eq_fields += 1;
            if !multi {
                m.single_eq_fields += 1;
            }
            m.used.insert(s.conjunct);
            if exact_ok {
                m.exact.insert(s.conjunct);
            }
            continue;
        }
        if let Some(s) = preds
            .iter()
            .find(|s| matches!(&s.kind, SargKind::In(v) if !v.is_empty()))
            && let SargKind::In(vals) = &s.kind
            && prefixes.len() * vals.len() <= MAX_RANGES
        {
            prefixes = prefixes
                .iter()
                .flat_map(|p| {
                    vals.iter().map(move |v| {
                        let mut q = p.clone();
                        q.push(Some(v.clone()));
                        q
                    })
                })
                .collect();
            multi = true;
            m.eq_fields += 1;
            m.used.insert(s.conjunct);
            if exact_ok {
                m.exact.insert(s.conjunct);
            }
            continue;
        }
        range = range_on_field(k, &preds, ix.multikey, &mut m);
        break;
    }
    if m.used.is_empty() {
        return None;
    }
    let desc = |k: usize| {
        ix.fields
            .get(k)
            .is_some_and(|f| f.order == IndexOrder::Desc)
    };
    for p in prefixes {
        let (lo, hi) = match &range {
            Some((k, lo, hi)) if desc(*k) => (hi.clone(), lo.clone()),
            Some((_, lo, hi)) => (lo.clone(), hi.clone()),
            None => (Bound::Unbounded, Bound::Unbounded),
        };
        m.ranges.push(KeyRange {
            lower: extend(&p, lo),
            upper: extend(&p, hi),
        });
    }
    Some(m)
}

/// The range a field's predicates allow (module docs), recording used and exact conjuncts.
fn range_on_field(
    k: usize,
    preds: &[&Sarg],
    multikey: bool,
    m: &mut IndexMatch,
) -> Option<(usize, Side, Side)> {
    if let Some(s) = preds.iter().find(|s| s.kind == SargKind::IsNull)
        && !preds.iter().any(|s| matches!(s.kind, SargKind::Range(..)))
    {
        m.used.insert(s.conjunct);
        if !multikey {
            m.exact.insert(s.conjunct);
        }
        m.range = true;
        return Some((k, Bound::Included(None), Bound::Included(Some(Value::Null))));
    }
    let (mut lo, mut hi): (Side, Side) = (Bound::Unbounded, Bound::Unbounded);
    let mut used = Vec::new();
    for s in preds {
        let SargKind::Range(op, v) = &s.kind else {
            continue;
        };
        if multikey && !used.is_empty() {
            break;
        }
        let v = Some(v.clone());
        match op {
            CmpOp::Gt => lo = tighter(&lo, Bound::Excluded(v), true),
            CmpOp::Ge => lo = tighter(&lo, Bound::Included(v), true),
            CmpOp::Lt => hi = tighter(&hi, Bound::Excluded(v), false),
            _ => hi = tighter(&hi, Bound::Included(v), false),
        }
        used.push((s.conjunct, *op));
    }
    if used.is_empty() {
        return None;
    }
    let has_lower = !matches!(lo, Bound::Unbounded);
    for (c, op) in used {
        m.used.insert(c);
        let exact = !multikey && (matches!(op, CmpOp::Gt | CmpOp::Ge) || has_lower);
        if exact {
            m.exact.insert(c);
        }
    }
    m.range = true;
    Some((k, lo, hi))
}

fn extend(prefix: &[Option<Value>], side: Side) -> Bound<Vec<Option<Value>>> {
    let with = |v: Option<Value>| {
        let mut t = prefix.to_vec();
        t.push(v);
        t
    };
    match side {
        Bound::Unbounded if prefix.is_empty() => Bound::Unbounded,
        Bound::Unbounded => Bound::Included(prefix.to_vec()),
        Bound::Included(v) => Bound::Included(with(v)),
        Bound::Excluded(v) => Bound::Excluded(with(v)),
    }
}

/// Matches a wildcard index: equality on one scalar field below its prefix (module docs).
#[must_use]
pub fn match_wildcard(ix: &IndexDescriptor, sargs: &[Sarg]) -> Option<IndexMatch> {
    let field = ix.fields.first()?;
    let prefix_text = field.wildcard_prefix();
    let prefix = match prefix_text {
        Some(p) => FieldPath::parse(p).ok()?.segments().to_vec(),
        None => Vec::new(),
    };
    for s in sargs {
        let values: Vec<Value> = match &s.kind {
            SargKind::Eq(v) if !matches!(v, Value::Object(_)) => vec![v.clone()],
            SargKind::In(vs)
                if !vs.is_empty() && vs.iter().all(|v| !matches!(v, Value::Object(_))) =>
            {
                vs.clone()
            }
            _ => continue,
        };
        let Some(text) = wildcard_leaf(&s.path, &prefix, prefix_text) else {
            continue;
        };
        if values.len() > MAX_RANGES {
            continue;
        }
        let ranges = values
            .into_iter()
            .map(|v| {
                let t = vec![Some(Value::String(text.clone())), Some(v)];
                KeyRange {
                    lower: Bound::Included(t.clone()),
                    upper: Bound::Included(t),
                }
            })
            .collect();
        return Some(IndexMatch {
            ranges,
            eq_fields: 1,
            single_eq_fields: 0,
            range: false,
            used: BTreeSet::from([s.conjunct]),
            exact: BTreeSet::new(),
        });
    }
    None
}

/// The leaf path string of `steps` in a wildcard index with `prefix` (as rustegon-index writes
/// it: the prefix as written, then each segment, backtick-quoted when it contains a dot).
fn wildcard_leaf(steps: &[Step], prefix: &[Segment], prefix_text: Option<&str>) -> Option<String> {
    if steps.len() <= prefix.len() || !same_path(&steps[..prefix.len()], prefix) {
        return None;
    }
    let mut text = prefix_text.unwrap_or_default().to_owned();
    for (i, s) in steps[prefix.len()..].iter().enumerate() {
        let Step::Field { name, index: None } = s else {
            return None;
        };
        if prefix.is_empty()
            && i == 0
            && (name == "_id" || SERVER_MAINTAINED_FIELDS.contains(&name.as_str()))
        {
            // Whole-document wildcards skip `_id` and the server-maintained fields.
            return None;
        }
        if !text.is_empty() {
            text.push('.');
        }
        if name.contains('.') {
            text.push('`');
            text.push_str(name);
            text.push('`');
        } else {
            text.push_str(name);
        }
    }
    Some(text)
}
