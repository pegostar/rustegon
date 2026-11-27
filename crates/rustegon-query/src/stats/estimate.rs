// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Cardinality estimation (query-engine.md §3): selectivity of a predicate over one
//! collection's [`CollectionStats`].
//!
//! [`Predicate`] is a deliberately small description, independent of the planner's types:
//! the optimizer (wave 3) translates its normalized filter into it. Rules:
//! - `=` — MCV frequency if the value is an MCV; `null` → fraction of null rows; otherwise the
//!   non-MCV mass spread uniformly over the non-MCV distinct values
//!   (`histogram mass / max(1, NDV − |MCV|)`).
//! - `IN` — sum over the distinct listed values (capped at 1).
//! - range — MCVs inside the bounds plus the histogram's interpolated fraction. Bounds are
//!   compared in the §2.1 total order; type bracketing (if the language requires it) is the
//!   caller's business: it passes bounds of the same order class (e.g. `[5, +Infinity]`).
//!   `null` and `missing` never satisfy a range.
//! - `IS NULL` — null or missing rows (data-model.md §2.1); `IS MISSING` — missing rows.
//! - `AND` — **exponential damping**: selectivities sorted ascending, `s1 × s2^½ × s3^¼ × …`
//!   (each further term with half the previous exponent).
//! - `OR` — `1 − Π(1 − sᵢ)` (independence); *Provisional (PD pending)*: the spec only names
//!   damping for conjunctions.
//! - `NOT` — `1 − s` (ignores three-valued logic: an upper bound for `NOT` over null-free data).
//! - A field without statistics falls back to fixed defaults ([`DEFAULT_EQ`], …).

use std::ops::Bound;

use rustegon_doc::{
    Value,
    keyenc::{Direction, encode_element},
};

use super::{
    clamp01,
    model::{CollectionStats, FieldStats},
    to_f64,
};

/// Selectivity of `=` without statistics (PostgreSQL's `DEFAULT_EQ_SEL`).
pub const DEFAULT_EQ: f64 = 0.005;
/// Selectivity of a range without statistics (PostgreSQL's `DEFAULT_INEQ_SEL`).
pub const DEFAULT_RANGE: f64 = 1.0 / 3.0;
/// Selectivity of `IS NULL` / `IS MISSING` without statistics.
pub const DEFAULT_NULL: f64 = 0.005;
/// Selectivity of a predicate the estimator does not understand.
pub const DEFAULT_OTHER: f64 = 0.25;

/// A selectivity in `[0, 1]`.
pub type Selectivity = f64;

/// A predicate over one collection's documents, as far as the estimator needs it.
#[derive(Debug, Clone, PartialEq)]
pub enum Predicate {
    /// `path = value`.
    Eq {
        /// Field path.
        path: String,
        /// Compared value.
        value: Value,
    },
    /// `path IN (values)`.
    In {
        /// Field path.
        path: String,
        /// Listed values.
        values: Vec<Value>,
    },
    /// `path` within bounds (§2.1 order).
    Range {
        /// Field path.
        path: String,
        /// Lower bound.
        lower: Bound<Value>,
        /// Upper bound.
        upper: Bound<Value>,
    },
    /// `path IS NULL` (null or missing).
    IsNull {
        /// Field path.
        path: String,
    },
    /// `path IS MISSING`.
    IsMissing {
        /// Field path.
        path: String,
    },
    /// Conjunction.
    And(Vec<Predicate>),
    /// Disjunction.
    Or(Vec<Predicate>),
    /// Negation.
    Not(Box<Predicate>),
    /// Anything else (functions, cross-field comparisons, …).
    Other,
}

/// Key encoding of a value (`None` for the non-encodable `counter`).
fn encode(v: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    encode_element(&mut out, Some(v), Direction::Ascending).ok()?;
    Some(out)
}

/// Estimated selectivity of `pred` (module docs).
#[must_use]
pub fn selectivity(stats: &CollectionStats, pred: &Predicate) -> Selectivity {
    let field = |p: &str| stats.field(p).filter(|_| stats.row_count > 0);
    let s = match pred {
        Predicate::Eq { path, value } => {
            field(path).map_or(DEFAULT_EQ, |f| eq_selectivity(f, stats.row_count, value))
        }
        Predicate::In { path, values } => {
            // Distinct values only: `IN (1, 1.0)` is one value.
            let mut seen: Vec<Option<Vec<u8>>> = Vec::new();
            let distinct: Vec<&Value> = values
                .iter()
                .filter(|v| {
                    let k = encode(v);
                    let fresh = !seen.contains(&k);
                    if fresh {
                        seen.push(k);
                    }
                    fresh
                })
                .collect();
            field(path).map_or(DEFAULT_EQ * to_f64(distinct.len() as u64), |f| {
                distinct
                    .iter()
                    .map(|v| eq_selectivity(f, stats.row_count, v))
                    .sum()
            })
        }
        Predicate::Range { path, lower, upper } => field(path).map_or(DEFAULT_RANGE, |f| {
            range_selectivity(f, lower.as_ref(), upper.as_ref())
        }),
        Predicate::IsNull { path } => field(path).map_or(DEFAULT_NULL, |f| {
            to_f64(f.rows_null + f.rows_missing) / to_f64(stats.row_count)
        }),
        Predicate::IsMissing { path } => field(path).map_or(DEFAULT_NULL, |f| {
            to_f64(f.rows_missing) / to_f64(stats.row_count)
        }),
        Predicate::And(items) => damped_and(items.iter().map(|p| selectivity(stats, p)).collect()),
        Predicate::Or(items) => {
            1.0 - items
                .iter()
                .map(|p| 1.0 - selectivity(stats, p))
                .product::<f64>()
        }
        Predicate::Not(inner) => 1.0 - selectivity(stats, inner),
        Predicate::Other => DEFAULT_OTHER,
    };
    clamp01(s)
}

/// Estimated number of matching rows: `row_count × selectivity`.
#[must_use]
pub fn estimate_rows(stats: &CollectionStats, pred: &Predicate) -> f64 {
    to_f64(stats.row_count) * selectivity(stats, pred)
}

/// Conjunction with exponential damping (query-engine.md §3): sorted ascending,
/// `s1 × s2^(1/2) × s3^(1/4) × …`. Empty → 1.
#[must_use]
pub fn damped_and(mut sels: Vec<Selectivity>) -> Selectivity {
    for s in &mut sels {
        *s = clamp01(*s);
    }
    sels.sort_by(f64::total_cmp);
    let mut exponent = 1.0;
    let mut out = 1.0;
    for s in sels {
        out *= s.powf(exponent);
        exponent /= 2.0;
    }
    out
}

fn eq_selectivity(f: &FieldStats, rows: u64, value: &Value) -> Selectivity {
    if matches!(value, Value::Null) {
        return to_f64(f.rows_null) / to_f64(rows);
    }
    let Some(key) = encode(value) else {
        return 0.0;
    };
    if let Some(m) = f.mcv.iter().find(|m| m.value == key) {
        return m.fraction;
    }
    let rest = f.histogram.total_fraction();
    if rest <= 0.0 {
        // The sample saw only MCVs: a value outside them is rare (not impossible when sampled).
        return 0.0;
    }
    let others = f.ndv.saturating_sub(f.mcv.len() as u64).max(1);
    rest / to_f64(others)
}

fn range_selectivity(f: &FieldStats, lower: Bound<&Value>, upper: Bound<&Value>) -> Selectivity {
    let enc = |b: Bound<&Value>| -> Option<Bound<Vec<u8>>> {
        Some(match b {
            Bound::Unbounded => Bound::Unbounded,
            Bound::Included(v) => Bound::Included(encode(v)?),
            Bound::Excluded(v) => Bound::Excluded(encode(v)?),
        })
    };
    let (Some(lo), Some(hi)) = (enc(lower), enc(upper)) else {
        return DEFAULT_RANGE;
    };
    let (lo, hi) = (as_slice(&lo), as_slice(&hi));
    let mcv: f64 = f
        .mcv
        .iter()
        .filter(|m| in_bounds(&m.value, lo, hi))
        .map(|m| m.fraction)
        .sum();
    mcv + f.histogram.range_fraction(lo, hi)
}

fn as_slice(b: &Bound<Vec<u8>>) -> Bound<&[u8]> {
    match b {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(v) => Bound::Included(v),
        Bound::Excluded(v) => Bound::Excluded(v),
    }
}

fn in_bounds(v: &[u8], lo: Bound<&[u8]>, hi: Bound<&[u8]>) -> bool {
    (match lo {
        Bound::Unbounded => true,
        Bound::Included(x) => v >= x,
        Bound::Excluded(x) => v > x,
    }) && (match hi {
        Bound::Unbounded => true,
        Bound::Included(x) => v <= x,
        Bound::Excluded(x) => v < x,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damping_sorts_ascending_and_halves_exponents() {
        let s = damped_and(vec![0.5, 0.1, 0.2, 0.8]);
        let expected = 0.1 * 0.2f64.sqrt() * 0.5f64.powf(0.25) * 0.8f64.powf(0.125);
        assert!((s - expected).abs() < 1e-12, "{s} vs {expected}");
        assert!((damped_and(vec![]) - 1.0).abs() < 1e-12);
        assert!((damped_and(vec![0.3]) - 0.3).abs() < 1e-12);
        // Damping is never more selective than independence.
        assert!(damped_and(vec![0.1, 0.1]) >= 0.01);
    }

    #[test]
    fn defaults_without_stats() {
        let stats = CollectionStats {
            database_id: 1,
            collection_id: 1,
            row_count: 0,
            total_bytes: 0,
            sample_rows: 0,
            collected_at_ms: 0,
            fields: vec![],
            indexes: vec![],
        };
        let eq = Predicate::Eq {
            path: "a".into(),
            value: Value::Int64(1),
        };
        assert!((selectivity(&stats, &eq) - DEFAULT_EQ).abs() < 1e-12);
        let or = Predicate::Or(vec![eq.clone(), eq.clone()]);
        let expected = 1.0 - (1.0 - DEFAULT_EQ) * (1.0 - DEFAULT_EQ);
        assert!((selectivity(&stats, &or) - expected).abs() < 1e-12);
        let not = Predicate::Not(Box::new(eq));
        assert!((selectivity(&stats, &not) - (1.0 - DEFAULT_EQ)).abs() < 1e-12);
        assert!((selectivity(&stats, &Predicate::Other) - DEFAULT_OTHER).abs() < 1e-12);
    }
}
