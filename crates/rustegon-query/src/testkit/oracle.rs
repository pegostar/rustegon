// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Test oracles in the style of the `SQLancer` tool: differential, TLP and `NoREC`.
//!
//! - **Differential**: the same statement on the engine under test and on the reference, from
//!   the same state, must give the same rows (module docs of [`super`] for the comparison
//!   rules), the same `affected` count, or errors with the same code; after a write the target
//!   collections must be identical.
//! - **TLP** (Rigger & Su, OOPSLA 2020): for a predicate `p` and a query `Q` without
//!   `WHERE`/`ORDER BY`/`LIMIT`, `Q` ≡ `Q WHERE p` ⊎ `Q WHERE NOT p` ⊎ `Q WHERE p IS NULL`
//!   (multisets). This holds because a generated predicate is always `true`, `false` or `null`
//!   (never `missing` or another type), and `IS NULL` matches exactly the unknown case.
//! - **`NoREC`** (Rigger & Su, ESEC/FSE 2020): `count(FROM c WHERE p)` equals the number of
//!   `true` values of `FROM c SELECT VALUE p` — the second form cannot use an index or a
//!   rewritten filter.
//!
//! Each oracle returns `Ok(Verdict)` or `Err(detail)` describing the disagreement.

use rustegon_common::Error;
use rustegon_doc::Value;

use super::{QueryEngine, is_unsupported, multiset, row_key, write_target};
use crate::{
    ast::{BinaryOp, Expr, IsTest, OrderItem, Query, Segment, Select, Statement},
    reference::{Output, Params},
};

/// Outcome of an oracle that found no disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Results compared and equal.
    Agreed,
    /// Both sides failed with the same error code.
    SameError,
    /// Skipped: a feature outside the implemented scope on some side.
    Unsupported,
}

/// How two row lists are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    /// Same rows in the same order.
    Sequence,
    /// Same rows, any order.
    Multiset,
    /// Same number of rows (an unordered `LIMIT` may pick any subset).
    Count,
}

/// The comparison a statement's result allows (see the [`super`] module docs).
#[must_use]
pub fn comparison(stmt: &Statement) -> Comparison {
    match stmt {
        Statement::Query(q) => {
            let total = q.order_by.last().is_some_and(|o| is_id_path(&o.expr, q));
            let bounded = q.limit.is_some() || q.offset.is_some();
            match (total, bounded) {
                (true, _) => Comparison::Sequence,
                (false, false) => Comparison::Multiset,
                (false, true) => Comparison::Count,
            }
        }
        // Writes visit documents in `_id` order, so `RETURNING` rows are ordered.
        _ => Comparison::Sequence,
    }
}

fn is_id_path(e: &Expr, q: &Query) -> bool {
    let Expr::Path { path } = e else { return false };
    let segs: Vec<&Segment> = path.0.iter().collect();
    match segs.as_slice() {
        [Segment::Field(id)] => id == "_id" && !aliases_id(q),
        [Segment::Field(a), Segment::Field(id)] => {
            id == "_id" && q.from.alias.as_deref() == Some(a.as_str())
        }
        _ => false,
    }
}

/// `ORDER BY _id` means a projected expression when `SELECT … AS _id` exists.
fn aliases_id(q: &Query) -> bool {
    matches!(&q.select, Some(Select::Items { items }) if items.iter().any(|p| matches!(
        p, crate::ast::Projection::Expr { alias: Some(a), .. } if a == "_id")))
}

/// Compares two row lists.
///
/// # Errors
/// A description of the first difference.
pub fn compare_rows(how: Comparison, expected: &[Value], actual: &[Value]) -> Result<(), String> {
    let (e, a) = match how {
        Comparison::Count => {
            if expected.len() == actual.len() {
                return Ok(());
            }
            return Err(format!(
                "row count: expected {}, got {}",
                expected.len(),
                actual.len()
            ));
        }
        Comparison::Sequence => (
            expected.iter().map(row_key).collect::<Vec<_>>(),
            actual.iter().map(row_key).collect(),
        ),
        Comparison::Multiset => (multiset(expected), multiset(actual)),
    };
    if e == a {
        return Ok(());
    }
    let first = e
        .iter()
        .zip(&a)
        .position(|(x, y)| x != y)
        .unwrap_or(e.len().min(a.len()));
    Err(format!(
        "{how:?} rows differ: expected {} rows, got {}; first difference at {first}: expected {}, got {}",
        e.len(),
        a.len(),
        e.get(first).map_or("<none>", String::as_str),
        a.get(first).map_or("<none>", String::as_str),
    ))
}

fn compare_results(
    stmt: &Statement,
    expected: &Result<Output, Error>,
    actual: &Result<Output, Error>,
) -> Result<Verdict, String> {
    match (expected, actual) {
        (Err(e), _) if is_unsupported(e) => Ok(Verdict::Unsupported),
        (_, Err(a)) if is_unsupported(a) => Ok(Verdict::Unsupported),
        (Err(e), Err(a)) if e.code() == a.code() => Ok(Verdict::SameError),
        (Err(e), Err(a)) => Err(format!("error codes differ: expected {e}, got {a}")),
        (Err(e), Ok(_)) => Err(format!("expected error {e}, got a result")),
        (Ok(_), Err(a)) => Err(format!("expected a result, got error {a}")),
        (Ok(e), Ok(a)) => {
            if e.affected != a.affected {
                return Err(format!(
                    "affected: expected {:?}, got {:?}",
                    e.affected, a.affected
                ));
            }
            compare_rows(comparison(stmt), &e.rows, &a.rows)?;
            Ok(Verdict::Agreed)
        }
    }
}

/// Differential oracle for one statement (engines must hold the same state).
///
/// # Errors
/// The disagreement, including a different collection state after a write.
pub fn differential(
    reference: &mut dyn QueryEngine,
    engine: &mut dyn QueryEngine,
    stmt: &Statement,
    params: &Params,
) -> Result<Verdict, String> {
    let expected = reference.run(stmt, params);
    let actual = engine.run(stmt, params);
    let verdict = compare_results(stmt, &expected, &actual)?;
    if verdict == Verdict::Unsupported {
        // A write that one side does not support was applied by the other side only, so the
        // collection states legitimately differ; the runner stops the case here.
        return Ok(verdict);
    }
    if let Some(coll) = write_target(stmt) {
        let scan = |e: &mut dyn QueryEngine| -> Result<Vec<Value>, String> {
            let mut docs = e.scan(&coll).map_err(|err| format!("scan failed: {err}"))?;
            docs.sort_by(|a, b| rustegon_doc::compare::compare(a.get("_id"), b.get("_id")));
            Ok(docs.into_iter().map(Value::Object).collect())
        };
        let (want, got) = (scan(reference)?, scan(engine)?);
        compare_rows(Comparison::Sequence, &want, &got)
            .map_err(|d| format!("collection state after the write: {d}"))?;
    }
    Ok(verdict)
}

/// The query `base` restricted to `filter`, with ordering and bounds removed.
fn variant(base: &Query, filter: Option<Expr>, select: Option<Select>) -> Statement {
    let mut q = base.clone();
    q.filter = filter;
    q.select = select;
    q.order_by = Vec::<OrderItem>::new();
    q.limit = None;
    q.offset = None;
    Statement::Query(q)
}

fn rows(
    engine: &mut dyn QueryEngine,
    stmt: &Statement,
    params: &Params,
) -> Result<Vec<Value>, Error> {
    engine.run(stmt, params).map(|o| o.rows)
}

/// TLP oracle: `Q` (with `query`'s `FROM` and `SELECT`) against its three partitions on `p`.
///
/// # Errors
/// The disagreement.
pub fn tlp(
    engine: &mut dyn QueryEngine,
    query: &Query,
    p: &Expr,
    params: &Params,
) -> Result<Verdict, String> {
    let select = query.select.clone();
    let all = variant(query, None, select.clone());
    let parts = [
        variant(query, Some(p.clone()), select.clone()),
        variant(
            query,
            Some(Expr::Not {
                expr: Box::new(p.clone()),
            }),
            select.clone(),
        ),
        variant(
            query,
            Some(Expr::Is {
                expr: Box::new(p.clone()),
                negated: false,
                test: IsTest::Null,
            }),
            select,
        ),
    ];
    let mut results = vec![rows(engine, &all, params)];
    for part in &parts {
        results.push(rows(engine, part, params));
    }
    if results
        .iter()
        .any(|r| r.as_ref().is_err_and(is_unsupported))
    {
        return Ok(Verdict::Unsupported);
    }
    let codes: Vec<_> = results[1..]
        .iter()
        .filter_map(|r| r.as_ref().err().map(Error::code))
        .collect();
    if !codes.is_empty() || results[0].is_err() {
        // An error in `p` must fail the three partitions alike (the unfiltered query does not
        // evaluate `p`, so it may succeed).
        let whole_ok_or_same = match &results[0] {
            Ok(_) => true,
            Err(e) => codes.first() == Some(&e.code()),
        };
        return if codes.len() == parts.len()
            && whole_ok_or_same
            && codes.iter().all(|c| *c == codes[0])
        {
            Ok(Verdict::SameError)
        } else {
            Err(format!("TLP: only some variants failed: {codes:?}"))
        };
    }
    let mut it = results.into_iter().flatten();
    let whole = it.next().unwrap_or_default();
    let union: Vec<Value> = it.flatten().collect();
    compare_rows(Comparison::Multiset, &whole, &union).map_err(|d| format!("TLP: {d}"))?;
    Ok(Verdict::Agreed)
}

/// `NoREC` oracle on predicate `p` over `query`'s `FROM`.
///
/// # Errors
/// The disagreement.
pub fn norec(
    engine: &mut dyn QueryEngine,
    query: &Query,
    p: &Expr,
    params: &Params,
) -> Result<Verdict, String> {
    let optimised = variant(query, Some(p.clone()), None);
    let unoptimised = variant(query, None, Some(Select::Value { expr: p.clone() }));
    let kept = rows(engine, &optimised, params);
    let values = rows(engine, &unoptimised, params);
    match (kept, values) {
        (Ok(kept), Ok(values)) => {
            let trues = values
                .iter()
                .filter(|v| matches!(v, Value::Bool(true)))
                .count();
            if kept.len() == trues {
                Ok(Verdict::Agreed)
            } else {
                Err(format!(
                    "NoREC: WHERE kept {} rows, SELECT VALUE gave {trues} true",
                    kept.len()
                ))
            }
        }
        (Err(err), _) | (_, Err(err)) if is_unsupported(&err) => Ok(Verdict::Unsupported),
        (Err(first), Err(second)) if first.code() == second.code() => Ok(Verdict::SameError),
        (Err(err), _) | (_, Err(err)) => Err(format!("NoREC: one form failed: {err}")),
    }
}

/// `p` with every `<=` turned into `<` — a planted bug used by the self-tests to check that the
/// oracles detect a wrong evaluator.
#[must_use]
pub fn plant_le_bug(e: &Expr) -> Expr {
    let mut out = e.clone();
    rewrite(&mut out);
    out
}

fn rewrite(e: &mut Expr) {
    match e {
        Expr::Binary { op, left, right } => {
            if *op == BinaryOp::Le {
                *op = BinaryOp::Lt;
            }
            rewrite(left);
            rewrite(right);
        }
        Expr::And { args } | Expr::Or { args } => args.iter_mut().for_each(rewrite),
        Expr::Not { expr } | Expr::Neg { expr } | Expr::Is { expr, .. } => rewrite(expr),
        _ => {}
    }
}
