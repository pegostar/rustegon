// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Read queries (query-language.md §3 `query`, §5) of the reference interpreter.
//!
//! Evaluation order: scan the collection in `_id` order → `WHERE` (rows whose predicate is
//! `true`) → `ORDER BY` → `OFFSET` / `LIMIT` → `SELECT`.
//!
//! - **`ORDER BY`** keys are evaluated on the source row; a key that is a bare name equal to a
//!   `SELECT … AS name` alias means that projected expression (§9 example `ORDER BY s`). Keys
//!   compare in the §2.1 total order as whole values (arrays are not reduced to an element),
//!   `missing` first ascending. Ties keep `_id` order (stable sort over an `_id`-ordered scan).
//! - **`LIMIT` / `OFFSET`** are evaluated once, without a row; a non-integer is `RGN-1011`, a
//!   negative value `RGN-1001`.
//! - **`SELECT`** (*Provisional*): `expr AS name` sets `name` (omitted when `missing`); an
//!   un-aliased path is named after its last field segment (`o.customer.name` → `name`,
//!   `tags.0` → `tags`), any other un-aliased expression `_<position>` (1-based; `$` cannot
//!   start a stored field name, data-model §2.2); two items with the same output name are
//!   `RGN-1001`; `path.*` merges the fields of the object at `path` (overwriting in place). `-path`
//!   items remove fields: from the projected document when there are other items, from the whole
//!   row when all items are exclusions. `_id` is not added implicitly. `SELECT VALUE e` rows are
//!   the values of `e` (`null` when `missing`).

use rustegon_common::Error;
use rustegon_doc::{Document, Value, compare::compare};

use super::{
    Reference,
    error::{invalid, type_error, unsupported},
    eval::{Ctx, Env, Tri, eval, truth},
};
use crate::ast::{Expr, OrderItem, Projection, Query, Segment, Select, Source};

/// Runs a read query.
///
/// # Errors
/// Expression errors, `LIMIT`/`OFFSET` errors, unsupported clauses.
pub fn run(r: &Reference, q: &Query, ctx: &Ctx<'_>) -> Result<Vec<Value>, Error> {
    check_scope(q)?;
    if let Some(Select::Items { items }) = &q.select {
        check_names(items)?;
    }
    let Source::Collection(name) = &q.from.source else {
        return Err(unsupported("sub-query and index sources"));
    };
    let alias = q.from.alias.as_deref();
    let rows = filter(r.collection(name), q.filter.as_ref(), alias, ctx)?;
    let rows = order(rows, &q.order_by, q.select.as_ref(), alias, ctx)?;
    let rows = limit(rows, q.limit.as_ref(), q.offset.as_ref(), ctx)?;
    rows.iter()
        .map(|row| select(q.select.as_ref(), row, alias, ctx))
        .collect()
}

fn check_scope(q: &Query) -> Result<(), Error> {
    let what = if !q.lookups.is_empty() {
        "LOOKUP"
    } else if !q.group_by.is_empty() || q.having.is_some() {
        "GROUP BY / HAVING"
    } else if !q.include.is_empty() {
        "INCLUDE"
    } else if !q.pipeline.is_empty() {
        "pipeline stages"
    } else if q.from.as_of.is_some() {
        "AS OF SYSTEM TIME"
    } else {
        return Ok(());
    };
    Err(unsupported(what))
}

/// Rows (as objects) whose predicate is `true`, in input order.
///
/// # Errors
/// Expression errors.
pub fn filter(
    docs: &[Document],
    predicate: Option<&Expr>,
    alias: Option<&str>,
    ctx: &Ctx<'_>,
) -> Result<Vec<Value>, Error> {
    let mut out = Vec::new();
    for d in docs {
        let row = Value::Object(d.clone());
        let keep = match predicate {
            Some(p) => truth(p, &Env::new(ctx, &row, alias))? == Tri::True,
            None => true,
        };
        if keep {
            out.push(row);
        }
    }
    Ok(out)
}

fn order(
    rows: Vec<Value>,
    items: &[OrderItem],
    select: Option<&Select>,
    alias: Option<&str>,
    ctx: &Ctx<'_>,
) -> Result<Vec<Value>, Error> {
    if items.is_empty() {
        return Ok(rows);
    }
    let keys: Vec<&Expr> = items
        .iter()
        .map(|i| resolve_alias(&i.expr, select))
        .collect();
    let mut keyed = Vec::with_capacity(rows.len());
    for row in rows {
        let env = Env::new(ctx, &row, alias);
        let k: Vec<Option<Value>> = keys
            .iter()
            .map(|e| eval(e, &env))
            .collect::<Result<_, _>>()?;
        keyed.push((k, row));
    }
    // Stable: equal keys keep the `_id` order of the scan.
    keyed.sort_by(|(a, _), (b, _)| {
        items
            .iter()
            .zip(a.iter().zip(b))
            .map(|(item, (x, y))| {
                let o = compare(x.as_ref(), y.as_ref());
                if item.descending { o.reverse() } else { o }
            })
            .find(|o| o.is_ne())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(keyed.into_iter().map(|(_, row)| row).collect())
}

/// An `ORDER BY` key naming a `SELECT` alias stands for the aliased expression.
fn resolve_alias<'q>(key: &'q Expr, select: Option<&'q Select>) -> &'q Expr {
    let (Expr::Path { path }, Some(Select::Items { items })) = (key, select) else {
        return key;
    };
    let [Segment::Field(name)] = path.0.as_slice() else {
        return key;
    };
    items
        .iter()
        .find_map(|p| match p {
            Projection::Expr {
                expr,
                alias: Some(a),
            } if a == name => Some(expr),
            _ => None,
        })
        .unwrap_or(key)
}

/// Applies `OFFSET` then `LIMIT`.
///
/// # Errors
/// `RGN-1011` for a non-integer count, `RGN-1001` for a negative one.
pub fn limit(
    rows: Vec<Value>,
    limit: Option<&Expr>,
    offset: Option<&Expr>,
    ctx: &Ctx<'_>,
) -> Result<Vec<Value>, Error> {
    let skip = count(offset, ctx)?.unwrap_or(0);
    let take = count(limit, ctx)?.unwrap_or(usize::MAX);
    Ok(rows.into_iter().skip(skip).take(take).collect())
}

fn count(e: Option<&Expr>, ctx: &Ctx<'_>) -> Result<Option<usize>, Error> {
    let Some(e) = e else { return Ok(None) };
    let empty = Value::Object(Document::new());
    match eval(e, &Env::new(ctx, &empty, None))? {
        Some(Value::Int64(n)) => usize::try_from(n)
            .map(Some)
            .map_err(|_| invalid("LIMIT/OFFSET must not be negative")),
        _ => Err(type_error("LIMIT/OFFSET must be an integer")),
    }
}

/// Projects one row.
///
/// # Errors
/// Expression errors.
pub fn select(
    select: Option<&Select>,
    row: &Value,
    alias: Option<&str>,
    ctx: &Ctx<'_>,
) -> Result<Value, Error> {
    let env = Env::new(ctx, row, alias);
    match select {
        None | Some(Select::Star) => Ok(row.clone()),
        Some(Select::Value { expr }) => Ok(eval(expr, &env)?.unwrap_or(Value::Null)),
        Some(Select::Items { items }) => project(items, &env),
    }
}

/// Builds the projected document of `items` (module docs).
///
/// # Errors
/// Expression errors.
pub fn project(items: &[Projection], env: &Env<'_>) -> Result<Value, Error> {
    check_names(items)?;
    let only_excludes = items
        .iter()
        .all(|p| matches!(p, Projection::Exclude { .. }));
    let mut out = if only_excludes {
        match env.row {
            Value::Object(d) => d.clone(),
            _ => Document::new(),
        }
    } else {
        Document::new()
    };
    for (i, item) in items.iter().enumerate() {
        match item {
            Projection::Expr { expr, alias } => {
                if let Some(v) = eval(expr, env)? {
                    out.insert(output_name(expr, alias.as_deref(), i), v);
                }
            }
            Projection::Wildcard { path } => {
                if let Some(Value::Object(d)) = eval(&Expr::Path { path: path.clone() }, env)? {
                    for (k, v) in d.iter() {
                        out.insert(k, v.clone());
                    }
                }
            }
            Projection::Exclude { .. } => {}
        }
    }
    for item in items {
        if let Projection::Exclude { path } = item {
            remove_path(&mut out, &path.0, env.alias);
        }
    }
    Ok(Value::Object(out))
}

/// `RGN-1001` when two `expr [AS name]` items have the same output name.
fn check_names(items: &[Projection]) -> Result<(), Error> {
    let mut seen: Vec<String> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if let Projection::Expr { expr, alias } = item {
            let name = output_name(expr, alias.as_deref(), i);
            if seen.contains(&name) {
                return Err(invalid(format!("duplicate output field {name}")));
            }
            seen.push(name);
        }
    }
    Ok(())
}

fn output_name(expr: &Expr, alias: Option<&str>, position: usize) -> String {
    if let Some(a) = alias {
        return a.to_owned();
    }
    if let Expr::Path { path } | Expr::Access { path, .. } = expr
        && let Some(Segment::Field(name)) =
            path.0.iter().rev().find(|s| matches!(s, Segment::Field(_)))
    {
        return name.clone();
    }
    format!("_{}", position + 1)
}

/// Removes a field path (object fields only; a leading `FROM` alias is skipped).
fn remove_path(doc: &mut Document, segments: &[Segment], alias: Option<&str>) {
    let segments = match segments.split_first() {
        Some((Segment::Field(first), rest))
            if Some(first.as_str()) == alias && !rest.is_empty() =>
        {
            rest
        }
        _ => segments,
    };
    match segments {
        [Segment::Field(last)] => {
            doc.remove(last);
        }
        [Segment::Field(head), rest @ ..] => {
            if let Some(Value::Object(inner)) = doc.get_mut(head) {
                remove_path(inner, rest, None);
            }
        }
        _ => {}
    }
}
