// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Binding of read queries (query-language.md §3 `query`, §5).

use rustegon_common::Error;

use super::{Binder, BoundProjection, BoundQuery, BoundSelect, ExprBinder, SortKey, bind_options};
use crate::{
    ast::{Expr, Projection, Query, Segment, Select, Source},
    error::{ExecResult, invalid, type_error, unsupported},
    expr::{BExpr, Step},
    plan::rewrite::{fold_constant, normalize},
};

/// Binds a read query.
///
/// # Errors
/// See [`Binder::bind`](super::Binder::bind).
pub fn bind_query(b: &mut Binder<'_>, q: &Query) -> ExecResult<BoundQuery> {
    reject_m7(q)?;
    let Source::Collection(name) = &q.from.source else {
        return Err(unsupported("sub-query and map-reduce index sources", "M7").into());
    };
    if q.from.as_of.is_some() {
        return Err(
            unsupported("AS OF SYSTEM TIME (historical reads)", "a later milestone").into(),
        );
    }
    let target = b.target(name, true)?;
    let options = bind_options(b, &q.options, Some(&target))?;
    let mut eb = ExprBinder::new(b.params, q.from.alias.clone());
    let filter = match &q.filter {
        Some(f) => Some(normalize(eb.bind(f)?)),
        None => None,
    };
    let select = bind_select(&mut eb, q.select.as_ref())?;
    let mut order = Vec::with_capacity(q.order_by.len());
    for item in &q.order_by {
        let expr = match projection_alias(q.select.as_ref(), &select, &item.expr) {
            Some(e) => e.clone(),
            None => normalize(eb.bind(&item.expr)?),
        };
        order.push(SortKey {
            expr,
            descending: item.descending,
        });
    }
    let limit = match &q.limit {
        Some(e) => Some(count(&mut eb, e, "LIMIT")?),
        None => None,
    };
    let offset = match &q.offset {
        Some(e) => count(&mut eb, e, "OFFSET")?,
        None => 0,
    };
    Ok(BoundQuery {
        target,
        filter,
        select,
        order,
        limit,
        offset,
        options,
    })
}

fn reject_m7(q: &Query) -> Result<(), Error> {
    let feature = if !q.lookups.is_empty() {
        Some("LOOKUP (joins)")
    } else if !q.group_by.is_empty() || q.having.is_some() {
        Some("GROUP BY / HAVING (aggregation)")
    } else if !q.pipeline.is_empty() {
        Some("aggregation pipeline stages")
    } else if !q.include.is_empty() {
        Some("INCLUDE (related documents)")
    } else {
        None
    };
    feature.map_or(Ok(()), |f| Err(unsupported(f, "M7")))
}

/// `ORDER BY name` where `name` is an explicit `AS` alias of the projection: the aliased
/// expression (SQL resolves output aliases in `ORDER BY`). Only explicit aliases count: the
/// derived name of an unaliased item (`tags.0` is named `tags`) must not shadow the document
/// field of the same name (query-language.md §4.3; TC-QL-010 seed 6840335469013534960).
fn projection_alias<'s>(
    ast: Option<&Select>,
    select: &'s BoundSelect,
    e: &Expr,
) -> Option<&'s BExpr> {
    let Expr::Path { path } = e else { return None };
    let [Segment::Field(name)] = path.0.as_slice() else {
        return None;
    };
    let (Some(Select::Items { items: ast_items }), BoundSelect::Items(items)) = (ast, select)
    else {
        return None;
    };
    // `bind_items` binds one item per AST item, in order, so positions correspond.
    let at = ast_items
        .iter()
        .position(|p| matches!(p, Projection::Expr { alias: Some(a), .. } if a == name))?;
    match items.get(at) {
        Some(BoundProjection::Field { expr, .. }) => Some(expr),
        _ => None,
    }
}

/// A `LIMIT` / `OFFSET` count: a non-negative `int64` constant (parameters allowed); another
/// type is `RGN-1011`, a negative value `RGN-1001` (query-language.md §4.3).
pub(super) fn count(eb: &mut ExprBinder<'_>, e: &Expr, what: &str) -> ExecResult<u64> {
    match fold_constant(eb.bind(e)?) {
        Some(rustegon_doc::Value::Int64(i)) => {
            u64::try_from(i).map_err(|_| invalid(format!("{what} must not be negative")).into())
        }
        _ => Err(type_error(format!("{what} must be an integer")).into()),
    }
}

/// Binds a `SELECT` clause (also `RETURNING` items).
///
/// Output names: the alias, else the last field name of a path, else `_<position>` (1-based).
/// *Provisional (PD pending)*: the specification does not name unaliased computed columns;
/// duplicate output names are `RGN-1001`.
///
/// # Errors
/// `RGN-1011` / `RGN-1012` from expressions, `RGN-1001` for duplicate names or a computed
/// excluded path.
pub fn bind_select(eb: &mut ExprBinder<'_>, select: Option<&Select>) -> Result<BoundSelect, Error> {
    match select {
        None | Some(Select::Star) => Ok(BoundSelect::Document),
        Some(Select::Value { expr }) => Ok(BoundSelect::Value(normalize(eb.bind(expr)?))),
        Some(Select::Items { items }) => Ok(BoundSelect::Items(bind_items(eb, items)?)),
    }
}

/// Binds projection items (see [`bind_select`]).
///
/// # Errors
/// As [`bind_select`].
pub fn bind_items(
    eb: &mut ExprBinder<'_>,
    items: &[Projection],
) -> Result<Vec<BoundProjection>, Error> {
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        out.push(match item {
            Projection::Expr { expr, alias } => {
                let name = match alias {
                    Some(a) => a.clone(),
                    None => derived_name(expr).unwrap_or_else(|| format!("_{}", i + 1)),
                };
                let dup = out
                    .iter()
                    .any(|p| matches!(p, BoundProjection::Field { name: n, .. } if *n == name));
                if dup {
                    return Err(invalid(format!("duplicate output field {name}"))
                        .with_detail("field", name));
                }
                BoundProjection::Field {
                    name,
                    expr: normalize(eb.bind(expr)?),
                }
            }
            Projection::Wildcard { path } => BoundProjection::Wildcard(eb.bind_path(path)?),
            Projection::Exclude { path } => match eb.bind_path(path)? {
                BExpr::Field(steps) if steps.iter().all(|s| matches!(s, Step::Field { .. })) => {
                    BoundProjection::Exclude(steps)
                }
                _ => return Err(invalid("an excluded path must be a field path of the row")),
            },
        });
    }
    Ok(out)
}

/// The last field-name segment of a path (positions and `[expr]` are skipped: `tags.0` is
/// named `tags`), query-language.md §4.3.
fn derived_name(e: &Expr) -> Option<String> {
    match e {
        Expr::Path { path } | Expr::Access { path, .. } => {
            path.0.iter().rev().find_map(|s| match s {
                Segment::Field(n) => Some(n.clone()),
                _ => None,
            })
        }
        _ => None,
    }
}
