// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Binding of write statements (query-language.md §3, §6; data-model.md §2.3).
//!
//! *Provisional (PD pending)* choices:
//! - `PUSH p VALUE v` and `ADD TO SET p VALUE v` add `v` as **one** element (an array value is
//!   not spread; MongoDB needs `$each` for that as well);
//! - `PUSH … SORT k` sorts by `k` relative to the element; a key equal to the target path sorts
//!   the elements themselves;
//! - in `UPDATE`, every value expression is evaluated against the document **before** the
//!   update (SQL semantics), then the operator list is applied atomically;
//! - `INSERT` / `UPSERT` value expressions cannot read a row (`RGN-1011`);
//! - `ON CONFLICT DO UPDATE` applies to `_id` conflicts; a conflict on another unique index is
//!   still `RGN-1005`.

use rustegon_common::{Error, ErrorCode};

use super::{
    Binder, BoundDelete, BoundQuery, BoundReturning, BoundSelect, BoundUpdate, BoundUpsert,
    ExprBinder, Target, bind_options, query::bind_items,
};
use crate::{
    ast::{
        Delete, Expr, Image, Insert, InsertSource, OnConflict, Path, PopEnd, Returning, Segment,
        Update, UpdateOp, Upsert,
    },
    error::{ExecResult, type_error, unsupported},
    expr::{BExpr, Step},
    plan::rewrite::normalize,
};

/// One bound update operator (paths may contain computed `[expr]` steps, evaluated per row).
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)] // Mirrors `ast::UpdateOp` / `rustegon_doc::update::UpdateOp`.
pub enum BoundUpdateOp {
    Set {
        path: Vec<Step>,
        value: BExpr,
    },
    Unset {
        path: Vec<Step>,
    },
    Inc {
        path: Vec<Step>,
        by: BExpr,
    },
    Mul {
        path: Vec<Step>,
        by: BExpr,
    },
    Push {
        path: Vec<Step>,
        value: BExpr,
        position: Option<BExpr>,
        slice: Option<BExpr>,
        /// `(steps relative to the element, descending)`; empty steps = the element.
        sort: Vec<(Vec<Step>, bool)>,
    },
    Pull {
        path: Vec<Step>,
        predicate: BExpr,
    },
    AddToSet {
        path: Vec<Step>,
        value: BExpr,
    },
    Pop {
        path: Vec<Step>,
        first: bool,
    },
    Rename {
        from: Vec<Step>,
        to: Vec<Step>,
    },
    Min {
        path: Vec<Step>,
        value: BExpr,
    },
    Max {
        path: Vec<Step>,
        value: BExpr,
    },
    CurrentDate {
        path: Vec<Step>,
    },
}

/// The change an `UPDATE` makes.
#[derive(Debug, Clone, PartialEq)]
pub enum BoundOps {
    /// Field operators, applied atomically in order.
    Ops(Vec<BoundUpdateOp>),
    /// `REPLACE WITH expr` (evaluated against the old document).
    Replace(BExpr),
}

/// Rows of an `INSERT`.
#[derive(Debug, Clone, PartialEq)]
pub enum InsertRows {
    /// `VALUE` / `VALUES`: each evaluates to a document or an array of documents.
    Exprs(Vec<BExpr>),
    /// `INSERT … FROM query`.
    Query(Box<BoundQuery>),
}

/// `ON CONFLICT`.
#[derive(Debug, Clone, PartialEq)]
pub enum BoundConflict {
    /// Skip the row.
    DoNothing,
    /// Update the existing document (field operators or `REPLACE WITH`).
    DoUpdate(BoundOps),
}

/// Binds an `update_ops` list: `REPLACE WITH e` alone, or field operators.
fn bind_update_ops(eb: &mut ExprBinder<'_>, ops: &[UpdateOp]) -> Result<BoundOps, Error> {
    match ops {
        [UpdateOp::Replace { value }] => Ok(BoundOps::Replace(normalize(eb.bind(value)?))),
        ops => {
            if ops.iter().any(|o| matches!(o, UpdateOp::Replace { .. })) {
                return Err(type_error("REPLACE WITH must be the only update operation"));
            }
            Ok(BoundOps::Ops(bind_ops(eb, ops)?))
        }
    }
}

/// `INSERT`.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundInsert {
    /// Target (may not exist yet).
    pub target: Target,
    /// Rows.
    pub rows: InsertRows,
    /// Conflict handling.
    pub on_conflict: Option<BoundConflict>,
    /// `RETURNING`.
    pub returning: Option<BoundReturning>,
}

fn rowless(eb: &mut ExprBinder<'_>, e: &crate::ast::Expr) -> Result<BExpr, Error> {
    let b = normalize(eb.bind(e)?);
    if b.reads_row() {
        return Err(type_error("a value to insert cannot refer to a row field"));
    }
    Ok(b)
}

pub(super) fn bind_insert(b: &mut Binder<'_>, i: &Insert) -> ExecResult<BoundInsert> {
    if i.ttl.is_some() {
        return Err(unsupported("USING TTL", "M8").into());
    }
    let target = b.target(&i.target, false)?;
    let mut eb = ExprBinder::new(b.params, None);
    let rows = match &i.source {
        InsertSource::Value { expr } => InsertRows::Exprs(vec![rowless(&mut eb, expr)?]),
        InsertSource::Values { rows } => InsertRows::Exprs(
            rows.iter()
                .map(|r| rowless(&mut eb, r))
                .collect::<Result<_, _>>()?,
        ),
        InsertSource::Tuples { .. } => {
            return Err(unsupported("wide-column rows", "M8").into());
        }
        InsertSource::Query { query } => InsertRows::Query(Box::new(super::bind_query(b, query)?)),
    };
    let mut eb = ExprBinder::new(b.params, None);
    let on_conflict = match &i.on_conflict {
        None => None,
        Some(OnConflict::DoNothing) => Some(BoundConflict::DoNothing),
        Some(OnConflict::DoUpdate { ops }) => {
            Some(BoundConflict::DoUpdate(bind_update_ops(&mut eb, ops)?))
        }
    };
    let returning = bind_returning(&mut eb, i.returning.as_ref())?;
    Ok(BoundInsert {
        target,
        rows,
        on_conflict,
        returning,
    })
}

/// The row source of `UPDATE` / `DELETE`.
fn write_source(
    b: &mut Binder<'_>,
    target: &crate::ast::QualifiedName,
    alias: Option<&String>,
    filter: Option<&crate::ast::Expr>,
    limit: Option<&crate::ast::Expr>,
    options: &[crate::ast::OptionItem],
) -> ExecResult<BoundQuery> {
    let target = b.target(target, true)?;
    let options = bind_options(b, options, Some(&target))?;
    if filter.is_none() && !options.allow_full_scan_write {
        return Err(Error::new(
            ErrorCode::QueryTooComplex,
            "UPDATE / DELETE without WHERE requires OPTIONS (allow_full_scan_write = true)",
        )
        .into());
    }
    let mut eb = ExprBinder::new(b.params, alias.cloned());
    let filter = match filter {
        Some(f) => Some(normalize(eb.bind(f)?)),
        None => None,
    };
    let limit = match limit {
        Some(e) => Some(super::query::count(&mut eb, e, "LIMIT")?),
        None => None,
    };
    Ok(BoundQuery {
        target,
        filter,
        select: BoundSelect::Document,
        // Writes visit the matching documents in `_id` order (query-language.md §4.3): `LIMIT`
        // picks the smallest `_id`s and `RETURNING` rows are ordered, whatever access path the
        // planner chooses. The rows are collected before the first write anyway.
        order: vec![super::SortKey {
            expr: BExpr::Field(vec![Step::field("_id")]),
            descending: false,
        }],
        limit,
        offset: 0,
        options,
    })
}

pub(super) fn bind_update(b: &mut Binder<'_>, u: &Update) -> ExecResult<BoundUpdate> {
    let source = write_source(
        b,
        &u.target,
        u.alias.as_ref(),
        u.filter.as_ref(),
        u.limit.as_ref(),
        &u.options,
    )?;
    let mut eb = ExprBinder::new(b.params, u.alias.clone());
    let ops = bind_update_ops(&mut eb, &u.ops)?;
    let returning = bind_returning(&mut eb, u.returning.as_ref())?;
    Ok(BoundUpdate {
        source,
        ops,
        returning,
    })
}

pub(super) fn bind_delete(b: &mut Binder<'_>, d: &Delete) -> ExecResult<BoundDelete> {
    if !d.columns.is_empty() {
        return Err(unsupported("wide-column cell deletes", "M8").into());
    }
    let source = write_source(
        b,
        &d.target,
        None,
        d.filter.as_ref(),
        d.limit.as_ref(),
        &d.options,
    )?;
    let mut eb = ExprBinder::new(b.params, None);
    let returning = bind_returning(&mut eb, d.returning.as_ref())?;
    Ok(BoundDelete { source, returning })
}

pub(super) fn bind_upsert(b: &mut Binder<'_>, u: &Upsert) -> ExecResult<BoundUpsert> {
    let target = b.target(&u.target, false)?;
    let mut eb = ExprBinder::new(b.params, None);
    let value = rowless(&mut eb, &u.value)?;
    let on =
        u.on.iter()
            .map(|p| static_path(&mut eb, p))
            .collect::<Result<Vec<_>, _>>()?;
    let returning = bind_returning(&mut eb, u.returning.as_ref())?;
    Ok(BoundUpsert {
        target,
        value,
        on,
        returning,
    })
}

fn bind_returning(
    eb: &mut ExprBinder<'_>,
    r: Option<&Returning>,
) -> Result<Option<BoundReturning>, Error> {
    let Some(r) = r else { return Ok(None) };
    let select = if r.items.is_empty() {
        BoundSelect::Document
    } else {
        BoundSelect::Items(bind_items(eb, &r.items)?)
    };
    Ok(Some(BoundReturning {
        new_image: r.image == Image::New,
        select,
    }))
}

/// A target path of an update operator (alias prefix stripped; computed steps allowed).
///
/// An *array filter* segment `[x -> pred]` (query-language.md §4.3) becomes a computed step
/// holding a [`BExpr::Lambda`] whose body is bound by [`ExprBinder::in_array_filter`]; the
/// executor lowers it to `UpdateSegment::Filtered` (`[x -> true]` = every element).
fn target_path(eb: &mut ExprBinder<'_>, p: &Path) -> Result<Vec<Step>, Error> {
    let is_filter = |s: &Segment| matches!(s, Segment::Index(e) if matches!(e.as_ref(), Expr::Lambda { params, .. } if params.len() == 1));
    if let Some(at) = p.0.iter().position(is_filter) {
        let mut steps = target_path(eb, &Path(p.0[..at].to_vec()))?;
        for seg in &p.0[at..] {
            match seg {
                Segment::Index(e) if is_filter(seg) => {
                    let Expr::Lambda { params, body } = e.as_ref() else {
                        continue;
                    };
                    let (body, first_slot) = eb.in_array_filter(&params[0], body)?;
                    steps.push(Step::Dyn(Box::new(BExpr::Lambda {
                        first_slot,
                        params: params.clone(),
                        body: Box::new(normalize(body)),
                    })));
                }
                other => steps.extend(eb.steps(std::slice::from_ref(other))?),
            }
        }
        return Ok(steps);
    }
    match eb.bind_path(p)? {
        BExpr::Field(steps) if !steps.is_empty() => Ok(steps),
        _ => Err(type_error(
            "an update target must be a field path of the document",
        )),
    }
}

/// A path without computed steps.
fn static_path(eb: &mut ExprBinder<'_>, p: &Path) -> Result<Vec<Step>, Error> {
    let steps = target_path(eb, p)?;
    if steps.iter().any(|s| matches!(s, Step::Dyn(_))) {
        return Err(type_error("a computed [expr] step is not allowed here"));
    }
    Ok(steps)
}

/// Binds update operators.
///
/// # Errors
/// `RGN-1011` / `RGN-1012` from expressions and paths.
pub fn bind_ops(eb: &mut ExprBinder<'_>, ops: &[UpdateOp]) -> Result<Vec<BoundUpdateOp>, Error> {
    let mut out = Vec::new();
    let value = |eb: &mut ExprBinder<'_>, e: &crate::ast::Expr| -> Result<BExpr, Error> {
        Ok(normalize(eb.bind(e)?))
    };
    for op in ops {
        match op {
            UpdateOp::Set { items } => {
                for item in items {
                    out.push(BoundUpdateOp::Set {
                        path: target_path(eb, &item.path)?,
                        value: value(eb, &item.value)?,
                    });
                }
            }
            UpdateOp::Unset { paths } => {
                for p in paths {
                    out.push(BoundUpdateOp::Unset {
                        path: target_path(eb, p)?,
                    });
                }
            }
            UpdateOp::Inc { path, by } => out.push(BoundUpdateOp::Inc {
                path: target_path(eb, path)?,
                by: value(eb, by)?,
            }),
            UpdateOp::Mul { path, by } => out.push(BoundUpdateOp::Mul {
                path: target_path(eb, path)?,
                by: value(eb, by)?,
            }),
            UpdateOp::Push {
                path,
                value: v,
                position,
                slice,
                sort,
            } => {
                let steps = target_path(eb, path)?;
                let mut keys = Vec::with_capacity(sort.len());
                for item in sort {
                    let crate::ast::Expr::Path { path: kp } = &item.expr else {
                        return Err(type_error("PUSH … SORT keys must be paths"));
                    };
                    let k = static_path(eb, kp)?;
                    let rel = if k.starts_with(&steps) {
                        k[steps.len()..].to_vec()
                    } else {
                        k
                    };
                    keys.push((rel, item.descending));
                }
                out.push(BoundUpdateOp::Push {
                    value: value(eb, v)?,
                    position: position.as_ref().map(|e| value(eb, e)).transpose()?,
                    slice: slice.as_ref().map(|e| value(eb, e)).transpose()?,
                    sort: keys,
                    path: steps,
                });
            }
            UpdateOp::Pull { path, predicate } => {
                let steps = target_path(eb, path)?;
                let slot = eb.next_slot();
                let (predicate, _) =
                    eb.in_element(steps.clone(), slot, |b| Ok(normalize(b.bind(predicate)?)))?;
                out.push(BoundUpdateOp::Pull {
                    path: steps,
                    predicate,
                });
            }
            UpdateOp::AddToSet { path, value: v } => out.push(BoundUpdateOp::AddToSet {
                path: target_path(eb, path)?,
                value: value(eb, v)?,
            }),
            UpdateOp::Pop { path, end } => out.push(BoundUpdateOp::Pop {
                path: target_path(eb, path)?,
                first: *end == PopEnd::First,
            }),
            UpdateOp::Rename { from, to } => out.push(BoundUpdateOp::Rename {
                from: static_path(eb, from)?,
                to: static_path(eb, to)?,
            }),
            UpdateOp::Min { path, value: v } => out.push(BoundUpdateOp::Min {
                path: target_path(eb, path)?,
                value: value(eb, v)?,
            }),
            UpdateOp::Max { path, value: v } => out.push(BoundUpdateOp::Max {
                path: target_path(eb, path)?,
                value: value(eb, v)?,
            }),
            UpdateOp::CurrentDate { path } => out.push(BoundUpdateOp::CurrentDate {
                path: target_path(eb, path)?,
            }),
            UpdateOp::Replace { .. } => {
                return Err(type_error("REPLACE WITH must be the only update operation"));
            }
        }
    }
    Ok(out)
}
