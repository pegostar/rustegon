// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Write operators: `Insert`, `Update`, `Delete`, `Upsert` (query-engine.md §5), running in the
//! caller's transaction through [`QueryStore`](super::QueryStore)'s single write path.
//!
//! The rows of `UPDATE` / `DELETE` are read completely before the first write (they are
//! bounded by the memory limit), so a statement never sees its own writes (no "Halloween
//! problem"). `UPDATE` operators are lowered to `rustegon_doc::update` operators whose values
//! are evaluated against the document before the update; `PULL … WHERE` becomes an
//! [`ElementPredicate`] backed by this crate's evaluator. *Provisional (PD pending)*: `SET p = e`
//! where `e` is `missing` removes `p` (as a projection omits it); every matched document counts
//! as updated, even when the operators leave it unchanged.

use std::sync::Arc;

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    compare::values_equal,
    keyenc::Direction,
    limits::validate_user_document,
    path::{FieldPath, Segment},
    update::{
        ElementPredicate, PopEnd, Push, PushSort, UpdateContext, UpdateOp, UpdatePath,
        UpdateSegment, apply_updates,
    },
};

use super::{ExecCtx, QueryResult, project::project, read::collect, read::collect_documents};
use crate::{
    bind::{
        BoundConflict, BoundDelete, BoundInsert, BoundOps, BoundQuery, BoundReturning, BoundSelect,
        BoundUpdate, BoundUpdateOp, BoundUpsert, InsertRows, StatementOptions, Target,
    },
    error::{ExecError, ExecResult, invalid, type_error},
    expr::{BExpr, CmpOp, EvalCtx, Scope, Step, eval, eval_predicate, ops::as_int},
    plan::rewrite::normalize,
};

/// Savepoint around one row of `INSERT … ON CONFLICT`.
const ROW_SAVEPOINT: &str = "rustegon.query.row";

fn plan_rows(cx: &mut ExecCtx<'_>, q: &BoundQuery) -> ExecResult<Vec<Document>> {
    let plan = Arc::new(super::plan_read(&mut *cx.store, q, cx.opts)?);
    collect_documents(cx, &plan)
}

fn returning_row(
    r: Option<&BoundReturning>,
    new_image: bool,
    doc: &Document,
    ctx: &EvalCtx,
) -> Result<Option<Value>, Error> {
    match r {
        Some(r) if r.new_image == new_image => {
            Ok(Some(project(&r.select, &Value::Object(doc.clone()), ctx)?))
        }
        _ => Ok(None),
    }
}

fn as_document(v: Option<Value>, what: &str) -> Result<Document, Error> {
    match v {
        Some(Value::Object(d)) => Ok(d),
        _ => Err(type_error(format!("{what} must be an object"))),
    }
}

/// Checks the interrupt before every `batch_rows` written rows (FR-QL-008): writing one batch
/// costs more than reading one (validators, index maintenance), so tying the check to the batch
/// size keeps "at most one batch of work after a deadline or a kill" true for writes too.
fn check(cx: &ExecCtx<'_>, i: usize) -> Result<(), Error> {
    if i.is_multiple_of(cx.opts.batch_rows.max(1)) {
        cx.interrupt.check()
    } else {
        Ok(())
    }
}

/// `INSERT`.
pub(super) fn insert(cx: &mut ExecCtx<'_>, i: &BoundInsert) -> ExecResult<QueryResult> {
    let docs = insert_rows(cx, i)?;
    let mut out = QueryResult::default();
    let (db, coll) = (i.target.database.name.clone(), i.target.name.clone());
    for (n, doc) in docs.into_iter().enumerate() {
        check(cx, n)?;
        validate_user_document(&doc)?;
        let Some(conflict) = &i.on_conflict else {
            let stored = cx.store.insert(&db, &coll, doc)?;
            out.inserted += 1;
            out.rows
                .extend(returning_row(i.returning.as_ref(), true, &stored, cx.eval)?);
            continue;
        };
        cx.store.savepoint(ROW_SAVEPOINT)?;
        let attempt = cx.store.insert(&db, &coll, doc.clone());
        match attempt {
            Ok(stored) => {
                cx.store.release_savepoint(ROW_SAVEPOINT)?;
                out.inserted += 1;
                out.rows
                    .extend(returning_row(i.returning.as_ref(), true, &stored, cx.eval)?);
            }
            Err(ExecError::Query(e)) if e.code() == ErrorCode::DuplicateKey => {
                cx.store.rollback_to_savepoint(ROW_SAVEPOINT)?;
                cx.store.release_savepoint(ROW_SAVEPOINT)?;
                if let BoundConflict::DoUpdate(ops) = conflict {
                    conflict_update(cx, i, &doc, ops, e, &mut out)?;
                }
            }
            Err(e) => {
                if matches!(e, ExecError::Query(_)) {
                    cx.store.rollback_to_savepoint(ROW_SAVEPOINT)?;
                    cx.store.release_savepoint(ROW_SAVEPOINT)?;
                }
                return Err(e);
            }
        }
    }
    Ok(out)
}

/// `ON CONFLICT DO UPDATE`: updates the document with the same `_id`; a conflict on another
/// unique index keeps its `RGN-1005`.
fn conflict_update(
    cx: &mut ExecCtx<'_>,
    i: &BoundInsert,
    doc: &Document,
    ops: &BoundOps,
    dup: Error,
    out: &mut QueryResult,
) -> ExecResult<()> {
    let coll = cx.store.collection(&i.target.database, &i.target.name)?;
    let old = match (coll.as_ref(), doc.get("_id")) {
        (Some(c), Some(id)) => cx.store.get(c, id)?,
        _ => None,
    };
    let (Some(coll), Some(old)) = (coll, old) else {
        return Err(dup.into());
    };
    let new = updated(cx, ops, &old)?;
    let stored = cx.store.replace(&coll, &old, new)?;
    out.updated += 1;
    out.rows
        .extend(returning_row(i.returning.as_ref(), false, &old, cx.eval)?);
    out.rows
        .extend(returning_row(i.returning.as_ref(), true, &stored, cx.eval)?);
    Ok(())
}

/// The new image of `old` under `ops`. `REPLACE WITH e` is evaluated against `old`; the new
/// document keeps the existing `_id` (added first when absent; a different one is
/// `RGN-1001`), query-language.md §4.3.
fn updated(cx: &ExecCtx<'_>, ops: &BoundOps, old: &Document) -> Result<Document, Error> {
    match ops {
        BoundOps::Ops(ops) => apply_ops(cx, ops, old),
        BoundOps::Replace(e) => {
            let row = Value::Object(old.clone());
            let doc = as_document(eval(e, &Scope::new(Some(&row), cx.eval))?, "REPLACE WITH")?;
            validate_user_document(&doc)?;
            let id = old.get("_id").cloned().unwrap_or(Value::Null);
            match doc.get("_id") {
                Some(new_id) if !values_equal(Some(new_id), Some(&id)) => {
                    Err(invalid("_id is immutable and cannot be changed"))
                }
                Some(_) => Ok(doc),
                None => {
                    let mut fields = vec![("_id".to_owned(), id)];
                    fields.extend(doc.into_fields());
                    Document::try_from_fields(fields).map_err(Error::from)
                }
            }
        }
    }
}

fn insert_rows(cx: &mut ExecCtx<'_>, i: &BoundInsert) -> ExecResult<Vec<Document>> {
    let values = match &i.rows {
        InsertRows::Exprs(exprs) => {
            let scope = Scope::new(None, cx.eval);
            let mut vals = Vec::with_capacity(exprs.len());
            for e in exprs {
                match eval(e, &scope)? {
                    Some(Value::Array(items)) => vals.extend(items),
                    v => vals.push(v.unwrap_or(Value::Null)),
                }
            }
            vals
        }
        InsertRows::Query(q) => {
            let plan = Arc::new(super::plan_read(&mut *cx.store, q, cx.opts)?);
            collect(cx, &plan)?
        }
    };
    values
        .into_iter()
        .map(|v| as_document(Some(v), "an inserted row").map_err(ExecError::from))
        .collect()
}

/// `UPDATE`.
pub(super) fn update(cx: &mut ExecCtx<'_>, u: &BoundUpdate) -> ExecResult<QueryResult> {
    let docs = plan_rows(cx, &u.source)?;
    let coll = existing(&u.source.target)?;
    let mut out = QueryResult::default();
    for (n, old) in docs.into_iter().enumerate() {
        check(cx, n)?;
        let new = updated(cx, &u.ops, &old)?;
        let stored = cx.store.replace(&coll, &old, new)?;
        out.updated += 1;
        out.rows
            .extend(returning_row(u.returning.as_ref(), false, &old, cx.eval)?);
        out.rows
            .extend(returning_row(u.returning.as_ref(), true, &stored, cx.eval)?);
    }
    Ok(out)
}

/// `DELETE`.
pub(super) fn delete(cx: &mut ExecCtx<'_>, d: &BoundDelete) -> ExecResult<QueryResult> {
    let docs = plan_rows(cx, &d.source)?;
    let coll = existing(&d.source.target)?;
    let mut out = QueryResult::default();
    for (n, old) in docs.into_iter().enumerate() {
        check(cx, n)?;
        cx.store.delete(&coll, &old)?;
        out.deleted += 1;
        out.rows
            .extend(returning_row(d.returning.as_ref(), false, &old, cx.eval)?);
    }
    Ok(out)
}

fn existing(t: &Target) -> Result<rustegon_catalog::CollectionDescriptor, Error> {
    t.collection
        .clone()
        .ok_or_else(|| crate::error::not_found("collection", &t.name))
}

/// `UPSERT`: replaces the document matching `on` (default `_id`) or inserts. An `ON` field
/// `missing` or `null` in the new document is `RGN-1001`, and so is a match of more than one
/// document (query-language.md §4.3).
pub(super) fn upsert(cx: &mut ExecCtx<'_>, u: &BoundUpsert) -> ExecResult<QueryResult> {
    let doc = as_document(
        eval(&u.value, &Scope::new(None, cx.eval))?,
        "an upserted value",
    )?;
    validate_user_document(&doc)?;
    let coll = cx.store.collection(&u.target.database, &u.target.name)?;
    let old = match &coll {
        None => None,
        Some(c) if u.on.is_empty() => match doc.get("_id") {
            Some(id) => cx.store.get(c, id)?,
            None => None,
        },
        Some(c) => upsert_match(cx, u, c, &doc)?,
    };
    let mut out = QueryResult::default();
    if let (Some(c), Some(old)) = (coll, old) {
        let stored = cx.store.replace(&c, &old, doc)?;
        out.updated += 1;
        out.rows
            .extend(returning_row(u.returning.as_ref(), false, &old, cx.eval)?);
        out.rows
            .extend(returning_row(u.returning.as_ref(), true, &stored, cx.eval)?);
    } else {
        let stored = cx
            .store
            .insert(&u.target.database.name, &u.target.name, doc)?;
        out.inserted += 1;
        out.rows
            .extend(returning_row(u.returning.as_ref(), true, &stored, cx.eval)?);
    }
    Ok(out)
}

fn upsert_match(
    cx: &mut ExecCtx<'_>,
    u: &BoundUpsert,
    coll: &rustegon_catalog::CollectionDescriptor,
    doc: &Document,
) -> ExecResult<Option<Document>> {
    let row = Value::Object(doc.clone());
    let mut conj = Vec::with_capacity(u.on.len());
    for path in &u.on {
        let field = BExpr::Field(path.clone());
        // A `null` key would never match (`==` with `null` is unknown) and insert a duplicate
        // on every retry, so it is rejected like a `missing` one (query-language.md §4.3).
        let Some(v) =
            eval(&field, &Scope::new(Some(&row), cx.eval))?.filter(|v| !matches!(v, Value::Null))
        else {
            return Err(invalid("an UPSERT ON field is missing or null in the document").into());
        };
        conj.push(BExpr::Cmp {
            op: CmpOp::EqWhole,
            left: Box::new(field),
            right: Box::new(BExpr::value(v)),
        });
    }
    let target = Target {
        database: u.target.database.clone(),
        name: u.target.name.clone(),
        indexes: cx.store.indexes(coll)?,
        collection: Some(coll.clone()),
    };
    let q = BoundQuery {
        target,
        filter: Some(normalize(BExpr::And(conj))),
        select: BoundSelect::Document,
        order: Vec::new(),
        limit: Some(2),
        offset: 0,
        options: StatementOptions::default(),
    };
    let mut found = plan_rows(cx, &q)?;
    if found.len() > 1 {
        return Err(invalid("the UPSERT ON fields match several documents").into());
    }
    Ok(found.pop())
}

// ---------------------------------------------------------------------------------------------
// Update operator lowering

fn segment(step: &Step, scope: &Scope<'_>) -> Result<UpdateSegment, Error> {
    if let Step::Dyn(e) = step
        && let BExpr::Lambda {
            first_slot, body, ..
        } = e.as_ref()
    {
        // Array filter `[x -> pred]`: the element is the lambda's slot (bind/write.rs); the
        // predicate sees the element before the update, the document stays readable through
        // the row alias.
        let (body, slot, now_ms) = (
            Arc::new(body.as_ref().clone()),
            *first_slot,
            scope.ctx.now_ms,
        );
        let row = scope.row.cloned().map(Arc::new);
        return Ok(UpdateSegment::Filtered(ElementPredicate::new(
            move |elem: &Value| {
                let ctx = EvalCtx::new(now_ms);
                let s = Scope::new(row.as_deref(), &ctx).with_var(slot, Some(elem.clone()));
                Ok(eval_predicate(&body, &s)? == Some(true))
            },
        )));
    }
    Ok(UpdateSegment::Field(match step {
        Step::Field { name, index } => Segment {
            name: name.clone(),
            index: *index,
        },
        Step::Dyn(e) => match eval(e, scope)? {
            Some(Value::String(s)) => Segment {
                name: s,
                index: None,
            },
            Some(v) => {
                let i = as_int(&v)
                    .and_then(|i| usize::try_from(i).ok())
                    .ok_or_else(|| type_error("a computed path step must be a string or index"))?;
                Segment {
                    name: i.to_string(),
                    index: Some(i),
                }
            }
            None => return Err(type_error("a computed path step is missing")),
        },
    }))
}

fn upath(steps: &[Step], scope: &Scope<'_>) -> Result<UpdatePath, Error> {
    Ok(UpdatePath::new(
        steps
            .iter()
            .map(|s| segment(s, scope))
            .collect::<Result<_, _>>()?,
    ))
}

fn value(e: &BExpr, scope: &Scope<'_>) -> Result<Value, Error> {
    Ok(eval(e, scope)?.unwrap_or(Value::Null))
}

fn int_operand(e: &BExpr, scope: &Scope<'_>, what: &str) -> Result<i64, Error> {
    eval(e, scope)?
        .as_ref()
        .and_then(as_int)
        .ok_or_else(|| type_error(format!("PUSH {what} must be an integer")))
}

fn push_sort(keys: &[(Vec<Step>, bool)]) -> Result<Option<PushSort>, Error> {
    let dir = |d: bool| {
        if d {
            Direction::Descending
        } else {
            Direction::Ascending
        }
    };
    match keys {
        [] => Ok(None),
        [(steps, d)] if steps.is_empty() => Ok(Some(PushSort::Elements(dir(*d)))),
        _ => {
            let mut fields = Vec::with_capacity(keys.len());
            for (steps, d) in keys {
                let segs = steps
                    .iter()
                    .map(|s| match s {
                        Step::Field { name, index } => Ok(Segment {
                            name: name.clone(),
                            index: *index,
                        }),
                        Step::Dyn(_) => Err(type_error("PUSH … SORT keys must be static paths")),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if segs.is_empty() {
                    return Err(type_error("PUSH … SORT mixes the element with its fields"));
                }
                fields.push((FieldPath::from_segments(segs), dir(*d)));
            }
            Ok(Some(PushSort::Fields(fields)))
        }
    }
}

/// Lowers bound operators against `old` and applies them atomically (data-model.md §2.3).
fn apply_ops(cx: &ExecCtx<'_>, ops: &[BoundUpdateOp], old: &Document) -> Result<Document, Error> {
    let row = Arc::new(Value::Object(old.clone()));
    let scope = Scope::new(Some(row.as_ref()), cx.eval);
    let mut lowered = Vec::with_capacity(ops.len());
    for op in ops {
        lowered.push(match op {
            BoundUpdateOp::Set { path, value: v } => match eval(v, &scope)? {
                Some(val) => UpdateOp::Set {
                    path: upath(path, &scope)?,
                    value: val,
                },
                None => UpdateOp::Unset {
                    path: upath(path, &scope)?,
                },
            },
            BoundUpdateOp::Unset { path } => UpdateOp::Unset {
                path: upath(path, &scope)?,
            },
            BoundUpdateOp::Inc { path, by } => UpdateOp::Inc {
                path: upath(path, &scope)?,
                by: value(by, &scope)?,
            },
            BoundUpdateOp::Mul { path, by } => UpdateOp::Mul {
                path: upath(path, &scope)?,
                by: value(by, &scope)?,
            },
            BoundUpdateOp::Push {
                path,
                value: v,
                position,
                slice,
                sort,
            } => UpdateOp::Push(Push {
                path: upath(path, &scope)?,
                values: vec![value(v, &scope)?],
                position: position
                    .as_ref()
                    .map(|e| int_operand(e, &scope, "POSITION"))
                    .transpose()?,
                sort: push_sort(sort)?,
                slice: slice
                    .as_ref()
                    .map(|e| int_operand(e, &scope, "SLICE"))
                    .transpose()?,
            }),
            BoundUpdateOp::Pull { path, predicate } => UpdateOp::Pull {
                path: upath(path, &scope)?,
                predicate: element_predicate(predicate, &row, cx.eval.now_ms),
            },
            BoundUpdateOp::AddToSet { path, value: v } => UpdateOp::AddToSet {
                path: upath(path, &scope)?,
                values: vec![value(v, &scope)?],
            },
            BoundUpdateOp::Pop { path, first } => UpdateOp::Pop {
                path: upath(path, &scope)?,
                end: if *first { PopEnd::First } else { PopEnd::Last },
            },
            BoundUpdateOp::Rename { from, to } => UpdateOp::Rename {
                from: upath(from, &scope)?,
                to: upath(to, &scope)?,
            },
            BoundUpdateOp::Min { path, value: v } => UpdateOp::Min {
                path: upath(path, &scope)?,
                value: value(v, &scope)?,
            },
            BoundUpdateOp::Max { path, value: v } => UpdateOp::Max {
                path: upath(path, &scope)?,
                value: value(v, &scope)?,
            },
            BoundUpdateOp::CurrentDate { path } => UpdateOp::CurrentDate {
                path: upath(path, &scope)?,
            },
        });
    }
    let ctx = UpdateContext {
        now_ms: cx.eval.now_ms,
    };
    apply_updates(old, &lowered, &ctx).map_err(Error::from)
}

/// `PULL … WHERE pred` as an element predicate: the element is the variable of the element
/// context (slot of the binder), the old document stays readable through the row alias.
fn element_predicate(pred: &BExpr, row: &Arc<Value>, now_ms: i64) -> ElementPredicate {
    // Update operators are bound at the top level of the statement, so the element context of
    // `PULL` is the first variable: slot 0.
    const PULL_ELEMENT_SLOT: usize = 0;
    let (pred, row) = (Arc::new(pred.clone()), Arc::clone(row));
    ElementPredicate::new(move |elem: &Value| {
        let ctx = EvalCtx::new(now_ms);
        let scope =
            Scope::new(Some(row.as_ref()), &ctx).with_var(PULL_ELEMENT_SLOT, Some(elem.clone()));
        Ok(eval_predicate(&pred, &scope)? == Some(true))
    })
}
