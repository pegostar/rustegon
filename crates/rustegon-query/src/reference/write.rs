// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Write statements (query-language.md §3, §6) of the reference interpreter.
//!
//! Every statement is atomic: it works on a copy of the collection and replaces it only on
//! success. Documents are visited in `_id` order (which fixes what `LIMIT` selects).
//!
//! - **`INSERT`**: each row must be an object (`RGN-1011`); `VALUES $docs` accepts an array of
//!   objects. Field names must be valid at every level and server-maintained top-level names are
//!   rejected (`RGN-1004`). A missing `_id` is generated and placed first. An `_id` equal (§2.1)
//!   to an existing one — including one inserted earlier by the same statement — is
//!   `RGN-1005 DuplicateKey`, skipped with `ON CONFLICT DO NOTHING`, or applies the `DO UPDATE`
//!   operators to the existing document (evaluated against it).
//! - **`UPDATE` / `DELETE`** without `WHERE` need `OPTIONS (allow_full_scan_write = true)`
//!   (§6), else `RGN-1013`. Operators are lowered to `rustegon_doc::update` and applied
//!   atomically per document (data-model §2.3); their expressions are evaluated against the
//!   document before the update. `affected` counts matched documents.
//! - **Update paths** (*Provisional*): a leading `FROM` alias is skipped; `.n` is an array index;
//!   `[e]` is an index (integer) or a field (string) computed once per document, except a
//!   one-parameter lambda `[x -> p]`, which is an *array filter*: every element for which `p`
//!   is `true` (`[x -> true]` = all elements). `SET p = e` with `e` `missing` is `UNSET p`.
//!   `PUSH … SORT k` sorts by element fields `k` (paths); whole-element sort is not expressible.
//! - **`PULL path WHERE p`** (*Provisional*): `p` is evaluated per element with the element as
//!   the row (paths relative to it) and bound to the variable named after the last field of
//!   `path` (`PULL tags WHERE tags = 'x'`); elements where `p` is `true` are removed.
//! - **`REPLACE WITH doc`**: the new document keeps the existing `_id` (a different `_id` is
//!   `RGN-1001`).
//! - **`UPSERT … ON paths`** (default `_id`): replaces the document whose values at all paths
//!   equal (§2.1) the new document's, else inserts. An explicit `ON` path that is `missing` or
//!   `null` in the new document, or a match of several documents, is `RGN-1001`.
//! - **`RETURNING OLD|NEW [items]`**: the image before/after, projected as `SELECT` items. An
//!   inserted document has no `OLD` image and a deleted one no `NEW` image (no row).

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    compare::values_equal,
    limits::{validate_field_name, validate_user_document},
    update::{UpdateContext, apply_updates},
};

use super::{
    Output, Reference,
    error::{invalid, type_error, unsupported},
    eval::{Ctx, Env, Tri, eval, truth},
    lower::lower,
    query,
};
use crate::ast::{
    Delete, Expr, Image, Insert, InsertSource, OnConflict, OptionItem, Path, Returning, Update,
    UpdateOp, Upsert,
};

/// Runs `INSERT`.
///
/// # Errors
/// See the module docs.
pub fn insert(r: &mut Reference, s: &Insert, ctx: &Ctx<'_>) -> Result<Output, Error> {
    if s.ttl.is_some() {
        return Err(unsupported("USING TTL (wide-column)"));
    }
    let rows = insert_rows(r, &s.source, ctx)?;
    let mut docs = r.collection(&s.target).to_vec();
    let mut out = Output {
        rows: Vec::new(),
        affected: Some(0),
    };
    for row in rows {
        let mut doc = user_document(row)?;
        if doc.get("_id").is_none() {
            doc = with_id_first(doc, r.fresh_object_id());
        }
        let existing = docs
            .iter()
            .position(|d| values_equal(d.get("_id"), doc.get("_id")));
        match (existing, &s.on_conflict) {
            (None, _) => {
                push_returning(&mut out.rows, s.returning.as_ref(), None, Some(&doc), ctx)?;
                docs.push(doc);
            }
            (Some(_), None) => {
                return Err(Error::new(ErrorCode::DuplicateKey, "duplicate _id"));
            }
            (Some(_), Some(OnConflict::DoNothing)) => continue,
            (Some(at), Some(OnConflict::DoUpdate { ops })) => {
                let new = apply_ops(ops, &docs[at], None, ctx)?;
                push_returning(
                    &mut out.rows,
                    s.returning.as_ref(),
                    Some(&docs[at]),
                    Some(&new),
                    ctx,
                )?;
                docs[at] = new;
            }
        }
        bump(&mut out);
    }
    r.replace_collection(&s.target, docs);
    Ok(out)
}

/// `RGN-1011` when an `INSERT` / `UPSERT` value expression reads a row: a path that does not
/// start with a lambda or quantifier variable, or `id()` (query-language.md §4.3: there is no
/// row to read).
fn rowless(e: &Expr) -> Result<(), Error> {
    if reads_row(e, &mut Vec::new()) {
        return Err(type_error("a value to insert cannot refer to a row field"));
    }
    Ok(())
}

fn reads_row(e: &Expr, vars: &mut Vec<String>) -> bool {
    fn any<'e>(es: impl IntoIterator<Item = &'e Expr>, vars: &mut Vec<String>) -> bool {
        es.into_iter().any(|x| reads_row(x, vars))
    }
    match e {
        Expr::Path { path } => match path.0.first() {
            Some(crate::ast::Segment::Field(f)) if vars.contains(f) => path_reads(path, vars),
            _ => true,
        },
        Expr::Access { base, path } => reads_row(base, vars) || path_reads(path, vars),
        Expr::Binary { left, right, .. } => any([&**left, &**right], vars),
        Expr::And { args } | Expr::Or { args } => any(args, vars),
        Expr::Array { elements } => any(elements, vars),
        Expr::Object { fields } => any(fields.iter().map(|f| &f.value), vars),
        Expr::Not { expr }
        | Expr::Neg { expr }
        | Expr::Is { expr, .. }
        | Expr::Extract { expr, .. } => reads_row(expr, vars),
        Expr::Between { expr, low, high } => any([&**expr, &**low, &**high], vars),
        Expr::Call { name, args } => name.eq_ignore_ascii_case("id") || any(args, vars),
        Expr::Case {
            operand,
            whens,
            otherwise,
        } => {
            operand.as_deref().is_some_and(|o| reads_row(o, vars))
                || whens
                    .iter()
                    .any(|w| reads_row(&w.when, vars) || reads_row(&w.then, vars))
                || otherwise.as_deref().is_some_and(|o| reads_row(o, vars))
        }
        Expr::Lambda { params, body } => {
            let n = vars.len();
            vars.extend(params.iter().cloned());
            let hit = reads_row(body, vars);
            vars.truncate(n);
            hit
        }
        Expr::Quantified {
            var,
            source,
            predicate,
            ..
        } => {
            if reads_row(source, vars) {
                return true;
            }
            vars.push(var.clone());
            let hit = reads_row(predicate, vars);
            vars.pop();
            hit
        }
        Expr::ElemMatch { .. } => true,
        Expr::Literal(_) | Expr::Param { .. } | Expr::Star => false,
    }
}

fn path_reads(path: &Path, vars: &mut Vec<String>) -> bool {
    path.0.iter().any(|s| match s {
        crate::ast::Segment::Index(e) => reads_row(e, vars),
        _ => false,
    })
}

fn insert_rows(r: &Reference, source: &InsertSource, ctx: &Ctx<'_>) -> Result<Vec<Value>, Error> {
    let empty = Value::Object(Document::new());
    let env = Env::new(ctx, &empty, None);
    match source {
        InsertSource::Value { expr } => rowless(expr)?,
        InsertSource::Values { rows } => rows.iter().try_for_each(rowless)?,
        _ => {}
    }
    Ok(match source {
        InsertSource::Value { expr } => vec![eval(expr, &env)?.unwrap_or(Value::Null)],
        InsertSource::Values { rows } => {
            let mut out = Vec::new();
            for e in rows {
                match eval(e, &env)? {
                    Some(Value::Array(items)) => out.extend(items),
                    other => out.push(other.unwrap_or(Value::Null)),
                }
            }
            out
        }
        InsertSource::Query { query } => query::run(r, query, ctx)?,
        InsertSource::Tuples { .. } => return Err(unsupported("wide-column INSERT")),
    })
}

/// Runs `UPDATE`.
///
/// # Errors
/// See the module docs.
pub fn update(r: &mut Reference, s: &Update, ctx: &Ctx<'_>) -> Result<Output, Error> {
    let alias = s.alias.as_deref();
    let mut docs = r.collection(&s.target).to_vec();
    let targets = matching(
        &docs,
        s.filter.as_ref(),
        &s.options,
        s.limit.as_ref(),
        alias,
        ctx,
    )?;
    let mut out = Output {
        rows: Vec::new(),
        affected: Some(0),
    };
    for at in targets {
        let new = apply_ops(&s.ops, &docs[at], alias, ctx)?;
        push_returning(
            &mut out.rows,
            s.returning.as_ref(),
            Some(&docs[at]),
            Some(&new),
            ctx,
        )?;
        docs[at] = new;
        bump(&mut out);
    }
    r.replace_collection(&s.target, docs);
    Ok(out)
}

/// Runs `DELETE`.
///
/// # Errors
/// See the module docs.
pub fn delete(r: &mut Reference, s: &Delete, ctx: &Ctx<'_>) -> Result<Output, Error> {
    if !s.columns.is_empty() {
        return Err(unsupported("cell DELETE (wide-column)"));
    }
    let mut docs = r.collection(&s.target).to_vec();
    let targets = matching(
        &docs,
        s.filter.as_ref(),
        &s.options,
        s.limit.as_ref(),
        None,
        ctx,
    )?;
    let mut out = Output {
        rows: Vec::new(),
        affected: Some(0),
    };
    for &at in &targets {
        push_returning(
            &mut out.rows,
            s.returning.as_ref(),
            Some(&docs[at]),
            None,
            ctx,
        )?;
        bump(&mut out);
    }
    // Remove from the back so earlier positions stay valid.
    for &at in targets.iter().rev() {
        docs.remove(at);
    }
    r.replace_collection(&s.target, docs);
    Ok(out)
}

/// Runs `UPSERT`.
///
/// # Errors
/// See the module docs.
pub fn upsert(r: &mut Reference, s: &Upsert, ctx: &Ctx<'_>) -> Result<Output, Error> {
    let empty = Value::Object(Document::new());
    rowless(&s.value)?;
    let value = eval(&s.value, &Env::new(ctx, &empty, None))?.unwrap_or(Value::Null);
    let mut new = user_document(value)?;
    let mut docs = r.collection(&s.target).to_vec();
    let id_path = [Path::fields(["_id"])];
    let on = if s.on.is_empty() {
        &id_path[..]
    } else {
        &s.on[..]
    };
    let new_row = Value::Object(new.clone());
    let mut keys = Vec::with_capacity(on.len());
    for p in on {
        keys.push(eval(
            &Expr::Path { path: p.clone() },
            &Env::new(ctx, &new_row, None),
        )?);
    }
    if !s.on.is_empty() && keys.iter().any(|k| matches!(k, None | Some(Value::Null))) {
        // An explicit key must identify the document: `missing` / `null` would match nothing
        // (or everything) and silently duplicate on every retry.
        return Err(invalid(
            "an UPSERT ON field is missing or null in the document",
        ));
    }
    let mut found = None;
    if keys.iter().all(Option::is_some) {
        for (i, d) in docs.iter().enumerate() {
            let row = Value::Object(d.clone());
            let env = Env::new(ctx, &row, None);
            let mut all = true;
            for (p, k) in on.iter().zip(&keys) {
                let v = eval(&Expr::Path { path: p.clone() }, &env)?;
                all &= v.is_some() && values_equal(v.as_ref(), k.as_ref());
            }
            if all {
                if found.is_some() {
                    // Several candidates: replacing an arbitrary one would hide a data error.
                    return Err(invalid("the UPSERT ON fields match several documents"));
                }
                found = Some(i);
            }
        }
    }
    let mut out = Output {
        rows: Vec::new(),
        affected: Some(1),
    };
    if let Some(at) = found {
        new = keep_id(new, &docs[at])?;
        let old = Some(&docs[at]);
        push_returning(&mut out.rows, s.returning.as_ref(), old, Some(&new), ctx)?;
        docs[at] = new;
    } else {
        if new.get("_id").is_none() {
            new = with_id_first(new, r.fresh_object_id());
        }
        if docs
            .iter()
            .any(|d| values_equal(d.get("_id"), new.get("_id")))
        {
            return Err(Error::new(ErrorCode::DuplicateKey, "duplicate _id"));
        }
        push_returning(&mut out.rows, s.returning.as_ref(), None, Some(&new), ctx)?;
        docs.push(new);
    }
    r.replace_collection(&s.target, docs);
    Ok(out)
}

fn bump(out: &mut Output) {
    out.affected = Some(out.affected.unwrap_or(0) + 1);
}

/// Positions (in `_id` order) of the documents a filtered write touches.
fn matching(
    docs: &[Document],
    filter: Option<&Expr>,
    options: &[OptionItem],
    limit: Option<&Expr>,
    alias: Option<&str>,
    ctx: &Ctx<'_>,
) -> Result<Vec<usize>, Error> {
    if filter.is_none() && !full_scan_allowed(options, ctx)? {
        return Err(Error::new(
            ErrorCode::QueryTooComplex,
            "UPDATE/DELETE without WHERE needs OPTIONS (allow_full_scan_write = true)",
        ));
    }
    let mut hits = Vec::new();
    for (i, d) in docs.iter().enumerate() {
        let row = Value::Object(d.clone());
        let keep = match filter {
            Some(p) => truth(p, &Env::new(ctx, &row, alias))? == Tri::True,
            None => true,
        };
        if keep {
            hits.push(i);
        }
    }
    let rows = hits
        .iter()
        .map(|&i| Value::Int64(i64::try_from(i).unwrap_or(i64::MAX)));
    Ok(query::limit(rows.collect(), limit, None, ctx)?
        .into_iter()
        .filter_map(|v| match v {
            Value::Int64(i) => usize::try_from(i).ok(),
            _ => None,
        })
        .collect())
}

fn full_scan_allowed(options: &[OptionItem], ctx: &Ctx<'_>) -> Result<bool, Error> {
    let empty = Value::Object(Document::new());
    for o in options {
        if o.name.eq_ignore_ascii_case("allow_full_scan_write") {
            return Ok(matches!(
                eval(&o.value, &Env::new(ctx, &empty, None))?,
                Some(Value::Bool(true))
            ));
        }
    }
    Ok(false)
}

fn push_returning(
    rows: &mut Vec<Value>,
    returning: Option<&Returning>,
    old: Option<&Document>,
    new: Option<&Document>,
    ctx: &Ctx<'_>,
) -> Result<(), Error> {
    let Some(ret) = returning else { return Ok(()) };
    let image = match ret.image {
        Image::Old => old,
        Image::New => new,
    };
    if let Some(doc) = image {
        let row = Value::Object(doc.clone());
        rows.push(if ret.items.is_empty() {
            row
        } else {
            query::project(&ret.items, &Env::new(ctx, &row, None))?
        });
    }
    Ok(())
}

/// Checks a user-written document (FR-DOC-005).
fn user_document(v: Value) -> Result<Document, Error> {
    let Value::Object(doc) = v else {
        return Err(type_error("a written document must be an object"));
    };
    validate_user_document(&doc).map_err(Error::from)?;
    check_names(&Value::Object(doc.clone()))?;
    Ok(doc)
}

fn check_names(v: &Value) -> Result<(), Error> {
    match v {
        Value::Object(d) => {
            for (k, v) in d.iter() {
                validate_field_name(k).map_err(Error::from)?;
                check_names(v)?;
            }
        }
        Value::Array(items) => {
            for i in items {
                check_names(i)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn with_id_first(doc: Document, id: Value) -> Document {
    let mut fields = vec![("_id".to_owned(), id)];
    fields.extend(doc.into_fields());
    // `_id` was absent, so the names stay unique.
    Document::try_from_fields(fields).unwrap_or_default()
}

/// The replacement keeps the existing `_id`; a different one is `RGN-1001`.
fn keep_id(new: Document, old: &Document) -> Result<Document, Error> {
    match (new.get("_id"), old.get("_id")) {
        (Some(a), Some(b)) if !values_equal(Some(a), Some(b)) => {
            Err(invalid("_id is immutable and cannot be changed"))
        }
        (None, Some(id)) => Ok(with_id_first(new, id.clone())),
        _ => Ok(new),
    }
}

/// Applies RGQL update operators to one document.
fn apply_ops(
    ops: &[UpdateOp],
    doc: &Document,
    alias: Option<&str>,
    ctx: &Ctx<'_>,
) -> Result<Document, Error> {
    let row = Value::Object(doc.clone());
    let env = Env::new(ctx, &row, alias);
    if let [UpdateOp::Replace { value }] = ops {
        let v = eval(value, &env)?.unwrap_or(Value::Null);
        return keep_id(user_document(v)?, doc);
    }
    let mut lowered = Vec::with_capacity(ops.len());
    for op in ops {
        lower(op, &env, &mut lowered)?;
    }
    apply_updates(doc, &lowered, &UpdateContext { now_ms: ctx.now_ms }).map_err(Error::from)
}
