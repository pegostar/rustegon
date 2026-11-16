// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Projection (`SELECT`, `RETURNING`): shapes one output row.
//!
//! A `missing` value omits its output field (`null` is kept); `SELECT VALUE` of `missing` is
//! `null`. *Provisional (PD pending)*: with only exclusions (`SELECT -secret`) the row is the
//! document minus the excluded paths; otherwise the listed fields are built first and the
//! exclusions are removed from that result.

use rustegon_common::Error;
use rustegon_doc::{Document, Value};

use crate::{
    bind::{BoundProjection, BoundSelect},
    expr::{EvalCtx, Scope, Step, eval},
};

/// Applies `select` to `row`.
///
/// # Errors
/// Evaluation errors (engine invariants only).
pub(crate) fn project(select: &BoundSelect, row: &Value, ctx: &EvalCtx) -> Result<Value, Error> {
    let scope = Scope::new(Some(row), ctx);
    match select {
        BoundSelect::Document => Ok(row.clone()),
        BoundSelect::Value(e) => Ok(eval(e, &scope)?.unwrap_or(Value::Null)),
        BoundSelect::Items(items) => {
            let only_excludes = items
                .iter()
                .all(|p| matches!(p, BoundProjection::Exclude(_)));
            let mut out = match (only_excludes, row) {
                (true, Value::Object(d)) => d.clone(),
                _ => Document::new(),
            };
            for item in items {
                match item {
                    BoundProjection::Field { name, expr } => {
                        if let Some(v) = eval(expr, &scope)? {
                            out.insert(name.clone(), v);
                        }
                    }
                    BoundProjection::Wildcard(expr) => {
                        if let Some(Value::Object(d)) = eval(expr, &scope)? {
                            for (n, v) in d.into_fields() {
                                out.insert(n, v);
                            }
                        }
                    }
                    BoundProjection::Exclude(_) => {}
                }
            }
            for item in items {
                if let BoundProjection::Exclude(steps) = item {
                    remove_path(&mut out, steps);
                }
            }
            Ok(Value::Object(out))
        }
    }
}

/// Removes the field at `steps` (objects only; a missing path is a no-op).
fn remove_path(doc: &mut Document, steps: &[Step]) {
    let Some((Step::Field { name, .. }, rest)) = steps.split_first() else {
        return;
    };
    if rest.is_empty() {
        doc.remove(name);
        return;
    }
    if let Some(Value::Object(inner)) = doc.get_mut(name) {
        remove_path(inner, rest);
    }
}
