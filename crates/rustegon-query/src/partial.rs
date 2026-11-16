// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Partial-index predicates (indexing.md §1 `partial`, §3.1): compilation of the stored RGQL
//! text and the [`PartialFilter`] the index write path calls.
//!
//! A partial predicate is an RGQL expression over the document (`total > 0`), without
//! parameters, aliases or row-independent functions (`now()`, `id()`, `rev()` would make index
//! membership depend on when or how a document was written). A document belongs to the index
//! when the predicate is **true** (unknown excludes it, like `WHERE`).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use rustegon_catalog::IndexDescriptor;
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_index::PartialFilter;

use crate::{
    bind::ExprBinder,
    expr::{BExpr, EvalCtx, Scope, eval_predicate},
    params::Params,
    parse::parse_expr,
    plan::rewrite::normalize,
};

/// Compiles partial-predicate text.
///
/// # Errors
/// `RGN-1010` (syntax), `RGN-1011` / `RGN-1012` (binding), `RGN-1001` for parameters or
/// volatile functions.
pub fn bind_partial(text: &str) -> Result<BExpr, Error> {
    let ast = parse_expr(text).map_err(Error::from)?;
    let params = Params::new();
    let mut binder = ExprBinder::new(&params, None);
    let bound = normalize(binder.bind(&ast)?);
    let mut volatile = false;
    bound.walk(&mut |e| {
        if matches!(e, BExpr::Call { func, .. } if func.is_volatile()) {
            volatile = true;
        }
    });
    if volatile {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "a partial-index predicate cannot use now(), id() or rev()",
        ));
    }
    Ok(bound)
}

/// Whether `doc` satisfies the compiled predicate.
///
/// # Errors
/// Evaluation errors (engine invariants only).
pub fn eval_partial(pred: &BExpr, doc: &Document) -> Result<bool, Error> {
    let row = Value::Object(doc.clone());
    let ctx = EvalCtx::new(0);
    Ok(eval_predicate(pred, &Scope::new(Some(&row), &ctx))? == Some(true))
}

/// The [`PartialFilter`] backed by this crate's evaluator, caching compiled predicates per
/// index descriptor version.
#[derive(Debug, Default)]
pub struct ExprPartialFilter {
    cache: Mutex<HashMap<(u32, u64), Arc<BExpr>>>,
}

impl ExprPartialFilter {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn compiled(&self, index: &IndexDescriptor, text: &str) -> Result<Arc<BExpr>, Error> {
        let key = (index.id, index.version);
        if let Some(p) = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Ok(Arc::clone(p));
        }
        let p = Arc::new(bind_partial(text)?);
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        // Older versions of the same index are dead entries: drop them (bounded cache).
        cache.retain(|(id, _), _| *id != index.id);
        cache.insert(key, Arc::clone(&p));
        Ok(p)
    }
}

impl PartialFilter for ExprPartialFilter {
    fn matches(&self, index: &IndexDescriptor, doc: &Document) -> Result<bool, Error> {
        let Some(text) = &index.partial else {
            return Ok(true);
        };
        let pred = self.compiled(index, text)?;
        eval_partial(pred.as_ref(), doc)
    }
}
