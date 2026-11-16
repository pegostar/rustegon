// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The expression evaluator.
//!
//! Paths are resolved by reference ([`operand`]) so that comparing a field of a large document
//! clones nothing; only computed values are owned. Path semantics (query-language.md §4.1,
//! consistent with index key extraction, indexing.md §3.1): a field step on an object selects
//! the field; a numeric step (`.0`) on an array selects the element; any other field step on an
//! array **fans out** over its object elements and yields the array of the values found,
//! flattening values that are arrays themselves (`missing` when none is found); everything else
//! is `missing`. *Provisional (PD pending)*: the flattening rule is MongoDB's implicit array
//! traversal; it makes `items.sku = 'x'` match exactly the documents an index on `items.sku`
//! finds.

use std::{borrow::Cow, cell::Cell};

use rustegon_common::Error;
use rustegon_doc::{Document, Value};

use super::{
    BExpr, Step, Val, func,
    ops::{self, Tri, contains, in_list, is_test, like, string_predicate, truth},
};

/// Per-statement evaluation context.
#[derive(Debug)]
pub struct EvalCtx {
    /// `now()`: the statement's transaction timestamp in ms since the Unix epoch.
    pub now_ms: i64,
    warnings: Cell<u64>,
}

impl EvalCtx {
    /// A context whose `now()` is `now_ms`.
    #[must_use]
    pub fn new(now_ms: i64) -> Self {
        Self {
            now_ms,
            warnings: Cell::new(0),
        }
    }

    /// Records a warning (a total function returned `null` for invalid input, §4.2).
    pub fn warn(&self) {
        self.warnings.set(self.warnings.get().saturating_add(1));
    }

    /// Warnings recorded so far.
    #[must_use]
    pub fn warnings(&self) -> u64 {
        self.warnings.get()
    }
}

/// The values an expression is evaluated against: the current row and the variable stack.
#[derive(Debug, Clone)]
pub struct Scope<'a> {
    /// Current row (`None`: no row, e.g. `INSERT … VALUE`).
    pub row: Option<&'a Value>,
    /// Variables by slot.
    pub vars: Vec<Val>,
    /// Statement context.
    pub ctx: &'a EvalCtx,
}

impl<'a> Scope<'a> {
    /// A scope over `row` without variables.
    #[must_use]
    pub fn new(row: Option<&'a Value>, ctx: &'a EvalCtx) -> Self {
        Self {
            row,
            vars: Vec::new(),
            ctx,
        }
    }

    /// A child scope with `value` bound at `slot` (dropping deeper slots).
    #[must_use]
    pub fn with_var(&self, slot: usize, value: Val) -> Self {
        let mut vars: Vec<Val> = self.vars.iter().take(slot).cloned().collect();
        vars.resize(slot, None);
        vars.push(value);
        Self {
            row: self.row,
            vars,
            ctx: self.ctx,
        }
    }
}

/// Evaluates `e`.
///
/// # Errors
/// Only engine invariant violations; invalid input yields `null` (functions are total).
#[allow(clippy::many_single_char_names)] // Operands named as in the operator tables (§4.1).
pub fn eval(e: &BExpr, s: &Scope<'_>) -> Result<Val, Error> {
    match e {
        BExpr::Const(v) => Ok(v.clone()),
        BExpr::Field(_) | BExpr::Var { .. } | BExpr::Access { .. } => {
            Ok(ops::owned(operand(e, s)?))
        }
        BExpr::Cmp { .. }
        | BExpr::And(_)
        | BExpr::Or(_)
        | BExpr::Not(_)
        | BExpr::In { .. }
        | BExpr::Like { .. }
        | BExpr::Matches { .. }
        | BExpr::Contains { .. }
        | BExpr::Quantified { .. }
        | BExpr::ElemMatch { .. } => Ok(Some(ops::tri_value(eval_predicate(e, s)?))),
        BExpr::Is {
            expr,
            kind,
            negated,
        } => {
            let v = operand(expr, s)?;
            Ok(Some(Value::Bool(is_test(v.as_deref(), *kind, *negated))))
        }
        BExpr::Arith { op, left, right } => {
            let (l, r) = (operand(left, s)?, operand(right, s)?);
            // `missing` in, `missing` out; else `null` in, `null` out (§4.3).
            let (Some(a), Some(b)) = (l.as_deref(), r.as_deref()) else {
                return Ok(None);
            };
            Ok(Some(
                if matches!(a, Value::Null) || matches!(b, Value::Null) {
                    Value::Null
                } else {
                    ops::arith(*op, a, b).unwrap_or_else(|| {
                        s.ctx.warn();
                        Value::Null
                    })
                },
            ))
        }
        BExpr::Neg(inner) => Ok(Some(match operand(inner, s)?.as_deref() {
            None => return Ok(None),
            Some(Value::Null) => Value::Null,
            Some(v) => ops::negate(v).unwrap_or_else(|| {
                s.ctx.warn();
                Value::Null
            }),
        })),
        BExpr::Call { func, args } => func::call(*func, args, s),
        BExpr::Case {
            operand: subject,
            whens,
            otherwise,
        } => eval_case(subject.as_deref(), whens, otherwise.as_deref(), s),
        // A lambda outside a higher-order function is rejected by the binder.
        BExpr::Lambda { .. } => Ok(Some(Value::Null)),
        BExpr::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for i in items {
                // `missing` cannot live inside an array: it becomes `null`.
                out.push(eval(i, s)?.unwrap_or(Value::Null));
            }
            Ok(Some(Value::Array(out)))
        }
        BExpr::Object(fields) => {
            let mut d = Document::new();
            for (name, fe) in fields {
                if let Some(v) = eval(fe, s)? {
                    d.insert(name.clone(), v);
                }
            }
            Ok(Some(Value::Object(d)))
        }
    }
}

fn eval_case(
    subject: Option<&BExpr>,
    whens: &[(BExpr, BExpr)],
    otherwise: Option<&BExpr>,
    s: &Scope<'_>,
) -> Result<Val, Error> {
    let subject = match subject {
        Some(e) => Some(operand(e, s)?),
        None => None,
    };
    for (w, t) in whens {
        let hit = match &subject {
            Some(v) => {
                let wv = operand(w, s)?;
                // Simple `CASE x WHEN v` uses `=` (multikey), §4.3.
                ops::compare(super::CmpOp::Eq, v.as_deref(), wv.as_deref()) == Some(true)
            }
            None => eval_predicate(w, s)? == Some(true),
        };
        if hit {
            return eval(t, s);
        }
    }
    match otherwise {
        Some(o) => eval(o, s),
        None => Ok(Some(Value::Null)),
    }
}

/// Evaluates `e` as a predicate (three-valued).
///
/// # Errors
/// As [`eval`].
#[allow(clippy::many_single_char_names)] // Operands named as in the operator tables (§4.1).
pub fn eval_predicate(e: &BExpr, s: &Scope<'_>) -> Result<Tri, Error> {
    Ok(match e {
        BExpr::Cmp { op, left, right } => {
            let (l, r) = (operand(left, s)?, operand(right, s)?);
            ops::compare(*op, l.as_deref(), r.as_deref())
        }
        BExpr::And(args) => {
            // Three-valued AND: false dominates, then unknown.
            let mut acc = Some(true);
            for a in args {
                match eval_predicate(a, s)? {
                    Some(false) => return Ok(Some(false)),
                    None => acc = None,
                    Some(true) => {}
                }
            }
            acc
        }
        BExpr::Or(args) => {
            let mut acc = Some(false);
            for a in args {
                match eval_predicate(a, s)? {
                    Some(true) => return Ok(Some(true)),
                    None => acc = None,
                    Some(false) => {}
                }
            }
            acc
        }
        BExpr::Not(inner) => ops::not(eval_predicate(inner, s)?),
        BExpr::In {
            expr,
            list,
            negated,
        } => {
            let (v, l) = (operand(expr, s)?, operand(list, s)?);
            let t = in_list(v.as_deref(), l.as_deref());
            if *negated { ops::not(t) } else { t }
        }
        BExpr::Like {
            expr,
            pattern,
            case_insensitive,
        } => {
            let (v, p) = (operand(expr, s)?, operand(pattern, s)?);
            match p.as_deref() {
                Some(Value::String(p)) => {
                    string_predicate(v.as_deref(), |t| like(t, p, *case_insensitive))
                }
                _ => None,
            }
        }
        BExpr::Matches {
            expr,
            pattern,
            compiled,
        } => {
            let v = operand(expr, s)?;
            let re = match compiled {
                Some(c) => Some(c.0.clone()),
                None => match operand(pattern, s)?.as_deref() {
                    Some(Value::String(p)) => func::compile_regex(p, s.ctx),
                    _ => None,
                },
            };
            re.and_then(|re| string_predicate(v.as_deref(), |t| re.is_match(t)))
        }
        BExpr::Contains { expr, arg, mode } => {
            let (l, r) = (operand(expr, s)?, operand(arg, s)?);
            contains(l.as_deref(), r.as_deref(), *mode)
        }
        BExpr::Quantified {
            every,
            slot,
            source,
            predicate,
            ..
        } => quantified(*every, *slot, source, predicate, s)?,
        BExpr::ElemMatch {
            source,
            slot,
            predicate,
        } => elem_match(*slot, source, predicate, s)?,
        other => truth(eval(other, s)?.as_ref()),
    })
}

/// `ANY` / `EVERY` over an array (unknown when the source is not an array).
fn quantified(
    every: bool,
    slot: usize,
    source: &BExpr,
    predicate: &BExpr,
    s: &Scope<'_>,
) -> Result<Tri, Error> {
    let src = operand(source, s)?;
    let Some(Value::Array(items)) = src.as_deref() else {
        return Ok(None);
    };
    let mut acc = Some(every);
    for item in items {
        let child = s.with_var(slot, Some(item.clone()));
        match eval_predicate(predicate, &child)? {
            Some(b) if b != every => return Ok(Some(b)),
            None => acc = None,
            Some(_) => {}
        }
    }
    Ok(acc)
}

/// `ELEM MATCH`: two-valued (§4.3) — `true` when some element satisfies the predicate,
/// otherwise `false` (also on a non-array).
fn elem_match(slot: usize, source: &BExpr, predicate: &BExpr, s: &Scope<'_>) -> Result<Tri, Error> {
    let src = operand(source, s)?;
    let Some(Value::Array(items)) = src.as_deref() else {
        return Ok(Some(false));
    };
    for item in items {
        let child = s.with_var(slot, Some(item.clone()));
        if eval_predicate(predicate, &child)? == Some(true) {
            return Ok(Some(true));
        }
    }
    Ok(Some(false))
}

/// Evaluates `e`, borrowing from the row, the variables or the constant when possible.
///
/// # Errors
/// As [`eval`].
pub fn operand<'s>(e: &'s BExpr, s: &'s Scope<'_>) -> Result<Option<Cow<'s, Value>>, Error> {
    match e {
        BExpr::Const(v) => Ok(v.as_ref().map(Cow::Borrowed)),
        BExpr::Field(steps) => match s.row {
            Some(row) => resolve(Cow::Borrowed(row), steps, s),
            None => Ok(None),
        },
        BExpr::Var { slot, steps, .. } => match s.vars.get(*slot).and_then(Option::as_ref) {
            Some(v) => resolve(Cow::Borrowed(v), steps, s),
            None => Ok(None),
        },
        BExpr::Access { base, steps } => match eval(base, s)? {
            Some(v) => resolve(Cow::Owned(v), steps, s),
            None => Ok(None),
        },
        other => Ok(eval(other, s)?.map(Cow::Owned)),
    }
}

/// Applies `steps` to `base` (module docs).
fn resolve<'v>(
    base: Cow<'v, Value>,
    steps: &[Step],
    s: &Scope<'_>,
) -> Result<Option<Cow<'v, Value>>, Error> {
    let mut cur = base;
    for step in steps {
        let next = match step {
            Step::Field { name, index } => field_step(cur, name, *index),
            Step::Dyn(e) => {
                let key = eval(e, s)?;
                match key {
                    Some(Value::String(name)) => field_step(cur, &name, None),
                    Some(k) => match ops::as_int(&k).and_then(|i| usize::try_from(i).ok()) {
                        Some(i) => index_step(cur, i),
                        None => None,
                    },
                    None => None,
                }
            }
        };
        match next {
            Some(v) => cur = v,
            None => return Ok(None),
        }
    }
    Ok(Some(cur))
}

fn index_step(cur: Cow<'_, Value>, i: usize) -> Option<Cow<'_, Value>> {
    match cur {
        Cow::Borrowed(Value::Array(items)) => items.get(i).map(Cow::Borrowed),
        Cow::Owned(Value::Array(mut items)) if i < items.len() => {
            Some(Cow::Owned(items.swap_remove(i)))
        }
        _ => None,
    }
}

fn field_step<'v>(cur: Cow<'v, Value>, name: &str, index: Option<usize>) -> Option<Cow<'v, Value>> {
    match cur {
        Cow::Borrowed(Value::Object(d)) => d.get(name).map(Cow::Borrowed),
        Cow::Owned(Value::Object(mut d)) => d.remove(name).map(Cow::Owned),
        Cow::Borrowed(Value::Array(_)) | Cow::Owned(Value::Array(_)) => match index {
            Some(i) => index_step(cur, i),
            None => fan_out(&cur, name),
        },
        _ => None,
    }
}

/// Fan-out of a field step over the object elements of an array (module docs).
fn fan_out<'v>(cur: &Value, name: &str) -> Option<Cow<'v, Value>> {
    let Value::Array(items) = cur else {
        return None;
    };
    let mut found = Vec::new();
    let mut any = false;
    for it in items {
        if let Value::Object(d) = it
            && let Some(v) = d.get(name)
        {
            any = true;
            match v {
                Value::Array(inner) => found.extend(inner.iter().cloned()),
                other => found.push(other.clone()),
            }
        }
    }
    any.then_some(Cow::Owned(Value::Array(found)))
}
