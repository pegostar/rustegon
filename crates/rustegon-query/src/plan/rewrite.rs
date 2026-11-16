// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Rule rewrites of bound expressions (query-engine.md §2 "Normalizer"): negation normal form
//! with `NOT` pushdown, flattening of `AND`/`OR`, boolean simplification, single-element `IN`
//! expansion and constant folding. (`BETWEEN` → range is done by the binder.)
//!
//! Every rule preserves three-valued semantics:
//! - De Morgan holds in Kleene logic; `NOT NOT x = x`;
//! - `NOT (a = b)` ⇔ `a != b` and `NOT (a IN l)` ⇔ `a NOT IN l` by definition (§4.1 docs in
//!   [`crate::expr::ops`]); `NOT (a IS NULL)` ⇔ `a IS NOT NULL` (`IS` is never unknown);
//! - `NOT` is **not** pushed into `<`, `<=`, `>`, `>=`: with multikey semantics
//!   `NOT (tags < 5)` (no element below 5) differs from `tags >= 5` (some element at least 5);
//! - `x AND true = x`, `x AND false = false`, `x OR true = true`, `x OR false = x` hold for
//!   unknown `x` as well; `null` constants are kept (they matter: `x AND null` is unknown or
//!   false).

use rustegon_doc::Value;

use crate::expr::{BExpr, CmpOp, EvalCtx, Scope, Step, Val, eval};

/// Normalises an expression (module docs).
#[must_use]
pub fn normalize(e: BExpr) -> BExpr {
    let e = map_children(e, normalize);
    let e = match e {
        BExpr::Not(inner) => push_not(*inner),
        BExpr::And(v) => simplify_and(v),
        BExpr::Or(v) => simplify_or(v),
        BExpr::In {
            expr,
            list,
            negated,
        } => expand_in(expr, list, negated),
        BExpr::Cmp { left, right, .. } if is_unknown_const(&left) || is_unknown_const(&right) => {
            // A comparison with a `null` / `missing` operand is unknown for every row (§4.1).
            BExpr::null()
        }
        other => other,
    };
    fold(e)
}

fn is_unknown_const(e: &BExpr) -> bool {
    matches!(e, BExpr::Const(None | Some(Value::Null)))
}

/// Normalises and returns the constant value of `e`, `None` when it is not constant.
#[must_use]
pub fn fold_constant(e: BExpr) -> Val {
    match normalize(e) {
        BExpr::Const(v) => v,
        _ => None,
    }
}

/// `x IN [v]` → `x = v` (an index point lookup; same semantics, element by element).
fn expand_in(expr: Box<BExpr>, list: Box<BExpr>, negated: bool) -> BExpr {
    if let BExpr::Const(Some(Value::Array(items))) = list.as_ref()
        && let [single] = items.as_slice()
        && !matches!(single, Value::Null | Value::Array(_))
    {
        let op = if negated { CmpOp::Ne } else { CmpOp::Eq };
        return BExpr::Cmp {
            op,
            left: expr,
            right: Box::new(BExpr::value(single.clone())),
        };
    }
    BExpr::In {
        expr,
        list,
        negated,
    }
}

/// `NOT e` with `e` already in negation normal form.
fn push_not(e: BExpr) -> BExpr {
    match e {
        BExpr::And(v) => simplify_or(v.into_iter().map(push_not).collect()),
        BExpr::Or(v) => simplify_and(v.into_iter().map(push_not).collect()),
        BExpr::Not(x) => *x,
        BExpr::Cmp {
            op: CmpOp::Eq,
            left,
            right,
        } => BExpr::Cmp {
            op: CmpOp::Ne,
            left,
            right,
        },
        BExpr::Cmp {
            op: CmpOp::Ne,
            left,
            right,
        } => BExpr::Cmp {
            op: CmpOp::Eq,
            left,
            right,
        },
        BExpr::In {
            expr,
            list,
            negated,
        } => BExpr::In {
            expr,
            list,
            negated: !negated,
        },
        BExpr::Is {
            expr,
            kind,
            negated,
        } => BExpr::Is {
            expr,
            kind,
            negated: !negated,
        },
        BExpr::Const(Some(Value::Bool(b))) => BExpr::value(Value::Bool(!b)),
        BExpr::Const(_) => BExpr::null(),
        other => BExpr::Not(Box::new(other)),
    }
}

fn is_bool(e: &BExpr, b: bool) -> bool {
    matches!(e, BExpr::Const(Some(Value::Bool(x))) if *x == b)
}

fn simplify_and(v: Vec<BExpr>) -> BExpr {
    let mut out = Vec::with_capacity(v.len());
    for e in v {
        match e {
            BExpr::And(inner) => out.extend(inner),
            e if is_bool(&e, true) => {}
            e if is_bool(&e, false) => return BExpr::value(Value::Bool(false)),
            e => out.push(e),
        }
    }
    match out.len() {
        0 => BExpr::value(Value::Bool(true)),
        1 => out.pop().unwrap_or_else(BExpr::null),
        _ => BExpr::And(out),
    }
}

fn simplify_or(v: Vec<BExpr>) -> BExpr {
    let mut out = Vec::with_capacity(v.len());
    for e in v {
        match e {
            BExpr::Or(inner) => out.extend(inner),
            e if is_bool(&e, false) => {}
            e if is_bool(&e, true) => return BExpr::value(Value::Bool(true)),
            e => out.push(e),
        }
    }
    match out.len() {
        0 => BExpr::value(Value::Bool(false)),
        1 => out.pop().unwrap_or_else(BExpr::null),
        _ => BExpr::Or(out),
    }
}

/// Whether `e` can be evaluated at bind time: no row, no variable, no volatile function.
fn foldable(e: &BExpr) -> bool {
    if matches!(e, BExpr::Const(_) | BExpr::Lambda { .. }) {
        return false;
    }
    let mut ok = true;
    e.walk(&mut |x| match x {
        BExpr::Field(_) | BExpr::Var { .. } | BExpr::Lambda { .. } => ok = false,
        BExpr::Call { func, .. } if func.is_volatile() => ok = false,
        _ => {}
    });
    ok
}

fn fold(e: BExpr) -> BExpr {
    if !foldable(&e) {
        return e;
    }
    let ctx = EvalCtx::new(0);
    match eval(&e, &Scope::new(None, &ctx)) {
        Ok(v) => BExpr::Const(v),
        Err(_) => e,
    }
}

fn map_steps(steps: Vec<Step>, f: fn(BExpr) -> BExpr) -> Vec<Step> {
    steps
        .into_iter()
        .map(|s| match s {
            Step::Dyn(e) => Step::Dyn(Box::new(f(*e))),
            other @ Step::Field { .. } => other,
        })
        .collect()
}

/// Applies `f` to every direct child expression.
// One arm per expression variant: splitting the match would only scatter the mapping.
#[allow(clippy::too_many_lines)]
fn map_children(e: BExpr, f: fn(BExpr) -> BExpr) -> BExpr {
    let bx = |b: Box<BExpr>| Box::new(f(*b));
    match e {
        BExpr::Const(_) => e,
        BExpr::Field(steps) => BExpr::Field(map_steps(steps, f)),
        BExpr::Var { slot, name, steps } => BExpr::Var {
            slot,
            name,
            steps: map_steps(steps, f),
        },
        BExpr::Access { base, steps } => BExpr::Access {
            base: bx(base),
            steps: map_steps(steps, f),
        },
        BExpr::Cmp { op, left, right } => BExpr::Cmp {
            op,
            left: bx(left),
            right: bx(right),
        },
        BExpr::Arith { op, left, right } => BExpr::Arith {
            op,
            left: bx(left),
            right: bx(right),
        },
        BExpr::And(v) => BExpr::And(v.into_iter().map(f).collect()),
        BExpr::Or(v) => BExpr::Or(v.into_iter().map(f).collect()),
        BExpr::Array(v) => BExpr::Array(v.into_iter().map(f).collect()),
        BExpr::Call { func, args } => BExpr::Call {
            func,
            args: args.into_iter().map(f).collect(),
        },
        BExpr::Not(x) => BExpr::Not(bx(x)),
        BExpr::Neg(x) => BExpr::Neg(bx(x)),
        BExpr::In {
            expr,
            list,
            negated,
        } => BExpr::In {
            expr: bx(expr),
            list: bx(list),
            negated,
        },
        BExpr::Like {
            expr,
            pattern,
            case_insensitive,
        } => BExpr::Like {
            expr: bx(expr),
            pattern: bx(pattern),
            case_insensitive,
        },
        BExpr::Matches {
            expr,
            pattern,
            compiled,
        } => BExpr::Matches {
            expr: bx(expr),
            pattern: bx(pattern),
            compiled,
        },
        BExpr::Contains { expr, arg, mode } => BExpr::Contains {
            expr: bx(expr),
            arg: bx(arg),
            mode,
        },
        BExpr::Is {
            expr,
            kind,
            negated,
        } => BExpr::Is {
            expr: bx(expr),
            kind,
            negated,
        },
        BExpr::Case {
            operand,
            whens,
            otherwise,
        } => BExpr::Case {
            operand: operand.map(bx),
            whens: whens.into_iter().map(|(w, t)| (f(w), f(t))).collect(),
            otherwise: otherwise.map(bx),
        },
        BExpr::Lambda {
            first_slot,
            params,
            body,
        } => BExpr::Lambda {
            first_slot,
            params,
            body: bx(body),
        },
        BExpr::Quantified {
            every,
            slot,
            var,
            source,
            predicate,
        } => BExpr::Quantified {
            every,
            slot,
            var,
            source: bx(source),
            predicate: bx(predicate),
        },
        BExpr::ElemMatch {
            source,
            slot,
            predicate,
        } => BExpr::ElemMatch {
            source: bx(source),
            slot,
            predicate: bx(predicate),
        },
        BExpr::Object(fields) => {
            BExpr::Object(fields.into_iter().map(|(n, v)| (n, f(v))).collect())
        }
    }
}

/// The top-level conjuncts of a normalised predicate.
#[must_use]
pub fn conjuncts(e: &BExpr) -> Vec<&BExpr> {
    match e {
        BExpr::And(v) => v.iter().collect(),
        other => vec![other],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::print_bexpr;

    fn field(n: &str) -> BExpr {
        BExpr::Field(vec![Step::field(n)])
    }

    fn cmp(op: CmpOp, l: BExpr, r: BExpr) -> BExpr {
        BExpr::Cmp {
            op,
            left: Box::new(l),
            right: Box::new(r),
        }
    }

    #[test]
    fn not_is_pushed_through_and_or_but_not_into_ranges() {
        let e = BExpr::Not(Box::new(BExpr::And(vec![
            cmp(CmpOp::Eq, field("a"), BExpr::value(Value::Int64(1))),
            BExpr::Or(vec![
                cmp(CmpOp::Lt, field("b"), BExpr::value(Value::Int64(2))),
                BExpr::Not(Box::new(field("c"))),
            ]),
        ])));
        assert_eq!(
            print_bexpr(&normalize(e)),
            "((a != 1) OR ((NOT (b < 2)) AND c))"
        );
    }

    #[test]
    fn constants_fold_and_booleans_simplify() {
        let e = BExpr::And(vec![
            cmp(
                CmpOp::Gt,
                field("a"),
                BExpr::Arith {
                    op: crate::expr::ArithOp::Add,
                    left: Box::new(BExpr::value(Value::Int64(1))),
                    right: Box::new(BExpr::value(Value::Int64(2))),
                },
            ),
            cmp(
                CmpOp::Eq,
                BExpr::value(Value::Int64(1)),
                BExpr::value(Value::Float64(1.0)),
            ),
        ]);
        assert_eq!(print_bexpr(&normalize(e)), "(a > 3)");
        let or = BExpr::Or(vec![field("x"), BExpr::value(Value::Bool(true))]);
        assert_eq!(print_bexpr(&normalize(or)), "true");
        let and_null = BExpr::And(vec![field("x"), BExpr::null()]);
        assert_eq!(print_bexpr(&normalize(and_null)), "(x AND null)");
    }
}
