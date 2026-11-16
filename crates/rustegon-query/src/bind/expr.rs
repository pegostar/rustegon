// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Expression binding: AST [`Expr`] → [`BExpr`] (query-engine.md §2 "Binder").
//!
//! - Names: a path whose first segment is the row alias refers to the row; one naming a lambda
//!   or quantifier variable refers to that variable (innermost first); any other path is a
//!   field of the row. Inside an *element context* (`ELEM MATCH (p, …)`, `PULL p WHERE …`) a
//!   path starting with `p` refers to the element, and any other unqualified path is relative
//!   to the element. *Provisional (PD pending)*: the specification shows `PULL tags WHERE
//!   tags = 'old'` and `ELEM MATCH (items, qty > 2)`; both spellings are accepted.
//! - Parameters become constants (FR-QL-003); `INTERVAL '…'` literals become their length in ms.
//! - Functions are resolved against the catalog (`RGN-1012` unknown, `RGN-1011` wrong arity or
//!   lambda shape, unsupported-feature error for M7+ names).
//! - `BETWEEN` becomes a range conjunction; constant-left comparisons are flipped so that the
//!   multikey operand is on the left.
//! - Statically known type errors (`IN` over a non-array constant, non-string `LIKE` pattern,
//!   invalid regular expression) are `RGN-1011`.

use std::sync::Arc;

use rustegon_common::Error;
use rustegon_doc::Value;

use crate::{
    ast::{BinaryOp, Expr, IsTest, Literal, Path, Quantifier, Segment},
    error::{type_error, unknown_function, unsupported},
    expr::{
        ArithOp, BExpr, CmpOp, CompiledRegex, ContainsMode, FuncClass, IsKind, Step,
        func::build_regex, func_date::parse_interval, lookup_function,
    },
    params::Params,
};

/// An element context (module docs).
#[derive(Debug, Clone)]
struct ElementCtx {
    prefix: Vec<Step>,
    slot: usize,
}

/// Binds expressions of one statement.
#[derive(Debug)]
pub struct ExprBinder<'p> {
    params: &'p Params,
    alias: Option<String>,
    vars: Vec<String>,
    element: Option<ElementCtx>,
}

impl<'p> ExprBinder<'p> {
    /// A binder for a statement whose rows are named `alias`.
    #[must_use]
    pub fn new(params: &'p Params, alias: Option<String>) -> Self {
        Self {
            params,
            alias,
            vars: Vec::new(),
            element: None,
        }
    }

    /// Binds `e`.
    ///
    /// # Errors
    /// `RGN-1011`, `RGN-1012`, unsupported-feature errors (module docs).
    // One arm per AST variant: splitting the match would only scatter the mapping.
    #[allow(clippy::too_many_lines)]
    pub fn bind(&mut self, e: &Expr) -> Result<BExpr, Error> {
        Ok(match e {
            Expr::Literal(l) => BExpr::Const(Some(literal_value(l)?)),
            Expr::Param { name } => BExpr::Const(Some(self.params.resolve(name)?.clone())),
            Expr::Path { path } => self.bind_path(path)?,
            Expr::Access { base, path } => BExpr::Access {
                base: Box::new(self.bind(base)?),
                steps: self.steps(&path.0)?,
            },
            Expr::Binary { op, left, right } => self.binary(*op, left, right)?,
            Expr::And { args } => BExpr::And(self.bind_all(args)?),
            Expr::Or { args } => BExpr::Or(self.bind_all(args)?),
            Expr::Neg { expr } => match self.bind(expr)? {
                BExpr::Const(Some(v)) if crate::expr::ops::is_numeric(&v) => {
                    match crate::expr::ops::negate(&v) {
                        Some(n) => BExpr::value(n),
                        None => BExpr::Neg(Box::new(BExpr::value(v))),
                    }
                }
                other => BExpr::Neg(Box::new(other)),
            },
            Expr::Not { expr } => BExpr::Not(Box::new(self.bind(expr)?)),
            Expr::Between { expr, low, high } => {
                let v = self.bind(expr)?;
                BExpr::And(vec![
                    cmp(CmpOp::Ge, v.clone(), self.bind(low)?),
                    cmp(CmpOp::Le, v, self.bind(high)?),
                ])
            }
            Expr::Is {
                expr,
                negated,
                test,
            } => BExpr::Is {
                expr: Box::new(self.bind(expr)?),
                kind: match test {
                    IsTest::Null => IsKind::Null,
                    IsTest::Missing => IsKind::Missing,
                },
                negated: *negated,
            },
            Expr::Call { name, args } => self.call(name, args)?,
            Expr::Star => return Err(type_error("`*` is only valid as the argument of count(*)")),
            Expr::Extract { unit, expr } => BExpr::Call {
                func: crate::expr::Func::Extract,
                args: vec![BExpr::value(Value::String(unit.clone())), self.bind(expr)?],
            },
            Expr::Case {
                operand,
                whens,
                otherwise,
            } => BExpr::Case {
                operand: match operand {
                    Some(o) => Some(Box::new(self.bind(o)?)),
                    None => None,
                },
                whens: whens
                    .iter()
                    .map(|w| Ok((self.bind(&w.when)?, self.bind(&w.then)?)))
                    .collect::<Result<_, Error>>()?,
                otherwise: match otherwise {
                    Some(o) => Some(Box::new(self.bind(o)?)),
                    None => None,
                },
            },
            Expr::Lambda { .. } => {
                return Err(type_error(
                    "a lambda is only valid as an argument of filter, map or reduce",
                ));
            }
            Expr::Quantified {
                quantifier,
                var,
                source,
                predicate,
            } => {
                let source = self.bind(source)?;
                let slot = self.vars.len();
                self.vars.push(var.clone());
                let predicate = self.bind(predicate);
                self.vars.pop();
                BExpr::Quantified {
                    every: *quantifier == Quantifier::Every,
                    slot,
                    var: var.clone(),
                    source: Box::new(source),
                    predicate: Box::new(predicate?),
                }
            }
            Expr::ElemMatch { path, predicate } => {
                let source = self.bind_path(path)?;
                let prefix = self.steps(&path.0)?;
                let slot = self.vars.len();
                let (predicate, _) = self.in_element(prefix, slot, |b| b.bind(predicate))?;
                BExpr::ElemMatch {
                    source: Box::new(source),
                    slot,
                    predicate: Box::new(predicate),
                }
            }
            Expr::Array { elements } => BExpr::Array(self.bind_all(elements)?),
            Expr::Object { fields } => BExpr::Object(
                fields
                    .iter()
                    .map(|f| Ok((f.name.clone(), self.bind(&f.value)?)))
                    .collect::<Result<_, Error>>()?,
            ),
        })
    }

    /// Binds `f` inside an element context whose element is `prefix` at `slot` (module docs).
    /// Returns the result and the slot.
    ///
    /// # Errors
    /// Whatever `f` returns.
    pub fn in_element<T>(
        &mut self,
        prefix: Vec<Step>,
        slot: usize,
        f: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<(T, usize), Error> {
        let saved = self.element.replace(ElementCtx { prefix, slot });
        self.vars.push("$elem".to_owned());
        let out = f(self);
        self.vars.pop();
        self.element = saved;
        Ok((out?, slot))
    }

    /// Binds the predicate of an update *array filter* `path[var -> body]` (query-language.md
    /// §4.3): the element is both the variable `var` and the context of unqualified paths
    /// (relative to the element). Returns the bound body and the element's slot.
    ///
    /// # Errors
    /// Binding errors of `body`.
    pub fn in_array_filter(&mut self, var: &str, body: &Expr) -> Result<(BExpr, usize), Error> {
        let slot = self.vars.len();
        let saved = self.element.replace(ElementCtx {
            prefix: Vec::new(),
            slot,
        });
        // The variable names the element slot itself, so `var.f` and `f` are the same field.
        self.vars.push(var.to_owned());
        let out = self.bind(body);
        self.vars.pop();
        self.element = saved;
        Ok((out?, slot))
    }

    /// The next free variable slot.
    #[must_use]
    pub fn next_slot(&self) -> usize {
        self.vars.len()
    }

    fn bind_all(&mut self, items: &[Expr]) -> Result<Vec<BExpr>, Error> {
        items.iter().map(|e| self.bind(e)).collect()
    }

    /// Converts path segments into steps.
    ///
    /// # Errors
    /// `RGN-1011` for `[]` segments (only valid in `INCLUDE`).
    pub fn steps(&mut self, segs: &[Segment]) -> Result<Vec<Step>, Error> {
        segs.iter()
            .map(|s| {
                Ok(match s {
                    Segment::Field(n) => Step::field(n.clone()),
                    Segment::Position(p) => Step::Field {
                        name: p.to_string(),
                        index: usize::try_from(*p).ok(),
                    },
                    Segment::Index(e) => Step::Dyn(Box::new(self.bind(e)?)),
                    Segment::Each => {
                        return Err(type_error("`[]` is only valid in INCLUDE paths"));
                    }
                })
            })
            .collect()
    }

    /// Binds a path expression (module docs: alias, variables, element context).
    ///
    /// # Errors
    /// As [`ExprBinder::steps`].
    pub fn bind_path(&mut self, path: &Path) -> Result<BExpr, Error> {
        let steps = self.steps(&path.0)?;
        let first = match steps.first() {
            Some(Step::Field { name, index: None }) => Some(name.clone()),
            _ => None,
        };
        if let Some(first) = &first {
            if let Some(slot) = self.vars.iter().rposition(|v| v == first) {
                return Ok(BExpr::Var {
                    slot,
                    name: first.clone(),
                    steps: steps[1..].to_vec(),
                });
            }
            if self.alias.as_deref() == Some(first.as_str()) {
                return Ok(BExpr::Field(steps[1..].to_vec()));
            }
        }
        if let Some(el) = &self.element {
            let rest = if steps.starts_with(&el.prefix) {
                steps[el.prefix.len()..].to_vec()
            } else {
                steps
            };
            return Ok(BExpr::Var {
                slot: el.slot,
                name: "$elem".to_owned(),
                steps: rest,
            });
        }
        Ok(BExpr::Field(steps))
    }

    fn binary(&mut self, op: BinaryOp, left: &Expr, right: &Expr) -> Result<BExpr, Error> {
        let (l, r) = (self.bind(left)?, self.bind(right)?);
        let cmp_op = match op {
            BinaryOp::Eq => Some(CmpOp::Eq),
            BinaryOp::EqWhole => Some(CmpOp::EqWhole),
            BinaryOp::Ne => Some(CmpOp::Ne),
            BinaryOp::Lt => Some(CmpOp::Lt),
            BinaryOp::Le => Some(CmpOp::Le),
            BinaryOp::Gt => Some(CmpOp::Gt),
            BinaryOp::Ge => Some(CmpOp::Ge),
            _ => None,
        };
        if let Some(c) = cmp_op {
            return Ok(cmp(c, l, r));
        }
        let arith = |op| BExpr::Arith {
            op,
            left: Box::new(l.clone()),
            right: Box::new(r.clone()),
        };
        Ok(match op {
            BinaryOp::Add => arith(ArithOp::Add),
            BinaryOp::Sub => arith(ArithOp::Sub),
            BinaryOp::Mul => arith(ArithOp::Mul),
            BinaryOp::Div => arith(ArithOp::Div),
            BinaryOp::Mod => arith(ArithOp::Mod),
            BinaryOp::Concat => arith(ArithOp::Concat),
            BinaryOp::In | BinaryOp::NotIn => {
                if matches!(&r, BExpr::Const(Some(v)) if !matches!(v, Value::Array(_) | Value::Null))
                {
                    return Err(type_error("the right operand of IN must be an array"));
                }
                BExpr::In {
                    expr: Box::new(l),
                    list: Box::new(r),
                    negated: op == BinaryOp::NotIn,
                }
            }
            BinaryOp::Like | BinaryOp::Ilike => {
                if matches!(&r, BExpr::Const(Some(v)) if !matches!(v, Value::String(_) | Value::Null))
                {
                    return Err(type_error("a LIKE pattern must be a string"));
                }
                BExpr::Like {
                    expr: Box::new(l),
                    pattern: Box::new(r),
                    case_insensitive: op == BinaryOp::Ilike,
                }
            }
            BinaryOp::Matches => {
                let compiled = match &r {
                    BExpr::Const(Some(Value::String(p))) => {
                        Some(CompiledRegex(Arc::new(build_regex(p).map_err(|e| {
                            type_error(format!("invalid regular expression: {e}"))
                        })?)))
                    }
                    BExpr::Const(Some(v)) if !matches!(v, Value::Null) => {
                        return Err(type_error("a MATCHES pattern must be a string"));
                    }
                    _ => None,
                };
                BExpr::Matches {
                    expr: Box::new(l),
                    pattern: Box::new(r),
                    compiled,
                }
            }
            BinaryOp::Contains | BinaryOp::ContainsAny | BinaryOp::ContainsAll => BExpr::Contains {
                expr: Box::new(l),
                arg: Box::new(r),
                mode: match op {
                    BinaryOp::Contains => ContainsMode::One,
                    BinaryOp::ContainsAny => ContainsMode::Any,
                    _ => ContainsMode::All,
                },
            },
            // Comparisons were handled above.
            _ => return Err(crate::error::internal("unhandled binary operator")),
        })
    }

    fn call(&mut self, name: &str, args: &[Expr]) -> Result<BExpr, Error> {
        let (func, min, max) = match lookup_function(name) {
            Some(FuncClass::Scalar(f, min, max)) => (f, min, max),
            Some(FuncClass::Deferred(feature, milestone)) => {
                return Err(unsupported(&format!("{feature} ({name})"), milestone));
            }
            None => return Err(unknown_function(name)),
        };
        if args.len() < min || args.len() > max {
            return Err(type_error(format!(
                "{}() takes {} argument(s), got {}",
                func.name(),
                if min == max {
                    min.to_string()
                } else if max == usize::MAX {
                    format!("at least {min}")
                } else {
                    format!("{min} to {max}")
                },
                args.len()
            ))
            .with_detail("function", func.name()));
        }
        let lambdas = func.lambda_args();
        let mut bound = Vec::with_capacity(args.len());
        for (i, a) in args.iter().enumerate() {
            match (lambdas.iter().find(|(at, _)| *at == i), a) {
                (Some(&(_, arity)), Expr::Lambda { params, body }) if params.len() == arity => {
                    let first_slot = self.vars.len();
                    self.vars.extend(params.iter().cloned());
                    let body = self.bind(body);
                    self.vars.truncate(first_slot);
                    bound.push(BExpr::Lambda {
                        first_slot,
                        params: params.clone(),
                        body: Box::new(body?),
                    });
                }
                (Some(&(_, arity)), _) => {
                    return Err(type_error(format!(
                        "argument {} of {}() must be a lambda with {arity} parameter(s)",
                        i + 1,
                        func.name()
                    )));
                }
                (None, e) => bound.push(self.bind(e)?),
            }
        }
        Ok(BExpr::Call { func, args: bound })
    }
}

/// A comparison with a constant left operand flipped to the right (module docs).
#[must_use]
pub fn cmp(op: CmpOp, l: BExpr, r: BExpr) -> BExpr {
    if l.is_const() && !r.is_const() {
        BExpr::Cmp {
            op: op.flipped(),
            left: Box::new(r),
            right: Box::new(l),
        }
    } else {
        BExpr::Cmp {
            op,
            left: Box::new(l),
            right: Box::new(r),
        }
    }
}

/// The value of a literal.
///
/// # Errors
/// `RGN-1011` for an invalid `INTERVAL` text.
pub fn literal_value(l: &Literal) -> Result<Value, Error> {
    Ok(match l {
        Literal::Null => Value::Null,
        Literal::Bool(b) => Value::Bool(*b),
        Literal::Int(i) => Value::Int64(*i),
        Literal::Float(f) => Value::Float64(*f),
        Literal::Decimal(d) => Value::Decimal(*d),
        Literal::String(s) => Value::String(s.clone()),
        Literal::DateTime(ms) => Value::DateTime(*ms),
        Literal::ObjectId(o) => Value::ObjectId(*o),
        Literal::Uuid(u) => Value::Uuid(*u),
        Literal::Interval(text) => Value::Int64(
            parse_interval(text).ok_or_else(|| type_error(format!("invalid interval '{text}'")))?,
        ),
    })
}
