// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Expression evaluation (query-language.md §4) for the reference interpreter.
//!
//! Values are [`Val`] = `Option<Value>`, `None` being `missing` (data-model §2: `missing` is never
//! a stored value). Predicates are three-valued ([`Tri`]): a `WHERE` keeps a row only when its
//! predicate is `true` (§4.1).
//!
//! Rules (the *Provisional* ones are listed in query-language.md §4.3):
//! - **Paths.** The first segment names, in this order, a variable bound by a quantifier, lambda
//!   or `PULL … WHERE` (innermost first), the `FROM` alias (the whole row), or a field of the
//!   row. `.name` on an object selects the field; `.name` on an array *fans out*: it yields the
//!   array of `.name` of the elements that are objects having it, flattening values that are
//!   arrays one level (MongoDB implicit traversal, the index key extraction of indexing.md
//!   §3.1), or `missing` when there is none. `.n` / `[int]` on an array select an element (`[-1]` and out of range:
//!   `missing`); `.n` on an object selects the field named `n`; `[string]` selects a field.
//!   Anything else is `missing`.
//! - **Logic.** Kleene `AND`/`OR`/`NOT`; an operand that is not a boolean (including `null` and
//!   `missing`) is *unknown*.
//! - **Constructors.** A `missing` array element becomes `null`; a `missing` object field is
//!   omitted; duplicate names are `RGN-1004`.
//! - **`CASE`.** The first branch whose condition is `true` (simple form: whose value is `=` to
//!   the operand) wins; no match and no `ELSE` gives `null`.
//! - **Quantifiers.** `ANY v IN arr SATISFIES p` is the Kleene `OR` of `p` over the elements
//!   (`false` on an empty array), `EVERY` the Kleene `AND` (`true` on an empty array); a
//!   non-array source is *unknown*.
//! - **`ELEM MATCH (path, p)`.** `true` if some element of the array at `path` satisfies `p`
//!   evaluated with that element as the row (paths inside `p` are relative to the element),
//!   `false` otherwise (also for a non-array): two-valued (*Provisional*).

use rustegon_common::Error;
use rustegon_doc::{Document, Value};

use super::{
    Params, arith,
    error::{invalid, type_error, unsupported},
    func, predicate,
};
use crate::ast::{BinaryOp, Expr, IsTest, Literal, Quantifier, Segment};

/// An expression value; `None` is `missing`.
pub type Val = Option<Value>;

/// Three-valued truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    /// `true`.
    True,
    /// `false`.
    False,
    /// `null` / unknown.
    Unknown,
}

impl Tri {
    /// Truth of a value: only booleans are known.
    #[must_use]
    pub fn of(v: &Val) -> Self {
        match v {
            Some(Value::Bool(b)) => Self::from(*b),
            _ => Self::Unknown,
        }
    }

    /// As a value: `true`, `false` or `null`.
    #[must_use]
    pub fn value(self) -> Val {
        Some(match self {
            Self::True => Value::Bool(true),
            Self::False => Value::Bool(false),
            Self::Unknown => Value::Null,
        })
    }

    /// Kleene negation.
    #[must_use]
    pub fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    /// Kleene conjunction of a sequence (`true` when empty).
    pub fn all(items: impl IntoIterator<Item = Self>) -> Self {
        let mut out = Self::True;
        for t in items {
            match t {
                Self::False => return Self::False,
                Self::Unknown => out = Self::Unknown,
                Self::True => {}
            }
        }
        out
    }

    /// Kleene disjunction of a sequence (`false` when empty).
    pub fn any(items: impl IntoIterator<Item = Self>) -> Self {
        let mut out = Self::False;
        for t in items {
            match t {
                Self::True => return Self::True,
                Self::Unknown => out = Self::Unknown,
                Self::False => {}
            }
        }
        out
    }
}

impl From<bool> for Tri {
    fn from(b: bool) -> Self {
        if b { Self::True } else { Self::False }
    }
}

/// Statement-wide evaluation inputs.
#[derive(Debug)]
pub struct Ctx<'a> {
    /// Bound parameters.
    pub params: &'a Params,
    /// `now()` in ms since the epoch.
    pub now_ms: i64,
}

/// Evaluation scope: the current row, the `FROM` alias and bound variables.
#[derive(Debug, Clone)]
pub struct Env<'a> {
    /// Statement inputs.
    pub ctx: &'a Ctx<'a>,
    /// Current row (a document as [`Value::Object`], or an array element).
    pub row: &'a Value,
    /// `FROM … AS alias`.
    pub alias: Option<&'a str>,
    /// Variables, innermost last.
    vars: Vec<(String, Val)>,
}

impl<'a> Env<'a> {
    /// A scope over `row`.
    #[must_use]
    pub fn new(ctx: &'a Ctx<'a>, row: &'a Value, alias: Option<&'a str>) -> Self {
        Self {
            ctx,
            row,
            alias,
            vars: Vec::new(),
        }
    }

    /// This scope plus variable `name` = `value`.
    #[must_use]
    pub fn with_var(&self, name: &str, value: Val) -> Self {
        let mut out = self.clone();
        out.vars.push((name.to_owned(), value));
        out
    }

    /// This scope with another current row (variables and alias kept).
    #[must_use]
    pub fn with_row<'b>(&'b self, row: &'b Value) -> Env<'b> {
        Env {
            ctx: self.ctx,
            row,
            alias: self.alias,
            vars: self.vars.clone(),
        }
    }

    fn var(&self, name: &str) -> Option<&Val> {
        self.vars
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }
}

/// Evaluates `e` in `env`.
///
/// # Errors
/// Unbound parameters (`RGN-1001`), misuse of `*` or lambdas, unknown functions or wrong arity
/// (`RGN-1011`/`RGN-1012`), duplicate constructor names (`RGN-1004`), unsupported features.
// One arm per AST variant, so the semantics of every expression form read in one place.
#[allow(clippy::too_many_lines)]
pub fn eval(e: &Expr, env: &Env<'_>) -> Result<Val, Error> {
    Ok(match e {
        Expr::Literal(l) => Some(literal(l)?),
        Expr::Param { name } => Some(
            env.ctx
                .params
                .get(name)
                .cloned()
                .ok_or_else(|| invalid(format!("parameter ${name} is not bound")))?,
        ),
        Expr::Path { path } => {
            let Some((Segment::Field(first), rest)) = path.0.split_first() else {
                return Err(type_error("a path must start with a field name"));
            };
            walk(root(first, env), rest, env)?
        }
        Expr::Access { base, path } => walk(eval(base, env)?, &path.0, env)?,
        Expr::Binary { op, left, right } => binary(*op, eval(left, env)?, eval(right, env)?)?,
        Expr::And { args } => Tri::all(truths(args, env)?).value(),
        Expr::Or { args } => Tri::any(truths(args, env)?).value(),
        Expr::Not { expr } => Tri::of(&eval(expr, env)?).negate().value(),
        Expr::Neg { expr } => arith::neg(eval(expr, env)?),
        Expr::Between { expr, low, high } => {
            let v = eval(expr, env)?;
            let ge = predicate::compare_op(BinaryOp::Ge, &v, &eval(low, env)?);
            let le = predicate::compare_op(BinaryOp::Le, &v, &eval(high, env)?);
            Tri::all([ge, le]).value()
        }
        Expr::Is {
            expr,
            negated,
            test,
        } => {
            let v = eval(expr, env)?;
            let hit = match test {
                IsTest::Null => matches!(v, None | Some(Value::Null)),
                IsTest::Missing => v.is_none(),
            };
            Some(Value::Bool(hit != *negated))
        }
        Expr::Call { name, args } => func::call(name, args, env)?,
        Expr::Star => return Err(type_error("`*` is only allowed in count(*)")),
        Expr::Extract { .. } => return Err(unsupported("extract (date functions)")),
        Expr::Case {
            operand,
            whens,
            otherwise,
        } => case(operand.as_deref(), whens, otherwise.as_deref(), env)?,
        Expr::Lambda { .. } => {
            return Err(type_error(
                "a lambda is only allowed as a function argument",
            ));
        }
        Expr::Quantified {
            quantifier,
            var,
            source,
            predicate,
        } => match eval(source, env)? {
            Some(Value::Array(items)) => {
                let mut truths = Vec::with_capacity(items.len());
                for item in items {
                    truths.push(Tri::of(&eval(predicate, &env.with_var(var, Some(item)))?));
                }
                match quantifier {
                    Quantifier::Any => Tri::any(truths),
                    Quantifier::Every => Tri::all(truths),
                }
                .value()
            }
            _ => Tri::Unknown.value(),
        },
        Expr::ElemMatch { path, predicate } => {
            let arr = eval(&Expr::Path { path: path.clone() }, env)?;
            let mut hit = false;
            if let Some(Value::Array(items)) = &arr {
                for item in items {
                    if Tri::of(&eval(predicate, &env.with_row(item))?) == Tri::True {
                        hit = true;
                        break;
                    }
                }
            }
            Some(Value::Bool(hit))
        }
        Expr::Array { elements } => {
            let mut out = Vec::with_capacity(elements.len());
            for el in elements {
                out.push(eval(el, env)?.unwrap_or(Value::Null));
            }
            Some(Value::Array(out))
        }
        Expr::Object { fields } => {
            let mut out = Vec::with_capacity(fields.len());
            for f in fields {
                if let Some(v) = eval(&f.value, env)? {
                    out.push((f.name.clone(), v));
                }
            }
            Some(Value::Object(
                Document::try_from_fields(out).map_err(Error::from)?,
            ))
        }
    })
}

/// Truth of a predicate on `env` (`WHERE`, `PULL … WHERE`, array filters).
///
/// # Errors
/// As [`eval`].
pub fn truth(e: &Expr, env: &Env<'_>) -> Result<Tri, Error> {
    Ok(Tri::of(&eval(e, env)?))
}

fn truths(args: &[Expr], env: &Env<'_>) -> Result<Vec<Tri>, Error> {
    args.iter().map(|a| truth(a, env)).collect()
}

/// Value of a literal; `INTERVAL` literals are their length in ms (`int64`, *Provisional*).
///
/// # Errors
/// `RGN-1011` for an interval text that is not `<integer> <unit>`.
pub fn literal(l: &Literal) -> Result<Value, Error> {
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
            interval_ms(text).ok_or_else(|| type_error(format!("invalid interval '{text}'")))?,
        ),
    })
}

/// `'<n> <unit>'` with units ms, second, minute, hour, day, week (singular or plural).
fn interval_ms(text: &str) -> Option<i64> {
    let mut parts = text.split_whitespace();
    let n: i64 = parts.next()?.parse().ok()?;
    let unit = parts.next()?.to_ascii_lowercase();
    if parts.next().is_some() {
        return None;
    }
    let ms: i64 = match unit.trim_end_matches('s') {
        "m" | "millisecond" => 1,
        "second" | "sec" => 1_000,
        "minute" | "min" => 60_000,
        "hour" => 3_600_000,
        "day" => 86_400_000,
        "week" => 604_800_000,
        _ => return None,
    };
    n.checked_mul(ms)
}

/// Value of the first path segment (see the module docs for the resolution order).
fn root(name: &str, env: &Env<'_>) -> Val {
    if let Some(v) = env.var(name) {
        return v.clone();
    }
    if env.alias == Some(name) {
        return Some(env.row.clone());
    }
    match env.row {
        Value::Object(d) => d.get(name).cloned(),
        _ => None,
    }
}

/// Applies path segments to a value.
fn walk(mut cur: Val, segments: &[Segment], env: &Env<'_>) -> Result<Val, Error> {
    for seg in segments {
        let Some(v) = cur else { return Ok(None) };
        cur = match seg {
            Segment::Field(name) => field(&v, name),
            Segment::Position(p) => match &v {
                Value::Array(items) => usize::try_from(*p).ok().and_then(|i| items.get(i)).cloned(),
                Value::Object(d) => d.get(&p.to_string()).cloned(),
                _ => None,
            },
            Segment::Index(e) => match (&v, eval(e, env)?) {
                (Value::Array(items), Some(Value::Int64(i))) => {
                    usize::try_from(i).ok().and_then(|i| items.get(i)).cloned()
                }
                (Value::Object(d), Some(Value::String(name))) => d.get(&name).cloned(),
                _ => None,
            },
            Segment::Each => return Err(type_error("`[]` is only allowed in INCLUDE paths")),
        };
    }
    Ok(cur)
}

/// `.name` on a value, fanning out over arrays (module docs).
fn field(v: &Value, name: &str) -> Val {
    match v {
        Value::Object(d) => d.get(name).cloned(),
        Value::Array(items) => {
            let mut hits: Vec<Value> = Vec::new();
            let mut found = false;
            for item in items {
                if let Value::Object(d) = item
                    && let Some(hit) = d.get(name)
                {
                    found = true;
                    // Array values are flattened one level, like index key extraction
                    // (indexing.md §3.1), so `items.tags = 'x'` holds exactly for the
                    // documents an index on `items.tags` finds.
                    match hit {
                        Value::Array(inner) => hits.extend(inner.iter().cloned()),
                        other => hits.push(other.clone()),
                    }
                }
            }
            found.then_some(Value::Array(hits))
        }
        _ => None,
    }
}

fn binary(op: BinaryOp, l: Val, r: Val) -> Result<Val, Error> {
    use BinaryOp as B;
    Ok(match op {
        B::Add | B::Sub | B::Mul | B::Div | B::Mod => arith::binary(op, l, r)?,
        B::Concat => arith::concat(l, r),
        B::Eq | B::EqWhole | B::Ne | B::Lt | B::Le | B::Gt | B::Ge => {
            predicate::compare_op(op, &l, &r).value()
        }
        B::In => predicate::in_list(&l, &r).value(),
        B::NotIn => predicate::in_list(&l, &r).negate().value(),
        B::Like => predicate::like(&l, &r, false).value(),
        B::Ilike => predicate::like(&l, &r, true).value(),
        B::Matches => predicate::matches(&l, &r).value(),
        B::Contains => predicate::contains(&l, &r).value(),
        B::ContainsAny => predicate::contains_set(&l, &r, false).value(),
        B::ContainsAll => predicate::contains_set(&l, &r, true).value(),
    })
}

fn case(
    operand: Option<&Expr>,
    whens: &[crate::ast::WhenThen],
    otherwise: Option<&Expr>,
    env: &Env<'_>,
) -> Result<Val, Error> {
    let subject = operand.map(|o| eval(o, env)).transpose()?;
    for w in whens {
        let cond = eval(&w.when, env)?;
        let hit = match &subject {
            Some(s) => predicate::compare_op(BinaryOp::Eq, s, &cond) == Tri::True,
            None => Tri::of(&cond) == Tri::True,
        };
        if hit {
            return eval(&w.then, env);
        }
    }
    match otherwise {
        Some(e) => eval(e, env),
        None => Ok(Some(Value::Null)),
    }
}
