// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Scalar functions (query-language.md §4.2): dispatch, type, arithmetic, object, conditional
//! and document functions. String, date and array functions live in sibling modules.
//!
//! Functions are total: invalid arguments yield `null` and count a warning; a `null` or
//! `missing` argument yields `null` unless the function is about null-ness (`coalesce`,
//! `if_null`, `type_of`, `is_number`, `is_string`, `if`, `switch`).

use std::sync::Arc;

use regex::{Regex, RegexBuilder};
use rustegon_common::Error;
use rustegon_doc::{Decimal128, Document, ObjectId, Value, compare::values_equal, json};

use super::{
    BExpr, EvalCtx, Func, Scope, Val, eval, eval_predicate, func_array, func_date, func_string, ops,
};

/// Size limit of a compiled regular expression (bytes of the compiled program): bounds the
/// memory a user-supplied pattern can take (the `regex` crate guarantees linear-time matching).
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Compiles a pattern; an invalid one counts a warning and yields `None`.
pub(super) fn compile_regex(pattern: &str, ctx: &EvalCtx) -> Option<Arc<Regex>> {
    if let Ok(r) = build_regex(pattern) {
        Some(Arc::new(r))
    } else {
        ctx.warn();
        None
    }
}

/// Compiles a pattern with the engine's limits.
///
/// # Errors
/// The `regex` crate's error for invalid or oversized patterns.
pub fn build_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// Evaluates `f(args)`.
pub(super) fn call(f: Func, args: &[BExpr], s: &Scope<'_>) -> Result<Val, Error> {
    // Lazy / null-aware functions first.
    match f {
        Func::Coalesce => {
            for a in args {
                match eval(a, s)? {
                    None | Some(Value::Null) => {}
                    v => return Ok(v),
                }
            }
            return Ok(Some(Value::Null));
        }
        Func::IfNull => {
            return match eval(&args[0], s)? {
                None | Some(Value::Null) => eval(&args[1], s),
                v => Ok(v),
            };
        }
        Func::If => {
            let branch = if eval_predicate(&args[0], s)? == Some(true) {
                1
            } else {
                2
            };
            return eval(&args[branch], s);
        }
        Func::Switch => return switch(args, s),
        Func::Filter | Func::Map | Func::Reduce => return func_array::higher_order(f, args, s),
        Func::Now => return Ok(Some(Value::DateTime(s.ctx.now_ms))),
        Func::Id => return Ok(row_field(s, "_id")),
        Func::Rev => return Ok(row_field(s, "_rev")),
        Func::TypeOf => {
            return Ok(Some(Value::String(
                type_name(eval(&args[0], s)?.as_ref()).into(),
            )));
        }
        // Type tests are two-valued: `null` and `missing` are neither numbers nor strings.
        Func::IsNumber => {
            let v = eval(&args[0], s)?;
            return Ok(Some(Value::Bool(v.as_ref().is_some_and(ops::is_numeric))));
        }
        Func::IsString => {
            let v = eval(&args[0], s)?;
            return Ok(Some(Value::Bool(matches!(v, Some(Value::String(_))))));
        }
        _ => {}
    }
    let mut vals = Vec::with_capacity(args.len());
    for a in args {
        vals.push(eval(a, s)?);
    }
    let out = match f {
        Func::Concat | Func::ArrayConcat | Func::MergeObjects | Func::Greatest | Func::Least => {
            variadic(f, &vals)
        }
        _ => {
            // Every other function maps null/missing arguments to null.
            if vals.iter().any(|v| matches!(v, None | Some(Value::Null))) {
                return Ok(Some(Value::Null));
            }
            let present: Vec<Value> = vals.into_iter().flatten().collect();
            strict(f, &present, s.ctx)
        }
    };
    Ok(Some(out.unwrap_or_else(|| {
        s.ctx.warn();
        Value::Null
    })))
}

fn row_field(s: &Scope<'_>, name: &str) -> Val {
    match s.row {
        Some(Value::Object(d)) => d.get(name).cloned(),
        _ => None,
    }
}

/// `switch(v, c1, r1, …, [default])`: the result of the first `ci` equal (`==`) to `v`.
/// *Provisional (PD pending)*: the specification names `switch` without a signature; this is the
/// `DECODE` form.
fn switch(args: &[BExpr], s: &Scope<'_>) -> Result<Val, Error> {
    let subject = eval(&args[0], s)?;
    let rest = &args[1..];
    for pair in rest.chunks(2) {
        match pair {
            [c, r] => {
                let cv = eval(c, s)?;
                if ops::compare(super::CmpOp::EqWhole, subject.as_ref(), cv.as_ref()) == Some(true)
                {
                    return eval(r, s);
                }
            }
            [default] => return eval(default, s),
            _ => {}
        }
    }
    Ok(Some(Value::Null))
}

/// Variadic functions that skip null/missing arguments.
fn variadic(f: Func, vals: &[Val]) -> Option<Value> {
    let present: Vec<&Value> = vals
        .iter()
        .filter_map(Option::as_ref)
        .filter(|v| !matches!(v, Value::Null))
        .collect();
    match f {
        Func::Greatest | Func::Least => {
            let mut best: Option<&Value> = None;
            for v in present {
                let better = best.is_none_or(|b| {
                    let o = rustegon_doc::compare::compare_values(v, b);
                    if f == Func::Greatest {
                        o.is_gt()
                    } else {
                        o.is_lt()
                    }
                });
                if better {
                    best = Some(v);
                }
            }
            Some(best.cloned().unwrap_or(Value::Null))
        }
        // `concat` of strings; `null` arguments make the result null like `||` (SQL).
        Func::Concat => {
            if present.len() != vals.len() {
                return Some(Value::Null);
            }
            let mut out = String::new();
            for v in present {
                match v {
                    Value::String(s) => out.push_str(s),
                    _ => return None,
                }
            }
            Some(Value::String(out))
        }
        Func::ArrayConcat => {
            if present.len() != vals.len() {
                return Some(Value::Null);
            }
            let mut out = Vec::new();
            for v in present {
                match v {
                    Value::Array(a) => out.extend(a.iter().cloned()),
                    _ => return None,
                }
            }
            Some(Value::Array(out))
        }
        Func::MergeObjects => {
            let mut out = Document::new();
            for v in present {
                match v {
                    Value::Object(d) => {
                        for (n, x) in d.iter() {
                            out.insert(n, x.clone());
                        }
                    }
                    _ => return None,
                }
            }
            Some(Value::Object(out))
        }
        _ => None,
    }
}

/// Functions over present, non-null arguments.
fn strict(f: Func, a: &[Value], ctx: &EvalCtx) -> Option<Value> {
    match f {
        Func::IsNumber => Some(Value::Bool(ops::is_numeric(&a[0]))),
        Func::IsString => Some(Value::Bool(matches!(a[0], Value::String(_)))),
        Func::ToString => Some(Value::String(to_string(&a[0]))),
        Func::ToInt => to_int(&a[0]),
        Func::ToFloat => to_float(&a[0]),
        Func::ToDecimal => to_decimal(&a[0]),
        Func::ToBool => to_bool(&a[0]),
        Func::ToOid => match &a[0] {
            Value::ObjectId(_) => Some(a[0].clone()),
            Value::String(s) => ObjectId::parse_hex(s).ok().map(Value::ObjectId),
            _ => None,
        },
        Func::Keys => match &a[0] {
            Value::Object(d) => Some(Value::Array(
                d.iter().map(|(n, _)| Value::String(n.to_owned())).collect(),
            )),
            _ => None,
        },
        Func::Values => match &a[0] {
            Value::Object(d) => Some(Value::Array(d.iter().map(|(_, v)| v.clone()).collect())),
            _ => None,
        },
        Func::GetField => match (&a[0], &a[1]) {
            (Value::Object(d), Value::String(n)) => Some(d.get(n).cloned().unwrap_or(Value::Null)),
            _ => None,
        },
        Func::SetField => match (&a[0], &a[1]) {
            (Value::Object(d), Value::String(n)) => {
                let mut d = d.clone();
                d.insert(n.clone(), a[2].clone());
                Some(Value::Object(d))
            }
            _ => None,
        },
        Func::UnsetField => match (&a[0], &a[1]) {
            (Value::Object(d), Value::String(n)) => {
                let mut d = d.clone();
                d.remove(n);
                Some(Value::Object(d))
            }
            _ => None,
        },
        Func::Abs
        | Func::Ceil
        | Func::Floor
        | Func::Trunc
        | Func::Sqrt
        | Func::Exp
        | Func::Ln
        | Func::Log10
        | Func::Round
        | Func::Pow
        | Func::Mod => math(f, a),
        Func::ToDate
        | Func::DateTrunc
        | Func::DateAdd
        | Func::DateDiff
        | Func::DateFormat
        | Func::TimeBucket
        | Func::Extract => func_date::call(f, a),
        Func::Length
        | Func::Lower
        | Func::Upper
        | Func::Trim
        | Func::Ltrim
        | Func::Rtrim
        | Func::Substr
        | Func::IndexOf
        | Func::Replace
        | Func::Split
        | Func::StartsWith
        | Func::EndsWith
        | Func::RegexMatch
        | Func::RegexExtract
        | Func::Format => func_string::call(f, a, ctx),
        _ => func_array::call(f, a),
    }
}

/// The type name of a value (`missing` included), as `type_of` returns it (data-model.md §2).
#[must_use]
pub fn type_name(v: Option<&Value>) -> &'static str {
    match v {
        None => "missing",
        Some(v) => match v {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int64(_) => "int64",
            Value::Float64(_) => "float64",
            Value::Decimal(_) => "decimal128",
            Value::String(_) => "string",
            Value::Binary { .. } => "binary",
            Value::DateTime(_) => "datetime",
            Value::Timestamp(_) => "timestamp",
            Value::ObjectId(_) => "objectId",
            Value::Uuid(_) => "uuid",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            Value::VectorF32(_) => "vector_f32",
            Value::Counter(_) => "counter",
            Value::MinKey => "minKey",
            Value::MaxKey => "maxKey",
        },
    }
}

/// `to_string`: strings as is, scalars in their literal form, non-finite floats as `NaN` /
/// `Infinity` / `-Infinity` (not their extended-JSON wrapper), other values as their canonical
/// JSON text (query-language.md §4.3; TC-QL-010 seed 6840335469013532086).
fn to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Float64(f) if f.is_nan() => "NaN".to_owned(),
        Value::Float64(f) if f.is_infinite() => {
            if *f > 0.0 { "Infinity" } else { "-Infinity" }.to_owned()
        }
        Value::Int64(i) | Value::Counter(i) => i.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Decimal(d) => d.to_string(),
        Value::ObjectId(o) => o.to_string(),
        Value::DateTime(ms) => crate::ast::literal::format_datetime(*ms),
        Value::Uuid(u) => crate::ast::literal::format_uuid(u),
        other => json::value_to_json(other, json::JsonMode::Canonical),
    }
}

fn to_int(v: &Value) -> Option<Value> {
    match v {
        Value::Int64(_) => Some(v.clone()),
        Value::Counter(i) => Some(Value::Int64(*i)),
        Value::Bool(b) => Some(Value::Int64(i64::from(*b))),
        Value::Float64(_) | Value::Decimal(_) => {
            let f = ops::number_f64(v)?.trunc();
            ops::as_int(&Value::Float64(f)).map(Value::Int64)
        }
        Value::String(s) => s.trim().parse::<i64>().ok().map(Value::Int64),
        Value::DateTime(ms) => Some(Value::Int64(*ms)),
        _ => None,
    }
}

fn to_float(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) => s.trim().parse::<f64>().ok().map(Value::Float64),
        Value::Bool(b) => Some(Value::Float64(if *b { 1.0 } else { 0.0 })),
        other => ops::number_f64(other).map(Value::Float64),
    }
}

fn to_decimal(v: &Value) -> Option<Value> {
    match v {
        Value::Decimal(_) => Some(v.clone()),
        Value::Int64(i) | Value::Counter(i) => Some(Value::Decimal(Decimal128::from_i64(*i))),
        Value::Float64(f) => ops::float_to_decimal(*f),
        Value::String(s) => Decimal128::parse(s.trim()).ok().map(Value::Decimal),
        _ => None,
    }
}

fn to_bool(v: &Value) -> Option<Value> {
    match v {
        Value::Bool(_) => Some(v.clone()),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        },
        // NaN is "no number", so it converts like zero (query-language.md §4.3).
        other => ops::number_f64(other).map(|f| Value::Bool(f != 0.0 && !f.is_nan())),
    }
}

/// Numeric functions. Integers stay integers where the result is integral (`abs`, `ceil`,
/// `floor`, `trunc`, `round` without digits, `mod`); otherwise the result is `float64`.
fn math(f: Func, a: &[Value]) -> Option<Value> {
    if !a.iter().all(ops::is_numeric) {
        return None;
    }
    if let Value::Int64(i) = a[0] {
        match f {
            Func::Abs => return i.checked_abs().map(Value::Int64),
            Func::Ceil | Func::Floor | Func::Trunc => return Some(Value::Int64(i)),
            Func::Round if a.len() == 1 => return Some(Value::Int64(i)),
            Func::Mod => return ops::arith(super::ArithOp::Mod, &a[0], &a[1]),
            _ => {}
        }
    }
    if let (Func::Abs, Value::Decimal(d)) = (f, &a[0]) {
        // `decimal128` stays `decimal128` (data-model §2.3 "decimal wins"); going through
        // `f64` would change the type and lose digits (TC-QL-010 seed 6840335469013538815).
        let negative = matches!(
            d,
            Decimal128::Finite { negative: true, .. } | Decimal128::Infinity { negative: true }
        );
        return if negative {
            ops::negate(&a[0])
        } else {
            Some(a[0].clone())
        };
    }
    let x = ops::number_f64(&a[0])?;
    let r = match f {
        Func::Abs => x.abs(),
        Func::Ceil => x.ceil(),
        Func::Floor => x.floor(),
        Func::Trunc => x.trunc(),
        // Outside the domain (negative, zero for logarithms, NaN) the input is invalid: `null`,
        // not `-Infinity` / NaN (query-language.md §4.3; same rule as the reference): those
        // inputs fall through to the `None` arm below.
        Func::Sqrt if x >= 0.0 => x.sqrt(),
        Func::Ln if x > 0.0 => x.ln(),
        Func::Log10 if x > 0.0 => x.log10(),
        Func::Exp => x.exp(),
        Func::Pow => x.powf(ops::number_f64(&a[1])?),
        Func::Mod => return ops::arith(super::ArithOp::Mod, &a[0], &a[1]),
        Func::Round => {
            let digits = a.get(1).and_then(ops::as_int).unwrap_or(0);
            let digits = i32::try_from(digits.clamp(-300, 300)).ok()?;
            let scale = 10f64.powi(digits);
            (x * scale).round() / scale
        }
        _ => return None,
    };
    // Domain errors (sqrt(-1), ln(0)) are invalid input, not values.
    if r.is_nan() && !x.is_nan() {
        return None;
    }
    Some(Value::Float64(r))
}

/// Whole-value equality used by array functions (`1 = 1.0`).
pub(super) fn same(a: &Value, b: &Value) -> bool {
    values_equal(Some(a), Some(b))
}
