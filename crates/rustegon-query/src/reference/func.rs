// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Scalar functions (query-language.md §4.2) of the reference interpreter.
//!
//! Names are case-insensitive. A wrong number of arguments is `RGN-1011`, an unknown name
//! `RGN-1012`. Functions are total (§4.2): an argument of the wrong type gives `null`. Unless
//! stated otherwise a `null` or `missing` argument gives `null`; `type_of`, `is_*`, `coalesce`,
//! `if_null` and `if` look at `missing` themselves (`to_string(missing)` is `null`).
//!
//! *Provisional* details (query-language.md §4.3): string positions and lengths count Unicode
//! scalar values and are 0-based (`substr(s, start [, len])`, `index_of` → -1 when absent);
//! `round(x, d)` rounds half away from zero and keeps `int64` integers; `slice(arr, start [, end])`
//! is 0-based, end-exclusive, negative positions count from the end; `range` is capped at
//! [`MAX_RANGE_LEN`] elements (`null` beyond); `size` counts array elements only; `to_string` of
//! a `float64` is its canonical JSON number text (`1.0`, `1e300`, `NaN`, `Infinity`).
//! Aggregates, window, search, geo, vector, date and document/system functions other than
//! `now()` and `id()` are outside the reference scope.

use std::cmp::Ordering;

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Value,
    compare::{compare_values, values_equal},
    json::{JsonMode, value_to_json},
};

use super::{
    arith::{self, abs_decimal, as_f64},
    error::{type_error, unsupported},
    eval::{Env, Tri, Val, eval},
    predicate,
};
use crate::ast::{BinaryOp, Expr, literal::format_datetime, literal::format_uuid};

/// Largest array `range(…)` builds.
pub const MAX_RANGE_LEN: i64 = 10_000;

/// Functions of §4.2 outside the reference scope (M7 and system functions).
const UNSUPPORTED: &[&str] = &[
    "count",
    "count_distinct",
    "count_distinct_approx",
    "sum",
    "avg",
    "array_agg",
    "set_agg",
    "percentile",
    "stddev_pop",
    "stddev_samp",
    "var_pop",
    "var_samp",
    "top_k",
    "row_number",
    "rank",
    "dense_rank",
    "lag",
    "lead",
    "moving_avg",
    "rate",
    "cumulative_sum",
    "derivative",
    "interpolate",
    "gap_fill",
    "search",
    "score",
    "highlight",
    "vector_near",
    "vector_distance",
    "vector_rank",
    "rrf",
    "geo_within",
    "geo_intersects",
    "geo_near",
    "geo_distance",
    "geo_circle",
    "geo_box",
    "rev",
    "load",
    "counter",
    "writetime",
    "ttl",
    "metadata",
    "date_trunc",
    "date_add",
    "date_diff",
    "date_format",
    "time_bucket",
    "to_date",
    "to_oid",
    "to_decimal",
    "format",
    "regex_extract",
    "zip",
    "array_to_object",
    "object_to_array",
    "set_field",
    "unset_field",
    "switch",
];

/// Calls function `name`.
///
/// # Errors
/// `RGN-1011` (arity, lambda misuse), `RGN-1012` (unknown), unsupported functions, and errors of
/// the argument expressions.
pub fn call(name: &str, args: &[Expr], env: &Env<'_>) -> Result<Val, Error> {
    let lname = name.to_ascii_lowercase();
    // `min`/`max`/`first`/`last` are aggregates only in GROUP BY; with one array argument they are
    // scalar array functions here except `min`/`max`, which have no scalar meaning in §4.2.
    if UNSUPPORTED.contains(&lname.as_str()) || matches!(lname.as_str(), "min" | "max") {
        return Err(unsupported(&format!("function {lname}")));
    }
    match lname.as_str() {
        "filter" | "map" | "reduce" => return higher_order(&lname, args, env),
        "now" => {
            arity(&lname, args.len(), 0, 0)?;
            return Ok(Some(Value::DateTime(env.ctx.now_ms)));
        }
        "id" => {
            arity(&lname, args.len(), 0, 0)?;
            return Ok(match env.row {
                Value::Object(d) => d.get("_id").cloned(),
                _ => None,
            });
        }
        _ => {}
    }
    let mut vals = Vec::with_capacity(args.len());
    for a in args {
        vals.push(eval(a, env)?);
    }
    scalar(&lname, vals)
}

fn arity(name: &str, n: usize, min: usize, max: usize) -> Result<(), Error> {
    if n < min || n > max {
        return Err(type_error(format!("wrong number of arguments for {name}")));
    }
    Ok(())
}

// `Val` constructors for present values; the `Option` is the `missing`-aware value type.
#[allow(clippy::unnecessary_wraps)]
fn null() -> Val {
    Some(Value::Null)
}

#[allow(clippy::unnecessary_wraps)]
fn int(i: i64) -> Val {
    Some(Value::Int64(i))
}

#[allow(clippy::unnecessary_wraps)]
fn string(s: String) -> Val {
    Some(Value::String(s))
}

#[allow(clippy::unnecessary_wraps)]
fn boolean(b: bool) -> Val {
    Some(Value::Bool(b))
}

/// Dispatch on evaluated arguments.
// One arm per function of the §4.2 catalog: a single table is easier to check against the spec.
#[allow(clippy::too_many_lines)]
fn scalar(name: &str, vals: Vec<Val>) -> Result<Val, Error> {
    let n = vals.len();
    let (min, max) = signature(name).ok_or_else(|| {
        Error::new(
            ErrorCode::UnknownFunction,
            format!("unknown function {name}"),
        )
    })?;
    arity(name, n, min, max)?;
    // Functions that inspect null / missing themselves.
    match name {
        "type_of" => return Ok(string(type_name(vals[0].as_ref()).into())),
        "is_number" => return Ok(boolean(vals[0].as_ref().is_some_and(arith::is_number))),
        "is_string" => return Ok(boolean(matches!(vals[0], Some(Value::String(_))))),
        "coalesce" => {
            return Ok(vals
                .into_iter()
                .find(|v| !matches!(v, None | Some(Value::Null)))
                .unwrap_or_else(null));
        }
        "if_null" => {
            let mut it = vals.into_iter();
            let (a, b) = (it.next().flatten(), it.next().flatten());
            return Ok(match a {
                None | Some(Value::Null) => b,
                some => some,
            });
        }
        "if" => {
            let mut it = vals.into_iter();
            let cond = it.next().flatten();
            let (a, b) = (it.next().flatten(), it.next().flatten());
            return Ok(if Tri::of(&cond) == Tri::True { a } else { b });
        }
        "to_string" => return Ok(Some(vals[0].as_ref().map_or(Value::Null, to_string))),
        "greatest" | "least" => return Ok(extreme(name == "greatest", vals)),
        _ => {}
    }
    // Null-in, null-out for everything else.
    let Some(args) = vals.into_iter().collect::<Option<Vec<Value>>>() else {
        return Ok(null());
    };
    if args.iter().any(|v| matches!(v, Value::Null)) {
        return Ok(null());
    }
    Ok(match name {
        "abs" | "ceil" | "floor" | "trunc" | "round" | "sqrt" | "exp" | "ln" | "log10" | "pow"
        | "mod" | "to_int" | "to_float" | "to_bool" => numeric(name, &args)?,
        "array_contains" => predicate::contains(&Some(args[0].clone()), &Some(args[1].clone()))
            .value()
            .filter(|_| matches!(args[0], Value::Array(_)))
            .or_else(null),
        _ => match (name, args.as_slice()) {
            ("size", [Value::Array(a)]) => int(len_i64(a.len())),
            ("first", [Value::Array(a)]) => a.first().cloned().or_else(null),
            ("last", [Value::Array(a)]) => a.last().cloned().or_else(null),
            ("array_reverse", [Value::Array(a)]) => {
                Some(Value::Array(a.iter().rev().cloned().collect()))
            }
            ("array_sort", [Value::Array(a)]) => {
                let mut a = a.clone();
                a.sort_by(compare_values);
                Some(Value::Array(a))
            }
            ("array_distinct", [Value::Array(a)]) => {
                let mut out: Vec<Value> = Vec::new();
                for v in a {
                    if !out.iter().any(|o| values_equal(Some(o), Some(v))) {
                        out.push(v.clone());
                    }
                }
                Some(Value::Array(out))
            }
            ("array_concat", _) if args.iter().all(|a| matches!(a, Value::Array(_))) => {
                Some(Value::Array(
                    args.iter()
                        .flat_map(|a| match a {
                            Value::Array(items) => items.clone(),
                            _ => Vec::new(),
                        })
                        .collect(),
                ))
            }
            ("slice", [Value::Array(a), Value::Int64(s), rest @ ..]) => {
                let end = match rest {
                    [] => Some(len_i64(a.len())),
                    [Value::Int64(e)] => Some(*e),
                    _ => None,
                };
                end.map_or_else(null, |e| Some(Value::Array(slice(a, *s, e))))
            }
            ("range", [Value::Int64(a), Value::Int64(b), rest @ ..]) => {
                let step = match rest {
                    [] => Some(1),
                    [Value::Int64(s)] if *s != 0 => Some(*s),
                    _ => None,
                };
                step.and_then(|s| range(*a, *b, s)).or_else(null)
            }
            ("keys", [Value::Object(d)]) => Some(Value::Array(
                d.iter().map(|(k, _)| Value::String(k.to_owned())).collect(),
            )),
            ("values", [Value::Object(d)]) => {
                Some(Value::Array(d.iter().map(|(_, v)| v.clone()).collect()))
            }
            ("get_field", [Value::Object(d), Value::String(k)]) => d.get(k).cloned(),
            ("merge_objects", _) if args.iter().all(|a| matches!(a, Value::Object(_))) => {
                let mut out = rustegon_doc::Document::new();
                for a in &args {
                    if let Value::Object(d) = a {
                        for (k, v) in d.iter() {
                            out.insert(k, v.clone());
                        }
                    }
                }
                Some(Value::Object(out))
            }
            _ => string_fn(name, &args),
        },
    })
}

/// `(min, max)` arity of the implemented scalar functions; `None` = unknown name.
fn signature(name: &str) -> Option<(usize, usize)> {
    const VARIADIC: usize = usize::MAX;
    Some(match name {
        "type_of" | "is_number" | "is_string" | "to_string" | "to_int" | "to_float" | "to_bool"
        | "abs" | "ceil" | "floor" | "trunc" | "sqrt" | "exp" | "ln" | "log10" | "length"
        | "lower" | "upper" | "trim" | "ltrim" | "rtrim" | "size" | "first" | "last"
        | "array_distinct" | "array_sort" | "array_reverse" | "keys" | "values" => (1, 1),
        "round" => (1, 2),
        "pow" | "mod" | "if_null" | "index_of" | "split" | "starts_with" | "ends_with"
        | "regex_match" | "array_contains" | "get_field" => (2, 2),
        "substr" | "slice" | "range" => (2, 3),
        "replace" | "if" => (3, 3),
        "coalesce" | "greatest" | "least" | "concat" | "array_concat" | "merge_objects" => {
            (1, VARIADIC)
        }
        _ => return None,
    })
}

fn string_fn(name: &str, args: &[Value]) -> Val {
    let strs: Option<Vec<&str>> = args
        .iter()
        .map(|a| match a {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    let int_arg = |i: usize| match args.get(i) {
        Some(Value::Int64(v)) => Some(*v),
        _ => None,
    };
    if name == "substr" {
        let (Value::String(s), Some(start)) = (&args[0], int_arg(1)) else {
            return null();
        };
        let len = if args.len() == 3 {
            int_arg(2)
        } else {
            Some(i64::MAX)
        };
        let (Ok(start), Some(Ok(len))) = (usize::try_from(start), len.map(usize::try_from)) else {
            return null();
        };
        string(s.chars().skip(start).take(len).collect())
    } else {
        {
            let Some(s) = strs else { return null() };
            match (name, s.as_slice()) {
                ("length", [a]) => int(len_i64(a.chars().count())),
                ("lower", [a]) => string(a.to_lowercase()),
                ("upper", [a]) => string(a.to_uppercase()),
                ("trim", [a]) => string(a.trim().to_owned()),
                ("ltrim", [a]) => string(a.trim_start().to_owned()),
                ("rtrim", [a]) => string(a.trim_end().to_owned()),
                ("concat", parts) => string(parts.concat()),
                ("starts_with", [a, b]) => boolean(a.starts_with(b)),
                ("ends_with", [a, b]) => boolean(a.ends_with(b)),
                ("index_of", [a, b]) => {
                    int(a.find(b).map_or(-1, |at| len_i64(a[..at].chars().count())))
                }
                ("replace", [a, from, to]) if !from.is_empty() => string(a.replace(from, to)),
                ("replace", [a, _, _]) => string((*a).to_owned()),
                ("split", [a, sep]) => Some(Value::Array(if sep.is_empty() {
                    a.chars().map(|c| Value::String(c.to_string())).collect()
                } else {
                    a.split(sep).map(|p| Value::String(p.to_owned())).collect()
                })),
                ("regex_match", [a, p]) => {
                    regex::Regex::new(p).map_or_else(|_| null(), |re| boolean(re.is_match(a)))
                }
                _ => null(),
            }
        }
    }
}

#[allow(clippy::cast_possible_truncation)] // guarded by the range checks before the casts.
fn numeric(name: &str, args: &[Value]) -> Result<Val, Error> {
    let x = &args[0];
    if matches!(x, Value::Decimal(_)) || args.iter().skip(1).any(|a| matches!(a, Value::Decimal(_)))
    {
        return Ok(match (name, x) {
            ("abs", Value::Decimal(d)) => Some(Value::Decimal(abs_decimal(*d))),
            ("mod", _) => arith::binary(BinaryOp::Mod, Some(x.clone()), Some(args[1].clone()))?,
            _ => return Err(unsupported(&format!("{name} on decimal128"))),
        });
    }
    let f = as_f64(x);
    let float = |v: f64| Some(Value::Float64(v));
    Ok(match (name, x) {
        (_, v) if !arith::is_number(v) && !matches!(name, "to_int" | "to_float" | "to_bool") => {
            null()
        }
        ("abs", Value::Int64(i)) => i.checked_abs().map_or_else(null, int),
        ("ceil" | "floor" | "trunc" | "round", Value::Int64(_)) if args.len() == 1 => {
            Some(x.clone())
        }
        ("round", Value::Int64(_)) => match &args[1] {
            Value::Int64(d) if *d >= 0 => Some(x.clone()),
            Value::Int64(_) => float(round_digits(f, &args[1])),
            _ => null(),
        },
        ("abs", _) => float(f.abs()),
        ("ceil", _) => float(f.ceil()),
        ("floor", _) => float(f.floor()),
        ("trunc", _) => float(f.trunc()),
        ("round", _) if args.len() == 1 => float(f.round()),
        ("round", _) => match &args[1] {
            Value::Int64(_) => float(round_digits(f, &args[1])),
            _ => null(),
        },
        ("sqrt", _) if f >= 0.0 => float(f.sqrt()),
        ("exp", _) => float(f.exp()),
        ("ln", _) if f > 0.0 => float(f.ln()),
        ("log10", _) if f > 0.0 => float(f.log10()),
        ("pow", _) if arith::is_number(&args[1]) => float(f.powf(as_f64(&args[1]))),
        ("mod", _) => arith::binary(BinaryOp::Mod, Some(x.clone()), Some(args[1].clone()))?,
        ("to_int", Value::Int64(_)) | ("to_bool", Value::Bool(_)) => Some(x.clone()),
        ("to_int", Value::Float64(v)) if v.is_finite() && v.trunc().abs() < 9.2e18 => {
            int(v.trunc() as i64)
        }
        ("to_int", Value::Bool(b)) => int(i64::from(*b)),
        ("to_int", Value::String(s)) => s.trim().parse().map_or_else(|_| null(), int),
        // A date converts to its epoch milliseconds (query-language.md §4.3, MongoDB `$toLong`).
        ("to_int", Value::DateTime(ms)) => int(*ms),
        ("to_float", Value::Int64(_) | Value::Float64(_)) => float(f),
        ("to_float", Value::Bool(b)) => float(if *b { 1.0 } else { 0.0 }),
        ("to_float", Value::String(s)) => s.trim().parse().map_or_else(|_| null(), float),
        ("to_bool", Value::Int64(i)) => boolean(*i != 0),
        ("to_bool", Value::Float64(v)) => boolean(*v != 0.0 && !v.is_nan()),
        ("to_bool", Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "true" => boolean(true),
            "false" => boolean(false),
            _ => null(),
        },
        _ => null(),
    })
}

fn round_digits(f: f64, digits: &Value) -> f64 {
    let Value::Int64(d) = digits else {
        return f64::NAN;
    };
    let d = i32::try_from((*d).clamp(-300, 300)).unwrap_or(0);
    let scale = 10f64.powi(d);
    (f * scale).round() / scale
}

fn extreme(greatest: bool, vals: Vec<Val>) -> Val {
    let want = if greatest {
        Ordering::Greater
    } else {
        Ordering::Less
    };
    vals.into_iter()
        .flatten()
        .filter(|v| !matches!(v, Value::Null))
        .reduce(|best, v| {
            if compare_values(&v, &best) == want {
                v
            } else {
                best
            }
        })
        .or_else(null)
}

fn slice(a: &[Value], start: i64, end: i64) -> Vec<Value> {
    let len = len_i64(a.len());
    let norm =
        |p: i64| usize::try_from(if p < 0 { (len + p).max(0) } else { p.min(len) }).unwrap_or(0);
    let (s, e) = (norm(start), norm(end));
    if s >= e { Vec::new() } else { a[s..e].to_vec() }
}

fn range(a: i64, b: i64, step: i64) -> Val {
    let mut out = Vec::new();
    let mut cur = a;
    while (step > 0 && cur < b) || (step < 0 && cur > b) {
        if len_i64(out.len()) >= MAX_RANGE_LEN {
            return None;
        }
        out.push(Value::Int64(cur));
        cur = cur.checked_add(step)?;
    }
    Some(Value::Array(out))
}

fn len_i64(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// `filter(arr, x -> p)`, `map(arr, x -> e)`, `reduce(arr, init, (acc, x) -> e)`.
fn higher_order(name: &str, args: &[Expr], env: &Env<'_>) -> Result<Val, Error> {
    let want = if name == "reduce" { 3 } else { 2 };
    arity(name, args.len(), want, want)?;
    let Some(Expr::Lambda { params, body }) = args.last() else {
        return Err(type_error(format!(
            "{name} expects a lambda as last argument"
        )));
    };
    if params.len() != want - 1 {
        return Err(type_error(format!(
            "wrong number of lambda parameters for {name}"
        )));
    }
    let Some(Value::Array(items)) = eval(&args[0], env)? else {
        return Ok(null());
    };
    match name {
        "filter" => {
            let mut out = Vec::new();
            for item in items {
                let keep = Tri::of(&eval(body, &env.with_var(&params[0], Some(item.clone())))?);
                if keep == Tri::True {
                    out.push(item);
                }
            }
            Ok(Some(Value::Array(out)))
        }
        "map" => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let v = eval(body, &env.with_var(&params[0], Some(item)))?;
                out.push(v.unwrap_or(Value::Null));
            }
            Ok(Some(Value::Array(out)))
        }
        _ => {
            let mut acc = eval(&args[1], env)?;
            for item in items {
                let scope = env
                    .with_var(&params[0], acc)
                    .with_var(&params[1], Some(item));
                acc = eval(body, &scope)?;
            }
            Ok(acc)
        }
    }
}

/// Type names of data-model §2 (`type_of`).
#[must_use]
pub fn type_name(v: Option<&Value>) -> &'static str {
    let Some(v) = v else { return "missing" };
    match v {
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
    }
}

fn to_string(v: &Value) -> Value {
    Value::String(match v {
        Value::Null => return Value::Null,
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Int64(i) | Value::Counter(i) => i.to_string(),
        Value::Float64(f) if f.is_nan() => "NaN".into(),
        Value::Float64(f) if f.is_infinite() => {
            if *f > 0.0 {
                "Infinity".into()
            } else {
                "-Infinity".into()
            }
        }
        Value::Decimal(d) => d.to_string(),
        Value::DateTime(ms) => format_datetime(*ms),
        Value::ObjectId(o) => o.to_string(),
        Value::Uuid(u) => format_uuid(u),
        other => value_to_json(other, JsonMode::Canonical),
    })
}
