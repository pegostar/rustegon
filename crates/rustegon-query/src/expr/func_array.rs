// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Array functions (query-language.md §4.2), including the higher-order `filter`, `map` and
//! `reduce`.
//!
//! *Provisional (PD pending)* conventions: `slice(arr, start [, len])` is 0-based and a negative
//! `start` counts from the end; `array_sort` uses the §2.1 total order; `array_distinct` keeps
//! the first of equal (`=`) elements; `range(a, b [, step])` is half-open `[a, b)` with at most
//! [`MAX_RANGE_LEN`] elements; `zip` stops at the shortest array; `array_to_object` takes
//! `[[k, v], …]` or `[{k, v}, …]`; `object_to_array` yields `[{k, v}, …]`.

use rustegon_common::Error;
use rustegon_doc::{Document, Value, compare::compare_values};

use super::{BExpr, Func, Scope, Val, eval, eval_predicate, func::same, ops};

/// Maximum number of elements `range` produces (a runaway `range(0, 1e18)` would otherwise
/// exhaust memory).
pub const MAX_RANGE_LEN: i64 = 1 << 20;

/// `filter`, `map`, `reduce`.
pub(super) fn higher_order(f: Func, args: &[BExpr], s: &Scope<'_>) -> Result<Val, Error> {
    let Some(Value::Array(items)) = eval(&args[0], s)? else {
        return Ok(Some(Value::Null));
    };
    let lambda = if f == Func::Reduce {
        &args[2]
    } else {
        &args[1]
    };
    let BExpr::Lambda {
        first_slot, body, ..
    } = lambda
    else {
        return Ok(Some(Value::Null));
    };
    match f {
        Func::Filter => {
            let mut out = Vec::new();
            for it in items {
                let child = s.with_var(*first_slot, Some(it.clone()));
                if eval_predicate(body, &child)? == Some(true) {
                    out.push(it);
                }
            }
            Ok(Some(Value::Array(out)))
        }
        Func::Map => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                let child = s.with_var(*first_slot, Some(it));
                out.push(eval(body, &child)?.unwrap_or(Value::Null));
            }
            Ok(Some(Value::Array(out)))
        }
        _ => {
            let mut acc = eval(&args[1], s)?;
            for it in items {
                let child = s
                    .with_var(*first_slot, acc)
                    .with_var(first_slot + 1, Some(it));
                acc = eval(body, &child)?;
            }
            Ok(acc)
        }
    }
}

fn int_arg(a: &[Value], i: usize) -> Option<i64> {
    a.get(i).and_then(ops::as_int)
}

/// Evaluates an array, object-to-array or conditional helper on present, non-null arguments.
#[allow(clippy::many_single_char_names)] // `f` function, `a` arguments, `n`, `s`, `e` indices.
pub(super) fn call(f: Func, a: &[Value]) -> Option<Value> {
    if f == Func::Range {
        return range(
            int_arg(a, 0)?,
            int_arg(a, 1)?,
            if a.len() > 2 { int_arg(a, 2)? } else { 1 },
        );
    }
    if f == Func::Zip {
        let arrays: Option<Vec<&Vec<Value>>> = a
            .iter()
            .map(|v| match v {
                Value::Array(x) => Some(x),
                _ => None,
            })
            .collect();
        let arrays = arrays?;
        let n = arrays.iter().map(|x| x.len()).min().unwrap_or(0);
        return Some(Value::Array(
            (0..n)
                .map(|i| Value::Array(arrays.iter().map(|x| x[i].clone()).collect()))
                .collect(),
        ));
    }
    if f == Func::ObjectToArray {
        let Value::Object(d) = &a[0] else { return None };
        return Some(Value::Array(
            d.iter()
                .map(|(k, v)| {
                    let mut e = Document::new();
                    e.insert("k", Value::String(k.to_owned()));
                    e.insert("v", v.clone());
                    Value::Object(e)
                })
                .collect(),
        ));
    }
    let Value::Array(items) = &a[0] else {
        return None;
    };
    match f {
        Func::Size => i64::try_from(items.len()).ok().map(Value::Int64),
        Func::ArrayContains => Some(Value::Bool(items.iter().any(|e| same(e, &a[1])))),
        Func::First => Some(items.first().cloned().unwrap_or(Value::Null)),
        Func::Last => Some(items.last().cloned().unwrap_or(Value::Null)),
        Func::ArrayReverse => Some(Value::Array(items.iter().rev().cloned().collect())),
        Func::ArraySort => {
            let mut v = items.clone();
            v.sort_by(compare_values);
            Some(Value::Array(v))
        }
        Func::ArrayDistinct => {
            let mut out: Vec<Value> = Vec::new();
            for e in items {
                if !out.iter().any(|o| same(o, e)) {
                    out.push(e.clone());
                }
            }
            Some(Value::Array(out))
        }
        Func::Slice => {
            let len = i64::try_from(items.len()).ok()?;
            let start = int_arg(a, 1)?;
            let start = if start < 0 {
                (len + start).max(0)
            } else {
                start.min(len)
            };
            let end = match a.get(2) {
                Some(_) => start.saturating_add(int_arg(a, 2)?.max(0)).min(len),
                None => len,
            };
            let (s, e) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
            Some(Value::Array(items[s..e.max(s)].to_vec()))
        }
        Func::ArrayToObject => {
            let mut d = Document::new();
            for e in items {
                let (k, v) = match e {
                    Value::Array(kv) if kv.len() == 2 => (&kv[0], kv[1].clone()),
                    Value::Object(o) => (o.get("k")?, o.get("v").cloned().unwrap_or(Value::Null)),
                    _ => return None,
                };
                let Value::String(k) = k else { return None };
                d.insert(k.clone(), v);
            }
            Some(Value::Object(d))
        }
        _ => None,
    }
}

fn range(a: i64, b: i64, step: i64) -> Option<Value> {
    if step == 0 {
        return None;
    }
    let count = if (step > 0 && a >= b) || (step < 0 && a <= b) {
        0
    } else {
        let span = i128::from(b) - i128::from(a);
        let n = (span.abs() + i128::from(step).abs() - 1) / i128::from(step).abs();
        i64::try_from(n).ok()?
    };
    if count > MAX_RANGE_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(usize::try_from(count).ok()?);
    for i in 0..count {
        let x = i128::from(a) + i128::from(i) * i128::from(step);
        out.push(Value::Int64(i64::try_from(x).ok()?));
    }
    Some(Value::Array(out))
}
