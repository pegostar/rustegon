// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Reference interpreter of the update operators (FR-DOC-006, AC-DOC-005).
//!
//! Deliberately simple and structurally independent of `rustegon_doc::update`: it rebuilds
//! values functionally (every step returns a new value) instead of mutating in place, uses its
//! own field-name check, its own path walk, its own stable insertion sort and `i128` arithmetic
//! for integers and decimals. Decimal results must be exact (the generators keep coefficients
//! and exponents small); rounding is covered by unit tests of the engine instead. Only the
//! semantics written in the `update` module docs are shared.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::many_single_char_names,
    clippy::needless_pass_by_value
)]

use std::cmp::Ordering;

use rustegon_common::ErrorCode;
use rustegon_doc::{
    Decimal128, Document, Value,
    compare::compare,
    decimal::MAX_COEFFICIENT,
    keyenc::Direction,
    path::get_path,
    update::{PopEnd, Push, PushSort, UpdateOp, UpdatePath, UpdateSegment},
};

type R<T> = Result<T, ErrorCode>;

const RESERVED: [&str; 5] = ["_rev", "_createdAt", "_updatedAt", "_conflict", "_origin"];

/// Applies `ops` to `doc`; `Err` carries the expected error code.
pub fn ref_apply(doc: &Document, ops: &[UpdateOp], now_ms: i64) -> R<Document> {
    // Phase 1: static checks, operator by operator.
    let mut skips = Vec::new();
    for op in ops {
        skips.push(check_op(doc, op)?);
    }
    // Phase 2: conflicting paths over the flattened path list.
    let all: Vec<&UpdatePath> = ops.iter().flat_map(paths_of).collect();
    for i in 0..all.len() {
        for j in i + 1..all.len() {
            if overlaps(all[i], all[j]) {
                return Err(ErrorCode::InvalidArgument);
            }
        }
    }
    // Phase 3: apply in order on an immutable value, rebuilt by every operator.
    let mut root = Value::Object(doc.clone());
    for (op, skip) in ops.iter().zip(skips) {
        if !skip {
            root = run_op(&root, op, now_ms)?;
        }
    }
    match root {
        Value::Object(d) => Ok(d),
        _ => panic!("root replaced"),
    }
}

fn paths_of(op: &UpdateOp) -> Vec<&UpdatePath> {
    match op {
        UpdateOp::Rename { from, to } => vec![from, to],
        UpdateOp::Set { path, .. }
        | UpdateOp::Unset { path }
        | UpdateOp::Inc { path, .. }
        | UpdateOp::Mul { path, .. }
        | UpdateOp::Min { path, .. }
        | UpdateOp::Max { path, .. }
        | UpdateOp::CurrentDate { path }
        | UpdateOp::Pull { path, .. }
        | UpdateOp::PullAll { path, .. }
        | UpdateOp::AddToSet { path, .. }
        | UpdateOp::Pop { path, .. } => vec![path],
        UpdateOp::Push(p) => vec![&p.path],
    }
}

fn name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 1024 && !n.contains('\0') && !n.starts_with('$')
}

fn head(p: &UpdatePath) -> Option<&str> {
    match p.segments().first()? {
        UpdateSegment::Field(s) => Some(&s.name),
        _ => None,
    }
}

fn storable(v: &Value) -> bool {
    match v {
        Value::Counter(_) => false,
        Value::Array(a) => a.iter().all(storable),
        Value::Object(d) => d.iter().all(|(n, v)| name_ok(n) && storable(v)),
        _ => true,
    }
}

fn numeric(v: &Value) -> bool {
    matches!(v, Value::Int64(_) | Value::Float64(_) | Value::Decimal(_))
}

/// Returns `true` when the operator is the accepted no-op `SET _id = <equal value>`.
fn check_op(doc: &Document, op: &UpdateOp) -> R<bool> {
    let ps = paths_of(op);
    if ps.iter().any(|p| p.segments().is_empty()) {
        return Err(ErrorCode::InvalidArgument);
    }
    let bad_name = ps.iter().any(|p| {
        p.segments()
            .iter()
            .any(|s| matches!(s, UpdateSegment::Field(f) if !name_ok(&f.name)))
    });
    if bad_name {
        return Err(ErrorCode::InvalidFieldName);
    }
    if ps
        .iter()
        .any(|p| head(p).is_some_and(|h| RESERVED.contains(&h)))
    {
        return Err(ErrorCode::InvalidFieldName);
    }
    let mut skip = false;
    if ps.iter().any(|p| head(p) == Some("_id")) {
        let same = match op {
            UpdateOp::Set { path, value } if path.segments().len() == 1 => doc
                .get("_id")
                .is_some_and(|c| compare(Some(c), Some(value)) == Ordering::Equal),
            _ => false,
        };
        if !same {
            return Err(ErrorCode::InvalidArgument);
        }
        skip = true;
    }
    match op {
        UpdateOp::Set { value, .. } | UpdateOp::Min { value, .. } | UpdateOp::Max { value, .. }
            if !storable(value) =>
        {
            Err(ErrorCode::InvalidFieldName)
        }
        UpdateOp::Push(Push { values, .. }) | UpdateOp::AddToSet { values, .. }
            if !values.iter().all(storable) =>
        {
            Err(ErrorCode::InvalidFieldName)
        }
        UpdateOp::Inc { by, .. } | UpdateOp::Mul { by, .. } if !numeric(by) => {
            Err(ErrorCode::QueryTypeError)
        }
        UpdateOp::Rename { from, to }
            if [from, to].iter().any(|p| {
                p.segments()
                    .iter()
                    .any(|s| !matches!(s, UpdateSegment::Field(_)))
            }) =>
        {
            Err(ErrorCode::InvalidArgument)
        }
        _ => Ok(skip),
    }
}

fn overlaps(a: &UpdatePath, b: &UpdatePath) -> bool {
    let n = a.segments().len().min(b.segments().len());
    (0..n).all(|i| match (&a.segments()[i], &b.segments()[i]) {
        (UpdateSegment::Field(x), UpdateSegment::Field(y)) => x.name == y.name,
        _ => true,
    })
}

fn creating(op: &UpdateOp) -> bool {
    !matches!(
        op,
        UpdateOp::Unset { .. }
            | UpdateOp::Pull { .. }
            | UpdateOp::PullAll { .. }
            | UpdateOp::Pop { .. }
            | UpdateOp::Rename { .. }
    )
}

fn run_op(root: &Value, op: &UpdateOp, now_ms: i64) -> R<Value> {
    if let UpdateOp::Rename { from, to } = op {
        return rename(root, from, to);
    }
    let path = paths_of(op)[0];
    let mut f = |old: Option<&Value>| step(op, old, now_ms);
    modify(root, path.segments(), creating(op), &mut f)
}

type StepFn<'a> = dyn FnMut(Option<&Value>) -> R<Option<Value>> + 'a;

/// Returns `container` with `f` applied at `segs` (relative to it).
fn modify(
    container: &Value,
    segs: &[UpdateSegment],
    creates: bool,
    f: &mut StepFn<'_>,
) -> R<Value> {
    let (seg, rest) = segs.split_first().expect("non-empty path");
    match (seg, container) {
        (UpdateSegment::Field(s), Value::Object(d)) => {
            let child = d.get(&s.name);
            let new_child = if rest.is_empty() {
                f(child)?
            } else {
                match child {
                    Some(c) => Some(modify(c, rest, creates, f)?),
                    None if creates => {
                        Some(modify(&Value::Object(Document::new()), rest, creates, f)?)
                    }
                    None => None,
                }
            };
            Ok(Value::Object(with_field(d, &s.name, new_child)))
        }
        (UpdateSegment::Field(s), Value::Array(items)) => match s.index {
            Some(i) if i < items.len() => {
                let mut out = items.clone();
                out[i] = if rest.is_empty() {
                    f(Some(&items[i]))?.unwrap_or(Value::Null)
                } else {
                    modify(&items[i], rest, creates, f)?
                };
                Ok(Value::Array(out))
            }
            Some(_) if creates => Err(ErrorCode::InvalidArgument),
            None if creates => Err(ErrorCode::QueryTypeError),
            _ => Ok(container.clone()),
        },
        (UpdateSegment::Field(_), _) => {
            if creates {
                Err(ErrorCode::QueryTypeError)
            } else {
                Ok(container.clone())
            }
        }
        (positional, Value::Array(items)) => {
            let mut out = Vec::new();
            for e in items {
                let selected = match positional {
                    UpdateSegment::Filtered(p) => p.matches(e).map_err(|err| err.code())?,
                    _ => true,
                };
                out.push(if !selected {
                    e.clone()
                } else if rest.is_empty() {
                    f(Some(e))?.unwrap_or(Value::Null)
                } else {
                    modify(e, rest, creates, f)?
                });
            }
            Ok(Value::Array(out))
        }
        _ => Err(ErrorCode::QueryTypeError),
    }
}

/// A copy of `d` with `name` set (in place if present, appended otherwise) or removed (`None`).
fn with_field(d: &Document, name: &str, v: Option<Value>) -> Document {
    let mut fields: Vec<(String, Value)> = Vec::new();
    let mut done = false;
    for (n, old) in d.iter() {
        if n == name {
            done = true;
            if let Some(v) = &v {
                fields.push((n.to_owned(), v.clone()));
            }
        } else {
            fields.push((n.to_owned(), old.clone()));
        }
    }
    if !done && let Some(v) = v {
        fields.push((name.to_owned(), v));
    }
    Document::try_from_fields(fields).unwrap()
}

fn step(op: &UpdateOp, old: Option<&Value>, now_ms: i64) -> R<Option<Value>> {
    let arr = |old: Option<&Value>| -> R<Option<Vec<Value>>> {
        match old {
            None => Ok(None),
            Some(Value::Array(a)) => Ok(Some(a.clone())),
            Some(_) => Err(ErrorCode::QueryTypeError),
        }
    };
    Ok(match op {
        UpdateOp::Set { value, .. } => Some(value.clone()),
        UpdateOp::Unset { .. } => None,
        UpdateOp::CurrentDate { .. } => Some(Value::DateTime(now_ms)),
        UpdateOp::Inc { by, .. } => Some(match old {
            None => by.clone(),
            Some(c) => arith(c, by, false)?,
        }),
        UpdateOp::Mul { by, .. } => Some(match old {
            None => match by {
                Value::Float64(_) => Value::Float64(0.0),
                Value::Decimal(_) => Value::Decimal(Decimal128::new(false, 0, 0).unwrap()),
                _ => Value::Int64(0),
            },
            Some(c) => arith(c, by, true)?,
        }),
        UpdateOp::Min { value, .. } | UpdateOp::Max { value, .. } => {
            let want = if matches!(op, UpdateOp::Min { .. }) {
                Ordering::Less
            } else {
                Ordering::Greater
            };
            match old {
                Some(c) if compare(Some(value), Some(c)) != want => Some(c.clone()),
                _ => Some(value.clone()),
            }
        }
        UpdateOp::Push(p) => Some(Value::Array(ref_push(arr(old)?.unwrap_or_default(), p))),
        UpdateOp::AddToSet { values, .. } => {
            let mut a = arr(old)?.unwrap_or_default();
            for v in values {
                if !a
                    .iter()
                    .any(|e| compare(Some(e), Some(v)) == Ordering::Equal)
                {
                    a.push(v.clone());
                }
            }
            Some(Value::Array(a))
        }
        UpdateOp::Pop { end, .. } => arr(old)?.map(|mut a| {
            if !a.is_empty() {
                match end {
                    PopEnd::First => {
                        a.remove(0);
                    }
                    PopEnd::Last => {
                        a.pop();
                    }
                }
            }
            Value::Array(a)
        }),
        UpdateOp::PullAll { values, .. } => arr(old)?.map(|a| {
            Value::Array(
                a.into_iter()
                    .filter(|e| {
                        !values
                            .iter()
                            .any(|v| compare(Some(e), Some(v)) == Ordering::Equal)
                    })
                    .collect(),
            )
        }),
        UpdateOp::Pull { predicate, .. } => match arr(old)? {
            None => None,
            Some(a) => {
                let mut out = Vec::new();
                for e in a {
                    if !predicate.matches(&e).map_err(|err| err.code())? {
                        out.push(e);
                    }
                }
                Some(Value::Array(out))
            }
        },
        UpdateOp::Rename { .. } => unreachable!("handled by run_op"),
    })
}

fn ref_push(mut a: Vec<Value>, p: &Push) -> Vec<Value> {
    let len = a.len() as i128;
    let pos = match p.position {
        None => len,
        Some(n) if n >= 0 => i128::from(n).min(len),
        Some(n) => (len + i128::from(n)).max(0),
    } as usize;
    for (k, v) in p.values.iter().enumerate() {
        a.insert(pos + k, v.clone());
    }
    if let Some(sort) = &p.sort {
        // Stable insertion sort: an element moves left only past strictly greater ones.
        for i in 1..a.len() {
            let mut j = i;
            while j > 0 && sort_key_cmp(sort, &a[j - 1], &a[j]) == Ordering::Greater {
                a.swap(j - 1, j);
                j -= 1;
            }
        }
    }
    if let Some(n) = p.slice {
        let len = a.len() as i128;
        let n = i128::from(n);
        a = if n >= 0 {
            a.into_iter().take(n.min(len) as usize).collect()
        } else {
            a.into_iter().skip((len + n).max(0) as usize).collect()
        };
    }
    a
}

fn sort_key_cmp(sort: &PushSort, x: &Value, y: &Value) -> Ordering {
    let dir = |o: Ordering, d: &Direction| match d {
        Direction::Ascending => o,
        Direction::Descending => o.reverse(),
    };
    match sort {
        PushSort::Elements(d) => dir(compare(Some(x), Some(y)), d),
        PushSort::Fields(keys) => {
            for (path, d) in keys {
                let gx = if let Value::Object(o) = x {
                    get_path(o, path)
                } else {
                    None
                };
                let gy = if let Value::Object(o) = y {
                    get_path(o, path)
                } else {
                    None
                };
                let o = dir(compare(gx, gy), d);
                if o != Ordering::Equal {
                    return o;
                }
            }
            Ordering::Equal
        }
    }
}

// ---------------------------------------------------------------- arithmetic

/// Decimal operand as (negative, coefficient, exponent), or a special.
enum Dec {
    Fin(bool, i128, i32),
    Inf(bool),
    NaN,
}

fn as_dec(v: &Value) -> Dec {
    let d = match v {
        Value::Int64(i) => {
            return Dec::Fin(*i < 0, i128::from(*i).abs(), 0);
        }
        Value::Float64(f) if f.is_nan() => return Dec::NaN,
        Value::Float64(f) if f.is_infinite() => return Dec::Inf(*f < 0.0),
        Value::Float64(f) => Decimal128::parse(&format!("{f:e}")).unwrap(),
        Value::Decimal(d) => *d,
        _ => unreachable!(),
    };
    match d {
        Decimal128::Finite {
            negative,
            coefficient,
            exponent,
        } => Dec::Fin(negative, coefficient as i128, i32::from(exponent)),
        Decimal128::Infinity { negative } => Dec::Inf(negative),
        Decimal128::NaN => Dec::NaN,
    }
}

fn arith(a: &Value, b: &Value, mul: bool) -> R<Value> {
    if !numeric(a) {
        return Err(ErrorCode::QueryTypeError);
    }
    match (a, b) {
        (Value::Int64(x), Value::Int64(y)) => {
            let r = if mul {
                i128::from(*x) * i128::from(*y)
            } else {
                i128::from(*x) + i128::from(*y)
            };
            i64::try_from(r)
                .map(Value::Int64)
                .map_err(|_| ErrorCode::InvalidArgument)
        }
        (Value::Decimal(_), _) | (_, Value::Decimal(_)) => {
            Ok(Value::Decimal(dec(as_dec(a), as_dec(b), mul)))
        }
        _ => {
            let f = |v: &Value| match v {
                Value::Int64(i) => *i as f64,
                Value::Float64(x) => *x,
                _ => unreachable!(),
            };
            Ok(Value::Float64(if mul { f(a) * f(b) } else { f(a) + f(b) }))
        }
    }
}

fn dec(x: Dec, y: Dec, mul: bool) -> Decimal128 {
    use Dec::{Fin, Inf, NaN};
    let neg_of = |d: &Dec| match d {
        Fin(n, ..) | Inf(n) => *n,
        NaN => false,
    };
    match (&x, &y) {
        (NaN, _) | (_, NaN) => Decimal128::NaN,
        (Inf(a), Inf(b)) if !mul => {
            if a == b {
                Decimal128::Infinity { negative: *a }
            } else {
                Decimal128::NaN
            }
        }
        (Inf(_), _) | (_, Inf(_)) if !mul => {
            let n = if matches!(x, Inf(_)) {
                neg_of(&x)
            } else {
                neg_of(&y)
            };
            Decimal128::Infinity { negative: n }
        }
        (Inf(_), Fin(_, 0, _)) | (Fin(_, 0, _), Inf(_)) => Decimal128::NaN,
        (Inf(_), _) | (_, Inf(_)) => Decimal128::Infinity {
            negative: neg_of(&x) != neg_of(&y),
        },
        (Fin(na, ca, ea), Fin(nb, cb, eb)) => {
            let (neg, mag, e) = if mul {
                (na != nb, ca * cb, ea + eb)
            } else {
                let e = (*ea).min(*eb);
                let sa = ca * 10i128.pow((ea - e) as u32) * if *na { -1 } else { 1 };
                let sb = cb * 10i128.pow((eb - e) as u32) * if *nb { -1 } else { 1 };
                let s = sa + sb;
                let neg = if s == 0 { *na && *nb } else { s < 0 };
                (neg, s.abs(), e)
            };
            assert!(
                mag <= MAX_COEFFICIENT as i128,
                "generator produced an inexact decimal case"
            );
            Decimal128::new(neg, mag as u128, e).expect("generator keeps exponents in range")
        }
    }
}

// ---------------------------------------------------------------- RENAME

fn names(p: &UpdatePath) -> Vec<String> {
    p.segments()
        .iter()
        .map(|s| match s {
            UpdateSegment::Field(f) => f.name.clone(),
            _ => unreachable!("validated"),
        })
        .collect()
}

fn rename(root: &Value, from: &UpdatePath, to: &UpdatePath) -> R<Value> {
    // Read the source: objects only; an array on the way is an error, a scalar means missing.
    let src = names(from);
    let mut cur = root;
    for n in &src[..src.len() - 1] {
        match cur {
            Value::Object(d) => match d.get(n) {
                Some(v @ Value::Object(_)) => cur = v,
                Some(Value::Array(_)) => return Err(ErrorCode::QueryTypeError),
                _ => return Ok(root.clone()),
            },
            _ => unreachable!(),
        }
    }
    let Value::Object(parent) = cur else {
        unreachable!()
    };
    let Some(moved) = parent.get(&src[src.len() - 1]).cloned() else {
        return Ok(root.clone());
    };
    let detached = modify(root, from.segments(), false, &mut |_| Ok(None))?;
    // The destination's intermediate values must be objects (or missing, then created).
    let dst = names(to);
    let mut cur = &detached;
    for n in &dst[..dst.len() - 1] {
        let Value::Object(d) = cur else {
            unreachable!()
        };
        match d.get(n) {
            None => break,
            Some(v @ Value::Object(_)) => cur = v,
            Some(_) => return Err(ErrorCode::QueryTypeError),
        }
    }
    modify(&detached, to.segments(), true, &mut |_| {
        Ok(Some(moved.clone()))
    })
}
