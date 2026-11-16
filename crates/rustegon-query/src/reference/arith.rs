// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Arithmetic and concatenation (query-language.md §4.1 levels 2–4) of the reference interpreter.
//!
//! - `missing` in, `missing` out; otherwise `null` in, `null` out (SQL++ convention).
//! - **Number types** follow the data-model §2.3 `INC`/`MUL` rules: `int64 ∘ int64` → `int64`;
//!   any `decimal128` operand → `decimal128`; otherwise `float64` (IEEE). Integer overflow gives
//!   `null` instead of an error, as the functions are total (§4.2) (*Provisional*).
//! - **`/`** always yields `float64` for integer and float operands (`7 / 2 = 3.5`); `%` keeps
//!   `int64` for integers (sign of the dividend) and is IEEE `fmod` otherwise. Division or
//!   remainder by zero is `null` (§4.2). `decimal128` `/` and `%` are not implemented (unsupported
//!   error) (*Provisional*).
//! - **Datetimes:** `datetime ± int64` (milliseconds; interval literals are milliseconds) →
//!   `datetime`; `datetime - datetime` → `int64` milliseconds (*Provisional*).
//! - Any other operand type → `null`.
//! - `||` concatenates two strings or two arrays; anything else is `null`.
//!
//! Decimal results are computed by the document model's update arithmetic (a one-field `INC` or
//! `MUL`), so the IEEE 754-2008 rounding rules are exactly those of §2.3.

use rustegon_common::Error;
use rustegon_doc::{
    Decimal128, Document, Value,
    update::{UpdateContext, UpdateOp, UpdatePath, apply_updates},
};

use super::{error::unsupported, eval::Val};
use crate::ast::BinaryOp;

/// `l op r` for `+ - * / %`.
///
/// # Errors
/// Unsupported `decimal128` division / remainder.
pub fn binary(op: BinaryOp, l: Val, r: Val) -> Result<Val, Error> {
    let (Some(l), Some(r)) = (l, r) else {
        return Ok(None);
    };
    Ok(Some(match (&l, &r) {
        (Value::DateTime(t), Value::Int64(ms)) => match op {
            BinaryOp::Add => t.checked_add(*ms).map_or(Value::Null, Value::DateTime),
            BinaryOp::Sub => t.checked_sub(*ms).map_or(Value::Null, Value::DateTime),
            _ => Value::Null,
        },
        (Value::DateTime(a), Value::DateTime(b)) if op == BinaryOp::Sub => {
            a.checked_sub(*b).map_or(Value::Null, Value::Int64)
        }
        _ if !is_number(&l) || !is_number(&r) => Value::Null,
        (Value::Decimal(_), _) | (_, Value::Decimal(_)) => decimal(op, l, r)?,
        (Value::Int64(a), Value::Int64(b)) => int(op, *a, *b),
        _ => float(op, as_f64(&l), as_f64(&r)),
    }))
}

/// Unary minus.
#[must_use]
pub fn neg(v: Val) -> Val {
    Some(match v? {
        Value::Int64(i) => i.checked_neg().map_or(Value::Null, Value::Int64),
        Value::Float64(f) => Value::Float64(-f),
        Value::Decimal(d) => Value::Decimal(negate_decimal(d)),
        _ => Value::Null,
    })
}

/// `l || r`.
#[must_use]
pub fn concat(l: Val, r: Val) -> Val {
    let (Some(l), Some(r)) = (l, r) else {
        return None;
    };
    Some(match (l, r) {
        (Value::String(a), Value::String(b)) => Value::String(a + &b),
        (Value::Array(mut a), Value::Array(b)) => {
            a.extend(b);
            Value::Array(a)
        }
        _ => Value::Null,
    })
}

/// `true` for `int64`, `float64` and `decimal128`.
#[must_use]
pub fn is_number(v: &Value) -> bool {
    matches!(v, Value::Int64(_) | Value::Float64(_) | Value::Decimal(_))
}

/// `int64` or `float64` as `f64` (decimals are handled before this is used).
#[allow(clippy::cast_precision_loss)] // IEEE conversion is the §2.3 promotion rule.
pub(crate) fn as_f64(v: &Value) -> f64 {
    match v {
        Value::Int64(i) => *i as f64,
        Value::Float64(f) => *f,
        _ => f64::NAN,
    }
}

fn int(op: BinaryOp, a: i64, b: i64) -> Value {
    let r = match op {
        BinaryOp::Add => a.checked_add(b),
        BinaryOp::Sub => a.checked_sub(b),
        BinaryOp::Mul => a.checked_mul(b),
        BinaryOp::Div => {
            return if b == 0 {
                Value::Null
            } else {
                float(op, as_f64(&Value::Int64(a)), as_f64(&Value::Int64(b)))
            };
        }
        // `checked_rem` is `None` for a zero divisor and for `i64::MIN % -1`.
        BinaryOp::Mod => a.checked_rem(b),
        _ => None,
    };
    r.map_or(Value::Null, Value::Int64)
}

fn float(op: BinaryOp, a: f64, b: f64) -> Value {
    Value::Float64(match op {
        BinaryOp::Add => a + b,
        BinaryOp::Sub => a - b,
        BinaryOp::Mul => a * b,
        BinaryOp::Div | BinaryOp::Mod if b == 0.0 => return Value::Null,
        BinaryOp::Div => a / b,
        BinaryOp::Mod => a % b,
        _ => return Value::Null,
    })
}

fn decimal(op: BinaryOp, l: Value, r: Value) -> Result<Value, Error> {
    let r = match op {
        BinaryOp::Add | BinaryOp::Mul => r,
        BinaryOp::Sub => match neg(Some(r)) {
            Some(v @ (Value::Int64(_) | Value::Float64(_) | Value::Decimal(_))) => v,
            _ => return Ok(Value::Null),
        },
        _ => return Err(unsupported("decimal128 division and remainder")),
    };
    Ok(via_update(op == BinaryOp::Mul, l, r))
}

/// Computes `l + r` (or `l * r`) as the update operator `INC v BY r` (`MUL v BY r`) on `{v: l}`;
/// an overflow (an update error) is `null`.
fn via_update(multiply: bool, l: Value, r: Value) -> Value {
    let mut doc = Document::new();
    doc.insert("v", l);
    let path = UpdatePath::new(vec![rustegon_doc::update::UpdateSegment::Field(
        rustegon_doc::path::Segment {
            name: "v".into(),
            index: None,
        },
    )]);
    let op = if multiply {
        UpdateOp::Mul { path, by: r }
    } else {
        UpdateOp::Inc { path, by: r }
    };
    match apply_updates(&doc, &[op], &UpdateContext { now_ms: 0 }) {
        Ok(out) => out.get("v").cloned().unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

/// Flips the sign of a decimal (NaN has none).
pub(crate) fn negate_decimal(d: Decimal128) -> Decimal128 {
    with_sign(d, |negative| !negative)
}

/// Clears the sign of a decimal.
pub(crate) fn abs_decimal(d: Decimal128) -> Decimal128 {
    with_sign(d, |_| false)
}

fn with_sign(d: Decimal128, sign: impl Fn(bool) -> bool) -> Decimal128 {
    match d {
        Decimal128::Finite {
            negative,
            coefficient,
            exponent,
        } => Decimal128::Finite {
            negative: sign(negative),
            coefficient,
            exponent,
        },
        Decimal128::Infinity { negative } => Decimal128::Infinity {
            negative: sign(negative),
        },
        Decimal128::NaN => Decimal128::NaN,
    }
}
