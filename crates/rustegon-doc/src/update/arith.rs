// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Numeric semantics of `INC` and `MUL` (FR-DOC-006).
//!
//! Type promotion (*Provisional, PD pending*: the specification is silent; this is the MongoDB
//! rule set, which drivers and users already expect):
//! - `int64 ∘ int64` → `int64`, checked; overflow is an error (`RGN-1001`), never a silent
//!   promotion to `float64` (that would lose precision behind the user's back);
//! - any `decimal128` operand → `decimal128`: `int64` converts exactly, `float64` converts through
//!   its shortest round-trip decimal string (so `0.1` becomes `0.1`, not the 55-digit binary
//!   expansion); the result is IEEE 754-2008 decimal128 arithmetic with round-half-even to 34
//!   digits and the ideal exponent (`min(e1, e2)` for addition, `e1 + e2` for multiplication),
//!   except that overflow is an error instead of ±Infinity;
//! - otherwise (`float64` involved) → `float64` IEEE arithmetic (`int64` operand converted with
//!   round-to-nearest).
//!
//! Decimal arithmetic uses exact little-endian digit vectors: operands have at most 34 digits and
//! alignment shifts are bounded by the exponent range (≈ 12 300 digits), so schoolbook arithmetic
//! is exact and cheap enough for an update operator, and needs no dependency.

use crate::{
    decimal::{Decimal128, EXP_MAX, EXP_MIN, MAX_DIGITS},
    value::Value,
};

/// Arithmetic operator of `INC` / `MUL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArithOp {
    Add,
    Mul,
}

/// Why an arithmetic step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArithError {
    /// An operand is not a number.
    NotNumeric,
    /// The result does not fit the result type (int64 range, decimal128 exponent range).
    Overflow,
}

/// `a ∘ b` under the promotion rules of the module documentation.
// Short operand names mirror the arithmetic notation of the module docs.
#[allow(clippy::many_single_char_names)]
pub(crate) fn apply(op: ArithOp, a: &Value, b: &Value) -> Result<Value, ArithError> {
    use Value as V;
    match (a, b) {
        (V::Int64(x), V::Int64(y)) => {
            let r = match op {
                ArithOp::Add => x.checked_add(*y),
                ArithOp::Mul => x.checked_mul(*y),
            };
            r.map(V::Int64).ok_or(ArithError::Overflow)
        }
        (V::Decimal(_), _) | (_, V::Decimal(_)) => {
            let (x, y) = (to_decimal(a)?, to_decimal(b)?);
            let r = match op {
                ArithOp::Add => dec_add(x, y),
                ArithOp::Mul => dec_mul(x, y),
            };
            r.map(V::Decimal)
        }
        _ => {
            let (x, y) = (to_f64(a)?, to_f64(b)?);
            Ok(V::Float64(match op {
                ArithOp::Add => x + y,
                ArithOp::Mul => x * y,
            }))
        }
    }
}

/// `true` for the numeric types an update operand may have (`counter` is a read-only projection
/// and never an operand).
pub(crate) fn is_numeric(v: &Value) -> bool {
    matches!(v, Value::Int64(_) | Value::Float64(_) | Value::Decimal(_))
}

fn to_f64(v: &Value) -> Result<f64, ArithError> {
    match v {
        // Round-to-nearest conversion is the documented float64 promotion.
        #[allow(clippy::cast_precision_loss)]
        Value::Int64(i) => Ok(*i as f64),
        Value::Float64(f) => Ok(*f),
        _ => Err(ArithError::NotNumeric),
    }
}

fn to_decimal(v: &Value) -> Result<Decimal128, ArithError> {
    match v {
        Value::Int64(i) => Ok(Decimal128::from_i64(*i)),
        Value::Float64(f) => Ok(f64_to_decimal(*f)),
        Value::Decimal(d) => Ok(*d),
        _ => Err(ArithError::NotNumeric),
    }
}

/// `float64` → `decimal128` through the shortest round-trip decimal representation.
pub(crate) fn f64_to_decimal(f: f64) -> Decimal128 {
    if f.is_nan() {
        return Decimal128::NaN;
    }
    if f.is_infinite() {
        return Decimal128::Infinity { negative: f < 0.0 };
    }
    // `{:e}` prints the shortest digit string that round-trips (≤ 17 digits, exponent within
    // ±324), which decimal128 always holds exactly, so parsing cannot fail; the fallback only
    // keeps this function total.
    Decimal128::parse(&format!("{f:e}")).unwrap_or(Decimal128::NaN)
}

/// IEEE 754-2008 decimal128 addition, round-half-even; overflow is an error.
#[allow(clippy::many_single_char_names)]
pub(crate) fn dec_add(x: Decimal128, y: Decimal128) -> Result<Decimal128, ArithError> {
    use Decimal128 as D;
    match (x, y) {
        (D::NaN, _) | (_, D::NaN) => Ok(D::NaN),
        (D::Infinity { negative: a }, D::Infinity { negative: b }) => {
            Ok(if a == b { x } else { D::NaN })
        }
        (D::Infinity { .. }, _) => Ok(x),
        (_, D::Infinity { .. }) => Ok(y),
        (
            D::Finite {
                negative: nx,
                coefficient: cx,
                exponent: ex,
            },
            D::Finite {
                negative: ny,
                coefficient: cy,
                exponent: ey,
            },
        ) => {
            let e = ex.min(ey);
            let a = shifted(cx, i64::from(ex) - i64::from(e));
            let b = shifted(cy, i64::from(ey) - i64::from(e));
            let (negative, mag) = if nx == ny {
                (nx, add_mag(&a, &b))
            } else {
                match cmp_mag(&a, &b) {
                    std::cmp::Ordering::Greater => (nx, sub_mag(&a, &b)),
                    std::cmp::Ordering::Less => (ny, sub_mag(&b, &a)),
                    // Exact cancellation gives +0 under round-half-even (IEEE 754 §6.3).
                    std::cmp::Ordering::Equal => (false, Vec::new()),
                }
            };
            finish(negative, mag, i64::from(e))
        }
    }
}

/// IEEE 754-2008 decimal128 multiplication, round-half-even; overflow is an error.
pub(crate) fn dec_mul(x: Decimal128, y: Decimal128) -> Result<Decimal128, ArithError> {
    use Decimal128 as D;
    let sign = |d: &D| match *d {
        D::Finite { negative, .. } | D::Infinity { negative } => negative,
        D::NaN => false,
    };
    let is_zero = |d: &D| matches!(*d, D::Finite { coefficient: 0, .. });
    let negative = sign(&x) != sign(&y);
    match (x, y) {
        (D::NaN, _) | (_, D::NaN) => Ok(D::NaN),
        (D::Infinity { .. }, _) | (_, D::Infinity { .. }) => {
            // ∞ × 0 is invalid (NaN); otherwise the sign is the XOR of the signs.
            Ok(if is_zero(&x) || is_zero(&y) {
                D::NaN
            } else {
                D::Infinity { negative }
            })
        }
        (
            D::Finite {
                coefficient: cx,
                exponent: ex,
                ..
            },
            D::Finite {
                coefficient: cy,
                exponent: ey,
                ..
            },
        ) => {
            let mag = mul_mag(&digits_of(cx), &digits_of(cy));
            finish(negative, mag, i64::from(ex) + i64::from(ey))
        }
    }
}

/// Little-endian decimal digits of `c` (empty for zero).
fn digits_of(mut c: u128) -> Vec<u8> {
    let mut d = Vec::new();
    while c > 0 {
        // `c % 10 < 10` always fits a u8.
        d.push(u8::try_from(c % 10).unwrap_or(0));
        c /= 10;
    }
    d
}

/// Digits of `c × 10^shift`.
fn shifted(c: u128, shift: i64) -> Vec<u8> {
    let d = digits_of(c);
    if d.is_empty() {
        return d;
    }
    let mut out = vec![0; usize::try_from(shift).unwrap_or(0)];
    out.extend_from_slice(&d);
    out
}

fn trim(d: &mut Vec<u8>) {
    while d.last() == Some(&0) {
        d.pop();
    }
}

fn cmp_mag(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    // Inputs are trimmed (no most-significant zeros), so length decides first.
    a.len()
        .cmp(&b.len())
        .then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

fn add_mag(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u8;
    for i in 0..a.len().max(b.len()) {
        let s = a.get(i).copied().unwrap_or(0) + b.get(i).copied().unwrap_or(0) + carry;
        out.push(s % 10);
        carry = s / 10;
    }
    if carry > 0 {
        out.push(carry);
    }
    out
}

/// `a − b` for `a ≥ b`.
fn sub_mag(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0u8;
    for (i, &da) in a.iter().enumerate() {
        let sub = b.get(i).copied().unwrap_or(0) + borrow;
        if da >= sub {
            out.push(da - sub);
            borrow = 0;
        } else {
            out.push(da + 10 - sub);
            borrow = 1;
        }
    }
    trim(&mut out);
    out
}

fn mul_mag(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    // Operands have at most 34 digits each: column sums stay far below u32::MAX.
    let mut acc = vec![0u32; a.len() + b.len()];
    for (i, &da) in a.iter().enumerate() {
        for (j, &db) in b.iter().enumerate() {
            acc[i + j] += u32::from(da) * u32::from(db);
        }
    }
    let mut out = Vec::with_capacity(acc.len());
    let mut carry = 0u32;
    for v in acc {
        let t = v + carry;
        out.push(u8::try_from(t % 10).unwrap_or(0));
        carry = t / 10;
    }
    while carry > 0 {
        out.push(u8::try_from(carry % 10).unwrap_or(0));
        carry /= 10;
    }
    trim(&mut out);
    out
}

/// Rounds the exact result `(-1)^negative × digits × 10^exp` to decimal128: at most 34 digits and
/// an exponent of at least `EXP_MIN` (both by dropping low digits, round-half-even), then clamps
/// an exponent above `EXP_MAX` by appending zeros when the coefficient has room.
fn finish(negative: bool, mut digits: Vec<u8>, mut exp: i64) -> Result<Decimal128, ArithError> {
    trim(&mut digits);
    let len = i64::try_from(digits.len()).unwrap_or(i64::MAX);
    let max_digits = i64::try_from(MAX_DIGITS).unwrap_or(i64::MAX);
    let drop = (len - max_digits).max(i64::from(EXP_MIN) - exp).max(0);
    if drop > 0 {
        digits = round_half_even(&digits, usize::try_from(drop).unwrap_or(usize::MAX));
        exp += drop;
        if digits.len() > MAX_DIGITS {
            // Rounding carried into a 35th digit: the value is 10^34, drop one more (exact) zero.
            digits.remove(0);
            exp += 1;
        }
    }
    if digits.is_empty() {
        // Zero keeps its sign; its exponent is clamped into range (value unchanged).
        let e = exp.clamp(i64::from(EXP_MIN), i64::from(EXP_MAX));
        return Decimal128::new(negative, 0, i32::try_from(e).unwrap_or(0))
            .map_err(|_| ArithError::Overflow);
    }
    while exp > i64::from(EXP_MAX) && digits.len() < MAX_DIGITS {
        digits.insert(0, 0);
        exp -= 1;
    }
    if exp > i64::from(EXP_MAX) {
        return Err(ArithError::Overflow);
    }
    let coefficient = digits
        .iter()
        .rev()
        .fold(0u128, |acc, d| acc * 10 + u128::from(*d));
    Decimal128::new(negative, coefficient, i32::try_from(exp).unwrap_or(0))
        .map_err(|_| ArithError::Overflow)
}

/// Drops the `drop` least significant digits, rounding half to even.
fn round_half_even(digits: &[u8], drop: usize) -> Vec<u8> {
    if drop > digits.len() {
        // Every digit, and the rounding digit beyond them, is dropped: the value rounds to 0
        // because the first dropped position (a leading zero) is below 5.
        return Vec::new();
    }
    let mut kept = digits[drop..].to_vec();
    let first_dropped = digits[drop - 1];
    let sticky = digits[..drop - 1].iter().any(|d| *d != 0);
    let odd = kept.first().is_some_and(|d| d % 2 == 1);
    if first_dropped > 5 || (first_dropped == 5 && (sticky || odd)) {
        let mut i = 0;
        loop {
            if i == kept.len() {
                kept.push(1);
                break;
            }
            if kept[i] == 9 {
                kept[i] = 0;
                i += 1;
            } else {
                kept[i] += 1;
                break;
            }
        }
    }
    trim(&mut kept);
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal128 {
        Decimal128::parse(s).unwrap()
    }

    #[test]
    fn decimal_add_ideal_exponent_and_cancellation() {
        assert_eq!(dec_add(d("1.50"), d("2.5")).unwrap().to_string(), "4.00");
        assert_eq!(dec_add(d("1"), d("-1")).unwrap().to_string(), "0");
        assert_eq!(dec_add(d("-0"), d("-0.0")).unwrap().to_string(), "-0.0");
        assert_eq!(dec_add(d("-0"), d("0")).unwrap().to_string(), "0");
        assert_eq!(
            dec_add(d("Infinity"), d("-Infinity")).unwrap(),
            Decimal128::NaN
        );
    }

    #[test]
    fn decimal_rounds_half_even_to_34_digits() {
        let max = "9999999999999999999999999999999999"; // 34 nines
        // 10^34 needs 35 digits: rounds to 1.000…E+34 exactly.
        assert_eq!(
            dec_add(d(max), d("1")).unwrap().to_string(),
            "1.000000000000000000000000000000000E+34"
        );
        // 1E+34 + 0.5 → tie at the 35th digit, even neighbour kept.
        let big = "1000000000000000000000000000000000"; // 34 digits
        assert_eq!(dec_add(d(big), d("0.5")).unwrap().to_string(), big);
        assert_eq!(
            dec_add(d("1000000000000000000000000000000001"), d("0.5"))
                .unwrap()
                .to_string(),
            "1000000000000000000000000000000002"
        );
        assert_eq!(
            dec_add(d(big), d("0.51")).unwrap().to_string(),
            "1000000000000000000000000000000001"
        );
        // Huge exponent gap: the tiny operand only rounds; the result keeps full precision (IEEE).
        assert_eq!(
            dec_add(d("1E+100"), d("1E-100")).unwrap(),
            Decimal128::new(false, 10u128.pow(33), 67).unwrap()
        );
    }

    #[test]
    fn decimal_mul_and_overflow() {
        assert_eq!(dec_mul(d("1.5"), d("-2.0")).unwrap().to_string(), "-3.00");
        assert_eq!(dec_mul(d("-0"), d("5")).unwrap().to_string(), "-0");
        assert_eq!(dec_mul(d("Infinity"), d("0")).unwrap(), Decimal128::NaN);
        assert_eq!(
            dec_mul(d("9999999999999999999999999999999999E+6111"), d("10")),
            Err(ArithError::Overflow)
        );
        // Clamping: 1E+6111 × 1E+1 = 1E+6112 is representable as 10E+6111.
        assert_eq!(
            dec_mul(d("1E+6111"), d("1E+1")).unwrap(),
            Decimal128::new(false, 10, 6111).unwrap()
        );
        // Underflow rounds toward the subnormal range, eventually to zero.
        assert_eq!(
            dec_mul(d("1E-6176"), d("0.1")).unwrap(),
            Decimal128::new(false, 0, EXP_MIN).unwrap()
        );
        assert_eq!(
            dec_mul(d("6E-6176"), d("0.1")).unwrap(),
            Decimal128::new(false, 1, EXP_MIN).unwrap()
        );
    }

    #[test]
    fn promotion_rules() {
        assert_eq!(
            apply(ArithOp::Add, &Value::Int64(i64::MAX), &Value::Int64(1)),
            Err(ArithError::Overflow)
        );
        assert_eq!(
            apply(ArithOp::Add, &Value::Int64(1), &Value::Float64(0.5)),
            Ok(Value::Float64(1.5))
        );
        assert_eq!(
            apply(
                ArithOp::Add,
                &Value::Decimal(d("1.0")),
                &Value::Float64(0.1)
            ),
            Ok(Value::Decimal(d("1.1")))
        );
        assert_eq!(
            apply(ArithOp::Mul, &Value::Int64(3), &Value::Decimal(d("0.5"))),
            Ok(Value::Decimal(d("1.5")))
        );
        assert_eq!(
            apply(ArithOp::Add, &Value::String("x".into()), &Value::Int64(1)),
            Err(ArithError::NotNumeric)
        );
        assert_eq!(f64_to_decimal(-0.0).to_string(), "-0");
    }
}
