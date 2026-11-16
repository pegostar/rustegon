// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Exact numeric normal form shared by comparison (§2.1) and key encoding (§3.1, DEC-018).
//!
//! Every finite non-zero `int64`, `float64` and `decimal128` is written as `±0.D × 10^E` where
//! `D` is its decimal digit string without leading or trailing zeros. This form is unique per
//! mathematical value, so comparing `(class, E, D)` compares numbers exactly across types —
//! including int64 values above 2^53 and float64 values with long binary fractions, where a
//! conversion to either type would round. Every finite float64 is `m × 2^e` and therefore has a
//! finite decimal expansion (`m × 5^-e × 10^e` for `e < 0`), computed here with a small bignum.

use std::{cmp::Ordering, fmt::Write as _};

use crate::decimal::Decimal128;

/// Order classes of numbers (§3.1 bytes `0x10`..`0x15` in the same order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NumClass {
    NaN,
    NegInf,
    Neg,
    Zero,
    Pos,
    PosInf,
}

/// A number in exact normal form. `digits` (each 0..=9, first and last non-zero) and `exp` are
/// meaningful only for [`NumClass::Neg`] / [`NumClass::Pos`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactNum {
    pub(crate) class: NumClass,
    pub(crate) exp: i32,
    pub(crate) digits: Vec<u8>,
}

impl Ord for ExactNum {
    fn cmp(&self, other: &Self) -> Ordering {
        self.class.cmp(&other.class).then_with(|| match self.class {
            NumClass::Pos => self.magnitude_cmp(other),
            NumClass::Neg => other.magnitude_cmp(self),
            _ => Ordering::Equal,
        })
    }
}

impl PartialOrd for ExactNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ExactNum {
    fn special(class: NumClass) -> Self {
        Self {
            class,
            exp: 0,
            digits: Vec::new(),
        }
    }

    /// Compares `|self|` and `|other|` for two finite non-zero numbers: `0.D` lies in [0.1, 1),
    /// so a larger exponent wins, and equal exponents compare digit strings lexicographically
    /// (a strict prefix is smaller because trailing zeros were stripped).
    fn magnitude_cmp(&self, other: &Self) -> Ordering {
        self.exp
            .cmp(&other.exp)
            .then_with(|| self.digits.cmp(&other.digits))
    }

    /// Builds from a non-negative integer's decimal digits (most significant first, possibly
    /// with trailing zeros) times `10^scale`.
    fn from_integer_digits(negative: bool, mut digits: Vec<u8>, scale: i32) -> Self {
        let first_nz = digits.iter().position(|d| *d != 0);
        let Some(first_nz) = first_nz else {
            return Self::special(NumClass::Zero);
        };
        digits.drain(..first_nz);
        let int_len = i32::try_from(digits.len()).unwrap_or(i32::MAX);
        while digits.last() == Some(&0) {
            digits.pop();
        }
        Self {
            class: if negative {
                NumClass::Neg
            } else {
                NumClass::Pos
            },
            exp: int_len + scale,
            digits,
        }
    }

    pub(crate) fn from_i64(v: i64) -> Self {
        Self::from_integer_digits(v < 0, ascii_digits(&v.unsigned_abs().to_string()), 0)
    }

    pub(crate) fn from_decimal(d: &Decimal128) -> Self {
        match *d {
            Decimal128::NaN => Self::special(NumClass::NaN),
            Decimal128::Infinity { negative: true } => Self::special(NumClass::NegInf),
            Decimal128::Infinity { negative: false } => Self::special(NumClass::PosInf),
            Decimal128::Finite {
                negative,
                coefficient,
                exponent,
            } => Self::from_integer_digits(
                negative,
                ascii_digits(&coefficient.to_string()),
                i32::from(exponent),
            ),
        }
    }

    pub(crate) fn from_f64(x: f64) -> Self {
        if x.is_nan() {
            return Self::special(NumClass::NaN);
        }
        if x.is_infinite() {
            return Self::special(if x < 0.0 {
                NumClass::NegInf
            } else {
                NumClass::PosInf
            });
        }
        if x == 0.0 {
            return Self::special(NumClass::Zero);
        }
        let (m, e) = f64_mantissa_exponent(x);
        // x = m × 2^e exactly. For e < 0 write it as (m × 5^-e) × 10^e.
        let digits = if e >= 0 {
            let mut n = BigDec::from_u64(m);
            n.mul_pow(2, e.unsigned_abs());
            n.digits()
        } else {
            let mut n = BigDec::from_u64(m);
            n.mul_pow(5, e.unsigned_abs());
            n.digits()
        };
        Self::from_integer_digits(x < 0.0, digits, e.min(0))
    }

    /// Decimal digits of `D` as ASCII, for re-parsing into a concrete type.
    pub(crate) fn digit_string(&self) -> String {
        self.digits.iter().map(|d| char::from(b'0' + d)).collect()
    }
}

fn ascii_digits(s: &str) -> Vec<u8> {
    s.bytes().map(|b| b - b'0').collect()
}

/// `(m, e)` with `|x| = m × 2^e`, `m` odd (fewer bignum steps), for finite non-zero `x`.
fn f64_mantissa_exponent(x: f64) -> (u64, i32) {
    const FRACTION_BITS: u32 = 52;
    const EXP_FIELD_MASK: u64 = 0x7FF;
    // Exponent bias plus the fraction width: value = significand × 2^(biased − 1075).
    const EXP_OFFSET: i32 = 1075;
    let bits = x.to_bits();
    let biased = i32::try_from((bits >> FRACTION_BITS) & EXP_FIELD_MASK).unwrap_or(0);
    let fraction = bits & ((1u64 << FRACTION_BITS) - 1);
    let (mut m, mut e) = if biased == 0 {
        (fraction, 1 - EXP_OFFSET) // subnormal
    } else {
        (fraction | (1u64 << FRACTION_BITS), biased - EXP_OFFSET)
    };
    let tz = m.trailing_zeros();
    m >>= tz;
    e += i32::try_from(tz).unwrap_or(0);
    (m, e)
}

/// Unsigned big integer in base 10^9 limbs (least significant first); only multiplication by
/// small factors is needed.
struct BigDec(Vec<u32>);

const LIMB_BASE: u64 = 1_000_000_000;

impl BigDec {
    fn from_u64(mut v: u64) -> Self {
        let mut limbs = Vec::new();
        while v > 0 {
            limbs.push(u32::try_from(v % LIMB_BASE).unwrap_or(0));
            v /= LIMB_BASE;
        }
        Self(limbs)
    }

    fn mul_small(&mut self, k: u32) {
        let mut carry = 0u64;
        for limb in &mut self.0 {
            // limb < 1e9 and k < 2^32: the product plus carry stays below 2^64.
            let t = u64::from(*limb) * u64::from(k) + carry;
            *limb = u32::try_from(t % LIMB_BASE).unwrap_or(0);
            carry = t / LIMB_BASE;
        }
        while carry > 0 {
            self.0.push(u32::try_from(carry % LIMB_BASE).unwrap_or(0));
            carry /= LIMB_BASE;
        }
    }

    /// Multiplies by `base^n` for base 2 or 5, in chunks that fit a `u32` factor.
    fn mul_pow(&mut self, base: u32, mut n: u32) {
        // 2^31 and 5^13 are the largest powers below 2^32.
        let (chunk_exp, chunk) = if base == 2 {
            (31, 1u32 << 31)
        } else {
            (13, 1_220_703_125)
        };
        while n >= chunk_exp {
            self.mul_small(chunk);
            n -= chunk_exp;
        }
        self.mul_small(base.pow(n));
    }

    fn digits(&self) -> Vec<u8> {
        let mut s = String::new();
        for (i, limb) in self.0.iter().rev().enumerate() {
            if i == 0 {
                s.push_str(&limb.to_string());
            } else {
                let _ = write!(s, "{limb:09}");
            }
        }
        ascii_digits(&s)
    }
}

/// Exact comparison of an `i64` with a finite or non-finite `f64` without bignums.
pub(crate) fn cmp_i64_f64(i: i64, f: f64) -> Ordering {
    // 2^63 as f64 (exact). Every f64 in [-2^63, 2^63) truncates to a representable i64.
    const TWO_63: f64 = 9_223_372_036_854_775_808.0;
    if f.is_nan() {
        return Ordering::Greater; // NaN is the lowest number (§2.1)
    }
    if f >= TWO_63 {
        return Ordering::Less;
    }
    if f < -TWO_63 {
        return Ordering::Greater;
    }
    // In range: truncation is exact and `as` cannot saturate here.
    #[allow(clippy::cast_possible_truncation)]
    let t = f.trunc() as i64;
    i.cmp(&t)
        .then_with(|| 0.0f64.partial_cmp(&f.fract()).unwrap_or(Ordering::Equal))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> ExactNum {
        ExactNum::from_decimal(&Decimal128::parse(s).unwrap())
    }

    #[test]
    fn exact_forms_agree_across_types() {
        assert_eq!(ExactNum::from_i64(1), ExactNum::from_f64(1.0));
        assert_eq!(ExactNum::from_i64(1), d("1.00"));
        assert_eq!(ExactNum::from_i64(-250), d("-2.5E+2"));
        assert_eq!(ExactNum::from_f64(0.5), d("0.5"));
        assert_eq!(ExactNum::from_f64(-0.0).class, NumClass::Zero);
        let x = ExactNum::from_i64(1);
        assert_eq!((x.exp, x.digits.clone()), (1, vec![1]));
    }

    #[test]
    fn exact_compare_beyond_2_pow_53() {
        let big = (1i64 << 53) + 1;
        #[allow(clippy::cast_precision_loss)]
        let f = big as f64; // rounds to 2^53
        assert_eq!(
            ExactNum::from_i64(big).cmp(&ExactNum::from_f64(f)),
            Ordering::Greater
        );
        assert_eq!(cmp_i64_f64(big, f), Ordering::Greater);
        assert_eq!(
            cmp_i64_f64(i64::MAX, 9_223_372_036_854_775_808.0),
            Ordering::Less
        );
        assert_eq!(
            cmp_i64_f64(i64::MIN, -9_223_372_036_854_775_808.0),
            Ordering::Equal
        );
    }

    #[test]
    fn f64_extremes_have_exact_expansions() {
        let tiny = ExactNum::from_f64(f64::from_bits(1)); // 2^-1074
        assert_eq!(tiny.exp, -323);
        assert_eq!(tiny.digits.len(), 751);
        let max = ExactNum::from_f64(f64::MAX);
        assert_eq!(max.exp, 309);
        assert!(ExactNum::from_f64(0.1) > d("0.1")); // 0.1f64 is slightly above 1/10
    }
}
