// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `decimal128`: IEEE 754-2008 decimal floating point, binary integer decimal (BID) encoding
//! (data-model.md §2, type tag 0x05).
//!
//! The value is kept decoded (sign, coefficient, exponent) so that arithmetic-free operations —
//! parsing, formatting, exact comparison (see `numeric.rs`) — need no bit twiddling. Like IEEE
//! 754, members of a cohort (`1.0` and `1.00`) are distinct representations of the same number:
//! they compare equal (§2.1) but keep their textual form through JSON and `RDoc`.
//!
//! Own implementation instead of a crate dependency (implementation-rules.md §7): only parsing,
//! formatting and BID packing are needed, no decimal arithmetic.

use std::fmt;

use crate::codec::error::{DocError, DocResult};

/// Largest coefficient: 34 decimal digits (IEEE 754-2008 decimal128 precision).
pub const MAX_COEFFICIENT: u128 = 10u128.pow(34) - 1;
/// Precision in decimal digits.
pub const MAX_DIGITS: usize = 34;
/// Smallest exponent (of the integer coefficient), IEEE 754-2008 decimal128 `emin - (p - 1)`.
pub const EXP_MIN: i32 = -6176;
/// Largest exponent (of the integer coefficient), IEEE 754-2008 decimal128 `emax - (p - 1)`.
pub const EXP_MAX: i32 = 6111;
/// Exponent bias of the BID encoding.
const EXP_BIAS: i32 = 6176;
/// Combination-field pattern `11110` (bits 126..122): infinity.
const INF_BITS: u128 = 0x78 << 120;
/// Combination-field pattern `11111` (bits 126..122): NaN (quiet, positive, no payload).
const NAN_BITS: u128 = 0x7C << 120;
/// Mask of the 113-bit coefficient of the small-coefficient BID form.
const COEFF_MASK: u128 = (1 << 113) - 1;

/// A decimal128 value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decimal128 {
    /// Finite value `(-1)^negative × coefficient × 10^exponent`.
    Finite {
        /// Sign (negative zero exists, as in IEEE 754).
        negative: bool,
        /// Coefficient, at most [`MAX_COEFFICIENT`].
        coefficient: u128,
        /// Exponent in `EXP_MIN..=EXP_MAX`.
        exponent: i16,
    },
    /// ±Infinity.
    Infinity {
        /// `true` for −Infinity.
        negative: bool,
    },
    /// NaN. Sign, signalling bit and payload are not preserved (canonical quiet NaN).
    NaN,
}

impl Decimal128 {
    /// Builds a finite value.
    ///
    /// # Errors
    /// [`DocError::Malformed`] if the coefficient has more than 34 digits or the exponent is
    /// outside `EXP_MIN..=EXP_MAX`.
    pub fn new(negative: bool, coefficient: u128, exponent: i32) -> DocResult<Self> {
        if coefficient > MAX_COEFFICIENT {
            return Err(DocError::malformed(
                0,
                "decimal128 coefficient exceeds 34 digits",
            ));
        }
        let exponent = i16::try_from(exponent)
            .ok()
            .filter(|e| (EXP_MIN..=EXP_MAX).contains(&i32::from(*e)))
            .ok_or_else(|| DocError::malformed(0, "decimal128 exponent out of range"))?;
        Ok(Self::Finite {
            negative,
            coefficient,
            exponent,
        })
    }

    /// The exact decimal128 representation of an `i64` (exponent 0).
    #[must_use]
    pub fn from_i64(v: i64) -> Self {
        Self::Finite {
            negative: v < 0,
            coefficient: u128::from(v.unsigned_abs()),
            exponent: 0,
        }
    }

    /// `true` for NaN.
    #[must_use]
    pub fn is_nan(&self) -> bool {
        matches!(self, Self::NaN)
    }

    /// Canonical BID bits (always the small-coefficient form, NaN without payload).
    #[must_use]
    pub fn to_bits(&self) -> u128 {
        match *self {
            Self::Finite {
                negative,
                coefficient,
                exponent,
            } => {
                // Invariant of the constructors: exponent in range, so the biased value is
                // 0..=12287 and fits the 14-bit field without touching the `11` pattern.
                let biased = u128::from((i32::from(exponent) + EXP_BIAS).unsigned_abs());
                (u128::from(negative) << 127) | (biased << 113) | (coefficient & COEFF_MASK)
            }
            Self::Infinity { negative } => (u128::from(negative) << 127) | INF_BITS,
            Self::NaN => NAN_BITS,
        }
    }

    /// Decodes BID bits. Returns the value and whether `bits` is its canonical encoding
    /// ([`Decimal128::to_bits`]). Non-canonical encodings decode as IEEE 754 says: coefficients
    /// above the precision are zero, NaN payloads and sign are dropped, infinity ignores the
    /// trailing bits.
    #[must_use]
    pub fn from_bits(bits: u128) -> (Self, bool) {
        let negative = bits >> 127 == 1;
        let combination = (bits >> 122) & 0x1F;
        if combination == 0x1F {
            return (Self::NaN, bits == NAN_BITS);
        }
        if combination == 0x1E {
            let canonical = bits & ((1 << 122) - 1) == 0;
            return (Self::Infinity { negative }, canonical);
        }
        let (biased, coefficient, canonical) = if (bits >> 125) & 0x3 == 0x3 {
            // Large-coefficient form: the implied coefficient is ≥ 2^113 > MAX_COEFFICIENT, so
            // the value is zero and the encoding never canonical.
            ((bits >> 111) & 0x3FFF, 0, false)
        } else {
            let c = bits & COEFF_MASK;
            if c > MAX_COEFFICIENT {
                ((bits >> 113) & 0x3FFF, 0, false)
            } else {
                ((bits >> 113) & 0x3FFF, c, true)
            }
        };
        // The large form can carry a biased exponent above 12287; clamp it (still zero).
        let max_biased = EXP_MAX + EXP_BIAS;
        let biased = i32::try_from(biased).map_or(max_biased, |b| b.min(max_biased));
        let exponent = i16::try_from(biased - EXP_BIAS).unwrap_or(0);
        (
            Self::Finite {
                negative,
                coefficient,
                exponent,
            },
            canonical,
        )
    }

    /// Parses the decimal string syntax (`[+-]digits[.digits][e[+-]digits]`, `Infinity`, `Inf`,
    /// `NaN`, case-insensitive). The value must be representable exactly: trailing zeros are
    /// dropped or added to bring the exponent into range, but no rounding takes place.
    ///
    /// # Errors
    /// [`DocError::Malformed`] on syntax errors, more than 34 significant digits, or an exponent
    /// that cannot be brought into range exactly.
    pub fn parse(s: &str) -> DocResult<Self> {
        let bad = |reason: &str| DocError::malformed(0, format!("decimal128: {reason}"));
        let (negative, body) = match s.as_bytes().first() {
            Some(b'-') => (true, &s[1..]),
            Some(b'+') => (false, &s[1..]),
            _ => (false, s),
        };
        if body.eq_ignore_ascii_case("inf") || body.eq_ignore_ascii_case("infinity") {
            return Ok(Self::Infinity { negative });
        }
        if body.eq_ignore_ascii_case("nan") {
            return Ok(Self::NaN);
        }
        let bytes = body.as_bytes();
        let mut i = 0;
        let mut digits: Vec<u8> = Vec::new();
        let mut frac_len: i64 = 0;
        let mut seen_digit = false;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            push_significant(&mut digits, bytes[i]);
            seen_digit = true;
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                push_significant(&mut digits, bytes[i]);
                frac_len += 1;
                seen_digit = true;
                i += 1;
            }
        }
        if !seen_digit {
            return Err(bad("no digits"));
        }
        let mut exp_lit: i64 = 0;
        if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
            i += 1;
            let exp_negative = match bytes.get(i) {
                Some(b'-') => {
                    i += 1;
                    true
                }
                Some(b'+') => {
                    i += 1;
                    false
                }
                _ => false,
            };
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                // Saturate: anything beyond ±10^12 is out of range whatever the digits are.
                exp_lit = (exp_lit * 10 + i64::from(bytes[i] - b'0')).min(1_000_000_000_000);
                i += 1;
            }
            if i == start {
                return Err(bad("empty exponent"));
            }
            if exp_negative {
                exp_lit = -exp_lit;
            }
        }
        if i != bytes.len() {
            return Err(bad("unexpected character"));
        }
        let exponent = exp_lit - frac_len;
        Self::from_digits(negative, digits, exponent)
    }

    /// Builds a value from significant digits (no leading zeros) and an exponent, exactly.
    fn from_digits(negative: bool, mut digits: Vec<u8>, mut exponent: i64) -> DocResult<Self> {
        let bad = |reason: &str| DocError::malformed(0, format!("decimal128: {reason}"));
        if digits.is_empty() {
            // Zero: clamping the exponent does not change the value (IEEE 754 does the same).
            let exponent = exponent.clamp(i64::from(EXP_MIN), i64::from(EXP_MAX));
            return Self::new(negative, 0, i32::try_from(exponent).unwrap_or(0));
        }
        while digits.len() > MAX_DIGITS && digits.last() == Some(&0) {
            digits.pop();
            exponent += 1;
        }
        if digits.len() > MAX_DIGITS {
            return Err(bad("more than 34 significant digits (inexact)"));
        }
        while exponent > i64::from(EXP_MAX) && digits.len() < MAX_DIGITS {
            digits.push(0);
            exponent -= 1;
        }
        if exponent > i64::from(EXP_MAX) {
            return Err(bad("exponent overflow"));
        }
        while exponent < i64::from(EXP_MIN) && digits.last() == Some(&0) {
            digits.pop();
            exponent += 1;
        }
        if exponent < i64::from(EXP_MIN) {
            return Err(bad("exponent underflow (inexact)"));
        }
        let coefficient = digits
            .iter()
            .fold(0u128, |acc, d| acc * 10 + u128::from(*d));
        Self::new(negative, coefficient, i32::try_from(exponent).unwrap_or(0))
    }
}

/// Appends a digit, skipping leading zeros (they are not significant).
fn push_significant(digits: &mut Vec<u8>, ascii: u8) {
    let d = ascii - b'0';
    if d != 0 || !digits.is_empty() {
        digits.push(d);
    }
}

impl fmt::Display for Decimal128 {
    /// IEEE 754 / General Decimal Arithmetic "to-scientific-string": plain notation when the
    /// exponent is ≤ 0 and the adjusted exponent ≥ −6, scientific otherwise. Parsing the output
    /// yields the same representation (cohort member included).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (negative, coefficient, exponent) = match *self {
            Self::NaN => return f.write_str("NaN"),
            Self::Infinity { negative } => {
                return f.write_str(if negative { "-Infinity" } else { "Infinity" });
            }
            Self::Finite {
                negative,
                coefficient,
                exponent,
            } => (negative, coefficient, i64::from(exponent)),
        };
        if negative {
            f.write_str("-")?;
        }
        let digits = coefficient.to_string();
        let n = i64::try_from(digits.len()).unwrap_or(i64::MAX);
        let adjusted = exponent + n - 1;
        if exponent <= 0 && adjusted >= -6 {
            if exponent == 0 {
                return f.write_str(&digits);
            }
            let point = n + exponent;
            if point > 0 {
                let p = usize::try_from(point).unwrap_or(0);
                write!(f, "{}.{}", &digits[..p], &digits[p..])
            } else {
                let zeros = usize::try_from(-point).unwrap_or(0);
                write!(f, "0.{}{}", "0".repeat(zeros), digits)
            }
        } else {
            let (first, rest) = digits.split_at(1);
            f.write_str(first)?;
            if !rest.is_empty() {
                write!(f, ".{rest}")?;
            }
            let sign = if adjusted < 0 { '-' } else { '+' };
            write!(f, "E{sign}{}", adjusted.unsigned_abs())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(s: &str) -> String {
        Decimal128::parse(s).unwrap().to_string()
    }

    #[test]
    fn decimal_format_matches_to_scientific_string() {
        assert_eq!(rt("12.50"), "12.50");
        assert_eq!(rt("0"), "0");
        assert_eq!(rt("-0"), "-0");
        assert_eq!(rt("0.000001"), "0.000001");
        assert_eq!(rt("0.0000001"), "1E-7");
        assert_eq!(rt("1e3"), "1E+3");
        assert_eq!(rt("123e-2"), "1.23");
        assert_eq!(rt("1.5E+10"), "1.5E+10");
        assert_eq!(rt("0e10"), "0E+10");
        assert_eq!(rt("inf"), "Infinity");
        assert_eq!(rt("-Infinity"), "-Infinity");
        assert_eq!(rt("nan"), "NaN");
        assert_eq!(rt("000123.4500"), "123.4500");
    }

    #[test]
    fn decimal_parse_rejects_inexact_and_garbage() {
        assert!(Decimal128::parse("12345678901234567890123456789012345").is_err());
        assert!(Decimal128::parse("1234567890123456789012345678901234").is_ok());
        assert!(Decimal128::parse("12345678901234567890123456789012340").is_ok());
        assert!(Decimal128::parse("1e6112").is_ok()); // padded with zeros
        assert!(Decimal128::parse("1e6144").is_ok());
        assert!(Decimal128::parse("1e6145").is_err());
        assert!(Decimal128::parse("1e-6176").is_ok());
        assert!(Decimal128::parse("1e-6177").is_err());
        assert!(Decimal128::parse("10e-6177").is_ok());
        assert!(Decimal128::parse("0e-99999").is_ok());
        for bad in ["", "-", ".", "e5", "1e", "1.2.3", "1x", " 1", "--1", "1e+"] {
            assert!(Decimal128::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn decimal_bits_round_trip_and_known_values() {
        // 1 = coefficient 1, exponent 0: biased exponent 6176 = 0x1820 at bit 113.
        let one = Decimal128::parse("1").unwrap();
        assert_eq!(one.to_bits(), (0x1820u128 << 113) | 1);
        for s in [
            "1",
            "-12.50",
            "0",
            "-0",
            "1E+6111",
            "9.999999999999999999999999999999999E+6144",
            "1E-6176",
            "Infinity",
            "-Infinity",
            "NaN",
        ] {
            let d = Decimal128::parse(s).unwrap();
            let (back, canonical) = Decimal128::from_bits(d.to_bits());
            assert!(canonical, "{s}");
            assert_eq!(back, d, "{s}");
        }
    }

    #[test]
    fn decimal_non_canonical_bits_detected() {
        let (v, c) = Decimal128::from_bits(NAN_BITS | 1);
        assert!(v.is_nan() && !c);
        let (v, c) = Decimal128::from_bits(INF_BITS | 5);
        assert_eq!(v, Decimal128::Infinity { negative: false });
        assert!(!c);
        let (v, c) = Decimal128::from_bits((0x1820u128 << 113) | (MAX_COEFFICIENT + 1));
        assert!(!c);
        assert!(matches!(v, Decimal128::Finite { coefficient: 0, .. }));
        let (_, c) = Decimal128::from_bits(0x3 << 125);
        assert!(!c);
    }
}
