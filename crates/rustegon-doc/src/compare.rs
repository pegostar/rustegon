// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Total order and equality of values (data-model.md §2.1).
//!
//! `minKey < missing < null < numbers < string < object < array < binary < objectId < uuid <
//! bool < datetime < timestamp < vector < maxKey`. `None` stands for `missing` (see
//! [`crate::value`]). Within a class:
//! - numbers (`int64`, `float64`, `decimal128`, and `counter` projections) compare by exact
//!   mathematical value; all NaNs are equal and lowest; `-0.0 = 0 = 0E+3`;
//! - strings by UTF-8 bytes (collations are PD-015);
//! - objects field by field in stored order (name bytes, then value), a prefix first;
//! - arrays element by element, a prefix first;
//! - binary by (length, subtype, bytes); vectors by (dims, elements in `f32::total_cmp` order).
//!
//! This order is exactly the byte order of the §3.1 key encoding (TC-DOC-003 checks it).

use std::cmp::Ordering;

use crate::{
    numeric::{ExactNum, cmp_i64_f64},
    value::{Document, Value},
};

/// Rank of a value's order class (§2.1); `None` = missing.
#[must_use]
pub fn class_rank(v: Option<&Value>) -> u8 {
    let Some(v) = v else { return 1 };
    match v {
        Value::MinKey => 0,
        Value::Null => 2,
        Value::Int64(_) | Value::Float64(_) | Value::Decimal(_) | Value::Counter(_) => 3,
        Value::String(_) => 4,
        Value::Object(_) => 5,
        Value::Array(_) => 6,
        Value::Binary { .. } => 7,
        Value::ObjectId(_) => 8,
        Value::Uuid(_) => 9,
        Value::Bool(_) => 10,
        Value::DateTime(_) => 11,
        Value::Timestamp(_) => 12,
        Value::VectorF32(_) => 13,
        Value::MaxKey => 14,
    }
}

/// Compares two values (or `missing` = `None`) in the §2.1 total order.
#[must_use]
pub fn compare(a: Option<&Value>, b: Option<&Value>) -> Ordering {
    let (ra, rb) = (class_rank(a), class_rank(b));
    if ra != rb {
        return ra.cmp(&rb);
    }
    match (a, b) {
        (Some(a), Some(b)) => compare_same_class(a, b),
        _ => Ordering::Equal, // both missing
    }
}

/// Compares two present values in the §2.1 total order.
#[must_use]
pub fn compare_values(a: &Value, b: &Value) -> Ordering {
    compare(Some(a), Some(b))
}

/// Query equality `=` (§2.1): same order class and equal value, so `1 = 1.0` but
/// `null = missing` is false. (`IS NULL`, which matches both, is a query-layer predicate.)
#[must_use]
pub fn values_equal(a: Option<&Value>, b: Option<&Value>) -> bool {
    compare(a, b) == Ordering::Equal
}

fn compare_same_class(a: &Value, b: &Value) -> Ordering {
    use Value as V;
    match (a, b) {
        (V::String(x), V::String(y)) => x.as_bytes().cmp(y.as_bytes()),
        (V::Object(x), V::Object(y)) => compare_documents(x, y),
        (V::Array(x), V::Array(y)) => compare_seq(x, y),
        (
            V::Binary {
                subtype: sx,
                data: dx,
            },
            V::Binary {
                subtype: sy,
                data: dy,
            },
        ) => dx
            .len()
            .cmp(&dy.len())
            .then(sx.cmp(sy))
            .then_with(|| dx.cmp(dy)),
        (V::ObjectId(x), V::ObjectId(y)) => x.cmp(y),
        (V::Uuid(x), V::Uuid(y)) => x.cmp(y),
        (V::Bool(x), V::Bool(y)) => x.cmp(y),
        (V::DateTime(x), V::DateTime(y)) => x.cmp(y),
        (V::Timestamp(x), V::Timestamp(y)) => x.cmp(y),
        (V::VectorF32(x), V::VectorF32(y)) => x.len().cmp(&y.len()).then_with(|| {
            x.iter()
                .zip(y)
                .map(|(p, q)| p.total_cmp(q))
                .find(|o| o.is_ne())
                .unwrap_or(Ordering::Equal)
        }),
        _ => compare_numbers(a, b),
    }
}

fn compare_seq(x: &[Value], y: &[Value]) -> Ordering {
    x.iter()
        .zip(y)
        .map(|(p, q)| compare_values(p, q))
        .find(|o| o.is_ne())
        .unwrap_or_else(|| x.len().cmp(&y.len()))
}

fn compare_documents(x: &Document, y: &Document) -> Ordering {
    x.iter()
        .zip(y.iter())
        .map(|((nx, vx), (ny, vy))| {
            nx.as_bytes()
                .cmp(ny.as_bytes())
                .then_with(|| compare_values(vx, vy))
        })
        .find(|o| o.is_ne())
        .unwrap_or_else(|| x.len().cmp(&y.len()))
}

/// Same-class comparison of two numbers (any other pair compares equal, which cannot happen
/// because the caller checked the class).
fn compare_numbers(a: &Value, b: &Value) -> Ordering {
    use Value as V;
    // Fast paths avoid the exact normal form for the common same-type cases.
    match (a, b) {
        (V::Int64(x) | V::Counter(x), V::Int64(y) | V::Counter(y)) => x.cmp(y),
        (V::Float64(x), V::Float64(y)) => cmp_f64(*x, *y),
        (V::Int64(x) | V::Counter(x), V::Float64(y)) => cmp_i64_f64(*x, *y),
        (V::Float64(x), V::Int64(y) | V::Counter(y)) => cmp_i64_f64(*y, *x).reverse(),
        _ => match (exact(a), exact(b)) {
            (Some(x), Some(y)) => x.cmp(&y),
            _ => Ordering::Equal,
        },
    }
}

/// NaN lowest and equal to itself; `-0.0 = 0.0`.
fn cmp_f64(x: f64, y: f64) -> Ordering {
    match (x.is_nan(), y.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => x.partial_cmp(&y).unwrap_or(Ordering::Equal),
    }
}

/// Exact normal form of a numeric value.
pub(crate) fn exact(v: &Value) -> Option<ExactNum> {
    match v {
        Value::Int64(i) | Value::Counter(i) => Some(ExactNum::from_i64(*i)),
        Value::Float64(f) => Some(ExactNum::from_f64(*f)),
        Value::Decimal(d) => Some(ExactNum::from_decimal(d)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decimal::Decimal128;

    fn dec(s: &str) -> Value {
        Value::Decimal(Decimal128::parse(s).unwrap())
    }

    #[test]
    fn numeric_cross_type_equality_and_nan() {
        assert!(values_equal(
            Some(&Value::Int64(1)),
            Some(&Value::Float64(1.0))
        ));
        assert!(values_equal(Some(&Value::Int64(1)), Some(&dec("1.00"))));
        assert!(values_equal(
            Some(&Value::Float64(-0.0)),
            Some(&dec("0E+5"))
        ));
        let nan = Value::Float64(f64::NAN);
        assert!(values_equal(Some(&nan), Some(&dec("NaN"))));
        assert_eq!(
            compare_values(&nan, &Value::Float64(f64::NEG_INFINITY)),
            Ordering::Less
        );
        assert_eq!(
            compare_values(&dec("-Infinity"), &Value::Int64(i64::MIN)),
            Ordering::Less
        );
    }

    #[test]
    fn null_is_not_missing_and_classes_ordered() {
        assert!(!values_equal(Some(&Value::Null), None));
        assert_eq!(compare(Some(&Value::MinKey), None), Ordering::Less);
        assert_eq!(compare(None, Some(&Value::Null)), Ordering::Less);
        assert_eq!(
            compare_values(&Value::Bool(false), &Value::DateTime(i64::MIN)),
            Ordering::Less
        );
        assert_eq!(
            compare_values(&Value::String("z".into()), &Value::Object(Document::new())),
            Ordering::Less
        );
    }
}
