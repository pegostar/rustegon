// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Equi-depth histogram over key-encoded values (query-engine.md §2: 64 buckets).
//!
//! Layout: a `lower` bound (smallest value seen) and buckets with an inclusive `upper` bound;
//! bucket `i` holds the values in `(upper[i-1], upper[i]]` (the first one `[lower, upper[0]]`).
//! Each bucket stores the *fraction of rows* whose value falls in it (so a histogram built from
//! a sample needs no row count to be used) and the number of distinct sample values in it.
//!
//! Construction never splits one value across buckets: heavy values are expected to be in the
//! MCV list (excluded from the histogram by the collector, as PostgreSQL does), so a bucket
//! boundary only lands on light values and the buckets stay close to equal depth.
//!
//! Range estimation interpolates linearly inside a bucket. Positions are computed numerically
//! when the bounds are numbers or datetimes (decoded from the key bytes), otherwise from the
//! first 8 bytes after the common prefix of the bucket bounds — monotone in the total order,
//! approximately uniform for strings and identifiers.

use std::ops::Bound;

use super::{clamp01, to_f64};

/// A histogram bucket: values in `(previous upper, upper]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Bucket {
    /// Inclusive upper bound (key-encoded value).
    pub upper: Vec<u8>,
    /// Fraction of rows with a value in this bucket.
    pub fraction: f64,
    /// Distinct sample values in this bucket.
    pub distinct: u64,
}

/// An equi-depth histogram (module docs). Empty when the field has no non-MCV values.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Histogram {
    /// Smallest value (key-encoded); empty for an empty histogram.
    pub lower: Vec<u8>,
    /// Buckets in ascending order of `upper`.
    pub buckets: Vec<Bucket>,
}

impl Histogram {
    /// Builds a histogram of at most `max_buckets` buckets from distinct values in ascending
    /// byte order with their row counts; `rows` is the number of rows the counts were taken
    /// from (the sample size), used to turn counts into fractions.
    #[must_use]
    pub fn build(sorted: &[(Vec<u8>, u64)], rows: u64, max_buckets: usize) -> Self {
        let (Some(first), true) = (sorted.first(), rows > 0 && max_buckets > 0) else {
            return Self::default();
        };
        let total: u64 = sorted.iter().map(|(_, c)| c).sum();
        let depth = to_f64(total) / to_f64(max_buckets as u64);
        let rows = to_f64(rows);
        let mut buckets = Vec::with_capacity(max_buckets.min(sorted.len()));
        let (mut acc, mut in_bucket, mut distinct) = (0u64, 0u64, 0u64);
        for (i, (value, count)) in sorted.iter().enumerate() {
            acc += count;
            in_bucket += count;
            distinct += 1;
            // Close the bucket once the cumulative count reaches the next equi-depth target,
            // or at the last value.
            let target = depth * to_f64(buckets.len() as u64 + 1);
            let last = i + 1 == sorted.len();
            if last || (to_f64(acc) >= target && buckets.len() + 1 < max_buckets) {
                buckets.push(Bucket {
                    upper: value.clone(),
                    fraction: to_f64(in_bucket) / rows,
                    distinct,
                });
                in_bucket = 0;
                distinct = 0;
            }
        }
        Self {
            lower: first.0.clone(),
            buckets,
        }
    }

    /// Whether the histogram has no buckets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Total fraction of rows covered by the histogram.
    #[must_use]
    pub fn total_fraction(&self) -> f64 {
        self.buckets.iter().map(|b| b.fraction).sum()
    }

    /// Distinct sample values covered by the histogram.
    #[must_use]
    pub fn total_distinct(&self) -> u64 {
        self.buckets.iter().map(|b| b.distinct).sum()
    }

    /// Estimated fraction of rows with a value within `(lower, upper)` bounds (key-encoded).
    #[must_use]
    pub fn range_fraction(&self, lower: Bound<&[u8]>, upper: Bound<&[u8]>) -> f64 {
        let mut sum = 0.0;
        let mut prev: &[u8] = &self.lower;
        for b in &self.buckets {
            let lo = prev;
            let hi = b.upper.as_slice();
            prev = hi;
            // A bucket holding a single value is a point mass at its upper bound.
            if lo == hi || b.distinct == 1 {
                if within(hi, lower, upper) {
                    sum += b.fraction;
                }
                continue;
            }
            let from = match lower {
                Bound::Unbounded => 0.0,
                Bound::Included(x) | Bound::Excluded(x) => position(x, lo, hi),
            };
            let to = match upper {
                Bound::Unbounded => 1.0,
                Bound::Included(x) | Bound::Excluded(x) => position(x, lo, hi),
            };
            if to > from {
                sum += b.fraction * (to - from);
            }
        }
        sum
    }

    /// Merges two histograms (e.g. of two ranges of one collection) into one of at most
    /// `max_buckets` buckets, `self` and `other` weighted by their row counts.
    ///
    /// Approximate (equi-depth histograms are not exactly mergeable): each bucket is treated as
    /// its mass concentrated at its upper bound, then the points are re-bucketed.
    #[must_use]
    pub fn merge(&self, self_rows: u64, other: &Self, other_rows: u64, max_buckets: usize) -> Self {
        // Weights in parts per 2^20 rows keep integer counts for `build`.
        const SCALE: f64 = 1_048_576.0;
        let rows = self_rows + other_rows;
        if rows == 0 {
            return Self::default();
        }
        let mut points: Vec<(Vec<u8>, u64)> = Vec::new();
        for (h, n) in [(self, self_rows), (other, other_rows)] {
            for b in &h.buckets {
                points.push((
                    b.upper.clone(),
                    super::to_u64(b.fraction * to_f64(n) * SCALE),
                ));
            }
        }
        points.sort_by(|a, b| a.0.cmp(&b.0));
        points.dedup_by(|later, kept| {
            if later.0 == kept.0 {
                kept.1 += later.1;
                true
            } else {
                false
            }
        });
        let total_rows = super::to_u64(to_f64(rows) * SCALE);
        let mut merged = Self::build(&points, total_rows, max_buckets);
        let lowers = [&self.lower, &other.lower];
        if let Some(min) = lowers.into_iter().filter(|l| !l.is_empty()).min() {
            merged.lower.clone_from(min);
        }
        merged
    }
}

/// Whether `v` satisfies the bounds.
fn within(v: &[u8], lower: Bound<&[u8]>, upper: Bound<&[u8]>) -> bool {
    let lo_ok = match lower {
        Bound::Unbounded => true,
        Bound::Included(x) => v >= x,
        Bound::Excluded(x) => v > x,
    };
    let hi_ok = match upper {
        Bound::Unbounded => true,
        Bound::Included(x) => v <= x,
        Bound::Excluded(x) => v < x,
    };
    lo_ok && hi_ok
}

/// Position of `x` in `[lo, hi]` as a fraction (0 at or below `lo`, 1 at or above `hi`).
#[must_use]
pub fn position(x: &[u8], lo: &[u8], hi: &[u8]) -> f64 {
    if x <= lo {
        return 0.0;
    }
    if x >= hi {
        return 1.0;
    }
    let scalar = |b: &[u8]| number(b).or_else(|| datetime(b));
    if let (Some(a), Some(b), Some(v)) = (scalar(lo), scalar(hi), scalar(x))
        && b > a
    {
        return clamp01((v - a) / (b - a));
    }
    let common = lo.iter().zip(hi).take_while(|(a, b)| a == b).count();
    let (a, b, v) = (
        prefix_u64(lo, common),
        prefix_u64(hi, common),
        prefix_u64(x, common),
    );
    if b <= a {
        return 0.5;
    }
    clamp01((to_f64(v.saturating_sub(a))) / to_f64(b - a))
}

/// The 8 bytes of `b` after `skip`, big endian, zero padded.
fn prefix_u64(b: &[u8], skip: usize) -> u64 {
    let mut buf = [0u8; 8];
    for (dst, src) in buf.iter_mut().zip(b.iter().skip(skip)) {
        *dst = *src;
    }
    u64::from_be_bytes(buf)
}

/// A key-encoded finite number as `f64` (data-model.md §3.1: class byte, then for non-zero
/// values the exponent as i16 BE with the sign bit flipped and base-100 digit pairs, inverted
/// for negatives). `None` for other classes and infinities.
#[must_use]
pub fn number(b: &[u8]) -> Option<f64> {
    const NEG: u8 = 0x12;
    const ZERO: u8 = 0x13;
    const POS: u8 = 0x14;
    let (&class, rest) = b.split_first()?;
    let negative = match class {
        ZERO => return Some(0.0),
        NEG => true,
        POS => false,
        _ => return None,
    };
    let byte = |i: usize| rest.get(i).map(|v| if negative { !v } else { *v });
    let exp_bits = u16::from_be_bytes([byte(0)?, byte(1)?]) ^ 0x8000;
    let exponent = f64::from(i16::from_be_bytes(exp_bits.to_be_bytes()));
    // 0.D × 10^E: accumulate up to 9 digit pairs (18 digits, beyond f64 precision).
    let (mut mantissa, mut scale, mut i) = (0.0f64, 1.0f64, 2usize);
    while let Some(v) = byte(i) {
        let pair = f64::from(v / 2);
        scale /= 100.0;
        mantissa += pair * scale;
        if v % 2 == 0 || i >= 10 {
            break;
        }
        i += 1;
    }
    let magnitude = mantissa * 10f64.powf(exponent);
    Some(if negative { -magnitude } else { magnitude })
}

/// A key-encoded datetime as milliseconds (`0x70` + i64 BE with the sign bit flipped).
fn datetime(b: &[u8]) -> Option<f64> {
    let (&class, rest) = b.split_first()?;
    if class != 0x70 {
        return None;
    }
    let bytes: [u8; 8] = rest.get(..8)?.try_into().ok()?;
    let ms = i64::from_be_bytes((u64::from_be_bytes(bytes) ^ (1 << 63)).to_be_bytes());
    #[allow(clippy::cast_precision_loss)]
    Some(ms as f64)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rustegon_doc::{
        Value,
        keyenc::{Direction, encode_element},
    };

    use super::*;

    fn enc(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        encode_element(&mut out, Some(v), Direction::Ascending).unwrap();
        out
    }

    #[test]
    fn number_decoding_matches_values() {
        for v in [1.0, -1.0, 123.0, 0.5, -2.25, 1e10, -7e-5, 98_765.432_1] {
            let got = number(&enc(&Value::Float64(v))).unwrap();
            assert!((got - v).abs() <= v.abs() * 1e-12, "{v} -> {got}");
        }
        assert_eq!(number(&enc(&Value::Int64(0))), Some(0.0));
        assert_eq!(number(&enc(&Value::String("x".into()))), None);
        assert_eq!(
            datetime(&enc(&Value::DateTime(-5))).map(f64::round),
            Some(-5.0)
        );
    }

    #[test]
    fn uniform_numbers_build_equal_depth() {
        let values: Vec<(Vec<u8>, u64)> = (0..6400).map(|i| (enc(&Value::Int64(i)), 1)).collect();
        let h = Histogram::build(&values, 6400, 64);
        assert_eq!(h.buckets.len(), 64);
        for b in &h.buckets {
            assert!((b.fraction - 1.0 / 64.0).abs() < 1e-9);
            assert_eq!(b.distinct, 100);
        }
        let lo = enc(&Value::Int64(1000));
        let hi = enc(&Value::Int64(3000));
        let f = h.range_fraction(Bound::Included(&lo), Bound::Excluded(&hi));
        assert!((f - 2000.0 / 6400.0).abs() < 0.01, "{f}");
        assert!((h.total_fraction() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn merge_keeps_mass() {
        let a: Vec<(Vec<u8>, u64)> = (0..1000).map(|i| (enc(&Value::Int64(i)), 1)).collect();
        let b: Vec<(Vec<u8>, u64)> = (1000..3000).map(|i| (enc(&Value::Int64(i)), 1)).collect();
        let ha = Histogram::build(&a, 1000, 64);
        let hb = Histogram::build(&b, 2000, 64);
        let m = ha.merge(1000, &hb, 2000, 64);
        assert!((m.total_fraction() - 1.0).abs() < 1e-3);
        let mid = enc(&Value::Int64(1000));
        let f = m.range_fraction(Bound::Unbounded, Bound::Excluded(&mid));
        assert!((f - 1.0 / 3.0).abs() < 0.03, "{f}");
        assert_eq!(m.lower, enc(&Value::Int64(0)));
    }

    #[test]
    fn empty_inputs() {
        assert!(Histogram::build(&[], 10, 64).is_empty());
        assert!(Histogram::default().range_fraction(Bound::Unbounded, Bound::Unbounded) < 1e-12);
    }
}
