// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `HyperLogLog` distinct-value estimator (Flajolet et al. 2007) for the NDV statistic
//! (query-engine.md §2).
//!
//! - Precision `p = 12`: `m = 4096` one-byte registers (4 KiB per field), relative standard
//!   error `1.04 / √m ≈ 1.63 %`. A fixed precision keeps every sketch mergeable with every
//!   other one (per-range sketches are merged in a cluster) and fixes the persisted size.
//! - Input: the key encoding of a value (`keyenc`), hashed with XXH3-64, so values equal under
//!   `=` (`1`, `1.0`) count once. XXH3 is already a workspace dependency and its output is
//!   stable across platforms and releases, which a persisted sketch requires.
//! - Estimate: the raw harmonic-mean estimator with the small-range (linear counting)
//!   correction; with a 64-bit hash the large-range correction of the paper is unnecessary.
//! - Merge: register-wise maximum (exact: the merged sketch equals the sketch of the union).

use twox_hash::XxHash3_64;

use super::to_f64;

/// Register-index bits.
pub const PRECISION: u32 = 12;
/// Number of registers (`2^PRECISION`).
pub const REGISTERS: usize = 1 << PRECISION;
/// Largest register value: leading zeros of the remaining `64 - p` bits, plus one.
pub const MAX_RANK: u8 = 64 - 12 + 1;

/// A `HyperLogLog` sketch with [`REGISTERS`] registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HyperLogLog {
    registers: Vec<u8>,
}

impl Default for HyperLogLog {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperLogLog {
    /// An empty sketch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registers: vec![0; REGISTERS],
        }
    }

    /// Rebuilds a sketch from persisted registers; `None` if the length is not [`REGISTERS`]
    /// or a register exceeds [`MAX_RANK`] (corrupt input).
    #[must_use]
    pub fn from_registers(registers: Vec<u8>) -> Option<Self> {
        (registers.len() == REGISTERS && registers.iter().all(|r| *r <= MAX_RANK))
            .then_some(Self { registers })
    }

    /// The registers (persisted form).
    #[must_use]
    pub fn registers(&self) -> &[u8] {
        &self.registers
    }

    /// Adds a key-encoded value.
    pub fn add(&mut self, encoded: &[u8]) {
        self.add_hash(XxHash3_64::oneshot(encoded));
    }

    /// Adds a precomputed 64-bit hash (callers with their own uniform hash).
    pub fn add_hash(&mut self, hash: u64) {
        // Top p bits pick the register; the rank is the position of the first 1 bit in the
        // remaining 64 - p bits (all zero → 64 - p + 1).
        let index = usize::try_from(hash >> (64 - PRECISION)).unwrap_or(0);
        let rest = hash << PRECISION;
        let rank = u8::try_from(rest.leading_zeros().min(64 - PRECISION) + 1).unwrap_or(MAX_RANK);
        if let Some(r) = self.registers.get_mut(index) {
            *r = (*r).max(rank);
        }
    }

    /// Merges `other` into `self` (sketch of the union).
    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.registers.iter_mut().zip(&other.registers) {
            *a = (*a).max(*b);
        }
    }

    /// Whether nothing was added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registers.iter().all(|r| *r == 0)
    }

    /// Estimated number of distinct values added.
    #[must_use]
    pub fn estimate(&self) -> f64 {
        let m = to_f64(REGISTERS as u64);
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let mut sum = 0.0;
        let mut zeros = 0u64;
        for r in &self.registers {
            sum += (-f64::from(*r)).exp2();
            if *r == 0 {
                zeros += 1;
            }
        }
        let raw = alpha * m * m / sum;
        if raw <= 2.5 * m && zeros > 0 {
            // Small-range correction: linear counting is far more accurate while registers
            // are still empty.
            m * (m / to_f64(zeros)).ln()
        } else {
            raw
        }
    }

    /// The relative standard error of the estimate, `1.04 / √m`.
    #[must_use]
    pub fn standard_error() -> f64 {
        1.04 / to_f64(REGISTERS as u64).sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_duplicates() {
        let mut h = HyperLogLog::new();
        assert!(h.is_empty());
        assert!(h.estimate().abs() < f64::EPSILON);
        for _ in 0..1000 {
            h.add(b"same");
        }
        assert!((h.estimate() - 1.0).abs() < 0.01, "{}", h.estimate());
    }

    #[test]
    fn registers_round_trip_and_reject_corruption() {
        let mut h = HyperLogLog::new();
        h.add(b"a");
        let back = HyperLogLog::from_registers(h.registers().to_vec());
        assert_eq!(back.as_ref(), Some(&h));
        assert!(HyperLogLog::from_registers(vec![0; 10]).is_none());
        let mut bad = vec![0; REGISTERS];
        bad[3] = MAX_RANK + 1;
        assert!(HyperLogLog::from_registers(bad).is_none());
    }

    #[test]
    fn all_zero_hash_gets_max_rank() {
        let mut h = HyperLogLog::new();
        h.add_hash(0);
        assert_eq!(h.registers()[0], MAX_RANK);
    }
}
