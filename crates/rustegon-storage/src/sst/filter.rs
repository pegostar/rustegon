// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Per-SST Ribbon filter (storage-engine.md §4).
//!
//! Algorithm: *Standard Ribbon* with coefficient width w = 64 (Dillinger & Walzer, "Ribbon filter:
//! practically smaller than Bloom and Xor", 2021, §2–§3). Each key hash defines one row of a
//! linear system over GF(2): a start slot `s`, a 64-bit coefficient vector `c` (bit 0 set) covering
//! slots `s..s+64`, and an r-bit fingerprint `f`. Construction solves `C·X = F` for an
//! `m × r` bit matrix `X` by on-the-fly Gaussian elimination ("banding", each row is XOR-reduced
//! until it finds an empty pivot slot) followed by back-substitution. A query recomputes the row
//! and checks `parity(c & X[s..s+64]) == f` for each of the r result bits, so a member always
//! matches and a non-member matches with probability 2^-r. With r = 7 the FPR is ≈ 0.8 % at about
//! 7.7 bits/key including slot overhead, i.e. ~25–30 % smaller than a Bloom filter at the same FPR.
//!
//! Banding can fail (linearly dependent rows); the builder then retries with a new hash seed and,
//! every few attempts, more slack slots. If every attempt fails the SST simply has no filter,
//! which costs reads but never correctness.
//!
//! Block layout: `format (u8 = 1) ‖ result_bits (u8) ‖ reserved (u16) ‖ seed (u32 LE) ‖
//! num_slots (u32 LE) ‖ words (u64 LE)…` where the solution is stored interleaved: for each group
//! of 64 slots, `result_bits` consecutive words (one per result bit), so a query touches at most
//! two adjacent groups.

use twox_hash::XxHash3_64;

use crate::{
    coding::Reader,
    error::{Result, StorageError},
};

/// Coefficient width in slots (one `u64`).
const WIDTH: usize = 64;
/// Filter block format: Standard Ribbon, w = 64, interleaved solution.
const FORMAT_STANDARD_RIBBON_64: u8 = 1;
const HEADER_LEN: usize = 12;
/// Default fingerprint bits: FPR ≈ 2^-7 ≈ 0.8 % (spec target ≈ 1 %).
pub const DEFAULT_RESULT_BITS: u8 = 7;
/// Attempts before giving up on a filter for this SST.
const MAX_ATTEMPTS: u32 = 16;
/// Slack slots in percent of the key count for the first attempts; grows by
/// [`SLACK_STEP_PERCENT`] every [`ATTEMPTS_PER_SLACK`] failed attempts. Standard Ribbon with
/// w = 64 needs a few percent of slack for millions of keys (paper §4); 10 % makes a
/// first-attempt failure rare.
const BASE_SLACK_PERCENT: usize = 10;
const SLACK_STEP_PERCENT: usize = 5;
const ATTEMPTS_PER_SLACK: u32 = 4;

/// Filter configuration for SSTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterPolicy {
    /// No filter block.
    Disabled,
    /// Ribbon filter with the given fingerprint bits (1..=8); FPR ≈ 2^-bits.
    Ribbon {
        /// Fingerprint bits per key.
        result_bits: u8,
    },
}

impl Default for FilterPolicy {
    fn default() -> Self {
        Self::Ribbon {
            result_bits: DEFAULT_RESULT_BITS,
        }
    }
}

/// Hash of a filter key (a user-key prefix).
pub(crate) fn filter_hash(prefix: &[u8]) -> u64 {
    XxHash3_64::oneshot(prefix)
}

/// `SplitMix64` finalizer: decorrelates the values derived from one 64-bit hash.
const fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

struct Row {
    start: usize,
    coeff: u64,
    result: u8,
}

fn row(hash: u64, seed: u32, num_slots: usize, result_bits: u8) -> Row {
    let h = mix(hash ^ u64::from(seed).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let num_starts = (num_slots - WIDTH + 1) as u64;
    // Multiply-shift maps h uniformly onto 0..num_starts without division bias.
    #[allow(clippy::cast_possible_truncation)]
    let start = ((u128::from(h) * u128::from(num_starts)) >> 64) as usize;
    let coeff = mix(h ^ 0xc2b2_ae3d_27d4_eb4f) | 1;
    // Truncation intended: the top byte, masked to `result_bits`.
    #[allow(clippy::cast_possible_truncation)]
    let result = ((mix(h ^ 0x1656_67b1_9e37_79f9) >> 56) as u8) & result_mask(result_bits);
    Row {
        start,
        coeff,
        result,
    }
}

const fn result_mask(result_bits: u8) -> u8 {
    if result_bits >= 8 {
        u8::MAX
    } else {
        (1 << result_bits) - 1
    }
}

/// Collects key hashes while an SST is written and builds the filter block at the end.
pub(crate) struct RibbonBuilder {
    hashes: Vec<u64>,
    result_bits: u8,
}

impl RibbonBuilder {
    pub(crate) fn new(result_bits: u8) -> Self {
        Self {
            hashes: Vec::new(),
            result_bits: result_bits.clamp(1, 8),
        }
    }

    /// Adds a key hash; consecutive duplicates (versions of one key) are skipped.
    pub(crate) fn add_hash(&mut self, hash: u64) {
        if self.hashes.last() != Some(&hash) {
            self.hashes.push(hash);
        }
    }

    /// Encodes the filter block, or `None` if construction failed on every attempt.
    pub(crate) fn finish(&self) -> Option<Vec<u8>> {
        if self.hashes.is_empty() {
            return Some(encode(self.result_bits, 0, 0, &[]));
        }
        let n = self.hashes.len();
        for attempt in 0..MAX_ATTEMPTS {
            let slack =
                BASE_SLACK_PERCENT + SLACK_STEP_PERCENT * (attempt / ATTEMPTS_PER_SLACK) as usize;
            let num_slots = (n + n * slack / 100 + WIDTH).next_multiple_of(WIDTH);
            let Ok(slots) = u32::try_from(num_slots) else {
                return None;
            };
            if let Some(words) = self.try_build(attempt, num_slots) {
                return Some(encode(self.result_bits, attempt, slots, &words));
            }
        }
        None
    }

    fn try_build(&self, seed: u32, num_slots: usize) -> Option<Vec<u64>> {
        // Banding: coeffs[i] != 0 means slot i is the pivot of a stored row.
        let mut coeffs = vec![0u64; num_slots];
        let mut results = vec![0u8; num_slots];
        for &hash in &self.hashes {
            let Row {
                mut start,
                mut coeff,
                mut result,
            } = row(hash, seed, num_slots, self.result_bits);
            loop {
                if coeffs[start] == 0 {
                    coeffs[start] = coeff;
                    results[start] = result;
                    break;
                }
                coeff ^= coeffs[start];
                result ^= results[start];
                if coeff == 0 {
                    // Dependent row: consistent (e.g. a 64-bit hash collision) or a failure.
                    if result == 0 {
                        break;
                    }
                    return None;
                }
                // Invariant: the row still spans slots start..start+64 inside the table, because
                // shifting right never extends past its original end.
                let shift = coeff.trailing_zeros();
                start += shift as usize;
                coeff >>= shift;
            }
        }
        Some(self.back_substitute(&coeffs, &results))
    }

    /// Solves the banded system from the last slot down. `window[j]` holds the solution bits of
    /// result column j for slots i..i+64 (bit k = slot i+k); free slots (no pivot) take 0.
    fn back_substitute(&self, coeffs: &[u64], results: &[u8]) -> Vec<u64> {
        let r = usize::from(self.result_bits);
        let mut words = vec![0u64; coeffs.len() / WIDTH * r];
        let mut window = [0u64; 8];
        for i in (0..coeffs.len()).rev() {
            let (coeff, result) = (coeffs[i], results[i]);
            for (j, w) in window.iter_mut().enumerate().take(r) {
                let shifted = *w << 1;
                let bit = if coeff == 0 {
                    0
                } else {
                    // Bit 0 of `coeff` is the pivot; `shifted` has slot i (bit 0) still clear.
                    u64::from((result >> j) & 1) ^ u64::from((coeff & shifted).count_ones() & 1)
                };
                *w = shifted | bit;
                words[i / WIDTH * r + j] |= bit << (i % WIDTH);
            }
        }
        words
    }
}

fn encode(result_bits: u8, seed: u32, num_slots: u32, words: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + words.len() * 8);
    out.push(FORMAT_STANDARD_RIBBON_64);
    out.push(result_bits);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&seed.to_le_bytes());
    out.extend_from_slice(&num_slots.to_le_bytes());
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// A loaded filter.
pub(crate) struct RibbonFilter {
    result_bits: u8,
    seed: u32,
    num_slots: usize,
    words: Vec<u64>,
}

impl RibbonFilter {
    /// Decodes a filter block.
    ///
    /// # Errors
    /// [`StorageError::Corruption`] on an unknown format or inconsistent sizes.
    pub(crate) fn decode(block: &[u8]) -> Result<Self> {
        let corrupt = |what: &str| StorageError::corruption(format!("ribbon filter: {what}"));
        let mut r = Reader::new(block);
        let format = r.u8().ok_or_else(|| corrupt("truncated header"))?;
        let result_bits = r.u8().ok_or_else(|| corrupt("truncated header"))?;
        r.bytes(2).ok_or_else(|| corrupt("truncated header"))?;
        let seed = r.u32().ok_or_else(|| corrupt("truncated header"))?;
        let num_slots = r.u32().ok_or_else(|| corrupt("truncated header"))? as usize;
        if format != FORMAT_STANDARD_RIBBON_64 {
            return Err(corrupt("unknown format"));
        }
        if !(1..=8).contains(&result_bits) || !num_slots.is_multiple_of(WIDTH) {
            return Err(corrupt("bad parameters"));
        }
        let expected = num_slots / WIDTH * usize::from(result_bits);
        if r.remaining() != expected * 8 {
            return Err(corrupt("size does not match slot count"));
        }
        let mut words = Vec::with_capacity(expected);
        while let Some(w) = r.u64() {
            words.push(w);
        }
        Ok(Self {
            result_bits,
            seed,
            num_slots,
            words,
        })
    }

    /// `false` means the key is definitely absent; `true` means it may be present.
    pub(crate) fn may_contain(&self, hash: u64) -> bool {
        if self.num_slots == 0 {
            return false;
        }
        let row = row(hash, self.seed, self.num_slots, self.result_bits);
        let r = usize::from(self.result_bits);
        let (group, offset) = (row.start / WIDTH, row.start % WIDTH);
        let mut got = 0u8;
        for j in 0..r {
            let lo = self.words.get(group * r + j).copied().unwrap_or(0);
            let window = if offset == 0 {
                lo
            } else {
                let hi = self.words.get((group + 1) * r + j).copied().unwrap_or(0);
                (lo >> offset) | (hi << (WIDTH - offset))
            };
            // Truncation intended: parity is 0 or 1.
            #[allow(clippy::cast_possible_truncation)]
            let parity = ((window & row.coeff).count_ones() & 1) as u8;
            got |= parity << j;
        }
        got == row.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(keys: impl Iterator<Item = u64>, bits: u8) -> RibbonFilter {
        let mut b = RibbonBuilder::new(bits);
        for k in keys {
            b.add_hash(filter_hash(&k.to_le_bytes()));
        }
        RibbonFilter::decode(&b.finish().unwrap()).unwrap()
    }

    #[test]
    fn ribbon_has_no_false_negatives_and_fpr_near_target() {
        let n = 100_000u64;
        let filter = build(0..n, DEFAULT_RESULT_BITS);
        assert!((0..n).all(|k| filter.may_contain(filter_hash(&k.to_le_bytes()))));
        let probes = 200_000u64;
        let fp = (n..n + probes)
            .filter(|k| filter.may_contain(filter_hash(&k.to_le_bytes())))
            .count();
        // Expected 2^-7 = 0.78 %; the bounds allow statistical noise.
        #[allow(clippy::cast_precision_loss)]
        let fpr = fp as f64 / probes as f64;
        assert!((0.004..0.012).contains(&fpr), "fpr {fpr}");
        #[allow(clippy::cast_precision_loss)]
        let bits_per_key = filter.words.len() as f64 * 64.0 / n as f64;
        assert!(bits_per_key < 8.0, "bits/key {bits_per_key}");
    }

    #[test]
    fn ribbon_handles_tiny_and_empty_sets_and_duplicates() {
        let empty = build(std::iter::empty(), 7);
        assert!(!empty.may_contain(filter_hash(b"x")));
        for n in [1u64, 2, 63, 64, 65, 500] {
            let f = build((0..n).chain(0..n), 7);
            assert!((0..n).all(|k| f.may_contain(filter_hash(&k.to_le_bytes()))));
        }
        let one_bit = build(0..1000, 1);
        assert!((0..1000u64).all(|k| one_bit.may_contain(filter_hash(&k.to_le_bytes()))));
    }

    #[test]
    fn ribbon_decode_rejects_inconsistent_blocks() {
        let mut b = RibbonBuilder::new(7);
        b.add_hash(1);
        let good = b.finish().unwrap();
        assert!(RibbonFilter::decode(&good).is_ok());
        assert!(RibbonFilter::decode(&good[..good.len() - 1]).is_err());
        let mut bad_format = good.clone();
        bad_format[0] = 9;
        assert!(RibbonFilter::decode(&bad_format).is_err());
        let mut bad_bits = good;
        bad_bits[1] = 0;
        assert!(RibbonFilter::decode(&bad_bits).is_err());
    }
}
