// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Seeded generator of the test kit: `SplitMix64` (Steele, Lea, Flood 2014), the convention of
//! the simulation workloads (`rustegon-sim` `workload::rng`). Self-contained so that a failing
//! case is reproduced from its seed alone, on any platform.

/// Golden-ratio increment of `SplitMix64`.
const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// `SplitMix64` finalizer; also derives independent per-case seeds from a base seed.
#[must_use]
pub fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A deterministic random stream.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A stream starting at `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(GAMMA);
        mix(self.0)
    }

    /// Uniform in `0..n` (`0` when `n == 0`); the modulo bias is irrelevant for test data.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        let n64 = u64::try_from(n).unwrap_or(u64::MAX);
        usize::try_from(self.next_u64() % n64).unwrap_or(0)
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
        let span = usize::try_from(hi.saturating_sub(lo))
            .unwrap_or(0)
            .saturating_add(1);
        lo.saturating_add(i64::try_from(self.below(span)).unwrap_or(0))
    }

    /// `true` with probability `percent` / 100.
    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    /// A uniformly chosen element (`items` must not be empty; the first element otherwise).
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let i = self.below(items.len());
        &items[i.min(items.len().saturating_sub(1))]
    }
}
