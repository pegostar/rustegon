// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Seeded random numbers for workloads: one `SplitMix64` stream per purpose (driver decisions,
//! the coordinator's transaction ids and priority bits), so a seed fixes every choice.

use std::sync::atomic::{AtomicU64, Ordering};

use rustegon_sim_api::Rng;

/// Golden-ratio increment of `SplitMix64` (Steele, Lea, Flood 2014).
const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// `SplitMix64` generator. The state only ever advances by the golden-ratio gamma, so an atomic
/// `fetch_add` is the whole update: the generator is `Sync` without a lock, as
/// [`Rng`] requires. `Relaxed` suffices: each draw needs a unique state value, not ordering
/// with other memory (and the workloads draw from one thread anyway).
#[derive(Debug)]
pub struct SimRng {
    state: AtomicU64,
}

impl SimRng {
    /// A generator seeded with `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: AtomicU64::new(seed),
        }
    }

    /// The next 64 random bits.
    pub fn next(&self) -> u64 {
        let s = self
            .state
            .fetch_add(GAMMA, Ordering::Relaxed)
            .wrapping_add(GAMMA);
        mix(s)
    }

    /// A value in `0..n` (`n = 0` yields 0). The modulo bias is irrelevant for workload spread.
    pub fn below(&self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }

    /// `true` with probability `per_mille / 1000`.
    pub fn chance(&self, per_mille: u64) -> bool {
        self.below(1000) < per_mille
    }

    /// A uniformly chosen index into a slice of length `len` (`len > 0`).
    pub fn index(&self, len: usize) -> usize {
        // usize -> u64 is lossless on every supported target; the result is < len.
        usize::try_from(self.below(len as u64)).unwrap_or(0)
    }
}

impl Rng for SimRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// The `SplitMix64` finalizer; also used to derive independent sub-seeds from one seed.
#[must_use]
pub fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_rng_same_seed_same_stream() {
        let (a, b) = (SimRng::new(42), SimRng::new(42));
        for _ in 0..100 {
            assert_eq!(a.next(), b.next());
        }
        assert_ne!(SimRng::new(1).next(), SimRng::new(2).next());
    }

    #[test]
    fn sim_rng_below_stays_in_range() {
        let r = SimRng::new(7);
        for n in 1..50 {
            assert!(r.below(n) < n);
        }
        assert_eq!(r.below(0), 0);
    }
}
