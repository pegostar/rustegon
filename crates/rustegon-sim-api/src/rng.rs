// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Randomness source.

/// Source of random bytes. Production output is cryptographically secure; simulation output is
/// seeded and reproducible.
pub trait Rng: Send + Sync + 'static {
    /// Fills `buf` with random bytes.
    fn fill_bytes(&self, buf: &mut [u8]);

    /// Returns a random `u64`.
    fn next_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
}

/// Production RNG: the operating system CSPRNG (`getrandom`).
///
/// Each call is a syscall-level request; hot paths that need many non-cryptographic numbers
/// should seed their own fast PRNG from this source.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        if getrandom::fill(buf).is_err() {
            // Without OS entropy, nonces and keys could repeat. Continuing would silently weaken
            // encryption and authentication, so abort instead (same policy as `ring`).
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_rng_fills_whole_buffer() {
        let mut buf = [0u8; 64];
        OsRng.fill_bytes(&mut buf);
        // 64 zero bytes from a CSPRNG has probability 2^-512.
        assert!(buf.iter().any(|b| *b != 0));
    }

    #[test]
    fn os_rng_values_differ() {
        assert_ne!(OsRng.next_u64(), OsRng.next_u64());
    }
}
