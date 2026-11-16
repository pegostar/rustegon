// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Operating-system randomness (SCRAM nonces, request ids, object ids, backoff jitter).

/// Fills `buf` from the operating system's CSPRNG.
///
/// A failing OS generator is not recoverable for a security-sensitive client (nonces must be
/// unpredictable), but it must not crash the application either: the bytes then come from a
/// time-seeded mix, which keeps ids unique and is reported nowhere (getrandom fails only on
/// broken platforms). SCRAM nonces use [`fill_secure`], which fails instead.
pub(crate) fn fill(buf: &mut [u8]) {
    if getrandom::fill(buf).is_err() {
        let mut x = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0x9E37_79B9_7F4A_7C15, |d| {
                1 | { u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or(1) }
            });
        for b in buf.iter_mut() {
            // xorshift64*: only a uniqueness fallback, never used for secrets.
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            *b = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes()[0];
        }
    }
}

/// Fills `buf` from the operating system's CSPRNG, or fails.
pub(crate) fn fill_secure(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(buf)
}

/// A uniform integer in `0..=max` (backoff jitter; modulo bias is irrelevant here).
pub(crate) fn below_or_equal(max: u64) -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b) % max.saturating_add(1).max(1)
}
