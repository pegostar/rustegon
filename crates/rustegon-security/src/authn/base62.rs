// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Base62 (`0-9A-Za-z`) for API keys and generated passwords.
//!
//! A 32-byte secret is the big-endian number it spells, written in exactly
//! [`SECRET_CHARS`] digits (left-padded with `'0'`): 62^43 > 2^256 > 62^42, so 43 digits are
//! the minimum that hold every value, and a fixed width makes the string length part of the
//! format check. Base62 instead of base64url keeps the key free of `_` (the field separator of
//! `rgn_<key_id>_<secret>`) and of `-`, so a key is one "word" for double-click selection.

use rustegon_sim_api::Rng;
use zeroize::Zeroize;

/// The alphabet, in digit order.
pub(crate) const ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// Digits of an encoded 32-byte secret.
pub(crate) const SECRET_CHARS: usize = 43;

fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'Z' => Some(c - b'A' + 10),
        b'a'..=b'z' => Some(c - b'a' + 36),
        _ => None,
    }
}

/// Encodes `bytes` (big-endian number) in exactly [`SECRET_CHARS`] digits.
pub(crate) fn encode_secret(bytes: &[u8; 32]) -> String {
    // Schoolbook long division by 62; the working copy is wiped because it is the secret.
    let mut num = *bytes;
    let mut digits = [0u8; SECRET_CHARS];
    for slot in digits.iter_mut().rev() {
        let mut rem: u32 = 0;
        for b in &mut num {
            let cur = (rem << 8) | u32::from(*b);
            // cur < 62 * 256, so the quotient fits in a byte.
            *b = u8::try_from(cur / 62).unwrap_or(0);
            rem = cur % 62;
        }
        *slot = ALPHABET[rem as usize];
    }
    num.zeroize();
    let s = digits.iter().map(|d| char::from(*d)).collect();
    digits.zeroize();
    s
}

/// Decodes a [`SECRET_CHARS`]-digit string back into 32 bytes; `None` for a wrong length, a
/// character outside the alphabet or a value ≥ 2^256.
pub(crate) fn decode_secret(s: &str) -> Option<[u8; 32]> {
    if s.len() != SECRET_CHARS {
        return None;
    }
    let mut num = [0u8; 32];
    for c in s.bytes() {
        let Some(d) = digit(c) else {
            num.zeroize();
            return None;
        };
        // num = num * 62 + d, from the least significant byte; a carry out of the top byte
        // means the value does not fit in 256 bits.
        let mut carry = u32::from(d);
        for b in num.iter_mut().rev() {
            let cur = u32::from(*b) * 62 + carry;
            *b = (cur & 0xFF) as u8;
            carry = cur >> 8;
        }
        if carry != 0 {
            num.zeroize();
            return None;
        }
    }
    Some(num)
}

/// A uniformly random string of `len` characters of `alphabet` (≤ 256 symbols), by rejection
/// sampling so that no symbol is more likely than another (a plain `byte % n` would bias the
/// first `256 % n` symbols).
pub(crate) fn random_string(rng: &dyn Rng, alphabet: &[u8], len: usize) -> String {
    let n = alphabet.len();
    debug_assert!(n > 0 && n <= 256);
    // Largest multiple of n not above 256: bytes at or above it are rejected.
    let limit = 256 - (256 % n);
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        rng.fill_bytes(&mut buf);
        for &b in &buf {
            if usize::from(b) < limit && out.len() < len {
                out.push(char::from(alphabet[usize::from(b) % n]));
            }
        }
    }
    buf.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_extremes_and_random() {
        for bytes in [[0u8; 32], [0xFF; 32], {
            let mut b = [0u8; 32];
            b[31] = 61;
            b
        }] {
            let s = encode_secret(&bytes);
            assert_eq!(s.len(), SECRET_CHARS);
            assert_eq!(decode_secret(&s), Some(bytes));
        }
        assert_eq!(encode_secret(&[0u8; 32]), "0".repeat(43));
        let mut b = [0u8; 32];
        b[31] = 61;
        assert!(encode_secret(&b).ends_with('z'));
        for seed in 0u8..50 {
            let bytes: [u8; 32] = std::array::from_fn(|i| {
                seed.wrapping_mul(31)
                    .wrapping_add(u8::try_from(i).unwrap() * 7)
            });
            assert_eq!(decode_secret(&encode_secret(&bytes)), Some(bytes));
        }
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert_eq!(decode_secret("abc"), None);
        assert_eq!(decode_secret(&"_".repeat(43)), None);
        // 'z'*43 = 62^43 - 1 > 2^256 - 1.
        assert_eq!(decode_secret(&"z".repeat(43)), None);
    }

    #[test]
    fn random_string_uses_alphabet() {
        let s = random_string(&rustegon_sim_api::OsRng, ALPHABET, 100);
        assert_eq!(s.len(), 100);
        assert!(s.bytes().all(|c| ALPHABET.contains(&c)));
    }
}
