// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Hexadecimal and base64 helpers for the JSON forms (internal).

const HEX: &[u8; 16] = b"0123456789abcdef";
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Lowercase hex of `bytes`.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0F)]));
    }
    s
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes exactly `2 × out.len()` hex digits (either case) into `out`.
pub(crate) fn decode_into(s: &str, out: &mut [u8]) -> Option<()> {
    let b = s.as_bytes();
    if b.len() != out.len() * 2 {
        return None;
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nibble(b[2 * i])? << 4) | nibble(b[2 * i + 1])?;
    }
    Some(())
}

/// Standard base64 with padding (RFC 4648 §4).
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                s.push(char::from(B64[((n >> shift) & 0x3F) as usize]));
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn b64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict standard base64 decode: padding required, no whitespace, unused bits must be zero (so
/// every byte string has exactly one accepted text form).
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let quads = b.len() / 4;
    for (qi, q) in b.chunks(4).enumerate() {
        let pad = q.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && qi + 1 != quads) {
            return None;
        }
        let mut n = 0u32;
        for c in &q[..4 - pad] {
            n = (n << 6) | b64_value(*c)?;
        }
        n <<= 6 * u32::try_from(pad).ok()?;
        let bytes = n.to_be_bytes();
        let keep = 3 - pad;
        // Bits beyond the kept bytes must be zero (canonical form).
        if bytes[1 + keep..].iter().any(|x| *x != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[1..=keep]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(raw.as_bytes()), enc);
            assert_eq!(base64_decode(enc).unwrap(), raw.as_bytes());
        }
        assert!(base64_decode("Zh==").is_none()); // non-zero unused bits
        assert!(base64_decode("Zg=").is_none());
        assert!(base64_decode("Zg==Zg==").is_none());
        assert!(base64_decode("Z===").is_none());
    }
}
