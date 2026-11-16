// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Integer encodings shared by the persisted formats: LEB128 varints and fixed-width little-endian
//! integers. Decoders never panic on malformed input; they return `None` and the caller reports
//! corruption with context.

/// Maximum encoded length of a `u64` varint.
pub(crate) const MAX_VARINT_LEN: usize = 10;

/// Appends `v` as an unsigned LEB128 varint.
pub(crate) fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        // Truncation intended: the low 7 bits plus the continuation flag.
        #[allow(clippy::cast_possible_truncation)]
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    #[allow(clippy::cast_possible_truncation)]
    buf.push(v as u8);
}

/// Decodes a varint from the front of `input`; returns the value and the bytes consumed.
/// `None` on truncated input or values exceeding 64 bits.
pub(crate) fn get_varint(input: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &byte) in input.iter().enumerate().take(MAX_VARINT_LEN) {
        let bits = u64::from(byte & 0x7f);
        // The 10th byte may only contribute the single remaining bit.
        if i == MAX_VARINT_LEN - 1 && bits > 1 {
            return None;
        }
        value |= bits << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Cursor over a byte slice for sequential decoding.
pub(crate) struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    /// Bytes not consumed yet.
    pub(crate) fn remaining(&self) -> usize {
        self.input.len()
    }

    pub(crate) fn varint(&mut self) -> Option<u64> {
        let (v, n) = get_varint(self.input)?;
        self.input = &self.input[n..];
        Some(v)
    }

    /// Like [`Reader::varint`] but also `None` for an over-long encoding (a multi-byte varint whose
    /// last byte is zero, e.g. `0x80 0x00` for 0). Formats that must be canonical (one value, one
    /// byte string) use this; other callers keep the lenient decoder.
    pub(crate) fn canonical_varint(&mut self) -> Option<u64> {
        let (v, n) = get_varint(self.input)?;
        if n > 1 && self.input[n - 1] == 0 {
            return None;
        }
        self.input = &self.input[n..];
        Some(v)
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if len > self.input.len() {
            return None;
        }
        let (head, tail) = self.input.split_at(len);
        self.input = tail;
        Some(head)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.bytes(N)?.try_into().ok()
    }
}

/// Reads a little-endian `u32` at `at`; `None` if out of bounds.
pub(crate) fn u32_at(input: &[u8], at: usize) -> Option<u32> {
    let bytes = input.get(at..at.checked_add(4)?)?;
    bytes.try_into().ok().map(u32::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn varint_round_trips(v in any::<u64>()) {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            prop_assert!(buf.len() <= MAX_VARINT_LEN);
            prop_assert_eq!(get_varint(&buf), Some((v, buf.len())));
            // Every strict prefix is truncated input.
            for cut in 0..buf.len() {
                prop_assert_eq!(get_varint(&buf[..cut]), None);
            }
            prop_assert_eq!(Reader::new(&buf).canonical_varint(), Some(v));
        }

        #[test]
        fn canonical_varint_rejects_over_long_encodings(v in 0u64..(1 << 56)) {
            // Pad with a continuation byte + trailing zero: same value, one byte longer.
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let last = buf.len() - 1;
            buf[last] |= 0x80;
            buf.push(0);
            prop_assert_eq!(Reader::new(&buf).varint(), Some(v));
            prop_assert_eq!(Reader::new(&buf).canonical_varint(), None);
        }
    }

    #[test]
    fn varint_rejects_overflow() {
        let too_big = [0xff; 9].into_iter().chain([0x02]).collect::<Vec<_>>();
        assert_eq!(get_varint(&too_big), None);
        assert_eq!(get_varint(&[0x80; 11]), None);
    }

    #[test]
    fn reader_decodes_sequence_and_stops_at_end() {
        let mut buf = vec![7u8];
        buf.extend_from_slice(&0xdead_beef_u32.to_le_bytes());
        buf.extend_from_slice(&42u64.to_le_bytes());
        put_varint(&mut buf, 300);
        buf.extend_from_slice(b"xy");
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8(), Some(7));
        assert_eq!(r.u32(), Some(0xdead_beef));
        assert_eq!(r.u64(), Some(42));
        assert_eq!(r.varint(), Some(300));
        assert_eq!(r.bytes(3), None);
        assert_eq!(r.bytes(2), Some(&b"xy"[..]));
        assert!(r.is_empty());
        assert_eq!(u32_at(&buf, buf.len() - 3), None);
    }
}
