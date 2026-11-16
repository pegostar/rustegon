// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `objectId` values and their generator (data-model.md §2 type 0x0A).
//!
//! Layout (12 bytes, big endian so ids sort by creation second): 4 B Unix seconds, 5 B random
//! value chosen once per generator, 3 B counter starting at a random value.

use std::{
    fmt,
    sync::atomic::{AtomicU32, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::codec::error::{DocError, DocResult};

/// Mask of the 3-byte counter.
const COUNTER_MASK: u32 = 0x00FF_FFFF;

/// A 12-byte object identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub [u8; 12]);

impl ObjectId {
    /// A new id from the process-wide generator.
    #[must_use]
    pub fn new() -> Self {
        static GENERATOR: std::sync::OnceLock<ObjectIdGenerator> = std::sync::OnceLock::new();
        GENERATOR.get_or_init(ObjectIdGenerator::new).generate()
    }

    /// The creation time in Unix seconds (first 4 bytes).
    #[must_use]
    pub fn seconds(&self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// Parses 24 hexadecimal digits (either case).
    ///
    /// # Errors
    /// [`DocError::Malformed`] if `s` is not exactly 24 hex digits.
    pub fn parse_hex(s: &str) -> DocResult<Self> {
        let mut out = [0u8; 12];
        crate::codec::hex::decode_into(s, &mut out)
            .ok_or_else(|| DocError::malformed(0, "objectId must be 24 hex digits"))?;
        Ok(Self(out))
    }
}

impl Default for ObjectId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ObjectId {
    /// 24 lowercase hex digits.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::codec::hex::encode(&self.0))
    }
}

/// Generates unique [`ObjectId`]s (the driver assigns `_id` to inserted documents without one,
/// so a retried insert carries the same id).
struct ObjectIdGenerator {
    process: [u8; 5],
    // Relaxed suffices: uniqueness only needs each fetch_add to return a distinct value.
    counter: AtomicU32,
}

impl ObjectIdGenerator {
    fn new() -> Self {
        let mut seed = [0u8; 8];
        crate::random::fill(&mut seed);
        Self {
            process: [seed[0], seed[1], seed[2], seed[3], seed[4]],
            counter: AtomicU32::new(u32::from_le_bytes([seed[5], seed[6], seed[7], 0])),
        }
    }

    fn generate(&self) -> ObjectId {
        // Seconds wrap modulo 2^32 and clamp to 0 before the epoch: a uniqueness aid only.
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let secs = u32::try_from(secs & u64::from(u32::MAX)).unwrap_or(0);
        let count = self.counter.fetch_add(1, Ordering::Relaxed) & COUNTER_MASK;
        let mut id = [0u8; 12];
        id[..4].copy_from_slice(&secs.to_be_bytes());
        id[4..9].copy_from_slice(&self.process);
        id[9..].copy_from_slice(&count.to_be_bytes()[1..]);
        ObjectId(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_id_hex_round_trip() {
        let id = ObjectId([0xAB; 12]);
        let s = id.to_string();
        assert_eq!(s, "abababababababababababab");
        assert_eq!(ObjectId::parse_hex(&s.to_uppercase()).unwrap(), id);
        assert!(ObjectId::parse_hex("abc").is_err());
        assert!(ObjectId::parse_hex("zzababababababababababab").is_err());
    }

    #[test]
    fn generated_ids_are_unique() {
        assert_ne!(ObjectId::new(), ObjectId::new());
    }
}
