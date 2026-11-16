// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Key-value blocks with prefix-compressed keys (storage-engine.md §4).
//!
//! Layout:
//! ```text
//! entry*  restart[num_restarts] (u32 LE offsets)  num_restarts (u32 LE)
//! entry = shared (varint) ‖ non_shared (varint) ‖ value_len (varint) ‖ key_delta ‖ value
//! ```
//! Each key stores only the suffix that differs from the previous key; every
//! `restart_interval`-th entry is a *restart point* storing its full key (`shared = 0`), so a seek
//! binary-searches the restart array and then scans at most one interval linearly. Data blocks
//! use an interval of 16, index blocks 1 (every entry is binary-searchable).

use std::{cmp::Ordering, ops::Range};

use bytes::Bytes;

use crate::{
    coding::{Reader, put_varint, u32_at},
    error::{Result, StorageError},
    key::compare_internal,
};

/// Size of one restart offset and of the trailing restart count.
const U32_LEN: usize = 4;

/// How keys inside a block are ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyOrder {
    /// Encoded internal keys (data and index blocks).
    Internal,
    /// Plain bytewise order (metaindex and properties blocks).
    Bytewise,
}

impl KeyOrder {
    pub(crate) fn compare(self, a: &[u8], b: &[u8]) -> Ordering {
        match self {
            Self::Internal => compare_internal(a, b),
            Self::Bytewise => a.cmp(b),
        }
    }
}

/// Builds one block in memory.
pub(crate) struct BlockBuilder {
    buf: Vec<u8>,
    restarts: Vec<u32>,
    restart_interval: usize,
    since_restart: usize,
    last_key: Vec<u8>,
}

impl BlockBuilder {
    pub(crate) fn new(restart_interval: usize) -> Self {
        Self {
            buf: Vec::new(),
            restarts: Vec::new(),
            restart_interval: restart_interval.max(1),
            since_restart: 0,
            last_key: Vec::new(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.restarts.is_empty()
    }

    /// Size of the block if finished now.
    pub(crate) fn estimated_size(&self) -> usize {
        self.buf.len() + (self.restarts.len() + 1) * U32_LEN
    }

    pub(crate) fn last_key(&self) -> &[u8] {
        &self.last_key
    }

    /// Appends an entry. Keys must be added in the block's order (checked by the SST writer).
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] if the block would exceed the 4 GiB offset range.
    pub(crate) fn add(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let shared = if self.is_empty() || self.since_restart >= self.restart_interval {
            let offset = u32::try_from(self.buf.len())
                .map_err(|_| StorageError::InvalidArgument("block exceeds 4 GiB".into()))?;
            self.restarts.push(offset);
            self.since_restart = 0;
            0
        } else {
            self.last_key
                .iter()
                .zip(key)
                .take_while(|(a, b)| a == b)
                .count()
        };
        put_varint(&mut self.buf, shared as u64);
        put_varint(&mut self.buf, (key.len() - shared) as u64);
        put_varint(&mut self.buf, value.len() as u64);
        self.buf.extend_from_slice(&key[shared..]);
        self.buf.extend_from_slice(value);
        self.last_key.truncate(shared);
        self.last_key.extend_from_slice(&key[shared..]);
        self.since_restart += 1;
        Ok(())
    }

    /// Returns the encoded block and resets the builder for reuse.
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.buf);
        for r in &self.restarts {
            out.extend_from_slice(&r.to_le_bytes());
        }
        // Lossless: restart offsets are u32 and strictly increasing, so their count fits too.
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(self.restarts.len() as u32).to_le_bytes());
        self.restarts.clear();
        self.since_restart = 0;
        self.last_key.clear();
        out
    }
}

/// A decoded, validated block. Cloning is cheap (reference-counted bytes).
#[derive(Clone)]
pub(crate) struct Block {
    data: Bytes,
    restarts_offset: usize,
    num_restarts: usize,
}

impl Block {
    /// Validates the restart array; entries are validated lazily while iterating.
    ///
    /// # Errors
    /// [`StorageError::Corruption`] if the restart array is malformed.
    pub(crate) fn new(data: Bytes) -> Result<Self> {
        let bad = |what: &str| StorageError::corruption(format!("block: {what}"));
        let count_at = data
            .len()
            .checked_sub(U32_LEN)
            .ok_or_else(|| bad("too short"))?;
        let num_restarts = u32_at(&data, count_at).ok_or_else(|| bad("too short"))? as usize;
        let restarts_offset = num_restarts
            .checked_mul(U32_LEN)
            .and_then(|n| count_at.checked_sub(n))
            .ok_or_else(|| bad("restart count exceeds block"))?;
        let block = Self {
            data,
            restarts_offset,
            num_restarts,
        };
        if (num_restarts == 0) != (restarts_offset == 0) {
            return Err(bad("restart count inconsistent with entries"));
        }
        let mut previous = None;
        for i in 0..num_restarts {
            let point = block.restart_point(i);
            let ordered = previous.is_none_or(|p| point > p);
            if point >= restarts_offset || !ordered || (i == 0 && point != 0) {
                return Err(bad("restart point out of order or range"));
            }
            previous = Some(point);
        }
        Ok(block)
    }

    /// Decoded size in bytes (the block cache charge).
    pub(crate) fn size(&self) -> usize {
        self.data.len()
    }

    fn restart_point(&self, index: usize) -> usize {
        // In bounds: validated in `new`.
        u32_at(&self.data, self.restarts_offset + index * U32_LEN).unwrap_or(0) as usize
    }

    pub(crate) fn cursor(&self, order: KeyOrder) -> BlockIter {
        BlockIter {
            block: self.clone(),
            order,
            next_offset: self.restarts_offset,
            current: 0,
            key: Vec::new(),
            value: 0..0,
            valid: false,
        }
    }
}

/// Bidirectional iterator over a block.
pub(crate) struct BlockIter {
    block: Block,
    order: KeyOrder,
    next_offset: usize,
    /// Offset of the current entry (meaningful while valid); `prev` scans up to it.
    current: usize,
    key: Vec<u8>,
    value: Range<usize>,
    valid: bool,
}

impl BlockIter {
    pub(crate) fn valid(&self) -> bool {
        self.valid
    }

    /// Current key. Only meaningful while [`BlockIter::valid`].
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    /// Current value as a zero-copy slice of the block.
    pub(crate) fn value(&self) -> Bytes {
        self.block.data.slice(self.value.clone())
    }

    pub(crate) fn value_bytes(&self) -> &[u8] {
        &self.block.data[self.value.clone()]
    }

    pub(crate) fn seek_to_first(&mut self) -> Result<()> {
        self.reset_to_restart(0);
        self.parse_next()
    }

    pub(crate) fn next(&mut self) -> Result<()> {
        self.parse_next()
    }

    /// Positions at the first entry with key >= `target`, or invalid if none.
    pub(crate) fn seek(&mut self, target: &[u8]) -> Result<()> {
        if self.block.num_restarts == 0 {
            self.valid = false;
            return Ok(());
        }
        // Binary search for the last restart point whose key is < target; if none, the scan from
        // restart 0 stops at its first entry.
        let (mut lo, mut hi) = (0, self.block.num_restarts - 1);
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            self.reset_to_restart(mid);
            self.parse_next()?;
            if self.order.compare(&self.key, target) == Ordering::Less {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        self.reset_to_restart(lo);
        loop {
            self.parse_next()?;
            if !self.valid || self.order.compare(&self.key, target) != Ordering::Less {
                return Ok(());
            }
        }
    }

    /// Positions at the last entry, or invalid for an empty block.
    pub(crate) fn seek_to_last(&mut self) -> Result<()> {
        let Some(last) = self.block.num_restarts.checked_sub(1) else {
            self.valid = false;
            return Ok(());
        };
        self.reset_to_restart(last);
        self.parse_next()?;
        while self.valid && self.next_offset < self.block.restarts_offset {
            self.parse_next()?;
        }
        Ok(())
    }

    /// Steps to the previous entry; invalid before the first one, no-op when invalid.
    ///
    /// Keys are prefix-compressed against their predecessor, so an entry can only be decoded by
    /// scanning forward from a restart point: find the last restart point before the current
    /// entry and scan until the entry that ends where the current one starts (`LevelDB`'s
    /// approach; at most one restart interval of entries is decoded).
    pub(crate) fn prev(&mut self) -> Result<()> {
        if !self.valid {
            return Ok(());
        }
        let target = self.current;
        // Number of restart points strictly before the current entry (restart 0 is offset 0).
        let (mut lo, mut hi) = (0, self.block.num_restarts);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.block.restart_point(mid) < target {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let Some(restart) = lo.checked_sub(1) else {
            // The current entry is the first one.
            self.valid = false;
            return Ok(());
        };
        self.reset_to_restart(restart);
        loop {
            self.parse_next()?;
            if !self.valid || self.next_offset > target {
                self.valid = false;
                return Err(StorageError::corruption("block: entries overlap"));
            }
            if self.next_offset == target {
                return Ok(());
            }
        }
    }

    fn reset_to_restart(&mut self, index: usize) {
        self.key.clear();
        self.next_offset = self.block.restart_point(index);
        self.valid = false;
    }

    /// Decodes the entry at `next_offset`, or becomes invalid at the end of the entries.
    fn parse_next(&mut self) -> Result<()> {
        let end = self.block.restarts_offset;
        if self.next_offset >= end {
            self.valid = false;
            return Ok(());
        }
        // Any malformed field leaves the iterator invalid and reports corruption.
        self.valid = false;
        let corrupt = || StorageError::corruption("block: malformed entry");
        let entries = &self.block.data[self.next_offset..end];
        let mut r = Reader::new(entries);
        let mut field = || {
            r.varint()
                .and_then(|v| usize::try_from(v).ok())
                .ok_or_else(corrupt)
        };
        let (shared, non_shared, value_len) = (field()?, field()?, field()?);
        let header_len = entries.len() - r.remaining();
        if shared > self.key.len() {
            return Err(corrupt());
        }
        self.current = self.next_offset;
        let delta = r.bytes(non_shared).ok_or_else(corrupt)?;
        r.bytes(value_len).ok_or_else(corrupt)?;
        self.key.truncate(shared);
        self.key.extend_from_slice(delta);
        let value_start = self.next_offset + header_len + non_shared;
        self.value = value_start..value_start + value_len;
        self.next_offset = self.value.end;
        self.valid = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::key::{InternalKey, ValueKind, seek_key};

    fn build(entries: &[(Vec<u8>, Vec<u8>)], interval: usize) -> Block {
        let mut b = BlockBuilder::new(interval);
        for (k, v) in entries {
            b.add(k, v).unwrap();
        }
        Block::new(Bytes::from(b.finish())).unwrap()
    }

    fn collect(block: &Block, order: KeyOrder) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut it = block.cursor(order);
        it.seek_to_first().unwrap();
        let mut out = Vec::new();
        while it.valid() {
            out.push((it.key().to_vec(), it.value().to_vec()));
            it.next().unwrap();
        }
        out
    }

    proptest! {
        #[test]
        fn block_round_trips_and_seeks(
            keys in prop::collection::btree_set(prop::collection::vec(0u8..4, 0..12), 0..200),
            interval in 1usize..20,
            probe in prop::collection::vec(0u8..4, 0..12),
        ) {
            let entries: Vec<_> = keys.iter().map(|k| (k.clone(), k.repeat(2))).collect();
            let block = build(&entries, interval);
            prop_assert_eq!(collect(&block, KeyOrder::Bytewise), entries);
            let mut it = block.cursor(KeyOrder::Bytewise);
            it.seek(&probe).unwrap();
            let expected = keys.range(probe.clone()..).next();
            let got = it.valid().then(|| it.key().to_vec());
            prop_assert_eq!(got.as_ref(), expected);
        }

        /// Reverse iteration yields the entries backwards, and `prev`/`next` interleave
        /// consistently from any seek position.
        #[test]
        fn block_reverse_and_mixed_direction(
            keys in prop::collection::btree_set(prop::collection::vec(0u8..4, 0..12), 0..200),
            interval in 1usize..20,
            probe in prop::collection::vec(0u8..4, 0..12),
            moves in prop::collection::vec(any::<bool>(), 0..40),
        ) {
            let entries: Vec<_> = keys.iter().map(|k| (k.clone(), k.repeat(2))).collect();
            let block = build(&entries, interval);
            let mut it = block.cursor(KeyOrder::Bytewise);
            it.seek_to_last().unwrap();
            let mut backwards = Vec::new();
            while it.valid() {
                backwards.push((it.key().to_vec(), it.value().to_vec()));
                it.prev().unwrap();
            }
            backwards.reverse();
            prop_assert_eq!(&backwards, &entries);

            let keys: Vec<_> = keys.into_iter().collect();
            let mut pos = keys.partition_point(|k| *k < probe);
            it.seek(&probe).unwrap();
            for forward in moves {
                if pos >= keys.len() {
                    prop_assert!(!it.valid());
                    break;
                }
                prop_assert_eq!(it.key(), keys[pos].as_slice());
                if forward {
                    it.next().unwrap();
                    pos += 1;
                } else if pos == 0 {
                    it.prev().unwrap();
                    prop_assert!(!it.valid());
                    break;
                } else {
                    it.prev().unwrap();
                    pos -= 1;
                }
            }
        }
    }

    #[test]
    fn block_seek_uses_internal_order() {
        let keys = [
            InternalKey::new(b"a", 7, ValueKind::Put),
            InternalKey::new(b"a", 3, ValueKind::Delete),
            InternalKey::new(b"b", 9, ValueKind::Put),
        ];
        let entries: Vec<_> = keys
            .iter()
            .map(|k| (k.as_bytes().to_vec(), vec![]))
            .collect();
        let block = build(&entries, 1);
        let mut it = block.cursor(KeyOrder::Internal);
        it.seek(&seek_key(b"a", 5)).unwrap();
        assert_eq!(it.key(), keys[1].as_bytes());
        it.seek(&seek_key(b"a", 2)).unwrap();
        assert_eq!(it.key(), keys[2].as_bytes());
    }

    #[test]
    fn empty_block_has_no_entries() {
        let block = build(&[], 16);
        let mut it = block.cursor(KeyOrder::Bytewise);
        it.seek_to_first().unwrap();
        assert!(!it.valid());
        it.seek(b"x").unwrap();
        assert!(!it.valid());
    }

    #[test]
    fn malformed_blocks_are_corruption_not_panics() {
        let good = {
            let mut b = BlockBuilder::new(2);
            for k in [b"aa", b"ab", b"ba"] {
                b.add(k, b"value").unwrap();
            }
            b.finish()
        };
        assert!(Block::new(Bytes::from_static(b"\x01")).is_err());
        let mut huge = good.clone();
        let n = huge.len();
        huge[n - 4..].copy_from_slice(&1000u32.to_le_bytes());
        assert!(Block::new(Bytes::from(huge)).is_err());
        // Every single-bit corruption either fails validation, fails iteration, or decodes to
        // something; it must never panic.
        for at in 0..good.len() {
            for bit in 0..8 {
                let mut bad = good.clone();
                bad[at] ^= 1 << bit;
                if let Ok(block) = Block::new(Bytes::from(bad)) {
                    let mut it = block.cursor(KeyOrder::Bytewise);
                    let _ = it.seek(b"ab");
                    let mut it = block.cursor(KeyOrder::Bytewise);
                    if it.seek_to_first().is_ok() {
                        while it.valid() && it.next().is_ok() {}
                    }
                    let mut it = block.cursor(KeyOrder::Bytewise);
                    if it.seek_to_last().is_ok() {
                        while it.valid() && it.prev().is_ok() {}
                    }
                }
            }
        }
    }
}
