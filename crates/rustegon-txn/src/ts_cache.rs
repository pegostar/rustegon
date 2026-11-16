// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The range-local timestamp cache (transaction-management.md §3, §4.1): for every key span
//! read, the highest read timestamp and the reader. A write to key *k* must be at a timestamp
//! above `TsCache(k)` unless that read was the writer's own — this is what keeps writers from
//! slipping under committed reads (SERIALIZABLE, and linearizable single-key operations under
//! SNAPSHOT).
//!
//! # Structure
//! Point reads and span reads are kept in two ordered maps; a lookup takes the maximum of the
//! overlapping entries and the **low-water mark**, which stands for every read the cache does
//! not remember: reads before the cache existed (the coordinator starts it at the HLC's current
//! time, §8: on a lease transfer, the transfer timestamp) and evicted entries.
//!
//! # Memory bound
//! When the cache holds more than `capacity` entries it evicts the oldest half and raises the
//! low-water mark to the newest evicted timestamp. That only over-approximates the reads seen
//! (writers get pushed more often, never less), so eviction is always safe.
//!
//! Not synchronised: the coordinator keeps it behind a mutex that is a leaf of its lock order.

use std::collections::BTreeMap;

use rustegon_mvcc::{Timestamp, TxnId};

/// The maximum read timestamp over a span and who read at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheEntry {
    /// Highest read timestamp.
    pub ts: Timestamp,
    /// The reader at `ts`; `None` when unknown (low-water mark, several readers at `ts`, or a
    /// non-transactional read).
    pub txn: Option<TxnId>,
}

impl CacheEntry {
    /// The entry covering both `self` and `other`.
    fn merge(self, other: Self) -> Self {
        match self.ts.cmp(&other.ts) {
            std::cmp::Ordering::Less => other,
            std::cmp::Ordering::Greater => self,
            std::cmp::Ordering::Equal if self.txn == other.txn => self,
            std::cmp::Ordering::Equal => Self {
                ts: self.ts,
                txn: None,
            },
        }
    }

    /// Whether a write by `writer` must be above this entry: always, unless the read was the
    /// writer's own (a transaction may write what it read at its own timestamp).
    #[must_use]
    pub fn blocks(&self, writer: &TxnId) -> bool {
        self.txn.as_ref() != Some(writer)
    }
}

/// The smallest key greater than `key` (`key ‖ 0x00`): `[key, successor(key))` is the point
/// span of `key`.
#[must_use]
pub fn successor(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 1);
    out.extend_from_slice(key);
    out.push(0);
    out
}

/// The timestamp cache of one range (module docs).
#[derive(Debug)]
pub struct TsCache {
    low_water: Timestamp,
    points: BTreeMap<Vec<u8>, CacheEntry>,
    /// Keyed by `(start, end)`, `start < end`.
    spans: BTreeMap<(Vec<u8>, Vec<u8>), CacheEntry>,
    capacity: usize,
}

impl TsCache {
    /// An empty cache whose low-water mark is `low_water`, evicting above `capacity` entries
    /// (at least 2).
    #[must_use]
    pub fn new(low_water: Timestamp, capacity: usize) -> Self {
        Self {
            low_water,
            points: BTreeMap::new(),
            spans: BTreeMap::new(),
            capacity: capacity.max(2),
        }
    }

    /// The low-water mark.
    #[must_use]
    pub fn low_water(&self) -> Timestamp {
        self.low_water
    }

    /// Raises the low-water mark to `ts` (never lowers it): e.g. on a lease transfer (§8).
    pub fn raise_low_water(&mut self, ts: Timestamp) {
        self.low_water = self.low_water.max(ts);
    }

    /// Number of remembered entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.points.len() + self.spans.len()
    }

    /// Whether no entry is remembered (lookups return the low-water mark).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Records a read of `key` at `ts` by `txn`.
    pub fn record_point(&mut self, key: &[u8], ts: Timestamp, txn: Option<TxnId>) {
        let entry = CacheEntry { ts, txn };
        match self.points.get_mut(key) {
            Some(e) => *e = e.merge(entry),
            None => {
                self.points.insert(key.to_vec(), entry);
            }
        }
        self.evict_if_full();
    }

    /// Records a read of the span `[start, end)` at `ts` by `txn` (no-op if empty).
    pub fn record_span(&mut self, start: &[u8], end: &[u8], ts: Timestamp, txn: Option<TxnId>) {
        if start >= end {
            return;
        }
        let entry = CacheEntry { ts, txn };
        match self.spans.get_mut(&(start.to_vec(), end.to_vec())) {
            Some(e) => *e = e.merge(entry),
            None => {
                self.spans.insert((start.to_vec(), end.to_vec()), entry);
            }
        }
        self.evict_if_full();
    }

    /// The maximum read over `key` (at least the low-water mark).
    #[must_use]
    pub fn max_point(&self, key: &[u8]) -> CacheEntry {
        self.max_span(key, &successor(key))
    }

    /// The maximum read over any key of `[start, end)` (at least the low-water mark).
    #[must_use]
    pub fn max_span(&self, start: &[u8], end: &[u8]) -> CacheEntry {
        let mut out = CacheEntry {
            ts: self.low_water,
            txn: None,
        };
        if start >= end {
            return out;
        }
        for (_, e) in self.points.range(start.to_vec()..end.to_vec()) {
            out = out.merge(*e);
        }
        // Spans starting before `end` that end after `start` overlap; tuples order by start
        // first, so `(end, [])` bounds every span starting before `end`.
        for ((_, span_end), e) in self.spans.range(..(end.to_vec(), Vec::new())) {
            if span_end.as_slice() > start {
                out = out.merge(*e);
            }
        }
        out
    }

    /// Evicts the oldest half into the low-water mark once over capacity (module docs).
    fn evict_if_full(&mut self) {
        if self.len() <= self.capacity {
            return;
        }
        let mut stamps: Vec<Timestamp> = self
            .points
            .values()
            .chain(self.spans.values())
            .map(|e| e.ts)
            .collect();
        stamps.sort_unstable();
        let cut = stamps[stamps.len() / 2];
        self.points.retain(|_, e| e.ts > cut);
        self.spans.retain(|_, e| e.ts > cut);
        self.raise_low_water(cut);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: TxnId = [1; 16];
    const B: TxnId = [2; 16];

    fn ts(w: u64) -> Timestamp {
        Timestamp::new(w, 0)
    }

    #[test]
    fn point_and_span_reads_cover_their_keys_only() {
        let mut c = TsCache::new(ts(1), 100);
        c.record_point(b"b", ts(5), Some(A));
        c.record_span(b"d", b"f", ts(7), Some(B));
        assert_eq!(c.max_point(b"a").ts, ts(1));
        assert_eq!(
            c.max_point(b"b"),
            CacheEntry {
                ts: ts(5),
                txn: Some(A)
            }
        );
        assert_eq!(c.max_point(b"b\x01").ts, ts(1));
        assert_eq!(c.max_point(b"d").ts, ts(7));
        assert_eq!(c.max_point(b"e\xff").ts, ts(7));
        assert_eq!(c.max_point(b"f").ts, ts(1));
        assert_eq!(c.max_span(b"a", b"c").ts, ts(5));
        assert_eq!(c.max_span(b"c", b"d\x00").ts, ts(7));
        assert_eq!(c.max_span(b"f", b"z").ts, ts(1));
    }

    #[test]
    fn same_timestamp_from_two_readers_has_no_owner() {
        let mut c = TsCache::new(ts(0), 100);
        c.record_point(b"k", ts(5), Some(A));
        c.record_point(b"k", ts(3), Some(B));
        assert!(!c.max_point(b"k").blocks(&A));
        assert!(c.max_point(b"k").blocks(&B));
        c.record_point(b"k", ts(5), Some(B));
        assert!(c.max_point(b"k").blocks(&A));
        assert!(c.max_point(b"k").blocks(&B));
    }

    #[test]
    fn eviction_raises_low_water_and_never_lowers_answers() {
        let mut c = TsCache::new(ts(0), 10);
        for i in 0..40u8 {
            c.record_point(&[i], ts(u64::from(i) + 1), Some(A));
            for j in 0..=i {
                assert!(
                    c.max_point(&[j]).ts >= ts(u64::from(j) + 1),
                    "key {j} after {i}"
                );
            }
        }
        assert!(c.len() <= 10);
        assert!(c.low_water() > ts(0));
    }

    #[test]
    fn low_water_only_moves_forward() {
        let mut c = TsCache::new(ts(9), 10);
        c.raise_low_water(ts(3));
        assert_eq!(c.low_water(), ts(9));
        c.raise_low_water(ts(12));
        assert_eq!(c.max_point(b"x").ts, ts(12));
    }
}
