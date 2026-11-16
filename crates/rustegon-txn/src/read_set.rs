// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The refresh spans of a SERIALIZABLE transaction (transaction-management.md §4.1): every key
//! and span it read at `read_ts`. When its write timestamp has moved above `read_ts`, commit
//! re-checks them for writes in `(read_ts, write_ts]` (read refresh).
//!
//! Size bound (`txn.max_refresh_spans_bytes`, §9): once the tracked keys exceed it, they are
//! condensed into one span covering all of them. Coarser spans can only make a refresh fail more
//! often (false conflicts), never succeed wrongly.

use std::collections::BTreeSet;

use crate::ts_cache::successor;

/// A logical key span `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpan {
    /// First key.
    pub start: Vec<u8>,
    /// Exclusive end.
    pub end: Vec<u8>,
}

/// The read spans of a transaction (module docs).
#[derive(Debug, Default)]
pub struct ReadSet {
    points: BTreeSet<Vec<u8>>,
    spans: Vec<KeySpan>,
    bytes: usize,
}

impl ReadSet {
    /// Records a point read.
    pub fn add_point(&mut self, key: &[u8], limit: usize) {
        if self.points.insert(key.to_vec()) {
            self.bytes += key.len();
            self.condense_if_needed(limit);
        }
    }

    /// Records a span read `[start, end)` (no-op if empty).
    pub fn add_span(&mut self, start: &[u8], end: &[u8], limit: usize) {
        if start < end {
            self.bytes += start.len() + end.len();
            self.spans.push(KeySpan {
                start: start.to_vec(),
                end: end.to_vec(),
            });
            self.condense_if_needed(limit);
        }
    }

    /// Whether nothing was read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.points.is_empty() && self.spans.is_empty()
    }

    /// Forgets every read (restart).
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// The point reads.
    pub fn points(&self) -> impl Iterator<Item = &[u8]> {
        self.points.iter().map(Vec::as_slice)
    }

    /// The span reads.
    #[must_use]
    pub fn spans(&self) -> &[KeySpan] {
        &self.spans
    }

    fn condense_if_needed(&mut self, limit: usize) {
        if self.bytes <= limit {
            return;
        }
        let starts = self
            .points
            .iter()
            .map(Vec::as_slice)
            .chain(self.spans.iter().map(|s| s.start.as_slice()));
        let Some(start) = starts.min().map(<[u8]>::to_vec) else {
            return;
        };
        let ends = self
            .points
            .iter()
            .map(|k| successor(k))
            .chain(self.spans.iter().map(|s| s.end.clone()));
        let Some(end) = ends.max() else {
            return;
        };
        self.points.clear();
        self.bytes = start.len() + end.len();
        self.spans = vec![KeySpan { start, end }];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condensing_covers_every_read() {
        let mut r = ReadSet::default();
        r.add_point(b"m", 3);
        r.add_span(b"c", b"e", 3);
        r.add_point(b"x", 3);
        assert_eq!(r.points().count(), 0);
        assert_eq!(
            r.spans(),
            [KeySpan {
                start: b"c".to_vec(),
                end: b"x\x00".to_vec()
            }]
        );
    }

    #[test]
    fn small_sets_stay_exact() {
        let mut r = ReadSet::default();
        r.add_point(b"a", 100);
        r.add_point(b"a", 100);
        r.add_span(b"b", b"b", 100);
        assert_eq!(r.points().collect::<Vec<_>>(), [b"a".as_slice()]);
        assert_eq!(r.spans(), []);
        r.clear();
        assert!(r.is_empty());
    }
}
