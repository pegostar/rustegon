// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Range tombstones (`DeleteRange`, storage-engine.md §1, §3) and their fragmented form.
//!
//! A tombstone `[start, end) @ seqno` deletes every version of every user key in the range whose
//! seqno is lower than `seqno`, for readers whose snapshot is >= `seqno`. Tombstones may overlap
//! arbitrarily; queries go through a *fragmented* list (as in `RocksDB`'s
//! `FragmentedRangeTombstoneList`): the key space is cut at every start and end into disjoint
//! fragments, each carrying the seqnos of all tombstones covering it, so "which tombstones cover
//! key k" is one binary search.

use crate::key::SeqNo;

/// One `DeleteRange(start, end)` written at `seqno`; `start < end`, end exclusive.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RangeTombstone {
    /// First deleted user key.
    pub start: Vec<u8>,
    /// First user key after the range.
    pub end: Vec<u8>,
    /// Sequence number of the delete.
    pub seqno: SeqNo,
}

/// A disjoint piece `[start, end)` of the key space with the seqnos of every tombstone covering
/// it, descending.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fragment {
    start: Vec<u8>,
    end: Vec<u8>,
    seqnos: Vec<SeqNo>,
}

/// Fragmented, query-ready set of range tombstones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FragmentedTombstones {
    /// Sorted by `start`, pairwise disjoint, non-empty `seqnos`.
    fragments: Vec<Fragment>,
}

impl FragmentedTombstones {
    /// Fragments `tombstones`, keeping only those with `seqno <= max_seqno` (a reader's snapshot;
    /// `MAX_SEQNO` keeps all). Empty ranges are ignored.
    ///
    /// Sweep over the sorted cut points: O(n log n + fragments × overlap).
    #[must_use]
    pub fn new<'a>(
        tombstones: impl IntoIterator<Item = &'a RangeTombstone>,
        max_seqno: SeqNo,
    ) -> Self {
        let mut live: Vec<&RangeTombstone> = tombstones
            .into_iter()
            .filter(|t| t.seqno <= max_seqno && t.start < t.end)
            .collect();
        live.sort_by(|a, b| a.start.cmp(&b.start));
        let mut cuts: Vec<&[u8]> = live
            .iter()
            .flat_map(|t| [t.start.as_slice(), t.end.as_slice()])
            .collect();
        cuts.sort_unstable();
        cuts.dedup();

        let mut fragments = Vec::new();
        let mut next = 0;
        let mut active: Vec<&RangeTombstone> = Vec::new();
        for pair in cuts.windows(2) {
            let (lo, hi) = (pair[0], pair[1]);
            while next < live.len() && live[next].start.as_slice() <= lo {
                active.push(live[next]);
                next += 1;
            }
            active.retain(|t| t.end.as_slice() > lo);
            if active.is_empty() {
                continue;
            }
            let mut seqnos: Vec<SeqNo> = active.iter().map(|t| t.seqno).collect();
            seqnos.sort_unstable_by(|a, b| b.cmp(a));
            seqnos.dedup();
            fragments.push(Fragment {
                start: lo.to_vec(),
                end: hi.to_vec(),
                seqnos,
            });
        }
        Self { fragments }
    }

    /// Whether there is no tombstone at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fragments.is_empty()
    }

    fn fragment(&self, user_key: &[u8]) -> Option<&Fragment> {
        let at = self
            .fragments
            .partition_point(|f| f.start.as_slice() <= user_key);
        let f = self.fragments.get(at.checked_sub(1)?)?;
        (user_key < f.end.as_slice()).then_some(f)
    }

    /// Largest seqno of a tombstone covering `user_key`: every version of the key with a lower
    /// seqno is deleted for this reader.
    #[must_use]
    pub fn max_covering(&self, user_key: &[u8]) -> Option<SeqNo> {
        self.fragment(user_key)
            .and_then(|f| f.seqnos.first().copied())
    }

    /// Smallest seqno of a tombstone covering `user_key` that is above `seqno` (the oldest
    /// tombstone that deletes a version at `seqno`; compaction uses it to decide whether some
    /// snapshot still sees the version).
    #[must_use]
    pub fn oldest_covering_above(&self, user_key: &[u8], seqno: SeqNo) -> Option<SeqNo> {
        self.fragment(user_key)
            .and_then(|f| f.seqnos.iter().rev().find(|&&s| s > seqno).copied())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn arb_tombstones() -> impl Strategy<Value = Vec<RangeTombstone>> {
        prop::collection::vec((0u8..20, 0u8..20, 1u64..50), 0..12).prop_map(|raw| {
            raw.into_iter()
                .map(|(a, b, seqno)| RangeTombstone {
                    start: vec![a],
                    end: vec![b],
                    seqno,
                })
                .collect()
        })
    }

    proptest! {
        /// Fragment queries equal a naive scan over the raw tombstones.
        #[test]
        fn fragments_match_naive_model(
            tombstones in arb_tombstones(),
            snapshot in 0u64..60,
            probe in 0u8..21,
            version in 0u64..60,
        ) {
            let f = FragmentedTombstones::new(&tombstones, snapshot);
            let key = [probe];
            let covering: Vec<SeqNo> = tombstones
                .iter()
                .filter(|t| t.seqno <= snapshot && t.start.as_slice() <= key.as_slice()
                    && key.as_slice() < t.end.as_slice())
                .map(|t| t.seqno)
                .collect();
            prop_assert_eq!(f.max_covering(&key), covering.iter().copied().max());
            prop_assert_eq!(
                f.oldest_covering_above(&key, version),
                covering.iter().copied().filter(|&s| s > version).min()
            );
            prop_assert_eq!(f.is_empty(), !tombstones.iter().any(|t| t.seqno <= snapshot && t.start < t.end));
        }
    }
}
