// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Internal-key iterators and the merging iterator that combines them (storage-engine.md §3).
//!
//! An internal iterator yields encoded internal keys (`user_key ‖ trailer`, see `key.rs`) in
//! internal-key order: user key ascending, seqno descending. Merging several of them yields the
//! union in the same order, which is what compaction consumes (every version of a user key arrives
//! newest first and contiguously) and what the read path (`read.rs`) builds on.

use bytes::Bytes;

use crate::{error::Result, key::compare_internal, sst::SstIterator};

/// A bidirectional cursor over entries ordered by internal key.
///
/// Advancing is fallible (I/O, corruption) and keys are borrowed from the current block, so this
/// is a lending cursor rather than a `std::iter::Iterator`.
pub trait InternalIterator: Send {
    /// Whether the cursor is positioned on an entry.
    fn valid(&self) -> bool;
    /// Encoded internal key of the current entry (empty unless [`Self::valid`]).
    fn key(&self) -> &[u8];
    /// Value of the current entry (empty unless [`Self::valid`]).
    fn value(&self) -> Bytes;
    /// Positions at the first entry.
    ///
    /// # Errors
    /// I/O or corruption errors; the cursor is then invalid.
    fn seek_to_first(&mut self) -> Result<()>;
    /// Positions at the first entry whose internal key is >= `target`.
    ///
    /// # Errors
    /// I/O or corruption errors; the cursor is then invalid.
    fn seek(&mut self, target: &[u8]) -> Result<()>;
    /// Advances to the next entry; no-op when invalid.
    ///
    /// # Errors
    /// I/O or corruption errors; the cursor is then invalid.
    fn next(&mut self) -> Result<()>;
    /// Positions at the last entry.
    ///
    /// # Errors
    /// I/O or corruption errors; the cursor is then invalid.
    fn seek_to_last(&mut self) -> Result<()>;
    /// Steps to the previous entry; invalid before the first one, no-op when invalid.
    ///
    /// # Errors
    /// I/O or corruption errors; the cursor is then invalid.
    fn prev(&mut self) -> Result<()>;
    /// Positions at the last entry whose internal key is <= `target`.
    ///
    /// # Errors
    /// I/O or corruption errors; the cursor is then invalid.
    fn seek_for_prev(&mut self, target: &[u8]) -> Result<()> {
        self.seek(target)?;
        if !self.valid() {
            return self.seek_to_last();
        }
        if compare_internal(self.key(), target).is_gt() {
            self.prev()?;
        }
        Ok(())
    }
}

impl InternalIterator for SstIterator {
    fn valid(&self) -> bool {
        SstIterator::valid(self)
    }
    fn key(&self) -> &[u8] {
        SstIterator::key(self)
    }
    fn value(&self) -> Bytes {
        SstIterator::value(self)
    }
    fn seek_to_first(&mut self) -> Result<()> {
        SstIterator::seek_to_first(self)
    }
    fn seek(&mut self, target: &[u8]) -> Result<()> {
        SstIterator::seek(self, target)
    }
    fn next(&mut self) -> Result<()> {
        SstIterator::next(self)
    }
    fn seek_to_last(&mut self) -> Result<()> {
        SstIterator::seek_to_last(self)
    }
    fn prev(&mut self) -> Result<()> {
        SstIterator::prev(self)
    }
}

/// Merges child iterators into one internal-key-ordered stream, in either direction.
///
/// The valid children are kept in a binary heap ordered by their current key: a min-heap while
/// moving forward, a max-heap while moving backward, so each step costs O(log children).
/// Changing direction repositions every child other than the current one on the other side of
/// the current key (the `LevelDB` `MergingIterator` scheme): forward → backward puts each on its
/// last entry before the key, backward → forward on its first entry after it; then the heap is
/// rebuilt and the current child is again on top.
///
/// Internal keys are unique across children (every write has its own seqno), so the order is
/// total; an impossible tie is broken by child index to stay deterministic.
pub struct MergingIterator {
    children: Vec<Box<dyn InternalIterator>>,
    /// Indexes of the valid children in heap order; `heap[0]` is the current one.
    heap: Vec<usize>,
    forward: bool,
}

impl MergingIterator {
    /// Creates an unpositioned merging iterator; call a seek method first.
    #[must_use]
    pub fn new(children: Vec<Box<dyn InternalIterator>>) -> Self {
        Self {
            children,
            heap: Vec::new(),
            forward: true,
        }
    }

    /// Whether child `a` comes before child `b` in the current direction.
    fn before(&self, a: usize, b: usize) -> bool {
        let order =
            compare_internal(self.children[a].key(), self.children[b].key()).then(a.cmp(&b));
        if self.forward {
            order.is_lt()
        } else {
            order.is_gt()
        }
    }

    fn sift_down(&mut self, mut at: usize) {
        loop {
            let (left, right) = (2 * at + 1, 2 * at + 2);
            let mut best = at;
            if left < self.heap.len() && self.before(self.heap[left], self.heap[best]) {
                best = left;
            }
            if right < self.heap.len() && self.before(self.heap[right], self.heap[best]) {
                best = right;
            }
            if best == at {
                return;
            }
            self.heap.swap(at, best);
            at = best;
        }
    }

    fn rebuild_heap(&mut self) {
        self.heap = (0..self.children.len())
            .filter(|&i| self.children[i].valid())
            .collect();
        for at in (0..self.heap.len() / 2).rev() {
            self.sift_down(at);
        }
    }

    /// Runs `op` on every child, sets the direction and rebuilds the heap; on error the
    /// iterator is invalid.
    fn reposition(
        &mut self,
        forward: bool,
        mut op: impl FnMut(&mut dyn InternalIterator) -> Result<()>,
    ) -> Result<()> {
        self.heap.clear();
        self.forward = forward;
        for child in &mut self.children {
            op(child.as_mut())?;
        }
        self.rebuild_heap();
        Ok(())
    }

    /// Moves the current child one step in the current direction and restores the heap.
    fn step_current(&mut self) -> Result<()> {
        let Some(&c) = self.heap.first() else {
            return Ok(());
        };
        let child = &mut self.children[c];
        let result = if self.forward {
            child.next()
        } else {
            child.prev()
        };
        if let Err(e) = result {
            self.heap.clear();
            return Err(e);
        }
        if !self.children[c].valid() {
            self.heap.swap_remove(0);
        }
        self.sift_down(0);
        Ok(())
    }

    /// Repositions the non-current children around the current key for a direction change.
    fn switch_direction(&mut self, forward: bool) -> Result<()> {
        let Some(&c) = self.heap.first() else {
            return Ok(());
        };
        let key = self.children[c].key().to_vec();
        for (i, child) in self.children.iter_mut().enumerate() {
            if i == c {
                continue;
            }
            let result = if forward {
                after(child.as_mut(), &key)
            } else {
                before(child.as_mut(), &key)
            };
            if let Err(e) = result {
                self.heap.clear();
                return Err(e);
            }
        }
        self.forward = forward;
        self.rebuild_heap();
        // The current child is still on `key`, the first entry in the new direction.
        debug_assert_eq!(self.heap.first(), Some(&c));
        Ok(())
    }
}

/// Positions `child` on its first entry strictly after `key`.
fn after(child: &mut dyn InternalIterator, key: &[u8]) -> Result<()> {
    child.seek(key)?;
    if child.valid() && compare_internal(child.key(), key).is_eq() {
        child.next()?;
    }
    Ok(())
}

/// Positions `child` on its last entry strictly before `key`.
fn before(child: &mut dyn InternalIterator, key: &[u8]) -> Result<()> {
    child.seek(key)?;
    if child.valid() {
        child.prev()
    } else {
        child.seek_to_last()
    }
}

impl InternalIterator for MergingIterator {
    fn valid(&self) -> bool {
        !self.heap.is_empty()
    }

    fn key(&self) -> &[u8] {
        self.heap.first().map_or(&[], |&c| self.children[c].key())
    }

    fn value(&self) -> Bytes {
        self.heap
            .first()
            .map_or_else(Bytes::new, |&c| self.children[c].value())
    }

    fn seek_to_first(&mut self) -> Result<()> {
        self.reposition(true, |c| c.seek_to_first())
    }

    fn seek(&mut self, target: &[u8]) -> Result<()> {
        self.reposition(true, |c| c.seek(target))
    }

    fn seek_to_last(&mut self) -> Result<()> {
        self.reposition(false, |c| c.seek_to_last())
    }

    fn seek_for_prev(&mut self, target: &[u8]) -> Result<()> {
        self.reposition(false, |c| c.seek_for_prev(target))
    }

    fn next(&mut self) -> Result<()> {
        if !self.forward {
            self.switch_direction(true)?;
        }
        self.step_current()
    }

    fn prev(&mut self) -> Result<()> {
        if self.forward {
            self.switch_direction(false)?;
        }
        self.step_current()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::key::{InternalKey, ValueKind};

    /// In-memory child for tests: sorted `(internal key, value)` pairs.
    pub(crate) struct VecIter {
        entries: Vec<(Vec<u8>, Bytes)>,
        pos: usize,
    }

    impl VecIter {
        pub(crate) fn new(mut entries: Vec<(Vec<u8>, Bytes)>) -> Self {
            entries.sort_by(|a, b| compare_internal(&a.0, &b.0));
            let pos = entries.len();
            Self { entries, pos }
        }
    }

    impl InternalIterator for VecIter {
        fn valid(&self) -> bool {
            self.pos < self.entries.len()
        }
        fn key(&self) -> &[u8] {
            self.entries.get(self.pos).map_or(&[], |e| &e.0)
        }
        fn value(&self) -> Bytes {
            self.entries
                .get(self.pos)
                .map_or_else(Bytes::new, |e| e.1.clone())
        }
        fn seek_to_first(&mut self) -> Result<()> {
            self.pos = 0;
            Ok(())
        }
        fn seek(&mut self, target: &[u8]) -> Result<()> {
            self.pos = self
                .entries
                .partition_point(|e| compare_internal(&e.0, target).is_lt());
            Ok(())
        }
        fn next(&mut self) -> Result<()> {
            self.pos = (self.pos + 1).min(self.entries.len());
            Ok(())
        }
        fn seek_to_last(&mut self) -> Result<()> {
            self.pos = self.entries.len().saturating_sub(1);
            Ok(())
        }
        fn prev(&mut self) -> Result<()> {
            self.pos = match self.pos {
                p if p >= self.entries.len() => p,
                0 => self.entries.len(),
                p => p - 1,
            };
            Ok(())
        }
    }

    fn ik(user: &str, seqno: u64) -> Vec<u8> {
        InternalKey::new(user.as_bytes(), seqno, ValueKind::Put)
            .as_bytes()
            .to_vec()
    }

    fn collect(it: &mut MergingIterator) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while it.valid() {
            out.push(it.key().to_vec());
            it.next().unwrap();
        }
        out
    }

    /// Splits `keys` over 4 children; returns them and the sorted union.
    fn build(
        keys: &std::collections::BTreeSet<(u8, u64)>,
        split: &[usize],
    ) -> (MergingIterator, Vec<Vec<u8>>) {
        let mut parts = vec![Vec::new(); 4];
        let mut all = Vec::new();
        for (i, (u, s)) in keys.iter().enumerate() {
            let k = ik(&format!("k{u:02}"), *s);
            parts[split[i]].push((k.clone(), Bytes::from(vec![*u])));
            all.push(k);
        }
        all.sort_by(|a, b| compare_internal(a, b));
        let children: Vec<Box<dyn InternalIterator>> = parts
            .into_iter()
            .map(|p| Box::new(VecIter::new(p)) as _)
            .collect();
        (MergingIterator::new(children), all)
    }

    proptest! {
        #[test]
        fn merging_iterator_equals_sorted_union(
            keys in prop::collection::btree_set((0u8..20, 1u64..1000), 0..200),
            split in prop::collection::vec(0usize..4, 200),
            seek_user in 0u8..20,
        ) {
            let (mut it, all) = build(&keys, &split);
            it.seek_to_first().unwrap();
            prop_assert_eq!(collect(&mut it), all.clone());

            let target =
                crate::key::seek_key(format!("k{seek_user:02}").as_bytes(), crate::MAX_SEQNO);
            it.seek(&target).unwrap();
            let expected: Vec<_> = all
                .into_iter()
                .filter(|k| compare_internal(k, &target).is_ge())
                .collect();
            prop_assert_eq!(collect(&mut it), expected);
        }

        /// Reverse scans, `seek_for_prev` and arbitrary `next`/`prev` interleavings agree with
        /// the sorted union.
        #[test]
        fn merging_iterator_reverse_and_direction_changes(
            keys in prop::collection::btree_set((0u8..20, 1u64..1000), 0..200),
            split in prop::collection::vec(0usize..4, 200),
            probe in (0u8..21, 0u64..1001),
            moves in prop::collection::vec(any::<bool>(), 0..60),
        ) {
            let (mut it, all) = build(&keys, &split);
            it.seek_to_last().unwrap();
            let mut backward = Vec::new();
            while it.valid() {
                backward.push(it.key().to_vec());
                it.prev().unwrap();
            }
            backward.reverse();
            prop_assert_eq!(&backward, &all);

            let target = ik(&format!("k{:02}", probe.0), probe.1);
            it.seek_for_prev(&target).unwrap();
            let mut pos = all
                .partition_point(|k| compare_internal(k, &target).is_le())
                .checked_sub(1);
            for forward in moves {
                let Some(p) = pos else {
                    prop_assert!(!it.valid());
                    break;
                };
                prop_assert_eq!(it.key(), all[p].as_slice());
                if forward {
                    it.next().unwrap();
                    pos = (p + 1 < all.len()).then_some(p + 1);
                } else {
                    it.prev().unwrap();
                    pos = p.checked_sub(1);
                }
            }
            if pos.is_none() {
                prop_assert!(!it.valid());
            }
        }
    }
}
