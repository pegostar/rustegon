// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! In-memory write buffer (storage-engine.md §3).
//!
//! A lock-free skiplist (`crossbeam-skiplist`) ordered by [`InternalKey`]. Writers insert
//! concurrently without locks; readers never block writers. Entries are never updated or removed:
//! every write carries a unique seqno, so a new version is a new entry, and the whole memtable is
//! dropped after it has been flushed to an SST. Sizes are approximate and only drive the flush
//! trigger (`storage.memtable_size`, default 64 MiB).

use std::{
    ops::Bound,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use crossbeam_skiplist::{SkipMap, map::Entry};

use crate::{
    error::Result,
    iter::InternalIterator,
    key::{InternalKey, SeqNo, ValueKind},
    range_del::RangeTombstone,
};

/// Estimated per-entry overhead of a skiplist node (tower pointers, refcount, `Box`/`Bytes`
/// headers), in bytes. An estimate is enough: it only shifts when a flush triggers.
const ENTRY_OVERHEAD: usize = 64;

/// The newest version of a user key visible at a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemtableEntry {
    /// Sequence number of the version.
    pub seqno: SeqNo,
    /// Kind of the version (a tombstone hides older data in lower levels too).
    pub kind: ValueKind,
    /// Value bytes (empty for tombstones).
    pub value: Bytes,
}

/// Concurrent memtable.
#[derive(Default)]
pub struct Memtable {
    map: SkipMap<InternalKey, Bytes>,
    /// Range tombstones, `(start, seqno, RangeDelete) -> end`, kept apart from point entries so
    /// point iteration never sees them (`range_del.rs`).
    range_dels: SkipMap<InternalKey, Bytes>,
    approximate_size: AtomicUsize,
}

impl Memtable {
    /// Creates an empty memtable.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a version. `seqno` must be unique per memtable (the write path assigns
    /// consecutive seqnos to batch entries); a duplicate `(key, seqno, kind)` would replace the
    /// value and break snapshot reads, so it is asserted in debug builds.
    pub fn add(&self, seqno: SeqNo, kind: ValueKind, user_key: &[u8], value: Bytes) {
        let size = user_key.len() + 8 + value.len() + ENTRY_OVERHEAD;
        let key = InternalKey::new(user_key, seqno, kind);
        debug_assert!(
            !self.map.contains_key(&key),
            "duplicate memtable entry {key:?}"
        );
        self.map.insert(key, value);
        // Relaxed: the size is a heuristic for the flush trigger, not a synchronisation point.
        self.approximate_size.fetch_add(size, Ordering::Relaxed);
    }

    /// Adds a range tombstone `[start, end)` at `seqno` (unique like point seqnos).
    pub fn add_range_tombstone(&self, seqno: SeqNo, start: &[u8], end: &[u8]) {
        let size = start.len() + end.len() + 8 + ENTRY_OVERHEAD;
        self.range_dels.insert(
            InternalKey::new(start, seqno, ValueKind::RangeDelete),
            Bytes::copy_from_slice(end),
        );
        // Relaxed: heuristic only (see `add`).
        self.approximate_size.fetch_add(size, Ordering::Relaxed);
    }

    /// All range tombstones (`DeleteRange` is rare, so a copy is cheap).
    #[must_use]
    pub fn range_tombstones(&self) -> Vec<RangeTombstone> {
        self.range_dels
            .iter()
            .map(|e| RangeTombstone {
                start: e.key().user_key().to_vec(),
                end: e.value().to_vec(),
                seqno: e.key().seqno(),
            })
            .collect()
    }

    /// Newest version of `user_key` with `seqno <= snapshot`, if the memtable has one.
    #[must_use]
    pub fn get(&self, user_key: &[u8], snapshot: SeqNo) -> Option<MemtableEntry> {
        // Seek to (user_key, snapshot, highest kind): the first entry at or after it is the
        // newest version with seqno <= snapshot, if it still has the same user key.
        // shortcut: the seek key is an owned allocation per lookup (SkipMap only seeks through
        // `Borrow`); revisit if BM-STO point-get benchmarks show it in profiles.
        let seek = InternalKey::new(user_key, snapshot, ValueKind::SingleDelete);
        let entry = self.map.lower_bound(Bound::Included(&seek))?;
        let key = entry.key();
        (key.user_key() == user_key).then(|| MemtableEntry {
            seqno: key.seqno(),
            kind: key.kind(),
            value: entry.value().clone(),
        })
    }

    /// All entries in internal-key order (used by flush and iterators). The iterator observes
    /// concurrent inserts that land after its position.
    pub fn iter(&self) -> impl Iterator<Item = Entry<'_, InternalKey, Bytes>> {
        self.map.iter()
    }

    /// A bidirectional internal iterator over a shared memtable (read path, M1 T6).
    #[must_use]
    pub fn cursor(self: &Arc<Self>) -> MemtableIterator {
        MemtableIterator {
            memtable: Arc::clone(self),
            current: None,
        }
    }

    /// Approximate memory used, in bytes.
    #[must_use]
    pub fn approximate_size(&self) -> usize {
        self.approximate_size.load(Ordering::Relaxed)
    }

    /// Number of point entries and range tombstones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len() + self.range_dels.len()
    }

    /// Whether the memtable has neither point entries nor range tombstones.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty() && self.range_dels.is_empty()
    }
}

/// Cursor over a memtable that owns a reference to it, so it can outlive the caller's borrow
/// (iterators pin memtables like versions pin SSTs).
///
/// It sees writes that land after its position, so readers must filter by snapshot seqno (the
/// read path does). Every step re-seeks the skiplist from the current key: a skiplist `Entry`
/// borrows the map and cannot be stored next to the `Arc` that owns it.
// shortcut: one key clone and one O(log n) skiplist search per step; a cursor over the
// skiplist's internal nodes would avoid both. Revisit if BM-STO scan benchmarks show it.
pub struct MemtableIterator {
    memtable: Arc<Memtable>,
    current: Option<(InternalKey, Bytes)>,
}

impl MemtableIterator {
    fn set(&mut self, entry: Option<Entry<'_, InternalKey, Bytes>>) {
        self.current = entry.map(|e| (e.key().clone(), e.value().clone()));
    }
}

impl InternalIterator for MemtableIterator {
    fn valid(&self) -> bool {
        self.current.is_some()
    }

    fn key(&self) -> &[u8] {
        self.current.as_ref().map_or(&[], |(k, _)| k.as_bytes())
    }

    fn value(&self) -> Bytes {
        self.current
            .as_ref()
            .map_or_else(Bytes::new, |(_, v)| v.clone())
    }

    fn seek_to_first(&mut self) -> Result<()> {
        let memtable = Arc::clone(&self.memtable);
        self.set(memtable.map.front());
        Ok(())
    }

    fn seek(&mut self, target: &[u8]) -> Result<()> {
        // Seek targets may carry the synthetic 0xFF kind of `seek_key`.
        let target = InternalKey::seek_target(target);
        let memtable = Arc::clone(&self.memtable);
        self.set(memtable.map.lower_bound(Bound::Included(&target)));
        Ok(())
    }

    fn next(&mut self) -> Result<()> {
        if let Some((key, _)) = self.current.take() {
            let memtable = Arc::clone(&self.memtable);
            self.set(memtable.map.lower_bound(Bound::Excluded(&key)));
        }
        Ok(())
    }

    fn seek_to_last(&mut self) -> Result<()> {
        let memtable = Arc::clone(&self.memtable);
        self.set(memtable.map.back());
        Ok(())
    }

    fn prev(&mut self) -> Result<()> {
        if let Some((key, _)) = self.current.take() {
            let memtable = Arc::clone(&self.memtable);
            self.set(memtable.map.upper_bound(Bound::Excluded(&key)));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use proptest::prelude::*;

    use super::*;
    use crate::key::MAX_SEQNO;

    fn put(m: &Memtable, seqno: SeqNo, key: &str, value: &str) {
        let value = Bytes::copy_from_slice(value.as_bytes());
        m.add(seqno, ValueKind::Put, key.as_bytes(), value);
    }

    #[test]
    fn memtable_get_respects_snapshot_and_tombstones() {
        let m = Memtable::new();
        put(&m, 1, "a", "v1");
        put(&m, 3, "a", "v3");
        m.add(5, ValueKind::Delete, b"a", Bytes::new());
        put(&m, 2, "ab", "x");
        assert_eq!(m.get(b"a", 0), None);
        assert_eq!(
            m.get(b"a", 2).map(|e| e.value),
            Some(Bytes::from_static(b"v1"))
        );
        assert_eq!(
            m.get(b"a", 4).map(|e| e.value),
            Some(Bytes::from_static(b"v3"))
        );
        let deleted = m.get(b"a", MAX_SEQNO).unwrap();
        assert_eq!((deleted.seqno, deleted.kind), (5, ValueKind::Delete));
        // A key that is a prefix of another must not see the other's versions.
        assert_eq!(m.get(b"", MAX_SEQNO), None);
        assert_eq!(m.get(b"abc", MAX_SEQNO), None);
        assert_eq!(m.len(), 4);
        assert!(m.approximate_size() >= 4 * ENTRY_OVERHEAD);
    }

    #[test]
    fn memtable_iter_is_in_internal_key_order() {
        let m = Memtable::new();
        put(&m, 2, "b", "");
        put(&m, 1, "a", "");
        put(&m, 3, "a", "");
        let got: Vec<_> = m
            .iter()
            .map(|e| (e.key().user_key().to_vec(), e.key().seqno()))
            .collect();
        assert_eq!(
            got,
            [(b"a".to_vec(), 3), (b"a".to_vec(), 1), (b"b".to_vec(), 2)]
        );
    }

    #[test]
    fn memtable_concurrent_writers_lose_nothing() {
        const THREADS: u64 = 8;
        const PER_THREAD: u64 = 2_000;
        let m = Arc::new(Memtable::new());
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let m = Arc::clone(&m);
                thread::spawn(move || {
                    for i in 0..PER_THREAD {
                        // Disjoint seqnos per thread, shared key space to force contention.
                        let seqno = t * PER_THREAD + i + 1;
                        let key = format!("k{:04}", i % 100);
                        let value = Bytes::from(seqno.to_le_bytes().to_vec());
                        m.add(seqno, ValueKind::Put, key.as_bytes(), value);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.len() as u64, THREADS * PER_THREAD);
        let keys: Vec<InternalKey> = m.iter().map(|e| e.key().clone()).collect();
        assert!(
            keys.windows(2).all(|w| w[0] < w[1]),
            "iteration not strictly ordered"
        );
    }

    #[derive(Debug, Clone)]
    enum Op {
        Write(u8, ValueKind, u8),
        Get(u8, SeqNo),
    }

    fn op() -> impl Strategy<Value = Op> {
        let kind = prop_oneof![
            Just(ValueKind::Put),
            Just(ValueKind::Delete),
            Just(ValueKind::Merge),
            Just(ValueKind::SingleDelete),
        ];
        prop_oneof![
            3 => (0u8..8, kind, any::<u8>()).prop_map(|(k, kind, v)| Op::Write(k, kind, v)),
            1 => (0u8..8, 0u64..80).prop_map(|(k, s)| Op::Get(k, s)),
        ]
    }

    proptest! {
        /// Model-based check (TC-STO-001 scaffolding at memtable level): `get` returns the newest
        /// write with seqno <= snapshot, computed from a plain list of all writes. Keys are drawn
        /// from {"", "k", "kk", ...} so prefix relations are exercised.
        #[test]
        fn memtable_get_matches_model(ops in proptest::collection::vec(op(), 1..200)) {
            let m = Memtable::new();
            let mut model: Vec<(Vec<u8>, SeqNo, ValueKind, u8)> = Vec::new();
            let mut seqno = 0;
            for op in ops {
                match op {
                    Op::Write(k, kind, v) => {
                        seqno += 1;
                        let key = vec![b'k'; usize::from(k)];
                        m.add(seqno, kind, &key, Bytes::from(vec![v]));
                        model.push((key, seqno, kind, v));
                    }
                    Op::Get(k, snapshot) => {
                        let key = vec![b'k'; usize::from(k)];
                        let expected = model
                            .iter()
                            .filter(|(mk, s, ..)| *mk == key && *s <= snapshot)
                            .max_by_key(|(_, s, ..)| *s)
                            .map(|(_, s, kind, v)| (*s, *kind, Bytes::from(vec![*v])));
                        let got = m.get(&key, snapshot).map(|e| (e.seqno, e.kind, e.value));
                        prop_assert_eq!(got, expected);
                    }
                }
            }
        }
    }
}
