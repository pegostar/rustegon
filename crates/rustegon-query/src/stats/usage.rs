// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Per-index usage counters (FR-IDX-004, indexing.md §1 `stats.ops` / `stats.last_used`).
//!
//! In memory, per node, keyed by index id: the executor records every point lookup and range
//! scan it serves from an index (one operation per executed index access of a plan, whatever
//! the number of key ranges, with the number of entries it read; `rustegon-query::exec`). A
//! transaction body re-run after a conflict executes — and counts — its index accesses again:
//! they were real index operations. Persisting them into the index catalog entry (`stats` of
//! indexing.md §1) and aggregating across nodes are later work (the GUI/API exposure is M4+),
//! as are the entry/byte sizes, which the statistics job records ([`super::IndexSize`]).
//! Counters are monotonic until [`IndexUsageRegistry::remove`] (index dropped).

use std::{
    collections::BTreeMap,
    sync::{Mutex, PoisonError},
};

/// Usage of one index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndexUsage {
    /// Point lookups (equality on the full key, e.g. unique lookups).
    pub lookups: u64,
    /// Range scans.
    pub scans: u64,
    /// Index entries read by those lookups and scans.
    pub rows: u64,
    /// Last use, ms since the epoch; `None` if never used.
    pub last_used_ms: Option<i64>,
}

impl IndexUsage {
    /// Total operations (`stats.ops` of indexing.md §1).
    #[must_use]
    pub fn ops(&self) -> u64 {
        self.lookups.saturating_add(self.scans)
    }
}

/// Kind of an index access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexAccess {
    /// Every key range is one full key (equality on every key field).
    Lookup,
    /// Anything else (prefix, range, sort-only scans).
    Scan,
}

/// The node's usage counters (thread-safe; a poisoned lock is recovered because counters
/// cannot be left half-updated).
#[derive(Debug, Default)]
pub struct IndexUsageRegistry {
    map: Mutex<BTreeMap<u32, IndexUsage>>,
}

impl IndexUsageRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn update(&self, index_id: u32, now_ms: i64, f: impl FnOnce(&mut IndexUsage)) {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        let u = map.entry(index_id).or_default();
        f(u);
        // Clocks may step back; keep the latest use.
        u.last_used_ms = Some(u.last_used_ms.map_or(now_ms, |l| l.max(now_ms)));
    }

    /// Records a point lookup at `now_ms`.
    pub fn record_lookup(&self, index_id: u32, now_ms: i64) {
        self.update(index_id, now_ms, |u| {
            u.lookups = u.lookups.saturating_add(1);
        });
    }

    /// Records a range scan at `now_ms`.
    pub fn record_scan(&self, index_id: u32, now_ms: i64) {
        self.update(index_id, now_ms, |u| {
            u.scans = u.scans.saturating_add(1);
        });
    }

    /// Records one access of kind `kind` that read `rows` index entries, at `now_ms`.
    pub fn record(&self, index_id: u32, kind: IndexAccess, rows: u64, now_ms: i64) {
        self.update(index_id, now_ms, |u| {
            match kind {
                IndexAccess::Lookup => u.lookups = u.lookups.saturating_add(1),
                IndexAccess::Scan => u.scans = u.scans.saturating_add(1),
            }
            u.rows = u.rows.saturating_add(rows);
        });
    }

    /// Adds `rows` index entries read by an access already recorded with [`Self::record`]
    /// (the later pages of a paged index scan), at `now_ms`.
    pub fn record_rows(&self, index_id: u32, rows: u64, now_ms: i64) {
        self.update(index_id, now_ms, |u| {
            u.rows = u.rows.saturating_add(rows);
        });
    }

    /// Usage of `index_id` (zero counters if never used).
    #[must_use]
    pub fn get(&self, index_id: u32) -> IndexUsage {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&index_id)
            .copied()
            .unwrap_or_default()
    }

    /// All counters, by index id.
    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<u32, IndexUsage> {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Forgets `index_id` (dropped index).
    pub fn remove(&self, index_id: u32) {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&index_id);
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;

    /// TC-IDX-007 (usage part): counters are exact under concurrent recording.
    #[test]
    fn tc_idx_007_usage_counters_exact_and_last_used_monotonic() {
        let r = Arc::new(IndexUsageRegistry::new());
        assert_eq!(r.get(1), IndexUsage::default());
        let handles: Vec<_> = (0..4i64)
            .map(|t| {
                let r = Arc::clone(&r);
                thread::spawn(move || {
                    for i in 0..1000 {
                        r.record_lookup(1, t * 1000 + i);
                        r.record_scan(2, 5);
                    }
                })
            })
            .collect();
        for h in handles {
            assert!(h.join().is_ok());
        }
        let one = r.get(1);
        assert_eq!((one.lookups, one.scans, one.ops()), (4000, 0, 4000));
        assert_eq!(one.last_used_ms, Some(3999));
        r.record_lookup(1, 10); // clock stepped back: last use kept
        assert_eq!(r.get(1).last_used_ms, Some(3999));
        assert_eq!(r.get(2).scans, 4000);
        assert_eq!(r.snapshot().len(), 2);
        r.remove(2);
        assert_eq!(r.get(2), IndexUsage::default());
    }
}
