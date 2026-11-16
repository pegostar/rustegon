// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Block cache: a sharded CLOCK-Pro cache of decoded SST blocks (storage-engine.md §5).
//!
//! Why CLOCK-Pro and not LRU: LSM workloads mix point reads over a hot working set with long
//! one-time scans (iterators, compaction-adjacent reads, backups). Under LRU a scan larger than
//! the cache flushes the whole working set; CLOCK-Pro only promotes blocks that are re-used
//! within their test period, so scanned blocks pass through the cold class and are evicted
//! without disturbing hot blocks. It also avoids moving entries on every hit (a hit only sets a
//! reference bit), which keeps the critical section of a hit tiny.
//!
//! # Algorithm
//! Reference: S. Jiang, F. Chen, X. Zhang, "CLOCK-Pro: An Effective Improvement of the CLOCK
//! Replacement", USENIX ATC 2005. Each shard keeps one circular list of entries in three
//! classes — *hot* (resident), *cold* (resident) and *test* (non-resident metadata of recently
//! evicted cold entries) — swept by three hands:
//! - `hand_cold` runs when resident bytes exceed the capacity: a referenced cold entry is
//!   promoted to hot, an unreferenced one loses its value and stays as a test entry.
//! - `hand_hot` runs when hot bytes exceed `capacity - cold_target`: a referenced hot entry
//!   gets its bit cleared (second chance), an unreferenced one is demoted to cold; a test entry
//!   it passes is retired.
//! - `hand_test` runs when test metadata exceeds the capacity (the paper bounds non-resident
//!   pages by the memory size) and retires test entries.
//!
//! `cold_target` adapts as in the paper: a miss on a key that still has a test entry means the
//! cold class was too small to tell that block was hot, so the target grows by its charge;
//! a test entry retired without such a hit shrinks it.
//!
//! Simplifications (same as most production ports, e.g. the Go `clockpro` package):
//! - Every referenced cold entry met by `hand_cold` is promoted; the paper only promotes it if
//!   it is still in its test period. Without the per-resident test flag a cold entry referenced
//!   once after insertion is promoted, which still keeps one-time scans out of the hot class
//!   because scanned blocks are never referenced after their insertion.
//! - Sizes are byte charges, not page counts; `hand_hot` runs on byte imbalance.
//! - High-priority entries (index partitions; the filter and top-level index are held by the
//!   reader itself, i.e. pinned while the file is open, see PD-022) skip the cold probation and
//!   enter the hot class with their reference bit set, so they survive at least two `hand_hot`
//!   sweeps. Replacing a resident entry keeps its reference bit, so a re-insert by a racing
//!   reader does not erase evidence of re-use.
//!
//! # Concurrency
//! 64 independent shards, each behind its own `Mutex`, chosen by a hash of the key. A lock is
//! held only for the in-memory bookkeeping of one lookup or insert; the caller performs the
//! block I/O between a missed lookup and the insert without holding any lock. Two threads
//! missing on the same block both read it and both insert; the second insert replaces the
//! first, which is harmless because blocks of an SST are immutable.
//!
//! A panic while a shard lock is held (only possible through a bug in the bookkeeping) may
//! leave that shard's byte counters and ring half-updated, and continuing on such a state can
//! underflow a counter or make `evict` loop forever under the lock. The cache holds no durable
//! state, so the next locker drops the poisoned shard's contents, rebuilds it empty and clears
//! the poison instead of either trusting the state or cascading the panic.

use std::{
    collections::HashMap,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::sst::Block;

/// Number of shards (storage-engine.md §5): enough to make lock contention negligible at the
/// core counts of the reference hardware while keeping per-shard capacity useful.
pub const SHARD_COUNT: usize = 64;

/// Bookkeeping bytes charged per cached block on top of its data: hash-map slot, ring node and
/// the `Block` handle. An estimate; it only needs to keep tiny blocks from looking free.
/// Also used by `StorageSettings` validation to size the smallest useful cache.
pub(crate) const ENTRY_OVERHEAD: usize = 96;

/// Fibonacci-hashing multiplier (2^64 / golden ratio) used to spread keys over shards.
const SHARD_HASH_MULTIPLIER: u64 = 0x9E37_79B9_7F4A_7C15;

/// Key of a cached block: the cache id of the open SST (see [`BlockCache::new_cache_id`]) and
/// the block's file offset.
pub type CacheKey = (u64, u64);

/// Replacement priority of an inserted entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// Data blocks: enter the cold class and must prove re-use before becoming hot.
    Low,
    /// Index (and filter) blocks: enter the hot class directly.
    High,
}

/// Hit/miss counters and current usage of a cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheStats {
    /// Lookups that found a resident entry.
    pub hits: u64,
    /// Lookups that did not.
    pub misses: u64,
    /// Bytes currently charged by resident entries.
    pub usage: usize,
    /// Inserts refused because the entry's charge exceeds one shard's share of the capacity;
    /// a growing count means the cache is too small for the block size (storage-engine.md §5).
    pub rejected_oversize: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Hot,
    Cold,
    /// Non-resident: value dropped, key and charge kept to detect re-use.
    Test,
}

struct Node<V> {
    key: CacheKey,
    value: Option<V>,
    charge: usize,
    class: Class,
    referenced: bool,
    prev: usize,
    next: usize,
}

/// One shard of a CLOCK-Pro cache. Generic over the value so the replacement logic can be
/// tested without SST blocks.
pub(crate) struct ClockPro<V> {
    capacity: usize,
    /// Adaptive target for cold resident bytes, in `[min_cold, capacity]`.
    cold_target: usize,
    min_cold: usize,
    hot_bytes: usize,
    cold_bytes: usize,
    test_bytes: usize,
    map: HashMap<CacheKey, usize>,
    /// Slab of ring nodes; `free` lists vacant slots.
    nodes: Vec<Node<V>>,
    free: Vec<usize>,
    hand_hot: Option<usize>,
    hand_cold: Option<usize>,
    hand_test: Option<usize>,
}

impl<V: Clone> ClockPro<V> {
    /// A shard holding at most `capacity` bytes of resident entries.
    pub(crate) fn new(capacity: usize) -> Self {
        // The paper keeps at least one cold page so new pages can enter; 1 % of the capacity
        // plays that role for byte charges. Start balanced: half hot, half cold.
        let min_cold = (capacity / 100).max(1).min(capacity);
        Self {
            capacity,
            cold_target: (capacity / 2).max(min_cold),
            min_cold,
            hot_bytes: 0,
            cold_bytes: 0,
            test_bytes: 0,
            map: HashMap::new(),
            nodes: Vec::new(),
            free: Vec::new(),
            hand_hot: None,
            hand_cold: None,
            hand_test: None,
        }
    }

    /// Bytes charged by resident entries.
    pub(crate) fn usage(&self) -> usize {
        self.hot_bytes + self.cold_bytes
    }

    /// The resident value of `key`, marking it referenced.
    pub(crate) fn lookup(&mut self, key: CacheKey) -> Option<V> {
        let idx = *self.map.get(&key)?;
        let node = &mut self.nodes[idx];
        let value = node.value.clone()?;
        node.referenced = true;
        Some(value)
    }

    /// Inserts or replaces `key`; returns `false` when the entry is larger than the whole shard
    /// and therefore not cached, so usage never exceeds the capacity. An oversize replace also
    /// drops the old entry of `key`, so the cache never serves a value older than the last
    /// insert.
    pub(crate) fn insert(
        &mut self,
        key: CacheKey,
        value: V,
        charge: usize,
        priority: Priority,
    ) -> bool {
        if charge > self.capacity {
            if let Some(&idx) = self.map.get(&key) {
                self.remove(idx);
            }
            return false;
        }
        let mut class = match priority {
            Priority::Low => Class::Cold,
            Priority::High => Class::Hot,
        };
        let mut referenced = priority == Priority::High;
        if let Some(&idx) = self.map.get(&key) {
            // A replaced resident entry keeps its reference bit: it was used since the last
            // sweep, and dropping that would let the cold hand evict a block in active use.
            referenced |= self.nodes[idx].referenced;
            if self.nodes[idx].class == Class::Test {
                // Re-used during its test period: the cold class was too small to see this
                // block's reuse distance, so grow it (paper §3.3) and admit the block as hot.
                self.cold_target = (self.cold_target + charge).min(self.capacity);
                class = Class::Hot;
            } else if self.nodes[idx].class == Class::Hot {
                class = Class::Hot;
            }
            self.remove(idx);
        }
        let idx = self.link(Node {
            key,
            value: Some(value),
            charge,
            class,
            referenced,
            prev: 0,
            next: 0,
        });
        self.map.insert(key, idx);
        match class {
            Class::Hot => self.hot_bytes += charge,
            _ => self.cold_bytes += charge,
        }
        self.balance_hot();
        self.evict();
        true
    }

    /// Runs `hand_cold` until the resident bytes fit. Terminates: every step either converts a
    /// cold entry (to hot or test) or, when no cold bytes remain, steps `hand_hot`, which demotes
    /// some hot entry within two sweeps.
    fn evict(&mut self) {
        while self.usage() > self.capacity {
            if self.cold_bytes == 0 {
                self.step_hot();
            } else {
                self.step_cold();
            }
        }
    }

    /// Runs `hand_hot` while hot bytes exceed their share of the capacity.
    fn balance_hot(&mut self) {
        while self.hot_bytes > 0 && self.hot_bytes > self.capacity - self.cold_target {
            self.step_hot();
        }
    }

    fn step_cold(&mut self) {
        let Some(idx) = self.hand_cold else { return };
        self.hand_cold = Some(self.nodes[idx].next);
        let node = &mut self.nodes[idx];
        if node.class != Class::Cold {
            return;
        }
        let charge = node.charge;
        self.cold_bytes -= charge;
        if node.referenced {
            node.class = Class::Hot;
            node.referenced = false;
            self.hot_bytes += charge;
            self.balance_hot();
        } else {
            node.class = Class::Test;
            node.value = None;
            self.test_bytes += charge;
            while self.test_bytes > self.capacity {
                self.step_test();
            }
        }
    }

    fn step_hot(&mut self) {
        let Some(idx) = self.hand_hot else { return };
        self.hand_hot = Some(self.nodes[idx].next);
        let node = &mut self.nodes[idx];
        match node.class {
            Class::Hot if node.referenced => node.referenced = false,
            Class::Hot => {
                node.class = Class::Cold;
                self.hot_bytes -= node.charge;
                self.cold_bytes += node.charge;
            }
            Class::Test => self.retire_test(idx),
            Class::Cold => {}
        }
    }

    fn step_test(&mut self) {
        let Some(idx) = self.hand_test else { return };
        self.hand_test = Some(self.nodes[idx].next);
        if self.nodes[idx].class == Class::Test {
            self.retire_test(idx);
        }
    }

    /// A test period ended without re-use: the block was not hot, so shrink the cold target.
    fn retire_test(&mut self, idx: usize) {
        let charge = self.nodes[idx].charge;
        self.cold_target = self.cold_target.saturating_sub(charge).max(self.min_cold);
        self.remove(idx);
    }

    /// Inserts `node` just behind `hand_hot`, i.e. at the head of the clock (newest position).
    fn link(&mut self, node: Node<V>) -> usize {
        let idx = if let Some(idx) = self.free.pop() {
            self.nodes[idx] = node;
            idx
        } else {
            self.nodes.push(node);
            self.nodes.len() - 1
        };
        if let Some(head) = self.hand_hot {
            let prev = self.nodes[head].prev;
            self.nodes[idx].prev = prev;
            self.nodes[idx].next = head;
            self.nodes[prev].next = idx;
            self.nodes[head].prev = idx;
        } else {
            self.nodes[idx].prev = idx;
            self.nodes[idx].next = idx;
            self.hand_hot = Some(idx);
            self.hand_cold = Some(idx);
            self.hand_test = Some(idx);
        }
        idx
    }

    /// Unlinks `idx`, moving any hand on it to its successor, and fixes the byte counters.
    fn remove(&mut self, idx: usize) {
        let (prev, next, charge, class, key) = {
            let n = &mut self.nodes[idx];
            n.value = None;
            (n.prev, n.next, n.charge, n.class, n.key)
        };
        match class {
            Class::Hot => self.hot_bytes -= charge,
            Class::Cold => self.cold_bytes -= charge,
            Class::Test => self.test_bytes -= charge,
        }
        self.map.remove(&key);
        let successor = (next != idx).then_some(next);
        for hand in [&mut self.hand_hot, &mut self.hand_cold, &mut self.hand_test] {
            if *hand == Some(idx) {
                *hand = successor;
            }
        }
        if successor.is_some() {
            self.nodes[prev].next = next;
            self.nodes[next].prev = prev;
        }
        self.free.push(idx);
    }
}

/// Generic sharded cache; [`BlockCache`] instantiates it with decoded SST blocks.
pub(crate) struct ShardedCache<V> {
    shards: Vec<Mutex<ClockPro<V>>>,
    /// Capacity of each shard: the configured total divided by [`SHARD_COUNT`], rounded down.
    per_shard: usize,
    hits: AtomicU64,
    misses: AtomicU64,
    rejected_oversize: AtomicU64,
}

impl<V: Clone> ShardedCache<V> {
    pub(crate) fn new(capacity: usize) -> Self {
        let per_shard = capacity / SHARD_COUNT;
        Self {
            shards: (0..SHARD_COUNT)
                .map(|_| Mutex::new(ClockPro::new(per_shard)))
                .collect(),
            per_shard,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            rejected_oversize: AtomicU64::new(0),
        }
    }

    /// Effective capacity: what the shards can hold together, i.e. the configured value
    /// rounded down to a multiple of [`SHARD_COUNT`].
    fn capacity(&self) -> usize {
        self.per_shard * SHARD_COUNT
    }

    fn shard(&self, key: CacheKey) -> MutexGuard<'_, ClockPro<V>> {
        let mixed = (key.0 ^ key.1.rotate_left(32)).wrapping_mul(SHARD_HASH_MULTIPLIER);
        // The top 6 bits select one of the 64 shards (Fibonacci hashing); lossless, < 64.
        #[allow(clippy::cast_possible_truncation)]
        let index = (mixed >> (64 - SHARD_COUNT.trailing_zeros())) as usize;
        self.lock(index)
    }

    /// Locks shard `index`, resetting it if a previous holder panicked (see the module docs):
    /// the half-updated state is dropped, never used.
    fn lock(&self, index: usize) -> MutexGuard<'_, ClockPro<V>> {
        let mutex = &self.shards[index];
        mutex.lock().unwrap_or_else(|poisoned| {
            let mut guard = poisoned.into_inner();
            *guard = ClockPro::new(self.per_shard);
            // Safe to clear while holding the guard: the state it protects was just rebuilt.
            mutex.clear_poison();
            guard
        })
    }

    pub(crate) fn lookup(&self, key: CacheKey) -> Option<V> {
        let found = self.shard(key).lookup(key);
        let counter = if found.is_some() {
            &self.hits
        } else {
            &self.misses
        };
        counter.fetch_add(1, Ordering::Relaxed);
        found
    }

    pub(crate) fn insert(&self, key: CacheKey, value: V, charge: usize, priority: Priority) {
        if !self.shard(key).insert(key, value, charge, priority) {
            self.rejected_oversize.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            usage: (0..SHARD_COUNT).map(|i| self.lock(i).usage()).sum(),
            rejected_oversize: self.rejected_oversize.load(Ordering::Relaxed),
        }
    }
}

/// Shared cache of decoded SST blocks (storage-engine.md §5), sized by
/// `storage.block_cache_size`. Share one instance between all readers through `Arc`.
pub struct BlockCache {
    inner: ShardedCache<Block>,
    next_cache_id: AtomicU64,
}

impl BlockCache {
    /// A cache holding at most `capacity` bytes of blocks (split evenly over
    /// [`SHARD_COUNT`] shards; a block larger than one shard's share is not cached and counted
    /// in [`CacheStats::rejected_oversize`]). `storage.block_cache_size` is validated to give
    /// every shard room for at least one block; this constructor accepts any value.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: ShardedCache::new(capacity),
            next_cache_id: AtomicU64::new(1),
        }
    }

    /// A fresh id for one open SST. Ids are never reused, so entries of a closed or deleted
    /// file can never be returned for another file; they simply age out.
    pub fn new_cache_id(&self) -> u64 {
        self.next_cache_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Effective capacity in bytes: the configured value rounded down to a multiple of
    /// [`SHARD_COUNT`], which is the most the shards can hold together.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Hit/miss counters and current usage.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.inner.stats()
    }

    pub(crate) fn lookup(&self, key: CacheKey) -> Option<Block> {
        self.inner.lookup(key)
    }

    pub(crate) fn insert(&self, key: CacheKey, block: Block, priority: Priority) {
        let charge = block.size() + ENTRY_OVERHEAD;
        self.inner.insert(key, block, charge, priority);
    }
}

impl std::fmt::Debug for BlockCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockCache")
            .field("capacity", &self.capacity())
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn hit_and_miss_counters() {
        let cache = ShardedCache::<u32>::new(SHARD_COUNT * 1000);
        assert_eq!(cache.lookup((1, 0)), None);
        cache.insert((1, 0), 7, 10, Priority::Low);
        assert_eq!(cache.lookup((1, 0)), Some(7));
        assert_eq!(cache.lookup((2, 0)), None);
        let stats = cache.stats();
        assert_eq!((stats.hits, stats.misses, stats.usage), (1, 2, 10));
    }

    /// A panic under a shard lock must not leave later users on a half-updated shard: the
    /// shard is rebuilt empty, the poison cleared, and the counters match the entries again.
    #[test]
    fn poisoned_shard_is_reset_and_keeps_serving() {
        let cache = Arc::new(ShardedCache::<u32>::new(SHARD_COUNT * 1000));
        let key = (1, 0);
        cache.insert(key, 7, 10, Priority::Low);
        let poisoner = Arc::clone(&cache);
        let joined = std::thread::spawn(move || {
            let mut shard = poisoner.shard(key);
            // Simulate a bookkeeping bug interrupted mid-update: counters no longer match.
            shard.hot_bytes = usize::MAX / 2;
            shard.cold_bytes = 0;
            panic!("injected panic while holding the shard lock");
        })
        .join();
        assert!(joined.is_err());
        // The poisoned shard lost its contents rather than serving inconsistent state.
        assert_eq!(cache.lookup(key), None);
        assert_eq!(cache.stats().usage, 0);
        cache.insert(key, 8, 10, Priority::Low);
        assert_eq!(cache.lookup(key), Some(8));
        assert_eq!(cache.stats().usage, 10);
        let index = cache
            .shards
            .iter()
            .position(|m| m.lock().is_ok_and(|s| s.map.contains_key(&key)));
        assert!(index.is_some_and(|i| !cache.shards[i].is_poisoned()));
    }

    #[test]
    fn effective_capacity_and_oversize_rejections_are_reported() {
        let cache = ShardedCache::<u32>::new(SHARD_COUNT * 100 + 63);
        assert_eq!(cache.capacity(), SHARD_COUNT * 100);
        // Fits the total but not one shard's share: refused and counted.
        cache.insert((1, 0), 1, 101, Priority::Low);
        cache.insert((1, 1), 1, 100, Priority::Low);
        let stats = cache.stats();
        assert_eq!((stats.rejected_oversize, stats.usage), (1, 100));
        // Below one byte per shard nothing can be cached at all.
        let tiny = ShardedCache::<u32>::new(SHARD_COUNT - 1);
        assert_eq!(tiny.capacity(), 0);
        tiny.insert((1, 0), 1, 1, Priority::High);
        assert_eq!(tiny.stats().rejected_oversize, 1);
    }

    #[test]
    fn replace_keeps_reference_bit() {
        let mut shard = ClockPro::<u32>::new(100);
        shard.insert((0, 0), 1, 10, Priority::Low);
        assert_eq!(shard.lookup((0, 0)), Some(1));
        // A racing reader re-inserts the same block at low priority.
        shard.insert((0, 0), 1, 10, Priority::Low);
        let idx = shard.map[&(0, 0)];
        assert!(shard.nodes[idx].referenced);
        // So the cold hand promotes it instead of evicting it.
        for i in 1..=20 {
            shard.insert((1, i), 0, 10, Priority::Low);
        }
        assert_eq!(shard.lookup((0, 0)), Some(1));
    }

    #[test]
    fn oversized_entry_is_not_cached() {
        let mut shard = ClockPro::<u32>::new(100);
        shard.insert((0, 0), 1, 101, Priority::High);
        assert_eq!(shard.lookup((0, 0)), None);
        assert_eq!(shard.usage(), 0);
    }

    #[test]
    fn oversized_replace_drops_old_entry() {
        let mut shard = ClockPro::<u32>::new(100);
        shard.insert((0, 0), 1, 30, Priority::Low);
        assert!(!shard.insert((0, 0), 2, 101, Priority::Low));
        assert_eq!(shard.lookup((0, 0)), None);
        assert_eq!(shard.usage(), 0);
    }

    #[test]
    fn replace_updates_value_and_charge() {
        let mut shard = ClockPro::<u32>::new(100);
        shard.insert((0, 0), 1, 30, Priority::Low);
        shard.insert((0, 0), 2, 50, Priority::Low);
        assert_eq!(shard.lookup((0, 0)), Some(2));
        assert_eq!(shard.usage(), 50);
    }

    /// The property CLOCK-Pro is chosen for: a one-time scan many times the capacity does not
    /// evict a hot working set that is in use.
    #[test]
    fn scan_does_not_evict_hot_working_set() {
        const CAP: usize = 1000;
        let mut shard = ClockPro::<u64>::new(CAP);
        let hot: Vec<CacheKey> = (0..30).map(|i| (1, i)).collect();
        // Working set: 30 % of the capacity, accessed repeatedly while other blocks come and go.
        for round in 0..20u64 {
            for &k in &hot {
                if shard.lookup(k).is_none() {
                    shard.insert(k, k.1, 10, Priority::Low);
                }
            }
            for j in 0..20 {
                shard.insert((3, round * 100 + j), 0, 10, Priority::Low);
            }
        }
        // One-time scan: 10x the capacity, interleaved with working-set use as in a real
        // workload (the working set is touched once per 50 scanned blocks).
        for i in 0..1000u64 {
            shard.insert((2, i), i, 10, Priority::Low);
            if i % 50 == 0 {
                for &k in &hot {
                    assert!(
                        shard.lookup(k).is_some(),
                        "hot key {k:?} evicted at scan {i}"
                    );
                }
            }
            assert!(shard.usage() <= CAP);
        }
        for &k in &hot {
            assert!(shard.lookup(k).is_some(), "hot key {k:?} evicted by scan");
        }
    }

    #[test]
    fn high_priority_entries_outlive_a_scan_of_low_priority_ones() {
        let mut shard = ClockPro::<u64>::new(1000);
        shard.insert((9, 0), 0, 10, Priority::High);
        for i in 0..500u64 {
            shard.insert((2, i), i, 10, Priority::Low);
        }
        assert!(shard.lookup((9, 0)).is_some());
    }

    #[derive(Debug, Clone)]
    enum Op {
        Get(u64),
        Put(u64, usize, bool),
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0..64u64).prop_map(Op::Get),
            (0..64u64, 1..120usize, any::<bool>()).prop_map(|(k, c, h)| Op::Put(k, c, h)),
        ]
    }

    proptest! {
        /// Usage never exceeds the capacity, counters stay consistent with the entries, and a
        /// hit always returns the value last inserted for that key.
        #[test]
        fn clock_pro_invariants(ops in prop::collection::vec(arb_op(), 1..400)) {
            const CAP: usize = 500;
            let mut shard = ClockPro::<(u64, usize)>::new(CAP);
            let mut last = HashMap::new();
            for op in ops {
                match op {
                    Op::Get(k) => {
                        if let Some(v) = shard.lookup((0, k)) {
                            prop_assert_eq!(Some(&v), last.get(&k));
                        }
                    }
                    Op::Put(k, c, high) => {
                        let prio = if high { Priority::High } else { Priority::Low };
                        shard.insert((0, k), (k, c), c, prio);
                        last.insert(k, (k, c));
                    }
                }
                prop_assert!(shard.usage() <= CAP);
                prop_assert!(shard.test_bytes <= CAP);
                let (mut hot, mut cold, mut test) = (0, 0, 0);
                for &idx in shard.map.values() {
                    let n = &shard.nodes[idx];
                    match n.class {
                        Class::Hot => hot += n.charge,
                        Class::Cold => cold += n.charge,
                        Class::Test => test += n.charge,
                    }
                    prop_assert_eq!(n.value.is_some(), n.class != Class::Test);
                }
                prop_assert_eq!((hot, cold, test), (shard.hot_bytes, shard.cold_bytes, shard.test_bytes));
                prop_assert!(shard.cold_target >= shard.min_cold && shard.cold_target <= CAP);
            }
        }
    }

    #[test]
    fn concurrent_stress_keeps_capacity_and_values() {
        const CAP: usize = SHARD_COUNT * 2000;
        let cache = Arc::new(ShardedCache::<(u64, u64)>::new(CAP));
        let threads: Vec<_> = (0..8u64)
            .map(|t| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || {
                    let mut x = t + 1;
                    for _ in 0..20_000 {
                        // xorshift: cheap deterministic per-thread key stream.
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        let key = (x % 4, x % 3000);
                        match cache.lookup(key) {
                            Some(v) => assert_eq!(v, key),
                            None => cache.insert(key, key, 50 + (x % 100) as usize, Priority::Low),
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let stats = cache.stats();
        assert!(stats.usage <= CAP);
        assert_eq!(stats.hits + stats.misses, 8 * 20_000);
        assert!(stats.hits > 0);
    }
}
