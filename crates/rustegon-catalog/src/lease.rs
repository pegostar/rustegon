// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Local descriptor cache keyed by descriptor version (database-engine.md §2.2, §2.5).
//!
//! **Local only (M2).** This is the per-node cache the gateway resolves descriptors from. It
//! holds no cluster-wide schema lease: the lease protocol (5 min leases, two-version invariant,
//! DDL waiting for old leases to drain) arrives with multi-node operation in M6. Until then a
//! single node is the only user of its descriptors, and freshness comes from version checks:
//! a newer version always replaces an older one, an older one never overwrites a newer one, and
//! a caller that learns about a newer version (e.g. `RGN-1034 DescriptorVersionMismatch`)
//! invalidates the entry and re-reads it.
//!
//! The cache is a plain value (`&mut self`); a shared server instance wraps it in its own lock.

use std::collections::HashMap;

use crate::descriptor::{Descriptor, DescriptorState};

/// What [`LeaseCache::insert`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheUpdate {
    /// The id was not cached.
    Inserted,
    /// An older version was replaced.
    Replaced,
    /// The cached version is the same or newer; nothing changed.
    Stale,
}

/// Descriptor cache by id and by `(parent id, name)`.
#[derive(Debug, Default)]
pub struct LeaseCache {
    by_id: HashMap<u32, Descriptor>,
    /// parent id → name → id; only public descriptors have a name entry (dropped names are
    /// free for reuse by a new object with a new id).
    by_name: HashMap<u32, HashMap<String, u32>>,
}

impl LeaseCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Caches `desc` unless the same or a newer version of that id is already cached.
    pub fn insert(&mut self, desc: Descriptor) -> CacheUpdate {
        let outcome = match self.by_id.get(&desc.id()) {
            Some(cur) if cur.version() >= desc.version() => return CacheUpdate::Stale,
            Some(_) => CacheUpdate::Replaced,
            None => CacheUpdate::Inserted,
        };
        self.remove(desc.id());
        if desc.state() == DescriptorState::Public {
            self.by_name
                .entry(desc.parent_id())
                .or_default()
                .insert(desc.name().to_owned(), desc.id());
        }
        self.by_id.insert(desc.id(), desc);
        outcome
    }

    /// The cached descriptor with id `id`.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&Descriptor> {
        self.by_id.get(&id)
    }

    /// The cached public descriptor named `name` under `parent_id`
    /// ([`crate::keys::ROOT_PARENT_ID`] for databases).
    #[must_use]
    pub fn get_by_name(&self, parent_id: u32, name: &str) -> Option<&Descriptor> {
        let id = self.by_name.get(&parent_id)?.get(name)?;
        self.by_id.get(id)
    }

    /// Drops the entry of `id` if its cached version is older than `version`; returns whether
    /// an entry was dropped. Used when a newer version is observed elsewhere.
    pub fn invalidate_older_than(&mut self, id: u32, version: u64) -> bool {
        match self.by_id.get(&id) {
            Some(cur) if cur.version() < version => {
                self.remove(id);
                true
            }
            _ => false,
        }
    }

    /// Removes the entry of `id` (and its name entry) if cached.
    pub fn remove(&mut self, id: u32) {
        let Some(old) = self.by_id.remove(&id) else {
            return;
        };
        let parent = old.parent_id();
        if let Some(names) = self.by_name.get_mut(&parent) {
            // Only remove the name if it still points at this id (another object may have taken
            // the name after a drop).
            if names.get(old.name()) == Some(&id) {
                names.remove(old.name());
            }
            if names.is_empty() {
                self.by_name.remove(&parent);
            }
        }
    }

    /// Number of cached descriptors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}
