// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The statistics job in the embedded test API (M3 wave 2 lane G; query-engine.md §2, §2.1,
//! §8; FR-IDX-004 index sizes).
//!
//! [`EmbeddedDb::analyze`] runs in two transactions:
//! 1. a **read-only** SERIALIZABLE transaction (one snapshot; it takes no write intents, so
//!    writers are never blocked by it) reads the collection's indexes, every document (fed to
//!    [`StatsCollector`]), every index span (entry count and bytes) and the previous record;
//! 2. a small write transaction stores the new record under `0x02 't' collection_id` (stats
//!    format 1).
//!
//! The two steps are not atomic on purpose: statistics are advisory and a concurrent `analyze`
//! simply wins last. A previous record that does not decode (corrupt, or a future format) is
//! treated as absent and overwritten — statistics are derived data and can always be
//! recollected. The read loads the collection in one scan, bounded like the synchronous index
//! build; the resumable, throttled job belongs to the jobs framework (later milestone).
//!
//! **Planner statistics** (M3 wave 3 lane J; FR-QL-001, *Provisional (PD-040)*): the query
//! engine's cost-based chooser reads statistics from a process-wide cache ([`StatsCache`]),
//! never through the query's transaction — a read of the stats key would join the read set of
//! every query and make each `analyze` conflict with concurrent readers. Policy:
//! - loaded lazily: the first query (or explicit transaction) after open reads every stored
//!   record in one read-only transaction; undecodable records are skipped (the collection is
//!   then planned by the rules); a failed load leaves the cache empty and is retried by the next
//!   query;
//! - refreshed write-through: [`EmbeddedDb::analyze`] puts its record into a loaded cache after
//!   the record committed; [`EmbeddedDb::reload_statistics`] drops the cache (next query
//!   reloads);
//! - correctness under MVCC does not depend on it: the statistics may be older or newer than
//!   the query's snapshot, or lost to a race between two `analyze` calls; they only choose
//!   among plans that all return the same rows.
//!
//! [`EmbeddedDb::index_stats`] exposes FR-IDX-004 for one index: sizes from the stored record
//! and the executor's in-memory usage counters.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use rustegon_catalog::{
    IndexState,
    index::ops::{list_indexes, require_index},
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    keyspace::{Family, family_prefix},
    rdoc,
};
use rustegon_index::index_span;
use rustegon_query::stats::{
    CollectionStats, IndexSize, IndexUsage, STATS_CHANGE_THRESHOLD, StatsCollector, StatsConfig,
    decode_stats, encode_stats, significant_change, stats_key, stats_prefix,
};
use rustegon_txn::{AccessMode, TxnError, TxnOptions};

use super::{
    Body, EmbeddedDb, MAX_ATTEMPTS, NANOS_PER_MILLI, catalog, existing_collection, prefix_end,
    version_ts,
};

/// Result of [`EmbeddedDb::analyze`].
#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzeOutcome {
    /// The statistics just collected and stored.
    pub stats: CollectionStats,
    /// The record they replaced, if any (and readable).
    pub previous: Option<CollectionStats>,
    /// Whether cached plans of the collection must be invalidated (query-engine.md §8:
    /// statistics changed by more than 20 %, or there were none before).
    pub invalidate_plans: bool,
}

impl EmbeddedDb {
    /// Collects and stores the statistics of `database.collection` (module docs).
    ///
    /// # Errors
    /// `RGN-1001` (invalid `config`), `RGN-1030` (database or collection missing), `RGN-5002`
    /// (undecodable document), transaction errors.
    pub fn analyze(
        &self,
        database: &str,
        collection: &str,
        config: &StatsConfig,
    ) -> Result<AnalyzeOutcome, Error> {
        config
            .validate()
            .map_err(|m| Error::new(ErrorCode::InvalidArgument, m))?;
        let read_only = TxnOptions {
            access: AccessMode::ReadOnly,
            ..TxnOptions::default()
        };
        let (collected, _) = self.coord.run(&read_only, MAX_ATTEMPTS, |txn| {
            collect(txn, database, collection, config)
        })?;
        let (stats, previous) = collected?;
        let bytes = encode_stats(&stats)?;
        let key = stats_key(stats.collection_id);
        self.run(|txn| {
            txn.put(&key, bytes.clone())?;
            Ok(Ok(()))
        })?;
        self.stats_cache.put(&stats);
        let invalidate_plans = previous
            .as_ref()
            .is_none_or(|p| significant_change(p, &stats, STATS_CHANGE_THRESHOLD));
        Ok(AnalyzeOutcome {
            stats,
            previous,
            invalidate_plans,
        })
    }

    /// The stored statistics of `database.collection`, `None` if never analyzed (or the
    /// collection is missing).
    ///
    /// # Errors
    /// `RGN-1030` for a missing database, `RGN-5002` for an undecodable record, transaction
    /// errors.
    pub fn collection_stats(
        &self,
        database: &str,
        collection: &str,
    ) -> Result<Option<CollectionStats>, Error> {
        self.run(|txn| {
            let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
                return Ok(Ok(None));
            };
            Ok(match txn.get(&stats_key(coll.id))? {
                None => Ok(None),
                Some(b) => decode_stats(&b).map(Some),
            })
        })
    }
}

/// FR-IDX-004 statistics of one index ([`EmbeddedDb::index_stats`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexStats {
    /// Index id.
    pub index_id: u32,
    /// Index name.
    pub name: String,
    /// Entries at the last `analyze` (`None`: not measured yet).
    pub entries: Option<u64>,
    /// Bytes (keys + values) at the last `analyze` (`None`: not measured yet).
    pub bytes: Option<u64>,
    /// Usage since the node started (ops = lookups + scans, entries read, last use).
    pub usage: IndexUsage,
}

/// Process-wide cache of the stored statistics records (module docs, "Planner statistics").
/// `None` = not loaded. The map is replaced, never mutated in place, so readers keep a
/// consistent snapshot without holding the lock.
#[derive(Debug, Default)]
pub(super) struct StatsCache {
    map: Mutex<Option<StatsMap>>,
}

/// Statistics by collection id.
type StatsMap = Arc<BTreeMap<u32, Arc<CollectionStats>>>;

impl StatsCache {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<StatsMap>> {
        // A poisoned lock is recovered: the guarded value is replaced atomically.
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The cached statistics of `collection_id` (`None`: not analyzed, or not loaded).
    pub(super) fn get(&self, collection_id: u32) -> Option<Arc<CollectionStats>> {
        self.lock()
            .as_ref()
            .and_then(|m| m.get(&collection_id).cloned())
    }

    fn loaded(&self) -> bool {
        self.lock().is_some()
    }

    /// Write-through of a committed record; a cache not loaded yet reads it from storage.
    fn put(&self, stats: &CollectionStats) {
        let mut guard = self.lock();
        if let Some(map) = guard.as_ref() {
            let mut next = BTreeMap::clone(map);
            next.insert(stats.collection_id, Arc::new(stats.clone()));
            *guard = Some(Arc::new(next));
        }
    }

    fn clear(&self) {
        *self.lock() = None;
    }
}

impl EmbeddedDb {
    /// Loads the statistics cache if needed (module docs). A failure leaves it unloaded:
    /// statistics are advisory, the query is then planned by the rules.
    pub(super) fn load_statistics(&self) {
        if self.stats_cache.loaded() {
            return;
        }
        let read_only = TxnOptions {
            access: AccessMode::ReadOnly,
            ..TxnOptions::default()
        };
        let prefix = stats_prefix();
        let Some(end) = prefix_end(&prefix) else {
            return;
        };
        let loaded = self.coord.run(&read_only, MAX_ATTEMPTS, |txn| {
            let mut map = BTreeMap::new();
            for (_, bytes) in txn.scan(&prefix, &end, usize::MAX)? {
                // An undecodable record is skipped (module docs).
                if let Ok(stats) = decode_stats(&bytes) {
                    map.insert(stats.collection_id, Arc::new(stats));
                }
            }
            Ok(map)
        });
        if let Ok((map, _)) = loaded {
            let mut guard = self.stats_cache.lock();
            if guard.is_none() {
                *guard = Some(Arc::new(map));
            }
        }
    }

    /// Drops the planner's statistics cache; the next query reloads every stored record.
    pub fn reload_statistics(&self) {
        self.stats_cache.clear();
    }

    /// FR-IDX-004 statistics of index `index` of `database.collection` (module docs).
    ///
    /// # Errors
    /// `RGN-1030` (database or collection missing), `RGN-1021` (no such index), transaction
    /// errors.
    pub fn index_stats(
        &self,
        database: &str,
        collection: &str,
        index: &str,
    ) -> Result<IndexStats, Error> {
        let ix = self.run(|txn| {
            let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
                return Ok(Err(Error::new(
                    ErrorCode::NotFound,
                    format!("collection not found: {collection}"),
                )
                .with_detail("kind", "collection")
                .with_detail("name", collection)));
            };
            catalog(txn, |r| require_index(r, &coll, index))
        })?;
        self.load_statistics();
        let size = self.stats_cache.get(ix.collection_id).and_then(|s| {
            s.indexes
                .iter()
                .find(|i| i.index_id == ix.id)
                .map(|i| (i.entries, i.bytes))
        });
        Ok(IndexStats {
            index_id: ix.id,
            name: ix.name,
            entries: size.map(|s| s.0),
            bytes: size.map(|s| s.1),
            usage: self.usage.get(ix.id),
        })
    }
}

/// The read-only body of [`EmbeddedDb::analyze`].
fn collect(
    txn: &mut rustegon_txn::Txn,
    database: &str,
    collection: &str,
    config: &StatsConfig,
) -> Body<(CollectionStats, Option<CollectionStats>)> {
    let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
        return Ok(Err(Error::new(
            ErrorCode::NotFound,
            format!("collection not found: {collection}"),
        )
        .with_detail("kind", "collection")
        .with_detail("name", collection)));
    };
    let indexes: Vec<_> = req!(catalog(txn, |r| list_indexes(r, coll.id))?)
        .into_iter()
        .filter(|i| i.state != IndexState::Dropping)
        .collect();
    let paths: Vec<String> = indexes
        .iter()
        .flat_map(|i| i.fields.iter().map(|f| f.path.clone()))
        .collect();
    let mut collector = StatsCollector::new(config.clone(), coll.database_id, coll.id, &paths);
    let start = family_prefix(coll.database_id, coll.id, Family::Document);
    let Some(end) = prefix_end(&start) else {
        return Err(TxnError::Internal("document span without end".into()));
    };
    for (_, bytes) in txn.scan(&start, &end, usize::MAX)? {
        let doc = req!(rdoc::decode(&bytes).map_err(Error::from));
        collector.add_document(&doc, bytes.len());
    }
    let mut sizes = Vec::with_capacity(indexes.len());
    for ix in &indexes {
        let (s, e) = req!(index_span(ix));
        let (mut entries, mut bytes) = (0u64, 0u64);
        for (k, v) in txn.scan(&s, &e, usize::MAX)? {
            entries += 1;
            bytes += (k.len() + v.len()) as u64;
        }
        sizes.push(IndexSize {
            index_id: ix.id,
            entries,
            bytes,
        });
    }
    let previous = txn
        .get(&stats_key(coll.id))?
        .and_then(|b| decode_stats(&b).ok());
    let millis = version_ts(txn).wall / NANOS_PER_MILLI;
    let mut stats = collector.finish(i64::try_from(millis).unwrap_or(i64::MAX));
    stats.indexes = sizes;
    Ok(Ok((stats, previous)))
}
