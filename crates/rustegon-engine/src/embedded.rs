// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Node-local engine API (M2, development-phases.md; moved out of `rustegon-sim` by PD-044):
//! document `insert` / `get` / `replace` / `delete` over the single-range [`TxnCoordinator`],
//! the catalog and the document codec, on the Raft-less [`LocalReplica`]. No network, no
//! sessions, no privileges: the server (M4) adds those around it, while the M2/M3 exit tests
//! (TC-DOC-007/008, TC-SCH-001, TC-QL-*) and the simulation workloads drive it directly.
//!
//! Every call is one SERIALIZABLE transaction run through [`TxnCoordinator::run`] (retried on
//! retryable errors), so implicit collection creation and the document write commit atomically
//! (catalog mutations are applied in the writing transaction, `rustegon_catalog::ops`).
//!
//! Server-maintained fields (FR-DOC-005, data-model.md §2.2, §9):
//! - `_id` (FR-DOC-002): generated as an `objectId` when absent on insert; a replace may repeat
//!   it but not change it (`RGN-1001`). Stored first.
//! - `_rev`: base32hex (RFC 4648 §7, lowercase, unpadded) of `ts ‖ site_id` (data-model.md §9),
//!   so revisions of one document sort like their timestamps.
//! - `_createdAt` / `_updatedAt`: `datetime` (ms) of the same timestamp; `_createdAt` is kept
//!   by a replace.
//! - User input naming `_rev`, `_createdAt`, `_updatedAt`, `_conflict` or `_origin` at top level
//!   is rejected with `RGN-1004`; `_expiresAt` is ordinary writable data.
//!
//! Secondary indexes (M3, FR-IDX-001/002; `embedded/indexes.rs`): every write maintains the
//! collection's non-dropping indexes in the same transaction, before the document write, so a
//! rejected index write (`RGN-1005` duplicate unique key, `RGN-1008`, `RGN-1025`) leaves nothing
//! behind. Indexes are created by the online build job (FR-IDX-003), driven step by step.
//!
//! RGQL (M3 lane F; `embedded/query.rs`): [`EmbeddedDb::query`] executes statements with the
//! `rustegon-query` engine in an implicit transaction, [`EmbeddedDb::transaction`] several in an
//! explicit one; the engine's writes use the same write path as the document methods
//! (`embedded/write.rs`: validators, then indexes, then the document). Partial-index
//! predicates are evaluated by the engine's evaluator, installed by [`EmbeddedDb::open`].
//!
//! Server handles (M4 wave 2a, PD-049; `embedded/interactive.rs`, `embedded/cursor.rs`):
//! [`EmbeddedDb::begin`] starts a client-driven [`Transaction`] (statements and document
//! operations over several calls, never retried by the engine) and
//! [`EmbeddedDb::open_owned_cursor`] an [`OwnedCursor`]; both are `Send + 'static` and can be
//! cancelled from another thread ([`CancelHandle`]).
//!
//! The timestamp used is `max(write_ts, read_ts.next())` taken when the document is written,
//! not the final commit timestamp, which is unknown until commit (the value is encoded before
//! the intent is written). It is strictly increasing per document: the previous version was
//! visible at `read_ts`, so its own timestamp is `<= read_ts`. See the proposed PD in the M2 T9
//! report; exact `commit_ts` revisions need the value to be finalised at commit.

use std::{cell::RefCell, path::Path, sync::Arc};

use rustegon_catalog::{
    CatalogError, CatalogRead, CollectionDescriptor, CollectionOptions, CollectionSpec,
    DatabaseDescriptor, DatabaseOptions, Mutation, ValidatorCache, create_collection,
    create_database, get_collection, get_database, ops::KvPairs, set_collection_options,
};
use rustegon_cluster::{LocalReplica, LocalReplicaConfig};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, ObjectIdGenerator, Value, keyspace::document_key, limits::validate_user_document,
    rdoc,
};
use rustegon_mvcc::{GcThreshold, Hlc, MvccGcFilter, Replica, Timestamp};
use rustegon_sim_api::{Clock, FileSystem, Rng};
use rustegon_storage::{EngineOptions, LsmEngine};
use rustegon_txn::{Txn, TxnConfig, TxnCoordinator, TxnError, TxnOptions};

/// `_id` field name.
pub const ID: &str = "_id";
/// `_rev` field name.
pub const REV: &str = "_rev";
/// `_createdAt` field name.
pub const CREATED_AT: &str = "_createdAt";
/// `_updatedAt` field name.
pub const UPDATED_AT: &str = "_updatedAt";
/// Site id encoded in `_rev` (data-model.md §9). XDC (M10) assigns real ids; a single site is
/// site 0. Width (u16 BE) is not specified yet — see the proposed PD in the M2 T9 report.
pub const LOCAL_SITE_ID: u16 = 0;
/// Range id of the embedded store's single range.
pub const RANGE_ID: u64 = 1;
/// Attempts of one API call on retryable transaction errors (conflicts, deadlock victims).
pub const MAX_ATTEMPTS: u32 = 16;
/// Engine directory under the store root.
const LSM_DIR: &str = "lsm";
/// Log store directory under the store root (storage-engine.md §2).
const LOG_DIR: &str = "raft-log";
/// Nanoseconds per millisecond (HLC wall is ns, `datetime` is ms).
const NANOS_PER_MILLI: u64 = 1_000_000;

/// Result of a transaction body: the outer error is the transaction's (retried by
/// [`TxnCoordinator::run`]), the inner one a request error (returned as is). A body returns an
/// inner error only before it wrote anything, so committing that transaction is a no-op.
type Body<T> = Result<Result<T, Error>, TxnError>;

/// Unwraps a request result inside a transaction body, returning a request error as such.
macro_rules! req {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Ok(Err(e.into())),
        }
    };
}

// DDL statements of RGQL through the embedded API (M3).
mod ddl;
// Secondary indexes (M3): maintenance in every write path, synchronous build, range reads.
mod indexes;
// RGQL statements (M3 lane F): `query`, explicit transactions, the `QueryStore` adapter.
mod query;
// The single document write path shared by the document API and the query engine.
mod write;

pub use indexes::SharedPartialFilter;
// Statistics job (M3 wave 2 lane G): analyze, stored statistics.
mod analyze;
pub use analyze::{AnalyzeOutcome, IndexStats};
// Server-side cursors and continuation tokens (M3 wave 3, FR-QL-006/007).
mod cursor;
pub use cursor::{Cursor, CursorOptions, OwnedCursor};
// Interactive transactions for the server (M4 wave 2a, PD-049).
mod interactive;
pub use interactive::{CancelHandle, Transaction, TransactionStatus, format_txn_id, parse_txn_id};
// Raw system-keyspace transactions for security records and settings (M4 lane H, PD-051).
mod system;
// Catalog listing and drops for the server's SchemaService (M4 wave 2b lane G, PD-053).
mod schema;
// Encryption at rest: the store's DEK registries under a KEK (M4 wave 3 lane M, PD-057).
mod keys;
pub use query::{QueryInput, QuerySession};
pub use system::SystemTxnHandle;
// The store directory lock (M13a lane BD, PD-068).
mod lock;
pub use lock::{LOCK_FILE, StoreLock};
// Backup primitives (M13a lane BD): the write fence, consistent checkpoints, GC pins, revert
// to a timestamp, and opening a restored store (PD-063, PD-067).
mod backup;
pub use backup::{
    CancelCheck, ConsistentCheckpoint, DEFAULT_FENCE_TIMEOUT, FenceOptions, GcOutcome,
    PinnedSnapshot, RESTORE_MARKER, RestorePoint, RevertOutcome,
};
// The log-archive primitives a point-in-time archiver and restore need (FR-BKP-002/004,
// PD-066), so `rustegon-backup` reaches them through the engine (PD-062 edge backup -> engine).
pub use rustegon_raft::{
    LogStoreOptions, SealedSegment, SegmentEntry, SegmentKey, SegmentReader, read_segment,
};
// Logical dump and import (M13a lane BD, PD-067): scans at a pinned timestamp, bulk load.
mod logical;
pub use logical::{ImportOptions, ImportOutcome, ScanOptions, SnapshotScan};

/// An embedded single-node, single-range document store (module docs).
pub struct EmbeddedDb {
    coord: TxnCoordinator,
    oids: ObjectIdGenerator,
    replica: Arc<LocalReplica>,
    /// Compiled collection validators (FR-SCH-002).
    validators: ValidatorCache,
    filter: indexes::FilterSlot,
    /// Monotonic time for query deadlines (`max_time_ms`).
    clock: Arc<dyn Clock>,
    /// Planner statistics read from the stored records (`embedded/analyze.rs`).
    stats_cache: analyze::StatsCache,
    /// Index usage counters fed by the query executor (FR-IDX-004).
    usage: rustegon_query::stats::IndexUsageRegistry,
    /// The store's key managers when it is encrypted at rest (`embedded/keys.rs`).
    keys: Option<keys::StoreKeys>,
    /// The MVCC GC threshold and its pins (`embedded/backup.rs`; PD-067).
    gc: Arc<GcThreshold>,
    /// The store directory lock, held for the lifetime of the handle (`embedded/lock.rs`,
    /// PD-068). Declared last: dropped after the engine, so no second open can start while
    /// this one still writes.
    _store_lock: StoreLock,
}

impl std::fmt::Debug for EmbeddedDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedDb")
            .field("coord", &self.coord)
            .field("replica", &self.replica)
            .field("filter", &self.filter)
            .finish_non_exhaustive()
    }
}

impl EmbeddedDb {
    /// Opens (or recovers) a store under `root` on `fs`; `clock` and `rng` drive the HLC,
    /// transaction ids and `objectId` generation, so a simulated clock and a seeded `rng` make
    /// runs reproducible (ADR-029).
    ///
    /// The HLC starts from `clock` without a persisted bound (the server's `HLC_BOUND` file is
    /// not used here): on a reopen, `clock` must be past every timestamp of the previous run,
    /// or reads would be served below committed versions.
    ///
    /// # Errors
    /// `RGN-3002` while the store lock is held or the store holds an unfinished restore
    /// (`RESTORING`, finish it with the restore command); storage and log store errors while
    /// opening or replaying the store.
    pub fn open(
        fs: Arc<dyn FileSystem>,
        root: &Path,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> Result<Self, Error> {
        Self::open_with_options(fs, root, clock, rng, EngineOptions::default())
    }

    /// [`EmbeddedDb::open`] with explicit storage options, e.g.
    /// `EngineOptions::from_settings(&storage_settings)` (block cache and memtable sizes from
    /// `[storage]`). No encryption at rest unless `options.encryption` carries a key manager;
    /// an encrypted store is refused with `RGN-4006` (see [`EmbeddedDb::open_with_kek`]).
    ///
    /// # Errors
    /// As [`EmbeddedDb::open`].
    pub fn open_with_options(
        fs: Arc<dyn FileSystem>,
        root: &Path,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        options: EngineOptions,
    ) -> Result<Self, Error> {
        Self::open_with_kek(fs, root, clock, rng, options, None)
    }

    /// [`EmbeddedDb::open_with_options`] with encryption at rest under `kek` (FR-EAR-001/002,
    /// PD-057), the provider `StorageSettings::kek_provider` builds from `[storage]`: every
    /// SST, MANIFEST and Raft log segment written from now on is encrypted with its own DEK
    /// (layout and rules in `embedded/keys.rs`). A plaintext store switches to encryption at
    /// this reopen; its existing files stay plaintext until rewritten
    /// ([`EmbeddedDb::plaintext_sst_count`]). With `kek = None` an encrypted store is refused.
    ///
    /// # Errors
    /// `RGN-4006 KeyUnavailable` when the KEK does not match the store's registries, a DEK
    /// does not unwrap, or the store is encrypted and `kek` is `None`; otherwise as
    /// [`EmbeddedDb::open`].
    pub fn open_with_kek(
        fs: Arc<dyn FileSystem>,
        root: &Path,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        options: EngineOptions,
        kek: Option<Arc<dyn rustegon_storage::encryption::KekProvider>>,
    ) -> Result<Self, Error> {
        Self::open_with_log_options(
            fs,
            root,
            clock,
            rng,
            options,
            kek,
            LogStoreOptions::default(),
        )
    }

    /// [`EmbeddedDb::open_with_kek`] with explicit Raft log store options, e.g. an
    /// [`LogStoreOptions::archive_floor`] that keeps log segments until the PITR archiver has
    /// copied them (FR-BKP-004, PD-066). It must be given here, at open: the open itself runs
    /// a deletion pass. `log_options.encryption` is ignored; the log's key manager comes from
    /// `kek` as in [`EmbeddedDb::open_with_kek`].
    ///
    /// # Errors
    /// As [`EmbeddedDb::open_with_kek`].
    pub fn open_with_log_options(
        fs: Arc<dyn FileSystem>,
        root: &Path,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        options: EngineOptions,
        kek: Option<Arc<dyn rustegon_storage::encryption::KekProvider>>,
        log_options: LogStoreOptions,
    ) -> Result<Self, Error> {
        // First, before any file of the store is read or written (PD-068).
        let store_lock = StoreLock::acquire(fs.as_ref(), root)?;
        backup::refuse_unfinished_restore(fs.as_ref(), root)?;
        Self::open_locked(store_lock, fs, root, clock, rng, options, kek, log_options)
    }

    /// [`EmbeddedDb::open_with_log_options`] with the store lock already held.
    #[allow(clippy::too_many_arguments)]
    fn open_locked(
        store_lock: StoreLock,
        fs: Arc<dyn FileSystem>,
        root: &Path,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        mut options: EngineOptions,
        kek: Option<Arc<dyn rustegon_storage::encryption::KekProvider>>,
        mut log_options: LogStoreOptions,
    ) -> Result<Self, Error> {
        log_options.encryption = None;
        // MVCC GC (PD-067): the threshold starts at the beginning of time, so nothing is
        // collected until `collect_garbage` advances it; the compaction filter then drops what
        // that threshold makes garbage, never anything a pinned snapshot can still see.
        let gc = Arc::new(GcThreshold::default());
        if options.compaction_filter.is_none() {
            options.compaction_filter = Some(Arc::new(MvccGcFilter::new(Arc::clone(&gc))));
        }
        // A caller-built key manager (tests) is used as is for the LSM.
        let store_keys = if options.encryption.is_some() && kek.is_none() {
            None
        } else {
            keys::open_store_keys(&fs, root, kek, &rng)?
        };
        if let Some(k) = &store_keys {
            options.encryption = Some(Arc::clone(&k.lsm));
            log_options.encryption = Some(Arc::clone(&k.log));
        }
        let engine = Arc::new(LsmEngine::open(
            Arc::clone(&fs),
            &root.join(LSM_DIR),
            options,
        )?);
        let replica = Arc::new(LocalReplica::open(LocalReplicaConfig {
            fs,
            log_dir: root.join(LOG_DIR),
            log_options,
            engine,
            gc: Some(Arc::clone(&gc)),
            range_id: RANGE_ID,
        })?);
        let hlc = Arc::new(Hlc::new(Arc::clone(&clock)));
        let oids = ObjectIdGenerator::new(Arc::clone(&clock), rng.as_ref());
        let dyn_replica: Arc<dyn Replica> = Arc::clone(&replica) as Arc<dyn Replica>;
        let coord = TxnCoordinator::new(
            dyn_replica,
            hlc,
            Arc::clone(&clock),
            rng,
            TxnConfig::default(),
        );
        let db = Self {
            coord,
            oids,
            replica,
            validators: ValidatorCache::new(),
            filter: indexes::FilterSlot::default(),
            clock,
            stats_cache: analyze::StatsCache::default(),
            usage: rustegon_query::stats::IndexUsageRegistry::new(),
            keys: store_keys,
            gc,
            _store_lock: store_lock,
        };
        // Partial-index predicates are evaluated by the query engine's evaluator.
        db.set_partial_filter(Arc::new(rustegon_query::partial::ExprPartialFilter::new()));
        Ok(db)
    }

    /// Whether the store is encrypted at rest (opened with a KEK).
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.keys.is_some()
    }

    /// For an encrypted store, the number of live SSTs without a DEK: files written before the
    /// store switched to encryption, still plaintext until compaction rewrites them
    /// (storage-engine.md §7; `rustegond` warns while it is non-zero, PD-057). `None` for a
    /// plaintext store.
    #[must_use]
    pub fn plaintext_sst_count(&self) -> Option<usize> {
        let keys = self.keys.as_ref()?;
        let registered = keys.lsm.file_numbers();
        let version = self.replica.engine().current_version();
        Some(
            version
                .all_files()
                .filter(|(_, f)| registered.binary_search(&f.number).is_err())
                .count(),
        )
    }

    /// Flushes every memtable to SSTs and purges the log entries they cover (a checkpoint of
    /// the in-memory state; `rustegond` runs it at graceful shutdown, PD-057). Not needed for
    /// durability (the log is the WAL); it bounds the replay at the next open and moves the
    /// data from the log into SSTs.
    ///
    /// # Errors
    /// Storage and log store errors; the data stays durable in the log either way.
    pub fn flush(&self) -> Result<(), Error> {
        self.replica.engine().flush()?;
        self.replica.purge_flushed()?;
        Ok(())
    }

    /// Background flush step (`rustegond` maintenance scheduler, PD-061): flushes the immutable
    /// memtables waiting for it — never the active one — and purges the log entries they now
    /// cover, which bounds both the memory and the log of a long-running node. Returns how many
    /// memtables were flushed (0: nothing to do, nothing written).
    ///
    /// # Errors
    /// As [`Self::flush`].
    pub fn flush_immutable(&self) -> Result<usize, Error> {
        let flushed = self.replica.engine().flush_immutable()?;
        if flushed > 0 {
            self.replica.purge_flushed()?;
        }
        Ok(flushed)
    }

    /// Background compaction step (PD-061): picks and runs one compaction; `false` when there
    /// is nothing to do. Several callers may run concurrently (the picker skips files that a
    /// running compaction holds). Rewritten files take the store's current encryption, so data
    /// written before a switch to encryption is encrypted as compaction reaches it.
    ///
    /// # Errors
    /// Storage errors of the failing compaction (its outputs are removed, its inputs stay live).
    pub fn compact_once(&self) -> Result<bool, Error> {
        Ok(self.replica.engine().compact_once()?)
    }

    /// The underlying replica (maintenance in long tests: flush, compact, purge).
    #[must_use]
    pub fn replica(&self) -> &Arc<LocalReplica> {
        &self.replica
    }

    /// Point-in-time statistics of the storage engine (exported at `/metrics`, PD-059).
    #[must_use]
    pub fn storage_metrics(&self) -> rustegon_storage::metrics::EngineMetrics {
        rustegon_mvcc::replica::Replica::engine(self.replica.as_ref()).metrics()
    }

    /// Transaction outcome counters of the node's coordinator (`/metrics`, PD-059).
    #[must_use]
    pub fn txn_stats(&self) -> rustegon_txn::TxnStatsSnapshot {
        self.coord.stats()
    }

    /// Whether the store still accepts writes (readiness probe, FR-OPS-003): `false` after a
    /// failed apply poisoned the replica, until the store is reopened.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.replica.is_healthy()
    }

    /// Creates a database. Databases are never created implicitly (PD-027).
    ///
    /// # Errors
    /// `RGN-1031` if it exists, `RGN-1001` for an invalid name, transaction errors.
    pub fn create_database(
        &self,
        name: &str,
        options: &DatabaseOptions,
    ) -> Result<DatabaseDescriptor, Error> {
        self.run(|txn| {
            let created = req!(catalog(txn, |r| create_database(r, name, options.clone()))?);
            apply(txn, &created.mutations)?;
            Ok(Ok(created.descriptor))
        })
    }

    /// Creates a collection explicitly, e.g. with a validator (FR-SCH-002).
    ///
    /// # Errors
    /// `RGN-1030` (missing database), `RGN-1031` (exists), `RGN-1001` (invalid name, shard key
    /// or validator), transaction errors.
    pub fn create_collection(
        &self,
        database: &str,
        spec: &CollectionSpec,
    ) -> Result<CollectionDescriptor, Error> {
        self.run(|txn| {
            let db = req!(catalog(txn, |r| require_database(r, database))?);
            let created = req!(catalog(txn, |r| create_collection(r, &db, spec.clone()))?);
            apply(txn, &created.mutations)?;
            Ok(Ok(created.descriptor))
        })
    }

    /// Replaces the validator options of an existing collection (FR-SCH-002). Existing
    /// documents are not checked; with `moderate`, those that fail can still be updated.
    ///
    /// # Errors
    /// `RGN-1030` (database or collection missing), `RGN-1001` (invalid validator),
    /// transaction errors.
    pub fn set_collection_options(
        &self,
        database: &str,
        collection: &str,
        options: &CollectionOptions,
    ) -> Result<CollectionDescriptor, Error> {
        self.run(|txn| {
            let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
                return Ok(Err(CatalogError::NotFound {
                    kind: rustegon_catalog::ObjectKind::Collection,
                    name: collection.to_owned(),
                    hint: None,
                }
                .into()));
            };
            let altered = req!(catalog(txn, |r| set_collection_options(
                r,
                &coll,
                options.clone()
            ))?);
            apply(txn, &altered.mutations)?;
            Ok(Ok(altered.descriptor))
        })
    }

    /// Writes accepted with validator warnings (`validationAction: warn`) so far. Counted per
    /// transaction attempt: a retried write that warns counts once per attempt.
    #[must_use]
    pub fn validation_warnings(&self) -> u64 {
        self.validators.warnings()
    }

    /// Inserts `doc` into `database.collection` and returns the stored document (with `_id`
    /// and the system fields). The collection is created if missing and the database allows it
    /// (FR-SCH-001).
    ///
    /// # Errors
    /// `RGN-1030` (missing database, or missing collection with implicit creation off),
    /// `RGN-1004` (server-maintained field in `doc`), `RGN-1005` (`_id` exists), `RGN-1006`
    /// (validator, FR-SCH-002), document limits (`RGN-1002/1003`), transaction errors.
    pub fn insert(
        &self,
        database: &str,
        collection: &str,
        doc: &Document,
    ) -> Result<Document, Error> {
        validate_user_document(doc)?;
        // Generated once per call, not per attempt: a retried insert keeps its id.
        let id = self.id_for(doc);
        self.run(|txn| self.insert_in(txn, database, collection, doc, &id))
    }

    /// The document `id` of `database.collection`, `None` if it or the collection is missing.
    ///
    /// # Errors
    /// `RGN-1030` for a missing database, corrupt documents, transaction errors.
    pub fn get(
        &self,
        database: &str,
        collection: &str,
        id: &Value,
    ) -> Result<Option<Document>, Error> {
        self.run(|txn| get_in(txn, database, collection, id))
    }

    /// Replaces the document `id` by `doc` and returns the stored document. `doc` may carry
    /// `_id` only if it equals `id` (FR-DOC-002); `_rev` and `_updatedAt` advance,
    /// `_createdAt` is kept (FR-DOC-005).
    ///
    /// # Errors
    /// `RGN-1001` (`_id` changed), `RGN-1004` (server-maintained field in `doc`), `RGN-1006`
    /// (validator; `moderate` exempts replacing an already-invalid document), `RGN-1030`
    /// (database, collection or document missing), document limits, transaction errors.
    pub fn replace(
        &self,
        database: &str,
        collection: &str,
        id: &Value,
        doc: &Document,
    ) -> Result<Document, Error> {
        validate_user_document(doc)?;
        self.run(|txn| self.replace_doc_in(txn, database, collection, id, doc))
    }

    /// Deletes the document `id` and returns it, `None` if it (or the collection) is missing.
    ///
    /// # Errors
    /// `RGN-1030` for a missing database, transaction errors.
    pub fn delete(
        &self,
        database: &str,
        collection: &str,
        id: &Value,
    ) -> Result<Option<Document>, Error> {
        self.run(|txn| self.delete_doc_in(txn, database, collection, id))
    }

    fn run<T>(&self, mut body: impl FnMut(&mut Txn) -> Body<T>) -> Result<T, Error> {
        let (result, _) = self
            .coord
            .run(&TxnOptions::default(), MAX_ATTEMPTS, |txn| body(txn))?;
        result
    }
}

/// [`CatalogRead`] over a transaction. Transaction errors are kept aside so that the caller
/// returns them as such (retryable conflicts must reach [`TxnCoordinator::run`]), instead of
/// as the catalog's opaque read error.
struct TxnReader<'a> {
    txn: RefCell<&'a mut Txn>,
    failed: RefCell<Option<TxnError>>,
}

impl TxnReader<'_> {
    fn fail(&self, e: TxnError) -> Error {
        let err = Error::new(e.code(), e.to_string());
        *self.failed.borrow_mut() = Some(e);
        err
    }
}

impl CatalogRead for TxnReader<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let result = self.txn.borrow_mut().get(key);
        result
            .map(|v| v.map(|b| b.to_vec()))
            .map_err(|e| self.fail(e))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<KvPairs, Error> {
        let Some(end) = prefix_end(prefix) else {
            return Err(Error::new(ErrorCode::Internal, "unbounded catalog scan"));
        };
        let result = self.txn.borrow_mut().scan(prefix, &end, usize::MAX);
        result
            .map(|rows| rows.into_iter().map(|(k, v)| (k, v.to_vec())).collect())
            .map_err(|e| self.fail(e))
    }
}

/// Runs a catalog operation over `txn`: outer error = transaction error, inner = request error.
fn catalog<T>(
    txn: &mut Txn,
    op: impl FnOnce(&TxnReader<'_>) -> Result<T, CatalogError>,
) -> Body<T> {
    let reader = TxnReader {
        txn: RefCell::new(txn),
        failed: RefCell::new(None),
    };
    let result = op(&reader);
    if let Some(e) = reader.failed.into_inner() {
        return Err(e);
    }
    Ok(result.map_err(Error::from))
}

/// The smallest key greater than every key starting with `prefix` (`None`: all `0xFF`).
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

fn require_database(r: &TxnReader<'_>, name: &str) -> Result<DatabaseDescriptor, CatalogError> {
    get_database(r, name)?.ok_or_else(|| CatalogError::NotFound {
        kind: rustegon_catalog::ObjectKind::Database,
        name: name.to_owned(),
        hint: None,
    })
}

/// The collection, `None` if missing; a missing database is a request error (`RGN-1030`).
fn existing_collection(
    txn: &mut Txn,
    database: &str,
    collection: &str,
) -> Body<Option<CollectionDescriptor>> {
    catalog(txn, |r| {
        let db = require_database(r, database)?;
        get_collection(r, db.id, collection)
    })
}

fn not_found_doc(collection: &str) -> Error {
    Error::new(
        ErrorCode::NotFound,
        format!("document not found in {collection}"),
    )
    .with_detail("kind", "document")
}

fn doc_key(coll: &CollectionDescriptor, id: &Value) -> Result<Vec<u8>, Error> {
    Ok(document_key(
        coll.database_id,
        coll.id,
        coll.shard_key.shard_hash(),
        id,
    )?)
}

/// The body of [`EmbeddedDb::get`]: the document `id`, `None` if it or the collection is missing.
fn get_in(txn: &mut Txn, database: &str, collection: &str, id: &Value) -> Body<Option<Document>> {
    let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
        return Ok(Ok(None));
    };
    read_doc(txn, &coll, id)
}

fn read_doc(txn: &mut Txn, coll: &CollectionDescriptor, id: &Value) -> Body<Option<Document>> {
    let key = req!(doc_key(coll, id));
    Ok(match txn.get(&key)? {
        None => Ok(None),
        Some(bytes) => rdoc::decode(&bytes).map(Some).map_err(Error::from),
    })
}

fn apply(txn: &mut Txn, mutations: &[Mutation]) -> Result<(), TxnError> {
    for m in mutations {
        match m {
            Mutation::Put { key, value } => txn.put(key, value.clone())?,
            Mutation::Delete { key } => txn.delete(key)?,
        }
    }
    Ok(())
}

/// Timestamp of the version being written (module docs): above the read timestamp, so above
/// the previous version of the document, whose revision it therefore follows strictly.
fn version_ts(txn: &Txn) -> Timestamp {
    txn.write_ts().max(txn.read_ts().next())
}

/// Builds the stored document — `_id` first, the user fields, then `_rev`, `_createdAt`
/// (`created`, or `ts` for a new document) and `_updatedAt` — and its `RDoc` encoding.
fn encode_stored(
    id: &Value,
    doc: &Document,
    ts: Timestamp,
    created: Option<&Value>,
) -> Result<(Document, Vec<u8>), Error> {
    let millis = i64::try_from(ts.wall / NANOS_PER_MILLI).unwrap_or(i64::MAX);
    let now = Value::DateTime(millis);
    let mut fields = Vec::with_capacity(doc.len() + 4);
    fields.push((ID.to_owned(), id.clone()));
    fields.extend(
        doc.iter()
            .filter(|(n, _)| *n != ID)
            .map(|(n, v)| (n.to_owned(), v.clone())),
    );
    fields.push((REV.to_owned(), Value::String(encode_rev(ts, LOCAL_SITE_ID))));
    fields.push((
        CREATED_AT.to_owned(),
        created.cloned().unwrap_or(now.clone()),
    ));
    fields.push((UPDATED_AT.to_owned(), now));
    let stored = Document::try_from_fields(fields)?;
    let bytes = rdoc::encode(&stored)?;
    Ok((stored, bytes))
}

/// `_rev` = base32hex (lowercase, unpadded) of `ts (12 B) ‖ site_id (u16 BE)`. The alphabet
/// is in ascending ASCII order and the length is fixed, so string order equals byte order,
/// i.e. timestamp order.
#[must_use]
pub fn encode_rev(ts: Timestamp, site_id: u16) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut bytes = ts.to_be_bytes().to_vec();
    bytes.extend_from_slice(&site_id.to_be_bytes());
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 0x1F) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 0x1F) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rev_order_follows_timestamp_order() {
        let a = encode_rev(Timestamp::new(5, 0), 0);
        let b = encode_rev(Timestamp::new(5, 1), 0);
        let c = encode_rev(Timestamp::new(6, 0), 0);
        assert_eq!(a.len(), 23);
        assert!(a < b && b < c);
        assert_eq!(encode_rev(Timestamp::MIN, 0), "0".repeat(23));
    }

    #[test]
    fn prefix_end_increments_last_non_max_byte() {
        assert_eq!(prefix_end(&[1, 2]), Some(vec![1, 3]));
        assert_eq!(prefix_end(&[1, 0xFF]), Some(vec![2]));
        assert_eq!(prefix_end(&[0xFF]), None);
    }
}
