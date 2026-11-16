// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Secondary indexes in the embedded test API (M3; FR-IDX-001/002/003, indexing.md §3–§5).
//!
//! - Every document write (`insert`, `replace`, `delete`) maintains the collection's
//!   non-dropping indexes in the same transaction ([`EmbeddedDb::write_indexes`], called by the
//!   write paths of the parent module).
//! - [`EmbeddedDb::create_index`] runs the **online build job** of `rustegon_index::build`: one
//!   DDL transaction creates the descriptor (`DeleteOnly`) and the job record, then the job's
//!   steps — each its own transaction, so concurrent writers interleave — walk `WriteOnly →
//!   Backfilling` (batches with a persisted checkpoint) `→ Validating → Public`. The embedded
//!   API drives the job synchronously to its end and ignores throttling pauses (it has no
//!   timer; a server driver waits them on its clock). A failed build (`RGN-1022` unique
//!   violation, `RGN-1025` / `RGN-1008` from existing data) leaves the index `Dropping`, cleans
//!   its span and returns the error.
//! - Step-wise control for tests and simulations: [`EmbeddedDb::start_index_build`] +
//!   [`EmbeddedDb::step_index_build`], [`EmbeddedDb::cancel_index_build`]; recovery after a
//!   reopen: [`EmbeddedDb::pending_index_builds`] / [`EmbeddedDb::resume_index_builds`] (the
//!   embedded store has no background threads, so resuming is an explicit call).
//! - [`EmbeddedDb::drop_index`] marks the index dropping, deletes its entries and any build job
//!   record in the same transaction (the GC job of a later milestone does this asynchronously on
//!   a cluster).
//! - [`EmbeddedDb::index_scan`]: index range read returning the documents (TC-IDX-001 part).

use std::{
    fmt,
    ops::Bound,
    sync::{Arc, PoisonError, RwLock},
};

use rustegon_catalog::{
    CollectionDescriptor, CollectionForWrite, IndexDescriptor, IndexSpec, IndexState,
    index::ops::{
        create_index, drop_index, list_indexes, mark_multikey, require_index, write_indexes,
    },
    resolve_collection_for_write,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value, rdoc};
use rustegon_index::{
    BuildConfig, BuildStep, IndexBuild, IndexError, IndexHit, NoPartialFilter, PartialFilter,
    build::{build_record_mutation, cancel_build, delete_build_record, pending_builds},
    document_key_for_element, index_span, maintain, scan_index,
};
use rustegon_txn::{Txn, TxnError};

use super::{
    Body, EmbeddedDb, NANOS_PER_MILLI, apply, catalog, existing_collection, require_database,
    version_ts,
};

/// A shared partial-index predicate evaluator.
pub type SharedPartialFilter = Arc<dyn PartialFilter + Send + Sync>;

/// The installed partial-index evaluator (`EmbeddedDb::open` installs the query engine's).
#[derive(Default)]
pub(super) struct FilterSlot(RwLock<Option<SharedPartialFilter>>);

impl fmt::Debug for FilterSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let set = self
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        f.debug_struct("FilterSlot")
            .field("installed", &set)
            .finish()
    }
}

impl FilterSlot {
    fn get(&self) -> Option<SharedPartialFilter> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Splits an [`IndexError`] into the body's two error levels.
fn split<T>(r: Result<T, IndexError>) -> Body<T> {
    match r {
        Ok(v) => Ok(Ok(v)),
        Err(IndexError::Txn(e)) => Err(e),
        Err(IndexError::Rejected(e)) => Ok(Err(e)),
    }
}

impl EmbeddedDb {
    /// Installs the evaluator of partial-index predicates (indexing.md §3). Without one,
    /// creating or maintaining a partial index fails with `RGN-1001`.
    pub fn set_partial_filter(&self, filter: SharedPartialFilter) {
        *self
            .filter
            .0
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(filter);
    }

    /// Maintains the indexes of `coll` for one document write, inside `txn` (FR-IDX-002):
    /// called by every write path before the document itself is written. A rejection
    /// (`RGN-1005`, `RGN-1008`, `RGN-1025`) is an inner error with nothing written.
    pub(super) fn write_indexes(
        &self,
        txn: &mut Txn,
        coll: &CollectionDescriptor,
        id: &Value,
        old: Option<&Document>,
        new: Option<&Document>,
    ) -> Body<()> {
        let indexes = match catalog(txn, |r| write_indexes(r, coll.id))? {
            Ok(i) => i,
            Err(e) => return Ok(Err(e)),
        };
        if indexes.is_empty() {
            return Ok(Ok(()));
        }
        let installed = self.filter.get();
        let filter: &dyn PartialFilter = match &installed {
            Some(f) => f.as_ref(),
            None => &NoPartialFilter,
        };
        let newly = match split(maintain(txn, &indexes, id, old, new, filter))? {
            Ok(n) => n,
            Err(e) => return Ok(Err(e)),
        };
        mark_newly_multikey(txn, coll, &indexes, &newly)
    }

    /// `CREATE INDEX` on `database.collection` (created implicitly like a write), built online
    /// with the default [`BuildConfig`] and driven to its end (module docs). Returns the public
    /// descriptor.
    ///
    /// # Errors
    /// `RGN-1001` (invalid spec; a partial index without an installed evaluator), `RGN-1020`,
    /// `RGN-1023`, `RGN-1030`, `RGN-1022` (unique violation in existing data), `RGN-1025` /
    /// `RGN-1008` from existing documents, `RGN-5005` if cancelled meanwhile, transaction
    /// errors.
    pub fn create_index(
        &self,
        database: &str,
        collection: &str,
        spec: &IndexSpec,
    ) -> Result<IndexDescriptor, Error> {
        self.create_index_with(database, collection, spec, &BuildConfig::default())
    }

    /// [`EmbeddedDb::create_index`] with explicit build settings (batch sizes).
    ///
    /// # Errors
    /// As [`EmbeddedDb::create_index`].
    pub fn create_index_with(
        &self,
        database: &str,
        collection: &str,
        spec: &IndexSpec,
        config: &BuildConfig,
    ) -> Result<IndexDescriptor, Error> {
        let mut build = self.start_index_build(database, collection, spec, config)?;
        let filter = self.filter_or_none();
        // No timer in the embedded store: throttling pauses are not waited (module docs).
        build.run(&self.coord, filter.as_ref(), &mut |_| {})
    }

    /// Starts an online build (the DDL transaction only) and returns the job handle; drive it
    /// with [`EmbeddedDb::step_index_build`].
    ///
    /// # Errors
    /// As [`EmbeddedDb::create_index`] for the definition errors.
    pub fn start_index_build(
        &self,
        database: &str,
        collection: &str,
        spec: &IndexSpec,
        config: &BuildConfig,
    ) -> Result<IndexBuild, Error> {
        // A partial predicate must compile (syntax, names, functions) before anything is built.
        if let Some(text) = &spec.partial {
            rustegon_query::partial::bind_partial(text)?;
        }
        let installed = self.filter.get();
        if spec.partial.is_some() && installed.is_none() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "partial indexes need a predicate evaluator (not available yet)",
            ));
        }
        let (collection_id, index_id) =
            self.run(|txn| start_in_txn(txn, database, collection, spec))?;
        Ok(IndexBuild::new(collection_id, index_id, config.clone()))
    }

    /// Runs one step of `build` (one transaction).
    ///
    /// # Errors
    /// Transaction and storage errors (the step can be retried).
    pub fn step_index_build(&self, build: &mut IndexBuild) -> Result<BuildStep, Error> {
        let filter = self.filter_or_none();
        build.step(&self.coord, filter.as_ref())
    }

    /// Cancels the in-progress build of index `name`: it becomes `Dropping` and its job turns
    /// into cleanup; returns the job handle to drive the cleanup (it ends with `RGN-5005`).
    ///
    /// # Errors
    /// `RGN-1021` (no such index), `RGN-1033` (the index has no running build, e.g. already
    /// public), `RGN-1030`, transaction errors.
    pub fn cancel_index_build(
        &self,
        database: &str,
        collection: &str,
        name: &str,
    ) -> Result<IndexBuild, Error> {
        let (coll, ix) = self.run(|txn| {
            let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
                return Ok(Err(missing_collection(collection)));
            };
            let ix = req!(catalog(txn, |r| require_index(r, &coll, name))?);
            Ok(Ok((coll, ix)))
        })?;
        if !cancel_build(&self.coord, &coll, ix.id)? {
            return Err(Error::new(
                ErrorCode::SchemaChangeInProgress,
                format!("index {name} has no running build"),
            ));
        }
        Ok(IndexBuild::new(coll.id, ix.id, BuildConfig::default()))
    }

    /// Handles on every unfinished build (after a reopen), resuming from their checkpoints.
    ///
    /// # Errors
    /// Transaction errors, corrupt job records.
    pub fn pending_index_builds(&self, config: &BuildConfig) -> Result<Vec<IndexBuild>, Error> {
        pending_builds(&self.coord, config)
    }

    /// Drives every unfinished build to its end (recovery after a reopen); one result per
    /// build: the public descriptor or why it was abandoned.
    ///
    /// # Errors
    /// Errors listing the builds; a step error stops the resumption (resumable again).
    pub fn resume_index_builds(
        &self,
        config: &BuildConfig,
    ) -> Result<Vec<Result<IndexDescriptor, Error>>, Error> {
        let filter = self.filter_or_none();
        let mut out = Vec::new();
        for mut build in self.pending_index_builds(config)? {
            loop {
                match build.step(&self.coord, filter.as_ref())? {
                    BuildStep::Continue { .. } => {}
                    BuildStep::Public(d) => {
                        out.push(Ok(d));
                        break;
                    }
                    BuildStep::Abandoned(e) => {
                        out.push(Err(e));
                        break;
                    }
                }
            }
        }
        Ok(out)
    }

    fn filter_or_none(&self) -> SharedPartialFilter {
        self.filter
            .get()
            .unwrap_or_else(|| Arc::new(NoPartialFilter))
    }

    /// `DROP INDEX name` on `database.collection`: the index becomes `Dropping`, its entries
    /// and any build job record are deleted in the same transaction (a racing build step then
    /// conflicts and finds the job gone, `rustegon_index::build` I5).
    ///
    /// # Errors
    /// `RGN-1021` (no such index), `RGN-1030` (database or collection missing), transaction
    /// errors.
    pub fn drop_index(&self, database: &str, collection: &str, name: &str) -> Result<(), Error> {
        let dropped_id = self.run(|txn| {
            let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
                return Ok(Err(missing_collection(collection)));
            };
            let (dropped, mutations) = match catalog(txn, |r| drop_index(r, &coll, name))? {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
            apply(txn, &mutations)?;
            apply(txn, &[delete_build_record(coll.id, dropped.id)])?;
            let (start, end) = match index_span(&dropped) {
                Ok(s) => s,
                Err(e) => return Err(TxnError::Internal(e.to_string())),
            };
            for (key, _) in txn.scan(&start, &end, usize::MAX)? {
                txn.delete(&key)?;
            }
            Ok(Ok(dropped.id))
        })?;
        // FR-IDX-004: the counters of a dropped index are forgotten (ids are never reused).
        self.usage.remove(dropped_id);
        Ok(())
    }

    /// The non-dropping indexes of `database.collection` (empty if the collection is missing).
    ///
    /// # Errors
    /// `RGN-1030` for a missing database, transaction errors.
    pub fn list_indexes(
        &self,
        database: &str,
        collection: &str,
    ) -> Result<Vec<IndexDescriptor>, Error> {
        self.run(|txn| {
            let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
                return Ok(Ok(Vec::new()));
            };
            catalog(txn, |r| {
                Ok(list_indexes(r, coll.id)?
                    .into_iter()
                    .filter(|d| d.state != IndexState::Dropping)
                    .collect())
            })
        })
    }

    /// Diagnostics for consistency checks: every index descriptor of `database.collection` in
    /// every state (dropping included) with the number of raw entries in its span.
    ///
    /// # Errors
    /// `RGN-1030`, transaction errors.
    pub fn index_spans(
        &self,
        database: &str,
        collection: &str,
    ) -> Result<Vec<(IndexDescriptor, usize)>, Error> {
        self.run(|txn| {
            let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
                return Ok(Err(missing_collection(collection)));
            };
            let all = req!(catalog(txn, |r| list_indexes(r, coll.id))?);
            let mut out = Vec::with_capacity(all.len());
            for ix in all {
                let (start, end) = req!(index_span(&ix));
                let n = txn.scan(&start, &end, usize::MAX)?.len();
                out.push((ix, n));
            }
            Ok(Ok(out))
        })
    }

    /// Reads index `index` of `database.collection` within `[lower, upper]` (bounds are key
    /// tuples in index key order, `rustegon_index::scan`) and returns each hit with its
    /// document, in index order. Hits with `truncated` set must be re-checked by the caller.
    /// The index is read in whatever state it is (tests inspect builds in progress); only a
    /// `Public` one is complete.
    ///
    /// # Errors
    /// `RGN-1021`, `RGN-1030`, `RGN-5002` for an entry without its document (index and base
    /// data out of sync), transaction errors.
    pub fn index_scan(
        &self,
        database: &str,
        collection: &str,
        index: &str,
        lower: Bound<&[Option<Value>]>,
        upper: Bound<&[Option<Value>]>,
    ) -> Result<Vec<(IndexHit, Document)>, Error> {
        self.run(|txn| {
            let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
                return Ok(Err(missing_collection(collection)));
            };
            let ix = match catalog(txn, |r| require_index(r, &coll, index))? {
                Ok(ix) => ix,
                Err(e) => return Ok(Err(e)),
            };
            let hits = match split(scan_index(txn, &ix, lower, upper, usize::MAX))? {
                Ok(h) => h,
                Err(e) => return Ok(Err(e)),
            };
            let mut out = Vec::with_capacity(hits.len());
            for hit in hits {
                let key = document_key_for_element(
                    coll.database_id,
                    coll.id,
                    coll.shard_key.shard_hash(),
                    &hit.id_element,
                );
                let Some(bytes) = txn.get(&key)? else {
                    return Ok(Err(Error::new(
                        ErrorCode::StorageCorruption,
                        format!("index {index} entry without its document"),
                    )));
                };
                match rdoc::decode(&bytes) {
                    Ok(doc) => out.push((hit, doc)),
                    Err(e) => return Ok(Err(e.into())),
                }
            }
            Ok(Ok(out))
        })
    }
}

fn missing_collection(collection: &str) -> Error {
    Error::new(
        ErrorCode::NotFound,
        format!("collection not found: {collection}"),
    )
    .with_detail("kind", "collection")
    .with_detail("name", collection)
}

/// Sets the `multikey` flag of the indexes that saw their first array value.
fn mark_newly_multikey(
    txn: &mut Txn,
    coll: &CollectionDescriptor,
    indexes: &[IndexDescriptor],
    newly: &[u32],
) -> Body<()> {
    for id in newly {
        let Some(ix) = indexes.iter().find(|i| i.id == *id) else {
            continue;
        };
        match catalog(txn, |r| mark_multikey(r, coll, ix))? {
            Ok(Some((_, mutations))) => apply(txn, &mutations)?,
            Ok(None) => {}
            Err(e) => return Ok(Err(e)),
        }
    }
    Ok(Ok(()))
}

/// The DDL transaction of an online build: resolves (or implicitly creates) the collection and
/// writes the `DeleteOnly` descriptor with its job record. Returns `(collection id, index id)`.
fn start_in_txn(
    txn: &mut Txn,
    database: &str,
    collection: &str,
    spec: &IndexSpec,
) -> Body<(u32, u32)> {
    let db = req!(catalog(txn, |r| require_database(r, database))?);
    let coll = match req!(catalog(txn, |r| resolve_collection_for_write(
        r, &db, collection
    ))?) {
        CollectionForWrite::Existing(c) => c,
        CollectionForWrite::Create(c) => {
            apply(txn, &c.mutations)?;
            c.descriptor
        }
    };
    let mut spec = spec.clone();
    let millis = version_ts(txn).wall / NANOS_PER_MILLI;
    spec.created_at_ms = i64::try_from(millis).unwrap_or(i64::MAX);
    let created = req!(catalog(txn, |r| create_index(r, &coll, spec))?);
    apply(txn, &created.mutations)?;
    let record = req!(build_record_mutation(&created.descriptor));
    apply(txn, &[record])?;
    Ok(Ok((coll.id, created.descriptor.id)))
}
