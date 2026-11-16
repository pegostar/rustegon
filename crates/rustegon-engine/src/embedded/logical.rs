// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Engine side of the logical dump and import (M13a lane BD; FR-BKP-007, PD-067; the dump
//! format and its orchestration belong to lane BG).
//!
//! # Dump: reads at a pinned snapshot
//! A client-side dump through the Query API would be one transaction, bounded by
//! `txn.max_duration` (60 s). The dump instead reads at the timestamp T of a
//! [`PinnedSnapshot`] ([`EmbeddedDb::pin_snapshot`]): T is closed (no transaction can commit at
//! or below it any more, PD-063) and its versions are protected from GC for as long as the
//! snapshot lives. Each batch is a committed-only read at T
//! (`MvccReader::scan_committed`): no transaction, no timestamp-cache entry, no waiting on
//! intents — every intent there belongs to a transaction that commits above T or never — so
//! the dump never blocks writers, is never blocked by them, and can run for hours. Catalog
//! reads at T ([`EmbeddedDb::collections_at`], [`EmbeddedDb::indexes_at`]) give the metadata
//! consistent with the data.
//!
//! # Import
//! [`EmbeddedDb::import_documents`] bulk-loads dumped documents in transactions of bounded size
//! ([`ImportOptions`], below `txn.max_write_keys` / `txn.max_write_bytes`), keeping `_id`,
//! `_createdAt` and `_updatedAt`, regenerating `_rev` from the importing transaction's
//! timestamp, and **without validators** (the dump holds what the source accepted, possibly
//! under an older validator or `moderate`). Existing indexes are maintained, so the order
//! "create collection without validator → import → set validator → build indexes" (PD-067)
//! and any other order both leave consistent indexes. [`EmbeddedDb::prepare_import_target`]
//! refuses a non-empty target unless asked to drop it.

use std::sync::Arc;

use rustegon_catalog::{
    CatalogRead, CollectionDescriptor, CollectionSpec, DatabaseDescriptor, Descriptor,
    DescriptorState, IndexDescriptor, IndexState, create_collection, get_collection, get_database,
    get_descriptor, index::ops::list_indexes, keys::ROOT_PARENT_ID, list_names, ops::KvPairs,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{
    Document, Value,
    keyspace::{Family, family_prefix},
    limits::validate_user_document,
    rdoc,
};
use rustegon_mvcc::{Replica, Timestamp, key::next_logical_key};
use rustegon_txn::Txn;

use super::{
    Body, CREATED_AT, EmbeddedDb, ID, LOCAL_SITE_ID, NANOS_PER_MILLI, REV, UPDATED_AT, apply,
    catalog, doc_key, encode_rev, existing_collection, prefix_end, require_database, version_ts,
};
use crate::embedded::backup::PinnedSnapshot;

/// Batch bounds of a [`SnapshotScan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    /// Documents per batch (at least 1).
    pub batch_docs: usize,
    /// A batch ends after the document that reaches this many bytes of `RDoc` (at least one
    /// document per batch).
    pub batch_bytes: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            batch_docs: 1000,
            batch_bytes: 4 << 20,
        }
    }
}

/// A streaming scan of one collection at a pinned snapshot ([`EmbeddedDb::scan_at`]); holds
/// the snapshot (and so its GC pin) until dropped. Documents come in key order (hash of `_id`
/// first for hashed collections), each exactly once.
pub struct SnapshotScan {
    db: Arc<EmbeddedDb>,
    snapshot: Arc<PinnedSnapshot>,
    collection: CollectionDescriptor,
    /// Where the next batch starts; `None` once the scan is complete.
    next: Option<Vec<u8>>,
    end: Vec<u8>,
    options: ScanOptions,
    returned: u64,
}

impl std::fmt::Debug for SnapshotScan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotScan")
            .field("ts", &self.snapshot.ts())
            .field("collection", &self.collection.name)
            .field("returned", &self.returned)
            .field("done", &self.next.is_none())
            .finish_non_exhaustive()
    }
}

impl SnapshotScan {
    /// The collection as it was at the snapshot (options, validator).
    #[must_use]
    pub fn collection(&self) -> &CollectionDescriptor {
        &self.collection
    }

    /// The snapshot timestamp.
    #[must_use]
    pub fn ts(&self) -> Timestamp {
        self.snapshot.ts()
    }

    /// Documents returned so far.
    #[must_use]
    pub fn returned(&self) -> u64 {
        self.returned
    }

    /// The next batch, `None` at the end.
    ///
    /// # Errors
    /// Storage errors, `RGN-5002` for a stored document that does not decode.
    pub fn next_batch(&mut self) -> Result<Option<Vec<Document>>, Error> {
        let Some(start) = self.next.take() else {
            return Ok(None);
        };
        let max = self.options.batch_docs.max(1);
        let rows =
            self.db
                .replica
                .reader()
                .scan_committed(&start, &self.end, self.snapshot.ts(), max)?;
        let mut docs = Vec::with_capacity(rows.len());
        let mut bytes = 0usize;
        let mut resume = (rows.len() == max).then(|| rows.last().map(|(k, _)| next_logical_key(k)));
        for (i, (key, value)) in rows.iter().enumerate() {
            docs.push(rdoc::decode(value).map_err(Error::from)?);
            bytes += value.len();
            if bytes >= self.options.batch_bytes && i + 1 < rows.len() {
                resume = Some(Some(next_logical_key(key)));
                break;
            }
        }
        self.next = resume.flatten();
        self.returned += docs.len() as u64;
        if docs.is_empty() {
            return Ok(None);
        }
        Ok(Some(docs))
    }
}

impl Iterator for SnapshotScan {
    type Item = Result<Vec<Document>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_batch() {
            Ok(Some(batch)) => Some(Ok(batch)),
            Ok(None) => None,
            Err(e) => {
                // A failed scan does not resume past the batch it could not read.
                self.next = None;
                Some(Err(e))
            }
        }
    }
}

/// [`CatalogRead`] at a pinned snapshot: committed-only reads at its timestamp.
struct SnapshotCatalog<'a> {
    db: &'a EmbeddedDb,
    ts: Timestamp,
}

impl CatalogRead for SnapshotCatalog<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .db
            .replica
            .reader()
            .get_committed(key, self.ts)?
            .map(|b| b.to_vec()))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<KvPairs, Error> {
        let Some(end) = prefix_end(prefix) else {
            return Err(Error::new(ErrorCode::Internal, "unbounded catalog scan"));
        };
        Ok(self
            .db
            .replica
            .reader()
            .scan_committed(prefix, &end, self.ts, usize::MAX)?
            .into_iter()
            .map(|(k, v)| (k, v.to_vec()))
            .collect())
    }
}

/// Bounds of one import transaction ([`EmbeddedDb::import_documents`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportOptions {
    /// Documents per transaction (at least 1). With `n` indexes a document writes `1 + n` keys
    /// or more (multikey); keep `batch_docs × keys per document` below `txn.max_write_keys`.
    pub batch_docs: usize,
    /// A transaction ends after the document that reaches this many bytes of `RDoc`; keep it
    /// well below `txn.max_write_bytes` (64 MiB) to leave room for index entries.
    pub batch_bytes: usize,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            batch_docs: 500,
            batch_bytes: 8 << 20,
        }
    }
}

/// What [`EmbeddedDb::import_documents`] loaded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Documents written.
    pub documents: u64,
    /// Transactions committed.
    pub transactions: u64,
}

impl EmbeddedDb {
    /// A streaming scan of `database.collection` at `snapshot` (module docs, PD-067), not
    /// bounded by `txn.max_duration`. The collection is resolved at the snapshot: one created
    /// later is missing, one dropped later is still there.
    ///
    /// # Errors
    /// `RGN-1030` if the database or the collection did not exist at the snapshot; storage
    /// errors.
    pub fn scan_at(
        self: &Arc<Self>,
        snapshot: &Arc<PinnedSnapshot>,
        database: &str,
        collection: &str,
        options: ScanOptions,
    ) -> Result<SnapshotScan, Error> {
        let reader = SnapshotCatalog {
            db: self,
            ts: snapshot.ts(),
        };
        let db = get_database(&reader, database)?.ok_or_else(|| missing("database", database))?;
        let coll = get_collection(&reader, db.id, collection)?
            .ok_or_else(|| missing("collection", collection))?;
        let start = family_prefix(coll.database_id, coll.id, Family::Document);
        let end = prefix_end(&start)
            .ok_or_else(|| Error::new(ErrorCode::Internal, "document span without end"))?;
        Ok(SnapshotScan {
            db: Arc::clone(self),
            snapshot: Arc::clone(snapshot),
            collection: coll,
            next: Some(start),
            end,
            options,
            returned: 0,
        })
    }

    /// The public databases at `snapshot`, in name order.
    ///
    /// # Errors
    /// Storage errors, corrupt catalog entries.
    pub fn databases_at(
        &self,
        snapshot: &PinnedSnapshot,
    ) -> Result<Vec<DatabaseDescriptor>, Error> {
        let reader = SnapshotCatalog {
            db: self,
            ts: snapshot.ts(),
        };
        let mut out = Vec::new();
        for (_, id) in list_names(&reader, ROOT_PARENT_ID)? {
            if let Some(Descriptor::Database(d)) = get_descriptor(&reader, id)?
                && d.state == DescriptorState::Public
            {
                out.push(d);
            }
        }
        Ok(out)
    }

    /// The public collections of `database` at `snapshot` (with their options and
    /// validators), in name order.
    ///
    /// # Errors
    /// `RGN-1030` if the database did not exist at the snapshot; storage errors.
    pub fn collections_at(
        &self,
        snapshot: &PinnedSnapshot,
        database: &str,
    ) -> Result<Vec<CollectionDescriptor>, Error> {
        let reader = SnapshotCatalog {
            db: self,
            ts: snapshot.ts(),
        };
        let db = get_database(&reader, database)?.ok_or_else(|| missing("database", database))?;
        let mut out = Vec::new();
        for (_, id) in list_names(&reader, db.id)? {
            if let Some(Descriptor::Collection(c)) = get_descriptor(&reader, id)?
                && c.state == DescriptorState::Public
            {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// The public indexes of `database.collection` at `snapshot` (the definitions a dump
    /// records; builds in progress at the snapshot are left out, they rebuild nothing a restore
    /// needs).
    ///
    /// # Errors
    /// `RGN-1030` if the database or collection did not exist at the snapshot; storage errors.
    pub fn indexes_at(
        &self,
        snapshot: &PinnedSnapshot,
        database: &str,
        collection: &str,
    ) -> Result<Vec<IndexDescriptor>, Error> {
        let reader = SnapshotCatalog {
            db: self,
            ts: snapshot.ts(),
        };
        let db = get_database(&reader, database)?.ok_or_else(|| missing("database", database))?;
        let coll = get_collection(&reader, db.id, collection)?
            .ok_or_else(|| missing("collection", collection))?;
        Ok(list_indexes(&reader, coll.id)?
            .into_iter()
            .filter(|d| d.state == IndexState::Public)
            .collect())
    }

    /// Prepares the target of an import (PD-067): creates `database.<spec.name>` from `spec`
    /// (pass it without validator; set it after the import with
    /// [`EmbeddedDb::set_collection_options`]). An existing **empty** collection is used as it
    /// is; an existing non-empty one is refused unless `drop_existing`, which drops it (data
    /// and indexes, `DROP COLLECTION`) and creates it anew. The database must exist
    /// ([`EmbeddedDb::create_database`]).
    ///
    /// # Errors
    /// `RGN-1031` for a non-empty target without `drop_existing`, `RGN-1030` for a missing
    /// database, `RGN-1001` for an invalid spec, transaction errors.
    pub fn prepare_import_target(
        &self,
        database: &str,
        spec: &CollectionSpec,
        drop_existing: bool,
    ) -> Result<CollectionDescriptor, Error> {
        let name = spec.name.as_str();
        if let Some(existing) = self.collection(database, name)? {
            let empty = self.run(|txn| collection_is_empty(txn, &existing))?;
            if !drop_existing {
                if empty {
                    return Ok(existing);
                }
                return Err(Error::new(
                    ErrorCode::AlreadyExists,
                    format!(
                        "collection {database}.{name} exists and is not empty; drop it first or \
                         ask the import to drop it"
                    ),
                )
                .with_detail("kind", "collection"));
            }
            self.drop_collection(database, name)?;
        }
        self.run(|txn| {
            let db = req!(catalog(txn, |r| require_database(r, database))?);
            let created = req!(catalog(txn, |r| create_collection(r, &db, spec.clone()))?);
            apply(txn, &created.mutations)?;
            Ok(Ok(created.descriptor))
        })
    }

    /// Bulk-loads dumped documents into the existing collection `database.collection` (module
    /// docs): transactions of at most `options` size, each retried on conflicts like every
    /// embedded call. Every document must carry `_id`; `_createdAt` / `_updatedAt` are kept
    /// when present (`datetime`) and set to the import time otherwise; `_rev` is regenerated;
    /// `_conflict` and `_origin` are refused like in any write. Validators are not applied;
    /// indexes are maintained.
    ///
    /// Not atomic as a whole: on error, the transactions committed before it stay (the
    /// outcome so far is in the error's details `imported`); the import of a dump is restarted
    /// from an emptied target.
    ///
    /// # Errors
    /// `RGN-1030` (database or collection missing), `RGN-1001` (a document without `_id`, an
    /// array `_id`, a system field of the wrong type), `RGN-1004` (other server-maintained
    /// fields), `RGN-1005` (an `_id` present twice or already stored; unique index violation),
    /// document limits, transaction errors.
    pub fn import_documents(
        &self,
        database: &str,
        collection: &str,
        docs: impl IntoIterator<Item = Document>,
        options: &ImportOptions,
    ) -> Result<ImportOutcome, Error> {
        let Some(coll) = self.collection(database, collection)? else {
            return Err(missing("collection", collection));
        };
        let max_docs = options.batch_docs.max(1);
        let mut outcome = ImportOutcome::default();
        let mut batch: Vec<Imported> = Vec::with_capacity(max_docs);
        let mut bytes = 0usize;
        for doc in docs {
            let imported = Imported::from_dump(doc).map_err(|e| with_progress(e, outcome))?;
            bytes += imported.approx_bytes;
            batch.push(imported);
            if batch.len() >= max_docs || bytes >= options.batch_bytes {
                self.import_batch(database, &coll, &batch)
                    .map_err(|e| with_progress(e, outcome))?;
                outcome.documents += batch.len() as u64;
                outcome.transactions += 1;
                batch.clear();
                bytes = 0;
            }
        }
        if !batch.is_empty() {
            self.import_batch(database, &coll, &batch)
                .map_err(|e| with_progress(e, outcome))?;
            outcome.documents += batch.len() as u64;
            outcome.transactions += 1;
        }
        Ok(outcome)
    }

    /// One import transaction.
    fn import_batch(
        &self,
        database: &str,
        coll: &CollectionDescriptor,
        batch: &[Imported],
    ) -> Result<(), Error> {
        self.run(|txn| {
            // The collection may have been dropped (or re-created) since it was resolved.
            let Some(current) = req!(existing_collection(txn, database, &coll.name)?) else {
                return Ok(Err(missing("collection", &coll.name)));
            };
            if current.id != coll.id {
                return Ok(Err(missing("collection", &coll.name)));
            }
            for doc in batch {
                let key = req!(doc_key(&current, &doc.id));
                if txn.get(&key)?.is_some() {
                    return Ok(Err(Error::new(
                        ErrorCode::DuplicateKey,
                        format!("_id already exists in {}", current.name),
                    )));
                }
                let ts = version_ts(txn);
                let (stored, encoded) = req!(doc.encode(ts));
                req!(self.write_indexes(txn, &current, &doc.id, None, Some(&stored))?);
                txn.put(&key, encoded)?;
            }
            Ok(Ok(()))
        })
    }
}

/// A dumped document split into what the import keeps and what it regenerates.
struct Imported {
    id: Value,
    /// The user fields (system fields removed), checked by `validate_user_document`.
    user: Document,
    created: Option<Value>,
    updated: Option<Value>,
    approx_bytes: usize,
}

impl Imported {
    fn from_dump(mut doc: Document) -> Result<Self, Error> {
        let id = doc
            .get(ID)
            .cloned()
            .ok_or_else(|| invalid("a dumped document has no _id"))?;
        if matches!(id, Value::Array(_)) {
            return Err(invalid("_id cannot be an array"));
        }
        let created = doc.remove(CREATED_AT);
        let updated = doc.remove(UPDATED_AT);
        // Regenerated: a revision names a write of this store (data-model.md §9).
        doc.remove(REV);
        for v in [&created, &updated].into_iter().flatten() {
            if !matches!(v, Value::DateTime(_)) {
                return Err(invalid("_createdAt and _updatedAt must be datetime values"));
            }
        }
        validate_user_document(&doc)?;
        let approx_bytes = rdoc::encode(&doc)?.len();
        Ok(Self {
            id,
            user: doc,
            created,
            updated,
            approx_bytes,
        })
    }

    /// The stored document (`_id` first, the user fields, `_rev`, `_createdAt`, `_updatedAt`,
    /// as every write stores it) and its encoding.
    fn encode(&self, ts: Timestamp) -> Result<(Document, Vec<u8>), Error> {
        let millis = i64::try_from(ts.wall / NANOS_PER_MILLI).unwrap_or(i64::MAX);
        let now = Value::DateTime(millis);
        let mut fields = Vec::with_capacity(self.user.len() + 4);
        fields.push((ID.to_owned(), self.id.clone()));
        fields.extend(
            self.user
                .iter()
                .filter(|(n, _)| *n != ID)
                .map(|(n, v)| (n.to_owned(), v.clone())),
        );
        fields.push((REV.to_owned(), Value::String(encode_rev(ts, LOCAL_SITE_ID))));
        fields.push((
            CREATED_AT.to_owned(),
            self.created.clone().unwrap_or_else(|| now.clone()),
        ));
        fields.push((UPDATED_AT.to_owned(), self.updated.clone().unwrap_or(now)));
        let stored = Document::try_from_fields(fields)?;
        let bytes = rdoc::encode(&stored)?;
        Ok((stored, bytes))
    }
}

/// Whether the collection holds no document (a one-key read of its document span).
fn collection_is_empty(txn: &mut Txn, coll: &CollectionDescriptor) -> Body<bool> {
    let start = family_prefix(coll.database_id, coll.id, Family::Document);
    let Some(end) = prefix_end(&start) else {
        return Ok(Err(Error::new(
            ErrorCode::Internal,
            "document span without end",
        )));
    };
    Ok(Ok(txn.scan(&start, &end, 1)?.is_empty()))
}

fn missing(kind: &str, name: &str) -> Error {
    Error::new(ErrorCode::NotFound, format!("{kind} {name} not found")).with_detail("kind", kind)
}

fn invalid(msg: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, msg)
}

/// Adds how much was imported before `e` to its details.
fn with_progress(e: Error, outcome: ImportOutcome) -> Error {
    e.with_detail("imported", outcome.documents.to_string())
}
