// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The single document write path of the embedded API, shared by the document methods
//! (`insert`, `replace`, `delete`) and the query engine's write operators (M3 lane F).
//!
//! Every write runs, in this order, inside the caller's transaction:
//! 1. the server-maintained fields (`_id`, `_rev`, `_createdAt`, `_updatedAt`, FR-DOC-005);
//! 2. the collection's validators (FR-SCH-002; database-engine.md §3), before anything is
//!    written;
//! 3. index maintenance (FR-IDX-002), so that a rejected index write (`RGN-1005`, `RGN-1008`,
//!    `RGN-1025`) leaves nothing behind;
//! 4. the document itself.
//!
//! `_id` cannot be an array (`RGN-1001`). *Provisional (PD pending)*: data-model.md does not
//! restrict the type of `_id`; arrays are rejected (as MongoDB does) because an array `_id`
//! would make `_id = v` (multikey: any element) differ from the primary-key lookup the planner
//! uses for it.

use rustegon_catalog::{CollectionDescriptor, CollectionForWrite, resolve_collection_for_write};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_txn::Txn;

use super::{
    Body, CREATED_AT, EmbeddedDb, ID, REV, UPDATED_AT, apply, catalog, doc_key, encode_stored,
    existing_collection, not_found_doc, read_doc, require_database, version_ts,
};

impl EmbeddedDb {
    /// The `_id` of a document to insert: its own, or a new `objectId`.
    pub(super) fn id_for(&self, doc: &Document) -> Value {
        doc.get(ID)
            .cloned()
            .unwrap_or_else(|| Value::ObjectId(self.oids.generate()))
    }

    /// Inserts the user document `doc` with `_id` = `id` into `database.collection`, creating
    /// the collection when missing and allowed (FR-SCH-001). The caller has validated `doc`
    /// (`validate_user_document`).
    pub(super) fn insert_in(
        &self,
        txn: &mut Txn,
        database: &str,
        collection: &str,
        doc: &Document,
        id: &Value,
    ) -> Body<Document> {
        if matches!(id, Value::Array(_)) {
            return Ok(Err(Error::new(
                ErrorCode::InvalidArgument,
                "_id cannot be an array",
            )));
        }
        let db = req!(catalog(txn, |r| require_database(r, database))?);
        let target = req!(catalog(txn, |r| resolve_collection_for_write(
            r, &db, collection
        ))?);
        let (coll, create) = match target {
            CollectionForWrite::Existing(c) => (c, Vec::new()),
            CollectionForWrite::Create(c) => (c.descriptor, c.mutations),
        };
        let key = req!(doc_key(&coll, id));
        // A freshly created collection is empty: skip the read.
        if create.is_empty() && txn.get(&key)?.is_some() {
            return Ok(Err(Error::new(
                ErrorCode::DuplicateKey,
                format!("_id already exists in {collection}"),
            )));
        }
        let ts = version_ts(txn);
        let stored = req!(encode_stored(id, doc, ts, None));
        req!(self.validators.check(&coll, None, &stored.0));
        if create.is_empty() {
            req!(self.write_indexes(txn, &coll, id, None, Some(&stored.0))?);
        }
        apply(txn, &create)?;
        txn.put(&key, stored.1)?;
        Ok(Ok(stored.0))
    }

    /// Replaces `old` (the stored document `id`) by `doc`. Server-maintained fields in `doc`
    /// (left there by update operators) are recomputed; `doc` may repeat `_id` but not change
    /// it (FR-DOC-002).
    pub(super) fn replace_in(
        &self,
        txn: &mut Txn,
        coll: &CollectionDescriptor,
        id: &Value,
        old: &Document,
        doc: &Document,
    ) -> Body<Document> {
        let key = req!(doc_key(coll, id));
        // `_id` is immutable: compared by key encoding, the identity the store uses.
        if let Some(new_id) = doc.get(ID) {
            match doc_key(coll, new_id) {
                Ok(k) if k == key => {}
                Ok(_) => {
                    return Ok(Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "_id is immutable and cannot be changed",
                    )));
                }
                Err(e) => return Ok(Err(e)),
            }
        }
        let user = strip_server_fields(doc);
        let ts = version_ts(txn);
        let stored = req!(encode_stored(id, &user, ts, old.get(CREATED_AT)));
        req!(self.validators.check(coll, Some(old), &stored.0));
        req!(self.write_indexes(txn, coll, id, Some(old), Some(&stored.0))?);
        txn.put(&key, stored.1)?;
        Ok(Ok(stored.0))
    }

    /// The body of [`EmbeddedDb::replace`]: replaces the stored document `id` of
    /// `database.collection` by the user document `doc` (validated by the caller).
    pub(super) fn replace_doc_in(
        &self,
        txn: &mut Txn,
        database: &str,
        collection: &str,
        id: &Value,
        doc: &Document,
    ) -> Body<Document> {
        let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
            return Ok(Err(not_found_doc(collection)));
        };
        let old = match read_doc(txn, &coll, id)? {
            Ok(Some(old)) => old,
            Ok(None) => return Ok(Err(not_found_doc(collection))),
            Err(e) => return Ok(Err(e)),
        };
        self.replace_in(txn, &coll, id, &old, doc)
    }

    /// The body of [`EmbeddedDb::delete`]: deletes the document `id` and returns it, `None` if
    /// it (or the collection) is missing.
    pub(super) fn delete_doc_in(
        &self,
        txn: &mut Txn,
        database: &str,
        collection: &str,
        id: &Value,
    ) -> Body<Option<Document>> {
        let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
            return Ok(Ok(None));
        };
        let old = match read_doc(txn, &coll, id)? {
            Ok(Some(old)) => old,
            other => return Ok(other),
        };
        req!(self.delete_in(txn, &coll, id, &old)?);
        Ok(Ok(Some(old)))
    }

    /// Deletes `old` (the stored document `id`) and its index entries.
    pub(super) fn delete_in(
        &self,
        txn: &mut Txn,
        coll: &CollectionDescriptor,
        id: &Value,
        old: &Document,
    ) -> Body<()> {
        let key = req!(doc_key(coll, id));
        req!(self.write_indexes(txn, coll, id, Some(old), None)?);
        txn.delete(&key)?;
        Ok(Ok(()))
    }
}

/// `doc` without `_rev`, `_createdAt` and `_updatedAt` (recomputed by `encode_stored`).
fn strip_server_fields(doc: &Document) -> Document {
    let mut out = doc.clone();
    for f in [REV, CREATED_AT, UPDATED_AT] {
        out.remove(f);
    }
    out
}
