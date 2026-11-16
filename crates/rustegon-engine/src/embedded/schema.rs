// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Catalog reads and drops for the server's `SchemaService` (M4 wave 2b lane G, PD-053):
//! listing databases and collections, describing one collection, `DROP COLLECTION` /
//! `DROP DATABASE`, and the transaction limits the server reports to clients.
//!
//! Each call is one SERIALIZABLE transaction like every embedded call. A drop only marks the
//! descriptors `Dropping` and frees the names (`rustegon_catalog::ops`): the documents and index
//! entries of a dropped collection stay in its key span until the GC job of a later milestone
//! reclaims it. They are unreachable — a collection created again with the same name gets a new
//! id and therefore a disjoint key span — so this costs space only (PD-053).

use rustegon_catalog::{
    CollectionDescriptor, DatabaseDescriptor, Descriptor, DescriptorState, IndexSpec,
    drop_collection, drop_database, get_descriptor, keys::ROOT_PARENT_ID, list_names,
};
use rustegon_common::Error;
use rustegon_query::{Params, ast::CreateIndex};
use rustegon_txn::TxnConfig;

use super::{EmbeddedDb, apply, catalog, ddl, existing_collection, require_database};

impl EmbeddedDb {
    /// The public databases, in name order.
    ///
    /// # Errors
    /// Transaction errors, corrupt catalog entries.
    pub fn list_databases(&self) -> Result<Vec<DatabaseDescriptor>, Error> {
        self.run(|txn| {
            catalog(txn, |r| {
                let mut out = Vec::new();
                for (_, id) in list_names(r, ROOT_PARENT_ID)? {
                    if let Some(Descriptor::Database(d)) = get_descriptor(r, id)?
                        && d.state == DescriptorState::Public
                    {
                        out.push(d);
                    }
                }
                Ok(out)
            })
        })
    }

    /// The public database `name`, `None` if missing.
    ///
    /// # Errors
    /// Transaction errors, corrupt catalog entries.
    pub fn database(&self, name: &str) -> Result<Option<DatabaseDescriptor>, Error> {
        self.run(|txn| catalog(txn, |r| rustegon_catalog::get_database(r, name)))
    }

    /// The public collections of `database`, in name order.
    ///
    /// # Errors
    /// `RGN-1030` for a missing database, transaction errors.
    pub fn list_collections(&self, database: &str) -> Result<Vec<CollectionDescriptor>, Error> {
        self.run(|txn| {
            catalog(txn, |r| {
                let db = require_database(r, database)?;
                let mut out = Vec::new();
                for (_, id) in list_names(r, db.id)? {
                    if let Some(Descriptor::Collection(c)) = get_descriptor(r, id)?
                        && c.state == DescriptorState::Public
                    {
                        out.push(c);
                    }
                }
                Ok(out)
            })
        })
    }

    /// The collection `database.collection`, `None` if it is missing.
    ///
    /// # Errors
    /// `RGN-1030` for a missing database, transaction errors.
    pub fn collection(
        &self,
        database: &str,
        collection: &str,
    ) -> Result<Option<CollectionDescriptor>, Error> {
        self.run(|txn| existing_collection(txn, database, collection))
    }

    /// `DROP COLLECTION database.collection` (module docs: the data is reclaimed later).
    /// Returns `false` if the collection does not exist.
    ///
    /// # Errors
    /// `RGN-1030` for a missing database, transaction errors.
    pub fn drop_collection(&self, database: &str, collection: &str) -> Result<bool, Error> {
        self.run(|txn| {
            let Some(coll) = req!(existing_collection(txn, database, collection)?) else {
                return Ok(Ok(false));
            };
            let mutations = req!(catalog(txn, |r| drop_collection(r, &coll))?);
            apply(txn, &mutations)?;
            Ok(Ok(true))
        })
    }

    /// `DROP DATABASE name` with every collection in it (module docs). Returns `false` if the
    /// database does not exist.
    ///
    /// # Errors
    /// Transaction errors.
    pub fn drop_database(&self, name: &str) -> Result<bool, Error> {
        self.run(|txn| {
            let Some(db) = req!(catalog(txn, |r| rustegon_catalog::get_database(r, name))?) else {
                return Ok(Ok(false));
            };
            let mutations = req!(catalog(txn, |r| drop_database(r, &db))?);
            apply(txn, &mutations)?;
            Ok(Ok(true))
        })
    }

    /// The [`IndexSpec`] of a structured `CREATE INDEX`, under exactly the rules of the RGQL
    /// statement (supported index types and options), for a caller that drives the online
    /// build itself ([`EmbeddedDb::start_index_build`] / [`EmbeddedDb::step_index_build`]).
    ///
    /// # Errors
    /// `RGN-1001` for unsupported index types, key paths or options.
    pub fn index_spec(ci: &CreateIndex, params: &Params) -> Result<IndexSpec, Error> {
        ddl::index_spec(ci, params)
    }

    /// The transaction limits of this store (`txn.liveness_timeout`, `txn.heartbeat_interval`,
    /// `txn.max_duration`, …), reported to clients by the server (`BeginResponse`).
    #[must_use]
    pub fn txn_config(&self) -> &TxnConfig {
        self.coord.config()
    }
}
