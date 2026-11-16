// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The security system store over the engine (PD-051): `rustegon_security`'s transaction-agnostic
//! record modules (users, API keys, sessions, realm, roles) and the runtime settings run inside
//! one [`rustegon_engine::EmbeddedDb::system_transaction`] per operation.
//!
//! [`EngineTxn`] adapts the engine's [`SystemTxnHandle`] to the
//! [`rustegon_security::authn::SystemTxn`] trait (the engine does not depend on the security
//! crate); [`Reader`] lets functions that take `&impl CatalogRead` read through a
//! `&dyn SystemTxn`.

use rustegon_catalog::{CatalogRead, Mutation, ops::KvPairs};
use rustegon_common::Error;
use rustegon_engine::SystemTxnHandle;
use rustegon_security::authn::SystemTxn;

/// [`SystemTxn`] over an engine system transaction.
pub struct EngineTxn<'h, 'a>(pub &'h mut SystemTxnHandle<'a>);

impl std::fmt::Debug for EngineTxn<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl CatalogRead for EngineTxn<'_, '_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.0.get(key)
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<KvPairs, Error> {
        self.0.scan_prefix(prefix)
    }
}

impl SystemTxn for EngineTxn<'_, '_> {
    fn apply(&mut self, mutations: Vec<Mutation>) -> Result<(), Error> {
        self.0.apply(mutations)
    }
}

/// A sized [`CatalogRead`] over any `&dyn SystemTxn` (for `&impl CatalogRead` parameters).
pub struct Reader<'a>(pub &'a dyn SystemTxn);

impl CatalogRead for Reader<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.0.get(key)
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<KvPairs, Error> {
        self.0.scan_prefix(prefix)
    }
}
