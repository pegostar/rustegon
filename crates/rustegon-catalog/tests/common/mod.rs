// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! In-memory [`CatalogRead`] for tests: a sorted map standing in for an MVCC snapshot that
//! sees its own writes.

use std::collections::BTreeMap;

use rustegon_catalog::{CatalogRead, Mutation, ops::KvPairs};
use rustegon_common::Error;

/// The system keyspace as a sorted map.
#[derive(Debug, Default, Clone)]
pub struct MemCatalog {
    pub kv: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemCatalog {
    /// Applies mutations as a committing transaction would.
    pub fn apply(&mut self, mutations: &[Mutation]) {
        for m in mutations {
            match m {
                Mutation::Put { key, value } => {
                    self.kv.insert(key.clone(), value.clone());
                }
                Mutation::Delete { key } => {
                    self.kv.remove(key);
                }
            }
        }
    }
}

impl CatalogRead for MemCatalog {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.kv.get(key).cloned())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<KvPairs, Error> {
        Ok(self
            .kv
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}
