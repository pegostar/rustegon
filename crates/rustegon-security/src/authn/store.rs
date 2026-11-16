// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transactional access to the system keyspace and the key layout of the authentication
//! records (security.md §2, PD-047).
//!
//! The modules follow the catalog's pattern (`rustegon_catalog::ops`): they read through
//! [`CatalogRead`] at the caller's transaction snapshot and write [`Mutation`]s **into the same
//! transaction** through [`SystemTxn::apply`]. Atomicity and isolation are the transaction
//! layer's job: two concurrent `create_user` calls with the same name both read the absent key
//! and write it, so serializable isolation makes one of them conflict instead of one silently
//! overwriting the other. The reader must observe the transaction's own writes.
//!
//! ```text
//! user            0x02 'u' name(UTF-8, no NUL)                 -> user record (user_format 1)
//! API key         0x02 'k' key_id(12 ASCII base62)            -> API key record (api_key_format 1)
//! session         0x02 'e' 0x01 blake3(token)(32)             -> session record (session_format 1)
//! session by user 0x02 'e' 0x02 user(UTF-8, no NUL) 0x00 blake3(token)(32) -> empty
//! authn secret    0x02 'e' 0x00                               -> realm record (realm_format 1)
//! ```
//! - The sub-namespace bytes `'u'`, `'k'`, `'e'` are owned by `rustegon-security::authn`
//!   (database-engine.md §2.5 lists the bytes taken by other modules).
//! - User names never contain NUL ([`crate::authn::users::validate_user_name`]), so the
//!   `0x00` after the user name in the by-user index ends the name unambiguously: the index is
//!   prefix-free and the sessions of one user are one contiguous prefix scan, which keeps the
//!   `rustegon-mvcc` rule "no key is a strict prefix of another one whose next byte is 0x00"
//!   (data-model.md §3.2).
//! - Session keys hold the BLAKE3 hash of the token, never the token: a leaked system keyspace
//!   (backup, debug dump) does not yield usable bearer tokens.

use std::{cell::RefCell, collections::BTreeMap};

use rustegon_catalog::{CatalogRead, Mutation, ops::KvPairs};
use rustegon_common::Error;
use rustegon_doc::keyspace::NS_SYSTEM;

/// Sub-namespace byte of user records.
pub const SUB_USER: u8 = b'u';
/// Sub-namespace byte of API key records.
pub const SUB_API_KEY: u8 = b'k';
/// Sub-namespace byte of session records and their by-user index.
pub const SUB_SESSION: u8 = b'e';
/// Session sub-key: the cluster-wide authentication secret (`crate::authn::realm`).
const REALM: u8 = 0x00;
/// Session sub-key: primary record by token hash.
const SESSION_BY_HASH: u8 = 0x01;
/// Session sub-key: by-user index.
const SESSION_BY_USER: u8 = 0x02;

/// A transaction over the system keyspace: snapshot reads (with read-your-writes) plus writes.
///
/// The server implements it over its engine transaction; [`MemSystemTxn`] is a non-durable
/// implementation for tests and tools.
pub trait SystemTxn: CatalogRead {
    /// Applies `mutations` in order inside the transaction.
    ///
    /// # Errors
    /// Any error of the underlying transaction (conflicts must be propagated unchanged so that
    /// the caller's retry loop sees them).
    fn apply(&mut self, mutations: Vec<Mutation>) -> Result<(), Error>;
}

/// Key of the user record `name`.
#[must_use]
pub fn user_key(name: &str) -> Vec<u8> {
    let mut k = user_prefix();
    k.extend_from_slice(name.as_bytes());
    k
}

/// Prefix of every user record.
#[must_use]
pub fn user_prefix() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_USER]
}

/// Key of the API key record `key_id`.
#[must_use]
pub fn api_key_key(key_id: &str) -> Vec<u8> {
    let mut k = api_key_prefix();
    k.extend_from_slice(key_id.as_bytes());
    k
}

/// Prefix of every API key record.
#[must_use]
pub fn api_key_prefix() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_API_KEY]
}

/// Key of the session record whose token hashes to `hash`.
#[must_use]
pub fn session_key(hash: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(35);
    k.extend_from_slice(&[NS_SYSTEM, SUB_SESSION, SESSION_BY_HASH]);
    k.extend_from_slice(hash);
    k
}

/// Key of the by-user index entry of session `hash` of `user`.
#[must_use]
pub fn session_user_key(user: &str, hash: &[u8; 32]) -> Vec<u8> {
    let mut k = session_user_prefix(user);
    k.extend_from_slice(hash);
    k
}

/// Prefix of the by-user index entries of `user` (ends with the `0x00` name terminator).
#[must_use]
pub fn session_user_prefix(user: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(4 + user.len() + 32);
    k.extend_from_slice(&[NS_SYSTEM, SUB_SESSION, SESSION_BY_USER]);
    k.extend_from_slice(user.as_bytes());
    k.push(0x00);
    k
}

/// Key of the realm record (cluster-wide authentication secret).
#[must_use]
pub fn realm_key() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_SESSION, REALM]
}

/// Prefix of every session record (not of the index).
#[must_use]
pub fn session_prefix() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_SESSION, SESSION_BY_HASH]
}

/// A non-durable [`SystemTxn`] over an in-memory map with read-your-writes, for tests and
/// single-process tools. It is not isolated from anything: one instance is one "transaction"
/// that is always committed.
#[derive(Debug, Default)]
pub struct MemSystemTxn {
    // `RefCell` is not needed for writes (they take `&mut self`), but keeps the type simple to
    // share by reference in tests.
    data: RefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemSystemTxn {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.borrow().len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.borrow().is_empty()
    }

    /// Every stored `(key, value)` pair in key order (tests inspect the persisted layout).
    #[must_use]
    pub fn dump(&self) -> KvPairs {
        self.data
            .borrow()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl CatalogRead for MemSystemTxn {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.data.borrow().get(key).cloned())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<KvPairs, Error> {
        Ok(self
            .data
            .borrow()
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

impl SystemTxn for MemSystemTxn {
    fn apply(&mut self, mutations: Vec<Mutation>) -> Result<(), Error> {
        let mut data = self.data.borrow_mut();
        for m in mutations {
            match m {
                Mutation::Put { key, value } => {
                    data.insert(key, value);
                }
                Mutation::Delete { key } => {
                    data.remove(&key);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_layout_is_prefix_free_per_user() {
        let h = [7u8; 32];
        assert_eq!(user_key("bob"), b"\x02ubob".to_vec());
        assert_eq!(api_key_key("abc"), b"\x02kabc".to_vec());
        assert_eq!(session_key(&h)[..3], [0x02, b'e', 0x01]);
        assert_eq!(session_key(&h).len(), 35);
        let bob = session_user_key("bob", &h);
        assert!(bob.starts_with(&session_user_prefix("bob")));
        assert!(!bob.starts_with(&session_user_prefix("bo")));
        assert!(!session_user_key("bob2", &h).starts_with(&session_user_prefix("bob")));
    }

    #[test]
    fn mem_txn_reads_own_writes_and_scans_prefixes() {
        let mut t = MemSystemTxn::new();
        t.apply(vec![
            Mutation::Put {
                key: user_key("a"),
                value: vec![1],
            },
            Mutation::Put {
                key: user_key("b"),
                value: vec![2],
            },
            Mutation::Put {
                key: api_key_key("x"),
                value: vec![3],
            },
        ])
        .unwrap();
        assert_eq!(t.get(&user_key("a")).unwrap(), Some(vec![1]));
        assert_eq!(t.scan_prefix(&user_prefix()).unwrap().len(), 2);
        t.apply(vec![Mutation::Delete { key: user_key("a") }])
            .unwrap();
        assert_eq!(t.get(&user_key("a")).unwrap(), None);
        assert_eq!(t.len(), 2);
    }
}
