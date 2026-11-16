// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Raw transactions over the system keyspace (`0x02`, data-model.md §3.2) for the security
//! records of `rustegon-security` (users, API keys, sessions, realm, roles) and the runtime
//! settings of the server (M4 wave 2b lane H, PD-051).
//!
//! The security and settings modules are transaction-agnostic like the catalog: they read
//! through [`CatalogRead`] at the caller's snapshot and write [`Mutation`]s into the same
//! transaction. [`EmbeddedDb::system_transaction`] provides that transaction:
//!
//! - one SERIALIZABLE transaction per call, retried by [`rustegon_txn::TxnCoordinator::run`] on
//!   retryable errors (conflicts, deadlock victims), so concurrent read-modify-write sequences
//!   (two `create_user` of one name, two role updates closing a cycle) cannot both commit;
//! - **writes are buffered** in the handle and applied to the transaction only when the body
//!   returns `Ok`: a body failing with a request error (`RGN-1001`, `RGN-1031`, …) after it
//!   already "wrote" leaves nothing behind, because the transaction it commits contains no
//!   write. Reads see the buffered writes (read-your-writes), which the security modules rely
//!   on (`drop_user` deletes the user, then scans its sessions);
//! - every key must lie in the system keyspace: the handle refuses keys outside `0x02`
//!   (`RGN-5001`), so this API cannot be used to bypass the document write path (validators,
//!   indexes, server-maintained fields) of user data.
//!
//! Transaction errors met while reading are kept aside and returned as such after the body,
//! like the catalog adapter does, so a retryable conflict reaches the retry loop even when the
//! body converted the read error into its own error type.

use std::{
    cell::RefCell,
    collections::{BTreeMap, btree_map::Entry},
};

use rustegon_catalog::{CatalogRead, Mutation, ops::KvPairs};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::keyspace::NS_SYSTEM;
use rustegon_txn::Txn;

use super::{EmbeddedDb, TxnReader, apply};

/// A transaction over the system keyspace (module docs): snapshot reads with read-your-writes,
/// buffered writes applied when the body succeeds.
pub struct SystemTxnHandle<'a> {
    reader: TxnReader<'a>,
    /// Buffered writes by key: `Some(value)` = put, `None` = delete. A `BTreeMap` keeps them in
    /// key order, so prefix scans merge them in one pass and they are applied deterministically.
    pending: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl std::fmt::Debug for SystemTxnHandle<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemTxnHandle")
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

fn check_system_key(key: &[u8]) -> Result<(), Error> {
    if key.first() == Some(&NS_SYSTEM) && key.len() > 1 {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::Internal,
            "system transaction write outside the system keyspace",
        ))
    }
}

impl SystemTxnHandle<'_> {
    /// Buffers `mutations` in order (later mutations of one key win).
    ///
    /// # Errors
    /// `RGN-5001` when a key is not a system key (`0x02` followed by a sub-namespace byte);
    /// nothing of this call is buffered then.
    pub fn apply(&mut self, mutations: Vec<Mutation>) -> Result<(), Error> {
        for m in &mutations {
            match m {
                Mutation::Put { key, .. } | Mutation::Delete { key } => check_system_key(key)?,
            }
        }
        for m in mutations {
            match m {
                Mutation::Put { key, value } => self.pending.insert(key, Some(value)),
                Mutation::Delete { key } => self.pending.insert(key, None),
            };
        }
        Ok(())
    }

    /// Number of buffered writes (distinct keys).
    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.pending.len()
    }
}

impl CatalogRead for SystemTxnHandle<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self.pending.get(key) {
            Some(buffered) => Ok(buffered.clone()),
            None => self.reader.get(key),
        }
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<KvPairs, Error> {
        let stored = self.reader.scan_prefix(prefix)?;
        if self.pending.is_empty() {
            return Ok(stored);
        }
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = stored.into_iter().collect();
        for (key, value) in self
            .pending
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
        {
            match (merged.entry(key.clone()), value) {
                (Entry::Occupied(mut e), Some(v)) => {
                    e.insert(v.clone());
                }
                (Entry::Vacant(e), Some(v)) => {
                    e.insert(v.clone());
                }
                (Entry::Occupied(e), None) => {
                    e.remove();
                }
                (Entry::Vacant(_), None) => {}
            }
        }
        Ok(merged.into_iter().collect())
    }
}

impl EmbeddedDb {
    /// Runs `body` in one serializable transaction over the system keyspace (module docs) and
    /// commits its writes atomically when it returns `Ok`.
    ///
    /// `body` may run more than once (retries after retryable conflicts), each time with a fresh
    /// handle, so it must not keep side effects outside the handle between attempts.
    ///
    /// # Errors
    /// The body's own error (nothing is written then); transaction errors after the retries
    /// (`RGN-2001`, …); `RGN-5001` for a write outside the system keyspace.
    pub fn system_transaction<T>(
        &self,
        mut body: impl FnMut(&mut SystemTxnHandle<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.run(|txn: &mut Txn| {
            let (result, pending, failed) = {
                let mut handle = SystemTxnHandle {
                    reader: TxnReader {
                        txn: RefCell::new(txn),
                        failed: RefCell::new(None),
                    },
                    pending: BTreeMap::new(),
                };
                let result = body(&mut handle);
                let failed = handle.reader.failed.into_inner();
                (result, handle.pending, failed)
            };
            // A transaction error seen by a read wins over whatever the body made of it: it
            // must reach the retry loop (or the caller) as the transaction error it is.
            if let Some(e) = failed {
                return Err(e);
            }
            match result {
                Ok(value) => {
                    let mutations: Vec<Mutation> = pending
                        .into_iter()
                        .map(|(key, value)| match value {
                            Some(value) => Mutation::Put { key, value },
                            None => Mutation::Delete { key },
                        })
                        .collect();
                    apply(txn, &mutations)?;
                    Ok(Ok(value))
                }
                // Nothing was applied to the transaction, so its commit writes nothing.
                Err(e) => Ok(Err(e)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::Arc;

    use rustegon_sim_api::{FileSystem, OsRng, StdFileSystem, SystemClock};

    use super::*;

    fn db() -> (tempfile::TempDir, EmbeddedDb) {
        let dir = tempfile::tempdir().unwrap();
        let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
        let db = EmbeddedDb::open(
            fs,
            dir.path(),
            Arc::new(SystemClock::new()),
            Arc::new(OsRng),
        )
        .unwrap();
        (dir, db)
    }

    fn put(key: &[u8], value: &[u8]) -> Mutation {
        Mutation::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        }
    }

    #[test]
    fn system_transaction_commits_and_reads_its_own_writes() {
        let (_dir, db) = db();
        let seen = db
            .system_transaction(|t| {
                t.apply(vec![put(b"\x02za", b"1"), put(b"\x02zb", b"2")])?;
                t.apply(vec![Mutation::Delete {
                    key: b"\x02za".to_vec(),
                }])?;
                assert_eq!(t.get(b"\x02za")?, None);
                t.scan_prefix(b"\x02z")
            })
            .unwrap();
        assert_eq!(seen, vec![(b"\x02zb".to_vec(), b"2".to_vec())]);
        let stored = db
            .system_transaction(|t| {
                t.apply(vec![put(b"\x02zc", b"3")])?;
                t.scan_prefix(b"\x02z")
            })
            .unwrap();
        assert_eq!(stored.len(), 2);
    }

    #[test]
    fn system_transaction_writes_nothing_when_the_body_fails() {
        let (_dir, db) = db();
        let err = db
            .system_transaction::<()>(|t| {
                t.apply(vec![put(b"\x02zx", b"1")])?;
                Err(Error::new(ErrorCode::AlreadyExists, "exists"))
            })
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        let after = db.system_transaction(|t| t.get(b"\x02zx")).unwrap();
        assert_eq!(after, None);
    }

    #[test]
    fn system_transaction_refuses_keys_outside_the_system_keyspace() {
        let (_dir, db) = db();
        for key in [&b"\x03user"[..], b"\x02", b""] {
            let err = db
                .system_transaction(|t| t.apply(vec![put(key, b"x")]))
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::Internal);
        }
    }
}
