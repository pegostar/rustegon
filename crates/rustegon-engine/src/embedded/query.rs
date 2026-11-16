// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! RGQL through the embedded API (M3 lane F; FR-QL-001, FR-QL-003, FR-QL-008).
//!
//! - [`EmbeddedDb::query`] runs one statement (text or AST) in an implicit SERIALIZABLE
//!   transaction, retried on retryable conflicts like every embedded call;
//! - [`EmbeddedDb::transaction`] runs several statements in one explicit transaction
//!   ([`QuerySession::query`]); a statement error rolls back only that statement, an error
//!   returned by the body rolls back the whole transaction, a transaction conflict re-runs the
//!   body;
//! - [`QueryTxn`] adapts a transaction to the engine's [`QueryStore`]: reads go straight to the
//!   transaction, writes through the shared write path (`write.rs`).
//!
//! DDL statements (`CREATE DATABASE|COLLECTION|INDEX`, `DROP INDEX`) are executed by the
//! existing catalog methods (`ddl.rs`), each in its own transaction, so they are rejected
//! inside an explicit transaction.

use std::{ops::Bound, sync::Arc};

use rustegon_catalog::{
    CollectionDescriptor, DatabaseDescriptor, IndexDescriptor, IndexState, get_collection,
    get_database, index::ops::list_indexes,
};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value, limits::validate_user_document, rdoc};
use rustegon_index::{IndexError, IndexPage, document_key_for_element, scan_index_page};
use rustegon_query::{
    ExecError, ExecOptions, ExecResult, Params, QueryResult, QueryStore, Statement,
    bind::CatalogView,
    execute, parse_statement,
    stats::{CollectionStats, IndexUsageRegistry},
};
use rustegon_txn::{Txn, TxnError};

use super::{Body, EmbeddedDb, ID, NANOS_PER_MILLI, catalog, ddl, read_doc};

/// Savepoint of an explicit transaction (a failing body leaves nothing to commit).
const TRANSACTION_SAVEPOINT: &str = "rustegon.embedded.transaction";

/// A statement as text or as a (structured) AST.
#[derive(Debug, Clone, Copy)]
pub enum QueryInput<'a> {
    /// RGQL text.
    Text(&'a str),
    /// A parsed or structured statement (FR-QL-002).
    Statement(&'a Statement),
}

impl<'a> From<&'a str> for QueryInput<'a> {
    fn from(s: &'a str) -> Self {
        Self::Text(s)
    }
}

impl<'a> From<&'a String> for QueryInput<'a> {
    fn from(s: &'a String) -> Self {
        Self::Text(s)
    }
}

impl<'a> From<&'a Statement> for QueryInput<'a> {
    fn from(s: &'a Statement) -> Self {
        Self::Statement(s)
    }
}

pub(super) fn parse(input: QueryInput<'_>) -> Result<Statement, Error> {
    match input {
        // `From` keeps line/column/found/expected in the details (errors.yaml RGN-1010).
        QueryInput::Text(t) => parse_statement(t).map_err(Error::from),
        QueryInput::Statement(s) => Ok(s.clone()),
    }
}

/// Splits a body result into the engine's error levels.
fn lift<T>(b: Body<T>) -> ExecResult<T> {
    match b {
        Err(t) => Err(ExecError::Txn(t)),
        Ok(Err(e)) => Err(ExecError::Query(e)),
        Ok(Ok(v)) => Ok(v),
    }
}

/// The engine's result as a transaction body.
pub(super) fn body<T>(r: ExecResult<T>) -> Body<T> {
    match r {
        Ok(v) => Ok(Ok(v)),
        Err(ExecError::Query(e)) => Ok(Err(e)),
        Err(ExecError::Txn(t)) => Err(t),
    }
}

fn index_result<T>(r: Result<T, IndexError>) -> ExecResult<T> {
    match r {
        Ok(v) => Ok(v),
        Err(IndexError::Txn(e)) => Err(ExecError::Txn(e)),
        Err(IndexError::Rejected(e)) => Err(ExecError::Query(e)),
    }
}

impl EmbeddedDb {
    /// Executes one RGQL statement on the session database `database` with `params`, in an
    /// implicit transaction (module docs).
    ///
    /// # Errors
    /// `RGN-1010`/`RGN-1013` (parse), bind errors (`RGN-1011`, `RGN-1012`, `RGN-1021`,
    /// `RGN-1030`), write errors (`RGN-1005`, `RGN-1006`, …), `RGN-5004`/`RGN-5006`,
    /// transaction errors after the retries.
    pub fn query<'a>(
        &self,
        database: &str,
        input: impl Into<QueryInput<'a>>,
        params: &Params,
    ) -> Result<QueryResult, Error> {
        self.query_with(database, input, params, &ExecOptions::default())
    }

    /// [`EmbeddedDb::query`] with executor options (batch sizes, memory limit, interrupt,
    /// access-path override for equivalence tests).
    ///
    /// # Errors
    /// As [`EmbeddedDb::query`].
    pub fn query_with<'a>(
        &self,
        database: &str,
        input: impl Into<QueryInput<'a>>,
        params: &Params,
        options: &ExecOptions,
    ) -> Result<QueryResult, Error> {
        let stmt = parse(input.into())?;
        if ddl::is_ddl(&stmt) {
            return ddl::run(self, database, &stmt, params);
        }
        let opts = self.exec_options(options);
        self.load_statistics();
        self.run(|txn| body(execute_in(self, txn, database, &stmt, params, &opts)))
    }

    /// Runs `f` in one explicit transaction (module docs); the body may run more than once
    /// (retries), so it must be repeatable.
    ///
    /// # Errors
    /// The body's error (the transaction is rolled back), transaction errors after retries.
    pub fn transaction<T>(
        &self,
        mut f: impl FnMut(&mut QuerySession<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.load_statistics();
        self.run(|txn| {
            txn.savepoint(TRANSACTION_SAVEPOINT)?;
            let (result, failed) = {
                let mut s = QuerySession {
                    db: self,
                    txn,
                    failed: None,
                };
                let r = f(&mut s);
                (r, s.failed)
            };
            if let Some(t) = failed {
                // Restart the whole transaction (the coordinator decides whether to retry).
                return Err(t);
            }
            match result {
                Ok(v) => Ok(Ok(v)),
                Err(e) => {
                    txn.rollback_to_savepoint(TRANSACTION_SAVEPOINT)?;
                    Ok(Err(e))
                }
            }
        })
    }

    pub(super) fn exec_options(&self, options: &ExecOptions) -> ExecOptions {
        let mut opts = options.clone();
        if opts.clock.is_none() {
            opts.clock = Some(std::sync::Arc::clone(&self.clock));
        }
        opts
    }
}

/// Executes the (non-DDL) statement `stmt` in `txn`: the one execution path of implicit,
/// explicit and interactive transactions.
pub(super) fn execute_in(
    db: &EmbeddedDb,
    txn: &mut Txn,
    database: &str,
    stmt: &Statement,
    params: &Params,
    opts: &ExecOptions,
) -> ExecResult<QueryResult> {
    let mut store = QueryTxn { db, txn };
    execute(&mut store, database, stmt, params, opts)
}

/// Statements of one explicit transaction (see [`EmbeddedDb::transaction`]).
pub struct QuerySession<'a> {
    db: &'a EmbeddedDb,
    txn: &'a mut Txn,
    failed: Option<TxnError>,
}

impl std::fmt::Debug for QuerySession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuerySession")
            .field("failed", &self.failed.is_some())
            .finish_non_exhaustive()
    }
}

impl QuerySession<'_> {
    /// Executes one statement in the session's transaction.
    ///
    /// # Errors
    /// As [`EmbeddedDb::query`]; DDL is rejected (`RGN-1001`); after a transaction error every
    /// further statement fails until the body returns (the transaction then restarts).
    pub fn query<'q>(
        &mut self,
        database: &str,
        input: impl Into<QueryInput<'q>>,
        params: &Params,
    ) -> Result<QueryResult, Error> {
        self.query_with(database, input, params, &ExecOptions::default())
    }

    /// [`QuerySession::query`] with executor options.
    ///
    /// # Errors
    /// As [`QuerySession::query`].
    pub fn query_with<'q>(
        &mut self,
        database: &str,
        input: impl Into<QueryInput<'q>>,
        params: &Params,
        options: &ExecOptions,
    ) -> Result<QueryResult, Error> {
        if self.failed.is_some() {
            return Err(Error::new(
                ErrorCode::TransactionAborted,
                "the transaction failed and must restart",
            ));
        }
        let stmt = parse(input.into())?;
        if ddl::is_ddl(&stmt) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "DDL statements cannot run inside an explicit transaction",
            ));
        }
        let opts = self.db.exec_options(options);
        match execute_in(self.db, self.txn, database, &stmt, params, &opts) {
            Ok(r) => Ok(r),
            Err(ExecError::Query(e)) => Err(e),
            Err(ExecError::Txn(t)) => {
                let e = Error::new(t.code(), t.to_string());
                self.failed = Some(t);
                Err(e)
            }
        }
    }
}

/// [`QueryStore`] over one embedded transaction (module docs).
pub struct QueryTxn<'a> {
    pub(super) db: &'a EmbeddedDb,
    pub(super) txn: &'a mut Txn,
}

impl CatalogView for QueryTxn<'_> {
    fn database(&mut self, name: &str) -> ExecResult<Option<DatabaseDescriptor>> {
        lift(catalog(self.txn, |r| get_database(r, name)))
    }

    fn collection(
        &mut self,
        db: &DatabaseDescriptor,
        name: &str,
    ) -> ExecResult<Option<CollectionDescriptor>> {
        lift(catalog(self.txn, |r| get_collection(r, db.id, name)))
    }

    fn indexes(&mut self, coll: &CollectionDescriptor) -> ExecResult<Vec<IndexDescriptor>> {
        let all = lift(catalog(self.txn, |r| list_indexes(r, coll.id)))?;
        Ok(all
            .into_iter()
            .filter(|i| i.state != IndexState::Dropping)
            .collect())
    }
}

impl QueryStore for QueryTxn<'_> {
    fn get(&mut self, coll: &CollectionDescriptor, id: &Value) -> ExecResult<Option<Document>> {
        lift(read_doc(self.txn, coll, id))
    }

    fn scan(
        &mut self,
        start: &[u8],
        end: &[u8],
        max: usize,
    ) -> ExecResult<Vec<(Vec<u8>, Document)>> {
        let rows = self.txn.scan(start, end, max)?;
        let mut out = Vec::with_capacity(rows.len());
        for (k, v) in rows {
            out.push((k, rdoc::decode(&v)?));
        }
        Ok(out)
    }

    fn scan_index(
        &mut self,
        index: &IndexDescriptor,
        lower: Bound<&[Option<Value>]>,
        upper: Bound<&[Option<Value>]>,
        after: Option<&[u8]>,
        max: usize,
    ) -> ExecResult<IndexPage> {
        index_result(scan_index_page(self.txn, index, lower, upper, after, max))
    }

    fn fetch(
        &mut self,
        coll: &CollectionDescriptor,
        id_element: &[u8],
    ) -> ExecResult<Option<Document>> {
        let key = document_key_for_element(
            coll.database_id,
            coll.id,
            coll.shard_key.shard_hash(),
            id_element,
        );
        match self.txn.get(&key)? {
            None => Ok(None),
            Some(bytes) => Ok(Some(rdoc::decode(&bytes)?)),
        }
    }

    fn insert(&mut self, database: &str, collection: &str, doc: Document) -> ExecResult<Document> {
        validate_user_document(&doc)?;
        let id = self.db.id_for(&doc);
        lift(self.db.insert_in(self.txn, database, collection, &doc, &id))
    }

    fn replace(
        &mut self,
        coll: &CollectionDescriptor,
        old: &Document,
        new: Document,
    ) -> ExecResult<Document> {
        let id = stored_id(old)?;
        lift(self.db.replace_in(self.txn, coll, &id, old, &new))
    }

    fn delete(&mut self, coll: &CollectionDescriptor, old: &Document) -> ExecResult<()> {
        let id = stored_id(old)?;
        lift(self.db.delete_in(self.txn, coll, &id, old))
    }

    fn now_ms(&self) -> i64 {
        i64::try_from(self.txn.read_ts().wall / NANOS_PER_MILLI).unwrap_or(i64::MAX)
    }

    fn savepoint(&mut self, name: &str) -> ExecResult<()> {
        Ok(self.txn.savepoint(name)?)
    }

    fn rollback_to_savepoint(&mut self, name: &str) -> ExecResult<()> {
        Ok(self.txn.rollback_to_savepoint(name)?)
    }

    fn release_savepoint(&mut self, name: &str) -> ExecResult<()> {
        Ok(self.txn.release_savepoint(name)?)
    }

    /// From the process cache, not through the transaction (`embedded/analyze.rs`).
    fn collection_stats(
        &mut self,
        coll: &CollectionDescriptor,
    ) -> ExecResult<Option<Arc<CollectionStats>>> {
        Ok(self.db.stats_cache.get(coll.id))
    }

    fn index_usage(&self) -> Option<&IndexUsageRegistry> {
        Some(&self.db.usage)
    }
}

fn stored_id(doc: &Document) -> Result<Value, Error> {
    doc.get(ID)
        .cloned()
        .ok_or_else(|| Error::new(ErrorCode::StorageCorruption, "stored document without _id"))
}
