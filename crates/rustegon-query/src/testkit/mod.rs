// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Differential-testing kit for RGQL engines (query-engine.md §11; AC-QL-002; TC-QL-010).
//!
//! Feature `testkit`. Pieces:
//! - [`QueryEngine`]: the adapter an engine implements to be tested (the reference interpreter
//!   implements it; a real engine needs a ~20-line adapter, see the trait docs);
//! - [`datagen`] / [`casegen`]: seeded generators of documents, expressions and statements;
//! - [`oracle`]: the differential oracle (engine vs reference, outputs and collection state
//!   after writes), TLP (ternary logic partitioning) and `NoREC` (non-optimising reference
//!   engine construction), in the style of the `SQLancer` tool;
//! - [`runner`]: seeded campaigns with a case or wall-clock budget (`RGQL_DIFF_SECONDS`,
//!   `RGQL_DIFF_CASES`, `RGQL_DIFF_SEED`) whose failures print the seed and the statement text.
//!
//! **Result comparison.** Rows are compared through their extended JSON text, i.e. by type and
//! value (`1` and `1.0` differ, field order counts). Results of a query whose `ORDER BY` ends with
//! `_id` (a total order) are compared as sequences; other results as multisets; with `LIMIT`/
//! `OFFSET` but no total order, only the row count is compared (any subset is correct).

pub mod casegen;
pub mod datagen;
pub mod oracle;
pub mod rng;
pub mod runner;

use rustegon_common::Error;
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, value_to_json},
};

pub use crate::reference::{Output, Params, Reference, is_unsupported};
use crate::{ast::Statement, reference::collection_key};

/// An engine under test.
///
/// Contract:
/// - `now()` and `CURRENT DATE` must evaluate to [`crate::reference::DEFAULT_NOW_MS`], or the
///   generator must run with [`datagen::GenConfig::time_dependent`] off (the default);
/// - an error for a feature the engine does not implement should carry the detail
///   [`crate::reference::UNSUPPORTED_DETAIL`] (the statement is then skipped, not failed);
/// - [`Output::affected`] is `None` for reads and the number of matched/written documents for
///   writes; [`Output::rows`] holds the result rows or `RETURNING` images.
///
/// A sketch of an adapter over an embedded engine:
/// ```ignore
/// struct Embedded(EmbeddedDb);
/// impl QueryEngine for Embedded {
///     fn name(&self) -> &str { "engine" }
///     fn reset(&mut self) -> Result<(), Error> { self.0 = EmbeddedDb::open_fresh()?; Ok(()) }
///     fn load(&mut self, coll: &str, docs: &[Document]) -> Result<(), Error> {
///         self.0.insert_many(coll, docs)
///     }
///     fn run(&mut self, stmt: &Statement, params: &Params) -> Result<Output, Error> {
///         let r = self.0.query(stmt, params)?;
///         Ok(Output { rows: r.rows, affected: r.affected })
///     }
///     fn scan(&mut self, coll: &str) -> Result<Vec<Document>, Error> { self.0.scan(coll) }
/// }
/// ```
pub trait QueryEngine {
    /// Name used in reports.
    fn name(&self) -> &str;

    /// Drops every collection.
    ///
    /// # Errors
    /// Engine failures.
    fn reset(&mut self) -> Result<(), Error>;

    /// Bulk-loads documents (each has an `_id`) into `collection`, creating it.
    ///
    /// # Errors
    /// Engine failures.
    fn load(&mut self, collection: &str, docs: &[Document]) -> Result<(), Error>;

    /// Executes one statement.
    ///
    /// # Errors
    /// The statement's error (compared by code with the reference's).
    fn run(&mut self, stmt: &Statement, params: &Params) -> Result<Output, Error>;

    /// Every document of `collection`, in any order (empty when it does not exist).
    ///
    /// # Errors
    /// Engine failures.
    fn scan(&mut self, collection: &str) -> Result<Vec<Document>, Error>;
}

impl QueryEngine for Reference {
    #[allow(clippy::unnecessary_literal_bound)] // The trait signature serves non-literal names.
    fn name(&self) -> &str {
        "reference"
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.clear();
        Ok(())
    }

    fn load(&mut self, collection: &str, docs: &[Document]) -> Result<(), Error> {
        Reference::load(self, collection, docs.iter().cloned());
        Ok(())
    }

    fn run(&mut self, stmt: &Statement, params: &Params) -> Result<Output, Error> {
        self.execute(stmt, params)
    }

    fn scan(&mut self, collection: &str) -> Result<Vec<Document>, Error> {
        Ok(self.documents(collection).to_vec())
    }
}

/// Canonical text of a row: extended JSON (type-exact, field order kept).
#[must_use]
pub fn row_key(v: &Value) -> String {
    value_to_json(v, JsonMode::Extended)
}

/// Canonical texts of rows, sorted (multiset form).
#[must_use]
pub fn multiset(rows: &[Value]) -> Vec<String> {
    let mut keys: Vec<String> = rows.iter().map(row_key).collect();
    keys.sort();
    keys
}

/// The collection a write statement modifies (`None` for reads and other statements).
#[must_use]
pub fn write_target(stmt: &Statement) -> Option<String> {
    let name = match stmt {
        Statement::Insert(s) => &s.target,
        Statement::Update(s) => &s.target,
        Statement::Upsert(s) => &s.target,
        Statement::Delete(s) => &s.target,
        _ => return None,
    };
    Some(collection_key(name))
}
