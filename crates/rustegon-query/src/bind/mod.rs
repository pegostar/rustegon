// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The binder (query-engine.md §2): resolves names against the catalog, substitutes parameters
//! and resolves functions, producing a [`BoundStatement`] whose expressions are normalised
//! ([`crate::plan::rewrite`]).
//!
//! Name resolution: `[db.]collection` uses the session database when the database is omitted;
//! a missing database is `RGN-1030`, and so is a missing collection for reads, `UPDATE` and
//! `DELETE` (`INSERT` / `UPSERT` create it implicitly when the database allows, FR-SCH-001).
//! `OPTIONS (index = 'name')` forces an index (`RGN-1021` when it does not exist; a hidden index
//! may be forced, FR-IDX-006).
//!
//! M3 scope: `LOOKUP`, `GROUP BY`/`HAVING`, pipeline stages, `INCLUDE`, sub-query and
//! map-reduce sources are aggregation/join features of M7 and rejected as unsupported, as are
//! `AS OF SYSTEM TIME` (historical reads), wide-column rows and `USING TTL` (M8).

mod query;
mod write;

use rustegon_catalog::{CollectionDescriptor, DatabaseDescriptor, IndexDescriptor};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::Value;

pub use self::{
    expr::{ExprBinder, cmp, literal_value},
    query::{bind_query, bind_select},
    write::{BoundConflict, BoundInsert, BoundOps, BoundUpdateOp, InsertRows},
};
use crate::{
    ast::{OptionItem, QualifiedName, Statement},
    error::{ExecResult, not_found, unsupported},
    expr::{BExpr, Step},
    params::Params,
};

pub mod expr;

/// Catalog access needed by the binder (implemented by the storage adapter; tests use an
/// in-memory catalog).
pub trait CatalogView {
    /// The database `name`.
    ///
    /// # Errors
    /// Transaction or catalog errors.
    fn database(&mut self, name: &str) -> ExecResult<Option<DatabaseDescriptor>>;

    /// The collection `name` of `db`.
    ///
    /// # Errors
    /// Transaction or catalog errors.
    fn collection(
        &mut self,
        db: &DatabaseDescriptor,
        name: &str,
    ) -> ExecResult<Option<CollectionDescriptor>>;

    /// The non-dropping indexes of `coll`.
    ///
    /// # Errors
    /// Transaction or catalog errors.
    fn indexes(&mut self, coll: &CollectionDescriptor) -> ExecResult<Vec<IndexDescriptor>>;
}

/// The collection a statement targets.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    /// Database.
    pub database: DatabaseDescriptor,
    /// Collection name.
    pub name: String,
    /// The collection, `None` when it does not exist yet (insert / upsert create it).
    pub collection: Option<CollectionDescriptor>,
    /// Its non-dropping indexes.
    pub indexes: Vec<IndexDescriptor>,
}

/// One `ORDER BY` key.
#[derive(Debug, Clone, PartialEq)]
pub struct SortKey {
    /// Key expression.
    pub expr: BExpr,
    /// Descending.
    pub descending: bool,
}

/// One projection item.
#[derive(Debug, Clone, PartialEq)]
pub enum BoundProjection {
    /// `expr [AS name]`.
    Field {
        /// Output field.
        name: String,
        /// Value.
        expr: BExpr,
    },
    /// `path.*`.
    Wildcard(BExpr),
    /// `-path`.
    Exclude(Vec<Step>),
}

/// What a query returns per row.
#[derive(Debug, Clone, PartialEq)]
pub enum BoundSelect {
    /// The whole document (`SELECT *` or no `SELECT`).
    Document,
    /// `SELECT VALUE expr`.
    Value(BExpr),
    /// Projection items (*Provisional (PD pending)*: when only exclusions are listed, the
    /// whole document minus them; otherwise the listed fields, then the exclusions removed).
    Items(Vec<BoundProjection>),
}

/// How the planner may choose the access path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum IndexHint {
    /// Rule-based choice.
    #[default]
    Auto,
    /// `OPTIONS (index = 'name')`.
    Force(String),
    /// Never use an index (equivalence testing, TC-IDX-001).
    CollectionScan,
}

/// Statement options (`OPTIONS (…)`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatementOptions {
    /// Access-path hint.
    pub index: IndexHint,
    /// `max_time_ms` deadline.
    pub max_time_ms: Option<u64>,
    /// `allow_full_scan_write` (UPDATE / DELETE without WHERE).
    pub allow_full_scan_write: bool,
}

/// A bound read (also the row source of `UPDATE` / `DELETE`).
#[derive(Debug, Clone, PartialEq)]
pub struct BoundQuery {
    /// Target collection (always existing).
    pub target: Target,
    /// Normalised `WHERE` predicate.
    pub filter: Option<BExpr>,
    /// Output.
    pub select: BoundSelect,
    /// `ORDER BY` (aliases of the projection already substituted).
    pub order: Vec<SortKey>,
    /// `LIMIT`.
    pub limit: Option<u64>,
    /// `OFFSET`.
    pub offset: u64,
    /// Options.
    pub options: StatementOptions,
}

/// `RETURNING OLD|NEW [items]`.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundReturning {
    /// `true` for `NEW`.
    pub new_image: bool,
    /// Projection.
    pub select: BoundSelect,
}

/// `UPDATE`.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundUpdate {
    /// Rows to update (`select` is the whole document).
    pub source: BoundQuery,
    /// Changes.
    pub ops: BoundOps,
    /// `RETURNING`.
    pub returning: Option<BoundReturning>,
}

/// `DELETE`.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundDelete {
    /// Rows to delete.
    pub source: BoundQuery,
    /// `RETURNING`.
    pub returning: Option<BoundReturning>,
}

/// `UPSERT`.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundUpsert {
    /// Target.
    pub target: Target,
    /// Document expression.
    pub value: BExpr,
    /// Match paths (default `_id`).
    pub on: Vec<Vec<Step>>,
    /// `RETURNING`.
    pub returning: Option<BoundReturning>,
}

/// A bound statement.
#[derive(Debug, Clone, PartialEq)]
pub enum BoundStatement {
    /// Read.
    Query(BoundQuery),
    /// `INSERT`.
    Insert(BoundInsert),
    /// `UPDATE`.
    Update(BoundUpdate),
    /// `DELETE`.
    Delete(BoundDelete),
    /// `UPSERT`.
    Upsert(BoundUpsert),
    /// `EXPLAIN [ANALYZE]` (FR-QL-005).
    Explain {
        /// `ANALYZE`: execute and report actual rows and timings.
        analyze: bool,
        /// The explained statement.
        statement: Box<BoundStatement>,
    },
}

/// Binding context of one statement.
pub struct Binder<'a> {
    /// Catalog.
    pub catalog: &'a mut dyn CatalogView,
    /// Session database.
    pub session_db: &'a str,
    /// Parameters.
    pub params: &'a Params,
}

impl Binder<'_> {
    /// Binds a statement.
    ///
    /// # Errors
    /// `RGN-1030`, `RGN-1021`, `RGN-1011`, `RGN-1012`, unsupported-feature errors, catalog and
    /// transaction errors.
    pub fn bind(&mut self, stmt: &Statement) -> ExecResult<BoundStatement> {
        Ok(match stmt {
            Statement::Query(q) => BoundStatement::Query(bind_query(self, q)?),
            Statement::Insert(i) => BoundStatement::Insert(write::bind_insert(self, i)?),
            Statement::Update(u) => BoundStatement::Update(write::bind_update(self, u)?),
            Statement::Delete(d) => BoundStatement::Delete(write::bind_delete(self, d)?),
            Statement::Upsert(u) => BoundStatement::Upsert(write::bind_upsert(self, u)?),
            Statement::Explain { analyze, statement } => BoundStatement::Explain {
                analyze: *analyze,
                statement: Box::new(self.bind(statement)?),
            },
            other => {
                return Err(unsupported(&statement_kind(other), "a later milestone").into());
            }
        })
    }

    /// Resolves `[db.]name`; `must_exist` makes a missing collection `RGN-1030`.
    ///
    /// # Errors
    /// `RGN-1030`, catalog and transaction errors.
    pub fn target(&mut self, name: &QualifiedName, must_exist: bool) -> ExecResult<Target> {
        let db_name = name.database.as_deref().unwrap_or(self.session_db);
        let Some(database) = self.catalog.database(db_name)? else {
            return Err(not_found("database", db_name).into());
        };
        let collection = self.catalog.collection(&database, &name.name)?;
        if collection.is_none() && must_exist {
            return Err(not_found("collection", &name.name).into());
        }
        let indexes = match &collection {
            Some(c) => self.catalog.indexes(c)?,
            None => Vec::new(),
        };
        Ok(Target {
            database,
            name: name.name.clone(),
            collection,
            indexes,
        })
    }
}

/// A short statement description for "unsupported" errors.
fn statement_kind(s: &Statement) -> String {
    let json = serde_json::to_value(s).ok();
    let kind = json
        .as_ref()
        .and_then(|v| v.get("kind"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("statement");
    format!(
        "{} statements through the query engine",
        kind.replace('_', " ")
    )
}

/// Parses `OPTIONS (…)`.
///
/// Known options: `index` (string), `max_time_ms` (non-negative integer),
/// `allow_full_scan_write`, `allow_scan`, `allow_disk_use` (booleans) and `consistency`
/// (string; only the default strong reads exist in M3). *Provisional (PD pending)*: unknown
/// options are `RGN-1001` rather than ignored, so that typos do not silently change behaviour.
///
/// # Errors
/// `RGN-1001` (unknown option or wrong type), `RGN-1021` for a forced index that does not exist.
pub fn bind_options(
    b: &mut Binder<'_>,
    items: &[OptionItem],
    target: Option<&Target>,
) -> ExecResult<StatementOptions> {
    let mut out = StatementOptions::default();
    for item in items {
        let mut eb = ExprBinder::new(b.params, None);
        let v = crate::plan::rewrite::fold_constant(eb.bind(&item.value)?);
        let bad = || {
            crate::error::invalid(format!("invalid value for option {}", item.name))
                .with_detail("option", item.name.clone())
        };
        match item.name.to_ascii_lowercase().as_str() {
            "index" => match v {
                Some(Value::String(name)) => {
                    if let Some(t) = target
                        && !t
                            .indexes
                            .iter()
                            .any(|i| i.name == name && i.state.readable())
                    {
                        return Err(Error::new(
                            ErrorCode::IndexNotFound,
                            format!("index not found: {name}"),
                        )
                        .with_detail("index", name)
                        .into());
                    }
                    out.index = IndexHint::Force(name);
                }
                _ => return Err(bad().into()),
            },
            "max_time_ms" => match v.as_ref().and_then(crate::expr::ops::as_int) {
                Some(ms) if ms >= 0 => out.max_time_ms = u64::try_from(ms).ok(),
                _ => return Err(bad().into()),
            },
            "allow_full_scan_write" => match v {
                Some(Value::Bool(x)) => out.allow_full_scan_write = x,
                _ => return Err(bad().into()),
            },
            "allow_scan" | "allow_disk_use" => {
                if !matches!(v, Some(Value::Bool(_))) {
                    return Err(bad().into());
                }
            }
            "consistency" => {
                if !matches!(v, Some(Value::String(_))) {
                    return Err(bad().into());
                }
            }
            _ => {
                return Err(
                    crate::error::invalid(format!("unknown option {}", item.name))
                        .with_detail("option", item.name.clone())
                        .into(),
                );
            }
        }
    }
    Ok(out)
}
