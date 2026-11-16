// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Statements: writes (query-language.md §3, §6, §10), DDL and admin (§11), transactions (§12).
//! Type definitions only; the file exceeds the 600-line target because every item is documented.

use serde::{Deserialize, Serialize};

use super::{
    expr::{Expr, Path},
    is_false,
    query::{
        GroupSpec, IndexName, OptionItem, OrderItem, Projection, QualifiedName, Query, SetItem,
    },
};

/// A statement. JSON: `"kind"` names the variant; struct payloads are inlined.
// One statement exists per request and is never stored in bulk, so boxing the large variants
// would only add indirection to every access.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Statement {
    /// Read query.
    Query(Query),
    /// `INSERT`.
    Insert(Insert),
    /// `UPDATE`.
    Update(Update),
    /// `UPSERT`.
    Upsert(Upsert),
    /// `DELETE`.
    Delete(Delete),
    /// `EXPLAIN [ANALYZE] (query | update | delete)`.
    Explain {
        /// `ANALYZE`: execute and report actual rows/timings.
        #[serde(default, skip_serializing_if = "is_false")]
        analyze: bool,
        /// Explained statement.
        statement: Box<Statement>,
    },
    /// `CREATE DATABASE name [WITH (…)]`.
    CreateDatabase {
        /// Database name.
        name: String,
        /// Options.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        options: Vec<OptionItem>,
    },
    /// `CREATE COLLECTION db.coll [WITH (…)]`.
    CreateCollection {
        /// Collection.
        name: QualifiedName,
        /// Options.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        options: Vec<OptionItem>,
    },
    /// `CREATE TABLE` (wide-column, data-model §6).
    CreateTable(CreateTable),
    /// `CREATE TIMESERIES` (data-model §7).
    CreateTimeseries(CreateTimeseries),
    /// `CREATE [UNIQUE|TTL|FULLTEXT|VECTOR|GEO|LOCAL] INDEX`.
    CreateIndex(CreateIndex),
    /// `CREATE MAPREDUCE INDEX name ON coll MAP (query) REDUCE (GROUP BY … AGG …)`.
    CreateMapreduceIndex {
        /// Index name.
        name: String,
        /// Indexed collection.
        on: QualifiedName,
        /// Map query.
        map: Box<Query>,
        /// Reduce grouping.
        reduce: GroupSpec,
    },
    /// `CREATE CONTINUOUS AGGREGATE name ON coll GROUP BY … AGG …`.
    CreateContinuousAggregate {
        /// Aggregate name.
        name: QualifiedName,
        /// Source collection (usually a time series).
        on: QualifiedName,
        /// Grouping.
        group: GroupSpec,
    },
    /// `CREATE CHANGE SUBSCRIPTION name ON coll [WHERE expr]`.
    CreateChangeSubscription {
        /// Subscription name.
        name: String,
        /// Watched collection.
        on: QualifiedName,
        /// Event filter.
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        filter: Option<Expr>,
    },
    /// `ALTER COLLECTION coll (SET (…) | SPLIT AT (…), …)`.
    AlterCollection {
        /// Collection.
        name: QualifiedName,
        /// Change.
        action: AlterCollectionAction,
    },
    /// `ALTER INDEX db.coll.idx SET HIDDEN | SET VISIBLE`.
    AlterIndex {
        /// Index.
        name: IndexName,
        /// `true` for `HIDDEN`.
        hidden: bool,
    },
    /// `DROP DATABASE name`.
    DropDatabase {
        /// Database.
        name: String,
    },
    /// `DROP COLLECTION db.coll`.
    DropCollection {
        /// Collection.
        name: QualifiedName,
    },
    /// `DROP INDEX db.coll.idx`.
    DropIndex {
        /// Index.
        name: IndexName,
    },
    /// `SHOW …`.
    Show {
        /// What is listed.
        target: ShowTarget,
    },
    /// `KILL QUERY id` / `KILL TRANSACTION id`.
    Kill {
        /// What is killed.
        target: KillTarget,
        /// Identifier (string or parameter).
        id: Expr,
    },
    /// `BEGIN …`.
    Begin(Begin),
    /// `SAVEPOINT name`.
    Savepoint {
        /// Savepoint name.
        name: String,
    },
    /// `ROLLBACK TO SAVEPOINT name`.
    RollbackToSavepoint {
        /// Savepoint name.
        name: String,
    },
    /// `RELEASE SAVEPOINT name`.
    ReleaseSavepoint {
        /// Savepoint name.
        name: String,
    },
    /// `COMMIT`.
    Commit,
    /// `ROLLBACK`.
    Rollback,
}

/// `INSERT INTO coll source [ON CONFLICT …] [USING TTL n] [RETURNING …]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Insert {
    /// Target collection or table.
    pub target: QualifiedName,
    /// Inserted rows.
    pub source: InsertSource,
    /// Conflict handling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_conflict: Option<OnConflict>,
    /// Per-cell TTL in seconds for wide-column tables (`USING TTL 86400`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<Expr>,
    /// `RETURNING`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returning: Option<Returning>,
}

/// Rows of an `INSERT`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InsertSource {
    /// `VALUE expr`: one document.
    Value {
        /// Document.
        expr: Expr,
    },
    /// `VALUES e1, e2`: documents (each may be an array parameter).
    Values {
        /// Documents.
        rows: Vec<Expr>,
    },
    /// `(c1, c2) VALUES (v1, v2), …`: wide-column rows.
    Tuples {
        /// Column names.
        columns: Vec<String>,
        /// Rows, each with one value per column.
        rows: Vec<Vec<Expr>>,
    },
    /// `INSERT INTO … FROM …`: rows of a query.
    Query {
        /// Source query.
        query: Box<Query>,
    },
}

/// `ON CONFLICT DO NOTHING | DO UPDATE ops`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OnConflict {
    /// Skip conflicting rows.
    DoNothing,
    /// Update the existing document.
    DoUpdate {
        /// Update operations.
        ops: Vec<UpdateOp>,
    },
}

/// `RETURNING OLD|NEW [projections]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Returning {
    /// Image returned.
    pub image: Image,
    /// Projections (empty: whole documents).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<Projection>,
}

/// Document image of `RETURNING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Image {
    /// Before the write.
    Old,
    /// After the write.
    New,
}

/// `UPDATE coll [AS a] ops [WHERE p] [LIMIT n] [OPTIONS (…)] [RETURNING …]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    /// Target collection.
    pub target: QualifiedName,
    /// Row alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Operations in order (at least one).
    pub ops: Vec<UpdateOp>,
    /// Filter.
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Expr>,
    /// Maximum documents updated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Expr>,
    /// Options (e.g. `allow_full_scan_write`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<OptionItem>,
    /// `RETURNING`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returning: Option<Returning>,
}

/// End of the array `POP` removes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PopEnd {
    /// `FIRST`.
    First,
    /// `LAST`.
    Last,
}

/// An update operation (§3 `update_ops`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpdateOp {
    /// `SET path = expr, …`.
    Set {
        /// Assignments.
        items: Vec<SetItem>,
    },
    /// `UNSET a, b`.
    Unset {
        /// Removed paths.
        paths: Vec<Path>,
    },
    /// `INC path BY n`.
    Inc {
        /// Target.
        path: Path,
        /// Increment.
        by: Expr,
    },
    /// `MUL path BY n`.
    Mul {
        /// Target.
        path: Path,
        /// Factor.
        by: Expr,
    },
    /// `PUSH path VALUE v [POSITION p] [SLICE n] [SORT keys]`.
    Push {
        /// Target array.
        path: Path,
        /// Appended value.
        value: Expr,
        /// Insert position.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        position: Option<Expr>,
        /// Keep only the first n (negative: last n) elements afterwards.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slice: Option<Expr>,
        /// Sort the array afterwards.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sort: Vec<OrderItem>,
    },
    /// `PULL path WHERE predicate`.
    Pull {
        /// Target array.
        path: Path,
        /// Removed-element predicate.
        #[serde(rename = "where")]
        predicate: Expr,
    },
    /// `ADD TO SET path VALUE v`.
    AddToSet {
        /// Target array.
        path: Path,
        /// Added value.
        value: Expr,
    },
    /// `POP path FIRST|LAST`.
    Pop {
        /// Target array.
        path: Path,
        /// Removed end.
        end: PopEnd,
    },
    /// `RENAME from TO to`.
    Rename {
        /// Old path.
        from: Path,
        /// New path.
        to: Path,
    },
    /// `MIN path WITH v`.
    Min {
        /// Target.
        path: Path,
        /// Candidate.
        value: Expr,
    },
    /// `MAX path WITH v`.
    Max {
        /// Target.
        path: Path,
        /// Candidate.
        value: Expr,
    },
    /// `CURRENT DATE path`.
    CurrentDate {
        /// Target.
        path: Path,
    },
    /// `REPLACE WITH doc` (sole operation).
    Replace {
        /// New document.
        value: Expr,
    },
}

/// `UPSERT INTO coll VALUE doc [ON path, …] [RETURNING …]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upsert {
    /// Target collection.
    pub target: QualifiedName,
    /// Document.
    pub value: Expr,
    /// Match fields (default `_id`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub on: Vec<Path>,
    /// `RETURNING`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returning: Option<Returning>,
}

/// `DELETE [cols] FROM coll [WHERE p] [LIMIT n] [OPTIONS (…)] [RETURNING …]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delete {
    /// Wide-column cells deleted (empty: whole rows/documents).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<Path>,
    /// Target collection.
    pub target: QualifiedName,
    /// Filter.
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Expr>,
    /// Maximum documents deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Expr>,
    /// Options.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<OptionItem>,
    /// `RETURNING`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returning: Option<Returning>,
}

/// `CREATE TABLE name (PARTITION KEY (…), CLUSTERING KEY (…), STATIC (…), COLUMNS (…),
/// DISTRIBUTION d, DEFAULT TTL n)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTable {
    /// Table.
    pub name: QualifiedName,
    /// Partition key columns (at least one).
    pub partition_key: Vec<ColumnDef>,
    /// Clustering key columns (may be descending).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clustering_key: Vec<ColumnDef>,
    /// Static (per-partition) columns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_columns: Vec<ColumnDef>,
    /// Declared regular columns (e.g. counters).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<ColumnDef>,
    /// `hashed` or `range`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution: Option<String>,
    /// Default TTL in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ttl: Option<Expr>,
}

/// `name type [ASC|DESC]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnDef {
    /// Column name.
    pub name: String,
    /// Type name (`string`, `datetime`, `counter`, …).
    #[serde(rename = "type")]
    pub type_name: String,
    /// Descending order (clustering columns only).
    #[serde(default, skip_serializing_if = "is_false")]
    pub descending: bool,
}

/// `CREATE TIMESERIES name (TIME FIELD f, META FIELD m, GRANULARITY g, BUCKET MAX POINTS n,
/// BUCKET SPAN d, RETENTION d)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTimeseries {
    /// Collection.
    pub name: QualifiedName,
    /// Time field.
    pub time_field: Path,
    /// Meta (series identity) field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_field: Option<Path>,
    /// `seconds`, `minutes` or `hours`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granularity: Option<String>,
    /// Maximum points per bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_max_points: Option<Expr>,
    /// Explicit bucket span.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_span: Option<Duration>,
    /// Retention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<Duration>,
}

/// `amount unit`, e.g. `90 DAYS`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Duration {
    /// Amount.
    pub amount: Expr,
    /// Unit as written (`DAYS`, `hours`, …).
    pub unit: String,
}

/// Index flavour of `CREATE … INDEX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexType {
    /// Plain secondary index (multikey and wildcard keys detected from the key paths).
    Standard,
    /// `UNIQUE`.
    Unique,
    /// `TTL` (with `EXPIRE AFTER`).
    Ttl,
    /// `FULLTEXT`.
    Fulltext,
    /// `VECTOR`.
    Vector,
    /// `GEO`.
    Geo,
    /// `LOCAL` (wide-column partition-local index).
    Local,
}

/// `CREATE [type] INDEX name ON coll (keys) [EXPIRE AFTER d] [WITH (…)]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIndex {
    /// Index flavour.
    pub index_type: IndexType,
    /// Index name.
    pub name: String,
    /// Indexed collection.
    pub on: QualifiedName,
    /// Keys (at least one).
    pub keys: Vec<IndexKey>,
    /// TTL (`EXPIRE AFTER '30 days'`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_after: Option<Expr>,
    /// Options.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<OptionItem>,
}

/// `path [ASC|DESC] [ANALYZER a] [BOOST b]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexKey {
    /// Key path (`` `payload.**` `` for wildcard keys).
    pub path: Path,
    /// Descending.
    #[serde(default, skip_serializing_if = "is_false")]
    pub descending: bool,
    /// Full-text analyzer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyzer: Option<Expr>,
    /// Full-text field boost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boost: Option<Expr>,
}

/// Change made by `ALTER COLLECTION`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AlterCollectionAction {
    /// `SET (name = value, …)`.
    SetOptions {
        /// Options.
        options: Vec<OptionItem>,
    },
    /// `SPLIT AT (k1, …), (…)`: manual range split points (shard-key tuples).
    SplitAt {
        /// Split points.
        points: Vec<Vec<Expr>>,
    },
}

/// Target of `SHOW`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShowTarget {
    /// `SHOW COLLECTIONS`.
    Collections,
    /// `SHOW INDEXES ON coll`.
    Indexes {
        /// Collection.
        on: QualifiedName,
    },
    /// `SHOW RANGES FROM COLLECTION coll`.
    Ranges {
        /// Collection.
        collection: QualifiedName,
    },
    /// `SHOW TRANSACTIONS`.
    Transactions,
}

/// Target of `KILL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillTarget {
    /// `KILL QUERY`.
    Query,
    /// `KILL TRANSACTION`.
    Transaction,
}

/// `BEGIN [ISOLATION LEVEL …] [READ ONLY] [PRIORITY …] [AS OF SYSTEM TIME expr]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Begin {
    /// Isolation level (default: the database default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<Isolation>,
    /// `READ ONLY`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub read_only: bool,
    /// Priority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    /// Historical snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<Expr>,
}

/// Transaction isolation level (§12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// `SERIALIZABLE`.
    Serializable,
    /// `SNAPSHOT`.
    Snapshot,
    /// `READ COMMITTED`.
    ReadCommitted,
}

/// Transaction priority (§12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// `HIGH`.
    High,
    /// `NORMAL`.
    Normal,
    /// `LOW`.
    Low,
}
