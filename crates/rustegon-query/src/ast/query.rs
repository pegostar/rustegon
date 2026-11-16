// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Read queries (query-language.md §3 `query`, §5, §8) and pipeline stages (§7).

use serde::{Deserialize, Serialize};

use super::{
    expr::{Expr, Path},
    is_false,
};

/// `FROM … [LOOKUP …] [WHERE …] [GROUP BY …] [HAVING …] [SELECT …] [ORDER BY …] [LIMIT …]
/// [INCLUDE …] [OPTIONS (…)] { |> stage }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    /// `FROM` clause.
    pub from: FromClause,
    /// `LOOKUP` clauses (left outer joins), in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lookups: Vec<LookupClause>,
    /// `WHERE` predicate.
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Expr>,
    /// `GROUP BY` keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_by: Vec<GroupKey>,
    /// `HAVING` predicate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub having: Option<Expr>,
    /// `SELECT` clause (absent: whole documents).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub select: Option<Select>,
    /// `ORDER BY` items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order_by: Vec<OrderItem>,
    /// `LIMIT` count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Expr>,
    /// `OFFSET` count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<Expr>,
    /// `INCLUDE` paths (may contain `[]` segments).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<Path>,
    /// `OPTIONS (…)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<OptionItem>,
    /// Pipeline stages after `|>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pipeline: Vec<Stage>,
}

impl Query {
    /// A bare `FROM <source>` query.
    #[must_use]
    pub fn from_source(source: Source) -> Self {
        Self {
            from: FromClause {
                source,
                alias: None,
                as_of: None,
            },
            lookups: Vec::new(),
            filter: None,
            group_by: Vec::new(),
            having: None,
            select: None,
            order_by: Vec::new(),
            limit: None,
            offset: None,
            include: Vec::new(),
            options: Vec::new(),
            pipeline: Vec::new(),
        }
    }
}

/// `FROM source [AS alias] [AS OF SYSTEM TIME expr]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FromClause {
    /// What is read.
    pub source: Source,
    /// Row alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Historical read timestamp (`AS OF SYSTEM TIME '-10s'`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<Expr>,
}

/// Source of a `FROM` clause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    /// A collection (or table / time series).
    Collection(QualifiedName),
    /// `( query )`.
    Subquery {
        /// The inner query.
        query: Box<Query>,
    },
    /// `INDEX db.collection.index`: the output of a map-reduce index.
    Index {
        /// Collection the index belongs to.
        collection: QualifiedName,
        /// Index name.
        index: String,
    },
}

/// `[database.]name`; the database defaults to the session database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedName {
    /// Database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// Collection (or other object) name.
    pub name: String,
}

impl QualifiedName {
    /// `database.name`.
    #[must_use]
    pub fn new(database: Option<&str>, name: &str) -> Self {
        Self {
            database: database.map(str::to_owned),
            name: name.to_owned(),
        }
    }
}

/// `[db.]collection.index` (DROP INDEX, ALTER INDEX).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexName {
    /// Collection.
    pub collection: QualifiedName,
    /// Index.
    pub index: String,
}

/// `LOOKUP coll [AS alias] ON local = foreign INTO field` (left outer join, §8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupClause {
    /// Joined collection.
    pub collection: QualifiedName,
    /// Alias of the joined rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Expression over the current row.
    pub local: Expr,
    /// Path in the joined collection.
    pub foreign: Path,
    /// Field receiving the array of matches.
    pub into: String,
}

/// A `GROUP BY` key with optional name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupKey {
    /// Key expression.
    pub expr: Expr,
    /// Output name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

/// `SELECT` clause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Select {
    /// `SELECT *`.
    Star,
    /// `SELECT a, b AS c, -d, e.*`.
    Items {
        /// Projections.
        items: Vec<Projection>,
    },
    /// `SELECT VALUE expr`: rows are the bare values.
    Value {
        /// Value per row.
        expr: Expr,
    },
}

/// A projection item (`SELECT`, `PROJECT`, `RETURNING`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Projection {
    /// `expr [AS alias]`.
    Expr {
        /// Value.
        expr: Expr,
        /// Output name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alias: Option<String>,
    },
    /// `path.*`: all fields of the object at `path`.
    Wildcard {
        /// Object path.
        path: Path,
    },
    /// `-path`: exclude a field.
    Exclude {
        /// Excluded path.
        path: Path,
    },
}

/// `expr [ASC | DESC]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderItem {
    /// Sort key.
    pub expr: Expr,
    /// `DESC` (default ascending).
    #[serde(default, skip_serializing_if = "is_false")]
    pub descending: bool,
}

/// `name = value` in `OPTIONS (…)` and `WITH (…)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionItem {
    /// Option name.
    pub name: String,
    /// Option value.
    pub value: Expr,
}

/// `path = expr` (`SET`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetItem {
    /// Target path.
    pub path: Path,
    /// New value.
    pub value: Expr,
}

/// `name = expr` in `AGG` / `COMPUTE` lists.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggItem {
    /// Output field.
    pub name: String,
    /// Aggregate (or window) expression.
    pub expr: Expr,
}

/// `GROUP BY keys [AGG aggs]` (pipeline stage, map-reduce `REDUCE`, continuous aggregate).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    /// Grouping keys.
    pub keys: Vec<GroupKey>,
    /// Aggregates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggs: Vec<AggItem>,
}

/// A named sub-pipeline of `FACET`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facet {
    /// Output field.
    pub name: String,
    /// Stages (at least one).
    pub pipeline: Vec<Stage>,
}

/// Action of `MERGE … WHEN MATCHED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeMatched {
    /// `REPLACE`.
    Replace,
    /// `UPDATE`.
    Update,
    /// `KEEP`.
    Keep,
    /// `FAIL`.
    Fail,
}

/// Action of `MERGE … WHEN NOT MATCHED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeNotMatched {
    /// `INSERT`.
    Insert,
    /// `DISCARD`.
    Discard,
}

/// A pipeline stage (§7, one variant per normative stage).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Stage {
    /// `MATCH expr`.
    Match {
        /// Filter.
        predicate: Expr,
    },
    /// `PROJECT a, b AS c, -d`.
    Project {
        /// Projections.
        items: Vec<Projection>,
    },
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
    /// `GROUP BY k [AS n], … [AGG name = agg, …]`.
    Group(GroupSpec),
    /// `SORT a DESC, b`.
    Sort {
        /// Sort keys.
        items: Vec<OrderItem>,
    },
    /// `LIMIT n`.
    Limit {
        /// Row count.
        count: Expr,
    },
    /// `SKIP n`.
    Skip {
        /// Row count.
        count: Expr,
    },
    /// `UNWIND path [AS alias] [WITH INDEX name] [PRESERVE EMPTY]`.
    Unwind {
        /// Array path.
        path: Path,
        /// Name of the element.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alias: Option<String>,
        /// Name of the element position field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index: Option<String>,
        /// Keep rows whose array is empty or missing.
        #[serde(default, skip_serializing_if = "is_false")]
        preserve_empty: bool,
    },
    /// `LOOKUP … [PIPELINE (stages)]`.
    Lookup {
        /// Join specification.
        lookup: LookupClause,
        /// Sub-pipeline applied to the joined rows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pipeline: Option<Vec<Stage>>,
    },
    /// `COUNT AS name`.
    Count {
        /// Output field.
        name: String,
    },
    /// `FACET name (stages), …`.
    Facet {
        /// Parallel sub-pipelines.
        facets: Vec<Facet>,
    },
    /// `BUCKET BY expr BOUNDARIES expr [DEFAULT expr] [AGG …]`.
    Bucket {
        /// Bucketed value.
        by: Expr,
        /// Sorted boundaries (an array expression or parameter).
        boundaries: Expr,
        /// Bucket for values outside the boundaries.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        default: Option<Expr>,
        /// Aggregates per bucket.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        aggs: Vec<AggItem>,
    },
    /// `BUCKET AUTO BY expr INTO n [AGG …]`.
    BucketAuto {
        /// Bucketed value.
        by: Expr,
        /// Number of buckets.
        buckets: Expr,
        /// Aggregates per bucket.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        aggs: Vec<AggItem>,
    },
    /// `SAMPLE n`.
    Sample {
        /// Sample size.
        size: Expr,
    },
    /// `REPLACE ROOT WITH expr`.
    ReplaceRoot {
        /// New row.
        expr: Expr,
    },
    /// `SORT BY COUNT expr`.
    SortByCount {
        /// Grouped value.
        expr: Expr,
    },
    /// `GRAPH LOOKUP coll START WITH expr CONNECT FROM a TO b [MAX DEPTH n] [WHERE p] INTO f`.
    GraphLookup {
        /// Traversed collection.
        collection: QualifiedName,
        /// Start value(s).
        start_with: Expr,
        /// Field of a visited document giving the next value(s).
        connect_from: Path,
        /// Field matched against those values.
        connect_to: Path,
        /// Maximum recursion depth (spec maximum 32).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_depth: Option<Expr>,
        /// Filter on visited documents.
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        filter: Option<Expr>,
        /// Output field.
        into: String,
    },
    /// `UNION WITH (query)`.
    UnionWith {
        /// Appended query.
        query: Box<Query>,
    },
    /// `WINDOW [PARTITION BY …] [ORDER BY …] COMPUTE name = expr, …` (`set_window_fields`).
    Window {
        /// Partition keys.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        partition_by: Vec<Expr>,
        /// Order within a partition.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        order_by: Vec<OrderItem>,
        /// Computed window fields.
        compute: Vec<AggItem>,
    },
    /// `OUT INTO coll`.
    Out {
        /// Target collection.
        collection: QualifiedName,
    },
    /// `MERGE INTO coll ON path, … [WHEN MATCHED …] [WHEN NOT MATCHED …]`.
    Merge {
        /// Target collection.
        collection: QualifiedName,
        /// Match fields.
        on: Vec<Path>,
        /// Action when a target document matches.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        when_matched: Option<MergeMatched>,
        /// Action when none matches.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        when_not_matched: Option<MergeNotMatched>,
    },
}
