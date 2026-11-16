// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Filter, update, sort and projection builders. They produce the structured AST of
//! `proto/rustegon/v1/query_ast.proto`, never RGQL text (PD-070), with the normative rules of
//! `drivers/conformance/README.md` §4 (pinned by `ast/*.json`, TC-DRV-RS-006):
//! 1. every filter value becomes parameter `f0, f1, …` and every update value `u0, u1, …` in
//!    depth-first, left-to-right order; field names become `AstPath` segments, never text;
//! 2. nested `and` in `and` (and `or` in `or`) are flattened (the server accepts only the
//!    canonical AST);
//! 3. a filter that is exactly `Filter::id(v)` routes single-document writes to
//!    `DocumentService`; any other filter uses `UPDATE/DELETE … WHERE … LIMIT 1` statements;
//! 4. the empty filter on statement writes adds `OPTIONS (allow_full_scan_write = true)`.
//!
//! Builder misuse (empty path segment, empty update, …) is recorded and reported as an argument
//! error when the operation runs, so builders chain without `?`.

use std::collections::HashMap;

use crate::{
    codec::{Document, Value, rdoc},
    error::{Error, Result},
    pb::{
        self, AstBinary, AstBinaryOp, AstCreateIndex, AstDelete, AstElemMatch, AstExpr,
        AstExprProjection, AstFromClause, AstIndexKey, AstIndexType, AstIs, AstIsTest, AstLiteral,
        AstNary, AstOptionItem, AstOrderItem, AstParam, AstPath, AstPathBy, AstPathExpr,
        AstPathOnly, AstPathProjection, AstPathValue, AstPopEnd, AstPopOp, AstProjection,
        AstPullOp, AstPushOp, AstQualifiedName, AstQuery, AstRenameOp, AstReplaceOp, AstSegment,
        AstSelect, AstSelectItems, AstSetItem, AstSetStage, AstSource, AstStatement, AstUnary,
        AstUnsetStage, AstUpdate, AstUpdateOp, ast_expr, ast_literal, ast_projection, ast_segment,
        ast_select, ast_source, ast_statement, ast_update_op,
    },
};

/// Collects the named parameters of one request (`f0…`, `u0…`).
#[derive(Debug, Default)]
#[doc(hidden)]
pub struct ParamSink {
    filters: u32,
    updates: u32,
    /// The parameters by name.
    pub params: HashMap<String, pb::Value>,
}

impl ParamSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn add(&mut self, prefix: char, v: &Value) -> Result<AstExpr> {
        let n = if prefix == 'f' {
            &mut self.filters
        } else {
            &mut self.updates
        };
        let name = format!("{prefix}{n}");
        *n += 1;
        let bytes =
            rdoc::encode_value(v).map_err(|e| Error::argument(format!("invalid value: {e}")))?;
        self.params
            .insert(name.clone(), pb::Value { rdoc_value: bytes });
        Ok(AstExpr {
            kind: Some(ast_expr::Kind::Param(AstParam { name })),
        })
    }
}

/// A dotted path as AST segments; an all-digit segment after the first is an array position.
pub(crate) fn ast_path(path: &str) -> std::result::Result<AstPath, String> {
    if path.is_empty() {
        return Err("empty path".into());
    }
    let mut segments = Vec::new();
    for (i, p) in path.split('.').enumerate() {
        if p.is_empty() {
            return Err(format!("the path {path:?} has an empty segment"));
        }
        let segment = match p.parse::<u32>() {
            Ok(n) if i > 0 && p.bytes().all(|b| b.is_ascii_digit()) => {
                ast_segment::Segment::Position(n)
            }
            _ => ast_segment::Segment::Field(p.to_owned()),
        };
        segments.push(AstSegment {
            segment: Some(segment),
        });
    }
    Ok(AstPath { segments })
}

/// The dotted text of an AST path.
pub(crate) fn path_text(p: &AstPath) -> String {
    p.segments
        .iter()
        .map(|s| match &s.segment {
            Some(ast_segment::Segment::Position(n)) => n.to_string(),
            Some(ast_segment::Segment::Field(f)) => f.clone(),
            _ => String::new(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn path_expr(p: AstPath) -> AstExpr {
    AstExpr {
        kind: Some(ast_expr::Kind::Path(AstPathExpr { path: Some(p) })),
    }
}

fn int_lit(v: i64) -> AstExpr {
    AstExpr {
        kind: Some(ast_expr::Kind::Literal(AstLiteral {
            value: Some(ast_literal::Value::IntValue(v)),
        })),
    }
}

fn allow_full_scan_write() -> AstOptionItem {
    AstOptionItem {
        name: "allow_full_scan_write".into(),
        value: Some(AstExpr {
            kind: Some(ast_expr::Kind::Literal(AstLiteral {
                value: Some(ast_literal::Value::BoolValue(true)),
            })),
        }),
    }
}

/// Checks that a value can be sent (encodable; `counter` is never accepted as input).
fn checked(v: Value) -> std::result::Result<Value, String> {
    rdoc::encode_value(&v)
        .map(|_| v)
        .map_err(|e| format!("invalid value: {e}"))
}

// ------------------------------------------------------------------------------------- filters

#[derive(Debug, Clone)]
enum FilterKind {
    Empty,
    Id(Value),
    Binary(AstPath, AstBinaryOp, Value),
    Exists(AstPath, bool),
    IsNull(AstPath),
    ElemMatch(AstPath, Box<Filter>),
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Invalid(String),
}

/// A query filter (README §4 builder DSL). Build with the associated functions:
/// `Filter::and([Filter::eq("status", "paid"), Filter::gte("total", 100)])`.
#[derive(Debug, Clone)]
#[must_use]
pub struct Filter(FilterKind);

impl Default for Filter {
    fn default() -> Self {
        Self::empty()
    }
}

impl Filter {
    /// Matches every document.
    pub fn empty() -> Self {
        Self(FilterKind::Empty)
    }

    /// `_id = id`; routes single-document writes to `DocumentService` (rule 3).
    pub fn id(id: impl Into<Value>) -> Self {
        match checked(id.into()) {
            Ok(v) => Self(FilterKind::Id(v)),
            Err(e) => Self(FilterKind::Invalid(e)),
        }
    }

    fn binary(path: &str, op: AstBinaryOp, v: Value) -> Self {
        match (ast_path(path), checked(v)) {
            (Ok(p), Ok(v)) => Self(FilterKind::Binary(p, op, v)),
            (Err(e), _) | (_, Err(e)) => Self(FilterKind::Invalid(e)),
        }
    }

    fn list<I, V>(path: &str, op: AstBinaryOp, values: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        Self::binary(
            path,
            op,
            Value::Array(values.into_iter().map(Into::into).collect()),
        )
    }

    /// `path = value`.
    pub fn eq(path: &str, value: impl Into<Value>) -> Self {
        Self::binary(path, AstBinaryOp::Eq, value.into())
    }
    /// `path != value`.
    pub fn ne(path: &str, value: impl Into<Value>) -> Self {
        Self::binary(path, AstBinaryOp::Ne, value.into())
    }
    /// `path > value`.
    pub fn gt(path: &str, value: impl Into<Value>) -> Self {
        Self::binary(path, AstBinaryOp::Gt, value.into())
    }
    /// `path >= value`.
    pub fn gte(path: &str, value: impl Into<Value>) -> Self {
        Self::binary(path, AstBinaryOp::Ge, value.into())
    }
    /// `path < value`.
    pub fn lt(path: &str, value: impl Into<Value>) -> Self {
        Self::binary(path, AstBinaryOp::Lt, value.into())
    }
    /// `path <= value`.
    pub fn lte(path: &str, value: impl Into<Value>) -> Self {
        Self::binary(path, AstBinaryOp::Le, value.into())
    }
    /// `path IN [values]` (one array parameter).
    pub fn r#in<I: IntoIterator<Item = V>, V: Into<Value>>(path: &str, values: I) -> Self {
        Self::list(path, AstBinaryOp::In, values)
    }
    /// `path NOT IN [values]`.
    pub fn nin<I: IntoIterator<Item = V>, V: Into<Value>>(path: &str, values: I) -> Self {
        Self::list(path, AstBinaryOp::NotIn, values)
    }
    /// `path CONTAINS value` (array element or substring).
    pub fn contains(path: &str, value: impl Into<Value>) -> Self {
        Self::binary(path, AstBinaryOp::Contains, value.into())
    }
    /// `path CONTAINS ANY [values]`.
    pub fn contains_any<I: IntoIterator<Item = V>, V: Into<Value>>(path: &str, values: I) -> Self {
        Self::list(path, AstBinaryOp::ContainsAny, values)
    }
    /// `path CONTAINS ALL [values]`.
    pub fn contains_all<I: IntoIterator<Item = V>, V: Into<Value>>(path: &str, values: I) -> Self {
        Self::list(path, AstBinaryOp::ContainsAll, values)
    }
    /// `path LIKE pattern`.
    pub fn like(path: &str, pattern: &str) -> Self {
        Self::binary(path, AstBinaryOp::Like, Value::from(pattern))
    }
    /// `path MATCHES regex`.
    pub fn regex(path: &str, re: &str) -> Self {
        Self::binary(path, AstBinaryOp::Matches, Value::from(re))
    }
    /// `path IS NOT MISSING` (`exists = true`) or `IS MISSING`.
    pub fn exists(path: &str, exists: bool) -> Self {
        match ast_path(path) {
            Ok(p) => Self(FilterKind::Exists(p, exists)),
            Err(e) => Self(FilterKind::Invalid(e)),
        }
    }
    /// `path IS NULL` (null or missing).
    pub fn is_null(path: &str) -> Self {
        match ast_path(path) {
            Ok(p) => Self(FilterKind::IsNull(p)),
            Err(e) => Self(FilterKind::Invalid(e)),
        }
    }
    /// `ELEM MATCH (path, filter)`: an array element matches `filter` (paths relative to it).
    pub fn elem_match(path: &str, filter: Filter) -> Self {
        match ast_path(path) {
            Ok(_) if matches!(filter.0, FilterKind::Empty) => Self(FilterKind::Invalid(
                "elem_match needs a non-empty element filter".into(),
            )),
            Ok(p) => Self(FilterKind::ElemMatch(p, Box::new(filter))),
            Err(e) => Self(FilterKind::Invalid(e)),
        }
    }
    /// Conjunction (flattened; empty filters are dropped).
    pub fn and(filters: impl IntoIterator<Item = Filter>) -> Self {
        Self::nary(true, filters)
    }
    /// Disjunction (flattened).
    pub fn or(filters: impl IntoIterator<Item = Filter>) -> Self {
        Self::nary(false, filters)
    }
    /// Negation (model `Filter.Not`).
    #[allow(clippy::should_implement_trait)]
    pub fn not(filter: Filter) -> Self {
        if matches!(filter.0, FilterKind::Empty) {
            return Self(FilterKind::Invalid(
                "not of the empty filter matches nothing; use a real condition".into(),
            ));
        }
        Self(FilterKind::Not(Box::new(filter)))
    }

    fn nary(and: bool, filters: impl IntoIterator<Item = Filter>) -> Self {
        let mut flat = Vec::new();
        for f in filters {
            match f.0 {
                FilterKind::Empty => {}
                FilterKind::And(c) if and => flat.extend(c),
                FilterKind::Or(c) if !and => flat.extend(c),
                k => flat.push(Self(k)),
            }
        }
        match flat.len() {
            0 => Self::empty(),
            1 => flat.pop().unwrap_or_default(),
            _ if and => Self(FilterKind::And(flat)),
            _ => Self(FilterKind::Or(flat)),
        }
    }

    /// The first builder error, as an argument error.
    pub(crate) fn check(&self) -> Result<()> {
        match &self.0 {
            FilterKind::Invalid(e) => Err(Error::argument(e.clone())),
            FilterKind::ElemMatch(_, f) | FilterKind::Not(f) => f.check(),
            FilterKind::And(c) | FilterKind::Or(c) => c.iter().try_for_each(Filter::check),
            _ => Ok(()),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        matches!(self.0, FilterKind::Empty)
    }

    /// The id of a `Filter::id`.
    pub(crate) fn id_value(&self) -> Option<&Value> {
        match &self.0 {
            FilterKind::Id(v) => Some(v),
            _ => None,
        }
    }

    /// The `WHERE` expression (`None` for the empty filter).
    #[doc(hidden)]
    pub fn to_ast(&self, s: &mut ParamSink) -> Result<Option<AstExpr>> {
        self.check()?;
        self.ast(s)
    }

    fn ast(&self, s: &mut ParamSink) -> Result<Option<AstExpr>> {
        let binary =
            |op: AstBinaryOp, p: &AstPath, v: &Value, s: &mut ParamSink| -> Result<AstExpr> {
                Ok(AstExpr {
                    kind: Some(ast_expr::Kind::Binary(Box::new(AstBinary {
                        op: op.into(),
                        left: Some(Box::new(path_expr(p.clone()))),
                        right: Some(Box::new(s.add('f', v)?)),
                    }))),
                })
            };
        let kind = match &self.0 {
            FilterKind::Empty => return Ok(None),
            FilterKind::Invalid(e) => return Err(Error::argument(e.clone())),
            FilterKind::Id(v) => {
                let p = ast_path("_id").map_err(Error::argument)?;
                return binary(AstBinaryOp::Eq, &p, v, s).map(Some);
            }
            FilterKind::Binary(p, op, v) => return binary(*op, p, v, s).map(Some),
            FilterKind::Exists(p, exists) => ast_expr::Kind::Is(Box::new(AstIs {
                expr: Some(Box::new(path_expr(p.clone()))),
                negated: *exists,
                test: AstIsTest::Missing.into(),
            })),
            FilterKind::IsNull(p) => ast_expr::Kind::Is(Box::new(AstIs {
                expr: Some(Box::new(path_expr(p.clone()))),
                negated: false,
                test: AstIsTest::Null.into(),
            })),
            FilterKind::ElemMatch(p, f) => ast_expr::Kind::ElemMatch(Box::new(AstElemMatch {
                path: Some(p.clone()),
                predicate: f.ast(s)?.map(Box::new),
            })),
            FilterKind::Not(f) => ast_expr::Kind::Not(Box::new(AstUnary {
                expr: f.ast(s)?.map(Box::new),
            })),
            FilterKind::And(c) | FilterKind::Or(c) => {
                let mut args = Vec::with_capacity(c.len());
                for f in c {
                    args.extend(f.ast(s)?);
                }
                if matches!(self.0, FilterKind::And(_)) {
                    ast_expr::Kind::And(AstNary { args })
                } else {
                    ast_expr::Kind::Or(AstNary { args })
                }
            }
        };
        Ok(Some(AstExpr { kind: Some(kind) }))
    }
}

// ------------------------------------------------------------------------------------- updates

#[derive(Debug, Clone)]
enum UpdateOp {
    Set(AstPath, Value),
    Unset(AstPath),
    Inc(AstPath, Value),
    Mul(AstPath, Value),
    Min(AstPath, Value),
    Max(AstPath, Value),
    Push(AstPath, Value),
    AddToSet(AstPath, Value),
    Pull(AstPath, Value),
    Pop(AstPath, AstPopEnd),
    Rename(AstPath, AstPath),
    CurrentDate(AstPath),
    Replace(Value),
}

/// An update: an ordered list of operators, one `AstUpdateOp` each:
/// `Update::new().set("status", "shipped").inc("version", 1)`.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct Update {
    ops: Vec<UpdateOp>,
    error: Option<String>,
}

impl Update {
    /// An empty update (add at least one operator).
    pub fn new() -> Self {
        Self::default()
    }

    fn push_op(mut self, op: std::result::Result<UpdateOp, String>) -> Self {
        match op {
            Ok(op) => self.ops.push(op),
            Err(e) => {
                self.error.get_or_insert(e);
            }
        }
        self
    }

    fn with_value(self, path: &str, v: Value, make: fn(AstPath, Value) -> UpdateOp) -> Self {
        let op = ast_path(path).and_then(|p| checked(v).map(|v| make(p, v)));
        self.push_op(op)
    }

    /// `SET path = value`.
    pub fn set(self, path: &str, value: impl Into<Value>) -> Self {
        self.with_value(path, value.into(), UpdateOp::Set)
    }
    /// `UNSET path`.
    pub fn unset(self, path: &str) -> Self {
        let op = ast_path(path).map(UpdateOp::Unset);
        self.push_op(op)
    }
    /// `INC path BY amount`.
    pub fn inc(self, path: &str, amount: impl Into<Value>) -> Self {
        self.with_value(path, amount.into(), UpdateOp::Inc)
    }
    /// `MUL path BY factor`.
    pub fn mul(self, path: &str, factor: impl Into<Value>) -> Self {
        self.with_value(path, factor.into(), UpdateOp::Mul)
    }
    /// `MIN path value`.
    pub fn min(self, path: &str, value: impl Into<Value>) -> Self {
        self.with_value(path, value.into(), UpdateOp::Min)
    }
    /// `MAX path value`.
    pub fn max(self, path: &str, value: impl Into<Value>) -> Self {
        self.with_value(path, value.into(), UpdateOp::Max)
    }
    /// `PUSH path value`.
    pub fn push(self, path: &str, value: impl Into<Value>) -> Self {
        self.with_value(path, value.into(), UpdateOp::Push)
    }
    /// `ADD TO SET path value`.
    pub fn add_to_set(self, path: &str, value: impl Into<Value>) -> Self {
        self.with_value(path, value.into(), UpdateOp::AddToSet)
    }
    /// `PULL path WHERE <last segment> = value`: removes the elements equal to `value`.
    pub fn pull(self, path: &str, value: impl Into<Value>) -> Self {
        self.with_value(path, value.into(), UpdateOp::Pull)
    }
    /// `POP FIRST path`.
    pub fn pop_first(self, path: &str) -> Self {
        let op = ast_path(path).map(|p| UpdateOp::Pop(p, AstPopEnd::First));
        self.push_op(op)
    }
    /// `POP LAST path`.
    pub fn pop_last(self, path: &str) -> Self {
        let op = ast_path(path).map(|p| UpdateOp::Pop(p, AstPopEnd::Last));
        self.push_op(op)
    }
    /// `RENAME from TO to`.
    pub fn rename(self, from: &str, to: &str) -> Self {
        let op = ast_path(from).and_then(|f| ast_path(to).map(|t| UpdateOp::Rename(f, t)));
        self.push_op(op)
    }
    /// `CURRENT DATE path`: the server's current datetime.
    pub fn current_date(self, path: &str) -> Self {
        let op = ast_path(path).map(UpdateOp::CurrentDate);
        self.push_op(op)
    }
    /// Appends the operators of `other`.
    pub fn and(mut self, other: Update) -> Self {
        self.ops.extend(other.ops);
        if self.error.is_none() {
            self.error = other.error;
        }
        self
    }

    /// The whole-document replacement used by `replace_one` with a non-id filter.
    #[doc(hidden)]
    pub fn replacement(doc: Document) -> Self {
        Self {
            ops: vec![UpdateOp::Replace(Value::Object(doc))],
            error: None,
        }
    }

    /// The `AstUpdateOp` list, adding the values to `s`.
    #[doc(hidden)]
    pub fn to_ast(&self, s: &mut ParamSink) -> Result<Vec<AstUpdateOp>> {
        if let Some(e) = &self.error {
            return Err(Error::argument(e.clone()));
        }
        if self.ops.is_empty() {
            return Err(Error::argument("an update needs at least one operator"));
        }
        let mut out = Vec::with_capacity(self.ops.len());
        for op in &self.ops {
            use ast_update_op::Kind as K;
            let pv = |p: &AstPath, v: &Value, s: &mut ParamSink| -> Result<AstPathValue> {
                Ok(AstPathValue {
                    path: Some(p.clone()),
                    value: Some(s.add('u', v)?),
                })
            };
            let pb_ = |p: &AstPath, v: &Value, s: &mut ParamSink| -> Result<AstPathBy> {
                Ok(AstPathBy {
                    path: Some(p.clone()),
                    by: Some(s.add('u', v)?),
                })
            };
            let kind = match op {
                UpdateOp::Set(p, v) => K::Set(AstSetStage {
                    items: vec![AstSetItem {
                        path: Some(p.clone()),
                        value: Some(s.add('u', v)?),
                    }],
                }),
                UpdateOp::Unset(p) => K::Unset(AstUnsetStage {
                    paths: vec![p.clone()],
                }),
                UpdateOp::Inc(p, v) => K::Inc(pb_(p, v, s)?),
                UpdateOp::Mul(p, v) => K::Mul(pb_(p, v, s)?),
                UpdateOp::Min(p, v) => K::Min(pv(p, v, s)?),
                UpdateOp::Max(p, v) => K::Max(pv(p, v, s)?),
                UpdateOp::AddToSet(p, v) => K::AddToSet(pv(p, v, s)?),
                UpdateOp::Push(p, v) => K::Push(AstPushOp {
                    path: Some(p.clone()),
                    value: Some(s.add('u', v)?),
                    ..AstPushOp::default()
                }),
                UpdateOp::Pull(p, v) => {
                    // PULL p WHERE <last field of p> = $u: the element is compared whole.
                    let last = match p.segments.last().and_then(|x| x.segment.clone()) {
                        Some(ast_segment::Segment::Field(f)) => f,
                        _ => String::new(),
                    };
                    let elem = AstPath {
                        segments: vec![AstSegment {
                            segment: Some(ast_segment::Segment::Field(last)),
                        }],
                    };
                    let right = s.add('u', v)?;
                    K::Pull(AstPullOp {
                        path: Some(p.clone()),
                        r#where: Some(AstExpr {
                            kind: Some(ast_expr::Kind::Binary(Box::new(AstBinary {
                                op: AstBinaryOp::Eq.into(),
                                left: Some(Box::new(path_expr(elem))),
                                right: Some(Box::new(right)),
                            }))),
                        }),
                    })
                }
                UpdateOp::Pop(p, end) => K::Pop(AstPopOp {
                    path: Some(p.clone()),
                    end: (*end).into(),
                }),
                UpdateOp::Rename(f, t) => K::Rename(AstRenameOp {
                    from: Some(f.clone()),
                    to: Some(t.clone()),
                }),
                UpdateOp::CurrentDate(p) => K::CurrentDate(AstPathOnly {
                    path: Some(p.clone()),
                }),
                UpdateOp::Replace(v) => K::Replace(AstReplaceOp {
                    value: Some(s.add('u', v)?),
                }),
            };
            out.push(AstUpdateOp { kind: Some(kind) });
        }
        Ok(out)
    }
}

// --------------------------------------------------------------------------- sort, projection

/// A sort key (also an index key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortKey {
    /// Dotted path.
    pub path: String,
    /// Descending order.
    pub descending: bool,
}

/// Sort order (also the keys of an index): `Sort::asc("a").then_desc("b")`.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct Sort {
    keys: Vec<SortKey>,
    error: Option<String>,
}

/// Index keys use the sort builder.
pub type IndexKeys = Sort;

impl Sort {
    fn key(mut self, path: &str, descending: bool) -> Self {
        if let Err(e) = ast_path(path) {
            self.error.get_or_insert(e);
        }
        self.keys.push(SortKey {
            path: path.to_owned(),
            descending,
        });
        self
    }
    /// Ascending on `path`.
    pub fn asc(path: &str) -> Self {
        Self::default().key(path, false)
    }
    /// Descending on `path`.
    pub fn desc(path: &str) -> Self {
        Self::default().key(path, true)
    }
    /// Then ascending on `path`.
    pub fn then_asc(self, path: &str) -> Self {
        self.key(path, false)
    }
    /// Then descending on `path`.
    pub fn then_desc(self, path: &str) -> Self {
        self.key(path, true)
    }
    /// The keys.
    #[must_use]
    pub fn keys(&self) -> &[SortKey] {
        &self.keys
    }
    pub(crate) fn check(&self) -> Result<()> {
        match (&self.error, self.keys.is_empty()) {
            (Some(e), _) => Err(Error::argument(e.clone())),
            (None, true) => Err(Error::argument("at least one key is required")),
            (None, false) => Ok(()),
        }
    }
    fn paths(&self) -> impl Iterator<Item = (AstPath, bool)> + '_ {
        self.keys
            .iter()
            .filter_map(|k| ast_path(&k.path).ok().map(|p| (p, k.descending)))
    }
    fn to_ast(&self) -> Vec<AstOrderItem> {
        self.paths()
            .map(|(p, descending)| AstOrderItem {
                expr: Some(path_expr(p)),
                descending,
            })
            .collect()
    }
    pub(crate) fn index_keys(&self) -> Vec<AstIndexKey> {
        self.paths()
            .map(|(p, descending)| AstIndexKey {
                path: Some(p),
                descending,
                analyzer: None,
                boost: None,
            })
            .collect()
    }
}

/// Projection: `Projection::include(["name", "total"])` or `Projection::exclude([...])`.
#[derive(Debug, Clone)]
#[must_use]
pub struct Projection {
    paths: Vec<String>,
    exclude: bool,
    error: Option<String>,
}

impl Projection {
    fn new<I: IntoIterator<Item = S>, S: Into<String>>(paths: I, exclude: bool) -> Self {
        let paths: Vec<String> = paths.into_iter().map(Into::into).collect();
        let mut error = paths
            .is_empty()
            .then(|| "a projection needs at least one path".to_owned());
        for p in &paths {
            if let Err(e) = ast_path(p) {
                error.get_or_insert(e);
            }
        }
        Self {
            paths,
            exclude,
            error,
        }
    }
    /// Only these paths (and `_id`).
    pub fn include<I: IntoIterator<Item = S>, S: Into<String>>(paths: I) -> Self {
        Self::new(paths, false)
    }
    /// Everything but these paths.
    pub fn exclude<I: IntoIterator<Item = S>, S: Into<String>>(paths: I) -> Self {
        Self::new(paths, true)
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.error
            .clone()
            .map_or(Ok(()), |e| Err(Error::argument(e)))
    }
    fn to_ast(&self) -> AstSelect {
        let items = self
            .paths
            .iter()
            .filter_map(|s| ast_path(s).ok())
            .map(|p| AstProjection {
                kind: Some(if self.exclude {
                    ast_projection::Kind::Exclude(AstPathProjection { path: Some(p) })
                } else {
                    ast_projection::Kind::Expr(AstExprProjection {
                        expr: Some(path_expr(p)),
                        alias: None,
                    })
                }),
            })
            .collect();
        AstSelect {
            kind: Some(ast_select::Kind::Items(AstSelectItems { items })),
        }
    }
}

// --------------------------------------------------------------------------------- statements

fn from_collection(c: &str) -> AstFromClause {
    AstFromClause {
        source: Some(Box::new(AstSource {
            kind: Some(ast_source::Kind::Collection(AstQualifiedName {
                database: None,
                name: c.to_owned(),
            })),
        })),
        alias: None,
        as_of: None,
    }
}

/// `FROM c [WHERE f] [SELECT p] [ORDER BY s] [LIMIT n] [OFFSET m]` (rule 6).
#[doc(hidden)]
pub fn find_statement(
    c: &str,
    f: &Filter,
    sort: Option<&Sort>,
    projection: Option<&Projection>,
    limit: Option<i64>,
    skip: Option<i64>,
    s: &mut ParamSink,
) -> Result<AstStatement> {
    let q = AstQuery {
        from: Some(Box::new(from_collection(c))),
        r#where: f.to_ast(s)?,
        select: projection.map(Projection::to_ast),
        order_by: sort.map(Sort::to_ast).unwrap_or_default(),
        limit: limit.map(int_lit),
        offset: skip.map(int_lit),
        ..AstQuery::default()
    };
    Ok(AstStatement {
        kind: Some(ast_statement::Kind::Query(q)),
    })
}

/// `UPDATE c <ops> [WHERE f] [LIMIT 1] [OPTIONS (allow_full_scan_write = true)]` (rules 4, 5).
#[doc(hidden)]
pub fn update_statement(
    c: &str,
    f: &Filter,
    u: &Update,
    one: bool,
    s: &mut ParamSink,
) -> Result<AstStatement> {
    let r#where = f.to_ast(s)?;
    let ops = u.to_ast(s)?;
    let st = AstUpdate {
        target: Some(AstQualifiedName {
            database: None,
            name: c.to_owned(),
        }),
        ops,
        r#where,
        limit: one.then(|| int_lit(1)),
        options: if f.is_empty() {
            vec![allow_full_scan_write()]
        } else {
            Vec::new()
        },
        ..AstUpdate::default()
    };
    Ok(AstStatement {
        kind: Some(ast_statement::Kind::Update(st)),
    })
}

/// `DELETE FROM c [WHERE f] [LIMIT 1] [OPTIONS (allow_full_scan_write = true)]`.
#[doc(hidden)]
pub fn delete_statement(c: &str, f: &Filter, one: bool, s: &mut ParamSink) -> Result<AstStatement> {
    let st = AstDelete {
        target: Some(AstQualifiedName {
            database: None,
            name: c.to_owned(),
        }),
        r#where: f.to_ast(s)?,
        limit: one.then(|| int_lit(1)),
        options: if f.is_empty() {
            vec![allow_full_scan_write()]
        } else {
            Vec::new()
        },
        ..AstDelete::default()
    };
    Ok(AstStatement {
        kind: Some(ast_statement::Kind::Delete(st)),
    })
}

/// The `CREATE INDEX` definition of `Collection::create_index`.
pub(crate) fn index_definition(c: &str, name: &str, keys: &Sort, unique: bool) -> AstCreateIndex {
    AstCreateIndex {
        index_type: if unique {
            AstIndexType::Unique
        } else {
            AstIndexType::Standard
        }
        .into(),
        name: name.to_owned(),
        on: Some(AstQualifiedName {
            database: None,
            name: c.to_owned(),
        }),
        keys: keys.index_keys(),
        ..AstCreateIndex::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_drv_rs_006_builder_misuse_is_an_argument_error() {
        assert!(
            Filter::and([Filter::eq("a", 1), Filter::gt("b", 2)])
                .check()
                .is_ok()
        );
        assert!(matches!(
            Filter::eq("a..b", 1).check(),
            Err(Error::Argument(_))
        ));
        assert!(Update::new().to_ast(&mut ParamSink::new()).is_err());
        assert!(Filter::not(Filter::empty()).check().is_err());
        assert!(Sort::default().check().is_err());
        assert!(Projection::include(Vec::<String>::new()).check().is_err());
    }

    #[test]
    fn tc_drv_rs_006_and_is_flattened_and_params_numbered() {
        let f = Filter::and([
            Filter::and([Filter::eq("a", 1), Filter::eq("b", 2)]),
            Filter::empty(),
            Filter::eq("c", 3),
        ]);
        let mut s = ParamSink::new();
        let Some(AstExpr {
            kind: Some(ast_expr::Kind::And(n)),
        }) = f.to_ast(&mut s).unwrap()
        else {
            panic!("expected and");
        };
        assert_eq!(n.args.len(), 3);
        let mut names: Vec<_> = s.params.keys().cloned().collect();
        names.sort();
        assert_eq!(names, ["f0", "f1", "f2"]);
    }
}
