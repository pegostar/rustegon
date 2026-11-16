// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `proptest` generators of canonical RGQL ASTs (TC-QL-003).
//!
//! Every generated AST is one the parser can produce (the invariants of `ast` module docs):
//! paths start with a field, `access` bases are never paths, `AND`/`OR` have ≥ 2 operands,
//! `*` only as a call argument, `[]` only in `INCLUDE`, non-empty names, finite numbers, list
//! productions that the grammar requires non-empty are non-empty. Names deliberately include
//! reserved words, keywords and arbitrary Unicode to exercise quoting.

use proptest::{collection::vec, option::of as opt, prelude::*, sample::select};
use rustegon_doc::{
    Decimal128, ObjectId,
    decimal::{EXP_MAX, EXP_MIN, MAX_COEFFICIENT},
};
use rustegon_query::ast::*;

const WORDS: &[&str] = &[
    "select", "VALUE", "from", "Where", "date", "index", "elem", "any", "of", "count", "first",
    "asc", "desc", "true", "null", "missing", "not", "and", "set", "match", "limit", "x", "_id",
];

const FUNCTIONS: &[&str] = &[
    "f",
    "now",
    "count",
    "sum",
    "if",
    "values",
    "any",
    "in",
    "date",
    "elem",
    "replace",
    "min",
    "first",
    "extract",
    "select",
    "COUNT",
    "vector_near",
];

pub fn name() -> BoxedStrategy<String> {
    prop_oneof![
        6 => "[a-z_][a-zA-Z0-9_]{0,6}",
        2 => select(WORDS).prop_map(str::to_owned),
        1 => "[ -~]{1,5}",
        1 => "\\PC{1,3}",
        1 => vec(any::<char>(), 1..4).prop_map(String::from_iter),
    ]
    .boxed()
}

fn text() -> BoxedStrategy<String> {
    prop_oneof![
        3 => "[a-z ]{0,8}",
        1 => "['\\\\%_\\-;/*]{0,6}",
        1 => vec(any::<char>(), 0..6).prop_map(String::from_iter),
    ]
    .boxed()
}

fn decimal() -> impl Strategy<Value = Decimal128> {
    (
        any::<bool>(),
        prop_oneof![0u128..1000, 0u128..=MAX_COEFFICIENT],
        prop_oneof![-10i32..10, EXP_MIN..=EXP_MAX],
    )
        .prop_filter_map("representable", |(neg, c, e)| {
            Decimal128::new(neg, c, e).ok()
        })
}

pub fn literal() -> BoxedStrategy<Literal> {
    prop_oneof![
        Just(Literal::Null),
        any::<bool>().prop_map(Literal::Bool),
        any::<i64>().prop_map(Literal::Int),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Literal::Float),
        decimal().prop_map(Literal::Decimal),
        text().prop_map(Literal::String),
        any::<i64>().prop_map(Literal::DateTime),
        any::<[u8; 12]>().prop_map(|b| Literal::ObjectId(ObjectId(b))),
        any::<[u8; 16]>().prop_map(Literal::Uuid),
        text().prop_map(Literal::Interval),
    ]
    .boxed()
}

fn param() -> BoxedStrategy<Expr> {
    prop_oneof![
        "[a-zA-Z_][a-zA-Z0-9_]{0,5}",
        (1u32..1000).prop_map(|n| n.to_string()),
    ]
    .prop_map(|name| Expr::Param { name })
    .boxed()
}

const BINARY_OPS: &[BinaryOp] = &[
    BinaryOp::Eq,
    BinaryOp::EqWhole,
    BinaryOp::Ne,
    BinaryOp::Lt,
    BinaryOp::Le,
    BinaryOp::Gt,
    BinaryOp::Ge,
    BinaryOp::In,
    BinaryOp::NotIn,
    BinaryOp::Like,
    BinaryOp::Ilike,
    BinaryOp::Matches,
    BinaryOp::Contains,
    BinaryOp::ContainsAny,
    BinaryOp::ContainsAll,
    BinaryOp::Add,
    BinaryOp::Sub,
    BinaryOp::Mul,
    BinaryOp::Div,
    BinaryOp::Mod,
    BinaryOp::Concat,
];

/// A path whose index segments use `inner`.
fn path_with(inner: BoxedStrategy<Expr>, each: bool) -> BoxedStrategy<Path> {
    let base = prop_oneof![
        3 => name().prop_map(Segment::Field),
        1 => any::<u32>().prop_map(Segment::Position),
        1 => inner.prop_map(|e| Segment::Index(Box::new(e))),
    ];
    let seg = if each {
        prop_oneof![4 => base, 1 => Just(Segment::Each)].boxed()
    } else {
        base.boxed()
    };
    (name(), vec(seg, 0..3))
        .prop_map(|(root, rest)| {
            let mut segs = vec![Segment::Field(root)];
            segs.extend(rest);
            Path(segs)
        })
        .boxed()
}

fn leaf() -> BoxedStrategy<Expr> {
    prop_oneof![
        3 => literal().prop_map(Expr::Literal),
        1 => param(),
        2 => name().prop_map(|n| Expr::Path { path: Path(vec![Segment::Field(n)]) }),
    ]
    .boxed()
}

pub fn path() -> BoxedStrategy<Path> {
    path_with(leaf(), false)
}

pub fn include_path() -> BoxedStrategy<Path> {
    path_with(leaf(), true)
}

pub fn expr() -> BoxedStrategy<Expr> {
    leaf()
        .prop_recursive(4, 32, 4, |inner| {
            let i = || inner.clone().boxed();
            let arg = prop_oneof![5 => i(), 1 => Just(Expr::Star)];
            prop_oneof![
                3 => (select(BINARY_OPS), i(), i())
                    .prop_map(|(op, l, r)| Expr::Binary { op, left: Box::new(l), right: Box::new(r) }),
                1 => vec(i(), 2..4).prop_map(|args| Expr::And { args }),
                1 => vec(i(), 2..4).prop_map(|args| Expr::Or { args }),
                1 => i().prop_map(|e| Expr::Neg { expr: Box::new(e) }),
                1 => i().prop_map(|e| Expr::Not { expr: Box::new(e) }),
                1 => (i(), i(), i()).prop_map(|(e, l, h)| Expr::Between {
                    expr: Box::new(e), low: Box::new(l), high: Box::new(h)
                }),
                1 => (i(), any::<bool>(), prop_oneof![Just(IsTest::Null), Just(IsTest::Missing)])
                    .prop_map(|(e, negated, test)| Expr::Is { expr: Box::new(e), negated, test }),
                2 => (select(FUNCTIONS), vec(arg, 0..3))
                    .prop_map(|(n, args)| Expr::Call { name: n.to_owned(), args }),
                1 => (name(), i()).prop_map(|(unit, e)| Expr::Extract { unit, expr: Box::new(e) }),
                1 => (opt(i()), vec((i(), i()), 1..3), opt(i())).prop_map(|(op, w, e)| Expr::Case {
                    operand: op.map(Box::new),
                    whens: w.into_iter().map(|(when, then)| WhenThen { when, then }).collect(),
                    otherwise: e.map(Box::new),
                }),
                1 => (vec(name(), 0..3), i())
                    .prop_map(|(params, b)| Expr::Lambda { params, body: Box::new(b) }),
                1 => (any::<bool>(), name(), i(), i()).prop_map(|(a, var, s, p)| Expr::Quantified {
                    quantifier: if a { Quantifier::Any } else { Quantifier::Every },
                    var,
                    source: Box::new(s),
                    predicate: Box::new(p),
                }),
                1 => (path_with(i(), false), i())
                    .prop_map(|(path, p)| Expr::ElemMatch { path, predicate: Box::new(p) }),
                1 => vec(i(), 0..3).prop_map(|elements| Expr::Array { elements }),
                1 => vec((name(), i()), 0..3).prop_map(|f| Expr::Object {
                    fields: f.into_iter().map(|(name, value)| ObjectField { name, value }).collect(),
                }),
                1 => path_with(i(), false).prop_map(|path| Expr::Path { path }),
                1 => (
                    i().prop_filter("access base is not a path", |b| {
                        !matches!(b, Expr::Path { .. } | Expr::Access { .. })
                    }),
                    path_with(i(), false),
                )
                    .prop_map(|(base, p)| Expr::Access { base: Box::new(base), path: Path(p.0) }),
            ]
        })
        .boxed()
}

fn qname() -> BoxedStrategy<QualifiedName> {
    (opt(name()), name())
        .prop_map(|(database, name)| QualifiedName { database, name })
        .boxed()
}

fn alias() -> BoxedStrategy<Option<String>> {
    opt(name()).boxed()
}

fn projection() -> BoxedStrategy<Projection> {
    prop_oneof![
        4 => (expr(), alias()).prop_map(|(expr, alias)| Projection::Expr { expr, alias }),
        1 => path().prop_map(|path| Projection::Wildcard { path }),
        1 => path().prop_map(|path| Projection::Exclude { path }),
    ]
    .boxed()
}

fn order_items(min: usize) -> BoxedStrategy<Vec<OrderItem>> {
    vec(
        (expr(), any::<bool>()).prop_map(|(expr, descending)| OrderItem { expr, descending }),
        min..3,
    )
    .boxed()
}

fn options(min: usize) -> BoxedStrategy<Vec<OptionItem>> {
    vec(
        (name(), expr()).prop_map(|(name, value)| OptionItem { name, value }),
        min..3,
    )
    .boxed()
}

fn set_items() -> BoxedStrategy<Vec<SetItem>> {
    vec(
        (path(), expr()).prop_map(|(path, value)| SetItem { path, value }),
        1..3,
    )
    .boxed()
}

fn agg_items(min: usize) -> BoxedStrategy<Vec<AggItem>> {
    vec(
        (name(), expr()).prop_map(|(name, expr)| AggItem { name, expr }),
        min..3,
    )
    .boxed()
}

fn group_keys() -> BoxedStrategy<Vec<GroupKey>> {
    vec(
        (expr(), alias()).prop_map(|(expr, alias)| GroupKey { expr, alias }),
        1..3,
    )
    .boxed()
}

fn group_spec() -> BoxedStrategy<GroupSpec> {
    (group_keys(), agg_items(0))
        .prop_map(|(keys, aggs)| GroupSpec { keys, aggs })
        .boxed()
}

fn lookup_clause() -> BoxedStrategy<LookupClause> {
    (qname(), alias(), expr(), path(), name())
        .prop_map(|(collection, alias, local, foreign, into)| LookupClause {
            collection,
            alias,
            local,
            foreign,
            into,
        })
        .boxed()
}

pub fn query(depth: u32) -> BoxedStrategy<Query> {
    let source = if depth == 0 {
        qname().prop_map(Source::Collection).boxed()
    } else {
        prop_oneof![
            4 => qname().prop_map(Source::Collection),
            1 => query(depth - 1).prop_map(|q| Source::Subquery { query: Box::new(q) }),
            1 => (qname(), name()).prop_map(|(collection, index)| Source::Index { collection, index }),
        ]
        .boxed()
    };
    let select = prop_oneof![
        Just(Select::Star),
        vec(projection(), 1..3).prop_map(|items| Select::Items { items }),
        expr().prop_map(|expr| Select::Value { expr }),
    ];
    let head = (
        source,
        alias(),
        opt(expr()),
        vec(lookup_clause(), 0..2),
        opt(expr()),
        prop_oneof![Just(Vec::new()), group_keys()],
        opt(expr()),
        opt(select),
    );
    let tail = (
        order_items(0),
        opt(expr()),
        opt(expr()),
        vec(include_path(), 0..2),
        options(0),
        vec(stage(depth), 0..3),
    );
    (head, tail)
        .prop_map(
            |((src, al, asof, lk, wh, gb, hv, sel), (ob, li, of, inc, opts, pl))| Query {
                from: FromClause {
                    source: src,
                    alias: al,
                    as_of: asof,
                },
                lookups: lk,
                filter: wh,
                group_by: gb,
                having: hv,
                select: sel,
                order_by: ob,
                limit: li,
                offset: of,
                include: inc,
                options: opts,
                pipeline: pl,
            },
        )
        .boxed()
}

fn sub_pipeline(depth: u32) -> BoxedStrategy<Vec<Stage>> {
    vec(stage(depth), 1..3).boxed()
}

fn simple_stage_a() -> BoxedStrategy<Stage> {
    prop_oneof![
        expr().prop_map(|predicate| Stage::Match { predicate }),
        vec(projection(), 1..3).prop_map(|items| Stage::Project { items }),
        set_items().prop_map(|items| Stage::Set { items }),
        vec(path(), 1..3).prop_map(|paths| Stage::Unset { paths }),
        group_spec().prop_map(Stage::Group),
        order_items(1).prop_map(|items| Stage::Sort { items }),
        expr().prop_map(|count| Stage::Limit { count }),
        expr().prop_map(|count| Stage::Skip { count }),
        (path(), alias(), alias(), any::<bool>()).prop_map(|(path, alias, index, pe)| {
            Stage::Unwind {
                path,
                alias,
                index,
                preserve_empty: pe,
            }
        }),
        name().prop_map(|name| Stage::Count { name }),
    ]
    .boxed()
}

pub fn stage(depth: u32) -> BoxedStrategy<Stage> {
    let simple = prop_oneof![
        simple_stage_a(),
        (expr(), expr(), opt(expr()), agg_items(0)).prop_map(|(by, boundaries, default, aggs)| {
            Stage::Bucket {
                by,
                boundaries,
                default,
                aggs,
            }
        }),
        (expr(), expr(), agg_items(0)).prop_map(|(by, buckets, aggs)| Stage::BucketAuto {
            by,
            buckets,
            aggs
        }),
        expr().prop_map(|size| Stage::Sample { size }),
        expr().prop_map(|expr| Stage::ReplaceRoot { expr }),
        expr().prop_map(|expr| Stage::SortByCount { expr }),
        (
            qname(),
            expr(),
            path(),
            path(),
            opt(expr()),
            opt(expr()),
            name()
        )
            .prop_map(
                |(collection, start_with, connect_from, connect_to, max_depth, filter, into)| {
                    Stage::GraphLookup {
                        collection,
                        start_with,
                        connect_from,
                        connect_to,
                        max_depth,
                        filter,
                        into,
                    }
                }
            ),
        (vec(expr(), 0..2), order_items(0), agg_items(1)).prop_map(|(p, o, c)| Stage::Window {
            partition_by: p,
            order_by: o,
            compute: c,
        }),
        qname().prop_map(|collection| Stage::Out { collection }),
        (
            qname(),
            vec(path(), 1..3),
            opt(select(
                &[
                    MergeMatched::Replace,
                    MergeMatched::Update,
                    MergeMatched::Keep,
                    MergeMatched::Fail
                ][..]
            )),
            opt(select(
                &[MergeNotMatched::Insert, MergeNotMatched::Discard][..]
            )),
        )
            .prop_map(
                |(collection, on, when_matched, when_not_matched)| Stage::Merge {
                    collection,
                    on,
                    when_matched,
                    when_not_matched,
                }
            ),
        lookup_clause().prop_map(|lookup| Stage::Lookup {
            lookup,
            pipeline: None
        }),
    ];
    if depth == 0 {
        return simple.boxed();
    }
    prop_oneof![
        6 => simple,
        1 => (lookup_clause(), sub_pipeline(depth - 1))
            .prop_map(|(lookup, p)| Stage::Lookup { lookup, pipeline: Some(p) }),
        1 => vec((name(), sub_pipeline(depth - 1)), 1..3).prop_map(|f| Stage::Facet {
            facets: f.into_iter().map(|(name, pipeline)| Facet { name, pipeline }).collect(),
        }),
        1 => query(depth - 1).prop_map(|q| Stage::UnionWith { query: Box::new(q) }),
    ]
    .boxed()
}

fn returning() -> BoxedStrategy<Option<Returning>> {
    opt(
        (any::<bool>(), vec(projection(), 0..3)).prop_map(|(old, items)| Returning {
            image: if old { Image::Old } else { Image::New },
            items,
        }),
    )
    .boxed()
}

fn update_op() -> BoxedStrategy<UpdateOp> {
    prop_oneof![
        set_items().prop_map(|items| UpdateOp::Set { items }),
        vec(path(), 1..3).prop_map(|paths| UpdateOp::Unset { paths }),
        (path(), expr()).prop_map(|(path, by)| UpdateOp::Inc { path, by }),
        (path(), expr()).prop_map(|(path, by)| UpdateOp::Mul { path, by }),
        (path(), expr(), opt(expr()), opt(expr()), order_items(0)).prop_map(
            |(path, value, position, slice, sort)| UpdateOp::Push {
                path,
                value,
                position,
                slice,
                sort
            }
        ),
        (path(), expr()).prop_map(|(path, predicate)| UpdateOp::Pull { path, predicate }),
        (path(), expr()).prop_map(|(path, value)| UpdateOp::AddToSet { path, value }),
        (path(), any::<bool>()).prop_map(|(path, f)| UpdateOp::Pop {
            path,
            end: if f { PopEnd::First } else { PopEnd::Last },
        }),
        (path(), path()).prop_map(|(from, to)| UpdateOp::Rename { from, to }),
        (path(), expr()).prop_map(|(path, value)| UpdateOp::Min { path, value }),
        (path(), expr()).prop_map(|(path, value)| UpdateOp::Max { path, value }),
        path().prop_map(|path| UpdateOp::CurrentDate { path }),
    ]
    .boxed()
}

fn update_ops() -> BoxedStrategy<Vec<UpdateOp>> {
    prop_oneof![
        5 => vec(update_op(), 1..4),
        1 => expr().prop_map(|value| vec![UpdateOp::Replace { value }]),
    ]
    .boxed()
}

fn update() -> BoxedStrategy<Statement> {
    (
        qname(),
        alias(),
        update_ops(),
        opt(expr()),
        opt(expr()),
        options(0),
        returning(),
    )
        .prop_map(|(target, alias, ops, filter, limit, options, returning)| {
            Statement::Update(Update {
                target,
                alias,
                ops,
                filter,
                limit,
                options,
                returning,
            })
        })
        .boxed()
}

fn delete() -> BoxedStrategy<Statement> {
    (
        vec(path(), 0..2),
        qname(),
        opt(expr()),
        opt(expr()),
        options(0),
        returning(),
    )
        .prop_map(|(columns, target, filter, limit, options, returning)| {
            Statement::Delete(Delete {
                columns,
                target,
                filter,
                limit,
                options,
                returning,
            })
        })
        .boxed()
}

fn insert() -> BoxedStrategy<Statement> {
    let source = prop_oneof![
        expr().prop_map(|expr| InsertSource::Value { expr }),
        vec(expr(), 1..3).prop_map(|rows| InsertSource::Values { rows }),
        (vec(name(), 1..3), vec(vec(expr(), 1..3), 1..3))
            .prop_map(|(columns, rows)| InsertSource::Tuples { columns, rows }),
        query(1).prop_map(|q| InsertSource::Query { query: Box::new(q) }),
    ];
    let conflict = opt(prop_oneof![
        Just(OnConflict::DoNothing),
        update_ops().prop_map(|ops| OnConflict::DoUpdate { ops }),
    ]);
    (qname(), source, conflict, opt(expr()), returning())
        .prop_map(|(target, source, on_conflict, ttl, returning)| {
            Statement::Insert(Insert {
                target,
                source,
                on_conflict,
                ttl,
                returning,
            })
        })
        .boxed()
}

fn column_defs(min: usize, clustering: bool) -> BoxedStrategy<Vec<ColumnDef>> {
    vec(
        (name(), name(), any::<bool>()).prop_map(move |(name, type_name, d)| ColumnDef {
            name,
            type_name,
            descending: clustering && d,
        }),
        min..3,
    )
    .boxed()
}

fn duration() -> BoxedStrategy<Duration> {
    (expr(), name())
        .prop_map(|(amount, unit)| Duration { amount, unit })
        .boxed()
}

fn ddl() -> BoxedStrategy<Statement> {
    let index_types = vec![
        IndexType::Standard,
        IndexType::Unique,
        IndexType::Ttl,
        IndexType::Fulltext,
        IndexType::Vector,
        IndexType::Geo,
        IndexType::Local,
    ];
    let key = (path(), any::<bool>(), opt(expr()), opt(expr())).prop_map(
        |(path, descending, analyzer, boost)| IndexKey {
            path,
            descending,
            analyzer,
            boost,
        },
    );
    prop_oneof![
        (name(), options(0))
            .prop_map(|(name, options)| Statement::CreateDatabase { name, options }),
        (qname(), options(0))
            .prop_map(|(name, options)| Statement::CreateCollection { name, options }),
        (
            qname(),
            column_defs(1, false),
            column_defs(0, true),
            column_defs(0, false),
            column_defs(0, false),
            opt(name()),
            opt(expr())
        )
            .prop_map(|(name, pk, ck, st, cols, distribution, default_ttl)| {
                Statement::CreateTable(CreateTable {
                    name,
                    partition_key: pk,
                    clustering_key: ck,
                    static_columns: st,
                    columns: cols,
                    distribution,
                    default_ttl,
                })
            }),
        (
            qname(),
            path(),
            opt(path()),
            opt(name()),
            opt(expr()),
            opt(duration()),
            opt(duration())
        )
            .prop_map(|(name, tf, mf, g, mp, span, ret)| {
                Statement::CreateTimeseries(CreateTimeseries {
                    name,
                    time_field: tf,
                    meta_field: mf,
                    granularity: g,
                    bucket_max_points: mp,
                    bucket_span: span,
                    retention: ret,
                })
            }),
        (
            select(index_types),
            name(),
            qname(),
            vec(key, 1..3),
            opt(expr()),
            options(0)
        )
            .prop_map(|(index_type, name, on, keys, expire_after, options)| {
                Statement::CreateIndex(CreateIndex {
                    index_type,
                    name,
                    on,
                    keys,
                    expire_after,
                    options,
                })
            }),
        (name(), qname(), query(1), group_spec()).prop_map(|(name, on, map, reduce)| {
            Statement::CreateMapreduceIndex {
                name,
                on,
                map: Box::new(map),
                reduce,
            }
        }),
        (qname(), qname(), group_spec())
            .prop_map(|(name, on, group)| Statement::CreateContinuousAggregate { name, on, group }),
        (name(), qname(), opt(expr())).prop_map(|(name, on, filter)| {
            Statement::CreateChangeSubscription { name, on, filter }
        }),
    ]
    .boxed()
}

fn index_name() -> BoxedStrategy<IndexName> {
    (qname(), name())
        .prop_map(|(collection, index)| IndexName { collection, index })
        .boxed()
}

fn admin() -> BoxedStrategy<Statement> {
    let action = prop_oneof![
        options(1).prop_map(|options| AlterCollectionAction::SetOptions { options }),
        vec(vec(expr(), 1..3), 1..3).prop_map(|points| AlterCollectionAction::SplitAt { points }),
    ];
    let show = prop_oneof![
        Just(ShowTarget::Collections),
        Just(ShowTarget::Transactions),
        qname().prop_map(|on| ShowTarget::Indexes { on }),
        qname().prop_map(|collection| ShowTarget::Ranges { collection }),
    ];
    let begin = (
        opt(select(
            &[
                Isolation::Serializable,
                Isolation::Snapshot,
                Isolation::ReadCommitted,
            ][..],
        )),
        any::<bool>(),
        opt(select(
            &[Priority::High, Priority::Normal, Priority::Low][..],
        )),
        opt(expr()),
    )
        .prop_map(|(isolation, read_only, priority, as_of)| {
            Statement::Begin(Begin {
                isolation,
                read_only,
                priority,
                as_of,
            })
        });
    prop_oneof![
        (qname(), action).prop_map(|(name, action)| Statement::AlterCollection { name, action }),
        (index_name(), any::<bool>())
            .prop_map(|(name, hidden)| Statement::AlterIndex { name, hidden }),
        name().prop_map(|name| Statement::DropDatabase { name }),
        qname().prop_map(|name| Statement::DropCollection { name }),
        index_name().prop_map(|name| Statement::DropIndex { name }),
        show.prop_map(|target| Statement::Show { target }),
        (any::<bool>(), expr()).prop_map(|(q, id)| Statement::Kill {
            target: if q {
                KillTarget::Query
            } else {
                KillTarget::Transaction
            },
            id,
        }),
        begin,
        name().prop_map(|name| Statement::Savepoint { name }),
        name().prop_map(|name| Statement::RollbackToSavepoint { name }),
        name().prop_map(|name| Statement::ReleaseSavepoint { name }),
        Just(Statement::Commit),
        Just(Statement::Rollback),
    ]
    .boxed()
}

pub fn statement() -> BoxedStrategy<Statement> {
    let explained = prop_oneof![query(1).prop_map(Statement::Query), update(), delete()];
    prop_oneof![
        6 => query(2).prop_map(Statement::Query),
        2 => insert(),
        2 => update(),
        1 => (qname(), expr(), vec(path(), 0..2), returning()).prop_map(
            |(target, value, on, returning)| Statement::Upsert(Upsert { target, value, on, returning })
        ),
        1 => delete(),
        1 => (any::<bool>(), explained)
            .prop_map(|(analyze, s)| Statement::Explain { analyze, statement: Box::new(s) }),
        2 => ddl(),
        2 => admin(),
    ]
    .boxed()
}
