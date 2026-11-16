// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The read side of the privilege walk (PD-056): queries, pipeline stages and expressions —
//! where sub-queries, joins and `load()` name further collections. Same rules as the parent
//! module: exhaustive matches, structs destructured without `..`.

use rustegon_query::ast::{
    AggItem, Expr, Facet, FromClause, GroupKey, GroupSpec, Literal, LookupClause, ObjectField,
    OptionItem, OrderItem, Path, Projection, Query, Segment, Select, SetItem, Source, Stage,
    WhenThen,
};
use rustegon_security::rbac::{Action, Resource};

use super::Walk;

impl Walk<'_> {
    pub(super) fn query(&mut self, q: &Query) {
        let Query {
            from,
            lookups,
            filter,
            group_by,
            having,
            select,
            order_by,
            limit,
            offset,
            include,
            options,
            pipeline,
        } = q;
        let FromClause {
            source,
            alias: _,
            as_of,
        } = from;
        match source {
            Source::Collection(name)
            | Source::Index {
                collection: name,
                index: _,
            } => self.on_coll(name, Action::Find),
            Source::Subquery { query } => self.query(query),
        }
        self.opt_expr(as_of.as_ref());
        for l in lookups {
            self.lookup(l);
        }
        self.opt_expr(filter.as_ref());
        self.group_keys(group_by);
        self.opt_expr(having.as_ref());
        if let Some(select) = select {
            self.select(select);
        }
        self.order_items(order_by);
        self.opt_expr(limit.as_ref());
        self.opt_expr(offset.as_ref());
        if !include.is_empty() {
            // INCLUDE dereferences ids into collections the statement does not name
            // (query-language.md §8 leaves the target open until M7).
            self.read_any();
        }
        for p in include {
            self.path(p);
        }
        self.options(options);
        self.stages(pipeline);
    }

    pub(super) fn lookup(&mut self, l: &LookupClause) {
        let LookupClause {
            collection,
            alias: _,
            local,
            foreign,
            into: _,
        } = l;
        self.on_coll(collection, Action::Find);
        self.expr(local);
        self.path(foreign);
    }

    pub(super) fn stages(&mut self, stages: &[Stage]) {
        for s in stages {
            self.stage(s);
        }
    }

    pub(super) fn stage(&mut self, stage: &Stage) {
        match stage {
            Stage::Match { predicate } => self.expr(predicate),
            Stage::Project { items } => self.projections(items),
            Stage::Set { items } => self.set_items(items),
            Stage::Unset { paths } => self.paths(paths),
            Stage::Group(g) => self.group_spec(g),
            Stage::Sort { items } => self.order_items(items),
            Stage::Limit { count } | Stage::Skip { count } => self.expr(count),
            Stage::Unwind {
                path,
                alias: _,
                index: _,
                preserve_empty: _,
            } => self.path(path),
            Stage::Lookup { lookup, pipeline } => {
                self.lookup(lookup);
                if let Some(p) = pipeline {
                    self.stages(p);
                }
            }
            Stage::Count { name: _ } => {}
            Stage::Facet { facets } => {
                for Facet { name: _, pipeline } in facets {
                    self.stages(pipeline);
                }
            }
            Stage::Bucket {
                by,
                boundaries,
                default,
                aggs,
            } => {
                self.expr(by);
                self.expr(boundaries);
                self.opt_expr(default.as_ref());
                self.agg_items(aggs);
            }
            Stage::BucketAuto { by, buckets, aggs } => {
                self.expr(by);
                self.expr(buckets);
                self.agg_items(aggs);
            }
            Stage::Sample { size } => self.expr(size),
            Stage::ReplaceRoot { expr } | Stage::SortByCount { expr } => self.expr(expr),
            Stage::GraphLookup {
                collection,
                start_with,
                connect_from,
                connect_to,
                max_depth,
                filter,
                into: _,
            } => {
                self.on_coll(collection, Action::Find);
                self.expr(start_with);
                self.path(connect_from);
                self.path(connect_to);
                self.opt_expr(max_depth.as_ref());
                self.opt_expr(filter.as_ref());
            }
            Stage::UnionWith { query } => self.query(query),
            Stage::Window {
                partition_by,
                order_by,
                compute,
            } => {
                self.exprs(partition_by);
                self.order_items(order_by);
                self.agg_items(compute);
            }
            Stage::Out { collection } => self.on_coll(collection, Action::AggregateWrite),
            Stage::Merge {
                collection,
                on,
                when_matched: _,
                when_not_matched: _,
            } => {
                self.on_coll(collection, Action::AggregateWrite);
                self.paths(on);
            }
        }
    }

    pub(super) fn group_spec(&mut self, g: &GroupSpec) {
        let GroupSpec { keys, aggs } = g;
        self.group_keys(keys);
        self.agg_items(aggs);
    }

    pub(super) fn group_keys(&mut self, keys: &[GroupKey]) {
        for GroupKey { expr, alias: _ } in keys {
            self.expr(expr);
        }
    }

    pub(super) fn agg_items(&mut self, items: &[AggItem]) {
        for AggItem { name: _, expr } in items {
            self.expr(expr);
        }
    }

    pub(super) fn select(&mut self, select: &Select) {
        match select {
            Select::Star => {}
            Select::Items { items } => self.projections(items),
            Select::Value { expr } => self.expr(expr),
        }
    }

    pub(super) fn projections(&mut self, items: &[Projection]) {
        for p in items {
            match p {
                Projection::Expr { expr, alias: _ } => self.expr(expr),
                Projection::Wildcard { path } | Projection::Exclude { path } => self.path(path),
            }
        }
    }

    pub(super) fn order_items(&mut self, items: &[OrderItem]) {
        for OrderItem {
            expr,
            descending: _,
        } in items
        {
            self.expr(expr);
        }
    }

    pub(super) fn options(&mut self, options: &[OptionItem]) {
        for OptionItem { name: _, value } in options {
            self.expr(value);
        }
    }

    pub(super) fn set_items(&mut self, items: &[SetItem]) {
        for SetItem { path, value } in items {
            self.path(path);
            self.expr(value);
        }
    }

    pub(super) fn paths(&mut self, paths: &[Path]) {
        for p in paths {
            self.path(p);
        }
    }

    /// Paths carry expressions in `[expr]` segments.
    pub(super) fn path(&mut self, path: &Path) {
        let Path(segments) = path;
        for s in segments {
            match s {
                Segment::Field(_) | Segment::Position(_) | Segment::Each => {}
                Segment::Index(e) => self.expr(e),
            }
        }
    }

    pub(super) fn exprs(&mut self, exprs: &[Expr]) {
        for e in exprs {
            self.expr(e);
        }
    }

    pub(super) fn opt_expr(&mut self, e: Option<&Expr>) {
        if let Some(e) = e {
            self.expr(e);
        }
    }

    pub(super) fn expr(&mut self, e: &Expr) {
        match e {
            Expr::Literal(_) | Expr::Param { name: _ } | Expr::Star => {}
            Expr::Path { path } => self.path(path),
            Expr::Access { base, path } => {
                self.expr(base);
                self.path(path);
            }
            Expr::Binary { op: _, left, right } => {
                self.expr(left);
                self.expr(right);
            }
            Expr::And { args } | Expr::Or { args } | Expr::Array { elements: args } => {
                self.exprs(args);
            }
            Expr::Neg { expr }
            | Expr::Not { expr }
            | Expr::Extract { unit: _, expr }
            | Expr::Is {
                expr,
                negated: _,
                test: _,
            } => self.expr(expr),
            Expr::Between { expr, low, high } => {
                self.expr(expr);
                self.expr(low);
                self.expr(high);
            }
            Expr::Call { name, args } => self.call(name, args),
            Expr::Case {
                operand,
                whens,
                otherwise,
            } => {
                self.opt_expr(operand.as_deref());
                for WhenThen { when, then } in whens {
                    self.expr(when);
                    self.expr(then);
                }
                self.opt_expr(otherwise.as_deref());
            }
            Expr::Lambda { params: _, body } => self.expr(body),
            Expr::Quantified {
                quantifier: _,
                var: _,
                source,
                predicate,
            } => {
                self.expr(source);
                self.expr(predicate);
            }
            Expr::ElemMatch { path, predicate } => {
                self.path(path);
                self.expr(predicate);
            }
            Expr::Object { fields } => {
                for ObjectField { name: _, value } in fields {
                    self.expr(value);
                }
            }
        }
    }

    /// `load(id [, collection])` (query-language.md §4.2, §8) reads another collection; every
    /// other catalog function reads only the current row.
    pub(super) fn call(&mut self, name: &str, args: &[Expr]) {
        // Function names bind case-insensitively (query-language.md §4.2).
        if name.eq_ignore_ascii_case("load") {
            match args {
                [_, Expr::Literal(Literal::String(target))] => {
                    // `db.coll` or `coll`; database names never contain `.` (resource.rs).
                    let resource = match target.split_once('.') {
                        Some((db, coll)) => Resource::collection(db, coll),
                        None => Resource::collection(self.session, target.clone()),
                    };
                    self.need(resource, Action::Find);
                }
                // No collection, a computed one or a wrong arity: not known statically.
                _ => self.read_any(),
            }
        }
        self.exprs(args);
    }
}
