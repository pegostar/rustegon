// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Canonical printing of queries, clauses and pipeline stages.

use super::Printer;
use crate::ast::{
    AggItem, GroupKey, GroupSpec, IndexName, LookupClause, MergeMatched, MergeNotMatched,
    OptionItem, OrderItem, Path, Projection, QualifiedName, Query, Select, SetItem, Source, Stage,
};

impl Printer {
    pub(super) fn query(&mut self, q: &Query) {
        self.kw("FROM ");
        match &q.from.source {
            Source::Collection(name) => self.qualified(name),
            Source::Subquery { query } => {
                self.out.push('(');
                self.query(query);
                self.out.push(')');
            }
            Source::Index { collection, index } => {
                self.kw("INDEX ");
                self.qualified(collection);
                self.out.push('.');
                self.name(index);
            }
        }
        if let Some(alias) = &q.from.alias {
            self.kw(" AS ");
            self.ident(alias);
        }
        if let Some(ts) = &q.from.as_of {
            self.kw(" AS OF SYSTEM TIME ");
            self.expr(ts);
        }
        for l in &q.lookups {
            self.out.push(' ');
            self.lookup(l);
        }
        if let Some(w) = &q.filter {
            self.kw(" WHERE ");
            self.expr(w);
        }
        if !q.group_by.is_empty() {
            self.kw(" GROUP BY ");
            self.group_keys(&q.group_by);
        }
        if let Some(h) = &q.having {
            self.kw(" HAVING ");
            self.expr(h);
        }
        if let Some(s) = &q.select {
            self.kw(" SELECT ");
            self.select(s);
        }
        if !q.order_by.is_empty() {
            self.kw(" ORDER BY ");
            self.order_items(&q.order_by);
        }
        if let Some(l) = &q.limit {
            self.kw(" LIMIT ");
            self.expr(l);
        }
        if let Some(o) = &q.offset {
            self.kw(" OFFSET ");
            self.expr(o);
        }
        if !q.include.is_empty() {
            self.kw(" INCLUDE ");
            self.list(&q.include, Self::path);
        }
        self.options(" OPTIONS ", &q.options);
        for s in &q.pipeline {
            self.kw(" |> ");
            self.stage(s);
        }
    }

    pub(super) fn qualified(&mut self, q: &QualifiedName) {
        if let Some(db) = &q.database {
            self.ident(db);
            self.out.push('.');
            self.name(&q.name);
        } else {
            self.ident(&q.name);
        }
    }

    pub(super) fn index_name(&mut self, n: &IndexName) {
        self.qualified(&n.collection);
        self.out.push('.');
        self.name(&n.index);
    }

    fn lookup(&mut self, l: &LookupClause) {
        self.kw("LOOKUP ");
        self.qualified(&l.collection);
        if let Some(a) = &l.alias {
            self.kw(" AS ");
            self.ident(a);
        }
        self.kw(" ON ");
        // `=` follows: an open-ended lambda/quantifier needs parentheses.
        self.operand(&l.local, crate::ast::expr::PREC_ADDITIVE);
        self.kw(" = ");
        self.path(&l.foreign);
        self.kw(" INTO ");
        self.ident(&l.into);
    }

    fn group_keys(&mut self, keys: &[GroupKey]) {
        self.list(keys, |p, k| {
            p.expr(&k.expr);
            if let Some(a) = &k.alias {
                p.kw(" AS ");
                p.ident(a);
            }
        });
    }

    fn select(&mut self, s: &Select) {
        match s {
            Select::Star => self.out.push('*'),
            Select::Value { expr } => {
                self.kw("VALUE ");
                self.expr(expr);
            }
            Select::Items { items } => self.projections(items),
        }
    }

    pub(super) fn projections(&mut self, items: &[Projection]) {
        self.list(items, |p, item| match item {
            Projection::Expr { expr, alias } => {
                p.expr_no_leading_minus(expr);
                if let Some(a) = alias {
                    p.kw(" AS ");
                    p.ident(a);
                }
            }
            Projection::Wildcard { path } => {
                p.path(path);
                p.out.push_str(".*");
            }
            Projection::Exclude { path } => {
                p.out.push('-');
                p.path(path);
            }
        });
    }

    pub(super) fn order_items(&mut self, items: &[OrderItem]) {
        self.list(items, |p, o| {
            p.expr(&o.expr);
            if o.descending {
                p.kw(" DESC");
            }
        });
    }

    /// `prefix(name = value, …)`, nothing when empty.
    pub(super) fn options(&mut self, prefix: &str, items: &[OptionItem]) {
        if items.is_empty() {
            return;
        }
        self.kw(prefix);
        self.option_list(items);
    }

    pub(super) fn option_list(&mut self, items: &[OptionItem]) {
        self.out.push('(');
        self.list(items, |p, o| {
            // Reserved words are valid bare option names (the parser reads any word here).
            p.name(&o.name);
            p.kw(" = ");
            p.expr(&o.value);
        });
        self.out.push(')');
    }

    pub(super) fn set_items(&mut self, items: &[SetItem]) {
        self.list(items, |p, s| {
            p.path(&s.path);
            p.kw(" = ");
            p.expr(&s.value);
        });
    }

    pub(super) fn paths(&mut self, paths: &[Path]) {
        self.list(paths, Self::path);
    }

    fn agg_items(&mut self, items: &[AggItem]) {
        self.list(items, |p, a| {
            p.ident(&a.name);
            p.kw(" = ");
            p.expr(&a.expr);
        });
    }

    fn opt_aggs(&mut self, items: &[AggItem]) {
        if !items.is_empty() {
            self.kw(" AGG ");
            self.agg_items(items);
        }
    }

    pub(super) fn group_spec(&mut self, g: &GroupSpec) {
        self.kw("GROUP BY ");
        self.group_keys(&g.keys);
        self.opt_aggs(&g.aggs);
    }

    fn sub_pipeline(&mut self, stages: &[Stage]) {
        self.out.push('(');
        for (i, s) in stages.iter().enumerate() {
            if i > 0 {
                self.kw(" |> ");
            }
            self.stage(s);
        }
        self.out.push(')');
    }

    fn stage(&mut self, s: &Stage) {
        match s {
            Stage::Match { predicate } => {
                self.kw("MATCH ");
                self.expr(predicate);
            }
            Stage::Project { items } => {
                self.kw("PROJECT ");
                self.projections(items);
            }
            Stage::Set { items } => {
                self.kw("SET ");
                self.set_items(items);
            }
            Stage::Unset { paths } => {
                self.kw("UNSET ");
                self.paths(paths);
            }
            Stage::Group(g) => self.group_spec(g),
            Stage::Sort { items } => {
                self.kw("SORT ");
                self.order_items(items);
            }
            Stage::Limit { count } => {
                self.kw("LIMIT ");
                self.expr(count);
            }
            Stage::Skip { count } => {
                self.kw("SKIP ");
                self.expr(count);
            }
            Stage::Lookup { lookup, pipeline } => {
                self.lookup(lookup);
                if let Some(stages) = pipeline {
                    self.kw(" PIPELINE ");
                    self.sub_pipeline(stages);
                }
            }
            Stage::Count { name } => {
                self.kw("COUNT AS ");
                self.ident(name);
            }
            Stage::Facet { facets } => {
                self.kw("FACET ");
                self.list(facets, |p, f| {
                    p.ident(&f.name);
                    p.out.push(' ');
                    p.sub_pipeline(&f.pipeline);
                });
            }
            Stage::Sample { size } => {
                self.kw("SAMPLE ");
                self.expr(size);
            }
            Stage::ReplaceRoot { expr } => {
                self.kw("REPLACE ROOT WITH ");
                self.expr(expr);
            }
            Stage::SortByCount { expr } => {
                self.kw("SORT BY COUNT ");
                self.expr(expr);
            }
            Stage::UnionWith { query } => {
                self.kw("UNION WITH (");
                self.query(query);
                self.out.push(')');
            }
            Stage::Out { collection } => {
                self.kw("OUT INTO ");
                self.qualified(collection);
            }
            _ => self.stage_complex(s),
        }
    }

    fn stage_complex(&mut self, s: &Stage) {
        match s {
            Stage::Unwind {
                path,
                alias,
                index,
                preserve_empty,
            } => {
                self.kw("UNWIND ");
                self.path(path);
                if let Some(a) = alias {
                    self.kw(" AS ");
                    self.ident(a);
                }
                if let Some(i) = index {
                    self.kw(" WITH INDEX ");
                    self.ident(i);
                }
                if *preserve_empty {
                    self.kw(" PRESERVE EMPTY");
                }
            }
            Stage::Bucket { .. } | Stage::BucketAuto { .. } | Stage::GraphLookup { .. } => {
                self.stage_bucket_or_graph(s);
            }
            Stage::Window {
                partition_by,
                order_by,
                compute,
            } => {
                self.kw("WINDOW");
                if !partition_by.is_empty() {
                    self.kw(" PARTITION BY ");
                    self.list(partition_by, Self::expr);
                }
                if !order_by.is_empty() {
                    self.kw(" ORDER BY ");
                    self.order_items(order_by);
                }
                self.kw(" COMPUTE ");
                self.agg_items(compute);
            }
            Stage::Merge {
                collection,
                on,
                when_matched,
                when_not_matched,
            } => {
                self.kw("MERGE INTO ");
                self.qualified(collection);
                self.kw(" ON ");
                self.paths(on);
                if let Some(m) = when_matched {
                    self.kw(match m {
                        MergeMatched::Replace => " WHEN MATCHED REPLACE",
                        MergeMatched::Update => " WHEN MATCHED UPDATE",
                        MergeMatched::Keep => " WHEN MATCHED KEEP",
                        MergeMatched::Fail => " WHEN MATCHED FAIL",
                    });
                }
                if let Some(n) = when_not_matched {
                    self.kw(match n {
                        MergeNotMatched::Insert => " WHEN NOT MATCHED INSERT",
                        MergeNotMatched::Discard => " WHEN NOT MATCHED DISCARD",
                    });
                }
            }
            _ => {}
        }
    }

    fn stage_bucket_or_graph(&mut self, s: &Stage) {
        match s {
            Stage::Bucket {
                by,
                boundaries,
                default,
                aggs,
            } => {
                self.kw("BUCKET BY ");
                self.expr(by);
                self.kw(" BOUNDARIES ");
                self.expr(boundaries);
                if let Some(d) = default {
                    self.kw(" DEFAULT ");
                    self.expr(d);
                }
                self.opt_aggs(aggs);
            }
            Stage::BucketAuto { by, buckets, aggs } => {
                self.kw("BUCKET AUTO BY ");
                self.expr(by);
                self.kw(" INTO ");
                self.expr(buckets);
                self.opt_aggs(aggs);
            }
            Stage::GraphLookup {
                collection,
                start_with,
                connect_from,
                connect_to,
                max_depth,
                filter,
                into,
            } => {
                self.kw("GRAPH LOOKUP ");
                self.qualified(collection);
                self.kw(" START WITH ");
                self.expr(start_with);
                self.kw(" CONNECT FROM ");
                self.path(connect_from);
                self.kw(" TO ");
                self.path(connect_to);
                if let Some(d) = max_depth {
                    self.kw(" MAX DEPTH ");
                    self.expr(d);
                }
                if let Some(f) = filter {
                    self.kw(" WHERE ");
                    self.expr(f);
                }
                self.kw(" INTO ");
                self.ident(into);
            }
            _ => {}
        }
    }
}
