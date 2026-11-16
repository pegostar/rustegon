// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Query clauses (query-language.md §3 `query`, §5, §8) and pipeline stages (§7).

use super::{PResult, Parser, lexer::TokenKind};
use crate::ast::{
    AggItem, Expr, Facet, GroupKey, GroupSpec, IndexName, LookupClause, MergeMatched,
    MergeNotMatched, OptionItem, OrderItem, Path, Projection, QualifiedName, Query, Select,
    SetItem, Source, Stage, expr::PREC_ADDITIVE,
};

impl Parser<'_> {
    /// `FROM … { |> stage }` (one nesting level: sub-queries recurse through here).
    pub(super) fn query(&mut self) -> PResult<Query> {
        self.nested_by(super::QUERY_NESTING_COST, Self::query_inner)
    }

    fn query_inner(&mut self) -> PResult<Query> {
        self.expect_kw("FROM")?;
        let mut q = Query::from_source(self.source()?);
        if self.check_kw("AS") && !self.is_kw(1, "OF") {
            self.advance();
            q.from.alias = Some(self.ident()?);
        }
        if self.check_kw("AS") && self.is_kw(1, "OF") {
            self.expect_kws(&["AS", "OF", "SYSTEM", "TIME"])?;
            q.from.as_of = Some(self.expr()?);
        }
        while self.check_kw("LOOKUP") {
            q.lookups.push(self.lookup_clause()?);
        }
        if self.eat_kw("WHERE") {
            q.filter = Some(self.expr()?);
        }
        if self.check_kw("GROUP") {
            self.expect_kws(&["GROUP", "BY"])?;
            q.group_by = self.group_keys()?;
        }
        if self.eat_kw("HAVING") {
            q.having = Some(self.expr()?);
        }
        if self.eat_kw("SELECT") {
            q.select = Some(self.select()?);
        }
        if self.check_kw("ORDER") {
            self.expect_kws(&["ORDER", "BY"])?;
            q.order_by = self.order_items()?;
        }
        if self.eat_kw("LIMIT") {
            q.limit = Some(self.expr()?);
        }
        if self.eat_kw("OFFSET") {
            q.offset = Some(self.expr()?);
        }
        if self.eat_kw("INCLUDE") {
            q.include = self.path_list(true)?;
        }
        q.options = self.opt_options("OPTIONS")?;
        while self.eat(&TokenKind::Pipe, "'|>'") {
            q.pipeline.push(self.stage()?);
        }
        Ok(q)
    }

    fn source(&mut self) -> PResult<Source> {
        if self.eat(&TokenKind::LParen, "'('") {
            let query = self.query()?;
            self.expect(&TokenKind::RParen, "')'")?;
            return Ok(Source::Subquery {
                query: Box::new(query),
            });
        }
        if self.is_kw(0, "INDEX") && self.is_ident_at(1) {
            self.advance();
            let IndexName { collection, index } = self.index_name()?;
            return Ok(Source::Index { collection, index });
        }
        Ok(Source::Collection(self.qualified_name()?))
    }

    /// `ident [. name]`.
    pub(super) fn qualified_name(&mut self) -> PResult<QualifiedName> {
        let first = self.ident()?;
        if self.eat(&TokenKind::Dot, "'.'") {
            let name = self.name()?;
            return Ok(QualifiedName {
                database: Some(first),
                name,
            });
        }
        Ok(QualifiedName {
            database: None,
            name: first,
        })
    }

    /// `[db.]collection.index`.
    pub(super) fn index_name(&mut self) -> PResult<IndexName> {
        let mut parts = vec![self.ident()?];
        while parts.len() < 3 && self.eat(&TokenKind::Dot, "'.'") {
            parts.push(self.name()?);
        }
        let index = parts.pop().unwrap_or_default();
        let collection = match parts.as_slice() {
            [db, coll] => QualifiedName::new(Some(db), coll),
            [coll] => QualifiedName::new(None, coll),
            _ => {
                return Err(self.error_at(self.pos, "index names are [database.]collection.index"));
            }
        };
        Ok(IndexName { collection, index })
    }

    /// `LOOKUP coll [AS a] ON expr = path INTO f`.
    pub(super) fn lookup_clause(&mut self) -> PResult<LookupClause> {
        self.expect_kw("LOOKUP")?;
        let collection = self.qualified_name()?;
        let alias = if self.eat_kw("AS") {
            Some(self.ident()?)
        } else {
            None
        };
        self.expect_kw("ON")?;
        // Above comparisons: the `=` belongs to the clause, not to the expression.
        let local = self.expr_bp(PREC_ADDITIVE)?;
        self.expect(&TokenKind::Eq, "'='")?;
        let foreign = self.path(false)?;
        self.expect_kw("INTO")?;
        let into = self.ident()?;
        Ok(LookupClause {
            collection,
            alias,
            local,
            foreign,
            into,
        })
    }

    pub(super) fn group_keys(&mut self) -> PResult<Vec<GroupKey>> {
        let mut keys = Vec::new();
        loop {
            let expr = self.expr()?;
            let alias = if self.eat_kw("AS") {
                Some(self.ident()?)
            } else {
                None
            };
            keys.push(GroupKey { expr, alias });
            if !self.eat(&TokenKind::Comma, "','") {
                return Ok(keys);
            }
        }
    }

    fn select(&mut self) -> PResult<Select> {
        if self.eat(&TokenKind::Star, "'*'") {
            return Ok(Select::Star);
        }
        if self.eat_kw("VALUE") {
            return Ok(Select::Value { expr: self.expr()? });
        }
        Ok(Select::Items {
            items: self.projections()?,
        })
    }

    /// `projection {, projection}`.
    pub(super) fn projections(&mut self) -> PResult<Vec<Projection>> {
        let mut items = vec![self.projection()?];
        while self.eat(&TokenKind::Comma, "','") {
            items.push(self.projection()?);
        }
        Ok(items)
    }

    /// `expr [AS ident] | path.* | -path`. A leading `-path` is an exclusion unless the
    /// projection continues as an expression (`-a + 1`, `-a AS x`).
    fn projection(&mut self) -> PResult<Projection> {
        if *self.kind(0) == TokenKind::Minus && self.is_ident_at(1) {
            let save = self.pos;
            self.advance();
            let path = self.path(false)?;
            if !self.continues_expression() {
                return Ok(Projection::Exclude { path });
            }
            self.pos = save;
        }
        let expr = self.expr()?;
        if *self.kind(0) == TokenKind::Dot && *self.kind(1) == TokenKind::Star {
            let Expr::Path { path } = expr else {
                return Err(self.error_at(self.pos, "`.*` applies to a field path only"));
            };
            self.advance();
            self.advance();
            return Ok(Projection::Wildcard { path });
        }
        let alias = if self.eat_kw("AS") {
            Some(self.ident()?)
        } else {
            None
        };
        Ok(Projection::Expr { expr, alias })
    }

    /// `expr [ASC|DESC] {, …}`.
    pub(super) fn order_items(&mut self) -> PResult<Vec<OrderItem>> {
        let mut items = Vec::new();
        loop {
            let expr = self.expr()?;
            let descending = if self.eat_kw("DESC") {
                true
            } else {
                self.eat_kw("ASC");
                false
            };
            items.push(OrderItem { expr, descending });
            if !self.eat(&TokenKind::Comma, "','") {
                return Ok(items);
            }
        }
    }

    /// `[kw (name = expr, …)]` for `OPTIONS` / `WITH`.
    pub(super) fn opt_options(&mut self, kw: &'static str) -> PResult<Vec<OptionItem>> {
        if !self.eat_kw(kw) {
            return Ok(Vec::new());
        }
        self.option_list()
    }

    /// `(name = expr, …)`. An option name may be any word, reserved ones included
    /// (`WITH (include = [...])`, indexing.md): it is always followed by `=`, so it cannot be
    /// confused with a keyword (PD-038).
    pub(super) fn option_list(&mut self) -> PResult<Vec<OptionItem>> {
        self.expect(&TokenKind::LParen, "'('")?;
        let mut items = Vec::new();
        loop {
            let name = self.name()?;
            self.expect(&TokenKind::Eq, "'='")?;
            let value = self.expr()?;
            items.push(OptionItem { name, value });
            if !self.eat(&TokenKind::Comma, "','") {
                break;
            }
        }
        self.expect(&TokenKind::RParen, "')'")?;
        Ok(items)
    }

    /// `path = expr {, …}`.
    pub(super) fn set_items(&mut self) -> PResult<Vec<SetItem>> {
        let mut items = Vec::new();
        loop {
            let path = self.path(false)?;
            self.expect(&TokenKind::Eq, "'='")?;
            let value = self.expr()?;
            items.push(SetItem { path, value });
            if !self.eat(&TokenKind::Comma, "','") {
                return Ok(items);
            }
        }
    }

    /// `name = expr {, …}` (`AGG`, `COMPUTE`).
    fn agg_items(&mut self) -> PResult<Vec<AggItem>> {
        let mut items = Vec::new();
        loop {
            let name = self.ident()?;
            self.expect(&TokenKind::Eq, "'='")?;
            let expr = self.expr()?;
            items.push(AggItem { name, expr });
            if !self.eat(&TokenKind::Comma, "','") {
                return Ok(items);
            }
        }
    }

    fn opt_aggs(&mut self) -> PResult<Vec<AggItem>> {
        if self.eat_kw("AGG") {
            self.agg_items()
        } else {
            Ok(Vec::new())
        }
    }

    /// `GROUP BY keys [AGG items]`.
    pub(super) fn group_spec(&mut self) -> PResult<GroupSpec> {
        self.expect_kws(&["GROUP", "BY"])?;
        let keys = self.group_keys()?;
        let aggs = self.opt_aggs()?;
        Ok(GroupSpec { keys, aggs })
    }

    /// `( stage {|> stage} )`.
    fn sub_pipeline(&mut self) -> PResult<Vec<Stage>> {
        self.nested_by(super::QUERY_NESTING_COST, |p| {
            p.expect(&TokenKind::LParen, "'('")?;
            let mut stages = vec![p.stage()?];
            while p.eat(&TokenKind::Pipe, "'|>'") {
                stages.push(p.stage()?);
            }
            p.expect(&TokenKind::RParen, "')'")?;
            Ok(stages)
        })
    }

    /// A pipeline stage (§7 table).
    fn stage(&mut self) -> PResult<Stage> {
        const STAGES: [&str; 20] = [
            "MATCH", "PROJECT", "SET", "UNSET", "GROUP", "SORT", "LIMIT", "SKIP", "UNWIND",
            "LOOKUP", "COUNT", "FACET", "BUCKET", "SAMPLE", "REPLACE", "GRAPH", "UNION", "WINDOW",
            "OUT", "MERGE",
        ];
        for kw in STAGES {
            self.note(kw);
        }
        let TokenKind::Word(w) = self.kind(0) else {
            return Err(self.unexpected());
        };
        let kw = w.to_ascii_uppercase();
        if kw == "GROUP" {
            return Ok(Stage::Group(self.group_spec()?));
        }
        if kw == "LOOKUP" {
            let lookup = self.lookup_clause()?;
            let pipeline = if self.eat_kw("PIPELINE") {
                Some(self.sub_pipeline()?)
            } else {
                None
            };
            return Ok(Stage::Lookup { lookup, pipeline });
        }
        if !STAGES.contains(&kw.as_str()) {
            return Err(self.unexpected());
        }
        self.advance();
        match kw.as_str() {
            "MATCH" => Ok(Stage::Match {
                predicate: self.expr()?,
            }),
            "PROJECT" => Ok(Stage::Project {
                items: self.projections()?,
            }),
            "SET" => Ok(Stage::Set {
                items: self.set_items()?,
            }),
            "UNSET" => Ok(Stage::Unset {
                paths: self.path_list(false)?,
            }),
            "SORT" if self.check_kw("BY") => {
                self.expect_kws(&["BY", "COUNT"])?;
                Ok(Stage::SortByCount { expr: self.expr()? })
            }
            "SORT" => Ok(Stage::Sort {
                items: self.order_items()?,
            }),
            "LIMIT" => Ok(Stage::Limit {
                count: self.expr()?,
            }),
            "SKIP" => Ok(Stage::Skip {
                count: self.expr()?,
            }),
            "UNWIND" => self.unwind(),
            "COUNT" => {
                self.expect_kw("AS")?;
                Ok(Stage::Count {
                    name: self.ident()?,
                })
            }
            "FACET" => self.facet(),
            "BUCKET" => self.bucket(),
            "SAMPLE" => Ok(Stage::Sample { size: self.expr()? }),
            "REPLACE" => {
                self.expect_kws(&["ROOT", "WITH"])?;
                Ok(Stage::ReplaceRoot { expr: self.expr()? })
            }
            "GRAPH" => self.graph_lookup(),
            "UNION" => {
                self.expect_kw("WITH")?;
                self.expect(&TokenKind::LParen, "'('")?;
                let query = Box::new(self.query()?);
                self.expect(&TokenKind::RParen, "')'")?;
                Ok(Stage::UnionWith { query })
            }
            "WINDOW" => self.window(),
            "OUT" => {
                self.expect_kw("INTO")?;
                Ok(Stage::Out {
                    collection: self.qualified_name()?,
                })
            }
            _ => self.merge(),
        }
    }

    fn unwind(&mut self) -> PResult<Stage> {
        let path = self.path(false)?;
        let alias = if self.eat_kw("AS") {
            Some(self.ident()?)
        } else {
            None
        };
        let index = if self.eat_kw("WITH") {
            self.expect_kw("INDEX")?;
            Some(self.ident()?)
        } else {
            None
        };
        let preserve_empty = self.eat_kw("PRESERVE");
        if preserve_empty {
            self.expect_kw("EMPTY")?;
        }
        Ok(Stage::Unwind {
            path,
            alias,
            index,
            preserve_empty,
        })
    }

    fn facet(&mut self) -> PResult<Stage> {
        let mut facets = Vec::new();
        loop {
            let name = self.ident()?;
            let pipeline = self.sub_pipeline()?;
            facets.push(Facet { name, pipeline });
            if !self.eat(&TokenKind::Comma, "','") {
                return Ok(Stage::Facet { facets });
            }
        }
    }

    fn bucket(&mut self) -> PResult<Stage> {
        if self.eat_kw("AUTO") {
            self.expect_kw("BY")?;
            let by = self.expr()?;
            self.expect_kw("INTO")?;
            let buckets = self.expr()?;
            let aggs = self.opt_aggs()?;
            return Ok(Stage::BucketAuto { by, buckets, aggs });
        }
        self.expect_kw("BY")?;
        let by = self.expr()?;
        self.expect_kw("BOUNDARIES")?;
        let boundaries = self.expr()?;
        let default = if self.eat_kw("DEFAULT") {
            Some(self.expr()?)
        } else {
            None
        };
        let aggs = self.opt_aggs()?;
        Ok(Stage::Bucket {
            by,
            boundaries,
            default,
            aggs,
        })
    }

    fn graph_lookup(&mut self) -> PResult<Stage> {
        self.expect_kw("LOOKUP")?;
        let collection = self.qualified_name()?;
        self.expect_kws(&["START", "WITH"])?;
        let start_with = self.expr()?;
        self.expect_kws(&["CONNECT", "FROM"])?;
        let connect_from = self.path(false)?;
        self.expect_kw("TO")?;
        let connect_to = self.path(false)?;
        let max_depth = if self.check_kw("MAX") {
            self.expect_kws(&["MAX", "DEPTH"])?;
            Some(self.expr()?)
        } else {
            None
        };
        let filter = if self.eat_kw("WHERE") {
            Some(self.expr()?)
        } else {
            None
        };
        self.expect_kw("INTO")?;
        let into = self.ident()?;
        Ok(Stage::GraphLookup {
            collection,
            start_with,
            connect_from,
            connect_to,
            max_depth,
            filter,
            into,
        })
    }

    fn window(&mut self) -> PResult<Stage> {
        let partition_by = if self.check_kw("PARTITION") {
            self.expect_kws(&["PARTITION", "BY"])?;
            self.expr_list()?
        } else {
            Vec::new()
        };
        let order_by = if self.check_kw("ORDER") {
            self.expect_kws(&["ORDER", "BY"])?;
            self.order_items()?
        } else {
            Vec::new()
        };
        self.expect_kw("COMPUTE")?;
        let compute = self.agg_items()?;
        Ok(Stage::Window {
            partition_by,
            order_by,
            compute,
        })
    }

    fn merge(&mut self) -> PResult<Stage> {
        self.expect_kw("INTO")?;
        let collection = self.qualified_name()?;
        self.expect_kw("ON")?;
        let on = self.path_list(false)?;
        let mut when_matched = None;
        let mut when_not_matched = None;
        if self.check_kw("WHEN") && !self.is_kw(1, "NOT") {
            self.expect_kws(&["WHEN", "MATCHED"])?;
            when_matched = Some(self.merge_matched()?);
        }
        if self.check_kw("WHEN") {
            self.expect_kws(&["WHEN", "NOT", "MATCHED"])?;
            when_not_matched = Some(if self.eat_kw("INSERT") {
                MergeNotMatched::Insert
            } else {
                self.expect_kw("DISCARD")?;
                MergeNotMatched::Discard
            });
        }
        Ok(Stage::Merge {
            collection,
            on,
            when_matched,
            when_not_matched,
        })
    }

    fn merge_matched(&mut self) -> PResult<MergeMatched> {
        for (kw, action) in [
            ("REPLACE", MergeMatched::Replace),
            ("UPDATE", MergeMatched::Update),
            ("KEEP", MergeMatched::Keep),
            ("FAIL", MergeMatched::Fail),
        ] {
            if self.eat_kw(kw) {
                return Ok(action);
            }
        }
        Err(self.unexpected())
    }

    /// Paths used by statements (`ON path, …`).
    pub(super) fn opt_on_paths(&mut self) -> PResult<Vec<Path>> {
        if self.eat_kw("ON") {
            self.path_list(false)
        } else {
            Ok(Vec::new())
        }
    }
}
