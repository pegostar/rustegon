// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Canonical printing of statements (writes, DDL, admin, transactions).

use super::Printer;
use crate::ast::{
    AlterCollectionAction, Begin, ColumnDef, CreateIndex, CreateTable, CreateTimeseries, Duration,
    Image, IndexType, Insert, InsertSource, Isolation, KillTarget, OnConflict, PopEnd, Priority,
    Returning, ShowTarget, Statement, UpdateOp,
};

impl Printer {
    pub(super) fn statement(&mut self, s: &Statement) {
        match s {
            Statement::Query(q) => self.query(q),
            Statement::Insert(i) => self.insert(i),
            Statement::Update(u) => {
                self.kw("UPDATE ");
                self.qualified(&u.target);
                if let Some(a) = &u.alias {
                    self.kw(" AS ");
                    self.ident(a);
                }
                self.out.push(' ');
                self.update_ops(&u.ops);
                self.write_tail(u.filter.as_ref(), u.limit.as_ref(), &u.options);
                self.returning(u.returning.as_ref());
            }
            Statement::Upsert(u) => {
                self.kw("UPSERT INTO ");
                self.qualified(&u.target);
                self.kw(" VALUE ");
                self.expr(&u.value);
                if !u.on.is_empty() {
                    self.kw(" ON ");
                    self.paths(&u.on);
                }
                self.returning(u.returning.as_ref());
            }
            Statement::Delete(d) => {
                self.kw("DELETE ");
                if !d.columns.is_empty() {
                    self.paths(&d.columns);
                    self.out.push(' ');
                }
                self.kw("FROM ");
                self.qualified(&d.target);
                self.write_tail(d.filter.as_ref(), d.limit.as_ref(), &d.options);
                self.returning(d.returning.as_ref());
            }
            Statement::Explain { analyze, statement } => {
                self.kw(if *analyze {
                    "EXPLAIN ANALYZE "
                } else {
                    "EXPLAIN "
                });
                self.statement(statement);
            }
            Statement::Begin(b) => self.begin(b),
            Statement::Savepoint { name } => {
                self.kw("SAVEPOINT ");
                self.ident(name);
            }
            Statement::RollbackToSavepoint { name } => {
                self.kw("ROLLBACK TO SAVEPOINT ");
                self.ident(name);
            }
            Statement::ReleaseSavepoint { name } => {
                self.kw("RELEASE SAVEPOINT ");
                self.ident(name);
            }
            Statement::Commit => self.kw("COMMIT"),
            Statement::Rollback => self.kw("ROLLBACK"),
            _ => self.ddl(s),
        }
    }

    fn insert(&mut self, i: &Insert) {
        self.kw("INSERT INTO ");
        self.qualified(&i.target);
        match &i.source {
            InsertSource::Value { expr } => {
                self.kw(" VALUE ");
                self.expr(expr);
            }
            InsertSource::Values { rows } => {
                self.kw(" VALUES ");
                self.list(rows, Self::expr);
            }
            InsertSource::Tuples { columns, rows } => {
                self.kw(" (");
                self.list(columns, |p, c| p.ident(c));
                self.kw(") VALUES ");
                self.list(rows, |p, row| {
                    p.out.push('(');
                    p.list(row, Self::expr);
                    p.out.push(')');
                });
            }
            InsertSource::Query { query } => {
                self.out.push(' ');
                self.query(query);
            }
        }
        match &i.on_conflict {
            Some(OnConflict::DoNothing) => self.kw(" ON CONFLICT DO NOTHING"),
            Some(OnConflict::DoUpdate { ops }) => {
                self.kw(" ON CONFLICT DO UPDATE ");
                self.update_ops(ops);
            }
            None => {}
        }
        if let Some(ttl) = &i.ttl {
            self.kw(" USING TTL ");
            self.expr(ttl);
        }
        self.returning(i.returning.as_ref());
    }

    fn write_tail(
        &mut self,
        filter: Option<&crate::ast::Expr>,
        limit: Option<&crate::ast::Expr>,
        options: &[crate::ast::OptionItem],
    ) {
        if let Some(w) = filter {
            self.kw(" WHERE ");
            self.expr(w);
        }
        if let Some(l) = limit {
            self.kw(" LIMIT ");
            self.expr(l);
        }
        self.options(" OPTIONS ", options);
    }

    fn returning(&mut self, r: Option<&Returning>) {
        let Some(r) = r else { return };
        self.kw(match r.image {
            Image::Old => " RETURNING OLD",
            Image::New => " RETURNING NEW",
        });
        if !r.items.is_empty() {
            self.out.push(' ');
            self.projections(&r.items);
        }
    }

    fn update_ops(&mut self, ops: &[UpdateOp]) {
        for (i, op) in ops.iter().enumerate() {
            if i > 0 {
                self.out.push(' ');
            }
            self.update_op(op);
        }
    }

    fn update_op(&mut self, op: &UpdateOp) {
        match op {
            UpdateOp::Set { items } => {
                self.kw("SET ");
                self.set_items(items);
            }
            UpdateOp::Unset { paths } => {
                self.kw("UNSET ");
                self.paths(paths);
            }
            UpdateOp::Inc { path, by } | UpdateOp::Mul { path, by } => {
                self.kw(if matches!(op, UpdateOp::Inc { .. }) {
                    "INC "
                } else {
                    "MUL "
                });
                self.path(path);
                self.kw(" BY ");
                self.expr(by);
            }
            UpdateOp::Push {
                path,
                value,
                position,
                slice,
                sort,
            } => {
                self.kw("PUSH ");
                self.path(path);
                self.kw(" VALUE ");
                self.expr(value);
                if let Some(p) = position {
                    self.kw(" POSITION ");
                    self.expr(p);
                }
                if let Some(s) = slice {
                    self.kw(" SLICE ");
                    self.expr(s);
                }
                if !sort.is_empty() {
                    self.kw(" SORT ");
                    self.order_items(sort);
                }
            }
            UpdateOp::Pull { path, predicate } => {
                self.kw("PULL ");
                self.path(path);
                self.kw(" WHERE ");
                self.expr(predicate);
            }
            UpdateOp::AddToSet { path, value } => {
                self.kw("ADD TO SET ");
                self.path(path);
                self.kw(" VALUE ");
                self.expr(value);
            }
            UpdateOp::Pop { path, end } => {
                self.kw("POP ");
                self.path(path);
                self.kw(match end {
                    PopEnd::First => " FIRST",
                    PopEnd::Last => " LAST",
                });
            }
            UpdateOp::Rename { from, to } => {
                self.kw("RENAME ");
                self.path(from);
                self.kw(" TO ");
                self.path(to);
            }
            UpdateOp::Min { path, value } | UpdateOp::Max { path, value } => {
                self.kw(if matches!(op, UpdateOp::Min { .. }) {
                    "MIN "
                } else {
                    "MAX "
                });
                self.path(path);
                self.kw(" WITH ");
                self.expr(value);
            }
            UpdateOp::CurrentDate { path } => {
                self.kw("CURRENT DATE ");
                self.path(path);
            }
            UpdateOp::Replace { value } => {
                self.kw("REPLACE WITH ");
                self.expr(value);
            }
        }
    }

    fn begin(&mut self, b: &Begin) {
        self.kw("BEGIN");
        if let Some(i) = b.isolation {
            self.kw(match i {
                Isolation::Serializable => " ISOLATION LEVEL SERIALIZABLE",
                Isolation::Snapshot => " ISOLATION LEVEL SNAPSHOT",
                Isolation::ReadCommitted => " ISOLATION LEVEL READ COMMITTED",
            });
        }
        if b.read_only {
            self.kw(" READ ONLY");
        }
        if let Some(p) = b.priority {
            self.kw(match p {
                Priority::High => " PRIORITY HIGH",
                Priority::Normal => " PRIORITY NORMAL",
                Priority::Low => " PRIORITY LOW",
            });
        }
        if let Some(ts) = &b.as_of {
            self.kw(" AS OF SYSTEM TIME ");
            self.expr(ts);
        }
    }

    fn ddl(&mut self, s: &Statement) {
        match s {
            Statement::CreateDatabase { name, options } => {
                self.kw("CREATE DATABASE ");
                self.ident(name);
                self.options(" WITH ", options);
            }
            Statement::CreateCollection { name, options } => {
                self.kw("CREATE COLLECTION ");
                self.qualified(name);
                self.options(" WITH ", options);
            }
            Statement::CreateTable(t) => self.create_table(t),
            Statement::CreateTimeseries(t) => self.create_timeseries(t),
            Statement::CreateIndex(i) => self.create_index(i),
            Statement::CreateMapreduceIndex {
                name,
                on,
                map,
                reduce,
            } => {
                self.kw("CREATE MAPREDUCE INDEX ");
                self.ident(name);
                self.kw(" ON ");
                self.qualified(on);
                self.kw(" MAP (");
                self.query(map);
                self.kw(") REDUCE (");
                self.group_spec(reduce);
                self.out.push(')');
            }
            Statement::CreateContinuousAggregate { name, on, group } => {
                self.kw("CREATE CONTINUOUS AGGREGATE ");
                self.qualified(name);
                self.kw(" ON ");
                self.qualified(on);
                self.out.push(' ');
                self.group_spec(group);
            }
            Statement::CreateChangeSubscription { name, on, filter } => {
                self.kw("CREATE CHANGE SUBSCRIPTION ");
                self.ident(name);
                self.kw(" ON ");
                self.qualified(on);
                if let Some(f) = filter {
                    self.kw(" WHERE ");
                    self.expr(f);
                }
            }
            _ => self.admin(s),
        }
    }

    fn admin(&mut self, s: &Statement) {
        match s {
            Statement::AlterCollection { name, action } => {
                self.kw("ALTER COLLECTION ");
                self.qualified(name);
                match action {
                    AlterCollectionAction::SetOptions { options } => {
                        self.kw(" SET ");
                        self.option_list(options);
                    }
                    AlterCollectionAction::SplitAt { points } => {
                        self.kw(" SPLIT AT ");
                        self.list(points, |p, point| {
                            p.out.push('(');
                            p.list(point, Self::expr);
                            p.out.push(')');
                        });
                    }
                }
            }
            Statement::AlterIndex { name, hidden } => {
                self.kw("ALTER INDEX ");
                self.index_name(name);
                self.kw(if *hidden {
                    " SET HIDDEN"
                } else {
                    " SET VISIBLE"
                });
            }
            Statement::DropDatabase { name } => {
                self.kw("DROP DATABASE ");
                self.ident(name);
            }
            Statement::DropCollection { name } => {
                self.kw("DROP COLLECTION ");
                self.qualified(name);
            }
            Statement::DropIndex { name } => {
                self.kw("DROP INDEX ");
                self.index_name(name);
            }
            Statement::Show { target } => match target {
                ShowTarget::Collections => self.kw("SHOW COLLECTIONS"),
                ShowTarget::Transactions => self.kw("SHOW TRANSACTIONS"),
                ShowTarget::Indexes { on } => {
                    self.kw("SHOW INDEXES ON ");
                    self.qualified(on);
                }
                ShowTarget::Ranges { collection } => {
                    self.kw("SHOW RANGES FROM COLLECTION ");
                    self.qualified(collection);
                }
            },
            Statement::Kill { target, id } => {
                self.kw(match target {
                    KillTarget::Query => "KILL QUERY ",
                    KillTarget::Transaction => "KILL TRANSACTION ",
                });
                self.expr(id);
            }
            _ => {}
        }
    }

    fn create_index(&mut self, i: &CreateIndex) {
        self.kw(match i.index_type {
            IndexType::Standard => "CREATE INDEX ",
            IndexType::Unique => "CREATE UNIQUE INDEX ",
            IndexType::Ttl => "CREATE TTL INDEX ",
            IndexType::Fulltext => "CREATE FULLTEXT INDEX ",
            IndexType::Vector => "CREATE VECTOR INDEX ",
            IndexType::Geo => "CREATE GEO INDEX ",
            IndexType::Local => "CREATE LOCAL INDEX ",
        });
        self.ident(&i.name);
        self.kw(" ON ");
        self.qualified(&i.on);
        self.kw(" (");
        self.list(&i.keys, |p, k| {
            p.path(&k.path);
            if k.descending {
                p.kw(" DESC");
            }
            if let Some(a) = &k.analyzer {
                p.kw(" ANALYZER ");
                p.expr(a);
            }
            if let Some(b) = &k.boost {
                p.kw(" BOOST ");
                p.expr(b);
            }
        });
        self.out.push(')');
        if let Some(e) = &i.expire_after {
            self.kw(" EXPIRE AFTER ");
            self.expr(e);
        }
        self.options(" WITH ", &i.options);
    }

    fn create_table(&mut self, t: &CreateTable) {
        self.kw("CREATE TABLE ");
        self.qualified(&t.name);
        self.kw(" (");
        let mut first = true;
        let mut sep = |p: &mut Self| {
            if !first {
                p.out.push_str(", ");
            }
            first = false;
        };
        for (label, cols) in [
            ("PARTITION KEY ", &t.partition_key),
            ("CLUSTERING KEY ", &t.clustering_key),
            ("STATIC ", &t.static_columns),
            ("COLUMNS ", &t.columns),
        ] {
            if !cols.is_empty() {
                sep(self);
                self.kw(label);
                self.column_defs(cols);
            }
        }
        if let Some(d) = &t.distribution {
            sep(self);
            self.kw("DISTRIBUTION ");
            self.ident(d);
        }
        if let Some(ttl) = &t.default_ttl {
            sep(self);
            self.kw("DEFAULT TTL ");
            self.expr(ttl);
        }
        self.out.push(')');
    }

    fn column_defs(&mut self, cols: &[ColumnDef]) {
        self.out.push('(');
        self.list(cols, |p, c| {
            p.ident(&c.name);
            p.out.push(' ');
            p.ident(&c.type_name);
            if c.descending {
                p.kw(" DESC");
            }
        });
        self.out.push(')');
    }

    fn create_timeseries(&mut self, t: &CreateTimeseries) {
        self.kw("CREATE TIMESERIES ");
        self.qualified(&t.name);
        self.kw(" (TIME FIELD ");
        self.path(&t.time_field);
        if let Some(m) = &t.meta_field {
            self.kw(", META FIELD ");
            self.path(m);
        }
        if let Some(g) = &t.granularity {
            self.kw(", GRANULARITY ");
            self.ident(g);
        }
        if let Some(n) = &t.bucket_max_points {
            self.kw(", BUCKET MAX POINTS ");
            self.expr(n);
        }
        if let Some(d) = &t.bucket_span {
            self.kw(", BUCKET SPAN ");
            self.duration(d);
        }
        if let Some(d) = &t.retention {
            self.kw(", RETENTION ");
            self.duration(d);
        }
        self.out.push(')');
    }

    fn duration(&mut self, d: &Duration) {
        self.expr(&d.amount);
        self.out.push(' ');
        if d.unit.eq_ignore_ascii_case("match") {
            // After an amount ending in the path `elem`, a bare `match` would read as the
            // contextual keywords `ELEM MATCH` (TC-QL-003 regression); quoting keeps the name.
            self.quoted(&d.unit);
        } else {
            self.ident(&d.unit);
        }
    }
}
