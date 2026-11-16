// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The privileges an RGQL statement needs (security.md §3.3; PD-051 `Access::Statement`,
//! PD-053, PD-056).
//!
//! The rule of every RPC is declared once in [`crate::security::RPC_ACCESS`]; for
//! `QueryService.Execute`/`Explain` that rule is "checked per statement", because one RPC runs
//! arbitrary RGQL. [`statement_privileges`] derives the checks from the statement's AST and the
//! query service requires each of them (`Security::require`, audited) before binding, so an
//! unauthorized caller learns nothing from bind errors (e.g. `RGN-1030` for a collection that
//! does not exist).
//!
//! **Every collection reference is walked (PD-056).** The walk visits the whole AST — every
//! clause, pipeline stage, sub-pipeline, sub-query and expression — and maps each reference to
//! an action:
//! - reads → `find`: the `FROM` source (collection, `INDEX` source, `FROM ( query )`), every
//!   `LOOKUP` (clause or stage, with its `PIPELINE`), `GRAPH LOOKUP`, `UNION WITH`, `FACET`
//!   sub-pipelines, the source of `INSERT … FROM query`, the `MAP` query of a map-reduce index,
//!   the source of a continuous aggregate, `load(id, 'db.coll')`;
//! - reads whose collection is not named statically (`INCLUDE`, `load` without a literal
//!   collection) → `find` on `cluster`: the walk fails closed until those targets are specified;
//! - writes: `insert` / `update` / `delete` on the target (`UPSERT` and
//!   `INSERT … ON CONFLICT DO UPDATE` need both `insert` and `update`); `OUT INTO` /
//!   `MERGE INTO` stages need `aggregate_write` on their target;
//! - DDL: the matching schema action on the named database or collection (never the session
//!   database when the statement names another); change subscriptions need
//!   `subscription_manage` and `change_stream` on the watched collection;
//! - `SHOW INDEXES|RANGES`: `find` on the named collection; `SHOW COLLECTIONS|TRANSACTIONS`:
//!   `find` on the session database; `KILL QUERY|TRANSACTION`: `query_kill` / `txn_kill` on it;
//! - transaction-control statements: nothing (beyond what their expressions reference).
//!
//! Every `match` on an AST enum is exhaustive (no `_` arm) and every AST struct is destructured
//! without `..`, so a new statement, stage, expression or field does not compile until the walk
//! handles it.

mod read;

use rustegon_query::{
    Statement,
    ast::{
        AlterCollectionAction, Begin, CreateIndex, CreateTable, CreateTimeseries, Delete, Duration,
        IndexKey, IndexName, Insert, InsertSource, KillTarget, OnConflict, QualifiedName,
        Returning, ShowTarget, Update, UpdateOp, Upsert,
    },
};
use rustegon_security::rbac::{Action, Resource};

/// The privileges an RGQL statement needs on session database `session` (module docs), in
/// the order the statement references them, without duplicates.
#[must_use]
pub fn statement_privileges(stmt: &Statement, session: &str) -> Vec<(Resource, Action)> {
    let mut walk = Walk {
        session,
        out: Vec::new(),
    };
    walk.statement(stmt);
    walk.out
}

/// Accumulates the privileges of one statement.
struct Walk<'a> {
    session: &'a str,
    out: Vec<(Resource, Action)>,
}

impl Walk<'_> {
    fn need(&mut self, resource: Resource, action: Action) {
        // Statements are small; a linear check keeps the output ordered for the audit trail.
        if !self.out.iter().any(|(r, a)| *r == resource && *a == action) {
            self.out.push((resource, action));
        }
    }

    fn coll(&self, name: &QualifiedName) -> Resource {
        let QualifiedName { database, name } = name;
        Resource::collection(database.as_deref().unwrap_or(self.session), name.clone())
    }

    fn on_coll(&mut self, name: &QualifiedName, action: Action) {
        let resource = self.coll(name);
        self.need(resource, action);
    }

    fn on_session_db(&mut self, action: Action) {
        self.need(Resource::database(self.session), action);
    }

    /// A read whose collection is not known before execution: only a cluster-wide `find`
    /// covers every collection it might read (fail closed, PD-056).
    fn read_any(&mut self) {
        self.need(Resource::Cluster, Action::Find);
    }

    // The arms mirror the statement kinds one to one; splitting the match would need a
    // catch-all arm, which is exactly what the walk must not have (module docs).
    #[allow(clippy::too_many_lines)]
    fn statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Query(q) => self.query(q),
            Statement::Insert(i) => self.insert(i),
            Statement::Update(u) => self.update(u),
            Statement::Upsert(u) => self.upsert(u),
            Statement::Delete(d) => self.delete(d),
            Statement::Explain {
                analyze: _,
                statement,
            } => self.statement(statement),
            Statement::CreateDatabase { name, options } => {
                self.need(Resource::database(name.clone()), Action::CreateDatabase);
                self.options(options);
            }
            Statement::CreateCollection { name, options } => {
                self.on_coll(name, Action::CreateCollection);
                self.options(options);
            }
            Statement::CreateTable(t) => self.create_table(t),
            Statement::CreateTimeseries(t) => self.create_timeseries(t),
            Statement::CreateIndex(ci) => self.create_index(ci),
            Statement::CreateMapreduceIndex {
                name: _,
                on,
                map,
                reduce,
            } => {
                self.on_coll(on, Action::CreateIndex);
                self.query(map);
                self.group_spec(reduce);
            }
            Statement::CreateContinuousAggregate { name, on, group } => {
                self.on_coll(name, Action::CreateCollection);
                self.on_coll(on, Action::Find);
                self.group_spec(group);
            }
            Statement::CreateChangeSubscription {
                name: _,
                on,
                filter,
            } => {
                self.on_coll(on, Action::SubscriptionManage);
                self.on_coll(on, Action::ChangeStream);
                self.opt_expr(filter.as_ref());
            }
            Statement::AlterCollection { name, action } => {
                self.on_coll(name, Action::AlterCollection);
                self.alter_collection(action);
            }
            Statement::AlterIndex { name, hidden: _ } => {
                self.index_name(name, Action::CreateIndex);
            }
            Statement::DropDatabase { name } => {
                self.need(Resource::database(name.clone()), Action::DropDatabase);
            }
            Statement::DropCollection { name } => self.on_coll(name, Action::DropCollection),
            Statement::DropIndex { name } => self.index_name(name, Action::DropIndex),
            Statement::Show { target } => self.show(target),
            Statement::Kill { target, id } => {
                self.on_session_db(match target {
                    KillTarget::Query => Action::QueryKill,
                    KillTarget::Transaction => Action::TxnKill,
                });
                self.expr(id);
            }
            Statement::Begin(b) => self.begin(b),
            Statement::Savepoint { name: _ }
            | Statement::RollbackToSavepoint { name: _ }
            | Statement::ReleaseSavepoint { name: _ }
            | Statement::Commit
            | Statement::Rollback => {}
        }
    }

    fn insert(&mut self, i: &Insert) {
        let Insert {
            target,
            source,
            on_conflict,
            ttl,
            returning,
        } = i;
        self.on_coll(target, Action::Insert);
        match on_conflict {
            None | Some(OnConflict::DoNothing) => {}
            Some(OnConflict::DoUpdate { ops }) => {
                self.on_coll(target, Action::Update);
                self.update_ops(ops);
            }
        }
        match source {
            InsertSource::Value { expr } => self.expr(expr),
            InsertSource::Values { rows } => self.exprs(rows),
            InsertSource::Tuples { columns: _, rows } => {
                for row in rows {
                    self.exprs(row);
                }
            }
            InsertSource::Query { query } => self.query(query),
        }
        self.opt_expr(ttl.as_ref());
        self.returning(returning.as_ref());
    }

    fn update(&mut self, u: &Update) {
        let Update {
            target,
            alias: _,
            ops,
            filter,
            limit,
            options,
            returning,
        } = u;
        self.on_coll(target, Action::Update);
        self.update_ops(ops);
        self.opt_expr(filter.as_ref());
        self.opt_expr(limit.as_ref());
        self.options(options);
        self.returning(returning.as_ref());
    }

    fn upsert(&mut self, u: &Upsert) {
        let Upsert {
            target,
            value,
            on,
            returning,
        } = u;
        self.on_coll(target, Action::Insert);
        self.on_coll(target, Action::Update);
        self.expr(value);
        self.paths(on);
        self.returning(returning.as_ref());
    }

    fn delete(&mut self, d: &Delete) {
        let Delete {
            columns,
            target,
            filter,
            limit,
            options,
            returning,
        } = d;
        self.on_coll(target, Action::Delete);
        self.paths(columns);
        self.opt_expr(filter.as_ref());
        self.opt_expr(limit.as_ref());
        self.options(options);
        self.returning(returning.as_ref());
    }

    fn returning(&mut self, r: Option<&Returning>) {
        if let Some(Returning { image: _, items }) = r {
            self.projections(items);
        }
    }

    fn update_ops(&mut self, ops: &[UpdateOp]) {
        for op in ops {
            match op {
                UpdateOp::Set { items } => self.set_items(items),
                UpdateOp::Unset { paths } => self.paths(paths),
                UpdateOp::Inc { path, by } | UpdateOp::Mul { path, by } => {
                    self.path(path);
                    self.expr(by);
                }
                UpdateOp::Push {
                    path,
                    value,
                    position,
                    slice,
                    sort,
                } => {
                    self.path(path);
                    self.expr(value);
                    self.opt_expr(position.as_ref());
                    self.opt_expr(slice.as_ref());
                    self.order_items(sort);
                }
                UpdateOp::Pull { path, predicate } => {
                    self.path(path);
                    self.expr(predicate);
                }
                UpdateOp::AddToSet { path, value }
                | UpdateOp::Min { path, value }
                | UpdateOp::Max { path, value } => {
                    self.path(path);
                    self.expr(value);
                }
                UpdateOp::Pop { path, end: _ } | UpdateOp::CurrentDate { path } => self.path(path),
                UpdateOp::Rename { from, to } => {
                    self.path(from);
                    self.path(to);
                }
                UpdateOp::Replace { value } => self.expr(value),
            }
        }
    }

    fn create_table(&mut self, t: &CreateTable) {
        let CreateTable {
            name,
            partition_key: _,
            clustering_key: _,
            static_columns: _,
            columns: _,
            distribution: _,
            default_ttl,
        } = t;
        self.on_coll(name, Action::CreateCollection);
        self.opt_expr(default_ttl.as_ref());
    }

    fn create_timeseries(&mut self, t: &CreateTimeseries) {
        let CreateTimeseries {
            name,
            time_field,
            meta_field,
            granularity: _,
            bucket_max_points,
            bucket_span,
            retention,
        } = t;
        self.on_coll(name, Action::CreateCollection);
        self.path(time_field);
        if let Some(p) = meta_field {
            self.path(p);
        }
        self.opt_expr(bucket_max_points.as_ref());
        for Duration { amount, unit: _ } in [bucket_span, retention].into_iter().flatten() {
            self.expr(amount);
        }
    }

    fn create_index(&mut self, ci: &CreateIndex) {
        let CreateIndex {
            index_type: _,
            name: _,
            on,
            keys,
            expire_after,
            options,
        } = ci;
        self.on_coll(on, Action::CreateIndex);
        for IndexKey {
            path,
            descending: _,
            analyzer,
            boost,
        } in keys
        {
            self.path(path);
            self.opt_expr(analyzer.as_ref());
            self.opt_expr(boost.as_ref());
        }
        self.opt_expr(expire_after.as_ref());
        self.options(options);
    }

    fn alter_collection(&mut self, action: &AlterCollectionAction) {
        match action {
            AlterCollectionAction::SetOptions { options } => self.options(options),
            AlterCollectionAction::SplitAt { points } => {
                for point in points {
                    self.exprs(point);
                }
            }
        }
    }

    fn index_name(&mut self, name: &IndexName, action: Action) {
        let IndexName {
            collection,
            index: _,
        } = name;
        self.on_coll(collection, action);
    }

    fn show(&mut self, target: &ShowTarget) {
        match target {
            ShowTarget::Collections | ShowTarget::Transactions => {
                self.on_session_db(Action::Find);
            }
            ShowTarget::Indexes { on: name } | ShowTarget::Ranges { collection: name } => {
                self.on_coll(name, Action::Find);
            }
        }
    }

    fn begin(&mut self, b: &Begin) {
        let Begin {
            isolation: _,
            read_only: _,
            priority: _,
            as_of,
        } = b;
        self.opt_expr(as_of.as_ref());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rustegon_query::parse_statement;

    use super::*;

    fn of(text: &str) -> Vec<(Resource, Action)> {
        statement_privileges(&parse_statement(text).unwrap(), "shop")
    }

    fn find(db: &str, coll: &str) -> (Resource, Action) {
        (Resource::collection(db, coll), Action::Find)
    }

    #[test]
    fn tc_sec_001_statement_privileges_follow_the_statement_kind() {
        assert_eq!(of("FROM orders WHERE a = 1"), vec![find("shop", "orders")]);
        assert_eq!(
            of("UPDATE other.c SET a = 1 WHERE _id = 1"),
            vec![(Resource::collection("other", "c"), Action::Update)]
        );
        assert_eq!(
            of("CREATE INDEX i ON c (a)"),
            vec![(Resource::collection("shop", "c"), Action::CreateIndex)]
        );
        assert_eq!(of("SAVEPOINT s"), Vec::new());
    }

    /// TC-SEC-001 / PD-056: every form that reads another collection needs `find` on it.
    #[test]
    fn tc_sec_001_every_collection_read_needs_find() {
        let cases: &[(&str, &[(&str, &str)])] = &[
            ("FROM (FROM b WHERE x = 1) AS s", &[("shop", "b")]),
            (
                "FROM a LOOKUP b ON k = _id INTO j",
                &[("shop", "a"), ("shop", "b")],
            ),
            (
                "FROM a LOOKUP o.b ON k = _id INTO j",
                &[("shop", "a"), ("o", "b")],
            ),
            (
                "FROM a |> LOOKUP b ON k = _id INTO j PIPELINE (LOOKUP c ON k = _id INTO m)",
                &[("shop", "a"), ("shop", "b"), ("shop", "c")],
            ),
            (
                "FROM a |> UNION WITH (FROM b)",
                &[("shop", "a"), ("shop", "b")],
            ),
            (
                "FROM a |> UNION WITH (FROM b |> UNION WITH (FROM o.c))",
                &[("shop", "a"), ("shop", "b"), ("o", "c")],
            ),
            (
                "FROM a |> FACET x (LOOKUP b ON k = _id INTO j), y (UNION WITH (FROM c))",
                &[("shop", "a"), ("shop", "b"), ("shop", "c")],
            ),
            (
                "FROM a |> GRAPH LOOKUP b START WITH k CONNECT FROM k TO _id INTO j",
                &[("shop", "a"), ("shop", "b")],
            ),
            ("FROM INDEX o.b.idx", &[("o", "b")]),
            (
                "FROM a SELECT load(k, 'o.b').name AS n",
                &[("shop", "a"), ("o", "b")],
            ),
            (
                "FROM a WHERE LOAD(k, 'b') IS NOT NULL",
                &[("shop", "a"), ("shop", "b")],
            ),
            (
                "FROM a WHERE ANY x IN arr SATISFIES load(x, 'b').ok = true",
                &[("shop", "a"), ("shop", "b")],
            ),
            (
                "FROM a SELECT VALUE map(arr, x -> load(x, 'b'))",
                &[("shop", "a"), ("shop", "b")],
            ),
            (
                "FROM a ORDER BY arr[load(k, 'b').i]",
                &[("shop", "a"), ("shop", "b")],
            ),
            (
                "EXPLAIN FROM a |> UNION WITH (FROM b)",
                &[("shop", "a"), ("shop", "b")],
            ),
        ];
        for (text, reads) in cases {
            let expected: Vec<_> = reads.iter().map(|(d, c)| find(d, c)).collect();
            assert_eq!(of(text), expected, "{text}");
        }
    }

    #[test]
    fn tc_sec_001_writes_with_reads_need_both() {
        assert_eq!(
            of("INSERT INTO a FROM b WHERE y < 2020"),
            vec![
                (Resource::collection("shop", "a"), Action::Insert),
                find("shop", "b")
            ]
        );
        assert_eq!(
            of("UPDATE a SET n = load(k, 'b').n WHERE _id = 1"),
            vec![
                (Resource::collection("shop", "a"), Action::Update),
                find("shop", "b")
            ]
        );
        assert_eq!(
            of("DELETE FROM a WHERE load(k, 'o.b') IS NULL"),
            vec![
                (Resource::collection("shop", "a"), Action::Delete),
                find("o", "b")
            ]
        );
        assert_eq!(
            of("UPSERT INTO a VALUE {_id: 1, v: load(1, 'b')}"),
            vec![
                (Resource::collection("shop", "a"), Action::Insert),
                (Resource::collection("shop", "a"), Action::Update),
                find("shop", "b")
            ]
        );
        assert_eq!(
            of("FROM a |> OUT INTO b"),
            vec![
                find("shop", "a"),
                (Resource::collection("shop", "b"), Action::AggregateWrite)
            ]
        );
        assert_eq!(
            of("FROM a |> MERGE INTO o.b ON _id WHEN NOT MATCHED INSERT"),
            vec![
                find("shop", "a"),
                (Resource::collection("o", "b"), Action::AggregateWrite)
            ]
        );
    }

    /// References whose collection is unknown before execution fail closed (PD-056).
    #[test]
    fn tc_sec_001_unresolved_reads_need_cluster_find() {
        let any = (Resource::Cluster, Action::Find);
        for text in [
            "FROM a INCLUDE customerId",
            "FROM a SELECT load(k).n AS n",
            "FROM a SELECT load(k, $coll).n AS n",
            "FROM a SELECT load(k, 'b' || 'c').n AS n",
        ] {
            assert_eq!(of(text), vec![find("shop", "a"), any.clone()], "{text}");
        }
    }

    /// DDL names its own database, never the session's (PD-056).
    #[test]
    fn tc_sec_001_ddl_checks_the_named_collection() {
        let on = |db: &str, c: &str, a: Action| (Resource::collection(db, c), a);
        assert_eq!(
            of("CREATE TABLE o.t (PARTITION KEY (k string))"),
            vec![on("o", "t", Action::CreateCollection)]
        );
        assert_eq!(
            of("CREATE TIMESERIES o.t (TIME FIELD ts)"),
            vec![on("o", "t", Action::CreateCollection)]
        );
        assert_eq!(
            of(
                "CREATE MAPREDUCE INDEX m ON a MAP (FROM a LOOKUP o.b ON k = _id INTO j) \
                REDUCE (GROUP BY k AGG n = count(*))"
            ),
            vec![
                on("shop", "a", Action::CreateIndex),
                find("shop", "a"),
                find("o", "b")
            ]
        );
        assert_eq!(
            of("CREATE CONTINUOUS AGGREGATE agg ON o.ts GROUP BY k AGG n = count(*)"),
            vec![on("shop", "agg", Action::CreateCollection), find("o", "ts")]
        );
        assert_eq!(
            of("CREATE CHANGE SUBSCRIPTION s ON o.b WHERE op = 'update'"),
            vec![
                on("o", "b", Action::SubscriptionManage),
                on("o", "b", Action::ChangeStream)
            ]
        );
        assert_eq!(of("SHOW INDEXES ON o.b"), vec![find("o", "b")]);
        assert_eq!(
            of("SHOW COLLECTIONS"),
            vec![(Resource::database("shop"), Action::Find)]
        );
    }
}
