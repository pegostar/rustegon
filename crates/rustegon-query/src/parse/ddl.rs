// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! DDL, administrative and transaction statements (query-language.md §11, §12; data-model §6,
//! §7).

use super::{PResult, Parser, lexer::TokenKind};
use crate::ast::{
    AlterCollectionAction, Begin, ColumnDef, CreateIndex, CreateTable, CreateTimeseries, Duration,
    IndexKey, IndexType, Isolation, KillTarget, Priority, ShowTarget, Statement,
};

impl Parser<'_> {
    pub(super) fn create(&mut self) -> PResult<Statement> {
        self.expect_kw("CREATE")?;
        let index_type = [
            ("UNIQUE", IndexType::Unique),
            ("TTL", IndexType::Ttl),
            ("FULLTEXT", IndexType::Fulltext),
            ("VECTOR", IndexType::Vector),
            ("GEO", IndexType::Geo),
            ("LOCAL", IndexType::Local),
        ]
        .into_iter()
        .find_map(|(kw, t)| self.eat_kw(kw).then_some(t));
        if let Some(t) = index_type {
            return self.create_index(t);
        }
        if self.check_kw("INDEX") {
            return self.create_index(IndexType::Standard);
        }
        if self.eat_kw("DATABASE") {
            let name = self.ident()?;
            let options = self.opt_options("WITH")?;
            return Ok(Statement::CreateDatabase { name, options });
        }
        if self.eat_kw("COLLECTION") {
            let name = self.qualified_name()?;
            let options = self.opt_options("WITH")?;
            return Ok(Statement::CreateCollection { name, options });
        }
        if self.eat_kw("TABLE") {
            return self.create_table();
        }
        if self.eat_kw("TIMESERIES") {
            return self.create_timeseries();
        }
        if self.eat_kw("MAPREDUCE") {
            return self.create_mapreduce();
        }
        if self.eat_kw("CONTINUOUS") {
            self.expect_kw("AGGREGATE")?;
            let name = self.qualified_name()?;
            self.expect_kw("ON")?;
            let on = self.qualified_name()?;
            let group = self.group_spec()?;
            return Ok(Statement::CreateContinuousAggregate { name, on, group });
        }
        if self.eat_kw("CHANGE") {
            self.expect_kw("SUBSCRIPTION")?;
            let name = self.ident()?;
            self.expect_kw("ON")?;
            let on = self.qualified_name()?;
            let filter = if self.eat_kw("WHERE") {
                Some(self.expr()?)
            } else {
                None
            };
            return Ok(Statement::CreateChangeSubscription { name, on, filter });
        }
        Err(self.unexpected())
    }

    fn create_index(&mut self, index_type: IndexType) -> PResult<Statement> {
        self.expect_kw("INDEX")?;
        let name = self.ident()?;
        self.expect_kw("ON")?;
        let on = self.qualified_name()?;
        self.expect(&TokenKind::LParen, "'('")?;
        let mut keys = Vec::new();
        loop {
            keys.push(self.index_key()?);
            if !self.eat(&TokenKind::Comma, "','") {
                break;
            }
        }
        self.expect(&TokenKind::RParen, "')'")?;
        let expire_after = if self.eat_kw("EXPIRE") {
            self.expect_kw("AFTER")?;
            Some(self.expr()?)
        } else {
            None
        };
        let options = self.opt_options("WITH")?;
        Ok(Statement::CreateIndex(CreateIndex {
            index_type,
            name,
            on,
            keys,
            expire_after,
            options,
        }))
    }

    fn index_key(&mut self) -> PResult<IndexKey> {
        let path = self.path(false)?;
        let descending = if self.eat_kw("DESC") {
            true
        } else {
            self.eat_kw("ASC");
            false
        };
        let analyzer = if self.eat_kw("ANALYZER") {
            Some(self.expr()?)
        } else {
            None
        };
        let boost = if self.eat_kw("BOOST") {
            Some(self.expr()?)
        } else {
            None
        };
        Ok(IndexKey {
            path,
            descending,
            analyzer,
            boost,
        })
    }

    fn create_mapreduce(&mut self) -> PResult<Statement> {
        self.expect_kw("INDEX")?;
        let name = self.ident()?;
        self.expect_kw("ON")?;
        let on = self.qualified_name()?;
        self.expect_kw("MAP")?;
        self.expect(&TokenKind::LParen, "'('")?;
        let map = Box::new(self.query()?);
        self.expect(&TokenKind::RParen, "')'")?;
        self.expect_kw("REDUCE")?;
        self.expect(&TokenKind::LParen, "'('")?;
        let reduce = self.group_spec()?;
        self.expect(&TokenKind::RParen, "')'")?;
        Ok(Statement::CreateMapreduceIndex {
            name,
            on,
            map,
            reduce,
        })
    }

    /// Items in any order, each at most once; `PARTITION KEY` is required.
    fn create_table(&mut self) -> PResult<Statement> {
        let name = self.qualified_name()?;
        let mut t = CreateTable {
            name,
            partition_key: Vec::new(),
            clustering_key: Vec::new(),
            static_columns: Vec::new(),
            columns: Vec::new(),
            distribution: None,
            default_ttl: None,
        };
        self.expect(&TokenKind::LParen, "'('")?;
        loop {
            let at = self.pos;
            let dup = if self.eat_kw("PARTITION") {
                self.expect_kw("KEY")?;
                set_once(&mut t.partition_key, self.column_defs(false)?)
            } else if self.eat_kw("CLUSTERING") {
                self.expect_kw("KEY")?;
                set_once(&mut t.clustering_key, self.column_defs(true)?)
            } else if self.eat_kw("STATIC") {
                set_once(&mut t.static_columns, self.column_defs(false)?)
            } else if self.eat_kw("COLUMNS") {
                set_once(&mut t.columns, self.column_defs(false)?)
            } else if self.eat_kw("DISTRIBUTION") {
                t.distribution.replace(self.ident()?).is_some()
            } else if self.eat_kw("DEFAULT") {
                self.expect_kw("TTL")?;
                t.default_ttl.replace(self.expr()?).is_some()
            } else {
                return Err(self.unexpected());
            };
            if dup {
                return Err(self.error_at(at, "table item given twice"));
            }
            if !self.eat(&TokenKind::Comma, "','") {
                break;
            }
        }
        self.expect(&TokenKind::RParen, "')'")?;
        if t.partition_key.is_empty() {
            return Err(self.error_at(self.pos - 1, "CREATE TABLE requires PARTITION KEY (…)"));
        }
        Ok(Statement::CreateTable(t))
    }

    /// `( name type [ASC|DESC], … )`; the direction only for clustering columns.
    fn column_defs(&mut self, clustering: bool) -> PResult<Vec<ColumnDef>> {
        self.expect(&TokenKind::LParen, "'('")?;
        let mut cols = Vec::new();
        loop {
            let name = self.ident()?;
            let type_name = self.ident()?;
            let descending = clustering && self.eat_kw("DESC");
            if clustering && !descending {
                self.eat_kw("ASC");
            }
            cols.push(ColumnDef {
                name,
                type_name,
                descending,
            });
            if !self.eat(&TokenKind::Comma, "','") {
                break;
            }
        }
        self.expect(&TokenKind::RParen, "')'")?;
        Ok(cols)
    }

    /// Items in any order, each at most once; `TIME FIELD` is required.
    fn create_timeseries(&mut self) -> PResult<Statement> {
        let name = self.qualified_name()?;
        let mut time_field = None;
        let mut t = CreateTimeseries {
            name,
            time_field: crate::ast::Path::default(),
            meta_field: None,
            granularity: None,
            bucket_max_points: None,
            bucket_span: None,
            retention: None,
        };
        self.expect(&TokenKind::LParen, "'('")?;
        loop {
            let at = self.pos;
            let dup = if self.eat_kw("TIME") {
                self.expect_kw("FIELD")?;
                time_field.replace(self.path(false)?).is_some()
            } else if self.eat_kw("META") {
                self.expect_kw("FIELD")?;
                t.meta_field.replace(self.path(false)?).is_some()
            } else if self.eat_kw("GRANULARITY") {
                t.granularity.replace(self.ident()?).is_some()
            } else if self.eat_kw("BUCKET") {
                if self.eat_kw("SPAN") {
                    t.bucket_span.replace(self.duration()?).is_some()
                } else {
                    self.expect_kws(&["MAX", "POINTS"])?;
                    t.bucket_max_points.replace(self.expr()?).is_some()
                }
            } else if self.eat_kw("RETENTION") {
                t.retention.replace(self.duration()?).is_some()
            } else {
                return Err(self.unexpected());
            };
            if dup {
                return Err(self.error_at(at, "time-series item given twice"));
            }
            if !self.eat(&TokenKind::Comma, "','") {
                break;
            }
        }
        self.expect(&TokenKind::RParen, "')'")?;
        t.time_field = time_field
            .ok_or_else(|| self.error_at(self.pos - 1, "CREATE TIMESERIES requires TIME FIELD"))?;
        Ok(Statement::CreateTimeseries(t))
    }

    fn duration(&mut self) -> PResult<Duration> {
        let amount = self.expr()?;
        let unit = self.ident()?;
        Ok(Duration { amount, unit })
    }

    pub(super) fn alter(&mut self) -> PResult<Statement> {
        self.expect_kw("ALTER")?;
        if self.eat_kw("INDEX") {
            let name = self.index_name()?;
            self.expect_kw("SET")?;
            let hidden = if self.eat_kw("HIDDEN") {
                true
            } else {
                self.expect_kw("VISIBLE")?;
                false
            };
            return Ok(Statement::AlterIndex { name, hidden });
        }
        self.expect_kw("COLLECTION")?;
        let name = self.qualified_name()?;
        let action = if self.eat_kw("SET") {
            AlterCollectionAction::SetOptions {
                options: self.option_list()?,
            }
        } else {
            self.expect_kws(&["SPLIT", "AT"])?;
            let mut points = Vec::new();
            loop {
                self.expect(&TokenKind::LParen, "'('")?;
                points.push(self.expr_list()?);
                self.expect(&TokenKind::RParen, "')'")?;
                if !self.eat(&TokenKind::Comma, "','") {
                    break;
                }
            }
            AlterCollectionAction::SplitAt { points }
        };
        Ok(Statement::AlterCollection { name, action })
    }

    pub(super) fn drop_stmt(&mut self) -> PResult<Statement> {
        self.expect_kw("DROP")?;
        if self.eat_kw("DATABASE") {
            return Ok(Statement::DropDatabase {
                name: self.ident()?,
            });
        }
        if self.eat_kw("COLLECTION") {
            return Ok(Statement::DropCollection {
                name: self.qualified_name()?,
            });
        }
        self.expect_kw("INDEX")?;
        Ok(Statement::DropIndex {
            name: self.index_name()?,
        })
    }

    pub(super) fn show(&mut self) -> PResult<Statement> {
        self.expect_kw("SHOW")?;
        let target = if self.eat_kw("COLLECTIONS") {
            ShowTarget::Collections
        } else if self.eat_kw("TRANSACTIONS") {
            ShowTarget::Transactions
        } else if self.eat_kw("INDEXES") {
            self.expect_kw("ON")?;
            ShowTarget::Indexes {
                on: self.qualified_name()?,
            }
        } else {
            self.expect_kws(&["RANGES", "FROM", "COLLECTION"])?;
            ShowTarget::Ranges {
                collection: self.qualified_name()?,
            }
        };
        Ok(Statement::Show { target })
    }

    pub(super) fn kill(&mut self) -> PResult<Statement> {
        self.expect_kw("KILL")?;
        let target = if self.eat_kw("QUERY") {
            KillTarget::Query
        } else {
            self.expect_kw("TRANSACTION")?;
            KillTarget::Transaction
        };
        Ok(Statement::Kill {
            target,
            id: self.expr()?,
        })
    }

    /// `BEGIN … | SAVEPOINT s | ROLLBACK [TO SAVEPOINT s] | RELEASE SAVEPOINT s | COMMIT`.
    pub(super) fn txn(&mut self) -> PResult<Statement> {
        if self.eat_kw("BEGIN") {
            return self.begin();
        }
        if self.eat_kw("SAVEPOINT") {
            return Ok(Statement::Savepoint {
                name: self.ident()?,
            });
        }
        if self.eat_kw("RELEASE") {
            self.expect_kw("SAVEPOINT")?;
            return Ok(Statement::ReleaseSavepoint {
                name: self.ident()?,
            });
        }
        if self.eat_kw("COMMIT") {
            return Ok(Statement::Commit);
        }
        self.expect_kw("ROLLBACK")?;
        if self.eat_kw("TO") {
            self.expect_kw("SAVEPOINT")?;
            return Ok(Statement::RollbackToSavepoint {
                name: self.ident()?,
            });
        }
        Ok(Statement::Rollback)
    }

    fn begin(&mut self) -> PResult<Statement> {
        let mut b = Begin::default();
        if self.eat_kw("ISOLATION") {
            self.expect_kw("LEVEL")?;
            b.isolation = Some(if self.eat_kw("SERIALIZABLE") {
                Isolation::Serializable
            } else if self.eat_kw("SNAPSHOT") {
                Isolation::Snapshot
            } else {
                self.expect_kws(&["READ", "COMMITTED"])?;
                Isolation::ReadCommitted
            });
        }
        if self.check_kw("READ") {
            self.expect_kws(&["READ", "ONLY"])?;
            b.read_only = true;
        }
        if self.eat_kw("PRIORITY") {
            b.priority = Some(if self.eat_kw("HIGH") {
                Priority::High
            } else if self.eat_kw("NORMAL") {
                Priority::Normal
            } else {
                self.expect_kw("LOW")?;
                Priority::Low
            });
        }
        if self.check_kw("AS") {
            self.expect_kws(&["AS", "OF", "SYSTEM", "TIME"])?;
            b.as_of = Some(self.expr()?);
        }
        Ok(Statement::Begin(b))
    }
}

/// Stores a column list, reporting whether one was already present.
fn set_once<T>(slot: &mut Vec<T>, value: Vec<T>) -> bool {
    let dup = !slot.is_empty();
    *slot = value;
    dup
}
