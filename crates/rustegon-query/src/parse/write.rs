// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Write statements (query-language.md §3 `insert`/`update`/`upsert`/`delete`, §6, §10).

use super::{PResult, Parser, lexer::TokenKind};
use crate::ast::{
    Delete, Image, Insert, InsertSource, OnConflict, PopEnd, Returning, Statement, Update,
    UpdateOp, Upsert,
};

impl Parser<'_> {
    /// `INSERT INTO coll ( VALUE e | VALUES e, … | (cols) VALUES (…), … | query )
    /// [ON CONFLICT …] [USING TTL e] [RETURNING …]`.
    pub(super) fn insert(&mut self) -> PResult<Statement> {
        self.expect_kws(&["INSERT", "INTO"])?;
        let target = self.qualified_name()?;
        let source = if self.eat(&TokenKind::LParen, "'('") {
            let columns = self.ident_list()?;
            self.expect(&TokenKind::RParen, "')'")?;
            self.expect_kw("VALUES")?;
            let mut rows = Vec::new();
            loop {
                self.expect(&TokenKind::LParen, "'('")?;
                rows.push(self.expr_list()?);
                self.expect(&TokenKind::RParen, "')'")?;
                if !self.eat(&TokenKind::Comma, "','") {
                    break;
                }
            }
            InsertSource::Tuples { columns, rows }
        } else if self.eat_kw("VALUE") {
            InsertSource::Value { expr: self.expr()? }
        } else if self.eat_kw("VALUES") {
            InsertSource::Values {
                rows: self.expr_list()?,
            }
        } else if self.check_kw("FROM") {
            InsertSource::Query {
                query: Box::new(self.query()?),
            }
        } else {
            return Err(self.unexpected());
        };
        let on_conflict = if self.check_kw("ON") {
            self.expect_kws(&["ON", "CONFLICT", "DO"])?;
            if self.eat_kw("NOTHING") {
                Some(OnConflict::DoNothing)
            } else {
                self.expect_kw("UPDATE")?;
                Some(OnConflict::DoUpdate {
                    ops: self.update_ops()?,
                })
            }
        } else {
            None
        };
        let ttl = if self.eat_kw("USING") {
            self.expect_kw("TTL")?;
            Some(self.expr()?)
        } else {
            None
        };
        let returning = self.opt_returning()?;
        Ok(Statement::Insert(Insert {
            target,
            source,
            on_conflict,
            ttl,
            returning,
        }))
    }

    /// `UPDATE coll [AS a] ops [WHERE p] [LIMIT n] [OPTIONS (…)] [RETURNING …]`.
    pub(super) fn update(&mut self) -> PResult<Statement> {
        self.expect_kw("UPDATE")?;
        let target = self.qualified_name()?;
        let alias = if self.eat_kw("AS") {
            Some(self.ident()?)
        } else {
            None
        };
        let ops = self.update_ops()?;
        let filter = self.opt_where()?;
        let limit = self.opt_limit()?;
        let options = self.opt_options("OPTIONS")?;
        let returning = self.opt_returning()?;
        Ok(Statement::Update(Update {
            target,
            alias,
            ops,
            filter,
            limit,
            options,
            returning,
        }))
    }

    /// `UPSERT INTO coll VALUE e [ON path, …] [RETURNING …]`.
    pub(super) fn upsert(&mut self) -> PResult<Statement> {
        self.expect_kws(&["UPSERT", "INTO"])?;
        let target = self.qualified_name()?;
        self.expect_kw("VALUE")?;
        let value = self.expr()?;
        let on = self.opt_on_paths()?;
        let returning = self.opt_returning()?;
        Ok(Statement::Upsert(Upsert {
            target,
            value,
            on,
            returning,
        }))
    }

    /// `DELETE [col, …] FROM coll [WHERE p] [LIMIT n] [OPTIONS (…)] [RETURNING …]`.
    pub(super) fn delete(&mut self) -> PResult<Statement> {
        self.expect_kw("DELETE")?;
        let columns = if self.check_kw("FROM") {
            Vec::new()
        } else {
            self.path_list(false)?
        };
        self.expect_kw("FROM")?;
        let target = self.qualified_name()?;
        let filter = self.opt_where()?;
        let limit = self.opt_limit()?;
        let options = self.opt_options("OPTIONS")?;
        let returning = self.opt_returning()?;
        Ok(Statement::Delete(Delete {
            columns,
            target,
            filter,
            limit,
            options,
            returning,
        }))
    }

    fn opt_where(&mut self) -> PResult<Option<crate::ast::Expr>> {
        if self.eat_kw("WHERE") {
            Ok(Some(self.expr()?))
        } else {
            Ok(None)
        }
    }

    fn opt_limit(&mut self) -> PResult<Option<crate::ast::Expr>> {
        if self.eat_kw("LIMIT") {
            Ok(Some(self.expr()?))
        } else {
            Ok(None)
        }
    }

    /// `RETURNING OLD|NEW [projections]`; the list is absent at the end of the statement.
    fn opt_returning(&mut self) -> PResult<Option<Returning>> {
        if !self.eat_kw("RETURNING") {
            return Ok(None);
        }
        let image = if self.eat_kw("OLD") {
            Image::Old
        } else {
            self.expect_kw("NEW")?;
            Image::New
        };
        let at_end = matches!(
            self.kind(0),
            TokenKind::Eof | TokenKind::Semicolon | TokenKind::RParen
        );
        let items = if at_end {
            Vec::new()
        } else {
            self.projections()?
        };
        Ok(Some(Returning { image, items }))
    }

    /// One or more update operations. `REPLACE WITH` must be the only one.
    ///
    /// Provisional (PD pending, query-language.md §3.1): the grammar of §3 requires a leading
    /// `SET`, but §6 writes `UPDATE … PUSH …` without one; any sequence of operations is
    /// accepted, in order.
    pub(super) fn update_ops(&mut self) -> PResult<Vec<UpdateOp>> {
        if self.check_kw("REPLACE") {
            self.expect_kws(&["REPLACE", "WITH"])?;
            return Ok(vec![UpdateOp::Replace {
                value: self.expr()?,
            }]);
        }
        let mut ops = Vec::new();
        while let Some(op) = self.update_op()? {
            ops.push(op);
        }
        if ops.is_empty() {
            return Err(self.unexpected());
        }
        Ok(ops)
    }

    fn update_op(&mut self) -> PResult<Option<UpdateOp>> {
        const OPS: [&str; 13] = [
            "SET", "UNSET", "INC", "MUL", "PUSH", "PULL", "ADD", "POP", "RENAME", "MIN", "MAX",
            "CURRENT", "REPLACE",
        ];
        for kw in OPS {
            self.note(kw);
        }
        let TokenKind::Word(w) = self.kind(0) else {
            return Ok(None);
        };
        let kw = w.to_ascii_uppercase();
        // REPLACE WITH is only valid alone; here it is an error reported by the caller.
        if !OPS.contains(&kw.as_str()) || kw == "REPLACE" {
            return Ok(None);
        }
        self.advance();
        let op = match kw.as_str() {
            "SET" => UpdateOp::Set {
                items: self.set_items()?,
            },
            "UNSET" => UpdateOp::Unset {
                paths: self.path_list(false)?,
            },
            "INC" | "MUL" => {
                let path = self.path(false)?;
                self.expect_kw("BY")?;
                let by = self.expr()?;
                if kw == "INC" {
                    UpdateOp::Inc { path, by }
                } else {
                    UpdateOp::Mul { path, by }
                }
            }
            "PUSH" => self.push_op()?,
            "PULL" => {
                let path = self.path(false)?;
                self.expect_kw("WHERE")?;
                UpdateOp::Pull {
                    path,
                    predicate: self.expr()?,
                }
            }
            "ADD" => {
                self.expect_kws(&["TO", "SET"])?;
                let path = self.path(false)?;
                self.expect_kw("VALUE")?;
                UpdateOp::AddToSet {
                    path,
                    value: self.expr()?,
                }
            }
            "POP" => {
                let path = self.path(false)?;
                let end = if self.eat_kw("FIRST") {
                    PopEnd::First
                } else {
                    self.expect_kw("LAST")?;
                    PopEnd::Last
                };
                UpdateOp::Pop { path, end }
            }
            "RENAME" => {
                let from = self.path(false)?;
                self.expect_kw("TO")?;
                UpdateOp::Rename {
                    from,
                    to: self.path(false)?,
                }
            }
            "MIN" | "MAX" => {
                let path = self.path(false)?;
                self.expect_kw("WITH")?;
                let value = self.expr()?;
                if kw == "MIN" {
                    UpdateOp::Min { path, value }
                } else {
                    UpdateOp::Max { path, value }
                }
            }
            _ => {
                self.expect_kw("DATE")?;
                UpdateOp::CurrentDate {
                    path: self.path(false)?,
                }
            }
        };
        Ok(Some(op))
    }

    /// `PUSH path VALUE e` then modifiers `POSITION e`, `SLICE e`, `SORT keys`, each at most
    /// once in any order (provisional `push_mods`, query-language.md §3.1).
    fn push_op(&mut self) -> PResult<UpdateOp> {
        let path = self.path(false)?;
        self.expect_kw("VALUE")?;
        let value = self.expr()?;
        let (mut position, mut slice, mut sort) = (None, None, Vec::new());
        loop {
            if position.is_none() && self.eat_kw("POSITION") {
                position = Some(self.expr()?);
            } else if slice.is_none() && self.eat_kw("SLICE") {
                slice = Some(self.expr()?);
            } else if sort.is_empty() && self.eat_kw("SORT") {
                sort = self.order_items()?;
            } else {
                break;
            }
        }
        Ok(UpdateOp::Push {
            path,
            value,
            position,
            slice,
            sort,
        })
    }
}
