// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Expression parsing: Pratt loop for binary operators (query-language.md §4.1), recursive
//! descent for primaries, and the path-only parser of §3 `path`.

use rustegon_doc::{Decimal128, ObjectId};

use super::{
    PResult, Parser, is_reserved,
    lexer::{NumberClass, TokenKind},
};
use crate::ast::{
    BinaryOp, Expr, IsTest, Literal, ObjectField, Path, Quantifier, Segment, WhenThen,
    expr::{PREC_ADDITIVE, PREC_COMPARISON},
    literal::{parse_datetime, parse_uuid},
};

/// Binding power of `OR` / `AND` (below `NOT` and comparisons, §4.1 levels 8 and 7).
const PREC_OR: u8 = 1;
const PREC_AND: u8 = 2;

/// An infix operator recognised at the current position.
#[derive(Clone, Copy)]
enum Infix {
    Binary(BinaryOp, usize),
    And,
    Or,
    Between,
    Is,
}

impl Infix {
    fn precedence(self) -> u8 {
        match self {
            Self::Binary(op, _) => op.precedence(),
            Self::And => PREC_AND,
            Self::Or => PREC_OR,
            Self::Between | Self::Is => PREC_COMPARISON,
        }
    }
}

impl Parser<'_> {
    /// A full expression.
    pub(super) fn expr(&mut self) -> PResult<Expr> {
        self.expr_bp(0)
    }

    /// An expression whose operators all have precedence `>= min`.
    ///
    /// Each operator applied in the loop adds one AST level above the operands, so it counts
    /// against the nesting limit (restored on return): a 10⁵-term `a + a + …` chain is
    /// rejected instead of producing a 10⁵-deep left spine that would overflow the stack in
    /// later recursive passes. n-ary `AND`/`OR` add one level per chain, not per operand.
    pub(super) fn expr_bp(&mut self, min: u8) -> PResult<Expr> {
        self.enter()?;
        let base = self.depth;
        let r = self.expr_loop(min);
        self.depth = base - 1;
        r
    }

    fn expr_loop(&mut self, min: u8) -> PResult<Expr> {
        let mut lhs = self.unary()?;
        while let Some(op) = self.peek_infix() {
            let prec = op.precedence();
            if prec < min {
                break;
            }
            self.enter()?;
            lhs = match op {
                Infix::And => Expr::And {
                    args: self.nary(lhs, "AND", PREC_AND + 1)?,
                },
                Infix::Or => Expr::Or {
                    args: self.nary(lhs, "OR", PREC_OR + 1)?,
                },
                Infix::Binary(op, tokens) => {
                    for _ in 0..tokens {
                        self.advance();
                    }
                    let rhs_min = if prec == PREC_COMPARISON {
                        PREC_ADDITIVE
                    } else {
                        prec + 1
                    };
                    let right = self.expr_bp(rhs_min)?;
                    Expr::Binary {
                        op,
                        left: Box::new(lhs),
                        right: Box::new(right),
                    }
                }
                Infix::Between => self.between(lhs)?,
                Infix::Is => self.is_test(lhs)?,
            };
            if prec == PREC_COMPARISON
                && self
                    .peek_infix_silent()
                    .is_some_and(|o| o.precedence() == PREC_COMPARISON)
            {
                return Err(self.error_at(
                    self.pos,
                    "comparison operators are non-associative; add parentheses",
                ));
            }
        }
        Ok(lhs)
    }

    fn nary(&mut self, first: Expr, kw: &'static str, min: u8) -> PResult<Vec<Expr>> {
        let mut args = vec![first];
        while self.eat_kw(kw) {
            args.push(self.expr_bp(min)?);
        }
        Ok(args)
    }

    fn between(&mut self, lhs: Expr) -> PResult<Expr> {
        self.expect_kw("BETWEEN")?;
        let low = self.expr_bp(PREC_ADDITIVE)?;
        self.expect_kw("AND")?;
        let high = self.expr_bp(PREC_ADDITIVE)?;
        Ok(Expr::Between {
            expr: Box::new(lhs),
            low: Box::new(low),
            high: Box::new(high),
        })
    }

    fn is_test(&mut self, lhs: Expr) -> PResult<Expr> {
        self.expect_kw("IS")?;
        let negated = self.eat_kw("NOT");
        let test = if self.eat_kw("NULL") {
            IsTest::Null
        } else if self.eat_kw("MISSING") {
            IsTest::Missing
        } else {
            return Err(self.unexpected());
        };
        Ok(Expr::Is {
            expr: Box::new(lhs),
            negated,
            test,
        })
    }

    fn peek_infix(&mut self) -> Option<Infix> {
        self.note("operator");
        self.peek_infix_silent()
    }

    fn peek_infix_silent(&self) -> Option<Infix> {
        use BinaryOp as B;
        let bin = |op| Some(Infix::Binary(op, 1));
        match self.kind(0) {
            TokenKind::Eq => bin(B::Eq),
            TokenKind::EqEq => bin(B::EqWhole),
            TokenKind::Ne => bin(B::Ne),
            TokenKind::Lt => bin(B::Lt),
            TokenKind::Le => bin(B::Le),
            TokenKind::Gt => bin(B::Gt),
            TokenKind::Ge => bin(B::Ge),
            TokenKind::Plus => bin(B::Add),
            TokenKind::Minus => bin(B::Sub),
            TokenKind::Star => bin(B::Mul),
            TokenKind::Slash => bin(B::Div),
            TokenKind::Percent => bin(B::Mod),
            TokenKind::Concat => bin(B::Concat),
            TokenKind::Word(w) => match w.to_ascii_uppercase().as_str() {
                "AND" => Some(Infix::And),
                "OR" => Some(Infix::Or),
                "IN" => bin(B::In),
                "NOT" if self.is_kw(1, "IN") => Some(Infix::Binary(B::NotIn, 2)),
                "LIKE" => bin(B::Like),
                "ILIKE" => bin(B::Ilike),
                "MATCHES" => bin(B::Matches),
                "BETWEEN" => Some(Infix::Between),
                "IS" => Some(Infix::Is),
                "CONTAINS" if self.is_kw(1, "ANY") => Some(Infix::Binary(B::ContainsAny, 2)),
                "CONTAINS" if self.is_kw(1, "ALL") => Some(Infix::Binary(B::ContainsAll, 2)),
                "CONTAINS" => bin(B::Contains),
                _ => None,
            },
            _ => None,
        }
    }

    /// `true` if an infix operator (or `AS`) follows: used to decide `-path` exclusions.
    pub(super) fn continues_expression(&self) -> bool {
        self.peek_infix_silent().is_some()
            || self.is_kw(0, "AS")
            || matches!(self.kind(0), TokenKind::Dot | TokenKind::LBracket)
    }

    /// Unary `-` (§4.1 level 2) or prefix `NOT` (level 6), then a primary with postfix
    /// segments.
    ///
    /// `NOT` follows SQL precedence (PD-033): its operand is a whole comparison-level
    /// expression, so `NOT a = b` is `NOT (a = b)` and `NOT a AND b` is `(NOT a) AND b`. As a
    /// prefix operator it is still accepted in any operand position, where it extends as far
    /// right as a comparison does (`x + NOT a = b` is `x + (NOT (a = b))`, as in PostgreSQL);
    /// the printer parenthesises it whenever an operator it would absorb follows.
    fn unary(&mut self) -> PResult<Expr> {
        if *self.kind(0) == TokenKind::Minus {
            if matches!(self.kind(1), TokenKind::Number { .. }) {
                // `-5` is a literal, so `i64::MIN` is writable and printing is unambiguous.
                let at = self.pos;
                self.advance();
                let lit = self.number(true, at)?;
                return self.postfix(lit);
            }
            self.advance();
            let operand = self.nested(Self::unary)?;
            return Ok(Expr::Neg {
                expr: Box::new(operand),
            });
        }
        if self.is_kw(0, "NOT") {
            self.advance();
            // `expr_bp` counts one nesting level, as `nested(unary)` did before PD-033.
            let operand = self.expr_bp(PREC_COMPARISON)?;
            return Ok(Expr::Not {
                expr: Box::new(operand),
            });
        }
        let base = self.primary()?;
        self.postfix(base)
    }

    /// `.name`, `.0` and `[expr]` segments (§4.1 level 1). A path base absorbs them.
    fn postfix(&mut self, base: Expr) -> PResult<Expr> {
        let mut segments = Vec::new();
        while let Some(seg) = self.segment(false)? {
            segments.push(seg);
        }
        if segments.is_empty() {
            return Ok(base);
        }
        Ok(match base {
            Expr::Path { mut path } => {
                path.0.extend(segments);
                Expr::Path { path }
            }
            Expr::Access { base, mut path } => {
                path.0.extend(segments);
                Expr::Access { base, path }
            }
            other => Expr::Access {
                base: Box::new(other),
                path: Path(segments),
            },
        })
    }

    /// One path segment if present. `.*` is left unconsumed (projection wildcard).
    fn segment(&mut self, allow_each: bool) -> PResult<Option<Segment>> {
        match self.kind(0) {
            TokenKind::Dot => match self.kind(1).clone() {
                TokenKind::Star => Ok(None),
                TokenKind::Number {
                    text,
                    class: NumberClass::Int,
                } => {
                    self.advance();
                    let at = self.pos;
                    let p = text
                        .parse::<u32>()
                        .map_err(|_| self.error_at(at, "array position out of range"))?;
                    self.advance();
                    Ok(Some(Segment::Position(p)))
                }
                _ => {
                    self.advance();
                    Ok(Some(Segment::Field(self.name()?)))
                }
            },
            TokenKind::LBracket => {
                self.advance();
                if allow_each && self.eat(&TokenKind::RBracket, "']'") {
                    return Ok(Some(Segment::Each));
                }
                let index = self.expr()?;
                self.expect(&TokenKind::RBracket, "']'")?;
                Ok(Some(Segment::Index(Box::new(index))))
            }
            _ => Ok(None),
        }
    }

    /// A field path (§3 `path`); `allow_each` admits `[]` (INCLUDE paths only).
    pub(super) fn path(&mut self, allow_each: bool) -> PResult<Path> {
        let mut segments = vec![Segment::Field(self.ident()?)];
        while let Some(seg) = self.segment(allow_each)? {
            segments.push(seg);
        }
        Ok(Path(segments))
    }

    /// `path {, path}`.
    pub(super) fn path_list(&mut self, allow_each: bool) -> PResult<Vec<Path>> {
        let mut paths = vec![self.path(allow_each)?];
        while self.eat(&TokenKind::Comma, "','") {
            paths.push(self.path(allow_each)?);
        }
        Ok(paths)
    }

    /// `expr {, expr}`.
    pub(super) fn expr_list(&mut self) -> PResult<Vec<Expr>> {
        let mut items = vec![self.expr()?];
        while self.eat(&TokenKind::Comma, "','") {
            items.push(self.expr()?);
        }
        Ok(items)
    }

    fn primary(&mut self) -> PResult<Expr> {
        self.note("expression");
        match self.kind(0).clone() {
            TokenKind::Number { .. } => {
                let at = self.pos;
                self.number(false, at)
            }
            TokenKind::Str(s) => {
                self.advance();
                Ok(Expr::Literal(Literal::String(s)))
            }
            TokenKind::Param(name) => {
                self.advance();
                Ok(Expr::Param { name })
            }
            TokenKind::LParen if self.lambda_params_ahead() => self.lambda(),
            TokenKind::LParen => {
                self.advance();
                let e = self.expr()?;
                self.expect(&TokenKind::RParen, "')'")?;
                Ok(e)
            }
            TokenKind::LBracket => self.array(),
            TokenKind::LBrace => self.object(),
            TokenKind::QuotedIdent(_) if *self.kind(1) == TokenKind::Arrow => self.lambda(),
            TokenKind::QuotedIdent(name) => {
                self.advance();
                Ok(Expr::Path {
                    path: Path(vec![Segment::Field(name)]),
                })
            }
            TokenKind::Word(w) => self.word_primary(&w),
            _ => Err(self.unexpected()),
        }
    }

    fn word_primary(&mut self, word: &str) -> PResult<Expr> {
        let upper = word.to_ascii_uppercase();
        let next_is_str = matches!(self.kind(1), TokenKind::Str(_));
        match upper.as_str() {
            "NULL" => Ok(self.keyword_literal(Literal::Null)),
            "TRUE" => Ok(self.keyword_literal(Literal::Bool(true))),
            "FALSE" => Ok(self.keyword_literal(Literal::Bool(false))),
            "DATE" | "OID" | "UUID" | "INTERVAL" if next_is_str => self.typed_literal(&upper),
            "CASE" => self.nested(Self::case),
            "ANY" | "EVERY" if self.is_ident_at(1) && self.is_kw(2, "IN") => {
                self.nested(Self::quantified)
            }
            "ELEM" if self.is_kw(1, "MATCH") => self.nested(Self::elem_match),
            _ if *self.kind(1) == TokenKind::LParen => self.nested(|p| p.call(word)),
            _ if is_reserved(word) => Err(self.unexpected()),
            _ if *self.kind(1) == TokenKind::Arrow => self.lambda(),
            _ => {
                self.advance();
                Ok(Expr::Path {
                    path: Path(vec![Segment::Field(word.to_owned())]),
                })
            }
        }
    }

    fn keyword_literal(&mut self, lit: Literal) -> Expr {
        self.advance();
        Expr::Literal(lit)
    }

    /// A number token (already positioned on it); `negative` when a `-` was folded in, `at`
    /// being the index of the first token of the literal for error positions.
    fn number(&mut self, negative: bool, at: usize) -> PResult<Expr> {
        let TokenKind::Number { text, class } = self.kind(0).clone() else {
            return Err(self.unexpected());
        };
        self.advance();
        let signed = if negative { format!("-{text}") } else { text };
        let lit = match class {
            NumberClass::Int => signed
                .parse::<i64>()
                .map(Literal::Int)
                .map_err(|_| self.error_at(at, "integer literal out of the int64 range"))?,
            NumberClass::Float => signed
                .parse::<f64>()
                .ok()
                .filter(|f| f.is_finite())
                .map(Literal::Float)
                .ok_or_else(|| self.error_at(at, "float literal out of the float64 range"))?,
            NumberClass::Decimal => Decimal128::parse(&signed)
                .map(Literal::Decimal)
                .map_err(|_| self.error_at(at, "decimal literal not representable exactly"))?,
        };
        Ok(Expr::Literal(lit))
    }

    fn typed_literal(&mut self, upper: &str) -> PResult<Expr> {
        self.advance();
        let at = self.pos;
        let TokenKind::Str(text) = self.kind(0).clone() else {
            return Err(self.unexpected());
        };
        self.advance();
        let lit = match upper {
            "DATE" => parse_datetime(&text)
                .map(Literal::DateTime)
                .ok_or_else(|| {
                    self.error_at(
                    at,
                    "invalid DATE literal (expected 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SS[.fff]Z')",
                )
                })?,
            "OID" => ObjectId::parse_hex(&text)
                .map(Literal::ObjectId)
                .map_err(|_| self.error_at(at, "invalid OID literal (expected 24 hex digits)"))?,
            "UUID" => parse_uuid(&text)
                .map(Literal::Uuid)
                .ok_or_else(|| self.error_at(at, "invalid UUID literal"))?,
            _ => Literal::Interval(text),
        };
        Ok(Expr::Literal(lit))
    }

    fn call(&mut self, name: &str) -> PResult<Expr> {
        self.advance();
        self.expect(&TokenKind::LParen, "'('")?;
        if name.eq_ignore_ascii_case("extract") && self.is_ident_at(0) && self.is_kw(1, "FROM") {
            let unit = self.ident()?;
            self.expect_kw("FROM")?;
            let expr = self.expr()?;
            self.expect(&TokenKind::RParen, "')'")?;
            return Ok(Expr::Extract {
                unit,
                expr: Box::new(expr),
            });
        }
        let mut args = Vec::new();
        if !self.eat(&TokenKind::RParen, "')'") {
            loop {
                let star = *self.kind(0) == TokenKind::Star
                    && matches!(self.kind(1), TokenKind::RParen | TokenKind::Comma);
                if star {
                    self.advance();
                    args.push(Expr::Star);
                } else {
                    args.push(self.expr()?);
                }
                if !self.eat(&TokenKind::Comma, "','") {
                    break;
                }
            }
            self.expect(&TokenKind::RParen, "')'")?;
        }
        Ok(Expr::Call {
            name: name.to_owned(),
            args,
        })
    }

    fn case(&mut self) -> PResult<Expr> {
        self.expect_kw("CASE")?;
        let operand = if self.check_kw("WHEN") {
            None
        } else {
            Some(Box::new(self.expr()?))
        };
        let mut whens = Vec::new();
        self.expect_kw("WHEN")?;
        loop {
            let when = self.expr()?;
            self.expect_kw("THEN")?;
            let then = self.expr()?;
            whens.push(WhenThen { when, then });
            if !self.eat_kw("WHEN") {
                break;
            }
        }
        let otherwise = if self.eat_kw("ELSE") {
            Some(Box::new(self.expr()?))
        } else {
            None
        };
        self.expect_kw("END")?;
        Ok(Expr::Case {
            operand,
            whens,
            otherwise,
        })
    }

    fn quantified(&mut self) -> PResult<Expr> {
        let quantifier = if self.eat_kw("ANY") {
            Quantifier::Any
        } else {
            self.expect_kw("EVERY")?;
            Quantifier::Every
        };
        let var = self.ident()?;
        self.expect_kw("IN")?;
        let source = self.expr()?;
        self.expect_kw("SATISFIES")?;
        let predicate = self.expr()?;
        Ok(Expr::Quantified {
            quantifier,
            var,
            source: Box::new(source),
            predicate: Box::new(predicate),
        })
    }

    fn elem_match(&mut self) -> PResult<Expr> {
        self.expect_kws(&["ELEM", "MATCH"])?;
        self.expect(&TokenKind::LParen, "'('")?;
        let path = self.path(false)?;
        self.expect(&TokenKind::Comma, "','")?;
        let predicate = self.expr()?;
        self.expect(&TokenKind::RParen, "')'")?;
        Ok(Expr::ElemMatch {
            path,
            predicate: Box::new(predicate),
        })
    }

    /// `true` if a lambda parameter list `( [ident {, ident}] ) ->` starts here. `(ident ,`
    /// already decides it: a parenthesized expression never contains a top-level comma, so the
    /// error of a malformed list is then reported inside the list.
    fn lambda_params_ahead(&self) -> bool {
        match (self.kind(1), self.kind(2)) {
            (TokenKind::RParen, next) => *next == TokenKind::Arrow,
            (_, TokenKind::Comma) => self.is_ident_at(1),
            (_, TokenKind::RParen) => self.is_ident_at(1) && *self.kind(3) == TokenKind::Arrow,
            _ => false,
        }
    }

    fn lambda(&mut self) -> PResult<Expr> {
        let mut params = Vec::new();
        if self.eat(&TokenKind::LParen, "'('") {
            if !self.eat(&TokenKind::RParen, "')'") {
                params = self.ident_list()?;
                self.expect(&TokenKind::RParen, "')'")?;
            }
        } else {
            params.push(self.ident()?);
        }
        self.expect(&TokenKind::Arrow, "'->'")?;
        let body = self.nested(Self::expr)?;
        Ok(Expr::Lambda {
            params,
            body: Box::new(body),
        })
    }

    /// `ident {, ident}`.
    pub(super) fn ident_list(&mut self) -> PResult<Vec<String>> {
        let mut names = vec![self.ident()?];
        while self.eat(&TokenKind::Comma, "','") {
            names.push(self.ident()?);
        }
        Ok(names)
    }

    fn array(&mut self) -> PResult<Expr> {
        self.nested(|p| {
            p.expect(&TokenKind::LBracket, "'['")?;
            let mut elements = Vec::new();
            if !p.eat(&TokenKind::RBracket, "']'") {
                elements = p.expr_list()?;
                p.expect(&TokenKind::RBracket, "']'")?;
            }
            Ok(Expr::Array { elements })
        })
    }

    fn object(&mut self) -> PResult<Expr> {
        self.nested(|p| {
            p.expect(&TokenKind::LBrace, "'{'")?;
            let mut fields = Vec::new();
            if !p.eat(&TokenKind::RBrace, "'}'") {
                loop {
                    let name = match p.kind(0).clone() {
                        TokenKind::Str(s) => {
                            p.advance();
                            s
                        }
                        _ => p.name()?,
                    };
                    p.expect(&TokenKind::Colon, "':'")?;
                    let value = p.expr()?;
                    fields.push(ObjectField { name, value });
                    if !p.eat(&TokenKind::Comma, "','") {
                        break;
                    }
                }
                p.expect(&TokenKind::RBrace, "'}'")?;
            }
            Ok(Expr::Object { fields })
        })
    }
}
