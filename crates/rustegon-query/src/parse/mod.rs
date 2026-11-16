// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! RGQL text front end (ADR-013: hand-written parser; query-language.md §2–§12).
//!
//! [`tokenize`] turns the text into tokens; the parser is recursive descent for statements and
//! clauses and Pratt (precedence climbing) for expressions (§4.1). Errors carry 1-based
//! line/column positions and the set of tokens that would have been accepted (`RGN-1010`).
//!
//! **Limits.** Untrusted text must not exhaust the stack: every recursive construct and every
//! operator applied in a left-associative chain counts against [`MAX_NESTING_DEPTH`], so the
//! AST height stays bounded (which also bounds recursion in the printer, in `Drop` and in later
//! compiler passes). Inputs above [`MAX_QUERY_BYTES`] are rejected before lexing. Both give
//! `RGN-1013 QueryTooComplex`.
//!
//! **Reserved words** ([`RESERVED_WORDS`]) cannot be bare identifiers; write them back-quoted
//! (`` `value` ``). All other keywords are contextual and stay usable as field names. After a
//! `.` (paths, qualified names) and as object keys any word is a name.

mod ddl;
mod error;
mod expr;
mod lexer;
mod query;
mod write;

pub use self::{
    error::ParseError,
    lexer::{NumberClass, Token, TokenKind, tokenize},
};
use crate::ast::{Expr, Statement};

/// Maximum nesting depth (parenthesized/nested expressions, operator chains, sub-queries,
/// sub-pipelines). Chosen so that the deepest accepted input parses on a 2 MiB thread stack in
/// debug builds (asserted by `tc_ql_002_robust_limits_hold_on_a_2mib_stack`) while leaving ample room for real queries;
/// n-ary `AND`/`OR` chains do not consume depth.
pub const MAX_NESTING_DEPTH: u32 = 128;

/// Nesting levels charged for a (sub-)query or a sub-pipeline. Their parse functions have far
/// larger stack frames than an expression level (debug builds: tens of KiB per sub-query), so
/// they consume more of the budget: at most 16 nested sub-queries, which real queries never
/// approach.
pub const QUERY_NESTING_COST: u32 = 8;

/// Maximum query text size in bytes (16 MiB, the maximum document size: bulk data belongs in
/// parameters, not literals).
pub const MAX_QUERY_BYTES: usize = 16 * 1024 * 1024;

/// Words that are never bare identifiers (provisional list, query-language.md §3.1).
pub const RESERVED_WORDS: &[&str] = &[
    "ALL",
    "AND",
    "ANY",
    "AS",
    "BETWEEN",
    "BY",
    "CASE",
    "CONTAINS",
    "ELSE",
    "END",
    "EVERY",
    "FALSE",
    "FROM",
    "GROUP",
    "HAVING",
    "ILIKE",
    "IN",
    "INCLUDE",
    "INTO",
    "IS",
    "LIKE",
    "LIMIT",
    "LOOKUP",
    "MATCHES",
    "MISSING",
    "NOT",
    "NULL",
    "OF",
    "OFFSET",
    "ON",
    "OPTIONS",
    "OR",
    "ORDER",
    "RETURNING",
    "SATISFIES",
    "SELECT",
    "SET",
    "THEN",
    "TRUE",
    "UNSET",
    "USING",
    "VALUE",
    "VALUES",
    "WHEN",
    "WHERE",
    "WITH",
];

/// `true` if `word` is reserved (case-insensitive).
#[must_use]
pub fn is_reserved(word: &str) -> bool {
    RESERVED_WORDS.iter().any(|r| r.eq_ignore_ascii_case(word))
}

/// `true` if `name` can be printed as a bare word (`[A-Za-z_][A-Za-z0-9_]*`).
#[must_use]
pub fn is_bare_word(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parses one statement, optionally followed by `;`.
///
/// # Errors
/// `RGN-1010` ([`ParseError::Syntax`]) or `RGN-1013` ([`ParseError::TooComplex`]).
pub fn parse_statement(text: &str) -> Result<Statement, ParseError> {
    let mut p = Parser::new(text)?;
    let stmt = p.statement()?;
    p.eat(&TokenKind::Semicolon, "';'");
    p.expect_eof()?;
    Ok(stmt)
}

/// Parses a `;`-separated script. More than one statement is allowed only as a transaction
/// script that starts with `BEGIN` and ends with `COMMIT` or `ROLLBACK` (§2).
///
/// # Errors
/// As [`parse_statement`]; a multi-statement script outside `BEGIN … COMMIT` is `RGN-1010`
/// at the second statement.
pub fn parse_script(text: &str) -> Result<Vec<Statement>, ParseError> {
    let mut p = Parser::new(text)?;
    let mut stmts = Vec::new();
    let mut second_at = None;
    loop {
        if stmts.len() == 1 {
            second_at = Some(p.pos);
        }
        stmts.push(p.statement()?);
        if !p.eat(&TokenKind::Semicolon, "';'") || p.at_eof() {
            break;
        }
    }
    p.expect_eof()?;
    let is_script = matches!(stmts.first(), Some(Statement::Begin(_)))
        && matches!(stmts.last(), Some(Statement::Commit | Statement::Rollback));
    if let (Some(at), false) = (second_at, is_script) {
        return Err(p.error_at(
            at,
            "multiple statements are allowed only in BEGIN … COMMIT scripts",
        ));
    }
    Ok(stmts)
}

/// Parses a standalone expression (tests, tools, binder unit tests).
///
/// # Errors
/// As [`parse_statement`].
pub fn parse_expr(text: &str) -> Result<Expr, ParseError> {
    let mut p = Parser::new(text)?;
    let e = p.expr()?;
    p.expect_eof()?;
    Ok(e)
}

type PResult<T> = Result<T, ParseError>;

/// Parser state over a token vector.
pub(crate) struct Parser<'s> {
    src: &'s str,
    tokens: Vec<Token>,
    pos: usize,
    depth: u32,
    /// What was tried at token index `expected_at`, for error messages.
    expected: Vec<&'static str>,
    expected_at: usize,
}

impl<'s> Parser<'s> {
    fn new(src: &'s str) -> PResult<Self> {
        if src.len() > MAX_QUERY_BYTES {
            return Err(ParseError::TooComplex {
                line: 1,
                column: 1,
                reason: format!("query text exceeds {MAX_QUERY_BYTES} bytes"),
            });
        }
        Ok(Self {
            src,
            tokens: tokenize(src)?,
            pos: 0,
            depth: 0,
            expected: Vec::new(),
            expected_at: 0,
        })
    }

    // ---- token access -------------------------------------------------------------------

    fn token(&self, n: usize) -> &Token {
        // The vector ends with Eof; positions past it read Eof again.
        let last = self.tokens.len() - 1;
        &self.tokens[(self.pos + n).min(last)]
    }

    fn kind(&self, n: usize) -> &TokenKind {
        &self.token(n).kind
    }

    fn advance(&mut self) {
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
    }

    fn at_eof(&self) -> bool {
        *self.kind(0) == TokenKind::Eof
    }

    /// Records that `what` would be accepted at the current position.
    fn note(&mut self, what: &'static str) {
        if self.expected_at != self.pos {
            self.expected.clear();
            self.expected_at = self.pos;
        }
        if !self.expected.contains(&what) {
            self.expected.push(what);
        }
    }

    /// `true` if the token `n` ahead is the keyword `kw` (no expectation recorded).
    fn is_kw(&self, n: usize, kw: &str) -> bool {
        matches!(self.kind(n), TokenKind::Word(w) if w.eq_ignore_ascii_case(kw))
    }

    fn check_kw(&mut self, kw: &'static str) -> bool {
        self.note(kw);
        self.is_kw(0, kw)
    }

    fn eat_kw(&mut self, kw: &'static str) -> bool {
        let hit = self.check_kw(kw);
        if hit {
            self.advance();
        }
        hit
    }

    fn expect_kw(&mut self, kw: &'static str) -> PResult<()> {
        if self.eat_kw(kw) {
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    /// Expects a keyword sequence such as `GROUP BY`.
    fn expect_kws(&mut self, kws: &[&'static str]) -> PResult<()> {
        kws.iter().try_for_each(|kw| self.expect_kw(kw))
    }

    fn check(&mut self, kind: &TokenKind, what: &'static str) -> bool {
        self.note(what);
        self.kind(0) == kind
    }

    fn eat(&mut self, kind: &TokenKind, what: &'static str) -> bool {
        let hit = self.check(kind, what);
        if hit {
            self.advance();
        }
        hit
    }

    fn expect(&mut self, kind: &TokenKind, what: &'static str) -> PResult<()> {
        if self.eat(kind, what) {
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    fn expect_eof(&mut self) -> PResult<()> {
        self.note("end of input");
        if self.at_eof() {
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    /// `true` if the token `n` ahead can be an identifier.
    fn is_ident_at(&self, n: usize) -> bool {
        match self.kind(n) {
            TokenKind::Word(w) => !is_reserved(w),
            TokenKind::QuotedIdent(_) => true,
            _ => false,
        }
    }

    /// An identifier: a non-reserved word or a quoted identifier.
    fn ident(&mut self) -> PResult<String> {
        self.note("identifier");
        match self.kind(0) {
            TokenKind::Word(w) if !is_reserved(w) => {
                let w = w.clone();
                self.advance();
                Ok(w)
            }
            TokenKind::QuotedIdent(q) => {
                let q = q.clone();
                self.advance();
                Ok(q)
            }
            _ => Err(self.unexpected()),
        }
    }

    /// A name after `.` or as an object key: any word or a quoted identifier.
    fn name(&mut self) -> PResult<String> {
        self.note("name");
        match self.kind(0) {
            TokenKind::Word(w) | TokenKind::QuotedIdent(w) => {
                let w = w.clone();
                self.advance();
                Ok(w)
            }
            _ => Err(self.unexpected()),
        }
    }

    // ---- depth accounting -----------------------------------------------------------------

    fn enter(&mut self) -> PResult<()> {
        self.enter_by(1)
    }

    fn enter_by(&mut self, cost: u32) -> PResult<()> {
        self.depth += cost;
        if self.depth > MAX_NESTING_DEPTH {
            let t = self.token(0);
            return Err(ParseError::TooComplex {
                line: t.line,
                column: t.column,
                reason: format!("nesting deeper than {MAX_NESTING_DEPTH} levels"),
            });
        }
        Ok(())
    }

    /// Runs `f` one nesting level deeper.
    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> PResult<T>) -> PResult<T> {
        self.nested_by(1, f)
    }

    /// Runs `f` `cost` nesting levels deeper (constructs with large stack frames).
    fn nested_by<T>(&mut self, cost: u32, f: impl FnOnce(&mut Self) -> PResult<T>) -> PResult<T> {
        self.enter_by(cost)?;
        let r = f(self);
        self.depth -= cost;
        r
    }

    // ---- errors -----------------------------------------------------------------------------

    fn describe(&self, index: usize) -> String {
        let t = &self.tokens[index.min(self.tokens.len() - 1)];
        if t.kind == TokenKind::Eof {
            "end of input".to_owned()
        } else {
            ParseError::quote_found(&self.src[t.start..t.end])
        }
    }

    /// Syntax error at the current token listing what was expected there.
    fn unexpected(&self) -> ParseError {
        let t = self.token(0);
        let expected = if self.expected_at == self.pos {
            self.expected.iter().map(|s| (*s).to_owned()).collect()
        } else {
            Vec::new()
        };
        ParseError::syntax(t.line, t.column, self.describe(self.pos), expected, None)
    }

    /// Syntax error at token `index` with an explanation.
    fn error_at(&self, index: usize, hint: &str) -> ParseError {
        let t = &self.tokens[index.min(self.tokens.len() - 1)];
        ParseError::syntax(
            t.line,
            t.column,
            self.describe(index),
            Vec::new(),
            Some(hint.to_owned()),
        )
    }

    // ---- statements -------------------------------------------------------------------------

    fn statement(&mut self) -> PResult<Statement> {
        const STARTS: [&str; 16] = [
            "FROM",
            "INSERT",
            "UPDATE",
            "UPSERT",
            "DELETE",
            "EXPLAIN",
            "CREATE",
            "ALTER",
            "DROP",
            "SHOW",
            "KILL",
            "BEGIN",
            "SAVEPOINT",
            "ROLLBACK",
            "RELEASE",
            "COMMIT",
        ];
        for kw in STARTS {
            self.note(kw);
        }
        let TokenKind::Word(w) = self.kind(0) else {
            return Err(self.unexpected());
        };
        match w.to_ascii_uppercase().as_str() {
            "FROM" => Ok(Statement::Query(self.query()?)),
            "INSERT" => self.insert(),
            "UPDATE" => self.update(),
            "UPSERT" => self.upsert(),
            "DELETE" => self.delete(),
            "EXPLAIN" => self.explain(),
            "CREATE" => self.create(),
            "ALTER" => self.alter(),
            "DROP" => self.drop_stmt(),
            "SHOW" => self.show(),
            "KILL" => self.kill(),
            "BEGIN" | "SAVEPOINT" | "ROLLBACK" | "RELEASE" | "COMMIT" => self.txn(),
            _ => Err(self.unexpected()),
        }
    }

    fn explain(&mut self) -> PResult<Statement> {
        self.expect_kw("EXPLAIN")?;
        let analyze = self.eat_kw("ANALYZE");
        for kw in ["FROM", "UPDATE", "DELETE"] {
            self.note(kw);
        }
        let statement = if self.is_kw(0, "FROM") {
            Statement::Query(self.query()?)
        } else if self.is_kw(0, "UPDATE") {
            self.update()?
        } else if self.is_kw(0, "DELETE") {
            self.delete()?
        } else {
            return Err(self.unexpected());
        };
        Ok(Statement::Explain {
            analyze,
            statement: Box::new(statement),
        })
    }
}
