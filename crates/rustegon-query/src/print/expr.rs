// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Canonical printing of expressions, literals, names and paths.
//!
//! Parentheses are emitted only where the parser would otherwise build a different tree:
//! precedence and non-associativity, lambdas/quantifiers (their body extends as far right as
//! possible) when an operator follows them, prefix `NOT` when a comparison-level or tighter
//! operator follows it (its operand would absorb it), `-(5)` (else it folds into the literal
//! `-5`), `(5).0` (else `5.0` is a float) and `x CONTAINS (any(…))`. Whatever needs parentheses here
//! also needed them in any text that parses to the same tree, so the canonical text never
//! nests deeper than the input it came from: the nesting limit accepts it again.

use std::fmt::Write as _;

use super::Printer;
use crate::{
    ast::{
        BinaryOp, Expr, IsTest, Literal, Path, Quantifier, Segment,
        expr::{PREC_ADDITIVE, PREC_COMPARISON, PREC_NOT},
        literal::{format_datetime, format_uuid},
    },
    parse::{is_bare_word, is_reserved},
};

/// Lambdas and quantifiers: their body extends as far right as possible.
const PREC_OPEN: u8 = 0;
const PREC_OR: u8 = 1;
const PREC_AND: u8 = 2;
const PREC_UNARY: u8 = 7;
pub(super) const PREC_POSTFIX: u8 = 8;

/// Precedence of the construct at the root of `e` (higher binds tighter).
fn precedence(e: &Expr) -> u8 {
    match e {
        Expr::Lambda { .. } | Expr::Quantified { .. } => PREC_OPEN,
        Expr::Or { .. } => PREC_OR,
        Expr::And { .. } => PREC_AND,
        Expr::Not { .. } => PREC_NOT,
        Expr::Binary { op, .. } => op.precedence(),
        Expr::Between { .. } | Expr::Is { .. } => PREC_COMPARISON,
        Expr::Neg { .. } => PREC_UNARY,
        _ => PREC_POSTFIX,
    }
}

impl Printer {
    /// Prints `e` as an operand requiring precedence `min`; `self.follow` is the binding power
    /// of what follows it (0: nothing that could be absorbed).
    ///
    /// Prefix constructs are parsed in any operand position (the parser reaches `unary` and
    /// `primary` at every level), so for them `min` is irrelevant: only what follows decides.
    /// A lambda/quantifier body takes everything, so any following operator needs
    /// parentheses; a `NOT` operand takes comparison-level and tighter operators (PD-033), so
    /// `(NOT a) = b` and `(NOT a).x` need them while `NOT a AND b` and `x + NOT a` do not.
    /// Binary/n-ary constructs need them exactly when they bind looser than `min`.
    pub(super) fn expr_min(&mut self, e: &Expr, min: u8) {
        let prec = precedence(e);
        let needs = match prec {
            PREC_OPEN => self.follow > 0,
            PREC_NOT => self.follow >= PREC_COMPARISON,
            _ => prec < min,
        };
        if needs {
            let saved = std::mem::replace(&mut self.follow, 0);
            self.out.push('(');
            self.expr_bare(e);
            self.out.push(')');
            self.follow = saved;
        } else {
            self.expr_bare(e);
        }
    }

    /// An operand followed by an unspecified operator or keyword (left operands, …): treated
    /// as the tightest possible follower.
    pub(super) fn operand(&mut self, e: &Expr, min: u8) {
        self.operand_before(e, min, PREC_POSTFIX);
    }

    /// An operand followed by an operator of binding power `follow`.
    fn operand_before(&mut self, e: &Expr, min: u8, follow: u8) {
        let saved = std::mem::replace(&mut self.follow, follow);
        self.expr_min(e, min);
        self.follow = saved;
    }

    /// A full expression in a delimited position (argument, element, clause).
    pub(super) fn expr(&mut self, e: &Expr) {
        let saved = std::mem::replace(&mut self.follow, 0);
        self.expr_min(e, 0);
        self.follow = saved;
    }

    /// Prints `e` (as [`Printer::expr_min`]) into a separate buffer, to inspect its text.
    fn render(&self, e: &Expr, min: u8) -> String {
        let mut sub = Printer {
            out: String::new(),
            follow: self.follow,
        };
        sub.expr_min(e, min);
        sub.out
    }

    /// An expression that must not start with `-` (projections: `-a` would be an exclusion).
    pub(super) fn expr_no_leading_minus(&mut self, e: &Expr) {
        let mut sub = Printer::default();
        sub.expr(e);
        if sub.out.starts_with('-') {
            self.out.push('(');
            self.out.push_str(&sub.out);
            self.out.push(')');
        } else {
            self.out.push_str(&sub.out);
        }
    }

    fn expr_bare(&mut self, e: &Expr) {
        match e {
            Expr::Literal(lit) => self.literal(lit),
            Expr::Param { name } => {
                self.out.push('$');
                self.out.push_str(name);
            }
            Expr::Path { path } => self.path(path),
            Expr::Access { base, path } => {
                // `5.0` would lex as a float: an integer base before a `.position` needs
                // parentheses (`5.x`, `5[0]`, `-5.x` are unambiguous).
                let int_then_position = matches!(**base, Expr::Literal(Literal::Int(_)))
                    && matches!(path.0.first(), Some(Segment::Position(_)));
                if int_then_position {
                    self.out.push('(');
                    self.expr(base);
                    self.out.push(')');
                } else {
                    self.operand(base, PREC_POSTFIX);
                }
                self.segments(&path.0);
            }
            Expr::Binary { op, left, right } => self.binary(*op, left, right),
            Expr::And { args } => self.nary(args, " AND ", PREC_AND + 1),
            Expr::Or { args } => self.nary(args, " OR ", PREC_OR + 1),
            Expr::Neg { expr } => {
                self.out.push('-');
                let text = self.render(expr, PREC_UNARY);
                if text.starts_with(|c: char| c.is_ascii_digit()) {
                    // `-(5)` stays a negation instead of folding into the literal `-5`.
                    self.out.push('(');
                    self.out.push_str(&text);
                    self.out.push(')');
                } else {
                    if text.starts_with('-') {
                        // `- -a`, never the line comment `--a`.
                        self.out.push(' ');
                    }
                    self.out.push_str(&text);
                }
            }
            Expr::Not { expr } => {
                self.out.push_str("NOT ");
                // The operand is a comparison-level expression (PD-033): `NOT a = b`.
                self.expr_min(expr, PREC_COMPARISON);
            }
            Expr::Between { expr, low, high } => {
                self.operand(expr, PREC_ADDITIVE);
                self.out.push_str(" BETWEEN ");
                // The `AND` of `BETWEEN` binds like the logical one: `x BETWEEN NOT a AND b`.
                self.operand_before(low, PREC_ADDITIVE, PREC_AND);
                self.out.push_str(" AND ");
                self.expr_min(high, PREC_ADDITIVE);
            }
            Expr::Is {
                expr,
                negated,
                test,
            } => {
                self.operand(expr, PREC_ADDITIVE);
                self.out
                    .push_str(if *negated { " IS NOT " } else { " IS " });
                self.out.push_str(match test {
                    IsTest::Null => "NULL",
                    IsTest::Missing => "MISSING",
                });
            }
            Expr::Call { name, args } => {
                self.out.push_str(name);
                self.out.push('(');
                self.list(args, Self::expr);
                self.out.push(')');
            }
            Expr::Star => self.out.push('*'),
            Expr::Extract { unit, expr } => {
                self.out.push_str("extract(");
                self.ident(unit);
                self.out.push_str(" FROM ");
                self.expr(expr);
                self.out.push(')');
            }
            _ => self.compound(e),
        }
    }

    fn binary(&mut self, op: BinaryOp, left: &Expr, right: &Expr) {
        let prec = op.precedence();
        let (lmin, rmin) = if prec == PREC_COMPARISON {
            (PREC_ADDITIVE, PREC_ADDITIVE)
        } else {
            (prec, prec + 1)
        };
        self.operand_before(left, lmin, prec);
        self.out.push(' ');
        self.out.push_str(op.symbol());
        self.out.push(' ');
        let text = self.render(right, rmin);
        // `x CONTAINS any(…)` would re-parse as `x CONTAINS ANY (…)`.
        let first_word = text
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next()
            .unwrap_or_default();
        let clash = op == BinaryOp::Contains
            && (first_word.eq_ignore_ascii_case("any") || first_word.eq_ignore_ascii_case("all"));
        if clash {
            self.out.push('(');
            self.out.push_str(&text);
            self.out.push(')');
        } else {
            self.out.push_str(&text);
        }
    }

    /// Bracketed and keyword-delimited constructs.
    fn compound(&mut self, e: &Expr) {
        match e {
            Expr::Case {
                operand,
                whens,
                otherwise,
            } => {
                self.out.push_str("CASE");
                if let Some(op) = operand {
                    self.out.push(' ');
                    self.expr(op);
                }
                for w in whens {
                    self.out.push_str(" WHEN ");
                    self.expr(&w.when);
                    self.out.push_str(" THEN ");
                    self.expr(&w.then);
                }
                if let Some(e) = otherwise {
                    self.out.push_str(" ELSE ");
                    self.expr(e);
                }
                self.out.push_str(" END");
            }
            Expr::Lambda { params, body } => {
                if let [single] = params.as_slice() {
                    self.ident(single);
                } else {
                    self.out.push('(');
                    self.list(params, |p, s| p.ident(s));
                    self.out.push(')');
                }
                self.out.push_str(" -> ");
                self.expr_min(body, 0);
            }
            Expr::Quantified {
                quantifier,
                var,
                source,
                predicate,
            } => {
                self.out.push_str(match quantifier {
                    Quantifier::Any => "ANY ",
                    Quantifier::Every => "EVERY ",
                });
                self.ident(var);
                self.out.push_str(" IN ");
                self.expr(source);
                self.out.push_str(" SATISFIES ");
                self.expr_min(predicate, 0);
            }
            Expr::ElemMatch { path, predicate } => {
                self.out.push_str("ELEM MATCH (");
                self.path(path);
                self.out.push_str(", ");
                self.expr(predicate);
                self.out.push(')');
            }
            Expr::Array { elements } => {
                self.out.push('[');
                self.list(elements, Self::expr);
                self.out.push(']');
            }
            Expr::Object { fields } => {
                self.out.push('{');
                self.list(fields, |p, f| {
                    if is_bare_word(&f.name) {
                        p.out.push_str(&f.name);
                    } else {
                        p.string(&f.name);
                    }
                    p.out.push_str(": ");
                    p.expr(&f.value);
                });
                self.out.push('}');
            }
            _ => {}
        }
    }

    /// `AND`/`OR` operands (`min` = the operator's precedence + 1): all but the last are
    /// followed by the operator, which a `NOT` operand does not absorb (`NOT a AND b`).
    fn nary(&mut self, args: &[Expr], sep: &str, min: u8) {
        for (i, a) in args.iter().enumerate() {
            if i + 1 < args.len() {
                self.operand_before(a, min, min - 1);
                self.out.push_str(sep);
            } else {
                self.expr_min(a, min);
            }
        }
    }

    pub(super) fn literal(&mut self, lit: &Literal) {
        match lit {
            Literal::Null => self.out.push_str("NULL"),
            Literal::Bool(true) => self.out.push_str("TRUE"),
            Literal::Bool(false) => self.out.push_str("FALSE"),
            Literal::Int(i) => {
                let _ = write!(self.out, "{i}");
            }
            // `{:?}` is the shortest text that parses back to the same bits and always has a
            // `.` or an exponent, so it re-lexes as a float.
            Literal::Float(f) => {
                let _ = write!(self.out, "{f:?}");
            }
            Literal::Decimal(d) => {
                let _ = write!(self.out, "{d}m");
            }
            Literal::String(s) => self.string(s),
            Literal::DateTime(ms) => {
                self.out.push_str("DATE ");
                self.string(&format_datetime(*ms));
            }
            Literal::ObjectId(oid) => {
                self.out.push_str("OID ");
                self.string(&oid.to_string());
            }
            Literal::Uuid(u) => {
                self.out.push_str("UUID ");
                self.string(&format_uuid(u));
            }
            Literal::Interval(s) => {
                self.out.push_str("INTERVAL ");
                self.string(s);
            }
        }
    }

    /// A string literal: `'` doubled, backslash and control characters escaped, so the text
    /// stays on one line.
    pub(super) fn string(&mut self, s: &str) {
        self.out.push('\'');
        for c in s.chars() {
            match c {
                '\'' => self.out.push_str("''"),
                '\\' => self.out.push_str("\\\\"),
                '\n' => self.out.push_str("\\n"),
                '\t' => self.out.push_str("\\t"),
                c if c.is_control() => {
                    let _ = write!(self.out, "\\u{{{:x}}}", u32::from(c));
                }
                c => self.out.push(c),
            }
        }
        self.out.push('\'');
    }

    /// An identifier where reserved words are not allowed bare.
    pub(super) fn ident(&mut self, name: &str) {
        if is_bare_word(name) && !is_reserved(name) {
            self.out.push_str(name);
        } else {
            self.quoted(name);
        }
    }

    /// A name after `.` (any word is allowed bare).
    pub(super) fn name(&mut self, name: &str) {
        if is_bare_word(name) {
            self.out.push_str(name);
        } else {
            self.quoted(name);
        }
    }

    pub(super) fn quoted(&mut self, name: &str) {
        self.out.push('`');
        self.out.push_str(&name.replace('`', "``"));
        self.out.push('`');
    }

    pub(super) fn path(&mut self, path: &Path) {
        let mut segs = path.0.iter();
        match segs.next() {
            Some(Segment::Field(root)) => self.ident(root),
            // Non-canonical (rejected by validation): print something that fails to parse
            // back rather than something that silently means another path.
            Some(other) => {
                self.out.push_str("``");
                self.segments(std::slice::from_ref(other));
            }
            None => {}
        }
        self.segments(segs.as_slice());
    }

    fn segments(&mut self, segs: &[Segment]) {
        for seg in segs {
            match seg {
                Segment::Field(f) => {
                    self.out.push('.');
                    self.name(f);
                }
                Segment::Position(p) => {
                    let _ = write!(self.out, ".{p}");
                }
                Segment::Index(e) => {
                    self.out.push('[');
                    self.expr(e);
                    self.out.push(']');
                }
                Segment::Each => self.out.push_str("[]"),
            }
        }
    }
}
