// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Canonical RGQL printer (query-language.md §13: `parse(print(ast)) == ast`, and
//! `print(parse(text))` is the canonical text).
//!
//! Canonical form: one line; keywords upper-case; single spaces; `, ` between list items;
//! defaults omitted (`ASC`); optional clauses in grammar order; identifiers bare unless reserved
//! or not `[A-Za-z_][A-Za-z0-9_]*` (then back-quoted); strings single-quoted with `''` for a
//! quote and backslash escapes for `\`, newline, tab and other control characters.

mod expr;
mod query;
mod stmt;

use crate::ast::{Expr, Statement};

/// Prints a statement in canonical form (no trailing `;`).
#[must_use]
pub fn print_statement(stmt: &Statement) -> String {
    let mut p = Printer::default();
    p.statement(stmt);
    p.out
}

/// Prints a script: each statement followed by `;`, one per line.
#[must_use]
pub fn print_script(stmts: &[Statement]) -> String {
    let mut out = String::new();
    for s in stmts {
        out.push_str(&print_statement(s));
        out.push_str(";\n");
    }
    out
}

/// Prints an expression in canonical form.
#[must_use]
pub fn print_expr(e: &Expr) -> String {
    let mut p = Printer::default();
    p.expr(e);
    p.out
}

/// Output buffer.
#[derive(Default)]
struct Printer {
    out: String,
    /// Binding power of the tightest operator (or postfix segment) that directly follows the
    /// expression being printed; 0 when a delimiter or the end follows. Prefix constructs that
    /// extend to the right (lambdas, quantifiers, `NOT`) are parenthesised when it would be
    /// absorbed into them.
    follow: u8,
}

impl Printer {
    /// Prints items separated by `, `.
    fn list<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) {
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                self.out.push_str(", ");
            }
            f(self, item);
        }
    }

    /// Appends ` KEYWORD ` style text.
    fn kw(&mut self, text: &str) {
        self.out.push_str(text);
    }
}
