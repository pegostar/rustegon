// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-QL-004 (parsing part; AC-QL-004): parameters are accepted everywhere a literal is, and
//! hostile text inside string literals or parameters never changes the structure of a query.
//! Binding parameter values to types is the binder's part of TC-QL-004 (later milestone).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::golden;
use rustegon_query::{
    Statement,
    ast::{Expr, Literal, Query, Select},
    parse::{TokenKind, tokenize},
    parse_script, parse_statement, print_statement,
};

fn param_count(stmts: &[Statement]) -> usize {
    stmts
        .iter()
        .map(|s| s.to_json().unwrap().matches(r#""kind":"param""#).count())
        .sum()
}

/// Byte spans of the literal tokens of `text` that sit in expression position.
fn literal_spans(text: &str) -> Vec<(usize, usize)> {
    let tokens = tokenize(text).unwrap();
    let mut spans = Vec::new();
    for (i, t) in tokens.iter().enumerate() {
        let prev = i.checked_sub(1).map(|p| &tokens[p].kind);
        let next = tokens.get(i + 1).map(|n| &n.kind);
        let word = |k: Option<&TokenKind>, w: &str| matches!(k, Some(TokenKind::Word(x)) if x.eq_ignore_ascii_case(w));
        let typed_prefix = ["DATE", "OID", "UUID", "INTERVAL"]
            .iter()
            .any(|w| word(prev, w));
        match &t.kind {
            // `a.0` is a path position, not a literal.
            TokenKind::Number { .. } if !matches!(prev, Some(TokenKind::Dot)) => {
                spans.push((t.start, t.end));
            }
            // Object keys (`{'b c': 2}`) are names; the text of a typed literal is replaced
            // together with its keyword below.
            TokenKind::Str(_) if !matches!(next, Some(TokenKind::Colon)) && !typed_prefix => {
                spans.push((t.start, t.end));
            }
            TokenKind::Str(_) if typed_prefix => spans.push((tokens[i - 1].start, t.end)),
            TokenKind::Word(w)
                if ["TRUE", "FALSE", "NULL"]
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(w))
                    && !word(prev, "IS")
                    && !word(prev, "NOT") =>
            {
                spans.push((t.start, t.end));
            }
            _ => {}
        }
    }
    spans
}

#[test]
fn tc_ql_004_every_literal_position_accepts_a_parameter() {
    let mut checked = 0;
    for case in golden::load("grammar.rgql") {
        let base = param_count(&parse_script(&case.input).unwrap());
        for (start, end) in literal_spans(&case.input) {
            for param in ["$p", "$1"] {
                let text = format!("{}{param}{}", &case.input[..start], &case.input[end..]);
                let stmts = parse_script(&text).unwrap_or_else(|e| {
                    panic!(
                        "`{}`: parameter rejected in a literal position: {e}\n{text}",
                        case.name
                    )
                });
                assert_eq!(param_count(&stmts), base + 1, "`{}`: {text}", case.name);
                checked += 1;
            }
        }
    }
    assert!(checked >= 300, "only {checked} literal positions checked");
}

#[test]
fn tc_ql_004_parameter_forms() {
    let q = parse_statement("FROM t WHERE a = $name AND b = $_x1 AND c = $1 AND d = $42").unwrap();
    let json = q.to_json().unwrap();
    for name in ["name", "_x1", "1", "42"] {
        assert!(
            json.contains(&format!(r#"{{"kind":"param","name":"{name}"}}"#)),
            "{json}"
        );
    }
    // A parameter ends at the first non-identifier character: nothing can be smuggled in.
    assert!(parse_statement("FROM t WHERE a = $x'--").is_err());
    assert!(parse_statement("FROM t WHERE a = $1x").is_err());
    assert!(parse_statement("FROM t WHERE a = $0").is_err());
}

const PAYLOADS: &[&str] = &[
    "' OR 1=1 --",
    "'; DROP DATABASE shop; --",
    "x' OR 'a'='a",
    "*/ OR /* ",
    "-- comment",
    "/* block */",
    "\\' OR \\'1\\'=\\'1",
    "$1",
    "$name",
    "|> OUT INTO shop.stolen",
    ") OR (1 = 1",
    "] , [",
    "} , {",
    "`quoted`",
    "line1\nline2 -- x\n",
    "tab\there",
    "\u{0}\u{1b}[31m",
    "café ‖ || ->",
    "''''",
    "\\",
    "\\n is not a newline here",
];

fn template(value: Literal) -> Statement {
    let mut q = Query::from_source(rustegon_query::ast::Source::Collection(
        rustegon_query::ast::QualifiedName::new(Some("shop"), "users"),
    ));
    q.filter = Some(Expr::And {
        args: vec![
            Expr::Binary {
                op: rustegon_query::ast::BinaryOp::Eq,
                left: Box::new(Expr::Path {
                    path: rustegon_query::ast::Path::fields(["name"]),
                }),
                right: Box::new(Expr::Literal(value)),
            },
            Expr::Binary {
                op: rustegon_query::ast::BinaryOp::Eq,
                left: Box::new(Expr::Path {
                    path: rustegon_query::ast::Path::fields(["tenant"]),
                }),
                right: Box::new(Expr::Param { name: "t".into() }),
            },
        ],
    });
    q.select = Some(Select::Star);
    Statement::Query(q)
}

#[test]
fn tc_ql_004_injection_payloads_in_strings_never_change_structure() {
    for payload in PAYLOADS {
        let stmt = template(Literal::String((*payload).to_owned()));
        let text = print_statement(&stmt);
        let parsed = parse_statement(&text)
            .unwrap_or_else(|e| panic!("payload {payload:?} broke the text: {e}\n{text}"));
        assert_eq!(
            parsed, stmt,
            "payload {payload:?} changed the structure: {text}"
        );
        // The same through the structured form.
        let decoded = Statement::from_json(&stmt.to_json().unwrap()).unwrap();
        assert_eq!(decoded, stmt);
    }
}

#[test]
fn tc_ql_004_hand_written_literals_keep_operators_and_comments_as_text() {
    for (text, value) in [
        (
            "FROM t WHERE a = 'it''s -- not a comment'",
            "it's -- not a comment",
        ),
        (
            "FROM t WHERE a = '/* not a comment */'",
            "/* not a comment */",
        ),
        ("FROM t WHERE a = '\\' OR 1 = 1 --'", "' OR 1 = 1 --"),
        ("FROM t WHERE a = '; DELETE FROM t'", "; DELETE FROM t"),
        ("FROM t WHERE a = '$1 |> OUT INTO x'", "$1 |> OUT INTO x"),
    ] {
        let stmt = parse_statement(text).unwrap();
        let Statement::Query(q) = &stmt else {
            panic!("query expected")
        };
        let Some(Expr::Binary { right, .. }) = &q.filter else {
            panic!("binary filter expected for {text}")
        };
        assert_eq!(
            **right,
            Expr::Literal(Literal::String(value.to_owned())),
            "{text}"
        );
    }
}
