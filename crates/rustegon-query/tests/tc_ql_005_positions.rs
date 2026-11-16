// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-QL-005: syntax errors report the correct line/column (AC-QL-005, corpus ≥ 200 queries).
//!
//! Two corpora:
//! - hand-written: `tests/golden/error_positions.rgql`, the error position is marked `@@`
//!   (multi-line inputs, comments, tabs, non-ASCII text before the error, lexer errors, limits);
//! - generated: every golden query of TC-QL-001 with a `)` inserted right after each token that
//!   must be followed by an operand or item (`,` operators `WHERE` `AND` `BY` `|>` …), where a
//!   `)` is never valid, so the error must be reported exactly at the inserted `)`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::golden;
use rustegon_query::{
    ParseError,
    parse::{TokenKind, tokenize},
    parse_script,
};

const MIN_CORPUS: usize = 200;

/// 1-based line and column (Unicode scalar values) of byte offset `at`.
fn position(text: &str, at: usize) -> (u32, u32) {
    let before = &text[..at];
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    (u32::try_from(line).unwrap(), u32::try_from(col).unwrap())
}

fn assert_error_at(name: &str, text: &str, expected: (u32, u32)) {
    let err = parse_script(text)
        .err()
        .unwrap_or_else(|| panic!("`{name}` parses but must fail:\n{text}"));
    assert_eq!(
        err.position(),
        expected,
        "`{name}`: wrong position for {err}\n{text}"
    );
}

fn marked_corpus() -> Vec<(String, String, (u32, u32))> {
    golden::load("error_positions.rgql")
        .into_iter()
        .map(|c| {
            let at = c
                .input
                .find("@@")
                .unwrap_or_else(|| panic!("case `{}` has no @@ marker", c.name));
            let text = c.input.replacen("@@", "", 1);
            let pos = position(&text, at);
            (c.name, text, pos)
        })
        .collect()
}

/// Tokens after which an operand/item is mandatory, so an inserted `)` is an error right there.
fn requires_operand(prev: Option<&TokenKind>, kind: &TokenKind) -> bool {
    match kind {
        TokenKind::Comma
        | TokenKind::Eq
        | TokenKind::EqEq
        | TokenKind::Ne
        | TokenKind::Lt
        | TokenKind::Le
        | TokenKind::Gt
        | TokenKind::Ge
        | TokenKind::Plus
        | TokenKind::Minus
        | TokenKind::Slash
        | TokenKind::Percent
        | TokenKind::Concat
        | TokenKind::Arrow
        | TokenKind::Pipe => true,
        // `count(*)` and `a.*` end with `*`.
        TokenKind::Star => !matches!(prev, Some(TokenKind::LParen | TokenKind::Dot)),
        TokenKind::Word(w) => [
            "WHERE", "HAVING", "LIMIT", "OFFSET", "AND", "OR", "THEN", "ELSE", "WHEN", "BY",
            "SELECT",
        ]
        .iter()
        .any(|k| k.eq_ignore_ascii_case(w)),
        _ => false,
    }
}

fn generated_corpus() -> Vec<(String, String, (u32, u32))> {
    let mut out = Vec::new();
    for case in golden::load("grammar.rgql") {
        let tokens = tokenize(&case.input).unwrap();
        let mut prev = None;
        for (i, t) in tokens.iter().enumerate() {
            if requires_operand(prev, &t.kind) {
                let text = format!("{}){}", &case.input[..t.end], &case.input[t.end..]);
                out.push((
                    format!("{}#{i}", case.name),
                    text,
                    position(&case.input, t.end),
                ));
            }
            prev = Some(&t.kind);
        }
    }
    out
}

#[test]
fn tc_ql_005_marked_corpus_positions() {
    for (name, text, pos) in marked_corpus() {
        assert_error_at(&name, &text, pos);
    }
}

#[test]
fn tc_ql_005_generated_corpus_positions() {
    let corpus = generated_corpus();
    for (name, text, pos) in &corpus {
        assert_error_at(name, text, *pos);
    }
}

#[test]
fn tc_ql_005_corpus_has_at_least_200_queries() {
    let (marked, generated) = (marked_corpus().len(), generated_corpus().len());
    let total = marked + generated;
    eprintln!("TC-QL-005 corpus: {marked} hand-written + {generated} generated = {total}");
    assert!(total >= MIN_CORPUS, "only {total} erroneous queries");
}

#[test]
fn tc_ql_005_lexer_and_parser_errors_share_the_position_model() {
    // Column counts scalar values: `é` is one column although two bytes.
    let err = parse_script("FROM t WHERE x = 'é' #").unwrap_err();
    assert_eq!(err.position(), (1, 22));
    let ParseError::Syntax { found, .. } = err else {
        panic!("syntax error expected");
    };
    assert_eq!(found, "\"#\"");
    // CRLF line breaks: the `\r` is whitespace, lines are counted on `\n`.
    let err = parse_script("FROM t\r\nWHERE\r\n  )").unwrap_err();
    assert_eq!(err.position(), (3, 3));
}
