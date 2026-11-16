// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-QL-002: error message golden tests (query-language.md §14, §15): the full message of
//! `RGN-1010 QuerySyntaxError {line, column, found, expected[]}` and `RGN-1013 QueryTooComplex`
//! for a corpus of invalid inputs (`tests/golden/errors.rgql`, bless with `RGQL_BLESS=1`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::golden;
use rustegon_common::ErrorCode;
use rustegon_query::{ParseError, parse_script};

const FILE: &str = "errors.rgql";

fn render(e: &ParseError) -> String {
    format!("{}: {e}", e.code())
}

#[test]
fn tc_ql_002_error_messages_match_goldens() {
    let cases = golden::load(FILE);
    let produced: Vec<_> = cases
        .iter()
        .map(|c| {
            let err = parse_script(&c.input)
                .err()
                .unwrap_or_else(|| panic!("case `{}` unexpectedly parses", c.name));
            vec![("error".to_owned(), render(&err))]
        })
        .collect();
    let failures = golden::check(FILE, &cases, &produced);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn tc_ql_002_error_converts_to_common_error_with_details() {
    let err = parse_script("FROM t WHERE").unwrap_err();
    assert_eq!(err.code(), ErrorCode::QuerySyntaxError);
    let common = err.into_error();
    assert_eq!(common.code(), ErrorCode::QuerySyntaxError);
    let d = common.details();
    assert_eq!(d.get("line").map(String::as_str), Some("1"));
    assert_eq!(d.get("column").map(String::as_str), Some("13"));
    assert_eq!(d.get("found").map(String::as_str), Some("end of input"));
    assert!(d.get("expected").is_some_and(|e| e.contains("expression")));
}

#[test]
fn tc_ql_002_too_complex_is_rgn_1013() {
    let deep = format!("FROM t WHERE {}a{}", "(".repeat(500), ")".repeat(500));
    let err = parse_script(&deep).unwrap_err();
    assert_eq!(err.code(), ErrorCode::QueryTooComplex);
    assert_eq!(err.into_error().code(), ErrorCode::QueryTooComplex);
}

#[test]
fn tc_ql_002_found_is_truncated_for_long_tokens() {
    let long = format!("FROM t LIMIT 5 '{}'", "x".repeat(1000));
    let ParseError::Syntax { found, .. } = parse_script(&long).unwrap_err() else {
        panic!("expected a syntax error");
    };
    assert!(found.chars().count() < 40, "{found}");
}
