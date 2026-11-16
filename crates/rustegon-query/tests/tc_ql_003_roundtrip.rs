// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-QL-003: AST round trip (query-language.md §13, AC-QL-003): for generated canonical ASTs,
//! `parse(print(ast)) == ast`, the printed text is a fixed point, and the structured JSON form
//! decodes (with validation) to the identical AST.
//!
//! Case count: `RGQL_ROUNDTRIP_CASES` (default 2000 for the regular run; the acceptance run
//! uses 100000: `RGQL_ROUNDTRIP_CASES=100000 cargo nextest run -p rustegon-query tc_ql_003`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use proptest::{prelude::*, test_runner::Config};
use rustegon_query::{Statement, parse_expr, parse_statement, print_expr, print_statement};

const DEFAULT_CASES: u32 = 2000;

fn cases() -> u32 {
    std::env::var("RGQL_ROUNDTRIP_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CASES)
}

proptest! {
    #![proptest_config(Config { cases: cases(), ..Config::default() })]

    #[test]
    fn tc_ql_003_statement_round_trip(stmt in common::arb::statement()) {
        let text = print_statement(&stmt);
        let parsed = parse_statement(&text)
            .unwrap_or_else(|e| panic!("printed text does not parse: {e}\n{text}\n{stmt:#?}"));
        prop_assert_eq!(&parsed, &stmt, "parse(print(ast)) != ast for `{}`", text);
        prop_assert_eq!(print_statement(&parsed), text.clone());
        let json = stmt.to_json().unwrap();
        let decoded = Statement::from_json(&json)
            .unwrap_or_else(|e| panic!("JSON rejected: {e}\n{json}"));
        prop_assert_eq!(decoded, stmt);
    }

    #[test]
    fn tc_ql_003_expression_round_trip(e in common::arb::expr()) {
        let text = print_expr(&e);
        let parsed = parse_expr(&text)
            .unwrap_or_else(|err| panic!("printed text does not parse: {err}\n{text}\n{e:#?}"));
        prop_assert_eq!(parsed, e, "parse(print(e)) != e for `{}`", text);
    }
}
