// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Parser robustness (AC-QL-002 stand-in until a `cargo fuzz` target can run in CI; TC-QL-002
//! error behaviour): arbitrary, token-soup and mutated inputs never panic, every accepted input
//! round-trips through the canonical printer, and the nesting/size limits turn pathological
//! input into `RGN-1013` instead of a stack overflow — checked on a 2 MiB thread stack, the
//! default for Rust threads and tokio workers, in debug builds.
//!
//! Case count: `RGQL_FUZZ_CASES` (default 3000 per property).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use proptest::{collection::vec, prelude::*, sample::select, test_runner::Config};
use rustegon_common::ErrorCode;
use rustegon_query::{
    Statement,
    ast::AstError,
    parse::{MAX_NESTING_DEPTH, MAX_QUERY_BYTES},
    parse_expr, parse_script, parse_statement, print_statement,
};

const DEFAULT_CASES: u32 = 3000;
/// Stack of the threads running the deep-input checks (Rust/tokio default).
const STACK: usize = 2 * 1024 * 1024;

fn cases() -> u32 {
    std::env::var("RGQL_FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CASES)
}

/// Any accepted text must print canonically and parse back to the same AST.
fn check_accepted(text: &str) {
    if let Ok(stmts) = parse_script(text) {
        for s in &stmts {
            let printed = print_statement(s);
            let again = parse_statement(&printed).unwrap_or_else(|e| {
                panic!("accepted `{text}` but its canonical `{printed}` fails: {e}")
            });
            assert_eq!(
                &again, s,
                "accepted `{text}`, canonical `{printed}` differs"
            );
        }
    }
    let _ = parse_expr(text);
}

const VOCAB: &[&str] = &[
    "FROM",
    "t",
    "db.c",
    "WHERE",
    "SELECT",
    "VALUE",
    "AS",
    "GROUP BY",
    "ORDER BY",
    "LIMIT",
    "OFFSET",
    "HAVING",
    "INCLUDE",
    "OPTIONS",
    "LOOKUP",
    "ON",
    "INTO",
    "|>",
    "MATCH",
    "PROJECT",
    "UNWIND",
    "SORT",
    "FACET",
    "AND",
    "OR",
    "NOT",
    "IN",
    "IS",
    "NULL",
    "MISSING",
    "BETWEEN",
    "CONTAINS",
    "ANY",
    "ALL",
    "EVERY",
    "SATISFIES",
    "CASE",
    "WHEN",
    "THEN",
    "ELSE",
    "END",
    "ELEM MATCH",
    "INSERT INTO",
    "UPDATE",
    "SET",
    "UNSET",
    "INC",
    "BY",
    "PUSH",
    "DELETE",
    "UPSERT",
    "RETURNING",
    "NEW",
    "CREATE",
    "INDEX",
    "TABLE",
    "BEGIN",
    "COMMIT",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ",",
    ";",
    ":",
    ".",
    "*",
    "+",
    "-",
    "/",
    "%",
    "=",
    "==",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "||",
    "->",
    "x",
    "a.b",
    "`q`",
    "'s'",
    "''",
    "1",
    "-2",
    "3.5",
    "4m",
    "$p",
    "$1",
    "DATE '2026-01-01'",
    "OID '507f1f77bcf86cd799439011'",
    "count(*)",
    "f(",
    "now()",
    "--c\n",
    "/*c*/",
];

proptest! {
    #![proptest_config(Config { cases: cases(), ..Config::default() })]

    #[test]
    fn tc_ql_002_robust_arbitrary_text_never_panics(text in "\\PC{0,200}") {
        check_accepted(&text);
    }

    #[test]
    fn tc_ql_002_robust_arbitrary_bytes_never_panic(chars in vec(any::<char>(), 0..120)) {
        check_accepted(&String::from_iter(chars));
    }

    #[test]
    fn tc_ql_002_robust_token_soup_never_panics(words in vec(select(VOCAB), 0..40)) {
        check_accepted(&words.join(" "));
    }

    #[test]
    fn tc_ql_002_robust_mutated_golden_inputs(
        case in 0usize..1000,
        edits in vec((any::<prop::sample::Index>(), 0usize..4, select(VOCAB)), 1..4),
    ) {
        let corpus = common::golden::load("grammar.rgql");
        let mut text = corpus[case % corpus.len()].input.clone();
        for (at, kind, word) in edits {
            let boundaries: Vec<usize> = (0..=text.len()).filter(|i| text.is_char_boundary(*i)).collect();
            let i = boundaries[at.index(boundaries.len())];
            let j = boundaries[(at.index(boundaries.len()) + 3).min(boundaries.len() - 1)];
            match kind {
                0 => text.replace_range(i..j, ""),
                1 => text.insert_str(i, word),
                2 => text.replace_range(i..j, word),
                _ => { let dup = text[i..j].to_owned(); text.insert_str(i, &dup); }
            }
        }
        check_accepted(&text);
    }
}

/// Runs `f` on a thread with the default 2 MiB stack.
fn on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

/// One generator per recursive construct: `n` levels of nesting.
/// A named generator of `n`-level nested input.
type Construct = (&'static str, fn(usize) -> String);

fn constructs() -> Vec<Construct> {
    vec![
        ("parens", |n| {
            format!("FROM t WHERE {}a{}", "(".repeat(n), ")".repeat(n))
        }),
        ("arrays", |n| {
            format!("FROM t SELECT VALUE {}1{}", "[".repeat(n), "]".repeat(n))
        }),
        ("objects", |n| {
            format!("FROM t SELECT VALUE {}1{}", "{a: ".repeat(n), "}".repeat(n))
        }),
        ("negations", |n| {
            format!("FROM t SELECT VALUE {}a", "- ".repeat(n))
        }),
        ("nots", |n| format!("FROM t WHERE {}a", "NOT ".repeat(n))),
        ("calls", |n| {
            format!("FROM t SELECT VALUE {}a{}", "f(".repeat(n), ")".repeat(n))
        }),
        ("indexes", |n| {
            format!("FROM t SELECT VALUE a{}{}", "[b".repeat(n), "]".repeat(n))
        }),
        ("lambdas", |n| {
            format!("FROM t SELECT VALUE {}1", "x -> ".repeat(n))
        }),
        ("cases", |n| {
            format!(
                "FROM t SELECT VALUE {}1{}",
                "CASE WHEN a THEN ".repeat(n),
                " END".repeat(n)
            )
        }),
        ("quantifiers", |n| {
            format!("FROM t WHERE {}p", "ANY x IN a SATISFIES ".repeat(n))
        }),
        ("operator chain", |n| {
            format!("FROM t SELECT VALUE {}", vec!["a"; n + 1].join(" + "))
        }),
        ("subqueries", |n| {
            format!("{}FROM t{}", "FROM (".repeat(n), ")".repeat(n))
        }),
        ("facets", |n| {
            format!(
                "FROM t |> {}MATCH a{}",
                "FACET f (".repeat(n),
                ")".repeat(n)
            )
        }),
        ("unions", |n| {
            format!(
                "FROM t{}{}",
                " |> UNION WITH (FROM t".repeat(n),
                ")".repeat(n)
            )
        }),
    ]
}

/// Largest `n` in `0..=max` for which `make(n)` parses (parsing is monotone in `n`).
fn deepest_accepted(make: fn(usize) -> String, max: usize) -> usize {
    let (mut lo, mut hi) = (0, max);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if parse_statement(&make(mid)).is_ok() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

#[test]
fn tc_ql_002_robust_limits_hold_on_a_2mib_stack() {
    on_small_stack(|| {
        let limit = usize::try_from(MAX_NESTING_DEPTH).unwrap();
        for (name, make) in constructs() {
            let n = deepest_accepted(make, 2 * limit);
            assert!(n >= 4, "{name}: only {n} levels accepted");
            assert!(n < 2 * limit, "{name}: limit not reached");
            // The deepest accepted input is printed, re-parsed, serialized and dropped.
            let stmt = parse_statement(&make(n)).unwrap();
            let printed = print_statement(&stmt);
            assert_eq!(parse_statement(&printed).unwrap(), stmt, "{name}");
            let json = stmt.to_json().unwrap();
            drop(stmt);
            // Deep JSON may exceed the JSON decoder's own nesting limit: an error, not a crash.
            let _ = Statement::from_json(&json);
            // One level more is RGN-1013, and so is a huge input.
            for depth in [n + 1, 100_000] {
                let err = parse_statement(&make(depth)).unwrap_err();
                assert_eq!(err.code(), ErrorCode::QueryTooComplex, "{name} at {depth}");
            }
        }
    });
}

#[test]
fn tc_ql_002_robust_long_flat_lists_are_not_limited() {
    on_small_stack(|| {
        let ands = vec!["a = 1"; 50_000].join(" AND ");
        let stmt = parse_statement(&format!("FROM t WHERE {ands}")).unwrap();
        let printed = print_statement(&stmt);
        assert_eq!(parse_statement(&printed).unwrap(), stmt);
        let items = vec!["1"; 50_000].join(", ");
        parse_statement(&format!("FROM t WHERE a IN [{items}]")).unwrap();
    });
}

#[test]
fn tc_ql_002_robust_deep_json_is_rejected_not_crashing() {
    on_small_stack(|| {
        let mut json = String::from(r#"{"kind":"literal","value":1}"#);
        for _ in 0..10_000 {
            json = format!(r#"{{"kind":"neg","expr":{json}}}"#);
        }
        let stmt = format!(
            r#"{{"kind":"query","from":{{"source":{{"kind":"collection","name":"t"}}}},"where":{json}}}"#
        );
        let err = Statement::from_json(&stmt).unwrap_err();
        assert!(matches!(err, AstError::TooComplex(_)), "{err}");
        assert_eq!(err.code(), ErrorCode::QueryTooComplex);
    });
}

#[test]
fn tc_ql_002_robust_oversized_text_is_too_complex() {
    let text = format!("FROM t WHERE a = '{}'", "x".repeat(MAX_QUERY_BYTES));
    assert_eq!(
        parse_statement(&text).unwrap_err().code(),
        ErrorCode::QueryTooComplex
    );
}
