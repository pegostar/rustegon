// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-QL-001 (precedence part, query-language.md §4.1, PD-033): prefix `NOT` binds looser than
//! every comparison and predicate and tighter than `AND`, as in SQL. Each case checks that the
//! input parses to the same tree as its fully parenthesised reading, and that the canonical
//! printer emits the expected minimal text, which parses back to the same tree.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustegon_query::{ast::Expr, parse_expr, print_expr};

fn parse(text: &str) -> Expr {
    parse_expr(text).unwrap_or_else(|e| panic!("`{text}` must parse: {e}"))
}

/// `(input, explicit reading, canonical text)`.
const CASES: &[(&str, &str, &str)] = &[
    // Comparisons and predicates are inside the negation.
    ("NOT a = b", "NOT (a = b)", "NOT a = b"),
    ("NOT a != b", "NOT (a != b)", "NOT a != b"),
    ("NOT a < b + 1", "NOT (a < (b + 1))", "NOT a < b + 1"),
    ("NOT a == [1]", "NOT (a == [1])", "NOT a == [1]"),
    ("NOT a IN [1, 2]", "NOT (a IN [1, 2])", "NOT a IN [1, 2]"),
    ("NOT a NOT IN $l", "NOT (a NOT IN $l)", "NOT a NOT IN $l"),
    ("NOT a IS NULL", "NOT (a IS NULL)", "NOT a IS NULL"),
    (
        "NOT a IS NOT MISSING",
        "NOT (a IS NOT MISSING)",
        "NOT a IS NOT MISSING",
    ),
    (
        "NOT a BETWEEN 1 AND 2",
        "NOT (a BETWEEN 1 AND 2)",
        "NOT a BETWEEN 1 AND 2",
    ),
    ("NOT a LIKE 'x%'", "NOT (a LIKE 'x%')", "NOT a LIKE 'x%'"),
    ("NOT a ILIKE 'x%'", "NOT (a ILIKE 'x%')", "NOT a ILIKE 'x%'"),
    (
        "NOT a MATCHES '^x'",
        "NOT (a MATCHES '^x')",
        "NOT a MATCHES '^x'",
    ),
    ("NOT a CONTAINS 1", "NOT (a CONTAINS 1)", "NOT a CONTAINS 1"),
    (
        "NOT a CONTAINS ANY [1]",
        "NOT (a CONTAINS ANY [1])",
        "NOT a CONTAINS ANY [1]",
    ),
    ("NOT a.b[0] = 1", "NOT ((a.b[0]) = 1)", "NOT a.b[0] = 1"),
    ("NOT -a = 1", "NOT ((-a) = 1)", "NOT -a = 1"),
    // `AND` / `OR` stay outside.
    ("NOT x AND y", "(NOT x) AND y", "NOT x AND y"),
    ("NOT x OR y", "(NOT x) OR y", "NOT x OR y"),
    ("x AND NOT y", "x AND (NOT y)", "x AND NOT y"),
    (
        "NOT a = 1 AND NOT b = 2 OR c",
        "((NOT (a = 1)) AND (NOT (b = 2))) OR c",
        "NOT a = 1 AND NOT b = 2 OR c",
    ),
    (
        "NOT a BETWEEN 1 AND 2 AND b",
        "(NOT (a BETWEEN 1 AND 2)) AND b",
        "NOT a BETWEEN 1 AND 2 AND b",
    ),
    ("NOT (x AND y)", "NOT (x AND y)", "NOT (x AND y)"),
    // Double negation nests.
    ("NOT NOT a", "NOT (NOT a)", "NOT NOT a"),
    ("NOT NOT a = b", "NOT (NOT (a = b))", "NOT NOT a = b"),
    // Negated operand of a comparison needs parentheses.
    ("(NOT a) = b", "(NOT a) = b", "(NOT a) = b"),
    ("(NOT a) IS NULL", "(NOT a) IS NULL", "(NOT a) IS NULL"),
    ("(NOT a).x", "(NOT a).x", "(NOT a).x"),
    ("(NOT a) + 1 = 2", "((NOT a) + 1) = 2", "(NOT a) + 1 = 2"),
    // As a prefix in an operand position it extends as far as a comparison (PostgreSQL).
    ("x = NOT a", "x = (NOT a)", "x = NOT a"),
    ("x = NOT a AND y", "(x = (NOT a)) AND y", "x = NOT a AND y"),
    ("x + NOT a = b", "x + (NOT (a = b))", "x + NOT a = b"),
    ("(x + NOT a) = b", "(x + (NOT a)) = b", "x + (NOT a) = b"),
    ("-NOT a", "-(NOT a)", "-NOT a"),
    ("-(NOT a) * 2", "(-(NOT a)) * 2", "-(NOT a) * 2"),
    (
        "x BETWEEN NOT a AND b",
        "x BETWEEN (NOT a) AND b",
        "x BETWEEN NOT a AND b",
    ),
    (
        "x BETWEEN (NOT a = 1) AND b",
        "x BETWEEN (NOT (a = 1)) AND b",
        "x BETWEEN NOT a = 1 AND b",
    ),
    ("[NOT a = 1, b]", "[(NOT (a = 1)), b]", "[NOT a = 1, b]"),
    ("f(NOT a IN $l)", "f(NOT (a IN $l))", "f(NOT a IN $l)"),
    // Lambdas and quantifiers still take everything.
    (
        "ANY x IN a SATISFIES NOT x = 1 AND y",
        "ANY x IN a SATISFIES ((NOT (x = 1)) AND y)",
        "ANY x IN a SATISFIES NOT x = 1 AND y",
    ),
];

#[test]
fn tc_ql_001_not_binds_looser_than_comparisons_and_tighter_than_and() {
    for &(input, explicit, canonical) in CASES {
        let tree = parse(input);
        assert_eq!(tree, parse(explicit), "`{input}` must read as `{explicit}`");
        let printed = print_expr(&tree);
        assert_eq!(printed, canonical, "canonical text of `{input}`");
        assert_eq!(parse(&printed), tree, "`{printed}` must parse back");
    }
}

#[test]
fn tc_ql_001_not_does_not_change_comparison_non_associativity() {
    // `NOT` does not make a chain of comparisons acceptable.
    for text in ["NOT a = b = c", "(NOT a) = b = c", "NOT a < b IS NULL"] {
        assert!(parse_expr(text).is_err(), "`{text}` must be rejected");
    }
}
