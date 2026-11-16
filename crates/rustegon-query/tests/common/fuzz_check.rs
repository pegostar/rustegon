// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Properties checked on arbitrary input by the cargo-fuzz targets (`fuzz/fuzz_targets/*`,
//! nightly) and by the stable smoke test `tc_ql_002_fuzz_smoke` (AC-QL-002, NFR-SEC-004).
//! The fuzz crate includes this file with `#[path]`, so both run exactly the same checks.
//!
//! Only the public API of `rustegon-query` is used. A violated property panics: libFuzzer
//! records the input as a crash, nextest reports a failure.

use rustegon_common::ErrorCode;
use rustegon_query::{
    Statement, parse_expr, parse_script, parse_statement, print_expr, print_script, print_statement,
};

/// `parse_statement` on arbitrary text: never panics; an accepted statement round-trips.
pub fn statement(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(stmt) = parse_statement(text) {
        statement_round_trip(text, &stmt);
    }
}

/// `parse_script` on arbitrary text: never panics; an accepted script round-trips.
pub fn script(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(stmts) = parse_script(text) {
        let printed = print_script(&stmts);
        let again = parse_script(&printed).unwrap_or_else(|e| {
            panic!("accepted script {text:?} but its canonical form {printed:?} fails: {e}")
        });
        assert_eq!(
            again, stmts,
            "script {text:?}: canonical {printed:?} differs"
        );
        for s in &stmts {
            statement_round_trip(text, s);
        }
    }
}

/// Every parser entry point on arbitrary text, with the round trip of whatever is accepted:
/// `parse(print(ast)) == ast`, the canonical text is a fixed point and the structured JSON
/// decodes to the same AST.
pub fn round_trip(data: &[u8]) {
    statement(data);
    script(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(e) = parse_expr(text) {
        let printed = print_expr(&e);
        let again = parse_expr(&printed).unwrap_or_else(|err| {
            panic!("accepted expression {text:?} but its canonical form {printed:?} fails: {err}")
        });
        assert_eq!(
            again, e,
            "expression {text:?}: canonical {printed:?} differs"
        );
        assert_eq!(
            print_expr(&again),
            printed,
            "canonical text is not a fixed point"
        );
    }
}

/// `Statement::from_json` on arbitrary text: never panics; an accepted AST re-encodes to an
/// equal AST and its canonical text parses back to it.
pub fn ast_json(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(stmt) = Statement::from_json(text) {
        let printed = print_statement(&stmt);
        let parsed = parse_statement(&printed).unwrap_or_else(|e| {
            panic!("validated JSON AST prints as {printed:?}, which fails: {e}")
        });
        assert_eq!(
            parsed, stmt,
            "validated JSON AST: canonical {printed:?} differs"
        );
        let json = stmt
            .to_json()
            .unwrap_or_else(|e| panic!("validated JSON AST does not re-encode: {e}"));
        let decoded = Statement::from_json(&json)
            .unwrap_or_else(|e| panic!("re-encoded JSON AST rejected: {e}\n{json}"));
        assert_eq!(decoded, stmt, "JSON AST re-encoding differs");
    }
}

fn statement_round_trip(text: &str, stmt: &Statement) {
    let printed = print_statement(stmt);
    let again = parse_statement(&printed).unwrap_or_else(|e| {
        panic!("accepted {text:?} but its canonical form {printed:?} fails: {e}")
    });
    assert_eq!(&again, stmt, "{text:?}: canonical {printed:?} differs");
    assert_eq!(
        print_statement(&again),
        printed,
        "canonical text is not a fixed point"
    );
    // Deep ASTs may exceed the JSON decoder's own nesting limit: RGN-1013, never a crash.
    let json = stmt
        .to_json()
        .unwrap_or_else(|e| panic!("{text:?}: parser output does not encode to JSON: {e}"));
    match Statement::from_json(&json) {
        Ok(decoded) => assert_eq!(&decoded, stmt, "{text:?}: JSON round trip differs"),
        Err(e) => assert_eq!(
            e.code(),
            ErrorCode::QueryTooComplex,
            "{text:?}: JSON of a parsed statement rejected: {e}"
        ),
    }
}
