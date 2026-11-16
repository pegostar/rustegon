// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Error catalog generation tests: `proto/errors.yaml` ⇄ generated `ErrorCode` ⇄ protocol.md §7.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;

#[path = "../build/codegen.rs"]
#[allow(dead_code, missing_docs)]
mod codegen;

use rustegon_common::{ErrorCode, GrpcCode, Retryable};

const CATALOG: &str = include_str!("../../../proto/errors.yaml");
const PROTOCOL_MD: &str = include_str!("../../../docs/specifications/protocol.md");

fn entries() -> Vec<codegen::Entry> {
    codegen::parse(CATALOG).expect("catalog must be valid")
}

#[test]
fn error_catalog_generated_enum_matches_yaml() {
    let entries = entries();
    assert_eq!(ErrorCode::ALL.len(), entries.len());
    for (e, code) in entries.iter().zip(ErrorCode::ALL) {
        assert_eq!(code.code(), e.code);
        assert_eq!(ErrorCode::from_code(e.code), Some(*code));
        assert_eq!(code.name(), e.name);
        assert_eq!(
            code.aliases(),
            e.aliases.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(code.is_internal(), e.internal);
        assert_eq!(codegen::GRPC_CODES[code.grpc_code() as usize], e.grpc);
        assert_eq!(code.http_status(), e.http);
        assert_eq!(code.retry_note(), e.retry_note.as_deref());
    }
    assert_eq!(ErrorCode::from_code(9999), None);
}

#[test]
fn error_catalog_spot_checks() {
    assert_eq!(ErrorCode::QueryTooComplex.aliases(), ["ScanNotAllowed"]);
    assert!(ErrorCode::NotLeaseholder.is_internal());
    assert_eq!(
        ErrorCode::CommitOutcomeUnknown.retryable(),
        Retryable::Conditional
    );
    assert_eq!(ErrorCode::StorageCorruption.grpc_code(), GrpcCode::DataLoss);
    assert_eq!(
        ErrorCode::WriteConcernTimeout.retry_note(),
        Some("committed=true")
    );
    assert_eq!(ErrorCode::RateLimited.http_status(), 429);
    assert_eq!(ErrorCode::NodeDraining.to_string(), "RGN-3004 NodeDraining");
}

/// Renders the catalog in the exact format of the protocol.md §7 table (docs table generator).
fn render_table(entries: &[codegen::Entry]) -> String {
    let mut out =
        String::from("| Code | Name | gRPC | HTTP | Retryable |\n|---|---|---|---|---|\n");
    for e in entries {
        let mut name = std::iter::once(e.name.as_str())
            .chain(e.aliases.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" / ");
        if e.internal {
            name.push_str(" (internal)");
        }
        let retry = match (e.retryable.as_str(), &e.retry_note) {
            ("conditional", Some(note)) => note.clone(),
            (kind, Some(note)) => format!("{kind} ({note})"),
            (kind, None) => kind.to_owned(),
        };
        let _ = writeln!(
            out,
            "| {} | {name} | {} | {} | {retry} |",
            e.code, e.grpc, e.http
        );
    }
    out
}

#[test]
fn error_catalog_protocol_md_table_in_sync() {
    let expected = render_table(&entries());
    let normalized = PROTOCOL_MD.replace("\r\n", "\n");
    assert!(
        normalized.contains(&expected),
        "protocol.md §7 table differs from proto/errors.yaml; expected table:\n{expected}"
    );
}

fn reject(yaml: &str, needle: &str) {
    let err = codegen::parse(yaml).expect_err("catalog must be rejected");
    assert!(
        err.contains(needle),
        "error `{err}` does not mention `{needle}`"
    );
}

const ENTRY_A: &str =
    "  - {code: 1001, name: A, grpc: INVALID_ARGUMENT, http: 400, retryable: \"no\"}\n";

#[test]
fn error_catalog_rejects_duplicate_or_descending_codes() {
    reject(
        &format!("version: 1\ncodes:\n{ENTRY_A}{ENTRY_A}"),
        "not ascending",
    );
}

#[test]
fn error_catalog_rejects_duplicate_names() {
    let b = ENTRY_A.replace("1001", "1002");
    reject(
        &format!("version: 1\ncodes:\n{ENTRY_A}{b}"),
        "duplicate name A",
    );
}

#[test]
fn error_catalog_rejects_invalid_fields() {
    let cases = [
        (ENTRY_A.replace("INVALID_ARGUMENT", "NOPE"), "`grpc`"),
        (ENTRY_A.replace("INVALID_ARGUMENT", "OK"), "`grpc`"),
        (ENTRY_A.replace("400", "200"), "`http`"),
        (ENTRY_A.replace("\"no\"", "\"conditional\""), "`retryable`"),
        (ENTRY_A.replace("\"no\"", "\"maybe\""), "`retryable`"),
        (ENTRY_A.replace("name: A", "name: lower"), "UpperCamelCase"),
        (ENTRY_A.replace("1001", "99"), "outside"),
    ];
    for (entry, needle) in cases {
        reject(&format!("version: 1\ncodes:\n{entry}"), needle);
    }
    reject(&format!("version: 2\ncodes:\n{ENTRY_A}"), "version");
    reject("version: 1\ncodes: []\n", "no codes");
}
