// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Conformance and integration tests of the Rust driver (FR-DRV-005, rust-driver.md §11).
//!
//! One test binary: the shared vectors (TC-DRV-RS-001…006), the retry scenarios on the
//! in-process fake server (TC-DRV-RS-016), the real-server tests (TC-DRV-RS-007…015) and the
//! conformance runner over `drivers/conformance/*/*.yaml` (TC-DRV-RS-020), which writes the
//! AC-DRV-003 results file.

// Test harness code (coding-standards.md §3.1 lets tests panic): the pedantic naming and
// style lints add noise to a port of the shared runner without catching defects.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::unused_self,
    clippy::assigning_clones,
    clippy::single_match_else,
    clippy::print_stdout,
    clippy::items_after_statements,
    clippy::format_push_string,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::cast_possible_truncation,
    missing_docs
)]

mod checks;
mod dsl;
mod fake;
mod fixture;
mod integration;
mod runner;
mod suite;
mod yaml;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tc_drv_rs_020_conformance_suite() {
    let (passed, failed, skipped, failures) = suite::run_suite().await;
    eprintln!("conformance: {passed} passed, {failed} failed, {skipped} skipped");
    assert!(
        failures.is_empty(),
        "conformance failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn tc_drv_rs_001_codec_vectors() {
    for f in [
        "codec/values.yaml",
        "codec/documents.yaml",
        "codec/invalid.yaml",
    ] {
        checks::codec_vectors(f).unwrap();
    }
}

#[test]
fn tc_drv_rs_003_scram_vectors() {
    checks::scram_vectors("scram/vectors.yaml").unwrap();
}

#[test]
fn tc_drv_rs_004_error_mapping() {
    checks::error_mapping("generated/errors.json").unwrap();
}

#[test]
fn tc_drv_rs_005_connection_strings() {
    checks::connection_strings("connstring.yaml").unwrap();
}

#[test]
fn tc_drv_rs_006_ast_vectors() {
    for f in [
        "ast/filters.json",
        "ast/updates.json",
        "ast/statements.json",
    ] {
        checks::ast_vectors(f).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tc_drv_rs_016_retry_scenarios() {
    let only = std::env::var("RGN_RETRY_SCENARIO").ok();
    fake::retry_scenarios("retry.yaml", only.as_deref())
        .await
        .unwrap();
}
