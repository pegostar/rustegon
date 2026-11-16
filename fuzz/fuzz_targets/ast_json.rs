// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! cargo-fuzz target `ast_json` (AC-QL-002): see `fuzz/README.md` and the checks in
//! `crates/rustegon-query/tests/common/fuzz_check.rs` (shared with the stable smoke test).

#![no_main]

#[path = "../../crates/rustegon-query/tests/common/fuzz_check.rs"]
#[allow(dead_code)]
mod fuzz_check;

libfuzzer_sys::fuzz_target!(|data: &[u8]| fuzz_check::ast_json(data));
