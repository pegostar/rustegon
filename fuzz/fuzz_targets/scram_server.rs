// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! cargo-fuzz target `scram_server` (TC-SEC-010, PD-060): the oracle lives in
//! `crates/rustegon-server/src/fuzzing.rs` and also runs on stable in the
//! `tc_sec_010_fuzz_smoke_scram_server` test.

#![no_main]

use rustegon_server::fuzzing;

libfuzzer_sys::fuzz_target!(|data: &[u8]| fuzzing::run_target(
    "scram_server",
    fuzzing::scram_server,
    data
));
