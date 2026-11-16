// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! cargo-fuzz target `request_headers` (TC-SEC-010, PD-060): the oracle lives in
//! `crates/rustegon-server/src/fuzzing.rs` and also runs on stable in the
//! `tc_sec_010_fuzz_smoke_request_headers` test.

#![no_main]

use rustegon_server::fuzzing;

libfuzzer_sys::fuzz_target!(|data: &[u8]| fuzzing::run_target(
    "request_headers",
    fuzzing::request_headers,
    data
));
