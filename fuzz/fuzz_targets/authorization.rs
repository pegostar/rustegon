// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! cargo-fuzz target `authorization` (TC-SEC-010, PD-060): the oracle lives in
//! `crates/rustegon-server/src/fuzzing.rs` and also runs on stable in the
//! `tc_sec_010_fuzz_smoke_authorization` test.

#![no_main]

use rustegon_server::fuzzing;

libfuzzer_sys::fuzz_target!(|data: &[u8]| fuzzing::run_target(
    "authorization",
    fuzzing::authorization,
    data
));
