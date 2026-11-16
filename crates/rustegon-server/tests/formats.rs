// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixture of the setting override record, format 1 (implementation-rules.md
//! §6; PD-051): the committed bytes must decode to the recorded value forever, and the current
//! encoder must reproduce them exactly (a failure means format 2, not a regeneration).
//!
//! Generate a missing fixture (existing files are never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-server --test formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

use rustegon_server::security::{SettingRecord, decode_setting, encode_setting, setting_key};

#[test]
fn setting_override_format_1_fixture_is_stable() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats/setting/1");
    let path = dir.join("auth_scram_iterations.rdoc");
    let record = SettingRecord {
        name: "auth.scram_iterations".into(),
        value: "700000".into(),
        updated_at: UNIX_EPOCH + Duration::from_millis(1_800_000_000_123),
    };
    let bytes = encode_setting(&record).unwrap();
    if !path.exists() && std::env::var_os("RUSTEGON_WRITE_FIXTURES").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &bytes).unwrap();
    }
    let committed = std::fs::read(&path).expect("fixture committed");
    assert_eq!(decode_setting(&committed).unwrap(), record);
    assert_eq!(bytes, committed, "encoder changed: setting format 2 needed");
    assert_eq!(
        setting_key("auth.scram_iterations"),
        b"\x02gauth.scram_iterations".to_vec()
    );
}
