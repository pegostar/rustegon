// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixtures of the backup manifest (implementation-rules.md §6; PD-064).
//!
//! `backup-manifest/1/manifest.json` is a manifest of format 1. Compatibility: it must parse to
//! the recorded values forever. Stability: the current writer must reproduce it byte for byte
//! (modulo line endings); a failure means the format changed and needs version 2 plus a new
//! fixture, not an edit of this one. The hashes and the KEK id are made-up constants.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use rustegon_backup::{
    Consistency, Encryption, HlcTimestamp, MANIFEST_FORMAT_VERSION, Manifest, SourceInfo,
};
use rustegon_common::ErrorCode;

fn fixture(version: u32, name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formats/backup-manifest")
        .join(version.to_string())
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    // Checkouts with CRLF line endings must not count as a format change.
    String::from_utf8(bytes)
        .unwrap()
        .replace("\r\n", "\n")
        .into_bytes()
}

#[test]
fn tc_bkp_010_manifest_v1_fixture_is_readable() {
    let bytes = fixture(1, "manifest.json");
    let m = Manifest::from_json("20261109T101500Z-3fa85f64", &bytes).unwrap();
    assert_eq!(m.format_version, 1);
    assert_eq!(m.backup_id, "20261109T101500Z-3fa85f64");
    assert_eq!(m.created_at, "2026-11-09T10:15:00Z");
    assert_eq!(
        m.consistency,
        Consistency {
            timestamp: HlcTimestamp {
                wall: 1_794_219_300_000_000_000,
                logical: 7,
            },
            applied_index: 4242,
            applied_term: 3,
            storage_seqno: 98_765,
        }
    );
    assert_eq!(
        m.source,
        SourceInfo {
            cluster_id: "c0ffee00-0000-4000-8000-000000000001".into(),
            node_id: "1".into(),
            server_version: "0.1.0".into(),
        }
    );
    assert_eq!(
        m.encryption,
        Encryption::Kek {
            kek_id: "file:/etc/rustegon/secrets/kek.key".into()
        }
    );
    let paths: Vec<_> = m.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "keys/registry.enc",
            "lsm/000007.rsst",
            "lsm/CURRENT",
            "lsm/MANIFEST-000001"
        ]
    );
    assert_eq!(m.total_bytes(), 96 + 1_048_576 + 16 + 512);
}

#[test]
fn manifest_v1_writer_reproduces_fixture() {
    let bytes = fixture(1, "manifest.json");
    let m = Manifest::from_json("20261109T101500Z-3fa85f64", &bytes).unwrap();
    assert_eq!(MANIFEST_FORMAT_VERSION, 1);
    assert_eq!(
        String::from_utf8(m.to_json().unwrap()).unwrap(),
        String::from_utf8(bytes).unwrap()
    );
}

#[test]
fn tc_bkp_010_manifest_newer_than_v1_is_refused_with_rgn_5007() {
    let mut value: serde_json::Value =
        serde_json::from_slice(&fixture(1, "manifest.json")).unwrap();
    value["format_version"] = serde_json::json!(MANIFEST_FORMAT_VERSION + 1);
    let err = Manifest::from_json(
        "20261109T101500Z-3fa85f64",
        &serde_json::to_vec(&value).unwrap(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::VersionIncompatible);
}

#[test]
fn manifest_v1_ignores_unknown_fields() {
    let mut value: serde_json::Value =
        serde_json::from_slice(&fixture(1, "manifest.json")).unwrap();
    value["added_later"] = serde_json::json!({"x": 1});
    Manifest::from_json(
        "20261109T101500Z-3fa85f64",
        &serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
}
