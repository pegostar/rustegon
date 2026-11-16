// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixture of index build record format 1 (implementation-rules.md §6;
//! `rustegon_index::build::record`; FR-IDX-003).
//!
//! `index_build/1/records.txt`: `<label> <key hex> <value hex>` per fixed record. The current
//! encoder must reproduce the file exactly and the decoder must read every line back; a
//! failure means the format changed and needs a new version plus reader support, not a
//! regeneration.
//!
//! Generate a missing fixture (an existing file is never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-index --test build_formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{fmt::Write as _, path::Path};

use rustegon_index::build::{BuildRecord, JobPhase, decode_build_record, encode_build_record};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn records() -> Vec<(&'static str, BuildRecord)> {
    let fresh = BuildRecord::new(100, 105, 117);
    let mut backfilling = fresh.clone();
    backfilling.cursor = Some(vec![
        0x03, 0x00, 0, 0, 0, 100, 0, 0, 0, 105, b'D', 0x12, 0x34,
    ]);
    backfilling.docs_scanned = 2000;
    backfilling.entries_written = 2450;
    let mut cleanup = backfilling.clone();
    cleanup.phase = JobPhase::Cleanup;
    cleanup.cursor = None;
    cleanup.error = Some("index ix build failed: duplicate key [3]".into());
    vec![
        ("fresh", fresh),
        ("backfilling", backfilling),
        ("cleanup", cleanup),
    ]
}

#[test]
fn index_build_record_v1_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formats/index_build/1/records.txt");
    let mut text = String::new();
    for (label, r) in records() {
        let bytes = encode_build_record(&r).unwrap();
        assert_eq!(decode_build_record(&bytes).unwrap(), r, "{label}");
        let _ = writeln!(text, "{label} {} {}", hex(&r.key()), hex(&bytes));
    }
    if std::env::var_os("RUSTEGON_WRITE_FIXTURES").is_some() && !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &text).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (generate with RUSTEGON_WRITE_FIXTURES=1)",
            path.display()
        )
    });
    assert_eq!(committed, text, "index build record format 1 changed");
}
