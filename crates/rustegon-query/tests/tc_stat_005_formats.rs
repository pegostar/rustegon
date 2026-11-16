// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-STAT-005: persisted-format fixtures of **stats format 1** (implementation-rules.md §6;
//! query-engine.md §2.1, *Provisional (PD pending)*).
//!
//! - `stats/1/<case>.rdoc` + `<case>.json`: record bytes and their canonical JSON. Every
//!   committed `.rdoc` must decode to the recorded statistics forever; the current encoder must
//!   reproduce the bytes (a failure means `stats_format` 2 plus new fixtures).
//! - `stats/1/keys.txt`: the system key layout.
//!
//! Generate missing fixtures (existing files are never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-query --test tc_stat_005_formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use rustegon_doc::{
    Document, Value,
    json::{JsonMode, to_json},
    rdoc,
};
use rustegon_query::stats::{
    CollectionStats, IndexSize, StatsCollector, StatsConfig, decode_stats, encode_stats, stats_key,
};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats/stats/1")
}

fn write_mode() -> bool {
    std::env::var_os("RUSTEGON_WRITE_FIXTURES").is_some()
}

fn doc(fields: Vec<(&str, Value)>) -> Document {
    Document::try_from_fields(fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect()).unwrap()
}

fn cases() -> Vec<(&'static str, CollectionStats)> {
    let empty = StatsCollector::new(StatsConfig::default(), 100, 102, &["status".to_owned()])
        .finish(1_767_225_600_000);
    // Deterministic data covering MCVs, a histogram, nulls, missing values and arrays.
    let mut c = StatsCollector::new(
        StatsConfig {
            histogram_buckets: 4,
            mcv_size: 2,
            ..StatsConfig::default()
        },
        100,
        103,
        &["status".to_owned(), "tags".to_owned()],
    );
    for i in 0..40i64 {
        let status = if i % 4 == 0 { "new" } else { "done" };
        let mut fields = vec![
            ("_id", Value::Int64(i)),
            ("status", Value::String(status.into())),
            (
                "price",
                Value::Float64(f64::from(i32::try_from(i).unwrap()) * 1.5),
            ),
        ];
        if i % 5 == 0 {
            fields.push(("note", Value::Null));
        }
        if i % 3 == 0 {
            fields.push((
                "tags",
                Value::Array((0..i % 4).map(|t| Value::String(format!("t{t}"))).collect()),
            ));
        }
        c.add_document(&doc(fields), 50 + usize::try_from(i).unwrap());
    }
    let mut filled = c.finish(1_767_225_600_000);
    filled.indexes = vec![
        IndexSize {
            index_id: 104,
            entries: 40,
            bytes: 1_234,
        },
        IndexSize {
            index_id: 105,
            entries: 30,
            bytes: 900,
        },
    ];
    vec![("stats_empty", empty), ("stats_filled", filled)]
}

#[test]
fn tc_stat_005_stats_v1_fixtures_stable_and_readable() {
    let dir = dir();
    if write_mode() {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (name, stats) in cases() {
        let bytes = encode_stats(&stats).unwrap();
        let json = to_json(&rdoc::decode(&bytes).unwrap(), JsonMode::Canonical);
        let (rdoc_path, json_path) = (
            dir.join(format!("{name}.rdoc")),
            dir.join(format!("{name}.json")),
        );
        if write_mode() && !rdoc_path.exists() {
            std::fs::write(&rdoc_path, &bytes).unwrap();
            std::fs::write(&json_path, &json).unwrap();
        }
        let committed = std::fs::read(&rdoc_path).unwrap_or_else(|e| {
            panic!(
                "{}: {e} (generate with RUSTEGON_WRITE_FIXTURES=1)",
                rdoc_path.display()
            )
        });
        assert_eq!(decode_stats(&committed).unwrap(), stats, "{name}: decode");
        assert_eq!(bytes, committed, "{name}: stats v1 encoder output changed");
        assert_eq!(
            std::fs::read_to_string(&json_path).unwrap(),
            json,
            "{name}: canonical JSON changed"
        );
    }
}

#[test]
fn tc_stat_005_stats_v1_key_layout_fixture() {
    let text =
        [("stats_key(102)", stats_key(102))]
            .iter()
            .fold(String::new(), |mut s, (label, bytes)| {
                let hex = bytes.iter().fold(String::new(), |mut h, b| {
                    let _ = write!(h, "{b:02x}");
                    h
                });
                let _ = writeln!(s, "{label} {hex}");
                s
            });
    let path = dir().join("keys.txt");
    if write_mode() && !path.exists() {
        std::fs::create_dir_all(dir()).unwrap();
        std::fs::write(&path, &text).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (generate with RUSTEGON_WRITE_FIXTURES=1)",
            path.display()
        )
    });
    assert_eq!(committed, text, "stats key layout changed");
}
