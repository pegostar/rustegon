// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixture of index entry format 1 (implementation-rules.md §6; indexing.md
//! §3; `rustegon_index::entry`).
//!
//! `index_entry/1/entries.txt`: `<label> <key hex> <value hex>` per entry of fixed documents in
//! fixed index descriptors. The current generator must reproduce the file exactly; a failure
//! means the entry format changed and needs a new version plus reader support, not a
//! regeneration.
//!
//! Generate a missing fixture (an existing file is never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-index --test entry_formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{fmt::Write as _, path::Path};

use rustegon_catalog::{
    IndexDescriptor, IndexField, IndexKind, IndexOrigin, IndexScope, IndexState,
};
use rustegon_doc::{Value, json::parse_document};
use rustegon_index::{EntryValue, NoPartialFilter, index_entries};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn ix(id: u32, fields: Vec<IndexField>) -> IndexDescriptor {
    IndexDescriptor {
        id,
        database_id: 100,
        collection_id: 102,
        name: format!("ix{id}"),
        kind: IndexKind::Secondary,
        fields,
        unique: false,
        sparse: false,
        partial: None,
        hidden: false,
        scope: IndexScope::Global,
        state: IndexState::Public,
        origin: IndexOrigin::Manual,
        version: 1,
        include: vec![],
        multikey: false,
        created_at_ms: 0,
    }
}

fn text() -> String {
    let compound = ix(
        200,
        vec![IndexField::asc("status"), IndexField::desc("total")],
    );
    let mut unique = ix(201, vec![IndexField::asc("email")]);
    unique.unique = true;
    let multikey = ix(202, vec![IndexField::asc("tags")]);
    let wildcard = ix(203, vec![IndexField::asc("attrs.**")]);
    let mut covered = ix(204, vec![IndexField::asc("status")]);
    covered.include = vec!["total".into()];
    let truncated = ix(205, vec![IndexField::asc("blob")]);
    let doc = parse_document(&format!(
        r#"{{"status":"paid","total":12.5,"email":"a@b.c","tags":["x","y"],"attrs":{{"k":1}},"blob":"{}"}}"#,
        "z".repeat(4200)
    ))
    .unwrap();
    let id = Value::String("o1".into());
    let mut out = String::new();
    for (label, index) in [
        ("compound", &compound),
        ("unique", &unique),
        ("multikey", &multikey),
        ("wildcard", &wildcard),
        ("covered", &covered),
        ("truncated", &truncated),
    ] {
        let e = index_entries(index, &id, &doc, &NoPartialFilter).unwrap();
        for (i, (k, v)) in e.entries.iter().enumerate() {
            // Every fixture value must decode (compatibility of the reader).
            EntryValue::decode(v).unwrap();
            let _ = writeln!(out, "{label}[{i}] {} {}", hex(k), hex(v));
        }
    }
    out
}

#[test]
fn index_entry_v1_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formats/index_entry/1/entries.txt");
    let text = text();
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
    assert_eq!(committed, text, "index entry format 1 changed");
}
