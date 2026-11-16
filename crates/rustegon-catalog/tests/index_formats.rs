// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixtures of index descriptor format 1 (implementation-rules.md §6;
//! indexing.md §1; database-engine.md §2.5 "Index descriptors").
//!
//! - `index/1/<case>.rdoc` + `<case>.json`: canonical descriptor bytes and their canonical JSON.
//!   Every committed `.rdoc` must decode to the recorded descriptor forever; the current encoder
//!   must reproduce the bytes (a failure means `index_format` 2 plus new fixtures).
//! - `index/1/keys.txt`: system keys, `<label> <hex>` per line.
//!
//! Generate missing fixtures (existing files are never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-catalog --test index_formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use rustegon_catalog::{
    IndexDescriptor, IndexField, IndexKind, IndexOrigin, IndexScope, IndexState,
    index::{
        codec::{decode_index_descriptor, encode_index_descriptor},
        ops::{index_descriptor_key, index_prefix},
    },
};
use rustegon_doc::{
    json::{JsonMode, to_json},
    rdoc,
};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats/index/1")
}

fn write_mode() -> bool {
    std::env::var_os("RUSTEGON_WRITE_FIXTURES").is_some()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn cases() -> Vec<(&'static str, IndexDescriptor)> {
    let base = IndexDescriptor {
        id: 104,
        database_id: 100,
        collection_id: 102,
        name: "by_status".into(),
        kind: IndexKind::Secondary,
        fields: vec![IndexField::asc("status")],
        unique: false,
        sparse: false,
        partial: None,
        hidden: false,
        scope: IndexScope::Global,
        state: IndexState::DeleteOnly,
        origin: IndexOrigin::Manual,
        version: 1,
        include: vec![],
        multikey: false,
        created_at_ms: 1_767_225_600_000,
    };
    vec![
        ("index_single_delete_only", base.clone()),
        (
            "index_compound_partial_public",
            IndexDescriptor {
                id: 4_000_000_001,
                name: "idx_status_created".into(),
                fields: vec![IndexField::asc("status"), IndexField::desc("createdAt")],
                sparse: true,
                partial: Some("total > 0".into()),
                hidden: true,
                state: IndexState::Public,
                origin: IndexOrigin::Auto,
                version: 5,
                include: vec!["total".into(), "customer.name".into()],
                multikey: true,
                ..base.clone()
            },
        ),
        (
            "index_unique_dropping",
            IndexDescriptor {
                id: 105,
                name: "uniq_email".into(),
                fields: vec![IndexField::asc("email")],
                unique: true,
                state: IndexState::Dropping,
                version: 7,
                created_at_ms: -1,
                ..base.clone()
            },
        ),
        (
            "index_wildcard_write_only",
            IndexDescriptor {
                id: 106,
                name: "attrs_wildcard".into(),
                fields: vec![IndexField::asc("attrs.**")],
                state: IndexState::WriteOnly,
                version: 2,
                ..base
            },
        ),
    ]
}

#[test]
fn index_v1_descriptor_fixtures_stable_and_readable() {
    let dir = dir();
    if write_mode() {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (name, desc) in cases() {
        let bytes = encode_index_descriptor(&desc).unwrap();
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
        assert_eq!(
            decode_index_descriptor(&committed).unwrap(),
            desc,
            "{name}: decode"
        );
        assert_eq!(bytes, committed, "{name}: index v1 encoder output changed");
        assert_eq!(
            std::fs::read_to_string(&json_path).unwrap(),
            json,
            "{name}: canonical JSON changed"
        );
    }
}

#[test]
fn index_v1_key_layout_fixture() {
    let lines = [
        (
            "index_descriptor_key(102,104)",
            index_descriptor_key(102, 104),
        ),
        ("index_prefix(102)", index_prefix(102)),
    ];
    let text = lines.iter().fold(String::new(), |mut s, (label, bytes)| {
        let _ = writeln!(s, "{label} {}", hex(bytes));
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
    assert_eq!(committed, text, "index descriptor key layout changed");
}
