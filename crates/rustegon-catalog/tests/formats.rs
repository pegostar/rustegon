// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixtures of catalog format v1 (implementation-rules.md §6; database-engine.md
//! §2.5; freezes at M2 exit, DEC-018).
//!
//! - `catalog/1/<case>.rdoc` + `<case>.json`: the canonical descriptor `RDoc` bytes of a fixed
//!   descriptor and their canonical JSON. Compatibility: every committed `.rdoc` must decode to
//!   the recorded descriptor, forever. Stability: the current encoder must reproduce the bytes
//!   exactly; a failure means the format changed and needs `catalog_format` 2 plus new fixtures,
//!   not a regeneration.
//! - `catalog/1/keys.txt`: system keys and id values, `<label> <hex>` per line.
//!
//! Generate missing fixtures (existing files are never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-catalog --test formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use rustegon_catalog::{
    CollectionDescriptor, CollectionKind, CollectionOptions, DatabaseDescriptor, DatabaseOptions,
    Descriptor, DescriptorState, ShardKey, ShardStrategy, ValidationAction, ValidationLevel,
    decode_descriptor, encode_descriptor, keys,
};
use rustegon_doc::{
    json::{JsonMode, to_json},
    rdoc,
};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats/catalog/1")
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

fn cases() -> Vec<(&'static str, Descriptor)> {
    vec![
        (
            "database_default",
            Descriptor::Database(DatabaseDescriptor {
                id: 100,
                name: "shop".into(),
                version: 1,
                state: DescriptorState::Public,
                options: DatabaseOptions::default(),
            }),
        ),
        (
            "database_explicit_only_dropping",
            Descriptor::Database(DatabaseDescriptor {
                id: 101,
                name: "ledger-2026".into(),
                version: 7,
                state: DescriptorState::Dropping,
                options: DatabaseOptions {
                    implicit_collection_creation: false,
                },
            }),
        ),
        (
            "collection_default",
            Descriptor::Collection(CollectionDescriptor {
                id: 102,
                database_id: 100,
                name: "orders".into(),
                kind: CollectionKind::Document,
                version: 1,
                state: DescriptorState::Public,
                shard_key: ShardKey::default(),
                options: CollectionOptions::default(),
            }),
        ),
        (
            "collection_validator_range",
            Descriptor::Collection(CollectionDescriptor {
                id: 4_000_000_000,
                database_id: 100,
                name: "users.v2".into(),
                kind: CollectionKind::Document,
                version: 3,
                state: DescriptorState::Public,
                shard_key: ShardKey {
                    strategy: ShardStrategy::Range,
                    fields: vec!["region".into(), "_id".into()],
                },
                options: CollectionOptions {
                    validator: Some(
                        r#"{"$jsonSchema":{"type":"object","required":["email"]}}"#.into(),
                    ),
                    validation_level: ValidationLevel::Moderate,
                    validation_action: ValidationAction::Warn,
                },
            }),
        ),
        (
            "collection_timeseries",
            Descriptor::Collection(CollectionDescriptor {
                id: 103,
                database_id: 100,
                name: "metrics".into(),
                kind: CollectionKind::Timeseries,
                version: 1,
                state: DescriptorState::Public,
                shard_key: ShardKey::default(),
                options: CollectionOptions {
                    validator: None,
                    validation_level: ValidationLevel::Off,
                    validation_action: ValidationAction::Error,
                },
            }),
        ),
    ]
}

#[test]
fn catalog_v1_descriptor_fixtures_stable_and_readable() {
    let dir = dir();
    if write_mode() {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (name, desc) in cases() {
        let bytes = encode_descriptor(&desc).unwrap();
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
        // Compatibility: the committed bytes decode to the recorded descriptor.
        assert_eq!(
            decode_descriptor(&committed).unwrap(),
            desc,
            "{name}: decode"
        );
        // Stability: the encoder reproduces them.
        assert_eq!(
            bytes, committed,
            "{name}: catalog v1 encoder output changed"
        );
        assert_eq!(
            std::fs::read_to_string(&json_path).unwrap(),
            json,
            "{name}: canonical JSON changed"
        );
    }
}

fn keys_text() -> String {
    let lines = [
        ("descriptor_key(100)", keys::descriptor_key(100)),
        (
            "descriptor_key(4000000000)",
            keys::descriptor_key(4_000_000_000),
        ),
        ("descriptor_prefix", keys::descriptor_prefix()),
        (
            "name_key(0,shop)",
            keys::name_key(keys::ROOT_PARENT_ID, "shop"),
        ),
        ("name_key(100,orders)", keys::name_key(100, "orders")),
        ("name_prefix(100)", keys::name_prefix(100)),
        (
            "descriptor_id_sequence_key",
            keys::descriptor_id_sequence_key(),
        ),
        ("id_value(100)", keys::encode_id(100)),
    ];
    lines.iter().fold(String::new(), |mut s, (label, bytes)| {
        let _ = writeln!(s, "{label} {}", hex(bytes));
        s
    })
}

#[test]
fn catalog_v1_key_layout_fixture() {
    let path = dir().join("keys.txt");
    let text = keys_text();
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
    assert_eq!(committed, text, "catalog v1 key layout changed");
}
