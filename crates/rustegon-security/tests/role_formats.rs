// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixture of role record format 1 (implementation-rules.md §6;
//! `rustegon_security::rbac::store`; FR-SEC-002, TC-SEC-014).
//!
//! `role/1/records.txt`: `<label> <key hex> <value hex>` per fixed record. The current encoder
//! must reproduce the file exactly and the decoder must read every line back; a failure means
//! the format changed and needs a new version plus reader support, not a regeneration.
//!
//! Generate a missing fixture (an existing file is never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-security --test role_formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{fmt::Write as _, path::Path};

use rustegon_security::rbac::{
    Action, Privilege, ResourcePattern, Role, RoleRef,
    store::{decode_role, encode_role, role_key},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn records() -> Vec<(&'static str, Role)> {
    let empty = Role {
        name: "empty".into(),
        privileges: vec![],
        inherits: vec![],
    };
    let analyst = Role {
        name: "analyst".into(),
        privileges: vec![
            Privilege::new(
                ResourcePattern::parse("collection:shop.orders").unwrap(),
                &[Action::Find, Action::ChangeStream],
            ),
            Privilege::new(
                ResourcePattern::parse("collection:*.metrics").unwrap(),
                &[Action::Find],
            ),
            Privilege::new(
                ResourcePattern::parse("database:shop").unwrap(),
                &[Action::QueryStatsView, Action::QueryKill],
            ),
            Privilege::new(ResourcePattern::Cluster, &[Action::ClusterView]),
        ],
        inherits: vec![
            RoleRef::parse("read@crm").unwrap(),
            RoleRef::parse("read_write@shop.carts").unwrap(),
            RoleRef::parse("empty").unwrap(),
        ],
    };
    vec![("empty", empty), ("analyst", analyst)]
}

#[test]
fn tc_sec_014_role_record_v1_fixture() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats/role/1/records.txt");
    let mut text = String::new();
    for (label, r) in records() {
        let bytes = encode_role(&r).unwrap();
        assert_eq!(decode_role(&bytes).unwrap(), r, "{label}");
        let _ = writeln!(text, "{label} {} {}", hex(&role_key(&r.name)), hex(&bytes));
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
    assert_eq!(committed, text, "role record format 1 changed");
}
