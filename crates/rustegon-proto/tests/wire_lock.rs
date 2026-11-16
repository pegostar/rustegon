// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-API-001 without `buf`: the wire contract of `rustegon.v1` against the checked-in lock
//! `proto/rustegon/v1.lock` (PD-060).
//!
//! The lock lists every RPC (types and streaming), every field (number, label, type, JSON
//! name), every enum value and every reserved range or name. protocol.md §9 allows additive
//! changes only, so every lock line must still hold: a renumbered, retyped, renamed or removed
//! field, enum value or RPC fails here even where `buf` is not installed. A removed field must
//! leave its number and name reserved (checked against the descriptors). New lines fail too
//! until the lock is regenerated with `RGN_PROTO_LOCK_BLESS=1`, so every addition is reviewed.
//! `buf breaking` against the `api-v1-alpha` tag remains the CI gate (scripts/ci-local.sh).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use prost::Message as _;
use prost_types::{
    DescriptorProto, FileDescriptorSet,
    field_descriptor_proto::{Label, Type},
};
use rustegon_proto::FILE_DESCRIPTOR_SET;

fn lock_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto/rustegon/v1.lock")
}

fn type_name(f: &prost_types::FieldDescriptorProto) -> String {
    match f.r#type() {
        Type::Message | Type::Enum => f.type_name().trim_start_matches('.').to_owned(),
        t => t
            .as_str_name()
            .trim_start_matches("TYPE_")
            .to_ascii_lowercase(),
    }
}

/// Per message: reserved numbers and names, used to check removals.
#[derive(Default)]
struct Reserved {
    ranges: Vec<(i32, i32)>,
    names: BTreeSet<String>,
}

fn walk_message(
    prefix: &str,
    m: &DescriptorProto,
    lines: &mut BTreeSet<String>,
    reserved: &mut BTreeMap<String, Reserved>,
) {
    let name = format!("{prefix}.{}", m.name());
    let mut seen = BTreeMap::new();
    for f in &m.field {
        assert!(
            seen.insert(f.number(), f.name()).is_none(),
            "{name}: field number {} used twice",
            f.number()
        );
        let label = match f.label() {
            Label::Repeated => "repeated",
            _ if f.proto3_optional() => "optional",
            _ => "singular",
        };
        let oneof = f
            .oneof_index
            .filter(|_| !f.proto3_optional())
            .map(|i| {
                format!(
                    " oneof={}",
                    m.oneof_decl[usize::try_from(i).unwrap()].name()
                )
            })
            .unwrap_or_default();
        lines.insert(format!(
            "field {name}.{} = {} {label} {} json={}{oneof}",
            f.name(),
            f.number(),
            type_name(f),
            f.json_name()
        ));
    }
    let mut r = Reserved::default();
    for range in &m.reserved_range {
        // DescriptorProto reserved ranges are end-exclusive.
        r.ranges.push((range.start(), range.end() - 1));
        lines.insert(format!(
            "reserved {name} {}..={}",
            range.start(),
            range.end() - 1
        ));
    }
    for n in &m.reserved_name {
        r.names.insert(n.clone());
        lines.insert(format!("reserved {name} \"{n}\""));
    }
    for f in &m.field {
        assert!(
            !r.ranges
                .iter()
                .any(|(a, b)| (*a..=*b).contains(&f.number())),
            "{name}.{} uses reserved number {}",
            f.name(),
            f.number()
        );
        assert!(
            !r.names.contains(f.name()),
            "{name}.{} uses a reserved name",
            f.name()
        );
    }
    reserved.insert(name.clone(), r);
    for e in &m.enum_type {
        for v in &e.value {
            lines.insert(format!(
                "enum {name}.{}.{} = {}",
                e.name(),
                v.name(),
                v.number()
            ));
        }
    }
    for nested in &m.nested_type {
        if nested
            .options
            .as_ref()
            .is_some_and(prost_types::MessageOptions::map_entry)
        {
            continue;
        }
        walk_message(&name, nested, lines, reserved);
    }
}

fn current() -> (BTreeSet<String>, BTreeMap<String, Reserved>) {
    let set = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let mut lines = BTreeSet::new();
    let mut reserved = BTreeMap::new();
    for file in set.file.iter().filter(|f| f.package() == "rustegon.v1") {
        let pkg = file.package();
        for m in &file.message_type {
            walk_message(pkg, m, &mut lines, &mut reserved);
        }
        for e in &file.enum_type {
            let mut numbers = BTreeSet::new();
            for v in &e.value {
                assert!(
                    numbers.insert(v.number()),
                    "{pkg}.{}: enum number {} used twice",
                    e.name(),
                    v.number()
                );
                lines.insert(format!(
                    "enum {pkg}.{}.{} = {}",
                    e.name(),
                    v.name(),
                    v.number()
                ));
            }
        }
        for s in &file.service {
            for m in &s.method {
                lines.insert(format!(
                    "rpc {pkg}.{}/{} ({}{}) -> ({}{})",
                    s.name(),
                    m.name(),
                    if m.client_streaming() { "stream " } else { "" },
                    m.input_type().trim_start_matches('.'),
                    if m.server_streaming() { "stream " } else { "" },
                    m.output_type().trim_start_matches('.'),
                ));
            }
        }
    }
    (lines, reserved)
}

#[test]
fn tc_api_001_wire_contract_matches_the_lock() {
    let (now, reserved) = current();
    let path = lock_path();
    if std::env::var("RGN_PROTO_LOCK_BLESS").is_ok_and(|v| v == "1") {
        let mut text = String::from(
            "# Wire lock of rustegon.v1 (TC-API-001, PD-060): generated by\n\
             # `RGN_PROTO_LOCK_BLESS=1 cargo nextest run -p rustegon-proto --test wire_lock`.\n\
             # Lines may be added, never changed or removed (protocol.md §9).\n",
        );
        for l in &now {
            text.push_str(l);
            text.push('\n');
        }
        std::fs::write(&path, text).unwrap();
        return;
    }
    let locked: BTreeSet<String> = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| {
            panic!(
                "{}: {e} (bless with RGN_PROTO_LOCK_BLESS=1)",
                path.display()
            )
        })
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect();
    let mut problems = Vec::new();
    for l in locked.difference(&now) {
        // A removed field is tolerated by the wire only if its number and name are reserved;
        // §9 still forbids it within v1, so it is reported either way, with the reason.
        let detail = l.strip_prefix("field ").and_then(|rest| {
            let (path, tail) = rest.split_once(" = ")?;
            let (msg, field) = path.rsplit_once('.')?;
            let number: i32 = tail.split(' ').next()?.parse().ok()?;
            let r = reserved.get(msg)?;
            let ok = r.ranges.iter().any(|(a, b)| (*a..=*b).contains(&number))
                && r.names.contains(field);
            Some(if ok {
                "removed (reserved, but §9 forbids removal in v1)"
            } else {
                "changed or removed without reserving its number and name"
            })
        });
        problems.push(format!("- {l}: {}", detail.unwrap_or("changed or removed")));
    }
    for l in now.difference(&locked) {
        problems.push(format!(
            "+ {l}: new (review and bless with RGN_PROTO_LOCK_BLESS=1)"
        ));
    }
    assert!(
        problems.is_empty(),
        "rustegon.v1 differs from {}:\n{}",
        path.display(),
        problems.join("\n")
    );
}

/// Every enum starts with an `_UNSPECIFIED = 0` value (protocol.md §9: receivers map unknown
/// values onto it), and no field of a message reuses a number (checked by the walk).
#[test]
fn tc_api_001_enums_have_an_unspecified_zero() {
    let (now, _) = current();
    let mut enums: BTreeMap<String, Vec<(String, i32)>> = BTreeMap::new();
    for l in now.iter().filter_map(|l| l.strip_prefix("enum ")) {
        let (path, number) = l.split_once(" = ").unwrap();
        let (enum_name, value) = path.rsplit_once('.').unwrap();
        enums
            .entry(enum_name.to_owned())
            .or_default()
            .push((value.to_owned(), number.parse().unwrap()));
    }
    assert!(!enums.is_empty());
    for (name, values) in enums {
        let zero = values.iter().find(|(_, n)| *n == 0);
        assert!(
            zero.is_some_and(|(v, _)| v.ends_with("_UNSPECIFIED")),
            "{name}: value 0 must be *_UNSPECIFIED, got {zero:?}"
        );
    }
}
