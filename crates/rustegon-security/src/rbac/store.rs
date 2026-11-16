// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Custom roles in the system keyspace: **role record format 1** (*Provisional (PD-048)*;
//! fixture `crates/rustegon-security/tests/fixtures/formats/role/1/`).
//!
//! ```text
//! key    0x02 'r' name(ASCII [a-z0-9_-], 1..=64)
//! value  { role_format: 1, type: "role", name,
//!          privileges: [ { resource: "database:shop", actions: ["find", ...] }, ... ],
//!          inherits: ["read@shop", "analyst", ...] }
//! ```
//! - Canonical `RDoc`, strict decoding (an unknown field is corruption: a new field means
//!   format 2, implementation-rules.md §6). Actions are written in declaration order.
//! - The sub-namespace byte `'r'` is taken next to the catalog's `'d' 'n' 's' 'i'`, the index
//!   build records' `'b'` and the statistics' `'t'`. Role names are NUL-free, so no role key
//!   is a strict prefix of another whose next byte is `0x00` (mvcc separator rule).
//!
//! Like the catalog's DDL, operations are transaction-agnostic: they read through
//! [`CatalogRead`] at the caller's snapshot and return [`Mutation`]s the caller applies in the
//! **same** transaction. Every write first reads **all** role records (the cycle check needs the
//! whole graph), so two concurrent writes that could together close a cycle (`a` inherits `b`
//! while `b` inherits `a`) read each other's keys and serializable isolation aborts one of them
//! (`RGN-2001`) — the acyclicity invariant cannot be broken by interleaving.

use rustegon_catalog::{CatalogRead, Mutation};
use rustegon_doc::{Document, Value, keyspace::NS_SYSTEM, rdoc};

use super::{
    RbacError,
    action::{Action, ActionSet},
    eval::RoleCatalog,
    resource::ResourcePattern,
    role::{Privilege, Role, RoleRef},
};

/// Sub-namespace byte of role records.
pub const SUB_ROLE: u8 = b'r';
/// Role record format written by this crate.
pub const ROLE_FORMAT: i64 = 1;

const F_FORMAT: &str = "role_format";
const F_TYPE: &str = "type";
const F_NAME: &str = "name";
const F_PRIVILEGES: &str = "privileges";
const F_INHERITS: &str = "inherits";
const F_RESOURCE: &str = "resource";
const F_ACTIONS: &str = "actions";
const TYPE_ROLE: &str = "role";
const FIELDS: &[&str] = &[F_FORMAT, F_TYPE, F_NAME, F_PRIVILEGES, F_INHERITS];
const PRIVILEGE_FIELDS: &[&str] = &[F_RESOURCE, F_ACTIONS];

/// Key of the role record `name`.
#[must_use]
pub fn role_key(name: &str) -> Vec<u8> {
    let mut k = role_prefix();
    k.extend_from_slice(name.as_bytes());
    k
}

/// Prefix of every role record.
#[must_use]
pub fn role_prefix() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_ROLE]
}

fn corrupt(msg: impl Into<String>) -> RbacError {
    RbacError::Corrupt(msg.into())
}

/// Encodes a role into its canonical `RDoc` bytes.
///
/// # Errors
/// [`RbacError::Corrupt`] if the document codec rejects the record (only for absurd sizes).
pub fn encode_role(role: &Role) -> Result<Vec<u8>, RbacError> {
    let privileges = role
        .privileges
        .iter()
        .map(|p| {
            let mut d = Document::new();
            d.insert(F_RESOURCE, Value::String(p.resource.to_string()));
            let actions = p
                .actions
                .iter()
                .map(|a| Value::String(a.as_str().into()))
                .collect();
            d.insert(F_ACTIONS, Value::Array(actions));
            Value::Object(d)
        })
        .collect();
    let inherits = role
        .inherits
        .iter()
        .map(|r| Value::String(r.as_str().into()))
        .collect();
    let mut doc = Document::new();
    doc.insert(F_FORMAT, Value::Int64(ROLE_FORMAT));
    doc.insert(F_TYPE, Value::String(TYPE_ROLE.into()));
    doc.insert(F_NAME, Value::String(role.name.clone()));
    doc.insert(F_PRIVILEGES, Value::Array(privileges));
    doc.insert(F_INHERITS, Value::Array(inherits));
    rdoc::encode(&doc).map_err(|e| corrupt(e.to_string()))
}

fn strings<'a>(doc: &'a Document, field: &str) -> Result<Vec<&'a str>, RbacError> {
    match doc.get(field) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                Value::String(s) => Ok(s.as_str()),
                _ => Err(corrupt(format!("{field} item is not a string"))),
            })
            .collect(),
        _ => Err(corrupt(format!("{field} missing or not an array"))),
    }
}

fn check_fields(doc: &Document, allowed: &[&str]) -> Result<(), RbacError> {
    match doc.iter().find(|(n, _)| !allowed.contains(n)) {
        Some((name, _)) => Err(corrupt(format!("unknown field {name:?}"))),
        None => Ok(()),
    }
}

fn decode_privilege(v: &Value) -> Result<Privilege, RbacError> {
    let Value::Object(d) = v else {
        return Err(corrupt("privilege is not an object"));
    };
    check_fields(d, PRIVILEGE_FIELDS)?;
    let resource = match d.get(F_RESOURCE) {
        Some(Value::String(s)) => ResourcePattern::parse(s).map_err(|e| corrupt(e.to_string()))?,
        _ => return Err(corrupt("resource missing or not a string")),
    };
    let actions = strings(d, F_ACTIONS)?
        .into_iter()
        .map(|a| Action::parse(a).ok_or_else(|| corrupt(format!("unknown action {a:?}"))))
        .collect::<Result<ActionSet, _>>()?;
    Ok(Privilege { resource, actions })
}

/// Decodes a record written by [`encode_role`].
///
/// # Errors
/// [`RbacError::Corrupt`] for anything else (unknown fields, wrong types, unsupported
/// `role_format`, invalid names).
pub fn decode_role(bytes: &[u8]) -> Result<Role, RbacError> {
    let doc = rdoc::decode(bytes).map_err(|e| corrupt(e.to_string()))?;
    match doc.get(F_FORMAT) {
        Some(Value::Int64(ROLE_FORMAT)) => {}
        Some(Value::Int64(v)) => return Err(corrupt(format!("unsupported role_format {v}"))),
        _ => return Err(corrupt("missing role_format")),
    }
    check_fields(&doc, FIELDS)?;
    if doc.get(F_TYPE) != Some(&Value::String(TYPE_ROLE.into())) {
        return Err(corrupt("type is not \"role\""));
    }
    let name = match doc.get(F_NAME) {
        Some(Value::String(s)) => s.clone(),
        _ => return Err(corrupt("name missing or not a string")),
    };
    let privileges = match doc.get(F_PRIVILEGES) {
        Some(Value::Array(items)) => items
            .iter()
            .map(decode_privilege)
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(corrupt("privileges missing or not an array")),
    };
    let inherits = strings(&doc, F_INHERITS)?
        .into_iter()
        .map(|r| RoleRef::parse(r).map_err(|e| corrupt(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    let role = Role {
        name,
        privileges,
        inherits,
    };
    role.validate().map_err(|e| corrupt(e.to_string()))?;
    Ok(role)
}

/// Loads every custom role into a [`RoleCatalog`].
///
/// # Errors
/// [`RbacError::Read`] from the store; [`RbacError::Corrupt`] for an undecodable record, a key
/// that does not match its record's name, or a stored graph that is not valid (cycle, dangling
/// inheritance).
pub fn load_roles(r: &impl CatalogRead) -> Result<RoleCatalog, RbacError> {
    let pairs = r.scan_prefix(&role_prefix()).map_err(RbacError::Read)?;
    let mut roles = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let role = decode_role(&value)?;
        if key != role_key(&role.name) {
            return Err(corrupt(format!(
                "role {:?} stored under a foreign key",
                role.name
            )));
        }
        roles.push(role);
    }
    // Insert in dependency order: parents first, so `upsert`'s existence check passes. A cycle or
    // a dangling parent leaves roles that never become insertable.
    let mut catalog = RoleCatalog::new();
    while !roles.is_empty() {
        let before = roles.len();
        let mut pending = Vec::new();
        for role in roles {
            let ready = role.inherits.iter().all(|p| {
                RoleRef::split(p).is_ok_and(|(n, b, _)| b.is_some() || catalog.get(n).is_some())
            });
            if ready {
                catalog
                    .upsert(role)
                    .map_err(|e| corrupt(format!("stored roles invalid: {e}")))?;
            } else {
                pending.push(role);
            }
        }
        if pending.len() == before {
            let names: Vec<_> = pending.iter().map(|r| r.name.as_str()).collect();
            return Err(corrupt(format!(
                "stored roles with cyclic or dangling inheritance: {names:?}"
            )));
        }
        roles = pending;
    }
    Ok(catalog)
}

fn put(role: &Role) -> Result<Mutation, RbacError> {
    Ok(Mutation::Put {
        key: role_key(&role.name),
        value: encode_role(role)?,
    })
}

/// Creates the custom role `role` (TC-SEC-014).
///
/// # Errors
/// [`RbacError::RoleExists`]; the validation errors of [`RoleCatalog::upsert`] (invalid name or
/// privilege, unknown parent, cycle); [`RbacError::Read`] / [`RbacError::Corrupt`].
pub fn create_role(r: &impl CatalogRead, role: Role) -> Result<Vec<Mutation>, RbacError> {
    let mut catalog = load_roles(r)?;
    if catalog.get(&role.name).is_some() {
        return Err(RbacError::RoleExists(role.name));
    }
    let m = put(&role)?;
    catalog.upsert(role)?;
    Ok(vec![m])
}

/// Replaces the privileges and inheritance of the existing custom role `role.name`. Rejects a
/// change that would close an inheritance cycle (TC-SEC-015).
///
/// # Errors
/// [`RbacError::UnknownRole`]; as [`create_role`] otherwise.
pub fn update_role(r: &impl CatalogRead, role: Role) -> Result<Vec<Mutation>, RbacError> {
    let mut catalog = load_roles(r)?;
    if catalog.get(&role.name).is_none() {
        return Err(RbacError::UnknownRole(role.name));
    }
    let m = put(&role)?;
    catalog.upsert(role)?;
    Ok(vec![m])
}

/// Drops the custom role `name`. Users still naming it simply stop receiving its privileges
/// ([`RoleCatalog::resolve`]); roles inheriting it block the drop.
///
/// # Errors
/// [`RbacError::UnknownRole`], [`RbacError::RoleInUse`], [`RbacError::Read`] /
/// [`RbacError::Corrupt`].
pub fn drop_role(r: &impl CatalogRead, name: &str) -> Result<Vec<Mutation>, RbacError> {
    let mut catalog = load_roles(r)?;
    catalog.remove(name)?;
    Ok(vec![Mutation::Delete {
        key: role_key(name),
    }])
}

/// The custom role `name`, if any.
///
/// # Errors
/// [`RbacError::Read`], [`RbacError::Corrupt`].
pub fn get_role(r: &impl CatalogRead, name: &str) -> Result<Option<Role>, RbacError> {
    r.get(&role_key(name))
        .map_err(RbacError::Read)?
        .map(|v| decode_role(&v))
        .transpose()
}
