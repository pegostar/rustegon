// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! RBAC: built-in roles of security.md §3.3, deny-by-default evaluation, custom roles in the
//! system keyspace (TC-SEC-014), inheritance cycles rejected (TC-SEC-015), API key scope
//! intersection (FR-SEC-002).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{cell::RefCell, collections::BTreeMap};

use rustegon_catalog::{CatalogRead, Mutation};
use rustegon_common::{Error, ErrorCode};
use rustegon_security::rbac::{
    Action, ActionGroup, ActionSet, BuiltinRole, EffectivePrivileges, Privilege, RbacError,
    Resource, ResourcePattern, Role, RoleCatalog, RoleRef, authorize, check_api_key_scope,
    store::{create_role, drop_role, get_role, load_roles, role_key, update_role},
};

/// A system keyspace in memory; `apply` plays the caller's transaction commit.
#[derive(Default)]
struct MemStore(RefCell<BTreeMap<Vec<u8>, Vec<u8>>>);

impl CatalogRead for MemStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.borrow().get(key).cloned())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
        Ok(self
            .0
            .borrow()
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

impl MemStore {
    fn apply(&self, mutations: Vec<Mutation>) {
        let mut m = self.0.borrow_mut();
        for mu in mutations {
            match mu {
                Mutation::Put { key, value } => {
                    m.insert(key, value);
                }
                Mutation::Delete { key } => {
                    m.remove(&key);
                }
            }
        }
    }
}

fn coll(db: &str, c: &str) -> Resource {
    Resource::collection(db, c)
}

fn resolve(roles: &[&str]) -> EffectivePrivileges {
    RoleCatalog::new().resolve(roles)
}

fn role(name: &str, privileges: &[(&str, &[Action])], inherits: &[&str]) -> Role {
    Role {
        name: name.into(),
        privileges: privileges
            .iter()
            .map(|(r, a)| Privilege::new(ResourcePattern::parse(r).unwrap(), a))
            .collect(),
        inherits: inherits
            .iter()
            .map(|r| RoleRef::parse(r).unwrap())
            .collect(),
    }
}

#[test]
fn rbac_deny_by_default_without_roles() {
    let none = resolve(&[] as &[&str]);
    for a in Action::ALL {
        for r in [
            Resource::Cluster,
            Resource::database("shop"),
            coll("shop", "o"),
        ] {
            let err = authorize(&none, &r, *a).unwrap_err();
            assert_eq!(err.code(), ErrorCode::PermissionDenied);
            assert_eq!(err.details()["action"], a.as_str());
            assert_eq!(err.details()["resource"], r.to_string());
        }
    }
}

#[test]
fn rbac_builtin_roles_grant_exactly_security_md_3_3() {
    let shop = Resource::database("shop");
    let orders = coll("shop", "orders");
    let other = coll("crm", "people");

    let read = resolve(&["read@shop"]);
    assert!(read.allows(&orders, Action::Find) && read.allows(&orders, Action::ChangeStream));
    assert!(!read.allows(&orders, Action::Insert));
    assert!(!read.allows(&other, Action::Find));

    let read_coll = resolve(&["read@shop.orders"]);
    assert!(read_coll.allows(&orders, Action::Find));
    assert!(!read_coll.allows(&coll("shop", "invoices"), Action::Find));
    assert!(!read_coll.allows(&shop, Action::Find));

    let rw = resolve(&["read_write@shop"]);
    for a in [
        Action::Find,
        Action::ChangeStream,
        Action::Insert,
        Action::Update,
        Action::Delete,
        Action::BulkWrite,
        Action::AggregateWrite,
    ] {
        assert!(rw.allows(&orders, a), "{a}");
    }
    assert!(!rw.allows(&orders, Action::CreateIndex));
    assert!(!rw.allows(&orders, Action::SubscriptionManage));

    let dba = resolve(&["db_admin@shop"]);
    for a in ActionSet::group(ActionGroup::Schema).iter() {
        assert!(dba.allows(&shop, a) && !dba.allows(&other, a), "{a}");
    }
    for a in [Action::QueryStatsView, Action::QueryKill, Action::TxnKill] {
        assert!(dba.allows(&shop, a) && !dba.allows(&Resource::Cluster, a));
    }
    assert!(!dba.allows(&orders, Action::Find));

    let owner = resolve(&["db_owner@shop"]);
    for a in [
        Action::Find,
        Action::Insert,
        Action::DropIndex,
        Action::UserManage,
    ] {
        assert!(owner.allows(&orders, a));
    }
    assert!(owner.allows(&shop, Action::RoleManage));
    assert!(!owner.allows(&Resource::Cluster, Action::UserManage));

    let ua = resolve(&["user_admin"]);
    assert!(ua.allows(&Resource::Cluster, Action::UserManage));
    assert!(ua.allows(&shop, Action::RoleManage));
    assert!(!ua.allows(&orders, Action::Find));

    let mon = resolve(&["monitor"]);
    assert!(mon.allows(&Resource::Cluster, Action::ClusterView));
    assert!(mon.allows(&shop, Action::QueryStatsView));
    assert!(!mon.allows(&Resource::Cluster, Action::ClusterManage));
    assert!(!mon.allows(&orders, Action::Find));

    let backup = resolve(&["backup_operator"]);
    assert!(backup.allows(&Resource::Cluster, Action::Backup));
    assert!(backup.allows(&Resource::Cluster, Action::ClusterView));
    assert!(
        !backup.allows(&orders, Action::Find),
        "backup API only, no find"
    );
    assert!(!backup.allows(&Resource::Cluster, Action::Restore));

    let restore = resolve(&["restore_operator"]);
    assert!(restore.allows(&Resource::Cluster, Action::Restore));
    assert!(!restore.allows(&Resource::Cluster, Action::Backup));

    let ca = resolve(&["cluster_admin"]);
    for a in [
        Action::ClusterManage,
        Action::ClusterView,
        Action::KeyManage,
        Action::XdcManage,
        Action::Diagnostics,
        Action::AuditView,
    ] {
        assert!(ca.allows(&Resource::Cluster, a), "{a}");
    }
    assert!(ca.allows(&shop, Action::QueryKill));
    for a in ActionSet::group(ActionGroup::Data).iter() {
        assert!(
            !ca.allows(&orders, a),
            "cluster_admin has no data access: {a}"
        );
    }
    assert!(!ca.allows(&Resource::Cluster, Action::UserManage));

    let root = resolve(&["root"]);
    for a in Action::ALL {
        for r in [Resource::Cluster, shop.clone(), orders.clone()] {
            assert!(root.allows(&r, *a));
        }
    }

    // Unscoped database roles cover every database, but not the cluster resource.
    let read_all = resolve(&["read"]);
    assert!(read_all.allows(&other, Action::Find));
    assert!(!read_all.allows(&Resource::Cluster, Action::Find));
    assert_eq!(BuiltinRole::ALL.len(), 11);
}

/// The built-in `node` role (PD-051): topology only, never data, schema or administration.
#[test]
fn rbac_node_role_grants_cluster_view_only() {
    let shop = Resource::database("shop");
    let orders = coll("shop", "orders");
    let node = resolve(&["node"]);
    assert!(node.allows(&Resource::Cluster, Action::ClusterView));
    for a in Action::ALL.iter().filter(|a| **a != Action::ClusterView) {
        for r in [Resource::Cluster, shop.clone(), orders.clone()] {
            assert!(!node.allows(&r, *a), "node must not be granted {a}");
        }
    }
    assert!(!BuiltinRole::Node.is_assignable());
    assert_eq!(
        BuiltinRole::Node.as_str(),
        rustegon_security::authn::x509::NODE_ROLE
    );
    assert!(
        BuiltinRole::ALL
            .iter()
            .filter(|r| **r != BuiltinRole::Node)
            .all(|r| r.is_assignable())
    );
}

#[test]
fn rbac_union_of_roles_and_unresolved_names_grant_nothing() {
    let e = resolve(&["read@shop", "monitor", "ghost", "Bad Name"]);
    assert!(e.allows(&coll("shop", "o"), Action::Find));
    assert!(e.allows(&Resource::Cluster, Action::ClusterView));
    assert_eq!(e.unresolved(), ["ghost", "Bad Name"]);
    assert_eq!(e.roles(), ["read@shop", "monitor"]);
}

#[test]
fn tc_sec_014_custom_roles_persist_and_grant_their_privileges() {
    let store = MemStore::default();
    let analyst = role(
        "analyst",
        &[
            ("collection:shop.orders", &[Action::Find]),
            ("collection:*.metrics", &[Action::Find]),
        ],
        &["read@crm"],
    );
    store.apply(create_role(&store, analyst.clone()).unwrap());
    assert_eq!(get_role(&store, "analyst").unwrap(), Some(analyst.clone()));
    assert!(matches!(
        create_role(&store, analyst.clone()),
        Err(RbacError::RoleExists(_))
    ));

    let lead = role(
        "lead",
        &[("database:shop", &[Action::Insert, Action::QueryKill])],
        &["analyst"],
    );
    store.apply(create_role(&store, lead).unwrap());

    let catalog = load_roles(&store).unwrap();
    assert_eq!(catalog.len(), 2);
    let e = catalog.resolve(&["lead"]);
    assert_eq!(e.roles(), ["lead", "analyst", "read@crm"]);
    assert!(e.allows(&coll("shop", "orders"), Action::Find));
    assert!(e.allows(&coll("shop", "invoices"), Action::Insert));
    assert!(!e.allows(&coll("shop", "invoices"), Action::Find));
    assert!(e.allows(&coll("iot", "metrics"), Action::Find));
    assert!(e.allows(&coll("crm", "people"), Action::ChangeStream));
    assert!(e.allows(&Resource::database("shop"), Action::QueryKill));
    assert!(!e.allows(&Resource::Cluster, Action::QueryKill));

    // Update narrows the role; drop of an inherited role is refused, then allowed.
    let narrowed = role(
        "analyst",
        &[("collection:shop.orders", &[Action::Find])],
        &[],
    );
    store.apply(update_role(&store, narrowed).unwrap());
    let e = load_roles(&store).unwrap().resolve(&["lead"]);
    assert!(!e.allows(&coll("crm", "people"), Action::Find));
    assert!(matches!(
        drop_role(&store, "analyst"),
        Err(RbacError::RoleInUse { .. })
    ));
    store.apply(drop_role(&store, "lead").unwrap());
    store.apply(drop_role(&store, "analyst").unwrap());
    assert!(load_roles(&store).unwrap().is_empty());
    assert!(matches!(
        drop_role(&store, "analyst"),
        Err(RbacError::UnknownRole(_))
    ));
}

#[test]
fn tc_sec_014_invalid_custom_roles_are_rejected() {
    let store = MemStore::default();
    let cases = [
        role("root", &[("cluster", &[Action::Find])], &[]),
        role("Analyst", &[("cluster", &[Action::Find])], &[]),
        role("a", &[("database:shop", &[Action::ClusterManage])], &[]),
        role("a", &[("database:shop", &[])], &[]),
        role("a", &[], &["missing"]),
    ];
    for r in cases {
        let err = create_role(&store, r.clone()).unwrap_err();
        let code = Error::from(err).code();
        assert!(
            matches!(code, ErrorCode::InvalidArgument | ErrorCode::NotFound),
            "{r:?}: {code:?}"
        );
    }
    assert!(matches!(
        update_role(&store, role("nobody", &[], &[])),
        Err(RbacError::UnknownRole(_))
    ));
    assert!(store.0.borrow().is_empty());
}

#[test]
fn tc_sec_015_inheritance_cycles_are_rejected() {
    let store = MemStore::default();
    // Self-inheritance on create.
    assert!(matches!(
        create_role(&store, role("a", &[], &["a"])),
        Err(RbacError::InheritanceCycle(_))
    ));
    store.apply(create_role(&store, role("a", &[], &["read"])).unwrap());
    store.apply(create_role(&store, role("b", &[], &["a"])).unwrap());
    store.apply(create_role(&store, role("c", &[], &["b", "monitor"])).unwrap());
    // a -> c closes a -> c -> b -> a.
    let err = update_role(&store, role("a", &[], &["c"])).unwrap_err();
    match &err {
        RbacError::InheritanceCycle(path) => assert_eq!(path, "a -> c -> b -> a"),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(Error::from(err).code(), ErrorCode::InvalidArgument);
    // Nothing was written and the stored graph is unchanged.
    assert_eq!(
        get_role(&store, "a").unwrap().unwrap().inherits,
        [RoleRef::parse("read").unwrap()]
    );
    // A diamond is not a cycle.
    store.apply(create_role(&store, role("d", &[], &["b", "c", "a"])).unwrap());
    let e = load_roles(&store).unwrap().resolve(&["d"]);
    assert_eq!(e.roles(), ["d", "b", "a", "read", "c", "monitor"]);

    // A cycle written behind the store's back is detected as corruption at load.
    let forged = rustegon_security::rbac::store::encode_role(&role("a", &[], &["d"])).unwrap();
    store.0.borrow_mut().insert(role_key("a"), forged);
    assert!(matches!(load_roles(&store), Err(RbacError::Corrupt(_))));

    // The in-memory catalog enforces the same rule and stays unchanged on rejection.
    let mut cat = RoleCatalog::new();
    cat.upsert(role("x", &[], &[])).unwrap();
    cat.upsert(role("y", &[], &["x"])).unwrap();
    assert!(cat.upsert(role("x", &[], &["y"])).is_err());
    assert_eq!(cat.get("x").unwrap().inherits, Vec::<RoleRef>::new());
}

#[test]
fn rbac_api_key_scope_is_a_subset_and_intersects() {
    let owner = ["read_write@shop", "monitor"];
    assert!(check_api_key_scope(&owner, &["monitor"]).is_ok());
    assert!(matches!(
        check_api_key_scope(&owner, &["root"]),
        Err(RbacError::ScopeNotSubset(_))
    ));
    let catalog = RoleCatalog::new();
    let key = catalog
        .resolve(&owner)
        .restrict_to(catalog.resolve(&["read@shop"]));
    let orders = coll("shop", "orders");
    assert!(key.allows(&orders, Action::Find));
    assert!(
        !key.allows(&orders, Action::Insert),
        "outside the key scope"
    );
    assert!(!key.allows(&Resource::Cluster, Action::ClusterView));
    // The owner losing a role shrinks the key too.
    let shrunk = catalog
        .resolve(&["monitor"])
        .restrict_to(catalog.resolve(&["read@shop"]));
    assert!(!shrunk.allows(&orders, Action::Find));
}
