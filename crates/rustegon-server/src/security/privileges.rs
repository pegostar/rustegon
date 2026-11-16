// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The access rule of every RPC (security.md §3, implementation-rules.md §8: "any new endpoint
//! must declare its privilege"; TC-SEC-001; PD-051).
//!
//! [`RPC_ACCESS`] lists every RPC of the `rustegon.v1` surface, registered or not, so a service
//! cannot be served without a declared rule: the gRPC gate fails closed (`RGN-5001`) for a
//! method of a registered service that has no entry, and the test
//! `tc_sec_001_every_rpc_declares_its_access` pins the table to the descriptor set.
//!
//! Who checks what:
//! - [`Access::Anonymous`]: nothing (still rate limited per source IP).
//! - [`Access::Authenticated`]: the gate requires a principal; the operation only touches the
//!   caller's own objects (its session, its cursors and transactions, its password).
//! - [`Access::Privilege`] at [`ResourceKind::Cluster`]: the gate checks `action` on `cluster`
//!   before the handler runs.
//! - [`Access::Privilege`] at database/collection level: the gate requires a principal; the
//!   handler checks `action` on the database or collection named in the request with
//!   [`crate::security::Security::require`] (the gate cannot see the decoded request).
//! - [`Access::SelfOr`]: the handler allows the caller's own objects (own user record, own API
//!   keys) and otherwise requires `action` on `cluster`.
//! - [`Access::Statement`]: RGQL statements; the query binder checks each statement's action on
//!   each collection it touches.
//! - [`Access::Listing`]: listings whose result the handler filters to the objects the caller
//!   holds any privilege on.
//!
//! Principals flagged `must_change_password` may only call RPCs whose
//! [`RpcAccess::during_password_change`] is set (security.md §2.2).

use rustegon_security::rbac::{Action, ResourceKind};

/// How an RPC is authorized (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// No authentication.
    Anonymous,
    /// Any authenticated principal, acting on its own objects only.
    Authenticated,
    /// Every listed action on a resource at the given level.
    Privilege(&'static [Action], ResourceKind),
    /// The caller's own objects, or the action on `cluster` for anybody else's.
    SelfOr(Action),
    /// Checked per statement by the query binder.
    Statement,
    /// Authenticated; results filtered to what the caller may see.
    Listing,
}

/// The access rule of one RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcAccess {
    /// Full gRPC method path, `/rustegon.v1.<Service>/<Rpc>`.
    pub method: &'static str,
    /// The rule.
    pub access: Access,
    /// Allowed for a principal that must change its password first.
    pub during_password_change: bool,
}

impl RpcAccess {
    /// The gRPC service name (`rustegon.v1.<Service>`).
    #[must_use]
    pub fn service(&self) -> &'static str {
        service_of(self.method).unwrap_or("")
    }
}

/// The service part of a gRPC method path (`/pkg.Service/Method` → `pkg.Service`).
#[must_use]
pub fn service_of(path: &str) -> Option<&str> {
    path.strip_prefix('/')?.split_once('/').map(|(s, _)| s)
}

const fn rule(method: &'static str, access: Access) -> RpcAccess {
    RpcAccess {
        method,
        access,
        during_password_change: false,
    }
}

const fn self_service(method: &'static str, access: Access) -> RpcAccess {
    RpcAccess {
        method,
        access,
        during_password_change: true,
    }
}

const fn cluster(action: &'static [Action]) -> Access {
    Access::Privilege(action, ResourceKind::Cluster)
}

const fn coll(action: &'static [Action]) -> Access {
    Access::Privilege(action, ResourceKind::Collection)
}

const fn db(action: &'static [Action]) -> Access {
    Access::Privilege(action, ResourceKind::Database)
}

/// Every RPC of `rustegon.v1` and its rule (module docs). Sorted by service as in the protos.
pub const RPC_ACCESS: &[RpcAccess] = &[
    // AuthService (auth.proto).
    self_service("/rustegon.v1.AuthService/Authenticate", Access::Anonymous),
    self_service("/rustegon.v1.AuthService/Logout", Access::Authenticated),
    self_service("/rustegon.v1.AuthService/WhoAmI", Access::Authenticated),
    // SessionService (session.proto).
    self_service("/rustegon.v1.SessionService/Ping", Access::Anonymous),
    self_service(
        "/rustegon.v1.SessionService/GetServerInfo",
        Access::Anonymous,
    ),
    // QueryService (query.proto): statements are authorized by the binder; cursors belong to
    // the principal that opened them.
    rule("/rustegon.v1.QueryService/Execute", Access::Statement),
    rule("/rustegon.v1.QueryService/GetMore", Access::Authenticated),
    rule(
        "/rustegon.v1.QueryService/KillCursor",
        Access::Authenticated,
    ),
    rule("/rustegon.v1.QueryService/Explain", Access::Statement),
    // DocumentService (document.proto).
    rule("/rustegon.v1.DocumentService/Get", coll(&[Action::Find])),
    rule(
        "/rustegon.v1.DocumentService/GetMany",
        coll(&[Action::Find]),
    ),
    rule(
        "/rustegon.v1.DocumentService/Insert",
        coll(&[Action::Insert]),
    ),
    rule(
        "/rustegon.v1.DocumentService/Replace",
        coll(&[Action::Update]),
    ),
    rule(
        "/rustegon.v1.DocumentService/Update",
        coll(&[Action::Update]),
    ),
    rule(
        "/rustegon.v1.DocumentService/Upsert",
        coll(&[Action::Insert, Action::Update]),
    ),
    rule(
        "/rustegon.v1.DocumentService/Delete",
        coll(&[Action::Delete]),
    ),
    rule(
        "/rustegon.v1.DocumentService/BulkWrite",
        coll(&[Action::BulkWrite]),
    ),
    // TransactionService (transaction.proto): a transaction belongs to its principal; the
    // statements inside it are authorized one by one.
    rule(
        "/rustegon.v1.TransactionService/Begin",
        Access::Authenticated,
    ),
    rule(
        "/rustegon.v1.TransactionService/Commit",
        Access::Authenticated,
    ),
    rule(
        "/rustegon.v1.TransactionService/Rollback",
        Access::Authenticated,
    ),
    rule(
        "/rustegon.v1.TransactionService/Status",
        Access::Authenticated,
    ),
    rule(
        "/rustegon.v1.TransactionService/Heartbeat",
        Access::Authenticated,
    ),
    // SchemaService (schema.proto).
    rule(
        "/rustegon.v1.SchemaService/CreateDatabase",
        db(&[Action::CreateDatabase]),
    ),
    rule(
        "/rustegon.v1.SchemaService/DropDatabase",
        db(&[Action::DropDatabase]),
    ),
    rule("/rustegon.v1.SchemaService/ListDatabases", Access::Listing),
    rule(
        "/rustegon.v1.SchemaService/CreateCollection",
        coll(&[Action::CreateCollection]),
    ),
    rule(
        "/rustegon.v1.SchemaService/DropCollection",
        coll(&[Action::DropCollection]),
    ),
    rule(
        "/rustegon.v1.SchemaService/AlterCollection",
        coll(&[Action::AlterCollection]),
    ),
    rule(
        "/rustegon.v1.SchemaService/GetCollection",
        coll(&[Action::Find]),
    ),
    rule(
        "/rustegon.v1.SchemaService/ListCollections",
        Access::Listing,
    ),
    rule(
        "/rustegon.v1.SchemaService/CreateIndex",
        coll(&[Action::CreateIndex]),
    ),
    rule(
        "/rustegon.v1.SchemaService/DropIndex",
        coll(&[Action::DropIndex]),
    ),
    rule(
        "/rustegon.v1.SchemaService/ListIndexes",
        coll(&[Action::Find]),
    ),
    rule(
        "/rustegon.v1.SchemaService/IndexBuildProgress",
        coll(&[Action::Find]),
    ),
    rule(
        "/rustegon.v1.SchemaService/GetValidator",
        coll(&[Action::Find]),
    ),
    rule(
        "/rustegon.v1.SchemaService/SetValidator",
        coll(&[Action::AlterCollection]),
    ),
    rule(
        "/rustegon.v1.SchemaService/RemoveValidator",
        coll(&[Action::AlterCollection]),
    ),
    // AdminService (admin.proto).
    rule(
        "/rustegon.v1.AdminService/CreateUser",
        cluster(&[Action::UserManage]),
    ),
    rule(
        "/rustegon.v1.AdminService/GetUser",
        Access::SelfOr(Action::UserManage),
    ),
    rule(
        "/rustegon.v1.AdminService/ListUsers",
        cluster(&[Action::UserManage]),
    ),
    rule(
        "/rustegon.v1.AdminService/UpdateUser",
        cluster(&[Action::UserManage]),
    ),
    rule(
        "/rustegon.v1.AdminService/DropUser",
        cluster(&[Action::UserManage]),
    ),
    self_service(
        "/rustegon.v1.AdminService/ChangePassword",
        Access::Authenticated,
    ),
    rule(
        "/rustegon.v1.AdminService/CreateRole",
        cluster(&[Action::RoleManage]),
    ),
    rule(
        "/rustegon.v1.AdminService/GetRole",
        cluster(&[Action::RoleManage]),
    ),
    rule(
        "/rustegon.v1.AdminService/ListRoles",
        cluster(&[Action::RoleManage]),
    ),
    rule(
        "/rustegon.v1.AdminService/UpdateRole",
        cluster(&[Action::RoleManage]),
    ),
    rule(
        "/rustegon.v1.AdminService/DropRole",
        cluster(&[Action::RoleManage]),
    ),
    rule(
        "/rustegon.v1.AdminService/CreateApiKey",
        Access::SelfOr(Action::UserManage),
    ),
    rule(
        "/rustegon.v1.AdminService/ListApiKeys",
        Access::SelfOr(Action::UserManage),
    ),
    rule(
        "/rustegon.v1.AdminService/RevokeApiKey",
        Access::SelfOr(Action::UserManage),
    ),
    rule(
        "/rustegon.v1.AdminService/GetSettings",
        cluster(&[Action::ClusterView]),
    ),
    rule(
        "/rustegon.v1.AdminService/UpdateSettings",
        cluster(&[Action::ClusterManage]),
    ),
    // BackupService (backup.proto, PD-062): `backup` for backups, snapshots and dumps (a dump
    // reads every document, so it is the backup action, never `find`); `restore` for the
    // logical import. Physical and snapshot restores are offline CLI operations without RPC.
    rule(
        "/rustegon.v1.BackupService/CreateBackup",
        cluster(&[Action::Backup]),
    ),
    rule(
        "/rustegon.v1.BackupService/ListBackups",
        cluster(&[Action::Backup]),
    ),
    rule(
        "/rustegon.v1.BackupService/GetBackup",
        cluster(&[Action::Backup]),
    ),
    rule(
        "/rustegon.v1.BackupService/VerifyBackup",
        cluster(&[Action::Backup]),
    ),
    rule(
        "/rustegon.v1.BackupService/CreateSnapshot",
        cluster(&[Action::Backup]),
    ),
    rule(
        "/rustegon.v1.BackupService/ListSnapshots",
        cluster(&[Action::Backup]),
    ),
    rule(
        "/rustegon.v1.BackupService/DeleteSnapshot",
        cluster(&[Action::Backup]),
    ),
    rule(
        "/rustegon.v1.BackupService/Dump",
        cluster(&[Action::Backup]),
    ),
    rule(
        "/rustegon.v1.BackupService/LogicalRestore",
        cluster(&[Action::Restore]),
    ),
];

/// Pseudo-method of the Prometheus scrape endpoint `GET /metrics` (protocol.md §1), which has
/// no gRPC counterpart. Not a `/pkg.Service/Method` path, so it can never collide with an RPC
/// and [`service_of`] gives it no service.
pub const METRICS_ENDPOINT: &str = "GET /metrics";

/// Access rules of HTTP-only endpoints, which have no RPC (PD-059). The REST endpoint table
/// names them like RPCs, so the REST gate and the privilege matrix treat them identically.
///
/// `GET /metrics`: the `monitor` role or a scrape API key (protocol.md §1). Scraping metrics is
/// the `cluster_view` action (security.md §3.3 lists "metrics" for `monitor`, which holds
/// `cluster_view`); a user or API key holding any role with `cluster_view` may scrape.
pub const HTTP_ACCESS: &[RpcAccess] = &[rule(METRICS_ENDPOINT, cluster(&[Action::ClusterView]))];

/// The rule of the RPC at `method` (full gRPC path) or of an HTTP-only endpoint
/// ([`HTTP_ACCESS`]), if declared.
#[must_use]
pub fn access_of(method: &str) -> Option<&'static RpcAccess> {
    RPC_ACCESS
        .iter()
        .chain(HTTP_ACCESS)
        .find(|r| r.method == method)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeSet;

    use prost::Message as _;
    use prost_types::FileDescriptorSet;
    use rustegon_proto::FILE_DESCRIPTOR_SET;

    use super::*;

    /// TC-SEC-001 part: the table covers exactly the RPCs of the descriptor set (no endpoint
    /// without a declared rule, no stale rule), and privileges name grantable levels.
    #[test]
    fn tc_sec_001_every_rpc_declares_its_access() {
        let fds = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
        let mut described = BTreeSet::new();
        for file in &fds.file {
            for service in &file.service {
                for method in &service.method {
                    described.insert(format!(
                        "/{}.{}/{}",
                        file.package(),
                        service.name(),
                        method.name()
                    ));
                }
            }
        }
        let declared: BTreeSet<String> = RPC_ACCESS.iter().map(|r| r.method.to_owned()).collect();
        assert_eq!(declared.len(), RPC_ACCESS.len(), "duplicate rule");
        assert_eq!(declared, described);
        for r in RPC_ACCESS {
            if let Access::Privilege(actions, level) = r.access {
                assert!(!actions.is_empty(), "{}", r.method);
                for a in actions {
                    assert!(a.finest_scope() <= level, "{}: {a} at {level:?}", r.method);
                }
            }
            assert_eq!(access_of(r.method), Some(r));
        }
        assert_eq!(
            service_of("/rustegon.v1.AdminService/GetUser"),
            Some("rustegon.v1.AdminService")
        );
        assert_eq!(service_of("nonsense"), None);
        // HTTP-only rules never shadow an RPC and belong to no gRPC service.
        for r in HTTP_ACCESS {
            assert!(!described.contains(r.method), "{}", r.method);
            assert_eq!(service_of(r.method), None);
            assert_eq!(access_of(r.method), Some(r));
        }
    }
}
