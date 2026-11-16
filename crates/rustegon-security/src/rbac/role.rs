// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Privileges, roles, role references and the built-in roles of security.md §3.3.

use std::fmt;

use super::{
    RbacError,
    action::{Action, ActionGroup, ActionSet},
    resource::{NamePattern, ResourcePattern},
};

/// Maximum length of a custom role name.
pub const MAX_ROLE_NAME_LEN: usize = 64;
/// Separator between a role name and its scope in a [`RoleRef`] (`read@shop`).
pub const SCOPE_SEPARATOR: char = '@';

/// A grant of `actions` on `resource` (security.md §3.1: one privilege per pair; pairs sharing a
/// resource are kept together).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Privilege {
    /// Resource pattern.
    pub resource: ResourcePattern,
    /// Granted actions (never empty in a valid role).
    pub actions: ActionSet,
}

impl Privilege {
    /// A privilege granting `actions` on `resource`.
    #[must_use]
    pub fn new(resource: ResourcePattern, actions: &[Action]) -> Self {
        Self {
            resource,
            actions: ActionSet::of(actions),
        }
    }

    /// Checks that the privilege grants something and that every action can be checked at the
    /// resource's level ([`Action::finest_scope`]): `cluster_manage` on `database:x` would never
    /// match any check, so it is rejected instead of silently granting nothing.
    ///
    /// # Errors
    /// [`RbacError::InvalidPrivilege`].
    pub fn validate(&self) -> Result<(), RbacError> {
        if self.actions.is_empty() {
            return Err(RbacError::InvalidPrivilege {
                resource: self.resource.to_string(),
                reason: "no actions".into(),
            });
        }
        let level = self.resource.kind();
        if let Some(a) = self.actions.iter().find(|a| level < a.finest_scope()) {
            return Err(RbacError::InvalidPrivilege {
                resource: self.resource.to_string(),
                reason: format!(
                    "action {a} cannot be granted below the {:?} level",
                    a.finest_scope()
                ),
            });
        }
        Ok(())
    }
}

/// Scope of a built-in database role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RoleScope {
    /// `<role>@<db>`.
    Database(String),
    /// `<role>@<db>.<coll>`.
    Collection(String, String),
}

/// A role as named in a user record, an API key scope or a custom role's `inherits`.
///
/// Grammar (*Provisional (PD-048)*): `<name>` or, for the database-scoped built-ins
/// (`read`, `read_write`, `db_admin`, `db_owner`), `<name>@<db>` and, for `read` and
/// `read_write`, `<name>@<db>.<coll>`. An unscoped database built-in applies to every
/// database (`database:*`). Custom roles carry their resources in their privileges and are
/// never scoped.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleRef(String);

impl RoleRef {
    /// Parses and validates a role reference.
    ///
    /// # Errors
    /// [`RbacError::InvalidRoleName`] when the name or scope is malformed or the scope does not
    /// fit the role.
    pub fn parse(text: &str) -> Result<Self, RbacError> {
        let r = Self(text.to_owned());
        r.split()?;
        Ok(r)
    }

    /// The text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The role name without scope.
    #[must_use]
    pub fn name(&self) -> &str {
        self.0
            .split_once(SCOPE_SEPARATOR)
            .map_or(self.0.as_str(), |(n, _)| n)
    }

    /// Splits into name, built-in role (if any) and scope.
    pub(crate) fn split(
        &self,
    ) -> Result<(&str, Option<BuiltinRole>, Option<RoleScope>), RbacError> {
        let invalid = |reason: &str| RbacError::InvalidRoleName {
            name: self.0.clone(),
            reason: reason.to_owned(),
        };
        let (name, scope_text) = match self.0.split_once(SCOPE_SEPARATOR) {
            Some((n, s)) => (n, Some(s)),
            None => (self.0.as_str(), None),
        };
        validate_role_name_syntax(name).map_err(|r| invalid(&r))?;
        let builtin = BuiltinRole::parse(name);
        let scope = match scope_text {
            None => None,
            Some(s) => {
                let scope = parse_scope(s).map_err(|r| invalid(&r))?;
                let allowed = builtin.map(BuiltinRole::scopes);
                let ok = matches!(
                    (&scope, allowed),
                    (
                        RoleScope::Database(_),
                        Some(RoleScopes::Database | RoleScopes::DatabaseOrCollection),
                    ) | (
                        RoleScope::Collection(..),
                        Some(RoleScopes::DatabaseOrCollection)
                    )
                );
                if !ok {
                    return Err(invalid("this role cannot take this scope"));
                }
                Some(scope)
            }
        };
        Ok((name, builtin, scope))
    }
}

impl fmt::Display for RoleRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn parse_scope(s: &str) -> Result<RoleScope, String> {
    match s.split_once('.') {
        None => {
            rustegon_catalog::name::validate_database_name(s).map_err(|e| e.to_string())?;
            Ok(RoleScope::Database(s.to_owned()))
        }
        Some((db, coll)) => {
            rustegon_catalog::name::validate_database_name(db).map_err(|e| e.to_string())?;
            rustegon_catalog::name::validate_collection_name(coll).map_err(|e| e.to_string())?;
            Ok(RoleScope::Collection(db.to_owned(), coll.to_owned()))
        }
    }
}

/// Role names: 1–64 characters `[a-z0-9_-]`, starting with a letter. The restricted set keeps
/// the system key (`0x02 'r' name`) NUL-free and case-insensitive collisions impossible.
fn validate_role_name_syntax(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_ROLE_NAME_LEN {
        return Err(format!(
            "role names have 1 to {MAX_ROLE_NAME_LEN} characters"
        ));
    }
    if !name.starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err("role names start with a lowercase letter".into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err("allowed characters are [a-z0-9_-]".into());
    }
    Ok(())
}

/// Validates the name of a new custom role (syntax, not a built-in name).
///
/// # Errors
/// [`RbacError::InvalidRoleName`].
pub fn validate_custom_role_name(name: &str) -> Result<(), RbacError> {
    let invalid = |reason: String| RbacError::InvalidRoleName {
        name: name.to_owned(),
        reason,
    };
    validate_role_name_syntax(name).map_err(invalid)?;
    if BuiltinRole::parse(name).is_some() {
        return Err(invalid("the name of a built-in role".into()));
    }
    Ok(())
}

/// A custom role (security.md §3.1). Built-in roles are not stored ([`BuiltinRole`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    /// Unique name ([`validate_custom_role_name`]).
    pub name: String,
    /// Directly granted privileges.
    pub privileges: Vec<Privilege>,
    /// Roles whose privileges this role also has (built-in or custom; acyclic).
    pub inherits: Vec<RoleRef>,
}

impl Role {
    /// Checks name and privileges (inheritance is checked against the role catalog).
    ///
    /// # Errors
    /// [`RbacError::InvalidRoleName`], [`RbacError::InvalidPrivilege`].
    pub fn validate(&self) -> Result<(), RbacError> {
        validate_custom_role_name(&self.name)?;
        self.privileges.iter().try_for_each(Privilege::validate)
    }
}

/// Scopes a built-in role accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleScopes {
    /// Cluster role: no scope.
    Cluster,
    /// `@<db>` only.
    Database,
    /// `@<db>` or `@<db>.<coll>`.
    DatabaseOrCollection,
}

/// The built-in roles of security.md §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinRole {
    /// `read`.
    Read,
    /// `read_write`.
    ReadWrite,
    /// `db_admin`.
    DbAdmin,
    /// `db_owner`.
    DbOwner,
    /// `user_admin`.
    UserAdmin,
    /// `monitor`.
    Monitor,
    /// `backup_operator`.
    BackupOperator,
    /// `restore_operator`.
    RestoreOperator,
    /// `cluster_admin`.
    ClusterAdmin,
    /// `root`.
    Root,
    /// `node`: cluster node principals (`node:<CN>`, mapped from the node role OID of a node
    /// certificate by `crate::authn::x509`). Not assignable to users or API keys
    /// ([`BuiltinRole::is_assignable`]); see [`NODE_ACTIONS`].
    Node,
}

/// Actions of the built-in `node` role (PD-051). A peer acts on the client-facing API only as
/// itself, never on behalf of a user: requests it forwards for a user are authorized at the
/// gateway node with that user's principal, and the inter-node services (`Internal*`, peer
/// port, security.md §5, protocol.md §1) authorize the *node identity* (a certificate-derived
/// `node:` principal), not RBAC actions. What remains for a node on the client port is
/// reading the cluster topology and server information (`cluster_view`). Everything else —
/// data, schema, users, settings, backups — is denied, so a stolen node certificate used
/// against the client port reveals no data.
pub const NODE_ACTIONS: &[Action] = &[Action::ClusterView];

const READ: &[Action] = &[Action::Find, Action::ChangeStream];
const WRITE: &[Action] = &[
    Action::Insert,
    Action::Update,
    Action::Delete,
    Action::BulkWrite,
    Action::AggregateWrite,
];
const DB_OPS: &[Action] = &[Action::QueryStatsView, Action::QueryKill, Action::TxnKill];
const DB_ACCESS_ADMIN: &[Action] = &[Action::UserManage, Action::RoleManage];
/// `cluster_admin`: "all cluster actions except data access" — the Admin group minus user and
/// role management (`user_admin`) and backup/restore (which read or write all data and have
/// their operator roles), plus the txn/ops group on every database (PD-048).
const CLUSTER_ADMIN: &[Action] = &[
    Action::ClusterView,
    Action::ClusterManage,
    Action::AuditView,
    Action::Diagnostics,
    Action::XdcManage,
    Action::KeyManage,
    Action::QueryStatsView,
    Action::QueryKill,
    Action::TxnKill,
];

impl BuiltinRole {
    /// Every built-in role.
    pub const ALL: [Self; 11] = [
        Self::Read,
        Self::ReadWrite,
        Self::DbAdmin,
        Self::DbOwner,
        Self::UserAdmin,
        Self::Monitor,
        Self::BackupOperator,
        Self::RestoreOperator,
        Self::ClusterAdmin,
        Self::Root,
        Self::Node,
    ];

    /// The role name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "read_write",
            Self::DbAdmin => "db_admin",
            Self::DbOwner => "db_owner",
            Self::UserAdmin => "user_admin",
            Self::Monitor => "monitor",
            Self::BackupOperator => "backup_operator",
            Self::RestoreOperator => "restore_operator",
            Self::ClusterAdmin => "cluster_admin",
            Self::Root => "root",
            Self::Node => "node",
        }
    }

    /// The built-in role named `name`, if any.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == name)
    }

    /// Whether the role may be granted to users and API keys. `node` may not: it is derived
    /// from node certificates only, so holding it always means "authenticated as a cluster
    /// node" (PD-051).
    #[must_use]
    pub const fn is_assignable(self) -> bool {
        !matches!(self, Self::Node)
    }

    /// The scopes the role accepts in a [`RoleRef`].
    #[must_use]
    pub const fn scopes(self) -> RoleScopes {
        match self {
            Self::Read | Self::ReadWrite => RoleScopes::DatabaseOrCollection,
            Self::DbAdmin | Self::DbOwner => RoleScopes::Database,
            _ => RoleScopes::Cluster,
        }
    }

    /// The actions the role grants on its resource (security.md §3.3).
    #[must_use]
    pub fn actions(self) -> ActionSet {
        let read = ActionSet::of(READ);
        let read_write = read.union(ActionSet::of(WRITE));
        let db_admin = ActionSet::group(ActionGroup::Schema).union(ActionSet::of(DB_OPS));
        match self {
            Self::Read => read,
            Self::ReadWrite => read_write,
            Self::DbAdmin => db_admin,
            Self::DbOwner => db_admin
                .union(read_write)
                .union(ActionSet::of(DB_ACCESS_ADMIN)),
            Self::UserAdmin => ActionSet::of(DB_ACCESS_ADMIN),
            // "metrics" in §3.3 is not an action of §3.2: scraping metrics is `cluster_view`.
            Self::Monitor => ActionSet::of(&[Action::ClusterView, Action::QueryStatsView]),
            // "read of all data via backup API only": the `backup` action, never `find`.
            Self::BackupOperator => ActionSet::of(&[Action::Backup, Action::ClusterView]),
            Self::RestoreOperator => ActionSet::of(&[Action::Restore]),
            Self::ClusterAdmin => ActionSet::of(CLUSTER_ADMIN),
            Self::Root => ActionSet::all(),
            Self::Node => ActionSet::of(NODE_ACTIONS),
        }
    }

    /// The privileges of the role under `scope` (unscoped database roles cover every
    /// database). The scope must already be valid for the role ([`RoleRef::parse`]).
    #[must_use]
    pub fn privileges(self, scope: Option<&RoleScope>) -> Privilege {
        let resource = match (self.scopes(), scope) {
            (RoleScopes::Cluster, _) => ResourcePattern::Cluster,
            (_, None) => ResourcePattern::Database(NamePattern::Any),
            (_, Some(RoleScope::Database(db))) => ResourcePattern::database(db.clone()),
            (_, Some(RoleScope::Collection(db, coll))) => {
                ResourcePattern::collection(db.clone(), coll.clone())
            }
        };
        Privilege {
            resource,
            actions: self.actions(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn role_refs_parse_with_valid_scopes_only() {
        for ok in [
            "read",
            "read@shop",
            "read@shop.orders",
            "read_write@shop.orders.2026",
            "db_admin@shop",
            "db_owner",
            "root",
            "analyst",
            "etl-writer2",
        ] {
            assert_eq!(RoleRef::parse(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            "Read",
            "1role",
            "root@shop",
            "db_admin@shop.orders",
            "analyst@shop",
            "read@",
            "read@Shop",
            "read@shop.",
            "re ad",
        ] {
            assert!(RoleRef::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(RoleRef::parse("read@shop").unwrap().name(), "read");
    }

    #[test]
    fn custom_role_names_cannot_shadow_builtins() {
        assert!(validate_custom_role_name("analyst").is_ok());
        for b in BuiltinRole::ALL {
            assert!(validate_custom_role_name(b.as_str()).is_err());
        }
        assert!(validate_custom_role_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn privileges_must_be_grantable_at_their_level() {
        let p = |r: &str, a: &[Action]| Privilege::new(ResourcePattern::parse(r).unwrap(), a);
        assert!(
            p("cluster", &[Action::Find, Action::KeyManage])
                .validate()
                .is_ok()
        );
        assert!(
            p("database:shop", &[Action::Find, Action::TxnKill])
                .validate()
                .is_ok()
        );
        assert!(
            p("database:shop", &[Action::ClusterManage])
                .validate()
                .is_err()
        );
        assert!(
            p("collection:shop.o", &[Action::CreateIndex])
                .validate()
                .is_ok()
        );
        assert!(
            p("collection:shop.o", &[Action::DropDatabase])
                .validate()
                .is_err()
        );
        assert!(p("collection:shop.o", &[]).validate().is_err());
    }
}
