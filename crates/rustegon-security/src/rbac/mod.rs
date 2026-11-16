// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Role-based access control (FR-SEC-002, security.md §3).
//!
//! - [`action`]: the actions of §3.2 and [`ActionSet`];
//! - [`resource`]: concrete [`Resource`]s and hierarchical [`ResourcePattern`]s with `*`;
//! - [`role`]: [`Privilege`], [`Role`], [`RoleRef`] and the built-in roles of §3.3;
//! - [`eval`]: role resolution, deny-by-default evaluation, [`authorize`], API-key scope
//!   intersection;
//! - [`store`]: custom roles in the system keyspace (role record format 1), written
//!   transactionally by the caller like the catalog's DDL.
//!
//! Callers (binder, service handlers) resolve a principal's role names once per session or
//! request with [`RoleCatalog::resolve`] and call [`authorize`] per check. The privilege matrix
//! over endpoints (TC-SEC-001) is declared with [`EndpointPrivilege`].

pub mod action;
pub mod eval;
pub mod resource;
pub mod role;
pub mod store;

use rustegon_common::{Error, ErrorCode};

pub use self::{
    action::{Action, ActionGroup, ActionSet},
    eval::{EffectivePrivileges, RoleCatalog, authorize, check_api_key_scope, permission_denied},
    resource::{NamePattern, Resource, ResourceKind, ResourcePattern},
    role::{BuiltinRole, Privilege, Role, RoleRef, RoleScope, RoleScopes},
};

/// The privilege an endpoint requires: `action` on the resource the request names, at level
/// `resource` (e.g. `find` on the request's collection). The privilege matrix test
/// (TC-SEC-001) enumerates one entry per gRPC/REST endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointPrivilege {
    /// Fully qualified endpoint name (`rustegon.v1.QueryService/Execute`, `POST /v1/...`).
    pub endpoint: &'static str,
    /// Required action.
    pub action: Action,
    /// Level of the resource the check is made on.
    pub resource: ResourceKind,
}

/// Errors of role management.
#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    /// Malformed role name or reference.
    #[error("invalid role name {name:?}: {reason}")]
    InvalidRoleName {
        /// The offending text.
        name: String,
        /// Why.
        reason: String,
    },
    /// Malformed resource pattern.
    #[error("invalid resource {resource:?}: {reason}")]
    InvalidResource {
        /// The offending text.
        resource: String,
        /// Why.
        reason: String,
    },
    /// Unknown action name.
    #[error("unknown action {0:?}")]
    UnknownAction(String),
    /// A privilege that can never match.
    #[error("invalid privilege on {resource}: {reason}")]
    InvalidPrivilege {
        /// Resource of the privilege.
        resource: String,
        /// Why.
        reason: String,
    },
    /// The role does not exist.
    #[error("role {0:?} not found")]
    UnknownRole(String),
    /// A custom role with this name exists already.
    #[error("role {0:?} already exists")]
    RoleExists(String),
    /// Inheritance would form a cycle (TC-SEC-015).
    #[error("role inheritance cycle: {0}")]
    InheritanceCycle(String),
    /// The role is inherited by another role.
    #[error("role {role:?} is inherited by role {inherited_by:?}")]
    RoleInUse {
        /// The role to drop.
        role: String,
        /// A role inheriting it.
        inherited_by: String,
    },
    /// An API key scope role the owner does not have.
    #[error("API key scope role {0:?} is not one of the owner's roles")]
    ScopeNotSubset(String),
    /// A role record that cannot be decoded.
    #[error("role record corrupt: {0}")]
    Corrupt(String),
    /// Error of the caller's transaction or store while reading roles.
    #[error("reading roles: {0}")]
    Read(Error),
}

impl RbacError {
    /// The protocol error code (protocol.md §7).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::UnknownRole(_) => ErrorCode::NotFound,
            Self::RoleExists(_) => ErrorCode::AlreadyExists,
            Self::Corrupt(_) => ErrorCode::StorageCorruption,
            Self::Read(e) => e.code(),
            Self::ScopeNotSubset(_) => ErrorCode::PermissionDenied,
            _ => ErrorCode::InvalidArgument,
        }
    }
}

impl From<RbacError> for Error {
    fn from(e: RbacError) -> Self {
        match e {
            RbacError::Read(inner) => inner,
            other => Error::new(other.code(), other.to_string()),
        }
    }
}
