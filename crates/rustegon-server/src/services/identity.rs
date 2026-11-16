// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Who is calling and over what connection (security.md §2–§3; PD-051).
//!
//! - [`crate::ConnectionInfo`] (in `crate::listener`) carries the per-connection facts the
//!   authentication layer needs: remote address, verified client certificate chain and the
//!   RFC 9266 `tls-exporter` channel binding.
//! - [`Principal`]: the authenticated caller of one request with its resolved privileges, set
//!   on the [`super::RequestContext`] by the authentication layer
//!   (`crate::security::Security::authenticate`).

use std::sync::Arc;

use rustegon_common::{Error, ErrorCode};
use rustegon_security::{
    authn::{self, AuthMethod, PasswordChange, users::NODE_PREFIX},
    rbac::{Action, EffectivePrivileges, Resource, permission_denied},
};

/// An authenticated caller and its effective privileges.
///
/// Built by the authentication layer from a session token, an API key or a client certificate;
/// the privileges are resolved once per request from the principal's roles (built-in and
/// custom, with inheritance; for API keys the key scope intersected with the owner's roles).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Principal {
    /// User name (`x509:CN=…` for certificate users, `node:<CN>` for cluster nodes).
    pub user: String,
    /// Role names that apply to this request.
    pub roles: Vec<String>,
    /// How the request authenticated.
    pub method: AuthMethod,
    /// Whether the user must change its password before anything else.
    pub password_change: PasswordChange,
    privileges: Arc<EffectivePrivileges>,
}

impl Principal {
    /// A principal for `user` without roles: every privilege check fails (tests, tools).
    #[must_use]
    pub fn new(user: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            roles: Vec::new(),
            method: AuthMethod::Session,
            password_change: PasswordChange::NotRequired,
            privileges: Arc::new(EffectivePrivileges::default()),
        }
    }

    /// The principal of an authentication result with its resolved privileges.
    #[must_use]
    pub fn resolved(principal: authn::Principal, privileges: EffectivePrivileges) -> Self {
        Self {
            user: principal.user,
            roles: principal.roles,
            method: principal.method,
            password_change: principal.password_change,
            privileges: Arc::new(privileges),
        }
    }

    /// The effective privileges.
    #[must_use]
    pub fn privileges(&self) -> &EffectivePrivileges {
        &self.privileges
    }

    /// Whether `action` on `resource` is allowed (no audit; see
    /// `crate::security::Security::require` for the audited check).
    #[must_use]
    pub fn allows(&self, resource: &Resource, action: Action) -> bool {
        self.privileges.allows(resource, action)
    }

    /// [`Principal::allows`] as a result.
    ///
    /// # Errors
    /// `RGN-4002 PermissionDenied`.
    pub fn check(&self, resource: &Resource, action: Action) -> Result<(), Error> {
        if self.allows(resource, action) {
            Ok(())
        } else {
            Err(permission_denied(resource, action))
        }
    }

    /// Whether this is a cluster node authenticated by its node certificate. Only the
    /// certificate mapping produces such principals: user names cannot start with `node:` and
    /// the `node` role cannot be granted (PD-051).
    #[must_use]
    pub fn is_node(&self) -> bool {
        self.method == AuthMethod::Certificate && self.user.starts_with(NODE_PREFIX)
    }

    /// The API key id when the request authenticated with an API key.
    #[must_use]
    pub fn api_key_id(&self) -> Option<&str> {
        match &self.method {
            AuthMethod::ApiKey(id) => Some(id),
            _ => None,
        }
    }
}

/// RGN-4001 for a request that needs a principal but has none (or a rejected credential).
#[must_use]
pub fn unauthenticated() -> Error {
    Error::new(ErrorCode::Unauthenticated, authn::AUTHENTICATION_FAILED)
}
