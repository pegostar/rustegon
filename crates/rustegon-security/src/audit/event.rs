// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Audit events (security.md §4): what callers hand to [`super::AuditLog::record`].
//!
//! Secrets never reach the file: a detail is either public text or a [`Redacted`] value that is
//! written as [`REDACTED`], and public details whose key names a secret by convention
//! (`*password`, `*secret`, `*token`, `*_key`, `key`) are redacted too, so a caller that forgets
//! to wrap a value still cannot leak it (TC-SEC-004, TC-SEC-009).

use std::{collections::BTreeMap, fmt, net::IpAddr, str::FromStr};

use rustegon_common::{Redacted, redacted::REDACTED};

/// Kind of an audited event (security.md §4). The string form is the `event` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AuditEventKind {
    /// Successful authentication.
    LoginSuccess,
    /// Failed authentication (wrong credentials, unknown user, locked account).
    LoginFailure,
    /// Explicit logout.
    Logout,
    /// A session was revoked (logout elsewhere, password/role change, admin action).
    SessionRevoked,
    /// An authorization check failed (`RGN-4002`).
    PrivilegeDenied,
    /// User created, altered, disabled or dropped.
    UserChange,
    /// Role created, altered or dropped; grants and revokes.
    RoleChange,
    /// API key created, revoked or altered.
    ApiKeyChange,
    /// Schema change (databases, collections, indexes).
    Ddl,
    /// Cluster setting changed.
    SettingsChange,
    /// Zone configuration changed.
    ZoneConfigChange,
    /// Backup started or finished.
    Backup,
    /// Restore started or finished.
    Restore,
    /// Cross-cluster replication configuration changed.
    XdcChange,
    /// Key management operation (KEK rotation, provider change).
    KeyOperation,
    /// Unsafe recovery tool used.
    UnsafeRecovery,
    /// Data write through the GUI (only with `audit.data_writes`).
    DataWrite,
    /// Account locked after repeated failures (PD-048).
    AccountLocked,
    /// Account unlocked by an administrator (PD-048).
    AccountUnlocked,
}

impl AuditEventKind {
    /// Every kind, in declaration order (TC-SEC-004 iterates it).
    pub const ALL: [Self; 19] = [
        Self::LoginSuccess,
        Self::LoginFailure,
        Self::Logout,
        Self::SessionRevoked,
        Self::PrivilegeDenied,
        Self::UserChange,
        Self::RoleChange,
        Self::ApiKeyChange,
        Self::Ddl,
        Self::SettingsChange,
        Self::ZoneConfigChange,
        Self::Backup,
        Self::Restore,
        Self::XdcChange,
        Self::KeyOperation,
        Self::UnsafeRecovery,
        Self::DataWrite,
        Self::AccountLocked,
        Self::AccountUnlocked,
    ];

    /// Wire name (`event` field).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LoginSuccess => "login_success",
            Self::LoginFailure => "login_failure",
            Self::Logout => "logout",
            Self::SessionRevoked => "session_revoked",
            Self::PrivilegeDenied => "privilege_denied",
            Self::UserChange => "user_change",
            Self::RoleChange => "role_change",
            Self::ApiKeyChange => "api_key_change",
            Self::Ddl => "ddl",
            Self::SettingsChange => "settings_change",
            Self::ZoneConfigChange => "zone_config_change",
            Self::Backup => "backup",
            Self::Restore => "restore",
            Self::XdcChange => "xdc_change",
            Self::KeyOperation => "key_operation",
            Self::UnsafeRecovery => "unsafe_recovery",
            Self::DataWrite => "data_write",
            Self::AccountLocked => "account_locked",
            Self::AccountUnlocked => "account_unlocked",
        }
    }
}

impl fmt::Display for AuditEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuditEventKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| format!("unknown audit event {s:?}"))
    }
}

/// Outcome of an audited event (`outcome` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditOutcome {
    /// The operation succeeded.
    Success,
    /// The operation failed (bad credentials, error).
    Failure,
    /// The operation was refused by policy (authorization, lockout, rate limit).
    Denied,
}

impl AuditOutcome {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

impl FromStr for AuditOutcome {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::Success, Self::Failure, Self::Denied]
            .into_iter()
            .find(|o| o.as_str() == s)
            .ok_or_else(|| format!("unknown audit outcome {s:?}"))
    }
}

/// Value of an event detail.
#[derive(Debug, Clone)]
pub enum DetailValue {
    /// Text written as is (unless its key names a secret, see [`is_secret_key`]).
    Public(String),
    /// A secret: written as [`REDACTED`], never as its value.
    Secret(Redacted<String>),
}

/// Whether a detail key names a secret by convention (security.md §7 applies the same rule to
/// configuration keys). Matching is case-insensitive.
#[must_use]
pub fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k == "key"
        || k.ends_with("_key")
        || k.ends_with("password")
        || k.ends_with("secret")
        || k.ends_with("token")
        || k.ends_with("credential")
        || k.ends_with("credentials")
}

/// One audited event, built by the caller.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub(crate) kind: AuditEventKind,
    pub(crate) outcome: AuditOutcome,
    pub(crate) user: Option<String>,
    pub(crate) roles: Vec<String>,
    pub(crate) source_ip: Option<IpAddr>,
    pub(crate) resource: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) details: BTreeMap<String, DetailValue>,
}

impl AuditEvent {
    /// A new event without principal, resource or details.
    #[must_use]
    pub fn new(kind: AuditEventKind, outcome: AuditOutcome) -> Self {
        Self {
            kind,
            outcome,
            user: None,
            roles: Vec::new(),
            source_ip: None,
            resource: None,
            action: None,
            details: BTreeMap::new(),
        }
    }

    /// Event kind.
    #[must_use]
    pub fn kind(&self) -> AuditEventKind {
        self.kind
    }

    /// Sets the acting (or, for login failures, the claimed) user name.
    #[must_use]
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Sets the user's effective role names.
    #[must_use]
    pub fn roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the client address.
    #[must_use]
    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Sets the resource (`cluster`, `database:<db>`, `collection:<db>.<coll>`, ...).
    #[must_use]
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Sets the action (security.md §3.2 name, or the operation for non-RBAC events).
    #[must_use]
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Adds a public detail (still redacted if `key` names a secret).
    #[must_use]
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details
            .insert(key.into(), DetailValue::Public(value.into()));
        self
    }

    /// Adds a secret detail: the file records only that it was present.
    #[must_use]
    pub fn secret_detail(mut self, key: impl Into<String>, value: Redacted<String>) -> Self {
        self.details.insert(key.into(), DetailValue::Secret(value));
        self
    }

    /// Details as written to the file: secrets replaced by [`REDACTED`].
    pub(crate) fn redacted_details(&self) -> BTreeMap<String, String> {
        self.details
            .iter()
            .map(|(k, v)| {
                let text = match v {
                    DetailValue::Public(s) if !is_secret_key(k) => s.clone(),
                    DetailValue::Public(_) | DetailValue::Secret(_) => REDACTED.to_owned(),
                };
                (k.clone(), text)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kind_names_round_trip() {
        for k in AuditEventKind::ALL {
            assert_eq!(k.as_str().parse::<AuditEventKind>(), Ok(k));
        }
        assert!("nope".parse::<AuditEventKind>().is_err());
    }

    #[test]
    fn secret_keys_by_convention() {
        for k in [
            "password",
            "new_password",
            "api_key",
            "client_secret",
            "Token",
            "key",
        ] {
            assert!(is_secret_key(k), "{k}");
        }
        for k in ["key_id", "user", "keyspace", "reason"] {
            assert!(!is_secret_key(k), "{k}");
        }
    }
}
