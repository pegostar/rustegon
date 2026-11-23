// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `AdminService`: users, roles, API keys and runtime settings (admin.proto, security.md §2–§3;
//! FR-SEC-001, FR-SEC-002; PD-051).
//!
//! Authorization follows [`crate::security::RPC_ACCESS`]: cluster-level privileges
//! (`user_manage`, `role_manage`, `cluster_view`, `cluster_manage`) are checked by the gate
//! before a handler runs; the "self or `user_manage`" operations (own user record, own API
//! keys) are decided here with [`Security::require`]. Every change is one system transaction,
//! counted against the per-user `admin_op` rate limit, and audited after it committed
//! (`user_change`, `role_change`, `api_key_change`, `settings_change`; never secret values).
//!
//! Role grants are role references (`read@shop`, `read_write@shop.orders`, `root`, custom role
//! names): built-in names must fit their scope, custom roles must exist, and the `node` role
//! cannot be granted. An API key's scope must be a non-empty subset of its owner's roles and,
//! when the caller creates a key for itself, of the caller's own effective roles — so a key
//! can never mint a broader key.
//!
//! X.509 users are named `x509:<subject>` (`x509:CN=svc`): `x509_subject` in a request must be
//! empty or equal that subject, and responses report it for `x509:` users (PD-051).

use std::{collections::BTreeMap, net::IpAddr, str::FromStr, sync::Arc, time::SystemTime};

use rustegon_common::{Error, ErrorCode};
use rustegon_security::{
    audit::{AuditEventKind, AuditOutcome},
    authn::{
        PasswordChange, SecretString, SystemTxn,
        apikey::{self, ApiKeyRecord, Cidr, NewApiKey},
        users::{self, NewUser, UserRecord, UserState, X509_PREFIX},
    },
    ratelimit::LimitClass,
    rbac::{
        Action, ActionSet, BuiltinRole, Privilege, Resource, ResourcePattern, Role, RoleRef,
        store as roles,
    },
};

use super::{RequestContext, unauthenticated};
use crate::{
    Completion,
    security::{Reader, Security, SettingInfo, access_of, override_mutations},
};

/// A user as reported by the service (no credentials).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    /// Name.
    pub name: String,
    /// Role references.
    pub roles: Vec<String>,
    /// Disabled users cannot authenticate.
    pub disabled: bool,
    /// The password must be changed at next login.
    pub must_change_password: bool,
    /// X.509 subject for `x509:` users.
    pub x509_subject: Option<String>,
    /// Creation time.
    pub created_at: SystemTime,
}

/// `CreateUser` input.
#[derive(Debug, Clone)]
pub struct NewUserSpec {
    /// Name.
    pub name: String,
    /// Initial password (secret).
    pub password: Option<SecretString>,
    /// Role references.
    pub roles: Vec<String>,
    /// Force a password change at first login.
    pub must_change_password: bool,
    /// X.509 subject (must match the name, module docs).
    pub x509_subject: Option<String>,
}

/// `UpdateUser` input; `None` = unchanged.
#[derive(Debug, Clone, Default)]
pub struct UserUpdate {
    /// Name of the user to change.
    pub name: String,
    /// New password (secret).
    pub password: Option<SecretString>,
    /// New role references.
    pub roles: Option<Vec<String>>,
    /// Enable/disable.
    pub disabled: Option<bool>,
    /// Force or clear a password change.
    pub must_change_password: Option<bool>,
    /// X.509 subject (cannot change: it is the name).
    pub x509_subject: Option<String>,
}

/// A role as reported by the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleInfo {
    /// Name.
    pub name: String,
    /// `(resource pattern, action names)` pairs.
    pub privileges: Vec<(String, Vec<String>)>,
    /// Inherited role references.
    pub inherits: Vec<String>,
    /// Built-in roles cannot be changed or dropped.
    pub built_in: bool,
}

/// An API key as reported by the service (never its secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyInfo {
    /// Key id.
    pub key_id: String,
    /// Owner.
    pub user: String,
    /// Description (the key's label).
    pub description: String,
    /// Scope.
    pub roles: Vec<String>,
    /// Expiry.
    pub expires_at: Option<SystemTime>,
    /// Allowed client networks.
    pub ip_allowlist: Vec<String>,
    /// Creation time.
    pub created_at: SystemTime,
}

/// `CreateApiKey` input.
#[derive(Debug, Clone, Default)]
pub struct NewApiKeySpec {
    /// Owner (default: the caller).
    pub user: Option<String>,
    /// Description.
    pub description: String,
    /// Scope.
    pub roles: Vec<String>,
    /// Expiry.
    pub expires_at: Option<SystemTime>,
    /// Allowed client IPs/CIDRs.
    pub ip_allowlist: Vec<String>,
}

/// The process side of a node restart (PD-230), installed by `rustegond`
/// ([`crate::services::Services::with_node_control`]): stopping and starting the node cannot
/// happen inside a request, so the service hands it over and returns.
pub trait NodeControl: Send + Sync + 'static {
    /// Asks the node to stop serving after the current requests and serve again in the same
    /// process, with its configuration file read again (static settings take effect).
    ///
    /// # Errors
    /// RGN-1031 when a restart is already under way.
    fn restart(&self) -> Result<(), Error>;

    /// Why the last restart could not start with the new configuration; the node then served
    /// with the previous one (`None`: no restart failed).
    fn last_restart_error(&self) -> Option<String>;
}

/// The administration service (module docs).
#[derive(Clone)]
pub struct AdminService {
    security: Option<Arc<Security>>,
    control: Option<Arc<dyn NodeControl>>,
}

impl std::fmt::Debug for AdminService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminService")
            .field("security", &self.security)
            .field("restartable", &self.control.is_some())
            .finish()
    }
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, msg)
}

fn user_info(u: &UserRecord) -> UserInfo {
    UserInfo {
        name: u.name.clone(),
        roles: u.roles.clone(),
        disabled: u.state == UserState::Disabled,
        must_change_password: u.password_change == PasswordChange::Required,
        x509_subject: u.name.strip_prefix(X509_PREFIX).map(str::to_owned),
        created_at: u.created_at,
    }
}

fn key_info(k: &ApiKeyRecord) -> ApiKeyInfo {
    ApiKeyInfo {
        key_id: k.key_id.clone(),
        user: k.user.clone(),
        description: k.name.clone(),
        roles: k.roles.clone(),
        expires_at: k.expires_at,
        ip_allowlist: k.allow.iter().map(ToString::to_string).collect(),
        created_at: k.created_at,
    }
}

fn role_info(r: &Role, built_in: bool) -> RoleInfo {
    RoleInfo {
        name: r.name.clone(),
        privileges: r
            .privileges
            .iter()
            .map(|p| {
                (
                    p.resource.to_string(),
                    p.actions.iter().map(|a| a.as_str().to_owned()).collect(),
                )
            })
            .collect(),
        inherits: r.inherits.iter().map(ToString::to_string).collect(),
        built_in,
    }
}

fn builtin_info(b: BuiltinRole) -> RoleInfo {
    let role = Role {
        name: b.as_str().to_owned(),
        privileges: vec![b.privileges(None)],
        inherits: Vec::new(),
    };
    role_info(&role, true)
}

/// Converts a role description into the RBAC model.
///
/// # Errors
/// `RGN-1001` for a malformed resource, an unknown action or a malformed inherited reference.
pub fn role_from_info(info: &RoleInfo) -> Result<Role, Error> {
    if info.built_in {
        return Err(invalid("built_in must be false for custom roles"));
    }
    let privileges = info
        .privileges
        .iter()
        .map(|(resource, actions)| {
            let resource = ResourcePattern::parse(resource)?;
            let actions = actions
                .iter()
                .map(|a| Action::parse(a).ok_or_else(|| invalid(format!("unknown action {a:?}"))))
                .collect::<Result<ActionSet, Error>>()?;
            Ok(Privilege { resource, actions })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let inherits = info
        .inherits
        .iter()
        .map(|r| RoleRef::parse(r).map_err(Error::from))
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Role {
        name: info.name.clone(),
        privileges,
        inherits,
    })
}

/// Validates role grants for a user: well-formed references, assignable built-ins, existing
/// custom roles.
fn check_grants(txn: &dyn SystemTxn, grants: &[String]) -> Result<(), Error> {
    let mut catalog = None;
    for grant in grants {
        let r = RoleRef::parse(grant)?;
        match BuiltinRole::parse(r.name()) {
            Some(b) if !b.is_assignable() => {
                return Err(invalid(format!("role {:?} cannot be granted", r.name())));
            }
            Some(_) => {}
            None => {
                if catalog.is_none() {
                    catalog = Some(roles::load_roles(&Reader(txn))?);
                }
                if catalog.as_ref().is_some_and(|c| c.get(r.name()).is_none()) {
                    return Err(Error::new(
                        ErrorCode::NotFound,
                        format!("role {:?} not found", r.name()),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn check_subject(name: &str, subject: Option<&str>) -> Result<(), Error> {
    match subject.filter(|s| !s.is_empty()) {
        None => Ok(()),
        Some(s) if name.strip_prefix(X509_PREFIX) == Some(s) => Ok(()),
        Some(_) => Err(invalid(format!(
            "x509_subject must match the user name ({X509_PREFIX}<subject>)"
        ))),
    }
}

impl AdminService {
    /// Creates the service; without a security layer every call fails with `RGN-4001`.
    #[must_use]
    pub fn new(security: Option<Arc<Security>>) -> Self {
        Self {
            security,
            control: None,
        }
    }

    pub(crate) fn with_control(mut self, control: Arc<dyn NodeControl>) -> Self {
        self.control = Some(control);
        self
    }

    /// Restarts the node in the same process (PD-230; rule of `UpdateSettings`,
    /// `cluster_manage`): pending static settings take effect. The answer comes before the stop;
    /// the node is unavailable for a few seconds. Audited as `settings_change` with
    /// `details.op = restart`.
    ///
    /// # Errors
    /// RGN-4001/4002/4003; RGN-5007 `not_implemented` without a [`NodeControl`]; RGN-1031 while
    /// a restart is under way.
    pub async fn restart_node(&self, ctx: &RequestContext) -> Result<(), Error> {
        let sec = self.guard(ctx, "UpdateSettings").await?;
        Self::admin_op(sec, ctx)?;
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| super::backup::not_implemented("RestartNode"))?;
        let result = control.restart();
        let outcome = if result.is_ok() {
            AuditOutcome::Success
        } else {
            AuditOutcome::Failure
        };
        let event = sec
            .event(ctx, AuditEventKind::SettingsChange, outcome)
            .detail("op", "restart");
        sec.audit_or_log(event).await;
        result
    }

    /// Why the last restart could not use the new configuration (see [`NodeControl`]).
    #[must_use]
    pub fn last_restart_error(&self) -> Option<String> {
        self.control.as_ref().and_then(|c| c.last_restart_error())
    }

    fn security(&self) -> Result<&Arc<Security>, Error> {
        self.security.as_ref().ok_or_else(unauthenticated)
    }

    /// The security layer after the checks the gRPC gate also makes for `rpc`
    /// (password-change restriction, cluster-level privileges): the service enforces its own
    /// rules, so every front end (gRPC, REST) gets the same authorization (PD-051).
    async fn guard(&self, ctx: &RequestContext, rpc: &str) -> Result<&Arc<Security>, Error> {
        let sec = self.security()?;
        let method = format!("/rustegon.v1.AdminService/{rpc}");
        let rule = access_of(&method)
            .ok_or_else(|| Error::new(ErrorCode::Internal, "no access rule declared"))?;
        sec.admit(ctx, rule).await?;
        Ok(sec)
    }

    fn admin_op(sec: &Security, ctx: &RequestContext) -> Result<String, Error> {
        let user = ctx.require_principal()?.user.clone();
        let ip: Option<IpAddr> = ctx.peer().map(|p| p.remote_addr.ip());
        sec.rate_limit(LimitClass::AdminOp, Some(&user), ip)?;
        Ok(user)
    }

    async fn audited(
        sec: &Security,
        ctx: &RequestContext,
        kind: AuditEventKind,
        op: &str,
        target: &str,
    ) {
        let event = sec
            .event(ctx, kind, AuditOutcome::Success)
            .detail("op", op)
            .detail("target", target);
        sec.audit_or_log(event).await;
    }

    /// Requires `user_manage` on `cluster` unless `target` is the caller.
    async fn self_or_user_manage(
        sec: &Security,
        ctx: &RequestContext,
        target: &str,
    ) -> Result<(), Error> {
        if ctx.require_principal()?.user == target {
            return Ok(());
        }
        sec.require(ctx, &Resource::Cluster, Action::UserManage)
            .await
    }

    /// Creates a user.
    ///
    /// # Errors
    /// `RGN-1001` (name, password policy, grants, subject), `RGN-1031`, `RGN-1030` (unknown
    /// custom role), `RGN-4003`, store errors.
    pub async fn create_user(
        &self,
        ctx: &RequestContext,
        new: NewUserSpec,
    ) -> Result<UserInfo, Error> {
        let sec = self.guard(ctx, "CreateUser").await?;
        Self::admin_op(sec, ctx)?;
        check_subject(&new.name, new.x509_subject.as_deref())?;
        let settings = sec.authn_settings();
        let now = sec.clock().wall();
        let rng = Arc::clone(sec.rng());
        let roles = new.roles.clone();
        // The PBKDF2 runs before the transaction (`Security::compute`).
        let prepared = sec
            .compute(ctx, move || {
                Ok(users::prepare_user(
                    &NewUser {
                        name: &new.name,
                        password: new.password.as_ref(),
                        roles: new.roles.clone(),
                        password_change: if new.must_change_password {
                            PasswordChange::Required
                        } else {
                            PasswordChange::NotRequired
                        },
                    },
                    &settings,
                    rng.as_ref(),
                )?)
            })
            .await?;
        let created = sec
            .transact(ctx, Completion::Await, move |t| {
                check_grants(t, &roles)?;
                let user = users::insert_user(t, &prepared, now)?;
                Ok(user_info(&user))
            })
            .await?;
        Self::audited(
            sec,
            ctx,
            AuditEventKind::UserChange,
            "create",
            &created.name,
        )
        .await;
        Ok(created)
    }

    /// Describes a user (self, or `user_manage`).
    ///
    /// # Errors
    /// `RGN-4002`, `RGN-1030`, store errors.
    pub async fn get_user(&self, ctx: &RequestContext, name: &str) -> Result<UserInfo, Error> {
        let sec = self.guard(ctx, "GetUser").await?;
        Self::self_or_user_manage(sec, ctx, name).await?;
        let name = name.to_owned();
        sec.transact(ctx, Completion::Abandon, move |t| {
            users::get_user(t, &name)?
                .map(|u| user_info(&u))
                .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("user {name:?} not found")))
        })
        .await
    }

    /// Lists users by name.
    ///
    /// # Errors
    /// Store errors.
    pub async fn list_users(&self, ctx: &RequestContext) -> Result<Vec<UserInfo>, Error> {
        let sec = self.guard(ctx, "ListUsers").await?;
        sec.transact(ctx, Completion::Abandon, |t| {
            Ok(users::list_users(t)?.iter().map(user_info).collect())
        })
        .await
    }

    /// Changes user attributes; password, role and disable changes revoke the user's sessions.
    ///
    /// # Errors
    /// As [`AdminService::create_user`]; `RGN-1030` for an unknown user; `RGN-1001` when the
    /// caller disables itself or the change leaves no enabled `root` holder (PD-145).
    pub async fn update_user(
        &self,
        ctx: &RequestContext,
        update: UserUpdate,
    ) -> Result<UserInfo, Error> {
        let sec = self.guard(ctx, "UpdateUser").await?;
        let caller = Self::admin_op(sec, ctx)?;
        if update.disabled == Some(true) && update.name == caller {
            return Err(self_lockout("disable"));
        }
        check_subject(&update.name, update.x509_subject.as_deref())?;
        let settings = sec.authn_settings();
        let now = sec.clock().wall();
        let rng = Arc::clone(sec.rng());
        let target = update.name.clone();
        // The PBKDF2 of a new password runs before the transaction (`Security::compute`).
        let credentials = match update.password.clone() {
            Some(pw) => {
                let name = update.name.clone();
                Some(
                    sec.compute(ctx, move || {
                        Ok(users::prepare_password(
                            &name,
                            &pw,
                            &settings,
                            rng.as_ref(),
                        )?)
                    })
                    .await?,
                )
            }
            None => None,
        };
        let updated = sec
            .transact(ctx, Completion::Await, move |t| {
                let name = update.name.as_str();
                let mut user = users::get_user(t, name)?.ok_or_else(|| {
                    Error::new(ErrorCode::NotFound, format!("user {name:?} not found"))
                })?;
                let keeps_root = update
                    .roles
                    .as_ref()
                    .is_none_or(|r| r.iter().any(|r| r == ROOT))
                    && update.disabled != Some(true);
                if !keeps_root {
                    ensure_root_remains(t, &user)?;
                }
                if let Some(roles) = &update.roles {
                    check_grants(t, roles)?;
                    user = users::set_roles(t, name, roles.clone(), now)?;
                }
                if let Some(scram) = &credentials {
                    user = users::set_credentials(t, name, scram.clone(), now)?;
                }
                if let Some(disabled) = update.disabled {
                    let state = if disabled {
                        UserState::Disabled
                    } else {
                        UserState::Enabled
                    };
                    user = users::set_state(t, name, state, now)?;
                }
                if let Some(must) = update.must_change_password {
                    let change = if must {
                        PasswordChange::Required
                    } else {
                        PasswordChange::NotRequired
                    };
                    user = users::set_password_change(t, name, change, now)?;
                }
                Ok(user_info(&user))
            })
            .await?;
        sec.key_cache().invalidate_user(&target);
        Self::audited(sec, ctx, AuditEventKind::UserChange, "update", &target).await;
        Ok(updated)
    }

    /// Drops a user with its sessions and API keys.
    ///
    /// # Errors
    /// `RGN-1030`, `RGN-4003`, store errors; `RGN-1001` for the caller itself or the last
    /// enabled `root` holder (PD-145).
    pub async fn drop_user(&self, ctx: &RequestContext, name: &str) -> Result<(), Error> {
        let sec = self.guard(ctx, "DropUser").await?;
        if Self::admin_op(sec, ctx)? == name {
            return Err(self_lockout("drop"));
        }
        let target = name.to_owned();
        sec.transact(ctx, Completion::Await, move |t| {
            if let Some(user) = users::get_user(t, &target)? {
                ensure_root_remains(t, &user)?;
            }
            Ok(users::drop_user(t, &target)?)
        })
        .await?;
        sec.key_cache().invalidate_user(name);
        Self::audited(sec, ctx, AuditEventKind::UserChange, "drop", name).await;
        Ok(())
    }

    /// Changes the caller's own password after verifying the current one (lockout applies);
    /// every session of the caller, including the current one, is revoked (TC-SEC-007).
    ///
    /// # Errors
    /// `RGN-4007` (locked), `RGN-4001` (wrong current password), `RGN-1001` (weak password),
    /// store errors.
    pub async fn change_password(
        &self,
        ctx: &RequestContext,
        current: SecretString,
        new: SecretString,
    ) -> Result<(), Error> {
        let sec = self.guard(ctx, "ChangePassword").await?;
        let user = ctx.require_principal()?.user.clone();
        sec.lockout().check(&user)?;
        let settings = sec.authn_settings();
        let rng = Arc::clone(sec.rng());
        let now = sec.clock().wall();
        // Three steps so that no PBKDF2 runs inside a transaction (`Security::compute`): read
        // the record, verify the current password and derive the new credentials, then write
        // them only if the record's credential epoch is still the one verified against.
        let name = user.clone();
        let read_rng = Arc::clone(&rng);
        let (record, fake) = sec
            .transact(ctx, Completion::Abandon, move |t| {
                let fake =
                    rustegon_security::authn::realm::load_or_ephemeral(t, read_rng.as_ref())?;
                Ok((users::get_user(t, &name)?, fake))
            })
            .await?;
        let name = user.clone();
        let epoch = record.as_ref().map(|u| u.credential_epoch);
        let checked = sec
            .compute(ctx, move || {
                if users::verify_user_password(record.as_ref(), &name, &current, &fake, &settings)
                    .is_err()
                {
                    return Ok(None);
                }
                Ok(Some(users::prepare_password(
                    &name,
                    &new,
                    &settings,
                    rng.as_ref(),
                )?))
            })
            .await?;
        let verified = checked.is_some();
        if let Some(scram) = checked {
            let name = user.clone();
            sec.transact(ctx, Completion::Await, move |t| {
                let current = users::get_user(t, &name)?.map(|u| u.credential_epoch);
                if current != epoch {
                    // Changed (password, roles, state) since the verification: the verified
                    // password may no longer be the user's. Retryable, nothing written.
                    return Err(Error::new(
                        ErrorCode::TransactionAborted,
                        "the user changed during the password change; retry",
                    )
                    .with_detail("reason", "conflict"));
                }
                users::set_credentials(t, &name, scram.clone(), now)?;
                Ok(())
            })
            .await?;
        }
        if !verified {
            if let rustegon_security::lockout::FailureOutcome::Locked { duration } =
                sec.lockout().record_failure(&user)
            {
                let event = sec
                    .event(ctx, AuditEventKind::AccountLocked, AuditOutcome::Success)
                    .detail("lock_secs", duration.as_secs().to_string());
                sec.audit_or_log(event).await;
            }
            let event = sec
                .event(ctx, AuditEventKind::LoginFailure, AuditOutcome::Failure)
                .detail("mechanism", "password")
                .detail("reason", "bad_credentials")
                .detail("op", "change_password");
            sec.audit_or_log(event).await;
            return Err(unauthenticated());
        }
        sec.lockout().record_success(&user);
        sec.key_cache().invalidate_user(&user);
        Self::audited(
            sec,
            ctx,
            AuditEventKind::UserChange,
            "change_password",
            &user,
        )
        .await;
        Ok(())
    }

    /// Creates a custom role.
    ///
    /// # Errors
    /// `RGN-1001` (invalid role, cycle), `RGN-1031`, `RGN-1030` (unknown parent), store errors.
    pub async fn create_role(
        &self,
        ctx: &RequestContext,
        info: RoleInfo,
    ) -> Result<RoleInfo, Error> {
        self.write_role(ctx, info, "create").await
    }

    /// Replaces a custom role's privileges and inheritance.
    ///
    /// # Errors
    /// As [`AdminService::create_role`].
    pub async fn update_role(
        &self,
        ctx: &RequestContext,
        info: RoleInfo,
    ) -> Result<RoleInfo, Error> {
        self.write_role(ctx, info, "update").await
    }

    async fn write_role(
        &self,
        ctx: &RequestContext,
        info: RoleInfo,
        op: &'static str,
    ) -> Result<RoleInfo, Error> {
        let sec = self
            .guard(
                ctx,
                if op == "create" {
                    "CreateRole"
                } else {
                    "UpdateRole"
                },
            )
            .await?;
        Self::admin_op(sec, ctx)?;
        let role = role_from_info(&info)?;
        let name = role.name.clone();
        let stored = sec
            .transact(ctx, Completion::Await, move |t| {
                let mutations = if op == "create" {
                    roles::create_role(&Reader(t), role.clone())?
                } else {
                    roles::update_role(&Reader(t), role.clone())?
                };
                t.apply(mutations)?;
                Ok(role_info(&role, false))
            })
            .await?;
        Self::audited(sec, ctx, AuditEventKind::RoleChange, op, &name).await;
        Ok(stored)
    }

    /// Describes a role (built-in or custom).
    ///
    /// # Errors
    /// `RGN-1030`, store errors.
    pub async fn get_role(&self, ctx: &RequestContext, name: &str) -> Result<RoleInfo, Error> {
        let sec = self.guard(ctx, "GetRole").await?;
        if let Some(b) = BuiltinRole::parse(name) {
            return Ok(builtin_info(b));
        }
        let name = name.to_owned();
        sec.transact(ctx, Completion::Abandon, move |t| {
            roles::get_role(&Reader(t), &name)?
                .map(|r| role_info(&r, false))
                .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("role {name:?} not found")))
        })
        .await
    }

    /// Lists built-in and custom roles by name.
    ///
    /// # Errors
    /// Store errors.
    pub async fn list_roles(&self, ctx: &RequestContext) -> Result<Vec<RoleInfo>, Error> {
        let sec = self.guard(ctx, "ListRoles").await?;
        let mut out: Vec<RoleInfo> = BuiltinRole::ALL.into_iter().map(builtin_info).collect();
        let custom = sec
            .transact(ctx, Completion::Abandon, |t| {
                let catalog = roles::load_roles(&Reader(t))?;
                Ok(catalog
                    .roles()
                    .map(|r| role_info(r, false))
                    .collect::<Vec<_>>())
            })
            .await?;
        out.extend(custom);
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Drops a custom role.
    ///
    /// # Errors
    /// `RGN-1001` (built-in or inherited role), `RGN-1030`, store errors.
    pub async fn drop_role(&self, ctx: &RequestContext, name: &str) -> Result<(), Error> {
        let sec = self.guard(ctx, "DropRole").await?;
        Self::admin_op(sec, ctx)?;
        if BuiltinRole::parse(name).is_some() {
            return Err(invalid(format!("built-in role {name:?} cannot be dropped")));
        }
        let target = name.to_owned();
        sec.transact(ctx, Completion::Await, move |t| {
            let mutations = roles::drop_role(&Reader(t), &target)?;
            t.apply(mutations)
        })
        .await?;
        Self::audited(sec, ctx, AuditEventKind::RoleChange, "drop", name).await;
        Ok(())
    }

    /// Creates an API key; returns it and its full secret (shown once).
    ///
    /// # Errors
    /// `RGN-1001` (description, scope, expiry, CIDR), `RGN-1030` (owner), `RGN-4002` (another
    /// owner without `user_manage`), store errors.
    pub async fn create_api_key(
        &self,
        ctx: &RequestContext,
        new: NewApiKeySpec,
    ) -> Result<(ApiKeyInfo, SecretString), Error> {
        let sec = self.guard(ctx, "CreateApiKey").await?;
        let caller = Self::admin_op(sec, ctx)?;
        let owner = new.user.clone().unwrap_or_else(|| caller.clone());
        Self::self_or_user_manage(sec, ctx, &owner).await?;
        if owner == caller {
            let mine = &ctx.require_principal()?.roles;
            if let Some(r) = new.roles.iter().find(|r| !mine.contains(r)) {
                return Err(Error::new(
                    ErrorCode::PermissionDenied,
                    format!("API key scope role {r:?} is not one of the caller's roles"),
                ));
            }
        }
        let allow = new
            .ip_allowlist
            .iter()
            .map(|c| Cidr::from_str(c).map_err(Error::from))
            .collect::<Result<Vec<_>, Error>>()?;
        let now = sec.clock().wall();
        let rng = Arc::clone(sec.rng());
        let cost = sec.api_key_cost();
        // The Argon2id hash runs before the transaction (`Security::compute`).
        let prepared = sec
            .compute(ctx, move || {
                Ok(apikey::prepare_api_key(rng.as_ref(), cost)?)
            })
            .await?;
        let (info, secret) = sec
            .transact(ctx, Completion::Await, move |t| {
                let (record, secret) = apikey::insert_api_key(
                    t,
                    NewApiKey {
                        user: &owner,
                        name: &new.description,
                        roles: new.roles.clone(),
                        expires_at: new.expires_at,
                        allow: allow.clone(),
                    },
                    &prepared,
                    now,
                )?;
                Ok((key_info(&record), secret))
            })
            .await?;
        Self::audited(
            sec,
            ctx,
            AuditEventKind::ApiKeyChange,
            "create",
            &info.key_id,
        )
        .await;
        Ok((info, secret))
    }

    /// Lists API keys: of `user`, or of every user for callers with `user_manage`, else the
    /// caller's own.
    ///
    /// # Errors
    /// `RGN-4002`, store errors.
    pub async fn list_api_keys(
        &self,
        ctx: &RequestContext,
        user: Option<String>,
    ) -> Result<Vec<ApiKeyInfo>, Error> {
        let sec = self.guard(ctx, "ListApiKeys").await?;
        let principal = ctx.require_principal()?;
        let filter = match user {
            Some(u) => {
                Self::self_or_user_manage(sec, ctx, &u).await?;
                Some(u)
            }
            None if principal.allows(&Resource::Cluster, Action::UserManage) => None,
            None => Some(principal.user.clone()),
        };
        sec.transact(ctx, Completion::Abandon, move |t| {
            Ok(apikey::list_api_keys(t, filter.as_deref())?
                .iter()
                .map(key_info)
                .collect())
        })
        .await
    }

    /// Revokes an API key (own, or any with `user_manage`).
    ///
    /// # Errors
    /// `RGN-1030`, `RGN-4002`, store errors.
    pub async fn revoke_api_key(&self, ctx: &RequestContext, key_id: &str) -> Result<(), Error> {
        let sec = self.guard(ctx, "RevokeApiKey").await?;
        Self::admin_op(sec, ctx)?;
        let id = key_id.to_owned();
        let owner = sec
            .transact(ctx, Completion::Abandon, move |t| {
                Ok(apikey::get_api_key(t, &id)?.map(|k| k.user))
            })
            .await?
            .ok_or_else(|| {
                Error::new(ErrorCode::NotFound, format!("API key {key_id} not found"))
            })?;
        Self::self_or_user_manage(sec, ctx, &owner).await?;
        let id = key_id.to_owned();
        sec.transact(ctx, Completion::Await, move |t| {
            Ok(apikey::revoke_api_key(t, &id)?)
        })
        .await?;
        sec.key_cache().invalidate_key(key_id);
        Self::audited(sec, ctx, AuditEventKind::ApiKeyChange, "revoke", key_id).await;
        Ok(())
    }

    /// Reads settings (all when `names` is empty), secrets redacted.
    ///
    /// # Errors
    /// `RGN-1030` for an unknown name.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // Same async shape as every service method (PD-050).
    pub async fn get_settings(
        &self,
        ctx: &RequestContext,
        names: Vec<String>,
    ) -> Result<Vec<SettingInfo>, Error> {
        let sec = self.guard(ctx, "GetSettings").await?;
        ctx.check_deadline(sec.clock().as_ref())?;
        sec.settings().describe(&names)
    }

    /// Applies settings and returns them: runtime-mutable ones atomically as persisted
    /// overrides, static ones written into the configuration file for the next restart (PD-230;
    /// `security::settings` module docs). Both kinds are validated before anything changes.
    ///
    /// # Errors
    /// `RGN-1001` (invalid value, a locked setting), `RGN-1030` (unknown setting), store and
    /// file errors.
    pub async fn update_settings(
        &self,
        ctx: &RequestContext,
        values: BTreeMap<String, String>,
    ) -> Result<Vec<SettingInfo>, Error> {
        let sec = self.guard(ctx, "UpdateSettings").await?;
        Self::admin_op(sec, ctx)?;
        // Held across the commit (an async mutex: no blocking lock across `.await`).
        let _serial = sec.settings_update_lock().lock().await;
        let (dynamic, stat) = sec.settings().split(&values)?;
        let prepared = if dynamic.is_empty() {
            None
        } else {
            Some(sec.settings().prepare(&dynamic)?)
        };
        if !stat.is_empty() {
            // File I/O on a blocking thread; validated as a whole before the file is replaced.
            let owner = Arc::clone(sec);
            sec.compute(ctx, move || {
                owner.settings().write_static(owner.fs().as_ref(), &stat)
            })
            .await?;
        }
        let names: Vec<String> = values.keys().cloned().collect();
        if let Some(config) = prepared {
            let mutations = override_mutations(&dynamic, sec.clock().wall())?;
            sec.transact(ctx, Completion::Await, move |t| t.apply(mutations.clone()))
                .await?;
            sec.settings().commit(dynamic, config);
            sec.reload_runtime_settings()?;
        }
        let event = sec
            .event(ctx, AuditEventKind::SettingsChange, AuditOutcome::Success)
            .detail("settings", names.join(","));
        sec.audit_or_log(event).await;
        sec.settings().describe(&names)
    }
}

const ROOT: &str = BuiltinRole::Root.as_str();

/// A principal may not drop or disable itself through the API (PD-145): it would end its own
/// access in the middle of the request, and the console hides those actions anyway (PD-141).
fn self_lockout(op: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!("a user cannot {op} itself"),
    )
    .with_detail("reason", "self")
}

/// Refuses a change that takes `root` away from `user` when it is the last enabled user holding
/// it directly (PD-145): nobody could then manage users, roles or the cluster without an offline
/// bootstrap. Runs in the caller's serializable system transaction, so two concurrent changes
/// to the last two holders cannot both pass. Inherited `root` is not counted, which can only
/// refuse more, never lock out.
fn ensure_root_remains(t: &dyn SystemTxn, user: &UserRecord) -> Result<(), Error> {
    let holds = |u: &UserRecord| u.state == UserState::Enabled && u.roles.iter().any(|r| r == ROOT);
    if !holds(user)
        || users::list_users(t)?
            .iter()
            .any(|u| u.name != user.name && holds(u))
    {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        format!(
            "user {:?} is the last enabled user holding role root",
            user.name
        ),
    )
    .with_detail("reason", "last_root"))
}
