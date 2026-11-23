// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST adapter of [`crate::services::AdminService`] (protocol.md §4 "security", "config";
//! FR-API-002, FR-SEC-002/003/005, PD-051, PD-055): users, roles, API keys and runtime
//! settings.
//!
//! Role grants use the gRPC `RoleGrant` shape `{role, resource}` and its mapping to role
//! references (`grpc::grant_to_role_ref`, PD-051), so both channels accept and report the same
//! grants. Passwords and the API key secret are request/response fields only: the request types
//! deliberately do not implement `Debug`, and nothing here logs them.

use std::collections::BTreeMap;

use axum::extract::State;
use rustegon_common::{Error, ErrorCode};
use rustegon_proto::v1::RoleGrant;
use rustegon_security::authn::secret;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    ApiError, Ctx, JsonBody, Reply, RestState,
    extract::{PathParams, QueryParams},
    wire::unix_ms,
};
use crate::{
    grpc::{grant_to_role_ref, role_ref_to_grant},
    security::SettingInfo,
    services::admin::{ApiKeyInfo, NewApiKeySpec, NewUserSpec, RoleInfo, UserInfo, UserUpdate},
};

/// Routes of this module.
pub(super) fn routes() -> OpenApiRouter<RestState> {
    OpenApiRouter::new()
        .routes(routes!(list_users, create_user))
        .routes(routes!(get_user, update_user, drop_user))
        .routes(routes!(list_roles, create_role))
        .routes(routes!(get_role, update_role, drop_role))
        .routes(routes!(list_api_keys, create_api_key))
        .routes(routes!(revoke_api_key))
        .routes(routes!(get_settings, update_settings))
        .routes(routes!(restart_node))
}

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

/// A role granted on a resource (protocol.md §8: `{r, "database:db"}` = `r@db`,
/// `{r, "collection:db.c"}` = `r@db.c`, `{r, "" | "cluster" | "database:*"}` = `r`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleGrantJson {
    /// Role name.
    pub role: String,
    /// `cluster`, `database:<db>`, `database:*`, `collection:<db>.<coll>` or empty.
    #[serde(default)]
    pub resource: String,
}

fn grants_in(list: &[RoleGrantJson]) -> Result<Vec<String>, Error> {
    list.iter()
        .map(|g| {
            grant_to_role_ref(&RoleGrant {
                role: g.role.clone(),
                resource: g.resource.clone(),
            })
        })
        .collect()
}

pub(crate) fn grants_out(refs: &[String]) -> Vec<RoleGrantJson> {
    refs.iter()
        .map(|r| {
            let g = role_ref_to_grant(r);
            RoleGrantJson {
                role: g.role,
                resource: g.resource,
            }
        })
        .collect()
}

/// A user (never its credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserJson {
    /// Name.
    pub name: String,
    /// Granted roles.
    pub roles: Vec<RoleGrantJson>,
    /// Disabled users cannot authenticate.
    pub disabled: bool,
    /// The password must be changed at next login.
    pub must_change_password: bool,
    /// X.509 subject of `x509:` users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_subject: Option<String>,
    /// Creation time (Unix ms).
    pub created_at_unix_ms: i64,
}

fn user_out(u: UserInfo) -> UserJson {
    UserJson {
        roles: grants_out(&u.roles),
        name: u.name,
        disabled: u.disabled,
        must_change_password: u.must_change_password,
        x509_subject: u.x509_subject,
        created_at_unix_ms: unix_ms(u.created_at),
    }
}

/// `{user}` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UserResponse {
    /// The user.
    pub user: UserJson,
}

/// `GET /users` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UserList {
    /// Users.
    pub users: Vec<UserJson>,
}

/// `POST /users` body.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateUserRequest {
    /// Name (`x509:<subject>` for certificate users).
    pub name: String,
    /// Initial password (password users).
    #[serde(default)]
    pub password: Option<String>,
    /// Granted roles.
    #[serde(default)]
    pub roles: Vec<RoleGrantJson>,
    /// Force a password change at first login.
    #[serde(default)]
    pub must_change_password: bool,
    /// X.509 subject (must equal the name after `x509:`).
    #[serde(default)]
    pub x509_subject: Option<String>,
}

/// `PATCH /users/{name}` body; absent fields are unchanged.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateUserRequest {
    /// New password (revokes the user's sessions).
    #[serde(default)]
    pub password: Option<String>,
    /// New role grants, replacing the old ones (revokes sessions).
    #[serde(default)]
    pub roles: Option<Vec<RoleGrantJson>>,
    /// Disable or enable.
    #[serde(default)]
    pub disabled: Option<bool>,
    /// Force or clear a password change.
    #[serde(default)]
    pub must_change_password: Option<bool>,
    /// X.509 subject (cannot change: it is the name).
    #[serde(default)]
    pub x509_subject: Option<String>,
}

/// Empty success body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EmptyResponse {}

/// A privilege of a custom role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeJson {
    /// Resource pattern (`cluster`, `database:<db>`, `collection:<db>.<coll>`, …).
    pub resource: String,
    /// Action names.
    pub actions: Vec<String>,
}

/// A role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleJson {
    /// Name.
    pub name: String,
    /// Privileges.
    #[serde(default)]
    pub privileges: Vec<PrivilegeJson>,
    /// Inherited role references.
    #[serde(default)]
    pub inherits: Vec<String>,
    /// Built-in roles cannot be changed or dropped (ignored in requests).
    #[serde(default)]
    pub built_in: bool,
}

fn role_out(r: RoleInfo) -> RoleJson {
    RoleJson {
        name: r.name,
        privileges: r
            .privileges
            .into_iter()
            .map(|(resource, actions)| PrivilegeJson { resource, actions })
            .collect(),
        inherits: r.inherits,
        built_in: r.built_in,
    }
}

fn role_in(name: String, privileges: Vec<PrivilegeJson>, inherits: Vec<String>) -> RoleInfo {
    RoleInfo {
        name,
        privileges: privileges
            .into_iter()
            .map(|p| (p.resource, p.actions))
            .collect(),
        inherits,
        built_in: false,
    }
}

/// `{role}` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RoleResponse {
    /// The role.
    pub role: RoleJson,
}

/// `GET /roles` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RoleList {
    /// Built-in and custom roles.
    pub roles: Vec<RoleJson>,
}

/// `PATCH /roles/{name}` body: the new privileges and inheritance (both replaced).
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRoleRequest {
    /// Privileges.
    #[serde(default)]
    pub privileges: Vec<PrivilegeJson>,
    /// Inherited role references.
    #[serde(default)]
    pub inherits: Vec<String>,
}

/// An API key (never its secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyJson {
    /// Key id.
    pub key_id: String,
    /// Owner.
    pub user: String,
    /// Description.
    pub description: String,
    /// Scope.
    pub roles: Vec<RoleGrantJson>,
    /// Expiry (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<i64>,
    /// Allowed client networks.
    pub ip_allowlist: Vec<String>,
    /// Creation time (Unix ms).
    pub created_at_unix_ms: i64,
}

fn key_out(k: ApiKeyInfo) -> ApiKeyJson {
    ApiKeyJson {
        roles: grants_out(&k.roles),
        key_id: k.key_id,
        user: k.user,
        description: k.description,
        expires_at_unix_ms: k.expires_at.map(unix_ms),
        ip_allowlist: k.ip_allowlist,
        created_at_unix_ms: unix_ms(k.created_at),
    }
}

/// `GET /api-keys` query parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ApiKeyQuery {
    /// Only the keys of this user (default: the caller's own; another user's need
    /// `user_manage`).
    pub user: Option<String>,
}

/// `GET /api-keys` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyList {
    /// Keys.
    pub keys: Vec<ApiKeyJson>,
}

/// `POST /api-keys` body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateApiKeyRequest {
    /// Owner (default: the caller).
    #[serde(default)]
    pub user: Option<String>,
    /// Description.
    #[serde(default)]
    pub description: String,
    /// Scope (intersected with the owner's roles).
    #[serde(default)]
    pub roles: Vec<RoleGrantJson>,
    /// Expiry (Unix ms).
    #[serde(default)]
    pub expires_at_unix_ms: Option<i64>,
    /// Allowed client IPs/CIDRs.
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
}

/// `POST /api-keys` response: the only time the secret is shown.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateApiKeyResponse {
    /// The key.
    pub key: ApiKeyJson,
    /// The full key (`rgn_<key_id>_<secret>`) for `Authorization: ApiKey …`.
    pub secret: String,
}

/// A runtime setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SettingJson {
    /// Name (`section.key`).
    pub name: String,
    /// Current value as TOML text (secrets redacted).
    pub value: String,
    /// Default value as TOML text.
    pub default_value: String,
    /// Changeable at runtime; a static setting takes effect at the next restart (PD-230).
    pub runtime_mutable: bool,
    /// Description.
    pub description: String,
    /// Value type: `bool`, `integer`, `string`, `path`, `enum`, `string_list` or `table`.
    pub kind: String,
    /// Inclusive range of an `integer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    /// Inclusive range of an `integer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    /// Allowed values of an `enum`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    /// Why it cannot be changed here: `secret`, `table`, `no_config_file`, `environment`
    /// (an environment variable or a `--set` flag sets it) or `manual` (absent: it can).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked: Option<String>,
    /// A static setting's value in the configuration file, taking effect at the next restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_value: Option<String>,
}

fn setting_out(s: SettingInfo) -> SettingJson {
    use rustegon_common::settings::Kind;
    let (kind, min, max, choices) = match s.kind {
        Kind::Bool => ("bool", None, None, Vec::new()),
        Kind::Integer { min, max } => ("integer", Some(min), Some(max), Vec::new()),
        Kind::String => ("string", None, None, Vec::new()),
        Kind::Path => ("path", None, None, Vec::new()),
        Kind::Enum(names) => (
            "enum",
            None,
            None,
            names.iter().map(|n| (*n).to_owned()).collect(),
        ),
        Kind::StringList => ("string_list", None, None, Vec::new()),
        Kind::Table => ("table", None, None, Vec::new()),
    };
    SettingJson {
        name: s.name,
        value: s.value,
        default_value: s.default_value,
        runtime_mutable: s.runtime_mutable,
        description: s.description,
        kind: kind.to_owned(),
        min,
        max,
        choices,
        locked: s.locked.map(|l| l.as_str().to_owned()),
        pending_value: s.pending_value,
    }
}

/// `GET /settings` query parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct SettingsQuery {
    /// Comma-separated setting names (default: every setting).
    pub names: Option<String>,
}

/// Settings response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SettingList {
    /// Settings.
    pub settings: Vec<SettingJson>,
    /// Why the last restart could not start with the new configuration file; the node then
    /// serves with the previous one (PD-230).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_restart_error: Option<String>,
}

/// `POST /node/restart` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RestartResponse {
    /// Always `true`: the node stops serving after this answer and starts again.
    pub restarting: bool,
}

/// `PATCH /settings` body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateSettingsRequest {
    /// Setting name → new value as TOML text, applied atomically.
    pub values: BTreeMap<String, String>,
}

fn time_from_unix_ms(ms: i64) -> Result<std::time::SystemTime, Error> {
    u64::try_from(ms)
        .ok()
        .and_then(|ms| std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_millis(ms)))
        .ok_or_else(|| {
            Error::new(ErrorCode::InvalidArgument, "timestamp out of range")
                .with_detail("field", "expiresAtUnixMs")
        })
}

// ---------------------------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------------------------

/// Every user (`AdminService.ListUsers`; `user_manage`).
#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "admin",
    operation_id = "listUsers",
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Users.", body = UserList))
)]
async fn list_users(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
) -> Result<Reply<UserList>, ApiError> {
    let users = state
        .services
        .admin()
        .list_users(&ctx)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        UserList {
            users: users.into_iter().map(user_out).collect(),
        },
        &ctx,
    ))
}

/// Creates a user (`AdminService.CreateUser`; `user_manage`).
#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "admin",
    operation_id = "createUser",
    request_body = CreateUserRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The user.", body = UserResponse))
)]
async fn create_user(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    JsonBody(body): JsonBody<CreateUserRequest>,
) -> Result<Reply<UserResponse>, ApiError> {
    let user = async {
        let spec = NewUserSpec {
            name: body.name,
            password: body.password.map(secret),
            roles: grants_in(&body.roles)?,
            must_change_password: body.must_change_password,
            x509_subject: body.x509_subject,
        };
        state.services.admin().create_user(&ctx, spec).await
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        UserResponse {
            user: user_out(user),
        },
        &ctx,
    ))
}

/// A user (`AdminService.GetUser`; the caller itself, or `user_manage`).
#[utoipa::path(
    get,
    path = "/api/v1/users/{name}",
    tag = "admin",
    operation_id = "getUser",
    params(("name" = String, Path, description = "User name.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The user.", body = UserResponse))
)]
async fn get_user(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(name): PathParams<String>,
) -> Result<Reply<UserResponse>, ApiError> {
    let user = state
        .services
        .admin()
        .get_user(&ctx, &name)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        UserResponse {
            user: user_out(user),
        },
        &ctx,
    ))
}

/// Changes a user (`AdminService.UpdateUser`; `user_manage`).
#[utoipa::path(
    patch,
    path = "/api/v1/users/{name}",
    tag = "admin",
    operation_id = "updateUser",
    params(("name" = String, Path, description = "User name.")),
    request_body = UpdateUserRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The user.", body = UserResponse))
)]
async fn update_user(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(name): PathParams<String>,
    JsonBody(body): JsonBody<UpdateUserRequest>,
) -> Result<Reply<UserResponse>, ApiError> {
    let user = async {
        let update = UserUpdate {
            name,
            password: body.password.map(secret),
            roles: body.roles.as_deref().map(grants_in).transpose()?,
            disabled: body.disabled,
            must_change_password: body.must_change_password,
            x509_subject: body.x509_subject,
        };
        state.services.admin().update_user(&ctx, update).await
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        UserResponse {
            user: user_out(user),
        },
        &ctx,
    ))
}

/// Drops a user (`AdminService.DropUser`; `user_manage`).
#[utoipa::path(
    delete,
    path = "/api/v1/users/{name}",
    tag = "admin",
    operation_id = "dropUser",
    params(("name" = String, Path, description = "User name.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Dropped.", body = EmptyResponse))
)]
async fn drop_user(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(name): PathParams<String>,
) -> Result<Reply<EmptyResponse>, ApiError> {
    state
        .services
        .admin()
        .drop_user(&ctx, &name)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(EmptyResponse {}, &ctx))
}

// ---------------------------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------------------------

/// Built-in and custom roles (`AdminService.ListRoles`; `role_manage`).
#[utoipa::path(
    get,
    path = "/api/v1/roles",
    tag = "admin",
    operation_id = "listRoles",
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Roles.", body = RoleList))
)]
async fn list_roles(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
) -> Result<Reply<RoleList>, ApiError> {
    let roles = state
        .services
        .admin()
        .list_roles(&ctx)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        RoleList {
            roles: roles.into_iter().map(role_out).collect(),
        },
        &ctx,
    ))
}

/// Creates a custom role (`AdminService.CreateRole`; `role_manage`).
#[utoipa::path(
    post,
    path = "/api/v1/roles",
    tag = "admin",
    operation_id = "createRole",
    request_body = RoleJson,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The role.", body = RoleResponse))
)]
async fn create_role(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    JsonBody(body): JsonBody<RoleJson>,
) -> Result<Reply<RoleResponse>, ApiError> {
    let role = state
        .services
        .admin()
        .create_role(&ctx, role_in(body.name, body.privileges, body.inherits))
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        RoleResponse {
            role: role_out(role),
        },
        &ctx,
    ))
}

/// A role (`AdminService.GetRole`; `role_manage`).
#[utoipa::path(
    get,
    path = "/api/v1/roles/{name}",
    tag = "admin",
    operation_id = "getRole",
    params(("name" = String, Path, description = "Role name.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The role.", body = RoleResponse))
)]
async fn get_role(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(name): PathParams<String>,
) -> Result<Reply<RoleResponse>, ApiError> {
    let role = state
        .services
        .admin()
        .get_role(&ctx, &name)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        RoleResponse {
            role: role_out(role),
        },
        &ctx,
    ))
}

/// Replaces a custom role's privileges and inheritance (`AdminService.UpdateRole`).
#[utoipa::path(
    patch,
    path = "/api/v1/roles/{name}",
    tag = "admin",
    operation_id = "updateRole",
    params(("name" = String, Path, description = "Role name.")),
    request_body = UpdateRoleRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The role.", body = RoleResponse))
)]
async fn update_role(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(name): PathParams<String>,
    JsonBody(body): JsonBody<UpdateRoleRequest>,
) -> Result<Reply<RoleResponse>, ApiError> {
    let role = state
        .services
        .admin()
        .update_role(&ctx, role_in(name, body.privileges, body.inherits))
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        RoleResponse {
            role: role_out(role),
        },
        &ctx,
    ))
}

/// Drops a custom role (`AdminService.DropRole`; `role_manage`).
#[utoipa::path(
    delete,
    path = "/api/v1/roles/{name}",
    tag = "admin",
    operation_id = "dropRole",
    params(("name" = String, Path, description = "Role name.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Dropped.", body = EmptyResponse))
)]
async fn drop_role(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(name): PathParams<String>,
) -> Result<Reply<EmptyResponse>, ApiError> {
    state
        .services
        .admin()
        .drop_role(&ctx, &name)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(EmptyResponse {}, &ctx))
}

// ---------------------------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------------------------

/// API keys (`AdminService.ListApiKeys`; own keys, or `user_manage`).
#[utoipa::path(
    get,
    path = "/api/v1/api-keys",
    tag = "admin",
    operation_id = "listApiKeys",
    params(ApiKeyQuery),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Keys (never their secrets).", body = ApiKeyList))
)]
async fn list_api_keys(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    QueryParams(q): QueryParams<ApiKeyQuery>,
) -> Result<Reply<ApiKeyList>, ApiError> {
    let keys = state
        .services
        .admin()
        .list_api_keys(&ctx, q.user)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        ApiKeyList {
            keys: keys.into_iter().map(key_out).collect(),
        },
        &ctx,
    ))
}

/// Creates an API key; the secret is returned once (`AdminService.CreateApiKey`).
#[utoipa::path(
    post,
    path = "/api/v1/api-keys",
    tag = "admin",
    operation_id = "createApiKey",
    request_body = CreateApiKeyRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The key and its secret.", body = CreateApiKeyResponse))
)]
async fn create_api_key(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    JsonBody(body): JsonBody<CreateApiKeyRequest>,
) -> Result<Reply<CreateApiKeyResponse>, ApiError> {
    let (key, full) = async {
        let spec = NewApiKeySpec {
            user: body.user,
            description: body.description,
            roles: grants_in(&body.roles)?,
            expires_at: body.expires_at_unix_ms.map(time_from_unix_ms).transpose()?,
            ip_allowlist: body.ip_allowlist,
        };
        state.services.admin().create_api_key(&ctx, spec).await
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        CreateApiKeyResponse {
            key: key_out(key),
            secret: full.expose().to_string(),
        },
        &ctx,
    ))
}

/// Revokes an API key (`AdminService.RevokeApiKey`; own keys, or `user_manage`).
#[utoipa::path(
    delete,
    path = "/api/v1/api-keys/{key_id}",
    tag = "admin",
    operation_id = "revokeApiKey",
    params(("key_id" = String, Path, description = "Key id.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Revoked.", body = EmptyResponse))
)]
async fn revoke_api_key(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(key_id): PathParams<String>,
) -> Result<Reply<EmptyResponse>, ApiError> {
    state
        .services
        .admin()
        .revoke_api_key(&ctx, &key_id)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(EmptyResponse {}, &ctx))
}

// ---------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------

/// Runtime settings with current and default values (`AdminService.GetSettings`;
/// `cluster_view`).
#[utoipa::path(
    get,
    path = "/api/v1/settings",
    tag = "admin",
    operation_id = "getSettings",
    params(SettingsQuery),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Settings (secrets redacted).", body = SettingList))
)]
async fn get_settings(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    QueryParams(q): QueryParams<SettingsQuery>,
) -> Result<Reply<SettingList>, ApiError> {
    let names = q
        .names
        .as_deref()
        .map(|n| {
            n.split(',')
                .map(|s| s.trim_matches(' ').to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let settings = state
        .services
        .admin()
        .get_settings(&ctx, names)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        SettingList {
            settings: settings.into_iter().map(setting_out).collect(),
            last_restart_error: state.services.admin().last_restart_error(),
        },
        &ctx,
    ))
}

/// Changes settings atomically (`AdminService.UpdateSettings`; `cluster_manage`): runtime ones
/// at once, static ones in the configuration file for the next restart (PD-230).
#[utoipa::path(
    patch,
    path = "/api/v1/settings",
    tag = "admin",
    operation_id = "updateSettings",
    request_body = UpdateSettingsRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The changed settings.", body = SettingList))
)]
async fn update_settings(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    JsonBody(body): JsonBody<UpdateSettingsRequest>,
) -> Result<Reply<SettingList>, ApiError> {
    let settings = state
        .services
        .admin()
        .update_settings(&ctx, body.values)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        SettingList {
            settings: settings.into_iter().map(setting_out).collect(),
            last_restart_error: None,
        },
        &ctx,
    ))
}

/// Restarts the node in the same process so that pending static settings take effect (PD-230;
/// rule of `UpdateSettings`, `cluster_manage`). The answer comes before the stop: poll
/// `/health/ready` until it answers again.
#[utoipa::path(
    post,
    path = "/api/v1/node/restart",
    tag = "admin",
    operation_id = "restartNode",
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The restart is under way.", body = RestartResponse))
)]
async fn restart_node(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
) -> Result<Reply<RestartResponse>, ApiError> {
    state
        .services
        .admin()
        .restart_node(&ctx)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        RestartResponse { restarting: true },
        &ctx,
    ))
}
