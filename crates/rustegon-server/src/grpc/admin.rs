// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC adapter of [`crate::services::AdminService`] (admin.proto) and the `RoleGrant` ↔ role
//! reference mapping shared with `AuthService.WhoAmI` (PD-051):
//!
//! | `RoleGrant{role, resource}`                  | role reference      |
//! |----------------------------------------------|---------------------|
//! | `{read, "database:shop"}`                    | `read@shop`         |
//! | `{read_write, "collection:shop.orders"}`     | `read_write@shop.orders` |
//! | `{read, "database:*"}` / `{read, ""}`        | `read` (every database) |
//! | `{root, "cluster"}` / `{root, ""}`           | `root`              |
//! | `{analyst, ""}` (custom role)                | `analyst`           |
//!
//! Responses use `cluster` for cluster roles, `database:*` for unscoped database roles and an
//! empty resource for custom roles, whose resources live in their privileges.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustegon_common::{Error, ErrorCode};
use rustegon_proto::v1::{
    ApiKey, ChangePasswordRequest, ChangePasswordResponse, CreateApiKeyRequest,
    CreateApiKeyResponse, CreateRoleRequest, CreateRoleResponse, CreateUserRequest,
    CreateUserResponse, DropRoleRequest, DropRoleResponse, DropUserRequest, DropUserResponse,
    GetRoleRequest, GetRoleResponse, GetSettingsRequest, GetSettingsResponse, GetUserRequest,
    GetUserResponse, ListApiKeysRequest, ListApiKeysResponse, ListRolesRequest, ListRolesResponse,
    ListUsersRequest, ListUsersResponse, Privilege, RevokeApiKeyRequest, RevokeApiKeyResponse,
    Role, RoleGrant, Setting, UpdateRoleRequest, UpdateRoleResponse, UpdateSettingsRequest,
    UpdateSettingsResponse, UpdateUserRequest, UpdateUserResponse, User, admin_service_server,
};
use rustegon_security::{
    authn::secret,
    rbac::{BuiltinRole, RoleRef, RoleScopes},
};
use tonic::{Request, Response, Status};

use super::metadata::{ResponseTrailers, context_from_request, respond, status_of};
use crate::{
    security::SettingInfo,
    services::{
        RequestContext, Services,
        admin::{ApiKeyInfo, NewApiKeySpec, NewUserSpec, RoleInfo, UserInfo, UserUpdate},
    },
};

/// Unix milliseconds of `t` (0 before the epoch, saturating).
#[must_use]
pub fn unix_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn from_unix_ms(ms: i64) -> Result<SystemTime, Error> {
    u64::try_from(ms)
        .ok()
        .and_then(|ms| UNIX_EPOCH.checked_add(Duration::from_millis(ms)))
        .ok_or_else(|| {
            Error::new(ErrorCode::InvalidArgument, "timestamp out of range")
                .with_detail("field", "expires_at_unix_ms")
        })
}

/// The `RoleGrant` of a role reference (module docs).
#[must_use]
pub fn role_ref_to_grant(reference: &str) -> RoleGrant {
    let (role, scope) = match reference.split_once('@') {
        Some((r, s)) => (r, Some(s)),
        None => (reference, None),
    };
    let resource = match scope {
        Some(s) => match s.split_once('.') {
            Some(_) => format!("collection:{s}"),
            None => format!("database:{s}"),
        },
        None => match BuiltinRole::parse(role).map(BuiltinRole::scopes) {
            Some(RoleScopes::Cluster) => "cluster".to_owned(),
            Some(_) => "database:*".to_owned(),
            None => String::new(),
        },
    };
    RoleGrant {
        role: role.to_owned(),
        resource,
    }
}

/// The role reference of a `RoleGrant` (module docs), validated.
///
/// # Errors
/// `RGN-1001` for a malformed resource or a scope the role cannot take.
pub fn grant_to_role_ref(grant: &RoleGrant) -> Result<String, Error> {
    let r = &grant.role;
    let text = match grant.resource.as_str() {
        "" | "cluster" | "database:*" => r.clone(),
        res => {
            if let Some(db) = res.strip_prefix("database:") {
                format!("{r}@{db}")
            } else if let Some(coll) = res.strip_prefix("collection:") {
                format!("{r}@{coll}")
            } else {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid role grant resource {res:?}"),
                )
                .with_detail("field", "resource"));
            }
        }
    };
    Ok(RoleRef::parse(&text)?.to_string())
}

fn grants(list: &[RoleGrant]) -> Result<Vec<String>, Error> {
    list.iter().map(grant_to_role_ref).collect()
}

fn user_msg(u: UserInfo) -> User {
    User {
        name: u.name,
        roles: u.roles.iter().map(|r| role_ref_to_grant(r)).collect(),
        disabled: u.disabled,
        must_change_password: u.must_change_password,
        x509_subject: u.x509_subject,
        created_at_unix_ms: unix_ms(u.created_at),
    }
}

fn role_msg(r: RoleInfo) -> Role {
    Role {
        name: r.name,
        privileges: r
            .privileges
            .into_iter()
            .map(|(resource, actions)| Privilege { resource, actions })
            .collect(),
        inherits: r.inherits,
        built_in: r.built_in,
    }
}

fn role_info(r: Option<Role>) -> Result<RoleInfo, Error> {
    let r = r.ok_or_else(|| {
        Error::new(ErrorCode::InvalidArgument, "role is required").with_detail("field", "role")
    })?;
    Ok(RoleInfo {
        name: r.name,
        privileges: r
            .privileges
            .into_iter()
            .map(|p| (p.resource, p.actions))
            .collect(),
        inherits: r.inherits,
        built_in: r.built_in,
    })
}

fn key_msg(k: ApiKeyInfo) -> ApiKey {
    ApiKey {
        key_id: k.key_id,
        user: k.user,
        description: k.description,
        roles: k.roles.iter().map(|r| role_ref_to_grant(r)).collect(),
        expires_at_unix_ms: k.expires_at.map(unix_ms),
        ip_allowlist: k.ip_allowlist,
        created_at_unix_ms: unix_ms(k.created_at),
    }
}

fn setting_msg(s: SettingInfo) -> Setting {
    Setting {
        name: s.name,
        value: s.value,
        default_value: s.default_value,
        runtime_mutable: s.runtime_mutable,
        description: s.description,
    }
}

/// `rustegon.v1.AdminService` over [`Services`].
#[derive(Debug, Clone)]
pub struct AdminGrpc {
    services: Services,
}

impl AdminGrpc {
    /// Creates the adapter.
    #[must_use]
    pub fn new(services: Services) -> Self {
        Self { services }
    }

    #[allow(clippy::result_large_err)] // tonic::Status is the gRPC error type of every handler.
    fn ctx<T>(&self, request: &Request<T>) -> Result<RequestContext, Status> {
        context_from_request(request, self.services.deps())
    }
}

fn reply<T>(ctx: &RequestContext, result: Result<T, Error>) -> Result<Response<T>, Status> {
    match result {
        Ok(message) => Ok(respond(
            message,
            ResponseTrailers {
                causality_token: ctx.causality_token().map(str::to_owned),
            },
        )),
        Err(e) => Err(status_of(&e, &ctx.trace_id_hex())),
    }
}

#[tonic::async_trait]
impl admin_service_server::AdminService for AdminGrpc {
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let admin = self.services.admin();
        let result = async {
            let spec = NewUserSpec {
                name: r.name,
                password: r.password.map(secret),
                roles: grants(&r.roles)?,
                must_change_password: r.must_change_password,
                x509_subject: r.x509_subject,
            };
            let user = admin.create_user(&ctx, spec).await?;
            Ok(CreateUserResponse {
                user: Some(user_msg(user)),
            })
        }
        .await;
        reply(&ctx, result)
    }

    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let name = request.into_inner().name;
        let result = self.services.admin().get_user(&ctx, &name).await;
        reply(
            &ctx,
            result.map(|u| GetUserResponse {
                user: Some(user_msg(u)),
            }),
        )
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let result = self.services.admin().list_users(&ctx).await;
        reply(
            &ctx,
            result.map(|users| ListUsersResponse {
                users: users.into_iter().map(user_msg).collect(),
            }),
        )
    }

    async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<UpdateUserResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let admin = self.services.admin();
        let result = async {
            let update = UserUpdate {
                name: r.name,
                password: r.password.map(secret),
                roles: r.roles.map(|l| grants(&l.grants)).transpose()?,
                disabled: r.disabled,
                must_change_password: r.must_change_password,
                x509_subject: r.x509_subject,
            };
            let user = admin.update_user(&ctx, update).await?;
            Ok(UpdateUserResponse {
                user: Some(user_msg(user)),
            })
        }
        .await;
        reply(&ctx, result)
    }

    async fn drop_user(
        &self,
        request: Request<DropUserRequest>,
    ) -> Result<Response<DropUserResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let name = request.into_inner().name;
        let result = self.services.admin().drop_user(&ctx, &name).await;
        reply(&ctx, result.map(|()| DropUserResponse {}))
    }

    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ChangePasswordResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let result = self
            .services
            .admin()
            .change_password(&ctx, secret(r.current_password), secret(r.new_password))
            .await;
        reply(&ctx, result.map(|()| ChangePasswordResponse {}))
    }

    async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<CreateRoleResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let role = request.into_inner().role;
        let admin = self.services.admin();
        let result = async { admin.create_role(&ctx, role_info(role)?).await }.await;
        reply(
            &ctx,
            result.map(|r| CreateRoleResponse {
                role: Some(role_msg(r)),
            }),
        )
    }

    async fn get_role(
        &self,
        request: Request<GetRoleRequest>,
    ) -> Result<Response<GetRoleResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let name = request.into_inner().name;
        let result = self.services.admin().get_role(&ctx, &name).await;
        reply(
            &ctx,
            result.map(|r| GetRoleResponse {
                role: Some(role_msg(r)),
            }),
        )
    }

    async fn list_roles(
        &self,
        request: Request<ListRolesRequest>,
    ) -> Result<Response<ListRolesResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let result = self.services.admin().list_roles(&ctx).await;
        reply(
            &ctx,
            result.map(|roles| ListRolesResponse {
                roles: roles.into_iter().map(role_msg).collect(),
            }),
        )
    }

    async fn update_role(
        &self,
        request: Request<UpdateRoleRequest>,
    ) -> Result<Response<UpdateRoleResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let role = request.into_inner().role;
        let admin = self.services.admin();
        let result = async { admin.update_role(&ctx, role_info(role)?).await }.await;
        reply(
            &ctx,
            result.map(|r| UpdateRoleResponse {
                role: Some(role_msg(r)),
            }),
        )
    }

    async fn drop_role(
        &self,
        request: Request<DropRoleRequest>,
    ) -> Result<Response<DropRoleResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let name = request.into_inner().name;
        let result = self.services.admin().drop_role(&ctx, &name).await;
        reply(&ctx, result.map(|()| DropRoleResponse {}))
    }

    async fn create_api_key(
        &self,
        request: Request<CreateApiKeyRequest>,
    ) -> Result<Response<CreateApiKeyResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let admin = self.services.admin();
        let result = async {
            let spec = NewApiKeySpec {
                user: r.user,
                description: r.description,
                roles: grants(&r.roles)?,
                expires_at: r.expires_at_unix_ms.map(from_unix_ms).transpose()?,
                ip_allowlist: r.ip_allowlist,
            };
            let (key, full) = admin.create_api_key(&ctx, spec).await?;
            Ok(CreateApiKeyResponse {
                key: Some(key_msg(key)),
                secret: full.expose().to_string(),
            })
        }
        .await;
        reply(&ctx, result)
    }

    async fn list_api_keys(
        &self,
        request: Request<ListApiKeysRequest>,
    ) -> Result<Response<ListApiKeysResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let user = request.into_inner().user;
        let result = self.services.admin().list_api_keys(&ctx, user).await;
        reply(
            &ctx,
            result.map(|keys| ListApiKeysResponse {
                keys: keys.into_iter().map(key_msg).collect(),
            }),
        )
    }

    async fn revoke_api_key(
        &self,
        request: Request<RevokeApiKeyRequest>,
    ) -> Result<Response<RevokeApiKeyResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let key_id = request.into_inner().key_id;
        let result = self.services.admin().revoke_api_key(&ctx, &key_id).await;
        reply(&ctx, result.map(|()| RevokeApiKeyResponse {}))
    }

    async fn get_settings(
        &self,
        request: Request<GetSettingsRequest>,
    ) -> Result<Response<GetSettingsResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let names = request.into_inner().names;
        let result = self.services.admin().get_settings(&ctx, names).await;
        reply(
            &ctx,
            result.map(|settings| GetSettingsResponse {
                settings: settings.into_iter().map(setting_msg).collect(),
            }),
        )
    }

    async fn update_settings(
        &self,
        request: Request<UpdateSettingsRequest>,
    ) -> Result<Response<UpdateSettingsResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let values = request.into_inner().values.into_iter().collect();
        let result = self.services.admin().update_settings(&ctx, values).await;
        reply(
            &ctx,
            result.map(|settings| UpdateSettingsResponse {
                settings: settings.into_iter().map(setting_msg).collect(),
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn role_grants_map_to_role_references_and_back() {
        let g = |role: &str, resource: &str| RoleGrant {
            role: role.into(),
            resource: resource.into(),
        };
        for (grant, reference) in [
            (g("read", "database:shop"), "read@shop"),
            (
                g("read_write", "collection:shop.orders"),
                "read_write@shop.orders",
            ),
            (g("read", "database:*"), "read"),
            (g("root", "cluster"), "root"),
            (g("analyst", ""), "analyst"),
        ] {
            assert_eq!(grant_to_role_ref(&grant).unwrap(), reference);
            assert_eq!(role_ref_to_grant(reference), grant);
        }
        assert_eq!(grant_to_role_ref(&g("root", "")).unwrap(), "root");
        for bad in [
            g("root", "database:shop"),
            g("read", "table:x"),
            g("db_admin", "collection:a.b"),
        ] {
            assert_eq!(
                grant_to_role_ref(&bad).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
        }
        assert_eq!(unix_ms(UNIX_EPOCH + Duration::from_millis(5)), 5);
        assert!(from_unix_ms(-1).is_err());
    }
}
