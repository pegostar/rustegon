// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `rustegon user …` and `rustegon role …`: users and roles over `AdminService`
//! (FR-SEC-001/002, security.md §3, PD-051, PD-058).
//!
//! Grants are written `role`, `role@db` or `role@db.coll` (the role-reference syntax of PD-051,
//! mapped onto `RoleGrant{role, resource}`); privileges `resource=action[,action…]` with the
//! resources of security.md §3.1 (`cluster`, `database:<db>`, `collection:<db>.<coll>`).
//! `grant`/`revoke` read the current record and write the merged one back; two administrators
//! changing the same record concurrently can lose one change (the API has no compare-and-set
//! yet; PD-058).

use std::path::PathBuf;

use clap::{Args, Subcommand};
use rustegon_proto::v1::{
    ApiKey, ChangePasswordRequest, CreateApiKeyRequest, CreateRoleRequest, CreateUserRequest,
    DropRoleRequest, DropUserRequest, GetRoleRequest, GetUserRequest, ListApiKeysRequest,
    ListRolesRequest, ListUsersRequest, Privilege, RevokeApiKeyRequest, Role, RoleGrant,
    RoleGrantList, UpdateRoleRequest, UpdateUserRequest, User, WhoAmIRequest,
    admin_service_client::AdminServiceClient, auth_service_client::AuthServiceClient,
};

use crate::{
    client::{Client, ConnArgs, PASSWORD_ENV},
    output::{CliError, CliResult, fail, out},
    secrets,
};

/// Environment variable with the password of a user being created or changed.
pub const NEW_PASSWORD_ENV: &str = "RUSTEGON_NEW_PASSWORD";

/// `rustegon user …`.
#[derive(Debug, Args)]
pub struct UserArgs {
    #[command(flatten)]
    conn: ConnArgs,
    #[command(subcommand)]
    command: UserCommand,
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    /// List users.
    List,
    /// Show one user.
    Show {
        /// User name.
        name: String,
    },
    /// Create a user with a password (or `--x509-subject` for a certificate user).
    Create {
        /// User name (`x509:CN=…` for a certificate user).
        name: String,
        /// Role grant `role`, `role@db` or `role@db.coll` (repeatable).
        #[arg(long = "role", value_name = "GRANT")]
        roles: Vec<String>,
        /// File with the new password (else `RUSTEGON_NEW_PASSWORD`, else a prompt).
        #[arg(long, value_name = "PATH", conflicts_with = "x509_subject")]
        new_password_file: Option<PathBuf>,
        /// Certificate subject of an `x509:` user (no password).
        #[arg(long, value_name = "SUBJECT")]
        x509_subject: Option<String>,
        /// Require a password change at the first login.
        #[arg(long)]
        must_change_password: bool,
    },
    /// Drop a user (revokes its sessions and API keys).
    Drop {
        /// User name.
        name: String,
    },
    /// Add role grants to a user.
    Grant {
        /// User name.
        name: String,
        /// Role grant `role`, `role@db` or `role@db.coll` (repeatable).
        #[arg(long = "role", value_name = "GRANT", required = true)]
        roles: Vec<String>,
    },
    /// Remove role grants from a user.
    Revoke {
        /// User name.
        name: String,
        /// Role grant `role`, `role@db` or `role@db.coll` (repeatable).
        #[arg(long = "role", value_name = "GRANT", required = true)]
        roles: Vec<String>,
    },
    /// Change a password: your own (default; needs the current one) or another user's
    /// (`user_manage`).
    Passwd {
        /// User name (default: the logged-in user).
        name: Option<String>,
        /// File with the new password (else `RUSTEGON_NEW_PASSWORD`, else a prompt).
        #[arg(long, value_name = "PATH")]
        new_password_file: Option<PathBuf>,
    },
}

/// `rustegon role …`.
#[derive(Debug, Args)]
pub struct RoleArgs {
    #[command(flatten)]
    conn: ConnArgs,
    #[command(subcommand)]
    command: RoleCommand,
}

#[derive(Debug, Subcommand)]
enum RoleCommand {
    /// List roles (built-in and custom).
    List,
    /// Show one role.
    Show {
        /// Role name.
        name: String,
    },
    /// Create a custom role.
    Create {
        /// Role name.
        name: String,
        /// Privilege `resource=action[,action…]` (repeatable).
        #[arg(long = "privilege", value_name = "PRIVILEGE")]
        privileges: Vec<String>,
        /// Inherited role (repeatable).
        #[arg(long = "inherits", value_name = "ROLE")]
        inherits: Vec<String>,
    },
    /// Drop a custom role.
    Drop {
        /// Role name.
        name: String,
    },
    /// Add privileges (and inherited roles) to a custom role.
    Grant {
        /// Role name.
        name: String,
        /// Privilege `resource=action[,action…]` (repeatable).
        #[arg(long = "privilege", value_name = "PRIVILEGE")]
        privileges: Vec<String>,
        /// Inherited role (repeatable).
        #[arg(long = "inherits", value_name = "ROLE")]
        inherits: Vec<String>,
    },
    /// Remove privileges (and inherited roles) from a custom role.
    Revoke {
        /// Role name.
        name: String,
        /// Privilege `resource=action[,action…]` (repeatable).
        #[arg(long = "privilege", value_name = "PRIVILEGE")]
        privileges: Vec<String>,
        /// Inherited role (repeatable).
        #[arg(long = "inherits", value_name = "ROLE")]
        inherits: Vec<String>,
    },
}

/// `rustegon apikey …`.
#[derive(Debug, Args)]
pub struct ApiKeyArgs {
    #[command(flatten)]
    conn: ConnArgs,
    #[command(subcommand)]
    command: ApiKeyCommand,
}

#[derive(Debug, Subcommand)]
enum ApiKeyCommand {
    /// Create an API key; its secret is written to a new owner-only file, never printed.
    Create {
        /// File receiving the key `rgn_<id>_<secret>` (must not exist).
        #[arg(long, value_name = "PATH")]
        secret_file: PathBuf,
        /// Owner of the key (default: the logged-in user; another user needs `user_manage`).
        #[arg(long, value_name = "USER")]
        for_user: Option<String>,
        /// Description.
        #[arg(long, default_value = "")]
        description: String,
        /// Scope grant `role`, `role@db` or `role@db.coll` (repeatable; default: the owner's
        /// roles).
        #[arg(long = "role", value_name = "GRANT")]
        roles: Vec<String>,
    },
    /// List API keys (never their secrets).
    List {
        /// Owner whose keys are listed (default: the logged-in user).
        #[arg(long, value_name = "USER")]
        for_user: Option<String>,
    },
    /// Revoke an API key.
    Revoke {
        /// Key id.
        key_id: String,
    },
}

/// `role`, `role@db`, `role@db.coll` → `RoleGrant` (PD-051).
fn parse_grant(text: &str) -> CliResult<RoleGrant> {
    let (role, scope) = match text.split_once('@') {
        Some((r, s)) => (r, Some(s)),
        None => (text, None),
    };
    if role.is_empty() || scope.is_some_and(str::is_empty) {
        return fail(format!(
            "invalid grant {text:?}: expected role, role@db or role@db.coll"
        ));
    }
    let resource = match scope {
        None => String::new(),
        Some(s) => match s.split_once('.') {
            Some(_) => format!("collection:{s}"),
            None => format!("database:{s}"),
        },
    };
    Ok(RoleGrant {
        role: role.to_owned(),
        resource,
    })
}

fn grant_text(g: &RoleGrant) -> String {
    let scope = g
        .resource
        .strip_prefix("database:")
        .or_else(|| g.resource.strip_prefix("collection:"));
    match scope {
        Some(s) if s != "*" => format!("{}@{s}", g.role),
        _ => g.role.clone(),
    }
}

/// `resource=action[,action…]` → `Privilege`.
fn parse_privilege(text: &str) -> CliResult<Privilege> {
    let Some((resource, actions)) = text.split_once('=') else {
        return fail(format!(
            "invalid privilege {text:?}: expected resource=action[,action…]"
        ));
    };
    let actions: Vec<String> = actions
        .split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_owned)
        .collect();
    if resource.is_empty() || actions.is_empty() {
        return fail(format!(
            "invalid privilege {text:?}: expected resource=action[,action…]"
        ));
    }
    Ok(Privilege {
        resource: resource.trim().to_owned(),
        actions,
    })
}

fn user_line(u: &User) -> String {
    let roles = u.roles.iter().map(grant_text).collect::<Vec<_>>().join(",");
    let mut flags = Vec::new();
    if u.disabled {
        flags.push("disabled");
    }
    if u.must_change_password {
        flags.push("must_change_password");
    }
    let mut line = format!(
        "{}\troles={}",
        u.name,
        if roles.is_empty() { "-" } else { &roles }
    );
    if let Some(s) = &u.x509_subject {
        line.push_str("\tx509_subject=");
        line.push_str(s);
    }
    if !flags.is_empty() {
        line.push('\t');
        line.push_str(&flags.join(","));
    }
    line
}

fn role_line(r: &Role) -> String {
    let privileges = r
        .privileges
        .iter()
        .map(|p| format!("{}={}", p.resource, p.actions.join(",")))
        .collect::<Vec<_>>()
        .join(" ");
    let mut line = format!(
        "{}\t{}\tprivileges={}",
        r.name,
        if r.built_in { "built-in" } else { "custom" },
        if privileges.is_empty() {
            "-"
        } else {
            &privileges
        }
    );
    if !r.inherits.is_empty() {
        line.push_str("\tinherits=");
        line.push_str(&r.inherits.join(","));
    }
    line
}

fn new_password(
    file: Option<&std::path::Path>,
) -> CliResult<rustegon_security::authn::SecretString> {
    secrets::obtain(
        "new password",
        file,
        NEW_PASSWORD_ENV,
        "--new-password-file",
        true,
    )
}

/// Runs `rustegon user …`.
///
/// # Errors
/// Option, connection and server errors.
pub fn run_user(args: UserArgs) -> CliResult<()> {
    // `passwd` of the logged-in user needs the current password for the login and for
    // `ChangePassword`: obtain it once.
    let own_passwd = matches!(&args.command, UserCommand::Passwd { name, .. }
        if name.is_none() || name.as_deref() == args.conn.user.as_deref());
    let current = if own_passwd && args.conn.api_key_file.is_none() && args.conn.user.is_some() {
        let user = args.conn.user.clone().unwrap_or_default();
        Some(secrets::obtain(
            &format!("current password of {user}"),
            args.conn.password_file.as_deref(),
            PASSWORD_ENV,
            "--password-file",
            false,
        )?)
    } else {
        None
    };
    let client = Client::connect_with(&args.conn, current.as_ref())?;
    let result = user_command(&client, args.command, current.as_ref());
    client.close();
    result
}

fn user_command(
    client: &Client,
    command: UserCommand,
    current: Option<&rustegon_security::authn::SecretString>,
) -> CliResult<()> {
    let mut admin = AdminServiceClient::new(client.channel());
    match command {
        UserCommand::List => {
            let users = client
                .call(admin.list_users(client.request(ListUsersRequest {})))?
                .into_inner()
                .users;
            for u in &users {
                out(&user_line(u))?;
            }
            Ok(())
        }
        UserCommand::Show { name } => {
            let user = get_user(client, &mut admin, &name)?;
            out(&user_line(&user))
        }
        UserCommand::Create {
            name,
            roles,
            new_password_file,
            x509_subject,
            must_change_password,
        } => {
            let roles = roles
                .iter()
                .map(|r| parse_grant(r))
                .collect::<CliResult<Vec<_>>>()?;
            let password = if x509_subject.is_some() {
                None
            } else {
                Some(new_password(new_password_file.as_deref())?)
            };
            let created = client
                .call(admin.create_user(client.request(CreateUserRequest {
                    name,
                    password: password.map(|p| p.expose().as_str().to_owned()),
                    roles,
                    must_change_password,
                    x509_subject,
                })))?
                .into_inner()
                .user
                .ok_or_else(|| CliError("the server returned no user".into()))?;
            out(&format!("created {}", user_line(&created)))
        }
        UserCommand::Drop { name } => {
            client.call(admin.drop_user(client.request(DropUserRequest { name: name.clone() })))?;
            out(&format!("dropped user {name}"))
        }
        UserCommand::Grant { name, roles } => {
            update_grants(client, &mut admin, &name, &roles, true)
        }
        UserCommand::Revoke { name, roles } => {
            update_grants(client, &mut admin, &name, &roles, false)
        }
        UserCommand::Passwd {
            name,
            new_password_file,
        } => {
            let target = name.or_else(|| client.user.clone());
            let Some(target) = target else {
                return fail("passwd with an API key needs the user name");
            };
            let new = new_password(new_password_file.as_deref())?;
            if let (Some(current), Some(me)) = (current, client.user.as_deref())
                && me == target
            {
                client.call(admin.change_password(client.request(ChangePasswordRequest {
                    current_password: current.expose().as_str().to_owned(),
                    new_password: new.expose().as_str().to_owned(),
                })))?;
                return out(&format!(
                    "password of {target} changed (its sessions were revoked)"
                ));
            }
            client.call(admin.update_user(client.request(UpdateUserRequest {
                name: target.clone(),
                password: Some(new.expose().as_str().to_owned()),
                ..UpdateUserRequest::default()
            })))?;
            out(&format!("password of {target} changed"))
        }
    }
}

type Admin = AdminServiceClient<tonic::transport::Channel>;

fn get_user(client: &Client, admin: &mut Admin, name: &str) -> CliResult<User> {
    client
        .call(admin.get_user(client.request(GetUserRequest {
            name: name.to_owned(),
        })))?
        .into_inner()
        .user
        .ok_or_else(|| CliError(format!("the server returned no user {name}")))
}

fn same_grant(a: &RoleGrant, b: &RoleGrant) -> bool {
    // `""`, `cluster` and `database:*` denote the same unscoped grant (PD-051).
    let norm = |r: &str| match r {
        "" | "cluster" | "database:*" => String::new(),
        other => other.to_owned(),
    };
    a.role == b.role && norm(&a.resource) == norm(&b.resource)
}

fn update_grants(
    client: &Client,
    admin: &mut Admin,
    name: &str,
    texts: &[String],
    add: bool,
) -> CliResult<()> {
    let changes = texts
        .iter()
        .map(|t| parse_grant(t))
        .collect::<CliResult<Vec<_>>>()?;
    let mut grants = get_user(client, admin, name)?.roles;
    for change in changes {
        let present = grants.iter().any(|g| same_grant(g, &change));
        if add && !present {
            grants.push(change);
        } else if !add {
            if !present {
                return fail(format!("user {name} has no grant {}", grant_text(&change)));
            }
            grants.retain(|g| !same_grant(g, &change));
        }
    }
    let user = client
        .call(admin.update_user(client.request(UpdateUserRequest {
            name: name.to_owned(),
            roles: Some(RoleGrantList { grants }),
            ..UpdateUserRequest::default()
        })))?
        .into_inner()
        .user
        .ok_or_else(|| CliError("the server returned no user".into()))?;
    out(&format!("updated {}", user_line(&user)))
}

/// Runs `rustegon role …`.
///
/// # Errors
/// Option, connection and server errors.
pub fn run_role(args: RoleArgs) -> CliResult<()> {
    let client = Client::connect(&args.conn)?;
    let result = role_command(&client, args.command);
    client.close();
    result
}

fn parse_privileges(texts: &[String]) -> CliResult<Vec<Privilege>> {
    texts.iter().map(|t| parse_privilege(t)).collect()
}

fn role_command(client: &Client, command: RoleCommand) -> CliResult<()> {
    let mut admin = AdminServiceClient::new(client.channel());
    match command {
        RoleCommand::List => {
            let roles = client
                .call(admin.list_roles(client.request(ListRolesRequest {})))?
                .into_inner()
                .roles;
            for r in &roles {
                out(&role_line(r))?;
            }
            Ok(())
        }
        RoleCommand::Show { name } => out(&role_line(&get_role(client, &mut admin, &name)?)),
        RoleCommand::Create {
            name,
            privileges,
            inherits,
        } => {
            let role = Role {
                name,
                privileges: parse_privileges(&privileges)?,
                inherits,
                built_in: false,
            };
            let created = client
                .call(admin.create_role(client.request(CreateRoleRequest { role: Some(role) })))?
                .into_inner()
                .role
                .ok_or_else(|| CliError("the server returned no role".into()))?;
            out(&format!("created {}", role_line(&created)))
        }
        RoleCommand::Drop { name } => {
            client.call(admin.drop_role(client.request(DropRoleRequest { name: name.clone() })))?;
            out(&format!("dropped role {name}"))
        }
        RoleCommand::Grant {
            name,
            privileges,
            inherits,
        } => update_role(client, &mut admin, &name, &privileges, &inherits, true),
        RoleCommand::Revoke {
            name,
            privileges,
            inherits,
        } => update_role(client, &mut admin, &name, &privileges, &inherits, false),
    }
}

fn get_role(client: &Client, admin: &mut Admin, name: &str) -> CliResult<Role> {
    client
        .call(admin.get_role(client.request(GetRoleRequest {
            name: name.to_owned(),
        })))?
        .into_inner()
        .role
        .ok_or_else(|| CliError(format!("the server returned no role {name}")))
}

fn update_role(
    client: &Client,
    admin: &mut Admin,
    name: &str,
    privileges: &[String],
    inherits: &[String],
    add: bool,
) -> CliResult<()> {
    if privileges.is_empty() && inherits.is_empty() {
        return fail("nothing to change: give --privilege and/or --inherits");
    }
    let changes = parse_privileges(privileges)?;
    let mut role = get_role(client, admin, name)?;
    for change in changes {
        let entry = role
            .privileges
            .iter_mut()
            .find(|p| p.resource == change.resource);
        match (entry, add) {
            (Some(p), true) => {
                for a in change.actions {
                    if !p.actions.contains(&a) {
                        p.actions.push(a);
                    }
                }
            }
            (None, true) => role.privileges.push(change),
            (Some(p), false) => p.actions.retain(|a| !change.actions.contains(a)),
            (None, false) => {
                return fail(format!(
                    "role {name} has no privilege on {}",
                    change.resource
                ));
            }
        }
    }
    role.privileges.retain(|p| !p.actions.is_empty());
    for i in inherits {
        if add && !role.inherits.contains(i) {
            role.inherits.push(i.clone());
        } else if !add {
            role.inherits.retain(|r| r != i);
        }
    }
    let updated = client
        .call(admin.update_role(client.request(UpdateRoleRequest { role: Some(role) })))?
        .into_inner()
        .role
        .ok_or_else(|| CliError("the server returned no role".into()))?;
    out(&format!("updated {}", role_line(&updated)))
}

/// Runs `rustegon apikey …`.
///
/// # Errors
/// Option, connection, server and file errors.
pub fn run_api_key(args: ApiKeyArgs) -> CliResult<()> {
    let client = Client::connect(&args.conn)?;
    let result = api_key_command(&client, args.command);
    client.close();
    result
}

fn api_key_line(k: &ApiKey) -> String {
    let roles = k.roles.iter().map(grant_text).collect::<Vec<_>>().join(",");
    format!(
        "{}\tuser={}\troles={}\tcreated={}\t{}",
        k.key_id,
        k.user,
        if roles.is_empty() { "-" } else { &roles },
        crate::cert::utc_text(k.created_at_unix_ms.div_euclid(1000)),
        k.description
    )
}

fn api_key_command(client: &Client, command: ApiKeyCommand) -> CliResult<()> {
    let mut admin = AdminServiceClient::new(client.channel());
    match command {
        ApiKeyCommand::Create {
            secret_file,
            for_user,
            description,
            roles,
        } => {
            if secret_file.exists() {
                return fail(format!(
                    "{}: already exists (never overwritten)",
                    secret_file.display()
                ));
            }
            let mut roles = roles
                .iter()
                .map(|r| parse_grant(r))
                .collect::<CliResult<Vec<_>>>()?;
            if roles.is_empty() {
                // The server requires an explicit scope (a non-empty subset of the owner's
                // roles); the documented default is all of them.
                roles = if let Some(u) = &for_user {
                    get_user(client, &mut admin, u)?.roles
                } else {
                    let mut auth = AuthServiceClient::new(client.channel());
                    client
                        .call(auth.who_am_i(client.request(WhoAmIRequest {})))?
                        .into_inner()
                        .roles
                };
            }
            let created = client
                .call(admin.create_api_key(client.request(CreateApiKeyRequest {
                    user: for_user,
                    description,
                    roles,
                    ..CreateApiKeyRequest::default()
                })))?
                .into_inner();
            // The secret exists only in this response: store it before reporting anything.
            let full = zeroize::Zeroizing::new(created.secret);
            crate::secrets::write_private(
                &secret_file,
                &rustegon_security::authn::secret(full.as_str()),
            )?;
            let key = created
                .key
                .ok_or_else(|| CliError("the server returned no key".into()))?;
            out(&format!(
                "created {} (secret written to {})",
                api_key_line(&key),
                secret_file.display()
            ))
        }
        ApiKeyCommand::List { for_user } => {
            let keys = client
                .call(admin.list_api_keys(client.request(ListApiKeysRequest { user: for_user })))?
                .into_inner()
                .keys;
            for k in &keys {
                out(&api_key_line(k))?;
            }
            Ok(())
        }
        ApiKeyCommand::Revoke { key_id } => {
            client.call(admin.revoke_api_key(client.request(RevokeApiKeyRequest {
                key_id: key_id.clone(),
            })))?;
            out(&format!("revoked API key {key_id}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_sec_002_grant_syntax_maps_to_role_grants() {
        let g = parse_grant("readWrite@shop").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            (g.role.as_str(), g.resource.as_str()),
            ("readWrite", "database:shop")
        );
        let g = parse_grant("read@shop.orders").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(g.resource, "collection:shop.orders");
        let g = parse_grant("root").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(g.resource, "");
        assert_eq!(grant_text(&g), "root");
        assert!(parse_grant("@shop").is_err());
        assert!(parse_grant("r@").is_err());
        assert!(same_grant(
            &RoleGrant {
                role: "r".into(),
                resource: "cluster".into()
            },
            &RoleGrant {
                role: "r".into(),
                resource: String::new()
            },
        ));
    }

    #[test]
    fn fr_sec_002_privilege_syntax() {
        let p = parse_privilege("database:shop=find, insert").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.resource, "database:shop");
        assert_eq!(p.actions, ["find", "insert"]);
        assert!(parse_privilege("cluster").is_err());
        assert!(parse_privilege("cluster=").is_err());
    }
}
