// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Authentication, sessions, API keys, lockout, rate limiting, audit and administration over
//! the real gRPC listener and engine (FR-SEC-001…006, FR-API-001 auth part; PD-051).

// End-to-end scenarios read best as one sequence per requirement.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::{collections::HashMap, time::Duration};

use common::{
    ADMIN, ADMIN_PASSWORD, Binding, Harness, OTHER_PASSWORD, authed, base_flags, bearer, code_of,
    open_security,
};
use rustegon_proto::v1::{
    AuthMechanism, ChangePasswordRequest, CreateApiKeyRequest, CreateRoleRequest,
    CreateUserRequest, DropUserRequest, GetSettingsRequest, ListUsersRequest, LogoutRequest,
    Privilege, RevokeApiKeyRequest, Role, RoleGrant, RoleGrantList, UpdateSettingsRequest,
    UpdateUserRequest, WhoAmIRequest, admin_service_client::AdminServiceClient,
    auth_service_client::AuthServiceClient,
};
use rustegon_security::{audit::verify_dir, authn::bootstrap::AdminPassword};
use rustegon_server::{
    Executor,
    security::{BootstrapOutcome, INITIAL_ADMIN_PASSWORD_FILE, write_initial_password},
    services::ServiceDeps,
};
use rustegon_sim_api::{OsRng, StdFileSystem};
use tonic::Code;

fn grant(role: &str, resource: &str) -> RoleGrant {
    RoleGrant {
        role: role.into(),
        resource: resource.into(),
    }
}

fn flags(extra: &[&str]) -> Vec<String> {
    let mut f = base_flags();
    f.extend(extra.iter().map(|s| (*s).to_owned()));
    f
}

async fn create_user(
    h: &Harness,
    token: &str,
    name: &str,
    password: Option<&str>,
    roles: Vec<RoleGrant>,
) {
    AdminServiceClient::new(h.channel().await.channel)
        .create_user(authed(
            CreateUserRequest {
                name: name.into(),
                password: password.map(str::to_owned),
                roles,
                must_change_password: false,
                x509_subject: None,
            },
            &bearer(token),
        ))
        .await
        .unwrap();
}

/// TC-SEC-002: SCRAM-SHA-256-PLUS (and plain SCRAM) over the wire, the session token
/// authenticates later calls, a `y` downgrade on TLS 1.3 fails, and the client verifies the
/// server signature (inside `login`).
#[tokio::test]
async fn tc_sec_002_scram_login_over_grpc_with_channel_binding() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let ok = conn
        .login(ADMIN, ADMIN_PASSWORD, Binding::Plus)
        .await
        .unwrap();
    assert_eq!(ok.user, ADMIN);
    assert_eq!(ok.session_token.len(), 43);
    assert!(!ok.must_change_password);
    let me = AuthServiceClient::new(conn.channel.clone())
        .who_am_i(authed(WhoAmIRequest {}, &bearer(&ok.session_token)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(me.user, ADMIN);
    assert_eq!(me.roles, vec![grant("root", "cluster")]);
    assert_eq!(me.mechanism, AuthMechanism::ScramSha256 as i32);
    assert_eq!(me.expires_at_unix_ms, ok.expires_at_unix_ms);

    // Without channel binding support (`n`) the login works too.
    conn.login(ADMIN, ADMIN_PASSWORD, Binding::None)
        .await
        .unwrap();
    // `y` while the server offers tls-exporter is a downgrade.
    let err = conn
        .login(ADMIN, ADMIN_PASSWORD, Binding::NotOffered)
        .await
        .unwrap_err();
    assert_eq!((err.code(), code_of(&err)), (Code::Unauthenticated, 4001));
    // No credentials, a garbage token, an unknown scheme: RGN-4001 / RGN-4005.
    let mut auth = AuthServiceClient::new(conn.channel.clone());
    let e = auth.who_am_i(WhoAmIRequest {}).await.unwrap_err();
    assert_eq!(code_of(&e), 4001);
    let e = auth
        .who_am_i(authed(WhoAmIRequest {}, "Bearer not-a-token"))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4005);
    let e = auth
        .who_am_i(authed(WhoAmIRequest {}, "Basic YWRtaW46eA=="))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4001);
    h.stop().await;
}

/// TC-SEC-002 / AC-SEC-002: a wrong password and an unknown user fail identically.
#[tokio::test]
async fn tc_sec_002_wrong_password_and_unknown_user_are_indistinguishable() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let wrong = conn
        .login(ADMIN, OTHER_PASSWORD, Binding::Plus)
        .await
        .unwrap_err();
    let unknown = conn
        .login("ghost", OTHER_PASSWORD, Binding::Plus)
        .await
        .unwrap_err();
    for e in [&wrong, &unknown] {
        assert_eq!(e.code(), Code::Unauthenticated);
        let d = rustegon_proto::status::error_detail_of(e).unwrap();
        assert_eq!((d.code, d.name.as_str()), (4001, "Unauthenticated"));
        assert!(d.details.is_empty());
    }
    assert_eq!(wrong.message(), unknown.message());
    assert!(h.audited("login_failure", "failure"));
    h.stop().await;
}

/// TC-SEC-003: a fresh store accepts no credential; the bootstrap runs once, hands out a
/// generated password through an owner-only file, and that admin must change it before doing
/// anything else; the change revokes the session.
#[tokio::test]
async fn tc_sec_003_bootstrap_generated_password_must_be_changed() {
    let h = Harness::start_with(base_flags(), false).await;
    let conn = h.channel().await;
    let e = conn
        .login(ADMIN, ADMIN_PASSWORD, Binding::Plus)
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4001);

    let BootstrapOutcome::Created(done) = h
        .security
        .bootstrap_if_needed(ADMIN, AdminPassword::Generate)
        .unwrap()
    else {
        panic!("first bootstrap creates the admin");
    };
    let generated = done.generated_password.unwrap();
    let path = write_initial_password(&StdFileSystem, &h.data_dir, &generated).unwrap();
    assert!(path.ends_with(INITIAL_ADMIN_PASSWORD_FILE));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap().trim_end(),
        generated.expose().as_str()
    );
    assert!(write_initial_password(&StdFileSystem, &h.data_dir, &generated).is_err());
    assert!(matches!(
        h.security
            .bootstrap_if_needed(ADMIN, AdminPassword::Generate)
            .unwrap(),
        BootstrapOutcome::AlreadyBootstrapped
    ));

    let ok = conn
        .login(ADMIN, generated.expose(), Binding::Plus)
        .await
        .unwrap();
    assert!(ok.must_change_password);
    let token = bearer(&ok.session_token);
    let mut admin = AdminServiceClient::new(conn.channel.clone());
    let e = admin
        .list_users(authed(ListUsersRequest {}, &token))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4002);
    assert_eq!(
        rustegon_proto::status::error_detail_of(&e).unwrap().details["reason"],
        "password_change_required"
    );
    admin
        .change_password(authed(
            ChangePasswordRequest {
                current_password: generated.expose().to_string(),
                new_password: ADMIN_PASSWORD.into(),
            },
            &token,
        ))
        .await
        .unwrap();
    // TC-SEC-007: the password change revoked every session, this one included.
    let e = admin
        .list_users(authed(ListUsersRequest {}, &token))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4005);
    let token = bearer(&conn.admin_token().await);
    let users = admin
        .list_users(authed(ListUsersRequest {}, &token))
        .await
        .unwrap()
        .into_inner()
        .users;
    assert_eq!(users.len(), 1);
    assert!(!users[0].must_change_password);
    h.stop().await;
}

/// TC-SEC-006: after `max_failures` wrong passwords the account is locked; the lock is checked
/// before the credentials, so even the right password gets RGN-4007, and it is audited.
#[tokio::test]
async fn tc_sec_006_lockout_returns_4007_before_credential_check() {
    let h = Harness::start(flags(&["lockout.max_failures=3"])).await;
    let conn = h.channel().await;
    for _ in 0..3 {
        let e = conn
            .login(ADMIN, OTHER_PASSWORD, Binding::Plus)
            .await
            .unwrap_err();
        assert_eq!(code_of(&e), 4001);
    }
    let e = conn
        .login(ADMIN, ADMIN_PASSWORD, Binding::Plus)
        .await
        .unwrap_err();
    assert_eq!((e.code(), code_of(&e)), (Code::PermissionDenied, 4007));
    // Unknown names lock the same way (no user enumeration).
    for _ in 0..3 {
        conn.login("ghost", OTHER_PASSWORD, Binding::Plus)
            .await
            .unwrap_err();
    }
    let e = conn
        .login("ghost", OTHER_PASSWORD, Binding::Plus)
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4007);
    assert!(h.audited("account_locked", "success"));
    assert!(h.security.lockout().unlock(ADMIN));
    conn.login(ADMIN, ADMIN_PASSWORD, Binding::Plus)
        .await
        .unwrap();
    h.stop().await;
}

/// TC-SEC-005: authentication attempts per source IP are rate limited with RGN-4003 and
/// `ErrorDetail.retry_after_ms`.
#[tokio::test]
async fn tc_sec_005_authentication_rate_limit_is_4003_with_retry_after() {
    let h = Harness::start(vec![
        "auth.scram_iterations=100000".into(),
        "rate_limit.auth_per_ip_per_min=1".into(),
        "rate_limit.auth_per_ip_burst=2".into(),
    ])
    .await;
    let conn = h.channel().await;
    conn.login(ADMIN, ADMIN_PASSWORD, Binding::Plus)
        .await
        .unwrap();
    conn.login(ADMIN, ADMIN_PASSWORD, Binding::Plus)
        .await
        .unwrap();
    let e = conn
        .login(ADMIN, ADMIN_PASSWORD, Binding::Plus)
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::ResourceExhausted);
    let d = rustegon_proto::status::error_detail_of(&e).unwrap();
    assert_eq!(d.code, 4003);
    assert!(d.retryable);
    assert!(d.retry_after_ms.unwrap() > 1000, "{:?}", d.retry_after_ms);
    assert_eq!(
        d.details["retry_after_ms"],
        d.retry_after_ms.unwrap().to_string()
    );
    h.stop().await;
}

/// TC-SEC-011: API keys — scope ⊆ owner roles, the scope bounds what the key can do (and
/// what keys it can mint), CIDR allowlist and expiry; verified-key cache hits after the first
/// use and revocation is immediate.
#[tokio::test]
async fn tc_sec_011_api_key_scope_cidr_expiry_cache_and_revocation() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let admin_token = conn.admin_token().await;
    create_user(
        &h,
        &admin_token,
        "svc",
        Some(OTHER_PASSWORD),
        vec![grant("monitor", "cluster"), grant("read", "database:*")],
    )
    .await;
    let svc = bearer(
        &conn
            .login("svc", OTHER_PASSWORD, Binding::Plus)
            .await
            .unwrap()
            .session_token,
    );
    let mut admin = AdminServiceClient::new(conn.channel.clone());
    let create =
        |roles: Vec<RoleGrant>, cidrs: Vec<String>, expires: Option<i64>| CreateApiKeyRequest {
            user: None,
            description: "scraper".into(),
            roles,
            expires_at_unix_ms: expires,
            ip_allowlist: cidrs,
        };
    // Scope outside the owner's roles: refused.
    let e = admin
        .create_api_key(authed(
            create(vec![grant("root", "cluster")], vec![], None),
            &svc,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4002);
    let made = admin
        .create_api_key(authed(
            create(vec![grant("monitor", "cluster")], vec![], None),
            &svc,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(made.secret.starts_with("rgn_"));
    let key = format!("ApiKey {}", made.secret);
    // The key can read settings (cluster_view) but not list users.
    admin
        .get_settings(authed(GetSettingsRequest { names: vec![] }, &key))
        .await
        .unwrap();
    assert_eq!(
        h.security.key_cache().len(),
        1,
        "first use verified and cached"
    );
    admin
        .get_settings(authed(GetSettingsRequest { names: vec![] }, &key))
        .await
        .unwrap();
    let e = admin
        .list_users(authed(ListUsersRequest {}, &key))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4002);
    // A key cannot mint a broader key, although the owner has `read`.
    let e = admin
        .create_api_key(authed(
            create(vec![grant("read", "database:*")], vec![], None),
            &key,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4002);
    let me = AuthServiceClient::new(conn.channel.clone())
        .who_am_i(authed(WhoAmIRequest {}, &key))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(me.mechanism, AuthMechanism::ApiKey as i32);
    assert_eq!(
        me.api_key_id.as_deref(),
        made.key.as_ref().map(|k| k.key_id.as_str())
    );

    // CIDR allowlist: the loopback client is outside 10.0.0.0/8.
    let fenced = admin
        .create_api_key(authed(
            create(
                vec![grant("monitor", "cluster")],
                vec!["10.0.0.0/8".into()],
                None,
            ),
            &svc,
        ))
        .await
        .unwrap()
        .into_inner();
    let e = admin
        .get_settings(authed(
            GetSettingsRequest { names: vec![] },
            &format!("ApiKey {}", fenced.secret),
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4001);
    // Expiry, on the server clock.
    let now_ms = i64::try_from(
        rustegon_sim_api::Clock::wall(h.clock.as_ref())
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let short = admin
        .create_api_key(authed(
            create(
                vec![grant("monitor", "cluster")],
                vec![],
                Some(now_ms + 60_000),
            ),
            &svc,
        ))
        .await
        .unwrap()
        .into_inner();
    let short_key = format!("ApiKey {}", short.secret);
    admin
        .get_settings(authed(GetSettingsRequest { names: vec![] }, &short_key))
        .await
        .unwrap();
    h.clock.advance(Duration::from_secs(120));
    let e = admin
        .get_settings(authed(GetSettingsRequest { names: vec![] }, &short_key))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4001);

    // Revocation is seen by the very next request, despite the cache.
    admin
        .revoke_api_key(authed(
            RevokeApiKeyRequest {
                key_id: made.key.unwrap().key_id,
            },
            &svc,
        ))
        .await
        .unwrap();
    let e = admin
        .get_settings(authed(GetSettingsRequest { names: vec![] }, &key))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4001);
    h.stop().await;
}

/// TC-SEC-007: logout revokes the session; a password or role change by an administrator
/// (credential epoch) revokes the user's sessions; the absolute timeout expires them.
#[tokio::test]
async fn tc_sec_007_logout_credential_epoch_and_expiry_end_sessions() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let admin_token = bearer(&conn.admin_token().await);
    create_user(
        &h,
        admin_token.trim_start_matches("Bearer "),
        "bob",
        Some(OTHER_PASSWORD),
        vec![grant("read", "database:shop")],
    )
    .await;
    let mut auth = AuthServiceClient::new(conn.channel.clone());
    let mut admin = AdminServiceClient::new(conn.channel.clone());

    let t1 = bearer(
        &conn
            .login("bob", OTHER_PASSWORD, Binding::Plus)
            .await
            .unwrap()
            .session_token,
    );
    auth.logout(authed(LogoutRequest {}, &t1)).await.unwrap();
    let e = auth
        .who_am_i(authed(WhoAmIRequest {}, &t1))
        .await
        .unwrap_err();
    assert_eq!((e.code(), code_of(&e)), (Code::Unauthenticated, 4005));

    let t2 = bearer(
        &conn
            .login("bob", OTHER_PASSWORD, Binding::Plus)
            .await
            .unwrap()
            .session_token,
    );
    admin
        .update_user(authed(
            UpdateUserRequest {
                name: "bob".into(),
                roles: Some(RoleGrantList {
                    grants: vec![grant("read_write", "database:shop")],
                }),
                ..UpdateUserRequest::default()
            },
            &admin_token,
        ))
        .await
        .unwrap();
    let e = auth
        .who_am_i(authed(WhoAmIRequest {}, &t2))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4005);

    let t3 = bearer(
        &conn
            .login("bob", OTHER_PASSWORD, Binding::Plus)
            .await
            .unwrap()
            .session_token,
    );
    let me = auth
        .who_am_i(authed(WhoAmIRequest {}, &t3))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(me.roles, vec![grant("read_write", "database:shop")]);
    h.clock.advance(Duration::from_hours(25));
    let e = auth
        .who_am_i(authed(WhoAmIRequest {}, &t3))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4005);
    h.stop().await;
}

/// FR-SEC-002 / TC-SEC-014/015 over the API: custom roles (cycles rejected), grants validated
/// (unknown role, non-assignable `node`), the role's privileges apply at the next request.
#[tokio::test]
async fn fr_sec_002_admin_roles_and_grants_over_grpc() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let token = bearer(&conn.admin_token().await);
    let mut admin = AdminServiceClient::new(conn.channel.clone());
    let role = |name: &str, actions: &[&str], inherits: &[&str]| Role {
        name: name.into(),
        privileges: vec![Privilege {
            resource: "cluster".into(),
            actions: actions.iter().map(|a| (*a).to_owned()).collect(),
        }],
        inherits: inherits.iter().map(|a| (*a).to_owned()).collect(),
        built_in: false,
    };
    admin
        .create_role(authed(
            CreateRoleRequest {
                role: Some(role("auditor", &["cluster_view"], &[])),
            },
            &token,
        ))
        .await
        .unwrap();
    admin
        .create_role(authed(
            CreateRoleRequest {
                role: Some(role("lead", &["user_manage"], &["auditor"])),
            },
            &token,
        ))
        .await
        .unwrap();
    let e = admin
        .update_role(authed(
            rustegon_proto::v1::UpdateRoleRequest {
                role: Some(role("auditor", &["cluster_view"], &["lead"])),
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 1001, "inheritance cycle");
    for bad in [grant("node", "cluster"), grant("nope", "")] {
        let e = admin
            .create_user(authed(
                CreateUserRequest {
                    name: "carol".into(),
                    password: Some(OTHER_PASSWORD.into()),
                    roles: vec![bad],
                    ..CreateUserRequest::default()
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert!(matches!(code_of(&e), 1001 | 1030), "{e:?}");
    }
    create_user(
        &h,
        token.trim_start_matches("Bearer "),
        "carol",
        Some(OTHER_PASSWORD),
        vec![grant("lead", "")],
    )
    .await;
    let carol = bearer(
        &conn
            .login("carol", OTHER_PASSWORD, Binding::Plus)
            .await
            .unwrap()
            .session_token,
    );
    // `lead` grants user_manage, inherited `auditor` grants cluster_view.
    admin
        .list_users(authed(ListUsersRequest {}, &carol))
        .await
        .unwrap();
    admin
        .get_settings(authed(GetSettingsRequest { names: vec![] }, &carol))
        .await
        .unwrap();
    let e = admin
        .update_settings(authed(
            UpdateSettingsRequest {
                values: HashMap::from([("auth.scram_iterations".to_owned(), "150000".to_owned())]),
            },
            &carol,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4002);
    admin
        .drop_user(authed(
            DropUserRequest {
                name: "carol".into(),
            },
            &token,
        ))
        .await
        .unwrap();
    let e = admin
        .list_users(authed(ListUsersRequest {}, &carol))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4005);
    h.stop().await;
}

/// Settings as TOML text (PD-045): runtime update validated atomically, static settings
/// refused, the override persisted in the system keyspace and applied after a reopen.
#[tokio::test]
async fn fr_sec_001_runtime_settings_update_and_persist() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let token = bearer(&conn.admin_token().await);
    let mut admin = AdminServiceClient::new(conn.channel.clone());
    let update = |pairs: &[(&str, &str)]| UpdateSettingsRequest {
        values: pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    };
    for bad in [
        update(&[("lockout.max_failures", "3")]),
        update(&[("auth.scram_iterations", "5")]),
        update(&[("auth.scram_iterations", "200000"), ("auth.nope", "1")]),
    ] {
        let e = admin
            .update_settings(authed(bad, &token))
            .await
            .unwrap_err();
        assert!(matches!(code_of(&e), 1001 | 1030), "{e:?}");
    }
    let changed = admin
        .update_settings(authed(
            update(&[("auth.scram_iterations", "200000")]),
            &token,
        ))
        .await
        .unwrap()
        .into_inner()
        .settings;
    assert_eq!(changed.len(), 1);
    assert_eq!(
        (changed[0].value.as_str(), changed[0].default_value.as_str()),
        ("200000", "600000")
    );
    assert_eq!(h.security.authn_settings().scram_iterations, 200_000);
    let all = admin
        .get_settings(authed(GetSettingsRequest { names: vec![] }, &token))
        .await
        .unwrap()
        .into_inner()
        .settings;
    let lockout = all
        .iter()
        .find(|s| s.name == "lockout.max_failures")
        .unwrap();
    assert!(!lockout.runtime_mutable);
    // Reopen the security layer over the same engine: the override persisted.
    let clock: std::sync::Arc<dyn rustegon_sim_api::Clock> = h.clock.clone();
    let deps = ServiceDeps {
        executor: Executor::new(std::sync::Arc::clone(&clock), 2),
        clock,
        rng: std::sync::Arc::new(OsRng),
    };
    let reopened = open_security(&h.engine, &h.data_dir.join("reopened"), base_flags(), &deps);
    assert_eq!(reopened.authn_settings().scram_iterations, 200_000);
    assert!(h.audited("settings_change", "success"));
    h.stop().await;
}

/// TC-SEC-004: the events of a session's life are audited, the chain verifies, and neither
/// passwords nor tokens reach the log.
#[tokio::test]
async fn tc_sec_004_audit_events_are_written_chained_and_free_of_secrets() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let ok = conn
        .login(ADMIN, ADMIN_PASSWORD, Binding::Plus)
        .await
        .unwrap();
    let token = bearer(&ok.session_token);
    conn.login(ADMIN, OTHER_PASSWORD, Binding::Plus)
        .await
        .unwrap_err();
    create_user(&h, &ok.session_token, "dave", Some(OTHER_PASSWORD), vec![]).await;
    let dave = bearer(
        &conn
            .login("dave", OTHER_PASSWORD, Binding::Plus)
            .await
            .unwrap()
            .session_token,
    );
    let mut admin = AdminServiceClient::new(conn.channel.clone());
    admin
        .list_users(authed(ListUsersRequest {}, &dave))
        .await
        .unwrap_err();
    let key = admin
        .create_api_key(authed(
            CreateApiKeyRequest {
                user: None,
                description: "k".into(),
                roles: vec![grant("root", "cluster")],
                expires_at_unix_ms: None,
                ip_allowlist: vec![],
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    AuthServiceClient::new(conn.channel.clone())
        .logout(authed(LogoutRequest {}, &token))
        .await
        .unwrap();

    let report = verify_dir(&StdFileSystem, &h.audit_dir()).unwrap();
    assert!(report.records >= 7, "{report:?}");
    let lines = h.audit_lines();
    for event in [
        ("login_success", "success"),
        ("login_failure", "failure"),
        ("user_change", "success"),
        ("privilege_denied", "denied"),
        ("api_key_change", "success"),
        ("logout", "success"),
    ] {
        assert!(h.audited(event.0, event.1), "missing {event:?}");
    }
    let denied = lines
        .iter()
        .find(|l| l["event"] == "privilege_denied")
        .unwrap();
    assert_eq!(denied["user"], "dave");
    assert_eq!(denied["action"], "user_manage");
    assert_eq!(denied["source_ip"], "127.0.0.1");
    let raw: String = std::fs::read_dir(h.audit_dir())
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    for secret_text in [
        ADMIN_PASSWORD,
        OTHER_PASSWORD,
        ok.session_token.as_str(),
        key.secret.as_str(),
    ] {
        assert!(
            !raw.contains(secret_text),
            "secret leaked into the audit log"
        );
    }
    h.stop().await;
}
