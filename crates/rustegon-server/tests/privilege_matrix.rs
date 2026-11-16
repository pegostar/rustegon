// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-SEC-001 privilege matrix over the real gRPC and REST endpoints (security.md §3.3, §11;
//! implementation-rules.md §8; PD-051, PD-055).
//!
//! The matrix is generated from the service definitions: every RPC this node serves
//! (`grpc::served_rpcs`, i.e. the registered services filtered from `security::RPC_ACCESS`) is
//! called with an empty request message by
//! - an anonymous caller: RGN-4001 unless the rule is `Anonymous`;
//! - an authenticated user without roles: RGN-4002 for cluster-level privileges (audited as
//!   `privilege_denied`), never RGN-4001/4002 for self-service rules;
//! - a user holding exactly the required actions: never RGN-4001/4002 (the empty request may
//!   still fail validation, `NotFound`, …).
//!
//! The REST matrix (`tc_sec_001_privilege_matrix_over_rest_endpoints`) is generated the same
//! way from `rest::REST_ENDPOINTS`: every endpoint is called with a request that decodes (so
//! authorization, not validation, decides), with the access rule of the RPC it maps to.
//!
//! **Extending it (lane G and later):** registering a service in `grpc::server::routes` and
//! `grpc::gate` makes its RPCs appear here automatically. Database/collection-level rules are
//! checked by the handlers with the request's resource, so an empty request may be rejected
//! before (RGN-1001); list such RPCs in [`expectation`] with the outcome an empty request must
//! produce, or extend [`request_bytes`]-style fixtures when a richer request is needed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use axum::body::{Body, to_bytes};
use common::{Binding, Conn, Harness, OTHER_PASSWORD, authed, base_flags, bearer, code_of};
use http::Request;
use rustegon_proto::v1::{
    CreateRoleRequest, CreateUserRequest, Privilege, Role, RoleGrant,
    admin_service_client::AdminServiceClient,
};
use rustegon_security::rbac::{Action, ResourceKind};
use rustegon_server::{
    grpc::served_rpcs,
    rest::{REST_ENDPOINTS, RestEndpoint, router},
    security::{Access, RpcAccess, access_of},
};
use serde_json::{Value as Json, json};
use tower::ServiceExt;

/// What a call must produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// RGN-4001.
    Unauthenticated,
    /// RGN-4002.
    Denied,
    /// Anything but RGN-4001/4002 (the call passed authorization).
    Allowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Who {
    Anonymous,
    Nobody,
    Holder,
}

/// Per-RPC outcomes of an empty request that differ from the rule's generic expectation.
fn expectation(rpc: &RpcAccess, who: Who) -> Expect {
    match (rpc.method, who) {
        // An empty `name` is not the caller: `user_manage` is required.
        ("/rustegon.v1.AdminService/GetUser", Who::Nobody) => return Expect::Denied,
        // A wrong (empty) current password is RGN-4001 by design (same as a failed login).
        ("/rustegon.v1.AdminService/ChangePassword", Who::Nobody | Who::Holder) => {
            return Expect::Unauthenticated;
        }
        // Data plane (lane G, PD-053): these requests are rejected while decoding (a required
        // field — id, document, definition, validator — is missing; or no documents to insert)
        // before the handler can name the resource to check.
        (
            "/rustegon.v1.DocumentService/Get"
            | "/rustegon.v1.DocumentService/Insert"
            | "/rustegon.v1.DocumentService/Replace"
            | "/rustegon.v1.DocumentService/Update"
            | "/rustegon.v1.DocumentService/Upsert"
            | "/rustegon.v1.DocumentService/Delete"
            | "/rustegon.v1.SchemaService/CreateIndex"
            | "/rustegon.v1.SchemaService/SetValidator",
            Who::Nobody,
        ) => return Expect::Allowed,
        _ => {}
    }
    match (rpc.access, who) {
        (Access::Anonymous, _) => Expect::Allowed,
        (_, Who::Anonymous) => Expect::Unauthenticated,
        (Access::Privilege(_, ResourceKind::Cluster), Who::Nobody) => Expect::Denied,
        // Database/collection privileges are checked by the handlers on the (empty) resource
        // the request names: a principal without roles is denied (lane G).
        (Access::Privilege(_, ResourceKind::Collection | ResourceKind::Database), Who::Nobody) => {
            Expect::Denied
        }
        _ => Expect::Allowed,
    }
}

fn outcome(result: &Result<(), tonic::Status>) -> Expect {
    match result {
        Err(s) if code_of(s) == 4001 => Expect::Unauthenticated,
        Err(s) if code_of(s) == 4002 => Expect::Denied,
        _ => Expect::Allowed,
    }
}

/// The actions a holder needs for `rpc` (on `cluster`).
fn required(rpc: &RpcAccess) -> Vec<Action> {
    match rpc.access {
        Access::Privilege(actions, _) => actions.to_vec(),
        Access::SelfOr(action) => vec![action],
        _ => Vec::new(),
    }
}

/// A user holding exactly `actions` on `cluster` through a custom role; returns its token.
async fn holder(h: &Harness, conn: &Conn, admin: &str, actions: &[Action]) -> String {
    let name = if actions.is_empty() {
        "nobody".to_owned()
    } else {
        format!(
            "holder-{}",
            actions
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join("-")
        )
        .replace('_', "-")
    };
    let mut client = AdminServiceClient::new(conn.channel.clone());
    let mut roles = Vec::new();
    if !actions.is_empty() {
        let role = format!("r-{name}");
        client
            .create_role(authed(
                CreateRoleRequest {
                    role: Some(Role {
                        name: role.clone(),
                        privileges: vec![Privilege {
                            resource: "cluster".into(),
                            actions: actions.iter().map(|a| a.as_str().to_owned()).collect(),
                        }],
                        inherits: vec![],
                        built_in: false,
                    }),
                },
                admin,
            ))
            .await
            .unwrap();
        roles.push(RoleGrant {
            role,
            resource: String::new(),
        });
    }
    client
        .create_user(authed(
            CreateUserRequest {
                name: name.clone(),
                password: Some(OTHER_PASSWORD.into()),
                roles,
                ..CreateUserRequest::default()
            },
            admin,
        ))
        .await
        .unwrap();
    let _ = h;
    bearer(
        &conn
            .login(&name, OTHER_PASSWORD, Binding::Plus)
            .await
            .unwrap()
            .session_token,
    )
}

#[tokio::test]
async fn tc_sec_001_privilege_matrix_over_grpc_endpoints() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let admin = bearer(&conn.admin_token().await);
    let mut rpcs: Vec<&RpcAccess> = served_rpcs(&h.services)
        .into_iter()
        // A bidirectional stream; covered by the authentication tests (anonymous by rule).
        .filter(|r| !r.method.ends_with("/Authenticate"))
        .collect();
    // Logout revokes the caller's session: run it last.
    rpcs.sort_by_key(|r| r.method.ends_with("/Logout"));
    let served: BTreeSet<&str> = rpcs.iter().map(|r| r.service()).collect();
    assert!(served.contains("rustegon.v1.AdminService"));
    assert!(served.contains("rustegon.v1.AuthService"));
    assert!(served.contains("rustegon.v1.SessionService"));

    let nobody = holder(&h, &conn, &admin, &[]).await;
    let mut holders: BTreeMap<Vec<Action>, String> = BTreeMap::new();
    holders.insert(Vec::new(), nobody.clone());
    let mut checked = 0;
    let mut denials = 0;
    for rpc in &rpcs {
        let actions = required(rpc);
        if !holders.contains_key(&actions) {
            let token = holder(&h, &conn, &admin, &actions).await;
            holders.insert(actions.clone(), token);
        }
        let holder_token = holders[&actions].clone();
        for (who, auth) in [
            (Who::Anonymous, None),
            (Who::Nobody, Some(nobody.as_str())),
            (Who::Holder, Some(holder_token.as_str())),
        ] {
            let result = conn.raw_call(rpc.method, auth).await;
            let want = expectation(rpc, who);
            assert_eq!(
                outcome(&result),
                want,
                "{} as {who:?}: {result:?}",
                rpc.method
            );
            if want == Expect::Denied {
                denials += 1;
            }
            checked += 1;
        }
    }
    assert!(checked >= 3 * 20, "{checked} cells");
    let audited = h
        .audit_lines()
        .iter()
        .filter(|l| l["event"] == "privilege_denied")
        .count();
    assert!(audited >= denials, "{audited} audited < {denials} denials");
    h.stop().await;
}

// ---------------------------------------------------------------------------------------------
// REST
// ---------------------------------------------------------------------------------------------

/// A body each REST endpoint decodes, so that the outcome is decided by authorization.
fn rest_body(ep: &RestEndpoint) -> Option<Json> {
    if matches!(ep.method, "GET" | "DELETE") {
        return None;
    }
    let mut index =
        serde_json::to_value(rustegon_query::parse_statement("CREATE INDEX i ON x (a)").unwrap())
            .unwrap();
    index.as_object_mut().unwrap().remove("kind");
    let set_op =
        serde_json::to_value(rustegon_query::parse_statement("UPDATE x SET a = 1").unwrap())
            .unwrap()["ops"]
            .clone();
    Some(match (ep.method, ep.path) {
        ("POST", "/api/v1/databases" | "/api/v1/databases/{db}/collections") => {
            json!({"name": "x"})
        }
        ("POST", "/api/v1/databases/{db}/collections/{coll}/indexes") => {
            json!({"definition": index})
        }
        ("PUT", "/api/v1/databases/{db}/collections/{coll}/validator") => {
            json!({"definition": {"$jsonSchema": {}}})
        }
        ("POST", "/api/v1/databases/{db}/collections/{coll}/documents") => {
            json!({"documents": [{}]})
        }
        ("PATCH", "/api/v1/databases/{db}/collections/{coll}/documents/{id}") => {
            json!({"operations": set_op})
        }
        ("POST", "/api/v1/databases/{db}/collections/{coll}/get-many") => json!({"ids": [1]}),
        ("POST", "/api/v1/databases/{db}/collections/{coll}/bulk") => {
            json!({"operations": [{"op": "insert", "document": {}}]})
        }
        ("POST", "/api/v1/databases/{db}/query" | "/api/v1/databases/{db}/explain") => {
            json!({"rgql": "FROM x"})
        }
        ("POST", "/api/v1/users" | "/api/v1/roles") => json!({"name": "x"}),
        ("PATCH", "/api/v1/settings") => json!({"values": {}}),
        ("POST", "/api/v1/auth/password") => {
            json!({"currentPassword": "wrong", "newPassword": OTHER_PASSWORD})
        }
        // Everything else takes `{}` (optional fields only, or a login with a missing field:
        // anonymous by rule, so any outcome but 4001/4002 is right).
        _ => json!({}),
    })
}

/// The actions a REST holder needs (statements are reads of collection `x.x`).
fn rest_required(rule: &RpcAccess) -> Vec<Action> {
    match rule.access {
        Access::Statement => vec![Action::Find],
        _ => required(rule),
    }
}

fn rest_expectation(ep: &RestEndpoint, rule: &RpcAccess, who: Who) -> Expect {
    match (ep.method, ep.path, who) {
        // A wrong current password is RGN-4001 by design (same as a failed login).
        ("POST", "/api/v1/auth/password", Who::Nobody | Who::Holder) => {
            return Expect::Unauthenticated;
        }
        // Another user's record needs `user_manage`.
        ("GET", "/api/v1/users/{name}", Who::Nobody) => return Expect::Denied,
        _ => {}
    }
    match (rule.access, who) {
        (Access::Anonymous, _) => Expect::Allowed,
        (_, Who::Anonymous) => Expect::Unauthenticated,
        // Cluster rules at the gate; database/collection rules and statements by the service
        // on the resource the path names (`x`, `x.x`).
        (Access::Privilege(..) | Access::Statement, Who::Nobody) => Expect::Denied,
        _ => Expect::Allowed,
    }
}

/// Calls `ep` with `{name}` path parameters set to `x`; returns the RGN code (0 = success).
async fn rest_call(app: &axum::Router, ep: &RestEndpoint, authorization: Option<&str>) -> u64 {
    let path = ep
        .path
        .split('/')
        .map(|seg| if seg.starts_with('{') { "x" } else { seg })
        .collect::<Vec<_>>()
        .join("/");
    let mut b = Request::builder().method(ep.method).uri(path);
    if let Some(a) = authorization {
        b = b.header("authorization", a);
    }
    let request = match rest_body(ep) {
        Some(body) => b
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice::<Json>(&bytes)
        .ok()
        .and_then(|j| j["error"]["code"].as_u64())
        .unwrap_or(0)
}

fn rest_outcome(code: u64) -> Expect {
    match code {
        4001 => Expect::Unauthenticated,
        4002 => Expect::Denied,
        _ => Expect::Allowed,
    }
}

#[tokio::test]
async fn tc_sec_001_privilege_matrix_over_rest_endpoints() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let admin = bearer(&conn.admin_token().await);
    let app = router(&h.services, 64 << 20);
    let mut endpoints: Vec<&RestEndpoint> =
        REST_ENDPOINTS.iter().filter(|e| e.rpc.is_some()).collect();
    // Logout revokes the caller's session, a wrong current password counts towards lockout:
    // run them last.
    endpoints.sort_by_key(|e| match e.path {
        "/api/v1/auth/logout" => 2,
        "/api/v1/auth/password" => 1,
        _ => 0,
    });
    assert!(endpoints.len() >= 55, "{} endpoints", endpoints.len());

    let nobody = holder(&h, &conn, &admin, &[]).await;
    let mut holders: BTreeMap<Vec<Action>, String> = BTreeMap::new();
    holders.insert(Vec::new(), nobody.clone());
    let mut checked = 0;
    let mut denials = 0;
    for ep in &endpoints {
        let rpc = ep.rpc.unwrap();
        let rule = access_of(rpc).unwrap_or_else(|| panic!("{rpc} has no rule"));
        let actions = rest_required(rule);
        if !holders.contains_key(&actions) {
            let token = holder(&h, &conn, &admin, &actions).await;
            holders.insert(actions.clone(), token);
        }
        let holder_token = holders[&actions].clone();
        for (who, auth) in [
            (Who::Anonymous, None),
            (Who::Nobody, Some(nobody.as_str())),
            (Who::Holder, Some(holder_token.as_str())),
        ] {
            let code = rest_call(&app, ep, auth).await;
            let want = rest_expectation(ep, rule, who);
            assert_eq!(
                rest_outcome(code),
                want,
                "{} {} as {who:?}: RGN-{code}",
                ep.method,
                ep.path
            );
            if want == Expect::Denied {
                denials += 1;
            }
            checked += 1;
        }
    }
    assert!(checked >= 3 * 55, "{checked} cells");
    let audited = h
        .audit_lines()
        .iter()
        .filter(|l| l["event"] == "privilege_denied")
        .count();
    assert!(audited >= denials, "{audited} audited < {denials} denials");
    h.stop().await;
}
