// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST endpoints of every served service against their gRPC counterparts (TC-API-006,
//! FR-API-002, FR-API-003, FR-SEC-001; PD-055).
//!
//! One node (`tests/common` harness: TLS gRPC listener, security layer, data plane over a real
//! `EmbeddedDb`) is driven through both front ends: gRPC over TLS and the REST router called
//! in-process over the same `Services`. For each service the same operation through both
//! channels must give equal results and equal error codes; the cookie + CSRF scheme, the
//! two-call SCRAM login and the REST-specific conventions (`If-Match`/`ETag`, paging,
//! default query deadline) are checked on the way.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::assert_is_empty
)]

mod common;

use axum::{
    Router,
    body::{Body, to_bytes},
};
use common::{ADMIN, ADMIN_PASSWORD, Harness, OTHER_PASSWORD, authed, base_flags, bearer, code_of};
use http::{HeaderMap, Method, Request, StatusCode};
use rustegon_doc::{
    Document, Value,
    json::{JsonMode, parse_document, parse_value, to_json},
    rdoc,
};
use rustegon_proto::v1::{
    self as pb, admin_service_client::AdminServiceClient, auth_service_client::AuthServiceClient,
    document_service_client::DocumentServiceClient, query_service_client::QueryServiceClient,
    schema_service_client::SchemaServiceClient,
    transaction_service_client::TransactionServiceClient,
};
use rustegon_query::parse_statement;
use rustegon_security::authn::{
    scram::{ClientBinding, ScramClient},
    secret,
};
use rustegon_server::rest::{CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, csrf_token, router};
use rustegon_sim_api::OsRng;
use serde_json::{Value as Json, json};
use tonic::transport::Channel;
use tower::ServiceExt;

const LIMIT: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// A REST response.
#[derive(Debug)]
struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Json,
}

impl Resp {
    /// The Rustegon error code (0 for a success).
    fn code(&self) -> u64 {
        self.body["error"]["code"].as_u64().unwrap_or(0)
    }

    #[track_caller]
    fn ok(self) -> Self {
        assert_eq!(self.status, StatusCode::OK, "{:?}", self.body);
        self
    }

    fn cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }
}

/// The REST router of the harness node, called in-process.
struct Api {
    router: Router,
}

/// Credentials of a REST call.
#[derive(Debug, Clone, Default)]
struct Auth {
    authorization: Option<String>,
    cookie: Option<String>,
    csrf: Option<String>,
    extra: Vec<(&'static str, String)>,
}

impl Auth {
    fn bearer(token: &str) -> Self {
        Self {
            authorization: Some(bearer(token)),
            ..Self::default()
        }
    }

    fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.extra.push((name, value.into()));
        self
    }
}

impl Api {
    fn new(h: &Harness) -> Self {
        Self {
            router: router(&h.services, LIMIT),
        }
    }

    async fn call(&self, method: Method, path: &str, auth: &Auth, body: Option<Json>) -> Resp {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(a) = &auth.authorization {
            b = b.header("authorization", a);
        }
        if let Some(c) = &auth.cookie {
            b = b.header("cookie", format!("{SESSION_COOKIE}={c}"));
        }
        if let Some(c) = &auth.csrf {
            b = b.header(CSRF_HEADER, c);
        }
        for (k, v) in &auth.extra {
            b = b.header(*k, v);
        }
        let request = match body {
            Some(j) => b
                .header("content-type", "application/json")
                .body(Body::from(j.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), LIMIT).await.unwrap();
        let body = if bytes.is_empty() {
            Json::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        Resp {
            status,
            headers,
            body,
        }
    }

    async fn get(&self, path: &str, auth: &Auth) -> Resp {
        self.call(Method::GET, path, auth, None).await
    }

    async fn post(&self, path: &str, auth: &Auth, body: Json) -> Resp {
        self.call(Method::POST, path, auth, Some(body)).await
    }

    /// The two-call SCRAM login; verifies the server signature. Returns the finish response.
    async fn scram_login(&self, user: &str, password: &str, delivery: &str) -> Resp {
        let (client, _, first) =
            ScramClient::new(user, &secret(password), ClientBinding::Unsupported, &OsRng);
        let start = self
            .post(
                "/api/v1/auth/scram/start",
                &Auth::default(),
                json!({"clientFirst": first, "delivery": delivery,
                       "clientInfo": {"driverName": "rest-test", "application": "tests"}}),
            )
            .await;
        if start.status != StatusCode::OK {
            return start;
        }
        let server_first = start.body["serverFirst"].as_str().unwrap().to_owned();
        let handshake = start.body["handshakeId"].as_str().unwrap().to_owned();
        let (fin, client_final) =
            tokio::task::spawn_blocking(move || client.server_first(&server_first).unwrap())
                .await
                .unwrap();
        let done = self
            .post(
                "/api/v1/auth/scram/finish",
                &Auth::default(),
                json!({"handshakeId": handshake, "clientFinal": client_final}),
            )
            .await;
        if done.status == StatusCode::OK {
            fin.server_final(done.body["serverFinal"].as_str().unwrap())
                .expect("server signature verifies");
        }
        done
    }

    /// A REST session token of `user`.
    async fn token(&self, user: &str, password: &str) -> String {
        self.scram_login(user, password, "token").await.ok().body["sessionToken"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

/// The value of cookie `name` in the `Set-Cookie` headers.
fn set_cookie<'a>(cookies: &'a [String], name: &str) -> &'a str {
    cookies
        .iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} cookie in {cookies:?}"))
}

fn cookie_value(set_cookie: &str) -> &str {
    set_cookie
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
}

/// gRPC request with `authorization: Bearer <token>`.
fn g<T>(message: T, token: &str) -> tonic::Request<T> {
    authed(message, &bearer(token))
}

fn pdoc(d: &Document) -> pb::Document {
    pb::Document {
        rdoc: rdoc::encode(d).unwrap(),
    }
}

fn pval(v: &Value) -> pb::Value {
    pb::Value {
        rdoc_value: rdoc::encode_value(v).unwrap(),
    }
}

/// A document from a parsed JSON body. `serde_json::Value` (without `preserve_order`) sorts
/// object keys, so documents compared across channels are normalized through it ([`norm`]).
fn jdoc(j: &Json) -> Document {
    parse_document(&j.to_string()).unwrap()
}

/// `d` with its fields in the order a parsed JSON body has them (sorted).
fn norm(d: &Document) -> Document {
    jdoc(&serde_json::from_str(&to_json(d, JsonMode::Canonical)).unwrap())
}

/// A gRPC document, normalized for comparison with REST bodies.
fn grpc_doc(d: &pb::Document) -> Document {
    norm(&rdoc::decode(&d.rdoc).unwrap())
}

/// Update operators of `UPDATE items <ops>` in the structured JSON form.
fn ops_json(ops: &str) -> Json {
    let stmt = parse_statement(&format!("UPDATE items {ops}")).unwrap();
    serde_json::to_value(&stmt).unwrap()["ops"].clone()
}

struct Grpc {
    channel: Channel,
}

impl Grpc {
    fn admin(&self) -> AdminServiceClient<Channel> {
        AdminServiceClient::new(self.channel.clone())
    }
    fn auth(&self) -> AuthServiceClient<Channel> {
        AuthServiceClient::new(self.channel.clone())
    }
    fn doc(&self) -> DocumentServiceClient<Channel> {
        DocumentServiceClient::new(self.channel.clone())
    }
    fn query(&self) -> QueryServiceClient<Channel> {
        QueryServiceClient::new(self.channel.clone())
    }
    fn schema(&self) -> SchemaServiceClient<Channel> {
        SchemaServiceClient::new(self.channel.clone())
    }
    fn txn(&self) -> TransactionServiceClient<Channel> {
        TransactionServiceClient::new(self.channel.clone())
    }
}

async fn node() -> (Harness, Api, Grpc, String) {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let admin = conn.admin_token().await;
    let api = Api::new(&h);
    let grpc = Grpc {
        channel: conn.channel,
    };
    (h, api, grpc, admin)
}

// ---------------------------------------------------------------------------------------------
// Authentication, cookies and CSRF
// ---------------------------------------------------------------------------------------------

/// FR-SEC-001, TC-SEC-008, TC-API-006: the REST SCRAM login yields sessions both channels
/// accept; cookie delivery sets the GUI cookies, CSRF guards state-changing cookie requests,
/// `Authorization` wins over the cookie, logout revokes and clears.
#[tokio::test]
async fn tc_api_006_rest_login_cookies_csrf_and_logout() {
    let (h, api, grpc, admin) = node().await;

    // Token delivery: a session usable on gRPC, no cookies.
    let done = api.scram_login(ADMIN, ADMIN_PASSWORD, "token").await.ok();
    assert!(done.cookies().is_empty());
    assert!(done.body.get("csrfToken").is_none());
    assert_eq!(done.body["user"], ADMIN);
    let token = done.body["sessionToken"].as_str().unwrap().to_owned();
    let who = grpc
        .auth()
        .who_am_i(g(pb::WhoAmIRequest {}, &token))
        .await
        .unwrap()
        .into_inner();
    let me = api.get("/api/v1/auth/me", &Auth::bearer(&token)).await.ok();
    assert_eq!(me.body["user"], who.user);
    assert_eq!(me.body["mechanism"], "scram");
    assert_eq!(who.mechanism, pb::AuthMechanism::ScramSha256 as i32);
    let rest_roles: Vec<(String, String)> = me.body["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["role"].as_str().unwrap().to_owned(),
                r["resource"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let grpc_roles: Vec<(String, String)> = who
        .roles
        .iter()
        .map(|r| (r.role.clone(), r.resource.clone()))
        .collect();
    assert_eq!(rest_roles, grpc_roles);
    // And the gRPC session works on REST.
    let me = api.get("/api/v1/auth/me", &Auth::bearer(&admin)).await.ok();
    assert_eq!(me.body["user"], ADMIN);

    // Cookie delivery: HttpOnly session cookie, readable CSRF cookie, CSRF token in the body,
    // no session token in the body.
    let done = api.scram_login(ADMIN, ADMIN_PASSWORD, "cookie").await.ok();
    assert!(done.body.get("sessionToken").is_none());
    let cookies = done.cookies();
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    let session = set_cookie(&cookies, SESSION_COOKIE);
    let csrf_cookie = set_cookie(&cookies, CSRF_COOKIE);
    for attr in ["Path=/", "Secure", "SameSite=Strict", "Max-Age="] {
        assert!(session.contains(attr), "{session}");
        assert!(csrf_cookie.contains(attr), "{csrf_cookie}");
    }
    assert!(session.contains("HttpOnly"));
    assert!(!csrf_cookie.contains("HttpOnly"));
    let cookie_token = cookie_value(session).to_owned();
    let csrf = cookie_value(csrf_cookie).to_owned();
    assert_eq!(csrf, csrf_token(&cookie_token));
    assert_eq!(done.body["csrfToken"], csrf.as_str());

    let by_cookie = Auth {
        cookie: Some(cookie_token.clone()),
        ..Auth::default()
    };
    let me = api.get("/api/v1/auth/me", &by_cookie).await.ok();
    assert_eq!(me.body["user"], ADMIN);

    // State-changing cookie requests need the CSRF token (RGN-4002 reason csrf).
    let create = json!({"name": "csrfdb"});
    let r = api
        .post("/api/v1/databases", &by_cookie, create.clone())
        .await;
    assert_eq!((r.status, r.code()), (StatusCode::FORBIDDEN, 4002));
    assert_eq!(r.body["error"]["details"]["reason"], "csrf");
    let wrong = Auth {
        csrf: Some(csrf_token("another session")),
        ..by_cookie.clone()
    };
    let r = api.post("/api/v1/databases", &wrong, create.clone()).await;
    assert_eq!(r.code(), 4002);
    let with_csrf = Auth {
        csrf: Some(csrf.clone()),
        ..by_cookie.clone()
    };
    let r = api.post("/api/v1/databases", &with_csrf, create).await.ok();
    assert_eq!(r.body["created"], true);

    // `Authorization` wins over the cookie and needs no CSRF token.
    let r = api
        .post(
            "/api/v1/users",
            &Auth::bearer(&admin),
            json!({"name": "bob", "password": OTHER_PASSWORD}),
        )
        .await
        .ok();
    assert_eq!(r.body["user"]["name"], "bob");
    let bob = api.token("bob", OTHER_PASSWORD).await;
    let both = Auth {
        authorization: Some(bearer(&bob)),
        cookie: Some(cookie_token.clone()),
        ..Auth::default()
    };
    assert_eq!(
        api.get("/api/v1/auth/me", &both).await.ok().body["user"],
        "bob"
    );
    let r = api
        .post("/api/v1/transactions", &both, json!({}))
        .await
        .ok();
    assert!(r.body["txnId"].is_string());

    // Plain-password login; wrong passwords and broken handshakes are the uniform RGN-4001,
    // as on gRPC.
    let r = api
        .post(
            "/api/v1/auth/login",
            &Auth::default(),
            json!({"user": "bob", "password": OTHER_PASSWORD, "delivery": "token"}),
        )
        .await
        .ok();
    assert_eq!(r.body["user"], "bob");
    assert!(r.body.get("serverFinal").is_none());
    let r = api
        .post(
            "/api/v1/auth/login",
            &Auth::default(),
            json!({"user": "bob", "password": "not the password"}),
        )
        .await;
    assert_eq!((r.status, r.code()), (StatusCode::UNAUTHORIZED, 4001));
    assert!(r.cookies().is_empty());
    let conn = h.channel().await;
    let grpc_wrong = conn
        .login("bob", "not the password", common::Binding::Plus)
        .await
        .unwrap_err();
    assert_eq!(u64::from(code_of(&grpc_wrong)), r.code());
    let r = api
        .post(
            "/api/v1/auth/scram/finish",
            &Auth::default(),
            json!({"handshakeId": "00", "clientFinal": "c=biws,r=x,p=eA=="}),
        )
        .await;
    assert_eq!(r.code(), 4001);
    // A handshake id works once.
    let (_, _, first) = ScramClient::new(
        "bob",
        &secret(OTHER_PASSWORD),
        ClientBinding::Unsupported,
        &OsRng,
    );
    let start = api
        .post(
            "/api/v1/auth/scram/start",
            &Auth::default(),
            json!({"clientFirst": first}),
        )
        .await
        .ok();
    let id = start.body["handshakeId"].as_str().unwrap();
    for _ in 0..2 {
        let r = api
            .post(
                "/api/v1/auth/scram/finish",
                &Auth::default(),
                json!({"handshakeId": id, "clientFinal": "c=biws,r=x,p=eA=="}),
            )
            .await;
        assert_eq!(r.code(), 4001);
    }

    // Logout: revokes the session and clears both cookies.
    let r = api
        .call(Method::POST, "/api/v1/auth/logout", &with_csrf, None)
        .await
        .ok();
    let cleared = r.cookies();
    assert_eq!(cleared.len(), 2);
    assert!(cleared.iter().all(|c| c.contains("Max-Age=0")));
    let rest_dead = api.get("/api/v1/auth/me", &by_cookie).await;
    let grpc_dead = grpc
        .auth()
        .who_am_i(g(pb::WhoAmIRequest {}, &cookie_token))
        .await
        .unwrap_err();
    assert_eq!(rest_dead.code(), u64::from(code_of(&grpc_dead)));
    assert!(matches!(rest_dead.code(), 4001 | 4005), "{rest_dead:?}");
    // Logging out a dead session still clears the cookies; a CSRF failure does not.
    let r = api
        .call(Method::POST, "/api/v1/auth/logout", &with_csrf, None)
        .await;
    assert_eq!(r.code(), rest_dead.code());
    assert_eq!(r.cookies().len(), 2);
    let r = api
        .call(Method::POST, "/api/v1/auth/logout", &by_cookie, None)
        .await;
    assert_eq!(r.code(), 4002);
    assert!(r.cookies().is_empty());
    // A stale cookie does not prevent a new login.
    let r = api
        .post(
            "/api/v1/auth/login",
            &by_cookie,
            json!({"user": ADMIN, "password": ADMIN_PASSWORD}),
        )
        .await
        .ok();
    assert_eq!(r.cookies().len(), 2);

    h.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------------------------

/// TC-API-006 (AdminService): users, roles, API keys and settings give equal results and
/// errors on both channels.
#[tokio::test]
async fn tc_api_006_admin_parity() {
    let (h, api, grpc, admin) = node().await;
    let a = Auth::bearer(&admin);

    // Users.
    let r = api
        .post(
            "/api/v1/users",
            &a,
            json!({"name": "carol", "password": OTHER_PASSWORD,
                   "roles": [{"role": "read", "resource": "database:shop"}]}),
        )
        .await
        .ok();
    let user = &r.body["user"];
    let got = grpc
        .admin()
        .get_user(g(
            pb::GetUserRequest {
                name: "carol".into(),
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner()
        .user
        .unwrap();
    assert_eq!(user["name"], got.name);
    assert_eq!(user["roles"][0]["role"], got.roles[0].role);
    assert_eq!(user["roles"][0]["resource"], got.roles[0].resource);
    assert_eq!(user["disabled"], got.disabled);
    assert_eq!(user["createdAtUnixMs"], got.created_at_unix_ms);
    let rest_get = api.get("/api/v1/users/carol", &a).await.ok();
    assert_eq!(&rest_get.body["user"], user);
    // Duplicate: equal codes.
    let dup_rest = api
        .post(
            "/api/v1/users",
            &a,
            json!({"name": "carol", "password": OTHER_PASSWORD}),
        )
        .await;
    let dup_grpc = grpc
        .admin()
        .create_user(g(
            pb::CreateUserRequest {
                name: "carol".into(),
                password: Some(OTHER_PASSWORD.into()),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(dup_rest.code(), u64::from(code_of(&dup_grpc)));
    assert_eq!(dup_rest.status, StatusCode::CONFLICT);
    let names = |v: &Json| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|u| u["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let rest_users = names(&api.get("/api/v1/users", &a).await.ok().body["users"]);
    let grpc_users: Vec<String> = grpc
        .admin()
        .list_users(g(pb::ListUsersRequest {}, &admin))
        .await
        .unwrap()
        .into_inner()
        .users
        .into_iter()
        .map(|u| u.name)
        .collect();
    assert_eq!(rest_users, grpc_users);
    let r = api
        .call(
            Method::PATCH,
            "/api/v1/users/carol",
            &a,
            Some(json!({"disabled": true})),
        )
        .await
        .ok();
    assert_eq!(r.body["user"]["disabled"], true);

    // A user without roles is denied cluster administration on both channels.
    api.post(
        "/api/v1/users",
        &a,
        json!({"name": "dan", "password": OTHER_PASSWORD}),
    )
    .await
    .ok();
    let dan = api.token("dan", OTHER_PASSWORD).await;
    let rest_denied = api.get("/api/v1/users", &Auth::bearer(&dan)).await;
    let grpc_denied = grpc
        .admin()
        .list_users(g(pb::ListUsersRequest {}, &dan))
        .await
        .unwrap_err();
    assert_eq!(rest_denied.code(), 4002);
    assert_eq!(rest_denied.code(), u64::from(code_of(&grpc_denied)));
    // …but may read itself.
    api.get("/api/v1/users/dan", &Auth::bearer(&dan)).await.ok();

    // Roles.
    let role = json!({"name": "analyst",
                      "privileges": [{"resource": "database:shop", "actions": ["find"]}]});
    let r = api.post("/api/v1/roles", &a, role).await.ok();
    let got = grpc
        .admin()
        .get_role(g(
            pb::GetRoleRequest {
                name: "analyst".into(),
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner()
        .role
        .unwrap();
    assert_eq!(
        r.body["role"]["privileges"][0]["resource"],
        got.privileges[0].resource
    );
    assert_eq!(
        r.body["role"]["privileges"][0]["actions"][0],
        got.privileges[0].actions[0]
    );
    let r = api
        .call(
            Method::PATCH,
            "/api/v1/roles/analyst",
            &a,
            Some(json!({"privileges": [{"resource": "database:shop", "actions": ["find", "insert"]}]})),
        )
        .await
        .ok();
    assert_eq!(
        r.body["role"]["privileges"][0]["actions"],
        json!(["find", "insert"])
    );
    let all = api.get("/api/v1/roles", &a).await.ok();
    assert!(all.body["roles"].as_array().unwrap().len() > 1);
    api.call(Method::DELETE, "/api/v1/roles/analyst", &a, None)
        .await
        .ok();
    let rest_missing = api.get("/api/v1/roles/analyst", &a).await;
    let grpc_missing = grpc
        .admin()
        .get_role(g(
            pb::GetRoleRequest {
                name: "analyst".into(),
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(rest_missing.code(), u64::from(code_of(&grpc_missing)));
    assert_eq!(rest_missing.status, StatusCode::NOT_FOUND);

    // API keys: the secret is shown once and authenticates REST calls.
    let r = api
        .post(
            "/api/v1/api-keys",
            &a,
            json!({"description": "ci", "roles": [{"role": "root", "resource": "cluster"}]}),
        )
        .await
        .ok();
    let key_secret = r.body["secret"].as_str().unwrap().to_owned();
    let key_id = r.body["key"]["keyId"].as_str().unwrap().to_owned();
    assert!(key_secret.starts_with("rgn_"));
    let by_key = Auth {
        authorization: Some(format!("ApiKey {key_secret}")),
        ..Auth::default()
    };
    let me = api.get("/api/v1/auth/me", &by_key).await.ok();
    assert_eq!(me.body["mechanism"], "api_key");
    assert_eq!(me.body["apiKeyId"], key_id.as_str());
    let rest_keys = api.get("/api/v1/api-keys", &a).await.ok();
    let grpc_keys = grpc
        .admin()
        .list_api_keys(g(pb::ListApiKeysRequest { user: None }, &admin))
        .await
        .unwrap()
        .into_inner()
        .keys;
    assert_eq!(
        rest_keys.body["keys"].as_array().unwrap().len(),
        grpc_keys.len()
    );
    assert_eq!(rest_keys.body["keys"][0]["keyId"], grpc_keys[0].key_id);
    assert!(rest_keys.body["keys"][0].get("secret").is_none());
    api.call(
        Method::DELETE,
        &format!("/api/v1/api-keys/{key_id}"),
        &a,
        None,
    )
    .await
    .ok();
    assert_eq!(api.get("/api/v1/auth/me", &by_key).await.code(), 4001);

    // Settings.
    let r = api
        .get("/api/v1/settings?names=auth.scram_iterations", &a)
        .await
        .ok();
    let grpc_settings = grpc
        .admin()
        .get_settings(g(
            pb::GetSettingsRequest {
                names: vec!["auth.scram_iterations".into()],
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner()
        .settings;
    assert_eq!(r.body["settings"][0]["value"], grpc_settings[0].value);
    assert_eq!(
        r.body["settings"][0]["defaultValue"],
        grpc_settings[0].default_value
    );
    let rest_bad = api
        .call(
            Method::PATCH,
            "/api/v1/settings",
            &a,
            Some(json!({"values": {"no.such_setting": "1"}})),
        )
        .await;
    let grpc_bad = grpc
        .admin()
        .update_settings(g(
            pb::UpdateSettingsRequest {
                values: [("no.such_setting".to_owned(), "1".to_owned())].into(),
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_ne!(rest_bad.code(), 0);
    assert_eq!(rest_bad.code(), u64::from(code_of(&grpc_bad)));

    // Must-change-password: only the password endpoint until it is changed.
    api.post(
        "/api/v1/users",
        &a,
        json!({"name": "erin", "password": OTHER_PASSWORD, "mustChangePassword": true}),
    )
    .await
    .ok();
    let erin = api.scram_login("erin", OTHER_PASSWORD, "token").await.ok();
    assert_eq!(erin.body["mustChangePassword"], true);
    let erin = erin.body["sessionToken"].as_str().unwrap().to_owned();
    let rest_blocked = api.get("/api/v1/databases", &Auth::bearer(&erin)).await;
    let grpc_blocked = grpc
        .schema()
        .list_databases(g(pb::ListDatabasesRequest {}, &erin))
        .await
        .unwrap_err();
    assert_eq!(rest_blocked.code(), 4002);
    assert_eq!(
        rest_blocked.body["error"]["details"]["reason"],
        "password_change_required"
    );
    assert_eq!(rest_blocked.code(), u64::from(code_of(&grpc_blocked)));
    api.post(
        "/api/v1/auth/password",
        &Auth::bearer(&erin),
        json!({"currentPassword": OTHER_PASSWORD, "newPassword": "Nw4%pQ8!zL2#rT6x"}),
    )
    .await
    .ok();
    let erin = api.token("erin", "Nw4%pQ8!zL2#rT6x").await;
    api.get("/api/v1/databases", &Auth::bearer(&erin))
        .await
        .ok();

    // Drop.
    api.call(Method::DELETE, "/api/v1/users/carol", &a, None)
        .await
        .ok();
    assert_eq!(api.get("/api/v1/users/carol", &a).await.code(), 1030);
    h.stop().await;
}

/// FR-SEC-002, PD-145: the server refuses dropping or disabling the caller itself and taking
/// `root` from the last enabled user holding it (REST and gRPC share `AdminService`).
#[tokio::test]
async fn fr_sec_002_no_self_drop_and_last_root_kept() {
    let (h, api, _grpc, admin) = node().await;
    let a = Auth::bearer(&admin);
    let reason = |r: &Resp| r.body["error"]["details"]["reason"].clone();

    let r = api
        .call(Method::DELETE, "/api/v1/users/admin", &a, None)
        .await;
    assert_eq!(
        (r.code(), reason(&r)),
        (1001, json!("self")),
        "{:?}",
        r.body
    );
    let r = api
        .call(
            Method::PATCH,
            "/api/v1/users/admin",
            &a,
            Some(json!({"disabled": true})),
        )
        .await;
    assert_eq!(
        (r.code(), reason(&r)),
        (1001, json!("self")),
        "{:?}",
        r.body
    );

    // A user administrator may not take root away from the last holder.
    api.post(
        "/api/v1/users",
        &a,
        json!({"name": "ua", "password": OTHER_PASSWORD, "roles": [{"role": "user_admin"}]}),
    )
    .await
    .ok();
    let ua = Auth::bearer(&api.token("ua", OTHER_PASSWORD).await);
    for (method, body) in [
        (Method::DELETE, None),
        (Method::PATCH, Some(json!({"disabled": true}))),
        (
            Method::PATCH,
            Some(json!({"roles": [{"role": "user_admin"}]})),
        ),
    ] {
        let r = api.call(method, "/api/v1/users/admin", &ua, body).await;
        assert_eq!(
            (r.code(), reason(&r)),
            (1001, json!("last_root")),
            "{:?}",
            r.body
        );
    }
    // Other changes to the last holder still pass.
    api.call(
        Method::PATCH,
        "/api/v1/users/admin",
        &ua,
        Some(json!({"roles": [{"role": "root"}, {"role": "monitor"}]})),
    )
    .await
    .ok();

    // The roles PATCH above revoked admin's sessions, so `a` is gone (4005).
    let a = Auth::bearer(&api.token(ADMIN, ADMIN_PASSWORD).await);
    // With a second enabled root holder the first one can go.
    api.post(
        "/api/v1/users",
        &a,
        json!({"name": "root2", "password": OTHER_PASSWORD, "roles": [{"role": "root"}]}),
    )
    .await
    .ok();
    api.call(Method::DELETE, "/api/v1/users/admin", &ua, None)
        .await
        .ok();
    let r = api
        .call(Method::DELETE, "/api/v1/users/root2", &ua, None)
        .await;
    assert_eq!(
        (r.code(), reason(&r)),
        (1001, json!("last_root")),
        "{:?}",
        r.body
    );
    h.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Schema and documents
// ---------------------------------------------------------------------------------------------

/// TC-API-006 (SchemaService, DocumentService): databases, collections, validators, indexes
/// and every document operation through both channels; `If-Match`/`ETag` ↔ `if_rev`/`_rev`.
#[tokio::test]
async fn tc_api_006_schema_and_document_parity() {
    let (h, api, grpc, admin) = node().await;
    let a = Auth::bearer(&admin);
    let docs = "/api/v1/databases/shop/collections/items/documents";

    api.post("/api/v1/databases", &a, json!({"name": "shop"}))
        .await
        .ok();
    let r = api
        .post(
            "/api/v1/databases",
            &a,
            json!({"name": "shop", "ifNotExists": true}),
        )
        .await
        .ok();
    assert_eq!(r.body["created"], false);
    let rest_dup = api
        .post("/api/v1/databases", &a, json!({"name": "shop"}))
        .await;
    let grpc_dup = grpc
        .schema()
        .create_database(g(
            pb::CreateDatabaseRequest {
                name: "shop".into(),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(rest_dup.code(), u64::from(code_of(&grpc_dup)));
    let grpc_dbs: Vec<String> = grpc
        .schema()
        .list_databases(g(pb::ListDatabasesRequest {}, &admin))
        .await
        .unwrap()
        .into_inner()
        .databases
        .into_iter()
        .map(|d| d.name)
        .collect();
    let rest_dbs = api.get("/api/v1/databases", &a).await.ok();
    let rest_names: Vec<&str> = rest_dbs.body["databases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(rest_names, grpc_dbs);
    api.get("/api/v1/databases/shop", &a).await.ok();
    assert_eq!(api.get("/api/v1/databases/nope", &a).await.code(), 1030);

    // Collections and validators.
    api.post(
        "/api/v1/databases/shop/collections",
        &a,
        json!({"name": "items"}),
    )
    .await
    .ok();
    let rest_coll = api
        .get("/api/v1/databases/shop/collections/items", &a)
        .await
        .ok();
    let grpc_coll = grpc
        .schema()
        .get_collection(g(
            pb::GetCollectionRequest {
                database: "shop".into(),
                name: "items".into(),
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner()
        .collection
        .unwrap();
    assert_eq!(rest_coll.body["name"], grpc_coll.name);
    let validator = "/api/v1/databases/shop/collections/items/validator";
    api.call(
        Method::PUT,
        validator,
        &a,
        Some(json!({"definition": {"$jsonSchema": {"required": ["n"]}}, "level": "strict"})),
    )
    .await
    .ok();
    let rest_v = api.get(validator, &a).await.ok();
    let grpc_v = grpc
        .schema()
        .get_validator(g(
            pb::GetValidatorRequest {
                database: "shop".into(),
                collection: "items".into(),
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner()
        .validator
        .unwrap();
    assert_eq!(
        rest_v.body["validator"]["definition"],
        serde_json::from_str::<Json>(&grpc_v.definition_json).unwrap()
    );
    assert_eq!(rest_v.body["validator"]["level"], "strict");
    // The validator applies to REST writes like to gRPC ones.
    let rest_invalid = api
        .post(docs, &a, json!({"documents": [{"_id": 99}]}))
        .await;
    let grpc_invalid = grpc
        .doc()
        .insert(g(
            pb::InsertRequest {
                database: "shop".into(),
                collection: "items".into(),
                documents: vec![pdoc(&jdoc(&json!({"_id": 99})))],
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(rest_invalid.code(), 1006);
    assert_eq!(rest_invalid.code(), u64::from(code_of(&grpc_invalid)));
    let r = api.call(Method::DELETE, validator, &a, None).await.ok();
    assert_eq!(r.body["removed"], true);
    assert!(
        api.get(validator, &a)
            .await
            .ok()
            .body
            .get("validator")
            .is_none()
    );

    // Insert (REST) → Get (both).
    let r = api
        .post(
            docs,
            &a,
            json!({"documents": (1..=5).map(|i| json!({"_id": i, "n": i, "tag": if i % 2 == 0 {"even"} else {"odd"}})).collect::<Vec<_>>()}),
        )
        .await
        .ok();
    assert_eq!(r.body["results"].as_array().unwrap().len(), 5);
    assert_eq!(r.body["results"][0]["id"], 1);
    let rest_get = api.get(&format!("{docs}/1"), &a).await.ok();
    let rest_doc = jdoc(&rest_get.body["document"]);
    let grpc_get = grpc
        .doc()
        .get(g(
            pb::GetRequest {
                database: "shop".into(),
                collection: "items".into(),
                id: Some(pval(&Value::Int64(1))),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rest_doc, grpc_doc(grpc_get.document.as_ref().unwrap()));
    let Some(Value::String(rev1)) = rest_doc.get("_rev").cloned() else {
        panic!("no _rev");
    };
    assert_eq!(rest_get.headers["etag"], format!("\"{rev1}\"").as_str());
    assert_eq!(r.body["results"][0]["rev"], rev1.as_str());
    // Missing: REST 404, gRPC an empty response.
    let missing = api.get(&format!("{docs}/42"), &a).await;
    assert_eq!(
        (missing.status, missing.code()),
        (StatusCode::NOT_FOUND, 1030)
    );
    // A string id is quoted; a bare non-JSON segment is a string.
    assert_eq!(api.get(&format!("{docs}/%2242%22"), &a).await.code(), 1030);
    // Duplicate insert: equal codes.
    let rest_dup = api.post(docs, &a, json!({"documents": [{"_id": 1}]})).await;
    let grpc_dup = grpc
        .doc()
        .insert(g(
            pb::InsertRequest {
                database: "shop".into(),
                collection: "items".into(),
                documents: vec![pdoc(&jdoc(&json!({"_id": 1})))],
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(rest_dup.code(), 1005);
    assert_eq!(rest_dup.code(), u64::from(code_of(&grpc_dup)));

    // Replace with If-Match.
    let stale = Auth {
        extra: vec![("if-match", "\"stale-rev\"".to_owned())],
        ..a.clone()
    };
    let rest_stale = api
        .call(
            Method::PUT,
            &format!("{docs}/1"),
            &stale,
            Some(json!({"n": 10})),
        )
        .await;
    let grpc_stale = grpc
        .doc()
        .replace(g(
            pb::ReplaceRequest {
                database: "shop".into(),
                collection: "items".into(),
                id: Some(pval(&Value::Int64(1))),
                document: Some(pdoc(&jdoc(&json!({"_id": 1, "n": 10})))),
                if_rev: Some("stale-rev".into()),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(
        (rest_stale.status, rest_stale.code()),
        (StatusCode::PRECONDITION_FAILED, 2009)
    );
    assert_eq!(rest_stale.code(), u64::from(code_of(&grpc_stale)));
    let fresh = a.clone().header("if-match", format!("\"{rev1}\""));
    let r = api
        .call(
            Method::PUT,
            &format!("{docs}/1?returnDocument=after"),
            &fresh,
            Some(json!({"n": 10})),
        )
        .await
        .ok();
    assert_eq!(r.body["matched"], true);
    assert_eq!(r.body["document"]["n"], 10);
    let rev2 = r.body["result"]["rev"].as_str().unwrap().to_owned();
    assert_ne!(rev2, rev1);
    assert_eq!(r.headers["etag"], format!("\"{rev2}\"").as_str());
    let r = api
        .call(
            Method::PUT,
            &format!("{docs}/1"),
            &a,
            Some(json!({"_id": 2})),
        )
        .await;
    assert_eq!(r.code(), 1001);

    // Update (PATCH) ↔ gRPC Update.
    let r = api
        .call(
            Method::PATCH,
            &format!("{docs}/2?returnDocument=after"),
            &a,
            Some(json!({"operations": ops_json("SET n = n * 10")})),
        )
        .await
        .ok();
    assert_eq!(
        (r.body["matched"].clone(), r.body["modified"].clone()),
        (json!(true), json!(true))
    );
    assert_eq!(r.body["document"]["n"], 20);
    let grpc_after = grpc
        .doc()
        .get(g(
            pb::GetRequest {
                database: "shop".into(),
                collection: "items".into(),
                id: Some(pval(&Value::Int64(2))),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        grpc_doc(grpc_after.document.as_ref().unwrap()),
        jdoc(&r.body["document"])
    );
    let r = api
        .call(
            Method::PATCH,
            &format!("{docs}/2"),
            &a,
            Some(json!({"operations": [{"kind": "nonsense"}]})),
        )
        .await;
    assert_eq!(r.code(), 1010);

    // Upsert (PUT ?upsert=true), Delete.
    let r = api
        .call(
            Method::PUT,
            &format!("{docs}/9?upsert=true"),
            &a,
            Some(json!({"n": 9})),
        )
        .await
        .ok();
    assert_eq!(r.body["inserted"], true);
    let r = api
        .call(
            Method::DELETE,
            &format!("{docs}/9?returnDocument=true"),
            &a,
            None,
        )
        .await
        .ok();
    assert_eq!(r.body["deleted"], true);
    assert_eq!(r.body["document"]["n"], 9);
    let rest_again = api
        .call(Method::DELETE, &format!("{docs}/9"), &a, None)
        .await
        .ok();
    let grpc_again = grpc
        .doc()
        .delete(g(
            pb::DeleteRequest {
                database: "shop".into(),
                collection: "items".into(),
                id: Some(pval(&Value::Int64(9))),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rest_again.body["deleted"], grpc_again.deleted);

    // GetMany.
    let r = api
        .post(
            "/api/v1/databases/shop/collections/items/get-many",
            &a,
            json!({"ids": [3, 42, 1]}),
        )
        .await
        .ok();
    let grpc_many = grpc
        .doc()
        .get_many(g(
            pb::GetManyRequest {
                database: "shop".into(),
                collection: "items".into(),
                ids: [3, 42, 1].iter().map(|i| pval(&Value::Int64(*i))).collect(),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner()
        .documents;
    let rest_many: Vec<Document> = r.body["documents"]
        .as_array()
        .unwrap()
        .iter()
        .map(jdoc)
        .collect();
    assert_eq!(
        rest_many,
        grpc_many.iter().map(grpc_doc).collect::<Vec<_>>()
    );
    assert_eq!(rest_many.len(), 2);

    // BulkWrite: per-operation errors with equal codes.
    let bulk = json!({"operations": [
        {"op": "insert", "document": {"_id": 1}},
        {"op": "insert", "document": {"_id": 100, "n": 100}},
        {"op": "update", "id": 3, "operations": ops_json("SET n = 30")},
        {"op": "delete", "id": 4, "ifRev": "nope"}
    ]});
    let r = api
        .post("/api/v1/databases/shop/collections/items/bulk", &a, bulk)
        .await
        .ok();
    let grpc_bulk = grpc
        .doc()
        .bulk_write(g(
            pb::BulkWriteRequest {
                database: "shop".into(),
                collection: "items".into(),
                operations: vec![
                    pb::BulkOperation {
                        op: Some(pb::bulk_operation::Op::Insert(pb::BulkInsert {
                            document: Some(pdoc(&jdoc(&json!({"_id": 1})))),
                        })),
                    },
                    pb::BulkOperation {
                        op: Some(pb::bulk_operation::Op::Insert(pb::BulkInsert {
                            document: Some(pdoc(&jdoc(&json!({"_id": 101, "n": 101})))),
                        })),
                    },
                ],
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.body["inserted"], 1);
    assert_eq!(r.body["matched"], 1);
    let errors = r.body["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0]["index"], 0);
    assert_eq!(
        errors[0]["error"]["code"],
        grpc_bulk.errors[0].error.as_ref().unwrap().code
    );
    assert_eq!(errors[1]["error"]["code"], 2009);

    // List: pages with a continuation token, filter and sort.
    let page = api.get(&format!("{docs}?limit=2&sort=-n"), &a).await.ok();
    let ns: Vec<i64> = page.body["documents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["n"].as_i64().unwrap())
        .collect();
    assert_eq!(ns, vec![101, 100]);
    let token = page.body["continuationToken"].as_str().unwrap();
    let next = api
        .get(
            &format!("{docs}?limit=2&sort=-n&continuationToken={token}"),
            &a,
        )
        .await
        .ok();
    assert_eq!(next.body["documents"][0]["n"], 30);
    assert_eq!(h.services.data().unwrap().query.open_cursors(), 0);
    let filtered = api
        .get(&format!("{docs}?filter=tag%20%3D%20'odd'"), &a)
        .await
        .ok();
    let ids: Vec<i64> = filtered.body["documents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["_id"].as_i64().unwrap())
        .collect();
    // Document 1 lost its tag when it was replaced above.
    assert_eq!(ids, vec![3, 5]);
    assert!(filtered.body.get("continuationToken").is_none());
    let bad = api.get(&format!("{docs}?filter=n%20%3D"), &a).await;
    assert_eq!(bad.code(), 1010);
    // errors.yaml RGN-1010: the position is in the details, not only in the message.
    assert_eq!(bad.body["error"]["details"]["line"], "1", "{:?}", bad.body);
    assert!(
        bad.body["error"]["details"]["column"].is_string(),
        "{:?}",
        bad.body
    );
    let bad = api.get(&format!("{docs}?limit=0"), &a).await;
    assert_eq!(bad.code(), 1001);
    let bad = api.get(&format!("{docs}?bogus=1"), &a).await;
    assert_eq!(
        (bad.code(), bad.body["error"]["details"]["query"].clone()),
        (1001, json!("invalid"))
    );

    // Indexes.
    let mut definition =
        serde_json::to_value(parse_statement("CREATE INDEX by_n ON items (n)").unwrap()).unwrap();
    definition.as_object_mut().unwrap().remove("kind");
    let indexes = "/api/v1/databases/shop/collections/items/indexes";
    let r = api
        .post(indexes, &a, json!({"definition": definition}))
        .await
        .ok();
    assert_eq!(r.body["index"]["definition"]["name"], "by_n");
    let mut wrong = definition.clone();
    wrong["on"]["name"] = json!("other");
    assert_eq!(
        api.post(indexes, &a, json!({"definition": wrong}))
            .await
            .code(),
        1001
    );
    let progress = api.get(&format!("{indexes}/by_n/progress"), &a).await.ok();
    assert!(progress.body["state"].is_string());
    let rest_list = api.get(indexes, &a).await.ok();
    let grpc_list = grpc
        .schema()
        .list_indexes(g(
            pb::ListIndexesRequest {
                database: "shop".into(),
                collection: "items".into(),
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner()
        .indexes;
    assert_eq!(
        rest_list.body["indexes"].as_array().unwrap().len(),
        grpc_list.len()
    );
    api.get(&format!("{indexes}/by_n"), &a).await.ok();
    api.call(Method::DELETE, &format!("{indexes}/by_n"), &a, None)
        .await
        .ok();
    assert_eq!(api.get(&format!("{indexes}/by_n"), &a).await.code(), 1021);
    let rest_drop = api
        .call(Method::DELETE, &format!("{indexes}/by_n"), &a, None)
        .await;
    let grpc_drop = grpc
        .schema()
        .drop_index(g(
            pb::DropIndexRequest {
                database: "shop".into(),
                collection: "items".into(),
                name: "by_n".into(),
                if_exists: false,
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(rest_drop.code(), u64::from(code_of(&grpc_drop)));

    // Drops.
    let r = api
        .call(
            Method::DELETE,
            "/api/v1/databases/shop/collections/items",
            &a,
            None,
        )
        .await
        .ok();
    assert_eq!(r.body["dropped"], true);
    let rest_gone = api
        .get("/api/v1/databases/shop/collections/items", &a)
        .await;
    let grpc_gone = grpc
        .schema()
        .get_collection(g(
            pb::GetCollectionRequest {
                database: "shop".into(),
                name: "items".into(),
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(rest_gone.code(), u64::from(code_of(&grpc_gone)));
    let r = api
        .call(
            Method::DELETE,
            "/api/v1/databases/shop?ifExists=true",
            &a,
            None,
        )
        .await
        .ok();
    assert_eq!(r.body["dropped"], true);
    h.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Queries, cursors and transactions
// ---------------------------------------------------------------------------------------------

/// TC-API-006 (QueryService, TransactionService): the first batch, cursor continuation and
/// kill, explain, errors and deadlines; transactions begun on one channel and finished on the
/// other.
#[tokio::test]
async fn tc_api_006_query_cursor_and_transaction_parity() {
    let (h, api, grpc, admin) = node().await;
    let a = Auth::bearer(&admin);
    let docs = "/api/v1/databases/shop/collections/items/documents";
    api.post("/api/v1/databases", &a, json!({"name": "shop"}))
        .await
        .ok();
    api.post(
        docs,
        &a,
        json!({"documents": (1..=5).map(|i| json!({"_id": i, "n": i})).collect::<Vec<_>>()}),
    )
    .await
    .ok();

    // First batch + cursor over REST equals Execute with max_batches = 1 over gRPC.
    let q = json!({"rgql": "FROM items ORDER BY n", "options": {"batchSize": 2}});
    let first = api
        .post("/api/v1/databases/shop/query", &a, q.clone())
        .await
        .ok();
    let mut stream = grpc
        .query()
        .execute(g(
            pb::ExecuteRequest {
                database: "shop".into(),
                query: Some(pb::execute_request::Query::Rgql(
                    "FROM items ORDER BY n".into(),
                )),
                options: Some(pb::ExecOptions {
                    batch_size: Some(2),
                    max_batches: Some(1),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner();
    let grpc_first = stream.message().await.unwrap().unwrap().batch.unwrap();
    let rest_rows: Vec<Document> = first.body["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(jdoc)
        .collect();
    assert_eq!(
        rest_rows,
        grpc_first.docs.iter().map(grpc_doc).collect::<Vec<_>>()
    );
    assert_eq!(rest_rows.len(), 2);
    assert!(grpc_first.cursor_id.is_some());
    let cursor = first.body["cursorId"].as_str().unwrap().to_owned();
    assert!(first.body["continuationToken"].is_string());
    let next = api
        .call(
            Method::POST,
            &format!("/api/v1/cursors/{cursor}/next?batchSize=2"),
            &a,
            None,
        )
        .await
        .ok();
    assert_eq!(next.body["rows"][0]["n"], 3);
    let last = api
        .call(
            Method::POST,
            &format!("/api/v1/cursors/{cursor}/next"),
            &a,
            None,
        )
        .await
        .ok();
    assert_eq!(last.body["rows"].as_array().unwrap().len(), 1);
    assert!(last.body.get("cursorId").is_none());
    assert_eq!(last.body["stats"]["docsReturned"], 5);
    let rest_gone = api
        .call(
            Method::POST,
            &format!("/api/v1/cursors/{cursor}/next"),
            &a,
            None,
        )
        .await;
    let grpc_gone = grpc
        .query()
        .get_more(g(
            pb::GetMoreRequest {
                cursor_id: cursor.clone(),
                batch_size: None,
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(rest_gone.code(), 1030);
    assert_eq!(rest_gone.code(), u64::from(code_of(&grpc_gone)));
    // Kill.
    let first = api.post("/api/v1/databases/shop/query", &a, q).await.ok();
    let cursor = first.body["cursorId"].as_str().unwrap();
    let r = api
        .call(
            Method::DELETE,
            &format!("/api/v1/cursors/{cursor}"),
            &a,
            None,
        )
        .await
        .ok();
    assert_eq!(r.body["killed"], true);
    // A cursor belongs to its principal.
    api.post(
        "/api/v1/users",
        &a,
        json!({"name": "fay", "password": OTHER_PASSWORD}),
    )
    .await
    .ok();
    let fay = api.token("fay", OTHER_PASSWORD).await;
    let first = api
        .post(
            "/api/v1/databases/shop/query",
            &a,
            json!({"rgql": "FROM items", "options": {"batchSize": 1}}),
        )
        .await
        .ok();
    let cursor = first.body["cursorId"].as_str().unwrap();
    let r = api
        .call(
            Method::POST,
            &format!("/api/v1/cursors/{cursor}/next"),
            &Auth::bearer(&fay),
            None,
        )
        .await;
    assert_eq!(r.code(), 1030);
    // Non-document rows travel as plain values; parameters are extended JSON.
    let r = api
        .post(
            "/api/v1/databases/shop/query",
            &a,
            json!({"rgql": "FROM items WHERE n >= $min SELECT VALUE n",
                   "params": {"min": {"$int64": "4"}}}),
        )
        .await
        .ok();
    let mut rows: Vec<i64> = r.body["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap())
        .collect();
    rows.sort_unstable();
    assert_eq!(rows, vec![4, 5]);
    // The structured AST form.
    let ast = serde_json::to_value(parse_statement("FROM items WHERE n = 1").unwrap()).unwrap();
    let r = api
        .post("/api/v1/databases/shop/query", &a, json!({"ast": ast}))
        .await
        .ok();
    assert_eq!(r.body["rows"][0]["_id"], 1);
    // Errors: equal codes; deadlines.
    let rest_syntax = api
        .post("/api/v1/databases/shop/query", &a, json!({"rgql": "FROM"}))
        .await;
    let grpc_syntax = grpc
        .query()
        .execute(g(
            pb::ExecuteRequest {
                database: "shop".into(),
                query: Some(pb::execute_request::Query::Rgql("FROM".into())),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(rest_syntax.code(), 1010);
    // errors.yaml RGN-1010 details (lane GQ found them empty, PD-137).
    let details = &rest_syntax.body["error"]["details"];
    assert_eq!(details["line"], "1", "{details:?}");
    assert_eq!(details["column"], "5", "{details:?}");
    assert_eq!(details["found"], "end of input", "{details:?}");
    assert_eq!(rest_syntax.code(), u64::from(code_of(&grpc_syntax)));
    let r = api
        .post("/api/v1/databases/shop/query", &a, json!({}))
        .await;
    assert_eq!(r.code(), 1001);
    let expired = a.clone().header("x-rgn-timeout-ms", "0");
    let r = api
        .post(
            "/api/v1/databases/shop/query",
            &expired,
            json!({"rgql": "FROM items"}),
        )
        .await;
    assert_eq!((r.status, r.code()), (StatusCode::GATEWAY_TIMEOUT, 5006));
    // Explain.
    let r = api
        .post(
            "/api/v1/databases/shop/explain",
            &a,
            json!({"rgql": "FROM items WHERE n = 1"}),
        )
        .await
        .ok();
    let grpc_plan = grpc
        .query()
        .explain(g(
            pb::ExplainRequest {
                database: "shop".into(),
                query: Some(pb::explain_request::Query::Rgql(
                    "FROM items WHERE n = 1".into(),
                )),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner()
        .plan_json;
    assert_eq!(
        r.body["plan"],
        serde_json::from_str::<Json>(&grpc_plan).unwrap()
    );

    // Transactions: begin on REST, write with rgn-txn-id, commit on gRPC, status on both.
    let begun = api
        .post(
            "/api/v1/transactions",
            &a,
            json!({"isolation": "serializable"}),
        )
        .await
        .ok();
    let txn = begun.body["txnId"].as_str().unwrap().to_owned();
    assert!(begun.body["heartbeatIntervalMs"].as_u64().unwrap() > 0);
    let in_txn = a.clone().header("rgn-txn-id", txn.clone());
    api.post(docs, &in_txn, json!({"documents": [{"_id": 50, "n": 50}]}))
        .await
        .ok();
    let status = api
        .get(&format!("/api/v1/transactions/{txn}"), &a)
        .await
        .ok();
    assert_eq!(status.body["state"], "active");
    let grpc_status = grpc
        .txn()
        .status(g(
            pb::StatusRequest {
                txn_id: txn.clone(),
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(grpc_status.state, pb::TransactionState::Active as i32);
    let hb = api
        .call(
            Method::POST,
            &format!("/api/v1/transactions/{txn}/heartbeat"),
            &a,
            None,
        )
        .await
        .ok();
    assert!(hb.body["expiresInMs"].as_u64().unwrap() > 0);
    grpc.txn()
        .commit(g(
            pb::CommitRequest {
                txn_id: txn.clone(),
            },
            &admin,
        ))
        .await
        .unwrap();
    let status = api
        .get(&format!("/api/v1/transactions/{txn}"), &a)
        .await
        .ok();
    assert_eq!(status.body["state"], "committed");
    // Commit is idempotent on REST too.
    api.call(
        Method::POST,
        &format!("/api/v1/transactions/{txn}/commit"),
        &a,
        None,
    )
    .await
    .ok();
    api.get(&format!("{docs}/50"), &a).await.ok();
    // Rollback.
    let txn = api
        .post("/api/v1/transactions", &a, json!({}))
        .await
        .ok()
        .body["txnId"]
        .as_str()
        .unwrap()
        .to_owned();
    api.call(
        Method::POST,
        &format!("/api/v1/transactions/{txn}/rollback"),
        &a,
        None,
    )
    .await
    .ok();
    let rest_status = api
        .get(&format!("/api/v1/transactions/{txn}"), &a)
        .await
        .ok();
    let grpc_status = grpc
        .txn()
        .status(g(
            pb::StatusRequest {
                txn_id: txn.clone(),
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rest_status.body["state"], "aborted");
    assert_eq!(
        rest_status.body["abortReason"].as_str(),
        grpc_status.abort_reason.as_deref()
    );
    // Unknown transaction and a foreign one: equal codes.
    let unknown = "00000000-0000-4000-8000-000000000000";
    let rest_unknown = api
        .get(&format!("/api/v1/transactions/{unknown}"), &a)
        .await;
    let grpc_unknown = grpc
        .txn()
        .status(g(
            pb::StatusRequest {
                txn_id: unknown.into(),
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(rest_unknown.code(), u64::from(code_of(&grpc_unknown)));
    let r = api
        .post("/api/v1/transactions", &a, json!({"isolation": "bogus"}))
        .await;
    assert_eq!(
        (r.code(), r.body["error"]["details"]["body"].clone()),
        (1001, json!("data"))
    );

    // Values written over REST read back unchanged over gRPC (extended JSON round trip).
    api.post(
        docs,
        &a,
        json!({"documents": [{"_id": "x", "big": {"$int64": "9007199254740993"},
                              "f": 1.5, "d": {"$decimal": "1.10"}}]}),
    )
    .await
    .ok();
    let got = grpc
        .doc()
        .get(g(
            pb::GetRequest {
                database: "shop".into(),
                collection: "items".into(),
                id: Some(pval(&Value::String("x".into()))),
                ..Default::default()
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner();
    let got = grpc_doc(got.document.as_ref().unwrap());
    assert_eq!(got.get("big"), Some(&Value::Int64(9_007_199_254_740_993)));
    assert_eq!(got.get("f"), Some(&Value::Float64(1.5)));
    let rest = api.get(&format!("{docs}/x"), &a).await.ok();
    assert_eq!(
        rest.body["document"]["big"],
        json!({"$int64": "9007199254740993"})
    );
    assert_eq!(
        parse_value(&rest.body["document"]["d"].to_string()).unwrap(),
        *got.get("d").unwrap()
    );
    h.stop().await;
}

/// Without a data plane the data endpoints do not exist (RGN-1030, the REST counterpart of
/// gRPC `UNIMPLEMENTED`), whoever asks.
#[tokio::test]
async fn fr_api_002_data_endpoints_need_a_data_plane() {
    let h = Harness::start_full(base_flags(), true, None, None).await;
    let api = Api::new(&h);
    for (method, path) in [
        (Method::GET, "/api/v1/databases"),
        (Method::POST, "/api/v1/transactions"),
        (Method::DELETE, "/api/v1/cursors/abc"),
    ] {
        let r = api.call(method, path, &Auth::default(), None).await;
        assert_eq!(
            (r.status, r.code()),
            (StatusCode::NOT_FOUND, 1030),
            "{path}"
        );
    }
    // Authentication endpoints are served.
    let token = api.token(ADMIN, ADMIN_PASSWORD).await;
    api.get("/api/v1/auth/me", &Auth::bearer(&token)).await.ok();
    h.stop().await;
}
