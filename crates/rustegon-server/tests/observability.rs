// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `GET /metrics` and the readiness probe over the in-process REST router (FR-OPS-001,
//! FR-OPS-003; TC-OPS-004, TC-OPS-005; PD-059). The process-level drain test is in
//! `bins/rustegond/tests/observability.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{collections::BTreeSet, sync::Arc};

use axum::body::{Body, to_bytes};
use common::{ADMIN, ADMIN_PASSWORD, Harness, OTHER_PASSWORD, base_flags, bearer};
use http::{Request, StatusCode};
use rustegon_server::{metrics, rest::router};
use serde_json::{Value as Json, json};
use tower::ServiceExt;

/// Families every M4 node with the security layer and the data plane exports (PD-059).
const M4_FAMILIES: &[&str] = &[
    "rustegon_build",
    "rustegon_ready",
    "rustegon_requests",
    "rustegon_errors",
    "rustegon_request_duration_seconds",
    "rustegon_executor_in_flight",
    "rustegon_executor_queued",
    "rustegon_executor_max_in_flight",
    "rustegon_auth_failures",
    "rustegon_lockouts",
    "rustegon_audit_write_failures",
    "rustegon_rate_limited",
    "rustegon_active_sessions",
    "rustegon_active_transactions",
    "rustegon_open_cursors",
    "rustegon_txn_commits",
    "rustegon_txn_aborts",
    "rustegon_txn_restarts",
    "rustegon_storage_healthy",
    "rustegon_storage_l0_files",
    "rustegon_storage_compaction_bytes",
    "rustegon_storage_block_cache_hit_ratio",
    "rustegon_storage_disk_used_bytes",
    "rustegon_cert_expiry_seconds",
];

struct Reply {
    status: StatusCode,
    content_type: String,
    body: String,
}

impl Reply {
    fn json(&self) -> Json {
        serde_json::from_str(&self.body).unwrap_or(Json::Null)
    }

    fn code(&self) -> u64 {
        self.json()["error"]["code"].as_u64().unwrap_or(0)
    }
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    body: Option<Json>,
) -> Reply {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(a) = authorization {
        b = b.header("authorization", a);
    }
    let request = match body {
        Some(j) => b
            .header("content-type", "application/json")
            .body(Body::from(j.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let bytes = to_bytes(response.into_body(), 16 << 20).await.unwrap();
    Reply {
        status,
        content_type,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

/// Checks the `OpenMetrics` shape (every sample belongs to the family declared just before it,
/// values parse, `# EOF` last) and returns the declared families.
fn families(text: &str) -> BTreeSet<String> {
    assert!(text.ends_with("# EOF\n"), "missing # EOF");
    let mut declared = BTreeSet::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        if line == "# EOF" {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').unwrap();
            assert!(
                ["counter", "gauge", "histogram", "info"].contains(&kind),
                "{line}"
            );
            assert!(
                declared.insert(name.to_owned()),
                "family {name} declared twice"
            );
            current = Some((name.to_owned(), kind.to_owned()));
            continue;
        }
        if line.starts_with("# HELP ") {
            continue;
        }
        let (family, kind) = current.as_ref().expect("sample before any family");
        let (series, value) = line.rsplit_once(' ').unwrap();
        let name = series.split('{').next().unwrap();
        let suffixes: &[&str] = match kind.as_str() {
            "counter" => &["_total"],
            "histogram" => &["_bucket", "_count", "_sum"],
            "info" => &["_info"],
            _ => &[""],
        };
        assert!(
            suffixes.iter().any(|s| name == format!("{family}{s}")),
            "sample {name} outside family {family}"
        );
        assert!(
            value.parse::<f64>().is_ok() || ["+Inf", "-Inf", "NaN"].contains(&value),
            "{line}"
        );
        if let Some(labels) = series.strip_prefix(name) {
            assert!(
                labels.is_empty() || (labels.starts_with('{') && labels.ends_with('}')),
                "{line}"
            );
        }
    }
    declared
}

/// TC-OPS-004 / AC-OPS-001 (M4 part): `/metrics` serves `OpenMetrics` text with every M4 family,
/// counts gRPC and REST requests per declared route with the outcome code, and never turns a
/// request path into a label.
#[tokio::test]
async fn tc_ops_004_metrics_exposes_every_m4_family() {
    let h = Harness::start(base_flags()).await;
    h.services
        .metrics()
        .register_cert("node", Arc::new(|| 86_400));
    let conn = h.channel().await;
    let admin = bearer(&conn.admin_token().await);
    let app = router(&h.services, 64 << 20);

    // Traffic: a gRPC call, REST successes and failures, an unknown path, a failed login.
    conn.raw_call("/rustegon.v1.SessionService/Ping", None)
        .await
        .unwrap();
    assert_eq!(
        call(&app, "GET", "/api/v1/ping", None, None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "GET", "/api/v1/no/such/path-SECRET", None, None)
            .await
            .code(),
        1030
    );
    let failed = call(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({"user": ADMIN, "password": OTHER_PASSWORD, "delivery": "token"})),
    )
    .await;
    assert_eq!(failed.code(), 4001);

    let reply = call(&app, "GET", "/metrics", Some(&admin), None).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.content_type, metrics::CONTENT_TYPE);
    let text = reply.body;
    let declared = families(&text);
    for family in M4_FAMILIES {
        assert!(declared.contains(*family), "{family} missing:\n{text}");
    }
    for expected in [
        "rustegon_requests_total{service=\"rustegon.v1.SessionService\",method=\"Ping\",code=\"ok\"} 1",
        "rustegon_requests_total{service=\"rustegon.v1.AuthService\",method=\"Authenticate\",code=\"ok\"}",
        "rustegon_requests_total{service=\"rest\",method=\"GET /api/v1/ping\",code=\"ok\"} 1",
        "rustegon_requests_total{service=\"rest\",method=\"POST /api/v1/auth/login\",code=\"4001\"} 1",
        "rustegon_requests_total{service=\"rest\",method=\"unknown\",code=\"1030\"} 1",
        "rustegon_errors_total{code=\"4001\"} 1",
        "rustegon_cert_expiry_seconds{cert=\"node\"} 86400",
        "rustegon_auth_failures_total 1",
        "rustegon_executor_max_in_flight 16",
        "rustegon_ready 0",
    ] {
        assert!(text.contains(expected), "{expected} missing:\n{text}");
    }
    assert!(!text.contains("SECRET"), "a request path became a label");
    let sessions: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("rustegon_active_sessions "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(sessions >= 1, "the admin session is active");
    let commits: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("rustegon_txn_commits_total "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(commits >= 1, "logins commit system transactions");
    // Bounded cardinality: every requests_total series names a declared route.
    for line in text
        .lines()
        .filter(|l| l.starts_with("rustegon_requests_total"))
    {
        assert!(
            line.contains("service=\"rest\"") || line.contains("service=\"rustegon.v1."),
            "{line}"
        );
    }
    h.stop().await;
}

/// TC-OPS-004 + TC-SEC-001: `/metrics` needs `cluster_view` — the `monitor` role by session or
/// a scrape API key of a monitor user; anonymous callers get RGN-4001 and a user without it
/// RGN-4002.
#[tokio::test]
async fn tc_ops_004_metrics_requires_monitor_role_or_scrape_key() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let admin = bearer(&conn.admin_token().await);
    let app = router(&h.services, 64 << 20);
    for (name, role) in [("scraper", "monitor"), ("reader", "read")] {
        let created = call(
            &app,
            "POST",
            "/api/v1/users",
            Some(&admin),
            Some(json!({
                "name": name,
                "password": OTHER_PASSWORD,
                "roles": [{"role": role, "resource": if role == "read" { "database:*" } else { "" }}],
            })),
        )
        .await;
        assert_eq!(created.status, StatusCode::OK, "{}", created.body);
    }

    assert_eq!(call(&app, "GET", "/metrics", None, None).await.code(), 4001);
    let reader = call(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({"user": "reader", "password": OTHER_PASSWORD, "delivery": "token"})),
    )
    .await
    .json()["sessionToken"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        call(&app, "GET", "/metrics", Some(&bearer(&reader)), None)
            .await
            .code(),
        4002
    );

    let scraper = call(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({"user": "scraper", "password": OTHER_PASSWORD, "delivery": "token"})),
    )
    .await
    .json()["sessionToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let by_session = call(&app, "GET", "/metrics", Some(&bearer(&scraper)), None).await;
    assert_eq!(by_session.status, StatusCode::OK, "{}", by_session.body);

    let key = call(
        &app,
        "POST",
        "/api/v1/api-keys",
        Some(&admin),
        Some(
            json!({"user": "scraper", "description": "prometheus", "roles": [{"role": "monitor"}]}),
        ),
    )
    .await;
    assert_eq!(key.status, StatusCode::OK, "{}", key.body);
    let secret = key.json()["secret"].as_str().unwrap().to_owned();
    let by_key = call(
        &app,
        "GET",
        "/metrics",
        Some(&format!("ApiKey {secret}")),
        None,
    )
    .await;
    assert_eq!(by_key.status, StatusCode::OK, "{}", by_key.body);
    assert!(by_key.body.ends_with("# EOF\n"));
    // The admin password and the key never reach the exposition.
    for text in [&by_session.body, &by_key.body] {
        assert!(!text.contains(ADMIN_PASSWORD) && !text.contains(&secret));
    }
    h.stop().await;
}

/// TC-OPS-005 / AC-OPS-003 (service part): `/api/v1/health/ready` is 503 `starting` until the
/// node is marked serving, 200 `ready` while serving, 503 `draining` once a shutdown began;
/// it needs no credentials and ignores invalid ones; `/api/v1/health/live` stays 200.
#[tokio::test]
async fn tc_ops_005_readiness_follows_the_node_lifecycle() {
    let h = Harness::start(base_flags()).await;
    let app = router(&h.services, 64 << 20);
    let ready = |auth: Option<&'static str>| {
        let app = app.clone();
        async move { call(&app, "GET", "/api/v1/health/ready", auth, None).await }
    };

    let r = ready(None).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.json()["status"], "starting");

    h.services.readiness().mark_serving();
    let r = ready(None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["status"], "ready");
    // Credentials are not read: a bogus token does not fail the probe.
    assert_eq!(
        ready(Some("Bearer not-a-session")).await.status,
        StatusCode::OK
    );

    h.services.readiness().mark_draining();
    let r = ready(None).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.json()["status"], "draining");
    assert_eq!(
        call(&app, "GET", "/api/v1/health/live", None, None)
            .await
            .status,
        StatusCode::OK
    );
    h.stop().await;
}
