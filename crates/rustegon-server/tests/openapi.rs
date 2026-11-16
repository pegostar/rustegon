// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The checked-in `OpenAPI` document matches the code (FR-API-002, FR-API-003, PD-052).
//!
//! `api/openapi/rustegon-v1.yaml` is the REST contract published with each release; it is
//! generated from the handlers' `utoipa` annotations. This golden test fails when the two
//! differ. After an intended API change, regenerate it with
//! `RGN_OPENAPI_BLESS=1 cargo nextest run -p rustegon-server tc_api_002` and review the diff:
//! within `/api/v1` only additive changes are allowed (protocol.md §9). The release-to-release
//! breaking-change check (TC-API-002, `oasdiff breaking`) needs a released baseline and runs
//! in CI from the first release on.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use std::collections::BTreeSet;

use rustegon_server::{
    rest::{REST_ENDPOINTS, openapi, openapi_yaml},
    security::access_of,
};

fn checked_in_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../api/openapi/rustegon-v1.yaml")
}

fn bless() -> bool {
    std::env::var("RGN_OPENAPI_BLESS").is_ok_and(|v| v == "1")
}

#[test]
fn tc_api_002_checked_in_openapi_matches_the_code() {
    let generated = openapi_yaml().unwrap();
    let path = checked_in_path();
    if bless() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let checked_in = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
        .replace("\r\n", "\n");
    assert!(
        checked_in == generated,
        "{} is stale: regenerate it with RGN_OPENAPI_BLESS=1 cargo nextest run -p \
         rustegon-server tc_api_002 and review the diff",
        path.display()
    );
}

#[test]
fn tc_api_002_document_is_openapi_3_1_under_api_v1() {
    let doc = serde_json::to_value(openapi()).unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(doc["info"]["version"], "1.0");
    let paths = doc["paths"].as_object().unwrap();
    assert!(!paths.is_empty());
    for (path, item) in paths {
        // The one exception: the Prometheus scrape endpoint lives at the root (protocol.md §1,
        // PD-059).
        assert!(
            path.starts_with("/api/v1/") || path == "/metrics",
            "{path} outside /api/v1"
        );
        for (method, op) in item.as_object().unwrap() {
            let id = op["operationId"].as_str();
            assert!(id.is_some(), "{method} {path} has no operationId");
            assert!(
                op["responses"]["default"]["$ref"] == "#/components/responses/Error",
                "{method} {path} lacks the error response"
            );
        }
    }
    for path in [
        "/api/v1/ping",
        "/api/v1/server-info",
        "/api/v1/health/live",
        "/api/v1/health/ready",
        "/metrics",
    ] {
        assert!(paths.contains_key(path), "{path} not documented");
    }
    // Shared request headers are referenced by API operations, not by probes.
    let ping_params = doc["paths"]["/api/v1/ping"]["get"]["parameters"]
        .as_array()
        .unwrap();
    assert!(
        ping_params
            .iter()
            .any(|p| p["$ref"] == "#/components/parameters/x-rgn-timeout-ms")
    );
    assert!(doc["paths"]["/api/v1/health/live"]["get"]["parameters"].is_null());
    assert!(doc["paths"]["/api/v1/health/ready"]["get"]["parameters"].is_null());
    assert!(
        doc["paths"]["/metrics"]["get"]["responses"]["200"]["content"]
            ["application/openmetrics-text; version=1.0.0; charset=utf-8"]
            .is_object()
    );
    for scheme in ["bearer", "apiKey", "sessionCookie"] {
        assert!(
            doc["components"]["securitySchemes"][scheme].is_object(),
            "{scheme}"
        );
    }
}

/// Every documented operation is in `REST_ENDPOINTS` (whose RPC rule the gate applies) and
/// every table entry is documented, so no route can be served without a declared access rule
/// (PD-055; implementation-rules.md §8).
#[test]
fn tc_api_002_every_documented_route_is_in_the_endpoint_table() {
    let doc = serde_json::to_value(openapi()).unwrap();
    let mut documented = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            documented.insert((method.to_uppercase(), path.clone()));
        }
    }
    let table: BTreeSet<(String, String)> = REST_ENDPOINTS
        .iter()
        .map(|e| (e.method.to_owned(), e.path.to_owned()))
        .collect();
    assert_eq!(table.len(), REST_ENDPOINTS.len(), "duplicate table entries");
    assert_eq!(documented, table);
    for e in REST_ENDPOINTS {
        if let Some(rpc) = e.rpc {
            assert!(
                access_of(rpc).is_some(),
                "{} {}: {rpc} has no rule",
                e.method,
                e.path
            );
        }
    }
    // Authenticated operations declare the security schemes; the login endpoints do not.
    for e in REST_ENDPOINTS {
        let op = &doc["paths"][e.path][e.method.to_lowercase()];
        let anonymous = e
            .rpc
            .and_then(access_of)
            .is_none_or(|r| r.access == rustegon_server::security::Access::Anonymous);
        assert_eq!(
            op["security"].is_array(),
            !anonymous,
            "{} {}",
            e.method,
            e.path
        );
    }
}
