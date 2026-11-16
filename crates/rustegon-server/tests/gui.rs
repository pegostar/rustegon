// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The GUI under `/ui` (ADR-027, FR-GUI-001, PD-130, PD-131) over a small in-memory fixture
//! instead of the Angular build: content types, ETag/304, cache headers, SPA fallback,
//! redirects, security headers, path traversal, a build without the GUI, and `/api/v1`
//! unchanged next to it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{borrow::Cow, collections::HashMap, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
};
use http::{Method, Request, Response, StatusCode, header};
use rustegon_server::{
    Executor,
    rest::{CSP, GuiAssets, GuiFile, gui_router, router},
    services::{NodeIdentity, ServiceDeps, Services},
};
use rustegon_sim_api::{OsRng, SystemClock};
use serde_json::Value;
use tower::ServiceExt;

const INDEX_HTML: &[u8] = b"<!doctype html><base href=\"/ui/\"><app-root></app-root>";

struct Fixture(HashMap<&'static str, &'static [u8]>);

impl GuiAssets for Fixture {
    fn get(&self, path: &str) -> Option<GuiFile> {
        self.0.get(path).map(|data| GuiFile {
            data: Cow::Borrowed(*data),
            hash: *blake3::hash(data).as_bytes(),
        })
    }
}

fn fixture() -> Arc<dyn GuiAssets> {
    Arc::new(Fixture(HashMap::from([
        ("index.html", INDEX_HTML),
        ("main-ABCD1234.js", b"console.log(1)".as_slice()),
        ("styles-5INURTSO.css", b"body{}".as_slice()),
        ("media/roboto-QWERTY12.woff2", b"wOF2".as_slice()),
        ("favicon.ico", b"ico".as_slice()),
        ("assets/logo.svg", b"<svg/>".as_slice()),
        ("3rdpartylicenses.txt", b"MIT".as_slice()),
        ("data.bin", b"\x00".as_slice()),
    ])))
}

fn services() -> Services {
    let clock = Arc::new(SystemClock::new());
    let deps = ServiceDeps {
        executor: Executor::new(clock.clone(), 2),
        clock,
        rng: Arc::new(OsRng),
    };
    Services::new(
        deps,
        NodeIdentity {
            node_id: 7,
            features: vec![],
            client_addresses: vec![],
        },
    )
}

/// The REST router as `RestServer::with_gui` builds it.
fn app(assets: Option<Arc<dyn GuiAssets>>) -> Router {
    let api = router(&services(), 1024 * 1024);
    match assets {
        Some(assets) => api.merge(gui_router(assets)),
        None => api,
    }
}

async fn send(app: &Router, method: Method, uri: &str, inm: Option<&str>) -> Response<Body> {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(tag) = inm {
        request = request.header(header::IF_NONE_MATCH, tag);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn get(app: &Router, uri: &str) -> Response<Body> {
    send(app, Method::GET, uri, None).await
}

async fn body(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec()
}

#[allow(clippy::needless_pass_by_value)]
fn header_of(response: &Response<Body>, name: header::HeaderName) -> &str {
    response
        .headers()
        .get(&name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .to_str()
        .unwrap()
}

fn assert_security_headers(response: &Response<Body>) {
    assert_eq!(header_of(response, header::CONTENT_SECURITY_POLICY), CSP);
    assert!(CSP.contains("frame-ancestors 'none'") && CSP.contains("script-src 'self';"));
    assert_eq!(header_of(response, header::X_FRAME_OPTIONS), "DENY");
    assert_eq!(header_of(response, header::REFERRER_POLICY), "no-referrer");
    assert_eq!(
        header_of(response, header::X_CONTENT_TYPE_OPTIONS),
        "nosniff"
    );
}

#[tokio::test]
async fn fr_gui_001_assets_have_content_type_cache_policy_and_security_headers() {
    let app = app(Some(fixture()));
    for (uri, content_type, cache) in [
        ("/ui/", "text/html; charset=utf-8", "no-cache"),
        ("/ui/index.html", "text/html; charset=utf-8", "no-cache"),
        (
            "/ui/main-ABCD1234.js",
            "text/javascript; charset=utf-8",
            "public, max-age=31536000, immutable",
        ),
        (
            "/ui/styles-5INURTSO.css",
            "text/css; charset=utf-8",
            "public, max-age=31536000, immutable",
        ),
        (
            "/ui/media/roboto-QWERTY12.woff2",
            "font/woff2",
            "public, max-age=31536000, immutable",
        ),
        ("/ui/favicon.ico", "image/x-icon", "no-cache"),
        ("/ui/assets/logo.svg", "image/svg+xml", "no-cache"),
        (
            "/ui/3rdpartylicenses.txt",
            "text/plain; charset=utf-8",
            "no-cache",
        ),
        ("/ui/data.bin", "application/octet-stream", "no-cache"),
    ] {
        let response = get(&app, uri).await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(
            header_of(&response, header::CONTENT_TYPE),
            content_type,
            "{uri}"
        );
        assert_eq!(header_of(&response, header::CACHE_CONTROL), cache, "{uri}");
        assert_security_headers(&response);
        // The GUI routes are not API operations: no node headers.
        assert!(response.headers().get("rgn-node-id").is_none());
    }
    let js = get(&app, "/ui/main-ABCD1234.js").await;
    assert_eq!(body(js).await, b"console.log(1)");
}

#[tokio::test]
async fn fr_gui_001_strong_etag_and_if_none_match_304() {
    let app = app(Some(fixture()));
    let first = get(&app, "/ui/main-ABCD1234.js").await;
    let etag = header_of(&first, header::ETAG).to_owned();
    assert!(etag.starts_with('"') && etag.ends_with('"') && etag.len() == 34);
    for inm in [
        etag.clone(),
        format!("W/{etag}"),
        format!("\"x\", {etag}"),
        "*".into(),
    ] {
        let again = send(&app, Method::GET, "/ui/main-ABCD1234.js", Some(&inm)).await;
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED, "{inm}");
        assert_eq!(header_of(&again, header::ETAG), etag);
        assert_eq!(
            header_of(&again, header::CACHE_CONTROL),
            "public, max-age=31536000, immutable"
        );
        assert_security_headers(&again);
        assert_eq!(body(again).await, b"");
    }
    let other = send(&app, Method::GET, "/ui/main-ABCD1234.js", Some("\"other\"")).await;
    assert_eq!(other.status(), StatusCode::OK);
    // Different files, different tags.
    let css = get(&app, "/ui/styles-5INURTSO.css").await;
    assert_ne!(header_of(&css, header::ETAG), etag);
}

#[tokio::test]
async fn fr_gui_001_deep_links_fall_back_to_index_html() {
    let app = app(Some(fixture()));
    let index_tag = header_of(&get(&app, "/ui/").await, header::ETAG).to_owned();
    for uri in [
        "/ui/db/x/c/y/doc/1",
        "/ui/login?next=%2Fui%2Fdb",
        "/ui/media/",
        "/ui/missing-ABCD1234.js",
    ] {
        let response = get(&app, uri).await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(
            header_of(&response, header::CONTENT_TYPE),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            header_of(&response, header::CACHE_CONTROL),
            "no-cache",
            "{uri}"
        );
        assert_eq!(header_of(&response, header::ETAG), index_tag);
        assert_eq!(body(response).await, INDEX_HTML);
    }
}

#[tokio::test]
async fn fr_gui_001_root_and_ui_redirect_to_ui_slash() {
    let app = app(Some(fixture()));
    for method in [Method::GET, Method::HEAD] {
        for uri in ["/", "/ui"] {
            let response = send(&app, method.clone(), uri, None).await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{method} {uri}");
            assert_eq!(header_of(&response, header::LOCATION), "/ui/");
            assert_security_headers(&response);
        }
    }
    let head = send(&app, Method::HEAD, "/ui/main-ABCD1234.js", None).await;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(head.headers().contains_key(header::ETAG));
    assert_eq!(body(head).await, b"");
}

#[tokio::test]
async fn fr_gui_001_path_traversal_is_rejected_before_lookup() {
    let app = app(Some(fixture()));
    for uri in [
        "/ui/../Cargo.toml",
        "/ui/a/../../Cargo.toml",
        "/ui/%2e%2e/Cargo.toml",
        "/ui/%2E%2E%2fCargo.toml",
        "/ui/..%2f..%2fCargo.toml",
        "/ui/a%5c..%5c..%5cCargo.toml",
        "/ui/./index.html",
        "/ui/%2fetc/passwd",
        "/ui/a%00b",
    ] {
        let response = get(&app, uri).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_security_headers(&response);
        assert_ne!(body(response).await, INDEX_HTML, "{uri}");
    }
}

#[tokio::test]
async fn fr_gui_001_build_without_the_gui_answers_503() {
    let app = app(Some(Arc::new(Fixture(HashMap::new()))));
    for uri in ["/ui/", "/ui/db/x", "/ui/main-ABCD1234.js"] {
        let response = get(&app, uri).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert_eq!(header_of(&response, header::CACHE_CONTROL), "no-store");
        assert_security_headers(&response);
        let text = String::from_utf8(body(response).await).unwrap();
        assert!(text.contains("not part of this build"), "{text}");
    }
}

#[tokio::test]
async fn fr_gui_001_disabled_gui_and_api_paths_answer_as_before() {
    // `[gui] enabled = false`: the routes are absent, `/ui` is an unknown path (404 RGN-1030).
    let disabled = app(None);
    for uri in ["/", "/ui", "/ui/", "/ui/index.html"] {
        let response = get(&disabled, uri).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        let json: Value = serde_json::from_slice(&body(response).await).unwrap();
        assert_eq!(json["error"]["code"], 1030, "{uri}");
    }
    // Enabled: the API keeps its headers and error bodies, and gets none of the GUI headers.
    let enabled = app(Some(fixture()));
    let ping = get(&enabled, "/api/v1/ping").await;
    assert_eq!(ping.status(), StatusCode::OK);
    assert_eq!(header_of(&ping, header::CACHE_CONTROL), "no-store");
    assert_eq!(header_of(&ping, "rgn-node-id".parse().unwrap()), "7");
    assert!(
        ping.headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .is_none()
    );
    for uri in ["/api/v1/nope", "/uix", "/other/ui", "/api/v1/ui/"] {
        let response = get(&enabled, uri).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(header_of(&response, "rgn-node-id".parse().unwrap()), "7");
        let json: Value = serde_json::from_slice(&body(response).await).unwrap();
        assert_eq!(json["error"]["code"], 1030, "{uri}");
    }
    let post = send(&enabled, Method::POST, "/api/v1/ping", None).await;
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    let json: Value = serde_json::from_slice(&body(post).await).unwrap();
    assert_eq!(json["error"]["code"], 1001);
}
