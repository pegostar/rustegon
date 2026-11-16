// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The built GUI served by the REST listener under `/ui` (ADR-027, FR-GUI-001, PD-130, PD-131).
//!
//! The files come from a [`GuiAssets`] source: `rustegond` embeds `gui/dist/` with `rust-embed`;
//! tests use an in-memory map, so this crate never needs the Angular build (or Node).
//!
//! Routes ([`gui_router`], merged into the REST router by [`super::RestServer::with_gui`]); they
//! are not API operations: not in `REST_ENDPOINTS`, not in the `OpenAPI` document, not behind the
//! gate (the files are public; the GUI authenticates through `/api/v1`):
//! - `GET`/`HEAD /` and `/ui` → `303` to `/ui/`;
//! - `/ui/<file>` → the file, strong `ETag` (`If-None-Match` → `304`), `Cache-Control: public,
//!   max-age=31536000, immutable` for content-hashed names (`main-ABCD1234.js`), `no-cache`
//!   otherwise;
//! - any other `/ui/...` path → `index.html` (`no-cache`): SPA deep links such as
//!   `/ui/db/x/c/y/doc/1`;
//! - paths with `.`/`..` segments, backslashes or control characters (also percent-encoded) →
//!   `404` without lookup;
//! - no `index.html` in the source (built without the GUI) → `503` with a plain-text hint.
//!
//! Every GUI response carries [`CSP`], `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`
//! and `X-Content-Type-Options: nosniff`.

use std::{borrow::Cow, fmt::Write as _, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    middleware::map_response,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use http::{HeaderMap, HeaderValue, StatusCode, header};

/// One file of the GUI.
#[derive(Debug, Clone)]
pub struct GuiFile {
    /// The content.
    pub data: Cow<'static, [u8]>,
    /// A digest of the content (rust-embed: SHA-256), the source of the strong `ETag`.
    pub hash: [u8; 32],
}

/// Source of the GUI files, by path relative to the build output (`index.html`,
/// `main-ABCD1234.js`, `media/x.woff2`).
pub trait GuiAssets: Send + Sync + 'static {
    /// The file at `path`, if any.
    fn get(&self, path: &str) -> Option<GuiFile>;
}

/// `Content-Security-Policy` of the GUI (PD-131): no inline or foreign scripts; inline
/// styles are allowed because Angular (component styles, Material, CDK overlays) and Monaco
/// inject `<style>` elements at runtime, which a nonce cannot cover for Monaco.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                       img-src 'self' data:; font-src 'self' data:; connect-src 'self'; \
                       worker-src 'self' blob:; manifest-src 'self'; base-uri 'self'; \
                       form-action 'self'; frame-ancestors 'none'; object-src 'none'";

const INDEX: &str = "index.html";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const NOT_BUILT: &str = "The Rustegon GUI is not part of this build: build it (`npm ci && npm \
                         run build` in gui/) and rebuild rustegond. The REST API under \
                         /api/v1 is not affected.\n";

/// The `/`, `/ui` and `/ui/...` routes over `assets` (module docs).
pub fn gui_router(assets: Arc<dyn GuiAssets>) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/ui/") }))
        .route("/ui", get(|| async { Redirect::to("/ui/") }))
        .route("/ui/", get(index))
        .route("/ui/{*path}", get(asset))
        .layer(map_response(security_headers))
        .with_state(assets)
}

async fn index(State(assets): State<Arc<dyn GuiAssets>>, headers: HeaderMap) -> Response {
    serve(assets.as_ref(), "", &headers)
}

async fn asset(
    State(assets): State<Arc<dyn GuiAssets>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    serve(assets.as_ref(), &path, &headers)
}

/// `path` is percent-decoded by the extractor, so `%2e%2e` and `%5c` are seen here as `..`
/// and `\`. The embedded source is a map, but `rust-embed` reads the disk in debug builds:
/// refuse anything that could address outside the build output before any lookup.
fn is_safe(path: &str) -> bool {
    !path.starts_with('/')
        && !path.chars().any(|c| c == '\\' || c.is_control())
        && path.split('/').all(|s| s != "." && s != "..")
}

fn serve(assets: &dyn GuiAssets, path: &str, headers: &HeaderMap) -> Response {
    if !is_safe(path) {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }
    let found = if path.is_empty() {
        None
    } else {
        assets.get(path).map(|f| (path, f))
    };
    let Some((name, file)) = found.or_else(|| assets.get(INDEX).map(|f| (INDEX, f))) else {
        let mut response = (StatusCode::SERVICE_UNAVAILABLE, NOT_BUILT).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    };
    let etag = etag_of(&file.hash);
    let cache = if is_hashed(name) {
        IMMUTABLE
    } else {
        "no-cache"
    };
    let mut builder = Response::builder()
        .header(header::ETAG, &etag)
        .header(header::CACHE_CONTROL, cache);
    if matches(headers, &etag) {
        builder = builder.status(StatusCode::NOT_MODIFIED);
        return builder.body(Body::empty()).unwrap_or_default();
    }
    builder
        .header(header::CONTENT_TYPE, content_type(name))
        .body(Body::from(file.data))
        .unwrap_or_default()
}

fn etag_of(hash: &[u8; 32]) -> String {
    let mut tag = String::with_capacity(34);
    tag.push('"');
    for b in &hash[..16] {
        let _ = write!(tag, "{b:02x}");
    }
    tag.push('"');
    tag
}

/// `If-None-Match` uses the weak comparison (RFC 9110 §13.1.2): `W/` is ignored.
fn matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().trim_start_matches("W/"))
        .any(|t| t == "*" || t == etag)
}

/// Angular's production build names bundles `<name>-<8+ uppercase alphanumerics>.<ext>`
/// (`main-ABCD1234.js`, `chunk-…`, `styles-…`, `media/font-…`); their content never changes
/// under that name.
fn is_hashed(name: &str) -> bool {
    let file = name.rsplit('/').next().unwrap_or(name);
    let stem = file.split_once('.').map_or(file, |(s, _)| s);
    stem.rsplit_once('-').is_some_and(|(_, h)| {
        h.len() >= 8
            && h.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    })
}

fn content_type(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
    match ext.to_ascii_lowercase().as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

async fn security_headers(mut response: Response) -> Response {
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn fr_gui_001_hashed_names_and_safe_paths() {
        assert!(is_hashed("main-ABCD1234.js"));
        assert!(is_hashed("media/roboto-ABCDEFGH.woff2"));
        assert!(is_hashed("styles-5INURTSO.css"));
        assert!(!is_hashed("index.html"));
        assert!(!is_hashed("favicon.ico"));
        assert!(!is_hashed("main-abcd1234.js"));
        assert!(!is_hashed("app-ABC.js"));
        assert!(is_safe("db/x/c/y/doc/1"));
        assert!(is_safe("main-ABCD1234.js"));
        for bad in [
            "../x",
            "a/../../x",
            "./x",
            "a\\..\\x",
            "/etc/passwd",
            "a\0b",
            "..",
        ] {
            assert!(!is_safe(bad), "{bad:?}");
        }
        assert_eq!(etag_of(&[0xab; 32]), format!("\"{}\"", "ab".repeat(16)));
    }
}
