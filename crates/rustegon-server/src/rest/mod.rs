// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST front end `/api/v1` (protocol.md §4, §7; FR-API-002, FR-API-003; PD-052).
//!
//! An axum router over the same [`Services`] as the gRPC front end (protocol.md §1), served
//! by [`RestServer`] on its own listener (port 7780) with HTTP/1.1 and HTTP/2 (ALPN), and
//! described by the `OpenAPI` 3.1 document [`openapi()`] checked in as
//! `api/openapi/rustegon-v1.yaml`.
//!
//! # Endpoints (PD-052, PD-055)
//! Session and liveness (`session.rs`), readiness and `GET /metrics` (`observability.rs`,
//! PD-059), authentication (`login.rs`: SCRAM in two calls, password
//! login, logout, identity, own password), administration (`admin.rs`), backups and
//! snapshots (`backup.rs`, PD-077), transactions
//! (`transactions.rs`), queries and cursors (`query.rs`), schema (`schema.rs`) and documents
//! (`documents.rs`), with the JSON conversions in `wire.rs`. [`REST_ENDPOINTS`] lists each
//! endpoint with the RPC whose access rule the gate (`gate.rs`) applies before the handler
//! runs, so REST authorizes exactly like gRPC.
//!
//! # Adding an endpoint
//! 1. In the service's module under `rest/` (copy `session.rs`), write an `async fn` handler
//!    annotated with `#[utoipa::path(<method>, path = "/api/v1/…", tag = "<service>",
//!    operation_id = "<camelCase>", responses((status = 200, body = <Response>)))]` (plus
//!    `request_body`, `params` for path/query parameters and `security(...)` when the
//!    operation requires a caller). Request and response types are camelCase serde structs
//!    deriving `ToSchema`; documents travel as extended JSON (`rustegon_doc::to_json` /
//!    `JsonMode`), not `RDoc`.
//! 2. List the endpoint in [`REST_ENDPOINTS`] with the RPC whose access rule protects it: the
//!    gate (`gate.rs`) authenticates and admits every request by that rule before the handler's
//!    extractors run (a route missing from the table fails closed with RGN-5001). Take [`Ctx`]
//!    (the admitted context) and `State<RestState>` (`gate::data` for the data-plane
//!    services), call the service with `.map_err(ApiError::on(&ctx))?`, and return [`Reply`]
//!    (attach the causality token the operation produced). Read JSON bodies with [`JsonBody`],
//!    path and query parameters with [`PathParams`]/[`QueryParams`], so malformed input fails
//!    with the RGN error body instead of axum's plain-text rejection.
//! 3. Register it with `.routes(routes!(handler))` in the module's `routes()` and merge that
//!    router in `rest::api()`. A route added this way is in the router and in the `OpenAPI` document by
//!    construction; never use axum's plain `.route()` for API endpoints.
//! 4. Bless the checked-in document (`RGN_OPENAPI_BLESS=1 cargo nextest run -p rustegon-server
//!    tc_api_002`) and review the diff: removing or renaming anything is a breaking change
//!    (protocol.md §9).
//!
//! The built GUI is served next to the API under `/ui` (`gui.rs`, ADR-027, PD-130), outside
//! the gate, the endpoint table and the `OpenAPI` document.
//!
//! Common request headers, response headers and the error response are added to every
//! operation by [`openapi()`]; the response headers themselves (`rgn-node-id`,
//! `rgn-server-time`, security headers) by the router middleware.

mod admin;
pub(crate) mod auth;
mod backup;
mod context;
pub(crate) mod documents;
pub mod endpoints;
mod error;
mod extract;
mod gate;
mod gui;
mod login;
mod observability;
mod openapi;
mod query;
mod reply;
mod schema;
mod server;
mod session;
mod transactions;
pub(crate) mod wire;

use std::sync::Arc;

use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    middleware::map_response_with_state,
    response::Response,
};
pub use context::{
    CAUSALITY_TOKEN, Ctx, NODE_ID, REQUEST_ID, SERVER_TIME, TIMEOUT_HEADER, TRACEPARENT, TXN_ID,
    context_from_headers, parse_timeout_ms,
};
pub use endpoints::{REST_ENDPOINTS, RestEndpoint};
pub use error::{ApiError, ErrorBody, ErrorInfo, status_of};
pub use extract::{JsonBody, PathParams, QueryParams};
pub use gate::DEFAULT_QUERY_TIMEOUT;
pub use gui::{CSP, GuiAssets, GuiFile, gui_router};
use http::{HeaderMap, HeaderValue, StatusCode, header};
pub use login::{HANDSHAKE_TIMEOUT, MAX_HANDSHAKES};
pub use observability::ReadyResponse;
pub use openapi::{openapi, openapi_yaml};
pub use reply::Reply;
use rustegon_common::{Error, ErrorCode};
use rustegon_sim_api::Clock;
pub use server::{RestServer, RestServerOptions};
pub use session::{LiveResponse, PingResponse, ServerInfoResponse};
use utoipa::OpenApi as _;
use utoipa_axum::router::OpenApiRouter;
pub use wire::IF_MATCH;

pub use self::auth::{CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, csrf_token, is_safe_method};
use crate::{listener::server_time_ms, services::Services};

/// Default request body limit (64 MiB), the gRPC `max_message_bytes`: a bulk write may carry
/// 48 MiB of operations (protocol.md §5.4) plus JSON overhead.
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// State shared by every REST handler.
#[derive(Clone)]
pub struct RestState {
    /// The service layer (the same instance the gRPC front end uses).
    pub services: Services,
    node_id: HeaderValue,
    clock: Arc<dyn Clock>,
    handshakes: Arc<login::Handshakes>,
}

impl RestState {
    /// State over `services`.
    #[must_use]
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
            node_id: HeaderValue::from(services.node().node_id),
            clock: Arc::clone(&services.deps().clock),
            handshakes: Arc::new(login::Handshakes::new(
                Arc::clone(&services.deps().clock),
                Arc::clone(&services.deps().rng),
            )),
        }
    }

    /// SCRAM handshakes waiting for their `scram/finish` call (tests, diagnostics).
    #[must_use]
    pub fn pending_handshakes(&self) -> usize {
        self.handshakes.len()
    }
}

impl std::fmt::Debug for RestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestState")
            .field("services", &self.services)
            .finish_non_exhaustive()
    }
}

/// Every documented route, with its `OpenAPI` paths. Wave 2b services merge their module
/// routers here.
pub(crate) fn api() -> OpenApiRouter<RestState> {
    OpenApiRouter::with_openapi(openapi::ApiDoc::openapi())
        .merge(session::routes())
        .merge(observability::routes())
        .merge(login::routes())
        .merge(admin::routes())
        .merge(backup::routes())
        .merge(transactions::routes())
        .merge(query::routes())
        .merge(schema::routes())
        .merge(documents::routes())
}

/// The complete REST router over `services`: documented routes, JSON error fallbacks, body
/// limit and response headers. Serve it with [`RestServer`], or call it in-process (tests)
/// through `tower::ServiceExt::oneshot`.
pub fn router(services: &Services, max_body_bytes: usize) -> Router {
    let state = RestState::new(services);
    let (routes, _) = api().split_for_parts();
    routes
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            gate::admission,
        ))
        // Outside the gate, so refused requests are counted too (PD-059).
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            observability::count,
        ))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(map_response_with_state(state.clone(), response_headers))
        .with_state(state)
}

/// Adds the headers every REST response carries: the node headers (gRPC sends them as
/// trailers; HTTP/1.1 trailers are unusable from browsers, so REST uses headers) and
/// API-hardening headers (no caching of API data by shared caches or browsers, no MIME
/// sniffing).
async fn response_headers(State(state): State<RestState>, mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(NODE_ID, state.node_id.clone());
    headers.insert(
        SERVER_TIME,
        HeaderValue::from(server_time_ms(state.clock.as_ref())),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Unknown path: RGN-1030 `NotFound` with the error body (the path is not echoed).
async fn not_found(State(state): State<RestState>, headers: HeaderMap) -> ApiError {
    count_unmatched(&state, ErrorCode::NotFound);
    let trace = context::trace_id_of(&headers, state.services.deps());
    ApiError::new(
        Error::new(ErrorCode::NotFound, "no such REST endpoint"),
        trace.to_string(),
    )
}

/// Counts a request that matched no documented route under the one `unknown` series (the
/// counting route layer only sees matched routes; the path is never a label).
fn count_unmatched(state: &RestState, code: ErrorCode) {
    state
        .services
        .metrics()
        .start(
            crate::metrics::Route::rest("", None),
            &state.services.deps().clock,
        )
        .finish(crate::metrics::Outcome::Error(code));
}

/// Known path, wrong method: HTTP 405 with RGN-1001 `InvalidArgument` in the body (the
/// catalog has no method code; the status keeps HTTP semantics for generic clients).
async fn method_not_allowed(State(state): State<RestState>, headers: HeaderMap) -> ApiError {
    count_unmatched(&state, ErrorCode::InvalidArgument);
    let trace = context::trace_id_of(&headers, state.services.deps());
    ApiError::new(
        Error::new(
            ErrorCode::InvalidArgument,
            "HTTP method not allowed for this endpoint",
        ),
        trace.to_string(),
    )
    .with_status(StatusCode::METHOD_NOT_ALLOWED)
}
