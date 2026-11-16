// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `GET /metrics` (Prometheus scrape) and `GET /api/v1/health/ready` (readiness probe)
//! (protocol.md §1, §4; FR-OPS-001, FR-OPS-003; PD-059), plus the router middleware that counts
//! every REST request for `rustegon_requests_total` and `rustegon_request_duration_seconds`.
//!
//! `/metrics` is served at the root, not under `/api/v1`: protocol.md §1 names it so, and it is
//! the default `metrics_path` of Prometheus scrape configurations. It is authorized like any
//! endpoint, through the gate with the HTTP-only rule `GET /metrics` (`cluster_view`, held by
//! the `monitor` role; a scrape API key is an API key of a user with that role).

use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{Ctx, RestState};
use crate::{
    health::{self, ReadyStatus},
    metrics::{self, Outcome, Route},
};

/// `GET /api/v1/health/ready` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReadyResponse {
    /// `ready` (200), or why not (503): `starting`, `draining`, `unhealthy`.
    #[schema(example = "ready")]
    pub status: String,
}

/// Routes of this module.
pub(super) fn routes() -> OpenApiRouter<RestState> {
    OpenApiRouter::new()
        .routes(routes!(ready))
        .routes(routes!(scrape))
}

/// Readiness probe (protocol.md §4 "no auth"; FR-OPS-003): 200 while the node serves with a
/// healthy store, 503 while starting, draining for shutdown, or with a store that refuses
/// writes. Reads no request header and no credentials, like the liveness probe.
#[utoipa::path(
    get,
    path = "/api/v1/health/ready",
    tag = "health",
    operation_id = "getReadiness",
    responses(
        (status = 200, description = "The node serves traffic.", body = ReadyResponse),
        (status = 503, description = "The node should not receive traffic (starting, draining, store unhealthy).", body = ReadyResponse)
    )
)]
async fn ready(State(state): State<RestState>) -> Response {
    let status = health::status(&state.services);
    let code = if status == ReadyStatus::Ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        axum::Json(ReadyResponse {
            status: status.as_str().to_owned(),
        }),
    )
        .into_response()
}

/// Node metrics in the `OpenMetrics` text format (protocol.md §1; FR-OPS-001). Requires
/// `cluster_view` (the `monitor` role), by session or API key.
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "monitoring",
    operation_id = "getMetrics",
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((
        status = 200,
        description = "OpenMetrics 1.0 text exposition (families of system-overview.md §7).",
        content_type = "application/openmetrics-text; version=1.0.0; charset=utf-8",
        body = String
    ))
)]
async fn scrape(State(state): State<RestState>, Ctx(_ctx): Ctx) -> Response {
    let body = metrics::render(&state.services).await;
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(metrics::CONTENT_TYPE),
    );
    response
}

/// The RGN code of an error response, stored by `ApiError::into_response` so the counting
/// middleware labels errors without parsing bodies.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResponseCode(pub(crate) rustegon_common::ErrorCode);

/// Route layer counting every request to a documented route (outermost layer, so requests
/// refused by the gate are counted too). A request whose future is dropped (client went away)
/// is counted as `cancelled` by the timer's guard.
pub(super) async fn count(
    State(state): State<RestState>,
    matched: Option<MatchedPath>,
    request: Request,
    next: Next,
) -> Response {
    let route = Route::rest(
        request.method().as_str(),
        matched.as_ref().map(MatchedPath::as_str),
    );
    let timer = state
        .services
        .metrics()
        .start(route, &state.services.deps().clock);
    let response = next.run(request).await;
    timer.finish(outcome_of(&response));
    response
}

/// The outcome label of a REST response.
pub(super) fn outcome_of(response: &Response) -> Outcome {
    // Every failure is an `ApiError` (the extractors convert axum's rejections), so a response
    // without an RGN code is one the handler produced on purpose; the only non-2xx one is the
    // readiness probe's 503, which is a successful probe.
    response
        .extensions()
        .get::<ResponseCode>()
        .map_or(Outcome::Ok, |ResponseCode(code)| Outcome::Error(*code))
}
