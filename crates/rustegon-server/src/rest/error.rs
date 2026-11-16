// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST error model (protocol.md §7; PD-052): HTTP status from the error catalog and the body
//! `{"error": {code, name, message, retryable, committed?, details, traceId}}`.
//!
//! The body is built from the same `ErrorDetail` the gRPC front end packs into its status
//! ([`rustegon_proto::status::error_detail`]), so both channels report identical code, name,
//! retry and commit flags, details and trace id for the same failure (TC-API-006).

use std::collections::BTreeMap;

use axum::{
    Json,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use rustegon_common::Error;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::services::RequestContext;

/// The JSON error body of every failed REST request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    /// The error.
    pub error: ErrorInfo,
}

/// Error fields (`ErrorDetail` of protocol.md §3 plus the message).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ErrorInfo {
    /// Numeric Rustegon code (`RGN-<code>`, protocol.md §7).
    #[schema(example = 1001)]
    pub code: u32,
    /// Stable code name.
    #[schema(example = "InvalidArgument")]
    pub name: String,
    /// Human-readable message; never contains document contents or secrets.
    pub message: String,
    /// Whether the client may retry the request.
    pub retryable: bool,
    /// Present (`true`) only when the operation is known to have committed despite the error
    /// (`WriteConcernTimeout`); absent means "not known to have committed".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed: Option<bool>,
    /// Structured details (for example `header` for a malformed request header).
    pub details: BTreeMap<String, String>,
    /// W3C trace id (32 lowercase hex digits) to correlate with server logs.
    #[schema(example = "4bf92f3577b34da6a3ce929d0e0e4736")]
    pub trace_id: String,
}

impl ErrorBody {
    /// The body for `error` reported under `trace_id`.
    #[must_use]
    pub fn of(error: &Error, trace_id: &str) -> Self {
        let detail = rustegon_proto::status::error_detail(error, trace_id);
        Self {
            error: ErrorInfo {
                code: detail.code,
                name: detail.name,
                message: error.message().to_owned(),
                retryable: detail.retryable,
                committed: detail.committed,
                details: detail.details.into_iter().collect(),
                trace_id: detail.trace_id,
            },
        }
    }
}

/// A failed REST request: the service error plus the trace id to report. Handlers return
/// `Result<_, ApiError>`; [`ApiError::on`] maps a service error with the request's trace id.
#[derive(Debug)]
pub struct ApiError {
    error: Error,
    trace_id: String,
    status: Option<StatusCode>,
}

impl ApiError {
    /// Wraps `error`, reported under `trace_id`.
    #[must_use]
    pub fn new(error: Error, trace_id: impl Into<String>) -> Self {
        Self {
            error,
            trace_id: trace_id.into(),
            status: None,
        }
    }

    /// `map_err` adapter: `service.op(&ctx, …).await.map_err(ApiError::on(&ctx))?`.
    pub fn on(ctx: &RequestContext) -> impl FnOnce(Error) -> Self + use<> {
        let trace_id = ctx.trace_id_hex();
        move |error| Self::new(error, trace_id)
    }

    /// Overrides the HTTP status for transport-level failures that have no catalog code of
    /// their own (405 Method Not Allowed); the body keeps the catalog code.
    #[must_use]
    pub(crate) fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    /// The service error.
    #[must_use]
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// The reported trace id.
    #[must_use]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// The HTTP status of the response.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status.unwrap_or_else(|| status_of(&self.error))
    }
}

/// The HTTP status of an error: the catalog's `http_status` (protocol.md §7).
#[must_use]
pub fn status_of(error: &Error) -> StatusCode {
    // Catalog statuses are generated from proto/errors.yaml and checked against protocol.md
    // by TC-API-005, so the fallback is unreachable unless the catalog is broken.
    StatusCode::from_u16(error.code().http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.error.code().is_internal() {
            // Node-internal codes (protocol.md §7 "internal") must never reach clients; reaching
            // here is a routing bug. The catalog maps them to 503 (retryable), so the client
            // retries instead of failing; the log makes the bug visible.
            tracing::error!(code = %self.error.code(), "internal error code escaped to a client");
        }
        let status = self.status();
        let mut response =
            (status, Json(ErrorBody::of(&self.error, &self.trace_id))).into_response();
        response
            .extensions_mut()
            .insert(super::observability::ResponseCode(self.error.code()));
        response
    }
}
