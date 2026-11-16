// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Request body extraction with Rustegon errors (PD-052).

use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Path, Query, Request, rejection::JsonRejection},
};
use http::{StatusCode, request::Parts};
use rustegon_common::{Error, ErrorCode};
use serde::de::DeserializeOwned;

use super::{ApiError, RestState, context::trace_id_of};

/// A JSON request body. Unlike `axum::Json`, failures produce the RGN error body:
/// - a body over the router's limit → RGN-1002 `DocumentTooLarge` (413);
/// - a missing `Content-Type: application/json`, invalid JSON or a body that does not match the
///   expected type → RGN-1001 `InvalidArgument` (400), detail `body` = `content-type` /
///   `syntax` / `data`.
///
/// The message never quotes the body: serde's messages can contain input values, and request
/// bodies may hold document contents (coding-standards: no data in errors or logs).
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonBody<T>(pub T);

impl<T> FromRequest<RestState> for JsonBody<T>
where
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &RestState) -> Result<Self, Self::Rejection> {
        let trace = trace_id_of(request.headers(), state.services.deps());
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::new(
                rejection_error(&rejection),
                trace.to_string(),
            )),
        }
    }
}

/// URL path parameters. Unlike `axum::extract::Path`, a failure (a segment that is not valid
/// UTF-8 after percent-decoding, or does not parse as the expected type) produces the RGN error
/// body: RGN-1001 with detail `path`; the message does not quote the path.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathParams<T>(pub T);

impl<T> FromRequestParts<RestState> for PathParams<T>
where
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &RestState,
    ) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(_) => Err(ApiError::new(
                Error::new(ErrorCode::InvalidArgument, "invalid path parameter")
                    .with_detail("path", "invalid"),
                trace_id_of(&parts.headers, state.services.deps()).to_string(),
            )),
        }
    }
}

/// URL query parameters. Unlike `axum::extract::Query`, a malformed query string, an unknown
/// parameter or a value of the wrong type produces RGN-1001 with detail `query` (the message
/// does not quote the value).
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryParams<T>(pub T);

impl<T> FromRequestParts<RestState> for QueryParams<T>
where
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &RestState,
    ) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(_) => Err(ApiError::new(
                Error::new(
                    ErrorCode::InvalidArgument,
                    "query parameters do not match the expected schema",
                )
                .with_detail("query", "invalid"),
                trace_id_of(&parts.headers, state.services.deps()).to_string(),
            )),
        }
    }
}

fn rejection_error(rejection: &JsonRejection) -> Error {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return Error::new(
            ErrorCode::DocumentTooLarge,
            "request body exceeds the size limit",
        );
    }
    let (kind, message) = match rejection {
        JsonRejection::MissingJsonContentType(_) => (
            "content-type",
            "expected a `Content-Type: application/json` body",
        ),
        JsonRejection::JsonSyntaxError(_) => ("syntax", "request body is not valid JSON"),
        JsonRejection::JsonDataError(_) => {
            ("data", "request body does not match the expected schema")
        }
        _ => ("body", "request body could not be read"),
    };
    Error::new(ErrorCode::InvalidArgument, message).with_detail("body", kind)
}
