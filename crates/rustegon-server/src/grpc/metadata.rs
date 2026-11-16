// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC request metadata → [`RequestContext`], and errors → `tonic::Status` (protocol.md §2,
//! §7; PD-050).

use rustegon_common::Error;
use tonic::metadata::MetadataMap;

use rustegon_security::ratelimit::RETRY_AFTER_MS;

use crate::services::{
    ConnectionInfo, RawRequestHeaders, RequestContext, ServiceDeps, TraceContext,
    context::parse_grpc_timeout, invalid_header,
};

/// `rgn-request-id` request header.
pub const REQUEST_ID: &str = "rgn-request-id";
/// `rgn-causality-token` request header and response trailer.
pub const CAUSALITY_TOKEN: &str = "rgn-causality-token";
/// `rgn-txn-id` request header.
pub const TXN_ID: &str = "rgn-txn-id";
/// W3C `traceparent` request header.
pub const TRACEPARENT: &str = "traceparent";
/// gRPC deadline header.
pub const GRPC_TIMEOUT: &str = "grpc-timeout";
/// `authorization` request header.
pub const AUTHORIZATION: &str = "authorization";
/// `rgn-node-id` response trailer.
pub const NODE_ID: &str = "rgn-node-id";
/// `rgn-server-time` response trailer (Unix milliseconds of the server wall clock).
pub const SERVER_TIME: &str = "rgn-server-time";

/// The single value of `name`, as text. Repeated headers are rejected: picking one of several
/// request ids or deadlines would make the request's meaning depend on proxy behaviour.
fn single<'a>(metadata: &'a MetadataMap, name: &str) -> Result<Option<&'a str>, Error> {
    let mut values = metadata.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(invalid_header(name, "header repeated"));
    }
    first
        .to_str()
        .map(Some)
        .map_err(|_| invalid_header(name, "value is not visible ASCII"))
}

/// Builds the request context from gRPC metadata.
///
/// # Errors
/// A `tonic::Status` carrying RGN-1001 and an `ErrorDetail` whose `trace_id` is the caller's
/// (when its `traceparent` was valid) or a fresh one, so the failure can still be correlated
/// with server logs.
#[allow(clippy::result_large_err)] // tonic::Status is the gRPC error type of every handler.
pub fn context_from_metadata(
    metadata: &MetadataMap,
    deps: &ServiceDeps,
) -> Result<RequestContext, tonic::Status> {
    let parse = || -> Result<RequestContext, Error> {
        let timeout = single(metadata, GRPC_TIMEOUT)?
            .map(parse_grpc_timeout)
            .transpose()?;
        let headers = RawRequestHeaders {
            request_id: single(metadata, REQUEST_ID)?,
            // A repeated or non-ASCII traceparent is ignored like any invalid one (W3C).
            traceparent: single(metadata, TRACEPARENT).ok().flatten(),
            timeout,
            txn_id: single(metadata, TXN_ID)?,
            causality_token: single(metadata, CAUSALITY_TOKEN)?,
            authorization: single(metadata, AUTHORIZATION)?,
        };
        RequestContext::from_headers(&headers, deps.clock.as_ref(), deps.rng.as_ref())
    };
    parse().map_err(|e| {
        let trace = single(metadata, TRACEPARENT)
            .ok()
            .flatten()
            .and_then(TraceContext::parse)
            .unwrap_or_else(|| TraceContext::generate(deps.rng.as_ref()));
        status_of(&e, &trace.trace_id.to_string())
    })
}

/// The request context of a handler: the one the gate built (with the authenticated principal,
/// PD-051) when present, otherwise parsed from the metadata (anonymous, with the connection).
///
/// # Errors
/// As [`context_from_metadata`].
#[allow(clippy::result_large_err)] // tonic::Status is the gRPC error type of every handler.
pub fn context_from_request<T>(
    request: &tonic::Request<T>,
    deps: &ServiceDeps,
) -> Result<RequestContext, tonic::Status> {
    if let Some(ctx) = request.extensions().get::<RequestContext>() {
        return Ok(ctx.clone());
    }
    Ok(context_from_metadata(request.metadata(), deps)?
        .with_peer(request.extensions().get::<ConnectionInfo>().cloned()))
}

/// Maps a service error onto the gRPC status with its packed `ErrorDetail`; the
/// `retry_after_ms` detail of `RGN-4003` also fills `ErrorDetail.retry_after_ms`.
#[must_use]
pub fn status_of(error: &Error, trace_id: &str) -> tonic::Status {
    if error.code().is_internal() {
        // Node-internal codes (protocol.md §7 "internal") must never reach clients; reaching
        // here is a routing bug. The catalog maps them to UNAVAILABLE (retryable), so the
        // client retries instead of failing; the log makes the bug visible.
        tracing::error!(code = %error.code(), "internal error code escaped to a client");
    }
    let mut detail = rustegon_proto::status::error_detail(error, trace_id);
    detail.retry_after_ms = error
        .details()
        .get(RETRY_AFTER_MS)
        .and_then(|ms| ms.parse::<u64>().ok())
        .map(|ms| u32::try_from(ms).unwrap_or(u32::MAX));
    rustegon_proto::status::to_status_with_detail(error, &detail)
}

/// Response metadata a handler wants sent as trailers, stored in the response extensions and
/// written by the connection layer (see `server::TrailerBody`).
#[derive(Debug, Clone, Default)]
pub struct ResponseTrailers {
    /// `rgn-causality-token` to return to the client.
    pub causality_token: Option<String>,
}

/// Wraps a successful response, attaching `trailers`.
pub fn respond<T>(message: T, trailers: ResponseTrailers) -> tonic::Response<T> {
    let mut response = tonic::Response::new(message);
    response.extensions_mut().insert(trailers);
    response
}
