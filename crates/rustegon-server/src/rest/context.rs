// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! HTTP request headers → [`RequestContext`] (protocol.md §2 metadata rules, §5.2; PD-050,
//! PD-052).
//!
//! The REST front end uses the gRPC header names (`rgn-request-id`, `traceparent`,
//! `rgn-txn-id`, `rgn-causality-token`, `authorization`; HTTP names are case-insensitive) and
//! the same validation through [`RequestContext::from_headers`]; only the deadline header
//! differs: `X-RGN-Timeout-Ms` (decimal milliseconds) instead of `grpc-timeout`. Browser
//! clients may authenticate with the `rgn_session` cookie instead of `authorization` (see
//! [`super::auth`]).

use std::time::Duration;

use axum::extract::FromRequestParts;
use http::{HeaderMap, Method, request::Parts};
use rustegon_common::Error;

use super::{ApiError, RestState, auth};
use crate::{
    ConnectionInfo,
    services::{
        RawRequestHeaders, RequestContext, ServiceDeps, TraceContext, TraceId, invalid_header,
    },
};

/// `X-RGN-Timeout-Ms` request header: the client timeout in decimal milliseconds (protocol.md
/// §5.2), the REST equivalent of `grpc-timeout`.
pub const TIMEOUT_HEADER: &str = "x-rgn-timeout-ms";
/// `rgn-request-id` request header.
pub const REQUEST_ID: &str = "rgn-request-id";
/// W3C `traceparent` request header.
pub const TRACEPARENT: &str = "traceparent";
/// `rgn-txn-id` request header.
pub const TXN_ID: &str = "rgn-txn-id";
/// `rgn-causality-token` request header and response header.
pub const CAUSALITY_TOKEN: &str = "rgn-causality-token";
/// `rgn-node-id` response header.
pub const NODE_ID: &str = "rgn-node-id";
/// `rgn-server-time` response header (Unix milliseconds of the server wall clock).
pub const SERVER_TIME: &str = "rgn-server-time";

/// Largest number of digits accepted in `X-RGN-Timeout-Ms`: 8 digits (≈ 27.8 hours), the same
/// bound gRPC puts on `grpc-timeout`, so both channels accept the same range of practical
/// deadlines and a huge value cannot overflow deadline arithmetic.
const MAX_TIMEOUT_DIGITS: usize = 8;

/// Parses an `X-RGN-Timeout-Ms` value: 1–8 ASCII digits, milliseconds. `0` is accepted and
/// yields an already expired deadline (useful to probe deadline handling), as `0m` does for
/// `grpc-timeout`.
///
/// # Errors
/// RGN-1001 for any other shape (sign, spaces, units, fractions, more digits).
pub fn parse_timeout_ms(value: &str) -> Result<Duration, Error> {
    if value.is_empty()
        || value.len() > MAX_TIMEOUT_DIGITS
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid_header(
            TIMEOUT_HEADER,
            "expected 1 to 8 decimal digits (milliseconds)",
        ));
    }
    let millis: u64 = value
        .parse()
        .map_err(|_| invalid_header(TIMEOUT_HEADER, "invalid number"))?;
    Ok(Duration::from_millis(millis))
}

/// The single value of header `name`, as text. Repeated headers are rejected, as on gRPC:
/// picking one of several request ids or deadlines would make the request's meaning depend on
/// proxy behaviour.
pub(crate) fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, Error> {
    let mut values = headers.get_all(name).iter();
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

/// The trace id to report for a request that failed before (or without) a context: the
/// caller's when its `traceparent` is valid, else a fresh one.
pub(crate) fn trace_id_of(headers: &HeaderMap, deps: &ServiceDeps) -> TraceId {
    single(headers, TRACEPARENT)
        .ok()
        .flatten()
        .and_then(TraceContext::parse)
        .map_or_else(
            || TraceContext::generate(deps.rng.as_ref()).trace_id,
            |t| t.trace_id,
        )
}

/// Builds the request context from HTTP headers.
///
/// Credentials: an `Authorization` header is used as is (`Bearer <session token>` or
/// `ApiKey rgn_…`). Without one, the `rgn_session` cookie is accepted for browser clients,
/// after the CSRF check for state-changing methods, and presented to the authentication layer
/// as `Bearer <token>`, because cookie and header carry the same session token (security.md
/// §2.1). The cookie is ignored when an `Authorization` header is present: header credentials
/// cannot be attached by a cross-site request, so they need no CSRF token.
///
/// # Errors
/// RGN-1001 for malformed or repeated headers, RGN-4002 for a failed CSRF check; the error
/// carries the caller's trace id (or a generated one).
pub fn context_from_headers(
    method: &Method,
    headers: &HeaderMap,
    deps: &ServiceDeps,
) -> Result<RequestContext, ApiError> {
    let parse = || -> Result<RequestContext, Error> {
        let timeout = single(headers, TIMEOUT_HEADER)?
            .map(parse_timeout_ms)
            .transpose()?;
        let authorization = single(headers, http::header::AUTHORIZATION.as_str())?;
        let cookie_credentials = match authorization {
            Some(_) => None,
            None => match auth::session_cookie(headers)? {
                Some(token) => {
                    auth::check_csrf(method, headers, &token)?;
                    Some(format!("Bearer {token}"))
                }
                None => None,
            },
        };
        let raw = RawRequestHeaders {
            request_id: single(headers, REQUEST_ID)?,
            // A repeated or non-ASCII traceparent is ignored like any invalid one (W3C).
            traceparent: single(headers, TRACEPARENT).ok().flatten(),
            timeout,
            txn_id: single(headers, TXN_ID)?,
            causality_token: single(headers, CAUSALITY_TOKEN)?,
            authorization: authorization.or(cookie_credentials.as_deref()),
        };
        RequestContext::from_headers(&raw, deps.clock.as_ref(), deps.rng.as_ref())
    };
    parse().map_err(|e| ApiError::new(e, trace_id_of(headers, deps).to_string()))
}

/// Extractor for the [`RequestContext`] of a REST request, with the caller resolved by the
/// installed [`crate::services::PrincipalResolver`]. Every handler that calls a service takes
/// it, so header validation and authentication cannot be forgotten on a new endpoint.
#[derive(Debug, Clone)]
pub struct Ctx(pub RequestContext);

impl FromRequestParts<RestState> for Ctx {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &RestState,
    ) -> Result<Self, Self::Rejection> {
        // Routes behind the gate were authenticated there: reuse that context, so credentials
        // are verified (and API keys rate limited) once per request.
        if let Some(super::gate::Admitted(ctx)) = parts.extensions.remove() {
            return Ok(Self(ctx));
        }
        let services = &state.services;
        let ctx = context_from_headers(&parts.method, &parts.headers, services.deps())?;
        let conn = parts.extensions.get::<ConnectionInfo>();
        let principal = services
            .principal_resolver()
            .resolve(&ctx, conn)
            .await
            .map_err(ApiError::on(&ctx))?;
        Ok(Self(ctx.with_principal(principal).with_peer(conn.cloned())))
    }
}

/// The [`RequestContext`] of a request that must not authenticate: the login endpoints
/// (PD-055). Credentials are ignored — neither `Authorization` nor the `rgn_session` cookie is
/// read — so a browser holding an expired or revoked session cookie can still log in again
/// (with [`Ctx`] the stale cookie would fail the request with RGN-4005, and its CSRF check
/// with RGN-4002, before the login handler runs). Every other header follows the PD-050 rules.
pub(crate) fn anonymous_context(
    headers: &HeaderMap,
    deps: &ServiceDeps,
) -> Result<RequestContext, ApiError> {
    let parse = || -> Result<RequestContext, Error> {
        let timeout = single(headers, TIMEOUT_HEADER)?
            .map(parse_timeout_ms)
            .transpose()?;
        let raw = RawRequestHeaders {
            request_id: single(headers, REQUEST_ID)?,
            traceparent: single(headers, TRACEPARENT).ok().flatten(),
            timeout,
            txn_id: single(headers, TXN_ID)?,
            causality_token: single(headers, CAUSALITY_TOKEN)?,
            authorization: None,
        };
        RequestContext::from_headers(&raw, deps.clock.as_ref(), deps.rng.as_ref())
    };
    parse().map_err(|e| ApiError::new(e, trace_id_of(headers, deps).to_string()))
}

/// Extractor for the credential-less context of the login endpoints ([`anonymous_context`]),
/// with the connection attached (rate limits per source address, SCRAM channel binding).
#[derive(Debug, Clone)]
pub(crate) struct AnonCtx(pub RequestContext);

impl FromRequestParts<RestState> for AnonCtx {
    type Rejection = ApiError;

    #[allow(clippy::unused_async_trait_impl)] // The trait is async; this extractor never waits.
    async fn from_request_parts(
        parts: &mut Parts,
        state: &RestState,
    ) -> Result<Self, Self::Rejection> {
        let ctx = anonymous_context(&parts.headers, state.services.deps())?;
        let conn = parts.extensions.get::<ConnectionInfo>().cloned();
        Ok(Self(ctx.with_peer(conn)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::HeaderValue;
    use rustegon_common::ErrorCode;
    use rustegon_sim_api::{OsRng, SystemClock};

    use super::*;
    use crate::Executor;

    fn deps() -> ServiceDeps {
        let clock = Arc::new(SystemClock::new());
        ServiceDeps {
            executor: Executor::new(clock.clone(), 1),
            clock,
            rng: Arc::new(OsRng),
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(*k, HeaderValue::from_static(v));
        }
        map
    }

    fn header_error(method: &Method, pairs: &[(&'static str, &'static str)]) -> ApiError {
        context_from_headers(method, &headers(pairs), &deps()).unwrap_err()
    }

    #[test]
    fn fr_api_002_timeout_ms_parse_accepts_digits_only() {
        assert_eq!(parse_timeout_ms("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_timeout_ms("250").unwrap(), Duration::from_millis(250));
        assert_eq!(
            parse_timeout_ms("99999999").unwrap(),
            Duration::from_millis(99_999_999)
        );
        for bad in [
            "",
            "123456789",
            "-1",
            "+1",
            "1.5",
            "10ms",
            " 10",
            "10 ",
            "1e3",
        ] {
            let err = parse_timeout_ms(bad).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(err.details().get("header").unwrap(), TIMEOUT_HEADER);
        }
    }

    #[test]
    fn fr_api_002_headers_follow_the_pd_050_rules() {
        let ctx = context_from_headers(
            &Method::GET,
            &headers(&[
                ("rgn-request-id", "0190a6e2-3c4d-7abc-8def-0123456789ab"),
                (
                    "traceparent",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                ),
                ("x-rgn-timeout-ms", "1500"),
                ("rgn-txn-id", "txn-1"),
                ("rgn-causality-token", "AAEC"),
                ("authorization", "ApiKey rgn_abc_def"),
            ]),
            &deps(),
        )
        .unwrap();
        assert!(ctx.has_client_request_id());
        assert_eq!(ctx.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.deadline().unwrap().timeout, Duration::from_millis(1500));
        assert_eq!(ctx.txn_id(), Some("txn-1"));
        assert_eq!(ctx.causality_token(), Some("AAEC"));
        assert_eq!(ctx.credentials().unwrap().expose(), "ApiKey rgn_abc_def");

        for (pairs, name) in [
            (
                vec![
                    ("rgn-request-id", "0190a6e2-3c4d-7abc-8def-0123456789ab"),
                    ("rgn-request-id", "0190a6e2-3c4d-7abc-8def-0123456789ac"),
                ],
                "rgn-request-id",
            ),
            (vec![("rgn-request-id", "not-a-uuid")], "rgn-request-id"),
            (vec![("x-rgn-timeout-ms", "soon")], TIMEOUT_HEADER),
            (
                vec![("x-rgn-timeout-ms", "1"), ("x-rgn-timeout-ms", "2")],
                TIMEOUT_HEADER,
            ),
            (vec![("rgn-txn-id", "two words")], "rgn-txn-id"),
            (vec![("rgn-causality-token", "")], "rgn-causality-token"),
            (vec![("authorization", "")], "authorization"),
        ] {
            let err = header_error(&Method::GET, &pairs);
            assert_eq!(err.error().code(), ErrorCode::InvalidArgument, "{name}");
            assert_eq!(err.error().details().get("header").unwrap(), name);
            assert_eq!(err.trace_id().len(), 32);
        }

        // The caller's trace id is kept on errors; an invalid traceparent is ignored.
        let err = header_error(
            &Method::GET,
            &[
                ("rgn-request-id", "x"),
                (
                    "traceparent",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                ),
            ],
        );
        assert_eq!(err.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        let ctx =
            context_from_headers(&Method::GET, &headers(&[("traceparent", "bogus")]), &deps())
                .unwrap();
        assert!(ctx.trace().parent_span_id.is_none());
    }

    #[test]
    fn fr_api_002_grpc_timeout_is_not_a_rest_header() {
        // REST has its own deadline header; `grpc-timeout` is not interpreted.
        let ctx = context_from_headers(&Method::GET, &headers(&[("grpc-timeout", "1S")]), &deps())
            .unwrap();
        assert!(ctx.deadline().is_none());
    }
}
