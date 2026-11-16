// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The gate in front of every REST route: the checks the gRPC gate (`grpc::gate`) makes, with
//! the access rule of the RPC the endpoint maps to (security.md §1 "authn → authz on every
//! request"; PD-051, PD-055).
//!
//! [`admission`] runs as a route layer, after routing (it needs the matched path template) and
//! before the handler's extractors, so — as on gRPC, where the gate runs before the message is
//! decoded — a request is authenticated and admitted before its path, query or body is
//! parsed: an anonymous caller learns nothing about what a well-formed request looks like. For
//! the endpoint ([`super::endpoints::endpoint`] by method and matched path) it
//! 1. fails closed with RGN-5001 when the route has no table entry or its RPC no access rule;
//! 2. answers RGN-1030 for data-plane endpoints of a node without an engine (gRPC:
//!    `UNIMPLEMENTED`);
//! 3. anonymous rules (login, ping, server info): rate limit per source address, then the
//!    handler (which builds its own context; the login endpoints ignore credentials);
//! 4. everything else: builds the [`RequestContext`] from the headers (PD-050 rules, cookie +
//!    CSRF), resolves the principal through the shared `PrincipalResolver`, and [`admit`]s it:
//!    no security layer or no principal → RGN-4001 (deny by default), rate limit per user and
//!    address, [`crate::security::Security::admit`] (password-change restriction, cluster-level
//!    privileges, audited denials). The admitted context is handed to the handler's
//!    [`super::Ctx`] extractor through the request extensions, so the credentials are verified
//!    once per request.
//!
//! Database- and collection-level privileges are checked by the services on the resource the
//! request names, as for gRPC, so both channels authorize identically (TC-API-006,
//! TC-SEC-001).

use std::time::Duration;

use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::{AppendHeaders, IntoResponse, Response},
};
use rustegon_common::{Error, ErrorCode};
use rustegon_security::ratelimit::LimitClass;

use super::{
    ApiError, RestState,
    context::{context_from_headers, trace_id_of},
    endpoints::{endpoint, rpc},
};
use crate::{
    ConnectionInfo,
    security::{Access, access_of, service_of},
    services::{DataServices, Deadline, RequestContext, unauthenticated},
};

/// Deadline of the query endpoints when the request carries no `X-RGN-Timeout-Ms`: the GUI
/// default of protocol.md §5.2 (60 s), so an interactive query cannot run unbounded.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Services that need the data plane (`Services::with_engine`).
const DATA_PLANE: [&str; 4] = [
    "rustegon.v1.QueryService",
    "rustegon.v1.DocumentService",
    "rustegon.v1.TransactionService",
    "rustegon.v1.SchemaService",
];

/// The context admitted by [`admission`], read by the `Ctx` extractor.
#[derive(Debug, Clone)]
pub(crate) struct Admitted(pub(crate) RequestContext);

/// Admits `ctx` (principal already resolved) for the RPC `rpc` (module docs, step 4).
///
/// # Errors
/// RGN-5001 (no rule), RGN-4001, RGN-4003, RGN-4002.
pub(crate) async fn admit(
    state: &RestState,
    ctx: &RequestContext,
    rpc: &'static str,
) -> Result<(), Error> {
    let rule = access_of(rpc).ok_or_else(|| no_rule(rpc))?;
    let ip = ctx.peer().map(|p| p.remote_addr.ip());
    let Some(security) = state.services.security() else {
        return if rule.access == Access::Anonymous {
            Ok(())
        } else {
            Err(unauthenticated())
        };
    };
    if rule.access == Access::Anonymous {
        return security.rate_limit(LimitClass::Request, None, ip);
    }
    let principal = ctx.principal().ok_or_else(unauthenticated)?;
    security.rate_limit(LimitClass::Request, Some(&principal.user), ip)?;
    security.admit(ctx, rule).await
}

fn no_rule(what: &str) -> Error {
    tracing::error!(
        endpoint = what,
        "REST endpoint without a declared access rule"
    );
    Error::new(ErrorCode::Internal, "endpoint has no declared access rule")
}

/// The route layer of every documented route (module docs).
pub(crate) async fn admission(
    State(state): State<RestState>,
    matched: Option<MatchedPath>,
    mut request: Request,
    next: Next,
) -> Response {
    let deps = state.services.deps();
    let trace = || trace_id_of(request.headers(), deps).to_string();
    let path = matched.as_ref().map_or("", MatchedPath::as_str);
    let Some(ep) = endpoint(request.method().as_str(), path) else {
        return ApiError::new(no_rule(path), trace()).into_response();
    };
    let Some(rpc) = ep.rpc else {
        // The liveness probe: reads nothing, authenticates nobody.
        return next.run(request).await;
    };
    let Some(rule) = access_of(rpc) else {
        return ApiError::new(no_rule(rpc), trace()).into_response();
    };
    if service_of(rpc).is_some_and(|s| DATA_PLANE.contains(&s)) && state.services.data().is_none() {
        return ApiError::new(
            Error::new(ErrorCode::NotFound, "this node serves no data plane"),
            trace(),
        )
        .into_response();
    }
    let conn = request.extensions().get::<ConnectionInfo>().cloned();
    if rule.access == Access::Anonymous {
        if let Some(security) = state.services.security() {
            let ip = conn.as_ref().map(|c| c.remote_addr.ip());
            if let Err(e) = security.rate_limit(LimitClass::Request, None, ip) {
                return ApiError::new(e, trace()).into_response();
            }
        }
        return next.run(request).await;
    }
    let ctx = match context_from_headers(request.method(), request.headers(), deps) {
        Ok(ctx) => ctx.with_peer(conn.clone()),
        Err(e) => return refused(rpc, conn.as_ref(), e),
    };
    let principal = match state
        .services
        .principal_resolver()
        .resolve(&ctx, conn.as_ref())
        .await
    {
        Ok(p) => p,
        Err(e) => return refused(rpc, conn.as_ref(), ApiError::on(&ctx)(e)),
    };
    let ctx = ctx.with_principal(principal);
    if let Err(e) = admit(&state, &ctx, rpc).await {
        return refused(rpc, conn.as_ref(), ApiError::on(&ctx)(e));
    }
    request.extensions_mut().insert(Admitted(ctx));
    next.run(request).await
}

/// The response of a refused request. A logout refused because the session is dead (unknown,
/// expired, revoked) still clears the browser's session cookies, so the GUI is never left
/// holding one; a CSRF or header failure does not, so another site cannot log the user out.
fn refused(rpc: &str, conn: Option<&ConnectionInfo>, e: ApiError) -> Response {
    let dead_session = matches!(
        e.error().code(),
        ErrorCode::Unauthenticated | ErrorCode::SessionExpired
    );
    if rpc == rpc::LOGOUT && dead_session {
        let secure = super::login::secure_cookies(conn);
        return (AppendHeaders(super::login::clearing_cookies(secure)), e).into_response();
    }
    e.into_response()
}

/// The data-plane services (present: [`admission`] answered RGN-1030 otherwise).
///
/// # Errors
/// RGN-1030 when the node serves no data plane.
pub(crate) fn data<'a>(
    state: &'a RestState,
    ctx: &RequestContext,
) -> Result<&'a DataServices, ApiError> {
    state.services.data().ok_or_else(|| {
        ApiError::on(ctx)(Error::new(
            ErrorCode::NotFound,
            "this node serves no data plane",
        ))
    })
}

/// `ctx` with the GUI's default query deadline when the request set none (protocol.md §4
/// conventions, §5.2).
#[must_use]
pub(crate) fn with_query_deadline(state: &RestState, ctx: RequestContext) -> RequestContext {
    if ctx.deadline().is_some() {
        return ctx;
    }
    let deadline = Deadline::after(state.services.deps().clock.as_ref(), DEFAULT_QUERY_TIMEOUT);
    ctx.with_deadline(Some(deadline))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::Arc;

    use rustegon_sim_api::{OsRng, SystemClock};

    use super::*;
    use crate::{
        Executor,
        services::{NodeIdentity, ServiceDeps, Services},
    };

    fn state() -> RestState {
        let clock = Arc::new(SystemClock::new());
        let deps = ServiceDeps {
            executor: Executor::new(clock.clone(), 1),
            clock,
            rng: Arc::new(OsRng),
        };
        RestState::new(&Services::new(deps, NodeIdentity::default()))
    }

    #[test]
    fn fr_api_002_query_endpoints_default_to_the_gui_deadline() {
        let state = state();
        let deps = state.services.deps();
        let ctx = RequestContext::internal(deps.clock.as_ref(), deps.rng.as_ref());
        assert!(ctx.deadline().is_none());
        let with = with_query_deadline(&state, ctx.clone());
        let remaining = with.deadline().unwrap().remaining(deps.clock.as_ref());
        assert!(remaining <= DEFAULT_QUERY_TIMEOUT && remaining > Duration::from_secs(59));
        // A client deadline is kept as it is.
        let short = ctx.with_deadline(Some(Deadline::after(
            deps.clock.as_ref(),
            Duration::from_millis(5),
        )));
        let kept = with_query_deadline(&state, short);
        assert!(
            kept.deadline().unwrap().remaining(deps.clock.as_ref()) <= Duration::from_millis(5)
        );
    }
}
