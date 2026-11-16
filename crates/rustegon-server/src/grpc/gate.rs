// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The gate in front of every gRPC route (security.md §1 "authn → authz on every request";
//! PD-051).
//!
//! For each request, before tonic decodes it, the gate
//! 1. builds the [`RequestContext`] from the metadata (PD-050 rules) and the connection;
//! 2. looks up the RPC's [`crate::security::RpcAccess`]; methods of services this node does not
//!    serve pass through to the router (`UNIMPLEMENTED`), a served method without a declared
//!    rule fails closed with `RGN-5001`;
//! 3. anonymous RPCs: rate limit per source IP, then the handler;
//! 4. everything else: authenticate the credentials (`RGN-4001` when missing or rejected,
//!    `RGN-4005` for an expired session), rate limit per user and IP, enforce the
//!    password-change restriction and cluster-level privileges (`RGN-4002`, audited);
//! 5. stores the context (with the principal) in the request extensions, where handlers read it
//!    with [`super::context_from_request`].
//!
//! Database- and collection-level privileges need the decoded request, so the handlers of those
//! RPCs check them with [`crate::security::Security::require`].

use http::HeaderMap;
use rustegon_common::{Error, ErrorCode};
use rustegon_security::ratelimit::LimitClass;
use tonic::metadata::MetadataMap;

use super::metadata::{context_from_metadata, status_of};
use crate::{
    security::{Access, RPC_ACCESS, RpcAccess, access_of, service_of},
    services::{ConnectionInfo, RequestContext, Services, unauthenticated},
};

/// Services served without the security layer.
const ALWAYS: &[&str] = &["rustegon.v1.SessionService"];
/// Services served only with the security layer installed.
const WITH_SECURITY: &[&str] = &[
    "rustegon.v1.AuthService",
    "rustegon.v1.AdminService",
    "rustegon.v1.BackupService",
];
/// Data-plane services (lane G, PD-053): served with the security layer *and* an engine
/// (`Services::with_engine`); every RPC needs an authenticated principal.
const DATA_PLANE: &[&str] = &[
    "rustegon.v1.QueryService",
    "rustegon.v1.DocumentService",
    "rustegon.v1.TransactionService",
    "rustegon.v1.SchemaService",
];

fn is_served(services: &Services, service: &str) -> bool {
    ALWAYS.contains(&service)
        || (services.security().is_some() && WITH_SECURITY.contains(&service))
        || (services.security().is_some()
            && services.data().is_some()
            && DATA_PLANE.contains(&service))
}

/// The rules of every RPC `services` serves over gRPC (input of the TC-SEC-001 matrix).
#[must_use]
pub fn served_rpcs(services: &Services) -> Vec<&'static RpcAccess> {
    RPC_ACCESS
        .iter()
        .filter(|r| is_served(services, r.service()))
        .collect()
}

/// Admits one request (module docs).
pub(super) async fn admit(
    services: &Services,
    path: &str,
    headers: &HeaderMap,
    conn: Option<&ConnectionInfo>,
) -> Result<RequestContext, tonic::Status> {
    let metadata = MetadataMap::from_headers(headers.clone());
    let ctx = context_from_metadata(&metadata, services.deps())?.with_peer(conn.cloned());
    let trace = ctx.trace_id_hex();
    let fail = |e: &Error| status_of(e, &trace);
    let Some(service) = service_of(path).filter(|s| is_served(services, s)) else {
        return Ok(ctx);
    };
    let Some(rule) = access_of(path) else {
        tracing::error!(
            method = path,
            service,
            "served RPC without a declared access rule"
        );
        return Err(fail(&Error::new(
            ErrorCode::Internal,
            "endpoint has no declared access rule",
        )));
    };
    let ip = conn.map(|c| c.remote_addr.ip());
    let Some(security) = services.security() else {
        // Without the security layer only anonymous RPCs are possible (deny by default).
        return if rule.access == Access::Anonymous {
            Ok(ctx)
        } else {
            Err(fail(&unauthenticated()))
        };
    };
    if rule.access == Access::Anonymous {
        security
            .rate_limit(LimitClass::Request, None, ip)
            .map_err(|e| fail(&e))?;
        return Ok(ctx);
    }
    // The same resolver as the REST front end (`services::PrincipalResolver`, installed by
    // `Services::with_security`), so both channels authenticate identically.
    let principal = services
        .principal_resolver()
        .resolve(&ctx, conn)
        .await
        .map_err(|e| fail(&e))?
        .ok_or_else(|| fail(&unauthenticated()))?;
    security
        .rate_limit(LimitClass::Request, Some(&principal.user), ip)
        .map_err(|e| fail(&e))?;
    let ctx = ctx.with_principal(Some(principal));
    security.admit(&ctx, rule).await.map_err(|e| fail(&e))?;
    Ok(ctx)
}
