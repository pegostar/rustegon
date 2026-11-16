// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Extension point for principal resolution (PD-052, filled by the authentication layer of
//! wave 2b lane H, PD-051).
//!
//! Front ends turn transport credentials into [`RequestContext::credentials`] (gRPC: the
//! `authorization` metadata; REST: the `Authorization` header or, for the GUI, the
//! `rgn_session` cookie after the CSRF check, presented as `Bearer <token>`) and expose the
//! connection's verified client certificate through [`ConnectionInfo`]. Turning those into a
//! [`Principal`] (session lookup, API key verification, X.509 mapping) is the job of a
//! [`PrincipalResolver`] installed with [`super::Services::with_principal_resolver`]; the
//! front end then stores the result with [`RequestContext::with_principal`] before calling a
//! service. Until the authentication layer exists every caller stays anonymous
//! ([`Anonymous`]).

use std::fmt;

use rustegon_common::Error;
use rustegon_sim_api::BoxFuture;

use super::{Principal, RequestContext};
use crate::ConnectionInfo;

/// Resolves the caller of a request.
pub trait PrincipalResolver: fmt::Debug + Send + Sync + 'static {
    /// The authenticated caller of `ctx`, or `None` for an anonymous request (no credentials
    /// and no client certificate). `conn` is `None` for in-process calls and tests.
    ///
    /// # Errors
    /// RGN-4001 `Unauthenticated` / RGN-4005 `SessionExpired` for credentials that were
    /// presented but are not valid; services decide separately whether `None` is acceptable.
    fn resolve<'a>(
        &'a self,
        ctx: &'a RequestContext,
        conn: Option<&'a ConnectionInfo>,
    ) -> BoxFuture<'a, Result<Option<Principal>, Error>>;
}

/// The resolver used until authentication is wired in: every request is anonymous and
/// presented credentials are ignored.
#[derive(Debug, Default, Clone, Copy)]
pub struct Anonymous;

impl PrincipalResolver for Anonymous {
    fn resolve<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _conn: Option<&'a ConnectionInfo>,
    ) -> BoxFuture<'a, Result<Option<Principal>, Error>> {
        Box::pin(std::future::ready(Ok(None)))
    }
}
