// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Successful REST responses: a JSON body plus the per-operation response headers that gRPC
//! sends as trailers (`rgn-causality-token`). The node headers (`rgn-node-id`,
//! `rgn-server-time`) are added to every response by the router middleware.

use axum::{
    Json,
    response::{IntoResponse, Response},
};
use http::HeaderValue;
use serde::Serialize;

use super::context::CAUSALITY_TOKEN;
use crate::services::RequestContext;

/// A JSON response with optional `rgn-causality-token`.
#[derive(Debug, Clone)]
pub struct Reply<T> {
    body: T,
    causality_token: Option<String>,
}

impl<T> Reply<T> {
    /// `body` without a causality token.
    pub fn new(body: T) -> Self {
        Self {
            body,
            causality_token: None,
        }
    }

    /// `body` with the causality token produced by the operation.
    #[must_use]
    pub fn with_causality_token(mut self, token: Option<String>) -> Self {
        self.causality_token = token;
        self
    }

    /// `body` for an operation that does not move the client's causal position: the token the
    /// client sent (if any) is returned unchanged, as on gRPC, so a client always holds the
    /// newest token it was given.
    pub fn passthrough(body: T, ctx: &RequestContext) -> Self {
        Self::new(body).with_causality_token(ctx.causality_token().map(str::to_owned))
    }
}

impl<T: Serialize> IntoResponse for Reply<T> {
    fn into_response(self) -> Response {
        let mut response = Json(self.body).into_response();
        // Tokens are validated as visible ASCII on the way in and produced by the server
        // otherwise, so conversion cannot fail in practice; a value that did would be dropped
        // rather than turn a successful operation into an error.
        if let Some(token) = self
            .causality_token
            .and_then(|t| HeaderValue::from_str(&t).ok())
        {
            response.headers_mut().insert(CAUSALITY_TOKEN, token);
        }
        response
    }
}
