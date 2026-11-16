// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC adapter of [`crate::services::AuthService`] (auth.proto, protocol.md §8).
//!
//! `Authenticate` is one bidirectional stream: the first request selects the mechanism. X.509
//! answers `success` at once. SCRAM answers the `challenge` (server-first), then a task waits
//! for the client-final message — bounded by [`HANDSHAKE_TIMEOUT`] and the request deadline, so
//! an abandoned handshake does not pin server state — and answers `success` or ends the
//! stream with the error status.

use std::time::Duration;

use rustegon_common::{Error, ErrorCode};
use rustegon_proto::v1::{
    AuthMechanism, AuthSuccess, AuthenticateRequest, AuthenticateResponse, LogoutRequest,
    LogoutResponse, WhoAmIRequest, WhoAmIResponse, auth_service_server, authenticate_response,
};
use rustegon_security::authn::session::SessionKind;
use tokio::sync::mpsc;
use tonic::{
    Request, Response, Status, Streaming, codegen::tokio_stream::wrappers::ReceiverStream,
};

use super::{
    admin::{role_ref_to_grant, unix_ms},
    metadata::{ResponseTrailers, context_from_request, respond, status_of},
};
use crate::services::{
    RequestContext, Services,
    auth::{AuthSuccess as Success, ClientInfo, LoginMechanism},
    unauthenticated,
};

/// Longest wait for the client-final message of a SCRAM handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// `rustegon.v1.AuthService` over [`Services`].
#[derive(Debug, Clone)]
pub struct AuthGrpc {
    services: Services,
}

impl AuthGrpc {
    /// Creates the adapter.
    #[must_use]
    pub fn new(services: Services) -> Self {
        Self { services }
    }
}

fn success(s: Success) -> AuthenticateResponse {
    AuthenticateResponse {
        step: Some(authenticate_response::Step::Success(AuthSuccess {
            server_final: s.server_final.into_bytes(),
            session_token: s.session_token.expose().to_string(),
            expires_at_unix_ms: s.expires_at.map_or(0, unix_ms),
            user: s.user,
            must_change_password: s.must_change_password,
        })),
    }
}

fn client_info(r: &AuthenticateRequest) -> ClientInfo {
    r.client_info
        .as_ref()
        .map(|c| ClientInfo {
            driver_name: c.driver_name.clone(),
            driver_version: c.driver_version.clone(),
            application: c.application.clone(),
        })
        .unwrap_or_default()
}

fn utf8(payload: Vec<u8>) -> Result<String, Error> {
    // A non-UTF-8 SASL message is malformed like any other unparsable one.
    String::from_utf8(payload).map_err(|_| unauthenticated())
}

type Stream = ReceiverStream<Result<AuthenticateResponse, Status>>;

#[tonic::async_trait]
impl auth_service_server::AuthService for AuthGrpc {
    type AuthenticateStream = Stream;

    async fn authenticate(
        &self,
        request: Request<Streaming<AuthenticateRequest>>,
    ) -> Result<Response<Stream>, Status> {
        let ctx = context_from_request(&request, self.services.deps())?;
        let trace = ctx.trace_id_hex();
        let mut inbound = request.into_inner();
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| status_of(&unauthenticated(), &trace))?;
        let (tx, rx) = mpsc::channel(2);
        let info = client_info(&first);
        let auth = self.services.auth().clone();
        match AuthMechanism::try_from(first.mechanism) {
            Ok(AuthMechanism::X509) => {
                let done = auth
                    .certificate(&ctx, SessionKind::Driver, &info)
                    .await
                    .map_err(|e| status_of(&e, &trace))?;
                // The receiver is alive (owned below), so the send cannot fail.
                let _ = tx.send(Ok(success(done))).await;
            }
            Ok(AuthMechanism::ScramSha256) => {
                let client_first = utf8(first.payload).map_err(|e| status_of(&e, &trace))?;
                let (pending, server_first) = auth
                    .scram_start(&ctx, &client_first, SessionKind::Driver, &info)
                    .await
                    .map_err(|e| status_of(&e, &trace))?;
                let _ = tx
                    .send(Ok(AuthenticateResponse {
                        step: Some(authenticate_response::Step::Challenge(
                            server_first.into_bytes(),
                        )),
                    }))
                    .await;
                let clock = std::sync::Arc::clone(&self.services.deps().clock);
                tokio::spawn(async move {
                    let timeout = ctx
                        .deadline()
                        .map_or(HANDSHAKE_TIMEOUT, |d| d.remaining(clock.as_ref()))
                        .min(HANDSHAKE_TIMEOUT);
                    let next = tokio::select! {
                        next = inbound.message() => next,
                        () = clock.sleep(timeout) => Ok(None),
                    };
                    let result = match next {
                        Ok(Some(msg)) => match utf8(msg.payload) {
                            Ok(client_final) => auth
                                .scram_finish(&ctx, pending, &client_final)
                                .await
                                .map(success),
                            Err(e) => Err(e),
                        },
                        // Timeout or a client that went away: nothing to answer usefully.
                        Ok(None) | Err(_) => Err(unauthenticated()),
                    };
                    let _ = tx
                        .send(result.map_err(|e| status_of(&e, &ctx.trace_id_hex())))
                        .await;
                });
            }
            _ => {
                let e = Error::new(ErrorCode::InvalidArgument, "unsupported mechanism")
                    .with_detail("field", "mechanism");
                return Err(status_of(&e, &trace));
            }
        }
        Ok(respond(
            ReceiverStream::new(rx),
            ResponseTrailers::default(),
        ))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        let ctx = context_from_request(&request, self.services.deps())?;
        self.services
            .auth()
            .logout(&ctx)
            .await
            .map_err(|e| status_of(&e, &ctx.trace_id_hex()))?;
        Ok(respond(LogoutResponse {}, trailers(&ctx)))
    }

    async fn who_am_i(
        &self,
        request: Request<WhoAmIRequest>,
    ) -> Result<Response<WhoAmIResponse>, Status> {
        let ctx = context_from_request(&request, self.services.deps())?;
        let me = self
            .services
            .auth()
            .who_am_i(&ctx)
            .await
            .map_err(|e| status_of(&e, &ctx.trace_id_hex()))?;
        let mechanism = match me.mechanism {
            LoginMechanism::Unspecified => AuthMechanism::Unspecified,
            LoginMechanism::Scram => AuthMechanism::ScramSha256,
            LoginMechanism::X509 => AuthMechanism::X509,
            LoginMechanism::ApiKey => AuthMechanism::ApiKey,
        };
        Ok(respond(
            WhoAmIResponse {
                user: me.user,
                roles: me.roles.iter().map(|r| role_ref_to_grant(r)).collect(),
                mechanism: mechanism as i32,
                expires_at_unix_ms: me.expires_at.map_or(0, unix_ms),
                api_key_id: me.api_key_id,
            },
            trailers(&ctx),
        ))
    }
}

fn trailers(ctx: &RequestContext) -> ResponseTrailers {
    ResponseTrailers {
        causality_token: ctx.causality_token().map(str::to_owned),
    }
}
