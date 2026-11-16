// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC adapter of [`crate::services::SessionService`].

use rustegon_proto::v1::{
    GetServerInfoRequest, GetServerInfoResponse, PingRequest, PingResponse, session_service_server,
};
use tonic::{Request, Response, Status};

use super::metadata::{ResponseTrailers, context_from_metadata, respond, status_of};
use crate::services::{RequestContext, Services};

/// `rustegon.v1.SessionService` over [`Services`].
#[derive(Debug, Clone)]
pub struct SessionGrpc {
    services: Services,
}

impl SessionGrpc {
    /// Creates the adapter.
    #[must_use]
    pub fn new(services: Services) -> Self {
        Self { services }
    }
}

/// Session calls do not move the client's causal position, so the token it sent (if any) is
/// returned unchanged: a client always holds the newest token it was given.
fn passthrough(ctx: &RequestContext) -> ResponseTrailers {
    ResponseTrailers {
        causality_token: ctx.causality_token().map(str::to_owned),
    }
}

#[tonic::async_trait]
impl session_service_server::SessionService for SessionGrpc {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let ctx = context_from_metadata(request.metadata(), self.services.deps())?;
        self.services
            .session()
            .ping(&ctx)
            .await
            .map_err(|e| status_of(&e, &ctx.trace_id_hex()))?;
        Ok(respond(PingResponse {}, passthrough(&ctx)))
    }

    async fn get_server_info(
        &self,
        request: Request<GetServerInfoRequest>,
    ) -> Result<Response<GetServerInfoResponse>, Status> {
        let ctx = context_from_metadata(request.metadata(), self.services.deps())?;
        let info = self
            .services
            .session()
            .server_info(&ctx)
            .await
            .map_err(|e| status_of(&e, &ctx.trace_id_hex()))?;
        Ok(respond(
            GetServerInfoResponse {
                server_version: info.server_version,
                protocol_version: info.protocol_version,
                features: info.features,
                node_addresses: info.node_addresses,
            },
            passthrough(&ctx),
        ))
    }
}
