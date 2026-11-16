// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST adapter of [`crate::services::SessionService`] and the liveness probe (protocol.md
//! §2, §4; PD-052). This module is the template for every REST adapter.

use axum::extract::State;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{ApiError, Ctx, Reply, RestState};

/// `GET /api/v1/ping` response (empty object, like gRPC `PingResponse`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PingResponse {}

/// `GET /api/v1/server-info` response (gRPC `GetServerInfoResponse`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfoResponse {
    /// Server version (semver of the release).
    #[schema(example = "0.1.0")]
    pub server_version: String,
    /// Protocol version `1.<minor>` (protocol.md §9).
    #[schema(example = "1.0")]
    pub protocol_version: String,
    /// Capability flags of this node (protocol.md §9).
    pub features: Vec<String>,
    /// Client endpoints (`host:port`) of the cluster nodes known to this node.
    pub node_addresses: Vec<String>,
}

/// `GET /api/v1/health/live` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LiveResponse {
    /// Always `live`.
    #[schema(example = "live")]
    pub status: String,
}

/// Routes of this module, documented by their `#[utoipa::path]` annotations.
pub(super) fn routes() -> OpenApiRouter<RestState> {
    OpenApiRouter::new()
        .routes(routes!(ping))
        .routes(routes!(server_info))
        .routes(routes!(live))
}

/// Liveness round trip (gRPC `SessionService.Ping`); honours the request deadline.
#[utoipa::path(
    get,
    path = "/api/v1/ping",
    tag = "session",
    operation_id = "ping",
    responses((status = 200, description = "The server answered.", body = PingResponse))
)]
async fn ping(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
) -> Result<Reply<PingResponse>, ApiError> {
    state
        .services
        .session()
        .ping(&ctx)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(PingResponse {}, &ctx))
}

/// Versions, capability flags and topology hint (gRPC `SessionService.GetServerInfo`).
#[utoipa::path(
    get,
    path = "/api/v1/server-info",
    tag = "session",
    operation_id = "getServerInfo",
    responses((status = 200, description = "Server versions and features.", body = ServerInfoResponse))
)]
async fn server_info(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
) -> Result<Reply<ServerInfoResponse>, ApiError> {
    let info = state
        .services
        .session()
        .server_info(&ctx)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        ServerInfoResponse {
            server_version: info.server_version,
            protocol_version: info.protocol_version,
            features: info.features,
            node_addresses: info.node_addresses,
        },
        &ctx,
    ))
}

/// Liveness probe for orchestrators (protocol.md §4 "no auth"): answers as long as the REST
/// listener serves requests. It deliberately reads no request header and no credentials, so a
/// probe can never fail on authentication.
#[utoipa::path(
    get,
    path = "/api/v1/health/live",
    tag = "health",
    operation_id = "getLiveness",
    responses((status = 200, description = "The process is serving requests.", body = LiveResponse))
)]
async fn live() -> Reply<LiveResponse> {
    Reply::new(LiveResponse {
        status: "live".to_owned(),
    })
}
