// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST adapter of [`crate::services::TransactionService`] (protocol.md §4 "txns"; FR-API-002,
//! FR-TXN-001/006, PD-049, PD-053, PD-055).
//!
//! `POST /transactions` begins a transaction; the statements of the transaction are ordinary
//! document and query requests carrying its id in the `rgn-txn-id` header (or the query
//! body's `txnId`); `…/commit`, `…/rollback`, `…/heartbeat` and `GET /transactions/{id}`
//! (status) end, keep alive and inspect it. A transaction belongs to the principal that began
//! it on either channel, so one begun over gRPC can be committed over REST.

use axum::extract::State;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    ApiError, Ctx, JsonBody, Reply, RestState,
    extract::PathParams,
    gate,
    wire::{
        Consistency, IsolationName, PriorityName, WriteConcernName, consistency_in, isolation_in,
        millis, priority_in, write_concern_in,
    },
};
use crate::services::{BeginInput, TxnState};

/// Routes of this module.
pub(super) fn routes() -> OpenApiRouter<RestState> {
    OpenApiRouter::new()
        .routes(routes!(begin))
        .routes(routes!(status))
        .routes(routes!(commit))
        .routes(routes!(rollback))
        .routes(routes!(heartbeat))
}

/// `POST /transactions` body (every field optional: `{}` begins a default transaction).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginRequest {
    /// Isolation (default serializable).
    #[serde(default)]
    pub isolation: Option<IsolationName>,
    /// Read-only transaction.
    #[serde(default)]
    pub read_only: bool,
    /// Priority (default normal).
    #[serde(default)]
    pub priority: Option<PriorityName>,
    /// Read consistency (`follower` / `bounded_staleness` only for read-only transactions).
    #[serde(default)]
    pub consistency: Option<Consistency>,
    /// Idle timeout in milliseconds (can only shorten `txn.liveness_timeout`).
    #[serde(default)]
    pub idle_timeout_ms: Option<u32>,
    /// Write concern at commit.
    #[serde(default)]
    pub write_concern: Option<WriteConcernName>,
}

/// `POST /transactions` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BeginResponse {
    /// Transaction id (canonical lowercase UUID text); send it as `rgn-txn-id`.
    pub txn_id: String,
    /// Send a heartbeat at this interval while idle (milliseconds).
    pub heartbeat_interval_ms: u64,
}

/// Transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    /// Open.
    Active,
    /// Commit outcome being decided (RGN-2006).
    Committing,
    /// Committed.
    Committed,
    /// Rolled back or aborted.
    Aborted,
}

/// `GET /transactions/{id}` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    /// State.
    pub state: TransactionState,
    /// RGN-2002 reason when aborted (`rollback`, `conflict`, `timeout_pushed`, `killed`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_reason: Option<String>,
}

/// Empty success body of commit and rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Empty {}

/// `POST /transactions/{id}/heartbeat` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatResponse {
    /// Time until the transaction expires without another call (milliseconds).
    pub expires_in_ms: u64,
}

/// Begins an interactive transaction (`TransactionService.Begin`).
#[utoipa::path(
    post,
    path = "/api/v1/transactions",
    tag = "transactions",
    operation_id = "beginTransaction",
    request_body = BeginRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The transaction began.", body = BeginResponse))
)]
async fn begin(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    JsonBody(body): JsonBody<BeginRequest>,
) -> Result<Reply<BeginResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let input = BeginInput {
        isolation: isolation_in(body.isolation),
        read_only: body.read_only,
        priority: priority_in(body.priority),
        consistency: consistency_in(body.consistency),
        idle_timeout: body
            .idle_timeout_ms
            .map(|ms| std::time::Duration::from_millis(u64::from(ms))),
        write_concern: write_concern_in(body.write_concern),
    };
    let out = data
        .transaction
        .begin(&ctx, input)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        BeginResponse {
            txn_id: out.txn_id,
            heartbeat_interval_ms: millis(out.heartbeat_interval),
        },
        &ctx,
    ))
}

/// The state of a transaction (`TransactionService.Status`).
#[utoipa::path(
    get,
    path = "/api/v1/transactions/{txn_id}",
    tag = "transactions",
    operation_id = "getTransactionStatus",
    params(("txn_id" = String, Path, description = "Transaction id.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The state.", body = StatusResponse))
)]
async fn status(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(txn_id): PathParams<String>,
) -> Result<Reply<StatusResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let s = data
        .transaction
        .status(&ctx, &txn_id)
        .await
        .map_err(ApiError::on(&ctx))?;
    let (state, abort_reason) = match s {
        TxnState::Active => (TransactionState::Active, None),
        TxnState::Committing => (TransactionState::Committing, None),
        TxnState::Committed => (TransactionState::Committed, None),
        TxnState::Aborted { reason } => (TransactionState::Aborted, Some(reason)),
    };
    Ok(Reply::passthrough(
        StatusResponse {
            state,
            abort_reason,
        },
        &ctx,
    ))
}

/// Commits a transaction; idempotent by id (`TransactionService.Commit`).
#[utoipa::path(
    post,
    path = "/api/v1/transactions/{txn_id}/commit",
    tag = "transactions",
    operation_id = "commitTransaction",
    params(("txn_id" = String, Path, description = "Transaction id.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Committed.", body = Empty))
)]
async fn commit(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(txn_id): PathParams<String>,
) -> Result<Reply<Empty>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    data.transaction
        .commit(&ctx, &txn_id)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(Empty {}, &ctx))
}

/// Rolls a transaction back (`TransactionService.Rollback`).
#[utoipa::path(
    post,
    path = "/api/v1/transactions/{txn_id}/rollback",
    tag = "transactions",
    operation_id = "rollbackTransaction",
    params(("txn_id" = String, Path, description = "Transaction id.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Rolled back.", body = Empty))
)]
async fn rollback(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(txn_id): PathParams<String>,
) -> Result<Reply<Empty>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    data.transaction
        .rollback(&ctx, &txn_id)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(Empty {}, &ctx))
}

/// Keeps an idle transaction alive (`TransactionService.Heartbeat`).
#[utoipa::path(
    post,
    path = "/api/v1/transactions/{txn_id}/heartbeat",
    tag = "transactions",
    operation_id = "heartbeatTransaction",
    params(("txn_id" = String, Path, description = "Transaction id.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The transaction is alive.", body = HeartbeatResponse))
)]
async fn heartbeat(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(txn_id): PathParams<String>,
) -> Result<Reply<HeartbeatResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let expires = data
        .transaction
        .heartbeat(&ctx, &txn_id)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        HeartbeatResponse {
            expires_in_ms: millis(expires),
        },
        &ctx,
    ))
}
