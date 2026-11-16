// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST adapter of [`crate::services::QueryService`] (protocol.md §4 "queries", §5.5, §6;
//! FR-API-002, FR-QL-006, PD-055).
//!
//! REST has no response streaming, so `POST /databases/{db}/query` is `Execute` with
//! `max_batches = 1`: it returns the first batch and, when more rows remain, the `cursorId`
//! that `POST /cursors/{id}/next` (`GetMore`, one batch per call) continues and
//! `DELETE /cursors/{id}` (`KillCursor`) releases; a cursor nobody continues expires after the
//! idle timeout (10 min). Ordered read queries also return a sealed `continuationToken` for
//! stateless keyset paging. Requests without `X-RGN-Timeout-Ms` get the GUI default deadline of
//! 60 s (protocol.md §5.2). Result rows are returned as they are (documents or any other
//! value); gRPC wraps non-document rows as `{"value": row}` only because `ResultBatch.docs`
//! carries documents.

use std::collections::BTreeMap;

use axum::extract::State;
use rustegon_common::{Error, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    ApiError, Ctx, JsonBody, Reply, RestState,
    extract::{PathParams, QueryParams},
    gate,
    wire::{
        Consistency, WarningJson, WriteConcernName, consistency_in, params_in, token_in, token_out,
        value_out, warnings_out, write_concern_in,
    },
};
use crate::{
    grpc::ast::statement_from_json,
    services::{
        ExecuteInput, ExplainInput, QueryOptions, QueryService, QueryText, RequestContext,
        ResultBatch,
    },
};

/// Routes of this module.
pub(super) fn routes() -> OpenApiRouter<RestState> {
    OpenApiRouter::new()
        .routes(routes!(execute))
        .routes(routes!(explain))
        .routes(routes!(get_more))
        .routes(routes!(kill_cursor))
}

/// Execution options (`ExecOptions` of protocol.md §3 without `maxBatches`, which REST fixes
/// at 1).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecOptionsJson {
    /// Preferred rows per batch.
    #[serde(default)]
    pub batch_size: Option<u32>,
    /// Server-side time limit covering every batch of the cursor (milliseconds).
    #[serde(default)]
    pub max_time_ms: Option<u64>,
    /// Read consistency outside transactions.
    #[serde(default)]
    pub consistency: Option<Consistency>,
    /// Allow blocking stages to spill (accepted; no effect in M4).
    #[serde(default)]
    pub allow_disk_use: bool,
    /// Continuation token of a previous batch (base64url).
    #[serde(default)]
    pub continuation_token: Option<String>,
    /// Write concern of data-modifying statements outside transactions.
    #[serde(default)]
    pub write_concern: Option<WriteConcernName>,
}

/// `POST /databases/{db}/query` and `…/explain` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryRequest {
    /// RGQL text (exactly one of `rgql` and `ast`).
    #[serde(default)]
    pub rgql: Option<String>,
    /// Structured statement in the JSON form of query-language.md §13.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub ast: Option<Box<RawValue>>,
    /// Parameters (`$name`, `$1`, …) as extended-JSON values.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub params: BTreeMap<String, Box<RawValue>>,
    /// Options.
    #[serde(default)]
    pub options: ExecOptionsJson,
    /// Interactive transaction (the `rgn-txn-id` header also applies).
    #[serde(default)]
    pub txn_id: Option<String>,
    /// `explain` only: `EXPLAIN ANALYZE` (executes; writes are rolled back).
    #[serde(default)]
    pub analyze: bool,
}

/// Execution statistics (last batch only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct QueryStatsJson {
    /// Rows returned by the whole result.
    pub docs_returned: u64,
    /// Documents inserted, updated or deleted.
    pub docs_affected: u64,
    /// Server time from the start of the query to this batch (µs).
    pub execution_time_us: u64,
}

/// One batch of results.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatchResponse {
    /// Rows (extended JSON): documents, or any value for `SELECT VALUE` queries.
    #[schema(value_type = Vec<Value>)]
    pub rows: Vec<Box<RawValue>>,
    /// Open cursor to continue with `POST /cursors/{id}/next`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_id: Option<String>,
    /// Sealed keyset token (ordered read queries with more rows; base64url).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
    /// Statistics (last batch only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<QueryStatsJson>,
    /// Warnings.
    pub warnings: Vec<WarningJson>,
}

/// `POST /cursors/{id}/next` query parameters.
#[derive(Debug, Clone, Copy, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct NextQuery {
    /// Rows for this and later batches.
    pub batch_size: Option<u32>,
}

/// `DELETE /cursors/{id}` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KillCursorResponse {
    /// `false` if the cursor was unknown or already closed.
    pub killed: bool,
}

/// `POST /databases/{db}/explain` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExplainResponse {
    /// The plan in explain format 1 (query-language.md §5.1).
    #[schema(value_type = Object)]
    pub plan: Box<RawValue>,
}

/// Runs `input` and returns its first batch; a cursor left open stays registered.
///
/// The stream is read to its end: with `max_batches = 1` it ends right after the first batch,
/// once the cursor has been handed to the registry. Dropping it earlier would cancel the cursor
/// (the stream's drop handler), so the client could not continue.
///
/// # Errors
/// The query's errors.
pub(crate) async fn first_batch(
    service: &QueryService,
    ctx: &RequestContext,
    input: ExecuteInput,
) -> Result<ResultBatch, Error> {
    let mut stream = service.execute(ctx, input).await?;
    let first = stream
        .next()
        .await
        .ok_or_else(|| Error::new(ErrorCode::Internal, "query produced no batch"))??;
    while let Some(more) = stream.next().await {
        // Unreachable with `max_batches = 1`; an error here still fails the request rather
        // than being dropped.
        more?;
    }
    Ok(first)
}

fn batch_out(b: &ResultBatch) -> Result<BatchResponse, Error> {
    Ok(BatchResponse {
        rows: b.rows.iter().map(value_out).collect::<Result<_, _>>()?,
        cursor_id: b.cursor_id.clone(),
        continuation_token: b.continuation_token.as_deref().map(token_out),
        stats: b.stats.as_ref().map(|s| QueryStatsJson {
            docs_returned: s.docs_returned,
            docs_affected: s.docs_affected,
            execution_time_us: s.execution_time_us,
        }),
        warnings: warnings_out(&b.warnings),
    })
}

fn query_text(r: &QueryRequest) -> Result<QueryText, Error> {
    match (&r.rgql, &r.ast) {
        (Some(text), None) => Ok(QueryText::Rgql(text.clone())),
        (None, Some(ast)) => Ok(QueryText::Ast(Box::new(statement_from_json(ast.get())?))),
        (None, None) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "the request carries no statement (rgql or ast)",
        )
        .with_detail("field", "query")),
        (Some(_), Some(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "rgql and ast are mutually exclusive",
        )
        .with_detail("field", "query")),
    }
}

fn options_in(o: &ExecOptionsJson) -> Result<QueryOptions, Error> {
    Ok(QueryOptions {
        batch_size: o.batch_size,
        max_time: o.max_time_ms.map(std::time::Duration::from_millis),
        consistency: consistency_in(o.consistency),
        allow_disk_use: o.allow_disk_use,
        max_batches: Some(1),
        continuation_token: o.continuation_token.as_deref().map(token_in).transpose()?,
        write_concern: write_concern_in(o.write_concern),
    })
}

/// Runs a statement and returns its first batch (`QueryService.Execute`, module docs).
#[utoipa::path(
    post,
    path = "/api/v1/databases/{db}/query",
    tag = "query",
    operation_id = "executeQuery",
    params(("db" = String, Path, description = "Session database for unqualified names.")),
    request_body = QueryRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The first batch.", body = BatchResponse))
)]
async fn execute(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(db): PathParams<String>,
    JsonBody(body): JsonBody<QueryRequest>,
) -> Result<Reply<BatchResponse>, ApiError> {
    let ctx = gate::with_query_deadline(&state, ctx);
    let data = gate::data(&state, &ctx)?;
    let out = async {
        if body.analyze {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "analyze applies to explain only",
            )
            .with_detail("field", "analyze"));
        }
        let input = ExecuteInput {
            database: db,
            query: query_text(&body)?,
            params: params_in(&body.params)?,
            options: options_in(&body.options)?,
            txn_id: body.txn_id.clone(),
        };
        batch_out(&first_batch(&data.query, &ctx, input).await?)
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// The plan of a statement (`QueryService.Explain`).
#[utoipa::path(
    post,
    path = "/api/v1/databases/{db}/explain",
    tag = "query",
    operation_id = "explainQuery",
    params(("db" = String, Path, description = "Session database for unqualified names.")),
    request_body = QueryRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The plan.", body = ExplainResponse))
)]
async fn explain(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(db): PathParams<String>,
    JsonBody(body): JsonBody<QueryRequest>,
) -> Result<Reply<ExplainResponse>, ApiError> {
    let ctx = gate::with_query_deadline(&state, ctx);
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let input = ExplainInput {
            database: db,
            query: query_text(&body)?,
            params: params_in(&body.params)?,
            options: options_in(&body.options)?,
            analyze: body.analyze,
            txn_id: body.txn_id.clone(),
        };
        let plan = data.query.explain(&ctx, input).await?;
        let plan = RawValue::from_string(plan)
            .map_err(|_| Error::new(ErrorCode::Internal, "plan is not JSON"))?;
        Ok::<_, Error>(ExplainResponse { plan })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// The next batch of a cursor (`QueryService.GetMore`).
#[utoipa::path(
    post,
    path = "/api/v1/cursors/{cursor_id}/next",
    tag = "query",
    operation_id = "getMore",
    params(
        ("cursor_id" = String, Path, description = "Cursor id from a previous batch."),
        NextQuery
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The next batch; no `cursorId` after the last.", body = BatchResponse))
)]
async fn get_more(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(cursor_id): PathParams<String>,
    QueryParams(q): QueryParams<NextQuery>,
) -> Result<Reply<BatchResponse>, ApiError> {
    let ctx = gate::with_query_deadline(&state, ctx);
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let batch = data.query.get_more(&ctx, &cursor_id, q.batch_size).await?;
        batch_out(&batch)
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// Closes a cursor (`QueryService.KillCursor`).
#[utoipa::path(
    delete,
    path = "/api/v1/cursors/{cursor_id}",
    tag = "query",
    operation_id = "killCursor",
    params(("cursor_id" = String, Path, description = "Cursor id.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Whether a cursor was closed.", body = KillCursorResponse))
)]
async fn kill_cursor(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(cursor_id): PathParams<String>,
) -> Result<Reply<KillCursorResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let killed = data
        .query
        .kill_cursor(&ctx, &cursor_id)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(KillCursorResponse { killed }, &ctx))
}
