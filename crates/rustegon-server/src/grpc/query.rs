// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC adapter of [`crate::services::QueryService`]: the `Execute` stream wraps the
//! service's [`ExecuteStream`]; dropping the response stream (client cancel, connection loss)
//! drops it, which cancels the batch in progress and closes the cursor (protocol.md §3).

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use rustegon_proto::v1::{
    ExecuteRequest, ExecuteResponse, ExplainRequest, ExplainResponse, GetMoreRequest,
    GetMoreResponse, KillCursorRequest, KillCursorResponse, execute_request, explain_request,
    query_service_server,
};
use tonic::{Request, Response, Status, codegen::tokio_stream::Stream};

use super::{
    ast::statement_from_proto,
    convert::{batch_to_proto, params_from_proto, query_options_from_proto},
    data::DataGrpc,
    metadata::{context_from_request, respond, status_of},
};
use crate::services::{ExecuteInput, ExecuteStream, ExplainInput, QueryText};

/// `rustegon.v1.QueryService` over the data services.
#[derive(Debug, Clone)]
pub struct QueryGrpc(pub(crate) DataGrpc);

/// The `Execute` response stream.
pub struct ExecuteResponses {
    inner: ExecuteStream,
    trace_id: String,
}

impl Stream for ExecuteResponses {
    type Item = Result<ExecuteResponse, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.inner.poll_next(cx).map(|item| {
            item.map(|r| {
                r.and_then(batch_to_proto)
                    .map(|b| ExecuteResponse { batch: Some(b) })
                    .map_err(|e| status_of(&e, &this.trace_id))
            })
        })
    }
}

fn query_text(
    rgql: Option<String>,
    ast: Option<&rustegon_proto::v1::AstStatement>,
) -> Result<QueryText, rustegon_common::Error> {
    match (rgql, ast) {
        (Some(text), _) => Ok(QueryText::Rgql(text)),
        (None, Some(ast)) => Ok(QueryText::Ast(Box::new(statement_from_proto(ast)?))),
        (None, None) => Err(rustegon_common::Error::new(
            rustegon_common::ErrorCode::InvalidArgument,
            "the request carries no statement (rgql or ast)",
        )
        .with_detail("field", "query")),
    }
}

#[tonic::async_trait]
impl query_service_server::QueryService for QueryGrpc {
    type ExecuteStream = ExecuteResponses;

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let trace_id = ctx.trace_id_hex();
        let fail = |e| status_of(&e, &trace_id);
        let r = request.into_inner();
        let query = match r.query {
            Some(execute_request::Query::Rgql(t)) => query_text(Some(t), None),
            Some(execute_request::Query::Ast(a)) => query_text(None, Some(&a)),
            None => query_text(None, None),
        }
        .map_err(fail)?;
        let input = ExecuteInput {
            database: r.database,
            query,
            params: params_from_proto(&r.params).map_err(fail)?,
            options: query_options_from_proto(r.options.as_ref()).map_err(fail)?,
            txn_id: r.txn_id,
        };
        let stream = self
            .0
            .data()?
            .query
            .execute(&ctx, input)
            .await
            .map_err(fail)?;
        Ok(respond(
            ExecuteResponses {
                inner: stream,
                trace_id: trace_id.clone(),
            },
            self.0.trailers(&ctx),
        ))
    }

    async fn get_more(
        &self,
        request: Request<GetMoreRequest>,
    ) -> Result<Response<GetMoreResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let batch = self
            .0
            .data()?
            .query
            .get_more(&ctx, &r.cursor_id, r.batch_size)
            .await
            .and_then(batch_to_proto)
            .map_err(fail)?;
        Ok(respond(
            GetMoreResponse { batch: Some(batch) },
            self.0.trailers(&ctx),
        ))
    }

    async fn kill_cursor(
        &self,
        request: Request<KillCursorRequest>,
    ) -> Result<Response<KillCursorResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let r = request.into_inner();
        let killed = self
            .0
            .data()?
            .query
            .kill_cursor(&ctx, &r.cursor_id)
            .await
            .map_err(|e| status_of(&e, &ctx.trace_id_hex()))?;
        Ok(respond(
            KillCursorResponse { killed },
            self.0.trailers(&ctx),
        ))
    }

    async fn explain(
        &self,
        request: Request<ExplainRequest>,
    ) -> Result<Response<ExplainResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let query = match r.query {
            Some(explain_request::Query::Rgql(t)) => query_text(Some(t), None),
            Some(explain_request::Query::Ast(a)) => query_text(None, Some(&a)),
            None => query_text(None, None),
        }
        .map_err(fail)?;
        let input = ExplainInput {
            database: r.database,
            query,
            params: params_from_proto(&r.params).map_err(fail)?,
            options: query_options_from_proto(r.options.as_ref()).map_err(fail)?,
            analyze: r.analyze,
            txn_id: r.txn_id,
        };
        let plan_json = self
            .0
            .data()?
            .query
            .explain(&ctx, input)
            .await
            .map_err(fail)?;
        Ok(respond(
            ExplainResponse { plan_json },
            self.0.trailers(&ctx),
        ))
    }
}
