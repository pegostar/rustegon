// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC adapter of [`crate::services::TransactionService`].

use std::time::Duration;

use rustegon_proto::v1::{
    BeginRequest, BeginResponse, CommitRequest, CommitResponse, HeartbeatRequest,
    HeartbeatResponse, RollbackRequest, RollbackResponse, StatusRequest, StatusResponse,
    TransactionState, transaction_service_server,
};
use tonic::{Request, Response, Status};

use super::{
    convert::{
        consistency_from_proto, isolation_from_proto, priority_from_proto, write_concern_from_proto,
    },
    data::{DataGrpc, millis_u32},
    metadata::{context_from_request, respond, status_of},
};
use crate::services::{BeginInput, TxnState};

/// `rustegon.v1.TransactionService` over the data services.
#[derive(Debug, Clone)]
pub struct TransactionGrpc(pub(crate) DataGrpc);

#[tonic::async_trait]
impl transaction_service_server::TransactionService for TransactionGrpc {
    async fn begin(
        &self,
        request: Request<BeginRequest>,
    ) -> Result<Response<BeginResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let input = BeginInput {
            isolation: isolation_from_proto(r.isolation).map_err(fail)?,
            read_only: r.read_only,
            priority: priority_from_proto(r.priority).map_err(fail)?,
            consistency: consistency_from_proto(r.consistency.as_ref()).map_err(fail)?,
            idle_timeout: r
                .idle_timeout_ms
                .map(|ms| Duration::from_millis(u64::from(ms))),
            write_concern: write_concern_from_proto(r.write_concern).map_err(fail)?,
        };
        let out = self
            .0
            .data()?
            .transaction
            .begin(&ctx, input)
            .await
            .map_err(fail)?;
        Ok(respond(
            BeginResponse {
                txn_id: out.txn_id,
                heartbeat_interval_ms: millis_u32(out.heartbeat_interval),
            },
            self.0.trailers(&ctx),
        ))
    }

    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let r = request.into_inner();
        self.0
            .data()?
            .transaction
            .commit(&ctx, &r.txn_id)
            .await
            .map_err(|e| status_of(&e, &ctx.trace_id_hex()))?;
        Ok(respond(CommitResponse {}, self.0.trailers(&ctx)))
    }

    async fn rollback(
        &self,
        request: Request<RollbackRequest>,
    ) -> Result<Response<RollbackResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let r = request.into_inner();
        self.0
            .data()?
            .transaction
            .rollback(&ctx, &r.txn_id)
            .await
            .map_err(|e| status_of(&e, &ctx.trace_id_hex()))?;
        Ok(respond(RollbackResponse {}, self.0.trailers(&ctx)))
    }

    async fn status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let r = request.into_inner();
        let state = self
            .0
            .data()?
            .transaction
            .status(&ctx, &r.txn_id)
            .await
            .map_err(|e| status_of(&e, &ctx.trace_id_hex()))?;
        let (state, abort_reason) = match state {
            TxnState::Active => (TransactionState::Active, None),
            TxnState::Committing => (TransactionState::Committing, None),
            TxnState::Committed => (TransactionState::Committed, None),
            TxnState::Aborted { reason } => (TransactionState::Aborted, Some(reason)),
        };
        Ok(respond(
            StatusResponse {
                state: state.into(),
                abort_reason,
            },
            self.0.trailers(&ctx),
        ))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let r = request.into_inner();
        let expires = self
            .0
            .data()?
            .transaction
            .heartbeat(&ctx, &r.txn_id)
            .await
            .map_err(|e| status_of(&e, &ctx.trace_id_hex()))?;
        Ok(respond(
            HeartbeatResponse {
                expires_in_ms: millis_u32(expires),
            },
            self.0.trailers(&ctx),
        ))
    }
}
