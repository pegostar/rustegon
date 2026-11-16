// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC adapter of [`crate::services::DocumentService`].

use rustegon_common::Error;
use rustegon_proto::{
    status::error_detail,
    v1::{
        self as pb, BulkWriteRequest, BulkWriteResponse, DeleteRequest, DeleteResponse,
        GetManyRequest, GetManyResponse, GetRequest, GetResponse, InsertRequest, InsertResponse,
        ReplaceRequest, ReplaceResponse, UpdateRequest, UpdateResponse, UpsertRequest,
        UpsertResponse, bulk_operation, document_service_server,
    },
};
use tonic::{Request, Response, Status};

use super::{
    ast::update_ops_from_proto,
    convert::{
        consistency_from_proto, document_from_proto, document_to_proto, opt_document_to_proto,
        params_from_proto, return_document_from_proto, value_from_proto, warning_to_proto,
        write_options_from_proto, write_result_to_proto,
    },
    data::DataGrpc,
    metadata::{context_from_request, respond, status_of},
};
use crate::services::{BulkOp, ReadOptions, Target, WriteOptions, WriteOutput};

/// `rustegon.v1.DocumentService` over the data services.
#[derive(Debug, Clone)]
pub struct DocumentGrpc(pub(crate) DataGrpc);

fn target(database: String, collection: String, txn_id: Option<String>) -> Target {
    Target {
        database,
        collection,
        txn_id,
    }
}

fn write_opts(o: Option<&pb::WriteOptions>) -> Result<WriteOptions, Error> {
    Ok(WriteOptions {
        write_concern: write_options_from_proto(o)?,
    })
}

type Images = (
    bool,
    bool,
    bool,
    Option<pb::WriteResult>,
    Option<pb::Document>,
    Vec<pb::Warning>,
);

fn images(out: &WriteOutput) -> Result<Images, Error> {
    Ok((
        out.matched,
        out.modified,
        out.inserted,
        out.result.as_ref().map(write_result_to_proto).transpose()?,
        opt_document_to_proto(out.document.as_ref())?,
        out.warnings.iter().map(warning_to_proto).collect(),
    ))
}

fn bulk_op(op: pb::BulkOperation) -> Result<BulkOp, Error> {
    let missing = || {
        Error::new(
            rustegon_common::ErrorCode::InvalidArgument,
            "bulk operation without op",
        )
        .with_detail("field", "operations")
    };
    Ok(match op.op.ok_or_else(missing)? {
        bulk_operation::Op::Insert(i) => BulkOp::Insert {
            document: document_from_proto(i.document.as_ref(), "document")?,
        },
        bulk_operation::Op::Replace(r) => BulkOp::Replace {
            id: value_from_proto(r.id.as_ref(), "id")?,
            document: document_from_proto(r.document.as_ref(), "document")?,
            if_rev: r.if_rev,
        },
        bulk_operation::Op::Update(u) => BulkOp::Update {
            id: value_from_proto(u.id.as_ref(), "id")?,
            operations: update_ops_from_proto(&u.operations)?,
            if_rev: u.if_rev,
        },
        bulk_operation::Op::Upsert(u) => BulkOp::Upsert {
            document: document_from_proto(u.document.as_ref(), "document")?,
        },
        bulk_operation::Op::Delete(d) => BulkOp::Delete {
            id: value_from_proto(d.id.as_ref(), "id")?,
            if_rev: d.if_rev,
        },
    })
}

#[tonic::async_trait]
impl document_service_server::DocumentService for DocumentGrpc {
    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let id = value_from_proto(r.id.as_ref(), "id").map_err(fail)?;
        let options = ReadOptions {
            consistency: consistency_from_proto(r.consistency.as_ref()).map_err(fail)?,
        };
        let doc = self
            .0
            .data()?
            .document
            .get(
                &ctx,
                &target(r.database, r.collection, r.txn_id),
                id,
                options,
            )
            .await
            .and_then(|d| opt_document_to_proto(d.as_ref()))
            .map_err(fail)?;
        Ok(respond(
            GetResponse { document: doc },
            self.0.trailers(&ctx),
        ))
    }

    async fn get_many(
        &self,
        request: Request<GetManyRequest>,
    ) -> Result<Response<GetManyResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let ids = r
            .ids
            .iter()
            .map(|v| value_from_proto(Some(v), "ids"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(fail)?;
        let options = ReadOptions {
            consistency: consistency_from_proto(r.consistency.as_ref()).map_err(fail)?,
        };
        let docs = self
            .0
            .data()?
            .document
            .get_many(
                &ctx,
                &target(r.database, r.collection, r.txn_id),
                ids,
                options,
            )
            .await
            .and_then(|docs| {
                docs.iter()
                    .map(document_to_proto)
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(fail)?;
        Ok(respond(
            GetManyResponse { documents: docs },
            self.0.trailers(&ctx),
        ))
    }

    async fn insert(
        &self,
        request: Request<InsertRequest>,
    ) -> Result<Response<InsertResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let docs = r
            .documents
            .iter()
            .map(|d| document_from_proto(Some(d), "documents"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(fail)?;
        let options = write_opts(r.options.as_ref()).map_err(fail)?;
        let out = self
            .0
            .data()?
            .document
            .insert(
                &ctx,
                &target(r.database, r.collection, r.txn_id),
                docs,
                options,
            )
            .await
            .map_err(fail)?;
        let results = out
            .results
            .iter()
            .map(write_result_to_proto)
            .collect::<Result<Vec<_>, _>>()
            .map_err(fail)?;
        Ok(respond(
            InsertResponse {
                results,
                warnings: out.warnings.iter().map(warning_to_proto).collect(),
            },
            self.0.trailers(&ctx),
        ))
    }

    async fn replace(
        &self,
        request: Request<ReplaceRequest>,
    ) -> Result<Response<ReplaceResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let id = value_from_proto(r.id.as_ref(), "id").map_err(fail)?;
        let doc = document_from_proto(r.document.as_ref(), "document").map_err(fail)?;
        let ret = return_document_from_proto(r.return_document).map_err(fail)?;
        let options = write_opts(r.options.as_ref()).map_err(fail)?;
        let out = self
            .0
            .data()?
            .document
            .replace(
                &ctx,
                &target(r.database, r.collection, r.txn_id),
                id,
                doc,
                r.if_rev,
                ret,
                options,
            )
            .await
            .and_then(|o| images(&o))
            .map_err(fail)?;
        let (matched, _, _, result, document, warnings) = out;
        Ok(respond(
            ReplaceResponse {
                matched,
                result,
                document,
                warnings,
            },
            self.0.trailers(&ctx),
        ))
    }

    async fn update(
        &self,
        request: Request<UpdateRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let id = value_from_proto(r.id.as_ref(), "id").map_err(fail)?;
        let ops = update_ops_from_proto(&r.operations).map_err(fail)?;
        let ret = return_document_from_proto(r.return_document).map_err(fail)?;
        let params = params_from_proto(&r.params).map_err(fail)?;
        let options = write_opts(r.options.as_ref()).map_err(fail)?;
        let out = self
            .0
            .data()?
            .document
            .update(
                &ctx,
                &target(r.database, r.collection, r.txn_id),
                id,
                ops,
                r.if_rev,
                ret,
                params,
                options,
            )
            .await
            .and_then(|o| images(&o))
            .map_err(fail)?;
        let (matched, modified, _, result, document, warnings) = out;
        Ok(respond(
            UpdateResponse {
                matched,
                modified,
                result,
                document,
                warnings,
            },
            self.0.trailers(&ctx),
        ))
    }

    async fn upsert(
        &self,
        request: Request<UpsertRequest>,
    ) -> Result<Response<UpsertResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let doc = document_from_proto(r.document.as_ref(), "document").map_err(fail)?;
        let ret = return_document_from_proto(r.return_document).map_err(fail)?;
        let options = write_opts(r.options.as_ref()).map_err(fail)?;
        let out = self
            .0
            .data()?
            .document
            .upsert(
                &ctx,
                &target(r.database, r.collection, r.txn_id),
                doc,
                r.if_rev,
                ret,
                options,
            )
            .await
            .and_then(|o| images(&o))
            .map_err(fail)?;
        let (_, _, inserted, result, document, warnings) = out;
        Ok(respond(
            UpsertResponse {
                inserted,
                result,
                document,
                warnings,
            },
            self.0.trailers(&ctx),
        ))
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let fail = |e| status_of(&e, &ctx.trace_id_hex());
        let r = request.into_inner();
        let id = value_from_proto(r.id.as_ref(), "id").map_err(fail)?;
        let options = write_opts(r.options.as_ref()).map_err(fail)?;
        let out = self
            .0
            .data()?
            .document
            .delete(
                &ctx,
                &target(r.database, r.collection, r.txn_id),
                id,
                r.if_rev,
                r.return_document,
                options,
            )
            .await
            .map_err(fail)?;
        Ok(respond(
            DeleteResponse {
                deleted: out.deleted,
                document: opt_document_to_proto(out.document.as_ref()).map_err(fail)?,
            },
            self.0.trailers(&ctx),
        ))
    }

    async fn bulk_write(
        &self,
        request: Request<BulkWriteRequest>,
    ) -> Result<Response<BulkWriteResponse>, Status> {
        let ctx = context_from_request(&request, self.0.services.deps())?;
        let trace_id = ctx.trace_id_hex();
        let fail = |e| status_of(&e, &trace_id);
        let r = request.into_inner();
        let ops = r
            .operations
            .into_iter()
            .map(bulk_op)
            .collect::<Result<Vec<_>, _>>()
            .map_err(fail)?;
        let params = params_from_proto(&r.params).map_err(fail)?;
        let options = write_opts(r.options.as_ref()).map_err(fail)?;
        let out = self
            .0
            .data()?
            .document
            .bulk_write(
                &ctx,
                &target(r.database, r.collection, r.txn_id),
                ops,
                r.ordered,
                params,
                options,
            )
            .await
            .map_err(fail)?;
        Ok(respond(
            BulkWriteResponse {
                inserted: out.inserted,
                matched: out.matched,
                modified: out.modified,
                deleted: out.deleted,
                errors: out
                    .errors
                    .iter()
                    .map(|e| pb::BulkWriteError {
                        index: e.index,
                        error: Some(error_detail(&e.to_error(), &trace_id)),
                        message: e.message.clone(),
                    })
                    .collect(),
                warnings: out.warnings.iter().map(warning_to_proto).collect(),
            },
            self.0.trailers(&ctx),
        ))
    }
}
