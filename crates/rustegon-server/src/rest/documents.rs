// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST adapter of [`crate::services::DocumentService`] (protocol.md §4 "documents"; FR-API-002,
//! FR-DOC-*, PD-055).
//!
//! - `GET …/documents` lists a collection page by page: an RGQL query
//!   ``FROM `coll` [WHERE (filter)] ORDER BY …`` through the query service (the caller needs
//!   `find`, checked per statement like any query), one batch of `limit` rows, a keyset
//!   `continuationToken` for the next page. The filter is parsed alone as an RGQL expression
//!   and re-printed in canonical form, so it can only ever be the `WHERE` condition; sort keys
//!   are field paths, quoted. The page is stateless: the cursor the query leaves is closed.
//! - `GET/PUT/PATCH/DELETE …/documents/{id}`: `Get`, `Replace` (`?upsert=true`: `Upsert`),
//!   `Update`, `Delete`. `If-Match: "<_rev>"` is `if_rev` (mismatch: RGN-2009, 412) and the
//!   response carries the document's `_rev` as `ETag`. A missing document is 404 RGN-1030 on
//!   `GET` (gRPC returns an empty response; REST uses the HTTP resource semantics).
//! - `POST …/documents` (`Insert`), `POST …/get-many` (`GetMany`), `POST …/bulk` (`BulkWrite`).

use std::collections::BTreeMap;

use axum::extract::State;
use http::HeaderMap;
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_query::{parse_expr, print_expr};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    ApiError, Ctx, ErrorInfo, JsonBody, Reply, RestState,
    extract::{PathParams, QueryParams},
    gate,
    wire::{
        Consistency, ConsistencyQuery, ReturnDocumentName, WarningJson, WriteConcernName,
        WriteResultJson, consistency_in, document_in, document_out, etag_headers, id_from_path,
        if_match, params_in, return_document_in, rev_of, token_in, token_out, value_in, value_out,
        warnings_out, write_concern_in, write_result_out,
    },
};
use crate::{
    grpc::ast::update_ops_from_json,
    services::{
        BulkOp, ExecuteInput, QueryOptions, QueryText, ReadOptions, Target, WriteOptions,
        WriteOutput,
    },
};

/// Default page size of `GET …/documents`.
const DEFAULT_PAGE: u32 = 100;
/// Largest page size of `GET …/documents`.
const MAX_PAGE: u32 = 10_000;
/// Longest accepted list filter (bytes), so the parser's work per request stays bounded
/// independently of the body limit (it travels in the URL).
const MAX_FILTER_LEN: usize = 16 * 1024;
/// Most sort keys of a list request.
const MAX_SORT_KEYS: usize = 32;

/// Routes of this module.
pub(super) fn routes() -> OpenApiRouter<RestState> {
    OpenApiRouter::new()
        .routes(routes!(list_documents, insert_documents))
        .routes(routes!(
            get_document,
            replace_document,
            update_document,
            delete_document
        ))
        .routes(routes!(get_many))
        .routes(routes!(bulk_write))
}

fn target(db: String, coll: String) -> Target {
    Target {
        database: db,
        collection: coll,
        txn_id: None,
    }
}

fn invalid(field: &str, message: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, message.to_owned()).with_detail("field", field)
}

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

/// `GET …/documents` query parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// RGQL boolean expression the documents must satisfy (the `WHERE` condition).
    pub filter: Option<String>,
    /// Comma-separated field paths; a leading `-` sorts descending. Default `_id`.
    pub sort: Option<String>,
    /// Page size (1–10 000, default 100).
    pub limit: Option<u32>,
    /// Token of the previous page (base64url).
    pub continuation_token: Option<String>,
    /// Read consistency level.
    pub consistency: Option<super::wire::ConsistencyLevel>,
    /// Staleness bound in milliseconds.
    pub max_staleness_ms: Option<u32>,
}

/// One page of documents.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DocumentPage {
    /// Documents (extended JSON) in sort order.
    #[schema(value_type = Vec<Object>)]
    pub documents: Vec<Box<RawValue>>,
    /// Token for the next page; absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
    /// Warnings.
    pub warnings: Vec<WarningJson>,
}

/// Write options of the single-document writes.
#[derive(Debug, Clone, Copy, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct WriteQuery {
    /// Write concern (default majority).
    pub write_concern: Option<WriteConcernName>,
    /// Document image returned by `PUT`/`PATCH` (default none).
    pub return_document: Option<ReturnDocumentName>,
    /// `PUT` only: insert the document when no document has the id (`Upsert`).
    pub upsert: Option<bool>,
}

/// Write options of `DELETE …/documents/{id}`.
#[derive(Debug, Clone, Copy, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct DeleteQuery {
    /// Write concern (default majority).
    pub write_concern: Option<WriteConcernName>,
    /// Return the deleted document.
    pub return_document: Option<bool>,
}

/// Write options in a body.
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteOptionsJson {
    /// Write concern (default majority).
    #[serde(default)]
    pub write_concern: Option<WriteConcernName>,
}

/// A document.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DocumentResponse {
    /// The document (extended JSON).
    #[schema(value_type = Object)]
    pub document: Box<RawValue>,
}

/// `POST …/documents` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InsertRequest {
    /// Documents to insert atomically (extended JSON; `_id` generated when absent).
    #[schema(value_type = Vec<Object>)]
    pub documents: Vec<Box<RawValue>>,
    /// Options.
    #[serde(default)]
    pub options: WriteOptionsJson,
}

/// `POST …/documents` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InsertResponse {
    /// One result per document, in request order.
    pub results: Vec<WriteResultJson>,
    /// Warnings.
    pub warnings: Vec<WarningJson>,
}

/// `PUT`/`PATCH …/documents/{id}` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WriteResponse {
    /// A document with the id existed.
    pub matched: bool,
    /// The document changed (`PATCH`).
    pub modified: bool,
    /// The document was inserted (`PUT ?upsert=true`).
    pub inserted: bool,
    /// Write result when something was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<WriteResultJson>,
    /// The requested image (`returnDocument`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub document: Option<Box<RawValue>>,
    /// Warnings.
    pub warnings: Vec<WarningJson>,
}

/// `PATCH …/documents/{id}` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRequest {
    /// Update operators: a JSON array in the structured-AST form of query-language.md §13
    /// (the `ops` of an `UPDATE` statement).
    #[schema(value_type = Vec<Object>)]
    pub operations: Box<RawValue>,
    /// Statement parameters (`$name`, `$1`, …) as extended-JSON values.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub params: BTreeMap<String, Box<RawValue>>,
}

/// `DELETE …/documents/{id}` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeleteResponse {
    /// A document was deleted.
    pub deleted: bool,
    /// The deleted document, if requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub document: Option<Box<RawValue>>,
}

/// `POST …/get-many` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetManyRequest {
    /// Ids (extended-JSON values).
    #[schema(value_type = Vec<Value>)]
    pub ids: Vec<Box<RawValue>>,
    /// Read consistency.
    #[serde(default)]
    pub consistency: Option<Consistency>,
}

/// `POST …/get-many` response: the documents found, in request order.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GetManyResponse {
    /// Documents (missing ids are omitted).
    #[schema(value_type = Vec<Object>)]
    pub documents: Vec<Box<RawValue>>,
}

/// Kind of a bulk operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BulkOpKind {
    /// Insert `document`.
    Insert,
    /// Replace the document `id` by `document`.
    Replace,
    /// Apply `operations` to the document `id`.
    Update,
    /// Insert or replace `document` by its `_id`.
    Upsert,
    /// Delete the document `id`.
    Delete,
}

/// One bulk operation: `op` selects which of the other fields are required.
///
/// A flat object rather than a tagged enum: serde buffers the fields of internally tagged
/// enums, and buffered content cannot hand raw JSON text to the extended-JSON parser.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkOperationJson {
    /// Operation.
    pub op: BulkOpKind,
    /// Document (`insert`, `replace`, `upsert`).
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub document: Option<Box<RawValue>>,
    /// Document id (`replace`, `update`, `delete`; extended-JSON value).
    #[serde(default)]
    #[schema(value_type = Option<Value>)]
    pub id: Option<Box<RawValue>>,
    /// Update operators (`update`; structured-AST form).
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    pub operations: Option<Box<RawValue>>,
    /// Expected `_rev` (`replace`, `update`, `delete`).
    #[serde(default)]
    pub if_rev: Option<String>,
}

/// `POST …/bulk` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkWriteRequest {
    /// Operations (≤ 100 000).
    pub operations: Vec<BulkOperationJson>,
    /// Stop at the first failure.
    #[serde(default)]
    pub ordered: bool,
    /// Parameters of the update operators.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub params: BTreeMap<String, Box<RawValue>>,
    /// Options.
    #[serde(default)]
    pub options: WriteOptionsJson,
}

/// A failed bulk operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkWriteErrorJson {
    /// Index of the operation in the request.
    pub index: u32,
    /// The error (code, name, retryable, details, trace id).
    pub error: ErrorInfo,
}

/// `POST …/bulk` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkWriteResponse {
    /// Inserted (inserts and inserting upserts).
    pub inserted: u64,
    /// Matched by replace/update/upsert.
    pub matched: u64,
    /// Changed by replace/update/upsert.
    pub modified: u64,
    /// Deleted.
    pub deleted: u64,
    /// Failed operations.
    pub errors: Vec<BulkWriteErrorJson>,
    /// Warnings.
    pub warnings: Vec<WarningJson>,
}

// ---------------------------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------------------------

/// `` `name` `` with backticks doubled (query-language.md §2).
fn quote(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

/// A sort key `a.b` / `-a.b` as `` `a`.`b` [DESC] ``.
fn sort_key(key: &str) -> Result<String, Error> {
    let (path, desc) = match key.strip_prefix('-') {
        Some(p) => (p, true),
        None => (key, false),
    };
    if path.is_empty() || path.split('.').any(str::is_empty) {
        return Err(invalid("sort", "sort keys are non-empty field paths"));
    }
    let quoted: Vec<String> = path.split('.').map(quote).collect();
    Ok(format!(
        "{}{}",
        quoted.join("."),
        if desc { " DESC" } else { "" }
    ))
}

/// The RGQL of a list request (module docs).
pub(crate) fn list_statement(coll: &str, q: &ListQuery) -> Result<String, Error> {
    let mut text = format!("FROM {}", quote(coll));
    if let Some(filter) = q.filter.as_deref() {
        if filter.len() > MAX_FILTER_LEN {
            return Err(invalid("filter", "filter too long"));
        }
        let expr = parse_expr(filter).map_err(Error::from)?;
        text.push_str(" WHERE (");
        text.push_str(&print_expr(&expr));
        text.push(')');
    }
    let keys: Vec<&str> = q
        .sort
        .as_deref()
        .map_or_else(|| vec!["_id"], |s| s.split(',').collect());
    if keys.len() > MAX_SORT_KEYS {
        return Err(invalid("sort", "too many sort keys"));
    }
    let keys = keys
        .iter()
        .map(|k| sort_key(k.trim_matches(' ')))
        .collect::<Result<Vec<_>, _>>()?;
    text.push_str(" ORDER BY ");
    text.push_str(&keys.join(", "));
    Ok(text)
}

/// One page of a collection (module docs; `QueryService.Execute`).
#[utoipa::path(
    get,
    path = "/api/v1/databases/{db}/collections/{coll}/documents",
    tag = "documents",
    operation_id = "listDocuments",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection."),
        ListQuery
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "One page of documents.", body = DocumentPage))
)]
async fn list_documents(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
    QueryParams(q): QueryParams<ListQuery>,
) -> Result<Reply<DocumentPage>, ApiError> {
    let ctx = gate::with_query_deadline(&state, ctx);
    let data = gate::data(&state, &ctx)?;
    let fail = ApiError::on(&ctx);
    let page = async {
        let limit = q.limit.unwrap_or(DEFAULT_PAGE);
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(invalid("limit", "limit must be between 1 and 10000"));
        }
        let consistency = ConsistencyQuery {
            consistency: q.consistency,
            max_staleness_ms: q.max_staleness_ms,
        }
        .read_consistency();
        let input = ExecuteInput {
            database: db,
            query: QueryText::Rgql(list_statement(&coll, &q)?),
            params: rustegon_query::Params::new(),
            options: QueryOptions {
                batch_size: Some(limit),
                max_batches: Some(1),
                consistency,
                continuation_token: q.continuation_token.as_deref().map(token_in).transpose()?,
                ..QueryOptions::default()
            },
            txn_id: None,
        };
        let batch = super::query::first_batch(&data.query, &ctx, input).await?;
        if let Some(cursor) = &batch.cursor_id {
            // Pages are stateless: the client continues with the token, not the cursor.
            data.query.kill_cursor(&ctx, cursor).await?;
        }
        Ok(DocumentPage {
            documents: batch.rows.iter().map(value_out).collect::<Result<_, _>>()?,
            continuation_token: batch.continuation_token.as_deref().map(token_out),
            warnings: warnings_out(&batch.warnings),
        })
    }
    .await
    .map_err(fail)?;
    Ok(Reply::passthrough(page, &ctx))
}

// ---------------------------------------------------------------------------------------------
// Single documents
// ---------------------------------------------------------------------------------------------

/// Inserts documents atomically (`DocumentService.Insert`).
#[utoipa::path(
    post,
    path = "/api/v1/databases/{db}/collections/{coll}/documents",
    tag = "documents",
    operation_id = "insertDocuments",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    request_body = InsertRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The documents were inserted.", body = InsertResponse))
)]
async fn insert_documents(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
    JsonBody(body): JsonBody<InsertRequest>,
) -> Result<Reply<InsertResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let docs = body
            .documents
            .iter()
            .map(|d| document_in(d, "documents"))
            .collect::<Result<Vec<_>, _>>()?;
        let options = WriteOptions {
            write_concern: write_concern_in(body.options.write_concern),
        };
        let out = data
            .document
            .insert(&ctx, &target(db, coll), docs, options)
            .await?;
        Ok(InsertResponse {
            results: out
                .results
                .iter()
                .map(write_result_out)
                .collect::<Result<_, Error>>()?,
            warnings: warnings_out(&out.warnings),
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// Reads one document by id (`DocumentService.Get`); 404 when it does not exist.
#[utoipa::path(
    get,
    path = "/api/v1/databases/{db}/collections/{coll}/documents/{id}",
    tag = "documents",
    operation_id = "getDocument",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection."),
        ("id" = String, Path, description = "Document id: an extended-JSON value (`42`, `\"42\"`, `{\"$oid\":…}`) or else the string itself."),
        ConsistencyQuery
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The document; `ETag` is its `_rev`.", body = DocumentResponse, headers(("ETag" = String, description = "The `_rev` as a strong entity tag (absent when nothing was written)."))))
)]
async fn get_document(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll, id)): PathParams<(String, String, String)>,
    QueryParams(q): QueryParams<ConsistencyQuery>,
) -> Result<(HeaderMap, Reply<DocumentResponse>), ApiError> {
    let data = gate::data(&state, &ctx)?;
    let (rev, body) = async {
        let doc = data
            .document
            .get(
                &ctx,
                &target(db, coll),
                id_from_path(&id),
                ReadOptions {
                    consistency: q.read_consistency(),
                },
            )
            .await?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "document not found"))?;
        Ok::<_, Error>((
            rev_of(&doc).map(str::to_owned),
            DocumentResponse {
                document: document_out(&doc)?,
            },
        ))
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok((etag_headers(rev.as_deref()), Reply::passthrough(body, &ctx)))
}

/// `doc` with `_id` = `id`: added first when absent; a different `_id` is RGN-1001 (the path
/// names the document).
fn with_path_id(doc: Document, id: &Value) -> Result<Document, Error> {
    match doc.get("_id") {
        Some(existing) if existing == id => Ok(doc),
        Some(_) => Err(invalid(
            "_id",
            "the document's _id differs from the id in the path",
        )),
        None => {
            let mut fields = vec![("_id".to_owned(), id.clone())];
            fields.extend(doc.iter().map(|(k, v)| (k.to_owned(), v.clone())));
            Ok(Document::try_from_fields(fields)?)
        }
    }
}

fn write_response(out: &WriteOutput) -> Result<(Option<String>, WriteResponse), Error> {
    let rev = out.result.as_ref().and_then(|r| r.rev.clone());
    Ok((
        rev,
        WriteResponse {
            matched: out.matched,
            modified: out.modified,
            inserted: out.inserted,
            result: out.result.as_ref().map(write_result_out).transpose()?,
            document: out.document.as_ref().map(document_out).transpose()?,
            warnings: warnings_out(&out.warnings),
        },
    ))
}

/// Replaces a document (`DocumentService.Replace`), or with `?upsert=true` replaces or inserts
/// it (`DocumentService.Upsert`). The body is the new document; its `_id`, when present, must
/// equal the path id.
#[utoipa::path(
    put,
    path = "/api/v1/databases/{db}/collections/{coll}/documents/{id}",
    tag = "documents",
    operation_id = "replaceDocument",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection."),
        ("id" = String, Path, description = "Document id (see `getDocument`)."),
        ("If-Match" = Option<String>, Header, description = "Expected `_rev` as a strong entity tag (`\"<_rev>\"`); a mismatch fails with RGN-2009 (412)."),
        WriteQuery
    ),
    request_body(content = Object, description = "The new document (extended JSON)."),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Outcome; `ETag` is the new `_rev`.", body = WriteResponse, headers(("ETag" = String, description = "The `_rev` as a strong entity tag (absent when nothing was written)."))))
)]
async fn replace_document(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    PathParams((db, coll, id)): PathParams<(String, String, String)>,
    QueryParams(q): QueryParams<WriteQuery>,
    JsonBody(document): JsonBody<Box<RawValue>>,
) -> Result<(HeaderMap, Reply<WriteResponse>), ApiError> {
    // The route is admitted with the `Replace` rule; `Upsert` has the same shape
    // (collection-level actions, checked by the service: `update`, plus `insert` to upsert).
    let upsert = q.upsert.unwrap_or(false);
    let data = gate::data(&state, &ctx)?;
    let (rev, body) = async {
        let if_rev = if_match(&headers)?;
        let id = id_from_path(&id);
        let doc = with_path_id(document_in(&document, "document")?, &id)?;
        let ret = return_document_in(q.return_document);
        let options = WriteOptions {
            write_concern: write_concern_in(q.write_concern),
        };
        let t = target(db, coll);
        let out = if upsert {
            data.document
                .upsert(&ctx, &t, doc, if_rev, ret, options)
                .await?
        } else {
            data.document
                .replace(&ctx, &t, id, doc, if_rev, ret, options)
                .await?
        };
        write_response(&out)
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok((etag_headers(rev.as_deref()), Reply::passthrough(body, &ctx)))
}

/// Applies update operators to a document (`DocumentService.Update`).
#[utoipa::path(
    patch,
    path = "/api/v1/databases/{db}/collections/{coll}/documents/{id}",
    tag = "documents",
    operation_id = "updateDocument",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection."),
        ("id" = String, Path, description = "Document id (see `getDocument`)."),
        ("If-Match" = Option<String>, Header, description = "Expected `_rev` (strong entity tag); a mismatch fails with RGN-2009 (412)."),
        WriteQuery
    ),
    request_body = UpdateRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Outcome; `ETag` is the new `_rev`.", body = WriteResponse, headers(("ETag" = String, description = "The `_rev` as a strong entity tag (absent when nothing was written)."))))
)]
async fn update_document(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    PathParams((db, coll, id)): PathParams<(String, String, String)>,
    QueryParams(q): QueryParams<WriteQuery>,
    JsonBody(body): JsonBody<UpdateRequest>,
) -> Result<(HeaderMap, Reply<WriteResponse>), ApiError> {
    let data = gate::data(&state, &ctx)?;
    let (rev, out) = async {
        if q.upsert.is_some() {
            return Err(invalid("upsert", "upsert applies to PUT only"));
        }
        let if_rev = if_match(&headers)?;
        let ops = update_ops_from_json(body.operations.get())?;
        let params = params_in(&body.params)?;
        let out = data
            .document
            .update(
                &ctx,
                &target(db, coll),
                id_from_path(&id),
                ops,
                if_rev,
                return_document_in(q.return_document),
                params,
                WriteOptions {
                    write_concern: write_concern_in(q.write_concern),
                },
            )
            .await?;
        write_response(&out)
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok((etag_headers(rev.as_deref()), Reply::passthrough(out, &ctx)))
}

/// Deletes a document (`DocumentService.Delete`); `deleted` is false when none had the id.
#[utoipa::path(
    delete,
    path = "/api/v1/databases/{db}/collections/{coll}/documents/{id}",
    tag = "documents",
    operation_id = "deleteDocument",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection."),
        ("id" = String, Path, description = "Document id (see `getDocument`)."),
        ("If-Match" = Option<String>, Header, description = "Expected `_rev` (strong entity tag); a mismatch fails with RGN-2009 (412)."),
        DeleteQuery
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Outcome.", body = DeleteResponse))
)]
async fn delete_document(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    PathParams((db, coll, id)): PathParams<(String, String, String)>,
    QueryParams(q): QueryParams<DeleteQuery>,
) -> Result<Reply<DeleteResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let if_rev = if_match(&headers)?;
        let out = data
            .document
            .delete(
                &ctx,
                &target(db, coll),
                id_from_path(&id),
                if_rev,
                q.return_document.unwrap_or(false),
                WriteOptions {
                    write_concern: write_concern_in(q.write_concern),
                },
            )
            .await?;
        Ok::<_, Error>(DeleteResponse {
            deleted: out.deleted,
            document: out.document.as_ref().map(document_out).transpose()?,
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

// ---------------------------------------------------------------------------------------------
// Many documents
// ---------------------------------------------------------------------------------------------

/// Reads several documents at one snapshot (`DocumentService.GetMany`).
#[utoipa::path(
    post,
    path = "/api/v1/databases/{db}/collections/{coll}/get-many",
    tag = "documents",
    operation_id = "getManyDocuments",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    request_body = GetManyRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The documents found, in request order.", body = GetManyResponse))
)]
async fn get_many(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
    JsonBody(body): JsonBody<GetManyRequest>,
) -> Result<Reply<GetManyResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let ids = body
            .ids
            .iter()
            .map(|v| value_in(v, "ids"))
            .collect::<Result<Vec<_>, _>>()?;
        let docs = data
            .document
            .get_many(
                &ctx,
                &target(db, coll),
                ids,
                ReadOptions {
                    consistency: consistency_in(body.consistency),
                },
            )
            .await?;
        Ok::<_, Error>(GetManyResponse {
            documents: docs.iter().map(document_out).collect::<Result<_, _>>()?,
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

fn required<'a>(v: Option<&'a RawValue>, field: &str) -> Result<&'a RawValue, Error> {
    v.ok_or_else(|| invalid(field, "required by this bulk operation"))
}

fn bulk_op(op: &BulkOperationJson) -> Result<BulkOp, Error> {
    let document = || document_in(required(op.document.as_deref(), "document")?, "document");
    let id = || value_in(required(op.id.as_deref(), "id")?, "id");
    let unexpected = |present: bool, field: &str| {
        if present {
            Err(invalid(field, "not allowed for this bulk operation"))
        } else {
            Ok(())
        }
    };
    Ok(match op.op {
        BulkOpKind::Insert | BulkOpKind::Upsert => {
            unexpected(op.id.is_some(), "id")?;
            unexpected(op.operations.is_some(), "operations")?;
            unexpected(op.if_rev.is_some(), "ifRev")?;
            if op.op == BulkOpKind::Insert {
                BulkOp::Insert {
                    document: document()?,
                }
            } else {
                BulkOp::Upsert {
                    document: document()?,
                }
            }
        }
        BulkOpKind::Replace => {
            unexpected(op.operations.is_some(), "operations")?;
            BulkOp::Replace {
                id: id()?,
                document: document()?,
                if_rev: op.if_rev.clone(),
            }
        }
        BulkOpKind::Update => {
            unexpected(op.document.is_some(), "document")?;
            BulkOp::Update {
                id: id()?,
                operations: update_ops_from_json(
                    required(op.operations.as_deref(), "operations")?.get(),
                )?,
                if_rev: op.if_rev.clone(),
            }
        }
        BulkOpKind::Delete => {
            unexpected(op.document.is_some(), "document")?;
            unexpected(op.operations.is_some(), "operations")?;
            BulkOp::Delete {
                id: id()?,
                if_rev: op.if_rev.clone(),
            }
        }
    })
}

/// Runs many writes in one call (`DocumentService.BulkWrite`; PD-053 atomicity rules).
#[utoipa::path(
    post,
    path = "/api/v1/databases/{db}/collections/{coll}/bulk",
    tag = "documents",
    operation_id = "bulkWrite",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    request_body = BulkWriteRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Counts and the failed operations.", body = BulkWriteResponse))
)]
async fn bulk_write(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
    JsonBody(body): JsonBody<BulkWriteRequest>,
) -> Result<Reply<BulkWriteResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let trace_id = ctx.trace_id_hex();
    let out = async {
        let ops = body
            .operations
            .iter()
            .map(bulk_op)
            .collect::<Result<Vec<_>, _>>()?;
        let params = params_in(&body.params)?;
        let out = data
            .document
            .bulk_write(
                &ctx,
                &target(db, coll),
                ops,
                body.ordered,
                params,
                WriteOptions {
                    write_concern: write_concern_in(body.options.write_concern),
                },
            )
            .await?;
        Ok::<_, Error>(BulkWriteResponse {
            inserted: out.inserted,
            matched: out.matched,
            modified: out.modified,
            deleted: out.deleted,
            errors: out
                .errors
                .iter()
                .map(|e| BulkWriteErrorJson {
                    index: e.index,
                    error: super::ErrorBody::of(&e.to_error(), &trace_id).error,
                })
                .collect(),
            warnings: warnings_out(&out.warnings),
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn fr_api_002_list_statement_quotes_names_and_canonicalizes_the_filter() {
        let q = ListQuery {
            filter: Some("n >= 2 AND tag = 'x'".into()),
            sort: Some("-n, a.b".into()),
            ..ListQuery::default()
        };
        let text = list_statement("it`ems", &q).unwrap();
        assert!(text.starts_with("FROM `it``ems` WHERE ("), "{text}");
        assert!(text.ends_with("ORDER BY `n` DESC, `a`.`b`"), "{text}");
        rustegon_query::parse_statement(&text).unwrap();
        assert_eq!(
            list_statement("c", &ListQuery::default()).unwrap(),
            "FROM `c` ORDER BY `_id`"
        );
        // A filter is one expression: anything that would extend the statement is rejected.
        for bad in [
            "n = 1) SELECT x FROM (y",
            "1; DROP DATABASE shop",
            "n = 1 LIMIT 1",
        ] {
            let q = ListQuery {
                filter: Some(bad.into()),
                ..ListQuery::default()
            };
            assert!(list_statement("c", &q).is_err(), "{bad}");
        }
        for bad in ["", "a..b", "-"] {
            let q = ListQuery {
                sort: Some(bad.into()),
                ..ListQuery::default()
            };
            assert!(list_statement("c", &q).is_err(), "{bad:?}");
        }
    }
}
