// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST adapter of [`crate::services::SchemaService`] (protocol.md §4 "databases",
//! "collections", "indexes"; FR-API-002, FR-SCH-001/002, FR-IDX-001/003, PD-053, PD-055).
//!
//! Options are JSON objects of extended-JSON values; index definitions are `CREATE INDEX`
//! statements in the structured-AST JSON form (query-language.md §13), as on gRPC; validators
//! carry their `{"$jsonSchema": …}` definition as a JSON object. `GET` of a single database or
//! index answers from the listing (no dedicated RPC): RGN-1030 / RGN-1021 when absent.

use std::collections::BTreeMap;

use axum::extract::State;
use rustegon_catalog::{ValidationAction, ValidationLevel};
use rustegon_common::{Error, ErrorCode};
use rustegon_query::ast::CreateIndex;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    ApiError, Ctx, JsonBody, Reply, RestState,
    extract::{PathParams, QueryParams},
    gate,
    wire::{options_in, options_out},
};
use crate::{
    grpc::ast::create_index_from_json,
    services::{CollectionInfo, DatabaseInfo, IndexInfo, IndexStatus, ValidatorDef},
};

/// Routes of this module.
pub(super) fn routes() -> OpenApiRouter<RestState> {
    OpenApiRouter::new()
        .routes(routes!(list_databases, create_database))
        .routes(routes!(get_database, drop_database))
        .routes(routes!(list_collections, create_collection))
        .routes(routes!(get_collection, alter_collection, drop_collection))
        .routes(routes!(list_indexes, create_index))
        .routes(routes!(get_index, drop_index))
        .routes(routes!(index_progress))
        .routes(routes!(get_validator, set_validator, remove_validator))
}

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

/// A database.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DatabaseJson {
    /// Name.
    pub name: String,
    /// Options (`implicit_collection_creation`) as extended-JSON values.
    #[schema(value_type = Object)]
    pub options: BTreeMap<String, Box<RawValue>>,
}

/// `GET /databases` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DatabaseList {
    /// Databases the caller holds any privilege on.
    pub databases: Vec<DatabaseJson>,
}

/// `POST /databases` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateDatabaseRequest {
    /// Name.
    pub name: String,
    /// Options as extended-JSON values.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub options: BTreeMap<String, Box<RawValue>>,
    /// Succeed with `created = false` when it exists.
    #[serde(default)]
    pub if_not_exists: bool,
}

/// Outcome of a create.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreatedResponse {
    /// `false` when `ifNotExists` found the object.
    pub created: bool,
}

/// Outcome of a drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DroppedResponse {
    /// `false` when `ifExists` found nothing.
    pub dropped: bool,
}

/// `?ifExists=` of the drops.
#[derive(Debug, Clone, Copy, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct DropQuery {
    /// Succeed with `dropped = false` when the object does not exist.
    pub if_exists: Option<bool>,
}

/// Validation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevelName {
    /// Off.
    Off,
    /// Strict (default).
    Strict,
    /// Moderate.
    Moderate,
}

/// Validation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationActionName {
    /// Reject the write (default).
    Error,
    /// Accept with a warning.
    Warn,
}

/// A collection validator (data-model.md §5).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidatorJson {
    /// `{"$jsonSchema": …}`, stored verbatim.
    #[schema(value_type = Object)]
    pub definition: Box<RawValue>,
    /// Level (default strict).
    #[serde(default)]
    pub level: Option<ValidationLevelName>,
    /// Action (default error).
    #[serde(default)]
    pub action: Option<ValidationActionName>,
}

/// A collection.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CollectionJson {
    /// Name.
    pub name: String,
    /// Options as extended-JSON values.
    #[schema(value_type = Object)]
    pub options: BTreeMap<String, Box<RawValue>>,
    /// Validator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<ValidatorJson>,
}

/// `GET …/collections` response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CollectionList {
    /// Collections the caller holds any privilege on.
    pub collections: Vec<CollectionJson>,
}

/// `POST …/collections` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateCollectionRequest {
    /// Name.
    pub name: String,
    /// Options.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub options: BTreeMap<String, Box<RawValue>>,
    /// Validator.
    #[serde(default)]
    pub validator: Option<ValidatorJson>,
    /// Succeed with `created = false` when it exists.
    #[serde(default)]
    pub if_not_exists: bool,
}

/// `PATCH …/collections/{coll}` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlterCollectionRequest {
    /// Options to set.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub set_options: BTreeMap<String, Box<RawValue>>,
    /// Options to remove.
    #[serde(default)]
    pub unset_options: Vec<String>,
}

/// Empty success body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EmptyResponse {}

/// Index state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IndexStateName {
    /// Being built.
    Building,
    /// Usable.
    Ready,
    /// Build failed.
    Failed,
    /// Maintained but hidden from the planner.
    Hidden,
}

/// An index.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IndexJson {
    /// Definition: `CREATE INDEX` in the structured-AST JSON form.
    #[schema(value_type = Object)]
    pub definition: serde_json::Value,
    /// State.
    pub state: IndexStateName,
    /// Failure message when failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `GET …/indexes` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IndexList {
    /// Indexes of the collection.
    pub indexes: Vec<IndexJson>,
}

/// `POST …/indexes` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateIndexRequest {
    /// `CREATE INDEX` in the structured-AST JSON form; it must name the collection of the
    /// path (and, when it names one, the database).
    #[schema(value_type = Object)]
    pub definition: Box<RawValue>,
    /// Succeed when an index of that name and definition exists.
    #[serde(default)]
    pub if_not_exists: bool,
}

/// `POST …/indexes` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IndexResponse {
    /// The index (state `building` until the online build completes).
    pub index: IndexJson,
}

/// `GET …/indexes/{name}/progress` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexProgressResponse {
    /// State.
    pub state: IndexStateName,
    /// Documents processed by this node's build task.
    pub docs_processed: u64,
    /// Estimated total (0: not estimated).
    pub docs_total: u64,
}

/// `GET …/validator` response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ValidatorResponse {
    /// The validator, absent when the collection has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<ValidatorJson>,
}

/// `DELETE …/validator` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RemovedResponse {
    /// `false` when the collection had no validator.
    pub removed: bool,
}

// ---------------------------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------------------------

fn validator_in(v: &ValidatorJson) -> ValidatorDef {
    ValidatorDef {
        definition_json: v.definition.get().to_owned(),
        level: match v.level {
            None | Some(ValidationLevelName::Strict) => ValidationLevel::Strict,
            Some(ValidationLevelName::Off) => ValidationLevel::Off,
            Some(ValidationLevelName::Moderate) => ValidationLevel::Moderate,
        },
        action: match v.action {
            None | Some(ValidationActionName::Error) => ValidationAction::Error,
            Some(ValidationActionName::Warn) => ValidationAction::Warn,
        },
    }
}

fn validator_out(v: &ValidatorDef) -> Result<ValidatorJson, Error> {
    Ok(ValidatorJson {
        // Stored verbatim from a JSON request on either channel; a stored text that is not
        // JSON (only possible through a corrupted catalog) is reported, not served.
        definition: RawValue::from_string(v.definition_json.clone())
            .map_err(|_| Error::new(ErrorCode::Internal, "stored validator is not JSON"))?,
        level: Some(match v.level {
            ValidationLevel::Off => ValidationLevelName::Off,
            ValidationLevel::Strict => ValidationLevelName::Strict,
            ValidationLevel::Moderate => ValidationLevelName::Moderate,
        }),
        action: Some(match v.action {
            ValidationAction::Error => ValidationActionName::Error,
            ValidationAction::Warn => ValidationActionName::Warn,
        }),
    })
}

fn database_out(d: &DatabaseInfo) -> Result<DatabaseJson, Error> {
    Ok(DatabaseJson {
        name: d.name.clone(),
        options: options_out(&d.options)?,
    })
}

fn collection_out(c: &CollectionInfo) -> Result<CollectionJson, Error> {
    Ok(CollectionJson {
        name: c.name.clone(),
        options: options_out(&c.options)?,
        validator: c.validator.as_ref().map(validator_out).transpose()?,
    })
}

fn state_out(s: IndexStatus) -> IndexStateName {
    match s {
        IndexStatus::Building => IndexStateName::Building,
        IndexStatus::Ready => IndexStateName::Ready,
        IndexStatus::Failed => IndexStateName::Failed,
        IndexStatus::Hidden => IndexStateName::Hidden,
    }
}

fn index_out(i: &IndexInfo) -> Result<IndexJson, Error> {
    Ok(IndexJson {
        definition: serde_json::to_value(&i.definition)
            .map_err(|_| Error::new(ErrorCode::Internal, "index definition has no JSON form"))?,
        state: state_out(i.state),
        error: i.error.clone(),
    })
}

fn index_name(i: &IndexInfo) -> &str {
    &i.definition.name
}

/// The definition of `POST …/indexes`, checked against the path.
fn index_definition(raw: &RawValue, db: &str, coll: &str) -> Result<CreateIndex, Error> {
    let definition = create_index_from_json(raw.get())?;
    let mismatch = |what: &str| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("the definition names another {what} than the path"),
        )
        .with_detail("field", "definition")
    };
    if definition.on.name != coll {
        return Err(mismatch("collection"));
    }
    if definition.on.database.as_deref().is_some_and(|d| d != db) {
        return Err(mismatch("database"));
    }
    Ok(definition)
}

// ---------------------------------------------------------------------------------------------
// Databases
// ---------------------------------------------------------------------------------------------

/// Databases the caller can see (`SchemaService.ListDatabases`).
#[utoipa::path(
    get,
    path = "/api/v1/databases",
    tag = "schema",
    operation_id = "listDatabases",
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The databases.", body = DatabaseList))
)]
async fn list_databases(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
) -> Result<Reply<DatabaseList>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let dbs = data.schema.list_databases(&ctx).await?;
        Ok::<_, Error>(DatabaseList {
            databases: dbs.iter().map(database_out).collect::<Result<_, _>>()?,
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// Creates a database (`SchemaService.CreateDatabase`).
#[utoipa::path(
    post,
    path = "/api/v1/databases",
    tag = "schema",
    operation_id = "createDatabase",
    request_body = CreateDatabaseRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Outcome.", body = CreatedResponse))
)]
async fn create_database(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    JsonBody(body): JsonBody<CreateDatabaseRequest>,
) -> Result<Reply<CreatedResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let created = async {
        let options = options_in(&body.options)?;
        data.schema
            .create_database(&ctx, body.name, options, body.if_not_exists)
            .await
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(CreatedResponse { created }, &ctx))
}

/// One database, from the listing (RGN-1030 when absent or not visible to the caller).
#[utoipa::path(
    get,
    path = "/api/v1/databases/{db}",
    tag = "schema",
    operation_id = "getDatabase",
    params(("db" = String, Path, description = "Database.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The database.", body = DatabaseJson))
)]
async fn get_database(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(db): PathParams<String>,
) -> Result<Reply<DatabaseJson>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let dbs = data.schema.list_databases(&ctx).await?;
        let found = dbs
            .iter()
            .find(|d| d.name == db)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "database not found"))?;
        database_out(found)
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// Drops a database (`SchemaService.DropDatabase`).
#[utoipa::path(
    delete,
    path = "/api/v1/databases/{db}",
    tag = "schema",
    operation_id = "dropDatabase",
    params(("db" = String, Path, description = "Database."), DropQuery),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Outcome.", body = DroppedResponse))
)]
async fn drop_database(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(db): PathParams<String>,
    QueryParams(q): QueryParams<DropQuery>,
) -> Result<Reply<DroppedResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let dropped = data
        .schema
        .drop_database(&ctx, db, q.if_exists.unwrap_or(false))
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(DroppedResponse { dropped }, &ctx))
}

// ---------------------------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------------------------

/// Collections of a database the caller can see (`SchemaService.ListCollections`).
#[utoipa::path(
    get,
    path = "/api/v1/databases/{db}/collections",
    tag = "schema",
    operation_id = "listCollections",
    params(("db" = String, Path, description = "Database.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The collections.", body = CollectionList))
)]
async fn list_collections(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(db): PathParams<String>,
) -> Result<Reply<CollectionList>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let list = data.schema.list_collections(&ctx, db).await?;
        Ok::<_, Error>(CollectionList {
            collections: list.iter().map(collection_out).collect::<Result<_, _>>()?,
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// Creates a collection (`SchemaService.CreateCollection`).
#[utoipa::path(
    post,
    path = "/api/v1/databases/{db}/collections",
    tag = "schema",
    operation_id = "createCollection",
    params(("db" = String, Path, description = "Database.")),
    request_body = CreateCollectionRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Outcome.", body = CreatedResponse))
)]
async fn create_collection(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(db): PathParams<String>,
    JsonBody(body): JsonBody<CreateCollectionRequest>,
) -> Result<Reply<CreatedResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let created = async {
        let options = options_in(&body.options)?;
        let validator = body.validator.as_ref().map(validator_in);
        data.schema
            .create_collection(&ctx, db, body.name, options, validator, body.if_not_exists)
            .await
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(CreatedResponse { created }, &ctx))
}

/// Describes a collection (`SchemaService.GetCollection`).
#[utoipa::path(
    get,
    path = "/api/v1/databases/{db}/collections/{coll}",
    tag = "schema",
    operation_id = "getCollection",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The collection.", body = CollectionJson))
)]
async fn get_collection(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
) -> Result<Reply<CollectionJson>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async { collection_out(&data.schema.get_collection(&ctx, db, coll).await?) }
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// Changes collection options (`SchemaService.AlterCollection`).
#[utoipa::path(
    patch,
    path = "/api/v1/databases/{db}/collections/{coll}",
    tag = "schema",
    operation_id = "alterCollection",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    request_body = AlterCollectionRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Changed.", body = EmptyResponse))
)]
async fn alter_collection(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
    JsonBody(body): JsonBody<AlterCollectionRequest>,
) -> Result<Reply<EmptyResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    async {
        let set = options_in(&body.set_options)?;
        data.schema
            .alter_collection(&ctx, db, coll, set, body.unset_options)
            .await
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(EmptyResponse {}, &ctx))
}

/// Drops a collection (`SchemaService.DropCollection`).
#[utoipa::path(
    delete,
    path = "/api/v1/databases/{db}/collections/{coll}",
    tag = "schema",
    operation_id = "dropCollection",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection."),
        DropQuery
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Outcome.", body = DroppedResponse))
)]
async fn drop_collection(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
    QueryParams(q): QueryParams<DropQuery>,
) -> Result<Reply<DroppedResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let dropped = data
        .schema
        .drop_collection(&ctx, db, coll, q.if_exists.unwrap_or(false))
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(DroppedResponse { dropped }, &ctx))
}

// ---------------------------------------------------------------------------------------------
// Indexes
// ---------------------------------------------------------------------------------------------

/// Indexes of a collection (`SchemaService.ListIndexes`).
#[utoipa::path(
    get,
    path = "/api/v1/databases/{db}/collections/{coll}/indexes",
    tag = "schema",
    operation_id = "listIndexes",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The indexes.", body = IndexList))
)]
async fn list_indexes(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
) -> Result<Reply<IndexList>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let list = data.schema.list_indexes(&ctx, db, coll).await?;
        Ok::<_, Error>(IndexList {
            indexes: list.iter().map(index_out).collect::<Result<_, _>>()?,
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// Starts an online index build (`SchemaService.CreateIndex`).
#[utoipa::path(
    post,
    path = "/api/v1/databases/{db}/collections/{coll}/indexes",
    tag = "schema",
    operation_id = "createIndex",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    request_body = CreateIndexRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The index (building).", body = IndexResponse))
)]
async fn create_index(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
    JsonBody(body): JsonBody<CreateIndexRequest>,
) -> Result<Reply<IndexResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let definition = index_definition(&body.definition, &db, &coll)?;
        let info = data
            .schema
            .create_index(&ctx, db, definition, body.if_not_exists)
            .await?;
        Ok::<_, Error>(IndexResponse {
            index: index_out(&info)?,
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// One index, from the listing (RGN-1021 when absent).
#[utoipa::path(
    get,
    path = "/api/v1/databases/{db}/collections/{coll}/indexes/{name}",
    tag = "schema",
    operation_id = "getIndex",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection."),
        ("name" = String, Path, description = "Index name.")
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The index.", body = IndexJson))
)]
async fn get_index(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll, name)): PathParams<(String, String, String)>,
) -> Result<Reply<IndexJson>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let list = data.schema.list_indexes(&ctx, db, coll).await?;
        let found = list
            .iter()
            .find(|i| index_name(i) == name)
            .ok_or_else(|| Error::new(ErrorCode::IndexNotFound, "index not found"))?;
        index_out(found)
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// Drops an index (`SchemaService.DropIndex`).
#[utoipa::path(
    delete,
    path = "/api/v1/databases/{db}/collections/{coll}/indexes/{name}",
    tag = "schema",
    operation_id = "dropIndex",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection."),
        ("name" = String, Path, description = "Index name."),
        DropQuery
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Outcome.", body = DroppedResponse))
)]
async fn drop_index(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll, name)): PathParams<(String, String, String)>,
    QueryParams(q): QueryParams<DropQuery>,
) -> Result<Reply<DroppedResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let dropped = data
        .schema
        .drop_index(&ctx, db, coll, name, q.if_exists.unwrap_or(false))
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(DroppedResponse { dropped }, &ctx))
}

/// Progress of an index build (`SchemaService.IndexBuildProgress`).
#[utoipa::path(
    get,
    path = "/api/v1/databases/{db}/collections/{coll}/indexes/{name}/progress",
    tag = "schema",
    operation_id = "getIndexBuildProgress",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection."),
        ("name" = String, Path, description = "Index name.")
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Progress.", body = IndexProgressResponse))
)]
async fn index_progress(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll, name)): PathParams<(String, String, String)>,
) -> Result<Reply<IndexProgressResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let p = data
        .schema
        .index_build_progress(&ctx, db, coll, name)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        IndexProgressResponse {
            state: state_out(p.state),
            docs_processed: p.docs_processed,
            docs_total: p.docs_total,
        },
        &ctx,
    ))
}

// ---------------------------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------------------------

/// The validator of a collection (`SchemaService.GetValidator`).
#[utoipa::path(
    get,
    path = "/api/v1/databases/{db}/collections/{coll}/validator",
    tag = "schema",
    operation_id = "getValidator",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The validator, if any.", body = ValidatorResponse))
)]
async fn get_validator(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
) -> Result<Reply<ValidatorResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let out = async {
        let v = data.schema.get_validator(&ctx, db, coll).await?;
        Ok::<_, Error>(ValidatorResponse {
            validator: v.as_ref().map(validator_out).transpose()?,
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// Sets (replaces) the validator of a collection (`SchemaService.SetValidator`).
#[utoipa::path(
    put,
    path = "/api/v1/databases/{db}/collections/{coll}/validator",
    tag = "schema",
    operation_id = "setValidator",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    request_body = ValidatorJson,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Set.", body = EmptyResponse))
)]
async fn set_validator(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
    JsonBody(body): JsonBody<ValidatorJson>,
) -> Result<Reply<EmptyResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    data.schema
        .set_validator(&ctx, db, coll, validator_in(&body))
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(EmptyResponse {}, &ctx))
}

/// Removes the validator of a collection (`SchemaService.RemoveValidator`).
#[utoipa::path(
    delete,
    path = "/api/v1/databases/{db}/collections/{coll}/validator",
    tag = "schema",
    operation_id = "removeValidator",
    params(
        ("db" = String, Path, description = "Database."),
        ("coll" = String, Path, description = "Collection.")
    ),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Outcome.", body = RemovedResponse))
)]
async fn remove_validator(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams((db, coll)): PathParams<(String, String)>,
) -> Result<Reply<RemovedResponse>, ApiError> {
    let data = gate::data(&state, &ctx)?;
    let removed = data
        .schema
        .remove_validator(&ctx, db, coll)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(RemovedResponse { removed }, &ctx))
}
