// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC adapter of [`crate::services::SchemaService`].

use std::collections::HashMap;

use rustegon_catalog::{ValidationAction, ValidationLevel};
use rustegon_common::{Error, ErrorCode};
use rustegon_doc::Value;
use rustegon_proto::v1::{self as pb, schema_service_server};
use tonic::{Request, Response, Status};

use super::{
    ast::{create_index_from_proto, create_index_to_proto},
    convert::{value_from_proto, value_to_proto},
    data::DataGrpc,
    metadata::{context_from_request, respond, status_of},
};
use crate::services::{CollectionInfo, IndexInfo, IndexStatus, ValidatorDef};

/// `rustegon.v1.SchemaService` over the data services.
#[derive(Debug, Clone)]
pub struct SchemaGrpc(pub(crate) DataGrpc);

fn options_from_proto(map: &HashMap<String, pb::Value>) -> Result<Vec<(String, Value)>, Error> {
    let mut out = map
        .iter()
        .map(|(k, v)| Ok((k.clone(), value_from_proto(Some(v), "options")?)))
        .collect::<Result<Vec<_>, Error>>()?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn options_to_proto(options: &[(String, Value)]) -> Result<HashMap<String, pb::Value>, Error> {
    options
        .iter()
        .map(|(k, v)| Ok((k.clone(), value_to_proto(v)?)))
        .collect()
}

fn validator_from_proto(v: &pb::Validator) -> Result<ValidatorDef, Error> {
    let bad = |field: &str| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown validator {field}"),
        )
        .with_detail("field", field)
    };
    let level = match pb::ValidationLevel::try_from(v.level).map_err(|_| bad("level"))? {
        pb::ValidationLevel::Unspecified | pb::ValidationLevel::Strict => ValidationLevel::Strict,
        pb::ValidationLevel::Off => ValidationLevel::Off,
        pb::ValidationLevel::Moderate => ValidationLevel::Moderate,
    };
    let action = match pb::ValidationAction::try_from(v.action).map_err(|_| bad("action"))? {
        pb::ValidationAction::Unspecified | pb::ValidationAction::Error => ValidationAction::Error,
        pb::ValidationAction::Warn => ValidationAction::Warn,
    };
    Ok(ValidatorDef {
        definition_json: v.definition_json.clone(),
        level,
        action,
    })
}

fn validator_to_proto(v: &ValidatorDef) -> pb::Validator {
    pb::Validator {
        definition_json: v.definition_json.clone(),
        level: match v.level {
            ValidationLevel::Off => pb::ValidationLevel::Off,
            ValidationLevel::Strict => pb::ValidationLevel::Strict,
            ValidationLevel::Moderate => pb::ValidationLevel::Moderate,
        }
        .into(),
        action: match v.action {
            ValidationAction::Error => pb::ValidationAction::Error,
            ValidationAction::Warn => pb::ValidationAction::Warn,
        }
        .into(),
    }
}

fn collection_to_proto(c: &CollectionInfo) -> Result<pb::CollectionInfo, Error> {
    Ok(pb::CollectionInfo {
        name: c.name.clone(),
        options: options_to_proto(&c.options)?,
        validator: c.validator.as_ref().map(validator_to_proto),
    })
}

fn state_to_proto(s: IndexStatus) -> pb::IndexState {
    match s {
        IndexStatus::Building => pb::IndexState::Building,
        IndexStatus::Ready => pb::IndexState::Ready,
        IndexStatus::Failed => pb::IndexState::Failed,
        IndexStatus::Hidden => pb::IndexState::Hidden,
    }
}

fn index_to_proto(i: &IndexInfo) -> Result<pb::IndexInfo, Error> {
    Ok(pb::IndexInfo {
        definition: Some(create_index_to_proto(&i.definition)?),
        state: state_to_proto(i.state).into(),
        error: i.error.clone(),
    })
}

/// Runs the boilerplate of one schema call: context, service call, error mapping, trailers.
macro_rules! schema_call {
    ($self:ident, $request:ident, |$ctx:ident, $r:ident, $svc:ident| $body:expr) => {{
        let $ctx = context_from_request(&$request, $self.0.services.deps())?;
        let $r = $request.into_inner();
        let $svc = &$self.0.data()?.schema;
        let out: Result<_, Error> = $body;
        let out = out.map_err(|e| status_of(&e, &$ctx.trace_id_hex()))?;
        Ok(respond(out, $self.0.trailers(&$ctx)))
    }};
}

#[tonic::async_trait]
impl schema_service_server::SchemaService for SchemaGrpc {
    async fn create_database(
        &self,
        request: Request<pb::CreateDatabaseRequest>,
    ) -> Result<Response<pb::CreateDatabaseResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| async {
            let options = options_from_proto(&r.options)?;
            let created = svc
                .create_database(&ctx, r.name, options, r.if_not_exists)
                .await?;
            Ok(pb::CreateDatabaseResponse { created })
        }
        .await)
    }

    async fn drop_database(
        &self,
        request: Request<pb::DropDatabaseRequest>,
    ) -> Result<Response<pb::DropDatabaseResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| svc
            .drop_database(&ctx, r.name, r.if_exists)
            .await
            .map(|dropped| pb::DropDatabaseResponse { dropped }))
    }

    async fn list_databases(
        &self,
        request: Request<pb::ListDatabasesRequest>,
    ) -> Result<Response<pb::ListDatabasesResponse>, Status> {
        schema_call!(self, request, |ctx, _r, svc| async {
            let databases = svc
                .list_databases(&ctx)
                .await?
                .iter()
                .map(|d| {
                    Ok(pb::DatabaseInfo {
                        name: d.name.clone(),
                        options: options_to_proto(&d.options)?,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(pb::ListDatabasesResponse { databases })
        }
        .await)
    }

    async fn create_collection(
        &self,
        request: Request<pb::CreateCollectionRequest>,
    ) -> Result<Response<pb::CreateCollectionResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| async {
            let options = options_from_proto(&r.options)?;
            let validator = r.validator.as_ref().map(validator_from_proto).transpose()?;
            let created = svc
                .create_collection(
                    &ctx,
                    r.database,
                    r.name,
                    options,
                    validator,
                    r.if_not_exists,
                )
                .await?;
            Ok(pb::CreateCollectionResponse { created })
        }
        .await)
    }

    async fn drop_collection(
        &self,
        request: Request<pb::DropCollectionRequest>,
    ) -> Result<Response<pb::DropCollectionResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| svc
            .drop_collection(&ctx, r.database, r.name, r.if_exists)
            .await
            .map(|dropped| pb::DropCollectionResponse { dropped }))
    }

    async fn alter_collection(
        &self,
        request: Request<pb::AlterCollectionRequest>,
    ) -> Result<Response<pb::AlterCollectionResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| async {
            let set = options_from_proto(&r.set_options)?;
            svc.alter_collection(&ctx, r.database, r.name, set, r.unset_options)
                .await?;
            Ok(pb::AlterCollectionResponse {})
        }
        .await)
    }

    async fn get_collection(
        &self,
        request: Request<pb::GetCollectionRequest>,
    ) -> Result<Response<pb::GetCollectionResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| async {
            let c = svc.get_collection(&ctx, r.database, r.name).await?;
            Ok(pb::GetCollectionResponse {
                collection: Some(collection_to_proto(&c)?),
            })
        }
        .await)
    }

    async fn list_collections(
        &self,
        request: Request<pb::ListCollectionsRequest>,
    ) -> Result<Response<pb::ListCollectionsResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| async {
            let collections = svc
                .list_collections(&ctx, r.database)
                .await?
                .iter()
                .map(collection_to_proto)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(pb::ListCollectionsResponse { collections })
        }
        .await)
    }

    async fn create_index(
        &self,
        request: Request<pb::CreateIndexRequest>,
    ) -> Result<Response<pb::CreateIndexResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| async {
            let definition = r.definition.as_ref().ok_or_else(|| {
                Error::new(ErrorCode::InvalidArgument, "definition is required")
                    .with_detail("field", "definition")
            })?;
            let definition = create_index_from_proto(definition)?;
            let info = svc
                .create_index(&ctx, r.database, definition, r.if_not_exists)
                .await?;
            Ok(pb::CreateIndexResponse {
                index: Some(index_to_proto(&info)?),
            })
        }
        .await)
    }

    async fn drop_index(
        &self,
        request: Request<pb::DropIndexRequest>,
    ) -> Result<Response<pb::DropIndexResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| svc
            .drop_index(&ctx, r.database, r.collection, r.name, r.if_exists)
            .await
            .map(|dropped| pb::DropIndexResponse { dropped }))
    }

    async fn list_indexes(
        &self,
        request: Request<pb::ListIndexesRequest>,
    ) -> Result<Response<pb::ListIndexesResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| async {
            let indexes = svc
                .list_indexes(&ctx, r.database, r.collection)
                .await?
                .iter()
                .map(index_to_proto)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(pb::ListIndexesResponse { indexes })
        }
        .await)
    }

    async fn index_build_progress(
        &self,
        request: Request<pb::IndexBuildProgressRequest>,
    ) -> Result<Response<pb::IndexBuildProgressResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| svc
            .index_build_progress(&ctx, r.database, r.collection, r.name)
            .await
            .map(|p| pb::IndexBuildProgressResponse {
                state: state_to_proto(p.state).into(),
                docs_processed: p.docs_processed,
                docs_total: p.docs_total,
                eta_ms: None,
            }))
    }

    async fn get_validator(
        &self,
        request: Request<pb::GetValidatorRequest>,
    ) -> Result<Response<pb::GetValidatorResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| svc
            .get_validator(&ctx, r.database, r.collection)
            .await
            .map(|v| pb::GetValidatorResponse {
                validator: v.as_ref().map(validator_to_proto),
            }))
    }

    async fn set_validator(
        &self,
        request: Request<pb::SetValidatorRequest>,
    ) -> Result<Response<pb::SetValidatorResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| async {
            let v = r.validator.as_ref().ok_or_else(|| {
                Error::new(ErrorCode::InvalidArgument, "validator is required")
                    .with_detail("field", "validator")
            })?;
            svc.set_validator(&ctx, r.database, r.collection, validator_from_proto(v)?)
                .await?;
            Ok(pb::SetValidatorResponse {})
        }
        .await)
    }

    async fn remove_validator(
        &self,
        request: Request<pb::RemoveValidatorRequest>,
    ) -> Result<Response<pb::RemoveValidatorResponse>, Status> {
        schema_call!(self, request, |ctx, r, svc| svc
            .remove_validator(&ctx, r.database, r.collection)
            .await
            .map(|removed| pb::RemoveValidatorResponse { removed }))
    }
}
