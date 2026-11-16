// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Database handles and the data context shared by databases, collections and cursors (inside or
//! outside a transaction).

use std::sync::Arc;

use crate::{
    builders::ParamSink,
    codec::{Document, rdoc},
    cursor::Cursor,
    error::{Error, Result},
    options::{Action, OpOptions, ValidationAction, ValidationLevel},
    pb::{
        self, AstStatement, CreateCollectionRequest, DropCollectionRequest, ExecOptions,
        ExecuteRequest, ListCollectionsRequest, ResultBatch, execute_request,
        query_service_client::QueryServiceClient,
    },
    settings::{ReadConsistency, WriteConcern},
    transaction::Transaction,
    transport::{Attempt, CallSpec, Executor, Failure, MAX_MESSAGE_SIZE, OpKind, unary},
};

/// Where operations run: a database of a client, optionally inside a transaction.
#[derive(Clone)]
pub(crate) struct DataContext {
    pub exec: Arc<Executor>,
    pub database: String,
    pub txn: Option<Transaction>,
}

impl DataContext {
    pub(crate) fn check(&self) -> Result<()> {
        if self.database.is_empty() {
            return Err(Error::argument(
                "no database name and no default database in the settings",
            ));
        }
        match &self.txn {
            Some(t) => t.check_active(),
            None => self.exec.check_open(),
        }
    }

    pub(crate) fn txn_id(&self) -> Option<String> {
        self.txn.as_ref().map(|t| t.id().to_owned())
    }

    /// Inside a transaction nothing is retried alone (R2) and sessions do not apply.
    pub(crate) fn spec<'o>(&self, kind: OpKind, o: &'o OpOptions) -> CallSpec<'o> {
        if self.txn.is_some() {
            CallSpec {
                kind: OpKind::NoRetry,
                timeout: o.timeout,
                session: None,
            }
        } else {
            CallSpec {
                kind,
                timeout: o.timeout,
                session: o.session.as_ref(),
            }
        }
    }

    /// The read consistency of a read (`None` inside transactions: the snapshot decides).
    pub(crate) fn consistency(&self, o: &OpOptions) -> Result<Option<pb::ReadConsistency>> {
        if self.txn.is_some() {
            return Ok(None);
        }
        let s = &self.exec.settings;
        let (level, staleness) = match o.read_consistency {
            Some((l, d)) => (Some(l), d.or(s.max_staleness)),
            None => (s.read_consistency, s.max_staleness),
        };
        consistency_of(level, staleness)
    }

    pub(crate) fn write_options(&self, o: &OpOptions) -> Option<pb::WriteOptions> {
        if self.txn.is_some() {
            return None;
        }
        Some(pb::WriteOptions {
            write_concern: concern_of(o.write_concern.or(self.exec.settings.write_concern)),
        })
    }

    pub(crate) fn not_transactional(&self, what: &str) -> Result<()> {
        if self.txn.is_some() {
            return Err(Error::argument(format!(
                "{what} is not transactional; run it on a handle of Client::database"
            )));
        }
        Ok(())
    }

    /// `QueryService.Execute`, every batch of the stream (an error after the first batch is
    /// never retried, R3).
    pub(crate) async fn execute(
        &self,
        mut req: ExecuteRequest,
        spec: CallSpec<'_>,
    ) -> Result<Vec<ResultBatch>> {
        req.txn_id = self.txn_id();
        let req = &req;
        self.exec
            .run(spec, |a: Attempt| async move {
                let mut stream = QueryServiceClient::new(a.channel.clone())
                    .max_decoding_message_size(MAX_MESSAGE_SIZE)
                    .max_encoding_message_size(MAX_MESSAGE_SIZE)
                    .execute(a.request(req.clone()))
                    .await?
                    .into_inner();
                let mut batches = Vec::new();
                loop {
                    match stream.message().await {
                        Ok(Some(m)) => batches.push(m.batch.unwrap_or_default()),
                        Ok(None) => break,
                        Err(s) => {
                            return Err(Failure {
                                error: Error::from_status(&s),
                                delivered: !batches.is_empty(),
                            });
                        }
                    }
                }
                let trailers = stream.trailers().await.ok().flatten().unwrap_or_default();
                Ok(tonic::Response::from_parts(
                    trailers,
                    batches,
                    tonic::Extensions::default(),
                ))
            })
            .await
    }

    /// A statement write; returns the server's `docs_affected`.
    pub(crate) async fn execute_write(
        &self,
        st: AstStatement,
        sink: ParamSink,
        o: &OpOptions,
    ) -> Result<u64> {
        let req = ExecuteRequest {
            database: self.database.clone(),
            query: Some(execute_request::Query::Ast(st)),
            params: sink.params,
            options: Some(ExecOptions {
                write_concern: if self.txn.is_none() {
                    concern_of(o.write_concern.or(self.exec.settings.write_concern))
                } else {
                    0
                },
                ..ExecOptions::default()
            }),
            txn_id: None,
        };
        let batches = self.execute(req, self.spec(OpKind::Write, o)).await?;
        Ok(batches
            .iter()
            .filter_map(|b| b.stats.as_ref())
            .map(|s| s.docs_affected)
            .next_back()
            .unwrap_or(0))
    }
}

pub(crate) fn consistency_of(
    level: Option<ReadConsistency>,
    staleness: Option<std::time::Duration>,
) -> Result<Option<pb::ReadConsistency>> {
    use pb::ReadConsistencyLevel as L;
    let Some(level) = level else {
        return Ok(None);
    };
    if level == ReadConsistency::BoundedStaleness && staleness.is_none_or(|d| d.is_zero()) {
        return Err(Error::argument("BoundedStaleness needs max_staleness"));
    }
    let max_staleness_ms = match (level, staleness) {
        (ReadConsistency::Linearizable, _) | (_, None) => None,
        // Round up so a bound of 1.5 ms is not tightened to 1 ms.
        (_, Some(d)) => Some(u32::try_from(d.as_micros().div_ceil(1000)).unwrap_or(u32::MAX)),
    };
    Ok(Some(pb::ReadConsistency {
        level: match level {
            ReadConsistency::Linearizable => L::Linearizable,
            ReadConsistency::BoundedStaleness => L::BoundedStaleness,
            ReadConsistency::Follower => L::Follower,
        }
        .into(),
        max_staleness_ms,
    }))
}

pub(crate) fn concern_of(wc: Option<WriteConcern>) -> i32 {
    match wc {
        None => pb::WriteConcern::Unspecified,
        Some(WriteConcern::Majority) => pb::WriteConcern::Majority,
        Some(WriteConcern::All) => pb::WriteConcern::All,
    }
    .into()
}

pub(crate) fn encode_params(
    params: &Document,
) -> Result<std::collections::HashMap<String, pb::Value>> {
    params
        .iter()
        .map(|(k, v)| {
            rdoc::encode_value(v)
                .map(|b| (k.to_owned(), pb::Value { rdoc_value: b }))
                .map_err(|e| Error::argument(format!("invalid parameter {k}: {e}")))
        })
        .collect()
}

/// A database handle (no I/O to create).
#[derive(Clone)]
pub struct Database {
    pub(crate) ctx: DataContext,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database")
            .field("name", &self.ctx.database)
            .finish()
    }
}

impl Database {
    /// The database name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.ctx.database
    }

    /// A collection handle (no I/O).
    #[must_use]
    pub fn collection(&self, name: &str) -> crate::Collection {
        crate::Collection {
            ctx: self.ctx.clone(),
            name: name.to_owned(),
        }
    }

    /// Runs RGQL text with named parameters (`$name`) and returns a cursor over the rows.
    /// The text may write, so it is retried as a write (R7).
    pub fn query(&self, rgql: &str, params: Document) -> Action<'_, Cursor> {
        let rgql = rgql.to_owned();
        Action::new(move |o| async move {
            if rgql.is_empty() {
                return Err(Error::argument("empty RGQL text"));
            }
            self.ctx.check()?;
            if o.batch_size == Some(0) {
                return Err(Error::argument("batch_size must be positive"));
            }
            let req = ExecuteRequest {
                database: self.ctx.database.clone(),
                query: Some(execute_request::Query::Rgql(rgql)),
                params: encode_params(&params)?,
                options: Some(ExecOptions {
                    batch_size: o.batch_size,
                    consistency: self.ctx.consistency(&o)?,
                    write_concern: if self.ctx.txn.is_none() {
                        concern_of(o.write_concern.or(self.ctx.exec.settings.write_concern))
                    } else {
                        0
                    },
                    ..ExecOptions::default()
                }),
                txn_id: None,
            };
            Cursor::open(&self.ctx, req, OpKind::Write, &o).await
        })
    }

    /// Creates a collection (`if_not_exists`, `validator` options); `true` when created.
    pub fn create_collection(&self, name: &str) -> Action<'_, bool> {
        let name = name.to_owned();
        Action::new(move |o| async move {
            if name.is_empty() {
                return Err(Error::argument("empty collection name"));
            }
            self.ctx.not_transactional("create_collection")?;
            self.ctx.check()?;
            let validator = o.validator.as_ref().map(|v| pb::Validator {
                definition_json: format!("{{\"$jsonSchema\":{}}}", v.json_schema),
                level: match v.level {
                    None => pb::ValidationLevel::Unspecified,
                    Some(ValidationLevel::Off) => pb::ValidationLevel::Off,
                    Some(ValidationLevel::Strict) => pb::ValidationLevel::Strict,
                    Some(ValidationLevel::Moderate) => pb::ValidationLevel::Moderate,
                }
                .into(),
                action: match v.action {
                    None => pb::ValidationAction::Unspecified,
                    Some(ValidationAction::Error) => pb::ValidationAction::Error,
                    Some(ValidationAction::Warn) => pb::ValidationAction::Warn,
                }
                .into(),
            });
            let req = CreateCollectionRequest {
                database: self.ctx.database.clone(),
                name,
                options: std::collections::HashMap::new(),
                validator,
                if_not_exists: o.if_not_exists,
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::NoRetry, &o),
                schema_service_client::SchemaServiceClient,
                create_collection,
                req
            )?;
            Ok(r.created)
        })
    }

    /// Drops a collection (`if_exists` option); `true` when dropped.
    pub fn drop_collection(&self, name: &str) -> Action<'_, bool> {
        let name = name.to_owned();
        Action::new(move |o| async move {
            if name.is_empty() {
                return Err(Error::argument("empty collection name"));
            }
            self.ctx.not_transactional("drop_collection")?;
            self.ctx.check()?;
            let req = DropCollectionRequest {
                database: self.ctx.database.clone(),
                name,
                if_exists: o.if_exists,
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::NoRetry, &o),
                schema_service_client::SchemaServiceClient,
                drop_collection,
                req
            )?;
            Ok(r.dropped)
        })
    }

    /// Collection names, sorted.
    pub fn list_collection_names(&self) -> Action<'_, Vec<String>> {
        Action::new(move |o| async move {
            self.ctx.not_transactional("list_collection_names")?;
            self.ctx.check()?;
            let req = ListCollectionsRequest {
                database: self.ctx.database.clone(),
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::Read, &o),
                schema_service_client::SchemaServiceClient,
                list_collections,
                req
            )?;
            let mut names: Vec<String> = r.collections.into_iter().map(|c| c.name).collect();
            names.sort();
            Ok(names)
        })
    }
}
