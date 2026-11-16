// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Collection handles: CRUD, find, bulk writes and indexes (rust-driver.md §4, model.yaml).
//!
//! Routing (README §4 rule 3): a single-document write whose filter is exactly
//! [`Filter::id`] goes to `DocumentService` (`Update` / `Replace` / `Upsert` / `Delete`); any
//! other filter becomes an `UPDATE`/`DELETE … LIMIT 1` statement on `QueryService.Execute`.

use std::time::Duration;

use crate::{
    Filter,
    builders::{
        IndexKeys, ParamSink, Projection, Sort, SortKey, Update, delete_statement, find_statement,
        index_definition, path_text, update_statement,
    },
    codec::{Document, Value, rdoc},
    cursor::{Cursor, decode_document},
    database::DataContext,
    error::{Error, Result},
    options::{Action, OpOptions, option_setters},
    pb::{
        self, BulkWriteRequest, CreateIndexRequest, DeleteRequest, DropIndexRequest, ExecOptions,
        ExecuteRequest, GetRequest, IndexBuildProgressRequest, IndexState as PbIndexState,
        InsertRequest, ListIndexesRequest, ReplaceRequest, UpdateRequest, UpsertRequest,
        bulk_operation, execute_request,
    },
    transport::{OpKind, unary},
};

/// A collection handle (no I/O to create; cheap to clone).
#[derive(Clone)]
pub struct Collection {
    pub(crate) ctx: DataContext,
    pub(crate) name: String,
}

impl std::fmt::Debug for Collection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Collection")
            .field("database", &self.ctx.database)
            .field("name", &self.name)
            .finish()
    }
}

/// Result of `insert_one`.
#[derive(Debug, Clone, PartialEq)]
pub struct InsertOneResult {
    /// The `_id` of the document (assigned by the server when absent).
    pub inserted_id: Value,
}

/// Result of `insert_many`.
#[derive(Debug, Clone, PartialEq)]
pub struct InsertManyResult {
    /// The `_id`s in input order.
    pub inserted_ids: Vec<Value>,
}

/// Result of updates and replacements.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UpdateResult {
    /// Matched documents (a statement reports the documents it wrote).
    pub matched_count: u64,
    /// Modified documents.
    pub modified_count: u64,
    /// The id of an upserted document.
    pub upserted_id: Option<Value>,
}

/// Result of deletes.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeleteResult {
    /// Deleted documents.
    pub deleted_count: u64,
}

/// One operation of [`Collection::bulk_write`].
#[derive(Debug, Clone)]
pub enum BulkOperation {
    /// Insert a document.
    Insert(Document),
    /// Replace the document `id` (optionally only at revision `if_rev`).
    Replace {
        /// Document id.
        id: Value,
        /// The new document.
        document: Document,
        /// Expected `_rev`.
        if_rev: Option<String>,
    },
    /// Update the document `id`.
    Update {
        /// Document id.
        id: Value,
        /// Operators.
        update: Update,
        /// Expected `_rev`.
        if_rev: Option<String>,
    },
    /// Insert or replace a document by its `_id`.
    Upsert(Document),
    /// Delete the document `id`.
    Delete {
        /// Document id.
        id: Value,
        /// Expected `_rev`.
        if_rev: Option<String>,
    },
}

/// A failed operation of a bulk write.
#[derive(Debug)]
pub struct BulkWriteError {
    /// Position in the request.
    pub index: usize,
    /// The error (catalog-coded).
    pub error: Error,
}

/// Result of [`Collection::bulk_write`]; per-operation failures are in `errors`.
#[derive(Debug, Default)]
pub struct BulkWriteResult {
    /// Inserted documents.
    pub inserted_count: u64,
    /// Matched documents.
    pub matched_count: u64,
    /// Modified documents.
    pub modified_count: u64,
    /// Deleted documents.
    pub deleted_count: u64,
    /// Failed operations.
    pub errors: Vec<BulkWriteError>,
}

/// Build state of an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexState {
    /// Being built.
    Building,
    /// Usable.
    Ready,
    /// The build failed.
    Failed,
    /// Hidden from the planner.
    Hidden,
}

impl IndexState {
    /// Lowercase name (`building`, `ready`, `failed`, `hidden`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Hidden => "hidden",
        }
    }

    fn of(s: i32) -> Self {
        match PbIndexState::try_from(s) {
            Ok(PbIndexState::Ready) => Self::Ready,
            Ok(PbIndexState::Failed) => Self::Failed,
            Ok(PbIndexState::Hidden) => Self::Hidden,
            _ => Self::Building,
        }
    }
}

/// An index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDescription {
    /// Name.
    pub name: String,
    /// Keys in order.
    pub keys: Vec<SortKey>,
    /// Unique index.
    pub unique: bool,
    /// Build state.
    pub state: IndexState,
    /// Build error, if failed.
    pub error: Option<String>,
}

fn describe(d: &pb::AstCreateIndex, state: i32, error: Option<String>) -> IndexDescription {
    IndexDescription {
        name: d.name.clone(),
        keys: d
            .keys
            .iter()
            .map(|k| SortKey {
                path: k.path.as_ref().map(path_text).unwrap_or_default(),
                descending: k.descending,
            })
            .collect(),
        unique: d.index_type == i32::from(pb::AstIndexType::Unique),
        state: IndexState::of(state),
        error,
    }
}

fn encode_doc(d: &Document) -> Result<pb::Document> {
    Ok(pb::Document {
        rdoc: rdoc::encode(d)?,
    })
}

fn value_proto(v: &Value) -> Result<pb::Value> {
    rdoc::encode_value(v)
        .map(|b| pb::Value { rdoc_value: b })
        .map_err(|e| Error::argument(format!("invalid value: {e}")))
}

fn value_of(v: Option<&pb::Value>) -> Result<Value> {
    match v {
        Some(v) => Ok(rdoc::decode_value(&v.rdoc_value)?),
        None => Ok(Value::Null),
    }
}

impl Collection {
    /// The collection name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The database name.
    #[must_use]
    pub fn database_name(&self) -> &str {
        &self.ctx.database
    }

    fn check(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::argument("empty collection name"));
        }
        self.ctx.check()
    }

    /// Inserts a document.
    pub fn insert_one(&self, document: Document) -> Action<'_, InsertOneResult> {
        Action::new(move |o| async move {
            let mut r = self.insert(vec![document], &o).await?;
            Ok(InsertOneResult {
                inserted_id: r.inserted_ids.pop().unwrap_or(Value::Null),
            })
        })
    }

    /// Inserts documents in order (atomically per request).
    pub fn insert_many(&self, documents: Vec<Document>) -> Action<'_, InsertManyResult> {
        Action::new(move |o| async move {
            if documents.is_empty() {
                return Err(Error::argument("insert_many needs at least one document"));
            }
            self.insert(documents, &o).await
        })
    }

    async fn insert(&self, docs: Vec<Document>, o: &OpOptions) -> Result<InsertManyResult> {
        self.check()?;
        let req = InsertRequest {
            database: self.ctx.database.clone(),
            collection: self.name.clone(),
            documents: docs.iter().map(encode_doc).collect::<Result<_>>()?,
            txn_id: self.ctx.txn_id(),
            options: self.ctx.write_options(o),
        };
        let r = unary!(
            self.ctx.exec,
            self.ctx.spec(OpKind::Write, o),
            document_service_client::DocumentServiceClient,
            insert,
            req
        )?;
        Ok(InsertManyResult {
            inserted_ids: r
                .results
                .iter()
                .map(|w| value_of(w.id.as_ref()))
                .collect::<Result<_>>()?,
        })
    }

    /// The document with `_id = id`, `None` when absent.
    pub fn find_by_id(&self, id: impl Into<Value>) -> Action<'_, Option<Document>> {
        let id = id.into();
        Action::new(move |o| async move {
            self.check()?;
            let req = GetRequest {
                database: self.ctx.database.clone(),
                collection: self.name.clone(),
                id: Some(value_proto(&id)?),
                txn_id: self.ctx.txn_id(),
                consistency: self.ctx.consistency(&o)?,
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::Read, &o),
                document_service_client::DocumentServiceClient,
                get,
                req
            )?;
            r.document.as_ref().map(decode_document).transpose()
        })
    }

    /// A query; finish it with [`Find::to_list`], [`Find::first`] or [`Find::cursor`].
    pub fn find(&self, filter: Filter) -> Find<'_> {
        Find {
            coll: self,
            filter,
            sort: None,
            projection: None,
            limit: None,
            skip: None,
            opts: OpOptions::default(),
            error: None,
        }
    }

    /// Updates the first matching document (lowest `_id`).
    pub fn update_one(&self, filter: Filter, update: Update) -> Action<'_, UpdateResult> {
        Action::new(move |o| async move { self.update(filter, update, true, &o).await })
    }

    /// Updates every matching document.
    pub fn update_many(&self, filter: Filter, update: Update) -> Action<'_, UpdateResult> {
        Action::new(move |o| async move { self.update(filter, update, false, &o).await })
    }

    async fn update(
        &self,
        filter: Filter,
        update: Update,
        one: bool,
        o: &OpOptions,
    ) -> Result<UpdateResult> {
        self.check()?;
        filter.check()?;
        let mut sink = ParamSink::new();
        if let (Some(id), true) = (filter.id_value(), one) {
            let req = UpdateRequest {
                database: self.ctx.database.clone(),
                collection: self.name.clone(),
                id: Some(value_proto(id)?),
                operations: update.to_ast(&mut sink)?,
                if_rev: o.if_rev.clone(),
                txn_id: self.ctx.txn_id(),
                options: self.ctx.write_options(o),
                return_document: 0,
                params: sink.params,
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::Write, o),
                document_service_client::DocumentServiceClient,
                update,
                req
            )?;
            return Ok(UpdateResult {
                matched_count: u64::from(r.matched),
                modified_count: u64::from(r.modified),
                upserted_id: None,
            });
        }
        if o.if_rev.is_some() {
            return Err(Error::argument("if_rev applies to id filters only"));
        }
        let st = update_statement(&self.name, &filter, &update, one, &mut sink)?;
        let n = self.ctx.execute_write(st, sink, o).await?;
        Ok(UpdateResult {
            matched_count: n,
            modified_count: n,
            upserted_id: None,
        })
    }

    /// Replaces the first matching document; with `upsert(true)` (id filter only) inserts it
    /// when absent.
    pub fn replace_one(&self, filter: Filter, replacement: Document) -> Action<'_, UpdateResult> {
        Action::new(move |o| async move {
            self.check()?;
            filter.check()?;
            let Some(id) = filter.id_value() else {
                if o.upsert {
                    return Err(Error::argument(
                        "an upserting replace_one needs an id filter",
                    ));
                }
                if o.if_rev.is_some() {
                    return Err(Error::argument("if_rev applies to id filters only"));
                }
                let mut s = ParamSink::new();
                let st = update_statement(
                    &self.name,
                    &filter,
                    &Update::replacement(replacement),
                    true,
                    &mut s,
                )?;
                let n = self.ctx.execute_write(st, s, &o).await?;
                return Ok(UpdateResult {
                    matched_count: n,
                    modified_count: n,
                    upserted_id: None,
                });
            };
            if o.upsert {
                let doc = with_id(replacement, id)?;
                let req = UpsertRequest {
                    database: self.ctx.database.clone(),
                    collection: self.name.clone(),
                    document: Some(encode_doc(&doc)?),
                    if_rev: o.if_rev.clone(),
                    txn_id: self.ctx.txn_id(),
                    options: self.ctx.write_options(&o),
                    return_document: 0,
                };
                let r = unary!(
                    self.ctx.exec,
                    self.ctx.spec(OpKind::Write, &o),
                    document_service_client::DocumentServiceClient,
                    upsert,
                    req
                )?;
                return Ok(if r.inserted {
                    UpdateResult {
                        upserted_id: Some(id.clone()),
                        ..UpdateResult::default()
                    }
                } else {
                    UpdateResult {
                        matched_count: 1,
                        modified_count: 1,
                        upserted_id: None,
                    }
                });
            }
            let req = ReplaceRequest {
                database: self.ctx.database.clone(),
                collection: self.name.clone(),
                id: Some(value_proto(id)?),
                document: Some(encode_doc(&replacement)?),
                if_rev: o.if_rev.clone(),
                txn_id: self.ctx.txn_id(),
                options: self.ctx.write_options(&o),
                return_document: 0,
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::Write, &o),
                document_service_client::DocumentServiceClient,
                replace,
                req
            )?;
            let m = u64::from(r.matched);
            Ok(UpdateResult {
                matched_count: m,
                modified_count: m,
                upserted_id: None,
            })
        })
    }

    /// Deletes the first matching document (lowest `_id`).
    pub fn delete_one(&self, filter: Filter) -> Action<'_, DeleteResult> {
        Action::new(move |o| async move { self.delete(filter, true, &o).await })
    }

    /// Deletes every matching document.
    pub fn delete_many(&self, filter: Filter) -> Action<'_, DeleteResult> {
        Action::new(move |o| async move { self.delete(filter, false, &o).await })
    }

    async fn delete(&self, f: Filter, one: bool, o: &OpOptions) -> Result<DeleteResult> {
        self.check()?;
        f.check()?;
        if let (Some(id), true) = (f.id_value(), one) {
            let req = DeleteRequest {
                database: self.ctx.database.clone(),
                collection: self.name.clone(),
                id: Some(value_proto(id)?),
                if_rev: o.if_rev.clone(),
                txn_id: self.ctx.txn_id(),
                options: self.ctx.write_options(o),
                return_document: false,
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::Write, o),
                document_service_client::DocumentServiceClient,
                delete,
                req
            )?;
            return Ok(DeleteResult {
                deleted_count: u64::from(r.deleted),
            });
        }
        if o.if_rev.is_some() {
            return Err(Error::argument("if_rev applies to id filters only"));
        }
        let mut s = ParamSink::new();
        let st = delete_statement(&self.name, &f, one, &mut s)?;
        Ok(DeleteResult {
            deleted_count: self.ctx.execute_write(st, s, o).await?,
        })
    }

    /// Several writes in one request (`ordered(false)` runs them all); per-operation failures
    /// are reported in the result. Inside a transaction any failure fails the call.
    pub fn bulk_write(&self, operations: Vec<BulkOperation>) -> Action<'_, BulkWriteResult> {
        Action::new(move |o| async move {
            self.check()?;
            if operations.is_empty() {
                return Err(Error::argument("a bulk write needs at least one operation"));
            }
            let mut s = ParamSink::new();
            let mut ops = Vec::with_capacity(operations.len());
            for op in &operations {
                use bulk_operation::Op;
                let op = match op {
                    BulkOperation::Insert(d) => Op::Insert(pb::BulkInsert {
                        document: Some(encode_doc(d)?),
                    }),
                    BulkOperation::Upsert(d) => Op::Upsert(pb::BulkUpsert {
                        document: Some(encode_doc(d)?),
                    }),
                    BulkOperation::Replace {
                        id,
                        document,
                        if_rev,
                    } => Op::Replace(pb::BulkReplace {
                        id: Some(value_proto(id)?),
                        document: Some(encode_doc(document)?),
                        if_rev: if_rev.clone(),
                    }),
                    BulkOperation::Update { id, update, if_rev } => Op::Update(pb::BulkUpdate {
                        id: Some(value_proto(id)?),
                        operations: update.to_ast(&mut s)?,
                        if_rev: if_rev.clone(),
                    }),
                    BulkOperation::Delete { id, if_rev } => Op::Delete(pb::BulkDelete {
                        id: Some(value_proto(id)?),
                        if_rev: if_rev.clone(),
                    }),
                };
                ops.push(pb::BulkOperation { op: Some(op) });
            }
            let req = BulkWriteRequest {
                database: self.ctx.database.clone(),
                collection: self.name.clone(),
                operations: ops,
                ordered: !o.unordered,
                txn_id: self.ctx.txn_id(),
                options: self.ctx.write_options(&o),
                params: s.params,
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::Write, &o),
                document_service_client::DocumentServiceClient,
                bulk_write,
                req
            )?;
            Ok(BulkWriteResult {
                inserted_count: r.inserted,
                matched_count: r.matched,
                modified_count: r.modified,
                deleted_count: r.deleted,
                errors: r
                    .errors
                    .iter()
                    .map(|e| BulkWriteError {
                        index: usize::try_from(e.index).unwrap_or(usize::MAX),
                        error: match &e.error {
                            Some(d) => Error::from_detail(d, e.message.clone()),
                            None => Error::from_transport(tonic::Code::Unknown, e.message.clone()),
                        },
                    })
                    .collect(),
            })
        })
    }

    /// Creates an index and waits until it is built (`unique` option).
    pub fn create_index(&self, name: &str, keys: IndexKeys) -> Action<'_, IndexDescription> {
        let name = name.to_owned();
        Action::new(move |o| async move {
            if name.is_empty() {
                return Err(Error::argument("empty index name"));
            }
            keys.check()?;
            self.ctx.not_transactional("create_index")?;
            self.check()?;
            let def = index_definition(&self.name, &name, &keys, o.unique);
            let req = CreateIndexRequest {
                database: self.ctx.database.clone(),
                definition: Some(def.clone()),
                if_not_exists: false,
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::NoRetry, &o),
                schema_service_client::SchemaServiceClient,
                create_index,
                req
            )?;
            let building = i32::from(PbIndexState::Building);
            let mut state = r.index.as_ref().map_or(building, |i| i.state);
            let info = r.index.unwrap_or_default();
            let mut delay = Duration::from_millis(10);
            while state == building {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(500));
                let preq = IndexBuildProgressRequest {
                    database: self.ctx.database.clone(),
                    collection: self.name.clone(),
                    name: name.clone(),
                };
                state = unary!(
                    self.ctx.exec,
                    self.ctx.spec(OpKind::Read, &o),
                    schema_service_client::SchemaServiceClient,
                    index_build_progress,
                    preq
                )?
                .state;
            }
            Ok(describe(
                info.definition.as_ref().unwrap_or(&def),
                state,
                info.error,
            ))
        })
    }

    /// Drops an index (`if_exists` option); `true` when dropped.
    pub fn drop_index(&self, name: &str) -> Action<'_, bool> {
        let name = name.to_owned();
        Action::new(move |o| async move {
            if name.is_empty() {
                return Err(Error::argument("empty index name"));
            }
            self.ctx.not_transactional("drop_index")?;
            self.check()?;
            let req = DropIndexRequest {
                database: self.ctx.database.clone(),
                collection: self.name.clone(),
                name,
                if_exists: o.if_exists,
            };
            Ok(unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::NoRetry, &o),
                schema_service_client::SchemaServiceClient,
                drop_index,
                req
            )?
            .dropped)
        })
    }

    /// The indexes, sorted by name.
    pub fn list_indexes(&self) -> Action<'_, Vec<IndexDescription>> {
        Action::new(move |o| async move {
            self.ctx.not_transactional("list_indexes")?;
            self.check()?;
            let req = ListIndexesRequest {
                database: self.ctx.database.clone(),
                collection: self.name.clone(),
            };
            let r = unary!(
                self.ctx.exec,
                self.ctx.spec(OpKind::Read, &o),
                schema_service_client::SchemaServiceClient,
                list_indexes,
                req
            )?;
            let mut out: Vec<IndexDescription> = r
                .indexes
                .iter()
                .map(|i| {
                    describe(
                        &i.definition.clone().unwrap_or_default(),
                        i.state,
                        i.error.clone(),
                    )
                })
                .collect();
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
    }
}

/// The replacement with `_id` set to the filter's id (an `_id` that differs is refused).
fn with_id(doc: Document, id: &Value) -> Result<Document> {
    match doc.get("_id") {
        Some(v) if v == id => Ok(doc),
        Some(_) => Err(Error::argument(
            "the replacement's _id differs from the id of the id filter",
        )),
        None => {
            let mut fields = vec![("_id".to_owned(), id.clone())];
            fields.extend(doc.into_fields());
            Ok(Document::try_from_fields(fields)?)
        }
    }
}

/// A find query being built (README §4 rule 6).
#[must_use = "finish the query with to_list, first or cursor"]
pub struct Find<'a> {
    coll: &'a Collection,
    filter: Filter,
    sort: Option<Sort>,
    projection: Option<Projection>,
    limit: Option<i64>,
    skip: Option<i64>,
    opts: OpOptions,
    error: Option<String>,
}

impl std::fmt::Debug for Find<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Find")
            .field("collection", &self.coll.name)
            .field("filter", &self.filter)
            .finish_non_exhaustive()
    }
}

impl Find<'_> {
    option_setters!();

    /// Sort order.
    pub fn sort(mut self, sort: Sort) -> Self {
        self.sort = Some(sort);
        self
    }

    /// At most `n` documents.
    pub fn limit(mut self, n: i64) -> Self {
        if n < 0 {
            self.error
                .get_or_insert_with(|| "limit must not be negative".into());
        }
        self.limit = Some(n);
        self
    }

    /// Skip the first `n` documents.
    pub fn skip(mut self, n: i64) -> Self {
        if n < 0 {
            self.error
                .get_or_insert_with(|| "skip must not be negative".into());
        }
        self.skip = Some(n);
        self
    }

    /// Projection.
    pub fn project(mut self, p: Projection) -> Self {
        self.projection = Some(p);
        self
    }

    fn request(&self, limit: Option<i64>) -> Result<ExecuteRequest> {
        if let Some(e) = &self.error {
            return Err(Error::argument(e.clone()));
        }
        if self.opts.batch_size == Some(0) {
            return Err(Error::argument("batch_size must be positive"));
        }
        if let Some(s) = &self.sort {
            s.check()?;
        }
        if let Some(p) = &self.projection {
            p.check()?;
        }
        self.filter.check()?;
        self.coll.check()?;
        let mut s = ParamSink::new();
        let st = find_statement(
            &self.coll.name,
            &self.filter,
            self.sort.as_ref(),
            self.projection.as_ref(),
            limit,
            self.skip,
            &mut s,
        )?;
        Ok(ExecuteRequest {
            database: self.coll.ctx.database.clone(),
            query: Some(execute_request::Query::Ast(st)),
            params: s.params,
            options: Some(ExecOptions {
                batch_size: self.opts.batch_size,
                consistency: self.coll.ctx.consistency(&self.opts)?,
                ..ExecOptions::default()
            }),
            txn_id: None,
        })
    }

    /// A cursor over the results.
    pub async fn cursor(self) -> Result<Cursor> {
        let req = self.request(self.limit)?;
        Cursor::open(&self.coll.ctx, req, OpKind::Read, &self.opts).await
    }

    /// Every result.
    pub async fn to_list(self) -> Result<Vec<Document>> {
        let mut c = self.cursor().await?;
        let out = c.to_list().await;
        let _ = c.close().await;
        out
    }

    /// The first result, `None` when nothing matches.
    pub async fn first(self) -> Result<Option<Document>> {
        let limit = Some(self.limit.filter(|l| *l < 1).unwrap_or(1));
        let req = self.request(limit)?;
        let mut c = Cursor::open(&self.coll.ctx, req, OpKind::Read, &self.opts).await?;
        let out = c.next().await;
        let _ = c.close().await;
        out
    }
}
