// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `DocumentService`: key-based document operations (FR-DOC-001…006, FR-TXN-003,
//! protocol.md §2–§3, §5.1, §5.4; PD-045, PD-053).
//!
//! The engine offers `get` / `insert` / `replace` / `delete` and RGQL; the rest is built here,
//! always inside **one transaction per call** so a call is atomic:
//! - `if_rev` (optimistic concurrency, REST `If-Match`) reads the document in the same
//!   transaction and compares its `_rev` before writing; a mismatch — or a precondition on a
//!   missing document — is RGN-2009 and nothing is written. Under SERIALIZABLE the read joins
//!   the read set, so a concurrent change between the check and the commit aborts the commit
//!   (RGN-2001) instead of being overwritten.
//! - `Update` runs `UPDATE coll <ops> WHERE _id = $id RETURNING NEW` (the operators keep their
//!   RGQL semantics, data-model.md §2.3); `modified` compares the user fields before and after.
//! - `Upsert` reads the `_id` (generated when absent), then replaces or inserts.
//! - `GetMany` reads every id at one snapshot.
//! - `Insert` of several documents and `BulkWrite` are atomic per call: outside a transaction
//!   they share one implicit transaction; inside an interactive one they run under a
//!   savepoint, so a failing call leaves the transaction as it was (statement-level error,
//!   transactions.md §3).
//! - `BulkWrite` outside a transaction reports per-operation failures in `errors` (each failed
//!   operation is rolled back alone by its statement savepoint) and commits the others
//!   together; `ordered` stops at the first failure. Inside a transaction any failure fails
//!   the call (proto contract) and undoes the whole bulk.
//!
//! Implicit transactions retry restartable conflicts ([`super::data::run_implicit`]); writes
//! outside a transaction with a client `rgn-request-id` are deduplicated
//! ([`super::idempotency`]). Writes run with [`Completion::Await`].

use std::{collections::BTreeMap, sync::Arc};

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value};
use rustegon_engine::{Transaction, TransactionStatus, TxnOptions};
use rustegon_query::{
    Params, Statement,
    ast::{BinaryOp, Expr, Image, Path, QualifiedName, Returning, Update, UpdateOp},
};
use rustegon_security::rbac::{Action, Resource};

use super::{
    RequestContext, ServiceDeps,
    data::{
        DataPlane, ReadConsistency, WriteConcern, check_consistency, check_write_concern,
        read_only, run_implicit, txn_id_of,
    },
    query::Warning,
};
use crate::Completion;

/// Parameter carrying the document id of `Update` (reserved: client parameters may not use
/// it).
const ID_PARAM: &str = "rgn_document_id";
/// Savepoint around one call inside an interactive transaction. Not producible by the RGQL
/// parser (it contains dots), so it cannot collide with a client savepoint.
const CALL_SAVEPOINT: &str = "rustegon.server.call";
/// Server-maintained fields ignored by `modified` (they change on every write).
const SYSTEM_FIELDS: [&str; 3] = ["_rev", "_createdAt", "_updatedAt"];

/// Which version of the document a write returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReturnDocument {
    /// None.
    #[default]
    None,
    /// Before the write.
    Before,
    /// After the write.
    After,
}

/// Outcome of one written document.
#[derive(Debug, Clone, PartialEq)]
pub struct WriteResult {
    /// Document id.
    pub id: Value,
    /// New `_rev` (absent for deletes).
    pub rev: Option<String>,
}

/// Target of a document call.
#[derive(Debug, Clone)]
pub struct Target {
    /// Database.
    pub database: String,
    /// Collection.
    pub collection: String,
    /// Interactive transaction (field; `rgn-txn-id` also applies).
    pub txn_id: Option<String>,
}

/// `Get` / `GetMany` options.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOptions {
    /// Read consistency outside transactions.
    pub consistency: ReadConsistency,
}

/// Options shared by writes.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteOptions {
    /// Write concern outside transactions.
    pub write_concern: WriteConcern,
}

/// `Replace` / `Update` / `Upsert` outcome.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WriteOutput {
    /// A document with the id existed (`Replace`, `Update`).
    pub matched: bool,
    /// The document changed (`Update`).
    pub modified: bool,
    /// The document was inserted (`Upsert`).
    pub inserted: bool,
    /// Write result when something was written.
    pub result: Option<WriteResult>,
    /// The requested image.
    pub document: Option<Document>,
    /// Warnings.
    pub warnings: Vec<Warning>,
}

/// `Delete` outcome.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeleteOutput {
    /// A document was deleted.
    pub deleted: bool,
    /// The deleted document, if requested.
    pub document: Option<Document>,
}

/// `Insert` outcome.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct InsertOutput {
    /// One result per document, in request order.
    pub results: Vec<WriteResult>,
    /// Warnings.
    pub warnings: Vec<Warning>,
}

/// One operation of a bulk write.
#[derive(Debug, Clone)]
pub enum BulkOp {
    /// Insert.
    Insert {
        /// Document.
        document: Document,
    },
    /// Replace by id.
    Replace {
        /// Id.
        id: Value,
        /// New document.
        document: Document,
        /// Expected `_rev`.
        if_rev: Option<String>,
    },
    /// Update by id.
    Update {
        /// Id.
        id: Value,
        /// Operators.
        operations: Vec<UpdateOp>,
        /// Expected `_rev`.
        if_rev: Option<String>,
    },
    /// Upsert.
    Upsert {
        /// Document.
        document: Document,
    },
    /// Delete by id.
    Delete {
        /// Id.
        id: Value,
        /// Expected `_rev`.
        if_rev: Option<String>,
    },
}

/// Failure of one bulk operation (cloneable copy of the error, for idempotent replays).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkError {
    /// Index of the operation in the request.
    pub index: u32,
    /// Error code.
    pub code: ErrorCode,
    /// Message.
    pub message: String,
    /// Structured details.
    pub details: BTreeMap<String, String>,
    /// Whether retrying this operation may succeed.
    pub retryable: bool,
}

impl BulkError {
    /// The error as the common type.
    #[must_use]
    pub fn to_error(&self) -> Error {
        let mut e = Error::new(self.code, self.message.clone()).with_retryable(self.retryable);
        for (k, v) in &self.details {
            e = e.with_detail(k.clone(), v.clone());
        }
        e
    }
}

/// `BulkWrite` outcome.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BulkWriteOutput {
    /// Inserted (inserts and inserting upserts).
    pub inserted: u64,
    /// Matched by replace/update/upsert.
    pub matched: u64,
    /// Changed by replace/update/upsert.
    pub modified: u64,
    /// Deleted.
    pub deleted: u64,
    /// Failed operations.
    pub errors: Vec<BulkError>,
    /// Warnings.
    pub warnings: Vec<Warning>,
}

fn precondition_failed(reason: &str) -> Error {
    Error::new(
        ErrorCode::PreconditionFailed,
        format!("if_rev precondition failed: {reason}"),
    )
    .with_detail("field", "if_rev")
}

fn rev_of(doc: &Document) -> Option<String> {
    match doc.get("_rev") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn check_rev(current: Option<&Document>, if_rev: Option<&str>) -> Result<(), Error> {
    match (if_rev, current) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(precondition_failed("the document does not exist")),
        (Some(expected), Some(doc)) if rev_of(doc).as_deref() == Some(expected) => Ok(()),
        (Some(_), Some(_)) => Err(precondition_failed("the document has another revision")),
    }
}

fn result_of(doc: &Document) -> WriteResult {
    WriteResult {
        id: doc.get("_id").cloned().unwrap_or(Value::Null),
        rev: rev_of(doc),
    }
}

fn user_fields(doc: &Document) -> Vec<(&str, &Value)> {
    doc.iter()
        .filter(|(n, _)| !SYSTEM_FIELDS.contains(n))
        .collect()
}

fn pick(
    ret: ReturnDocument,
    before: Option<Document>,
    after: Option<Document>,
) -> Option<Document> {
    match ret {
        ReturnDocument::None => None,
        ReturnDocument::Before => before,
        ReturnDocument::After => after,
    }
}

/// `UPDATE coll <ops> WHERE _id = $rgn_document_id RETURNING NEW`, validated as canonical so
/// structured operators obey the same rules as text (query-language.md §13).
fn update_statement(
    database: &str,
    collection: &str,
    ops: Vec<UpdateOp>,
) -> Result<Statement, Error> {
    if ops.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "an update needs at least one operation",
        ));
    }
    let stmt = Statement::Update(Update {
        target: QualifiedName {
            database: Some(database.to_owned()),
            name: collection.to_owned(),
        },
        alias: None,
        ops,
        filter: Some(Expr::Binary {
            op: BinaryOp::Eq,
            left: Box::new(Expr::Path {
                path: Path::fields(["_id"]),
            }),
            right: Box::new(Expr::Param {
                name: ID_PARAM.to_owned(),
            }),
        }),
        limit: None,
        options: Vec::new(),
        returning: Some(Returning {
            image: Image::New,
            items: Vec::new(),
        }),
    });
    stmt.validate()
        .map_err(|e| Error::new(ErrorCode::QuerySyntaxError, e.to_string()))?;
    Ok(stmt)
}

/// Before/after images of one write.
type Images = (Option<Document>, Option<Document>);

/// The blocking document operations on one transaction.
struct Ops<'a> {
    txn: &'a Transaction,
    database: &'a str,
    collection: &'a str,
}

impl Ops<'_> {
    fn get(&self, id: &Value) -> Result<Option<Document>, Error> {
        self.txn.get(self.database, self.collection, id)
    }

    fn insert(&self, doc: &Document) -> Result<Document, Error> {
        self.txn.insert(self.database, self.collection, doc)
    }

    fn replace(&self, id: &Value, doc: &Document, if_rev: Option<&str>) -> Result<Images, Error> {
        let before = self.get(id)?;
        check_rev(before.as_ref(), if_rev)?;
        if before.is_none() {
            return Ok((None, None));
        }
        let after = self.txn.replace(self.database, self.collection, id, doc)?;
        Ok((before, Some(after)))
    }

    fn update(
        &self,
        id: &Value,
        stmt: &Statement,
        params: &Params,
        if_rev: Option<&str>,
    ) -> Result<Images, Error> {
        let before = self.get(id)?;
        check_rev(before.as_ref(), if_rev)?;
        if before.is_none() {
            return Ok((None, None));
        }
        let mut params = params.clone();
        params.set(ID_PARAM, id.clone());
        let result = self.txn.query(self.database, stmt, &params)?;
        let after = result.documents().into_iter().next();
        Ok((before, after))
    }

    /// `(inserted, before, after)`.
    fn upsert(&self, doc: &Document, if_rev: Option<&str>) -> Result<(bool, Images), Error> {
        let existing = match doc.get("_id") {
            Some(id) => self.get(id)?.map(|d| (id.clone(), d)),
            None => None,
        };
        match existing {
            Some((id, before)) => {
                check_rev(Some(&before), if_rev)?;
                let after = self.txn.replace(self.database, self.collection, &id, doc)?;
                Ok((false, (Some(before), Some(after))))
            }
            // `if_rev` is only meaningful when the document exists (document.proto).
            None => Ok((true, (None, Some(self.insert(doc)?)))),
        }
    }

    fn delete(&self, id: &Value, if_rev: Option<&str>) -> Result<Option<Document>, Error> {
        if if_rev.is_some() {
            let current = self.get(id)?;
            check_rev(current.as_ref(), if_rev)?;
        }
        self.txn.delete(self.database, self.collection, id)
    }
}

/// Runs `body` under a savepoint of the interactive transaction `txn`: a failing call is
/// undone as a whole and the transaction stays active (statement-level error).
fn atomic_in<T>(txn: &Transaction, body: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    let none = Params::new();
    let savepoint = |stmt: Statement| txn.query("", &stmt, &none).map(|_| ());
    savepoint(Statement::Savepoint {
        name: CALL_SAVEPOINT.to_owned(),
    })?;
    match body() {
        Ok(v) => {
            savepoint(Statement::ReleaseSavepoint {
                name: CALL_SAVEPOINT.to_owned(),
            })?;
            Ok(v)
        }
        Err(e) => {
            if txn.status() == TransactionStatus::Active {
                savepoint(Statement::RollbackToSavepoint {
                    name: CALL_SAVEPOINT.to_owned(),
                })?;
                savepoint(Statement::ReleaseSavepoint {
                    name: CALL_SAVEPOINT.to_owned(),
                })?;
            }
            Err(e)
        }
    }
}

fn check_params(params: &Params) -> Result<(), Error> {
    if params.resolve(ID_PARAM).is_ok() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("parameter ${ID_PARAM} is reserved"),
        ));
    }
    Ok(())
}

/// `DocumentService` (module docs).
#[derive(Debug, Clone)]
pub struct DocumentService {
    deps: ServiceDeps,
    plane: Arc<DataPlane>,
}

impl DocumentService {
    pub(crate) fn new(deps: ServiceDeps, plane: Arc<DataPlane>) -> Self {
        Self { deps, plane }
    }

    /// The collection privileges of a call (PD-051 rule of the RPC, checked here because it
    /// names the collection).
    async fn authorize(
        &self,
        ctx: &RequestContext,
        target: &Target,
        actions: &[Action],
    ) -> Result<(), Error> {
        let resource = Resource::collection(target.database.clone(), target.collection.clone());
        let checks: Vec<(Resource, Action)> =
            actions.iter().map(|a| (resource.clone(), *a)).collect();
        self.plane.authorize(ctx, &checks).await
    }

    /// Runs a read: in the transaction, or in an implicit read-only one.
    async fn read<T: Send + 'static>(
        &self,
        ctx: &RequestContext,
        target: &Target,
        actions: &[Action],
        body: impl Fn(&Ops<'_>) -> Result<T, Error> + Send + Sync + 'static,
    ) -> Result<T, Error> {
        self.authorize(ctx, target, actions).await?;
        let txn_id = txn_id_of(ctx, target.txn_id.as_deref())?;
        let (database, collection) = (target.database.clone(), target.collection.clone());
        if let Some(id) = txn_id {
            let lease = self.plane.txns.lease(ctx, &id)?;
            let txn = Arc::clone(lease.txn());
            let r = self
                .deps
                .executor
                .run(ctx, Completion::Abandon, move |_| {
                    body(&Ops {
                        txn: &txn,
                        database: &database,
                        collection: &collection,
                    })
                })
                .await;
            self.plane.txns.mark_finished_if_done(lease.entry());
            return r;
        }
        let db = Arc::clone(&self.plane.db);
        self.deps
            .executor
            .run(ctx, Completion::Abandon, move |token| {
                run_implicit(&db, &read_only(), token, |txn| {
                    body(&Ops {
                        txn,
                        database: &database,
                        collection: &collection,
                    })
                })
            })
            .await
    }

    /// Runs a write atomically (module docs): under a savepoint of the transaction, or in an
    /// implicit transaction deduplicated by `rgn-request-id`.
    async fn write<T: Clone + Send + Sync + 'static>(
        &self,
        ctx: &RequestContext,
        target: &Target,
        name: &'static str,
        actions: &[Action],
        body: impl Fn(&Ops<'_>, bool) -> Result<T, Error> + Send + Sync + 'static,
    ) -> Result<T, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        self.authorize(ctx, target, actions).await?;
        let txn_id = txn_id_of(ctx, target.txn_id.as_deref())?;
        let (database, collection) = (target.database.clone(), target.collection.clone());
        if let Some(id) = txn_id {
            let lease = self.plane.txns.lease(ctx, &id)?;
            let txn = Arc::clone(lease.txn());
            let r = self
                .deps
                .executor
                .run(ctx, Completion::Await, move |_| {
                    atomic_in(&txn, || {
                        body(
                            &Ops {
                                txn: &txn,
                                database: &database,
                                collection: &collection,
                            },
                            true,
                        )
                    })
                })
                .await;
            self.plane.txns.mark_finished_if_done(lease.entry());
            return r;
        }
        let db = Arc::clone(&self.plane.db);
        let executor = self.deps.executor.clone();
        let run_ctx = ctx.clone();
        let op = async move {
            executor
                .run(&run_ctx, Completion::Await, move |token| {
                    run_implicit(&db, &TxnOptions::default(), token, |txn| {
                        body(
                            &Ops {
                                txn,
                                database: &database,
                                collection: &collection,
                            },
                            false,
                        )
                    })
                })
                .await
        };
        self.plane.idempotency.run(ctx, name, op).await
    }

    /// Reads one document (`None` when missing; not an error).
    ///
    /// # Errors
    /// RGN-1030 (missing database), RGN-1001, RGN-5006.
    pub async fn get(
        &self,
        ctx: &RequestContext,
        target: &Target,
        id: Value,
        options: ReadOptions,
    ) -> Result<Option<Document>, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        check_consistency(options.consistency)?;
        self.read(ctx, target, &[Action::Find], move |ops| ops.get(&id))
            .await
    }

    /// Reads several documents at one snapshot; missing ids are omitted, order is kept.
    ///
    /// # Errors
    /// As [`DocumentService::get`].
    pub async fn get_many(
        &self,
        ctx: &RequestContext,
        target: &Target,
        ids: Vec<Value>,
        options: ReadOptions,
    ) -> Result<Vec<Document>, Error> {
        ctx.check_deadline(self.deps.clock.as_ref())?;
        check_consistency(options.consistency)?;
        self.read(ctx, target, &[Action::Find], move |ops| {
            let mut out = Vec::with_capacity(ids.len());
            for id in &ids {
                if let Some(doc) = ops.get(id)? {
                    out.push(doc);
                }
            }
            Ok(out)
        })
        .await
    }

    /// Inserts documents atomically (RGN-1005 if an id exists).
    ///
    /// # Errors
    /// Engine write errors (RGN-1002/1003/1004/1005/1006/1030), RGN-1001, RGN-5006.
    pub async fn insert(
        &self,
        ctx: &RequestContext,
        target: &Target,
        documents: Vec<Document>,
        options: WriteOptions,
    ) -> Result<InsertOutput, Error> {
        check_write_concern(options.write_concern)?;
        if documents.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "no documents to insert",
            ));
        }
        self.write(
            ctx,
            target,
            "DocumentService/Insert",
            &[Action::Insert],
            move |ops, _| {
                let mut results = Vec::with_capacity(documents.len());
                for doc in &documents {
                    results.push(result_of(&ops.insert(doc)?));
                }
                Ok(InsertOutput {
                    results,
                    warnings: Vec::new(),
                })
            },
        )
        .await
    }

    /// Replaces a whole document by id (`matched = false` and nothing written if missing).
    ///
    /// # Errors
    /// RGN-2009 (`if_rev`), engine write errors, RGN-1001, RGN-5006.
    #[allow(clippy::too_many_arguments)] // One argument per request field, like the RPC.
    pub async fn replace(
        &self,
        ctx: &RequestContext,
        target: &Target,
        id: Value,
        document: Document,
        if_rev: Option<String>,
        ret: ReturnDocument,
        options: WriteOptions,
    ) -> Result<WriteOutput, Error> {
        check_write_concern(options.write_concern)?;
        self.write(
            ctx,
            target,
            "DocumentService/Replace",
            &[Action::Update],
            move |ops, _| {
                let (before, after) = ops.replace(&id, &document, if_rev.as_deref())?;
                Ok(WriteOutput {
                    matched: before.is_some(),
                    result: after.as_ref().map(result_of),
                    document: pick(ret, before, after),
                    ..WriteOutput::default()
                })
            },
        )
        .await
    }

    /// Applies update operators to a document by id (atomic).
    ///
    /// # Errors
    /// RGN-2009, RGN-1010 (malformed operators), RGN-1001 (reserved parameter, `_id`
    /// change), engine write errors, RGN-5006.
    #[allow(clippy::too_many_arguments)] // One argument per request field, like the RPC.
    pub async fn update(
        &self,
        ctx: &RequestContext,
        target: &Target,
        id: Value,
        operations: Vec<UpdateOp>,
        if_rev: Option<String>,
        ret: ReturnDocument,
        params: Params,
        options: WriteOptions,
    ) -> Result<WriteOutput, Error> {
        check_write_concern(options.write_concern)?;
        check_params(&params)?;
        let stmt = update_statement(&target.database, &target.collection, operations)?;
        self.write(
            ctx,
            target,
            "DocumentService/Update",
            &[Action::Update],
            move |ops, _| {
                let (before, after) = ops.update(&id, &stmt, &params, if_rev.as_deref())?;
                let modified = match (&before, &after) {
                    (Some(b), Some(a)) => user_fields(b) != user_fields(a),
                    _ => false,
                };
                Ok(WriteOutput {
                    matched: before.is_some(),
                    modified,
                    result: after.as_ref().map(result_of),
                    document: pick(ret, before, after),
                    ..WriteOutput::default()
                })
            },
        )
        .await
    }

    /// Inserts the document or replaces the one with its `_id`.
    ///
    /// # Errors
    /// RGN-2009, engine write errors, RGN-5006.
    pub async fn upsert(
        &self,
        ctx: &RequestContext,
        target: &Target,
        document: Document,
        if_rev: Option<String>,
        ret: ReturnDocument,
        options: WriteOptions,
    ) -> Result<WriteOutput, Error> {
        check_write_concern(options.write_concern)?;
        self.write(
            ctx,
            target,
            "DocumentService/Upsert",
            &[Action::Insert, Action::Update],
            move |ops, _| {
                let (inserted, (before, after)) = ops.upsert(&document, if_rev.as_deref())?;
                Ok(WriteOutput {
                    matched: !inserted,
                    modified: !inserted,
                    inserted,
                    result: after.as_ref().map(result_of),
                    document: pick(ret, before, after),
                    ..WriteOutput::default()
                })
            },
        )
        .await
    }

    /// Deletes a document by id.
    ///
    /// # Errors
    /// RGN-2009, RGN-1030 (missing database), RGN-5006.
    pub async fn delete(
        &self,
        ctx: &RequestContext,
        target: &Target,
        id: Value,
        if_rev: Option<String>,
        return_document: bool,
        options: WriteOptions,
    ) -> Result<DeleteOutput, Error> {
        check_write_concern(options.write_concern)?;
        self.write(
            ctx,
            target,
            "DocumentService/Delete",
            &[Action::Delete],
            move |ops, _| {
                let deleted = ops.delete(&id, if_rev.as_deref())?;
                Ok(DeleteOutput {
                    deleted: deleted.is_some(),
                    document: if return_document { deleted } else { None },
                })
            },
        )
        .await
    }

    /// A mixed batch of writes on one collection (module docs).
    ///
    /// # Errors
    /// RGN-1001 (too many operations, reserved parameter), RGN-1010 (malformed operators),
    /// transaction errors; inside a transaction, the first failed operation (detail `index`).
    pub async fn bulk_write(
        &self,
        ctx: &RequestContext,
        target: &Target,
        operations: Vec<BulkOp>,
        ordered: bool,
        params: Params,
        options: WriteOptions,
    ) -> Result<BulkWriteOutput, Error> {
        check_write_concern(options.write_concern)?;
        check_params(&params)?;
        if operations.len() > self.plane.config.max_bulk_ops {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "a bulk write carries at most {} operations",
                    self.plane.config.max_bulk_ops
                ),
            ));
        }
        // Update statements are built (and validated) once, before any transaction.
        let mut prepared = Vec::with_capacity(operations.len());
        for op in operations {
            prepared.push(match op {
                BulkOp::Update {
                    id,
                    operations,
                    if_rev,
                } => Prepared::Update {
                    id,
                    stmt: Box::new(update_statement(
                        &target.database,
                        &target.collection,
                        operations,
                    )?),
                    if_rev,
                },
                other => Prepared::Plain(other),
            });
        }
        self.write(
            ctx,
            target,
            "DocumentService/BulkWrite",
            &[Action::BulkWrite],
            move |ops, in_txn| bulk(ops, &prepared, ordered, &params, in_txn),
        )
        .await
    }
}

enum Prepared {
    Plain(BulkOp),
    Update {
        id: Value,
        stmt: Box<Statement>,
        if_rev: Option<String>,
    },
}

/// Effect of one bulk operation on the counters.
#[derive(Default)]
struct Effect {
    inserted: u64,
    matched: u64,
    modified: u64,
    deleted: u64,
}

fn apply(ops: &Ops<'_>, op: &Prepared, params: &Params) -> Result<Effect, Error> {
    let changed = |images: &Images| match images {
        (Some(b), Some(a)) => u64::from(user_fields(b) != user_fields(a)),
        _ => 0,
    };
    Ok(match op {
        Prepared::Plain(BulkOp::Insert { document }) => {
            ops.insert(document)?;
            Effect {
                inserted: 1,
                ..Effect::default()
            }
        }
        Prepared::Plain(BulkOp::Replace {
            id,
            document,
            if_rev,
        }) => {
            let images = ops.replace(id, document, if_rev.as_deref())?;
            Effect {
                matched: u64::from(images.0.is_some()),
                modified: changed(&images),
                ..Effect::default()
            }
        }
        Prepared::Plain(BulkOp::Upsert { document }) => {
            let (inserted, images) = ops.upsert(document, None)?;
            Effect {
                inserted: u64::from(inserted),
                matched: u64::from(!inserted),
                modified: changed(&images),
                ..Effect::default()
            }
        }
        Prepared::Plain(BulkOp::Delete { id, if_rev }) => Effect {
            deleted: u64::from(ops.delete(id, if_rev.as_deref())?.is_some()),
            ..Effect::default()
        },
        Prepared::Update { id, stmt, if_rev } => {
            let images = ops.update(id, stmt, params, if_rev.as_deref())?;
            Effect {
                matched: u64::from(images.0.is_some()),
                modified: changed(&images),
                ..Effect::default()
            }
        }
        Prepared::Plain(BulkOp::Update { .. }) => {
            return Err(Error::new(ErrorCode::Internal, "unprepared bulk update"));
        }
    })
}

fn bulk(
    ops: &Ops<'_>,
    prepared: &[Prepared],
    ordered: bool,
    params: &Params,
    in_txn: bool,
) -> Result<BulkWriteOutput, Error> {
    let mut out = BulkWriteOutput::default();
    for (i, op) in prepared.iter().enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        match apply(ops, op, params) {
            Ok(e) => {
                out.inserted += e.inserted;
                out.matched += e.matched;
                out.modified += e.modified;
                out.deleted += e.deleted;
            }
            // A transaction-level error (conflict, …) aborted the whole transaction: the call
            // fails (and an implicit transaction is restarted by `run_implicit`).
            Err(e) if ops.txn.status() != TransactionStatus::Active => return Err(e),
            Err(e) if in_txn => return Err(e.with_detail("index", index.to_string())),
            Err(e) => {
                out.errors.push(BulkError {
                    index,
                    code: e.code(),
                    message: e.message().to_owned(),
                    details: e.details().clone(),
                    retryable: e.retryable(),
                });
                if ordered {
                    break;
                }
            }
        }
    }
    Ok(out)
}
