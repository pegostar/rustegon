// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Data-plane gRPC services end to end over TLS (FR-API-001, FR-QL-002/005/006/007/008,
//! FR-TXN-001/003/005/006, FR-DOC-*, FR-SCH-*, FR-IDX-001/003; PD-053): a tonic client talks
//! to [`GrpcServer`] serving `QueryService`, `DocumentService`, `TransactionService` and
//! `SchemaService` over a real `EmbeddedDb` in a temporary directory.
//!
//! Test ids (protocol.md §10, PD-053): TC-API-007 streaming, TC-API-008 cursors, TC-API-009
//! idempotency, TC-API-010 deadlines; TC-QL-007 continuation tokens; TC-TXN-* transactions;
//! `fr_*` where no TC number exists.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::assert_is_empty
)]

mod common;

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use common::{Harness, base_flags, bearer};
use prost::Message;
use rustegon_doc::{Document, Value, rdoc};
use rustegon_proto::{
    status::error_detail_of,
    v1::{
        self as pb, ast_statement, document_service_client::DocumentServiceClient,
        query_service_client::QueryServiceClient, schema_service_client::SchemaServiceClient,
        transaction_service_client::TransactionServiceClient,
    },
};
use rustegon_query::parse_statement;
use rustegon_server::{
    grpc::ast::statement_to_proto,
    services::{DataPlaneConfig, Services},
};
use rustegon_sim_api::{BoxFuture, Clock, SystemClock};
use tonic::{
    Code, Request,
    metadata::{Ascii, MetadataValue},
    service::{Interceptor, interceptor::InterceptedService},
    transport::Channel,
};

const DB: &str = "shop";
const COLL: &str = "items";

// ---------------------------------------------------------------------------------------------
// Harness: the security tests' TLS server (`tests/common`) with the data plane, and clients
// authenticated as the bootstrap administrator.
// ---------------------------------------------------------------------------------------------

/// Monotonic time jumps one hour per reading: every request deadline has passed by the
/// time the server checks it.
struct JumpingClock {
    inner: SystemClock,
    jumps: AtomicU64,
}

impl Clock for JumpingClock {
    fn monotonic(&self) -> Duration {
        let n = self.jumps.fetch_add(1, Ordering::SeqCst);
        self.inner.monotonic() + Duration::from_secs(3600 * n)
    }
    fn wall(&self) -> SystemTime {
        self.inner.wall()
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        self.inner.sleep(d)
    }
}

/// Adds `authorization` to every call that does not set it.
#[derive(Clone)]
struct Auth(MetadataValue<Ascii>);

impl Interceptor for Auth {
    fn call(&mut self, mut r: Request<()>) -> Result<Request<()>, tonic::Status> {
        if !r.metadata().contains_key("authorization") {
            r.metadata_mut().insert("authorization", self.0.clone());
        }
        Ok(r)
    }
}

type Ch = InterceptedService<Channel, Auth>;

struct Node {
    h: Harness,
    services: Services,
}

impl Node {
    async fn start(config: DataPlaneConfig, service_clock: Option<Arc<dyn Clock>>) -> Self {
        let h = Harness::start_full(base_flags(), true, Some(config), service_clock).await;
        Self {
            services: h.services.clone(),
            h,
        }
    }

    async fn default() -> Self {
        Self::start(DataPlaneConfig::default(), None).await
    }

    /// Clients authenticated with a session of `token`.
    async fn clients_with(&self, token: &str) -> Clients {
        let conn = self.h.channel().await;
        let auth = Auth(MetadataValue::try_from(bearer(token)).unwrap());
        let ch = conn.channel;
        Clients {
            query: QueryServiceClient::with_interceptor(ch.clone(), auth.clone()),
            doc: DocumentServiceClient::with_interceptor(ch.clone(), auth.clone()),
            txn: TransactionServiceClient::with_interceptor(ch.clone(), auth.clone()),
            schema: SchemaServiceClient::with_interceptor(ch, auth),
        }
    }

    /// Clients of the bootstrap administrator.
    async fn clients(&self) -> Clients {
        let token = self.h.channel().await.admin_token().await;
        self.clients_with(&token).await
    }

    async fn stop(self) {
        self.h.stop().await;
    }
}

struct Clients {
    query: QueryServiceClient<Ch>,
    doc: DocumentServiceClient<Ch>,
    txn: TransactionServiceClient<Ch>,
    schema: SchemaServiceClient<Ch>,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn doc(fields: &[(&str, Value)]) -> Document {
    Document::try_from_fields(
        fields
            .iter()
            .map(|(n, v)| ((*n).to_owned(), v.clone()))
            .collect(),
    )
    .unwrap()
}

fn pdoc(fields: &[(&str, Value)]) -> pb::Document {
    pb::Document {
        rdoc: rdoc::encode(&doc(fields)).unwrap(),
    }
}

#[allow(clippy::needless_pass_by_value)] // Call sites build the value inline.
fn pval(v: Value) -> pb::Value {
    pb::Value {
        rdoc_value: rdoc::encode_value(&v).unwrap(),
    }
}

fn decode(d: &pb::Document) -> Document {
    rdoc::decode(&d.rdoc).unwrap()
}

fn int(d: &Document, field: &str) -> i64 {
    match d.get(field) {
        Some(Value::Int64(i)) => *i,
        other => panic!("{field}: {other:?}"),
    }
}

fn rev(d: &Document) -> String {
    match d.get("_rev") {
        Some(Value::String(s)) => s.clone(),
        other => panic!("_rev: {other:?}"),
    }
}

fn detail(status: &tonic::Status) -> pb::ErrorDetail {
    error_detail_of(status).unwrap_or_else(|| panic!("no ErrorDetail in {status:?}"))
}

fn with_header<T>(message: T, name: &'static str, value: &str) -> Request<T> {
    let mut r = Request::new(message);
    r.metadata_mut()
        .insert(name, MetadataValue::try_from(value).unwrap());
    r
}

async fn create_db(c: &mut Clients) {
    c.schema
        .create_database(pb::CreateDatabaseRequest {
            name: DB.into(),
            ..Default::default()
        })
        .await
        .unwrap();
}

async fn insert_n(c: &mut Clients, n: i64) {
    let documents = (0..n)
        .map(|i| pdoc(&[("_id", Value::Int64(i)), ("n", Value::Int64(i))]))
        .collect();
    c.doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents,
            ..Default::default()
        })
        .await
        .unwrap();
}

async fn get(c: &mut Clients, id: i64, txn_id: Option<&str>) -> Option<Document> {
    c.doc
        .get(pb::GetRequest {
            database: DB.into(),
            collection: COLL.into(),
            id: Some(pval(Value::Int64(id))),
            txn_id: txn_id.map(str::to_owned),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .document
        .as_ref()
        .map(decode)
}

fn execute(rgql: &str, options: pb::ExecOptions) -> pb::ExecuteRequest {
    pb::ExecuteRequest {
        database: DB.into(),
        query: Some(pb::execute_request::Query::Rgql(rgql.into())),
        options: Some(options),
        ..Default::default()
    }
}

/// Every batch of an `Execute` stream.
async fn batches(c: &mut Clients, req: pb::ExecuteRequest) -> Vec<pb::ResultBatch> {
    let mut stream = c.query.execute(req).await.unwrap().into_inner();
    let mut out = Vec::new();
    while let Some(r) = stream.message().await.unwrap() {
        out.push(r.batch.unwrap());
    }
    out
}

fn update_ops(rgql: &str) -> Vec<pb::AstUpdateOp> {
    let stmt = statement_to_proto(&parse_statement(rgql).unwrap()).unwrap();
    match stmt.kind.unwrap() {
        ast_statement::Kind::Update(u) => u.ops,
        other => panic!("not an update: {other:?}"),
    }
}

async fn begin(c: &mut Clients) -> String {
    c.txn
        .begin(pb::BeginRequest::default())
        .await
        .unwrap()
        .into_inner()
        .txn_id
}

// ---------------------------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------------------------

/// FR-TXN-001/006: Begin → writes with `txn_id` / `rgn-txn-id` → Commit is visible only after
/// the commit; Rollback leaves nothing; Commit is idempotent; Status reports the outcome.
#[tokio::test]
async fn tc_txn_001_interactive_transaction_across_rpcs() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    create_db(&mut c).await;

    let begun = c
        .txn
        .begin(pb::BeginRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(begun.txn_id.len(), 36);
    assert!(begun.heartbeat_interval_ms > 0);
    let t = begun.txn_id;
    c.doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents: vec![pdoc(&[("_id", Value::Int64(1))])],
            txn_id: Some(t.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    // Through the header instead of the field.
    c.doc
        .insert(with_header(
            pb::InsertRequest {
                database: DB.into(),
                collection: COLL.into(),
                documents: vec![pdoc(&[("_id", Value::Int64(2))])],
                ..Default::default()
            },
            "rgn-txn-id",
            &t,
        ))
        .await
        .unwrap();
    // (A read outside the transaction would wait on its intents — MVCC readers do not skip
    // pending writes — so visibility is checked after the commit.)
    assert!(
        get(&mut c, 2, Some(&t)).await.is_some(),
        "own write invisible"
    );
    let hb = c
        .txn
        .heartbeat(pb::HeartbeatRequest { txn_id: t.clone() })
        .await
        .unwrap()
        .into_inner();
    assert!(hb.expires_in_ms > 0);
    c.txn
        .commit(pb::CommitRequest { txn_id: t.clone() })
        .await
        .unwrap();
    c.txn
        .commit(pb::CommitRequest { txn_id: t.clone() })
        .await
        .unwrap();
    let st = c
        .txn
        .status(pb::StatusRequest { txn_id: t.clone() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.state, pb::TransactionState::Committed as i32);
    assert!(get(&mut c, 1, None).await.is_some());
    assert!(get(&mut c, 2, None).await.is_some());

    // Rollback: invisible afterwards; Status says aborted (rollback).
    let r = begin(&mut c).await;
    c.doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents: vec![pdoc(&[("_id", Value::Int64(3))])],
            txn_id: Some(r.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    c.txn
        .rollback(pb::RollbackRequest { txn_id: r.clone() })
        .await
        .unwrap();
    c.txn
        .rollback(pb::RollbackRequest { txn_id: r.clone() })
        .await
        .unwrap();
    assert!(get(&mut c, 3, None).await.is_none());
    let st = c
        .txn
        .status(pb::StatusRequest { txn_id: r.clone() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.state, pb::TransactionState::Aborted as i32);
    assert_eq!(st.abort_reason.as_deref(), Some("rollback"));
    // Further operations in it: RGN-2002, not retryable.
    let err = c
        .doc
        .get(pb::GetRequest {
            database: DB.into(),
            collection: COLL.into(),
            id: Some(pval(Value::Int64(1))),
            txn_id: Some(r),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 2002);
    // Unknown and malformed ids.
    let err = c
        .txn
        .commit(pb::CommitRequest {
            txn_id: "00000000-0000-4000-8000-000000000000".into(),
        })
        .await
        .unwrap_err();
    assert_eq!((err.code(), detail(&err).code), (Code::NotFound, 1030));
    let err = c
        .txn
        .commit(pb::CommitRequest {
            txn_id: "nope".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1001);
    // Field and header naming different transactions.
    let err = c
        .doc
        .get(with_header(
            pb::GetRequest {
                database: DB.into(),
                collection: COLL.into(),
                id: Some(pval(Value::Int64(1))),
                txn_id: Some(t),
                ..Default::default()
            },
            "rgn-txn-id",
            "00000000-0000-4000-8000-000000000001",
        ))
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1001);
    assert_eq!(node.services.data().unwrap().transaction.active_count(), 0);
    node.stop().await;
}

/// FR-TXN-005: a write-write conflict between two interactive transactions surfaces as a
/// retryable error with its `ErrorDetail`; the other transaction commits.
#[tokio::test]
async fn tc_txn_002_conflict_surfaces_retryable_error_detail() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    insert_n(&mut c, 1).await;

    let t1 = begin(&mut c).await;
    // T1 reads the document…
    get(&mut c, 0, Some(&t1)).await.unwrap();
    // …T2 changes it and commits…
    let t2 = begin(&mut c).await;
    c.doc
        .replace(pb::ReplaceRequest {
            database: DB.into(),
            collection: COLL.into(),
            id: Some(pval(Value::Int64(0))),
            document: Some(pdoc(&[("n", Value::Int64(100))])),
            txn_id: Some(t2.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    c.txn
        .commit(pb::CommitRequest { txn_id: t2 })
        .await
        .unwrap();
    // …then T1 writes it: its read is stale, so T1 cannot commit (SERIALIZABLE).
    let write = c
        .doc
        .replace(pb::ReplaceRequest {
            database: DB.into(),
            collection: COLL.into(),
            id: Some(pval(Value::Int64(0))),
            document: Some(pdoc(&[("n", Value::Int64(200))])),
            txn_id: Some(t1.clone()),
            ..Default::default()
        })
        .await;
    let err = match write {
        Err(e) => e,
        Ok(_) => c
            .txn
            .commit(pb::CommitRequest { txn_id: t1 })
            .await
            .unwrap_err(),
    };
    let d = detail(&err);
    assert!(matches!(d.code, 2001 | 2002 | 2008), "{d:?}");
    assert!(d.retryable, "{d:?}");
    assert_eq!(d.trace_id.len(), 32);
    assert_eq!(int(&get(&mut c, 0, None).await.unwrap(), "n"), 100);
    node.stop().await;
}

/// The registry's client idle timeout (shorter than the engine's) aborts an idle
/// transaction with `timeout_pushed` (retryable).
#[tokio::test]
async fn tc_txn_008_client_idle_timeout_aborts_idle_transaction() {
    let node = Node::start(
        DataPlaneConfig {
            sweep_interval: Duration::from_millis(20),
            ..DataPlaneConfig::default()
        },
        None,
    )
    .await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    let t = c
        .txn
        .begin(pb::BeginRequest {
            idle_timeout_ms: Some(150),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .txn_id;
    SystemClock::new().sleep(Duration::from_millis(500)).await;
    let st = c
        .txn
        .status(pb::StatusRequest { txn_id: t.clone() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.state, pb::TransactionState::Aborted as i32);
    assert_eq!(st.abort_reason.as_deref(), Some("timeout_pushed"));
    let err = c
        .txn
        .commit(pb::CommitRequest { txn_id: t })
        .await
        .unwrap_err();
    let d = detail(&err);
    assert_eq!(d.code, 2002);
    assert!(d.retryable);
    node.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Query: streaming, cursors, tokens, explain
// ---------------------------------------------------------------------------------------------

/// TC-API-007: without `max_batches` the result streams to exhaustion in `batch_size`
/// batches; the last carries the statistics and no cursor. Structured AST requests work too.
#[tokio::test]
async fn tc_api_007_execute_streams_batches_to_exhaustion() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    insert_n(&mut c, 25).await;

    let all = batches(
        &mut c,
        execute(
            "FROM items ORDER BY n",
            pb::ExecOptions {
                batch_size: Some(10),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(
        all.iter().map(|b| b.docs.len()).collect::<Vec<_>>(),
        [10, 10, 5]
    );
    assert!(all.iter().all(|b| b.cursor_id.is_none()));
    let last = all.last().unwrap();
    assert_eq!(last.stats.as_ref().unwrap().docs_returned, 25);
    assert!(all[0].stats.is_none());
    let ns: Vec<i64> = all
        .iter()
        .flat_map(|b| b.docs.iter().map(|d| int(&decode(d), "n")))
        .collect();
    assert_eq!(ns, (0..25).collect::<Vec<_>>());

    // Structured AST and positional parameters; non-document rows are wrapped.
    let ast =
        statement_to_proto(&parse_statement("FROM items WHERE n >= $1 SELECT VALUE n").unwrap())
            .unwrap();
    let mut req = pb::ExecuteRequest {
        database: DB.into(),
        query: Some(pb::execute_request::Query::Ast(ast)),
        ..Default::default()
    };
    req.params.insert("1".into(), pval(Value::Int64(23)));
    let out = batches(&mut c, req).await;
    let mut values: Vec<i64> = out
        .iter()
        .flat_map(|b| b.docs.iter().map(|d| int(&decode(d), "value")))
        .collect();
    values.sort_unstable();
    assert_eq!(values, [23, 24]);

    // A write statement gives one batch with docs_affected.
    let out = batches(
        &mut c,
        execute(
            "UPDATE items SET tag = 'x' WHERE n < 3",
            pb::ExecOptions::default(),
        ),
    )
    .await;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].stats.as_ref().unwrap().docs_affected, 3);

    // Syntax errors carry ErrorDetail.
    let err = c
        .query
        .execute(execute("FROM", pb::ExecOptions::default()))
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1010);

    // EXPLAIN returns explain format 1.
    let plan = c
        .query
        .explain(pb::ExplainRequest {
            database: DB.into(),
            query: Some(pb::explain_request::Query::Rgql(
                "FROM items WHERE n = 1".into(),
            )),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .plan_json;
    assert!(plan.contains("\"explain_format\":1"), "{plan}");
    node.stop().await;
}

/// TC-API-008: `max_batches` ends the stream with an open cursor; `GetMore` continues it
/// (batch by batch, honouring its `batch_size`), reading to the end closes it, `KillCursor`
/// is idempotent, and an unknown cursor is RGN-1030.
#[tokio::test]
async fn tc_api_008_max_batches_get_more_and_kill_cursor() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    insert_n(&mut c, 25).await;
    let query = node.services.data().unwrap().query.clone();

    let first = batches(
        &mut c,
        execute(
            "FROM items ORDER BY n",
            pb::ExecOptions {
                batch_size: Some(10),
                max_batches: Some(1),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(first.len(), 1);
    let cursor = first[0].cursor_id.clone().expect("cursor id");
    assert_eq!(query.open_cursors(), 1);
    let more = c
        .query
        .get_more(pb::GetMoreRequest {
            cursor_id: cursor.clone(),
            batch_size: Some(4),
        })
        .await
        .unwrap()
        .into_inner()
        .batch
        .unwrap();
    assert_eq!(more.docs.len(), 4);
    assert_eq!(int(&decode(&more.docs[0]), "n"), 10);
    assert_eq!(more.cursor_id.as_deref(), Some(cursor.as_str()));
    // Read to the end: the last batch has no cursor and carries stats.
    let rest = c
        .query
        .get_more(pb::GetMoreRequest {
            cursor_id: cursor.clone(),
            batch_size: Some(100),
        })
        .await
        .unwrap()
        .into_inner()
        .batch
        .unwrap();
    assert_eq!(rest.docs.len(), 11);
    assert!(rest.cursor_id.is_none());
    assert_eq!(rest.stats.unwrap().docs_returned, 25);
    assert_eq!(query.open_cursors(), 0);
    let err = c
        .query
        .get_more(pb::GetMoreRequest {
            cursor_id: cursor.clone(),
            batch_size: None,
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1030);

    // KillCursor.
    let first = batches(
        &mut c,
        execute(
            "FROM items",
            pb::ExecOptions {
                batch_size: Some(5),
                max_batches: Some(2),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(first.len(), 2);
    let cursor = first[1].cursor_id.clone().unwrap();
    assert!(first[0].cursor_id.is_none());
    let k = c
        .query
        .kill_cursor(pb::KillCursorRequest {
            cursor_id: cursor.clone(),
        })
        .await
        .unwrap();
    assert!(k.into_inner().killed);
    let k = c
        .query
        .kill_cursor(pb::KillCursorRequest {
            cursor_id: cursor.clone(),
        })
        .await
        .unwrap();
    assert!(!k.into_inner().killed);
    assert_eq!(query.open_cursors(), 0);
    node.stop().await;
}

/// FR-QL-006: an idle cursor is closed by the registry after `cursor_idle_timeout`.
#[tokio::test]
async fn tc_api_008_idle_cursor_expires() {
    let node = Node::start(
        DataPlaneConfig {
            cursor_idle_timeout: Duration::from_millis(150),
            sweep_interval: Duration::from_millis(20),
            ..DataPlaneConfig::default()
        },
        None,
    )
    .await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    insert_n(&mut c, 10).await;
    let first = batches(
        &mut c,
        execute(
            "FROM items",
            pb::ExecOptions {
                batch_size: Some(2),
                max_batches: Some(1),
                ..Default::default()
            },
        ),
    )
    .await;
    let cursor = first[0].cursor_id.clone().unwrap();
    let query = node.services.data().unwrap().query.clone();
    let deadline = SystemClock::new().monotonic() + Duration::from_secs(10);
    while query.open_cursors() > 0 {
        assert!(
            SystemClock::new().monotonic() < deadline,
            "cursor never expired"
        );
        SystemClock::new().sleep(Duration::from_millis(20)).await;
    }
    let err = c
        .query
        .get_more(pb::GetMoreRequest {
            cursor_id: cursor,
            batch_size: None,
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1030);
    node.stop().await;
}

/// TC-API-007: cancelling the `Execute` stream kills its cursor (the producer releases the
/// engine cursor) and leaves nothing in the registry.
#[tokio::test]
async fn tc_api_007_cancelled_stream_kills_its_cursor() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    insert_n(&mut c, 50).await;
    let query = node.services.data().unwrap().query.clone();
    let mut stream = c
        .query
        .execute(execute(
            "FROM items",
            pb::ExecOptions {
                batch_size: Some(1),
                ..Default::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(stream.message().await.unwrap().is_some());
    assert_eq!(query.active_streams(), 1);
    drop(stream);
    let deadline = SystemClock::new().monotonic() + Duration::from_secs(10);
    while query.active_streams() > 0 {
        assert!(
            SystemClock::new().monotonic() < deadline,
            "stream producer kept running"
        );
        SystemClock::new().sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(query.open_cursors(), 0);
    node.stop().await;
}

/// TC-QL-007: continuation tokens are sealed; a valid one resumes after its position, a
/// tampered one is RGN-1001.
#[tokio::test]
async fn tc_ql_007_sealed_continuation_tokens() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    insert_n(&mut c, 12).await;
    let first = batches(
        &mut c,
        execute(
            "FROM items ORDER BY n",
            pb::ExecOptions {
                batch_size: Some(5),
                max_batches: Some(1),
                ..Default::default()
            },
        ),
    )
    .await;
    let token = first[0].continuation_token.clone().expect("token");
    c.query
        .kill_cursor(pb::KillCursorRequest {
            cursor_id: first[0].cursor_id.clone().unwrap(),
        })
        .await
        .unwrap();
    let resumed = batches(
        &mut c,
        execute(
            "FROM items ORDER BY n",
            pb::ExecOptions {
                continuation_token: Some(token.clone()),
                ..Default::default()
            },
        ),
    )
    .await;
    let ns: Vec<i64> = resumed
        .iter()
        .flat_map(|b| b.docs.iter().map(|d| int(&decode(d), "n")))
        .collect();
    assert_eq!(ns, (5..12).collect::<Vec<_>>());
    for i in [0, token.len() / 2, token.len() - 1] {
        let mut bad = token.clone();
        bad[i] ^= 0x40;
        let err = c
            .query
            .execute(execute(
                "FROM items ORDER BY n",
                pb::ExecOptions {
                    continuation_token: Some(bad),
                    ..Default::default()
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(
            (err.code(), detail(&err).code),
            (Code::InvalidArgument, 1001)
        );
    }
    node.stop().await;
}

/// TC-API-010: an expired deadline is RGN-5006 and the write is not applied (nothing is
/// reported failed that committed, nothing half-written).
#[tokio::test]
async fn tc_api_010_deadline_is_rgn_5006_without_partial_write() {
    let clock: Arc<dyn Clock> = Arc::new(JumpingClock {
        inner: SystemClock::new(),
        jumps: AtomicU64::new(0),
    });
    let node = Node::start(DataPlaneConfig::default(), Some(clock)).await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    let mut req = Request::new(pb::InsertRequest {
        database: DB.into(),
        collection: COLL.into(),
        documents: vec![
            pdoc(&[("_id", Value::Int64(1))]),
            pdoc(&[("_id", Value::Int64(2))]),
        ],
        ..Default::default()
    });
    req.set_timeout(Duration::from_secs(30));
    let err = c.doc.insert(req).await.unwrap_err();
    assert_eq!(
        (err.code(), detail(&err).code),
        (Code::DeadlineExceeded, 5006)
    );
    let mut req = Request::new(execute(
        "INSERT INTO items VALUE {_id: 3}",
        pb::ExecOptions::default(),
    ));
    req.set_timeout(Duration::from_secs(30));
    let err = c.query.execute(req).await.unwrap_err();
    assert_eq!(detail(&err).code, 5006);
    for id in [1, 2, 3] {
        assert!(get(&mut c, id, None).await.is_none(), "id {id} written");
    }
    node.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------------------------

/// FR-DOC: Get/GetMany/Insert/Replace/Update/Upsert/Delete with `if_rev` (RGN-2009) and
/// `ReturnDocument`.
#[tokio::test]
async fn fr_doc_document_crud_with_if_rev() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    let ins = c
        .doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents: vec![
                pdoc(&[("_id", Value::Int64(1)), ("n", Value::Int64(1))]),
                pdoc(&[("n", Value::Int64(7))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ins.results.len(), 2);
    let generated = rdoc::decode_value(&ins.results[1].id.as_ref().unwrap().rdoc_value).unwrap();
    assert!(matches!(generated, Value::ObjectId(_)));
    let d1 = get(&mut c, 1, None).await.unwrap();
    let rev1 = rev(&d1);
    assert_eq!(ins.results[0].rev.as_deref(), Some(rev1.as_str()));

    // Duplicate id: RGN-1005, nothing of the call applied.
    let err = c
        .doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents: vec![
                pdoc(&[("_id", Value::Int64(9))]),
                pdoc(&[("_id", Value::Int64(1))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!((err.code(), detail(&err).code), (Code::AlreadyExists, 1005));
    assert!(
        get(&mut c, 9, None).await.is_none(),
        "insert call not atomic"
    );

    // Replace with a stale revision: RGN-2009; with the current one: new revision.
    let replace = |if_rev: &str, n: i64| pb::ReplaceRequest {
        database: DB.into(),
        collection: COLL.into(),
        id: Some(pval(Value::Int64(1))),
        document: Some(pdoc(&[("n", Value::Int64(n))])),
        if_rev: Some(if_rev.to_owned()),
        return_document: pb::ReturnDocument::Before as i32,
        ..Default::default()
    };
    let err = c.doc.replace(replace("0000", 2)).await.unwrap_err();
    assert_eq!(
        (err.code(), detail(&err).code),
        (Code::FailedPrecondition, 2009)
    );
    let r = c.doc.replace(replace(&rev1, 2)).await.unwrap().into_inner();
    assert!(r.matched);
    assert_eq!(
        int(&decode(r.document.as_ref().unwrap()), "n"),
        1,
        "BEFORE image"
    );
    let rev2 = r.result.unwrap().rev.unwrap();
    assert_ne!(rev2, rev1);

    // Update with structured operators, AFTER image, `modified`.
    let u = c
        .doc
        .update(pb::UpdateRequest {
            database: DB.into(),
            collection: COLL.into(),
            id: Some(pval(Value::Int64(1))),
            operations: update_ops("UPDATE items INC n BY $k SET tag = 'a'"),
            if_rev: Some(rev2),
            return_document: pb::ReturnDocument::After as i32,
            params: [("k".to_owned(), pval(Value::Int64(5)))]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(u.matched && u.modified);
    let after = decode(u.document.as_ref().unwrap());
    assert_eq!(int(&after, "n"), 7);
    // Update of a missing document: matched = false.
    let u = c
        .doc
        .update(pb::UpdateRequest {
            database: DB.into(),
            collection: COLL.into(),
            id: Some(pval(Value::Int64(404))),
            operations: update_ops("UPDATE items SET a = 1"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!u.matched && u.result.is_none());

    // Upsert inserts, then replaces.
    let up = |n: i64| pb::UpsertRequest {
        database: DB.into(),
        collection: COLL.into(),
        document: Some(pdoc(&[("_id", Value::Int64(5)), ("n", Value::Int64(n))])),
        ..Default::default()
    };
    assert!(c.doc.upsert(up(1)).await.unwrap().into_inner().inserted);
    assert!(!c.doc.upsert(up(2)).await.unwrap().into_inner().inserted);
    assert_eq!(int(&get(&mut c, 5, None).await.unwrap(), "n"), 2);

    // GetMany keeps request order and omits missing ids.
    let many = c
        .doc
        .get_many(pb::GetManyRequest {
            database: DB.into(),
            collection: COLL.into(),
            ids: vec![
                pval(Value::Int64(5)),
                pval(Value::Int64(404)),
                pval(Value::Int64(1)),
            ],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .documents;
    let ids: Vec<i64> = many.iter().map(|d| int(&decode(d), "_id")).collect();
    assert_eq!(ids, [5, 1]);

    // Delete with if_rev and the deleted document returned.
    let current = rev(&get(&mut c, 5, None).await.unwrap());
    let d = c
        .doc
        .delete(pb::DeleteRequest {
            database: DB.into(),
            collection: COLL.into(),
            id: Some(pval(Value::Int64(5))),
            if_rev: Some(current),
            return_document: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(d.deleted);
    assert_eq!(int(&decode(d.document.as_ref().unwrap()), "n"), 2);
    assert!(get(&mut c, 5, None).await.is_none());
    // Missing id: not an error.
    assert!(get(&mut c, 404, None).await.is_none());
    // XDC write concerns need XDC collections.
    let err = c
        .doc
        .delete(pb::DeleteRequest {
            database: DB.into(),
            collection: COLL.into(),
            id: Some(pval(Value::Int64(1))),
            options: Some(pb::WriteOptions {
                write_concern: pb::WriteConcern::SyncCrossDc as i32,
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1001);
    node.stop().await;
}

fn bulk_insert(id: i64) -> pb::BulkOperation {
    pb::BulkOperation {
        op: Some(pb::bulk_operation::Op::Insert(pb::BulkInsert {
            document: Some(pdoc(&[("_id", Value::Int64(id))])),
        })),
    }
}

/// FR-DOC / protocol.md §5.4: BulkWrite outside a transaction reports per-operation errors
/// and commits the rest together (ordered stops at the first failure); inside a transaction a
/// failure fails the call and undoes the whole bulk, leaving the transaction usable.
#[tokio::test]
async fn fr_doc_bulk_write_atomicity() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    insert_n(&mut c, 1).await; // _id 0
    let bulk =
        |ops: Vec<pb::BulkOperation>, ordered: bool, txn_id: Option<String>| pb::BulkWriteRequest {
            database: DB.into(),
            collection: COLL.into(),
            operations: ops,
            ordered,
            txn_id,
            ..Default::default()
        };
    let out = c
        .doc
        .bulk_write(bulk(
            vec![bulk_insert(10), bulk_insert(0), bulk_insert(11)],
            false,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(out.inserted, 2);
    assert_eq!(out.errors.len(), 1);
    assert_eq!(out.errors[0].index, 1);
    assert_eq!(out.errors[0].error.as_ref().unwrap().code, 1005);
    assert!(get(&mut c, 10, None).await.is_some() && get(&mut c, 11, None).await.is_some());

    let out = c
        .doc
        .bulk_write(bulk(
            vec![bulk_insert(20), bulk_insert(0), bulk_insert(21)],
            true,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((out.inserted, out.errors.len()), (1, 1));
    assert!(get(&mut c, 20, None).await.is_some());
    assert!(
        get(&mut c, 21, None).await.is_none(),
        "ordered bulk continued after a failure"
    );

    let t = begin(&mut c).await;
    let err = c
        .doc
        .bulk_write(bulk(
            vec![bulk_insert(30), bulk_insert(0)],
            false,
            Some(t.clone()),
        ))
        .await
        .unwrap_err();
    let d = detail(&err);
    assert_eq!(d.code, 1005);
    assert_eq!(d.details.get("index").map(String::as_str), Some("1"));
    // The transaction is still active and the bulk left nothing in it.
    c.doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents: vec![pdoc(&[("_id", Value::Int64(31))])],
            txn_id: Some(t.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    c.txn.commit(pb::CommitRequest { txn_id: t }).await.unwrap();
    assert!(
        get(&mut c, 30, None).await.is_none(),
        "failed bulk left a write behind"
    );
    assert!(get(&mut c, 31, None).await.is_some());
    node.stop().await;
}

/// TC-API-009: a retried write with the same `rgn-request-id` returns the first outcome and
/// is applied once; reusing the id for another operation is RGN-1001.
#[tokio::test]
async fn tc_api_009_idempotent_retry_returns_same_result() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    create_db(&mut c).await;
    const ID: &str = "0190a6e2-3c4d-7abc-8def-0123456789ab";
    let req = || {
        with_header(
            pb::InsertRequest {
                database: DB.into(),
                collection: COLL.into(),
                documents: vec![pdoc(&[("n", Value::Int64(1))])],
                ..Default::default()
            },
            "rgn-request-id",
            ID,
        )
    };
    let first = c.doc.insert(req()).await.unwrap().into_inner();
    let second = c.doc.insert(req()).await.unwrap().into_inner();
    assert_eq!(first, second);
    let count = batches(&mut c, execute("FROM items", pb::ExecOptions::default())).await;
    assert_eq!(count.iter().map(|b| b.docs.len()).sum::<usize>(), 1);
    let err = c
        .doc
        .delete(with_header(
            pb::DeleteRequest {
                database: DB.into(),
                collection: COLL.into(),
                id: Some(pval(Value::Int64(1))),
                ..Default::default()
            },
            "rgn-request-id",
            ID,
        ))
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1001);
    node.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------------------------

/// FR-SCH-001/002, FR-IDX-001/003: databases, collections, validators and background index
/// builds through SchemaService.
#[tokio::test]
async fn fr_sch_schema_service_operations() {
    let node = Node::default().await;
    let mut c = node.clients().await;
    let s = &mut c.schema;
    let created = s
        .create_database(pb::CreateDatabaseRequest {
            name: DB.into(),
            options: [(
                "implicit_collection_creation".to_owned(),
                pval(Value::Bool(false)),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(created.created);
    let err = s
        .create_database(pb::CreateDatabaseRequest {
            name: DB.into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1031);
    let again = s
        .create_database(pb::CreateDatabaseRequest {
            name: DB.into(),
            if_not_exists: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!again.created);
    let dbs = s
        .list_databases(pb::ListDatabasesRequest {})
        .await
        .unwrap()
        .into_inner()
        .databases;
    assert_eq!(dbs.len(), 1);
    assert_eq!(dbs[0].name, DB);

    // Implicit creation is off: inserting into a missing collection is RGN-1030.
    let err = c
        .doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents: vec![pdoc(&[("n", Value::Int64(1))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1030);

    let validator = pb::Validator {
        definition_json: r#"{"$jsonSchema":{"required":["n"]}}"#.into(),
        ..Default::default()
    };
    let s = &mut c.schema;
    s.create_collection(pb::CreateCollectionRequest {
        database: DB.into(),
        name: COLL.into(),
        validator: Some(validator.clone()),
        ..Default::default()
    })
    .await
    .unwrap();
    let got = s
        .get_validator(pb::GetValidatorRequest {
            database: DB.into(),
            collection: COLL.into(),
        })
        .await
        .unwrap()
        .into_inner()
        .validator
        .unwrap();
    assert_eq!(got.definition_json, validator.definition_json);
    assert_eq!(got.level, pb::ValidationLevel::Strict as i32);
    let err = c
        .doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents: vec![pdoc(&[("m", Value::Int64(1))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1006);
    insert_n(&mut c, 20).await;
    let s = &mut c.schema;
    assert!(
        s.remove_validator(pb::RemoveValidatorRequest {
            database: DB.into(),
            collection: COLL.into(),
        })
        .await
        .unwrap()
        .into_inner()
        .removed
    );
    let colls = s
        .list_collections(pb::ListCollectionsRequest {
            database: DB.into(),
        })
        .await
        .unwrap()
        .into_inner()
        .collections;
    assert_eq!(colls.len(), 1);
    assert!(colls[0].validator.is_none());

    // Index: created BUILDING, then READY through IndexBuildProgress; listed with its
    // structured definition.
    let definition = match statement_to_proto(
        &parse_statement("CREATE UNIQUE INDEX by_n ON items (n DESC) WITH (sparse = true)")
            .unwrap(),
    )
    .unwrap()
    .kind
    .unwrap()
    {
        ast_statement::Kind::CreateIndex(ci) => ci,
        other => panic!("{other:?}"),
    };
    let info = s
        .create_index(pb::CreateIndexRequest {
            database: DB.into(),
            definition: Some(definition.clone()),
            if_not_exists: false,
        })
        .await
        .unwrap()
        .into_inner()
        .index
        .unwrap();
    assert_eq!(info.state, pb::IndexState::Building as i32);
    let deadline = SystemClock::new().monotonic() + Duration::from_secs(20);
    loop {
        let p = s
            .index_build_progress(pb::IndexBuildProgressRequest {
                database: DB.into(),
                collection: COLL.into(),
                name: "by_n".into(),
            })
            .await
            .unwrap()
            .into_inner();
        if p.state == pb::IndexState::Ready as i32 {
            break;
        }
        assert_eq!(p.state, pb::IndexState::Building as i32);
        assert!(
            SystemClock::new().monotonic() < deadline,
            "index never became ready"
        );
        SystemClock::new().sleep(Duration::from_millis(20)).await;
    }
    let listed = s
        .list_indexes(pb::ListIndexesRequest {
            database: DB.into(),
            collection: COLL.into(),
        })
        .await
        .unwrap()
        .into_inner()
        .indexes;
    assert_eq!(listed.len(), 1);
    let def = listed[0].definition.as_ref().unwrap();
    assert_eq!(def.name, "by_n");
    assert!(!def.encode_to_vec().is_empty());
    // Same definition again with if_not_exists: no change; without: RGN-1020.
    let same = s
        .create_index(pb::CreateIndexRequest {
            database: DB.into(),
            definition: Some(definition.clone()),
            if_not_exists: true,
        })
        .await
        .unwrap()
        .into_inner()
        .index
        .unwrap();
    assert_eq!(same.state, pb::IndexState::Ready as i32);
    let err = s
        .create_index(pb::CreateIndexRequest {
            database: DB.into(),
            definition: Some(definition),
            if_not_exists: false,
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1020);
    // The unique index is enforced.
    let err = c
        .doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents: vec![pdoc(&[("n", Value::Int64(3))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1005);
    let s = &mut c.schema;
    assert!(
        s.drop_index(pb::DropIndexRequest {
            database: DB.into(),
            collection: COLL.into(),
            name: "by_n".into(),
            if_exists: false,
        })
        .await
        .unwrap()
        .into_inner()
        .dropped
    );
    let err = s
        .drop_index(pb::DropIndexRequest {
            database: DB.into(),
            collection: COLL.into(),
            name: "by_n".into(),
            if_exists: false,
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1021);
    assert!(
        s.drop_collection(pb::DropCollectionRequest {
            database: DB.into(),
            name: COLL.into(),
            if_exists: false,
        })
        .await
        .unwrap()
        .into_inner()
        .dropped
    );
    assert!(
        !s.drop_collection(pb::DropCollectionRequest {
            database: DB.into(),
            name: COLL.into(),
            if_exists: true,
        })
        .await
        .unwrap()
        .into_inner()
        .dropped
    );
    assert!(
        s.drop_database(pb::DropDatabaseRequest {
            name: DB.into(),
            if_exists: false,
        })
        .await
        .unwrap()
        .into_inner()
        .dropped
    );
    assert!(
        s.list_databases(pb::ListDatabasesRequest {})
            .await
            .unwrap()
            .into_inner()
            .databases
            .is_empty()
    );
    node.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Authorization (PD-051 rules, enforced by the data services; PD-053)
// ---------------------------------------------------------------------------------------------

/// TC-SEC-001 (data plane): collection privileges are checked on the collection the request
/// names, `Execute` per statement, listings are filtered, and transactions and cursors belong
/// to the principal that created them.
#[tokio::test]
async fn tc_sec_001_data_plane_privileges_and_handle_ownership() {
    use common::{Binding, OTHER_PASSWORD, authed};
    use pb::{
        CreateRoleRequest, CreateUserRequest, Privilege, Role, RoleGrant,
        admin_service_client::AdminServiceClient,
    };

    let node = Node::default().await;
    let mut admin = node.clients().await;
    create_db(&mut admin).await;
    insert_n(&mut admin, 3).await;
    admin
        .doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: "secret".into(),
            documents: vec![pdoc(&[("_id", Value::Int64(1))])],
            ..Default::default()
        })
        .await
        .unwrap();

    // `reader` may only find in shop.items.
    let conn = node.h.channel().await;
    let admin_auth = bearer(&conn.admin_token().await);
    let mut accounts = AdminServiceClient::new(conn.channel.clone());
    accounts
        .create_role(authed(
            CreateRoleRequest {
                role: Some(Role {
                    name: "items-reader".into(),
                    privileges: vec![Privilege {
                        resource: "collection:shop.items".into(),
                        actions: vec!["find".into()],
                    }],
                    inherits: vec![],
                    built_in: false,
                }),
            },
            &admin_auth,
        ))
        .await
        .unwrap();
    accounts
        .create_user(authed(
            CreateUserRequest {
                name: "reader".into(),
                password: Some(OTHER_PASSWORD.into()),
                roles: vec![RoleGrant {
                    role: "items-reader".into(),
                    resource: String::new(),
                }],
                ..CreateUserRequest::default()
            },
            &admin_auth,
        ))
        .await
        .unwrap();
    let token = conn
        .login("reader", OTHER_PASSWORD, Binding::Plus)
        .await
        .unwrap()
        .session_token;
    let mut reader = node.clients_with(&token).await;

    assert!(get(&mut reader, 0, None).await.is_some());
    let err = reader
        .doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: COLL.into(),
            documents: vec![pdoc(&[("n", Value::Int64(9))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), detail(&err).code),
        (Code::PermissionDenied, 4002)
    );
    // Statements: reading items is allowed; another collection or a write is not.
    let rows = batches(
        &mut reader,
        execute("FROM items", pb::ExecOptions::default()),
    )
    .await;
    assert_eq!(rows.iter().map(|b| b.docs.len()).sum::<usize>(), 3);
    for denied in [
        "FROM secret",
        "UPDATE items SET a = 1 WHERE _id = 0",
        "CREATE INDEX i ON items (a)",
    ] {
        let err = reader
            .query
            .execute(execute(denied, pb::ExecOptions::default()))
            .await
            .unwrap_err();
        assert_eq!(detail(&err).code, 4002, "{denied}");
    }
    // Listings show only what the caller may see.
    let colls = reader
        .schema
        .list_collections(pb::ListCollectionsRequest {
            database: DB.into(),
        })
        .await
        .unwrap()
        .into_inner()
        .collections;
    assert_eq!(
        colls.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        [COLL]
    );
    let all = admin
        .schema
        .list_collections(pb::ListCollectionsRequest {
            database: DB.into(),
        })
        .await
        .unwrap()
        .into_inner()
        .collections;
    assert_eq!(all.len(), 2);

    // Handles of another principal are unknown to the caller.
    let t = begin(&mut admin).await;
    let err = reader
        .txn
        .status(pb::StatusRequest { txn_id: t.clone() })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1030);
    let first = batches(
        &mut admin,
        execute(
            "FROM items",
            pb::ExecOptions {
                batch_size: Some(1),
                max_batches: Some(1),
                ..Default::default()
            },
        ),
    )
    .await;
    let cursor = first[0].cursor_id.clone().unwrap();
    let err = reader
        .query
        .get_more(pb::GetMoreRequest {
            cursor_id: cursor.clone(),
            batch_size: None,
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 1030);
    let killed = reader
        .query
        .kill_cursor(pb::KillCursorRequest {
            cursor_id: cursor.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .killed;
    assert!(!killed);
    // Still the admin's.
    admin
        .query
        .get_more(pb::GetMoreRequest {
            cursor_id: cursor,
            batch_size: None,
        })
        .await
        .unwrap();
    admin
        .txn
        .rollback(pb::RollbackRequest { txn_id: t })
        .await
        .unwrap();
    // Anonymous callers are refused by the gate.
    let mut anon = QueryServiceClient::new(node.h.channel().await.channel);
    let err = anon
        .kill_cursor(pb::KillCursorRequest {
            cursor_id: "x".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(detail(&err).code, 4001);
    node.stop().await;
}

/// Creates role `role` with `privileges` (`(resource, actions)`) and a user `user` holding
/// it, and returns clients logged in as that user.
async fn user_with(node: &Node, user: &str, privileges: &[(&str, &[&str])]) -> Clients {
    use common::{Binding, OTHER_PASSWORD, authed};
    use pb::{
        CreateRoleRequest, CreateUserRequest, Privilege, Role, RoleGrant,
        admin_service_client::AdminServiceClient,
    };

    let conn = node.h.channel().await;
    let admin_auth = bearer(&conn.admin_token().await);
    let mut accounts = AdminServiceClient::new(conn.channel.clone());
    let role = format!("{user}-role");
    let privileges = privileges
        .iter()
        .map(|(resource, actions)| Privilege {
            resource: (*resource).into(),
            actions: actions.iter().map(|a| (*a).into()).collect(),
        })
        .collect();
    accounts
        .create_role(authed(
            CreateRoleRequest {
                role: Some(Role {
                    name: role.clone(),
                    privileges,
                    inherits: vec![],
                    built_in: false,
                }),
            },
            &admin_auth,
        ))
        .await
        .unwrap();
    accounts
        .create_user(authed(
            CreateUserRequest {
                name: user.into(),
                password: Some(OTHER_PASSWORD.into()),
                roles: vec![RoleGrant {
                    role,
                    resource: String::new(),
                }],
                ..CreateUserRequest::default()
            },
            &admin_auth,
        ))
        .await
        .unwrap();
    let token = conn
        .login(user, OTHER_PASSWORD, Binding::Plus)
        .await
        .unwrap()
        .session_token;
    node.clients_with(&token).await
}

/// The outcome of `Execute`: `Ok(affected)` or the RGN code of the error, whether the call
/// or the stream fails.
async fn outcome(c: &mut Clients, rgql: &str) -> Result<u64, u32> {
    let mut stream = c
        .query
        .execute(execute(rgql, pb::ExecOptions::default()))
        .await
        .map_err(|e| detail(&e).code)?
        .into_inner();
    let mut affected = 0;
    while let Some(r) = stream.message().await.map_err(|e| detail(&e).code)? {
        affected += r.batch.and_then(|b| b.stats).map_or(0, |s| s.docs_affected);
    }
    Ok(affected)
}

/// The outcome of `Explain` of `rgql`: `Ok(())` or the RGN code of the error.
async fn explain_outcome(c: &mut Clients, rgql: &str) -> Result<(), u32> {
    c.query
        .explain(pb::ExplainRequest {
            database: DB.into(),
            query: Some(pb::explain_request::Query::Rgql(rgql.into())),
            ..Default::default()
        })
        .await
        .map(|_| ())
        .map_err(|e| detail(&e).code)
}

/// `privilege_denied` audit records of `user` on `resource` / `action`.
fn denials(node: &Node, user: &str, resource: &str, action: &str) -> usize {
    node.h
        .audit_lines()
        .iter()
        .filter(|l| {
            l["event"] == "privilege_denied"
                && l["outcome"] == "denied"
                && l["user"] == user
                && l["resource"] == resource
                && l["action"] == action
        })
        .count()
}

/// TC-SEC-001 / FR-SEC-002 (PD-056): `Execute` and `Explain` check `find` on **every**
/// collection a statement reads — sub-query sources, `LOOKUP` clauses and stages with their
/// pipelines, `UNION WITH`, `FACET` sub-pipelines, `GRAPH LOOKUP`, map-reduce `INDEX` sources,
/// `load(id, 'coll')` anywhere in an expression and the source of `INSERT … FROM` — and
/// `aggregate_write` on `OUT` / `MERGE` targets. A user with privileges on `items` only is
/// denied (RGN-4002, audited) reading `secret` through each form; a user also granted on
/// `secret` passes authorization (the statement then runs, or fails with the engine's own
/// RGN-1001 for a form of a later milestone). Reads whose collection is not named
/// (`INCLUDE`, `load(id)`) need `find` on `cluster`.
#[tokio::test]
async fn tc_sec_001_statement_privileges_cover_every_collection_read() {
    let node = Node::default().await;
    let mut admin = node.clients().await;
    create_db(&mut admin).await;
    insert_n(&mut admin, 3).await;
    admin
        .doc
        .insert(pb::InsertRequest {
            database: DB.into(),
            collection: "secret".into(),
            documents: vec![pdoc(&[("_id", Value::Int64(100)), ("n", Value::Int64(0))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let items: &[&str] = &["find", "insert", "update", "delete"];
    let mut reader = user_with(&node, "reader", &[("collection:shop.items", items)]).await;
    let mut trusted = user_with(
        &node,
        "trusted",
        &[
            ("collection:shop.items", items),
            ("collection:shop.secret", &["find", "aggregate_write"]),
        ],
    )
    .await;

    let reads = [
        "FROM (FROM secret) AS s",
        "FROM items LOOKUP secret ON n = _id INTO j",
        "FROM items LOOKUP shop.secret AS s ON n = s._id INTO j",
        "FROM items |> LOOKUP secret ON n = _id INTO j",
        "FROM items |> LOOKUP items ON n = _id INTO j PIPELINE (LOOKUP secret ON n = _id INTO k)",
        "FROM items |> UNION WITH (FROM secret)",
        "FROM items |> UNION WITH (FROM items |> UNION WITH (FROM shop.secret))",
        "FROM items |> FACET a (COUNT AS c), b (UNION WITH (FROM secret))",
        "FROM items |> GRAPH LOOKUP secret START WITH n CONNECT FROM n TO _id INTO g",
        "FROM INDEX secret.by_n",
        "FROM items SELECT load(n, 'secret') AS s",
        "FROM items SELECT VALUE load(n, 'shop.secret')",
        "FROM items WHERE load(n, 'secret') IS NOT NULL",
        "FROM items WHERE ANY x IN [n] SATISFIES load(x, 'secret').n = 0",
        "FROM items SELECT VALUE map([n], x -> load(x, 'secret'))",
        "FROM items GROUP BY n HAVING count(load(n, 'secret')) > 0",
        "FROM items ORDER BY load(n, 'secret').n",
        "FROM items |> SET s = load(n, 'secret')",
        "UPDATE items SET s = load(n, 'secret') WHERE _id = 0",
        "UPDATE items SET a = 1 WHERE load(n, 'secret') IS NULL",
        "DELETE FROM items WHERE load(n, 'secret') IS NULL",
        "UPSERT INTO items VALUE {_id: 9, s: load(100, 'secret')}",
        "INSERT INTO items VALUE {_id: 9, s: load(100, 'secret')}",
        "EXPLAIN FROM items |> UNION WITH (FROM secret)",
        "EXPLAIN UPDATE items SET a = 1 WHERE load(n, 'secret') IS NULL",
    ];
    for rgql in reads {
        let before = denials(&node, "reader", "collection:shop.secret", "find");
        assert_eq!(
            outcome(&mut reader, rgql).await,
            Err(4002),
            "reader: {rgql}"
        );
        assert_eq!(
            denials(&node, "reader", "collection:shop.secret", "find"),
            before + 1,
            "audit of {rgql}"
        );
        let granted = outcome(&mut trusted, rgql).await;
        assert!(granted != Err(4002), "trusted: {rgql}: {granted:?}");
    }

    // `Explain` checks the same privileges as the statement it plans.
    for rgql in [
        "FROM items |> UNION WITH (FROM secret)",
        "FROM items LOOKUP secret ON n = _id INTO j",
        "FROM items WHERE load(n, 'secret') IS NOT NULL",
        "UPDATE items SET a = 1 WHERE load(n, 'secret') IS NULL",
        "DELETE FROM items WHERE load(n, 'secret') IS NULL",
    ] {
        let before = denials(&node, "reader", "collection:shop.secret", "find");
        assert_eq!(
            explain_outcome(&mut reader, rgql).await,
            Err(4002),
            "explain: {rgql}"
        );
        assert_eq!(
            denials(&node, "reader", "collection:shop.secret", "find"),
            before + 1,
            "audit of explain {rgql}"
        );
        let granted = explain_outcome(&mut trusted, rgql).await;
        assert!(granted != Err(4002), "trusted explain: {rgql}: {granted:?}");
    }

    // `INSERT … FROM` runs today: denied, nothing is copied; granted, the row is copied.
    let copy = "INSERT INTO items FROM secret SELECT _id, n";
    assert_eq!(outcome(&mut reader, copy).await, Err(4002));
    assert!(get(&mut admin, 100, None).await.is_none());
    assert_eq!(outcome(&mut trusted, copy).await, Ok(1));
    assert!(get(&mut admin, 100, None).await.is_some());

    // Pipeline writes need `aggregate_write` on their target.
    for rgql in [
        "FROM items |> OUT INTO secret",
        "FROM items |> MERGE INTO secret ON _id WHEN NOT MATCHED INSERT",
    ] {
        let before = denials(&node, "reader", "collection:shop.secret", "aggregate_write");
        assert_eq!(outcome(&mut reader, rgql).await, Err(4002), "{rgql}");
        assert_eq!(
            denials(&node, "reader", "collection:shop.secret", "aggregate_write"),
            before + 1
        );
        let granted = outcome(&mut trusted, rgql).await;
        assert!(granted != Err(4002), "trusted: {rgql}: {granted:?}");
    }

    // Reads whose collection is not named fail closed: only a cluster-wide `find` passes.
    for rgql in [
        "FROM items INCLUDE n",
        "FROM items SELECT load(n) AS s",
        "FROM items SELECT load(n, $coll) AS s",
    ] {
        for (user, client) in [("reader", &mut reader), ("trusted", &mut trusted)] {
            let before = denials(&node, user, "cluster", "find");
            assert_eq!(outcome(client, rgql).await, Err(4002), "{user}: {rgql}");
            assert_eq!(denials(&node, user, "cluster", "find"), before + 1);
        }
        let root = outcome(&mut admin, rgql).await;
        assert!(root != Err(4002), "root: {rgql}: {root:?}");
    }
    node.stop().await;
}
