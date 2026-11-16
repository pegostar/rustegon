// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The in-process fake gRPC server of `retry.yaml` (README §8, PD-073) and the scenario runner
//! (TC-DRV-RS-016).
//!
//! The server is generic: one tonic service per `rustegon.v1` service name routes every method
//! through raw bytes; requests are decoded and replies built from protobuf JSON with
//! `prost-reflect` over the driver's descriptor set, with documents and values written as
//! canonical extended JSON (encoded to RDoc here). Every call is recorded with its
//! `rgn-request-id`, whether it carried `grpc-timeout`, and its arrival and reply times.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use bytes::{Buf as _, BufMut as _, Bytes};
use hmac::{Hmac, KeyInit, Mac};
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, Kind, MessageDescriptor};
use rustegon::{
    Client, Credential, Settings, Value,
    codec::{ObjectId, rdoc},
    pb,
};
use sha2::{Digest, Sha256};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::{
    Request, Response, Status, Streaming,
    body::Body,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    codegen::{BoxFuture, Service, http},
    server::{Grpc, NamedService, StreamingService},
};

use crate::{
    runner::Run,
    yaml::{Y, Yaml, load, plain, to_document, to_json, to_value},
};

const SCRAM_USER: &str = "fake";
const SCRAM_PASSWORD: &str = "fake-password-123";
const TXN_ID: &str = "0190f3a4-7b1c-7cc1-8a9e-1d2c3b4a5f60";
/// Absorbs scheduling delays on a loaded host (retry.yaml header).
const TOLERANCE: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
struct Call {
    rpc: String,
    request_id: String,
    has_timeout: bool,
    arrival: Instant,
    replied: Option<Instant>,
    failed: bool,
}

struct State {
    script: HashMap<String, Vec<Yaml>>,
    consumed: HashMap<String, usize>,
    calls: Vec<Call>,
    sessions: u32,
}

struct Fake {
    pool: DescriptorPool,
    grpc_of_code: HashMap<i64, String>,
    state: Mutex<State>,
}

impl Fake {
    fn record(&self, rpc: &str, md: &tonic::metadata::MetadataMap) -> usize {
        let call = Call {
            rpc: rpc.to_owned(),
            request_id: md
                .get("rgn-request-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned(),
            has_timeout: md.get("grpc-timeout").is_some(),
            arrival: Instant::now(),
            replied: None,
            failed: false,
        };
        let mut s = self.state.lock().unwrap();
        s.calls.push(call);
        s.calls.len() - 1
    }

    fn done(&self, i: usize, failed: bool) {
        let mut s = self.state.lock().unwrap();
        s.calls[i].replied = Some(Instant::now());
        s.calls[i].failed = failed;
    }

    /// The next scripted reply of `rpc`; the last one repeats; `None` = default `ok`.
    fn next(&self, rpc: &str) -> Option<Yaml> {
        let mut s = self.state.lock().unwrap();
        let replies = s.script.get(rpc)?.clone();
        if replies.is_empty() {
            return None;
        }
        let n = s.consumed.entry(rpc.to_owned()).or_insert(0);
        let r = replies[(*n).min(replies.len() - 1)].clone();
        *n += 1;
        Some(r)
    }

    fn error_status(&self, e: &Yaml) -> Status {
        let code = e.int("code").unwrap_or(5001);
        let Some(grpc) = self.grpc_of_code.get(&code) else {
            return Status::internal(format!("unknown code {code}"));
        };
        let mut trace = [0u8; 16];
        getrandom::fill(&mut trace).ok();
        let d = pb::ErrorDetail {
            code: u32::try_from(code).unwrap_or(5001),
            name: rustegon::__conformance::name_of(u32::try_from(code).unwrap_or(0)),
            retryable: e.is_true("retryable"),
            committed: e.get("committed").as_bool(),
            details: e
                .get("details")
                .as_hash()
                .map(|h| {
                    h.iter()
                        .map(|(k, v)| {
                            (
                                k.as_str().unwrap_or("").to_owned(),
                                v.as_str().map_or_else(|| to_json(v), str::to_owned),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            trace_id: rustegon::codec::to_hex(&trace),
            retry_after_ms: e.int("retryAfterMs").and_then(|ms| u32::try_from(ms).ok()),
        };
        let code = crate::checks::grpc_code_of(grpc);
        let rpc = RpcStatus {
            code: code as i32,
            message: d.name.clone(),
            details: vec![Any {
                type_url: "type.googleapis.com/rustegon.v1.ErrorDetail".into(),
                value: d.encode_to_vec(),
            }],
        };
        Status::with_details(code, d.name.clone(), rpc.encode_to_vec().into())
    }

    /// Protobuf JSON → message bytes, with `Document`/`Value` fields from extended JSON.
    fn build(&self, desc: &MessageDescriptor, y: &Yaml) -> Result<Bytes, String> {
        let json = convert(desc, y)?;
        let m = DynamicMessage::deserialize(desc.clone(), json).map_err(|e| e.to_string())?;
        Ok(m.encode_to_vec().into())
    }

    fn ok_replies(
        &self,
        rpc: &str,
        method: &prost_reflect::MethodDescriptor,
        req: &[u8],
        ok: Option<&Yaml>,
    ) -> Result<Vec<Bytes>, String> {
        let output = method.output();
        let Some(ok) = ok.filter(|o| !o.is_null() && !o.is_badvalue()) else {
            return Ok(vec![default_reply(rpc, req)]);
        };
        if rpc == "QueryService.Execute" {
            return ok
                .list("batches")
                .iter()
                .map(|b| {
                    let mut h = yaml_rust2::yaml::Hash::new();
                    h.insert(Yaml::String("batch".into()), b.clone());
                    self.build(&output, &Yaml::Hash(h))
                })
                .collect();
        }
        Ok(vec![self.build(&output, ok)?])
    }
}

fn default_reply(rpc: &str, req: &[u8]) -> Bytes {
    let v = match rpc {
        "SessionService.GetServerInfo" => pb::GetServerInfoResponse {
            server_version: "0.0.0-fake".into(),
            protocol_version: "1.0".into(),
            ..Default::default()
        }
        .encode_to_vec(),
        "TransactionService.Begin" => pb::BeginResponse {
            txn_id: TXN_ID.into(),
            heartbeat_interval_ms: 1000,
        }
        .encode_to_vec(),
        "TransactionService.Status" => pb::StatusResponse {
            state: pb::TransactionState::Committed.into(),
            abort_reason: None,
        }
        .encode_to_vec(),
        "DocumentService.Insert" => {
            let r = pb::InsertRequest::decode(req).unwrap_or_default();
            pb::InsertResponse {
                results: r
                    .documents
                    .iter()
                    .map(|d| {
                        let id = rdoc::decode(&d.rdoc)
                            .ok()
                            .and_then(|d| d.get("_id").cloned())
                            .unwrap_or_else(|| Value::ObjectId(ObjectId::new()));
                        pb::WriteResult {
                            id: Some(pb::Value {
                                rdoc_value: rdoc::encode_value(&id).unwrap_or_default(),
                            }),
                            rev: None,
                        }
                    })
                    .collect(),
                warnings: Vec::new(),
            }
            .encode_to_vec()
        }
        "QueryService.Execute" => pb::ExecuteResponse {
            batch: Some(pb::ResultBatch::default()),
        }
        .encode_to_vec(),
        _ => Vec::new(),
    };
    v.into()
}

/// YAML protobuf JSON → `serde_json::Value`, converting `Document`/`Value` fields to RDoc.
fn convert(desc: &MessageDescriptor, y: &Yaml) -> Result<serde_json::Value, String> {
    let Some(h) = y.as_hash() else {
        return Err(format!("{} expects a mapping", desc.full_name()));
    };
    let mut out = serde_json::Map::new();
    for (k, v) in h {
        let k = k.as_str().unwrap_or("");
        let field = desc
            .get_field_by_json_name(k)
            .or_else(|| desc.get_field_by_name(k))
            .ok_or_else(|| format!("{} has no field {k}", desc.full_name()))?;
        let one = |v: &Yaml| -> Result<serde_json::Value, String> {
            match field.kind() {
                Kind::Message(m) if !field.is_map() => match m.full_name() {
                    "rustegon.v1.Document" => {
                        let b = rdoc::encode(&to_document(v, &plain)).map_err(|e| e.to_string())?;
                        Ok(serde_json::json!({ "rdoc": B64.encode(b) }))
                    }
                    "rustegon.v1.Value" => {
                        let b =
                            rdoc::encode_value(&to_value(v, &plain)).map_err(|e| e.to_string())?;
                        Ok(serde_json::json!({ "rdocValue": B64.encode(b) }))
                    }
                    _ => convert(&m, v),
                },
                _ => serde_json::from_str(&to_json(v)).map_err(|e| e.to_string()),
            }
        };
        let value = match (field.is_list(), v.as_vec()) {
            (true, Some(items)) => {
                serde_json::Value::Array(items.iter().map(one).collect::<Result<_, _>>()?)
            }
            _ => one(v)?,
        };
        out.insert(k.to_owned(), value);
    }
    Ok(serde_json::Value::Object(out))
}

#[derive(Clone, PartialEq, prost::Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<Any>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Any {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

// ----------------------------------------------------------------------------- raw gRPC plumbing

#[derive(Clone, Copy, Default)]
struct Raw;

impl Codec for Raw {
    type Encode = Bytes;
    type Decode = Bytes;
    type Encoder = Raw;
    type Decoder = Raw;
    fn encoder(&mut self) -> Raw {
        Raw
    }
    fn decoder(&mut self) -> Raw {
        Raw
    }
}

impl Encoder for Raw {
    type Item = Bytes;
    type Error = Status;
    fn encode(&mut self, item: Bytes, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        dst.put(item);
        Ok(())
    }
}

impl Decoder for Raw {
    type Item = Bytes;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Bytes>, Status> {
        Ok(Some(src.copy_to_bytes(src.remaining())))
    }
}

type ReplyStream = std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

struct Handler {
    fake: Arc<Fake>,
    path: String,
}

impl StreamingService<Bytes> for Handler {
    type Response = Bytes;
    type ResponseStream = ReplyStream;
    type Future = BoxFuture<Response<ReplyStream>, Status>;

    fn call(&mut self, req: Request<Streaming<Bytes>>) -> Self::Future {
        let fake = Arc::clone(&self.fake);
        let path = self.path.clone();
        Box::pin(async move { handle(fake, &path, req).await })
    }
}

async fn handle(
    fake: Arc<Fake>,
    path: &str,
    req: Request<Streaming<Bytes>>,
) -> Result<Response<ReplyStream>, Status> {
    let (svc, method) = path
        .trim_start_matches('/')
        .split_once('/')
        .ok_or_else(|| Status::unimplemented(path.to_owned()))?;
    let rpc = format!("{}.{method}", svc.trim_start_matches("rustegon.v1."));
    let md = fake
        .pool
        .get_service_by_name(svc)
        .and_then(|s| s.methods().find(|m| m.name() == method))
        .ok_or_else(|| Status::unimplemented(rpc.clone()))?;
    let metadata = req.metadata().clone();
    let mut stream = req.into_inner();
    if md.is_client_streaming() {
        let i = fake.record(&rpc, &metadata);
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let ok = authenticate(&fake, &mut stream, &tx).await;
            fake.done(i, !ok);
            if !ok {
                let _ = tx
                    .send(Err(Status::unauthenticated("fake-authentication-failed")))
                    .await;
            }
        });
        return Ok(Response::new(Box::pin(ReceiverStream::new(rx))));
    }
    let body = stream.message().await?.unwrap_or_default();
    let i = fake.record(&rpc, &metadata);
    let reply = fake.next(&rpc);
    if let Some(ms) = reply.as_ref().and_then(|r| r.int("delayMs")) {
        tokio::time::sleep(Duration::from_millis(u64::try_from(ms).unwrap_or(0))).await;
    }
    if let Some(r) = &reply {
        if r.has("error") {
            fake.done(i, true);
            return Err(fake.error_status(r.get("error")));
        }
        if r.has("transport") {
            fake.done(i, true);
            let name = r.str_("transport");
            return Err(Status::new(crate::checks::grpc_code_of(name), name));
        }
    }
    let msgs = fake
        .ok_replies(&rpc, &md, &body, reply.as_ref().map(|r| r.get("ok")))
        .map_err(|e| {
            fake.done(i, true);
            Status::internal(e)
        })?;
    fake.done(i, false);
    Ok(Response::new(Box::pin(tokio_stream::iter(
        msgs.into_iter().map(Ok),
    ))))
}

/// The SCRAM-SHA-256 server side for `fake` / `fake-password-123`.
async fn authenticate(
    fake: &Fake,
    stream: &mut Streaming<Bytes>,
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, Status>>,
) -> bool {
    let Ok(Some(first)) = stream.message().await else {
        return false;
    };
    let Ok(first) = pb::AuthenticateRequest::decode(first) else {
        return false;
    };
    let text = String::from_utf8_lossy(&first.payload).into_owned();
    let bare = text.trim_start_matches("n,,").to_owned();
    let Some((_, client_nonce)) = bare.split_once(",r=") else {
        return false;
    };
    let mut salt = [0u8; 16];
    let mut extra = [0u8; 18];
    getrandom::fill(&mut salt).ok();
    getrandom::fill(&mut extra).ok();
    let iterations = 4096;
    let server_first = format!(
        "r={client_nonce}{},s={},i={iterations}",
        B64.encode(extra),
        B64.encode(salt)
    );
    let challenge = pb::AuthenticateResponse {
        step: Some(pb::authenticate_response::Step::Challenge(
            server_first.clone().into_bytes(),
        )),
    };
    if tx.send(Ok(challenge.encode_to_vec().into())).await.is_err() {
        return false;
    }
    let Ok(Some(fin)) = stream.message().await else {
        return false;
    };
    let Ok(fin) = pb::AuthenticateRequest::decode(fin) else {
        return false;
    };
    let client_final = String::from_utf8_lossy(&fin.payload).into_owned();
    let Some((without_proof, proof)) = client_final.split_once(",p=") else {
        return false;
    };
    let auth_message = format!("{bare},{server_first},{without_proof}");
    let salted =
        pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(SCRAM_PASSWORD.as_bytes(), &salt, iterations);
    let mac = |key: &[u8], msg: &[u8]| -> [u8; 32] {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        m.update(msg);
        m.finalize().into_bytes().into()
    };
    let client_key = mac(&salted, b"Client Key");
    let stored: [u8; 32] = Sha256::digest(client_key).into();
    let sig = mac(&stored, auth_message.as_bytes());
    let Ok(mut proof) = B64.decode(proof) else {
        return false;
    };
    if proof.len() != 32 {
        return false;
    }
    for (p, s) in proof.iter_mut().zip(sig) {
        *p ^= s;
    }
    if proof != client_key {
        return false;
    }
    let server_sig = mac(&mac(&salted, b"Server Key"), auth_message.as_bytes());
    let n = {
        let mut s = fake.state.lock().unwrap();
        s.sessions += 1;
        s.sessions
    };
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(0))
        + 3_600_000;
    let success = pb::AuthenticateResponse {
        step: Some(pb::authenticate_response::Step::Success(pb::AuthSuccess {
            server_final: format!("v={}", B64.encode(server_sig)).into_bytes(),
            session_token: format!("fake-session-{n}"),
            expires_at_unix_ms: expires,
            user: SCRAM_USER.into(),
            must_change_password: false,
        })),
    };
    tx.send(Ok(success.encode_to_vec().into())).await.is_ok()
}

/// One tonic service per `rustegon.v1` service name, all routed to the same handler.
const SERVICES: [&str; 7] = [
    "rustegon.v1.SessionService",
    "rustegon.v1.AuthService",
    "rustegon.v1.DocumentService",
    "rustegon.v1.QueryService",
    "rustegon.v1.SchemaService",
    "rustegon.v1.TransactionService",
    "rustegon.v1.AdminService",
];

#[derive(Clone)]
struct Svc<const N: usize>(Arc<Fake>);

impl<const N: usize> NamedService for Svc<N> {
    const NAME: &'static str = SERVICES[N];
}

impl<const N: usize> Service<http::Request<Body>> for Svc<N> {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<http::Response<Body>, Infallible>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let fake = Arc::clone(&self.0);
        Box::pin(async move {
            let path = req.uri().path().to_owned();
            let mut grpc = Grpc::new(Raw);
            Ok(grpc.streaming(Handler { fake, path }, req).await)
        })
    }
}

struct Running {
    fake: Arc<Fake>,
    addr: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
}

async fn start(script: &Yaml) -> Running {
    let mut grpc_of_code = HashMap::new();
    for c in load("generated/errors.json").list("codes") {
        grpc_of_code.insert(c.int("code").unwrap_or(0), c.str_("grpc").to_owned());
    }
    let mut map = HashMap::new();
    for k in script.keys() {
        map.insert(k.to_owned(), script.list(k).to_vec());
    }
    let fake = Arc::new(Fake {
        pool: DescriptorPool::decode(pb::FILE_DESCRIPTOR_SET).unwrap(),
        grpc_of_code,
        state: Mutex::new(State {
            script: map,
            consumed: HashMap::new(),
            calls: Vec::new(),
            sessions: 0,
        }),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let f = Arc::clone(&fake);
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(Svc::<0>(Arc::clone(&f)))
            .add_service(Svc::<1>(Arc::clone(&f)))
            .add_service(Svc::<2>(Arc::clone(&f)))
            .add_service(Svc::<3>(Arc::clone(&f)))
            .add_service(Svc::<4>(Arc::clone(&f)))
            .add_service(Svc::<5>(Arc::clone(&f)))
            .add_service(Svc::<6>(f))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = rx.await;
                },
            )
            .await;
    });
    Running { fake, addr, stop }
}

// ------------------------------------------------------------------------ scenarios (R1–R8)

/// `runRetryScenarios` (every scenario, or only `only`).
pub async fn retry_scenarios(file: &str, only: Option<&str>) -> Result<(), String> {
    let root = load(file);
    let mut ran = 0;
    for s in root.list("scenarios") {
        if only.is_some_and(|o| o != s.str_("name")) {
            continue;
        }
        scenario(&root, s)
            .await
            .map_err(|e| format!("{}: {e}", s.str_("name")))?;
        ran += 1;
    }
    if ran == 0 {
        return Err("no scenario ran".into());
    }
    Ok(())
}

async fn scenario(root: &Yaml, s: &Yaml) -> Result<(), String> {
    let defaults = root.get("defaults");
    let setting = |k: &str| -> &Yaml {
        if s.get("settings").has(k) {
            s.get("settings").get(k)
        } else {
            defaults.get("settings").get(k)
        }
    };
    let fake = start(s.get("server")).await;
    let credential = if s.str_("credential") == "scram" {
        Credential::scram(SCRAM_USER, SCRAM_PASSWORD)
    } else {
        Credential::api_key("rgn_fake_key")
    };
    let settings = Settings::builder()
        .endpoints([fake.addr.to_string()])
        .credential(credential)
        .retry_reads(setting("retryReads").as_bool().unwrap_or(true))
        .retry_writes(setting("retryWrites").as_bool().unwrap_or(true))
        .max_retries(u32::try_from(setting("maxRetries").as_i64().unwrap_or(1)).unwrap_or(1))
        .operation_timeout(Duration::from_millis(
            u64::try_from(setting("operationTimeoutMs").as_i64().unwrap_or(30_000))
                .unwrap_or(30_000),
        ))
        .default_database("fake")
        .connections_per_endpoint(1)
        .build()
        .map_err(|e| e.to_string())?;
    let client = Client::new(settings).map_err(|e| e.to_string())?;
    let expect = s.get("expect");
    // The scenario's operation with the expected outcome attached (match: subset).
    let mut op = s.get("operation").as_hash().cloned().unwrap_or_default();
    op.insert(Yaml::String("expect".into()), expect.get("outcome").clone());
    op.insert(Yaml::String("match".into()), Yaml::String("subset".into()));
    let ops = vec![Yaml::Hash(op)];
    let identity = |x: &str| x.to_owned();
    let run = Run::new(client.clone(), "fake", "c", &identity, "");
    let r = run.run_ops(&ops, true).await;
    run.close().await;
    client.close().await;
    let _ = fake.stop.send(());
    if let Err(e) = r {
        return Err(format!("{e:?}"));
    }
    let calls = fake.fake.state.lock().unwrap().calls.clone();
    let names = || {
        calls
            .iter()
            .map(|c| c.rpc.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    for rpc in expect.get("calls").keys() {
        let n = calls.iter().filter(|c| c.rpc == rpc).count();
        let want = expect.get("calls").int(rpc).unwrap_or(-1);
        if i64::try_from(n).ok() != Some(want) {
            return Err(format!(
                "{rpc} called {n} times, expected {want}; calls: {}",
                names()
            ));
        }
    }
    for rpc in expect.list("sameRequestId").iter().filter_map(Yaml::as_str) {
        let mut ids: Vec<&str> = calls
            .iter()
            .filter(|c| c.rpc == rpc)
            .map(|c| c.request_id.as_str())
            .collect();
        ids.dedup();
        if ids.len() != 1 || ids[0].is_empty() {
            return Err(format!("{rpc} request ids {ids:?}"));
        }
    }
    if expect.is_true("grpcTimeoutSent")
        && let Some(c) = calls
            .iter()
            .find(|c| c.rpc != "AuthService.Logout" && !c.has_timeout)
    {
        return Err(format!("{} without grpc-timeout", c.rpc));
    }
    let backoff = defaults.get("backoff");
    let failures: Vec<&Call> = calls
        .iter()
        .filter(|c| c.failed && c.replied.is_some() && c.rpc != "TransactionService.Rollback")
        .collect();
    for d in expect.list("delays") {
        let n = usize::try_from(d.int("retry").unwrap_or(1)).unwrap_or(1);
        let Some(failed) = failures.get(n - 1) else {
            return Err(format!(
                "retry {n} expected but only {} failures",
                failures.len()
            ));
        };
        let replied = failed.replied.unwrap_or(failed.arrival);
        let next = calls
            .iter()
            .filter(|c| {
                c.arrival > replied
                    && c.rpc != "TransactionService.Rollback"
                    && c.rpc != "TransactionService.Heartbeat"
            })
            .min_by_key(|c| c.arrival)
            .ok_or_else(|| format!("no call after failure {n}"))?;
        let gap = next.arrival - replied;
        if let Some(min) = d.int("minMs") {
            if gap < Duration::from_millis(u64::try_from(min).unwrap_or(0)) {
                return Err(format!(
                    "retry {n} after {gap:?}, expected at least {min} ms"
                ));
            }
        } else {
            let base = backoff.int("baseMs").unwrap_or(10);
            let factor = backoff.int("factor").unwrap_or(2);
            let cap = backoff.int("capMs").unwrap_or(1000);
            let ceiling = cap.min(base * factor.pow(u32::try_from(n - 1).unwrap_or(0)));
            if gap > Duration::from_millis(u64::try_from(ceiling).unwrap_or(0)) + TOLERANCE {
                return Err(format!(
                    "retry {n} after {gap:?}, expected at most {ceiling} ms + tolerance"
                ));
            }
        }
    }
    Ok(())
}
