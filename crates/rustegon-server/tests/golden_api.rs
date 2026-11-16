// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-API-003 golden request/response fixtures (`api/fixtures/*.json`, AC-API-001, PD-060).
//!
//! Every fixture file is one scenario replayed step by step against a fresh in-process node
//! (`tests/common` harness: TLS gRPC listener, security layer, data plane over a real
//! `EmbeddedDb`; REST through the in-process router over the same `Services`). A step is a
//! request written by hand and the response recorded by the bless run; the replay fails on any
//! difference after normalisation.
//!
//! Fixture conventions (also in PD-060):
//! - gRPC requests and responses are the protobuf JSON mapping of the `rustegon.v1` messages,
//!   mapped through the descriptor set (`prost-reflect`), so a fixture is exactly what a JSON
//!   transcoding client sends. RDoc bytes (`Document.rdoc`, `Value.rdoc_value`) are shown as
//!   their canonical extended JSON under `{"$rdoc": …}` / `{"$rdocValue": …}`: the wire carries
//!   the RDoc encoding of that JSON (base64 in the plain mapping), which is not reviewable.
//! - `${name}` in a request is replaced by the value captured from an earlier response
//!   (`capture: {name: "/json/pointer"}`); in recorded responses the captured values are
//!   written back as `${name}`, so a fixture also checks that ids are echoed consistently.
//! - Volatile values (session tokens, ids, timestamps, revisions, trace ids, nonces, timings)
//!   are replaced by `<placeholder>` after capture (see [`VOLATILE_KEYS`]). A step may list more
//!   member names in `volatile` (e.g. the consistency point of a backup the step takes, the
//!   bytes of a dump chunk): their values become `<volatile>` in that step's response only.
//! - A client-streaming RPC sends the messages of `requests` (an array) instead of `request`.
//! - An `OpenMetrics` body (`GET /metrics`) is recorded as its metadata lines only
//!   ([`openmetrics_shape`]): the family set is the contract, sample values are volatile.
//! - Steps carry either a gRPC `rpc` or a REST `method` + `path`. The SCRAM login is a
//!   challenge/response with random nonces, so it is a `scram` step driven by the test client
//!   (`Authenticate` on gRPC, `/auth/scram/start` + `/auth/scram/finish` on REST) whose
//!   recorded responses are normalised like any other.
//!
//! Bless: `RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-server --test golden_api`
//! rewrites the `expect` member of every step; review the diff like any golden change.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::case_sensitive_file_extension_comparisons
)]

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use axum::{
    Router,
    body::{Body, to_bytes},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use common::{Binding, Conn, Harness, base_flags, seed_backup};
use prost::Message as _;
use prost_reflect::{
    DescriptorPool, DeserializeOptions, DynamicMessage, MessageDescriptor, SerializeOptions,
};
use rustegon_doc::{
    json::{JsonMode, parse_document, parse_value, to_json, value_to_json},
    rdoc,
};
use rustegon_security::authn::{
    scram::{ClientBinding, ScramClient},
    secret,
};
use rustegon_server::rest::{REST_ENDPOINTS, router};
use rustegon_sim_api::OsRng;
use serde_json::{Map, Value as Json, json};
use tonic::{
    Status,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    metadata::MetadataValue,
};
use tower::ServiceExt;

const LIMIT: usize = 64 * 1024 * 1024;
const BLESS_ENV: &str = "RGN_FIXTURES_BLESS";

/// Response members whose values change from run to run, with the placeholder they become.
/// Keys are protobuf JSON names (camelCase), REST body names and document system fields.
const VOLATILE_KEYS: &[(&str, &str)] = &[
    ("sessionToken", "<token>"),
    ("csrfToken", "<csrf>"),
    ("secret", "<api-key-secret>"),
    ("handshakeId", "<handshake>"),
    ("serverFirst", "<scram-server-first>"),
    ("serverFinal", "<scram-server-final>"),
    ("challenge", "<scram-challenge>"),
    ("traceId", "<trace-id>"),
    ("trace_id", "<trace-id>"),
    ("txnId", "<txn-id>"),
    ("cursorId", "<cursor-id>"),
    ("continuationToken", "<continuation-token>"),
    ("keyId", "<api-key-id>"),
    ("apiKeyId", "<api-key-id>"),
    ("expiresAtUnixMs", "<unix-ms>"),
    ("createdAtUnixMs", "<unix-ms>"),
    ("expiresInMs", "<ms>"),
    ("executionTimeUs", "<us>"),
    ("etaMs", "<ms>"),
    ("rev", "<rev>"),
    ("_rev", "<rev>"),
    ("_createdAt", "<datetime>"),
    ("_updatedAt", "<datetime>"),
];

/// REST response headers recorded with a placeholder value (present, value volatile).
const VOLATILE_HEADERS: &[(&str, &str)] = &[
    ("rgn-server-time", "<unix-ms>"),
    ("etag", "<etag>"),
    ("rgn-causality-token", "<causality-token>"),
];

/// REST response headers not recorded (transport details).
const SKIPPED_HEADERS: &[&str] = &["content-length", "date", "vary"];

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../api/fixtures")
}

fn blessing() -> bool {
    std::env::var(BLESS_ENV).is_ok_and(|v| v == "1")
}

fn pool() -> &'static DescriptorPool {
    static POOL: OnceLock<DescriptorPool> = OnceLock::new();
    POOL.get_or_init(|| DescriptorPool::decode(rustegon_proto::FILE_DESCRIPTOR_SET).unwrap())
}

// ---------------------------------------------------------------------------------------------
// Dynamic gRPC codec
// ---------------------------------------------------------------------------------------------

/// A tonic codec for `DynamicMessage`: requests are encoded as they are, responses decoded
/// with the method's output descriptor.
struct DynCodec {
    output: MessageDescriptor,
}

struct DynEncoder;

struct DynDecoder {
    output: MessageDescriptor,
}

impl Codec for DynCodec {
    type Encode = DynamicMessage;
    type Decode = DynamicMessage;
    type Encoder = DynEncoder;
    type Decoder = DynDecoder;

    fn encoder(&mut self) -> DynEncoder {
        DynEncoder
    }

    fn decoder(&mut self) -> DynDecoder {
        DynDecoder {
            output: self.output.clone(),
        }
    }
}

impl Encoder for DynEncoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn encode(&mut self, item: DynamicMessage, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        item.encode(dst)
            .map_err(|e| Status::internal(e.to_string()))
    }
}

impl Decoder for DynDecoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<DynamicMessage>, Status> {
        DynamicMessage::decode(self.output.clone(), src)
            .map(Some)
            .map_err(|e| Status::internal(e.to_string()))
    }
}

fn message_json(m: &DynamicMessage) -> Json {
    m.serialize_with_options(serde_json::value::Serializer, &SerializeOptions::new())
        .unwrap()
}

fn message_from_json(desc: &MessageDescriptor, j: &Json) -> DynamicMessage {
    DynamicMessage::deserialize_with_options(desc.clone(), j, &DeserializeOptions::new())
        .unwrap_or_else(|e| {
            panic!(
                "request is not a valid {} JSON: {e}\n{j:#}",
                desc.full_name()
            )
        })
}

/// The JSON of a prost message of `rustegon.v1` (through its bytes).
fn prost_json(full_name: &str, m: &impl prost::Message) -> Json {
    let desc = pool().get_message_by_name(full_name).unwrap();
    message_json(&DynamicMessage::decode(desc, m.encode_to_vec().as_slice()).unwrap())
}

fn status_json(s: &Status) -> Json {
    let detail = rustegon_proto::status::error_detail_of(s)
        .map_or(Json::Null, |d| prost_json("rustegon.v1.ErrorDetail", &d));
    json!({"grpcCode": format!("{:?}", s.code()), "message": s.message(), "detail": detail})
}

// ---------------------------------------------------------------------------------------------
// RDoc rendering
// ---------------------------------------------------------------------------------------------

/// Replaces `{"$rdoc": json}` / `{"$rdocValue": json}` by the base64 RDoc bytes.
fn encode_rdoc(j: &mut Json) {
    match j {
        Json::Object(map) => {
            if map.len() == 1 {
                if let Some(doc) = map.get("$rdoc") {
                    let d = parse_document(&doc.to_string()).unwrap();
                    *j = Json::String(B64.encode(rdoc::encode(&d).unwrap()));
                    return;
                }
                if let Some(v) = map.get("$rdocValue") {
                    let v = parse_value(&v.to_string()).unwrap();
                    *j = Json::String(B64.encode(rdoc::encode_value(&v).unwrap()));
                    return;
                }
            }
            map.values_mut().for_each(encode_rdoc);
        }
        Json::Array(items) => items.iter_mut().for_each(encode_rdoc),
        _ => {}
    }
}

/// Replaces the base64 RDoc of `rdoc` / `rdocValue` members by `{"$rdoc": json}`.
fn decode_rdoc(j: &mut Json) {
    match j {
        Json::Object(map) => {
            for (k, v) in map.iter_mut() {
                match (k.as_str(), &*v) {
                    ("rdoc", Json::String(b)) => {
                        let d = rdoc::decode(&B64.decode(b).unwrap()).unwrap();
                        let text = to_json(&d, JsonMode::Canonical);
                        *v = json!({"$rdoc": serde_json::from_str::<Json>(&text).unwrap()});
                    }
                    ("rdocValue", Json::String(b)) => {
                        let d = rdoc::decode_value(&B64.decode(b).unwrap()).unwrap();
                        let text = value_to_json(&d, JsonMode::Canonical);
                        *v = json!({"$rdocValue": serde_json::from_str::<Json>(&text).unwrap()});
                    }
                    _ => decode_rdoc(v),
                }
            }
        }
        Json::Array(items) => items.iter_mut().for_each(decode_rdoc),
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------------
// Variables and normalisation
// ---------------------------------------------------------------------------------------------

/// Values captured from earlier responses.
#[derive(Default)]
struct Vars {
    values: BTreeMap<String, Json>,
}

impl Vars {
    fn text(v: &Json) -> String {
        match v {
            Json::String(s) => s.clone(),
            other => other.to_string(),
        }
    }

    /// `${name}` in `s` replaced by the captured values.
    fn interpolate(&self, s: &str) -> String {
        let mut out = s.to_owned();
        for (k, v) in &self.values {
            out = out.replace(&format!("${{{k}}}"), &Self::text(v));
        }
        out
    }

    /// Substitutes variables in a request: a string that is exactly `${name}` becomes the
    /// captured JSON value, other strings are interpolated.
    fn substitute(&self, j: &mut Json) {
        match j {
            Json::String(s) => {
                if let Some(name) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}'))
                    && let Some(v) = self.values.get(name)
                {
                    *j = v.clone();
                    return;
                }
                *s = self.interpolate(s);
            }
            Json::Array(items) => items.iter_mut().for_each(|i| self.substitute(i)),
            Json::Object(map) => map.values_mut().for_each(|v| self.substitute(v)),
            _ => {}
        }
    }

    fn capture(&mut self, step: &Json, actual: &Json) {
        let Some(captures) = step.get("capture").and_then(Json::as_object) else {
            return;
        };
        for (name, pointer) in captures {
            let pointer = pointer.as_str().unwrap();
            let value = actual.pointer(pointer).unwrap_or_else(|| {
                panic!("capture {name}: no {pointer} in {actual:#}");
            });
            self.values.insert(name.clone(), value.clone());
        }
    }

    /// Captured values written back as `${name}` (whole strings and substrings). Short values
    /// are left alone: a one-character id would rewrite unrelated text.
    fn unsubstitute(&self, s: &str) -> String {
        let mut out = s.to_owned();
        for (k, v) in &self.values {
            let text = Self::text(v);
            if text.len() >= 8 {
                out = out.replace(&text, &format!("${{{k}}}"));
            }
        }
        out
    }
}

/// Normalises a recorded response: captured values back to `${name}`, volatile members to
/// placeholders.
fn normalize(j: &mut Json, vars: &Vars) {
    match j {
        Json::String(s) => *s = vars.unsubstitute(s),
        Json::Array(items) => items.iter_mut().for_each(|i| normalize(i, vars)),
        Json::Object(map) => {
            for (k, v) in map.iter_mut() {
                normalize(v, vars);
                let already = v.as_str().is_some_and(|s| s.starts_with("${"));
                if let Some((_, placeholder)) = VOLATILE_KEYS.iter().find(|(key, _)| key == k)
                    && !already
                    && !v.is_null()
                {
                    *v = Json::String((*placeholder).to_owned());
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------------------------

struct Node {
    h: Harness,
    conn: Conn,
    rest: Router,
    /// Holds the backup destination seeded for the `BackupService` fixtures.
    backups: tempfile::TempDir,
}

impl Node {
    async fn start() -> Self {
        // The engine backup backend (M13a lane BE): backup and snapshot fixtures record real
        // outcomes.
        let h = Harness::start_with_engine_backup(base_flags()).await;
        let conn = h.channel().await;
        let rest = router(&h.services, LIMIT);
        // As `rustegond` does once both listeners are bound: the readiness fixture records a
        // serving node (the other lifecycle phases are TC-OPS-005, `tests/observability.rs`).
        h.services.readiness().mark_serving();
        let backups = tempfile::tempdir().unwrap();
        Self {
            h,
            conn,
            rest,
            backups,
        }
    }

    /// Variables every fixture may use (M13a, PD-077): `${backup_dest}` = an absolute local
    /// destination holding `common::SEEDED_BACKUP_ID`, `${backup_dest_q}` = the same,
    /// percent-encoded for a query string. Being variables, the machine-specific path is written
    /// back as `${backup_dest}` in recorded responses.
    fn seed_vars(&self, vars: &mut Vars) {
        let (dest, _) = seed_backup(self.backups.path());
        let text = dest.to_str().unwrap().to_owned();
        let encoded: String = text
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        vars.values.insert("backup_dest".into(), Json::String(text));
        vars.values
            .insert("backup_dest_q".into(), Json::String(encoded));
    }

    /// Runs one step. A step with `poll: {pointer, value}` is repeated (up to 200 times, 25 ms
    /// apart) until the response has `value` at `pointer`: progress endpoints are polled by
    /// contract, and how many calls a background build needs depends on the machine.
    async fn step(&self, step: &Json, vars: &Vars) -> Json {
        let poll = step.get("poll");
        let mut attempts = 0;
        loop {
            let actual = if step.get("rpc").is_some() {
                self.grpc(step, vars).await
            } else {
                self.rest(step, vars).await
            };
            let Some(poll) = poll else {
                return actual;
            };
            attempts += 1;
            if actual.pointer(poll["pointer"].as_str().unwrap()) == Some(&poll["value"])
                || attempts >= 200
            {
                return actual;
            }
            rustegon_sim_api::Clock::sleep(
                &rustegon_sim_api::SystemClock::new(),
                std::time::Duration::from_millis(25),
            )
            .await;
        }
    }

    async fn grpc(&self, step: &Json, vars: &Vars) -> Json {
        let rpc = step["rpc"].as_str().unwrap();
        let (service, method) = rpc.split_once('/').unwrap();
        let method = pool()
            .get_service_by_name(service)
            .unwrap_or_else(|| panic!("no service {service}"))
            .methods()
            .find(|m| m.name() == method)
            .unwrap_or_else(|| panic!("no method {rpc}"));
        if let Some(scram) = step.get("scram") {
            return self.grpc_scram(scram).await;
        }
        let mut body = step.get("request").cloned().unwrap_or_else(|| json!({}));
        vars.substitute(&mut body);
        encode_rdoc(&mut body);
        let message = message_from_json(&method.input(), &body);
        let mut request = tonic::Request::new(message);
        let mut metadata = tonic::metadata::MetadataMap::new();
        if let Some(md) = step.get("metadata").and_then(Json::as_object) {
            for (k, v) in md {
                let value = vars.interpolate(v.as_str().unwrap());
                metadata.insert(
                    http::HeaderName::from_bytes(k.as_bytes())
                        .map(|n| tonic::metadata::MetadataKey::from_bytes(n.as_str().as_bytes()))
                        .unwrap()
                        .unwrap(),
                    MetadataValue::try_from(value.as_str()).unwrap(),
                );
            }
        }
        *request.metadata_mut() = metadata.clone();
        let mut grpc = tonic::client::Grpc::new(self.conn.channel.clone());
        grpc.ready().await.unwrap();
        let path = http::uri::PathAndQuery::try_from(format!("/{rpc}")).unwrap();
        let codec = DynCodec {
            output: method.output(),
        };
        if let Some(items) = step.get("requests").and_then(Json::as_array) {
            assert!(
                method.is_client_streaming(),
                "{rpc}: `requests` needs a client stream"
            );
            let messages: Vec<DynamicMessage> = items
                .iter()
                .map(|item| {
                    let mut body = item.clone();
                    vars.substitute(&mut body);
                    encode_rdoc(&mut body);
                    message_from_json(&method.input(), &body)
                })
                .collect();
            let mut request = tonic::Request::new(tonic::codegen::tokio_stream::iter(messages));
            *request.metadata_mut() = metadata;
            return match grpc.client_streaming(request, path, codec).await {
                Ok(r) => json!({"ok": message_json(r.get_ref())}),
                Err(s) => json!({"error": status_json(&s)}),
            };
        }
        if method.is_server_streaming() {
            match grpc.server_streaming(request, path, codec).await {
                Err(s) => json!({"error": status_json(&s)}),
                Ok(response) => {
                    let mut stream = response.into_inner();
                    let mut messages = Vec::new();
                    loop {
                        match stream.message().await {
                            Ok(Some(m)) => messages.push(message_json(&m)),
                            Ok(None) => break json!({"messages": messages}),
                            Err(s) => {
                                break json!({"messages": messages, "error": status_json(&s)});
                            }
                        }
                    }
                }
            }
        } else {
            match grpc.unary(request, path, codec).await {
                Ok(r) => json!({"ok": message_json(r.get_ref())}),
                Err(s) => json!({"error": status_json(&s)}),
            }
        }
    }

    /// `Authenticate` with the SCRAM test client (random nonces: the exchange itself cannot be
    /// a fixed fixture); the outcome is recorded.
    async fn grpc_scram(&self, scram: &Json) -> Json {
        let binding = match scram.get("binding").and_then(Json::as_str) {
            None | Some("plus") => Binding::Plus,
            Some("none") => Binding::None,
            Some(other) => panic!("unknown binding {other}"),
        };
        match self
            .conn
            .login(
                scram["user"].as_str().unwrap(),
                scram["password"].as_str().unwrap(),
                binding,
            )
            .await
        {
            Ok(success) => {
                json!({"ok": {"success": prost_json("rustegon.v1.AuthSuccess", &success)}})
            }
            Err(s) => json!({"error": status_json(&s)}),
        }
    }

    async fn rest_call(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<&Json>,
    ) -> Json {
        let mut b = http::Request::builder().method(method).uri(path);
        for (k, v) in headers {
            b = b.header(k.as_str(), v.as_str());
        }
        let request = match body {
            Some(j) => b
                .header("content-type", "application/json")
                .body(Body::from(j.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let response = self.rest.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let mut recorded = BTreeMap::<String, Json>::new();
        for name in response.headers().keys() {
            let n = name.as_str();
            if SKIPPED_HEADERS.contains(&n) {
                continue;
            }
            let values: Vec<Json> = response
                .headers()
                .get_all(name)
                .iter()
                .map(|v| {
                    let v = v.to_str().unwrap();
                    match VOLATILE_HEADERS.iter().find(|(h, _)| *h == n) {
                        Some((_, p)) => Json::String((*p).to_owned()),
                        None if n == "set-cookie" => Json::String(cookie_shape(v)),
                        None => Json::String(v.to_owned()),
                    }
                })
                .collect();
            let value = if values.len() == 1 {
                values.into_iter().next().unwrap()
            } else {
                Json::Array(values)
            };
            recorded.insert(n.to_owned(), value);
        }
        let bytes = to_bytes(response.into_body(), LIMIT).await.unwrap();
        let openmetrics = recorded
            .get("content-type")
            .and_then(Json::as_str)
            .is_some_and(|c| c.starts_with("application/openmetrics-text"));
        let body = if bytes.is_empty() {
            Json::Null
        } else if openmetrics {
            openmetrics_shape(&String::from_utf8_lossy(&bytes))
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Json::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        json!({"status": status, "headers": recorded, "body": body})
    }

    async fn rest(&self, step: &Json, vars: &Vars) -> Json {
        if let Some(scram) = step.get("scram") {
            return self.rest_scram(scram).await;
        }
        let method = step["method"].as_str().unwrap();
        let path = vars.interpolate(step["path"].as_str().unwrap());
        let headers: Vec<(String, String)> = step
            .get("headers")
            .and_then(Json::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), vars.interpolate(v.as_str().unwrap())))
                    .collect()
            })
            .unwrap_or_default();
        let body = step.get("body").cloned().map(|mut b| {
            vars.substitute(&mut b);
            b
        });
        self.rest_call(method, &path, &headers, body.as_ref()).await
    }

    /// `/auth/scram/start` + `/auth/scram/finish` with the SCRAM test client; both responses
    /// are recorded (the server signature is verified on the way).
    async fn rest_scram(&self, scram: &Json) -> Json {
        let (client, _, first) = ScramClient::new(
            scram["user"].as_str().unwrap(),
            &secret(scram["password"].as_str().unwrap()),
            ClientBinding::Unsupported,
            &OsRng,
        );
        let mut start_body = json!({"clientFirst": first});
        if let Some(d) = scram.get("delivery") {
            start_body["delivery"] = d.clone();
        }
        let start = self
            .rest_call("POST", "/api/v1/auth/scram/start", &[], Some(&start_body))
            .await;
        if start["status"] != 200 {
            return json!({"start": start});
        }
        let server_first = start["body"]["serverFirst"].as_str().unwrap().to_owned();
        let handshake = start["body"]["handshakeId"].as_str().unwrap().to_owned();
        let (fin, client_final) =
            tokio::task::spawn_blocking(move || client.server_first(&server_first).unwrap())
                .await
                .unwrap();
        let finish = self
            .rest_call(
                "POST",
                "/api/v1/auth/scram/finish",
                &[],
                Some(&json!({"handshakeId": handshake, "clientFinal": client_final})),
            )
            .await;
        if finish["status"] == 200 {
            fin.server_final(finish["body"]["serverFinal"].as_str().unwrap())
                .expect("server signature verifies");
        }
        json!({"start": start, "finish": finish})
    }
}

/// An `OpenMetrics` exposition reduced to its metadata lines (`# TYPE`, `# HELP`, `# UNIT`,
/// `# EOF`): family names, types and help texts are the stable contract (PD-059), while sample
/// values (counters, latencies, timestamps, build info) change from run to run.
fn openmetrics_shape(text: &str) -> Json {
    Json::Array(
        text.lines()
            .filter(|l| {
                ["# TYPE ", "# HELP ", "# UNIT "]
                    .iter()
                    .any(|p| l.starts_with(p))
                    || *l == "# EOF"
            })
            .map(|l| Json::String(l.to_owned()))
            .collect(),
    )
}

/// `Set-Cookie` with the cookie value replaced (the attributes are the contract).
fn cookie_shape(v: &str) -> String {
    let mut parts = v.split(';');
    let first = parts.next().unwrap_or_default();
    let name = first.split_once('=').map_or(first, |(n, _)| n);
    let rest: Vec<String> = parts
        .map(|p| {
            let p = p.trim();
            if p.starts_with("Max-Age=") && p != "Max-Age=0" {
                "Max-Age=<seconds>".to_owned()
            } else {
                p.to_owned()
            }
        })
        .collect();
    let value = if v.contains("Max-Age=0") {
        ""
    } else {
        "<value>"
    };
    std::iter::once(format!("{name}={value}"))
        .chain(rest)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Replaces the values of members named in `keys` by `<volatile>` (a step's `volatile` list);
/// a name written `-name` is removed instead, for members the protobuf JSON mapping omits when
/// they happen to be zero (e.g. the logical part of an HLC timestamp).
fn mask_keys(j: &mut Json, keys: &[&str]) {
    match j {
        Json::Array(items) => items.iter_mut().for_each(|i| mask_keys(i, keys)),
        Json::Object(map) => {
            map.retain(|k, _| {
                !keys
                    .iter()
                    .any(|key| key.strip_prefix('-') == Some(k.as_str()))
            });
            for (k, v) in map.iter_mut() {
                if keys.contains(&k.as_str()) && !v.is_null() {
                    *v = Json::String("<volatile>".to_owned());
                } else {
                    mask_keys(v, keys);
                }
            }
        }
        _ => {}
    }
}

fn load(path: &Path) -> Json {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Replays `api/fixtures/<file>`: compares (or, when blessing, records) every step.
async fn replay(file: &str) {
    let path = fixtures_dir().join(file);
    let mut fixture = load(&path);
    let node = Node::start().await;
    let mut vars = Vars::default();
    node.seed_vars(&mut vars);
    let mut failures = Vec::new();
    let steps = fixture["steps"].as_array_mut().unwrap();
    for (i, step) in steps.iter_mut().enumerate() {
        let name = step["name"].as_str().unwrap_or("?").to_owned();
        let mut actual = node.step(step, &vars).await;
        decode_rdoc(&mut actual);
        vars.capture(step, &actual);
        normalize(&mut actual, &vars);
        if let Some(keys) = step.get("volatile").and_then(Json::as_array) {
            let keys: Vec<&str> = keys.iter().filter_map(Json::as_str).collect();
            mask_keys(&mut actual, &keys);
        }
        if blessing() {
            step["expect"] = actual;
        } else if step.get("expect") != Some(&actual) {
            failures.push(format!(
                "step {i} `{name}` differs\n--- expected\n{:#}\n--- actual\n{actual:#}",
                step.get("expect").unwrap_or(&Json::Null)
            ));
        }
    }
    node.h.stop().await;
    if blessing() {
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{file}: {} step(s) differ (bless with {BLESS_ENV}=1 after review)\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

macro_rules! fixture_tests {
    ($($name:ident => $file:literal),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                replay($file).await;
            }
        )*
        const FIXTURE_FILES: &[&str] = &[$($file),*];
    };
}

fixture_tests! {
    tc_api_003_grpc_session => "grpc-session.json",
    tc_api_003_grpc_auth => "grpc-auth.json",
    tc_api_003_grpc_admin => "grpc-admin.json",
    tc_api_003_grpc_schema => "grpc-schema.json",
    tc_api_003_grpc_document => "grpc-document.json",
    tc_api_003_grpc_query => "grpc-query.json",
    tc_api_003_grpc_transaction => "grpc-transaction.json",
    tc_api_003_grpc_backup => "grpc-backup.json",
    tc_api_003_rest_session => "rest-session.json",
    tc_api_003_rest_auth => "rest-auth.json",
    tc_api_003_rest_admin => "rest-admin.json",
    tc_api_003_rest_schema => "rest-schema.json",
    tc_api_003_rest_documents => "rest-documents.json",
    tc_api_003_rest_query => "rest-query.json",
    tc_api_003_rest_transactions => "rest-transactions.json",
    tc_api_003_rest_backup => "rest-backup.json",
}

/// RPCs and REST endpoints whose operation needs a backend this build does not install yet
/// (PD-077): their fixture step records the documented RGN-5007 `not_implemented` error, which
/// counts as coverage; an entry must be removed as soon as its fixture records a success (the
/// coverage test enforces it). Empty since M13a lanes BE and BG installed the backup backend.
const PENDING_BACKEND: &[&str] = &[];

/// Whether a recorded outcome is the RGN-5007 `not_implemented` of a pending backend.
fn pending_backend(step: &Json) -> bool {
    let e = &step["expect"];
    let detail = if step.get("rpc").is_some() {
        &e["error"]["detail"]
    } else {
        &e["body"]["error"]
    };
    detail["code"] == 5007 && detail["details"]["reason"] == "not_implemented"
}

/// Whether a recorded outcome is a success.
fn succeeded(step: &Json) -> bool {
    let e = &step["expect"];
    if step.get("rpc").is_some() {
        e.get("ok").is_some() || (e.get("messages").is_some() && e.get("error").is_none())
    } else if step.get("scram").is_some() {
        e["finish"]["status"] == 200
    } else {
        e["status"] == 200
    }
}

/// Whether the concrete `path` (query string removed, variables unresolved) matches the
/// documented template (`{param}` matches one segment).
fn path_matches(template: &str, path: &str) -> bool {
    let path = path.split('?').next().unwrap_or_default();
    let t: Vec<&str> = template.split('/').collect();
    let p: Vec<&str> = path.split('/').collect();
    t.len() == p.len()
        && t.iter()
            .zip(&p)
            .all(|(t, p)| (t.starts_with('{') && !p.is_empty()) || t == p)
}

/// AC-API-001: every RPC of every `rustegon.v1` service and every REST endpoint has at least
/// one fixture step that succeeds (or, for the entries of [`PENDING_BACKEND`], one that records
/// the RGN-5007 `not_implemented` of the missing backend); every fixture file in `api/fixtures`
/// is replayed by a test.
#[test]
fn tc_api_003_fixtures_cover_every_rpc_and_rest_endpoint() {
    let mut rpcs = BTreeSet::new();
    let mut rest = BTreeSet::new();
    let on_disk: BTreeSet<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    let replayed: BTreeSet<String> = FIXTURE_FILES.iter().map(|f| (*f).to_owned()).collect();
    assert_eq!(on_disk, replayed, "every fixture file needs a replay test");
    // Names (`<service>/<rpc>`, `<METHOD> <path>`) covered by a pending-backend step.
    let mut pending = BTreeSet::new();
    for file in FIXTURE_FILES {
        let fixture = load(&fixtures_dir().join(file));
        for step in fixture["steps"].as_array().unwrap() {
            if !succeeded(step) {
                if pending_backend(step) {
                    if let Some(rpc) = step.get("rpc").and_then(Json::as_str) {
                        pending.insert(rpc.to_owned());
                    } else if let (Some(m), Some(p)) = (
                        step.get("method").and_then(Json::as_str),
                        step.get("path").and_then(Json::as_str),
                    ) {
                        for e in REST_ENDPOINTS {
                            if e.method == m && path_matches(e.path, p) {
                                pending.insert(format!("{} {}", e.method, e.path));
                            }
                        }
                    }
                }
                continue;
            }
            if let Some(rpc) = step.get("rpc").and_then(Json::as_str) {
                rpcs.insert(rpc.to_owned());
            } else if step.get("scram").is_some() {
                rest.insert(("POST", "/api/v1/auth/scram/start"));
                rest.insert(("POST", "/api/v1/auth/scram/finish"));
            } else {
                let method = step["method"].as_str().unwrap();
                let path = step["path"].as_str().unwrap();
                for e in REST_ENDPOINTS {
                    if e.method == method && path_matches(e.path, path) {
                        rest.insert((e.method, e.path));
                    }
                }
            }
        }
    }
    let mut missing = Vec::new();
    let mut stale = Vec::new();
    let mut check = |name: String, covered: bool| {
        let is_pending = PENDING_BACKEND.contains(&name.as_str());
        if covered && is_pending {
            stale.push(name);
        } else if !covered && (!is_pending || !pending.contains(&name)) {
            missing.push(name);
        }
    };
    for service in pool().services() {
        for m in service.methods() {
            let name = format!("{}/{}", service.full_name(), m.name());
            let covered = rpcs.contains(&name);
            check(name, covered);
        }
    }
    for e in REST_ENDPOINTS {
        let covered = rest.contains(&(e.method, e.path));
        check(format!("{} {}", e.method, e.path), covered);
    }
    assert!(
        stale.is_empty(),
        "remove from PENDING_BACKEND (a fixture step now succeeds):\n{}",
        stale.join("\n")
    );
    assert!(
        missing.is_empty(),
        "no successful fixture step for:\n{}",
        missing.join("\n")
    );
}

/// The normaliser itself: placeholders, `${name}` write-back, RDoc rendering.
#[test]
fn tc_api_003_normalisation_rules() {
    let mut vars = Vars::default();
    vars.values.insert("txn".into(), json!("0123456789abcdef"));
    let mut j = json!({
        "txnId": "0123456789abcdef",
        "message": "transaction 0123456789abcdef aborted",
        "sessionToken": "zzz",
        "nested": [{"_rev": "r1", "n": 1}],
        "id": null,
    });
    normalize(&mut j, &vars);
    assert_eq!(
        j,
        json!({
            "txnId": "${txn}",
            "message": "transaction ${txn} aborted",
            "sessionToken": "<token>",
            "nested": [{"_rev": "<rev>", "n": 1}],
            "id": null,
        })
    );
    let mut doc = json!({"document": {"rdoc": {"$rdoc": {"_id": 1, "a": "x"}}}});
    encode_rdoc(&mut doc);
    assert!(doc["document"]["rdoc"].is_string());
    let mut back = Map::new();
    back.insert("rdoc".into(), doc["document"]["rdoc"].clone());
    let mut back = Json::Object(back);
    decode_rdoc(&mut back);
    assert_eq!(back, json!({"rdoc": {"$rdoc": {"_id": 1, "a": "x"}}}));
    assert_eq!(
        cookie_shape("rgn_session=abc; Path=/; Secure; HttpOnly; Max-Age=3600"),
        "rgn_session=<value>; Path=/; Secure; HttpOnly; Max-Age=<seconds>"
    );
    assert!(path_matches("/api/v1/users/{name}", "/api/v1/users/bob"));
    assert!(path_matches("/api/v1/settings", "/api/v1/settings?names=x"));
    assert!(!path_matches("/api/v1/users/{name}", "/api/v1/users"));
}
