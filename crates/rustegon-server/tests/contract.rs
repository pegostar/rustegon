// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! API contract checks that need a running node (PD-060):
//!
//! - TC-API-004 (M4 part): how the server treats a client of a newer minor version
//!   (protocol.md §9). On gRPC, fields unknown to the server are ignored (protobuf rules), enum
//!   values unknown to the server are refused with RGN-1001 instead of being guessed; on REST,
//!   unknown body members and enum strings are refused with RGN-1001 (`details.body`). A newer
//!   driver must therefore gate new fields and values on `GetServerInfo.features` /
//!   `protocol_version`, which the server reports. The driver N−2..N × server matrix and mixed
//!   N−1/N nodes need the drivers (M11) and a previous release.
//! - TC-API-002 complement: every `$ref` of the checked-in OpenAPI document resolves (the
//!   `oasdiff` gate cannot load a document with dangling references).
//! - TC-TLS-006 (part): the gRPC listener refuses a TLS client whose ALPN offer does not
//!   include `h2`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::{marker::PhantomData, path::PathBuf, sync::Arc};

use axum::body::{Body, to_bytes};
use common::{Harness, authed, base_flags, bearer, code_of};
use prost::Message;
use rustegon_net::{rustls::pki_types::ServerName, tokio_rustls::TlsConnector};
use rustegon_proto::v1::{
    self as pb, schema_service_client::SchemaServiceClient,
    session_service_client::SessionServiceClient,
    transaction_service_client::TransactionServiceClient,
};
use rustegon_server::rest::router;
use rustegon_sim_api::{Connection, Network, TokioNetwork};
use serde_json::{Value as Json, json};
use tonic::{
    Status,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
};
use tower::ServiceExt;
use yaml_rust2::{Yaml, YamlLoader};

/// A codec sending pre-encoded request bytes (to add fields the generated types lack) and
/// decoding the response as `D`.
struct RawCodec<D>(PhantomData<D>);

struct RawEncoder;

struct RawDecoder<D>(PhantomData<D>);

impl<D: Message + Default + Send + 'static> Codec for RawCodec<D> {
    type Encode = Vec<u8>;
    type Decode = D;
    type Encoder = RawEncoder;
    type Decoder = RawDecoder<D>;

    fn encoder(&mut self) -> RawEncoder {
        RawEncoder
    }

    fn decoder(&mut self) -> RawDecoder<D> {
        RawDecoder(PhantomData)
    }
}

impl Encoder for RawEncoder {
    type Item = Vec<u8>;
    type Error = Status;

    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        bytes::BufMut::put_slice(dst, &item);
        Ok(())
    }
}

impl<D: Message + Default> Decoder for RawDecoder<D> {
    type Item = D;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<D>, Status> {
        D::decode(src)
            .map(Some)
            .map_err(|e| Status::internal(e.to_string()))
    }
}

/// An unknown field of each wire type a newer minor could add: varint, 64-bit, length-delimited
/// (string or message), 32-bit, with field numbers far above the ones in use.
fn newer_minor_fields() -> Vec<u8> {
    let mut out = Vec::new();
    prost::encoding::uint64::encode(1000, &1234, &mut out);
    prost::encoding::fixed64::encode(1001, &7, &mut out);
    prost::encoding::string::encode(1002, &"from a newer minor".to_owned(), &mut out);
    prost::encoding::bytes::encode(
        1003,
        &pb::Document { rdoc: vec![1, 2] }.encode_to_vec(),
        &mut out,
    );
    prost::encoding::fixed32::encode(1004, &9, &mut out);
    out
}

async fn raw_unary<D: Message + Default + Send + 'static>(
    h: &Harness,
    path: &'static str,
    body: Vec<u8>,
    token: Option<&str>,
) -> Result<D, Status> {
    let conn = h.channel().await;
    let mut grpc = tonic::client::Grpc::new(conn.channel.clone());
    grpc.ready().await.unwrap();
    let request = match token {
        Some(t) => authed(body, &bearer(t)),
        None => tonic::Request::new(body),
    };
    grpc.unary(
        request,
        http::uri::PathAndQuery::from_static(path),
        RawCodec::<D>(PhantomData),
    )
    .await
    .map(tonic::Response::into_inner)
}

/// TC-API-004 (M4 part): unknown fields from a newer minor are ignored on gRPC.
#[tokio::test]
async fn tc_api_004_grpc_ignores_fields_of_a_newer_minor() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let token = conn.admin_token().await;

    // A request message with only unknown fields.
    let mut ping = pb::PingRequest {}.encode_to_vec();
    ping.extend(newer_minor_fields());
    let _: pb::PingResponse = raw_unary(&h, "/rustegon.v1.SessionService/Ping", ping, None)
        .await
        .unwrap();

    // Known fields keep their meaning next to unknown ones.
    let mut create = pb::CreateDatabaseRequest {
        name: "newer".into(),
        ..Default::default()
    }
    .encode_to_vec();
    create.extend(newer_minor_fields());
    let r: pb::CreateDatabaseResponse = raw_unary(
        &h,
        "/rustegon.v1.SchemaService/CreateDatabase",
        create,
        Some(&token),
    )
    .await
    .unwrap();
    assert!(r.created);
    let dbs = SchemaServiceClient::new(conn.channel.clone())
        .list_databases(authed(pb::ListDatabasesRequest {}, &bearer(&token)))
        .await
        .unwrap()
        .into_inner()
        .databases;
    assert!(dbs.iter().any(|d| d.name == "newer"));

    // Negotiation inputs a newer driver relies on (protocol.md §9).
    let info = SessionServiceClient::new(conn.channel.clone())
        .get_server_info(pb::GetServerInfoRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.protocol_version.split('.').next(), Some("1"));
    assert!(
        info.protocol_version
            .split('.')
            .nth(1)
            .is_some_and(|m| m.parse::<u32>().is_ok())
    );
    h.stop().await;
}

/// TC-API-004 (M4 part): enum values unknown to the server are refused with RGN-1001, never
/// mapped onto a default (a newer isolation level must not silently become another one).
#[tokio::test]
async fn tc_api_004_grpc_refuses_enum_values_of_a_newer_minor() {
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let token = conn.admin_token().await;
    let mut txn = TransactionServiceClient::new(conn.channel.clone());
    for request in [
        pb::BeginRequest {
            isolation: 99,
            ..Default::default()
        },
        pb::BeginRequest {
            write_concern: 42,
            ..Default::default()
        },
        pb::BeginRequest {
            priority: 7,
            ..Default::default()
        },
    ] {
        let err = txn
            .begin(authed(request, &bearer(&token)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{request:?}");
        assert_eq!(code_of(&err), 1001, "{request:?}");
    }
    // The zero value (`*_UNSPECIFIED`) is the documented default.
    txn.begin(authed(pb::BeginRequest::default(), &bearer(&token)))
        .await
        .unwrap();
    h.stop().await;
}

/// TC-API-004 (M4 part): REST is strict both ways: unknown members and unknown enum strings
/// are RGN-1001 (`details.body` = `data`), so a newer client learns the server is older.
#[tokio::test]
async fn tc_api_004_rest_refuses_members_and_values_of_a_newer_minor() {
    let h = Harness::start(base_flags()).await;
    let token = h.channel().await.admin_token().await;
    let api = router(&h.services, 64 * 1024 * 1024);
    for (path, body) in [
        ("/api/v1/databases", json!({"name": "a", "shardCount": 3})),
        (
            "/api/v1/transactions",
            json!({"isolation": "linearizable_plus"}),
        ),
        (
            "/api/v1/transactions",
            json!({"readOnly": false, "newFlag": true}),
        ),
    ] {
        let response = api
            .clone()
            .oneshot(
                http::Request::post(path)
                    .header("authorization", bearer(&token))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST, "{body}");
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let j: Json = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(j["error"]["code"], 1001, "{j}");
        assert_eq!(j["error"]["details"]["body"], "data", "{j}");
    }
    h.stop().await;
}

/// TC-API-002 complement: every `$ref` of `api/openapi/rustegon-v1.yaml` names an existing
/// component (an unresolved one makes the document unusable for generators and `oasdiff`).
#[test]
fn tc_api_002_every_openapi_reference_resolves() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../api/openapi/rustegon-v1.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let doc = &YamlLoader::load_from_str(&text).unwrap()[0];
    let mut refs = Vec::new();
    collect_refs(doc, &mut refs);
    assert_ne!(refs.len(), 0);
    let mut missing = Vec::new();
    for r in refs {
        let parts: Vec<&str> = r.trim_start_matches("#/").split('/').collect();
        let mut node = doc;
        for p in &parts {
            node = &node[*p];
        }
        if node.is_badvalue() {
            missing.push(r);
        }
    }
    missing.sort();
    missing.dedup();
    assert!(missing.is_empty(), "unresolved references: {missing:?}");
}

fn collect_refs(y: &Yaml, out: &mut Vec<String>) {
    match y {
        Yaml::Hash(h) => {
            for (k, v) in h {
                if k.as_str() == Some("$ref")
                    && let Some(s) = v.as_str()
                {
                    out.push(s.to_owned());
                }
                collect_refs(v, out);
            }
        }
        Yaml::Array(a) => a.iter().for_each(|v| collect_refs(v, out)),
        _ => {}
    }
}

/// TC-TLS-006 (part): the gRPC listener only speaks HTTP/2; a client offering other ALPN
/// protocols only is refused during the handshake (no fallback to a protocol the listener
/// does not serve).
#[tokio::test]
async fn tc_tls_006_grpc_listener_refuses_alpn_without_h2() {
    let h = Harness::start(base_flags()).await;
    let mut config = h.pki.client_config(None);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn: Box<dyn Connection> = TokioNetwork.connect(h.addr).await.unwrap();
    let result = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), conn)
        .await;
    let err = result.err().expect("handshake must fail");
    assert!(err.to_string().contains("NoApplicationProtocol"), "{err}");
    // The same client with `h2` succeeds (the refusal is the ALPN, not the certificate).
    let ok = TlsConnector::from(Arc::new(h.pki.client_config(None)))
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TokioNetwork.connect(h.addr).await.unwrap(),
        )
        .await;
    assert!(ok.is_ok());
    h.stop().await;
}
