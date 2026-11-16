// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Contract tests of the generated `rustegon.v1` code: error mapping (TC-API-005) and the
//! service/RPC surface of the M4 subset (FR-API-001, PD-045).
//!
//! `rustegon-common/tests/error_catalog.rs` already checks `proto/errors.yaml` ⇄ `ErrorCode` ⇄
//! the protocol.md §7 table text. These tests close the remaining gap: the status actually put
//! on the wire (`tonic::Code`) and the `ErrorDetail` message.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use prost::Message as _;
use prost_types::FileDescriptorSet;
use rustegon_common::{Error, ErrorCode};
use rustegon_proto::{
    FILE_DESCRIPTOR_SET,
    status::{
        ERROR_DETAIL_TYPE_URL, RpcStatus, error_detail, error_detail_of, to_status, tonic_code,
    },
};

const PROTOCOL_MD: &str = include_str!("../../../docs/specifications/protocol.md");

/// `INVALID_ARGUMENT` -> `InvalidArgument` (the `Debug` form of `tonic::Code`).
fn camel(screaming: &str) -> String {
    screaming
        .split('_')
        .map(|w| {
            let lower = w.to_ascii_lowercase();
            let mut chars = lower.chars();
            chars.next().map_or_else(String::new, |c| {
                c.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect()
}

/// Rows of the protocol.md §7 table: (code, gRPC name, HTTP status).
fn protocol_rows() -> Vec<(u16, String, u16)> {
    let section = PROTOCOL_MD
        .split("## 7. Error model")
        .nth(1)
        .expect("protocol.md has §7")
        .split("\n## ")
        .next()
        .expect("section body");
    section
        .lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            // `| code | name | grpc | http | retryable |` splits into 7 cells.
            let code = cells.get(1)?.parse::<u16>().ok()?;
            Some((
                code,
                cells[3].to_owned(),
                cells[4].parse().expect("HTTP status is numeric"),
            ))
        })
        .collect()
}

#[test]
fn tc_api_005_every_error_code_maps_to_protocol_grpc_and_http_status() {
    let rows = protocol_rows();
    assert_eq!(
        rows.len(),
        ErrorCode::ALL.len(),
        "protocol.md §7 and proto/errors.yaml list different numbers of codes"
    );
    for (code, grpc, http) in rows {
        let error_code = ErrorCode::from_code(code)
            .unwrap_or_else(|| panic!("RGN-{code} of protocol.md §7 is not in errors.yaml"));
        let wire = tonic_code(error_code.grpc_code());
        assert_eq!(
            format!("{wire:?}"),
            camel(&grpc),
            "RGN-{code}: gRPC status on the wire differs from protocol.md §7"
        );
        assert_ne!(wire, tonic::Code::Ok, "RGN-{code} must not map to OK");
        assert_eq!(error_code.http_status(), http, "RGN-{code}: HTTP status");
    }
}

#[test]
fn tc_api_005_status_packs_error_detail_in_google_rpc_status() {
    let err = Error::new(ErrorCode::DuplicateKey, "duplicate _id").with_detail("index", "_id");
    let status = to_status(&err, "trace-1");
    assert_eq!(status.code(), tonic::Code::AlreadyExists);
    assert_eq!(status.message(), "duplicate _id");

    // The details bytes are a standard google.rpc.Status with one packed ErrorDetail, so any
    // gRPC client library's rich-error support can read it.
    let rpc = RpcStatus::decode(status.details()).expect("google.rpc.Status");
    assert_eq!(rpc.code, tonic::Code::AlreadyExists as i32);
    assert_eq!(rpc.message, "duplicate _id");
    assert_eq!(rpc.details.len(), 1);
    assert_eq!(rpc.details[0].type_url, ERROR_DETAIL_TYPE_URL);

    let detail = error_detail_of(&status).expect("ErrorDetail");
    assert_eq!(detail, error_detail(&err, "trace-1"));

    // A status without Rustegon details yields None instead of a bogus detail.
    assert_eq!(error_detail_of(&tonic::Status::internal("x")), None);
}

#[test]
fn tc_api_005_error_detail_carries_code_name_retry_and_details() {
    let err = Error::new(ErrorCode::DuplicateKey, "duplicate _id").with_detail("index", "_id");
    let detail = error_detail(&err, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(detail.code, 1005);
    assert_eq!(detail.name, "DuplicateKey");
    assert!(!detail.retryable);
    assert_eq!(detail.committed, None);
    assert_eq!(
        detail.details,
        [("index".to_owned(), "_id".to_owned())].into()
    );
    assert_eq!(detail.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");

    // WriteConcernTimeout: the write is committed (protocol.md §7).
    let detail = error_detail(
        &Error::new(ErrorCode::WriteConcernTimeout, "slow voter"),
        "",
    );
    assert_eq!(detail.committed, Some(true));
    assert!(!detail.retryable);

    // CommitOutcomeUnknown: the outcome must stay unknown to the client.
    let detail = error_detail(
        &Error::new(ErrorCode::CommitOutcomeUnknown, "lost").with_retryable(true),
        "",
    );
    assert_eq!(detail.committed, None);
    assert!(detail.retryable);

    // ErrorDetail round-trips through its wire encoding (it travels inside google.rpc.Status).
    let bytes = detail.encode_to_vec();
    let decoded = rustegon_proto::v1::ErrorDetail::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded, detail);
}

/// The M4 RPC subset (PD-045) plus the services added additively since (M13a
/// `BackupService`): service -> RPCs.
const M4_SURFACE: &[(&str, &[&str])] = &[
    ("AuthService", &["Authenticate", "Logout", "WhoAmI"]),
    ("SessionService", &["Ping", "GetServerInfo"]),
    (
        "QueryService",
        &["Execute", "GetMore", "KillCursor", "Explain"],
    ),
    (
        "DocumentService",
        &[
            "Get",
            "GetMany",
            "Insert",
            "Replace",
            "Update",
            "Upsert",
            "Delete",
            "BulkWrite",
        ],
    ),
    (
        "TransactionService",
        &["Begin", "Commit", "Rollback", "Status", "Heartbeat"],
    ),
    (
        "SchemaService",
        &[
            "CreateDatabase",
            "DropDatabase",
            "ListDatabases",
            "CreateCollection",
            "DropCollection",
            "AlterCollection",
            "GetCollection",
            "ListCollections",
            "CreateIndex",
            "DropIndex",
            "ListIndexes",
            "IndexBuildProgress",
            "GetValidator",
            "SetValidator",
            "RemoveValidator",
        ],
    ),
    (
        "AdminService",
        &[
            "CreateUser",
            "GetUser",
            "ListUsers",
            "UpdateUser",
            "DropUser",
            "ChangePassword",
            "CreateRole",
            "GetRole",
            "ListRoles",
            "UpdateRole",
            "DropRole",
            "CreateApiKey",
            "ListApiKeys",
            "RevokeApiKey",
            "GetSettings",
            "UpdateSettings",
        ],
    ),
    // M13a (PD-062, PD-077): added additively after `api-v1-alpha`.
    (
        "BackupService",
        &[
            "CreateBackup",
            "ListBackups",
            "GetBackup",
            "VerifyBackup",
            "CreateSnapshot",
            "ListSnapshots",
            "DeleteSnapshot",
            "Dump",
            "LogicalRestore",
        ],
    ),
];

/// (service, rpc) -> (client streaming, server streaming).
fn descriptor_surface() -> BTreeMap<(String, String), (bool, bool)> {
    let fds = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("valid descriptor set");
    let mut out = BTreeMap::new();
    for file in &fds.file {
        assert_eq!(file.package(), "rustegon.v1", "{}", file.name());
        for service in &file.service {
            for method in &service.method {
                out.insert(
                    (service.name().to_owned(), method.name().to_owned()),
                    (method.client_streaming(), method.server_streaming()),
                );
            }
        }
    }
    out
}

#[test]
fn tc_api_001_descriptors_expose_exactly_the_m4_rpc_surface() {
    let surface = descriptor_surface();
    let expected: BTreeSet<(String, String)> = M4_SURFACE
        .iter()
        .flat_map(|(service, rpcs)| {
            rpcs.iter()
                .map(|rpc| ((*service).to_owned(), (*rpc).to_owned()))
        })
        .collect();
    let actual: BTreeSet<(String, String)> = surface.keys().cloned().collect();
    assert_eq!(actual, expected);

    // Streaming shapes of protocol.md §2/§6 and §8.
    let key = |s: &str, r: &str| (s.to_owned(), r.to_owned());
    assert_eq!(surface[&key("AuthService", "Authenticate")], (true, true));
    assert_eq!(surface[&key("QueryService", "Execute")], (false, true));
    assert_eq!(surface[&key("BackupService", "Dump")], (false, true));
    assert_eq!(
        surface[&key("BackupService", "LogicalRestore")],
        (true, false)
    );
    let streaming: Vec<_> = surface
        .iter()
        .filter(|(_, (c, s))| *c || *s)
        .map(|(k, _)| k.clone())
        .collect();
    assert_eq!(
        streaming,
        [
            key("AuthService", "Authenticate"),
            key("BackupService", "Dump"),
            key("BackupService", "LogicalRestore"),
            key("QueryService", "Execute")
        ]
    );
}

#[test]
fn tc_api_001_enums_have_unspecified_zero_values() {
    // protocol.md §9: new enum values must be tolerated, so every enum has a 0 "not set /
    // unknown" value that receivers treat as unknown.
    let fds = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("valid descriptor set");
    let mut enums = Vec::new();
    for file in &fds.file {
        enums.extend(file.enum_type.iter());
        let mut stack: Vec<_> = file.message_type.iter().collect();
        while let Some(msg) = stack.pop() {
            enums.extend(msg.enum_type.iter());
            stack.extend(msg.nested_type.iter());
        }
    }
    assert_ne!(enums.len(), 0, "the descriptor set declares enums");
    for e in enums {
        let zero = e
            .value
            .iter()
            .find(|v| v.number() == 0)
            .unwrap_or_else(|| panic!("enum {} has no 0 value", e.name()));
        assert!(
            zero.name().ends_with("_UNSPECIFIED"),
            "enum {}: zero value {} must be *_UNSPECIFIED",
            e.name(),
            zero.name()
        );
    }
}

#[test]
fn tc_api_001_generated_clients_and_servers_exist() {
    // Both sides were generated for every service, under their fully qualified gRPC names.
    use rustegon_proto::v1 as pb;
    use tonic::transport::Channel;
    let servers = [
        pb::admin_service_server::SERVICE_NAME,
        pb::auth_service_server::SERVICE_NAME,
        pb::backup_service_server::SERVICE_NAME,
        pb::document_service_server::SERVICE_NAME,
        pb::query_service_server::SERVICE_NAME,
        pb::schema_service_server::SERVICE_NAME,
        pb::session_service_server::SERVICE_NAME,
        pb::transaction_service_server::SERVICE_NAME,
    ];
    let expected: Vec<String> = M4_SURFACE
        .iter()
        .map(|(service, _)| format!("rustegon.v1.{service}"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(servers.map(str::to_owned).to_vec(), expected);
    let clients = [
        std::any::type_name::<pb::admin_service_client::AdminServiceClient<Channel>>(),
        std::any::type_name::<pb::auth_service_client::AuthServiceClient<Channel>>(),
        std::any::type_name::<pb::backup_service_client::BackupServiceClient<Channel>>(),
        std::any::type_name::<pb::document_service_client::DocumentServiceClient<Channel>>(),
        std::any::type_name::<pb::query_service_client::QueryServiceClient<Channel>>(),
        std::any::type_name::<pb::schema_service_client::SchemaServiceClient<Channel>>(),
        std::any::type_name::<pb::session_service_client::SessionServiceClient<Channel>>(),
        std::any::type_name::<pb::transaction_service_client::TransactionServiceClient<Channel>>(),
    ];
    assert!(clients.iter().all(|name| name.contains("ServiceClient")));
}
