// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `BackupService` over gRPC and REST (M13a lane BC; FR-BKP-001/003/004/006/007, PD-062,
//! PD-077): listing, describing and verifying backups at a local destination for real
//! (TC-BKP-009/010 over the API, TC-API-006 parity), the documented RGN-5007 of the engine
//! operations without a backend, the streaming plumbing of `Dump`/`LogicalRestore` and the
//! audit records through a fake backend (TC-SEC-004), and the built-in backup/restore roles
//! (TC-SEC-001).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::naive_bytecount
)]

mod common;

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use axum::body::{Body, to_bytes};
use common::{
    ADMIN, Binding, Conn, Harness, OTHER_PASSWORD, SEEDED_BACKUP_ID, authed, base_flags, bearer,
    code_of, seed_backup,
};
use rustegon_backup::{
    BackupId, BackupMetadata, Consistency, Destination, Encryption, HlcTimestamp, NewBackup,
    SourceInfo, write_backup,
};
use rustegon_common::Error;
use rustegon_proto::v1::{
    CreateBackupRequest, CreateSnapshotRequest, CreateUserRequest, DeleteSnapshotRequest,
    DumpRequest, GetBackupRequest, ListBackupsRequest, ListSnapshotsRequest,
    LogicalRestoreOptions as PbOptions, LogicalRestoreRequest, RoleGrant, VerifyBackupRequest,
    admin_service_client::AdminServiceClient, backup_service_client::BackupServiceClient,
    dump_response, logical_restore_request,
};
use rustegon_server::{
    CancelToken,
    rest::router,
    services::backup::{
        BackupBackend, CreatedBackup, DumpChunk, DumpScope, DumpSink, DumpSource, DumpSummary,
        LogicalRestoreOptions, LogicalRestoreSummary, NOT_IMPLEMENTED_REASON, RestoredCollection,
        SnapshotInfo,
    },
};
use rustegon_sim_api::{FileSystem, OpenMode, StdFileSystem};
use serde_json::{Value as Json, json};
use tokio::sync::mpsc;
use tonic::{Request, Status, codegen::tokio_stream::wrappers::ReceiverStream};
use tower::ServiceExt;

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn client(conn: &Conn) -> BackupServiceClient<tonic::transport::Channel> {
    BackupServiceClient::new(conn.channel.clone())
}

fn reason(status: &Status) -> String {
    rustegon_proto::status::error_detail_of(status)
        .and_then(|d| d.details.get("reason").cloned())
        .unwrap_or_default()
}

/// Percent-encodes a query parameter value.
fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// A REST call through the in-process router: (status, body).
async fn rest(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Json>,
) -> (u16, Json) {
    let b = http::Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", bearer(token));
    let request = match body {
        Some(j) => b
            .header("content-type", "application/json")
            .body(Body::from(j.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Json::Null))
}

/// The audit records of `event` (`backup` / `restore`).
fn audit_of(h: &Harness, event: &str) -> Vec<Json> {
    h.audit_lines()
        .into_iter()
        .filter(|l| l["event"] == event)
        .collect()
}

fn path_text(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}

// ---------------------------------------------------------------------------------------------
// Fake backend
// ---------------------------------------------------------------------------------------------

const T: HlcTimestamp = HlcTimestamp {
    wall: 1_794_219_300_000_000_000,
    logical: 3,
};

/// Stands in for the wave-2 engine backend: writes a fixed backup, lists one snapshot, dumps a
/// fixed layout and records what a logical restore receives.
#[derive(Default)]
struct FakeBackend {
    received: Mutex<Vec<DumpChunk>>,
}

impl BackupBackend for FakeBackend {
    fn create_backup(
        &self,
        dest: &dyn Destination,
        cancel: &CancelToken,
    ) -> Result<CreatedBackup, Error> {
        cancel.check()?;
        let stage = tempfile::tempdir().unwrap();
        let fs = StdFileSystem;
        let path = stage.path().join("lsm").join("000001.rsst");
        fs.create_dir_all(path.parent().unwrap()).unwrap();
        let mut f = fs.open(&path, OpenMode::Truncate).unwrap();
        f.append(b"sst").unwrap();
        f.sync_data().unwrap();
        let manifest = write_backup(
            dest,
            &fs,
            stage.path(),
            &NewBackup {
                id: BackupId::parse("20261110T080000Z-0badc0de").unwrap(),
                created_at: SystemTime::UNIX_EPOCH + Duration::new(1_794_297_600, 0),
                metadata: BackupMetadata {
                    consistency: Consistency {
                        timestamp: T,
                        applied_index: 9,
                        applied_term: 1,
                        storage_seqno: 50,
                    },
                    source: SourceInfo {
                        cluster_id: "c".into(),
                        node_id: "7".into(),
                        server_version: "0.1.0".into(),
                    },
                    encryption: Encryption::Plaintext,
                    pitr: None,
                },
            },
        )?;
        Ok(CreatedBackup {
            manifest,
            warnings: vec![rustegon_server::services::Warning {
                kind: "PlaintextBackup".into(),
                message: "the store is not encrypted: the backup is plaintext".into(),
                details: std::collections::BTreeMap::new(),
            }],
        })
    }

    fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>, Error> {
        Ok(vec![SnapshotInfo {
            name: "pre-upgrade".into(),
            created_at: SystemTime::UNIX_EPOCH + Duration::new(1_794_297_600, 0),
            consistency: Consistency {
                timestamp: T,
                applied_index: 9,
                applied_term: 1,
                storage_seqno: 50,
            },
            file_count: 3,
            total_bytes: 1234,
        }])
    }

    fn dump(
        &self,
        scope: &DumpScope,
        sink: &mut dyn DumpSink,
        cancel: &CancelToken,
    ) -> Result<DumpSummary, Error> {
        cancel.check()?;
        assert_eq!(scope.databases, ["shop"]);
        sink.started(T)?;
        for (path, data, eof) in [
            ("shop/orders.metadata.json", &b"{}"[..], true),
            ("shop/orders.ndjson", b"{\"_id\":1}\n", false),
            ("shop/orders.ndjson", b"{\"_id\":2}\n", true),
            ("dump.json", b"{\"format_version\":1}", true),
        ] {
            sink.chunk(DumpChunk {
                path: path.into(),
                data: data.to_vec(),
                end_of_file: eof,
            })?;
        }
        Ok(DumpSummary {
            collections: 1,
            documents: 2,
        })
    }

    fn logical_restore(
        &self,
        options: &LogicalRestoreOptions,
        source: &mut dyn DumpSource,
        cancel: &CancelToken,
    ) -> Result<LogicalRestoreSummary, Error> {
        cancel.check()?;
        assert!(options.drop_existing);
        let mut documents = 0;
        while let Some(chunk) = source.next_chunk()? {
            if chunk.path.ends_with(".ndjson") {
                documents += chunk.data.iter().filter(|b| **b == b'\n').count() as u64;
            }
            self.received.lock().unwrap().push(chunk);
        }
        Ok(LogicalRestoreSummary {
            source_timestamp: T,
            collections: vec![RestoredCollection {
                database: "shop".into(),
                collection: "orders".into(),
                documents,
                indexes: 1,
            }],
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// TC-BKP-009 / TC-BKP-010 over the API, TC-API-006 parity: list, get and verify a backup at a
/// local destination over gRPC and REST.
#[tokio::test]
async fn tc_bkp_009_list_get_and_verify_a_local_destination_over_grpc_and_rest() {
    let dir = tempfile::tempdir().unwrap();
    let (dest, manifest) = seed_backup(dir.path());
    let destination = path_text(&dest);
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let token = conn.admin_token().await;
    let auth = bearer(&token);
    let mut svc = client(&conn);

    let listed = svc
        .list_backups(authed(
            ListBackupsRequest {
                destination: destination.clone(),
            },
            &auth,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.backups.len(), 1);
    assert_eq!(listed.unreadable.len(), 0);
    let info = &listed.backups[0];
    assert_eq!(info.backup_id, SEEDED_BACKUP_ID);
    assert_eq!(info.created_at_unix_ms, 1_794_219_300_000);
    assert_eq!(info.file_count, manifest.files.len() as u64);
    assert_eq!(info.total_bytes, manifest.total_bytes());
    let consistency = info.consistency.as_ref().unwrap();
    assert_eq!(consistency.applied_index, 42);
    assert_eq!(
        consistency.timestamp.as_ref().unwrap().wall_ns,
        1_794_219_300_000_000_000
    );

    let got = svc
        .get_backup(authed(
            GetBackupRequest {
                destination: destination.clone(),
                backup_id: SEEDED_BACKUP_ID.into(),
            },
            &auth,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.files.len(), manifest.files.len());
    assert_eq!(got.files[0].path, manifest.files[0].path);
    assert_eq!(got.files[0].blake3, manifest.files[0].blake3);

    let verified = svc
        .verify_backup(authed(
            VerifyBackupRequest {
                destination: destination.clone(),
                backup_id: SEEDED_BACKUP_ID.into(),
                deep: true,
            },
            &auth,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(verified.files_checked, manifest.files.len() as u64);
    assert_eq!(verified.bytes_hashed, manifest.total_bytes());

    // The same operations over REST return the same data.
    let app = router(&h.services, 64 << 20);
    let q = pct(&destination);
    let (status, body) = rest(
        &app,
        "GET",
        &format!("/api/v1/backups?destination={q}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["backups"][0]["backupId"], SEEDED_BACKUP_ID);
    assert_eq!(body["backups"][0]["fileCount"], info.file_count);
    assert_eq!(
        body["backups"][0]["createdAtUnixMs"],
        info.created_at_unix_ms
    );
    assert_eq!(body["backups"][0]["encryption"], "plaintext");
    assert_eq!(
        body["backups"][0]["consistency"]["timestamp"]["wallNs"],
        "1794219300000000000"
    );
    let (status, body) = rest(
        &app,
        "GET",
        &format!("/api/v1/backups/{SEEDED_BACKUP_ID}?destination={q}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["files"].as_array().unwrap().len(), got.files.len());
    assert_eq!(body["files"][0]["blake3"], got.files[0].blake3);
    let (status, body) = rest(
        &app,
        "POST",
        &format!("/api/v1/backups/{SEEDED_BACKUP_ID}/verify"),
        &token,
        Some(json!({"destination": destination, "deep": true})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["filesChecked"], verified.files_checked);
    assert_eq!(body["bytesHashed"], verified.bytes_hashed);

    // An unknown id is RGN-1030 on both channels.
    let missing = "20261109T101500Z-00000000";
    let err = svc
        .get_backup(authed(
            GetBackupRequest {
                destination: destination.clone(),
                backup_id: missing.into(),
            },
            &auth,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), 1030);
    let (status, body) = rest(
        &app,
        "GET",
        &format!("/api/v1/backups/{missing}?destination={q}"),
        &token,
        None,
    )
    .await;
    assert_eq!((status, body["error"]["code"].as_u64()), (404, Some(1030)));
    h.stop().await;
}

/// TC-BKP-010 over the API: a corrupt file passes the shallow check (same size) and fails the
/// deep one; a truncated file fails both (RGN-5002).
#[tokio::test]
async fn tc_bkp_010_verify_over_the_api_detects_corrupt_and_truncated_files() {
    let dir = tempfile::tempdir().unwrap();
    let (dest, manifest) = seed_backup(dir.path());
    let destination = path_text(&dest);
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let auth = bearer(&conn.admin_token().await);
    let mut svc = client(&conn);
    let verify = |deep: bool| {
        authed(
            VerifyBackupRequest {
                destination: destination.clone(),
                backup_id: SEEDED_BACKUP_ID.into(),
                deep,
            },
            &auth,
        )
    };
    let big = manifest.files.iter().find(|f| f.size == 4096).unwrap();
    let file = dest
        .join("backups")
        .join(SEEDED_BACKUP_ID)
        .join(big.path.replace('/', std::path::MAIN_SEPARATOR_STR));
    let mut bytes = std::fs::read(&file).unwrap();
    bytes[100] ^= 0xff;
    std::fs::write(&file, &bytes).unwrap();
    svc.verify_backup(verify(false)).await.unwrap();
    let err = svc.verify_backup(verify(true)).await.unwrap_err();
    assert_eq!(code_of(&err), 5002, "{err:?}");
    std::fs::write(&file, &bytes[..10]).unwrap();
    let err = svc.verify_backup(verify(false)).await.unwrap_err();
    assert_eq!(code_of(&err), 5002, "{err:?}");
    h.stop().await;
}

/// FR-BKP-004 on the server: a relative path is RGN-1001; a missing directory is RGN-1030 and
/// is not created by a read.
#[tokio::test]
async fn fr_bkp_004_server_destinations_are_absolute_and_never_created_by_reads() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let auth = bearer(&conn.admin_token().await);
    let mut svc = client(&conn);
    let err = svc
        .list_backups(authed(
            ListBackupsRequest {
                destination: "relative/backups".into(),
            },
            &auth,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), 1001);
    let missing = dir.path().join("nowhere");
    let err = svc
        .list_backups(authed(
            ListBackupsRequest {
                destination: path_text(&missing),
            },
            &auth,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), 1030);
    assert!(
        !missing.exists(),
        "a listing must not create the destination"
    );
    // Credentials never travel in a destination URL.
    let err = svc
        .list_backups(authed(
            ListBackupsRequest {
                destination: "s3://key:secret@bucket/p".into(),
            },
            &auth,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), 1001);
    assert!(!err.message().contains("secret"), "{}", err.message());
    h.stop().await;
}

/// The engine operations without a backend fail with the documented RGN-5007
/// `not_implemented` (PD-077), on gRPC and REST.
#[tokio::test]
async fn tc_bkp_001_engine_operations_without_a_backend_are_rgn_5007() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(base_flags()).await;
    let conn = h.channel().await;
    let token = conn.admin_token().await;
    let auth = bearer(&token);
    let mut svc = client(&conn);
    let destination = path_text(dir.path());
    let check = |r: Result<(), Status>, what: &str| {
        let s = r.unwrap_err();
        assert_eq!(code_of(&s), 5007, "{what}: {s:?}");
        assert_eq!(reason(&s), NOT_IMPLEMENTED_REASON, "{what}");
        assert_eq!(s.code(), tonic::Code::FailedPrecondition, "{what}");
    };
    check(
        svc.create_backup(authed(
            CreateBackupRequest {
                destination: destination.clone(),
            },
            &auth,
        ))
        .await
        .map(|_| ()),
        "CreateBackup",
    );
    check(
        svc.create_snapshot(authed(CreateSnapshotRequest { name: "s1".into() }, &auth))
            .await
            .map(|_| ()),
        "CreateSnapshot",
    );
    check(
        svc.list_snapshots(authed(ListSnapshotsRequest {}, &auth))
            .await
            .map(|_| ()),
        "ListSnapshots",
    );
    check(
        svc.delete_snapshot(authed(DeleteSnapshotRequest { name: "s1".into() }, &auth))
            .await
            .map(|_| ()),
        "DeleteSnapshot",
    );
    check(
        svc.dump(authed(DumpRequest::default(), &auth))
            .await
            .map(|_| ()),
        "Dump",
    );
    let (tx, rx) = mpsc::channel(2);
    tx.send(LogicalRestoreRequest {
        item: Some(logical_restore_request::Item::Options(PbOptions::default())),
    })
    .await
    .unwrap();
    drop(tx);
    check(
        svc.logical_restore(authed(ReceiverStream::new(rx), &auth))
            .await
            .map(|_| ()),
        "LogicalRestore",
    );
    let app = router(&h.services, 64 << 20);
    for (method, path, body) in [
        (
            "POST",
            "/api/v1/backups",
            Some(json!({"destination": destination})),
        ),
        ("GET", "/api/v1/snapshots", None),
        ("POST", "/api/v1/snapshots", Some(json!({"name": "s1"}))),
        ("DELETE", "/api/v1/snapshots/s1", None),
    ] {
        let (status, body) = rest(&app, method, path, &token, body).await;
        assert_eq!(status, 400, "{method} {path}: {body}");
        assert_eq!(body["error"]["code"], 5007, "{method} {path}");
        assert_eq!(body["error"]["details"]["reason"], NOT_IMPLEMENTED_REASON);
    }
    // Nothing was written to the destination.
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    h.stop().await;
}

/// TC-SEC-004 for backup/restore: every audited operation writes a start record before it runs
/// and an end record with its outcome (success with details, or failure with the code).
#[tokio::test]
async fn tc_sec_004_backup_and_restore_are_audited_at_start_and_end() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FakeBackend::default());
    let h = Harness::start_with_backup(base_flags(), backend.clone()).await;
    let conn = h.channel().await;
    let auth = bearer(&conn.admin_token().await);
    let mut svc = client(&conn);
    let destination = path_text(&dir.path().join("dest"));

    let created = svc
        .create_backup(authed(
            CreateBackupRequest {
                destination: destination.clone(),
            },
            &auth,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        created.backup.unwrap().backup_id,
        "20261110T080000Z-0badc0de"
    );
    assert_eq!(created.warnings[0].kind, "PlaintextBackup");
    // The fake backend does not implement snapshots: a failed operation is audited too.
    let err = svc
        .create_snapshot(authed(CreateSnapshotRequest { name: "s1".into() }, &auth))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), 5007);

    let backup = audit_of(&h, "backup");
    let phases: Vec<(String, String, String)> = backup
        .iter()
        .map(|l| {
            (
                l["details"]["op"].as_str().unwrap().to_owned(),
                l["details"]["phase"].as_str().unwrap().to_owned(),
                l["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let s = |a: &str, b: &str, c: &str| (a.to_owned(), b.to_owned(), c.to_owned());
    assert_eq!(
        phases,
        [
            s("create_backup", "start", "success"),
            s("create_backup", "end", "success"),
            s("create_snapshot", "start", "success"),
            s("create_snapshot", "end", "failure"),
        ]
    );
    assert_eq!(
        backup[1]["details"]["backup_id"],
        "20261110T080000Z-0badc0de"
    );
    assert_eq!(backup[1]["user"], ADMIN);
    assert_eq!(backup[1]["resource"], "cluster");
    assert_eq!(backup[1]["action"], "backup");
    assert_eq!(backup[3]["details"]["error_code"], "5007");

    // A logical restore is a `restore` event.
    let (tx, rx) = mpsc::channel(4);
    tx.send(LogicalRestoreRequest {
        item: Some(logical_restore_request::Item::Options(PbOptions {
            drop_existing: true,
            ..PbOptions::default()
        })),
    })
    .await
    .unwrap();
    drop(tx);
    svc.logical_restore(authed(ReceiverStream::new(rx), &auth))
        .await
        .unwrap();
    let restore = audit_of(&h, "restore");
    assert_eq!(restore.len(), 2);
    assert_eq!(restore[0]["details"]["phase"], "start");
    assert_eq!(restore[1]["details"]["phase"], "end");
    assert_eq!(restore[1]["outcome"], "success");
    assert_eq!(restore[1]["action"], "restore");
    h.stop().await;
}

/// FR-BKP-007 plumbing: `Dump` streams the backend's timestamp and chunks in order;
/// `LogicalRestore` hands the client's chunks to the backend and refuses malformed streams.
#[tokio::test]
async fn fr_bkp_007_dump_and_logical_restore_stream_through_the_backend() {
    let backend = Arc::new(FakeBackend::default());
    let h = Harness::start_with_backup(base_flags(), backend.clone()).await;
    let conn = h.channel().await;
    let auth = bearer(&conn.admin_token().await);
    let mut svc = client(&conn);

    let mut stream = svc
        .dump(authed(
            DumpRequest {
                databases: vec!["shop".into()],
                collections: vec![],
            },
            &auth,
        ))
        .await
        .unwrap()
        .into_inner();
    let mut items = Vec::new();
    while let Some(m) = stream.message().await.unwrap() {
        items.push(m.item.unwrap());
    }
    let Some(dump_response::Item::Started(t)) = items.first() else {
        panic!("first item is not the timestamp: {items:?}");
    };
    assert_eq!((t.wall_ns, t.logical), (T.wall, T.logical));
    let chunks: Vec<_> = items[1..]
        .iter()
        .map(|i| match i {
            dump_response::Item::Chunk(c) => c.clone(),
            dump_response::Item::Started(_) => panic!("second timestamp"),
        })
        .collect();
    assert_eq!(chunks.len(), 4);
    assert_eq!(chunks[3].path, "dump.json");
    let audited = audit_of(&h, "backup");
    let end = audited.last().unwrap();
    assert_eq!(end["details"]["op"], "dump");
    assert_eq!(end["details"]["documents"], "2");
    assert_eq!(end["details"]["target"], "shop");

    // Send the chunks back.
    let restore = |items: Vec<LogicalRestoreRequest>| {
        let mut svc = svc.clone();
        let auth = auth.clone();
        async move {
            let (tx, rx) = mpsc::channel(8);
            for i in items {
                tx.send(i).await.unwrap();
            }
            drop(tx);
            svc.logical_restore(authed(ReceiverStream::new(rx), &auth))
                .await
        }
    };
    let options = LogicalRestoreRequest {
        item: Some(logical_restore_request::Item::Options(PbOptions {
            drop_existing: true,
            ..PbOptions::default()
        })),
    };
    let chunk = |c: &rustegon_proto::v1::DumpChunk| LogicalRestoreRequest {
        item: Some(logical_restore_request::Item::Chunk(c.clone())),
    };
    let mut requests = vec![options.clone()];
    requests.extend(chunks.iter().map(chunk));
    let summary = restore(requests).await.unwrap().into_inner();
    assert_eq!(summary.collections[0].documents, 2);
    let seen: Vec<String> = backend
        .received
        .lock()
        .unwrap()
        .iter()
        .map(|c| c.path.clone())
        .collect();
    assert_eq!(
        seen,
        chunks.iter().map(|c| c.path.clone()).collect::<Vec<_>>()
    );

    // Malformed streams: chunk first, interleaved files, unfinished file, path traversal.
    let err = restore(vec![chunk(&chunks[0])]).await.unwrap_err();
    assert_eq!(code_of(&err), 1001, "{err:?}");
    for bad in [
        vec![chunks[1].clone(), chunks[0].clone()],
        vec![chunks[1].clone()],
        vec![rustegon_proto::v1::DumpChunk {
            path: "../escape".into(),
            data: vec![],
            end_of_file: true,
        }],
    ] {
        let mut requests = vec![options.clone()];
        requests.extend(bad.iter().map(chunk));
        let err = restore(requests).await.unwrap_err();
        assert_eq!(code_of(&err), 1001, "{err:?}");
    }
    // A bad scope is refused before the backend runs.
    let err = svc
        .dump(authed(
            DumpRequest {
                databases: vec![],
                collections: vec!["nodot".into()],
            },
            &auth,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), 1001);
    let listed = svc
        .list_snapshots(Request::new(ListSnapshotsRequest {}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&listed), 4001, "anonymous");
    h.stop().await;
}

/// TC-SEC-001 with the built-in roles of security.md §3.3: `backup_operator` may back up but
/// not restore, `restore_operator` may restore but not back up, `read` may do neither.
#[tokio::test]
async fn tc_sec_001_backup_and_restore_operator_roles() {
    let dir = tempfile::tempdir().unwrap();
    let (dest, _) = seed_backup(dir.path());
    let backend = Arc::new(FakeBackend::default());
    let h = Harness::start_with_backup(base_flags(), backend).await;
    let conn = h.channel().await;
    let admin = bearer(&conn.admin_token().await);
    let users = AdminServiceClient::new(conn.channel.clone());
    let login = |name: &'static str, role: &'static str| {
        let conn = conn.clone();
        let admin = admin.clone();
        let mut users = users.clone();
        async move {
            users
                .create_user(authed(
                    CreateUserRequest {
                        name: name.into(),
                        password: Some(OTHER_PASSWORD.into()),
                        roles: vec![RoleGrant {
                            role: role.into(),
                            resource: String::new(),
                        }],
                        ..CreateUserRequest::default()
                    },
                    &admin,
                ))
                .await
                .unwrap();
            bearer(
                &conn
                    .login(name, OTHER_PASSWORD, Binding::Plus)
                    .await
                    .unwrap()
                    .session_token,
            )
        }
    };
    let backup_op = login("bob", "backup_operator").await;
    let restore_op = login("rita", "restore_operator").await;
    let reader = login("ray", "read").await;
    let mut svc = client(&conn);
    let list = |auth: &str| {
        authed(
            ListBackupsRequest {
                destination: path_text(&dest),
            },
            auth,
        )
    };
    let options = || {
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(LogicalRestoreRequest {
            item: Some(logical_restore_request::Item::Options(PbOptions {
                drop_existing: true,
                ..PbOptions::default()
            })),
        })
        .unwrap();
        ReceiverStream::new(rx)
    };
    svc.list_backups(list(&backup_op)).await.unwrap();
    let err = svc
        .logical_restore(authed(options(), &backup_op))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), 4002);
    svc.logical_restore(authed(options(), &restore_op))
        .await
        .unwrap();
    for who in [&restore_op, &reader] {
        let err = svc.list_backups(list(who)).await.unwrap_err();
        assert_eq!(code_of(&err), 4002);
    }
    let err = svc
        .logical_restore(authed(options(), &reader))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), 4002);
    assert!(h.audited("privilege_denied", "denied"));
    h.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Engine backend (M13a lane BE) and the destination allowlist (PD-082)
// ---------------------------------------------------------------------------------------------

fn shop_doc(id: i64) -> rustegon_doc::Document {
    rustegon_doc::Document::try_from_fields(vec![
        ("_id".to_owned(), rustegon_doc::Value::Int64(id)),
        (
            "v".to_owned(),
            rustegon_doc::Value::String(format!("doc-{id}")),
        ),
    ])
    .unwrap()
}

/// TC-BKP-009 through the server (FR-BKP-001, FR-BKP-004): `CreateBackup` with the engine
/// backend writes a complete, deep-verifiable backup to a local destination (plaintext warning,
/// PD-064), `ListBackups` over REST shows it, the staging directory is gone, and the offline
/// restore of it holds the source's documents.
#[tokio::test]
async fn tc_bkp_009_engine_backup_round_trip_through_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start_with_engine_backup(base_flags()).await;
    h.engine
        .create_database("shop", &rustegon_catalog::DatabaseOptions::default())
        .unwrap();
    for id in 0..50 {
        h.engine.insert("shop", "items", &shop_doc(id)).unwrap();
    }
    let conn = h.channel().await;
    let token = conn.admin_token().await;
    let auth = bearer(&token);
    let mut svc = client(&conn);
    let destination = path_text(&dir.path().join("dest"));
    let created = svc
        .create_backup(authed(
            CreateBackupRequest {
                destination: destination.clone(),
            },
            &auth,
        ))
        .await
        .unwrap()
        .into_inner();
    let backup = created.backup.unwrap();
    assert!(
        created
            .warnings
            .iter()
            .any(|w| w.kind == rustegon_backup::physical::PLAINTEXT_WARNING),
        "{:?}",
        created.warnings
    );
    assert!(backup.file_count > 0);
    let verified = svc
        .verify_backup(authed(
            VerifyBackupRequest {
                destination: destination.clone(),
                backup_id: backup.backup_id.clone(),
                deep: true,
            },
            &auth,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(verified.files_checked, backup.file_count);
    let app = router(&h.services, 64 << 20);
    let (status, body) = rest(
        &app,
        "GET",
        &format!("/api/v1/backups?destination={}", pct(&destination)),
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["backups"][0]["backupId"], backup.backup_id.as_str());
    let staging = h
        .engine_dir()
        .join(rustegon_backup::physical::BACKUP_STAGING_DIR);
    assert_eq!(std::fs::read_dir(&staging).map_or(0, Iterator::count), 0);

    let restored = dir.path().join("restored");
    let source =
        rustegon_backup::LocalDestination::open(Arc::new(StdFileSystem), dir.path().join("dest"))
            .unwrap();
    rustegon_backup::restore_data_dir(
        &(Arc::new(StdFileSystem) as Arc<dyn rustegon_sim_api::FileSystem>),
        &(Arc::new(rustegon_sim_api::SystemClock::new()) as Arc<dyn rustegon_sim_api::Clock>),
        &(Arc::new(rustegon_sim_api::OsRng) as Arc<dyn rustegon_sim_api::Rng>),
        &rustegon_backup::RestoreRequest {
            source: &source,
            id: &rustegon_backup::BackupId::parse(&backup.backup_id).unwrap(),
            data_dir: &restored,
            kind: rustegon_backup::RestoreKind::Backup,
            kek: None,
        },
    )
    .unwrap();
    let db = rustegon_engine::EmbeddedDb::open(
        Arc::new(StdFileSystem),
        &restored.join("store"),
        Arc::new(rustegon_sim_api::SystemClock::new()),
        Arc::new(rustegon_sim_api::OsRng),
    )
    .unwrap();
    for id in 0..50 {
        let d = db
            .get("shop", "items", &rustegon_doc::Value::Int64(id))
            .unwrap()
            .unwrap();
        assert_eq!(
            d.get("v"),
            Some(&rustegon_doc::Value::String(format!("doc-{id}")))
        );
    }
    drop(db);
    h.stop().await;
}

/// TC-BKP-005 over the API (FR-BKP-003, PD-083): snapshots created, listed (gRPC and REST),
/// refused when the name exists (RGN-1031) and deleted, with the engine backend; a snapshot is
/// a deep-verifiable backup under `<data_dir>/snapshots`.
#[tokio::test]
async fn tc_bkp_005_snapshots_over_grpc_and_rest_with_the_engine_backend() {
    let h = Harness::start_with_engine_backup(base_flags()).await;
    h.engine
        .create_database("shop", &rustegon_catalog::DatabaseOptions::default())
        .unwrap();
    h.engine.insert("shop", "items", &shop_doc(1)).unwrap();
    let conn = h.channel().await;
    let token = conn.admin_token().await;
    let auth = bearer(&token);
    let mut svc = client(&conn);
    let s = svc
        .create_snapshot(authed(CreateSnapshotRequest { name: "s1".into() }, &auth))
        .await
        .unwrap()
        .into_inner()
        .snapshot
        .unwrap();
    assert_eq!(s.name, "s1");
    assert!(s.file_count > 0);
    let dup = svc
        .create_snapshot(authed(CreateSnapshotRequest { name: "s1".into() }, &auth))
        .await
        .unwrap_err();
    assert_eq!(code_of(&dup), 1031, "{dup:?}");
    let app = router(&h.services, 64 << 20);
    let (status, body) = rest(
        &app,
        "POST",
        "/api/v1/snapshots",
        &token,
        Some(json!({"name": "s2"})),
    )
    .await;
    assert!((200..300).contains(&status), "{status} {body}");
    let listed = svc
        .list_snapshots(authed(ListSnapshotsRequest {}, &auth))
        .await
        .unwrap()
        .into_inner()
        .snapshots;
    let names: Vec<&str> = listed.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["s1", "s2"]);
    let (status, body) = rest(&app, "DELETE", "/api/v1/snapshots/s1", &token, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["deleted"], true);
    let (status, body) = rest(&app, "GET", "/api/v1/snapshots", &token, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["snapshots"].as_array().unwrap().len(), 1);
    assert_eq!(body["snapshots"][0]["name"], "s2");
    let deleted = svc
        .delete_snapshot(authed(DeleteSnapshotRequest { name: "s1".into() }, &auth))
        .await
        .unwrap()
        .into_inner()
        .deleted;
    assert!(!deleted);
    let snaps = rustegon_backup::LocalDestination::open(
        Arc::new(StdFileSystem),
        rustegon_backup::snapshots_dir(h.engine_dir()),
    )
    .unwrap();
    rustegon_backup::verify(
        &snaps,
        &rustegon_backup::BackupId::parse("s2").unwrap(),
        rustegon_backup::VerifyMode::Deep,
    )
    .unwrap();
    h.stop().await;
}

/// PD-082 (PD-077 owner note): a destination outside `backup.allowed_destinations` is refused
/// with RGN-4002 `destination_not_allowed` for create, list, get and verify, over gRPC and
/// REST, audited as `privilege_denied`, refused before the `backup` start record, and nothing is
/// created there.
#[tokio::test]
async fn pd_082_destinations_outside_the_allowlist_are_refused_and_audited() {
    let h = Harness::start_with_engine_backup(base_flags()).await;
    let conn = h.channel().await;
    let token = conn.admin_token().await;
    let auth = bearer(&token);
    let mut svc = client(&conn);
    let outside = common::disallowed_destination();
    let destination = path_text(&outside);
    let check = |r: Result<(), Status>, what: &str| {
        let s = r.unwrap_err();
        assert_eq!(code_of(&s), 4002, "{what}: {s:?}");
        assert_eq!(s.code(), tonic::Code::PermissionDenied, "{what}");
        assert_eq!(reason(&s), "destination_not_allowed", "{what}");
    };
    check(
        svc.create_backup(authed(
            CreateBackupRequest {
                destination: destination.clone(),
            },
            &auth,
        ))
        .await
        .map(|_| ()),
        "CreateBackup",
    );
    check(
        svc.list_backups(authed(
            ListBackupsRequest {
                destination: destination.clone(),
            },
            &auth,
        ))
        .await
        .map(|_| ()),
        "ListBackups",
    );
    check(
        svc.get_backup(authed(
            GetBackupRequest {
                destination: destination.clone(),
                backup_id: SEEDED_BACKUP_ID.into(),
            },
            &auth,
        ))
        .await
        .map(|_| ()),
        "GetBackup",
    );
    check(
        svc.verify_backup(authed(
            VerifyBackupRequest {
                destination: destination.clone(),
                backup_id: SEEDED_BACKUP_ID.into(),
                deep: false,
            },
            &auth,
        ))
        .await
        .map(|_| ()),
        "VerifyBackup",
    );
    // `..` cannot climb out of an allowed directory.
    let climbing = std::env::temp_dir().join("..").join("rustegon-not-allowed");
    check(
        svc.create_backup(authed(
            CreateBackupRequest {
                destination: path_text(&climbing),
            },
            &auth,
        ))
        .await
        .map(|_| ()),
        "CreateBackup with ..",
    );
    let app = router(&h.services, 64 << 20);
    let q = pct(&destination);
    for (method, path, body) in [
        (
            "POST",
            "/api/v1/backups".to_owned(),
            Some(json!({"destination": destination})),
        ),
        ("GET", format!("/api/v1/backups?destination={q}"), None),
        (
            "GET",
            format!("/api/v1/backups/{SEEDED_BACKUP_ID}?destination={q}"),
            None,
        ),
        (
            "POST",
            format!("/api/v1/backups/{SEEDED_BACKUP_ID}/verify"),
            Some(json!({"destination": destination})),
        ),
    ] {
        let (status, body) = rest(&app, method, &path, &token, body).await;
        assert_eq!(status, 403, "{method} {path}: {body}");
        assert_eq!(body["error"]["code"], 4002, "{method} {path}");
        assert_eq!(
            body["error"]["details"]["reason"],
            "destination_not_allowed"
        );
    }
    assert!(!outside.exists(), "nothing created outside the allowlist");
    let denied: Vec<Json> = audit_of(&h, "privilege_denied")
        .into_iter()
        .filter(|l| l["details"]["reason"] == "destination_not_allowed")
        .collect();
    assert!(denied.len() >= 9, "{denied:?}");
    assert!(
        audit_of(&h, "backup").is_empty(),
        "refused before the start record"
    );
    h.stop().await;
}
