// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! gRPC adapter of [`crate::services::BackupService`] (backup.proto; PD-062, PD-077).
//!
//! `Dump` wraps the service's [`DumpStream`]: dropping the response stream (client cancel,
//! connection loss) drops it, which stops the backend at its next chunk. `LogicalRestore` reads
//! the options from the first request message and pumps the remaining chunks from the request
//! stream into the service's bounded channel on a separate task, so a slow import pushes back
//! on the client through HTTP/2 flow control.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use rustegon_backup::{Consistency, Encryption, HlcTimestamp, Manifest};
use rustegon_common::{Error, ErrorCode};
use rustegon_proto::v1::{
    self as pb, BackupConsistency, BackupEncryptionMode, BackupFile, BackupInfo,
    CreateBackupRequest, CreateBackupResponse, CreateSnapshotRequest, CreateSnapshotResponse,
    DeleteSnapshotRequest, DeleteSnapshotResponse, DumpRequest, DumpResponse, GetBackupRequest,
    GetBackupResponse, ListBackupsRequest, ListBackupsResponse, ListSnapshotsRequest,
    ListSnapshotsResponse, LogicalRestoreRequest, LogicalRestoreResponse, RestoredCollection,
    UnreadableBackup, VerifyBackupRequest, VerifyBackupResponse, backup_service_server,
    dump_response, logical_restore_request,
};
use tonic::{Request, Response, Status, Streaming, codegen::tokio_stream::Stream};

use super::{
    admin::unix_ms,
    convert::warning_to_proto,
    metadata::{ResponseTrailers, context_from_request, respond, status_of},
};
use crate::services::{
    RequestContext, Services,
    backup::{
        DumpChunk, DumpItem, DumpScope, DumpStream, LogicalRestoreOptions, SnapshotInfo,
        restore_channel, rfc3339_unix_ms,
    },
};

/// `rustegon.v1.BackupService` over [`Services`].
#[derive(Debug, Clone)]
pub struct BackupGrpc {
    services: Services,
}

impl BackupGrpc {
    /// Creates the adapter.
    #[must_use]
    pub fn new(services: Services) -> Self {
        Self { services }
    }

    #[allow(clippy::result_large_err)] // tonic::Status is the gRPC error type of every handler.
    fn ctx<T>(&self, request: &Request<T>) -> Result<RequestContext, Status> {
        context_from_request(request, self.services.deps())
    }
}

fn trailers(ctx: &RequestContext) -> ResponseTrailers {
    ResponseTrailers {
        causality_token: ctx.causality_token().map(str::to_owned),
    }
}

#[allow(clippy::result_large_err)] // tonic::Status is the gRPC error type of every handler.
fn reply<T>(ctx: &RequestContext, result: Result<T, Error>) -> Result<Response<T>, Status> {
    match result {
        Ok(message) => Ok(respond(message, trailers(ctx))),
        Err(e) => Err(status_of(&e, &ctx.trace_id_hex())),
    }
}

/// The wire form of an HLC timestamp.
#[must_use]
pub fn hlc_to_proto(t: HlcTimestamp) -> pb::HlcTimestamp {
    pb::HlcTimestamp {
        wall_ns: t.wall,
        logical: t.logical,
    }
}

fn consistency_to_proto(c: &Consistency) -> BackupConsistency {
    BackupConsistency {
        timestamp: Some(hlc_to_proto(c.timestamp)),
        applied_index: c.applied_index,
        applied_term: c.applied_term,
        storage_seqno: c.storage_seqno,
    }
}

/// The wire summary of a manifest.
#[must_use]
pub fn backup_info(m: &Manifest) -> BackupInfo {
    let (encryption, kek_id) = match &m.encryption {
        Encryption::Plaintext => (BackupEncryptionMode::Plaintext, None),
        Encryption::Kek { kek_id } => (BackupEncryptionMode::Kek, Some(kek_id.clone())),
    };
    BackupInfo {
        backup_id: m.backup_id.clone(),
        format_version: m.format_version,
        created_at_unix_ms: rfc3339_unix_ms(&m.created_at),
        consistency: Some(consistency_to_proto(&m.consistency)),
        source_cluster_id: m.source.cluster_id.clone(),
        source_node_id: m.source.node_id.clone(),
        source_server_version: m.source.server_version.clone(),
        encryption: encryption as i32,
        kek_id,
        file_count: m.files.len() as u64,
        total_bytes: m.total_bytes(),
    }
}

fn snapshot_msg(s: SnapshotInfo) -> pb::SnapshotInfo {
    pb::SnapshotInfo {
        name: s.name,
        created_at_unix_ms: unix_ms(s.created_at),
        consistency: Some(consistency_to_proto(&s.consistency)),
        file_count: s.file_count,
        total_bytes: s.total_bytes,
    }
}

fn chunk_to_proto(c: DumpChunk) -> pb::DumpChunk {
    pb::DumpChunk {
        path: c.path,
        data: c.data,
        end_of_file: c.end_of_file,
    }
}

fn chunk_from_proto(c: pb::DumpChunk) -> DumpChunk {
    DumpChunk {
        path: c.path,
        data: c.data,
        end_of_file: c.end_of_file,
    }
}

/// The `Dump` response stream.
pub struct DumpResponses {
    inner: DumpStream,
    trace_id: String,
}

impl Stream for DumpResponses {
    type Item = Result<DumpResponse, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_next(cx).map(|item| {
            item.map(|r| {
                r.map(|item| DumpResponse {
                    item: Some(match item {
                        DumpItem::Started(t) => dump_response::Item::Started(hlc_to_proto(t)),
                        DumpItem::Chunk(c) => dump_response::Item::Chunk(chunk_to_proto(c)),
                    }),
                })
                .map_err(|e| status_of(&e, &this.trace_id))
            })
        })
    }
}

fn malformed_stream(msg: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, msg).with_detail("field", "item")
}

#[tonic::async_trait]
impl backup_service_server::BackupService for BackupGrpc {
    type DumpStream = DumpResponses;

    async fn create_backup(
        &self,
        request: Request<CreateBackupRequest>,
    ) -> Result<Response<CreateBackupResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let result = self
            .services
            .backup()
            .create_backup(&ctx, &r.destination)
            .await
            .map(|b| CreateBackupResponse {
                backup: Some(backup_info(&b.manifest)),
                warnings: b.warnings.iter().map(warning_to_proto).collect(),
            });
        reply(&ctx, result)
    }

    async fn list_backups(
        &self,
        request: Request<ListBackupsRequest>,
    ) -> Result<Response<ListBackupsResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let trace = ctx.trace_id_hex();
        let result = self
            .services
            .backup()
            .list_backups(&ctx, &r.destination)
            .await
            .map(|l| ListBackupsResponse {
                backups: l.backups.iter().map(backup_info).collect(),
                unreadable: l
                    .unreadable
                    .iter()
                    .map(|(id, e)| UnreadableBackup {
                        backup_id: id.clone(),
                        error: Some(rustegon_proto::status::error_detail(e, &trace)),
                    })
                    .collect(),
            });
        reply(&ctx, result)
    }

    async fn get_backup(
        &self,
        request: Request<GetBackupRequest>,
    ) -> Result<Response<GetBackupResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let result = self
            .services
            .backup()
            .get_backup(&ctx, &r.destination, &r.backup_id)
            .await
            .map(|m| GetBackupResponse {
                backup: Some(backup_info(&m)),
                files: m
                    .files
                    .iter()
                    .map(|f| BackupFile {
                        path: f.path.clone(),
                        size: f.size,
                        blake3: f.blake3.clone(),
                    })
                    .collect(),
            });
        reply(&ctx, result)
    }

    async fn verify_backup(
        &self,
        request: Request<VerifyBackupRequest>,
    ) -> Result<Response<VerifyBackupResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let result = self
            .services
            .backup()
            .verify_backup(&ctx, &r.destination, &r.backup_id, r.deep)
            .await
            .map(|v| VerifyBackupResponse {
                backup: Some(backup_info(&v.manifest)),
                files_checked: v.files_checked as u64,
                bytes_hashed: v.bytes_hashed,
            });
        reply(&ctx, result)
    }

    async fn create_snapshot(
        &self,
        request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let result = self
            .services
            .backup()
            .create_snapshot(&ctx, &r.name)
            .await
            .map(|s| CreateSnapshotResponse {
                snapshot: Some(snapshot_msg(s)),
            });
        reply(&ctx, result)
    }

    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let result = self
            .services
            .backup()
            .list_snapshots(&ctx)
            .await
            .map(|list| ListSnapshotsResponse {
                snapshots: list.into_iter().map(snapshot_msg).collect(),
            });
        reply(&ctx, result)
    }

    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let r = request.into_inner();
        let result = self
            .services
            .backup()
            .delete_snapshot(&ctx, &r.name)
            .await
            .map(|deleted| DeleteSnapshotResponse { deleted });
        reply(&ctx, result)
    }

    async fn dump(
        &self,
        request: Request<DumpRequest>,
    ) -> Result<Response<Self::DumpStream>, Status> {
        let ctx = self.ctx(&request)?;
        let trace_id = ctx.trace_id_hex();
        let r = request.into_inner();
        let result = async {
            let scope = DumpScope::parse(r.databases, &r.collections)?;
            self.services.backup().dump(&ctx, scope).await
        }
        .await;
        match result {
            Ok(inner) => Ok(respond(DumpResponses { inner, trace_id }, trailers(&ctx))),
            Err(e) => Err(status_of(&e, &trace_id)),
        }
    }

    async fn logical_restore(
        &self,
        request: Request<Streaming<LogicalRestoreRequest>>,
    ) -> Result<Response<LogicalRestoreResponse>, Status> {
        let ctx = self.ctx(&request)?;
        let trace_id = ctx.trace_id_hex();
        let mut stream = request.into_inner();
        let options = match stream.message().await {
            Ok(Some(LogicalRestoreRequest {
                item: Some(logical_restore_request::Item::Options(o)),
            })) => o,
            Ok(_) => {
                return Err(status_of(
                    &malformed_stream("the first message must carry the options"),
                    &trace_id,
                ));
            }
            Err(status) => return Err(status),
        };
        let result = async {
            let options = LogicalRestoreOptions {
                drop_existing: options.drop_existing,
                scope: DumpScope::parse(options.databases, &options.collections)?,
            };
            let (tx, rx) = restore_channel();
            // The pump ends when the client finished (closing the channel ends the source), on
            // a transport error (forwarded as an error item) or when the service dropped the
            // receiver (the restore ended early).
            tokio::spawn(async move {
                loop {
                    let item = match stream.message().await {
                        Ok(None) => break,
                        Ok(Some(LogicalRestoreRequest {
                            item: Some(logical_restore_request::Item::Chunk(c)),
                        })) => Ok(chunk_from_proto(c)),
                        Ok(Some(_)) => Err(malformed_stream(
                            "every message after the first must carry a chunk",
                        )),
                        Err(status) => Err(Error::new(
                            ErrorCode::Cancelled,
                            format!("the request stream failed: {}", status.message()),
                        )),
                    };
                    let stop = item.is_err();
                    if tx.send(item).await.is_err() || stop {
                        break;
                    }
                }
            });
            self.services
                .backup()
                .logical_restore(&ctx, options, rx)
                .await
        }
        .await;
        reply(
            &ctx,
            result.map(|s| LogicalRestoreResponse {
                source_timestamp: Some(hlc_to_proto(s.source_timestamp)),
                collections: s
                    .collections
                    .into_iter()
                    .map(|c| RestoredCollection {
                        database: c.database,
                        collection: c.collection,
                        documents: c.documents,
                        indexes: c.indexes,
                    })
                    .collect(),
            }),
        )
    }
}
