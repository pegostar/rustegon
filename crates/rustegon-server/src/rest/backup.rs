// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST adapter of [`crate::services::BackupService`] (protocol.md §4 "backup"; FR-BKP-001/003/
//! 004/006, PD-062, PD-077): backups at a destination and local snapshots.
//!
//! The streaming RPCs `Dump` and `LogicalRestore` have no REST form in M13a: a dump is a set of
//! files of any size, which the CLI writes to disk over gRPC (PD-077). The whole-node restore
//! from a backup is online (`POST /backups/{id}/restore`, `GET /restore-status`, ADR-037);
//! snapshot, point-in-time and new-data-directory restores are offline CLI operations and have
//! no endpoint (PD-062); `POST /restores` of protocol.md §4 is the M13b cluster restore.
//!
//! HLC wall times are nanoseconds since the epoch, beyond the integers a JavaScript number holds
//! exactly, so they travel as decimal strings (`wallNs`).

use axum::extract::State;
use rustegon_backup::{Consistency, Encryption, HlcTimestamp, Manifest};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    ApiError, Ctx, ErrorBody, ErrorInfo, JsonBody, Reply, RestState,
    extract::{PathParams, QueryParams},
    wire::{WarningJson, unix_ms, warnings_out},
};
use crate::services::backup::{RestoreOutcome, SnapshotInfo, rfc3339_unix_ms};

/// Routes of this module.
pub(super) fn routes() -> OpenApiRouter<RestState> {
    OpenApiRouter::new()
        .routes(routes!(list_backups, create_backup))
        .routes(routes!(get_backup))
        .routes(routes!(verify_backup))
        .routes(routes!(restore_backup))
        .routes(routes!(restore_status))
        .routes(routes!(list_snapshots, create_snapshot))
        .routes(routes!(delete_snapshot))
}

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

/// An HLC timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HlcJson {
    /// Physical component: nanoseconds since the Unix epoch, as a decimal string.
    pub wall_ns: String,
    /// Logical component.
    pub logical: u32,
}

fn hlc_out(t: HlcTimestamp) -> HlcJson {
    HlcJson {
        wall_ns: t.wall.to_string(),
        logical: t.logical,
    }
}

/// The consistency point of a backup or snapshot (PD-063).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsistencyJson {
    /// Consistency timestamp T.
    pub timestamp: HlcJson,
    /// Last applied Raft log index in the image.
    pub applied_index: u64,
    /// Term of `appliedIndex`.
    pub applied_term: u64,
    /// Every storage write with a sequence number up to this one is in the image.
    pub storage_seqno: u64,
}

fn consistency_out(c: &Consistency) -> ConsistencyJson {
    ConsistencyJson {
        timestamp: hlc_out(c.timestamp),
        applied_index: c.applied_index,
        applied_term: c.applied_term,
        storage_seqno: c.storage_seqno,
    }
}

/// Encryption scope of a backup (PD-064).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackupEncryptionName {
    /// Plaintext backup of a plaintext store.
    Plaintext,
    /// Files encrypted as in the store; the DEK registry is wrapped by `kekId`.
    Kek,
}

/// Summary of one complete backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupJson {
    /// Backup id.
    pub backup_id: String,
    /// Manifest format version.
    pub format_version: u32,
    /// Creation time (Unix ms).
    pub created_at_unix_ms: i64,
    /// Consistency point.
    pub consistency: ConsistencyJson,
    /// Cluster id of the source.
    pub source_cluster_id: String,
    /// Node id of the source.
    pub source_node_id: String,
    /// Version of the server that took the backup.
    pub source_server_version: String,
    /// Encryption scope.
    pub encryption: BackupEncryptionName,
    /// KEK needed to restore (`kek` encryption only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek_id: Option<String>,
    /// Number of files.
    pub file_count: u64,
    /// Total size of the files (bytes).
    pub total_bytes: u64,
}

fn backup_out(m: &Manifest) -> BackupJson {
    let (encryption, kek_id) = match &m.encryption {
        Encryption::Plaintext => (BackupEncryptionName::Plaintext, None),
        Encryption::Kek { kek_id } => (BackupEncryptionName::Kek, Some(kek_id.clone())),
    };
    BackupJson {
        backup_id: m.backup_id.clone(),
        format_version: m.format_version,
        created_at_unix_ms: rfc3339_unix_ms(&m.created_at),
        consistency: consistency_out(&m.consistency),
        source_cluster_id: m.source.cluster_id.clone(),
        source_node_id: m.source.node_id.clone(),
        source_server_version: m.source.server_version.clone(),
        encryption,
        kek_id,
        file_count: m.files.len() as u64,
        total_bytes: m.total_bytes(),
    }
}

/// One file of a backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BackupFileJson {
    /// Path relative to the backup directory.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// BLAKE3 hash (64 lowercase hex digits).
    pub blake3: String,
}

/// A complete backup whose manifest cannot be used.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnreadableBackupJson {
    /// Backup id.
    pub backup_id: String,
    /// Why (the error body of protocol.md §7).
    pub error: ErrorInfo,
}

/// Query parameters naming a destination.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct DestinationQuery {
    /// Destination: absolute path on the server, `file://…` or `s3://…` URL.
    pub destination: String,
}

/// `GET /backups` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BackupList {
    /// Complete backups, oldest first.
    pub backups: Vec<BackupJson>,
    /// Complete backups whose manifest cannot be used.
    pub unreadable: Vec<UnreadableBackupJson>,
}

/// `POST /backups` body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateBackupRequest {
    /// Destination: absolute path on the server, `file://…` or `s3://…` URL.
    pub destination: String,
}

/// `POST /backups` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateBackupResponse {
    /// The written backup.
    pub backup: BackupJson,
    /// Non-fatal conditions.
    pub warnings: Vec<WarningJson>,
}

/// `GET /backups/{backup_id}` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BackupResponse {
    /// The backup.
    pub backup: BackupJson,
    /// Its files, sorted by path.
    pub files: Vec<BackupFileJson>,
}

/// `POST /backups/{backup_id}/verify` body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyBackupRequest {
    /// Destination of the backup.
    pub destination: String,
    /// Also read every file and compare its BLAKE3 hash.
    #[serde(default)]
    pub deep: bool,
}

/// `POST /backups/{backup_id}/verify` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyBackupResponse {
    /// The verified backup.
    pub backup: BackupJson,
    /// Files checked.
    pub files_checked: u64,
    /// Bytes read and hashed (0 for a shallow verification).
    pub bytes_hashed: u64,
}

/// `POST /backups/{backup_id}/restore` body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreBackupRequest {
    /// Destination of the backup.
    pub destination: String,
}

/// `POST /backups/{backup_id}/restore` response: the restore is scheduled and the node stops
/// serving right after it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RestoreBackupResponse {
    /// The verified backup that will be restored.
    pub backup: BackupJson,
}

/// How the last online restore ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RestoreStateJson {
    /// This node never ran an online restore.
    None,
    /// Restored; the node serves the backup.
    Completed,
    /// Failed before its swap; the node serves its previous store, unchanged.
    Failed,
}

/// `GET /restore-status` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RestoreStatusResponse {
    /// Outcome of the last online restore.
    pub state: RestoreStateJson,
    /// The restored (or failed) backup; absent for `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
    /// When the restore ended (Unix ms); absent for `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
    /// Why it failed (`failed` only; the error body of protocol.md §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    /// Directory name, in the data directory, of the store the restore replaced (`completed`
    /// only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_store: Option<String>,
}

/// A local snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotJson {
    /// Name.
    pub name: String,
    /// Creation time (Unix ms).
    pub created_at_unix_ms: i64,
    /// Consistency point.
    pub consistency: ConsistencyJson,
    /// Number of files.
    pub file_count: u64,
    /// Total size of the files (bytes, shared with the store through hard links).
    pub total_bytes: u64,
}

fn snapshot_out(s: &SnapshotInfo) -> SnapshotJson {
    SnapshotJson {
        name: s.name.clone(),
        created_at_unix_ms: unix_ms(s.created_at),
        consistency: consistency_out(&s.consistency),
        file_count: s.file_count,
        total_bytes: s.total_bytes,
    }
}

/// `GET /snapshots` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapshotList {
    /// Snapshots by name.
    pub snapshots: Vec<SnapshotJson>,
}

/// `POST /snapshots` body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateSnapshotRequest {
    /// Name: 1 to 64 characters `[A-Za-z0-9._-]`, not starting with `.`.
    pub name: String,
}

/// `{snapshot}` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapshotResponse {
    /// The snapshot.
    pub snapshot: SnapshotJson,
}

/// `DELETE /snapshots/{name}` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeleteSnapshotResponse {
    /// False when no snapshot of that name existed.
    pub deleted: bool,
}

// ---------------------------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------------------------

/// The complete backups at a destination (`BackupService.ListBackups`; `backup`).
#[utoipa::path(
    get,
    path = "/api/v1/backups",
    tag = "backup",
    operation_id = "listBackups",
    params(DestinationQuery),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Backups.", body = BackupList))
)]
async fn list_backups(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    QueryParams(q): QueryParams<DestinationQuery>,
) -> Result<Reply<BackupList>, ApiError> {
    let listing = state
        .services
        .backup()
        .list_backups(&ctx, &q.destination)
        .await
        .map_err(ApiError::on(&ctx))?;
    let trace = ctx.trace_id_hex();
    Ok(Reply::passthrough(
        BackupList {
            backups: listing.backups.iter().map(backup_out).collect(),
            unreadable: listing
                .unreadable
                .iter()
                .map(|(id, e)| UnreadableBackupJson {
                    backup_id: id.clone(),
                    error: ErrorBody::of(e, &trace).error,
                })
                .collect(),
        },
        &ctx,
    ))
}

/// Takes an online backup of the node (`BackupService.CreateBackup`; `backup`).
#[utoipa::path(
    post,
    path = "/api/v1/backups",
    tag = "backup",
    operation_id = "createBackup",
    request_body = CreateBackupRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The written backup.", body = CreateBackupResponse))
)]
async fn create_backup(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    JsonBody(body): JsonBody<CreateBackupRequest>,
) -> Result<Reply<CreateBackupResponse>, ApiError> {
    let created = state
        .services
        .backup()
        .create_backup(&ctx, &body.destination)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        CreateBackupResponse {
            backup: backup_out(&created.manifest),
            warnings: warnings_out(&created.warnings),
        },
        &ctx,
    ))
}

/// One complete backup (`BackupService.GetBackup`; `backup`).
#[utoipa::path(
    get,
    path = "/api/v1/backups/{backup_id}",
    tag = "backup",
    operation_id = "getBackup",
    params(("backup_id" = String, Path, description = "Backup id."), DestinationQuery),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The backup and its files.", body = BackupResponse))
)]
async fn get_backup(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(backup_id): PathParams<String>,
    QueryParams(q): QueryParams<DestinationQuery>,
) -> Result<Reply<BackupResponse>, ApiError> {
    let manifest = state
        .services
        .backup()
        .get_backup(&ctx, &q.destination, &backup_id)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        BackupResponse {
            backup: backup_out(&manifest),
            files: manifest
                .files
                .iter()
                .map(|f| BackupFileJson {
                    path: f.path.clone(),
                    size: f.size,
                    blake3: f.blake3.clone(),
                })
                .collect(),
        },
        &ctx,
    ))
}

/// Verifies a backup (`BackupService.VerifyBackup`; `backup`). A failed verification is
/// RGN-5002.
#[utoipa::path(
    post,
    path = "/api/v1/backups/{backup_id}/verify",
    tag = "backup",
    operation_id = "verifyBackup",
    params(("backup_id" = String, Path, description = "Backup id.")),
    request_body = VerifyBackupRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The verified backup.", body = VerifyBackupResponse))
)]
async fn verify_backup(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(backup_id): PathParams<String>,
    JsonBody(body): JsonBody<VerifyBackupRequest>,
) -> Result<Reply<VerifyBackupResponse>, ApiError> {
    let report = state
        .services
        .backup()
        .verify_backup(&ctx, &body.destination, &backup_id, body.deep)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        VerifyBackupResponse {
            backup: backup_out(&report.manifest),
            files_checked: report.files_checked as u64,
            bytes_hashed: report.bytes_hashed,
        },
        &ctx,
    ))
}

/// Restores the whole node from a backup, online (`BackupService.RestoreBackup`; `restore`;
/// ADR-037). The backup is deep-verified first; then the node stops serving, replaces its store
/// with the backup's image (keeping the replaced one) and serves again. Every database, user and
/// role comes from the backup, so sessions end. The response arrives before the node stops;
/// `GET /api/v1/restore-status` reports how the restore ended.
#[utoipa::path(
    post,
    path = "/api/v1/backups/{backup_id}/restore",
    tag = "backup",
    operation_id = "restoreBackup",
    params(("backup_id" = String, Path, description = "Backup id.")),
    request_body = RestoreBackupRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The restore is scheduled.", body = RestoreBackupResponse))
)]
async fn restore_backup(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(backup_id): PathParams<String>,
    JsonBody(body): JsonBody<RestoreBackupRequest>,
) -> Result<Reply<RestoreBackupResponse>, ApiError> {
    let manifest = state
        .services
        .backup()
        .restore_backup(&ctx, &body.destination, &backup_id)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        RestoreBackupResponse {
            backup: backup_out(&manifest),
        },
        &ctx,
    ))
}

/// The outcome of the last online restore of this node (`BackupService.GetRestoreStatus`;
/// `backup`; ADR-037).
#[utoipa::path(
    get,
    path = "/api/v1/restore-status",
    tag = "backup",
    operation_id = "getRestoreStatus",
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The last online restore.", body = RestoreStatusResponse))
)]
async fn restore_status(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
) -> Result<Reply<RestoreStatusResponse>, ApiError> {
    let outcome = state
        .services
        .backup()
        .restore_status(&ctx)
        .await
        .map_err(ApiError::on(&ctx))?;
    let trace = ctx.trace_id_hex();
    let response = match outcome {
        RestoreOutcome::None => RestoreStatusResponse {
            state: RestoreStateJson::None,
            backup_id: None,
            finished_at: None,
            error: None,
            previous_store: None,
        },
        RestoreOutcome::Completed {
            backup_id,
            finished_at_unix_ms,
            previous_store,
        } => RestoreStatusResponse {
            state: RestoreStateJson::Completed,
            backup_id: Some(backup_id),
            finished_at: Some(finished_at_unix_ms),
            error: None,
            previous_store: Some(previous_store),
        },
        RestoreOutcome::Failed {
            backup_id,
            finished_at_unix_ms,
            error,
        } => RestoreStatusResponse {
            state: RestoreStateJson::Failed,
            backup_id: Some(backup_id),
            finished_at: Some(finished_at_unix_ms),
            error: Some(ErrorBody::of(&error, &trace).error),
            previous_store: None,
        },
    };
    Ok(Reply::passthrough(response, &ctx))
}

// ---------------------------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------------------------

/// The node's local snapshots (`BackupService.ListSnapshots`; `backup`).
#[utoipa::path(
    get,
    path = "/api/v1/snapshots",
    tag = "backup",
    operation_id = "listSnapshots",
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Snapshots.", body = SnapshotList))
)]
async fn list_snapshots(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
) -> Result<Reply<SnapshotList>, ApiError> {
    let list = state
        .services
        .backup()
        .list_snapshots(&ctx)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        SnapshotList {
            snapshots: list.iter().map(snapshot_out).collect(),
        },
        &ctx,
    ))
}

/// Creates a local snapshot (`BackupService.CreateSnapshot`; `backup`).
#[utoipa::path(
    post,
    path = "/api/v1/snapshots",
    tag = "backup",
    operation_id = "createSnapshot",
    request_body = CreateSnapshotRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The snapshot.", body = SnapshotResponse))
)]
async fn create_snapshot(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    JsonBody(body): JsonBody<CreateSnapshotRequest>,
) -> Result<Reply<SnapshotResponse>, ApiError> {
    let snapshot = state
        .services
        .backup()
        .create_snapshot(&ctx, &body.name)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        SnapshotResponse {
            snapshot: snapshot_out(&snapshot),
        },
        &ctx,
    ))
}

/// Deletes a local snapshot (`BackupService.DeleteSnapshot`; `backup`).
#[utoipa::path(
    delete,
    path = "/api/v1/snapshots/{name}",
    tag = "backup",
    operation_id = "deleteSnapshot",
    params(("name" = String, Path, description = "Snapshot name.")),
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Whether it existed.", body = DeleteSnapshotResponse))
)]
async fn delete_snapshot(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    PathParams(name): PathParams<String>,
) -> Result<Reply<DeleteSnapshotResponse>, ApiError> {
    let deleted = state
        .services
        .backup()
        .delete_snapshot(&ctx, &name)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(DeleteSnapshotResponse { deleted }, &ctx))
}
