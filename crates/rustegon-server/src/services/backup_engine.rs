// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The engine backend of `BackupService` (FR-BKP-001/003/007; PD-063, PD-064, PD-083; M13a
//! lane BE): online physical backups and local snapshots through
//! [`rustegon_backup::PhysicalBackups`], the logical dump and restore through
//! [`super::backup_logical`] (lane BG, PD-067, PD-084). `rustegond` installs it with
//! [`crate::services::Services::with_backup_backend`].
//!
//! The trait lives in this crate and the physical machinery in `rustegon-backup` (which cannot
//! depend on the server), so this file only adapts: it turns the executor's [`CancelToken`]
//! into the fence's cancel check and the manifests into the service's types.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use rustegon_backup::{BackupId, Destination, Manifest, PhysicalBackups};
use rustegon_common::Error;
use rustegon_engine::{EmbeddedDb, embedded::CancelCheck};

use super::{
    Warning,
    backup::{
        BackupBackend, CreatedBackup, DumpScope, DumpSink, DumpSource, DumpSummary,
        LogicalRestoreOptions, LogicalRestoreSummary, SnapshotInfo, SnapshotName, rfc3339_unix_ms,
    },
    backup_logical,
};
use crate::CancelToken;

/// The engine backend (module docs).
pub struct EngineBackupBackend {
    db: Arc<EmbeddedDb>,
    physical: PhysicalBackups,
}

impl std::fmt::Debug for EngineBackupBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineBackupBackend")
            .field("physical", &self.physical)
            .finish_non_exhaustive()
    }
}

impl EngineBackupBackend {
    /// A backend over `db`, whose physical backups and snapshots `physical` takes (built over
    /// the same store).
    #[must_use]
    pub fn new(db: Arc<EmbeddedDb>, physical: PhysicalBackups) -> Self {
        Self { db, physical }
    }
}

/// The fence polls this: a client that went away or a request past its deadline stops the
/// backup (RGN-5005).
fn cancel_check(cancel: &CancelToken) -> CancelCheck {
    let token = cancel.clone();
    Arc::new(move || token.is_cancelled())
}

fn snapshot_info(m: &Manifest) -> SnapshotInfo {
    let ms = u64::try_from(rfc3339_unix_ms(&m.created_at)).unwrap_or(0);
    SnapshotInfo {
        name: m.backup_id.clone(),
        created_at: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        consistency: m.consistency,
        file_count: m.files.len() as u64,
        total_bytes: m.total_bytes(),
    }
}

fn snapshot_id(name: &SnapshotName) -> Result<BackupId, Error> {
    // Same character rule as backup ids, so this never fails for a validated name.
    Ok(BackupId::parse(name.as_str())?)
}

impl BackupBackend for EngineBackupBackend {
    fn create_backup(
        &self,
        dest: &dyn Destination,
        cancel: &CancelToken,
    ) -> Result<CreatedBackup, Error> {
        let created = self.physical.create_backup(dest, &cancel_check(cancel))?;
        Ok(CreatedBackup {
            manifest: created.manifest,
            warnings: created
                .warnings
                .into_iter()
                .map(|w| Warning {
                    kind: w.code.to_owned(),
                    message: w.message,
                    details: std::collections::BTreeMap::new(),
                })
                .collect(),
        })
    }

    fn create_snapshot(
        &self,
        name: &SnapshotName,
        cancel: &CancelToken,
    ) -> Result<SnapshotInfo, Error> {
        let manifest = self
            .physical
            .create_snapshot(&snapshot_id(name)?, &cancel_check(cancel))?;
        Ok(snapshot_info(&manifest))
    }

    fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>, Error> {
        Ok(self
            .physical
            .list_snapshots()?
            .iter()
            .map(snapshot_info)
            .collect())
    }

    fn delete_snapshot(&self, name: &SnapshotName) -> Result<bool, Error> {
        self.physical.delete_snapshot(&snapshot_id(name)?)
    }

    fn dump(
        &self,
        scope: &DumpScope,
        sink: &mut dyn DumpSink,
        cancel: &CancelToken,
    ) -> Result<DumpSummary, Error> {
        backup_logical::dump(&self.db, scope, sink, cancel)
    }

    fn logical_restore(
        &self,
        options: &LogicalRestoreOptions,
        source: &mut dyn DumpSource,
        cancel: &CancelToken,
    ) -> Result<LogicalRestoreSummary, Error> {
        backup_logical::logical_restore(&self.db, options, source, cancel)
    }
}
