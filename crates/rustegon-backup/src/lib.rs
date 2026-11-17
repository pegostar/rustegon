// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Backup, restore and point-in-time recovery with pluggable destinations.
//!
//! M13a core (PD-062, PD-064; docs/deployment/backup-restore.md "Backup format v1"): the
//! backup format, destinations, and the file-level write / list / verify / restore that the
//! server's backup service and the offline CLI build on. Taking the consistent checkpoint
//! (PD-063), KEK handling and log bootstrap at restore live with their callers.
//!
//! # Layout at a destination (format v1)
//! ```text
//! <prefix>/backups/<id>/manifest.json     versioned JSON manifest (manifest::Manifest)
//! <prefix>/backups/<id>/lsm/…             checkpoint SSTs + its MANIFEST-*/CURRENT
//! <prefix>/backups/<id>/keys/registry.enc DEK registry (encrypted stores only)
//! <prefix>/backups/<id>/COMPLETE          written last; a backup without it does not exist
//! ```
//!
//! All I/O goes through [`rustegon_sim_api::FileSystem`] (local destination, staged directory,
//! restore target), so the crash tests run everything on the simulated file system.

pub mod bak;
pub mod dest;
pub mod error;
mod fsutil;
pub mod id;
pub mod manifest;
pub mod offline;
pub mod physical;
pub mod pitr;
pub mod policy;
pub mod restore;
pub mod settings;
pub mod url;
pub mod verify;
pub mod writer;

pub use bak::{BAK_EXTENSION, BakDestination, bak_id, bak_key, write_bak};
pub use dest::{
    Destination, ObjectReader,
    local::LocalDestination,
    s3::{S3Credentials, S3Destination, S3Io, S3Location, S3Settings},
    validate_key,
};
pub use error::{BackupError, Result};
pub use id::BackupId;
pub use manifest::{
    Consistency, Encryption, FileEntry, HlcTimestamp, MANIFEST_FORMAT_VERSION, Manifest, PitrLink,
    SourceInfo,
};
pub use offline::{
    PitrTarget, RestoreKind, RestoreReport, RestoreRequest, abandon_unswapped_restore,
    restore_data_dir, restore_data_dir_to_time,
};
pub use physical::{
    BackupWarning, CreatedPhysicalBackup, PhysicalBackups, PhysicalConfig, snapshots_dir,
};
pub use policy::{AllowedDestination, DestinationPolicy};
pub use restore::restore_files;
pub use settings::{BackupSettings, PitrSettings};
pub use url::{DestinationUrl, open_destination};
pub use verify::{
    BackupSource, ListedBackup, VerifyMode, VerifyReport, list, load_manifest, open_backup, verify,
};
pub use writer::{BackupMetadata, NewBackup, backup_prefix, write_backup};

/// Directory below the destination root that holds one directory per backup.
pub const BACKUPS_DIR: &str = "backups";
/// Manifest file name inside a backup directory.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Completion marker inside a backup directory; written last.
pub const COMPLETE_FILE: &str = "COMPLETE";
/// Relative path of the wrapped DEK registry of an encrypted store's backup.
pub const KEY_REGISTRY_FILE: &str = "keys/registry.enc";
