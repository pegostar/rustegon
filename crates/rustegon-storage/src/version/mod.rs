// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! LSM versions and their persistence: version edits, the MANIFEST record log, the `CURRENT`
//! pointer and the version set (storage-engine.md §2, §9, §11).
//!
//! The MANIFEST format freezes with `rsst` v1 at the end of M1 (development-phases.md §3).

mod edit;
mod files;
mod log;
mod set;

pub use edit::{FileMeta, NUM_LEVELS, VersionEdit};
pub(crate) use files::create_dir_durable;
pub use files::{FileKind, manifest_file_name, parse_file_name, sst_file_name};
pub(crate) use set::write_manifest_snapshot;
pub use set::{Version, VersionSet};
