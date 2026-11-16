// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Leveled compaction with dynamic level sizing (storage-engine.md §3).
//!
//! - `picker`: per-level targets and the score-based choice of the next compaction;
//! - `job`: running a compaction (merge, version resolution, merge operators, compaction
//!   filter, output split) and installing it through the MANIFEST.
//!
//! Scheduling (background threads running jobs, rate limiting) is the caller's job; this module
//! holds no locks. Callers serialise [`pick_compaction`] and [`install_compaction`] on the
//! `VersionSet` and pass the inputs of running jobs as `busy`. The one exception is inside a
//! job: a compaction is split into subcompactions that [`run_compaction`] runs on scoped
//! threads of its own (`picker.rs`, `job.rs`; NFR-PERF-005).

mod job;
mod picker;

pub use job::{CompactionOutput, delete_obsolete_files, install_compaction, run_compaction};
pub use picker::{
    Compaction, LevelTargets, level_targets, pick_compaction, subcompaction_boundaries,
};

use crate::{settings::StorageSettings, sst::SstWriterOptions};

/// L0 file count that triggers an L0 compaction (§3: "≤ 4 before compaction").
pub const DEFAULT_L0_TRIGGER: usize = 4;
/// Base level target: 256 MiB (§3, "L1 target 256 MiB").
pub const DEFAULT_LEVEL_BASE_BYTES: u64 = 256 << 20;
/// Size ratio between adjacent levels (§3, fanout 10).
pub const DEFAULT_LEVEL_MULTIPLIER: u64 = 10;
/// Output file target at L1: 64 MiB, doubling per level (§4).
pub const DEFAULT_TARGET_FILE_SIZE: u64 = 64 << 20;
/// Largest output file target: 256 MiB (§4).
pub const DEFAULT_MAX_TARGET_FILE_SIZE: u64 = 256 << 20;

/// What a [`CompactionFilter`] wants done with a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    /// Keep the value.
    Keep,
    /// Drop the value (it becomes a tombstone unless the compaction is bottommost).
    Remove,
}

/// Hook for dropping values during compaction (MVCC GC below the GC threshold, §3 "compaction
/// filters"). Called only for the newest `Put` of a user key when it is newer than every live
/// snapshot, so it can never change a snapshot's view.
///
/// Within one sub-job the filter is consulted in ascending user-key order. A filter whose
/// decision depends on the keys before it (the MVCC GC filter: a version is garbage only if a
/// newer one of the same logical key was kept) returns a fresh instance per sub-job from
/// [`CompactionFilter::for_subcompaction`], so concurrent sub-jobs never share that state.
pub trait CompactionFilter: Send + Sync {
    /// Decides the fate of `value` stored under `user_key`, being written to `level`.
    fn filter(&self, level: usize, user_key: &[u8], value: &[u8]) -> FilterDecision;

    /// The instance one sub-job uses, created when the sub-job starts. The default `None` makes
    /// every sub-job share `self`, which is right for stateless filters.
    fn for_subcompaction(&self) -> Option<Box<dyn CompactionFilter>> {
        None
    }
}

/// Tuning of the picker and the job.
#[derive(Debug, Clone)]
pub struct CompactionOptions {
    /// L0 file count giving score 1.0.
    pub l0_trigger: usize,
    /// Upper bound of the base level target (dynamic sizing).
    pub level_base_bytes: u64,
    /// Size ratio between adjacent levels.
    pub level_multiplier: u64,
    /// Output file target at L1; doubles per level.
    pub target_file_size_base: u64,
    /// Cap of the per-level output file target.
    pub max_target_file_size: u64,
    /// Zstd level for bottommost outputs (`storage.bottommost_zstd_level`).
    pub bottommost_zstd_level: i32,
    /// Writer options for outputs; `compression` is overridden per level.
    pub writer: SstWriterOptions,
    /// Most sub-ranges an L0 → base-level compaction is split into (`storage.max_compactions`,
    /// §3; default [`default_max_subcompactions`]); 1 disables subcompactions.
    pub max_subcompactions: usize,
    /// Run subcompactions on parallel threads (production). `false` runs the same sub-jobs one
    /// after another in key order on the calling thread: the deterministic simulation needs a
    /// reproducible order of file-system operations to enumerate crash points (TC-STO-002).
    /// Both modes produce identical outputs and install them identically.
    pub parallel_subcompactions: bool,
}

/// `storage.max_compactions` default (§3): `max(2, num_cpus / 4)`.
#[must_use]
pub fn default_max_subcompactions() -> usize {
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    (cpus / 4).max(2)
}

impl Default for CompactionOptions {
    fn default() -> Self {
        Self::from_settings(&StorageSettings::default())
    }
}

impl CompactionOptions {
    /// Options from the `[storage]` settings; the level shape uses the §3 constants.
    #[must_use]
    pub fn from_settings(settings: &StorageSettings) -> Self {
        Self {
            l0_trigger: DEFAULT_L0_TRIGGER,
            level_base_bytes: DEFAULT_LEVEL_BASE_BYTES,
            level_multiplier: DEFAULT_LEVEL_MULTIPLIER,
            target_file_size_base: DEFAULT_TARGET_FILE_SIZE,
            max_target_file_size: DEFAULT_MAX_TARGET_FILE_SIZE,
            bottommost_zstd_level: settings.bottommost_zstd_level,
            writer: SstWriterOptions::from_settings(settings),
            max_subcompactions: default_max_subcompactions(),
            parallel_subcompactions: true,
        }
    }

    /// Output file target for `level` (≥ 1): `target_file_size_base · 2^(level-1)`, capped.
    #[must_use]
    pub fn target_file_size(&self, level: usize) -> u64 {
        // Doubling per level, saturating (a plain shift would silently drop high bits).
        let mut size = self.target_file_size_base;
        for _ in 1..level {
            size = size.saturating_mul(2);
        }
        size.min(self.max_target_file_size)
    }
}
