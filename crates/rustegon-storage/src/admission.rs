// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Write-stall signals for admission control (storage-engine.md §3 "Write stalls",
//! system-overview.md §5 "Back-pressure").
//!
//! The storage engine never sleeps in the write path. Instead it derives a [`WriteCondition`]
//! from the LSM shape and publishes it in a [`WriteConditionCell`]; the node's admission control
//! (token buckets for KV writes "based on L0 file count and memtable stall signals") reads the
//! cell and throttles (`Slowdown`) or rejects (`Stop`) new writes with `RGN-5004
//! ResourceExhausted` + `retryAfterMs`. Rejecting upstream instead of blocking a writer thread
//! keeps Raft workers and the Tokio reactor responsive while compaction catches up.
//!
//! §3 thresholds (none is a ⚙ tunable, so they are constants in [`AdmissionOptions`]):
//! - **stop**: memtables full (the active one plus 3 immutable waiting for flush, i.e. the
//!   "max 4 memtables" of database-engine.md) or L0 ≥ 36 files;
//! - **slowdown**: L0 ≥ 20 files or estimated pending compaction bytes > 64 GiB.
//!
//! The functions here are pure and cost O(levels + files): the engine evaluates them when a
//! version is installed or a memtable is sealed/flushed, not per write.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::{
    compaction::{CompactionOptions, level_targets},
    version::{NUM_LEVELS, Version},
};

/// Immutable memtables at which writes stop (§3 "Immutable memtables ≤3").
pub const DEFAULT_MAX_IMMUTABLE_MEMTABLES: usize = 3;
/// L0 file count that raises the slowdown signal (§3 "L0 ≥ 20 → slowdown").
pub const DEFAULT_L0_SLOWDOWN_FILES: usize = 20;
/// L0 file count that stops writes (§3 "L0 ≥ 36 → stall").
pub const DEFAULT_L0_STOP_FILES: usize = 36;
/// Pending compaction bytes above which the slowdown signal is raised: 64 GiB (§3).
pub const DEFAULT_PENDING_COMPACTION_SLOWDOWN_BYTES: u64 = 64 << 30;

/// Last LSM level; never a compaction source, so it never contributes pending bytes.
const LAST_LEVEL: usize = NUM_LEVELS - 1;

/// Stall thresholds (§3 defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionOptions {
    /// Immutable memtables (sealed, not yet flushed) at which writes stop.
    pub max_immutable_memtables: usize,
    /// L0 file count raising [`WriteCondition::Slowdown`].
    pub l0_slowdown_files: usize,
    /// L0 file count raising [`WriteCondition::Stop`].
    pub l0_stop_files: usize,
    /// Pending compaction bytes strictly above which [`WriteCondition::Slowdown`] is raised.
    pub pending_compaction_slowdown_bytes: u64,
}

impl Default for AdmissionOptions {
    fn default() -> Self {
        Self {
            max_immutable_memtables: DEFAULT_MAX_IMMUTABLE_MEMTABLES,
            l0_slowdown_files: DEFAULT_L0_SLOWDOWN_FILES,
            l0_stop_files: DEFAULT_L0_STOP_FILES,
            pending_compaction_slowdown_bytes: DEFAULT_PENDING_COMPACTION_SLOWDOWN_BYTES,
        }
    }
}

/// Why writes are throttled or stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StallReason {
    /// Every memtable slot is in use: flush is behind.
    MemtablesFull,
    /// Too many L0 files: L0 → base compaction is behind (reads also degrade, one probe per file).
    L0Files,
    /// Too many bytes waiting for compaction below L0.
    PendingCompactionBytes,
}

/// Write admission state of one engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriteCondition {
    /// Admit writes at full rate.
    Normal,
    /// Admission control should reduce the write rate.
    Slowdown(StallReason),
    /// Admission control must reject new writes until the condition clears.
    Stop(StallReason),
}

impl WriteCondition {
    /// The reason, or `None` for [`WriteCondition::Normal`].
    #[must_use]
    pub fn reason(self) -> Option<StallReason> {
        match self {
            Self::Normal => None,
            Self::Slowdown(r) | Self::Stop(r) => Some(r),
        }
    }

    /// Dense code used by [`WriteConditionCell`]. Codes identify a condition only: they are not
    /// ordered by severity, so never compare raw codes.
    fn encode(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Slowdown(StallReason::L0Files) => 1,
            Self::Slowdown(StallReason::PendingCompactionBytes) => 2,
            Self::Slowdown(StallReason::MemtablesFull) => 3,
            Self::Stop(StallReason::MemtablesFull) => 4,
            Self::Stop(StallReason::L0Files) => 5,
            Self::Stop(StallReason::PendingCompactionBytes) => 6,
        }
    }

    fn decode(code: u8) -> Self {
        match code {
            1 => Self::Slowdown(StallReason::L0Files),
            2 => Self::Slowdown(StallReason::PendingCompactionBytes),
            3 => Self::Slowdown(StallReason::MemtablesFull),
            4 => Self::Stop(StallReason::MemtablesFull),
            5 => Self::Stop(StallReason::L0Files),
            6 => Self::Stop(StallReason::PendingCompactionBytes),
            // Only `encode` writes the cell, so any other code is 0.
            _ => Self::Normal,
        }
    }
}

/// Computes the write condition from the current version and the number of immutable memtables.
///
/// Precedence: stop reasons before slowdown reasons; memtables before L0 (a flush backlog is
/// cleared first, and it is what turns into more L0 files); L0 before pending bytes.
#[must_use]
pub fn write_condition(
    version: &Version,
    immutable_memtables: usize,
    compaction: &CompactionOptions,
    options: &AdmissionOptions,
) -> WriteCondition {
    let l0 = version.files(0).len();
    if immutable_memtables >= options.max_immutable_memtables {
        return WriteCondition::Stop(StallReason::MemtablesFull);
    }
    if l0 >= options.l0_stop_files {
        return WriteCondition::Stop(StallReason::L0Files);
    }
    if l0 >= options.l0_slowdown_files {
        return WriteCondition::Slowdown(StallReason::L0Files);
    }
    if pending_compaction_bytes(version, compaction) > options.pending_compaction_slowdown_bytes {
        return WriteCondition::Slowdown(StallReason::PendingCompactionBytes);
    }
    WriteCondition::Normal
}

/// Estimates the bytes compaction must rewrite to bring every level within its
/// [`level_targets`] target (`RocksDB`'s `EstimatedCompactionNeededBytes`).
///
/// Formula, walking `base_level..LAST_LEVEL` top-down with a carry `c` (bytes pushed down from
/// the level above, initially 0):
/// - L0 counts when it would be picked (file count ≥ `l0_trigger`, as in the picker): its
///   compaction rewrites all of L0 plus the whole base level, so `est += L0 + size(base)` and
///   `c = L0`;
/// - for each level `n`: `s = size(n) + c`; if `s > target(n)` the excess `e = s - target(n)`
///   moves to `n+1`, rewriting itself plus the overlapping part of `n+1`, estimated by the size
///   ratio: `est += e + e · size(n+1) / s`, and `c = e`; otherwise `c = 0`.
///
/// Unlike `RocksDB` the excess is counted even when `n+1` is empty (the bytes are still
/// rewritten once), so the estimate is zero exactly when no level is over target. Arithmetic is
/// in `u128` and saturates at `u64::MAX`.
#[must_use]
pub fn pending_compaction_bytes(version: &Version, compaction: &CompactionOptions) -> u64 {
    let targets = level_targets(version, compaction);
    let mut estimate: u128 = 0;
    let mut carry: u128 = 0;
    if version.files(0).len() >= compaction.l0_trigger.max(1) {
        let l0 = u128::from(version.level_size(0));
        estimate += l0 + u128::from(version.level_size(targets.base_level));
        carry = l0;
    }
    for level in targets.base_level..LAST_LEVEL {
        let size = u128::from(version.level_size(level)) + carry;
        let target = u128::from(targets.targets[level]);
        carry = 0;
        if size > target {
            let excess = size - target;
            let next = u128::from(version.level_size(level + 1));
            // `size > target ≥ 0`, so the division is safe.
            estimate += excess + excess * next / size;
            carry = excess;
        }
    }
    u64::try_from(estimate).unwrap_or(u64::MAX)
}

/// Lock-free cell the engine publishes its [`WriteCondition`] into and admission control polls.
///
/// One atomic byte: `load` never blocks and needs no async runtime. `Release`/`Acquire` order the
/// publish after the version install that caused it, so a reader that sees a cleared condition
/// also sees the version that cleared it.
#[derive(Debug, Default)]
pub struct WriteConditionCell {
    code: AtomicU8,
}

impl WriteConditionCell {
    /// A cell holding [`WriteCondition::Normal`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes `condition`, returning the previous one (callers can log transitions).
    pub fn publish(&self, condition: WriteCondition) -> WriteCondition {
        WriteCondition::decode(self.code.swap(condition.encode(), Ordering::AcqRel))
    }

    /// The last published condition.
    #[must_use]
    pub fn load(&self) -> WriteCondition {
        WriteCondition::decode(self.code.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn copts() -> CompactionOptions {
        CompactionOptions {
            l0_trigger: 4,
            level_base_bytes: 256,
            level_multiplier: 10,
            ..CompactionOptions::default()
        }
    }

    fn aopts() -> AdmissionOptions {
        AdmissionOptions {
            pending_compaction_slowdown_bytes: 10_000,
            ..AdmissionOptions::default()
        }
    }

    fn with_l0(files: usize, l0_size: u64, rest: &[(usize, u64)]) -> Version {
        let mut all: Vec<_> = (0..files).map(|_| (0, l0_size)).collect();
        all.extend_from_slice(rest);
        Version::for_test(&all)
    }

    fn severity(c: WriteCondition) -> u8 {
        match c {
            WriteCondition::Normal => 0,
            WriteCondition::Slowdown(_) => 1,
            WriteCondition::Stop(_) => 2,
        }
    }

    #[test]
    fn tc_sto_009_defaults_match_spec() {
        let o = AdmissionOptions::default();
        assert_eq!(o.max_immutable_memtables, 3);
        assert_eq!(o.l0_slowdown_files, 20);
        assert_eq!(o.l0_stop_files, 36);
        assert_eq!(o.pending_compaction_slowdown_bytes, 64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn tc_sto_009_thresholds_and_reasons() {
        let (c, a) = (copts(), aopts());
        let cond = |l0: usize, imm: usize| write_condition(&with_l0(l0, 1, &[]), imm, &c, &a);
        assert_eq!(cond(0, 0), WriteCondition::Normal);
        assert_eq!(cond(19, 2), WriteCondition::Normal);
        assert_eq!(cond(20, 0), WriteCondition::Slowdown(StallReason::L0Files));
        assert_eq!(cond(35, 0), WriteCondition::Slowdown(StallReason::L0Files));
        assert_eq!(cond(36, 0), WriteCondition::Stop(StallReason::L0Files));
        assert_eq!(cond(0, 3), WriteCondition::Stop(StallReason::MemtablesFull));
        // Memtables take precedence over L0.
        assert_eq!(
            cond(40, 3),
            WriteCondition::Stop(StallReason::MemtablesFull)
        );
        // Pending bytes: one huge stranded L1 over a small L6 (L1 target tiny).
        let v = Version::for_test(&[(1, 50_000), (6, 300)]);
        assert_eq!(
            write_condition(&v, 0, &c, &a),
            WriteCondition::Slowdown(StallReason::PendingCompactionBytes)
        );
        // L0 slowdown wins over pending bytes.
        let v = with_l0(20, 1, &[(1, 50_000), (6, 300)]);
        assert_eq!(
            write_condition(&v, 0, &c, &a),
            WriteCondition::Slowdown(StallReason::L0Files)
        );
        assert_eq!(cond(36, 0).reason(), Some(StallReason::L0Files));
        assert_eq!(cond(0, 0).reason(), None);
    }

    #[test]
    fn tc_sto_009_pending_threshold_is_strict() {
        let c = copts();
        let v = Version::for_test(&[(1, 50_000), (6, 300)]);
        let pending = pending_compaction_bytes(&v, &c);
        let at = AdmissionOptions {
            pending_compaction_slowdown_bytes: pending,
            ..AdmissionOptions::default()
        };
        assert_eq!(write_condition(&v, 0, &c, &at), WriteCondition::Normal);
        let below = AdmissionOptions {
            pending_compaction_slowdown_bytes: pending - 1,
            ..at
        };
        assert_eq!(
            write_condition(&v, 0, &c, &below),
            WriteCondition::Slowdown(StallReason::PendingCompactionBytes)
        );
    }

    #[test]
    fn tc_sto_009_pending_zero_within_target() {
        let c = copts();
        assert_eq!(pending_compaction_bytes(&Version::for_test(&[]), &c), 0);
        // Three L0 files (< trigger 4) and a last level alone: nothing to do.
        assert_eq!(
            pending_compaction_bytes(&with_l0(3, 100, &[(6, 10_000)]), &c),
            0
        );
        // Geometric shape exactly at target (L6 1_000_000 → L5 100_000 … L2 100).
        let v = Version::for_test(&[
            (2, 100),
            (3, 1_000),
            (4, 10_000),
            (5, 100_000),
            (6, 1_000_000),
        ]);
        assert_eq!(pending_compaction_bytes(&v, &c), 0);
    }

    #[test]
    fn tc_sto_009_pending_formula() {
        let c = copts();
        // L0 triggered: 4 × 10 B into base L6 (100 B) → 40 + 100; L6 is the last level.
        assert_eq!(
            pending_compaction_bytes(&with_l0(4, 10, &[(6, 100)]), &c),
            140
        );
        // L5 target = 2000 / 10 = 200; L5 = 300 → excess 100, next 2000:
        // 100 + 100 · 2000 / 300 = 100 + 666.
        let v = Version::for_test(&[(5, 300), (6, 2000)]);
        assert_eq!(pending_compaction_bytes(&v, &c), 766);
        // Excess into an empty next level still counts once.
        let v = Version::for_test(&[(1, 50), (6, 300)]);
        let t = level_targets(&v, &c);
        assert!(pending_compaction_bytes(&v, &c) >= 50 - t.targets[1]);
    }

    #[test]
    fn tc_sto_009_cell_publishes_every_condition() {
        let cell = WriteConditionCell::new();
        assert_eq!(cell.load(), WriteCondition::Normal);
        let all = [
            WriteCondition::Normal,
            WriteCondition::Slowdown(StallReason::L0Files),
            WriteCondition::Slowdown(StallReason::PendingCompactionBytes),
            WriteCondition::Slowdown(StallReason::MemtablesFull),
            WriteCondition::Stop(StallReason::MemtablesFull),
            WriteCondition::Stop(StallReason::L0Files),
            WriteCondition::Stop(StallReason::PendingCompactionBytes),
        ];
        let mut prev = WriteCondition::Normal;
        for c in all {
            assert_eq!(cell.publish(c), prev);
            assert_eq!(cell.load(), c);
            prev = c;
        }
        assert_eq!(WriteCondition::decode(200), WriteCondition::Normal);
    }

    /// Synthetic version: `l0` files of `l0_size` plus up to one file per L1..L6.
    fn arb_shape() -> impl Strategy<Value = (usize, u64, Vec<(usize, u64)>)> {
        (
            0usize..45,
            1u64..5_000,
            // One optional file per level (`for_test` files span "a".."z", so two would overlap);
            // 0 means the level is empty.
            proptest::array::uniform6(prop_oneof![Just(0u64), 1u64..2_000_000]),
        )
            .prop_map(|(l0, l0_size, sizes)| {
                let rest = (1..NUM_LEVELS).zip(sizes).filter(|&(_, s)| s > 0).collect();
                (l0, l0_size, rest)
            })
    }

    proptest! {
        /// More L0 files, bigger L0 files or more immutable memtables never improve the condition
        /// and never lower the pending-bytes estimate.
        #[test]
        fn tc_sto_009_monotonic(
            (l0, l0_size, rest) in arb_shape(),
            extra_files in 0usize..10,
            extra_size in 0u64..5_000,
            imm in 0usize..4,
            extra_imm in 0usize..2,
            slowdown_bytes in 0u64..3_000_000,
        ) {
            let c = copts();
            let a = AdmissionOptions { pending_compaction_slowdown_bytes: slowdown_bytes, ..aopts() };
            let base = with_l0(l0, l0_size, &rest);
            let worse = with_l0(l0 + extra_files, l0_size + extra_size, &rest);
            prop_assert!(pending_compaction_bytes(&worse, &c) >= pending_compaction_bytes(&base, &c));
            let before = severity(write_condition(&base, imm, &c, &a));
            prop_assert!(severity(write_condition(&worse, imm, &c, &a)) >= before);
            prop_assert!(severity(write_condition(&base, imm + extra_imm, &c, &a)) >= before);
        }

        /// The estimate is zero iff no level is over target (L0 counted by its trigger).
        #[test]
        fn tc_sto_009_pending_zero_iff_within_target((l0, l0_size, rest) in arb_shape()) {
            let c = copts();
            let v = with_l0(l0, l0_size, &rest);
            let t = level_targets(&v, &c);
            let over = l0 >= c.l0_trigger
                || (t.base_level..LAST_LEVEL).any(|n| v.level_size(n) > t.targets[n]);
            prop_assert_eq!(pending_compaction_bytes(&v, &c) > 0, over);
        }
    }
}
