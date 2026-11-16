// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Compaction picker: dynamic level sizing and score-based selection (storage-engine.md §3).
//!
//! Dynamic level sizing (the scheme `RocksDB` calls `level_compaction_dynamic_level_bytes`): the
//! last level's target is the size of the largest level (at least `level_base_bytes`), and every
//! level above is a `level_multiplier`-th of the one below. The *base level* — where L0 compacts
//! into — is the highest level whose target still exceeds `level_base_bytes / level_multiplier`,
//! so its target lies in `(base / multiplier, base]` once the store is large and levels above it
//! stay empty. A small store therefore compacts L0 straight into the last level, and the shape
//! converges to "each level 1/multiplier of the next", which bounds space amplification at about
//! `1 + 1/(multiplier - 1)` ≈ 1.11.
//!
//! Scores are in permille: L0 = file count / `l0_trigger`, Ln = level bytes / target. The highest
//! score ≥ 1000 wins; the last level is never a compaction source.
//!
//! Concurrency rules (callers pass the files of running compactions in `busy`):
//! - at most one L0 compaction runs, and it takes *all* L0 files: taking a newer L0 file without
//!   an older overlapping one would move newer data below older data, and reads consult L0 first;
//! - a candidate is skipped when any of its inputs (including the overlapping files of the output
//!   level) is busy, so two running compactions never write overlapping key ranges to one level.
//!
//! Subcompactions (NFR-PERF-005): the single all-of-L0 compaction is the write-throughput
//! bottleneck (it cannot run concurrently with another L0 compaction, see above), so its key
//! range is split into disjoint sub-ranges compacted in parallel; Ln → Ln+1 jobs are split the
//! same way, because the L0 compaction waits for busy base-level files (PD-025) ([`subcompaction_boundaries`],
//! `job.rs`). Boundaries are user keys taken from data-block index separators, so every
//! sub-range holds about the same number of input blocks, and:
//! - a boundary is a *user* key and each sub-range is `[b_i, b_{i+1})` by user key, so all
//!   versions of a key (snapshot stripes, merge operands and their base) land in one sub-job and
//!   are resolved exactly as by a single job;
//! - no boundary `b` lies in `(start, end]` of an input range tombstone. Every tombstone then
//!   falls entirely inside one sub-range and is carried unclipped, and the sub-jobs' outputs
//!   stay disjoint by user key (L1+ invariant, `version/set.rs`): a file's upper bound for a
//!   tombstone is the user key `end` itself (`sst/writer.rs`), so a tombstone clipped at `b`
//!   would make the file touch the next sub-range's first file. This is the same rule the job
//!   applies to its own output cuts.

use std::{collections::BTreeSet, sync::Arc};

use super::CompactionOptions;
use crate::{
    range_del::RangeTombstone,
    version::{FileMeta, NUM_LEVELS, Version},
};

/// Last LSM level; never a compaction source.
const LAST_LEVEL: usize = NUM_LEVELS - 1;
/// Scores are expressed in permille; this is "exactly at target".
const SCORE_UNIT: u64 = 1000;

/// Per-level byte targets derived from the current shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelTargets {
    /// Level that L0 compacts into.
    pub base_level: usize,
    /// Target bytes per level; meaningful for `base_level..=LAST_LEVEL` (0 above the base level).
    pub targets: [u64; NUM_LEVELS],
}

/// A chosen compaction.
#[derive(Debug, Clone)]
pub struct Compaction {
    /// Source level.
    pub level: usize,
    /// Level the outputs are written to.
    pub output_level: usize,
    /// Input files as `(level, file)`.
    pub inputs: Vec<(usize, Arc<FileMeta>)>,
    /// No file below `output_level` overlaps the inputs: tombstones with nothing beneath can be
    /// dropped and merge operands can be folded into a value.
    pub bottommost: bool,
    /// Score of the source level in permille (≥ 1000 for picked compactions).
    pub score: u64,
}

/// Computes the dynamic level targets for `version`.
#[must_use]
pub fn level_targets(version: &Version, options: &CompactionOptions) -> LevelTargets {
    let base = options.level_base_bytes.max(1);
    let multiplier = options.level_multiplier.max(2);
    let largest = (1..=LAST_LEVEL)
        .map(|l| version.level_size(l))
        .max()
        .unwrap_or(0);
    let mut targets = [0; NUM_LEVELS];
    targets[LAST_LEVEL] = largest.max(base);
    let mut base_level = LAST_LEVEL;
    for level in (1..LAST_LEVEL).rev() {
        let target = targets[level + 1] / multiplier;
        if target <= base / multiplier {
            break;
        }
        targets[level] = target;
        base_level = level;
    }
    // Data stranded above the computed base level (e.g. after a large deletion shrank the last
    // level) is still compacted downwards: start at the first non-empty level and give the levels
    // in between their geometric targets.
    if let Some(first) = (1..base_level).find(|&l| !version.files(l).is_empty()) {
        for level in (first..base_level).rev() {
            targets[level] = (targets[level + 1] / multiplier).max(1);
        }
        base_level = first;
    }
    LevelTargets {
        base_level,
        targets,
    }
}

/// Picks the most urgent compaction, or `None` when every level is within target (or every
/// candidate conflicts with a running compaction in `busy`).
#[must_use]
pub fn pick_compaction(
    version: &Version,
    options: &CompactionOptions,
    busy: &BTreeSet<u64>,
) -> Option<Compaction> {
    let targets = level_targets(version, options);
    let mut scores: Vec<(u64, usize)> = Vec::new();
    let l0 = version.files(0).len() as u64;
    // Saturating: a score only needs to order levels, and wrapping would hide a huge backlog.
    scores.push((
        l0.saturating_mul(SCORE_UNIT) / options.l0_trigger.max(1) as u64,
        0,
    ));
    for level in targets.base_level..LAST_LEVEL {
        let target = targets.targets[level].max(1);
        scores.push((
            version.level_size(level).saturating_mul(SCORE_UNIT) / target,
            level,
        ));
    }
    // Highest score first; on a tie the upper level, whose backlog blocks the levels below.
    scores.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scores
        .into_iter()
        .take_while(|&(score, _)| score >= SCORE_UNIT)
        .find_map(|(score, level)| {
            if level == 0 {
                pick_l0(version, targets.base_level, busy, score)
            } else {
                pick_level(version, level, busy, score)
            }
        })
}

fn pick_l0(
    version: &Version,
    base_level: usize,
    busy: &BTreeSet<u64>,
    score: u64,
) -> Option<Compaction> {
    let l0 = version.files(0);
    if l0.iter().any(|f| busy.contains(&f.number)) {
        return None;
    }
    let (lo, hi) = user_range(l0.iter())?;
    let mut inputs: Vec<_> = l0.iter().map(|f| (0, Arc::clone(f))).collect();
    let overlap = overlapping(version, base_level, lo, hi);
    if overlap.iter().any(|f| busy.contains(&f.number)) {
        return None;
    }
    inputs.extend(overlap.into_iter().map(|f| (base_level, f)));
    Some(finish(version, 0, base_level, inputs, score))
}

/// Picks one file of `level` (L1+ files hold whole user keys, see `version/set.rs`), the one with
/// the smallest overlap ratio with the next level: it rewrites the fewest bytes per byte moved
/// down, which keeps write amplification low (`RocksDB`'s `kMinOverlappingRatio`).
fn pick_level(
    version: &Version,
    level: usize,
    busy: &BTreeSet<u64>,
    score: u64,
) -> Option<Compaction> {
    let output_level = level + 1;
    let mut best: Option<(u128, Arc<FileMeta>, Vec<Arc<FileMeta>>)> = None;
    for file in version.files(level) {
        if busy.contains(&file.number) {
            continue;
        }
        let overlap = overlapping(
            version,
            output_level,
            file.smallest.user_key(),
            file.largest.user_key(),
        );
        if overlap.iter().any(|f| busy.contains(&f.number)) {
            continue;
        }
        let overlap_bytes: u128 = overlap.iter().map(|f| u128::from(f.size)).sum();
        let ratio = overlap_bytes * u128::from(SCORE_UNIT) / u128::from(file.size.max(1));
        // Files are in key order, so `<` keeps the leftmost file on ties (deterministic).
        if best.as_ref().is_none_or(|(r, _, _)| ratio < *r) {
            best = Some((ratio, Arc::clone(file), overlap));
        }
    }
    let (_, file, overlap) = best?;
    let mut inputs = vec![(level, file)];
    inputs.extend(overlap.into_iter().map(|f| (output_level, f)));
    Some(finish(version, level, output_level, inputs, score))
}

fn finish(
    version: &Version,
    level: usize,
    output_level: usize,
    inputs: Vec<(usize, Arc<FileMeta>)>,
    score: u64,
) -> Compaction {
    let bottommost = match user_range(inputs.iter().map(|(_, f)| f)) {
        Some((lo, hi)) => {
            ((output_level + 1)..NUM_LEVELS).all(|l| overlapping(version, l, lo, hi).is_empty())
        }
        None => true,
    };
    Compaction {
        level,
        output_level,
        inputs,
        bottommost,
        score,
    }
}

/// Chooses at most `max_subcompactions - 1` boundaries splitting a compaction into disjoint
/// user-key sub-ranges `(-inf, b_1), [b_1, b_2), …, [b_n, +inf)` (module docs).
///
/// `candidates` are user keys of data-block separators of the inputs (any order, duplicates
/// allowed); `tombstones` are all range tombstones of the inputs. Candidates inside a tombstone's
/// `(start, end]` are discarded; of the rest, boundaries are taken at even quantiles, so each
/// sub-range gets about the same number of input blocks. Returns strictly increasing keys;
/// empty when no split is possible or wanted.
#[must_use]
pub fn subcompaction_boundaries(
    mut candidates: Vec<Vec<u8>>,
    tombstones: &[RangeTombstone],
    max_subcompactions: usize,
) -> Vec<Vec<u8>> {
    if max_subcompactions < 2 {
        return Vec::new();
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates.retain(|b| {
        !tombstones
            .iter()
            .any(|t| t.start.as_slice() < b.as_slice() && b.as_slice() <= t.end.as_slice())
    });
    // The smallest candidate would leave only the first block's keys below it; dropping it keeps
    // the first sub-range comparable to the others when there are few candidates.
    if candidates.len() > 1 {
        candidates.remove(0);
    }
    let parts = max_subcompactions.min(candidates.len() + 1);
    let mut out: Vec<Vec<u8>> = (1..parts)
        .map(|j| candidates[j * candidates.len() / parts].clone())
        .collect();
    out.dedup();
    out
}

/// Smallest and largest user key over `files`.
fn user_range<'a>(files: impl Iterator<Item = &'a Arc<FileMeta>>) -> Option<(&'a [u8], &'a [u8])> {
    files.fold(None, |acc, f| {
        let (lo, hi) = (f.smallest.user_key(), f.largest.user_key());
        Some(match acc {
            None => (lo, hi),
            Some((a, b)) => (a.min(lo), b.max(hi)),
        })
    })
}

/// Files of `level` whose user-key range intersects `[lo, hi]`.
fn overlapping(version: &Version, level: usize, lo: &[u8], hi: &[u8]) -> Vec<Arc<FileMeta>> {
    version
        .files(level)
        .iter()
        .filter(|f| f.smallest.user_key() <= hi && f.largest.user_key() >= lo)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> CompactionOptions {
        CompactionOptions {
            l0_trigger: 4,
            level_base_bytes: 256,
            level_multiplier: 10,
            ..CompactionOptions::default()
        }
    }

    fn version_with(sizes: &[(usize, u64)]) -> Version {
        Version::for_test(sizes)
    }

    #[test]
    fn target_file_size_doubles_and_saturates() {
        let o = CompactionOptions {
            target_file_size_base: 64,
            max_target_file_size: 256,
            ..opts()
        };
        assert_eq!(
            (1..=4).map(|l| o.target_file_size(l)).collect::<Vec<_>>(),
            [64, 128, 256, 256]
        );
        let huge = CompactionOptions {
            target_file_size_base: 1 << 62,
            max_target_file_size: u64::MAX,
            ..opts()
        };
        assert_eq!(
            huge.target_file_size(6),
            u64::MAX,
            "saturates, never wraps to 0"
        );
    }

    #[test]
    fn small_store_compacts_l0_into_last_level() {
        let t = level_targets(&version_with(&[(6, 100)]), &opts());
        assert_eq!(t.base_level, 6);
        assert_eq!(t.targets[6], 256);
    }

    #[test]
    fn large_store_derives_upper_targets_geometrically() {
        let t = level_targets(&version_with(&[(6, 1_000_000)]), &opts());
        // 1_000_000 → L5 100_000 → L4 10_000 → L3 1_000 → L2 100 (> 25) → L1 10 (≤ 25, stop).
        assert_eq!(t.base_level, 2);
        assert_eq!(t.targets[2..], [100, 1_000, 10_000, 100_000, 1_000_000]);
        let base = t.targets[t.base_level];
        assert!(base > 256 / 10 && base <= 256, "base target {base}");
    }

    #[test]
    fn stranded_upper_level_is_drained() {
        let t = level_targets(&version_with(&[(1, 50), (6, 300)]), &opts());
        assert_eq!(t.base_level, 1);
        assert!(t.targets[1] < 50, "L1 over target so it compacts down");
    }

    #[test]
    fn l0_trigger_picks_all_l0_files_into_base_level() {
        let v = version_with(&[(0, 10), (0, 10), (0, 10), (0, 10), (6, 100)]);
        let c = pick_compaction(&v, &opts(), &BTreeSet::new()).unwrap();
        assert_eq!((c.level, c.output_level), (0, 6));
        assert_eq!(c.inputs.iter().filter(|(l, _)| *l == 0).count(), 4);
        assert!(c.bottommost);
        let three_files = version_with(&[(0, 10), (0, 10), (0, 10)]);
        assert!(pick_compaction(&three_files, &opts(), &BTreeSet::new()).is_none());
    }

    #[test]
    fn busy_inputs_are_never_picked_twice() {
        let v = version_with(&[(0, 10), (0, 10), (0, 10), (0, 10), (6, 100)]);
        let c = pick_compaction(&v, &opts(), &BTreeSet::new()).unwrap();
        let busy: BTreeSet<u64> = c.inputs.iter().map(|(_, f)| f.number).collect();
        assert!(pick_compaction(&v, &opts(), &busy).is_none());
    }

    const NONE: [Vec<u8>; 0] = [];

    fn keys(names: &[&str]) -> Vec<Vec<u8>> {
        names.iter().map(|n| n.as_bytes().to_vec()).collect()
    }

    fn tomb(start: &str, end: &str) -> RangeTombstone {
        RangeTombstone {
            start: start.as_bytes().to_vec(),
            end: end.as_bytes().to_vec(),
            seqno: 1,
        }
    }

    #[test]
    fn tc_sto_004_subcompaction_boundaries_split_evenly() {
        let cands = keys(&["h", "b", "d", "f", "b", "j", "l", "n"]);
        // Sorted, deduplicated, smallest ("b") dropped: d f h j l n → 3 parts at 2/6 and 4/6.
        assert_eq!(
            subcompaction_boundaries(cands.clone(), &[], 3),
            keys(&["h", "l"])
        );
        assert_eq!(subcompaction_boundaries(cands.clone(), &[], 1), NONE);
        // More parts than candidates: every remaining candidate becomes a boundary.
        assert_eq!(
            subcompaction_boundaries(cands, &[], 64),
            keys(&["d", "f", "h", "j", "l", "n"])
        );
        assert_eq!(subcompaction_boundaries(Vec::new(), &[], 4), NONE);
    }

    #[test]
    fn tc_sto_004_subcompaction_boundaries_avoid_range_tombstones() {
        let cands = keys(&["a", "c", "e", "g", "i", "k"]);
        // [c, g) forbids e and g (g = end: the file bound would touch the next sub-range);
        // c (= start) stays allowed: the tombstone then lies wholly in the sub-range from c.
        let out = subcompaction_boundaries(cands, &[tomb("c", "g")], 64);
        assert_eq!(out, keys(&["c", "i", "k"]));
        for b in &out {
            assert!(!(b.as_slice() > b"c".as_slice() && b.as_slice() <= b"g".as_slice()));
        }
        // A tombstone over everything leaves no split at all.
        let all = subcompaction_boundaries(keys(&["b", "c", "d"]), &[tomb("a", "z")], 8);
        assert_eq!(all, NONE);
    }

    #[test]
    fn over_target_level_picks_min_overlap_file() {
        // Largest level L6 = 2000 B → L5 target 200 B = its size (score 1000). Of the two L5
        // files the second has no overlap below and must win.
        let v = Version::for_test_ranges(&[
            (5, 100, "a", "c"),
            (5, 100, "m", "p"),
            (6, 1000, "a", "d"),
            (6, 1000, "x", "z"),
        ]);
        let c = pick_compaction(&v, &opts(), &BTreeSet::new()).unwrap();
        assert_eq!((c.level, c.output_level), (5, 6));
        assert_eq!(c.inputs.len(), 1);
        assert_eq!(c.inputs[0].1.smallest.user_key(), b"m");
        assert!(c.bottommost);
    }
}
