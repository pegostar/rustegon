// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Optimizer statistics and the v1 cost / cardinality model (query-engine.md §2 "Statistics",
//! §3 cost model, §8 plan-cache invalidation; FR-QL-001 optimizer inputs, FR-IDX-004 usage).
//!
//! M3 wave 2 lane G delivers standalone building blocks the cost-based optimizer plugs in
//! (wave 3); nothing here depends on the planner's types:
//! - [`hll`]: `HyperLogLog` distinct-value sketch (mergeable, serializable);
//! - [`histogram`]: equi-depth histogram (64 buckets) over the §2.1 total order;
//! - [`model`]: [`CollectionStats`] / [`FieldStats`] and the "changed > 20 %" signal;
//! - [`collect`]: [`StatsCollector`], the per-document accumulator of the stats job (full scan
//!   or seeded reservoir sample); the transactional driver lives with the caller
//!   (`rustegon-sim::EmbeddedDb::analyze` until the jobs framework exists);
//! - [`codec`]: the persisted stats record (*stats format 1*, system key `0x02 't'`);
//! - [`estimate`]: selectivity of a small predicate description ([`Predicate`]);
//! - [`cost`]: the §3 cost formula with `query.cost.*` constants ([`CostConfig`]);
//! - [`usage`]: in-memory per-index usage counters (FR-IDX-004).
//!
//! **Values are compared as key-encoded bytes** (data-model.md §3.1) everywhere: histogram
//! bounds, MCV values and HLL hash input are `keyenc` elements. The byte order *is* the §2.1
//! total order (frozen at M2 exit), so ordering needs a `memcmp` instead of a type dispatch,
//! numerically equal values (`1`, `1.0`, `1.00`) collapse to one value exactly as `=` and the
//! indexes treat them, the bounds are directly comparable with index keys built by the same
//! encoder, and the persisted form is plain bytes without a second value codec.
//!
//! Layouts and estimator rules not fixed by query-engine.md are *Provisional (PD pending)*; they
//! are documented in query-engine.md §2.1.

pub mod codec;
pub mod collect;
pub mod cost;
pub mod estimate;
pub mod histogram;
pub mod hll;
pub mod model;
pub mod usage;

pub use self::{
    codec::{STATS_FORMAT, decode_stats, encode_stats, stats_key, stats_prefix},
    collect::{StatsCollector, StatsConfig},
    cost::{CostConfig, CostInputs},
    estimate::{Predicate, Selectivity, damped_and, estimate_rows, selectivity},
    histogram::Histogram,
    hll::HyperLogLog,
    model::{
        ARRAY_LENGTH_BOUNDS, CollectionStats, FieldStats, IndexSize, McvEntry,
        STATS_CHANGE_THRESHOLD, significant_change,
    },
    usage::{IndexAccess, IndexUsage, IndexUsageRegistry},
};

/// `u64` → `f64` for ratios and estimates. Counts above 2^53 lose low bits, which is
/// irrelevant for statistics (a relative error below 1e-15).
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub(crate) fn to_f64(v: u64) -> f64 {
    v as f64
}

/// `f64` → `u64`, rounded, saturating; NaN and negatives give 0. Used for estimates only.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[must_use]
pub(crate) fn to_u64(v: f64) -> u64 {
    if v.is_nan() || v <= 0.0 {
        0
    } else {
        // `as` saturates for values above u64::MAX.
        v.round() as u64
    }
}

/// Clamps a fraction to `[0, 1]` (NaN → 0).
#[must_use]
pub(crate) fn clamp01(v: f64) -> f64 {
    if v.is_nan() { 0.0 } else { v.clamp(0.0, 1.0) }
}
