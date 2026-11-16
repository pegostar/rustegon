// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The v1 cost formula (query-engine.md §3, *Provisional*; calibrated by BM-QRY-CAL in M3/M7):
//!
//! `cost = seq_pages × 1.0 + random_pages × 4.0 + rows_cpu × 0.01 + network_bytes × 0.002 +
//! rpc_count × 50`
//!
//! The constants are configuration (`query.cost.*`, [`CostConfig`]). The access-path helpers
//! below translate statistics into the formula's inputs for the two single-collection access
//! methods every plan has (query-engine.md §4); the optimizer (wave 3) composes the rest.

use super::{model::CollectionStats, to_f64};

/// `query.cost.*` settings (implementation-rules.md §5: default, range, dynamic flag). All are
/// dynamic (read per optimization), finite and `>= 0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostConfig {
    /// `query.cost.seq_page` — cost of one sequentially read page. Default 1.0.
    pub seq_page: f64,
    /// `query.cost.random_page` — cost of one randomly read page. Default 4.0.
    pub random_page: f64,
    /// `query.cost.cpu_row` — CPU cost of processing one row. Default 0.01.
    pub cpu_row: f64,
    /// `query.cost.network_byte` — cost of moving one byte between nodes. Default 0.002.
    pub network_byte: f64,
    /// `query.cost.rpc` — fixed cost of one RPC. Default 50.
    pub rpc: f64,
    /// `query.cost.page_bytes` — bytes per page when converting sizes to pages. Default
    /// 16 384 (the SST data block target, storage-engine.md §4); range `> 0`.
    /// *Provisional (PD pending)*: the formula does not define a page.
    pub page_bytes: f64,
}

impl Default for CostConfig {
    fn default() -> Self {
        Self {
            seq_page: 1.0,
            random_page: 4.0,
            cpu_row: 0.01,
            network_byte: 0.002,
            rpc: 50.0,
            page_bytes: 16_384.0,
        }
    }
}

impl CostConfig {
    /// Checks the ranges.
    ///
    /// # Errors
    /// The name of the first invalid setting.
    pub fn validate(&self) -> Result<(), String> {
        let all = [
            ("query.cost.seq_page", self.seq_page),
            ("query.cost.random_page", self.random_page),
            ("query.cost.cpu_row", self.cpu_row),
            ("query.cost.network_byte", self.network_byte),
            ("query.cost.rpc", self.rpc),
        ];
        if let Some((name, _)) = all.iter().find(|(_, v)| !v.is_finite() || *v < 0.0) {
            return Err(format!("{name} must be finite and >= 0"));
        }
        if !self.page_bytes.is_finite() || self.page_bytes <= 0.0 {
            return Err("query.cost.page_bytes must be finite and > 0".into());
        }
        Ok(())
    }

    /// The §3 formula.
    #[must_use]
    pub fn cost(&self, i: &CostInputs) -> f64 {
        i.seq_pages * self.seq_page
            + i.random_pages * self.random_page
            + i.rows_cpu * self.cpu_row
            + i.network_bytes * self.network_byte
            + i.rpc_count * self.rpc
    }

    /// Pages occupied by `bytes`.
    #[must_use]
    pub fn pages(&self, bytes: f64) -> f64 {
        (bytes / self.page_bytes).ceil().max(0.0)
    }

    /// Inputs of a full collection scan: every row is read sequentially and evaluated
    /// whatever the filter's selectivity (network terms are the distributed planner's).
    #[must_use]
    pub fn collection_scan(&self, stats: &CollectionStats) -> CostInputs {
        let rows = to_f64(stats.row_count);
        CostInputs {
            seq_pages: self.pages(to_f64(stats.total_bytes)),
            rows_cpu: rows,
            ..CostInputs::default()
        }
    }

    /// Inputs of an index scan matching a fraction `sel` of the rows. Index entries are read
    /// sequentially (entry size from the index statistics when known, else 32 bytes); without
    /// `covered`, each matching row costs one random document fetch (page) — pessimistic for
    /// clustered data, the usual v1 assumption.
    #[must_use]
    pub fn index_scan(
        &self,
        stats: &CollectionStats,
        index_id: u32,
        sel: f64,
        covered: bool,
    ) -> CostInputs {
        const DEFAULT_ENTRY_BYTES: f64 = 32.0;
        let rows = to_f64(stats.row_count) * super::clamp01(sel);
        let entry_bytes = stats
            .indexes
            .iter()
            .find(|i| i.index_id == index_id && i.entries > 0)
            .map_or(DEFAULT_ENTRY_BYTES, |i| to_f64(i.bytes) / to_f64(i.entries));
        CostInputs {
            seq_pages: self.pages(rows * entry_bytes).max(1.0),
            random_pages: if covered { 0.0 } else { rows },
            rows_cpu: rows,
            ..CostInputs::default()
        }
    }
}

/// Inputs of the cost formula (fractional: they are estimates).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct CostInputs {
    /// Sequentially read pages.
    pub seq_pages: f64,
    /// Randomly read pages.
    pub random_pages: f64,
    /// Rows processed by CPU.
    pub rows_cpu: f64,
    /// Bytes moved between nodes.
    pub network_bytes: f64,
    /// RPCs.
    pub rpc_count: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_uses_spec_defaults() {
        let c = CostConfig::default();
        assert!(c.validate().is_ok());
        let i = CostInputs {
            seq_pages: 10.0,
            random_pages: 2.0,
            rows_cpu: 1000.0,
            network_bytes: 500.0,
            rpc_count: 3.0,
        };
        // 10 + 8 + 10 + 1 + 150
        assert!((c.cost(&i) - 179.0).abs() < 1e-9);
        let bad = CostConfig { rpc: f64::NAN, ..c };
        assert!(bad.validate().is_err());
        let bad = CostConfig {
            page_bytes: 0.0,
            ..c
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn selective_index_beats_scan_and_unselective_does_not() {
        let stats = CollectionStats {
            database_id: 1,
            collection_id: 1,
            row_count: 100_000,
            total_bytes: 100_000 * 200,
            sample_rows: 100_000,
            collected_at_ms: 0,
            fields: vec![],
            indexes: vec![],
        };
        let c = CostConfig::default();
        let scan = c.cost(&c.collection_scan(&stats));
        assert!(c.cost(&c.index_scan(&stats, 7, 0.001, false)) < scan);
        assert!(c.cost(&c.index_scan(&stats, 7, 0.5, false)) > scan);
        assert!(c.cost(&c.index_scan(&stats, 7, 0.5, true)) < scan);
    }
}
