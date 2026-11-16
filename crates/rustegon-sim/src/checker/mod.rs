// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! In-process Elle-style transactional consistency checker (TC-TXN-001, testing-strategy.md).
//!
//! Implements the approach of *Elle: Inferring Isolation Anomalies from Experimental
//! Observations* (Kingsbury & Alvaro, VLDB 2020) over recorded [`History`] values; pure
//! functions, no I/O.
//!
//! # Pipeline ([`check`])
//! 1. **Per-workload inference** (`list_append`, `rw_register`): from the observed reads,
//!    infer as much of each key's version order as is sound, report non-cycle anomalies
//!    (G1a, G1b, internal, lost update, …) and emit ww / wr / rw dependency edges.
//! 2. **Real-time edges** (only for [`ConsistencyModel::StrictSerializable`]): `T1 -> T2`
//!    whenever `T1` was acknowledged before `T2` started, reduced to a sparse frontier.
//! 3. **Cycle search** (`graph`): Tarjan SCC, then a shortest explaining cycle per class and
//!    component.
//! 4. **Model filter**: each anomaly is split into forbidden / allowed by
//!    [`ConsistencyModel::forbids`] (transaction-management.md §4.2).
//!
//! # Which transactions are graph nodes
//! Committed (`Ok`) transactions, plus `Info` transactions one of whose writes was observed by
//! a committed read (so they must have committed). Aborted transactions and unobserved `Info`
//! transactions are left out: an edge to a transaction that never committed would produce
//! false cycles.
//!
//! # Limits (soundness first: an edge is added only when it is implied)
//! - list-append: version order per key = the longest committed read; appends no committed
//!   read observed are unordered and produce no edges. Reads not a prefix of that order are
//!   reported (incompatible order) and contribute no edges.
//! - rw-register: a read shows only the latest value, so the version order is mostly unknown.
//!   Inferred: wr edges (unique values); the initial nil precedes every written value (rw from
//!   nil readers to all writers); and, with [`RegisterInference::WritesFollowReads`], a
//!   transaction that read `a` then wrote `b` installed `b` after `a` (ww from `a`'s writer, rw
//!   from `a`'s other readers). Edges may be transitive rather than direct successors, which
//!   preserves the rw count of a cycle and hence its class. Anything else (e.g. two blind
//!   writes) stays unordered: G0 and many G2 cases are invisible in rw-register histories,
//!   which is why TC-TXN-001 runs list-append as its primary workload.
//! - Real time: a strict-serializability violation is reported for any keys; the database
//!   guarantees real-time order only for transactions whose keys overlap
//!   (transaction-management.md §4.2), so workloads must use overlapping keys or causality
//!   tokens for real-time checks to be meaningful.

mod anomaly;
mod graph;
mod history;
mod list_append;
mod realtime;
mod rw_register;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_serial;

pub use anomaly::{Anomaly, AnomalyKind, ConsistencyModel, CycleStep, EdgeKind};
pub use history::{
    History, HistoryError, Key, Op, Outcome, RealTime, RegisterRead, Txn, TxnId, Value,
};

/// What the rw-register analysis may assume about version order (see module docs, Limits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegisterInference {
    /// Only the initial-nil ordering: sound for any database.
    InitialStateOnly,
    /// Also assume a transaction that read `a` and then wrote the same key installed its value
    /// after `a`. Holds for any database whose per-key version order is commit order and that
    /// forbids G1 (Rustegon: writes are pushed above every committed version and read, §4.1).
    #[default]
    WritesFollowReads,
}

/// Parameters of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckOptions {
    /// Model the history must satisfy.
    pub model: ConsistencyModel,
    /// Version-order assumptions for rw-register keys.
    pub register_inference: RegisterInference,
}

impl CheckOptions {
    /// Options for `model` with default inference.
    #[must_use]
    pub fn new(model: ConsistencyModel) -> Self {
        Self {
            model,
            register_inference: RegisterInference::default(),
        }
    }
}

/// Result of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// The model checked.
    pub model: ConsistencyModel,
    /// Anomalies the model forbids: the history is valid iff this is empty.
    pub forbidden: Vec<Anomaly>,
    /// Anomalies found that the model permits (e.g. write skew under SNAPSHOT).
    pub allowed: Vec<Anomaly>,
}

impl CheckReport {
    /// Returns `true` if the history satisfies the model.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.forbidden.is_empty()
    }

    /// Kinds of the forbidden anomalies, sorted and deduplicated.
    #[must_use]
    pub fn forbidden_kinds(&self) -> Vec<AnomalyKind> {
        kinds(&self.forbidden)
    }

    /// Kinds of all anomalies found (forbidden and allowed), sorted and deduplicated.
    #[must_use]
    pub fn all_kinds(&self) -> Vec<AnomalyKind> {
        let mut all = kinds(&self.forbidden);
        all.extend(kinds(&self.allowed));
        all.sort_unstable();
        all.dedup();
        all
    }
}

fn kinds(anomalies: &[Anomaly]) -> Vec<AnomalyKind> {
    let mut k: Vec<_> = anomalies.iter().map(Anomaly::kind).collect();
    k.sort_unstable();
    k.dedup();
    k
}

/// Checks `history` against `options.model`.
///
/// # Errors
/// [`HistoryError`] if the history is malformed (see [`History::validate`]).
pub fn check(history: &History, options: &CheckOptions) -> Result<CheckReport, HistoryError> {
    history.validate()?;
    let n = history.txns.len();
    let mut c = Collector::new(n);
    list_append::analyze(history, &mut c);
    rw_register::analyze(history, options.register_inference, &mut c);

    let in_graph: Vec<bool> = history
        .txns
        .iter()
        .zip(&c.observed)
        .map(|(t, &seen)| match t.outcome {
            Outcome::Ok => true,
            Outcome::Info => seen,
            Outcome::Fail => false,
        })
        .collect();
    let mut edges = c.edges;
    edges.retain(|&(u, v, _)| u != v && in_graph[u] && in_graph[v]);
    let real_time = options.model.uses_real_time();
    if real_time {
        edges.extend(realtime::edges(history, &in_graph));
    }
    let g = graph::Graph::new(n, edges);

    let mut anomalies = c.anomalies;
    for cycle in graph::find_cycles(&g, real_time) {
        let steps = cycle
            .steps
            .iter()
            .map(|&(u, v, edge)| CycleStep {
                from: history.txns[u].id,
                to: history.txns[v].id,
                edge,
            })
            .collect();
        anomalies.push(Anomaly::Cycle {
            kind: cycle.kind,
            steps,
        });
    }
    let (forbidden, allowed) = anomalies
        .into_iter()
        .partition(|a| options.model.forbids(a.kind()));
    Ok(CheckReport {
        model: options.model,
        forbidden,
        allowed,
    })
}

/// Shared output of the per-workload analyses.
pub(super) struct Collector {
    /// Non-cycle anomalies found so far.
    pub anomalies: Vec<Anomaly>,
    /// Dependency edges `(from, to, kind bits)` over transaction indices.
    pub edges: Vec<(usize, usize, u8)>,
    /// `observed[i]`: a committed read saw a write of transaction `i`.
    pub observed: Vec<bool>,
}

impl Collector {
    fn new(n: usize) -> Self {
        Self {
            anomalies: Vec::new(),
            edges: Vec::new(),
            observed: vec![false; n],
        }
    }
}
