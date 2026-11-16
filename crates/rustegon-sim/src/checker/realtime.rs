// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Real-time precedence edges for strict serializability.
//!
//! `T1 -> T2` holds when `T1` was acknowledged (`end`) strictly before `T2` was invoked
//! (`start`). The full relation has `O(n^2)` pairs, so — as in Elle — only a transitive
//! reduction is emitted: sweep start/end events in time order keeping a *frontier* of completed
//! transactions not yet known to precede another completed one. On `T2`'s start an edge from
//! every frontier member is added; on `T1`'s end, members that ended before `T1` started are
//! dropped (they reach every later transaction through `T1`, which they precede) and `T1`
//! joins. Reachability in the reduced graph equals the full relation; the frontier only holds
//! mutually concurrent transactions, so its size is bounded by the workload's concurrency.

use super::graph::RT;
use super::history::{History, Outcome};

/// Event order at equal timestamps: starts before ends, because `end == start` is concurrency,
/// not precedence.
const START: u8 = 0;
const END: u8 = 1;

/// Returns the reduced real-time edges among transactions with `in_graph[i]`.
pub(super) fn edges(history: &History, in_graph: &[bool]) -> Vec<(usize, usize, u8)> {
    let mut events = Vec::new();
    for (i, t) in history.txns.iter().enumerate() {
        let Some(time) = t.time else { continue };
        if !in_graph[i] {
            continue;
        }
        events.push((time.start, START, i));
        // Only acknowledged commits have a known completion; an Info transaction may take
        // effect after the client gave up.
        if let (Outcome::Ok, Some(end)) = (t.outcome, time.end) {
            events.push((end, END, i));
        }
    }
    events.sort_unstable();
    let mut frontier: Vec<(u64, usize)> = Vec::new(); // (end, txn)
    let mut out = Vec::new();
    for (at, kind, i) in events {
        if kind == START {
            out.extend(frontier.iter().map(|&(_, f)| (f, i, RT)));
        } else {
            let start = history.txns[i].time.map_or(at, |t| t.start);
            frontier.retain(|&(end, _)| end >= start);
            frontier.push((at, i));
        }
    }
    out
}
