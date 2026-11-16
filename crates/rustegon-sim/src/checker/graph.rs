// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transaction dependency graph and cycle search.
//!
//! Nodes are transaction indices into `History::txns`; an edge carries a bit mask of the
//! dependency kinds that hold between its endpoints. Anomalies are found as in Elle §5:
//! 1. restrict the graph to the edge kinds a class may use and compute its strongly connected
//!    components with Tarjan's algorithm (iterative, so 10^5-node graphs cannot overflow the
//!    stack): a cycle exists iff some component has two or more nodes (self-edges are never
//!    added);
//! 2. inside each such component, find a short cycle of the class by fixing one edge
//!    `u -> v` of the defining kind and searching the shortest path `v ~> u` with BFS over the
//!    kinds the rest of the cycle may use. Up to [`MAX_CYCLE_ATTEMPTS`] edges are tried per
//!    component and the shortest cycle is kept, which is exact for small components and keeps
//!    the cost bounded (`O(attempts * (V + E))` per component) for huge ones.
//!
//! Classes, by the multiset of edge labels on the cycle: G0 = ww only; G1c = ww/wr with at
//! least one wr; G-single = exactly one rw; G2-item = two or more rw; a cycle with an rt label
//! is the `*-realtime` variant of the class of its other labels.

use std::collections::{HashMap, HashSet, VecDeque};

use super::anomaly::{AnomalyKind, EdgeKind};

/// Edge-kind bits.
pub(super) const WW: u8 = 1;
pub(super) const WR: u8 = 2;
pub(super) const RW: u8 = 4;
pub(super) const RT: u8 = 8;
const NON_RT: u8 = WW | WR | RW;
const ALL: u8 = NON_RT | RT;

/// Edges tried per component and class; a bound on explanation effort, not on detection
/// (detection is complete through the SCC step). 32 makes the explanation exact for every
/// component of up to 32 defining edges, far beyond hand-made and typical failing histories.
const MAX_CYCLE_ATTEMPTS: usize = 32;

/// Adjacency-list dependency graph.
pub(super) struct Graph {
    adj: Vec<Vec<(usize, u8)>>,
}

impl Graph {
    /// Builds the graph from `(from, to, kind bits)` edges, merging parallel edges.
    pub(super) fn new(nodes: usize, mut edges: Vec<(usize, usize, u8)>) -> Self {
        edges.sort_unstable_by_key(|&(u, v, _)| (u, v));
        let mut adj: Vec<Vec<(usize, u8)>> = vec![Vec::new(); nodes];
        for (u, v, bits) in edges {
            if u == v {
                continue;
            }
            let list = &mut adj[u];
            match list.last_mut() {
                Some((target, mask)) if *target == v => *mask |= bits,
                _ => list.push((v, bits)),
            }
        }
        Self { adj }
    }

    fn len(&self) -> usize {
        self.adj.len()
    }

    /// Kind bits of edge `u -> v` (0 if absent). Lists are sorted by target.
    fn bits(&self, u: usize, v: usize) -> u8 {
        self.adj[u]
            .binary_search_by_key(&v, |&(t, _)| t)
            .map_or(0, |i| self.adj[u][i].1)
    }

    /// Tarjan's SCC algorithm restricted to edges with a bit in `mask`.
    ///
    /// Returns the component id of every node. Iterative version: the explicit `call` stack
    /// holds `(node, next adjacency index)` frames, replacing recursion.
    fn scc(&self, mask: u8) -> Vec<usize> {
        const UNVISITED: usize = usize::MAX;
        let n = self.len();
        let mut index = vec![UNVISITED; n];
        let mut low = vec![0; n];
        let mut on_stack = vec![false; n];
        let mut comp = vec![UNVISITED; n];
        let mut stack = Vec::new();
        // Frames `(node, next adjacency index to examine)`.
        let mut call: Vec<(usize, usize)> = Vec::new();
        let (mut next_index, mut next_comp) = (0, 0);
        for root in 0..n {
            if index[root] != UNVISITED {
                continue;
            }
            call.push((root, 0));
            while let Some(&(u, mut pos)) = call.last() {
                if index[u] == UNVISITED {
                    index[u] = next_index;
                    low[u] = next_index;
                    next_index += 1;
                    stack.push(u);
                    on_stack[u] = true;
                }
                // Advance to the next qualifying successor of `u`.
                let mut child = None;
                while pos < self.adj[u].len() {
                    let (v, bits) = self.adj[u][pos];
                    pos += 1;
                    if bits & mask == 0 {
                        continue;
                    }
                    if index[v] == UNVISITED {
                        child = Some(v);
                        break;
                    } else if on_stack[v] {
                        low[u] = low[u].min(index[v]);
                    }
                }
                if let Some(frame) = call.last_mut() {
                    frame.1 = pos;
                }
                if let Some(v) = child {
                    call.push((v, 0));
                    continue;
                }
                // All successors done: `u` roots a component iff low == index.
                call.pop();
                if low[u] == index[u] {
                    while let Some(w) = stack.pop() {
                        on_stack[w] = false;
                        comp[w] = next_comp;
                        if w == u {
                            break;
                        }
                    }
                    next_comp += 1;
                }
                if let Some(&(parent, _)) = call.last() {
                    low[parent] = low[parent].min(low[u]);
                }
            }
        }
        comp
    }
}

/// Reusable BFS scratch space; `stamp` avoids clearing `seen` between searches.
struct Bfs {
    seen: Vec<u32>,
    parent: Vec<usize>,
    stamp: u32,
    queue: VecDeque<usize>,
}

impl Bfs {
    fn new(n: usize) -> Self {
        Self {
            seen: vec![0; n],
            parent: vec![0; n],
            stamp: 0,
            queue: VecDeque::new(),
        }
    }

    /// Shortest path `from ~> to` over edges with a bit in `mask` whose endpoints are both in
    /// component `cid` of `comp`. Returns the node sequence `[from, …, to]`.
    fn path(
        &mut self,
        g: &Graph,
        (from, to): (usize, usize),
        mask: u8,
        (comp, cid): (&[usize], usize),
    ) -> Option<Vec<usize>> {
        self.stamp = self.stamp.wrapping_add(1);
        if self.stamp == 0 {
            // Stamp wrapped: reset so stale marks cannot alias the new stamp.
            self.seen.fill(0);
            self.stamp = 1;
        }
        self.queue.clear();
        self.queue.push_back(from);
        self.seen[from] = self.stamp;
        while let Some(u) = self.queue.pop_front() {
            if u == to {
                let mut path = vec![to];
                let mut cur = to;
                while cur != from {
                    cur = self.parent[cur];
                    path.push(cur);
                }
                path.reverse();
                return Some(path);
            }
            for &(v, bits) in &g.adj[u] {
                if bits & mask != 0 && comp[v] == cid && self.seen[v] != self.stamp {
                    self.seen[v] = self.stamp;
                    self.parent[v] = u;
                    self.queue.push_back(v);
                }
            }
        }
        None
    }
}

/// A cycle found by the search: its class and labelled edges (node indices).
pub(super) struct FoundCycle {
    pub kind: AnomalyKind,
    pub steps: Vec<(usize, usize, EdgeKind)>,
}

/// One search pass: SCCs over `scc_mask`, forced edge of kind `forced`, path over `path_mask`.
struct Pass {
    scc_mask: u8,
    forced: u8,
    path_mask: u8,
}

/// Finds one explaining cycle per class and component (see module docs).
///
/// With `real_time`, also searches cycles through rt edges. A component that already holds a
/// G-single cycle is not searched for G2-item: the stronger evidence suffices for every model
/// that forbids G2-item.
pub(super) fn find_cycles(g: &Graph, real_time: bool) -> Vec<FoundCycle> {
    let mut bfs = Bfs::new(g.len());
    let mut found = Vec::new();
    // G0: ww only.
    run_pass(
        g,
        &mut bfs,
        &Pass {
            scc_mask: WW,
            forced: WW,
            path_mask: WW,
        },
        &mut found,
        |_| true,
    );
    // G1c: one forced wr, rest ww/wr.
    let g1c = Pass {
        scc_mask: WW | WR,
        forced: WR,
        path_mask: WW | WR,
    };
    run_pass(g, &mut bfs, &g1c, &mut found, |_| true);
    // G-single: one forced rw, rest ww/wr; then G2-item in components without G-single.
    let comp = g.scc(NON_RT);
    let single = Pass {
        scc_mask: NON_RT,
        forced: RW,
        path_mask: WW | WR,
    };
    let before = found.len();
    run_pass(g, &mut bfs, &single, &mut found, |_| true);
    let has_single: HashSet<usize> = found[before..]
        .iter()
        .filter_map(|c| c.steps.first().map(|s| comp[s.0]))
        .collect();
    let g2 = Pass {
        scc_mask: NON_RT,
        forced: RW,
        path_mask: NON_RT,
    };
    run_pass(g, &mut bfs, &g2, &mut found, |cid| {
        !has_single.contains(&cid)
    });
    if real_time {
        let rt = Pass {
            scc_mask: ALL,
            forced: RT,
            path_mask: ALL,
        };
        run_pass(g, &mut bfs, &rt, &mut found, |_| true);
    }
    found
}

/// Runs one pass over every non-trivial component accepted by `want`.
fn run_pass(
    g: &Graph,
    bfs: &mut Bfs,
    pass: &Pass,
    found: &mut Vec<FoundCycle>,
    want: impl Fn(usize) -> bool,
) {
    let comp = g.scc(pass.scc_mask);
    // best[cid] = shortest cycle so far, attempts[cid] = forced edges tried.
    let mut best: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut attempts: HashMap<usize, usize> = HashMap::new();
    for u in 0..g.len() {
        for &(v, bits) in &g.adj[u] {
            let cid = comp[u];
            if bits & pass.forced == 0 || comp[v] != cid || !want(cid) {
                continue;
            }
            let tried = attempts.entry(cid).or_insert(0);
            if *tried >= MAX_CYCLE_ATTEMPTS {
                continue;
            }
            *tried += 1;
            // The cycle is `u -> v ~> u`; as a node list: [u, v, …, u].
            if let Some(path) = bfs.path(g, (v, u), pass.path_mask, (&comp, cid)) {
                let shorter = best.get(&cid).is_none_or(|b| path.len() + 1 < b.len());
                if shorter {
                    let mut cycle = Vec::with_capacity(path.len() + 1);
                    cycle.push(u);
                    cycle.extend(path);
                    best.insert(cid, cycle);
                }
            }
        }
    }
    let mut cycles: Vec<Vec<usize>> = best.into_values().collect();
    cycles.sort_unstable(); // deterministic report order
    for nodes in cycles {
        let steps = label(g, &nodes, pass);
        found.push(FoundCycle {
            kind: classify(&steps),
            steps,
        });
    }
}

/// Labels each edge of the closed node walk `nodes` with one kind: the first edge (the forced
/// one) with the forced kind, the others with the strongest allowed kind by preference
/// ww > wr > rw > rt, so a cycle is never classified weaker than its edges prove.
fn label(g: &Graph, nodes: &[usize], pass: &Pass) -> Vec<(usize, usize, EdgeKind)> {
    nodes
        .windows(2)
        .enumerate()
        .map(|(i, w)| {
            let allowed = if i == 0 { pass.forced } else { pass.path_mask };
            let bits = g.bits(w[0], w[1]) & allowed;
            let kind = if bits & WW != 0 {
                EdgeKind::Ww
            } else if bits & WR != 0 {
                EdgeKind::Wr
            } else if bits & RW != 0 {
                EdgeKind::Rw
            } else {
                EdgeKind::Rt
            };
            (w[0], w[1], kind)
        })
        .collect()
}

/// Classifies a labelled cycle (module docs).
fn classify(steps: &[(usize, usize, EdgeKind)]) -> AnomalyKind {
    let count = |k: EdgeKind| steps.iter().filter(|s| s.2 == k).count();
    let (wr, rw, rt) = (
        count(EdgeKind::Wr),
        count(EdgeKind::Rw),
        count(EdgeKind::Rt),
    );
    match (rt > 0, rw, wr) {
        (false, 0, 0) => AnomalyKind::G0,
        (false, 0, _) => AnomalyKind::G1c,
        (false, 1, _) => AnomalyKind::GSingle,
        (false, _, _) => AnomalyKind::G2Item,
        (true, 0, 0) => AnomalyKind::G0Realtime,
        (true, 0, _) => AnomalyKind::G1cRealtime,
        (true, 1, _) => AnomalyKind::GSingleRealtime,
        (true, _, _) => AnomalyKind::G2ItemRealtime,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scc_finds_cycle_and_singletons() {
        let g = Graph::new(4, vec![(0, 1, WW), (1, 2, WW), (2, 0, WW), (2, 3, WW)]);
        let comp = g.scc(WW);
        assert_eq!(comp[0], comp[1]);
        assert_eq!(comp[1], comp[2]);
        assert_ne!(comp[2], comp[3]);
        // Masked out: no cycle over wr.
        let comp = g.scc(WR);
        assert_eq!(comp.iter().collect::<HashSet<_>>().len(), 4);
    }

    #[test]
    fn scc_handles_deep_chains_without_recursion() {
        let n = 200_000;
        let mut edges: Vec<_> = (0..n - 1).map(|i| (i, i + 1, WW)).collect();
        edges.push((n - 1, 0, WW));
        let g = Graph::new(n, edges);
        let comp = g.scc(WW);
        assert!(comp.iter().all(|&c| c == comp[0]));
    }

    #[test]
    fn shortest_cycle_is_preferred() {
        // Long cycle 0->1->2->3->0 and short 0->1->0.
        let edges = vec![(0, 1, WW), (1, 2, WW), (2, 3, WW), (3, 0, WW), (1, 0, WW)];
        let found = find_cycles(&Graph::new(4, edges), false);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, AnomalyKind::G0);
        assert_eq!(found[0].steps.len(), 2);
    }
}
