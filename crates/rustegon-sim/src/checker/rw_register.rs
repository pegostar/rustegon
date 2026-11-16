// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! rw-register inference (Elle §4.2), deliberately conservative.
//!
//! Writes are unique per key, so a read of value `v` names its writer: **wr** edges and G1a /
//! G1b are exact. A read reveals nothing about older versions, so the version order is only
//! partially known; the edges added are those implied by orderings that must hold:
//! - the initial nil precedes every written value: a reader of nil **rw**-precedes every
//!   writer of the key;
//! - with [`RegisterInference::WritesFollowReads`]: if committed `T` read `a` and later wrote
//!   the key, `a` precedes `T`'s value, giving **ww** `writer(a) -> T` and **rw**
//!   `reader(a) -> T` for every other reader of `a`.
//!
//! These may be transitive (not immediate-successor) edges; replacing a transitive ww/rw edge
//! by the real chain (rw then ww…, or ww…) keeps the number of rw edges in any cycle, so cycle
//! classes stay correct. Orders between blind writes are never guessed, so G0 and most G2 are
//! undetectable here (documented in the module root).
//!
//! Per-transaction checks: a read after an own write must return it (*internal*); two external
//! reads of a key must agree (*non-repeatable read*); two committed transactions that read the
//! same version and then wrote the key is a *lost update*.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::{
    Collector, RegisterInference,
    anomaly::Anomaly,
    graph::{RW, WR, WW},
    history::{History, Key, Op, Outcome, RegisterRead, Value},
};

/// Version read by an external read: `None` = initial nil.
type Version = Option<Value>;

/// Who wrote what.
struct Writes {
    /// `(key, value)` → writer transaction index.
    writer: HashMap<(Key, Value), usize>,
    /// `(txn, key)` → that transaction's final value for the key.
    last: HashMap<(usize, Key), Value>,
    /// key → distinct writer transactions.
    by_key: HashMap<Key, Vec<usize>>,
}

/// Committed reads that observed another transaction's state.
#[derive(Default)]
struct Reads {
    /// `(txn, key, version)` in history order.
    external: Vec<(usize, Key, Version)>,
    /// `(key, version)` → readers.
    readers: HashMap<(Key, Version), Vec<usize>>,
    /// `(key, version read first)` → transactions that wrote the key after that read.
    read_then_write: BTreeMap<(Key, Version), Vec<usize>>,
}

/// Per-transaction, per-key walk state.
#[derive(Default)]
struct KeyState {
    own_last: Option<Value>,
    last_read: Option<Version>,
    first_read: Option<Version>,
    wrote_after_read: bool,
}

/// Runs the rw-register analysis, appending anomalies and edges to `c`.
pub(super) fn analyze(history: &History, inference: RegisterInference, c: &mut Collector) {
    let index = index_writes(history, c);
    let mut reads = Reads::default();
    for (t, txn) in history.txns.iter().enumerate() {
        if txn.outcome == Outcome::Ok {
            walk_txn(history, t, c, &mut reads);
        }
    }
    let mut g1b_reported = HashSet::new();
    for &(t, key, version) in &reads.external {
        let reader = history.txns[t].id;
        let Some(v) = version else {
            // Nil precedes every written value.
            for &w in index.by_key.get(&key).into_iter().flatten() {
                c.edges.push((t, w, RW));
            }
            continue;
        };
        match index.writer.get(&(key, v)) {
            None => c.anomalies.push(Anomaly::GarbageRead {
                key,
                value: v,
                reader,
            }),
            Some(&w) if w == t => {
                let detail = format!("read {v} before writing it");
                c.anomalies.push(Anomaly::Internal {
                    key,
                    txn: reader,
                    detail,
                });
            }
            Some(&w) if history.txns[w].outcome == Outcome::Fail => {
                let writer = history.txns[w].id;
                c.anomalies.push(Anomaly::AbortedRead {
                    key,
                    value: v,
                    reader,
                    writer,
                });
            }
            Some(&w) => {
                c.observed[w] = true;
                c.edges.push((w, t, WR));
                if index.last.get(&(w, key)) != Some(&v) && g1b_reported.insert((key, v)) {
                    let writer = history.txns[w].id;
                    c.anomalies.push(Anomaly::IntermediateRead {
                        key,
                        value: v,
                        reader,
                        writer,
                    });
                }
            }
        }
    }
    for (&(key, version), txns) in &reads.read_then_write {
        if inference == RegisterInference::WritesFollowReads {
            for &t in txns {
                writes_follow_reads(history, &index, &reads, (t, key, version), c);
            }
        }
        if txns.len() > 1 {
            let txns = txns.iter().map(|&t| history.txns[t].id).collect();
            c.anomalies.push(Anomaly::LostUpdate { key, txns });
        }
    }
}

/// Edges from "`t` read `version` of `key`, then overwrote it".
fn writes_follow_reads(
    history: &History,
    writes: &Writes,
    reads: &Reads,
    (t, key, version): (usize, Key, Version),
    c: &mut Collector,
) {
    if let Some(v) = version
        && let Some(&w) = writes.writer.get(&(key, v))
        && w != t
        && history.txns[w].outcome != Outcome::Fail
    {
        c.edges.push((w, t, WW));
    }
    for &r in reads.readers.get(&(key, version)).into_iter().flatten() {
        if r != t {
            c.edges.push((r, t, RW));
        }
    }
}

fn index_writes(history: &History, c: &mut Collector) -> Writes {
    let mut w = Writes {
        writer: HashMap::new(),
        last: HashMap::new(),
        by_key: HashMap::new(),
    };
    for (t, txn) in history.txns.iter().enumerate() {
        for op in &txn.ops {
            if let Op::Write { key, value } = *op {
                if let Some(&first) = w.writer.get(&(key, value)) {
                    let txns = [history.txns[first].id, txn.id];
                    c.anomalies
                        .push(Anomaly::DuplicateWrite { key, value, txns });
                } else {
                    w.writer.insert((key, value), t);
                }
                if w.last.insert((t, key), value).is_none() {
                    w.by_key.entry(key).or_default().push(t);
                }
            }
        }
    }
    w
}

/// Internal / non-repeatable-read checks of one committed transaction; records its external
/// reads and read-then-write pairs.
fn walk_txn(history: &History, t: usize, c: &mut Collector, reads: &mut Reads) {
    let txn = &history.txns[t];
    let mut state: BTreeMap<Key, KeyState> = BTreeMap::new();
    for op in &txn.ops {
        match *op {
            Op::Write { key, value } => {
                let s = state.entry(key).or_default();
                s.own_last = Some(value);
                s.wrote_after_read |= s.first_read.is_some();
            }
            Op::ReadRegister { key, value } => {
                let version = match value {
                    RegisterRead::Unknown => continue,
                    RegisterRead::Nil => None,
                    RegisterRead::Value(v) => Some(v),
                };
                let s = state.entry(key).or_default();
                if let Some(own) = s.own_last {
                    if version != Some(own) {
                        let detail = format!("read {version:?} after own write {own}");
                        c.anomalies.push(Anomaly::Internal {
                            key,
                            txn: txn.id,
                            detail,
                        });
                    }
                    continue;
                }
                if s.last_read.is_some_and(|prev| prev != version) {
                    c.anomalies
                        .push(Anomaly::NonRepeatableRead { key, txn: txn.id });
                }
                s.last_read = Some(version);
                s.first_read.get_or_insert(version);
                reads.external.push((t, key, version));
                reads.readers.entry((key, version)).or_default().push(t);
            }
            _ => {}
        }
    }
    for (key, s) in state {
        if let (Some(version), true) = (s.first_read, s.wrote_after_read) {
            reads
                .read_then_write
                .entry((key, version))
                .or_default()
                .push(t);
        }
    }
}
