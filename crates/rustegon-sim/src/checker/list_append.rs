// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! list-append inference (Elle §4.1 "Traceability" and §5).
//!
//! Every append writes a unique element, so a committed read of a list names, for each element
//! it contains, the transaction that wrote it (*recoverability*), and its order is a prefix of
//! the key's version order (*traceability*). Hence:
//! - **version order** of a key = its longest committed read; every other read must be a
//!   prefix of it (else *incompatible order*);
//! - **ww**: writers of consecutive elements (skipping repeats of the same writer);
//! - **wr**: writer of the last element of a read (other than the reader) → reader;
//! - **rw**: reader → writer of the first element after the read's prefix (other than the
//!   reader), i.e. the transaction that installed the version following the one it saw.
//!
//! Per-transaction checks: a read must end with the transaction's own appends to the key so far
//! (*internal*); two reads of a key must differ only by the reader's own appends in between
//! (*non-repeatable read*, legal under READ COMMITTED); two committed transactions that read
//! the same version of a key before appending to it is a *lost update*.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::{
    Collector,
    anomaly::Anomaly,
    graph::{RW, WR, WW},
    history::{History, Key, Op, Outcome, Value},
};

/// A committed read of one key.
struct Read<'h> {
    txn: usize,
    list: &'h [Value],
}

/// Who appended what.
struct Appends {
    /// `(key, element)` → writer transaction index.
    writer: HashMap<(Key, Value), usize>,
    /// `(txn, key)` → that transaction's last element appended to the key.
    last: HashMap<(usize, Key), Value>,
}

/// Per-transaction, per-key state while walking a transaction's operations.
#[derive(Default)]
struct KeyState<'h> {
    /// All own appends so far, in order.
    own: Vec<Value>,
    /// Previous read and own appends after it.
    last_read: Option<&'h [Value]>,
    since_read: Vec<Value>,
    /// Length of the first read, if it happened before any own append.
    first_read_len: Option<usize>,
    appended_after_first_read: bool,
}

/// Runs the list-append analysis, appending anomalies and edges to `c`.
pub(super) fn analyze(history: &History, c: &mut Collector) {
    let appends = index_appends(history, c);
    let mut reads: BTreeMap<Key, Vec<Read<'_>>> = BTreeMap::new();
    let mut lost_updates: BTreeMap<(Key, usize), Vec<usize>> = BTreeMap::new();
    for (t, txn) in history.txns.iter().enumerate() {
        if txn.outcome == Outcome::Ok {
            walk_txn(history, t, c, &mut reads, &mut lost_updates);
        }
    }
    for (key, key_reads) in &reads {
        analyze_key(history, *key, key_reads, &appends, c);
    }
    for ((key, _), txns) in lost_updates {
        if txns.len() > 1 {
            let txns = txns.iter().map(|&t| history.txns[t].id).collect();
            c.anomalies.push(Anomaly::LostUpdate { key, txns });
        }
    }
}

fn index_appends(history: &History, c: &mut Collector) -> Appends {
    let mut a = Appends {
        writer: HashMap::new(),
        last: HashMap::new(),
    };
    for (t, txn) in history.txns.iter().enumerate() {
        for op in &txn.ops {
            if let Op::Append { key, value } = *op {
                if let Some(&first) = a.writer.get(&(key, value)) {
                    let txns = [history.txns[first].id, txn.id];
                    c.anomalies
                        .push(Anomaly::DuplicateWrite { key, value, txns });
                } else {
                    a.writer.insert((key, value), t);
                }
                a.last.insert((t, key), value);
            }
        }
    }
    a
}

/// Internal / non-repeatable-read / duplicate checks of one committed transaction; records its
/// reads and lost-update candidates.
fn walk_txn<'h>(
    history: &'h History,
    t: usize,
    c: &mut Collector,
    reads: &mut BTreeMap<Key, Vec<Read<'h>>>,
    lost_updates: &mut BTreeMap<(Key, usize), Vec<usize>>,
) {
    let txn = &history.txns[t];
    let mut state: BTreeMap<Key, KeyState<'h>> = BTreeMap::new();
    for op in &txn.ops {
        match op {
            Op::Append { key, value } => {
                let s = state.entry(*key).or_default();
                s.own.push(*value);
                s.since_read.push(*value);
                s.appended_after_first_read |= s.first_read_len.is_some();
            }
            Op::ReadList {
                key,
                value: Some(list),
            } => {
                let key = *key;
                let s = state.entry(key).or_default();
                let mut seen = HashSet::with_capacity(list.len());
                if let Some(&dup) = list.iter().find(|v| !seen.insert(**v)) {
                    c.anomalies.push(Anomaly::DuplicateElements {
                        key,
                        txn: txn.id,
                        value: dup,
                    });
                }
                if !list.ends_with(&s.own) {
                    let detail = format!("read {list:?} does not end with own appends {:?}", s.own);
                    c.anomalies.push(Anomaly::Internal {
                        key,
                        txn: txn.id,
                        detail,
                    });
                }
                if let Some(prev) = s.last_read {
                    // Snapshot reads are stable: the second read must be the first plus own
                    // appends since.
                    let expected = prev.len() + s.since_read.len();
                    let same = list.len() == expected
                        && list.starts_with(prev)
                        && list.ends_with(&s.since_read);
                    if !same {
                        c.anomalies
                            .push(Anomaly::NonRepeatableRead { key, txn: txn.id });
                    }
                } else if s.own.is_empty() {
                    s.first_read_len = Some(list.len());
                }
                s.last_read = Some(list);
                s.since_read.clear();
                reads.entry(key).or_default().push(Read { txn: t, list });
            }
            _ => {}
        }
    }
    for (key, s) in state {
        if let (Some(len), true) = (s.first_read_len, s.appended_after_first_read) {
            lost_updates.entry((key, len)).or_default().push(t);
        }
    }
}

/// Infers the version order of `key` and emits its anomalies and edges.
fn analyze_key(
    history: &History,
    key: Key,
    reads: &[Read<'_>],
    appends: &Appends,
    c: &mut Collector,
) {
    // The longest read is the most complete view of the version order (first one on ties).
    let Some(longest) = reads
        .iter()
        .reduce(|a, b| if b.list.len() > a.list.len() { b } else { a })
    else {
        return;
    };
    let order = longest.list;
    let mut compatible = Vec::with_capacity(reads.len());
    let mut reported_incompatible = false;
    for r in reads {
        let ok = order.starts_with(r.list);
        if !ok && !reported_incompatible {
            reported_incompatible = true;
            c.anomalies.push(Anomaly::IncompatibleOrder {
                key,
                left: order.to_vec(),
                right: r.list.to_vec(),
            });
        }
        compatible.push(ok);
    }

    // Writer of each position, if it is a usable graph node (known and not aborted).
    let reader_id = history.txns[longest.txn].id;
    let mut writers = Vec::with_capacity(order.len());
    for &v in order {
        let w = match appends.writer.get(&(key, v)) {
            None => {
                c.anomalies.push(Anomaly::GarbageRead {
                    key,
                    value: v,
                    reader: reader_id,
                });
                None
            }
            Some(&w) if history.txns[w].outcome == Outcome::Fail => {
                let writer = history.txns[w].id;
                c.anomalies.push(Anomaly::AbortedRead {
                    key,
                    value: v,
                    reader: reader_id,
                    writer,
                });
                None
            }
            Some(&w) => {
                c.observed[w] = true;
                Some(w)
            }
        };
        writers.push(w);
    }

    // ww: consecutive distinct writers along the version order.
    let mut prev: Option<usize> = None;
    for &w in writers.iter().flatten() {
        if let Some(p) = prev.filter(|&p| p != w) {
            c.edges.push((p, w, WW));
        }
        prev = Some(w);
    }

    let mut g1b_reported = HashSet::new();
    for (r, _) in reads.iter().zip(&compatible).filter(|(_, ok)| **ok) {
        let m = r.list.len();
        // wr (and G1b): the last element written by another transaction.
        if let Some(p) = (0..m)
            .rev()
            .find(|&p| writers[p].is_some_and(|w| w != r.txn))
            && let Some(w) = writers[p]
        {
            c.edges.push((w, r.txn, WR));
            let value = order[p];
            if appends.last.get(&(w, key)) != Some(&value) && g1b_reported.insert(value) {
                c.anomalies.push(Anomaly::IntermediateRead {
                    key,
                    value,
                    reader: history.txns[r.txn].id,
                    writer: history.txns[w].id,
                });
            }
        }
        // rw: the first later version installed by another transaction.
        if let Some(w) = writers[m..].iter().flatten().find(|&&w| w != r.txn) {
            c.edges.push((r.txn, *w, RW));
        }
    }
}
