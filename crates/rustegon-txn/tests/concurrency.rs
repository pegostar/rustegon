// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Multi-threaded single-range workloads: TC-TXN-002 (bank invariant) and TC-TXN-001
//! (Elle list-append checked by `rustegon_sim::checker`; FR-TXN-001/002).
//!
//! Scale: `RUSTEGON_TXN_THREADS` (default 4) threads, `RUSTEGON_TXN_OPS` (default 60)
//! transactions per thread.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use bytes::Bytes;
use common::{TestRng, as_int, int, key};
use rustegon_mvcc::VersionValue;
use rustegon_sim::checker::{self, CheckOptions, ConsistencyModel, History, Op, Outcome, Txn};
use rustegon_txn::{Isolation, TxnConfig, TxnError, TxnOptions};

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Retry budget per transaction: conflicts are expected under contention.
const ATTEMPTS: u32 = 10_000;

#[test]
fn tc_txn_002_bank_invariant() {
    const ACCOUNTS: u8 = 5;
    const INITIAL: i64 = 100;
    let threads = env("RUSTEGON_TXN_THREADS", 4);
    let ops = env("RUSTEGON_TXN_OPS", 60);
    let co = common::system(TxnConfig::default());
    for a in 0..ACCOUNTS {
        co.put_single_key(&key(a), &VersionValue::Value(int(INITIAL)))
            .unwrap();
    }
    let total = i64::from(ACCOUNTS) * INITIAL;
    let done = Arc::new(AtomicBool::new(false));
    let audits = Arc::new(AtomicU64::new(0));
    let auditor = {
        let (co, done, audits) = (co.clone(), done.clone(), audits.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let (sum, _) = co
                    .run(&TxnOptions::default(), ATTEMPTS, |t| {
                        let mut sum = 0;
                        for a in 0..ACCOUNTS {
                            sum += as_int(t.get(&key(a))?.as_ref());
                        }
                        Ok(sum)
                    })
                    .unwrap();
                assert_eq!(
                    sum, total,
                    "a SERIALIZABLE snapshot saw money appear or vanish"
                );
                audits.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    let workers: Vec<_> = (0..threads)
        .map(|w| {
            let co = co.clone();
            std::thread::spawn(move || {
                let rng = TestRng::new(0xBA4C + w);
                for _ in 0..ops {
                    let from = u8::try_from(rng.below(u64::from(ACCOUNTS))).unwrap();
                    let to = (from + 1 + u8::try_from(rng.below(u64::from(ACCOUNTS) - 1)).unwrap())
                        % ACCOUNTS;
                    let amount = i64::try_from(rng.below(30)).unwrap() + 1;
                    co.run(&TxnOptions::default(), ATTEMPTS, |t| {
                        let a = as_int(t.get(&key(from))?.as_ref());
                        let b = as_int(t.get(&key(to))?.as_ref());
                        if a >= amount {
                            t.put(&key(from), int(a - amount))?;
                            t.put(&key(to), int(b + amount))?;
                        }
                        Ok(())
                    })
                    .unwrap();
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    done.store(true, Ordering::SeqCst);
    auditor.join().unwrap();
    let mut sum = 0;
    for a in 0..ACCOUNTS {
        let balance = as_int(co.get_latest(&key(a)).unwrap().as_ref());
        assert!(balance >= 0, "account {a} overdrawn: {balance}");
        sum += balance;
    }
    assert_eq!(sum, total);
    assert!(audits.load(Ordering::SeqCst) > 0);
    assert_eq!(co.live_transactions(), 0);
}

/// Encodes a list of elements as concatenated big-endian `u64`s.
fn encode_list(list: &[u64]) -> Bytes {
    list.iter()
        .flat_map(|v| v.to_be_bytes())
        .collect::<Vec<_>>()
        .into()
}

fn decode_list(bytes: Option<&Bytes>) -> Vec<u64> {
    bytes.map_or_else(Vec::new, |b| {
        b.chunks(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
            .collect()
    })
}

/// One generated transaction: `(append?, key)` steps.
fn plan(rng: &TestRng, keys: u64) -> Vec<(bool, u64)> {
    let n = 1 + rng.below(4);
    (0..n)
        .map(|_| (rng.below(2) == 0, rng.below(keys)))
        .collect()
}

/// Runs a planned transaction; returns the observed operations of the committed attempt.
fn execute(
    co: &rustegon_txn::TxnCoordinator,
    isolation: Isolation,
    steps: &[(bool, u64)],
    next_value: &AtomicU64,
) -> Result<Vec<Op>, TxnError> {
    let options = TxnOptions::with_isolation(isolation);
    co.run(&options, ATTEMPTS, |t| {
        let mut ops = Vec::with_capacity(steps.len());
        for &(append, k) in steps {
            let lk = key(u8::try_from(k).unwrap());
            if append {
                // Unique per history (and per attempt, so no retried value is reused).
                let v = next_value.fetch_add(1, Ordering::SeqCst);
                t.update(&lk, |cur| {
                    let mut list = decode_list(cur);
                    list.push(v);
                    Some(VersionValue::Value(encode_list(&list)))
                })?;
                ops.push(Op::append(k, v));
            } else {
                let list = decode_list(t.get(&lk)?.as_ref());
                ops.push(Op::read_list(k, &list));
            }
        }
        Ok(ops)
    })
    .map(|(ops, _)| ops)
}

#[test]
fn tc_txn_001_elle_list_append_single_range() {
    const KEYS: u64 = 4;
    let threads = env("RUSTEGON_TXN_THREADS", 4);
    let per_thread = env("RUSTEGON_TXN_OPS", 60);
    let co = common::system(TxnConfig::default());
    let history = Arc::new(Mutex::new(Vec::new()));
    let next_value = Arc::new(AtomicU64::new(1));
    let next_id = Arc::new(AtomicU64::new(0));
    let clock = Arc::new(AtomicU64::new(0));
    let workers: Vec<_> = (0..threads)
        .map(|w| {
            let (co, history, next_value, next_id, clock) = (
                co.clone(),
                history.clone(),
                next_value.clone(),
                next_id.clone(),
                clock.clone(),
            );
            std::thread::spawn(move || {
                let rng = TestRng::new(0xE11E + w);
                for _ in 0..per_thread {
                    let steps = plan(&rng, KEYS);
                    let start = clock.fetch_add(1, Ordering::SeqCst);
                    let result = execute(&co, Isolation::Serializable, &steps, &next_value);
                    let end = clock.fetch_add(1, Ordering::SeqCst);
                    let id = next_id.fetch_add(1, Ordering::SeqCst);
                    let txn = match result {
                        Ok(ops) => Txn::new(id, Outcome::Ok, ops),
                        Err(e) if e.code().code() == 2006 => {
                            Txn::new(id, Outcome::Info, Vec::new())
                        }
                        Err(e) => panic!("transaction failed after retries: {e}"),
                    };
                    history
                        .lock()
                        .unwrap()
                        .push(txn.with_time(start, Some(end)));
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let history = History::new(history.lock().unwrap().clone());
    assert_eq!(history.txns.len() as u64, threads * per_thread);
    for model in [
        ConsistencyModel::Serializable,
        ConsistencyModel::StrictSerializable,
    ] {
        let report = checker::check(&history, &CheckOptions::new(model)).unwrap();
        assert!(
            report.is_valid(),
            "{model:?}: forbidden anomalies {:?}",
            report.forbidden
        );
    }
    // The workload must actually exercise the database: every key was appended to.
    for k in 0..KEYS {
        let list = decode_list(
            co.get_latest(&key(u8::try_from(k).unwrap()))
                .unwrap()
                .as_ref(),
        );
        assert!(!list.is_empty(), "key {k} never appended");
    }
    assert_eq!(co.live_transactions(), 0);
}
