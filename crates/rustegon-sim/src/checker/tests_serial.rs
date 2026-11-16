// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Serial histories must never be flagged (no false positives), and the checker must scale to
//! 10^5-operation histories (TC-TXN-001).

use std::collections::HashMap;

use proptest::prelude::*;

use super::{CheckOptions, ConsistencyModel as M, History, Op, Outcome, RegisterRead, Txn, check};

/// A generated transaction: outcome selector, whether an `Info` one took effect, and
/// `(op kind, key)` pairs (kind 0 append, 1 list read, 2 register write, 3 register read).
#[derive(Debug, Clone)]
struct Spec {
    outcome: u8,
    applied: bool,
    ops: Vec<(u8, u64)>,
}

/// In-memory model database executing transactions one at a time.
#[derive(Default, Clone)]
struct Model {
    lists: HashMap<u64, Vec<u64>>,
    regs: HashMap<u64, u64>,
}

impl Model {
    /// Executes `spec` and returns the recorded ops (reads with their results).
    fn exec(&mut self, spec: &Spec, next_value: &mut u64) -> Vec<Op> {
        spec.ops
            .iter()
            .map(|&(kind, key)| match kind % 4 {
                0 => {
                    *next_value += 1;
                    self.lists.entry(key).or_default().push(*next_value);
                    Op::append(key, *next_value)
                }
                1 => Op::read_list(key, self.lists.get(&key).map_or(&[][..], Vec::as_slice)),
                2 => {
                    *next_value += 1;
                    self.regs.insert(key, *next_value);
                    Op::write(key, *next_value)
                }
                _ => Op::read_register(key, self.regs.get(&key).copied()),
            })
            .collect()
    }
}

/// Builds a serial history: transaction `i` runs alone in `[2i, 2i + 1]`. Aborted and
/// not-applied `Info` transactions run against a scratch copy so their effects vanish.
fn serial_history(specs: &[Spec]) -> History {
    let mut db = Model::default();
    let mut next_value = 0;
    let mut txns = Vec::with_capacity(specs.len());
    for (i, spec) in (0u64..).zip(specs) {
        let outcome = match spec.outcome % 8 {
            0 => Outcome::Fail,
            1 => Outcome::Info,
            _ => Outcome::Ok,
        };
        let mut ops = if outcome == Outcome::Ok || (outcome == Outcome::Info && spec.applied) {
            db.exec(spec, &mut next_value)
        } else {
            db.clone().exec(spec, &mut next_value)
        };
        if outcome == Outcome::Info {
            // The client never learned the results of an indeterminate transaction.
            for op in &mut ops {
                match op {
                    Op::ReadList { value, .. } => *value = None,
                    Op::ReadRegister { value, .. } => *value = RegisterRead::Unknown,
                    _ => {}
                }
            }
        }
        let end = (outcome != Outcome::Info).then_some(2 * i + 1);
        txns.push(Txn::new(i, outcome, ops).with_time(2 * i, end));
    }
    History::new(txns)
}

fn spec_strategy(keys: u64) -> impl Strategy<Value = Spec> {
    (
        any::<u8>(),
        any::<bool>(),
        prop::collection::vec((0u8..4, 0..keys), 1..6),
    )
        .prop_map(|(outcome, applied, ops)| Spec {
            outcome,
            applied,
            ops,
        })
}

proptest! {
    #[test]
    fn tc_txn_001_checker_serial_histories_are_strict_serializable(
        specs in prop::collection::vec(spec_strategy(4), 0..40),
    ) {
        let history = serial_history(&specs);
        let report = check(&history, &CheckOptions::new(M::StrictSerializable)).unwrap();
        prop_assert!(report.is_valid(), "forbidden: {:?}", report.forbidden);
        prop_assert!(report.allowed.is_empty(), "allowed: {:?}", report.allowed);
    }
}

/// Deterministic generator for the large history (`SplitMix64`; no I/O, no global RNG).
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[test]
fn tc_txn_001_checker_handles_100k_op_serial_history() {
    const TXNS: usize = 25_000;
    const OPS_PER_TXN: usize = 4;
    const KEYS: u64 = 2_000;
    let mut seed = 0x5EED;
    let specs: Vec<Spec> = (0..TXNS)
        .map(|_| {
            let r = splitmix(&mut seed);
            let ops = (0..OPS_PER_TXN)
                .map(|_| {
                    let r = splitmix(&mut seed);
                    ((r % 4) as u8, (r >> 8) % KEYS)
                })
                .collect();
            Spec {
                outcome: (r % 8) as u8,
                applied: r & 0x100 != 0,
                ops,
            }
        })
        .collect();
    let history = serial_history(&specs);
    assert_eq!(
        history.txns.iter().map(|t| t.ops.len()).sum::<usize>(),
        TXNS * OPS_PER_TXN
    );
    let report = check(&history, &CheckOptions::new(M::StrictSerializable)).unwrap();
    assert!(
        report.is_valid() && report.allowed.is_empty(),
        "{:?}",
        report.forbidden.first()
    );
}
