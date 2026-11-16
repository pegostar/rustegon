// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Hand-crafted histories, one per anomaly class (TC-TXN-001 checker validation).

use super::{
    Anomaly, AnomalyKind as K, CheckOptions, CheckReport, ConsistencyModel as M, EdgeKind, History,
    HistoryError, Op, Outcome, RegisterInference, Txn, check,
};

const X: u64 = 1;
const Y: u64 = 2;

fn ok(id: u64, ops: Vec<Op>) -> Txn {
    Txn::new(id, Outcome::Ok, ops)
}

fn run(txns: Vec<Txn>, model: M) -> CheckReport {
    check(&History::new(txns), &CheckOptions::new(model)).unwrap()
}

/// Asserts the history is valid exactly for the models in `valid_for`, and that every model
/// finds `expected` (forbidden or allowed).
fn assert_models(txns: &[Txn], expected: K, valid_for: &[M]) {
    for model in M::ALL {
        let report = run(txns.to_vec(), model);
        assert_eq!(
            report.is_valid(),
            valid_for.contains(&model),
            "{model:?}: forbidden {:?}",
            report.forbidden
        );
        assert!(
            report.all_kinds().contains(&expected),
            "{model:?}: {report:?}"
        );
    }
}

fn cycle_of(report: &CheckReport, kind: K) -> Vec<super::CycleStep> {
    report
        .forbidden
        .iter()
        .chain(&report.allowed)
        .find_map(|a| match a {
            Anomaly::Cycle { kind: k, steps } if *k == kind => Some(steps.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {kind:?} cycle in {report:?}"))
}

fn assert_closed(steps: &[super::CycleStep]) {
    for w in steps.windows(2) {
        assert_eq!(w[0].to, w[1].from);
    }
    assert_eq!(steps.last().map(|s| s.to), steps.first().map(|s| s.from));
}

#[test]
fn tc_txn_001_checker_list_append_g0_dirty_write() {
    let txns = vec![
        ok(1, vec![Op::append(X, 1), Op::append(Y, 1)]),
        ok(2, vec![Op::append(X, 2), Op::append(Y, 2)]),
        ok(
            3,
            vec![Op::read_list(X, &[1, 2]), Op::read_list(Y, &[2, 1])],
        ),
    ];
    assert_models(&txns, K::G0, &[]);
    let steps = cycle_of(&run(txns, M::ReadCommitted), K::G0);
    assert_eq!(steps.len(), 2);
    assert!(steps.iter().all(|s| s.edge == EdgeKind::Ww));
    assert_closed(&steps);
}

#[test]
fn tc_txn_001_checker_list_append_g1a_aborted_read() {
    let txns = vec![
        Txn::new(1, Outcome::Fail, vec![Op::append(X, 1)]),
        ok(2, vec![Op::read_list(X, &[1])]),
    ];
    assert_models(&txns, K::G1a, &[]);
    let report = run(txns, M::ReadCommitted);
    assert!(report.forbidden.contains(&Anomaly::AbortedRead {
        key: X,
        value: 1,
        reader: 2,
        writer: 1
    }));
}

#[test]
fn tc_txn_001_checker_list_append_g1b_intermediate_read() {
    let txns = vec![
        ok(1, vec![Op::append(X, 1), Op::append(X, 2)]),
        ok(2, vec![Op::read_list(X, &[1])]),
    ];
    assert_models(&txns, K::G1b, &[]);
}

#[test]
fn tc_txn_001_checker_list_append_g1c_circular_information_flow() {
    let txns = vec![
        ok(1, vec![Op::append(X, 1), Op::read_list(Y, &[1])]),
        ok(2, vec![Op::append(Y, 1), Op::read_list(X, &[1])]),
    ];
    assert_models(&txns, K::G1c, &[]);
    let steps = cycle_of(&run(txns, M::ReadCommitted), K::G1c);
    assert_eq!(steps.len(), 2);
    assert!(steps.iter().all(|s| s.edge == EdgeKind::Wr));
    assert_closed(&steps);
}

#[test]
fn tc_txn_001_checker_list_append_read_skew_is_g_single() {
    // T2 sees T1's write to y but not to x.
    let txns = vec![
        ok(1, vec![Op::append(X, 1), Op::append(Y, 1)]),
        ok(2, vec![Op::read_list(X, &[]), Op::read_list(Y, &[1])]),
        ok(3, vec![Op::read_list(X, &[1])]),
    ];
    assert_models(&txns, K::GSingle, &[M::ReadCommitted]);
    let steps = cycle_of(&run(txns, M::Snapshot), K::GSingle);
    assert_eq!(steps.iter().filter(|s| s.edge == EdgeKind::Rw).count(), 1);
    assert_closed(&steps);
}

#[test]
fn tc_txn_001_checker_list_append_non_repeatable_read_passes_read_committed_only() {
    let txns = vec![
        ok(1, vec![Op::append(X, 1)]),
        ok(2, vec![Op::read_list(X, &[]), Op::read_list(X, &[1])]),
    ];
    assert_models(&txns, K::NonRepeatableRead, &[M::ReadCommitted]);
    assert!(
        run(txns, M::Snapshot)
            .forbidden_kinds()
            .contains(&K::GSingle)
    );
}

#[test]
fn tc_txn_001_checker_list_append_write_skew_passes_snapshot_fails_serializable() {
    let txns = vec![
        ok(
            1,
            vec![
                Op::read_list(X, &[]),
                Op::read_list(Y, &[]),
                Op::append(X, 1),
            ],
        ),
        ok(
            2,
            vec![
                Op::read_list(X, &[]),
                Op::read_list(Y, &[]),
                Op::append(Y, 2),
            ],
        ),
        ok(3, vec![Op::read_list(X, &[1]), Op::read_list(Y, &[2])]),
    ];
    assert_models(&txns, K::G2Item, &[M::ReadCommitted, M::Snapshot]);
    let report = run(txns, M::Serializable);
    assert_eq!(report.forbidden_kinds(), vec![K::G2Item]);
    let steps = cycle_of(&report, K::G2Item);
    assert_eq!(steps.len(), 2);
    assert!(steps.iter().all(|s| s.edge == EdgeKind::Rw));
    let mut ids: Vec<_> = steps.iter().map(|s| s.from).collect();
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2]);
    assert_closed(&steps);
}

#[test]
fn tc_txn_001_checker_list_append_lost_update_fails_snapshot() {
    let txns = vec![
        ok(1, vec![Op::read_list(X, &[]), Op::append(X, 1)]),
        ok(2, vec![Op::read_list(X, &[]), Op::append(X, 2)]),
        ok(3, vec![Op::read_list(X, &[1, 2])]),
    ];
    assert_models(&txns, K::LostUpdate, &[M::ReadCommitted]);
    let report = run(txns, M::Snapshot);
    assert!(report.forbidden.contains(&Anomaly::LostUpdate {
        key: X,
        txns: vec![1, 2]
    }));
}

#[test]
fn tc_txn_001_checker_list_append_stale_read_fails_strict_serializable_only() {
    // T1 commits before T2 starts, yet T2 does not see T1's append.
    let txns = vec![
        ok(1, vec![Op::append(X, 1)]).with_time(0, Some(1)),
        ok(2, vec![Op::read_list(X, &[])]).with_time(2, Some(3)),
        ok(3, vec![Op::read_list(X, &[1])]).with_time(4, Some(5)),
    ];
    let valid = [M::ReadCommitted, M::Snapshot, M::Serializable];
    for model in M::ALL {
        assert_eq!(
            run(txns.clone(), model).is_valid(),
            valid.contains(&model),
            "{model:?}"
        );
    }
    let report = run(txns, M::StrictSerializable);
    assert_eq!(report.forbidden_kinds(), vec![K::GSingleRealtime]);
    let steps = cycle_of(&report, K::GSingleRealtime);
    assert!(steps.iter().any(|s| s.edge == EdgeKind::Rt));
    assert_closed(&steps);
}

#[test]
fn tc_txn_001_checker_list_append_concurrent_txns_have_no_real_time_order() {
    // Same as the stale read, but the intervals overlap: legal under strict serializability.
    let txns = vec![
        ok(1, vec![Op::append(X, 1)]).with_time(0, Some(3)),
        ok(2, vec![Op::read_list(X, &[])]).with_time(3, Some(4)),
        ok(3, vec![Op::read_list(X, &[1])]).with_time(5, Some(6)),
    ];
    assert!(run(txns, M::StrictSerializable).is_valid());
}

#[test]
fn tc_txn_001_checker_list_append_internal_inconsistency() {
    let txns = vec![ok(1, vec![Op::append(X, 1), Op::read_list(X, &[])])];
    assert_models(&txns, K::Internal, &[]);
}

#[test]
fn tc_txn_001_checker_list_append_incompatible_order() {
    let txns = vec![
        ok(1, vec![Op::append(X, 1)]),
        ok(2, vec![Op::append(X, 2)]),
        ok(3, vec![Op::read_list(X, &[1, 2])]),
        ok(4, vec![Op::read_list(X, &[2, 1])]),
    ];
    assert_models(&txns, K::IncompatibleOrder, &[]);
}

#[test]
fn tc_txn_001_checker_list_append_duplicate_elements_and_garbage() {
    let txns = vec![
        ok(1, vec![Op::append(X, 1)]),
        ok(2, vec![Op::read_list(X, &[1, 1])]),
    ];
    assert_models(&txns, K::DuplicateElements, &[]);
    let txns = vec![ok(1, vec![Op::read_list(X, &[9])])];
    assert_models(&txns, K::GarbageRead, &[]);
    let txns = vec![ok(1, vec![Op::append(X, 1)]), ok(2, vec![Op::append(X, 1)])];
    assert_models(&txns, K::DuplicateWrite, &[]);
}

#[test]
fn tc_txn_001_checker_list_append_info_txn_counts_once_observed() {
    // An Info txn whose append was observed committed: it takes part in the G1c cycle.
    let txns = vec![
        Txn::new(
            1,
            Outcome::Info,
            vec![Op::append(X, 1), Op::read_list(Y, &[1])],
        ),
        ok(2, vec![Op::append(Y, 1), Op::read_list(X, &[1])]),
    ];
    // T1's read result is unknown to the checker (Info), so only wr T1 -> T2 exists: valid.
    assert!(run(txns, M::StrictSerializable).is_valid());
    // An unobserved Info append is not a node at all.
    let txns = vec![
        Txn::new(1, Outcome::Info, vec![Op::append(X, 1)]),
        ok(2, vec![Op::read_list(X, &[])]),
    ];
    assert!(run(txns, M::StrictSerializable).is_valid());
}

#[test]
fn tc_txn_001_checker_rw_register_g1a_g1b_g1c() {
    let g1a = vec![
        Txn::new(1, Outcome::Fail, vec![Op::write(X, 1)]),
        ok(2, vec![Op::read_register(X, Some(1))]),
    ];
    assert_models(&g1a, K::G1a, &[]);
    let g1b = vec![
        ok(1, vec![Op::write(X, 1), Op::write(X, 2)]),
        ok(2, vec![Op::read_register(X, Some(1))]),
    ];
    assert_models(&g1b, K::G1b, &[]);
    let g1c = vec![
        ok(1, vec![Op::write(X, 1), Op::read_register(Y, Some(1))]),
        ok(2, vec![Op::write(Y, 1), Op::read_register(X, Some(1))]),
    ];
    assert_models(&g1c, K::G1c, &[]);
}

#[test]
fn tc_txn_001_checker_rw_register_internal_and_garbage() {
    let txns = vec![
        ok(1, vec![Op::write(X, 1), Op::read_register(X, Some(2))]),
        ok(2, vec![Op::write(X, 2)]),
    ];
    assert_models(&txns, K::Internal, &[]);
    let txns = vec![ok(1, vec![Op::read_register(X, Some(7))])];
    assert_models(&txns, K::GarbageRead, &[]);
}

#[test]
fn tc_txn_001_checker_rw_register_read_skew_from_initial_state() {
    let txns = vec![
        ok(1, vec![Op::write(X, 1), Op::write(Y, 1)]),
        ok(
            2,
            vec![Op::read_register(X, None), Op::read_register(Y, Some(1))],
        ),
    ];
    assert_models(&txns, K::GSingle, &[M::ReadCommitted]);
}

#[test]
fn tc_txn_001_checker_rw_register_non_repeatable_read() {
    let txns = vec![
        ok(1, vec![Op::write(X, 1)]),
        ok(
            2,
            vec![Op::read_register(X, None), Op::read_register(X, Some(1))],
        ),
    ];
    assert_models(&txns, K::NonRepeatableRead, &[M::ReadCommitted]);
}

#[test]
fn tc_txn_001_checker_rw_register_write_skew_passes_snapshot_fails_serializable() {
    let txns = vec![
        ok(
            1,
            vec![
                Op::read_register(X, None),
                Op::read_register(Y, None),
                Op::write(X, 1),
            ],
        ),
        ok(
            2,
            vec![
                Op::read_register(X, None),
                Op::read_register(Y, None),
                Op::write(Y, 2),
            ],
        ),
    ];
    assert_models(&txns, K::G2Item, &[M::ReadCommitted, M::Snapshot]);
}

#[test]
fn tc_txn_001_checker_rw_register_lost_update_fails_snapshot() {
    let txns = vec![
        ok(1, vec![Op::read_register(X, None), Op::write(X, 1)]),
        ok(2, vec![Op::read_register(X, None), Op::write(X, 2)]),
    ];
    assert_models(&txns, K::LostUpdate, &[M::ReadCommitted]);
}

#[test]
fn tc_txn_001_checker_rw_register_writes_follow_reads_inference() {
    // T1 read x=1 (from T0) and overwrote it; T2 read x=1 too, so T2 -rw-> T1, while T2 also
    // read T1's y: a G-single visible only under the writes-follow-reads assumption.
    let txns = vec![
        ok(0, vec![Op::write(X, 1)]),
        ok(
            1,
            vec![
                Op::read_register(X, Some(1)),
                Op::write(X, 2),
                Op::write(Y, 5),
            ],
        ),
        ok(
            2,
            vec![Op::read_register(X, Some(1)), Op::read_register(Y, Some(5))],
        ),
    ];
    let history = History::new(txns);
    let mut options = CheckOptions::new(M::Snapshot);
    let report = check(&history, &options).unwrap();
    assert_eq!(report.forbidden_kinds(), vec![K::GSingle]);
    options.register_inference = RegisterInference::InitialStateOnly;
    assert!(check(&history, &options).unwrap().is_valid());
}

#[test]
fn tc_txn_001_checker_serial_example_is_valid_everywhere() {
    let txns = vec![
        ok(1, vec![Op::append(X, 1), Op::write(Y, 1)]).with_time(0, Some(1)),
        ok(
            2,
            vec![
                Op::read_list(X, &[1]),
                Op::append(X, 2),
                Op::read_register(Y, Some(1)),
            ],
        )
        .with_time(2, Some(3)),
        Txn::new(3, Outcome::Fail, vec![Op::append(X, 3), Op::write(Y, 3)]).with_time(4, Some(5)),
        ok(
            4,
            vec![
                Op::read_list(X, &[1, 2]),
                Op::read_register(Y, Some(1)),
                Op::write(Y, 4),
            ],
        )
        .with_time(6, Some(7)),
    ];
    for model in M::ALL {
        let report = run(txns.clone(), model);
        assert!(
            report.is_valid() && report.allowed.is_empty(),
            "{model:?}: {report:?}"
        );
    }
}

#[test]
fn tc_txn_001_checker_rejects_malformed_histories() {
    let dup = History::new(vec![ok(1, vec![]), ok(1, vec![])]);
    let options = CheckOptions::new(M::Serializable);
    assert_eq!(check(&dup, &options), Err(HistoryError::DuplicateTxnId(1)));
    let bad_time = History::new(vec![ok(1, vec![]).with_time(5, Some(4))]);
    assert_eq!(
        check(&bad_time, &options),
        Err(HistoryError::InvalidInterval(1))
    );
}
