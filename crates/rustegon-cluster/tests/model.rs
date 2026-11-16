// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Model-based test of the local replica (TC-TXN-004, FR-TXN-001): random sequences of
//! proposals, engine flushes and compactions, log purges, restarts and power cuts are checked
//! against a reference model after every step. A power cut after a completed step loses no
//! acknowledged proposal; the persisted `RangeAppliedState` always equals the replica's and the
//! log always holds every entry the engine has not flushed (`common::observe`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::{KEYS, Model, Op, command, observe, open};
use proptest::prelude::*;
use rustegon_mvcc::Replica;
use rustegon_sim::{CrashMode, SimFileSystem};

#[derive(Debug, Clone)]
enum Action {
    Propose(Vec<Op>),
    Flush,
    Compact,
    Purge,
    Restart,
    PowerCut(CrashMode, u64),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (0..KEYS, prop::collection::vec(any::<u8>(), 0..24)).prop_map(|(k, v)| Op::Put(k, v)),
        2 => (0..KEYS).prop_map(Op::Delete),
        1 => (0..KEYS, 1u8..4).prop_map(|(k, n)| Op::DeleteRange(k, k + n)),
    ]
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        12 => prop::collection::vec(op(), 0..5).prop_map(Action::Propose),
        2 => Just(Action::Flush),
        1 => Just(Action::Compact),
        2 => Just(Action::Purge),
        1 => Just(Action::Restart),
        1 => (prop::sample::select(CrashMode::ALL.to_vec()), any::<u64>())
            .prop_map(|(m, s)| Action::PowerCut(m, s)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn tc_txn_004_local_replica_matches_model(actions in prop::collection::vec(action(), 1..60)) {
        let fs = Arc::new(SimFileSystem::new());
        let mut store = open(&fs).unwrap();
        let mut model = Model::default();
        for (i, action) in actions.iter().enumerate() {
            match action {
                Action::Propose(ops) => {
                    let state = store.replica.propose(command(ops, i as u64)).unwrap();
                    model = model.after(ops);
                    prop_assert_eq!(state.applied_index, model.applied);
                }
                Action::Flush => store.engine.flush().unwrap(),
                Action::Compact => {
                    store.engine.compact().unwrap();
                }
                Action::Purge => {
                    let first = store.replica.purge_flushed().unwrap();
                    // Never beyond the applied (and flushed) prefix.
                    prop_assert!(first <= model.applied + 1);
                }
                Action::Restart => {
                    drop(store);
                    store = open(&fs).unwrap();
                }
                Action::PowerCut(mode, seed) => {
                    // Every completed step was acknowledged: nothing may be lost.
                    drop(store);
                    fs.crash(*seed, *mode);
                    store = open(&fs).unwrap();
                }
            }
            let got = observe(&store).map_err(TestCaseError::fail)?;
            prop_assert_eq!(&got, &model, "after step {} {:?}", i, action);
        }
    }
}
