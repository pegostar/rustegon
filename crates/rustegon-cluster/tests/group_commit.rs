// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Group commit of the local replica (ADR-040; FR-TXN-001, NFR-REL-001, TC-TXN-004): a proposal
//! may be applied before it is durable (`Replica::propose_unsynced`), one log sync carries every
//! proposal applied by then (`Replica::sync_through`), `Replica::unsynced_index` names what an
//! observer must wait for, and neither proposals nor reads wait for a sync in progress.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, mpsc},
    time::Duration,
};

use common::{LOG_DIR, LSM_DIR, Model, Op, command, key, observe, open, open_on};
use rustegon_mvcc::{Replica, ReplicaError};
use rustegon_sim::{CrashMode, SimFileSystem};
use rustegon_sim_api::{File, FileSystem, OpenMode};

/// Upper bound on any wait of a test: a bug shows as a failure, not as a hang.
const LIMIT: Duration = Duration::from_secs(20);

fn put(k: u8) -> Vec<Op> {
    vec![Op::Put(k, vec![k])]
}

#[test]
fn tc_txn_004_unsynced_proposal_is_applied_at_once_and_durable_after_its_sync() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    store.replica.propose(command(&put(1), 1)).unwrap();
    assert_eq!(
        store.replica.unsynced_index(),
        None,
        "a proposal is durable"
    );

    let state = store.replica.propose_unsynced(command(&put(2), 2)).unwrap();
    assert_eq!(state.applied_index, 2);
    // Applied: readers see it and the applied state.
    assert_eq!(
        store.engine.get(&key(2), None).unwrap().as_deref(),
        Some(&[2][..])
    );
    assert_eq!(store.replica.applied_index(), 2);
    // Not durable: not in the log, and whoever saw it is told to wait for it.
    assert_eq!(store.replica.log_bounds(), (1, 1));
    assert_eq!(store.replica.unsynced_index(), Some(2));

    store.replica.sync_through(2).unwrap();
    assert_eq!(store.replica.log_bounds(), (1, 2));
    assert_eq!(store.replica.unsynced_index(), None);
}

#[test]
fn tc_txn_004_power_cut_loses_an_unsynced_proposal_and_keeps_a_synced_one() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    store.replica.propose_unsynced(command(&put(1), 1)).unwrap();
    store.replica.sync_through(1).unwrap();
    store.replica.propose_unsynced(command(&put(2), 2)).unwrap();
    // Power cut: the close cannot write what is pending.
    fs.halt_after_ops(0);
    drop(store);
    fs.crash(0, CrashMode::Clean);
    let store = open(&fs).unwrap();
    assert_eq!(observe(&store).unwrap(), Model::default().after(&put(1)));
    // The index of the lost proposal is used again.
    let state = store.replica.propose(command(&put(3), 3)).unwrap();
    assert_eq!(state.applied_index, 2);
}

#[test]
fn tc_txn_004_one_sync_carries_every_proposal_applied_before_it() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    // The cost of one command: its log record and the sync.
    store.replica.propose_unsynced(command(&put(1), 1)).unwrap();
    let before = fs.op_count();
    store.replica.sync_through(1).unwrap();
    let one = fs.op_count() - before;
    assert!(one > 0);

    for i in 2..=4 {
        store
            .replica
            .propose_unsynced(command(&put(i), u64::from(i)))
            .unwrap();
    }
    assert_eq!(fs.op_count(), before + one, "a proposal does no log I/O");
    let before = fs.op_count();
    // Asking for the oldest of the three writes all of them: one record, one sync.
    store.replica.sync_through(2).unwrap();
    assert_eq!(
        fs.op_count() - before,
        one,
        "three commands, the I/O of one"
    );
    assert_eq!(store.replica.log_bounds(), (1, 4));
    assert_eq!(store.replica.unsynced_index(), None);
    // Already durable: no I/O at all.
    let before = fs.op_count();
    store.replica.sync_through(3).unwrap();
    store.replica.sync_through(4).unwrap();
    assert_eq!(fs.op_count(), before);
}

#[test]
fn tc_txn_004_deferred_proposal_is_not_awaited_and_rides_on_the_next_sync() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    // An intent of an uncommitted transaction (ADR-038): nobody waits for it.
    store.replica.propose_deferred(command(&put(1), 1)).unwrap();
    assert_eq!(store.replica.unsynced_index(), None);
    assert_eq!(store.replica.log_bounds(), (1, 0));
    store.replica.propose_unsynced(command(&put(2), 2)).unwrap();
    assert_eq!(store.replica.unsynced_index(), Some(2));
    store.replica.sync_through(2).unwrap();
    assert_eq!(store.replica.log_bounds(), (1, 2));
    drop(store);
    fs.crash(0, CrashMode::Clean);
    let store = open(&fs).unwrap();
    let both = Model::default().after(&put(1)).after(&put(2));
    assert_eq!(observe(&store).unwrap(), both);
}

#[test]
fn tc_txn_004_failed_sync_poisons_the_replica_and_keeps_its_index_unsynced() {
    let fs = Arc::new(SimFileSystem::new());
    let store = open(&fs).unwrap();
    store.replica.propose(command(&put(1), 1)).unwrap();
    store.replica.propose_unsynced(command(&put(2), 2)).unwrap();
    fs.halt_after_ops(0);
    assert!(store.replica.sync_through(2).is_err());
    assert!(!store.replica.is_healthy());
    // The engine holds command 2 and the log may not: whoever saw it must keep failing.
    assert_eq!(store.replica.unsynced_index(), Some(2));
    assert!(matches!(
        store.replica.sync_through(2),
        Err(ReplicaError::Poisoned { .. })
    ));
    // What was durable stays acknowledged; nothing new is accepted.
    store.replica.sync_through(1).unwrap();
    assert!(matches!(
        store.replica.propose_unsynced(command(&put(3), 3)),
        Err(ReplicaError::Poisoned { .. })
    ));
    drop(store);
    fs.crash(0, CrashMode::Clean);
    let store = open(&fs).unwrap();
    assert_eq!(observe(&store).unwrap(), Model::default().after(&put(1)));
}

/// Holds back the `sync_data` of log files while closed.
#[derive(Default)]
struct Gate {
    /// `(closed, syncs held at the gate)`.
    state: Mutex<(bool, usize)>,
    changed: Condvar,
}

impl Gate {
    fn set_closed(&self, closed: bool) {
        self.state.lock().unwrap().0 = closed;
        self.changed.notify_all();
    }

    /// Called by a log sync: waits while the gate is closed.
    fn pass(&self) {
        let mut st = self.state.lock().unwrap();
        st.1 += 1;
        self.changed.notify_all();
        while st.0 {
            st = self.changed.wait(st).unwrap();
        }
        st.1 -= 1;
    }

    /// Waits until a log sync is held at the gate.
    fn wait_for_sync(&self) {
        let st = self.state.lock().unwrap();
        let (_st, timeout) = self
            .changed
            .wait_timeout_while(st, LIMIT, |s| s.1 == 0)
            .unwrap();
        assert!(!timeout.timed_out(), "no log sync reached the gate");
    }
}

/// The simulated file system with a [`Gate`] in front of every log sync.
struct GatedFs {
    fs: Arc<SimFileSystem>,
    gate: Arc<Gate>,
}

struct GatedFile {
    file: Box<dyn File>,
    gate: Option<Arc<Gate>>,
}

impl File for GatedFile {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.file.read_exact_at(buf, offset)
    }

    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.append(buf)
    }

    fn sync_data(&self) -> io::Result<()> {
        if let Some(gate) = &self.gate {
            gate.pass();
        }
        self.file.sync_data()
    }

    fn size(&self) -> io::Result<u64> {
        self.file.size()
    }
}

impl FileSystem for GatedFs {
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Box<dyn File>> {
        let file = self.fs.open(path, mode)?;
        let gate = path.starts_with(LOG_DIR).then(|| Arc::clone(&self.gate));
        Ok(Box::new(GatedFile { file, gate }))
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.fs.create_dir_all(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.fs.rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.fs.remove_file(path)
    }

    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        self.fs.hard_link(original, link)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.fs.read_dir(path)
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        self.fs.sync_dir(path)
    }
}

/// Runs `f` on its own thread and returns its result; fails if it takes longer than [`LIMIT`].
fn within<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(LIMIT)
        .unwrap_or_else(|_| panic!("{what} waited for the log sync in progress"))
}

#[test]
fn tc_txn_004_proposals_and_reads_do_not_wait_for_the_sync_in_progress() {
    let gate = Arc::new(Gate::default());
    let fs = Arc::new(GatedFs {
        fs: Arc::new(SimFileSystem::new()),
        gate: Arc::clone(&gate),
    });
    let store = Arc::new(open_on(fs, LSM_DIR).unwrap());
    store.replica.propose_unsynced(command(&put(1), 1)).unwrap();
    gate.set_closed(true);
    let first = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || store.replica.sync_through(1))
    };
    gate.wait_for_sync();

    // The fsync of entry 1 is running. A new proposal applies at once ...
    let state = {
        let store = Arc::clone(&store);
        within("a proposal", move || {
            store.replica.propose_unsynced(command(&put(2), 2))
        })
    }
    .unwrap();
    assert_eq!(state.applied_index, 2);
    // ... readers see it, the applied state and what they have to wait for ...
    let seen = {
        let store = Arc::clone(&store);
        within("a read", move || {
            (
                store.engine.get(&key(2), None).unwrap(),
                store.replica.applied_index(),
                store.replica.unsynced_index(),
            )
        })
    };
    assert_eq!(seen.0.as_deref(), Some(&[2][..]));
    assert_eq!((seen.1, seen.2), (2, Some(2)));
    // ... and its sync waits for the one in progress, then carries what was applied meanwhile.
    let second = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || store.replica.sync_through(2))
    };
    store.replica.propose_unsynced(command(&put(3), 3)).unwrap();
    assert_eq!(store.replica.unsynced_index(), Some(3));

    gate.set_closed(false);
    first.join().unwrap().unwrap();
    second.join().unwrap().unwrap();
    // Entries 2 and 3 went out in the second record.
    assert_eq!(store.replica.unsynced_index(), None);
    assert_eq!(store.replica.log_bounds(), (1, 3));
}
