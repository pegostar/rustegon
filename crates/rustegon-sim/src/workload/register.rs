// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Elle rw-register workload on the single-range coordinator, with optional seeded faults
//! (TC-TXN-001; FR-TXN-001/002). See the parent module for the execution model.
//!
//! # Workload
//! `clients` clients each run planned transactions of 1–4 operations, each a read or a write of
//! one of `registers` registers. Every written value is unique in the whole history (one global
//! counter, never reused by a retry), so a read names its writer and the checker can infer wr
//! edges and, with `WritesFollowReads`, part of the version order.
//!
//! # Recording (the client's view, Elle's `ok` / `fail` / `info`)
//! One history transaction per **attempt**:
//! - `Ok`: `commit` returned. Its interval is `[begin, acknowledgement]` on a logical clock that
//!   ticks at every begin and acknowledgement.
//! - `Fail`: the attempt ended before its commit proposal (any error from an operation, a commit
//!   error other than `RGN-2006`, an abandoned attempt at a crash). Such an attempt can never
//!   commit: only the commit command turns intents into versions, and a restart starts a new
//!   epoch whose predecessor's intents never commit. Its writes are recorded, so a committed read
//!   of one of them is reported as G1a.
//! - `Info`: `commit` returned `RGN-2006` (the proposal failed after it may have been logged).
//!   The driver then reopens the store; the recovery read decides the outcome — all its writes
//!   visible: it committed (recorded as `Ok` without an acknowledgement time); none visible: it
//!   did not (`Fail`); some visible: **partial commit**, an atomicity violation. Exactly one
//!   commit can be in doubt per store epoch: the failed proposal poisons the log (or the file
//!   system is halted), and the reopen follows in the same step.
//!
//! # Retries
//! `RGN-2001` restarts the same transaction (next epoch, `Txn::restart`, which keeps its older
//! intents as locks); other retryable aborts (`RGN-2002` conflict / deadlock / `timeout_pushed`,
//! `RGN-2005`, `RGN-2008`) and storage errors start a new transaction for the same plan; a
//! plan is abandoned after [`MAX_ATTEMPTS`] attempts. `RGN-2003` (the transaction's own timeout)
//! abandons the plan.
//!
//! # Faults (seeded, at most one armed at a time)
//! Before each step, with small probabilities: arm a crash point (`halt_after_ops`; the next
//! mutating file operations fail, then the store is power-cut in a seeded [`CrashMode`] and
//! reopened), arm an I/O error (`EIO` on the next `sync` or `append`, then power cut and reopen),
//! cut the power now, restart the process now (reopen without losing unsynced data), or pause
//! the clients for twice the liveness timeout (their transactions expire and are pushed). Some
//! plans get a short transaction timeout (`RGN-2003`).
//!
//! # Invariants checked after every reopen and at the end
//! - **Durability / no resurrection**: the recovery read of every register returns exactly the
//!   value of the last committed write (acknowledged, or in-doubt resolved as committed), or nil.
//!   Per register, commit order equals acknowledgement order: a write to a register held by
//!   another open transaction's intent waits for it (see the scheduler), so two transactions are
//!   never both writing one register.
//! - **Atomicity** of the in-doubt commit (above).
//! - **Status after a restart** (FR-TXN-005/006, PD-121): before the recovery read, every
//!   attempt of the ended store epoch is asked for its persisted outcome
//!   (`TxnCoordinator::orphan_status`, which durably aborts expired `PENDING` records, as
//!   `TransactionService.Status` does). An attempt that committed (acknowledged, or in doubt and
//!   resolved committed) must have no outcome at all (its record went with its commit): it is
//!   never reported aborted. The recovery read then runs on the store those aborts changed.
//! - **Commit timestamps** of acknowledged writes increase per register (MVCC monotonicity).
//! - The whole history passes the Elle checker at the strongest model the isolation level
//!   promises (transaction-management.md §4.2): SERIALIZABLE → serializable and strict
//!   serializable (all transactions share the registers, and on one node the HLC orders every
//!   transaction after the acknowledged ones), SNAPSHOT → snapshot isolation, READ COMMITTED →
//!   read committed. Checker limits respected: lost update is flagged from SNAPSHOT up only;
//!   rw-register cannot order blind writes (G0 and most G2 are invisible here).

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use rustegon_mvcc::Timestamp;
use rustegon_txn::{
    AbortReason, Isolation, OrphanStatus, Txn as DbTxn, TxnConfig, TxnError, TxnOptions,
};

use super::{
    clock::SimClock,
    isolation_name,
    rng::{SimRng, mix},
    store::{Store, register_key},
};
use crate::{
    CrashMode, SimFileSystem,
    checker::{
        self, Anomaly, CheckOptions, CheckReport, ConsistencyModel, History, HistoryError, Key, Op,
        Outcome, Txn, TxnId, Value,
    },
};

/// Virtual start time: 2026-01-01T00:00:00Z.
const START: Duration = Duration::from_hours(490_896);
/// Base clock tick per reading (see `clock.rs`).
const TICK: Duration = Duration::from_micros(10);
/// `txn.liveness_timeout` of the workload: long against a client action (microseconds of
/// virtual time), short enough that a pause or a forced wait expires holders quickly.
const LIVENESS: Duration = Duration::from_millis(50);
/// Clock advance per reading in a wait loop (`clock.rs`): a wait iteration makes 2–3 readings,
/// so the waiter's heartbeat gap stays below [`LIVENESS`] while the holder's idleness grows.
const STALL_TICK: Duration = Duration::from_millis(10);
/// Real-time slice of the coordinator's wait loop: zero. Waits only happen when every client is
/// blocked (a forced wait); nothing can wake the waiter but virtual time, so it spins on the
/// clock instead of sleeping (which would also make the run's speed depend on the OS timer).
const WAIT_SLICE: Duration = Duration::ZERO;
/// Steps between two maintenance runs (flush, compact, purge).
const MAINTENANCE_EVERY: u64 = 32;
/// Attempts of one plan before it is abandoned.
pub const MAX_ATTEMPTS: u32 = 25;
/// Attempts of the recovery read.
const READ_ALL_ATTEMPTS: u32 = 50;
/// Steps allowed per planned transaction before the run stops planning (a liveness guard; the
/// workload normally needs fewer than ten).
const STEPS_PER_TXN: u64 = 200;

/// Parameters of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterConfig {
    /// Seed of every random choice of the run.
    pub seed: u64,
    /// Isolation level of every transaction.
    pub isolation: Isolation,
    /// Whether to inject faults.
    pub faults: bool,
    /// Number of registers (keys).
    pub registers: u64,
    /// Concurrent clients.
    pub clients: usize,
    /// Planned transactions.
    pub txns: usize,
    /// After an injected `EIO`, sometimes restart the process instead of cutting the power.
    ///
    /// On by default. It found a recovery bug of the Raft log store (M2 T10): `LogStore::open`
    /// accepted the readable but never-synced tail a failed sync left in the last segment, then
    /// started a new segment without syncing the old one; a later power cut tore that tail and
    /// the next open failed with `RGN-5002` or reported a gap. Fixed by syncing every recovered
    /// segment at open (`rustegon-raft` `recovery::sync_recovered`); `tests/workload.rs` keeps
    /// a regression test (seed `0xa`).
    pub io_restart: bool,
}

impl RegisterConfig {
    /// Default sizes: 4 registers, 4 clients, 150 transactions.
    #[must_use]
    pub fn new(seed: u64, isolation: Isolation, faults: bool) -> Self {
        Self {
            seed,
            isolation,
            faults,
            registers: 4,
            clients: 4,
            txns: 150,
            io_restart: true,
        }
    }

    /// The workload name used by the CLI.
    #[must_use]
    pub fn workload_name(&self) -> &'static str {
        if self.faults {
            "rw-register-faults"
        } else {
            "rw-register"
        }
    }

    /// The command line that reruns exactly this configuration.
    #[must_use]
    pub fn reproduce_command(&self) -> String {
        format!(
            "cargo run -p rustegon-sim -- --workload {} --isolation {} --seed {:#x} \
             --registers {} --clients {} --txns {}{}",
            self.workload_name(),
            isolation_name(self.isolation),
            self.seed,
            self.registers,
            self.clients,
            self.txns,
            if self.io_restart { " --io-restart" } else { "" }
        )
    }
}

/// Counters of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunStats {
    /// Driver steps.
    pub steps: u64,
    /// Acknowledged commits (excluding recovery reads).
    pub committed: u64,
    /// Attempts recorded as failed.
    pub failed: u64,
    /// Commits with unknown outcome (`RGN-2006`).
    pub indeterminate: u64,
    /// In-doubt commits found committed at recovery.
    pub resolved_committed: u64,
    /// In-doubt commits found not committed at recovery.
    pub resolved_aborted: u64,
    /// `RGN-2001` restarts.
    pub conflict_restarts: u64,
    /// Attempts aborted because their heartbeat expired (`timeout_pushed`).
    pub expired: u64,
    /// Attempts that exceeded their own timeout (`RGN-2003`).
    pub timeouts: u64,
    /// Plans abandoned after [`MAX_ATTEMPTS`] attempts.
    pub abandoned: u64,
    /// Steps where every client was blocked and one was run into a wait anyway.
    pub forced_waits: u64,
    /// Steps where every client was blocked and one rolled back.
    pub client_rollbacks: u64,
    /// Power cuts (`SimFileSystem::crash`).
    pub crashes: u64,
    /// Reopens without power loss.
    pub process_restarts: u64,
    /// Armed crash points.
    pub crash_points: u64,
    /// Injected I/O errors.
    pub io_faults: u64,
    /// Client pauses.
    pub pauses: u64,
    /// Maintenance runs.
    pub maintenance: u64,
    /// Attempts of an ended store epoch whose persisted outcome was `ABORTED` after the reopen.
    pub orphans_aborted: u64,
}

impl RunStats {
    /// Adds `other` into `self`.
    pub fn add(&mut self, other: &Self) {
        self.steps += other.steps;
        self.committed += other.committed;
        self.failed += other.failed;
        self.indeterminate += other.indeterminate;
        self.resolved_committed += other.resolved_committed;
        self.resolved_aborted += other.resolved_aborted;
        self.conflict_restarts += other.conflict_restarts;
        self.expired += other.expired;
        self.timeouts += other.timeouts;
        self.abandoned += other.abandoned;
        self.forced_waits += other.forced_waits;
        self.client_rollbacks += other.client_rollbacks;
        self.crashes += other.crashes;
        self.process_restarts += other.process_restarts;
        self.crash_points += other.crash_points;
        self.io_faults += other.io_faults;
        self.pauses += other.pauses;
        self.maintenance += other.maintenance;
        self.orphans_aborted += other.orphans_aborted;
    }
}

/// Result of a successful run.
#[derive(Debug, Clone)]
pub struct RunReport {
    /// The configuration run.
    pub config: RegisterConfig,
    /// The recorded history.
    pub history: History,
    /// Counters.
    pub stats: RunStats,
    /// One checker report per model checked (all valid).
    pub reports: Vec<CheckReport>,
}

/// Why a run failed.
#[derive(Debug, Clone)]
pub enum FailureKind {
    /// The checker found anomalies the model forbids.
    Anomalies {
        /// The model violated.
        model: ConsistencyModel,
        /// The forbidden anomalies.
        forbidden: Vec<Anomaly>,
    },
    /// After a reopen a register does not hold the last committed value: an acknowledged write
    /// was lost, or a write that never committed became visible.
    RecoveryMismatch {
        /// The register.
        key: Key,
        /// The last committed value (`None`: never written).
        expected: Option<Value>,
        /// What the recovery read returned.
        found: Option<Value>,
    },
    /// An in-doubt commit is visible on some of its registers only.
    PartialCommit {
        /// The history transaction.
        txn: TxnId,
        /// Registers showing its write.
        visible: Vec<Key>,
        /// Registers not showing it.
        missing: Vec<Key>,
    },
    /// Two acknowledged writes of one register did not get increasing commit timestamps.
    TimestampOrder {
        /// The register.
        key: Key,
        /// Commit timestamp of the earlier acknowledged write.
        earlier: Timestamp,
        /// Commit timestamp of the later one.
        later: Timestamp,
    },
    /// A committed transaction still had a persisted outcome after a reopen (it could be
    /// reported aborted, PD-121).
    CommittedOrphan {
        /// The history transaction.
        txn: TxnId,
        /// The outcome found.
        found: OrphanStatus,
    },
    /// The store could not be (re)opened or read after a reopen.
    Recovery(String),
    /// An error the workload does not expect (a bug, or a storage error without a fault).
    Unexpected(String),
    /// The recorded history is malformed (a workload bug).
    History(HistoryError),
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anomalies { model, forbidden } => {
                write!(f, "{} anomalies forbidden by {model:?}:", forbidden.len())?;
                for a in forbidden.iter().take(5) {
                    write!(f, "\n    {a:?}")?;
                }
                Ok(())
            }
            Self::RecoveryMismatch {
                key,
                expected,
                found,
            } => write!(
                f,
                "after reopen register {key} holds {found:?}, last committed value {expected:?}"
            ),
            Self::PartialCommit {
                txn,
                visible,
                missing,
            } => write!(
                f,
                "in-doubt transaction {txn} partially committed: visible on {visible:?}, \
                 missing on {missing:?}"
            ),
            Self::TimestampOrder {
                key,
                earlier,
                later,
            } => write!(
                f,
                "register {key}: acknowledged write at {later:?} after one at {earlier:?}"
            ),
            Self::CommittedOrphan { txn, found } => write!(
                f,
                "committed transaction {txn} has persisted outcome {found:?} after reopen"
            ),
            Self::Recovery(msg) => write!(f, "recovery failed: {msg}"),
            Self::Unexpected(msg) => write!(f, "unexpected error: {msg}"),
            Self::History(e) => write!(f, "malformed history: {e}"),
        }
    }
}

/// A failed run, with what is needed to reproduce it.
#[derive(Debug, Clone)]
pub struct Failure {
    /// The configuration that failed (its seed reproduces the run).
    pub config: RegisterConfig,
    /// What went wrong.
    pub kind: FailureKind,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} workload failed (seed {:#x}, isolation {}): {}\n  reproduce: {}",
            self.config.workload_name(),
            self.config.seed,
            isolation_name(self.config.isolation),
            self.kind,
            self.config.reproduce_command()
        )
    }
}

impl std::error::Error for Failure {}

/// The models a history of `isolation` must satisfy (module docs).
#[must_use]
pub fn models(isolation: Isolation) -> &'static [ConsistencyModel] {
    match isolation {
        Isolation::Serializable => &[
            ConsistencyModel::Serializable,
            ConsistencyModel::StrictSerializable,
        ],
        Isolation::Snapshot => &[ConsistencyModel::Snapshot],
        Isolation::ReadCommitted => &[ConsistencyModel::ReadCommitted],
    }
}

/// Runs the rw-register workload described by `config` and checks it.
///
/// # Errors
/// A [`Failure`] naming the seed and the reproduction command.
pub fn run_rw_register(config: &RegisterConfig) -> Result<RunReport, Failure> {
    let fail = |kind| Failure {
        config: config.clone(),
        kind,
    };
    let mut driver = Driver::new(config.clone()).map_err(fail)?;
    driver.run().map_err(fail)?;
    let Driver { history, stats, .. } = driver;
    let history = History::new(history);
    let mut reports = Vec::new();
    for &model in models(config.isolation) {
        let report = checker::check(&history, &CheckOptions::new(model))
            .map_err(|e| fail(FailureKind::History(e)))?;
        if !report.is_valid() {
            return Err(fail(FailureKind::Anomalies {
                model,
                forbidden: report.forbidden,
            }));
        }
        reports.push(report);
    }
    Ok(RunReport {
        config: config.clone(),
        history,
        stats,
        reports,
    })
}

/// One operation of a plan.
#[derive(Debug, Clone, Copy)]
enum Step {
    Read(Key),
    Write(Key),
}

impl Step {
    fn key(self) -> Key {
        match self {
            Self::Read(k) | Self::Write(k) => k,
        }
    }
}

/// A planned transaction, retried until it commits or is abandoned.
#[derive(Debug)]
struct Plan {
    steps: Vec<Step>,
    attempts: u32,
    timeout: Option<Duration>,
}

/// The attempt in progress: what the client has observed so far.
#[derive(Debug)]
struct Attempt {
    id: TxnId,
    /// The engine transaction of the attempt.
    engine: [u8; 16],
    start: u64,
    next: usize,
    ops: Vec<Op>,
}

#[derive(Default)]
struct Client {
    plan: Option<Plan>,
    txn: Option<DbTxn>,
    attempt: Option<Attempt>,
    /// Registers on which the open transaction may hold intents, over all its epochs (a
    /// restart keeps older intents as locks). Over-approximate: a failed write counts.
    held: BTreeSet<Key>,
}

/// An armed fault that has not taken effect yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Armed {
    Halt,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reopen {
    /// Process restart: unsynced data survives (unless a fault forces a power cut).
    Restart,
    /// Power cut.
    PowerLoss,
}

/// The single-threaded workload driver (module docs).
struct Driver {
    config: RegisterConfig,
    rng: SimRng,
    fs: Arc<SimFileSystem>,
    clock: Arc<SimClock>,
    txn_config: TxnConfig,
    store: Option<Store>,
    store_epoch: u64,
    clients: Vec<Client>,
    history: Vec<Txn>,
    next_value: Value,
    next_id: TxnId,
    /// Logical real-time clock of the history (ticks at begins and acknowledgements).
    time: u64,
    planned: usize,
    /// Last committed value per register (absent: never written).
    latest: BTreeMap<Key, Value>,
    /// Commit timestamp of the last acknowledged write per register.
    last_commit_ts: BTreeMap<Key, Timestamp>,
    /// History indices of in-doubt commits of the current store epoch.
    in_doubt: Vec<usize>,
    /// History index and engine transaction of every attempt recorded in the current store
    /// epoch.
    epoch_attempts: Vec<(usize, [u8; 16])>,
    armed: Option<Armed>,
    needs_reopen: bool,
    stats: RunStats,
}

impl Driver {
    fn new(config: RegisterConfig) -> Result<Self, FailureKind> {
        let fs = Arc::new(SimFileSystem::new());
        let clock = Arc::new(SimClock::new(START, TICK, STALL_TICK));
        let txn_config = TxnConfig {
            liveness_timeout: LIVENESS,
            heartbeat_interval: LIVENESS / 5,
            wait_slice: WAIT_SLICE,
            ..TxnConfig::default()
        };
        let store = Store::open(&fs, &clock, txn_config.clone(), mix(config.seed ^ 1))
            .map_err(|e| FailureKind::Recovery(format!("initial open: {e}")))?;
        let clients = (0..config.clients).map(|_| Client::default()).collect();
        Ok(Self {
            rng: SimRng::new(config.seed),
            config,
            fs,
            clock,
            txn_config,
            store: Some(store),
            store_epoch: 1,
            clients,
            history: Vec::new(),
            next_value: 1,
            next_id: 0,
            time: 0,
            planned: 0,
            latest: BTreeMap::new(),
            last_commit_ts: BTreeMap::new(),
            in_doubt: Vec::new(),
            epoch_attempts: Vec::new(),
            armed: None,
            needs_reopen: false,
            stats: RunStats::default(),
        })
    }

    fn run(&mut self) -> Result<(), FailureKind> {
        let max_steps = STEPS_PER_TXN.saturating_mul(self.config.txns as u64);
        while !self.done() && self.stats.steps < max_steps {
            self.step()?;
        }
        // A final restart checks that everything acknowledged survives it (a power cut if a
        // fault is still armed: only a crash clears it).
        self.reopen(Reopen::Restart)
    }

    fn done(&self) -> bool {
        self.planned >= self.config.txns && self.clients.iter().all(|c| c.plan.is_none())
    }

    fn step(&mut self) -> Result<(), FailureKind> {
        self.stats.steps += 1;
        self.clock.begin_step();
        if self.config.faults {
            self.inject_fault()?;
        }
        if self.stats.steps.is_multiple_of(MAINTENANCE_EVERY) {
            self.maintain()?;
        }
        if !self.needs_reopen
            && !self.fs.is_halted()
            && let Some(c) = self.pick_client()?
        {
            // Stalled readings are for waits inside one client action only (clock.rs).
            self.clock.begin_step();
            self.advance(c)?;
        }
        if self.needs_reopen || self.fs.is_halted() {
            self.reopen(Reopen::Restart)?;
        }
        Ok(())
    }

    fn store(&self) -> Result<&Store, FailureKind> {
        self.store
            .as_ref()
            .ok_or_else(|| FailureKind::Unexpected("store not open".into()))
    }

    fn tick(&mut self) -> u64 {
        self.time += 1;
        self.time
    }

    fn new_attempt(&mut self, engine: [u8; 16]) -> Attempt {
        let id = self.next_id;
        self.next_id += 1;
        Attempt {
            id,
            engine,
            start: self.tick(),
            next: 0,
            ops: Vec::new(),
        }
    }

    /// Whether storage errors are explained by an injected fault.
    fn fault_active(&self) -> bool {
        self.armed.is_some() || self.fs.is_halted()
    }

    // ---- faults ------------------------------------------------------------------------------

    fn inject_fault(&mut self) -> Result<(), FailureKind> {
        if self.armed.is_some() || self.needs_reopen {
            return Ok(());
        }
        let r = self.rng.below(1000);
        if r < 10 {
            // Crash point: one of the next few mutating file operations fails, and so does
            // every later one, until the power cut of the reopen.
            self.fs.halt_after_ops(self.rng.below(24));
            self.armed = Some(Armed::Halt);
            self.stats.crash_points += 1;
        } else if r < 18 {
            if self.rng.below(2) == 0 {
                self.fs.fail_next_syncs(1);
            } else {
                self.fs.fail_next_appends(1);
            }
            self.armed = Some(Armed::Io);
            self.stats.io_faults += 1;
        } else if r < 23 {
            self.reopen(Reopen::PowerLoss)?;
        } else if r < 28 {
            self.reopen(Reopen::Restart)?;
        } else if r < 40 {
            // The clients stall: every open transaction misses its heartbeat and is aborted by
            // the next one meeting its intents, or by itself on its next operation.
            self.clock.advance(LIVENESS * 2);
            self.stats.pauses += 1;
        }
        Ok(())
    }

    fn maintain(&mut self) -> Result<(), FailureKind> {
        self.stats.maintenance += 1;
        if let Err(e) = self.store()?.maintain() {
            if !self.fault_active() {
                return Err(FailureKind::Unexpected(format!(
                    "maintenance failed without an injected fault: {e}"
                )));
            }
            self.needs_reopen = true;
        }
        Ok(())
    }

    /// Drops the store and reopens it: a process restart, or a power cut when asked for or
    /// when a fault is armed or has fired. Then verifies the recovered state (module docs).
    fn reopen(&mut self, kind: Reopen) -> Result<(), FailureKind> {
        // Open attempts never reached their commit proposal (commit is synchronous): they are
        // definitely not committed. Dropping their handles runs the coordinator's cleanup
        // against the old store; when that fails, their intents stay behind with PENDING
        // records and are resolved as aborted once expired.
        for c in 0..self.clients.len() {
            if let Some(attempt) = self.clients[c].attempt.take() {
                self.record(attempt, Outcome::Fail, None);
            }
            if self.clients[c].txn.is_some() {
                self.drop_txn(c);
                self.retry_plan(c);
            }
        }
        // Exactly one coordinator may serve a replica; the old one goes with the old store.
        self.store = None;
        // A halt and an unconsumed I/O fault can only be cleared by a power cut. After an I/O
        // error that has fired (it is what asked for the reopen), `io_restart` also allows a
        // process restart, which keeps the unsynced bytes of the failed write: an in-doubt
        // commit can then turn out committed (see `RegisterConfig::io_restart`).
        let power_cut = match (kind, self.armed) {
            (Reopen::PowerLoss, _) | (_, Some(Armed::Halt)) => true,
            (Reopen::Restart, Some(Armed::Io)) => {
                !(self.config.io_restart && self.needs_reopen && self.rng.below(2) == 0)
            }
            (Reopen::Restart, None) => self.fs.is_halted(),
        };
        if power_cut {
            let mode = CrashMode::ALL[self.rng.index(CrashMode::ALL.len())];
            self.fs.crash(self.rng.next(), mode);
            self.stats.crashes += 1;
        } else {
            self.stats.process_restarts += 1;
        }
        self.armed = None;
        self.needs_reopen = false;
        // Downtime: records of transactions interrupted by the reopen expire, so the first
        // reader resolves their intents instead of waiting for them.
        self.clock.advance(LIVENESS * 2);
        self.store_epoch += 1;
        let seed = mix(self.config.seed ^ self.store_epoch);
        let store =
            Store::open(&self.fs, &self.clock, self.txn_config.clone(), seed).map_err(|e| {
                FailureKind::Recovery(format!(
                    "reopen #{} ({}): {e}",
                    self.store_epoch,
                    if power_cut { "power cut" } else { "restart" }
                ))
            })?;
        self.store = Some(store);
        self.verify_recovery()
    }

    /// Reads every register, resolves the in-doubt commit of the epoch and checks durability.
    fn verify_recovery(&mut self) -> Result<(), FailureKind> {
        let mut orphans = Vec::new();
        for (idx, engine) in std::mem::take(&mut self.epoch_attempts) {
            let status = self.store()?.co.orphan_status(&engine).map_err(|e| {
                FailureKind::Recovery(format!("status of an attempt after reopen: {e}"))
            })?;
            if let Some(status) = status {
                orphans.push((idx, status));
            }
        }
        let observed = self.read_all()?;
        for idx in std::mem::take(&mut self.in_doubt) {
            let writes = final_writes(&self.history[idx].ops);
            let (visible, missing): (Vec<Key>, Vec<Key>) = writes
                .keys()
                .copied()
                .partition(|k| observed.get(k).copied().flatten() == writes.get(k).copied());
            if visible.is_empty() {
                self.history[idx].outcome = Outcome::Fail;
                self.stats.resolved_aborted += 1;
            } else if missing.is_empty() {
                // Committed: its reads are real observations; it has no acknowledgement time.
                self.history[idx].outcome = Outcome::Ok;
                self.latest.extend(writes);
                self.stats.resolved_committed += 1;
            } else {
                return Err(FailureKind::PartialCommit {
                    txn: self.history[idx].id,
                    visible,
                    missing,
                });
            }
        }
        for (idx, found) in orphans {
            if self.history[idx].outcome == Outcome::Ok {
                return Err(FailureKind::CommittedOrphan {
                    txn: self.history[idx].id,
                    found,
                });
            }
            if found == OrphanStatus::Aborted {
                self.stats.orphans_aborted += 1;
            }
        }
        for key in 0..self.config.registers {
            let expected = self.latest.get(&key).copied();
            let found = observed.get(&key).copied().flatten();
            if expected != found {
                return Err(FailureKind::RecoveryMismatch {
                    key,
                    expected,
                    found,
                });
            }
        }
        Ok(())
    }

    /// One read-only transaction over all registers, recorded in the history.
    fn read_all(&mut self) -> Result<BTreeMap<Key, Option<Value>>, FailureKind> {
        let options = TxnOptions::with_isolation(self.config.isolation);
        let mut last_error = String::new();
        for _ in 0..READ_ALL_ATTEMPTS {
            // The reopen made many clock readings in this step: without a fresh step the
            // stall tick would expire the reader between its own operations.
            self.clock.begin_step();
            let mut txn = self.store()?.co.begin(options.clone());
            let attempt = self.new_attempt(txn.id());
            let mut ops = Vec::new();
            let mut seen = BTreeMap::new();
            let mut error = None;
            for key in 0..self.config.registers {
                match txn.get(&register_key(key)) {
                    Ok(v) => {
                        let v = decode(key, v.as_deref())?;
                        ops.push(Op::read_register(key, v));
                        seen.insert(key, v);
                    }
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                }
            }
            if error.is_none() {
                error = txn.commit().err();
            }
            match error {
                None => {
                    let end = self.tick();
                    self.history.push(
                        Txn::new(attempt.id, Outcome::Ok, ops).with_time(attempt.start, Some(end)),
                    );
                    return Ok(seen);
                }
                Some(e) if e.is_retryable() => last_error = e.to_string(),
                Some(e) => {
                    return Err(FailureKind::Recovery(format!(
                        "reading the registers after reopen: {e}"
                    )));
                }
            }
        }
        Err(FailureKind::Recovery(format!(
            "reading the registers after reopen: {READ_ALL_ATTEMPTS} attempts, last: {last_error}"
        )))
    }

    // ---- scheduling --------------------------------------------------------------------------

    /// Chooses the client to advance. A client whose next operation would wait for another
    /// client's intent is not runnable: on one thread that wait could only end by expiring the
    /// holder. If every client with work is blocked (a deadlock among clients), either one is
    /// run into the wait anyway — it ends when the stalling clock expires the holder, which
    /// exercises the liveness push of §5.1 — or one rolls back, as a client-side timeout would.
    fn pick_client(&mut self) -> Result<Option<usize>, FailureKind> {
        let can_plan = self.planned < self.config.txns;
        let mut runnable = Vec::new();
        let mut blocked = Vec::new();
        for (i, c) in self.clients.iter().enumerate() {
            if c.plan.is_none() {
                if can_plan {
                    runnable.push(i);
                }
            } else if self.is_blocked(i) {
                blocked.push(i);
            } else {
                runnable.push(i);
            }
        }
        if !runnable.is_empty() {
            return Ok(Some(runnable[self.rng.index(runnable.len())]));
        }
        if blocked.is_empty() {
            return Ok(None);
        }
        let c = blocked[self.rng.index(blocked.len())];
        if self.rng.below(2) == 0 {
            self.stats.forced_waits += 1;
            return Ok(Some(c));
        }
        self.stats.client_rollbacks += 1;
        if let Some(attempt) = self.clients[c].attempt.take() {
            self.record(attempt, Outcome::Fail, None);
        }
        if let Some(txn) = self.clients[c].txn.as_mut()
            && let Err(e) = txn.rollback()
        {
            self.storage_error(&e)?;
        }
        self.drop_txn(c);
        self.retry_plan(c);
        Ok(None)
    }

    /// Whether client `i`'s next operation would wait (conservatively): another client's open
    /// transaction may hold an intent on the register and does not have a lower priority (a
    /// strictly higher-priority reader pushes the holder's timestamp, a writer aborts it, §5.1).
    fn is_blocked(&self, i: usize) -> bool {
        let c = &self.clients[i];
        let (Some(plan), Some(txn), Some(attempt)) = (&c.plan, &c.txn, &c.attempt) else {
            return false;
        };
        let Some(step) = plan.steps.get(attempt.next) else {
            return false; // commit never waits in a single range
        };
        let key = step.key();
        let mine = txn.priority();
        self.clients.iter().enumerate().any(|(j, o)| {
            j != i && o.held.contains(&key) && o.txn.as_ref().is_some_and(|t| t.priority() >= mine)
        })
    }

    // ---- client actions ----------------------------------------------------------------------

    fn advance(&mut self, c: usize) -> Result<(), FailureKind> {
        if self.clients[c].plan.is_none() {
            let plan = self.new_plan();
            self.clients[c].plan = Some(plan);
            self.planned += 1;
        }
        if self.clients[c].txn.is_none() {
            let timeout = self.clients[c].plan.as_ref().and_then(|p| p.timeout);
            let options = TxnOptions {
                timeout,
                ..TxnOptions::with_isolation(self.config.isolation)
            };
            let txn = self.store()?.co.begin(options);
            let attempt = self.new_attempt(txn.id());
            let client = &mut self.clients[c];
            client.txn = Some(txn);
            client.attempt = Some(attempt);
            return Ok(());
        }
        let next = {
            let client = &self.clients[c];
            let (Some(plan), Some(attempt)) = (&client.plan, &client.attempt) else {
                return Err(FailureKind::Unexpected("client without attempt".into()));
            };
            plan.steps.get(attempt.next).copied()
        };
        match next {
            Some(step) => self.execute(c, step),
            None => self.commit(c),
        }
    }

    fn new_plan(&mut self) -> Plan {
        let n = 1 + self.rng.below(4);
        let steps = (0..n)
            .map(|_| {
                let key = self.rng.below(self.config.registers);
                if self.rng.below(2) == 0 {
                    Step::Read(key)
                } else {
                    Step::Write(key)
                }
            })
            .collect();
        let timeout = (self.config.faults && self.rng.chance(40))
            .then(|| Duration::from_micros(300 + self.rng.below(3000)));
        Plan {
            steps,
            attempts: 0,
            timeout,
        }
    }

    fn execute(&mut self, c: usize, step: Step) -> Result<(), FailureKind> {
        let key = step.key();
        let k = register_key(key);
        let value = match step {
            Step::Read(_) => None,
            Step::Write(_) => {
                let v = self.next_value;
                self.next_value += 1;
                Some(v)
            }
        };
        let client = &mut self.clients[c];
        let (Some(txn), Some(attempt)) = (client.txn.as_mut(), client.attempt.as_mut()) else {
            return Err(FailureKind::Unexpected("client without transaction".into()));
        };
        let result = match value {
            None => match txn.get(&k) {
                Ok(read) => {
                    let read = decode(key, read.as_deref())?;
                    attempt.ops.push(Op::read_register(key, read));
                    Ok(())
                }
                Err(e) => Err(e),
            },
            Some(v) => {
                // Recorded before the call: if it fails, the attempt is a Fail with this write,
                // which no committed read may ever observe.
                attempt.ops.push(Op::write(key, v));
                client.held.insert(key);
                txn.put(&k, v.to_be_bytes().to_vec())
            }
        };
        match result {
            Ok(()) => {
                attempt.next += 1;
                Ok(())
            }
            Err(e) => self.on_error(c, &e, false),
        }
    }

    fn commit(&mut self, c: usize) -> Result<(), FailureKind> {
        let result = match self.clients[c].txn.as_mut() {
            Some(txn) => txn.commit(),
            None => return Err(FailureKind::Unexpected("commit without transaction".into())),
        };
        let info = match result {
            Ok(info) => info,
            Err(e) => return self.on_error(c, &e, true),
        };
        let Some(attempt) = self.clients[c].attempt.take() else {
            return Err(FailureKind::Unexpected("commit without attempt".into()));
        };
        for (key, value) in final_writes(&attempt.ops) {
            if let Some(&earlier) = self.last_commit_ts.get(&key)
                && earlier >= info.commit_ts
            {
                return Err(FailureKind::TimestampOrder {
                    key,
                    earlier,
                    later: info.commit_ts,
                });
            }
            self.last_commit_ts.insert(key, info.commit_ts);
            self.latest.insert(key, value);
        }
        let end = self.tick();
        self.record(attempt, Outcome::Ok, Some(end));
        self.stats.committed += 1;
        self.drop_txn(c);
        self.clients[c].plan = None;
        Ok(())
    }

    /// Handles a failed operation or commit of client `c` (module docs, "Recording", "Retries").
    fn on_error(&mut self, c: usize, err: &TxnError, in_commit: bool) -> Result<(), FailureKind> {
        let attempt = self.clients[c].attempt.take();
        if in_commit && matches!(err, TxnError::CommitOutcomeUnknown(_)) {
            self.storage_error(err)?;
            if let Some(attempt) = attempt {
                self.in_doubt.push(self.history.len());
                self.record(attempt, Outcome::Info, None);
            }
            self.stats.indeterminate += 1;
            self.drop_txn(c);
            self.clients[c].plan = None;
            self.needs_reopen = true;
            return Ok(());
        }
        if let Some(attempt) = attempt {
            self.record(attempt, Outcome::Fail, None);
        }
        match err {
            TxnError::Mvcc(_) | TxnError::Replica(_) | TxnError::CommitOutcomeUnknown(_) => {
                self.storage_error(err)?;
                self.needs_reopen = true;
                self.drop_txn(c);
                self.retry_plan(c);
            }
            TxnError::Conflict(_) => {
                self.stats.conflict_restarts += 1;
                let restarted = self.clients[c]
                    .txn
                    .as_mut()
                    .and_then(|t| t.restart().is_ok().then(|| t.id()));
                if let Some(engine) = restarted {
                    let attempt = self.new_attempt(engine);
                    self.clients[c].attempt = Some(attempt);
                    self.count_attempt(c);
                } else {
                    self.drop_txn(c);
                    self.retry_plan(c);
                }
            }
            TxnError::Aborted { reason } => {
                if *reason == AbortReason::TimeoutPushed {
                    self.stats.expired += 1;
                }
                self.drop_txn(c);
                if reason.retryable() {
                    self.retry_plan(c);
                } else {
                    self.clients[c].plan = None;
                }
            }
            TxnError::Deadlock | TxnError::WriteTooOld { .. } => {
                self.drop_txn(c);
                self.retry_plan(c);
            }
            TxnError::Timeout { .. } => {
                self.stats.timeouts += 1;
                self.drop_txn(c);
                self.clients[c].plan = None;
            }
            other => {
                return Err(FailureKind::Unexpected(format!(
                    "client {c}: {other} (code {})",
                    other.code().code()
                )));
            }
        }
        Ok(())
    }

    /// Accepts a storage error only while an injected fault explains it.
    fn storage_error(&self, err: &TxnError) -> Result<(), FailureKind> {
        if self.fault_active() {
            Ok(())
        } else {
            Err(FailureKind::Unexpected(format!(
                "storage error without an injected fault: {err}"
            )))
        }
    }

    fn drop_txn(&mut self, c: usize) {
        let client = &mut self.clients[c];
        client.txn = None;
        client.attempt = None;
        client.held.clear();
    }

    /// Counts one more attempt of `c`'s plan; abandons it at the limit.
    fn count_attempt(&mut self, c: usize) {
        let client = &mut self.clients[c];
        let Some(plan) = client.plan.as_mut() else {
            return;
        };
        plan.attempts += 1;
        if plan.attempts >= MAX_ATTEMPTS {
            self.stats.abandoned += 1;
            client.plan = None;
            client.txn = None;
            client.attempt = None;
            client.held.clear();
        }
    }

    /// The plan of `c` runs again in a new transaction (the next step begins it).
    fn retry_plan(&mut self, c: usize) {
        self.count_attempt(c);
    }

    fn record(&mut self, attempt: Attempt, outcome: Outcome, end: Option<u64>) {
        if outcome == Outcome::Fail {
            self.stats.failed += 1;
        }
        self.epoch_attempts
            .push((self.history.len(), attempt.engine));
        self.history
            .push(Txn::new(attempt.id, outcome, attempt.ops).with_time(attempt.start, end));
    }
}

/// Decodes a register value (8 bytes, big-endian).
fn decode(key: Key, bytes: Option<&[u8]>) -> Result<Option<Value>, FailureKind> {
    match bytes {
        None => Ok(None),
        Some(b) => <[u8; 8]>::try_from(b)
            .map(|a| Some(Value::from_be_bytes(a)))
            .map_err(|_| {
                FailureKind::Unexpected(format!("register {key} holds a {}-byte value", b.len()))
            }),
    }
}

/// The last value each register was written with by `ops`.
fn final_writes(ops: &[Op]) -> BTreeMap<Key, Value> {
    ops.iter()
        .filter_map(|op| match *op {
            Op::Write { key, value } => Some((key, value)),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_writes_keeps_last_write_per_register() {
        let ops = [
            Op::write(1, 10),
            Op::read_register(1, Some(10)),
            Op::write(2, 20),
            Op::write(1, 11),
        ];
        let w = final_writes(&ops);
        assert_eq!(w.get(&1), Some(&11));
        assert_eq!(w.get(&2), Some(&20));
        assert_eq!(w.len(), 2);
    }

    #[test]
    fn decode_rejects_malformed_values() {
        assert_eq!(decode(0, None).ok(), Some(None));
        assert_eq!(decode(0, Some(&7u64.to_be_bytes())).ok(), Some(Some(7)));
        assert!(decode(0, Some(&[1, 2, 3])).is_err());
    }

    #[test]
    fn failure_display_names_seed_and_reproduction() {
        let f = Failure {
            config: RegisterConfig::new(0xABC, Isolation::Snapshot, true),
            kind: FailureKind::Unexpected("boom".into()),
        };
        let s = f.to_string();
        assert!(s.contains("seed 0xabc"), "{s}");
        assert!(
            s.contains("--workload rw-register-faults --isolation snapshot --seed 0xabc"),
            "{s}"
        );
    }
}
