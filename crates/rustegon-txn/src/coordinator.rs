// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The single-range transaction coordinator (crate docs): owns the range latch, the timestamp
//! cache, the live-transaction registry and the wait queues of one [`Replica`], and starts
//! transactions on it.

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use bytes::Bytes;
use rustegon_mvcc::{
    Hlc, MvccWriter, RangeAppliedState, Replica, ReplicaCommand, ReplicaError, Timestamp, TxnId,
    VersionValue,
};
use rustegon_sim_api::{Clock, Rng};

use crate::{
    config::{TxnConfig, TxnOptions},
    error::{AbortReason, Result, TxnError},
    lock_table::LockTable,
    registry::{Registry, Status, TxnShared},
    stats::{TxnStats, TxnStatsSnapshot},
    ts_cache::TsCache,
    txn::Txn,
};

/// What a successful commit reports (transaction-management.md §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitInfo {
    /// The commit timestamp: every write of the transaction is visible at it and above.
    pub commit_ts: Timestamp,
}

/// State shared by the coordinator and its transactions.
pub(crate) struct Core {
    pub(crate) replica: Arc<dyn Replica>,
    pub(crate) hlc: Arc<Hlc>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) rng: Arc<dyn Rng>,
    pub(crate) config: TxnConfig,
    /// Range latch (crate docs, "Latching"): shared for reads, exclusive for evaluating and
    /// proposing a write batch.
    latch: RwLock<()>,
    ts_cache: Mutex<TsCache>,
    pub(crate) registry: Registry,
    pub(crate) locks: LockTable,
    pub(crate) stats: TxnStats,
}

impl Core {
    /// Takes the range latch for reading.
    pub(crate) fn read_latch(&self) -> RwLockReadGuard<'_, ()> {
        // The latch guards no data of its own: poison carries no information.
        self.latch.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the range latch for evaluating and proposing a write batch.
    pub(crate) fn write_latch(&self) -> RwLockWriteGuard<'_, ()> {
        self.latch.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The timestamp cache (leaf lock).
    pub(crate) fn ts_cache(&self) -> MutexGuard<'_, TsCache> {
        // Every cache operation completes its update before returning: poison is harmless.
        self.ts_cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Monotonic time.
    pub(crate) fn now(&self) -> Duration {
        self.clock.monotonic()
    }

    /// A fresh transaction id (random UUID bytes, version 4 layout).
    pub(crate) fn new_txn_id(&self) -> TxnId {
        let mut id = [0; 16];
        self.rng.fill_bytes(&mut id);
        id[6] = (id[6] & 0x0F) | 0x40;
        id[8] = (id[8] & 0x3F) | 0x80;
        id
    }

    /// Proposes the batch of `writer` (a no-op for an empty batch). Must be called under the
    /// write latch: the batch was evaluated against the state the latch protects.
    pub(crate) fn propose(
        &self,
        writer: MvccWriter<'_>,
    ) -> Result<Option<RangeAppliedState>, ReplicaError> {
        if writer.is_empty() {
            return Ok(None);
        }
        let cmd = ReplicaCommand::new(self.hlc.now(), writer.into_batch());
        self.replica.propose(cmd).map(Some)
    }
}

/// The transaction coordinator of one range (crate docs). Cheap to clone; all clones share the
/// same state. Exactly one coordinator may serve a replica: the registry and the timestamp cache
/// are the range's in-memory concurrency state.
#[derive(Clone)]
pub struct TxnCoordinator {
    core: Arc<Core>,
}

impl fmt::Debug for TxnCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxnCoordinator")
            .field("range_id", &self.core.replica.range_id())
            .field("live_txns", &self.core.registry.len())
            .finish_non_exhaustive()
    }
}

impl TxnCoordinator {
    /// A coordinator over `replica`. The timestamp cache starts with its low-water mark at the
    /// HLC's current time: reads served before (e.g. before a restart, whose HLC recovery puts
    /// every new timestamp above them) are covered by it (§8).
    #[must_use]
    pub fn new(
        replica: Arc<dyn Replica>,
        hlc: Arc<Hlc>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        config: TxnConfig,
    ) -> Self {
        let low_water = hlc.now();
        let ts_cache = TsCache::new(low_water, config.ts_cache_capacity);
        Self {
            core: Arc::new(Core {
                replica,
                hlc,
                clock,
                rng,
                config,
                latch: RwLock::new(()),
                ts_cache: Mutex::new(ts_cache),
                registry: Registry::default(),
                locks: LockTable::default(),
                stats: TxnStats::default(),
            }),
        }
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &TxnConfig {
        &self.core.config
    }

    /// The HLC the coordinator takes timestamps from.
    #[must_use]
    pub fn hlc(&self) -> &Arc<Hlc> {
        &self.core.hlc
    }

    /// Transaction outcome counters since the coordinator was created (`crate::stats`).
    #[must_use]
    pub fn stats(&self) -> TxnStatsSnapshot {
        self.core.stats.snapshot()
    }

    /// Number of live (registered) transactions.
    #[must_use]
    pub fn live_transactions(&self) -> usize {
        self.core.registry.len()
    }

    /// The transactions queued on `key`'s wait queue, head first (observability, tests).
    #[must_use]
    pub fn waiters(&self, key: &[u8]) -> Vec<TxnId> {
        self.core.locks.waiters(key)
    }

    /// Starts a transaction.
    #[must_use]
    pub fn begin(&self, options: TxnOptions) -> Txn {
        let priority = options.priority.base();
        self.begin_with_priority(options, priority, 0)
    }

    fn begin_with_priority(&self, options: TxnOptions, priority: u32, restarts: u32) -> Txn {
        let id = self.core.new_txn_id();
        let start_ts = self.core.hlc.now();
        let shared = Arc::new(TxnShared::new(id, start_ts, priority, self.core.now()));
        self.core.registry.insert(Arc::clone(&shared));
        Txn::new(Arc::clone(&self.core), shared, options, restarts)
    }

    /// Single-key fast path (§6): an implicit transaction writing one key commits its value
    /// directly as a version, with no intent and no transaction record. Waits for (or pushes)
    /// conflicting intents like any writer. Returns the commit timestamp.
    ///
    /// # Errors
    /// As [`Txn::put`]; the write is atomic (one proposal).
    pub fn put_single_key(&self, key: &[u8], value: &VersionValue) -> Result<Timestamp> {
        let mut txn = self.begin(TxnOptions::default());
        txn.fast_path_write(key, value)
    }

    /// Reads `key` at a fresh timestamp outside any transaction (an implicit read-only
    /// transaction).
    ///
    /// # Errors
    /// As [`Txn::get`].
    pub fn get_latest(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let mut txn = self.begin(TxnOptions::default());
        let value = txn.get(key)?;
        txn.commit()?;
        Ok(value)
    }

    /// Runs `body` in a transaction and commits it, retrying on retryable errors up to
    /// `max_attempts` times in total (the server-side retry of transactions.md §1; the driver
    /// helper of §5 has the same shape). A conflict restarts the same transaction (next epoch,
    /// intents kept as locks, priority raised, §5.3); an abort (deadlock victim, pushed) starts a
    /// new one that inherits the raised priority. `body` must be repeatable.
    ///
    /// # Errors
    /// The last error; non-retryable errors are returned at once (after a rollback).
    pub fn run<T, F>(
        &self,
        options: &TxnOptions,
        max_attempts: u32,
        mut body: F,
    ) -> Result<(T, CommitInfo)>
    where
        F: FnMut(&mut Txn) -> Result<T>,
    {
        let mut txn = self.begin(options.clone());
        let mut attempt = 1;
        loop {
            let result = body(&mut txn).and_then(|v| txn.commit().map(|c| (v, c)));
            match result {
                Ok(done) => return Ok(done),
                Err(e) if e.is_retryable() && attempt < max_attempts => {
                    attempt += 1;
                    if txn.restart().is_err() {
                        let (priority, restarts) = txn.bumped_priority();
                        txn = self.begin_with_priority(options.clone(), priority, restarts);
                    }
                }
                Err(e) => {
                    if let Err(rollback) = txn.rollback() {
                        tracing::warn!(error = %rollback, "rollback after a failed transaction");
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Raises the timestamp cache's low-water mark (e.g. to a lease transfer timestamp, §8).
    pub fn raise_ts_cache_low_water(&self, ts: Timestamp) {
        self.core.ts_cache().raise_low_water(ts);
    }

    /// Closes a fresh timestamp T for writes and returns it once no transaction can commit at
    /// or below it any more (the write fence of an online backup, PD-063): from then on, the
    /// committed state as of T never changes, so a storage checkpoint taken afterwards holds
    /// everything a read at T sees, and a reader at T may ignore every intent
    /// ([`rustegon_mvcc::MvccReader::scan_committed`]).
    ///
    /// Why it is sufficient:
    /// 1. Under the exclusive range latch (no write or commit is being evaluated), T is taken
    ///    from the HLC — above every timestamp written so far, since each write and commit
    ///    merges its timestamp into the HLC before releasing the latch — and the timestamp
    ///    cache's low-water mark is raised to T. Every write evaluated afterwards, intent or
    ///    single-key fast path, lands strictly above T (it must be above the cache, §4.1), and
    ///    so does every later commit of a transaction that writes it.
    /// 2. What remains are transactions that already hold an intent at a write timestamp
    ///    `<= T`: they could still commit at `<= T`. The fence waits until each of them has
    ///    committed, aborted, or moved above T (a later write or a timestamp push raises its
    ///    write timestamp; the commit timestamp is never below it). A holder idle for longer than
    ///    `txn.liveness_timeout` is aborted, as any pusher would (§5.1), so an abandoned client
    ///    cannot hold a backup for longer than that. Transactions without intents (`has_intents`
    ///    false) never block: their first write lands above T by step 1.
    ///
    /// Writers are never blocked; serializable transactions that read below T and write after
    /// the fence commit above T and may need a read refresh, exactly as after a lease transfer
    /// (§8). Intents left behind by transactions still running at a checkpoint taken after the
    /// fence commit above T or never: a restore at T aborts them all.
    ///
    /// # Errors
    /// [`TxnError::CloseTimedOut`] (`RGN-5006`) after `timeout` with blockers left;
    /// [`TxnError::Cancelled`] (`RGN-5005`) once `cancelled` returns `true`;
    /// [`TxnError::Internal`] if a blocker's commit outcome is unknown (`RGN-2006` earlier: the
    /// log decides at the next open, so T cannot be closed until the store is reopened). The
    /// raised low-water mark stays in every case; it only costs pushes.
    pub fn close_timestamp(
        &self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Timestamp> {
        let ts = {
            let _latch = self.core.write_latch();
            let ts = self.core.hlc.now();
            self.core.ts_cache().raise_low_water(ts);
            ts
        };
        let started = self.core.now();
        loop {
            let mut first = None;
            let mut blockers = 0;
            for txn in self.core.registry.all() {
                let blocking = {
                    let mut st = txn.lock();
                    if !st.has_intents || st.write_ts > ts {
                        false
                    } else {
                        match st.status {
                            Status::Committed { .. } | Status::Aborted(_) => false,
                            Status::Ambiguous => {
                                return Err(TxnError::Internal(format!(
                                    "cannot close {ts}: a transaction's commit outcome is \
                                     unknown until the store is reopened"
                                )));
                            }
                            Status::Pending
                                if self.core.now().saturating_sub(st.last_heartbeat)
                                    > self.core.config.liveness_timeout =>
                            {
                                // Expired holder: abortable by anyone (§5.1); its owner
                                // cleans up its intents.
                                txn.set_status(
                                    &mut st,
                                    Status::Aborted(AbortReason::TimeoutPushed),
                                );
                                false
                            }
                            Status::Pending | Status::Committing => true,
                        }
                    }
                };
                if blocking {
                    blockers += 1;
                    first.get_or_insert(txn);
                }
            }
            let Some(blocker) = first else {
                return Ok(ts);
            };
            if cancelled() {
                return Err(TxnError::Cancelled);
            }
            let waited = self.core.now().saturating_sub(started);
            if waited >= timeout {
                return Err(TxnError::CloseTimedOut {
                    ts,
                    waited,
                    blockers,
                });
            }
            // Holds no lock but the blocker's own state mutex (lock order, crate docs).
            blocker.wait_for_change(self.core.config.wait_slice);
        }
    }

    /// The persisted outcome of a transaction whose coordinator is not in this process, e.g.
    /// one that ran before a restart (`None`: no record, or still live here). A missing record
    /// may mean committed: never read it as aborted. An expired `PENDING` record is aborted
    /// durably first. Why this is safe: `conflict.rs`, `Core::orphan_status` (PD-121).
    ///
    /// # Errors
    /// Storage, corruption and replica errors.
    pub fn orphan_status(&self, txn: &TxnId) -> Result<Option<crate::OrphanStatus>> {
        self.core.orphan_status(txn)
    }

    /// Whether `txn` is still registered (tests and observability).
    #[must_use]
    pub fn is_live(&self, txn: &TxnId) -> bool {
        self.core.registry.get(txn).is_some()
    }
}
