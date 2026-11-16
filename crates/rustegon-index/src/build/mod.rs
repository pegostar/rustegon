// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The online, resumable, throttled index build job (FR-IDX-003; database-engine.md §2.3,
//! indexing.md §5; TC-IDX-002/003).
//!
//! A build is a sequence of **steps**, each one transaction ([`IndexBuild::step`]), so writers
//! interleave with it and a crash loses at most the step in flight:
//!
//! 1. [`start_build`] (in the caller's DDL transaction): the descriptor is created in
//!    `DeleteOnly` together with the job record ([`record`]).
//! 2. `DeleteOnly → WriteOnly`, `WriteOnly → Backfilling`: one transaction each.
//! 3. `Backfilling`: batches of at most [`BuildConfig::batch_docs`] documents /
//!    [`BuildConfig::batch_bytes`] bytes, in document key order after the checkpoint; each batch
//!    writes the entries of its documents and the new checkpoint (the last key processed) in
//!    one transaction. The batch that reaches the end of the collection also moves the index to
//!    `Validating`.
//! 4. `Validating → Public`: one transaction compares the index span with the entries the
//!    documents produce at its snapshot (count and content; unique collisions → `RGN-1022` with
//!    the offending `_id`s) and makes the index public, deleting the job record.
//! 5. Failure (`RGN-1022`, or `RGN-1025` / `RGN-1008` from existing data) or cancellation
//!    ([`cancel_build`], `DROP INDEX`): the index goes to `Dropping` (writers stop maintaining
//!    it) and the job turns into **cleanup** batches deleting the index span, then deletes its
//!    record. The error of a failed build is returned once the span is clean.
//!
//! Throttling: after each batch the step reports a `pause` derived from the documents/bytes
//! processed and [`BuildConfig::max_bytes_per_sec`] / [`BuildConfig::max_docs_per_sec`]; the
//! driver waits it on its clock before the next step (the job itself never sleeps, so a
//! simulation drives it deterministically). Auto-pausing on foreground latency (indexing.md §5)
//! needs the metrics of a later milestone.
//!
//! # Correctness under concurrent writes (the invariants)
//! Writers maintain every non-dropping index in their own transaction (`crate::maintain`):
//! `DeleteOnly` → deletes only; `WriteOnly` and later → deletes and puts.
//!
//! **I1 — every document version committed after `WriteOnly` is maintained by its writer.**
//! Each state transition rewrites the collection descriptor (`version + 1`), which every writer
//! reads in its SERIALIZABLE transaction. A writer that read the old state and commits after the
//! transition fails its read refresh and retries with the new state; one that commits before it
//! is serialized before it. So a writer whose version is ordered after the `WriteOnly`
//! transition saw `WriteOnly` (or later) and wrote its entries. This is why `WriteOnly` precedes
//! `Backfilling`; `DeleteOnly` precedes `WriteOnly` so that, on a cluster, no node still running
//! without the index can leave entries of a version it overwrote (database-engine.md §2.3).
//!
//! **I2 — every document visible when the backfill passes its key gets its entries.** Batch
//! snapshots are taken after the `WriteOnly` transition, so a document version committed before
//! it is seen by the batch covering its key; versions committed later are covered by I1.
//! Batch writes are idempotent (non-unique puts of identical bytes; unique puts check the owner),
//! so a writer having written the same entry first is harmless.
//!
//! **I3 — a batch never leaves an entry of a version that was replaced concurrently.** Batches
//! run at SNAPSHOT isolation (SERIALIZABLE would refresh the whole remaining document span, which
//! every concurrent insert invalidates, so batches would retry endlessly under load). A batch
//! that read version `v` of a document writes `entries(v)`; a writer replacing `v` by `v'`
//! deletes `entries(v) − entries(v')`. Every entry the batch writes that is stale (in
//! `entries(v)` but not `entries(v')`) is therefore also written (deleted) by the writer: the two
//! transactions write the same key, so one of them fails with a write-write conflict and
//! retries on the other's result, or the writer's tombstone lands above the batch's put.
//! Entries in both sets are correct either way. Unique deletes always write a tombstone unless
//! another document owns the key (`crate::maintain`, "Unique deletes"), which keeps this
//! write-write overlap.
//!
//! **I4 — unique indexes never commit a duplicate.** Batches and writers check the owner of a
//! unique key with a transactional read-modify-write (`crate::maintain`); a batch meeting a key
//! owned by another document fails the build (`RGN-1022`) because the data holds a duplicate.
//! Validation re-checks the whole index against the data before it becomes public.
//!
//! **I5 — the job and DDL serialize.** Every step reads the job record and the index
//! descriptor; batches rewrite the record, transitions rewrite the descriptor, and cancellation
//! / `DROP INDEX` rewrite both, so a step racing a cancellation fails with a write-write
//! conflict and re-reads the cancelled state. A job always re-reads the descriptor (its version
//! moves when writers set the multikey flag), never trusts a cached copy.
//!
//! **I6 — crash atomicity.** Every step's writes (entries, checkpoint, state) commit in one
//! transaction; [`pending_builds`] finds the records after a restart and the job resumes after
//! the last committed checkpoint. A crash therefore never leaves entries without base data in a
//! public index (validation would reject it) nor a public index missing entries.

mod phases;
pub mod record;

use std::time::Duration;

use rustegon_catalog::{
    CatalogRead, CollectionDescriptor, IndexDescriptor, IndexSpec, IndexState, Mutation,
    index::ops::{create_index, index_descriptor_key, transition_index},
};
use rustegon_common::{Error, ErrorCode};
use rustegon_txn::{Isolation, TxnCoordinator, TxnOptions};

use self::phases::{Outcome, apply, catalog, step_body};
pub use self::record::{
    BuildRecord, JobPhase, build_record_key, build_record_prefix, decode_build_record,
    encode_build_record,
};
use crate::keygen::PartialFilter;

/// Attempts of one step on retryable transaction errors (conflicts with writers).
pub const MAX_ATTEMPTS: u32 = 16;
/// Failure message recorded for a cancelled build.
pub const CANCELLED: &str = "index build cancelled";
/// At most this many offending `_id`s are reported (indexing.md §5).
pub const MAX_OFFENDING_IDS: usize = 100;

/// Build job settings (implementation-rules.md §5; all dynamic, per job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildConfig {
    /// Documents per backfill batch (one transaction). Default 1000 (*Provisional*): bounded
    /// far below the transaction write limits (`RGN-2004`) for documents with up to ~100
    /// entries each.
    pub batch_docs: usize,
    /// Document bytes per batch (a batch stops after the document that crosses it). Default
    /// 4 MiB (*Provisional*).
    pub batch_bytes: u64,
    /// `index.build_max_bytes_per_sec` (indexing.md §5): default 64 MiB/s; 0 = unthrottled.
    pub max_bytes_per_sec: u64,
    /// Documents per second; 0 (default) = unthrottled.
    pub max_docs_per_sec: u64,
    /// Index entries deleted per cleanup batch. Default 1000 (*Provisional*).
    pub cleanup_batch_keys: usize,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            batch_docs: 1000,
            batch_bytes: 4 << 20,
            max_bytes_per_sec: 64 << 20,
            max_docs_per_sec: 0,
            cleanup_batch_keys: 1000,
        }
    }
}

impl BuildConfig {
    /// The pause owed after processing `docs` documents of `bytes` bytes: the longer of the
    /// two rate limits (token-bucket debt of one batch).
    #[must_use]
    pub fn pause_after(&self, docs: u64, bytes: u64) -> Duration {
        let owed = |amount: u64, rate: u64| {
            if rate == 0 || amount == 0 {
                Duration::ZERO
            } else {
                let nanos = u128::from(amount) * 1_000_000_000 / u128::from(rate);
                Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
            }
        };
        owed(bytes, self.max_bytes_per_sec).max(owed(docs, self.max_docs_per_sec))
    }
}

/// Progress of a build (indexing.md §5 `{scanned_keys, …}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildProgress {
    /// Index state after the step.
    pub state: IndexState,
    /// Job phase after the step.
    pub phase: JobPhase,
    /// Documents processed by the backfill.
    pub docs_scanned: u64,
    /// Entries written by the backfill.
    pub entries_written: u64,
}

/// Result of one [`IndexBuild::step`].
#[derive(Debug)]
pub enum BuildStep {
    /// More work to do; wait `pause` (throttling) before the next step.
    Continue {
        /// Progress after this step.
        progress: BuildProgress,
        /// Throttling delay owed.
        pause: Duration,
    },
    /// The index is public and the job is finished.
    Public(IndexDescriptor),
    /// The build failed or was cancelled; the index is `Dropping`, its span clean and the job
    /// finished. The error says why (`RGN-1022`, `RGN-1025`, `RGN-1008`, `RGN-5005`, …).
    Abandoned(Error),
}

/// Handle on the job of one index build; any number of handles may drive the same job (the
/// steps are transactions on the persisted record).
#[derive(Debug)]
pub struct IndexBuild {
    collection_id: u32,
    index_id: u32,
    config: BuildConfig,
    /// The failure seen by this handle, returned with full details once cleanup ends.
    failure: Option<Error>,
}

impl IndexBuild {
    /// A handle on the job of index `index_id` of collection `collection_id`.
    #[must_use]
    pub fn new(collection_id: u32, index_id: u32, config: BuildConfig) -> Self {
        Self {
            collection_id,
            index_id,
            config,
            failure: None,
        }
    }

    /// The collection.
    #[must_use]
    pub fn collection_id(&self) -> u32 {
        self.collection_id
    }

    /// The index.
    #[must_use]
    pub fn index_id(&self) -> u32 {
        self.index_id
    }

    /// The settings.
    #[must_use]
    pub fn config(&self) -> &BuildConfig {
        &self.config
    }

    /// Runs one step (one transaction at SNAPSHOT isolation, module docs I3), retried on
    /// conflicts.
    ///
    /// # Errors
    /// Transaction and storage errors (the step is not committed; calling `step` again
    /// retries it), `RGN-5002` for a corrupt record or descriptor.
    pub fn step(
        &mut self,
        coord: &TxnCoordinator,
        filter: &dyn PartialFilter,
    ) -> Result<BuildStep, Error> {
        let opts = TxnOptions::with_isolation(Isolation::Snapshot);
        let (collection_id, index_id) = (self.collection_id, self.index_id);
        let config = &self.config;
        let (outcome, _) = coord.run(&opts, MAX_ATTEMPTS, |txn| {
            step_body(txn, collection_id, index_id, config, filter)
        })?;
        Ok(match outcome? {
            Outcome::Progress {
                progress,
                docs,
                bytes,
            } => BuildStep::Continue {
                progress,
                pause: self.config.pause_after(docs, bytes),
            },
            Outcome::Public(d) => BuildStep::Public(d),
            Outcome::Failed(e) => {
                self.failure = Some(e);
                BuildStep::Continue {
                    progress: BuildProgress {
                        state: IndexState::Dropping,
                        phase: JobPhase::Cleanup,
                        docs_scanned: 0,
                        entries_written: 0,
                    },
                    pause: Duration::ZERO,
                }
            }
            Outcome::Finished(msg) => BuildStep::Abandoned(self.take_failure(msg)),
            Outcome::Missing => BuildStep::Abandoned(self.take_failure(None)),
        })
    }

    fn take_failure(&mut self, msg: Option<String>) -> Error {
        if let Some(e) = self.failure.take() {
            return e;
        }
        match msg {
            Some(m) if m == CANCELLED => Error::new(ErrorCode::Cancelled, m),
            Some(m) => Error::new(ErrorCode::IndexBuildFailed, m),
            None => Error::new(
                ErrorCode::IndexNotFound,
                format!("no build job for index {}", self.index_id),
            ),
        }
    }

    /// Drives the job to its end, calling `pace` with every throttling pause (the caller waits
    /// it on its clock; a no-op ignores throttling).
    ///
    /// # Errors
    /// The abandon reason of a failed or cancelled build (after cleanup); step errors.
    pub fn run(
        &mut self,
        coord: &TxnCoordinator,
        filter: &dyn PartialFilter,
        pace: &mut dyn FnMut(Duration),
    ) -> Result<IndexDescriptor, Error> {
        loop {
            match self.step(coord, filter)? {
                BuildStep::Continue { pause, .. } => {
                    if !pause.is_zero() {
                        pace(pause);
                    }
                }
                BuildStep::Public(d) => return Ok(d),
                BuildStep::Abandoned(e) => return Err(e),
            }
        }
    }
}

/// Prepares `CREATE INDEX` as an online build: the descriptor in `DeleteOnly` (see
/// `rustegon_catalog::index::ops::create_index`) and its job record; the caller applies the
/// mutations in its DDL transaction and then drives [`IndexBuild`].
///
/// # Errors
/// The errors of `create_index` (`RGN-1001`, `RGN-1020`, `RGN-1023`, `RGN-1030`, …).
pub fn start_build(
    r: &impl CatalogRead,
    collection: &CollectionDescriptor,
    spec: IndexSpec,
) -> Result<(IndexDescriptor, Vec<Mutation>), Error> {
    let created = create_index(r, collection, spec)?;
    let d = created.descriptor;
    let mut mutations = created.mutations;
    mutations.push(build_record_mutation(&d)?);
    Ok((d, mutations))
}

/// The mutation writing the fresh job record of a build of `index` (part of [`start_build`],
/// for callers that create the descriptor themselves).
///
/// # Errors
/// Encoding errors (none for valid ids).
pub fn build_record_mutation(index: &IndexDescriptor) -> Result<Mutation, Error> {
    Ok(Mutation::Put {
        key: build_record_key(index.collection_id, index.id),
        value: encode_build_record(&BuildRecord::new(
            index.database_id,
            index.collection_id,
            index.id,
        ))?,
    })
}

/// The mutation deleting the job record of an index (for `DROP INDEX`, which deletes the
/// entries itself; deleting the record makes a racing step conflict, module docs I5).
#[must_use]
pub fn delete_build_record(collection_id: u32, index_id: u32) -> Mutation {
    Mutation::Delete {
        key: build_record_key(collection_id, index_id),
    }
}

/// Cancels the build of index `index_id`: the index becomes `Dropping` and the job turns into
/// cleanup (driven by [`IndexBuild`] handles, which then return `RGN-5005 Cancelled`). Returns
/// `false` when there is no build job (finished or never started).
///
/// # Errors
/// Transaction and catalog errors.
pub fn cancel_build(
    coord: &TxnCoordinator,
    collection: &CollectionDescriptor,
    index_id: u32,
) -> Result<bool, Error> {
    let (cancelled, _) = coord.run(&TxnOptions::default(), MAX_ATTEMPTS, |txn| {
        let key = build_record_key(collection.id, index_id);
        let Some(bytes) = txn.get(&key)? else {
            return Ok(Ok(false));
        };
        let mut rec = match decode_build_record(&bytes) {
            Ok(r) => r,
            Err(e) => return Ok(Err(e)),
        };
        let Some(ix_bytes) = txn.get(&index_descriptor_key(collection.id, index_id))? else {
            return Ok(Ok(false));
        };
        let ix = match rustegon_catalog::index::codec::decode_index_descriptor(&ix_bytes) {
            Ok(ix) => ix,
            Err(e) => return Ok(Err(e.into())),
        };
        if ix.state != IndexState::Dropping {
            let m = match catalog(txn, |r| {
                transition_index(r, collection, &ix, IndexState::Dropping)
            })? {
                Ok((_, m)) => m,
                Err(e) => return Ok(Err(e)),
            };
            apply(txn, &m)?;
        }
        if rec.phase == JobPhase::Build {
            rec.phase = JobPhase::Cleanup;
            rec.cursor = None;
            rec.error = Some(CANCELLED.to_owned());
            let value = match encode_build_record(&rec) {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
            txn.put(&key, value)?;
        }
        Ok(Ok(true))
    })?;
    cancelled
}

/// Handles on every unfinished build job (recovery after a restart: each resumes from its
/// persisted checkpoint), in key order.
///
/// # Errors
/// Transaction errors; `RGN-5002` for a corrupt record.
pub fn pending_builds(
    coord: &TxnCoordinator,
    config: &BuildConfig,
) -> Result<Vec<IndexBuild>, Error> {
    let prefix = build_record_prefix();
    let end = crate::scan::prefix_end(&prefix)
        .ok_or_else(|| Error::new(ErrorCode::Internal, "build record span without end"))?;
    let (rows, _) = coord.run(&TxnOptions::default(), MAX_ATTEMPTS, |txn| {
        txn.scan(&prefix, &end, usize::MAX)
    })?;
    rows.iter()
        .map(|(_, v)| {
            let r = decode_build_record(v)?;
            Ok(IndexBuild::new(r.collection_id, r.index_id, config.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_follows_the_stricter_rate() {
        let c = BuildConfig {
            max_bytes_per_sec: 1000,
            max_docs_per_sec: 10,
            ..BuildConfig::default()
        };
        assert_eq!(c.pause_after(0, 0), Duration::ZERO);
        assert_eq!(c.pause_after(1, 500), Duration::from_millis(500));
        assert_eq!(c.pause_after(20, 500), Duration::from_secs(2));
        let unthrottled = BuildConfig {
            max_bytes_per_sec: 0,
            ..BuildConfig::default()
        };
        assert_eq!(unthrottled.pause_after(1_000, 1 << 30), Duration::ZERO);
        assert_eq!(
            BuildConfig::default().pause_after(1, 64 << 20),
            Duration::from_secs(1)
        );
    }
}
