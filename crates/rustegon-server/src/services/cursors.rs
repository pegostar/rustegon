// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The server's cursor registry (FR-QL-006, query-language.md §5.2, protocol.md §3/§6,
//! PD-041, PD-049, PD-053).
//!
//! An `Execute` with `max_batches` that does not reach the end of its result leaves its engine
//! cursor ([`OwnedCursor`]) here under a random 128-bit id (`ResultBatch.cursor_id`); `GetMore`
//! checks it out for one batch and puts it back, `KillCursor` or reading to the end removes it.
//!
//! Rules (*Provisional (PD-053)*):
//! - **Owner**: the principal that executed the query; another caller gets RGN-1030.
//! - **Idle timeout** `cursor_idle_timeout` (FR-QL-006: 10 min) without a `GetMore`: the
//!   cursor is closed by the sweep (or lazily on its next use) and its id becomes unknown
//!   (RGN-1030). The engine bounds a cursor's snapshot by `txn.max_duration` (60 s, RGN-2003
//!   on the next batch) until reads at a pinned timestamp exist (PD-049).
//! - **Bounds**: `max_cursors` per node, `max_cursors_per_principal`, and a memory reservation
//!   of `cursor_reservation_bytes` per idle cursor (its pending operator batch) against
//!   `cursor_memory_budget` / `cursor_memory_per_principal`; beyond them RGN-5004 (retryable).
//! - **One batch at a time**: a `GetMore` racing another `GetMore` of the same cursor gets
//!   RGN-1001 (the cursor is in use).
//! - **Cancellation**: a `GetMore` whose client goes away or whose deadline passes kills the
//!   cursor (its half-read batch cannot be handed out again); the batch in progress stops
//!   within one operator batch through the cursor's [`CancelHandle`].

use std::{
    collections::HashMap,
    fmt::Write as _,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use rustegon_common::{Error, ErrorCode};
use rustegon_engine::{CancelHandle, OwnedCursor};
use rustegon_sim_api::{Clock, Rng};

use super::data::DataPlaneConfig;

/// One open cursor.
pub(crate) struct CursorEntry {
    pub(crate) owner: Option<String>,
    /// `None` while a `GetMore` holds the cursor.
    slot: Mutex<Option<OwnedCursor>>,
    pub(crate) cancel: CancelHandle,
    last_used: Mutex<Duration>,
    reserved: usize,
    /// Monotonic time at which the query started (`QueryStats.execution_time_us`).
    pub(crate) started: Duration,
    /// The interactive transaction the cursor reads through, if any.
    pub(crate) txn: Option<String>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each protected value is replaced in one assignment: a panic cannot leave it torn.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct Usage {
    count: usize,
    bytes: usize,
}

struct Inner {
    cursors: HashMap<String, Arc<CursorEntry>>,
    per_owner: HashMap<Option<String>, Usage>,
    total: Usage,
}

/// The cursor registry (module docs).
pub(crate) struct CursorRegistry {
    inner: Mutex<Inner>,
    clock: Arc<dyn Clock>,
    idle_timeout: Duration,
    max_global: usize,
    max_per_owner: usize,
    budget_global: usize,
    budget_per_owner: usize,
    reservation: usize,
}

pub(crate) fn not_found() -> Error {
    Error::new(ErrorCode::NotFound, "cursor not found").with_detail("kind", "cursor")
}

impl CursorRegistry {
    pub(crate) fn new(clock: Arc<dyn Clock>, config: &DataPlaneConfig) -> Self {
        Self {
            inner: Mutex::new(Inner {
                cursors: HashMap::new(),
                per_owner: HashMap::new(),
                total: Usage::default(),
            }),
            clock,
            idle_timeout: config.cursor_idle_timeout,
            max_global: config.max_cursors,
            max_per_owner: config.max_cursors_per_principal,
            budget_global: config.cursor_memory_budget,
            budget_per_owner: config.cursor_memory_per_principal,
            reservation: config.cursor_reservation_bytes,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        lock(&self.inner)
    }

    /// Registers `cursor` for `owner` and returns its id.
    ///
    /// # Errors
    /// RGN-5004 beyond the count or memory bounds (the cursor is then dropped: closed).
    pub(crate) fn register(
        &self,
        cursor: OwnedCursor,
        owner: Option<String>,
        started: Duration,
        rng: &dyn Rng,
        txn: Option<String>,
    ) -> Result<String, Error> {
        let mut raw = [0u8; 16];
        rng.fill_bytes(&mut raw);
        let mut id = String::with_capacity(32);
        for b in raw {
            let _ = write!(id, "{b:02x}");
        }
        let entry = Arc::new(CursorEntry {
            owner: owner.clone(),
            cancel: cursor.cancel_handle(),
            slot: Mutex::new(Some(cursor)),
            last_used: Mutex::new(self.clock.monotonic()),
            reserved: self.reservation,
            started,
            txn,
        });
        let mut inner = self.lock();
        let mine = inner
            .per_owner
            .get(&owner)
            .map_or((0, 0), |u| (u.count, u.bytes));
        if inner.total.count >= self.max_global
            || mine.0 >= self.max_per_owner
            || inner.total.bytes + entry.reserved > self.budget_global
            || mine.1 + entry.reserved > self.budget_per_owner
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "too many open cursors",
            ));
        }
        inner.total.count += 1;
        inner.total.bytes += entry.reserved;
        let usage = inner.per_owner.entry(owner).or_default();
        usage.count += 1;
        usage.bytes += entry.reserved;
        inner.cursors.insert(id.clone(), entry);
        Ok(id)
    }

    /// Checks the cursor out for one batch.
    ///
    /// # Errors
    /// RGN-1030 (unknown, expired or another owner's), RGN-1001 (in use by another call).
    pub(crate) fn checkout(
        &self,
        id: &str,
        owner: Option<&str>,
    ) -> Result<(Arc<CursorEntry>, OwnedCursor), Error> {
        let entry = self
            .lock()
            .cursors
            .get(id)
            .cloned()
            .filter(|e| e.owner.as_deref() == owner)
            .ok_or_else(not_found)?;
        let mut slot = lock(&entry.slot);
        let idle_for = self
            .clock
            .monotonic()
            .saturating_sub(*lock(&entry.last_used));
        if slot.is_some() && idle_for > self.idle_timeout {
            let expired = slot.take();
            drop(slot);
            self.remove(id);
            close_off_thread(expired);
            return Err(not_found());
        }
        let cursor = slot.take().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "the cursor is in use by another call",
            )
        })?;
        drop(slot);
        Ok((entry, cursor))
    }

    /// Returns a cursor after a batch.
    pub(crate) fn put_back(&self, entry: &CursorEntry, cursor: OwnedCursor) {
        *lock(&entry.last_used) = self.clock.monotonic();
        *lock(&entry.slot) = Some(cursor);
    }

    /// Forgets the cursor `id` (its handle, if checked in, is returned to be closed).
    pub(crate) fn remove(&self, id: &str) -> Option<OwnedCursor> {
        let mut inner = self.lock();
        let entry = inner.cursors.remove(id)?;
        inner.total.count -= 1;
        inner.total.bytes -= entry.reserved;
        if let Some(u) = inner.per_owner.get_mut(&entry.owner) {
            u.count -= 1;
            u.bytes -= entry.reserved;
            if u.count == 0 {
                inner.per_owner.remove(&entry.owner);
            }
        }
        drop(inner);
        lock(&entry.slot).take()
    }

    /// `KillCursor`: `false` if unknown (kill is idempotent).
    pub(crate) fn kill(&self, id: &str, owner: Option<&str>) -> bool {
        let known = self
            .lock()
            .cursors
            .get(id)
            .is_some_and(|e| e.owner.as_deref() == owner);
        if !known {
            return false;
        }
        if let Some(entry) = self.lock().cursors.get(id) {
            // Stops a batch in progress (a racing GetMore then fails and drops the cursor).
            entry.cancel.cancel();
        }
        close_off_thread(self.remove(id));
        true
    }

    /// Closes cursors idle beyond the timeout. Blocking (closing commits read-only snapshots).
    pub(crate) fn sweep_blocking(&self) {
        let now = self.clock.monotonic();
        let expired: Vec<String> = self
            .lock()
            .cursors
            .iter()
            .filter(|(_, e)| {
                lock(&e.slot).is_some()
                    && now.saturating_sub(*lock(&e.last_used)) > self.idle_timeout
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(cursor) = self.remove(&id) {
                close(cursor);
            }
        }
    }

    /// Closes every registered cursor (graceful shutdown, PD-054) and returns how many were
    /// closed. A cursor checked out by a batch still running is cancelled; that batch then
    /// fails and drops (closes) it. Blocking.
    pub(crate) fn close_all_blocking(&self) -> usize {
        let ids: Vec<String> = self.lock().cursors.keys().cloned().collect();
        let mut closed = 0;
        for id in ids {
            if let Some(entry) = self.lock().cursors.get(&id) {
                entry.cancel.cancel();
            }
            if let Some(cursor) = self.remove(&id) {
                close(cursor);
                closed += 1;
            }
        }
        closed
    }

    /// Open cursors (tests, diagnostics).
    pub(crate) fn len(&self) -> usize {
        self.lock().cursors.len()
    }
}

fn close(cursor: OwnedCursor) {
    // A read-only snapshot: a failed close only means the commit of nothing failed.
    if let Err(e) = cursor.close() {
        tracing::debug!(error = %e, "closing an expired cursor failed");
    }
}

/// Closes a cursor without blocking the caller's async worker.
pub(crate) fn close_off_thread(cursor: Option<OwnedCursor>) {
    let Some(cursor) = cursor else {
        return;
    };
    match tokio::runtime::Handle::try_current() {
        Ok(rt) => drop(rt.spawn_blocking(move || close(cursor))),
        Err(_) => close(cursor),
    }
}
