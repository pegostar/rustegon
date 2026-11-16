// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Waiting on conflicting intents (transaction-management.md §5): the waiter joins the key's
//! wait queue, records its wait-for edge, runs the local deadlock detector and re-evaluates the
//! push decision (`conflict.rs`) every `wait_slice` until the intent can be resolved or read
//! past. Every slice also checks the waiter's own state (it may have been chosen as a deadlock
//! victim or exceeded its duration) and counts as its heartbeat.
//!
//! No latch is held while waiting; the only lock held across a blocking wait is the mutex of
//! the condition variable waited on (the holder's state, the waiter's own state, or the wait
//! queues), each a leaf at that point.

use std::sync::Arc;

use rustegon_mvcc::{Intent, TxnId};

use super::Txn;
use crate::{
    conflict::{Access, Decision},
    coordinator::Core,
    error::{AbortReason, Result, TxnError},
    lock_table::QueueSlot,
};

impl Txn {
    /// Waits until every intent in `intents` is resolved (or, for a single intent met by a
    /// point read, until the reader may read past it: returns its holder).
    pub(super) fn wait_conflicts(
        &mut self,
        intents: &[Intent],
        access: Access,
    ) -> Result<Option<TxnId>> {
        let single = intents.len() == 1;
        for intent in intents {
            if intent.meta.txn_id == self.shared.id {
                return Err(TxnError::Internal(
                    "own intent reported as a conflict".into(),
                ));
            }
            let read_past = self.wait_one(intent, access)?;
            if single && read_past {
                return Ok(Some(intent.meta.txn_id));
            }
        }
        Ok(None)
    }

    /// Waits for one intent; `true` if the caller may read past it.
    fn wait_one(&mut self, intent: &Intent, access: Access) -> Result<bool> {
        let core = Arc::clone(&self.core);
        let slot = core.locks.enqueue(&intent.key, self.shared.id);
        let result = self.wait_loop(&core, &slot, intent, access);
        self.shared.set_waiting_on(None);
        drop(slot);
        result
    }

    fn wait_loop(
        &mut self,
        core: &Core,
        slot: &QueueSlot<'_>,
        intent: &Intent,
        access: Access,
    ) -> Result<bool> {
        let slice = core.config.wait_slice;
        let mut yielded = false;
        loop {
            self.check_active()?;
            let priority = self.shared.lock().priority;
            match core.decide(intent, priority, access)? {
                Decision::ReadPast => return Ok(true),
                Decision::Pushed {
                    resolution,
                    persist_abort,
                } => {
                    core.resolve(intent, &resolution, persist_abort)?;
                    return Ok(false);
                }
                Decision::Finished(resolution) => {
                    // Wait-queue order: the head resolves and retries first. Others yield to
                    // it for one slice only: the head may itself be waiting for another
                    // holder, and a queue edge is not in the wait-for graph, so waiting for
                    // it indefinitely could hide a deadlock.
                    if slot.is_head() || yielded {
                        core.resolve(intent, &resolution, false)?;
                        return Ok(false);
                    }
                    yielded = true;
                    slot.wait_turn(slice);
                }
                Decision::Wait(holder) => {
                    self.shared.set_waiting_on(Some(intent.meta.txn_id));
                    if let Some(victim) = core.registry.find_deadlock_victim(&self.shared) {
                        // The victim notices on its next check and removes its intents. Until
                        // it has, the cycle is still visible here: keep waiting (below) instead
                        // of re-detecting in a busy loop; only a self-victim re-checks at once.
                        if victim.abort_if_pending(AbortReason::Deadlock) {
                            tracing::info!(
                                victim = ?victim.id,
                                waiter = ?self.shared.id,
                                "deadlock detected"
                            );
                        }
                        if victim.id == self.shared.id {
                            continue;
                        }
                    }
                    match holder {
                        Some(holder) => holder.wait_for_change(slice),
                        // Unregistered holder: poll its record each slice (woken early only if
                        // this transaction itself is aborted).
                        None => self.shared.wait_for_change(slice),
                    }
                }
            }
        }
    }
}
