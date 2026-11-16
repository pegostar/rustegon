// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Write batches: the public [`LogBatch`] builder and its validation against the current state
//! ([`Shadow`]) into the persisted operations of format v1 ([`encode`]).
//!
//! Validation runs completely before anything is written, against a per-group view that
//! includes the batch's own earlier operations, so an invalid batch has no effect at all and a
//! valid one is persisted and applied as a unit.

use super::{
    error::{LogStoreError, Result},
    format::RecordBuilder,
    group::{Change, GroupMeta, GroupState, HardState},
};

#[derive(Debug, Clone)]
pub(super) enum BatchOp {
    Append {
        group: u64,
        index: u64,
        term: u64,
        payload: Vec<u8>,
    },
    HardState {
        group: u64,
        hs: HardState,
    },
    TruncateSuffix {
        group: u64,
        from: u64,
    },
    Purge {
        group: u64,
        up_to: u64,
    },
    InstallSnapshot {
        group: u64,
        index: u64,
        term: u64,
    },
    RemoveGroup {
        group: u64,
    },
}

impl BatchOp {
    pub(super) fn group(&self) -> u64 {
        match self {
            Self::Append { group, .. }
            | Self::HardState { group, .. }
            | Self::TruncateSuffix { group, .. }
            | Self::Purge { group, .. }
            | Self::InstallSnapshot { group, .. }
            | Self::RemoveGroup { group } => *group,
        }
    }
}

/// Operations of any number of groups persisted together with one sync (group commit).
/// Operations apply in insertion order; validation happens in [`LogStore::write`](super::LogStore::write).
#[derive(Debug, Clone, Default)]
pub struct LogBatch {
    pub(super) ops: Vec<BatchOp>,
}

impl LogBatch {
    /// An empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends entry `index` of `group`. Existing entries at or above `index` are replaced (Raft
    /// conflict resolution). Requires `first_index <= index <= last_index + 1` and a term not
    /// lower than that of `index - 1`.
    pub fn append(
        &mut self,
        group: u64,
        index: u64,
        term: u64,
        payload: impl Into<Vec<u8>>,
    ) -> &mut Self {
        self.ops.push(BatchOp::Append {
            group,
            index,
            term,
            payload: payload.into(),
        });
        self
    }

    /// Persists `group`'s hard state.
    pub fn set_hard_state(&mut self, group: u64, hs: HardState) -> &mut Self {
        self.ops.push(BatchOp::HardState { group, hs });
        self
    }

    /// Removes `group`'s entries at or above `from` (no-op if `from > last_index`; `from` must
    /// not be below `first_index`).
    pub fn truncate_suffix(&mut self, group: u64, from: u64) -> &mut Self {
        self.ops.push(BatchOp::TruncateSuffix { group, from });
        self
    }

    /// Removes `group`'s entries up to and including `up_to` (applied and flushed, or covered by
    /// a snapshot). No-op if already purged; `up_to` must not exceed `last_index`.
    pub fn purge(&mut self, group: u64, up_to: u64) -> &mut Self {
        self.ops.push(BatchOp::Purge { group, up_to });
        self
    }

    /// Replaces `group`'s log by an empty one positioned after a snapshot at `(index, term)`:
    /// all entries are dropped, the next append is `index + 1`. The hard state is kept.
    pub fn install_snapshot(&mut self, group: u64, index: u64, term: u64) -> &mut Self {
        self.ops
            .push(BatchOp::InstallSnapshot { group, index, term });
        self
    }

    /// Forgets `group` entirely (replica removed from this node).
    pub fn remove_group(&mut self, group: u64) -> &mut Self {
        self.ops.push(BatchOp::RemoveGroup { group });
        self
    }

    /// Whether the batch holds no operation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Number of operations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Removes all operations, keeping the allocation.
    pub fn clear(&mut self) {
        self.ops.clear();
    }
}

/// A batch operation validated against the current state, in its persisted form.
pub(super) enum Resolved<'b> {
    Entry {
        group: u64,
        index: u64,
        term: u64,
        payload: &'b [u8],
    },
    Change {
        group: u64,
        change: Change,
    },
    Remove {
        group: u64,
    },
}

/// A group's state as seen by the batch being resolved: metadata plus the terms of entries the
/// batch appended. Terms of older entries come from the committed state while
/// `use_committed` holds (the batch neither removed nor reset the group).
pub(super) struct Shadow {
    meta: GroupMeta,
    appended_start: u64,
    appended: Vec<u64>,
    use_committed: bool,
}

impl Shadow {
    pub(super) fn new(committed: Option<&GroupState>) -> Self {
        let meta = committed.map_or_else(GroupMeta::default, |g| g.meta);
        Self {
            meta,
            appended_start: meta.last_index.saturating_add(1),
            appended: Vec::new(),
            use_committed: committed.is_some(),
        }
    }

    fn term(&self, index: u64, committed: Option<&GroupState>) -> Option<u64> {
        if index.checked_add(1) == Some(self.meta.first_index) {
            return Some(self.meta.boundary_term);
        }
        if index < self.meta.first_index || index > self.meta.last_index {
            return None;
        }
        if index >= self.appended_start {
            let pos = usize::try_from(index - self.appended_start).ok()?;
            return self.appended.get(pos).copied();
        }
        if self.use_committed {
            committed?.term(index)
        } else {
            None
        }
    }

    /// Forgets appended terms at or above `index`.
    fn cut(&mut self, index: u64) {
        if index < self.appended_start {
            self.appended.clear();
            self.appended_start = index;
        } else {
            let keep = usize::try_from(index - self.appended_start).unwrap_or(usize::MAX);
            self.appended.truncate(keep);
        }
    }

    /// Validates `op` of `group` against this view, updates the view, and returns the persisted
    /// form (`None` for a no-op).
    // One short arm per operation kind; splitting them would scatter the shared validation
    // context (`range`, `term_of`) over several functions (coding-standards.md §1 exception).
    #[allow(clippy::too_many_lines)]
    pub(super) fn resolve<'b>(
        &mut self,
        group: u64,
        op: &'b BatchOp,
        committed: Option<&GroupState>,
    ) -> Result<Option<Resolved<'b>>> {
        let m = self.meta;
        let range = || {
            format!(
                "group {group} with log [{}, {}]",
                m.first_index, m.last_index
            )
        };
        let term_of = |s: &Self, index: u64| {
            s.term(index, committed).ok_or_else(|| {
                LogStoreError::invalid(format!("no term for {index} in {}", range()))
            })
        };
        let change = match *op {
            BatchOp::Append {
                index,
                term,
                ref payload,
                ..
            } => {
                if index < m.first_index || Some(index) > m.last_index.checked_add(1) {
                    return Err(LogStoreError::invalid(format!(
                        "append of index {index} to {}",
                        range()
                    )));
                }
                let prev = term_of(self, index - 1)?;
                if term < prev {
                    return Err(LogStoreError::invalid(format!(
                        "entry {index} term {term} below term {prev} of its predecessor in {}",
                        range()
                    )));
                }
                self.cut(index);
                self.appended.push(term);
                self.meta.last_index = index;
                self.meta.last_term = term;
                return Ok(Some(Resolved::Entry {
                    group,
                    index,
                    term,
                    payload,
                }));
            }
            BatchOp::HardState { hs, .. } => {
                self.meta.hard_state = hs;
                Change::HardState(hs)
            }
            BatchOp::TruncateSuffix { from, .. } => {
                if from > m.last_index {
                    return Ok(None);
                }
                if from < m.first_index {
                    return Err(LogStoreError::invalid(format!(
                        "truncation from purged index {from} in {}",
                        range()
                    )));
                }
                let last_term = term_of(self, from - 1)?;
                self.cut(from);
                self.meta.last_index = from - 1;
                self.meta.last_term = last_term;
                Change::Truncate {
                    last_index: from - 1,
                    last_term,
                }
            }
            BatchOp::Purge { up_to, .. } => {
                if up_to < m.first_index {
                    return Ok(None);
                }
                if up_to > m.last_index {
                    return Err(LogStoreError::invalid(format!(
                        "purge up to {up_to} beyond the end of {}",
                        range()
                    )));
                }
                let boundary_term = term_of(self, up_to)?;
                self.meta.first_index = up_to + 1;
                self.meta.boundary_term = boundary_term;
                Change::Purge {
                    first_index: up_to + 1,
                    boundary_term,
                }
            }
            BatchOp::InstallSnapshot { index, term, .. } => {
                let first_index = index.checked_add(1).ok_or_else(|| {
                    LogStoreError::invalid(format!("snapshot index {index} too large"))
                })?;
                let meta = GroupMeta {
                    first_index,
                    last_index: index,
                    last_term: term,
                    boundary_term: term,
                    hard_state: m.hard_state,
                };
                self.reset(meta);
                Change::SetState(meta)
            }
            BatchOp::RemoveGroup { .. } => {
                self.reset(GroupMeta::default());
                return Ok(Some(Resolved::Remove { group }));
            }
        };
        Ok(Some(Resolved::Change { group, change }))
    }

    fn reset(&mut self, meta: GroupMeta) {
        self.meta = meta;
        self.appended.clear();
        self.appended_start = meta.last_index.saturating_add(1);
        self.use_committed = false;
    }
}

/// Encodes `ops` as one record into `buf`; returns the record offsets of the entry payloads.
/// With `sealed` (encrypted segment) each payload is followed by room for its GCM tag; the
/// store seals the payloads in place once the record's position in the segment is known.
pub(super) fn encode(buf: &mut Vec<u8>, ops: &[Resolved<'_>], sealed: bool) -> Result<Vec<usize>> {
    let mut b = RecordBuilder::new(buf);
    let mut offsets = Vec::new();
    for op in ops {
        match *op {
            Resolved::Entry {
                group,
                index,
                term,
                payload,
            } => {
                if u32::try_from(payload.len()).is_err() {
                    return Err(LogStoreError::invalid("entry payload exceeds 4 GiB"));
                }
                offsets.push(b.entry(group, index, term, payload, sealed));
            }
            Resolved::Change { group, change } => match change {
                Change::HardState(hs) => b.hard_state(group, hs),
                Change::Truncate {
                    last_index,
                    last_term,
                } => b.truncate(group, last_index, last_term),
                Change::Purge {
                    first_index,
                    boundary_term,
                } => b.purge(group, first_index, boundary_term),
                Change::SetState(meta) => b.set_state(group, &meta),
                // Entries carry their payload and are encoded above.
                Change::Entry { .. } => {
                    return Err(LogStoreError::invalid("entry change without payload"));
                }
            },
            Resolved::Remove { group } => b.remove_group(group),
        }
    }
    b.finish().map_err(LogStoreError::invalid)?;
    Ok(offsets)
}
