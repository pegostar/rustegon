// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Per-group in-memory state: metadata plus the location of every stored entry.
//!
//! The same state machine ([`GroupState::apply`]) runs when a batch is acknowledged and when
//! recovery replays the segments, so the live index and the recovered index cannot drift apart.
//! During replay a group's entries may temporarily be incomplete: segments whose entries were
//! all purged are deleted, while the metadata snapshot at the head of the next segment still
//! describes the group as it was when that segment started. A later `Purge` record (which must
//! exist, or the segment would not have been deleted) brings the two back in line;
//! [`GroupState::verify_complete`] checks that at the end of recovery.

use std::collections::{BTreeMap, VecDeque};

/// Raft hard state of one group, persisted in the same batch as the entries it covers
/// (replication.md §2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct HardState {
    /// Current term.
    pub term: u64,
    /// Candidate voted for in `term` (0 = none).
    pub vote: u64,
    /// Highest index known to be committed.
    pub commit: u64,
}

/// Log metadata of one group (persisted by `SetState` records, format v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GroupMeta {
    /// First stored index; entries below were purged.
    pub(crate) first_index: u64,
    /// Last stored index (`first_index - 1` when the log is empty).
    pub(crate) last_index: u64,
    /// Term of `last_index` (equals `boundary_term` when the log is empty).
    pub(crate) last_term: u64,
    /// Term of `first_index - 1`, the last purged entry (0 for a fresh group).
    pub(crate) boundary_term: u64,
    /// Latest persisted hard state.
    pub(crate) hard_state: HardState,
}

impl Default for GroupMeta {
    /// A group never written: Raft logs start at index 1.
    fn default() -> Self {
        Self {
            first_index: 1,
            last_index: 0,
            last_term: 0,
            boundary_term: 0,
            hard_state: HardState::default(),
        }
    }
}

/// Where an entry's payload lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Loc {
    /// Segment id.
    pub(crate) segment: u64,
    /// File offset of the payload.
    pub(crate) offset: u64,
    /// Payload length.
    pub(crate) len: u32,
    /// Entry term.
    pub(crate) term: u64,
}

/// A state change carried by one persisted operation.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Change {
    /// Entry `index` stored at `loc`; any entries at or above `index` are replaced.
    Entry { index: u64, loc: Loc },
    /// New hard state.
    HardState(HardState),
    /// Entries above `last_index` removed; `last_term` is the term of `last_index`.
    Truncate { last_index: u64, last_term: u64 },
    /// Entries below `first_index` removed; `boundary_term` is the term of `first_index - 1`.
    Purge {
        first_index: u64,
        boundary_term: u64,
    },
    /// Metadata replaced wholesale (segment-head snapshot, snapshot install).
    SetState(GroupMeta),
}

/// Live entries per segment: a segment can be deleted once it holds none (and is not the
/// active one), because every later segment starts with a snapshot of all groups' metadata.
pub(crate) type LiveCounts = BTreeMap<u64, u64>;

/// Applies `change` to `group` in `groups`; `None` removes the group with all its entries.
pub(crate) fn apply_to(
    groups: &mut BTreeMap<u64, GroupState>,
    counts: &mut LiveCounts,
    group: u64,
    change: Option<Change>,
) -> Result<(), String> {
    let Some(change) = change else {
        if let Some(mut g) = groups.remove(&group) {
            g.drop_all(counts);
        }
        return Ok(());
    };
    groups
        .entry(group)
        .or_default()
        .apply(change, counts)
        .map_err(|e| format!("group {group}: {e}"))
}

/// One group's metadata and entry locations.
#[derive(Debug, Default)]
pub(crate) struct GroupState {
    pub(crate) meta: GroupMeta,
    /// Index of `locs[0]`.
    start: u64,
    /// Contiguous entry locations from `start`; after recovery exactly `first..=last`.
    locs: VecDeque<Loc>,
}

fn dec(counts: &mut LiveCounts, loc: &Loc) {
    if let Some(n) = counts.get_mut(&loc.segment) {
        *n = n.saturating_sub(1);
    }
}

impl GroupState {
    /// Applies one change. Errors describe a sequence the writer never produces: corruption at
    /// replay, a bug in batch resolution when live.
    pub(crate) fn apply(&mut self, change: Change, counts: &mut LiveCounts) -> Result<(), String> {
        let m = &mut self.meta;
        match change {
            Change::Entry { index, loc } => {
                if index < m.first_index || index > m.last_index.saturating_add(1) {
                    return Err(format!(
                        "entry {index} outside [{}, {}]",
                        m.first_index,
                        m.last_index.saturating_add(1)
                    ));
                }
                self.drop_from(index, counts);
                if self.locs.is_empty() {
                    self.start = index;
                } else if self.end() != index {
                    return Err(format!(
                        "entry {index} leaves a gap after {}",
                        self.end() - 1
                    ));
                }
                self.locs.push_back(loc);
                *counts.entry(loc.segment).or_insert(0) += 1;
                self.meta.last_index = index;
                self.meta.last_term = loc.term;
            }
            Change::HardState(hs) => m.hard_state = hs,
            Change::Truncate {
                last_index,
                last_term,
            } => {
                if last_index.saturating_add(1) < m.first_index || last_index > m.last_index {
                    return Err(format!(
                        "truncation to {last_index} outside [{}, {}]",
                        m.first_index.saturating_sub(1),
                        m.last_index
                    ));
                }
                m.last_index = last_index;
                m.last_term = last_term;
                self.drop_from(last_index + 1, counts);
            }
            Change::Purge {
                first_index,
                boundary_term,
            } => {
                if first_index < m.first_index || first_index > m.last_index.saturating_add(1) {
                    return Err(format!(
                        "purge to {first_index} outside [{}, {}]",
                        m.first_index,
                        m.last_index.saturating_add(1)
                    ));
                }
                m.first_index = first_index;
                m.boundary_term = boundary_term;
                if m.last_index + 1 == first_index {
                    m.last_term = boundary_term;
                }
                self.drop_below(first_index, counts);
            }
            Change::SetState(meta) => {
                if meta.first_index == 0 || meta.last_index.saturating_add(1) < meta.first_index {
                    return Err(format!(
                        "invalid group state [{}, {}]",
                        meta.first_index, meta.last_index
                    ));
                }
                self.meta = meta;
                self.drop_below(meta.first_index, counts);
                self.drop_from(meta.last_index.saturating_add(1), counts);
            }
        }
        Ok(())
    }

    /// One past the last tracked index.
    fn end(&self) -> u64 {
        self.start + self.locs.len() as u64
    }

    /// Forgets tracked entries at or above `index`.
    fn drop_from(&mut self, index: u64, counts: &mut LiveCounts) {
        while !self.locs.is_empty() && self.end() > index {
            if let Some(loc) = self.locs.pop_back() {
                dec(counts, &loc);
            }
        }
    }

    /// Forgets tracked entries below `index`.
    fn drop_below(&mut self, index: u64, counts: &mut LiveCounts) {
        while self.start < index {
            match self.locs.pop_front() {
                Some(loc) => {
                    dec(counts, &loc);
                    self.start += 1;
                }
                None => break,
            }
        }
    }

    /// Forgets every entry (group removal).
    pub(crate) fn drop_all(&mut self, counts: &mut LiveCounts) {
        for loc in self.locs.drain(..) {
            dec(counts, &loc);
        }
    }

    /// Checks that exactly `first..=last` is tracked (end of recovery).
    pub(crate) fn verify_complete(&self) -> Result<(), String> {
        let want = self.meta.last_index + 1 - self.meta.first_index;
        let complete = self.locs.len() as u64 == want
            && (self.locs.is_empty() || self.start == self.meta.first_index);
        if complete {
            Ok(())
        } else {
            Err(format!(
                "log [{}, {}] but entries [{}, {}) are stored",
                self.meta.first_index,
                self.meta.last_index,
                self.start,
                self.end()
            ))
        }
    }

    /// Location of stored entry `index`.
    pub(crate) fn loc(&self, index: u64) -> Option<&Loc> {
        if index < self.meta.first_index || index > self.meta.last_index {
            return None;
        }
        let pos = usize::try_from(index.checked_sub(self.start)?).ok()?;
        self.locs.get(pos)
    }

    /// Term of `index`: a stored entry or the last purged one.
    pub(crate) fn term(&self, index: u64) -> Option<u64> {
        if index + 1 == self.meta.first_index {
            return Some(self.meta.boundary_term);
        }
        self.loc(index).map(|l| l.term)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(segment: u64, term: u64) -> Loc {
        Loc {
            segment,
            offset: 0,
            len: 0,
            term,
        }
    }

    #[test]
    fn group_state_tracks_entries_and_live_counts() {
        let mut g = GroupState::default();
        let mut counts = LiveCounts::new();
        for i in 1..=5 {
            g.apply(
                Change::Entry {
                    index: i,
                    loc: loc(i / 3, 1),
                },
                &mut counts,
            )
            .unwrap();
        }
        assert_eq!(counts, LiveCounts::from([(0, 2), (1, 3)]));
        // Overwrite from 4 with a higher term.
        g.apply(
            Change::Entry {
                index: 4,
                loc: loc(2, 2),
            },
            &mut counts,
        )
        .unwrap();
        assert_eq!((g.meta.last_index, g.meta.last_term), (4, 2));
        assert_eq!(counts, LiveCounts::from([(0, 2), (1, 1), (2, 1)]));
        g.apply(
            Change::Purge {
                first_index: 3,
                boundary_term: 1,
            },
            &mut counts,
        )
        .unwrap();
        assert_eq!(counts, LiveCounts::from([(0, 0), (1, 1), (2, 1)]));
        assert_eq!(g.term(2), Some(1));
        assert_eq!(g.term(1), None);
        g.verify_complete().unwrap();
        // Gaps and out-of-range changes are rejected.
        assert!(
            g.apply(
                Change::Entry {
                    index: 9,
                    loc: loc(2, 2)
                },
                &mut counts
            )
            .is_err()
        );
        assert!(
            g.apply(
                Change::Truncate {
                    last_index: 1,
                    last_term: 1
                },
                &mut counts
            )
            .is_err()
        );
    }
}
