// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Hybrid logical clock (transaction-management.md §2; Kulkarni et al., "Logical Physical
//! Clocks", 2014) and its persisted upper bound (§7 "clock jump backward").
//!
//! - [`Hlc::now`]: `max(physical, last)`, the logical counter incremented when the physical
//!   clock has not passed `last.wall` (ties, or a physical clock behind `last`).
//! - [`Hlc::update`]: on message receipt `last = max(last, received)`, so every later local event
//!   is ordered after the sender's event (causality across nodes).
//!
//! **Restart monotonicity** (TC-TXN-009). A clock that jumps backward while the process is down
//! would make the restarted node issue timestamps below ones it already handed out. The node
//! therefore persists an upper bound `wall_max` of every wall time it may issue
//! ([`HlcBoundStore`]), and a restarted HLC starts at `wall_max` ([`Hlc::recover`]):
//! - the bound is extended to `max(physical, last.wall) + HLC_BOUND_AHEAD` (1 s) and persisted
//!   every [`HLC_PERSIST_INTERVAL`] (500 ms) by [`Hlc::persist_bound`] (the server's
//!   scheduler calls it from the I/O pool; it is synchronous file I/O);
//! - [`Hlc::now`] never lets the *physical* component pass the persisted bound: if the
//!   physical clock runs past it (the persister is late), the wall component is held at
//!   `bound − 1` and only the logical counter advances. Timestamps stay strictly monotonic and
//!   below the bound, so after a restart `now() > wall_max >` everything issued before.
//! - [`Hlc::update`] must adopt a received timestamp even above the bound (causality beats the
//!   bound); such a timestamp already exists in the cluster, and the next persist covers it.
//!
//! Only if the logical counter would overflow while held (2³² events with the physical clock
//! stalled at the bound) does the wall component pass the bound; that is logged as an error.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, UNIX_EPOCH},
};

use rustegon_sim_api::{Clock, FileSystem, OpenMode};
use twox_hash::XxHash3_64;

use crate::error::{MvccError, Result};

/// How far ahead of the current wall time the persisted bound is set (§7: `now + 1 s`).
pub const HLC_BOUND_AHEAD: Duration = Duration::from_secs(1);
/// How often the server persists the bound (§7: every 500 ms). Half of [`HLC_BOUND_AHEAD`], so a
/// timely persister keeps the physical clock below the bound.
pub const HLC_PERSIST_INTERVAL: Duration = Duration::from_millis(500);

/// A hybrid logical clock timestamp; total order is lexicographic on `(wall, logical)` (§2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    /// Physical component, nanoseconds since the Unix epoch.
    pub wall: u64,
    /// Logical component, orders events with the same wall time.
    pub logical: u32,
}

impl Timestamp {
    /// The smallest timestamp.
    pub const MIN: Self = Self::new(0, 0);
    /// The largest timestamp.
    pub const MAX: Self = Self::new(u64::MAX, u32::MAX);
    /// Encoded size: wall u64 BE ‖ logical u32 BE.
    pub const ENCODED_LEN: usize = 12;

    /// A timestamp from its components.
    #[must_use]
    pub const fn new(wall: u64, logical: u32) -> Self {
        Self { wall, logical }
    }

    /// The smallest timestamp greater than `self` (saturating at [`Timestamp::MAX`]).
    #[must_use]
    pub const fn next(self) -> Self {
        if self.logical < u32::MAX {
            Self::new(self.wall, self.logical + 1)
        } else if self.wall < u64::MAX {
            Self::new(self.wall + 1, 0)
        } else {
            Self::MAX
        }
    }

    /// `wall u64 BE ‖ logical u32 BE` (byte order = timestamp order).
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0; Self::ENCODED_LEN];
        out[..8].copy_from_slice(&self.wall.to_be_bytes());
        out[8..].copy_from_slice(&self.logical.to_be_bytes());
        out
    }

    /// Inverse of [`Timestamp::to_be_bytes`].
    #[must_use]
    pub fn from_be_bytes(bytes: [u8; Self::ENCODED_LEN]) -> Self {
        let mut wall = [0; 8];
        let mut logical = [0; 4];
        wall.copy_from_slice(&bytes[..8]);
        logical.copy_from_slice(&bytes[8..]);
        Self::new(u64::from_be_bytes(wall), u32::from_be_bytes(logical))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:010}", self.wall, self.logical)
    }
}

/// Mutable clock state.
#[derive(Debug)]
struct HlcState {
    /// The largest timestamp issued or received.
    last: Timestamp,
    /// Persisted upper bound of issued wall times; `None` when the clock is not persisted
    /// (tests, tools).
    bound: Option<u64>,
}

/// The node's hybrid logical clock. Cheap to share behind an `Arc`; all methods take `&self`.
///
/// Locking: one mutex protects the state; it is never held across I/O ([`Hlc::persist_bound`]
/// writes the file between two short critical sections).
pub struct Hlc {
    clock: Arc<dyn Clock>,
    state: Mutex<HlcState>,
}

impl fmt::Debug for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hlc")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Hlc {
    /// A clock without a persisted bound, starting at the physical time.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            state: Mutex::new(HlcState {
                last: Timestamp::MIN,
                bound: None,
            }),
        }
    }

    /// The clock of a restarting node: starts at the bound persisted in `store` (if any), so
    /// every timestamp it issues exceeds every timestamp issued before the restart, even if the
    /// physical clock went backward meanwhile. Call [`Hlc::persist_bound`] before serving: until
    /// then the wall component is held at the old bound.
    ///
    /// # Errors
    /// Corruption or I/O errors reading the bound file.
    pub fn recover(clock: Arc<dyn Clock>, store: &HlcBoundStore) -> Result<Self> {
        let persisted = store.load()?;
        let hlc = Self::new(clock);
        if let Some(wall_max) = persisted {
            let mut state = hlc.lock();
            state.last = Timestamp::new(wall_max, 0);
            state.bound = Some(wall_max);
        }
        Ok(hlc)
    }

    fn lock(&self) -> MutexGuard<'_, HlcState> {
        // The state is two plain values updated together; a panicking holder cannot leave them
        // half-written, so poison carries no information.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Physical time in nanoseconds since the Unix epoch (0 before it, saturating far after).
    fn physical(&self) -> u64 {
        self.clock
            .wall()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
    }

    /// A new timestamp, strictly greater than every timestamp issued or received before (§2).
    #[must_use]
    pub fn now(&self) -> Timestamp {
        let physical = self.physical();
        let mut state = self.lock();
        // Hold the physical component below the persisted bound (module docs).
        let physical = match state.bound {
            Some(bound) => physical.min(bound.saturating_sub(1)),
            None => physical,
        };
        let next = if physical > state.last.wall {
            Timestamp::new(physical, 0)
        } else if state.last.logical < u32::MAX {
            Timestamp::new(state.last.wall, state.last.logical + 1)
        } else {
            let next = state.last.next();
            if state.bound.is_some_and(|b| next.wall >= b) {
                tracing::error!(
                    wall = next.wall,
                    "HLC logical counter exhausted at the persisted bound; wall time passes it"
                );
            }
            next
        };
        state.last = next;
        next
    }

    /// Merges a timestamp received from another node: `last = max(last, received)` (§2), so the
    /// next [`Hlc::now`] is greater than `received`.
    pub fn update(&self, received: Timestamp) {
        let mut state = self.lock();
        if received > state.last {
            state.last = received;
        }
    }

    /// The largest timestamp issued or received so far (not a new timestamp).
    #[must_use]
    pub fn last(&self) -> Timestamp {
        self.lock().last
    }

    /// The persisted upper bound, if the clock is persisted.
    #[must_use]
    pub fn bound(&self) -> Option<u64> {
        self.lock().bound
    }

    /// Extends the persisted bound to `max(physical, last.wall) + ahead`, writes it durably to
    /// `store`, and only then lets [`Hlc::now`] use it; returns the new bound. Run every
    /// [`HLC_PERSIST_INTERVAL`] with [`HLC_BOUND_AHEAD`].
    ///
    /// # Errors
    /// I/O errors writing the bound; the in-memory bound is then unchanged (still safe).
    pub fn persist_bound(&self, store: &HlcBoundStore, ahead: Duration) -> Result<u64> {
        let ahead = u64::try_from(ahead.as_nanos()).unwrap_or(u64::MAX);
        let (last, bound) = {
            let state = self.lock();
            (state.last.wall, state.bound)
        };
        // Never lower the persisted bound (a backward clock would otherwise shrink it below
        // timestamps already issued).
        let target = self
            .physical()
            .max(last)
            .saturating_add(ahead)
            .max(bound.unwrap_or(0));
        // Durable first: a bound the clock may use must survive a crash (module docs).
        store.store(target)?;
        let mut state = self.lock();
        let bound = state.bound.map_or(target, |b| b.max(target));
        state.bound = Some(bound);
        Ok(bound)
    }
}

/// Magic of the HLC bound file.
const BOUND_MAGIC: &[u8; 4] = b"RHLC";
/// Format version of the HLC bound file (implementation-rules.md §6).
pub const BOUND_FORMAT_VERSION: u8 = 1;
/// Encoded size: magic(4) ‖ version(1) ‖ `wall_max` u64 BE (8) ‖ xxh3-64 of the preceding 13
/// bytes, u64 BE (8).
pub const BOUND_FILE_LEN: usize = 21;
/// File name of the bound inside the store's directory.
pub const BOUND_FILE_NAME: &str = "HLC_BOUND";
const BOUND_TMP_NAME: &str = "HLC_BOUND.tmp";

/// Encodes the bound file (transaction-management.md §3 "HLC bound file").
#[must_use]
pub fn encode_bound(wall_max: u64) -> [u8; BOUND_FILE_LEN] {
    let mut out = [0; BOUND_FILE_LEN];
    out[..4].copy_from_slice(BOUND_MAGIC);
    out[4] = BOUND_FORMAT_VERSION;
    out[5..13].copy_from_slice(&wall_max.to_be_bytes());
    let sum = XxHash3_64::oneshot(&out[..13]);
    out[13..].copy_from_slice(&sum.to_be_bytes());
    out
}

/// Decodes the bound file.
///
/// # Errors
/// [`MvccError::Corruption`] on a wrong length, magic, version or checksum.
pub fn decode_bound(bytes: &[u8]) -> Result<u64> {
    let bytes: &[u8; BOUND_FILE_LEN] = bytes
        .try_into()
        .map_err(|_| MvccError::corruption(format!("HLC bound file of {} bytes", bytes.len())))?;
    if &bytes[..4] != BOUND_MAGIC {
        return Err(MvccError::corruption("HLC bound file: bad magic"));
    }
    if bytes[4] != BOUND_FORMAT_VERSION {
        return Err(MvccError::corruption(format!(
            "HLC bound file: unknown version {}",
            bytes[4]
        )));
    }
    let mut sum = [0; 8];
    sum.copy_from_slice(&bytes[13..]);
    if u64::from_be_bytes(sum) != XxHash3_64::oneshot(&bytes[..13]) {
        return Err(MvccError::corruption("HLC bound file: checksum mismatch"));
    }
    let mut wall = [0; 8];
    wall.copy_from_slice(&bytes[5..13]);
    Ok(u64::from_be_bytes(wall))
}

/// Durable storage of the HLC upper bound: one small file, replaced atomically (write a
/// temporary file, fsync, rename, fsync the directory) so a crash leaves the old or the new
/// bound, never a torn one.
pub struct HlcBoundStore {
    fs: Arc<dyn FileSystem>,
    dir: PathBuf,
}

impl fmt::Debug for HlcBoundStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HlcBoundStore")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl HlcBoundStore {
    /// A store keeping the bound in `dir` (created on the first [`HlcBoundStore::store`]).
    #[must_use]
    pub fn new(fs: Arc<dyn FileSystem>, dir: &Path) -> Self {
        Self {
            fs,
            dir: dir.to_path_buf(),
        }
    }

    /// The persisted bound; `None` if none was ever written.
    ///
    /// # Errors
    /// Corruption of the file, I/O errors.
    pub fn load(&self) -> Result<Option<u64>> {
        let path = self.dir.join(BOUND_FILE_NAME);
        let file = match self.fs.open(&path, OpenMode::Read) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(MvccError::Storage(e.into())),
        };
        let size = file.size().map_err(|e| MvccError::Storage(e.into()))?;
        if size != BOUND_FILE_LEN as u64 {
            return Err(MvccError::corruption(format!(
                "HLC bound file of {size} bytes"
            )));
        }
        let mut buf = [0; BOUND_FILE_LEN];
        file.read_exact_at(&mut buf, 0)
            .map_err(|e| MvccError::Storage(e.into()))?;
        decode_bound(&buf).map(Some)
    }

    /// Durably replaces the bound with `wall_max`.
    ///
    /// # Errors
    /// I/O errors; the previous bound then stays in place.
    pub fn store(&self, wall_max: u64) -> Result<()> {
        let io = |e: std::io::Error| MvccError::Storage(e.into());
        self.fs.create_dir_all(&self.dir).map_err(io)?;
        let tmp = self.dir.join(BOUND_TMP_NAME);
        let mut file = self.fs.open(&tmp, OpenMode::Truncate).map_err(io)?;
        file.append(&encode_bound(wall_max)).map_err(io)?;
        file.sync_data().map_err(io)?;
        drop(file);
        self.fs
            .rename(&tmp, &self.dir.join(BOUND_FILE_NAME))
            .map_err(io)?;
        self.fs.sync_dir(&self.dir).map_err(io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_bytes_round_trip_and_order() {
        let a = Timestamp::new(5, u32::MAX);
        let b = Timestamp::new(6, 0);
        assert!(a < b);
        assert!(a.to_be_bytes() < b.to_be_bytes());
        assert_eq!(Timestamp::from_be_bytes(a.to_be_bytes()), a);
        assert_eq!(a.next(), b);
        assert_eq!(Timestamp::MAX.next(), Timestamp::MAX);
    }

    #[test]
    fn bound_decoder_rejects_damage() {
        let good = encode_bound(42);
        assert_eq!(decode_bound(&good).unwrap(), 42);
        for i in 0..good.len() {
            let mut bad = good;
            bad[i] ^= 0x40;
            assert!(decode_bound(&bad).is_err(), "byte {i}");
        }
        assert!(decode_bound(&good[..20]).is_err());
        assert!(decode_bound(&[]).is_err());
    }
}
