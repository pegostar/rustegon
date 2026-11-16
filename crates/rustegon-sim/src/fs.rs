// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Simulated file system `SimFs` (ADR-029, testing-strategy.md §3, storage-engine.md §15
//! TC-STO-002): an in-memory, deterministic implementation of [`FileSystem`] / [`File`] with
//! crash and fault injection.
//!
//! # Durability model
//! It is deliberately as weak as POSIX allows, so crash tests catch every missing `fsync`:
//! - File contents: each inode has its current bytes and a durable length. Appends change only
//!   the current bytes; [`File::sync_data`] makes all of them durable. Opening with
//!   [`OpenMode::Truncate`] sets the old durable bytes aside until the next sync, because a crash
//!   may or may not have persisted the truncation.
//! - Namespace (create, rename, remove, hard link): a path → inode binding is durable only after
//!   [`FileSystem::sync_dir`] on the path's parent. `fdatasync` of a new file does **not** make
//!   its name durable (it does not on ext4/XFS either), so an engine that forgets the directory
//!   fsync loses whole files. Unsynced changes are also kept as a journal in issue order (one
//!   entry per operation; a rename is one entry) for [`CrashMode::Journaled`].
//! - Directories created by [`FileSystem::create_dir_all`] are durable immediately.
//!   shortcut: directory creation is never lost; upgrade when an engine creates directories
//!   on a hot path whose crash behaviour matters (today only store/checkpoint setup does).
//! - Renaming a directory moves everything below it, durably and atomically at once (live and
//!   durable bindings and pending journal entries alike); the target must be absent or an empty
//!   directory. shortcut: a directory rename is never lost or torn, so a missing directory
//!   fsync after it goes unnoticed; upgrade when a crash test must catch one (today the restore
//!   swap of `rustegon-backup` renames directories and syncs the parent anyway).
//!
//! # Crash
//! [`SimFileSystem::crash`] models power loss followed by a reboot. Every file reverts to its
//! durable bytes and the namespace to its durable bindings; what else survives depends on the
//! [`CrashMode`] and a seed:
//! - [`CrashMode::Clean`]: nothing unsynced.
//! - [`CrashMode::TornPrefix`]: each file keeps a seeded prefix of its unsynced tail (the kernel
//!   wrote back some dirty pages, in file order for append-only files).
//! - [`CrashMode::TornZeroTail`]: each file keeps a seeded prefix of its unsynced tail followed by
//!   zero bytes, up to a seeded total length no larger than the tail. File systems that persist
//!   the new size before the data (ext4 delayed allocation, XFS) leave exactly this; it is the
//!   "torn tail followed by zeros only" that the MANIFEST reader must tolerate (§9).
//! - [`CrashMode::Journaled`]: a seeded prefix, in issue order, of the unsynced namespace
//!   operations survives, as on a journaling file system (ext4 `data=ordered`) that commits
//!   metadata in order; each file is torn as in one of the two torn modes, chosen per file.
//!
//! A file truncated since its last sync comes back either with its old durable bytes or truncated
//! (then torn as above), again seeded. All handles opened before the crash become stale and fail
//! every call, like the descriptors of a dead process.
//!
//! # Faults
//! All faults are deterministic, so a failing run is reproducible from its seed and op counts:
//! fail the next N syncs (`EIO`), fail the next N appends (`EIO`), `ENOSPC` above a byte quota
//! (the sum of the sizes of files that still have a name or an open handle: as on POSIX, an
//! unlinked file keeps its space until its last descriptor closes, and removing a file frees it
//! otherwise), and halt after N mutating operations — the
//! process "dies": every later call fails until [`SimFileSystem::crash`]. Halting at each op
//! count in turn enumerates every crash point of a workload.
//!
//! # Sharing
//! [`SimFileSystem`] is a cheap handle to shared state (`Arc<Mutex<…>>`): clone it into the
//! engine as `Arc<dyn FileSystem>` and keep a clone in the test to inject faults and crash while
//! the engine still holds open files.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use rustegon_sim_api::{File, FileLock, FileSystem, OpenMode};

/// What survives a simulated power loss beyond the durable state (module docs, "Crash").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashMode {
    /// Nothing unsynced survives.
    Clean,
    /// Each file keeps a seeded prefix of its unsynced tail.
    TornPrefix,
    /// Each file keeps a seeded prefix of its unsynced tail, then zero bytes up to a seeded
    /// length no larger than the tail.
    TornZeroTail,
    /// A seeded prefix of the unsynced namespace operations survives, in issue order; file tails
    /// are torn as in [`CrashMode::TornPrefix`] or [`CrashMode::TornZeroTail`], chosen per file.
    Journaled,
}

impl CrashMode {
    /// Every mode, for crash tests that sweep all of them.
    pub const ALL: [Self; 4] = [
        Self::Clean,
        Self::TornPrefix,
        Self::TornZeroTail,
        Self::Journaled,
    ];
}

/// In-memory simulated file system. See the module docs for the durability model.
#[derive(Clone, Default)]
pub struct SimFileSystem {
    state: Arc<Mutex<State>>,
}

/// Durable state is a length into `data` rather than a copy, so `sync_data` is O(1) and an
/// append-heavy workload stays linear.
#[derive(Default)]
struct Inode {
    /// Current contents, as seen by reads.
    data: Vec<u8>,
    /// `data[..durable_len]` survives a crash (unless `pre_truncate` is set).
    durable_len: usize,
    /// Durable contents set aside by a truncation since the last sync: `data` no longer extends
    /// them, and a crash may bring them back.
    pre_truncate: Option<Vec<u8>>,
    /// Live names bound to this inode.
    links: u32,
    /// Open handles of the current epoch.
    handles: u32,
}

impl Inode {
    /// Whether the inode's bytes count against the quota: it is reachable by a name or a handle.
    fn allocated(&self) -> bool {
        self.links > 0 || self.handles > 0
    }
}

/// One unsynced namespace operation: the bindings it changed (`None` = unbound), applied
/// atomically on journal replay.
type JournalEntry = Vec<(PathBuf, Option<u64>)>;

#[derive(Default)]
struct Faults {
    fail_syncs: u64,
    fail_appends: u64,
    quota: Option<u64>,
    /// Absolute mutating-op count at which the file system halts.
    halt_at: Option<u64>,
    halted: bool,
}

/// Ordered maps everywhere: crash consumes random numbers while iterating, and a `HashMap`
/// order would make the outcome of a seed vary between runs.
#[derive(Default)]
struct State {
    dirs: BTreeSet<PathBuf>,
    /// Bindings visible now.
    live: BTreeMap<PathBuf, u64>,
    /// Bindings that survive a crash.
    durable: BTreeMap<PathBuf, u64>,
    /// Namespace changes not yet covered by a `sync_dir`, in issue order. Invariant: replaying
    /// all of them onto `durable` yields `live`.
    journal: Vec<JournalEntry>,
    inodes: BTreeMap<u64, Inode>,
    next_ino: u64,
    /// Sum of `data.len()` over allocated inodes (`Inode::allocated`), kept incrementally for
    /// the quota check.
    used_bytes: u64,
    /// Incremented by every crash; handles from an older epoch are stale.
    epoch: u64,
    /// Mutating operations performed so far.
    ops: u64,
    faults: Faults,
    /// Held exclusive locks (`FileSystem::try_lock_exclusive`): path → (epoch, token). A lock
    /// of an older epoch died with its process at the crash that ended that epoch.
    locks: BTreeMap<PathBuf, (u64, u64)>,
    /// Token of the next lock (tells a released lock from a newer one on the same path).
    next_lock: u64,
}

fn halted_error() -> io::Error {
    io::Error::other("simulated crash: file system halted")
}

fn eio(what: &str) -> io::Error {
    io::Error::other(format!("simulated EIO on {what}"))
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, path.display().to_string())
}

fn already_exists(path: &Path) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, path.display().to_string())
}

impl State {
    /// Rejects every call once the simulated process has died.
    fn alive(&self) -> io::Result<()> {
        if self.faults.halted {
            Err(halted_error())
        } else {
            Ok(())
        }
    }

    /// Counts a mutating operation; halts when the configured crash point is reached, so the
    /// operation that hits the point never takes effect.
    fn mutation(&mut self) -> io::Result<()> {
        self.alive()?;
        if self.faults.halt_at.is_some_and(|at| self.ops >= at) {
            self.faults.halted = true;
            return Err(halted_error());
        }
        self.ops += 1;
        Ok(())
    }

    fn take_sync_fault(&mut self, what: &str) -> io::Result<()> {
        if self.faults.fail_syncs > 0 {
            self.faults.fail_syncs -= 1;
            return Err(eio(what));
        }
        Ok(())
    }

    fn check_parent(&self, path: &Path) -> io::Result<()> {
        match path.parent() {
            Some(p) if self.dirs.contains(p) => Ok(()),
            _ => Err(not_found(path)),
        }
    }

    /// Changes live bindings and journals them as one operation; keeps link counts and the
    /// quota usage in step (a file whose last name goes and that has no open handle frees its
    /// bytes, as unlink(2) does).
    fn bind(&mut self, changes: JournalEntry) {
        let mut touched = Vec::new();
        for (path, ino) in &changes {
            let old = match ino {
                Some(ino) => self.live.insert(path.clone(), *ino),
                None => self.live.remove(path),
            };
            if let Some(old) = old
                && let Some(inode) = self.inodes.get_mut(&old)
            {
                touched.push((old, inode.allocated()));
                inode.links -= 1;
            }
            if let Some(ino) = ino
                && let Some(inode) = self.inodes.get_mut(ino)
            {
                touched.push((*ino, inode.allocated()));
                inode.links += 1;
            }
        }
        // `touched` may hold an inode twice (a rename touches one inode through two paths);
        // its first entry is its state before this operation.
        let mut seen = BTreeSet::new();
        for (ino, was) in touched {
            if seen.insert(ino) {
                self.account(ino, was);
            }
        }
        self.journal.push(changes);
    }

    /// Adjusts `used_bytes` after inode `ino` changed from `was` allocated to its current state.
    fn account(&mut self, ino: u64, was: bool) {
        let Some(inode) = self.inodes.get(&ino) else {
            return;
        };
        let size = inode.data.len() as u64;
        match (was, inode.allocated()) {
            (true, false) => self.used_bytes -= size,
            (false, true) => self.used_bytes += size,
            _ => {}
        }
    }

    fn create(&mut self, path: &Path) -> io::Result<u64> {
        self.check_parent(path)?;
        if self.dirs.contains(path) {
            return Err(already_exists(path));
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.inodes.insert(ino, Inode::default());
        self.bind(vec![(path.to_path_buf(), Some(ino))]);
        Ok(ino)
    }

    /// Moves directory `from` with everything below it to `to` (module docs: durable and
    /// atomic at once). `to` must be absent or an empty directory, and not below `from`.
    fn rename_dir(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        if to.starts_with(from) && to != from {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is below {}", to.display(), from.display()),
            ));
        }
        if self.live.contains_key(to) {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                to.display().to_string(),
            ));
        }
        let to_has_children = self.live.keys().any(|p| p.parent() == Some(to))
            || self.dirs.iter().any(|d| d.parent() == Some(to));
        if to_has_children {
            return Err(io::Error::new(
                io::ErrorKind::DirectoryNotEmpty,
                to.display().to_string(),
            ));
        }
        let moved = |p: &Path| -> Option<PathBuf> {
            p.strip_prefix(from).ok().map(|rest| {
                if rest.as_os_str().is_empty() {
                    to.to_path_buf()
                } else {
                    to.join(rest)
                }
            })
        };
        let rebind = |map: &mut BTreeMap<PathBuf, u64>| {
            let keys: Vec<PathBuf> = map
                .keys()
                .filter(|p| p.starts_with(from))
                .cloned()
                .collect();
            for old in keys {
                if let (Some(ino), Some(new)) = (map.remove(&old), moved(&old)) {
                    map.insert(new, ino);
                }
            }
        };
        rebind(&mut self.live);
        rebind(&mut self.durable);
        for entry in &mut self.journal {
            for (path, _) in entry.iter_mut() {
                if let Some(new) = moved(path) {
                    *path = new;
                }
            }
        }
        let dirs: Vec<PathBuf> = self
            .dirs
            .iter()
            .filter(|d| d.starts_with(from))
            .cloned()
            .collect();
        for dir in dirs {
            self.dirs.remove(&dir);
            if let Some(new) = moved(&dir) {
                self.dirs.insert(new);
            }
        }
        Ok(())
    }

    fn inode(&mut self, ino: u64) -> io::Result<&mut Inode> {
        // Inodes are only collected at crash, which also invalidates every handle.
        self.inodes
            .get_mut(&ino)
            .ok_or_else(|| io::Error::other("simulated fs: dangling inode"))
    }
}

impl SimFileSystem {
    /// An empty file system (no directories).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panicking test thread must not hide the state from the crash checks that follow.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Simulates power loss and reboot (see module docs); `seed` drives which unsynced bytes and
    /// namespace operations survive under `mode`. Clears every fault, including a halt.
    pub fn crash(&self, seed: u64, mode: CrashMode) {
        let mut rng = SplitMix64(seed);
        let mut st = self.lock();
        for inode in st.inodes.values_mut() {
            crash_inode(inode, mode, &mut rng);
        }
        if mode == CrashMode::Journaled {
            // Metadata commits in order: replay a prefix of the journal onto the durable state.
            let survivors = rng.below(st.journal.len() as u64 + 1);
            let journal = std::mem::take(&mut st.journal);
            for entry in journal
                .into_iter()
                .take(usize::try_from(survivors).unwrap_or(usize::MAX))
            {
                for (path, ino) in entry {
                    match ino {
                        Some(ino) => st.durable.insert(path, ino),
                        None => st.durable.remove(&path),
                    };
                }
            }
        }
        st.journal.clear();
        st.live = st.durable.clone();
        let mut links: BTreeMap<u64, u32> = BTreeMap::new();
        for ino in st.live.values() {
            *links.entry(*ino).or_default() += 1;
        }
        st.inodes.retain(|ino, _| links.contains_key(ino));
        // Every handle dies with the process; only named inodes remain.
        for (ino, inode) in &mut st.inodes {
            inode.links = links[ino];
            inode.handles = 0;
        }
        st.used_bytes = st.inodes.values().map(|i| i.data.len() as u64).sum();
        st.epoch += 1;
        st.faults = Faults::default();
        // Locks die with the process, as OS file locks do.
        st.locks.clear();
    }

    /// Makes the next `n` `sync_data` / `sync_dir` calls fail with `EIO`; nothing becomes durable.
    pub fn fail_next_syncs(&self, n: u64) {
        self.lock().faults.fail_syncs = n;
    }

    /// Makes the next `n` appends fail with `EIO`, writing nothing.
    pub fn fail_next_appends(&self, n: u64) {
        self.lock().faults.fail_appends = n;
    }

    /// Fails appends with `ENOSPC` (`StorageFull`) once the total size of all files would exceed
    /// `bytes`; `None` removes the limit.
    pub fn set_quota(&self, bytes: Option<u64>) {
        self.lock().faults.quota = bytes;
    }

    /// Halts after `n` more mutating operations (open for writing, append, sync, rename, remove,
    /// link, directory create/sync): that operation and every later call fail until
    /// [`SimFileSystem::crash`]. `n = 0` halts at the next mutation.
    pub fn halt_after_ops(&self, n: u64) {
        let mut st = self.lock();
        st.faults.halt_at = Some(st.ops.saturating_add(n));
    }

    /// Mutating operations performed since creation; used to enumerate crash points.
    #[must_use]
    pub fn op_count(&self) -> u64 {
        self.lock().ops
    }

    /// Whether a halt has been triggered and no crash has happened since.
    #[must_use]
    pub fn is_halted(&self) -> bool {
        self.lock().faults.halted
    }
}

/// Reverts one inode to what reached the disk (module docs, "Crash").
fn crash_inode(inode: &mut Inode, mode: CrashMode, rng: &mut SplitMix64) {
    // `base`: length of the durable prefix of `data`; `None` if the old contents came back.
    let base = match inode.pre_truncate.take() {
        Some(_) if rng.next() & 1 == 0 => Some(0),
        Some(old) => {
            inode.data = old;
            None
        }
        None => Some(inode.durable_len),
    };
    if let Some(base) = base {
        let tail = (inode.data.len() - base) as u64;
        let zero_fill = match mode {
            CrashMode::Clean => {
                inode.data.truncate(base);
                inode.durable_len = base;
                return;
            }
            CrashMode::TornPrefix => false,
            CrashMode::TornZeroTail => true,
            CrashMode::Journaled => rng.next() & 1 == 0,
        };
        // Lossless: both are at most `tail`, which is a `usize` length.
        #[allow(clippy::cast_possible_truncation)]
        let (written, len) = if zero_fill {
            let len = rng.below(tail + 1);
            (rng.below(len + 1) as usize, len as usize)
        } else {
            let n = rng.below(tail + 1) as usize;
            (n, n)
        };
        inode.data.truncate(base + written);
        inode.data.resize(base + len, 0);
    }
    inode.durable_len = inode.data.len();
}

impl FileSystem for SimFileSystem {
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Box<dyn File>> {
        let mut st = self.lock();
        let existing = st.live.get(path).copied();
        let ino = match mode {
            OpenMode::Read => {
                st.alive()?;
                existing.ok_or_else(|| not_found(path))?
            }
            OpenMode::CreateNew => {
                st.mutation()?;
                if existing.is_some() {
                    return Err(already_exists(path));
                }
                st.create(path)?
            }
            OpenMode::Append => {
                st.mutation()?;
                match existing {
                    Some(ino) => ino,
                    None => st.create(path)?,
                }
            }
            OpenMode::Truncate => {
                st.mutation()?;
                match existing {
                    Some(ino) => {
                        let inode = st.inode(ino)?;
                        let freed = inode.data.len() as u64;
                        if inode.pre_truncate.is_none() {
                            let mut old = std::mem::take(&mut inode.data);
                            old.truncate(inode.durable_len);
                            inode.pre_truncate = Some(old);
                        } else {
                            // Still unsynced since the first truncation: those bytes stay the
                            // durable ones.
                            inode.data.clear();
                        }
                        inode.durable_len = 0;
                        st.used_bytes -= freed;
                        ino
                    }
                    None => st.create(path)?,
                }
            }
        };
        st.inode(ino)?.handles += 1;
        Ok(Box::new(SimFile {
            state: Arc::clone(&self.state),
            ino,
            epoch: st.epoch,
            writable: mode != OpenMode::Read,
        }))
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        let mut st = self.lock();
        st.mutation()?;
        if st.live.contains_key(path) {
            return Err(already_exists(path));
        }
        if let Some(file) = path.ancestors().find(|a| st.live.contains_key(*a)) {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                file.display().to_string(),
            ));
        }
        for dir in path.ancestors() {
            st.dirs.insert(dir.to_path_buf());
        }
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut st = self.lock();
        st.mutation()?;
        st.check_parent(to)?;
        if st.dirs.contains(from) {
            return st.rename_dir(from, to);
        }
        let ino = *st.live.get(from).ok_or_else(|| not_found(from))?;
        // Replacing an existing `to` is part of the same atomic operation, as with rename(2).
        st.bind(vec![
            (from.to_path_buf(), None),
            (to.to_path_buf(), Some(ino)),
        ]);
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let mut st = self.lock();
        st.mutation()?;
        if !st.live.contains_key(path) {
            return Err(not_found(path));
        }
        st.bind(vec![(path.to_path_buf(), None)]);
        Ok(())
    }

    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        let mut st = self.lock();
        st.mutation()?;
        st.check_parent(link)?;
        let ino = *st.live.get(original).ok_or_else(|| not_found(original))?;
        if st.live.contains_key(link) {
            return Err(already_exists(link));
        }
        st.bind(vec![(link.to_path_buf(), Some(ino))]);
        Ok(())
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        let mut st = self.lock();
        st.mutation()?;
        if !st.dirs.contains(path) {
            return Err(not_found(path));
        }
        // Directories are not journaled here (their creation is durable at once), so neither is
        // their removal; an empty directory carries no data a crash could lose.
        let has_children = st.live.keys().any(|p| p.parent() == Some(path))
            || st.dirs.iter().any(|d| d.parent() == Some(path));
        if has_children {
            return Err(io::Error::new(
                io::ErrorKind::DirectoryNotEmpty,
                path.display().to_string(),
            ));
        }
        st.dirs.remove(path);
        // The directory is empty only in the live view: a file moved or unlinked out of it
        // whose removal is not durable yet would come back at a crash under a directory that no
        // longer exists, unreachable by `read_dir`. A real file system cannot persist the rmdir
        // without the earlier metadata operations that emptied it (ordered metadata), so this
        // durable removal commits the journal up to the last entry below the directory.
        if let Some(last) = st
            .journal
            .iter()
            .rposition(|entry| entry.iter().any(|(p, _)| p.starts_with(path)))
        {
            let committed: Vec<JournalEntry> = st.journal.drain(..=last).collect();
            for (p, ino) in committed.into_iter().flatten() {
                match ino {
                    Some(ino) => st.durable.insert(p, ino),
                    None => st.durable.remove(&p),
                };
            }
        }
        Ok(())
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let st = self.lock();
        st.alive()?;
        if !st.dirs.contains(path) {
            return Err(not_found(path));
        }
        let files = st.live.keys();
        let subdirs = st.dirs.iter().filter(|d| d.as_path() != path);
        Ok(files
            .chain(subdirs)
            .filter(|p| p.parent() == Some(path))
            .cloned()
            .collect())
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        let mut st = self.lock();
        st.mutation()?;
        if !st.dirs.contains(path) {
            return Err(not_found(path));
        }
        st.take_sync_fault("sync_dir")?;
        // Every binding change under `path` since the last sync becomes durable at once.
        let children: Vec<PathBuf> = st
            .live
            .keys()
            .chain(st.durable.keys())
            .filter(|p| p.parent() == Some(path))
            .cloned()
            .collect();
        for child in children {
            match st.live.get(&child).copied() {
                Some(ino) => st.durable.insert(child, ino),
                None => st.durable.remove(&child),
            };
        }
        // Those changes leave the journal; the other half of a cross-directory rename stays.
        // Keeps the invariant "durable + journal = live".
        for entry in &mut st.journal {
            entry.retain(|(p, _)| p.parent() != Some(path));
        }
        st.journal.retain(|entry| !entry.is_empty());
        Ok(())
    }

    fn try_lock_exclusive(&self, path: &Path) -> io::Result<FileLock> {
        let mut st = self.lock();
        st.alive()?;
        // Like the std implementation the lock needs an existing parent directory, but it
        // creates no file: the lock table is process state, not file system state, and a
        // file here would shift the op counts that crash sweeps enumerate.
        st.check_parent(path)?;
        let epoch = st.epoch;
        if st.locks.get(path).is_some_and(|(e, _)| *e == epoch) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{} is locked", path.display()),
            ));
        }
        let token = st.next_lock;
        st.next_lock += 1;
        st.locks.insert(path.to_path_buf(), (epoch, token));
        Ok(FileLock::new(SimLock {
            state: Arc::clone(&self.state),
            path: path.to_path_buf(),
            epoch,
            token,
        }))
    }
}

/// A held simulated lock; dropping it releases the entry unless a crash already did.
struct SimLock {
    state: Arc<Mutex<State>>,
    path: PathBuf,
    epoch: u64,
    token: u64,
}

impl Drop for SimLock {
    fn drop(&mut self) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // Only this lock's own entry: after a crash the path may be locked by a new process.
        if st.locks.get(&self.path) == Some(&(self.epoch, self.token)) {
            st.locks.remove(&self.path);
        }
    }
}

struct SimFile {
    state: Arc<Mutex<State>>,
    ino: u64,
    epoch: u64,
    writable: bool,
}

impl SimFile {
    /// Locks the state, rejecting handles that predate a crash.
    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        let st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if st.epoch != self.epoch {
            return Err(io::Error::other(
                "stale file handle: opened before a simulated crash",
            ));
        }
        Ok(st)
    }
}

impl Drop for SimFile {
    /// Closing the last handle of an unlinked file frees its bytes (quota, module docs).
    fn drop(&mut self) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if st.epoch != self.epoch {
            return; // stale handle: the crash already reset every handle count
        }
        let Some(inode) = st.inodes.get_mut(&self.ino) else {
            return;
        };
        let was = inode.allocated();
        inode.handles = inode.handles.saturating_sub(1);
        st.account(self.ino, was);
    }
}

impl File for SimFile {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let mut st = self.lock()?;
        st.alive()?;
        let data = &st.inode(self.ino)?.data;
        let src = usize::try_from(offset)
            .ok()
            .and_then(|start| data.get(start..start.checked_add(buf.len())?))
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut st = self.lock()?;
        st.mutation()?;
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file opened read-only",
            ));
        }
        if st.faults.fail_appends > 0 {
            st.faults.fail_appends -= 1;
            return Err(eio("append"));
        }
        let used = st.used_bytes.saturating_add(buf.len() as u64);
        if st.faults.quota.is_some_and(|quota| used > quota) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "simulated ENOSPC",
            ));
        }
        st.inode(self.ino)?.data.extend_from_slice(buf);
        st.used_bytes = used;
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        let mut st = self.lock()?;
        st.mutation()?;
        st.take_sync_fault("sync_data")?;
        let inode = st.inode(self.ino)?;
        inode.durable_len = inode.data.len();
        inode.pre_truncate = None;
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        let mut st = self.lock()?;
        st.alive()?;
        Ok(st.inode(self.ino)?.data.len() as u64)
    }
}

/// `SplitMix64` (Steele, Lea, Flood 2014): a tiny, well-mixed seeded generator. Crash outcomes
/// only need reproducibility and spread, not cryptographic quality.
struct SplitMix64(u64);

impl SplitMix64 {
    /// Golden-ratio increment and finalizer constants from the reference implementation.
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-enough value in `0..n` (`n > 0`); the modulo bias is irrelevant for test spread.
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Enough seeds that every seeded outcome of the small scenarios below shows up.
    const SEEDS: u64 = 64;

    fn setup() -> (SimFileSystem, PathBuf) {
        let fs = SimFileSystem::new();
        let dir = PathBuf::from("/db");
        fs.create_dir_all(&dir).unwrap();
        (fs, dir)
    }

    fn read_all(fs: &SimFileSystem, path: &Path) -> io::Result<Vec<u8>> {
        let f = fs.open(path, OpenMode::Read)?;
        let mut buf = vec![0; usize::try_from(f.size()?).unwrap()];
        f.read_exact_at(&mut buf, 0)?;
        Ok(buf)
    }

    fn write_synced(fs: &SimFileSystem, path: &Path, data: &[u8]) {
        let mut f = fs.open(path, OpenMode::CreateNew).unwrap();
        f.append(data).unwrap();
        f.sync_data().unwrap();
    }

    #[test]
    fn directory_rename_moves_the_tree_durably() {
        for mode in CrashMode::ALL {
            let (fs, dir) = setup();
            let (a, b) = (dir.join("a"), dir.join("b"));
            fs.create_dir_all(&a.join("sub")).unwrap();
            write_synced(&fs, &a.join("synced"), b"s");
            fs.sync_dir(&a).unwrap();
            write_synced(&fs, &a.join("sub").join("pending"), b"p");
            fs.create_dir_all(&b).unwrap();
            fs.rename(&a, &b).unwrap();
            assert!(fs.read_dir(&a).is_err());
            assert_eq!(read_all(&fs, &b.join("synced")).unwrap(), b"s");
            assert_eq!(read_all(&fs, &b.join("sub").join("pending")).unwrap(), b"p");
            fs.crash(1, mode);
            // The move itself survives; the never-synced name below it does not (Clean).
            assert!(fs.read_dir(&a).is_err(), "{mode:?}");
            assert_eq!(read_all(&fs, &b.join("synced")).unwrap(), b"s", "{mode:?}");
            if mode == CrashMode::Clean {
                assert!(read_all(&fs, &b.join("sub").join("pending")).is_err());
            }
        }
        let (fs, dir) = setup();
        fs.create_dir_all(&dir.join("x")).unwrap();
        fs.create_dir_all(&dir.join("y").join("z")).unwrap();
        let err = fs.rename(&dir.join("x"), &dir.join("y")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::DirectoryNotEmpty);
        assert!(
            fs.rename(&dir.join("y"), &dir.join("y").join("z").join("w"))
                .is_err()
        );
    }

    #[test]
    fn synced_data_survives_and_unsynced_is_dropped() {
        let (fs, dir) = setup();
        let path = dir.join("a");
        let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
        f.append(b"durable").unwrap();
        f.sync_data().unwrap();
        fs.sync_dir(&dir).unwrap();
        f.append(b" lost").unwrap();
        assert_eq!(read_all(&fs, &path).unwrap(), b"durable lost");
        fs.crash(1, CrashMode::Clean);
        assert_eq!(read_all(&fs, &path).unwrap(), b"durable");
    }

    #[test]
    fn namespace_changes_need_sync_dir() {
        let (fs, dir) = setup();
        let (a, b, c) = (dir.join("a"), dir.join("b"), dir.join("c"));
        // A synced file whose name was never made durable disappears.
        write_synced(&fs, &a, b"x");
        fs.crash(0, CrashMode::TornPrefix);
        assert_eq!(fs.read_dir(&dir).unwrap(), Vec::<PathBuf>::new());

        write_synced(&fs, &a, b"x");
        fs.sync_dir(&dir).unwrap();
        // Unsynced rename, link and remove are all undone.
        fs.rename(&a, &b).unwrap();
        fs.hard_link(&b, &c).unwrap();
        fs.remove_file(&b).unwrap();
        assert_eq!(fs.read_dir(&dir).unwrap(), std::slice::from_ref(&c));
        fs.crash(0, CrashMode::TornPrefix);
        assert_eq!(fs.read_dir(&dir).unwrap(), std::slice::from_ref(&a));
        assert_eq!(read_all(&fs, &a).unwrap(), b"x");

        // After sync_dir they stick, and a link shares the inode.
        fs.hard_link(&a, &c).unwrap();
        fs.rename(&a, &b).unwrap();
        fs.sync_dir(&dir).unwrap();
        fs.crash(0, CrashMode::TornPrefix);
        assert_eq!(fs.read_dir(&dir).unwrap(), [b.clone(), c.clone()]);
        assert_eq!(read_all(&fs, &c).unwrap(), b"x");
    }

    #[test]
    fn journaled_crash_keeps_a_prefix_of_namespace_ops() {
        // States after each unsynced operation of the scenario, in issue order.
        let names = |s: &[&str]| s.iter().map(|n| PathBuf::from("/db").join(n)).collect();
        let states: Vec<Vec<PathBuf>> = vec![
            names(&["a"]),
            names(&["a", "b"]),
            names(&["a", "c"]),
            names(&["c"]),
            names(&["c", "d"]),
        ];
        let mut seen = BTreeSet::new();
        for mode in CrashMode::ALL {
            for seed in 0..SEEDS {
                let (fs, dir) = setup();
                write_synced(&fs, &dir.join("a"), b"a");
                fs.sync_dir(&dir).unwrap();
                write_synced(&fs, &dir.join("b"), b"b");
                fs.rename(&dir.join("b"), &dir.join("c")).unwrap();
                fs.remove_file(&dir.join("a")).unwrap();
                fs.hard_link(&dir.join("c"), &dir.join("d")).unwrap();
                fs.crash(seed, mode);
                let got = fs.read_dir(&dir).unwrap();
                let at = states.iter().position(|s| *s == got);
                assert!(at.is_some(), "{mode:?} seed {seed}: not a prefix: {got:?}");
                if mode != CrashMode::Journaled {
                    assert_eq!(at, Some(0), "{mode:?} reverts all unsynced ops");
                }
                seen.extend(at);
                // The surviving names still reach their synced data.
                for p in &got {
                    let want: &[u8] = if p.ends_with("a") { b"a" } else { b"b" };
                    assert_eq!(read_all(&fs, p).unwrap(), want);
                }
            }
        }
        assert_eq!(seen.len(), states.len(), "every prefix occurs: {seen:?}");
    }

    #[test]
    fn sync_dir_removes_only_its_own_ops_from_the_journal() {
        let mut outcomes = BTreeSet::new();
        for seed in 0..SEEDS {
            let (fs, dir) = setup();
            let sub = dir.join("sub");
            fs.create_dir_all(&sub).unwrap();
            write_synced(&fs, &sub.join("x"), b"x");
            fs.sync_dir(&sub).unwrap();
            // Cross-directory rename; only the destination's directory is synced, so the source
            // name stays in the journal and may or may not be removed by the crash.
            fs.rename(&sub.join("x"), &dir.join("y")).unwrap();
            fs.sync_dir(&dir).unwrap();
            fs.crash(seed, CrashMode::Journaled);
            assert_eq!(read_all(&fs, &dir.join("y")).unwrap(), b"x");
            outcomes.insert(fs.read_dir(&sub).unwrap());
        }
        let sub = PathBuf::from("/db/sub");
        assert_eq!(outcomes, BTreeSet::from([vec![], vec![sub.join("x")]]));
    }

    #[test]
    fn sync_dir_only_covers_its_own_directory() {
        let (fs, dir) = setup();
        let sub = dir.join("sub");
        fs.create_dir_all(&sub).unwrap();
        fs.open(&dir.join("a"), OpenMode::CreateNew).unwrap();
        fs.open(&sub.join("b"), OpenMode::CreateNew).unwrap();
        fs.sync_dir(&sub).unwrap();
        fs.crash(0, CrashMode::Clean);
        assert_eq!(fs.read_dir(&dir).unwrap(), std::slice::from_ref(&sub));
        assert_eq!(fs.read_dir(&sub).unwrap(), [sub.join("b")]);
    }

    #[test]
    fn handles_go_stale_after_crash() {
        let (fs, dir) = setup();
        let path = dir.join("a");
        let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
        f.append(b"x").unwrap();
        f.sync_data().unwrap();
        fs.sync_dir(&dir).unwrap();
        fs.crash(0, CrashMode::Clean);
        assert!(f.append(b"y").is_err());
        assert!(f.sync_data().is_err());
        assert!(f.size().is_err());
        assert!(f.read_exact_at(&mut [0], 0).is_err());
        // Fresh handles work.
        let mut g = fs.open(&path, OpenMode::Append).unwrap();
        g.append(b"y").unwrap();
        assert_eq!(read_all(&fs, &path).unwrap(), b"xy");
    }

    #[test]
    fn open_modes_and_errors_follow_std_semantics() {
        let (fs, dir) = setup();
        let path = dir.join("f");
        assert_eq!(
            fs.open(&path, OpenMode::Read).err().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            fs.open(&PathBuf::from("/nodir/f"), OpenMode::CreateNew)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotFound
        );
        fs.open(&path, OpenMode::CreateNew)
            .unwrap()
            .append(b"abc")
            .unwrap();
        assert_eq!(
            fs.open(&path, OpenMode::CreateNew).err().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        let mut r = fs.open(&path, OpenMode::Read).unwrap();
        assert_eq!(
            r.append(b"x").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let err = r.read_exact_at(&mut [0; 2], 2).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            fs.open(&path, OpenMode::Truncate).unwrap().size().unwrap(),
            0
        );
        fs.open(&path, OpenMode::Append)
            .unwrap()
            .append(b"xy")
            .unwrap();
        assert_eq!(read_all(&fs, &path).unwrap(), b"xy");
        assert_eq!(
            fs.remove_file(&dir.join("missing")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn namespace_errors_follow_posix() {
        let (fs, dir) = setup();
        let (a, b) = (dir.join("a"), dir.join("b"));
        write_synced(&fs, &a, b"a");
        write_synced(&fs, &b, b"b");
        let kind = |r: io::Result<()>| r.unwrap_err().kind();
        // link(2) never replaces an existing name.
        assert_eq!(kind(fs.hard_link(&a, &b)), io::ErrorKind::AlreadyExists);
        assert_eq!(read_all(&fs, &b).unwrap(), b"b");
        // A missing parent directory fails, leaving the source untouched.
        let orphan = PathBuf::from("/missing/x");
        assert_eq!(kind(fs.rename(&a, &orphan)), io::ErrorKind::NotFound);
        assert_eq!(kind(fs.hard_link(&a, &orphan)), io::ErrorKind::NotFound);
        assert_eq!(read_all(&fs, &a).unwrap(), b"a");
        // A directory cannot be created over or below a file.
        assert_eq!(kind(fs.create_dir_all(&a)), io::ErrorKind::AlreadyExists);
        assert_eq!(
            kind(fs.create_dir_all(&a.join("sub"))),
            io::ErrorKind::NotADirectory
        );
        assert_eq!(fs.read_dir(&dir).unwrap(), [a, b]);
    }

    #[test]
    fn rename_over_existing_replaces_atomically_and_needs_sync_dir() {
        let mut outcomes = BTreeSet::new();
        for mode in CrashMode::ALL {
            for seed in 0..SEEDS {
                let (fs, dir) = setup();
                let (a, b) = (dir.join("a"), dir.join("b"));
                write_synced(&fs, &a, b"new");
                write_synced(&fs, &b, b"old");
                fs.sync_dir(&dir).unwrap();
                fs.rename(&a, &b).unwrap();
                assert_eq!(read_all(&fs, &b).unwrap(), b"new");
                assert_eq!(
                    read_all(&fs, &a).unwrap_err().kind(),
                    io::ErrorKind::NotFound
                );
                fs.crash(seed, mode);
                // Unsynced: `a` and the old `b` come back, or (journaled) the whole rename
                // survives — never half of it.
                let state = (fs.read_dir(&dir).unwrap().len(), read_all(&fs, &b).unwrap());
                if mode != CrashMode::Journaled {
                    assert_eq!(state, (2, b"old".to_vec()), "{mode:?} seed {seed}");
                }
                outcomes.insert(state);
            }
        }
        assert_eq!(
            outcomes,
            BTreeSet::from([(2, b"old".to_vec()), (1, b"new".to_vec())])
        );

        let (fs, dir) = setup();
        let (a, b) = (dir.join("a"), dir.join("b"));
        write_synced(&fs, &a, b"new");
        write_synced(&fs, &b, b"old");
        fs.rename(&a, &b).unwrap();
        fs.sync_dir(&dir).unwrap();
        fs.crash(0, CrashMode::Clean);
        assert_eq!(fs.read_dir(&dir).unwrap(), std::slice::from_ref(&b));
        assert_eq!(read_all(&fs, &b).unwrap(), b"new");
    }

    #[test]
    fn truncate_without_sync_reverts_to_old_or_empty() {
        let mut outcomes: BTreeMap<_, BTreeSet<Vec<u8>>> = BTreeMap::new();
        for mode in [CrashMode::Clean, CrashMode::TornPrefix] {
            for seed in 0..SEEDS {
                let (fs, dir) = setup();
                let path = dir.join("f");
                write_synced(&fs, &path, b"old");
                fs.sync_dir(&dir).unwrap();
                fs.open(&path, OpenMode::Truncate)
                    .unwrap()
                    .append(b"xx")
                    .unwrap();
                // A second truncation before any sync keeps "old" as the durable contents.
                fs.open(&path, OpenMode::Truncate)
                    .unwrap()
                    .append(b"new")
                    .unwrap();
                fs.crash(seed, mode);
                let mode_key = format!("{mode:?}");
                outcomes
                    .entry(mode_key)
                    .or_default()
                    .insert(read_all(&fs, &path).unwrap());
            }
        }
        let set = |v: &[&[u8]]| v.iter().map(|o| o.to_vec()).collect::<BTreeSet<_>>();
        assert_eq!(outcomes["Clean"], set(&[b"old", b""]));
        // Torn writes may also keep a prefix of the new bytes after the truncation.
        assert_eq!(
            outcomes["TornPrefix"],
            set(&[b"old", b"", b"n", b"ne", b"new"])
        );
    }

    #[test]
    fn torn_zero_tail_is_a_prefix_followed_by_zeros() {
        let tail: Vec<u8> = (1..=20).collect();
        let mut zero_filled = 0;
        for seed in 0..SEEDS {
            let (fs, dir) = setup();
            let path = dir.join("log");
            let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
            fs.sync_dir(&dir).unwrap();
            f.append(b"abc").unwrap();
            f.sync_data().unwrap();
            f.append(&tail).unwrap();
            fs.crash(seed, CrashMode::TornZeroTail);
            let got = read_all(&fs, &path).unwrap();
            assert!(
                got.starts_with(b"abc") && got.len() <= 3 + tail.len(),
                "{got:?}"
            );
            let rest = &got[3..];
            let written = rest.iter().take_while(|&&b| b != 0).count();
            assert_eq!(&rest[..written], &tail[..written], "seed {seed}");
            assert!(rest[written..].iter().all(|&b| b == 0), "seed {seed}");
            zero_filled += usize::from(written < rest.len());
        }
        assert!(zero_filled > 0, "no seed produced a zero-filled tail");
    }

    #[test]
    fn sync_and_append_faults() {
        let (fs, dir) = setup();
        let path = dir.join("a");
        let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
        fs.sync_dir(&dir).unwrap();
        fs.fail_next_syncs(2);
        f.append(b"abc").unwrap();
        assert!(f.sync_data().is_err());
        assert!(fs.sync_dir(&dir).is_err());
        f.sync_data().unwrap();

        fs.fail_next_appends(1);
        assert!(f.append(b"x").is_err());
        f.append(b"d").unwrap();
        assert_eq!(read_all(&fs, &path).unwrap(), b"abcd");

        fs.set_quota(Some(6));
        f.append(b"ef").unwrap();
        assert_eq!(
            f.append(b"g").unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        fs.set_quota(None);
        f.append(b"g").unwrap();
        assert_eq!(read_all(&fs, &path).unwrap(), b"abcdefg");
    }

    #[test]
    fn quota_counts_all_files_and_frees_on_truncate_and_crash() {
        let (fs, dir) = setup();
        let (a, b) = (dir.join("a"), dir.join("b"));
        fs.set_quota(Some(10));
        let mut fa = fs.open(&a, OpenMode::CreateNew).unwrap();
        let mut fb = fs.open(&b, OpenMode::CreateNew).unwrap();
        fs.sync_dir(&dir).unwrap();
        fa.append(&[1; 6]).unwrap();
        fa.sync_data().unwrap();
        fb.append(&[2; 4]).unwrap();
        let full = |r: io::Result<()>| r.unwrap_err().kind() == io::ErrorKind::StorageFull;
        assert!(full(fb.append(&[2])));
        assert!(full(fa.append(&[1])));
        // Truncation releases a's 6 bytes.
        let mut fa = fs.open(&a, OpenMode::Truncate).unwrap();
        fb.append(&[2; 6]).unwrap();
        assert!(full(fa.append(&[1])));
        // The crash drops b's unsynced 10 bytes and keeps a's synced 6 (or the truncation).
        fs.crash(1, CrashMode::Clean);
        fs.set_quota(Some(10)); // a crash clears every fault
        let kept = read_all(&fs, &a).unwrap().len();
        assert_eq!(read_all(&fs, &b).unwrap(), b"");
        let mut fb = fs.open(&b, OpenMode::Append).unwrap();
        fb.append(&vec![2; 10 - kept]).unwrap();
        assert!(full(fb.append(&[2])));
    }

    #[test]
    fn quota_frees_removed_files_after_their_last_handle_closes() {
        let (fs, dir) = setup();
        let (a, b, c) = (dir.join("a"), dir.join("b"), dir.join("c"));
        fs.set_quota(Some(10));
        write_synced(&fs, &a, &[1; 10]);
        fs.sync_dir(&dir).unwrap();
        let mut fb = fs.open(&b, OpenMode::CreateNew).unwrap();
        let full = |r: io::Result<()>| r.unwrap_err().kind() == io::ErrorKind::StorageFull;
        assert!(full(fb.append(&[2])));
        // An open handle keeps the unlinked file's space (POSIX).
        let held = fs.open(&a, OpenMode::Read).unwrap();
        fs.remove_file(&a).unwrap();
        assert!(full(fb.append(&[2])));
        drop(held);
        fb.append(&[2; 6]).unwrap();
        // A rename over an existing file frees the replaced file's bytes.
        write_synced(&fs, &c, &[3; 4]);
        assert!(full(fb.append(&[2])));
        fs.rename(&b, &c).unwrap();
        fb.append(&[2; 4]).unwrap();
        assert!(full(fb.append(&[2])));
        // A hard link does not double-count, and removing one of two names frees nothing.
        fs.hard_link(&c, &a).unwrap();
        fs.remove_file(&c).unwrap();
        assert!(full(fb.append(&[2])));
        drop(fb);
        fs.remove_file(&a).unwrap();
        let mut fd = fs.open(&dir.join("d"), OpenMode::CreateNew).unwrap();
        fd.append(&[4; 10]).unwrap();
        drop(fd);
        // The unsynced removal of `a` is undone by the crash, and so is its usage: only the
        // durable `a` (10 bytes) exists again.
        fs.crash(0, CrashMode::Clean);
        fs.set_quota(Some(10));
        assert_eq!(read_all(&fs, &a).unwrap(), [1; 10]);
        let mut fe = fs.open(&dir.join("e"), OpenMode::CreateNew).unwrap();
        assert!(full(fe.append(&[5])));
    }

    #[test]
    fn failed_sync_makes_nothing_durable() {
        let (fs, dir) = setup();
        let path = dir.join("a");
        let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
        fs.sync_dir(&dir).unwrap();
        f.append(b"abc").unwrap();
        fs.fail_next_syncs(1);
        assert!(f.sync_data().is_err());
        fs.crash(0, CrashMode::Clean);
        assert_eq!(read_all(&fs, &path).unwrap(), b"");
    }

    #[test]
    fn halt_stops_every_call_until_crash() {
        let (fs, dir) = setup();
        let path = dir.join("a");
        let start = fs.op_count();
        fs.halt_after_ops(2);
        let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
        f.append(b"x").unwrap();
        assert!(f.sync_data().is_err());
        assert!(fs.is_halted());
        assert_eq!(fs.op_count(), start + 2);
        assert!(fs.read_dir(&dir).is_err());
        assert!(fs.open(&path, OpenMode::Read).is_err());
        assert!(f.size().is_err());
        fs.crash(0, CrashMode::Clean);
        assert!(!fs.is_halted());
        assert_eq!(fs.read_dir(&dir).unwrap(), Vec::<PathBuf>::new());
    }

    /// Runs one fixed scenario and returns what survived a crash with `seed`.
    fn scenario(seed: u64, mode: CrashMode) -> Vec<Vec<u8>> {
        let (fs, dir) = setup();
        let mut out = Vec::new();
        for i in 0..4u8 {
            let path = dir.join(format!("f{i}"));
            let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
            f.append(&[i; 10]).unwrap();
            f.sync_data().unwrap();
            f.append(&[i + 100; 50]).unwrap();
        }
        fs.sync_dir(&dir).unwrap();
        fs.crash(seed, mode);
        for i in 0..4u8 {
            out.push(read_all(&fs, &dir.join(format!("f{i}"))).unwrap());
        }
        out
    }

    #[test]
    fn tc_bkp_014_sim_lock_is_exclusive_and_dies_with_a_crash() {
        let fs = SimFileSystem::new();
        fs.create_dir_all(Path::new("/d")).unwrap();
        let lock = Path::new("/d/LOCK");
        assert!(fs.try_lock_exclusive(Path::new("/missing/LOCK")).is_err());
        let first = fs.try_lock_exclusive(lock).unwrap();
        let err = fs.try_lock_exclusive(lock).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        drop(first);
        let second = fs.try_lock_exclusive(lock).unwrap();
        // A crash kills the holder: the path is free for the next process, and dropping the
        // stale guard afterwards must not release the new holder's lock.
        fs.crash(1, CrashMode::Clean);
        let third = fs.try_lock_exclusive(lock).unwrap();
        drop(second);
        assert_eq!(
            fs.try_lock_exclusive(lock).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(third);
        assert!(fs.try_lock_exclusive(lock).is_ok());
        // No file is created and no mutating operation is counted.
        assert_eq!(fs.op_count(), 1);
        assert_eq!(fs.read_dir(Path::new("/d")).unwrap(), Vec::<PathBuf>::new());
    }

    /// A file moved out of a directory (removal from it not yet synced), then the directory
    /// removed: no crash brings the file back under the missing directory, and it is never lost
    /// (found by the BH1 snapshot crash sweep of an encrypted store, `tests/crash.rs` of
    /// rustegon-backup).
    #[test]
    fn remove_dir_never_leaves_an_orphan_binding() {
        for mode in CrashMode::ALL {
            for seed in 0..8 {
                let fs = SimFileSystem::new();
                fs.create_dir_all(Path::new("/a/k")).unwrap();
                fs.create_dir_all(Path::new("/b")).unwrap();
                let mut f = fs.open(Path::new("/a/k/r"), OpenMode::CreateNew).unwrap();
                f.append(b"x").unwrap();
                f.sync_data().unwrap();
                drop(f);
                fs.sync_dir(Path::new("/a/k")).unwrap();
                fs.rename(Path::new("/a/k/r"), Path::new("/b/r")).unwrap();
                fs.sync_dir(Path::new("/b")).unwrap();
                fs.remove_dir(Path::new("/a/k")).unwrap();
                fs.crash(seed, mode);
                assert!(
                    fs.open(Path::new("/a/k/r"), OpenMode::Read).is_err(),
                    "{mode:?} {seed}"
                );
                assert_eq!(read_all(&fs, Path::new("/b/r")).unwrap(), b"x", "{mode:?}");
            }
        }
    }

    #[test]
    fn crash_is_deterministic_per_seed() {
        for mode in [
            CrashMode::TornPrefix,
            CrashMode::TornZeroTail,
            CrashMode::Journaled,
        ] {
            assert_eq!(scenario(7, mode), scenario(7, mode));
            assert!((0..8).any(|s| scenario(s, mode) != scenario(7, mode)));
        }
    }

    proptest! {
        /// Model property: after a crash, a file holds its last synced contents plus, after
        /// them, a prefix of what was appended afterwards, possibly followed by zeros (torn
        /// zero tail) — never more bytes than were written; exactly the synced contents when
        /// clean.
        #[test]
        fn crash_keeps_synced_prefix(
            ops in prop::collection::vec((prop::collection::vec(any::<u8>(), 0..16), any::<bool>()), 0..20),
            seed in any::<u64>(),
            mode in prop::sample::select(CrashMode::ALL.to_vec()),
        ) {
            let (fs, dir) = setup();
            let path = dir.join("log");
            let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
            fs.sync_dir(&dir).unwrap();
            let (mut written, mut synced) = (Vec::new(), 0);
            for (chunk, sync) in &ops {
                f.append(chunk).unwrap();
                written.extend_from_slice(chunk);
                if *sync {
                    f.sync_data().unwrap();
                    synced = written.len();
                }
            }
            fs.crash(seed, mode);
            let got = read_all(&fs, &path).unwrap();
            prop_assert!(got.len() >= synced && got.len() <= written.len());
            let data_end = got.len() - got.iter().rev().take_while(|&&b| b == 0).count();
            prop_assert_eq!(&got[..data_end.max(synced)], &written[..data_end.max(synced)]);
            match mode {
                CrashMode::Clean => prop_assert_eq!(got.len(), synced),
                CrashMode::TornPrefix => prop_assert!(written.starts_with(&got)),
                CrashMode::TornZeroTail | CrashMode::Journaled => {}
            }
        }
    }
}
