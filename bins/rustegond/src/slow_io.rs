// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Stall diagnostics of a running node (PD-233): the soak saw 40–60 s windows in which every
//! operation was 2–3x slower while the node's CPU did not rise, so the node was waiting. Two
//! cheap probes name what it waits on, as `warn` lines with `took_ms` / `late_ms`:
//!
//! - [`SlowFs`] wraps the node's file system and logs every call slower than [`SLOW_IO`]
//!   (log fsync, SST writes and reads, file removals and renames);
//! - [`stall_probe`] wakes every [`STALL_TICK`] and logs a wake-up late by [`SLOW_IO`] or more:
//!   a blocked or starved async runtime delays every request at once.
//!
//! The logging file system is not wrapped: a slow log write must not log itself.

use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use rustegon_sim_api::{Clock, File, FileLock, FileSystem, OpenMode};
use tokio::sync::watch;

/// A file-system call or a runtime wake-up this late is logged.
pub const SLOW_IO: Duration = Duration::from_millis(50);
/// Period of [`stall_probe`].
pub const STALL_TICK: Duration = Duration::from_millis(100);

/// Calls summed by [`stall_probe`] every [`SUMMARY_TICKS`]: a slowdown made of many calls
/// below [`SLOW_IO`] (a 2 ms fsync that takes 30 ms) logs no line of its own.
const SUMMED: [&str; 3] = ["sync_data", "append", "read"];
/// Per [`SUMMED`] call: count, total microseconds, longest microseconds since the last summary.
static STATS: [[AtomicU64; 3]; 3] = [const { [const { AtomicU64::new(0) }; 3] }; 3];
/// [`stall_probe`] logs the I/O summary every this many ticks (10 s).
const SUMMARY_TICKS: u32 = 100;

/// Times `f`; logs it when it took [`SLOW_IO`] or longer. Paths are data-directory file names,
/// never document contents.
fn timed<T>(clock: &dyn Clock, op: &'static str, path: &Path, f: impl FnOnce() -> T) -> T {
    let start = clock.monotonic();
    let out = f();
    let took = clock.monotonic().saturating_sub(start);
    if let Some(i) = SUMMED.iter().position(|o| *o == op) {
        let us = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        STATS[i][0].fetch_add(1, Ordering::Relaxed);
        STATS[i][1].fetch_add(us, Ordering::Relaxed);
        STATS[i][2].fetch_max(us, Ordering::Relaxed);
    }
    if took >= SLOW_IO {
        tracing::warn!(
            op,
            path = %path.display(),
            took_ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
            "slow file-system call"
        );
    }
    out
}

/// The node's file system with [`timed`] calls (module docs).
pub struct SlowFs {
    inner: Arc<dyn FileSystem>,
    clock: Arc<dyn Clock>,
}

impl SlowFs {
    pub fn new(inner: Arc<dyn FileSystem>, clock: Arc<dyn Clock>) -> Self {
        Self { inner, clock }
    }

    fn wrap(&self, path: &Path, file: Box<dyn File>) -> Box<dyn File> {
        Box::new(SlowFile {
            inner: file,
            clock: Arc::clone(&self.clock),
            path: path.to_path_buf(),
        })
    }
}

struct SlowFile {
    inner: Box<dyn File>,
    clock: Arc<dyn Clock>,
    path: PathBuf,
}

impl File for SlowFile {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        timed(self.clock.as_ref(), "read", &self.path, || {
            self.inner.read_exact_at(buf, offset)
        })
    }

    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        let (clock, path) = (Arc::clone(&self.clock), self.path.clone());
        timed(clock.as_ref(), "append", &path, || self.inner.append(buf))
    }

    fn sync_data(&self) -> io::Result<()> {
        timed(self.clock.as_ref(), "sync_data", &self.path, || {
            self.inner.sync_data()
        })
    }

    fn size(&self) -> io::Result<u64> {
        self.inner.size()
    }
}

impl FileSystem for SlowFs {
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Box<dyn File>> {
        let file = timed(self.clock.as_ref(), "open", path, || {
            self.inner.open(path, mode)
        })?;
        Ok(self.wrap(path, file))
    }

    fn create_new_private(&self, path: &Path) -> io::Result<Box<dyn File>> {
        let file = self.inner.create_new_private(path)?;
        Ok(self.wrap(path, file))
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        timed(self.clock.as_ref(), "rename", to, || {
            self.inner.rename(from, to)
        })
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        timed(self.clock.as_ref(), "remove_file", path, || {
            self.inner.remove_file(path)
        })
    }

    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        self.inner.hard_link(original, link)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.inner.read_dir(path)
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        timed(self.clock.as_ref(), "sync_dir", path, || {
            self.inner.sync_dir(path)
        })
    }

    fn permission_mode(&self, path: &Path) -> io::Result<Option<u32>> {
        self.inner.permission_mode(path)
    }

    fn try_lock_exclusive(&self, path: &Path) -> io::Result<FileLock> {
        self.inner.try_lock_exclusive(path)
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        self.inner.remove_dir(path)
    }
}

/// Logs async-runtime wake-ups late by [`SLOW_IO`] or more until `stopping` turns true
/// (module docs).
pub async fn stall_probe(clock: Arc<dyn Clock>, mut stopping: watch::Receiver<bool>) {
    let mut ticks = 0;
    while !*stopping.borrow() {
        ticks += 1;
        if ticks == SUMMARY_TICKS {
            ticks = 0;
            let take = |i: usize, j: usize| STATS[i][j].swap(0, Ordering::Relaxed);
            tracing::info!(
                sync_n = take(0, 0),
                sync_us = take(0, 1),
                sync_max_us = take(0, 2),
                append_n = take(1, 0),
                append_us = take(1, 1),
                append_max_us = take(1, 2),
                read_n = take(2, 0),
                read_us = take(2, 1),
                read_max_us = take(2, 2),
                "file-system summary"
            );
            #[cfg(feature = "heap-stats")]
            crate::heap_stats::log();
        }
        let start = clock.monotonic();
        tokio::select! {
            () = clock.sleep(STALL_TICK) => {}
            _ = stopping.changed() => return,
        }
        let late = clock
            .monotonic()
            .saturating_sub(start)
            .saturating_sub(STALL_TICK);
        if late >= SLOW_IO {
            tracing::warn!(
                late_ms = u64::try_from(late.as_millis()).unwrap_or(u64::MAX),
                "async runtime stalled"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rustegon_sim_api::{StdFileSystem, SystemClock};

    use super::*;

    /// PD-233: the wrapper is transparent (data written through it reads back unchanged).
    #[test]
    fn pd_233_slow_fs_passes_calls_through() {
        let dir = std::env::temp_dir().join(format!("rgn-slowfs-{}", std::process::id()));
        let fs = SlowFs::new(Arc::new(StdFileSystem), Arc::new(SystemClock::new()));
        fs.create_dir_all(&dir).unwrap();
        let path = dir.join("f");
        let mut f = fs.open(&path, OpenMode::CreateNew).unwrap();
        f.append(b"abc").unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.size().unwrap(), 3);
        let mut buf = [0; 3];
        fs.open(&path, OpenMode::Read)
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        assert_eq!(&buf, b"abc");
        drop(f);
        fs.remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
