// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Memtable flush integration tests (storage-engine.md §3, §9): flushed content round trip,
//! persistence across reopen, L0 ordering, argument validation, cleanup after an injected write
//! failure (with logging of failed removals) and an injected MANIFEST write failure.

// Test helpers outside `#[test]` functions may unwrap (coding-standards.md §3.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::Bytes;
use proptest::prelude::*;
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{File, FileSystem, OpenMode, StdFileSystem};
use rustegon_storage::{
    Memtable, StorageError, ValueKind, flush_memtable,
    sst::{SstReader, SstReaderOptions, SstWriterOptions},
    version::{VersionSet, parse_file_name, sst_file_name},
};

fn options() -> SstWriterOptions {
    // Small blocks so that flushes span several data blocks.
    SstWriterOptions {
        block_size: 128,
        ..SstWriterOptions::default()
    }
}

fn std_fs() -> Arc<dyn FileSystem> {
    Arc::new(StdFileSystem)
}

fn sst_files(dir: &Path) -> Vec<PathBuf> {
    StdFileSystem
        .read_dir(dir)
        .unwrap()
        .into_iter()
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap();
            matches!(
                parse_file_name(name),
                Some(rustegon_storage::version::FileKind::Sst(_))
            )
        })
        .collect()
}

/// Memtable with `n` puts; seqnos `base+1..=base+n`.
fn memtable(base: u64, n: u64) -> Memtable {
    let m = Memtable::new();
    for i in 1..=n {
        m.add(
            base + i,
            ValueKind::Put,
            format!("k{i:03}").as_bytes(),
            Bytes::from(vec![7; 10]),
        );
    }
    m
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// The flushed SST holds exactly the memtable's entries in order, and the MANIFEST entry
    /// matches the file.
    #[test]
    fn flushed_sst_matches_memtable(
        raw in prop::collection::vec(
            (prop::collection::vec(b'a'..=b'd', 0..5), prop::collection::vec(any::<u8>(), 0..30), any::<bool>()),
            1..200,
        ),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut versions = VersionSet::create(std_fs(), dir.path()).unwrap();
        let m = Memtable::new();
        // Unique seqnos keep memtable entries distinct (Memtable::add contract).
        for (seq, (key, value, put)) in (1u64..).zip(&raw) {
            let kind = if *put { ValueKind::Put } else { ValueKind::Delete };
            m.add(seq, kind, key, Bytes::from(value.clone()));
        }
        let flushed = raw.len() as u64;
        let meta = flush_memtable(&StdFileSystem, dir.path(), &mut versions, &m, &options(), flushed)
            .unwrap()
            .unwrap();

        let path = dir.path().join(sst_file_name(meta.number));
        let reader = SstReader::open(
            StdFileSystem.open(&path, OpenMode::Read).unwrap(),
            SstReaderOptions::default(),
        ).unwrap();
        let mut it = reader.new_iterator();
        it.seek_to_first().unwrap();
        let mut got = Vec::new();
        while it.valid() {
            got.push((it.key().to_vec(), it.value().to_vec()));
            it.next().unwrap();
        }
        let want: Vec<_> = m.iter().map(|e| (e.key().as_bytes().to_vec(), e.value().to_vec())).collect();
        prop_assert_eq!(got, want);

        prop_assert_eq!(&meta.smallest, &m.iter().next().unwrap().key().clone());
        prop_assert_eq!(&meta.largest, &m.iter().last().unwrap().key().clone());
        prop_assert_eq!((meta.smallest_seqno, meta.largest_seqno), (1, flushed));
        prop_assert_eq!(meta.size, StdFileSystem.open(&path, OpenMode::Read).unwrap().size().unwrap());
        let current = versions.current();
        prop_assert_eq!(current.files(0).len(), 1);
        prop_assert_eq!(versions.flushed_seqno(), flushed);
        prop_assert_eq!(versions.last_seqno(), flushed);
    }
}

#[test]
fn flushes_order_l0_newest_first_and_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let mut versions = VersionSet::create(std_fs(), dir.path()).unwrap();
    let mut numbers = Vec::new();
    for round in 0..3 {
        let m = memtable(round * 10, 10);
        let meta = flush_memtable(
            &StdFileSystem,
            dir.path(),
            &mut versions,
            &m,
            &options(),
            round * 10 + 10,
        )
        .unwrap()
        .unwrap();
        numbers.push(meta.number);
    }
    numbers.reverse();
    let l0 = |v: &VersionSet| {
        v.current()
            .files(0)
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>()
    };
    assert_eq!(l0(&versions), numbers);
    drop(versions);

    let reopened = VersionSet::open(std_fs(), dir.path()).unwrap();
    assert_eq!(l0(&reopened), numbers);
    assert_eq!(reopened.flushed_seqno(), 30);
    assert_eq!(reopened.last_seqno(), 30);
    assert_eq!(
        reopened.obsolete_files(&BTreeSet::new()).unwrap(),
        Vec::<PathBuf>::new()
    );
}

#[test]
fn empty_memtable_writes_no_file_but_advances_flushed_seqno() {
    let dir = tempfile::tempdir().unwrap();
    let mut versions = VersionSet::create(std_fs(), dir.path()).unwrap();
    let got = flush_memtable(
        &StdFileSystem,
        dir.path(),
        &mut versions,
        &Memtable::new(),
        &options(),
        42,
    )
    .unwrap();
    assert!(got.is_none());
    assert_eq!(sst_files(dir.path()), Vec::<PathBuf>::new());
    drop(versions);
    let reopened = VersionSet::open(std_fs(), dir.path()).unwrap();
    assert_eq!(reopened.flushed_seqno(), 42);
    assert_eq!(reopened.current().all_files().count(), 0);
}

#[test]
fn seqno_above_flushed_seqno_is_rejected_without_leftovers() {
    let dir = tempfile::tempdir().unwrap();
    let mut versions = VersionSet::create(std_fs(), dir.path()).unwrap();
    let err = flush_memtable(
        &StdFileSystem,
        dir.path(),
        &mut versions,
        &memtable(0, 5),
        &options(),
        4,
    )
    .unwrap_err();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
    assert_eq!(sst_files(dir.path()), Vec::<PathBuf>::new());
    assert_eq!(versions.flushed_seqno(), 0);
}

/// File system whose SST files fail every append (simulates EIO/ENOSPC mid-flush); with
/// `fail_remove` the cleanup `remove_file` fails too.
struct FailingSstFs {
    fail_remove: bool,
}

struct FailingFile;

impl File for FailingFile {
    fn read_exact_at(&self, _buf: &mut [u8], _offset: u64) -> io::Result<()> {
        Err(io::Error::other("injected"))
    }
    fn append(&mut self, _buf: &[u8]) -> io::Result<()> {
        Err(io::Error::other("injected append failure"))
    }
    fn sync_data(&self) -> io::Result<()> {
        Ok(())
    }
    fn size(&self) -> io::Result<u64> {
        Ok(0)
    }
}

impl FileSystem for FailingSstFs {
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Box<dyn File>> {
        let file = StdFileSystem.open(path, mode)?;
        if path.extension().is_some_and(|e| e == "sst") {
            // The real file exists (so cleanup is observable); writes to it fail.
            drop(file);
            return Ok(Box::new(FailingFile));
        }
        Ok(file)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        StdFileSystem.create_dir_all(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        StdFileSystem.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        if self.fail_remove {
            return Err(io::Error::other("injected remove failure"));
        }
        StdFileSystem.remove_file(path)
    }
    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        StdFileSystem.hard_link(original, link)
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        StdFileSystem.read_dir(path)
    }
    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        StdFileSystem.sync_dir(path)
    }
}

#[test]
fn injected_write_failure_leaves_no_live_file_and_no_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let fs: Arc<dyn FileSystem> = Arc::new(FailingSstFs { fail_remove: false });
    let mut versions = VersionSet::create(Arc::clone(&fs), dir.path()).unwrap();
    let err = flush_memtable(
        fs.as_ref(),
        dir.path(),
        &mut versions,
        &memtable(0, 50),
        &options(),
        50,
    )
    .unwrap_err();
    assert!(matches!(err, StorageError::Io(_)), "{err}");
    assert_eq!(versions.current().all_files().count(), 0);
    assert_eq!(versions.flushed_seqno(), 0);
    assert_eq!(sst_files(dir.path()), Vec::<PathBuf>::new());
    assert_eq!(
        versions.obsolete_files(&BTreeSet::new()).unwrap(),
        Vec::<PathBuf>::new()
    );

    // The version set is still usable: a later flush on a healthy file system succeeds.
    drop(versions);
    let mut versions = VersionSet::open(std_fs(), dir.path()).unwrap();
    let meta = flush_memtable(
        &StdFileSystem,
        dir.path(),
        &mut versions,
        &memtable(0, 5),
        &options(),
        5,
    )
    .unwrap();
    assert!(meta.is_some());
}

/// Subscriber that records the formatted fields of every `WARN` event.
#[derive(Default)]
struct WarnCapture(Mutex<Vec<String>>);

struct FieldsToString<'a>(&'a mut String);

impl tracing::field::Visit for FieldsToString<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        // Writing to a String cannot fail.
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() == tracing::Level::WARN {
            let mut s = String::new();
            event.record(&mut FieldsToString(&mut s));
            self.0.lock().unwrap().push(s);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn failed_cleanup_removal_is_logged_with_file_number() {
    let dir = tempfile::tempdir().unwrap();
    let fs: Arc<dyn FileSystem> = Arc::new(FailingSstFs { fail_remove: true });
    let mut versions = VersionSet::create(Arc::clone(&fs), dir.path()).unwrap();
    let capture = Arc::new(WarnCapture::default());
    let err = tracing::subscriber::with_default(Arc::clone(&capture), || {
        flush_memtable(
            fs.as_ref(),
            dir.path(),
            &mut versions,
            &memtable(0, 50),
            &options(),
            50,
        )
        .unwrap_err()
    });
    // The original write error is reported, not the cleanup failure.
    assert!(err.to_string().contains("append"), "{err}");
    let warns = capture.0.lock().unwrap();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("file_number=2"), "{warns:?}");
    // The orphan is left for startup cleanup.
    assert_eq!(sst_files(dir.path()).len(), 1);
}

#[test]
fn flushed_seqno_below_recorded_is_rejected_on_both_paths() {
    let dir = tempfile::tempdir().unwrap();
    let mut versions = VersionSet::create(std_fs(), dir.path()).unwrap();
    flush_memtable(
        &StdFileSystem,
        dir.path(),
        &mut versions,
        &memtable(0, 5),
        &options(),
        10,
    )
    .unwrap();
    let before = sst_files(dir.path());

    // Non-empty path: entries are all <= 9, so only the regression can trigger the error.
    let err = flush_memtable(
        &StdFileSystem,
        dir.path(),
        &mut versions,
        &memtable(0, 3),
        &options(),
        9,
    )
    .unwrap_err();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
    // Empty path: previously a silent no-op.
    let err = flush_memtable(
        &StdFileSystem,
        dir.path(),
        &mut versions,
        &Memtable::new(),
        &options(),
        9,
    )
    .unwrap_err();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
    assert_eq!(sst_files(dir.path()), before);
    assert_eq!(versions.flushed_seqno(), 10);

    // Re-declaring the recorded value is not a regression.
    let got = flush_memtable(
        &StdFileSystem,
        dir.path(),
        &mut versions,
        &Memtable::new(),
        &options(),
        10,
    )
    .unwrap();
    assert!(got.is_none());
}

#[test]
fn seqno_above_flushed_seqno_fails_before_any_fsync() {
    let sim = Arc::new(SimFileSystem::new());
    let fs: Arc<dyn FileSystem> = sim.clone();
    let dir = Path::new("/db");
    let mut versions = VersionSet::create(Arc::clone(&fs), dir).unwrap();
    // Had the SST been finished (fsynced) before the seqno check, this would surface as `Io`.
    sim.fail_next_syncs(1);
    let err = flush_memtable(
        fs.as_ref(),
        dir,
        &mut versions,
        &memtable(0, 5),
        &options(),
        4,
    )
    .unwrap_err();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
    assert!(
        versions
            .obsolete_files(&BTreeSet::new())
            .unwrap()
            .is_empty(),
        "partial SST must be removed"
    );
}

/// Delegates to a [`SimFileSystem`] and, once armed, fails the first append after the next
/// directory fsync: in a flush that is exactly the MANIFEST record append (module ordering,
/// step 3).
struct FailManifestAppendFs {
    sim: Arc<SimFileSystem>,
    armed: AtomicBool,
}

impl FileSystem for FailManifestAppendFs {
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Box<dyn File>> {
        self.sim.open(path, mode)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.sim.create_dir_all(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.sim.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.sim.remove_file(path)
    }
    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        self.sim.hard_link(original, link)
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.sim.read_dir(path)
    }
    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        self.sim.sync_dir(path)?;
        if self.armed.swap(false, Ordering::SeqCst) {
            self.sim.fail_next_appends(1);
        }
        Ok(())
    }
}

#[test]
fn manifest_write_failure_keeps_sst_and_poisons_set_until_reopen() {
    let sim = Arc::new(SimFileSystem::new());
    let dir = Path::new("/db");
    let wrapper = Arc::new(FailManifestAppendFs {
        sim: Arc::clone(&sim),
        armed: AtomicBool::new(false),
    });
    let fs: Arc<dyn FileSystem> = wrapper.clone();
    let mut versions = VersionSet::create(Arc::clone(&fs), dir).unwrap();
    wrapper.armed.store(true, Ordering::SeqCst);

    let err = flush_memtable(
        fs.as_ref(),
        dir,
        &mut versions,
        &memtable(0, 5),
        &options(),
        5,
    )
    .unwrap_err();
    assert!(matches!(err, StorageError::Io(_)), "{err}");
    let sst = dir.join(sst_file_name(2));
    assert!(sim.open(&sst, OpenMode::Read).is_ok(), "SST must be kept");

    // The set refuses every later edit, including a further flush (documented error).
    let err = flush_memtable(
        fs.as_ref(),
        dir,
        &mut versions,
        &Memtable::new(),
        &options(),
        6,
    )
    .unwrap_err();
    assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
    drop(versions);

    // The failed append wrote nothing, so the reopened store does not reference the SST and
    // reports it as obsolete instead of refusing to open.
    let reopened = VersionSet::open(Arc::clone(&fs), dir).unwrap();
    assert_eq!(reopened.current().all_files().count(), 0);
    assert_eq!(reopened.flushed_seqno(), 0);
    assert!(
        reopened
            .obsolete_files(&BTreeSet::new())
            .unwrap()
            .contains(&sst)
    );
}
