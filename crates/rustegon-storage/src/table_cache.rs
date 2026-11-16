// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Cache of open SST readers keyed by file number (storage-engine.md §5).
//!
//! Opening an SST reads and validates its footer, metaindex, properties, top-level index and
//! filter, so the read path must not do it per lookup. Readers are cheap to clone (`Arc`) and stay
//! usable after eviction, so an iterator holding one is unaffected when the engine evicts the file
//! after deleting it.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
};

use rustegon_sim_api::{FileSystem, OpenMode};

use crate::{
    error::Result,
    sst::{SstReader, SstReaderOptions},
    version::sst_file_name,
};

/// Open readers of one store's SSTs.
// shortcut: unbounded (one entry per live SST); `max_open_files`-style LRU bounding and charging
// pinned index/filter memory to the block cache arrive with the cache follow-up PD.
pub struct TableCache {
    fs: Arc<dyn FileSystem>,
    dir: PathBuf,
    options: SstReaderOptions,
    /// Protects only the map; readers are opened outside the lock.
    readers: Mutex<HashMap<u64, SstReader>>,
}

impl TableCache {
    /// A cache for SSTs in `dir`, opened with `options` (prefix extractor, block cache,
    /// encryption context for the files' DEKs).
    #[must_use]
    pub fn new(fs: Arc<dyn FileSystem>, dir: PathBuf, options: SstReaderOptions) -> Self {
        Self {
            fs,
            dir,
            options,
            readers: Mutex::new(HashMap::new()),
        }
    }

    /// The reader of file `number`, opening it on first use.
    ///
    /// # Errors
    /// I/O errors and corruption from opening the file.
    pub fn get(&self, number: u64) -> Result<SstReader> {
        if let Some(reader) = self.lock().get(&number) {
            return Ok(reader.clone());
        }
        // Opened without the lock (it does I/O). Two racing opens are harmless: the first
        // inserted reader wins and the other is dropped.
        let file = self
            .fs
            .open(&self.dir.join(sst_file_name(number)), OpenMode::Read)?;
        let reader = SstReader::open_numbered(file, number, self.options.clone())?;
        Ok(self.lock().entry(number).or_insert(reader).clone())
    }

    /// Forgets file `number` (after it was deleted); open clones keep working.
    pub fn evict(&self, number: u64) {
        self.lock().remove(&number);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, SstReader>> {
        // Every critical section is a single map operation, so a panic cannot leave the map
        // half-updated; the poison flag carries no information here.
        self.readers.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
