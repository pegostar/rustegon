// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Encryption at rest of the embedded store (storage-engine.md §2, §7, §9; security.md §6;
//! FR-EAR-001/002, PD-057).
//!
//! Two DEK registries under `<root>/keys/`, both wrapped by the same KEK:
//! - `keys/registry.enc` for the LSM (`lsm/`: SSTs and MANIFESTs, numbered by LSM file
//!   numbers);
//! - `keys/raft-log/registry.enc` for the Raft log store (`raft-log/`: segments, numbered by
//!   segment ids).
//!
//! They are separate because the two number spaces overlap and each owner drops the DEKs of
//! numbers it does not know (the LSM forgets every registered number without a live file), so a
//! shared registry would let one side shred the other's keys.
//!
//! Open rules (recovery step "unwrap KEK / load DEK registry", §9):
//! - with a KEK: each registry is opened, or created when absent: a new store, or a plaintext
//!   store switching to encryption at this reopen (its plaintext files stay readable and are
//!   admitted once, storage-engine.md §7); a registry under another KEK, or a KEK that cannot
//!   unwrap it, is `RGN-4006`;
//! - without a KEK: a store that has either registry is encrypted, and opening it is
//!   `RGN-4006` (refused before any file is read, so the error names the cause).

use std::{path::Path, sync::Arc};

use rustegon_common::{Error, ErrorCode};
use rustegon_sim_api::{FileSystem, Rng};
use rustegon_storage::encryption::{KekProvider, KeyManager};

/// Key directory under the store root (storage-engine.md §2).
pub(super) const KEYS_DIR: &str = "keys";
/// The log store's registry directory, under [`KEYS_DIR`].
pub(super) const LOG_KEYS_DIR: &str = "raft-log";

/// The store's two key managers.
#[derive(Debug, Clone)]
pub(super) struct StoreKeys {
    pub(super) lsm: Arc<KeyManager>,
    pub(super) log: Arc<KeyManager>,
}

/// Opens (or creates) the store's key managers under `kek`, or checks that a store opened
/// without a KEK is not encrypted (module docs).
pub(super) fn open_store_keys(
    fs: &Arc<dyn FileSystem>,
    root: &Path,
    kek: Option<Arc<dyn KekProvider>>,
    rng: &Arc<dyn Rng>,
) -> Result<Option<StoreKeys>, Error> {
    let lsm_dir = root.join(KEYS_DIR);
    let log_dir = lsm_dir.join(LOG_KEYS_DIR);
    let Some(kek) = kek else {
        if KeyManager::exists(fs.as_ref(), &lsm_dir)? || KeyManager::exists(fs.as_ref(), &log_dir)?
        {
            return Err(Error::new(
                ErrorCode::KeyUnavailable,
                format!(
                    "the store in {} is encrypted at rest (DEK registry in {}) but no \
                     key-encryption key is configured; set storage.encryption = aes-256-gcm with \
                     its key provider",
                    root.display(),
                    lsm_dir.display()
                ),
            ));
        }
        return Ok(None);
    };
    let lsm =
        KeyManager::open_or_create(Arc::clone(fs), &lsm_dir, Arc::clone(&kek), Arc::clone(rng))?;
    let log = KeyManager::open_or_create(Arc::clone(fs), &log_dir, kek, Arc::clone(rng))?;
    Ok(Some(StoreKeys {
        lsm: Arc::new(lsm),
        log: Arc::new(log),
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::path::PathBuf;

    use rustegon_catalog::DatabaseOptions;
    use rustegon_doc::{Document, Value};
    use rustegon_sim_api::{OsRng, StdFileSystem, SystemClock};
    use rustegon_storage::{
        EngineOptions,
        encryption::{FileKekProvider, SecretKey},
    };

    use super::*;
    use crate::embedded::{EmbeddedDb, ID};

    fn kek(byte: u8) -> Arc<dyn KekProvider> {
        Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([byte; 32])))
    }

    fn open(root: &Path, kek: Option<Arc<dyn KekProvider>>) -> Result<EmbeddedDb, Error> {
        // Small memtables: the canaries reach SSTs through rotations, not only the log.
        let options = EngineOptions {
            memtable_size: 16 << 10,
            ..EngineOptions::default()
        };
        EmbeddedDb::open_with_kek(
            Arc::new(StdFileSystem),
            root,
            Arc::new(SystemClock::new()),
            Arc::new(OsRng),
            options,
            kek,
        )
    }

    fn canary(i: usize) -> String {
        format!("EAR-ENGINE-CANARY-{i:05}")
    }

    fn insert(db: &EmbeddedDb, range: std::ops::Range<usize>) {
        for i in range {
            let doc = Document::try_from_fields(vec![
                (ID.to_owned(), Value::Int64(i64::try_from(i).unwrap())),
                ("secret".to_owned(), Value::String(canary(i))),
            ])
            .unwrap();
            db.insert("shop", "orders", &doc).unwrap();
        }
    }

    fn files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                out.extend(files(&p));
            } else {
                out.push(p);
            }
        }
        out
    }

    /// Canaries of `range` found in any file under `dir` (one pass per file: every occurrence of
    /// the common prefix is decoded to its number).
    fn on_disk(dir: &Path, range: std::ops::Range<usize>) -> Vec<usize> {
        const PREFIX: &[u8] = b"EAR-ENGINE-CANARY-";
        let mut found = std::collections::BTreeSet::new();
        for path in files(dir) {
            // The store lock holds no data, and Windows locks are mandatory: unreadable while
            // the store is open (embedded/lock.rs).
            if path
                .file_name()
                .is_some_and(|n| n == crate::embedded::LOCK_FILE)
            {
                continue;
            }
            let bytes = std::fs::read(path).unwrap();
            for (at, _) in bytes
                .windows(PREFIX.len())
                .enumerate()
                .filter(|(_, w)| *w == PREFIX)
            {
                let digits = bytes.get(at + PREFIX.len()..at + PREFIX.len() + 5);
                if let Some(n) = digits
                    .and_then(|d| std::str::from_utf8(d).ok())
                    .and_then(|d| d.parse::<usize>().ok())
                {
                    found.insert(n);
                }
            }
        }
        range.filter(|i| found.contains(i)).collect()
    }

    fn secret_of(db: &EmbeddedDb, i: usize) -> Option<Value> {
        db.get("shop", "orders", &Value::Int64(i64::try_from(i).unwrap()))
            .unwrap()
            .and_then(|d| d.get("secret").cloned())
    }

    /// TC-EAR-001 (engine part, PD-057): documents written to an encrypted store are in no file
    /// (LSM SSTs and MANIFEST, Raft log segments, registries), before and after a flush, and
    /// read back after a reopen; the plaintext control run finds them.
    #[test]
    fn tc_ear_001_encrypted_embedded_store_holds_no_plaintext_document() {
        const N: usize = 300;
        let control = tempfile::tempdir().unwrap();
        let db = open(control.path(), None).unwrap();
        db.create_database("shop", &DatabaseOptions::default())
            .unwrap();
        insert(&db, 0..N);
        drop(db);
        assert_eq!(
            on_disk(control.path(), 0..N).len(),
            N,
            "control sees the canaries"
        );

        let dir = tempfile::tempdir().unwrap();
        let db = open(dir.path(), Some(kek(1))).unwrap();
        assert!(db.is_encrypted());
        db.create_database("shop", &DatabaseOptions::default())
            .unwrap();
        insert(&db, 0..N);
        assert_eq!(
            on_disk(dir.path(), 0..N),
            Vec::<usize>::new(),
            "log + rotated SSTs"
        );
        db.flush().unwrap();
        assert_eq!(db.plaintext_sst_count(), Some(0));
        drop(db);
        assert_eq!(
            on_disk(dir.path(), 0..N),
            Vec::<usize>::new(),
            "after flush"
        );
        assert!(dir.path().join("keys/registry.enc").exists());
        assert!(dir.path().join("keys/raft-log/registry.enc").exists());

        let db = open(dir.path(), Some(kek(1))).unwrap();
        assert_eq!(secret_of(&db, 7), Some(Value::String(canary(7))));
        assert_eq!(secret_of(&db, N - 1), Some(Value::String(canary(N - 1))));
    }

    /// TC-EAR-003 (engine part): an encrypted store opened without a KEK or under another KEK
    /// is refused with `RGN-4006`, and the message carries no key material.
    #[test]
    fn tc_ear_003_encrypted_embedded_store_refuses_a_missing_or_wrong_kek() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(dir.path(), Some(kek(1))).unwrap();
        db.create_database("shop", &DatabaseOptions::default())
            .unwrap();
        insert(&db, 0..10);
        drop(db);
        let err = open(dir.path(), None).err().unwrap();
        assert_eq!(err.code(), ErrorCode::KeyUnavailable, "{err}");
        assert!(err.message().contains("encrypted at rest"), "{err}");
        let err = open(dir.path(), Some(kek(2))).err().unwrap();
        assert_eq!(err.code(), ErrorCode::KeyUnavailable, "{err}");
        // Still readable with the right key: the refused opens changed nothing.
        let db = open(dir.path(), Some(kek(1))).unwrap();
        assert_eq!(secret_of(&db, 3), Some(Value::String(canary(3))));
    }

    /// TC-EAR-004 (engine part, storage-engine.md §7): a plaintext store switches to
    /// encryption at a reopen. Old data stays readable (and, until compaction rewrites it, in
    /// plaintext SSTs, which `plaintext_sst_count` reports); new data is encrypted; the store
    /// can no longer be opened without the key.
    #[test]
    fn tc_ear_004_plaintext_embedded_store_switches_to_encryption_at_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(dir.path(), None).unwrap();
        assert!(!db.is_encrypted());
        assert_eq!(db.plaintext_sst_count(), None);
        db.create_database("shop", &DatabaseOptions::default())
            .unwrap();
        insert(&db, 0..150);
        db.flush().unwrap();
        drop(db);

        let db = open(dir.path(), Some(kek(1))).unwrap();
        assert_eq!(secret_of(&db, 42), Some(Value::String(canary(42))));
        assert!(
            db.plaintext_sst_count().unwrap() > 0,
            "pre-switch SSTs are reported"
        );
        insert(&db, 150..300);
        db.flush().unwrap();
        drop(db);
        assert_eq!(on_disk(dir.path(), 150..300), Vec::<usize>::new());
        assert!(
            !on_disk(dir.path(), 0..150).is_empty(),
            "documented residual"
        );

        let err = open(dir.path(), None).err().unwrap();
        assert_eq!(err.code(), ErrorCode::KeyUnavailable);
        let db = open(dir.path(), Some(kek(1))).unwrap();
        assert_eq!(secret_of(&db, 7), Some(Value::String(canary(7))));
        assert_eq!(secret_of(&db, 277), Some(Value::String(canary(277))));
    }
}
