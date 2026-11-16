// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The DEK registry `keys/registry.enc` and the store's key manager (storage-engine.md §2, §7,
//! §9).
//!
//! The registry maps `file_number → (wrapped DEK, KEK id)`. It is small and rewritten whole on
//! every change, atomically: write `registry.enc.tmp`, fsync it, rename it over
//! `registry.enc`, fsync the directory. A crash at any point leaves the old or the new registry,
//! never a mix, and a leftover temp file is removed at open.
//!
//! Durability ordering: a file's DEK is durable in the registry *before* the file is created
//! ([`KeyManager::new_file_cipher`]), so every durable encrypted file has a durable key. A crash
//! in between leaves an unused entry, which costs ~100 bytes and is dropped by
//! [`KeyManager::forget`] when the engine's orphan cleanup runs.
//!
//! File format v2 (integers little endian; written by this build):
//! ```text
//! magic "RGNKEYS\x01" (8) ‖ format version u32 ‖ KEK id len u8 ‖ KEK id ‖
//! wrapped registry key len u32 ‖ wrapped registry key ‖ body len u32 ‖ body ‖ xxh3-64 u64
//! body = AES-256-GCM(registry key, nonce 0^12, aad = every byte before `body len`)
//!        of: admission u8 (0 none, 1 present) ‖ [plaintext MANIFEST number varint] ‖
//!            count varint ‖ (file number varint ‖ KEK id len u8 ‖ KEK id ‖
//!            wrapped len varint ‖ wrapped DEK)*   (ascending file number)
//! ```
//! v1 (read only) is v2 without the admission field. Readers accept both; writers always
//! write v2, so a v1 registry becomes v2 at its next rewrite.
//!
//! Plaintext-MANIFEST admission (v2): in an encrypted store the MANIFEST named by `CURRENT` must
//! have a DEK, otherwise anyone able to write the data directory could swap in a plaintext
//! MANIFEST of their choosing (a forged layout, seqnos, plaintext SSTs). The one legitimate
//! exception is switching a plaintext store to encryption: its last MANIFEST is plaintext until
//! the first encrypted one is current. [`KeyManager::admit_plaintext_manifest`] allows that only
//! for a registry that holds no DEK yet, and records the admitted MANIFEST number inside the
//! authenticated body in the same atomic rewrite as the first DEK, so a crash anywhere in the
//! switch still reopens; [`KeyManager::forget`] (called once the encrypted MANIFEST is current) drops it.
//! Not covered: replaying an older registry file together with older store files (rollback);
//! that needs a monotonic counter outside the data directory and is out of scope for v2.
//! "Encrypted with the active KEK" (§7) is realised as an envelope: each rewrite draws a fresh
//! registry key, encrypts the body with it and stores it wrapped by the KEK. KMS providers
//! (M13) can only wrap small keys, not encrypt a growing blob, so this keeps one scheme for every
//! provider (PD-023). Because a registry key encrypts exactly one message, the fixed all-zero
//! nonce never repeats under one key. The trailing checksum separates damage (corruption) from
//! a wrong KEK, which the KEK id in the header reports as `RGN-4006` before any decryption.
//!
//! Concurrency: rewrites are serialised by a mutex held across the rewrite I/O (a registry
//! change costs one small file write and two fsyncs, rare next to the SST it precedes); lookups
//! take a read lock on the in-memory map only, never during I/O. Unwrapped DEKs are cached per
//! file so a KMS provider is called once per file, not per open.

use std::{
    collections::BTreeMap,
    fmt,
    hash::Hasher as _,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, PoisonError, RwLock},
};

use rustegon_sim_api::{FileSystem, OpenMode, Rng};
use twox_hash::XxHash3_64;
use zeroize::Zeroize;

use super::{FileCipher, KekId, KekProvider, NONCE_LEN, SecretKey, WrappedKey, open, seal};
use crate::{
    coding::{Reader, put_varint},
    error::{Result, StorageError},
};

/// File name of the registry inside the keys directory (storage-engine.md §2).
pub const REGISTRY_FILE_NAME: &str = "registry.enc";
const REGISTRY_TMP_NAME: &str = "registry.enc.tmp";
const MAGIC: [u8; 8] = *b"RGNKEYS\x01";
/// Version written by this build (module docs: v2 adds the plaintext-MANIFEST admission).
const FORMAT_VERSION: u32 = 2;
/// Oldest version still read: v1, the registry of the M1 format fixtures.
const FORMAT_VERSION_V1: u32 = 1;
/// Upper bound on the registry file: ~100 bytes per entry, so 64 MiB is over half a million
/// files, far beyond a store's live file count. Larger files are refused before reading.
const MAX_REGISTRY_LEN: u64 = 64 << 20;
const CHECKSUM_LEN: usize = 8;
/// Upper bound on one wrapped key (KMS ciphertexts are a few hundred bytes).
const MAX_WRAPPED_LEN: u64 = 4 << 10;

/// One registry entry and its lazily unwrapped cipher (`Debug` redacts the cipher).
#[derive(Debug)]
struct Entry {
    wrapped: WrappedKey,
    cipher: OnceLock<Arc<FileCipher>>,
}

/// The store's encryption context: KEK provider, DEK registry and RNG (storage-engine.md §7).
/// Shared through `Arc` by the SST writer/reader options and the version set.
pub struct KeyManager {
    fs: Arc<dyn FileSystem>,
    dir: PathBuf,
    provider: Arc<dyn KekProvider>,
    rng: Arc<dyn Rng>,
    /// Serialises rewrites; held across the rewrite I/O (module docs). Also guards
    /// `plaintext_manifest`, which only changes in a rewrite.
    write: Mutex<Option<u64>>,
    entries: RwLock<Arc<BTreeMap<u64, Arc<Entry>>>>,
}

/// Decoded registry body (`Debug` redacts ciphers through `Entry`).
#[derive(Debug)]
struct Contents {
    entries: BTreeMap<u64, Arc<Entry>>,
    /// The plaintext MANIFEST admitted while switching to encryption (module docs).
    plaintext_manifest: Option<u64>,
}

impl KeyManager {
    /// Creates an empty registry in `dir` (created if missing) for a new store.
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] if `dir` already holds a registry; I/O errors;
    /// [`StorageError::KeyUnavailable`] if the provider cannot wrap.
    pub fn create(
        fs: Arc<dyn FileSystem>,
        dir: &Path,
        provider: Arc<dyn KekProvider>,
        rng: Arc<dyn Rng>,
    ) -> Result<Self> {
        // `keys/` itself must be durable before any DEK in it protects a file (§7).
        crate::version::create_dir_durable(fs.as_ref(), dir)?;
        if Self::exists(fs.as_ref(), dir)? {
            return Err(StorageError::InvalidArgument(format!(
                "{} already contains a DEK registry",
                dir.display()
            )));
        }
        let empty = Contents {
            entries: BTreeMap::new(),
            plaintext_manifest: None,
        };
        let manager = Self::with_contents(fs, dir, provider, rng, empty);
        manager.persist(&BTreeMap::new(), None)?;
        Ok(manager)
    }

    /// Loads the registry of an existing store (recovery step "unwrap KEK / load DEK registry",
    /// §9).
    ///
    /// # Errors
    /// [`StorageError::KeyUnavailable`] if the registry is missing or was written under another
    /// KEK, or the provider cannot unwrap it (the node must refuse to start, `RGN-4006`);
    /// [`StorageError::Corruption`] for a damaged registry; I/O errors.
    pub fn open(
        fs: Arc<dyn FileSystem>,
        dir: &Path,
        provider: Arc<dyn KekProvider>,
        rng: Arc<dyn Rng>,
    ) -> Result<Self> {
        let path = dir.join(REGISTRY_FILE_NAME);
        let file = match fs.open(&path, OpenMode::Read) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::key_unavailable(format!(
                    "DEK registry {} not found",
                    path.display()
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let size = file.size()?;
        if size > MAX_REGISTRY_LEN {
            return Err(StorageError::corruption(format!(
                "DEK registry of {size} bytes exceeds {MAX_REGISTRY_LEN}"
            )));
        }
        // Lossless: bounded by MAX_REGISTRY_LEN.
        #[allow(clippy::cast_possible_truncation)]
        let mut data = vec![0u8; size as usize];
        file.read_exact_at(&mut data, 0)?;
        drop(file);
        let contents = decode(&data, provider.as_ref())?;
        // A temp file is left only by a crash before its rename; it is never needed.
        match fs.remove_file(&dir.join(REGISTRY_TMP_NAME)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        Ok(Self::with_contents(fs, dir, provider, rng, contents))
    }

    /// [`KeyManager::open`] when `dir` holds a registry, else [`KeyManager::create`]: the open
    /// path of a store whose configuration enables encryption (a new store, or a plaintext
    /// store switching to encryption at this reopen, storage-engine.md §7).
    ///
    /// # Errors
    /// As [`KeyManager::open`] and [`KeyManager::create`].
    pub fn open_or_create(
        fs: Arc<dyn FileSystem>,
        dir: &Path,
        provider: Arc<dyn KekProvider>,
        rng: Arc<dyn Rng>,
    ) -> Result<Self> {
        if Self::exists(fs.as_ref(), dir)? {
            Self::open(fs, dir, provider, rng)
        } else {
            Self::create(fs, dir, provider, rng)
        }
    }

    /// Whether `dir` holds a registry (an encrypted store); lets the engine refuse to open an
    /// encrypted store without a key instead of failing on the first encrypted file.
    ///
    /// # Errors
    /// I/O errors other than "not found".
    pub fn exists(fs: &dyn FileSystem, dir: &Path) -> Result<bool> {
        match fs.open(&dir.join(REGISTRY_FILE_NAME), OpenMode::Read) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn with_contents(
        fs: Arc<dyn FileSystem>,
        dir: &Path,
        provider: Arc<dyn KekProvider>,
        rng: Arc<dyn Rng>,
        contents: Contents,
    ) -> Self {
        Self {
            fs,
            dir: dir.to_path_buf(),
            provider,
            rng,
            write: Mutex::new(contents.plaintext_manifest),
            entries: RwLock::new(Arc::new(contents.entries)),
        }
    }

    /// Creates a new registry in `dir` (created if missing) that holds exactly the DEKs this
    /// registry has for `file_numbers`, and returns its manager, which shares this one's KEK
    /// provider, RNG and file system (storage-engine.md §10, checkpoints of encrypted stores).
    ///
    /// The wrapped DEKs are copied as they are, never unwrapped: the copy is readable with the
    /// same KEK and nothing else, and no key material is exposed. Numbers without a DEK (files
    /// written before the store switched to encryption, which are plaintext) are skipped; the
    /// plaintext-MANIFEST admission is not copied, since the caller writes its own (encrypted)
    /// MANIFEST. The new file is written with the same atomic rewrite as every registry change,
    /// in the unchanged on-disk format, so it is durable when this returns.
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] if `dir` already holds a registry; I/O errors;
    /// [`StorageError::KeyUnavailable`] if the provider cannot wrap the fresh registry key.
    pub fn export_subset(&self, dir: &Path, file_numbers: &[u64]) -> Result<Self> {
        // Exporting into this registry's own directory is refused by the existence check.
        crate::version::create_dir_durable(self.fs.as_ref(), dir)?;
        if Self::exists(self.fs.as_ref(), dir)? {
            return Err(StorageError::InvalidArgument(format!(
                "{} already contains a DEK registry",
                dir.display()
            )));
        }
        let current = self.snapshot();
        // Entries are immutable apart from their unwrapped-cipher cache, which holds the same
        // DEK in both registries, so sharing the `Arc` is sound and saves a KMS unwrap later.
        let entries: BTreeMap<u64, Arc<Entry>> = file_numbers
            .iter()
            .filter_map(|n| current.get(n).map(|e| (*n, Arc::clone(e))))
            .collect();
        let exported = Self::with_contents(
            Arc::clone(&self.fs),
            dir,
            Arc::clone(&self.provider),
            Arc::clone(&self.rng),
            Contents {
                entries: BTreeMap::new(),
                plaintext_manifest: None,
            },
        );
        exported.persist(&entries, None)?;
        *exported
            .entries
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(entries);
        Ok(exported)
    }

    /// Id of the active KEK.
    #[must_use]
    pub fn kek_id(&self) -> &KekId {
        self.provider.key_id()
    }

    /// File numbers with a registered DEK, ascending.
    #[must_use]
    pub fn file_numbers(&self) -> Vec<u64> {
        self.snapshot().keys().copied().collect()
    }

    /// Generates a fresh DEK for the new file `file_number`, makes it durable in the registry,
    /// and returns the file's cipher. Must be called before the file is created (module docs).
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] if `file_number` already has a DEK (a reused file
    /// number would make an existing file undecryptable); I/O errors from the rewrite;
    /// [`StorageError::KeyUnavailable`] if the provider cannot wrap.
    pub fn new_file_cipher(&self, file_number: u64) -> Result<Arc<FileCipher>> {
        let admission = self.lock_write();
        let current = self.snapshot();
        if current.contains_key(&file_number) {
            return Err(StorageError::InvalidArgument(format!(
                "file {file_number} already has a DEK"
            )));
        }
        let dek = SecretKey::generate(self.rng.as_ref());
        let entry = Entry {
            wrapped: self.provider.wrap(&dek, self.rng.as_ref())?,
            cipher: OnceLock::new(),
        };
        let cipher = Arc::new(FileCipher::new(file_number, &dek));
        drop(dek);
        // Cached only once the entry is durable, so a failed rewrite leaves no usable key.
        let _ = entry.cipher.set(Arc::clone(&cipher));
        let mut next = BTreeMap::clone(&current);
        next.insert(file_number, Arc::new(entry));
        self.persist(&next, *admission)?;
        *self.entries.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
        Ok(cipher)
    }

    /// Like [`KeyManager::new_file_cipher`], but replaces a DEK `file_number` may already have,
    /// and keeps the plaintext admission (unlike [`KeyManager::forget`]).
    ///
    /// For file kinds whose numbers must be reused after a crash: a Raft log segment id must
    /// stay contiguous, so a segment whose creation was interrupted (DEK registered, file never
    /// made durable or removed as a torn creation) is created again under the same id. The
    /// caller guarantees that no durable data was ever encrypted under the old DEK (a torn
    /// creation holds only the plaintext segment head), so dropping it loses nothing; the new
    /// DEK is fresh, so no nonce is ever reused under one key.
    ///
    /// # Errors
    /// As [`KeyManager::new_file_cipher`], except that an existing DEK is not an error.
    pub fn replace_file_cipher(&self, file_number: u64) -> Result<Arc<FileCipher>> {
        let admission = self.lock_write();
        let current = self.snapshot();
        let dek = SecretKey::generate(self.rng.as_ref());
        let entry = Entry {
            wrapped: self.provider.wrap(&dek, self.rng.as_ref())?,
            cipher: OnceLock::new(),
        };
        let cipher = Arc::new(FileCipher::new(file_number, &dek));
        drop(dek);
        let _ = entry.cipher.set(Arc::clone(&cipher));
        let mut next = BTreeMap::clone(&current);
        next.insert(file_number, Arc::new(entry));
        self.persist(&next, *admission)?;
        *self.entries.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
        Ok(cipher)
    }

    /// The cipher of file `file_number`, or `None` if the file has no DEK (a plaintext file).
    ///
    /// # Errors
    /// [`StorageError::KeyUnavailable`] if the DEK does not unwrap under the active KEK.
    pub fn file_cipher(&self, file_number: u64) -> Result<Option<Arc<FileCipher>>> {
        let Some(entry) = self.snapshot().get(&file_number).cloned() else {
            return Ok(None);
        };
        if let Some(cipher) = entry.cipher.get() {
            return Ok(Some(Arc::clone(cipher)));
        }
        // Racing first lookups may both unwrap; the first stored cipher wins.
        let dek = self.provider.unwrap(&entry.wrapped)?;
        let cipher = entry
            .cipher
            .get_or_init(|| Arc::new(FileCipher::new(file_number, &dek)));
        Ok(Some(Arc::clone(cipher)))
    }

    /// The wrapped DEK of file `file_number` exactly as the registry stores it (still encrypted
    /// under the KEK named by its `kek_id`), or `None` for a file without a DEK.
    ///
    /// Export hook for backups (FR-BKP-002/004, PD-066): an archiver stores this next to a
    /// copied file so the copy stays readable after the live file — and with it the registry
    /// entry — is deleted and shredded. The key never leaves the registry in the clear, so the
    /// archive is no weaker than the store: reading it needs the same KEK
    /// ([`KekProvider::unwrap`]). Nothing is written; the registry format is unchanged.
    #[must_use]
    pub fn wrapped_key(&self, file_number: u64) -> Option<WrappedKey> {
        self.snapshot()
            .get(&file_number)
            .map(|entry| entry.wrapped.clone())
    }

    /// Durably drops the DEKs of deleted files (obsolete SSTs and MANIFESTs, orphans). Without
    /// its DEK a leftover copy of the file is unreadable (crypto-shredding). Also the DEK
    /// rotation hook: forget nothing live; a full compaction rewrites every SST with fresh DEKs
    /// and the old files' keys are forgotten when they are deleted.
    ///
    /// Also drops a plaintext-MANIFEST admission (module docs): callers forget files only once
    /// an encrypted MANIFEST is current, after which no plaintext MANIFEST is legitimate.
    ///
    /// # Errors
    /// I/O errors from the rewrite (the registry then holds the old or the new set).
    pub fn forget(&self, file_numbers: &[u64]) -> Result<()> {
        let mut admission = self.lock_write();
        let current = self.snapshot();
        if admission.is_none() && !file_numbers.iter().any(|n| current.contains_key(n)) {
            return Ok(());
        }
        let mut next = BTreeMap::clone(&current);
        for n in file_numbers {
            next.remove(n);
        }
        self.persist(&next, None)?;
        *admission = None;
        *self.entries.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
        Ok(())
    }

    /// Admits MANIFEST `manifest_number`, which has no DEK, as the plaintext MANIFEST of a store
    /// being switched to encryption (module docs, "Plaintext-MANIFEST admission"). Allowed only
    /// while the registry holds no DEK (nothing is encrypted yet; the admission becomes durable
    /// together with the first DEK) or when this number is the one already admitted (a crash
    /// interrupted the switch).
    ///
    /// # Errors
    /// [`StorageError::Corruption`] when the registry already protects files: a plaintext
    /// MANIFEST in an encrypted store was not written by the engine.
    pub fn admit_plaintext_manifest(&self, manifest_number: u64) -> Result<()> {
        let mut admission = self.lock_write();
        if *admission == Some(manifest_number) {
            return Ok(());
        }
        let current = self.snapshot();
        if admission.is_some() || !current.is_empty() {
            return Err(StorageError::corruption(format!(
                "MANIFEST {manifest_number} has no DEK in an encrypted store: a plaintext \
                 MANIFEST is only accepted while switching a plaintext store to encryption"
            )));
        }
        // Held in memory only: nothing needs it durable until the first DEK exists, and
        // `new_file_cipher` writes it in the same atomic rewrite as that DEK. A crash before
        // then leaves an empty registry, which admits the MANIFEST again.
        *admission = Some(manifest_number);
        Ok(())
    }

    /// The plaintext MANIFEST currently admitted, if any (for tests and diagnostics).
    #[must_use]
    pub fn admitted_plaintext_manifest(&self) -> Option<u64> {
        *self.lock_write()
    }

    fn snapshot(&self) -> Arc<BTreeMap<u64, Arc<Entry>>> {
        // Writers replace the whole map in one assignment, so a poisoned lock still guards a
        // consistent value.
        Arc::clone(&self.entries.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn lock_write(&self) -> std::sync::MutexGuard<'_, Option<u64>> {
        // The guarded state is the file on disk, which a panic mid-rewrite leaves old or new
        // (atomic rename), and the admission, assigned only after a successful rewrite; the
        // poison flag carries no information.
        self.write.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Atomically replaces the registry file with `entries` and `admission` (module docs).
    fn persist(&self, entries: &BTreeMap<u64, Arc<Entry>>, admission: Option<u64>) -> Result<()> {
        let data = encode(
            entries,
            admission,
            self.provider.as_ref(),
            self.rng.as_ref(),
        )?;
        let tmp = self.dir.join(REGISTRY_TMP_NAME);
        let mut file = self.fs.open(&tmp, OpenMode::Truncate)?;
        file.append(&data)?;
        file.sync_data()?;
        // Close before renaming: Windows refuses to rename a file with an open handle.
        drop(file);
        self.fs.rename(&tmp, &self.dir.join(REGISTRY_FILE_NAME))?;
        self.fs.sync_dir(&self.dir)?;
        Ok(())
    }
}

impl fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyManager")
            .field("dir", &self.dir)
            .field("kek_id", self.provider.key_id())
            .field("files", &self.snapshot().len())
            .finish_non_exhaustive()
    }
}

fn checksum(data: &[u8]) -> u64 {
    let mut h = XxHash3_64::new();
    h.write(data);
    h.finish()
}

fn put_kek_id(out: &mut Vec<u8>, id: &KekId) {
    // Lossless: KekId::new bounds the length to 255.
    #[allow(clippy::cast_possible_truncation)]
    out.push(id.as_str().len() as u8);
    out.extend_from_slice(id.as_str().as_bytes());
}

fn get_kek_id(r: &mut Reader<'_>) -> Option<KekId> {
    let len = r.u8()?;
    let text = std::str::from_utf8(r.bytes(usize::from(len))?).ok()?;
    KekId::new(text).ok()
}

fn encode(
    entries: &BTreeMap<u64, Arc<Entry>>,
    admission: Option<u64>,
    provider: &dyn KekProvider,
    rng: &dyn Rng,
) -> Result<Vec<u8>> {
    let registry_key = SecretKey::generate(rng);
    let wrapped = provider.wrap(&registry_key, rng)?;
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    put_kek_id(&mut out, &wrapped.kek_id);
    let wrapped_len = u32::try_from(wrapped.bytes.len())
        .map_err(|_| StorageError::InvalidArgument("wrapped registry key too long".into()))?;
    out.extend_from_slice(&wrapped_len.to_le_bytes());
    out.extend_from_slice(&wrapped.bytes);
    let header_len = out.len();

    let mut body = Vec::new();
    match admission {
        None => body.push(0),
        Some(number) => {
            body.push(1);
            put_varint(&mut body, number);
        }
    }
    put_varint(&mut body, entries.len() as u64);
    for (&number, entry) in entries {
        put_varint(&mut body, number);
        put_kek_id(&mut body, &entry.wrapped.kek_id);
        put_varint(&mut body, entry.wrapped.bytes.len() as u64);
        body.extend_from_slice(&entry.wrapped.bytes);
    }
    let mut sealed = Vec::with_capacity(body.len() + super::TAG_LEN);
    sealed.extend_from_slice(&body);
    body.zeroize();
    // Single-use key (module docs): the fixed nonce cannot repeat under it.
    seal(
        &registry_key.aead(),
        [0u8; NONCE_LEN],
        &out[..header_len],
        &mut sealed,
        0,
    )?;
    let sealed_len = u32::try_from(sealed.len())
        .map_err(|_| StorageError::InvalidArgument("DEK registry too large".into()))?;
    out.extend_from_slice(&sealed_len.to_le_bytes());
    out.extend_from_slice(&sealed);
    let sum = checksum(&out);
    out.extend_from_slice(&sum.to_le_bytes());
    Ok(out)
}

fn decode(data: &[u8], provider: &dyn KekProvider) -> Result<Contents> {
    let corrupt = |what: &str| StorageError::corruption(format!("DEK registry: {what}"));
    let Some(body_end) = data.len().checked_sub(CHECKSUM_LEN) else {
        return Err(corrupt("truncated"));
    };
    let stored = Reader::new(&data[body_end..])
        .u64()
        .ok_or_else(|| corrupt("truncated"))?;
    if stored != checksum(&data[..body_end]) {
        return Err(corrupt("checksum mismatch"));
    }
    let mut r = Reader::new(&data[..body_end]);
    if r.bytes(MAGIC.len()) != Some(&MAGIC[..]) {
        return Err(corrupt("bad magic"));
    }
    let version = match r.u32() {
        Some(v @ (FORMAT_VERSION_V1 | FORMAT_VERSION)) => v,
        Some(v) => return Err(corrupt(&format!("unsupported format version {v}"))),
        None => return Err(corrupt("truncated")),
    };
    let kek_id = get_kek_id(&mut r).ok_or_else(|| corrupt("bad KEK id"))?;
    let wrapped_len = r.u32().ok_or_else(|| corrupt("truncated"))?;
    if u64::from(wrapped_len) > MAX_WRAPPED_LEN {
        return Err(corrupt("oversized wrapped key"));
    }
    let wrapped = r
        .bytes(wrapped_len as usize)
        .ok_or_else(|| corrupt("truncated"))?
        .to_vec();
    let header_len = body_end - r.remaining();
    if &kek_id != provider.key_id() {
        return Err(StorageError::key_unavailable(format!(
            "DEK registry was written under KEK {kek_id}, but the configured KEK is {}",
            provider.key_id()
        )));
    }
    let registry_key = provider.unwrap(&WrappedKey {
        kek_id,
        bytes: wrapped,
    })?;
    let sealed_len = r.u32().ok_or_else(|| corrupt("truncated"))?;
    let mut body = r
        .bytes(sealed_len as usize)
        .ok_or_else(|| corrupt("truncated"))?
        .to_vec();
    if !r.is_empty() {
        return Err(corrupt("trailing bytes"));
    }
    open(
        &registry_key.aead(),
        [0u8; NONCE_LEN],
        &data[..header_len],
        &mut body,
    )
    .map_err(|()| corrupt("authentication failed"))?;
    let contents = decode_body(&body, version).ok_or_else(|| corrupt("malformed body"));
    body.zeroize();
    contents
}

fn decode_body(body: &[u8], version: u32) -> Option<Contents> {
    let mut r = Reader::new(body);
    let plaintext_manifest = if version == FORMAT_VERSION_V1 {
        None
    } else {
        match r.u8()? {
            0 => None,
            1 => Some(r.varint()?),
            _ => return None,
        }
    };
    let count = r.varint()?;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let number = r.varint()?;
        let kek_id = get_kek_id(&mut r)?;
        let len = r.varint()?;
        if len > MAX_WRAPPED_LEN {
            return None;
        }
        let bytes = r.bytes(usize::try_from(len).ok()?)?.to_vec();
        let entry = Entry {
            wrapped: WrappedKey { kek_id, bytes },
            cipher: OnceLock::new(),
        };
        if entries.insert(number, Arc::new(entry)).is_some() {
            return None;
        }
    }
    r.is_empty().then_some(Contents {
        entries,
        plaintext_manifest,
    })
}

#[cfg(test)]
mod tests {
    use rustegon_sim_api::StdFileSystem;

    use super::*;
    use crate::encryption::{FileKekProvider, tests::TestRng};

    fn provider(seed: u8) -> Arc<dyn KekProvider> {
        Arc::new(FileKekProvider::from_key(SecretKey::from_bytes([seed; 32])))
    }

    fn manager(dir: &Path, kek: u8) -> Result<KeyManager> {
        KeyManager::open(
            Arc::new(StdFileSystem),
            dir,
            provider(kek),
            Arc::new(TestRng::default()),
        )
    }

    #[test]
    fn registry_round_trips_and_caches_ciphers() {
        let dir = tempfile::tempdir().unwrap();
        let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
        let rng = Arc::new(TestRng::default());
        let km = KeyManager::create(Arc::clone(&fs), dir.path(), provider(1), rng).unwrap();
        assert!(km.file_cipher(5).unwrap().is_none());
        let c5 = km.new_file_cipher(5).unwrap();
        let c9 = km.new_file_cipher(9).unwrap();
        assert!(km.new_file_cipher(5).is_err(), "duplicate DEK accepted");
        let mut sealed = b"block".to_vec();
        c5.seal_in_place(0, b"", &mut sealed, 0).unwrap();
        assert!(Arc::ptr_eq(&km.file_cipher(5).unwrap().unwrap(), &c5));
        assert!(format!("{km:?}").contains("files: 2"));

        let reopened = manager(dir.path(), 1).unwrap();
        assert_eq!(reopened.file_numbers(), [5, 9]);
        let r5 = reopened.file_cipher(5).unwrap().unwrap();
        let mut copy = sealed.clone();
        r5.open_in_place(0, b"", &mut copy).unwrap();
        assert_eq!(copy, b"block");
        // Distinct files get distinct DEKs: file 9's DEK cannot open file 5's data even with
        // file 5's nonces.
        let dek9 = reopened
            .provider
            .unwrap(&reopened.snapshot()[&9].wrapped)
            .unwrap();
        let mut copy = sealed.clone();
        assert!(
            FileCipher::new(5, &dek9)
                .open_in_place(0, b"", &mut copy)
                .is_err()
        );
        assert_eq!(c9.file_number(), 9);

        reopened.forget(&[5, 77]).unwrap();
        reopened.forget(&[77]).unwrap();
        assert_eq!(manager(dir.path(), 1).unwrap().file_numbers(), [9]);
        assert!(KeyManager::exists(fs.as_ref(), dir.path()).unwrap());
        assert!(
            KeyManager::create(fs, dir.path(), provider(1), Arc::new(TestRng::default())).is_err()
        );
    }

    /// FR-BKP-003 (checkpoints of encrypted stores, §10): the export holds exactly the requested
    /// DEKs that exist, opens with the same KEK only, and its keys decrypt the source's data.
    #[test]
    fn tc_bkp_005_export_subset_copies_exactly_the_requested_deks() {
        let root = tempfile::tempdir().unwrap();
        let (src_dir, dst_dir) = (root.path().join("src"), root.path().join("dst"));
        let km = KeyManager::create(
            Arc::new(StdFileSystem),
            &src_dir,
            provider(1),
            Arc::new(TestRng::default()),
        )
        .unwrap();
        let c4 = km.new_file_cipher(4).unwrap();
        for n in [5, 6] {
            km.new_file_cipher(n).unwrap();
        }
        let mut sealed = b"block".to_vec();
        c4.seal_in_place(0, b"", &mut sealed, 0).unwrap();

        // 9 has no DEK (a plaintext file): skipped, not an error.
        let exported = km.export_subset(&dst_dir, &[4, 6, 9]).unwrap();
        assert_eq!(exported.file_numbers(), [4, 6]);
        assert!(
            km.export_subset(&dst_dir, &[4]).is_err(),
            "overwrote a registry"
        );
        assert!(
            km.export_subset(&src_dir, &[4]).is_err(),
            "exported onto itself"
        );
        // The source is untouched.
        assert_eq!(manager(&src_dir, 1).unwrap().file_numbers(), [4, 5, 6]);

        let reopened = manager(&dst_dir, 1).unwrap();
        assert_eq!(reopened.file_numbers(), [4, 6]);
        assert_eq!(reopened.admitted_plaintext_manifest(), None);
        let mut copy = sealed.clone();
        reopened
            .file_cipher(4)
            .unwrap()
            .unwrap()
            .open_in_place(0, b"", &mut copy)
            .unwrap();
        assert_eq!(copy, b"block");
        let err = manager(&dst_dir, 2).unwrap_err();
        assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");
    }

    #[test]
    fn wrong_or_missing_kek_and_missing_registry_are_key_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let km = KeyManager::create(
            Arc::new(StdFileSystem),
            dir.path(),
            provider(1),
            Arc::new(TestRng::default()),
        )
        .unwrap();
        km.new_file_cipher(3).unwrap();
        let err = manager(dir.path(), 2).unwrap_err();
        assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");
        assert!(err.to_string().contains("written under KEK"), "{err}");
        let empty = tempfile::tempdir().unwrap();
        let err = manager(empty.path(), 1).unwrap_err();
        assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");
        assert!(!KeyManager::exists(&StdFileSystem, empty.path()).unwrap());
    }

    #[test]
    fn damaged_registry_is_corruption_at_every_byte() {
        let rng = TestRng::default();
        let mut entries = BTreeMap::new();
        let p = provider(1);
        for n in [2u64, 3, 40] {
            let dek = SecretKey::generate(&rng);
            entries.insert(
                n,
                Arc::new(Entry {
                    wrapped: p.wrap(&dek, &rng).unwrap(),
                    cipher: OnceLock::new(),
                }),
            );
        }
        let data = encode(&entries, Some(9), p.as_ref(), &rng).unwrap();
        let contents = decode(&data, p.as_ref()).unwrap();
        assert_eq!(
            (contents.entries.len(), contents.plaintext_manifest),
            (3, Some(9))
        );
        for at in 0..data.len() {
            let mut bad = data.clone();
            bad[at] ^= 0x04;
            let err = decode(&bad, p.as_ref()).unwrap_err();
            assert!(err.is_corruption(), "flip at {at}: {err}");
        }
        for cut in 0..data.len() {
            assert!(decode(&data[..cut], p.as_ref()).is_err(), "cut {cut}");
        }
    }

    /// A body tampered with a valid checksum (as an attacker could forge) fails the GCM tag;
    /// malformed bodies and duplicate entries are rejected by the body parser.
    #[test]
    fn forged_checksum_still_fails_authentication_and_body_checks() {
        let rng = TestRng::default();
        let p = provider(1);
        let data = encode(&BTreeMap::new(), None, p.as_ref(), &rng).unwrap();
        let mut forged = data[..data.len() - CHECKSUM_LEN].to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let sum = checksum(&forged);
        forged.extend_from_slice(&sum.to_le_bytes());
        let err = decode(&forged, p.as_ref()).unwrap_err();
        assert!(err.to_string().contains("authentication failed"), "{err}");

        let mut dup = Vec::new();
        put_varint(&mut dup, 2);
        for _ in 0..2 {
            put_varint(&mut dup, 7);
            put_kek_id(&mut dup, p.key_id());
            put_varint(&mut dup, 1);
            dup.push(0);
        }
        assert!(decode_body(&dup, FORMAT_VERSION_V1).is_none());
        assert!(decode_body(&[1], FORMAT_VERSION_V1).is_none());
        let mut oversized = Vec::new();
        put_varint(&mut oversized, 1);
        put_varint(&mut oversized, 7);
        put_kek_id(&mut oversized, p.key_id());
        put_varint(&mut oversized, MAX_WRAPPED_LEN + 1);
        assert!(decode_body(&oversized, FORMAT_VERSION_V1).is_none());
        // v2 bodies start with the admission: absent, present, or an invalid flag byte.
        let v2 = |body: &[u8]| decode_body(body, FORMAT_VERSION).map(|c| c.plaintext_manifest);
        assert_eq!(v2(&[0, 0]), Some(None));
        assert_eq!(v2(&[1, 5, 0]), Some(Some(5)));
        assert_eq!(v2(&[2, 5, 0]), None);
        // A v1 body read as v2 (or the reverse) does not parse as the other version's layout.
        assert!(decode_body(&[0], FORMAT_VERSION).is_none());
    }
}
