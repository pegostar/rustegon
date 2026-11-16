// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `[storage]` configuration section (implementation-rules.md §5, coding-standards.md §3.7).
//! Fields are added by the M1 task that introduces each tunable.

use std::{path::Path, sync::Arc};

use rustegon_common::settings::{FieldSpec, Kind, Mutability, Sensitivity, Settings};
use rustegon_sim_api::FileSystem;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    cache::{BlockCache, ENTRY_OVERHEAD, SHARD_COUNT},
    encryption::{FileKekProvider, KekProvider},
    error::Result,
    sst::{
        DEFAULT_BLOCK_SIZE, DEFAULT_BOTTOMMOST_ZSTD_LEVEL, DEFAULT_INDEX_PARTITION_SIZE,
        MAX_ZSTD_LEVEL, MIN_ZSTD_LEVEL, SstWriterOptions,
    },
};

/// Smallest accepted data block size: below 1 KiB the per-block trailer and index entry dominate.
const MIN_BLOCK_SIZE: i64 = 1 << 10;
/// Largest accepted data block size: beyond 4 MiB a point read decodes far more than it needs.
const MAX_BLOCK_SIZE: i64 = 4 << 20;

/// Default block cache size: 512 MiB, a conservative share of the 64 GiB reference node that
/// leaves memory for memtables, the OS page cache and the query layer.
pub const DEFAULT_BLOCK_CACHE_SIZE: u64 = 512 << 20;
/// Largest accepted block cache size: 1 TiB, beyond any supported node.
const MAX_BLOCK_CACHE_SIZE: i64 = 1 << 40;
/// Largest data block the cache validation plans for, as a multiple of `block_size`: the SST
/// writer cuts a block only once it reaches `block_size`, so the last entry can push it past
/// the target; 2x covers entries up to one block in size.
const BLOCK_OVERSHOOT_FACTOR: u64 = 2;

/// Default memtable size: 64 MiB (storage-engine.md §3).
pub const DEFAULT_MEMTABLE_SIZE: u64 = 64 << 20;
/// Smallest accepted memtable: 1 MiB; below it flushes and L0 files dominate the work.
const MIN_MEMTABLE_SIZE: i64 = 1 << 20;
/// Largest accepted memtable: 4 GiB; beyond it Raft replay after a crash exceeds the 60 s
/// recovery target (§9, bounded by `raft.max_unflushed_log_bytes` anyway).
const MAX_MEMTABLE_SIZE: i64 = 4 << 30;
/// `storage.encryption` value: files are written in plaintext.
pub const ENCRYPTION_NONE: &str = "none";
/// `storage.encryption` value: AES-256-GCM with per-file DEKs (storage-engine.md §7).
pub const ENCRYPTION_AES_256_GCM: &str = "aes-256-gcm";
/// `storage.encryption_key_provider` value: the KEK is read from `encryption_key_file`.
pub const KEY_PROVIDER_FILE: &str = "file";
/// `storage.encryption_key_provider` value: the KEK is read (base64) from the environment
/// variable named by `encryption_key_env`.
pub const KEY_PROVIDER_ENV: &str = "env";
/// Default `storage.encryption_key_env`. One underscore after `RUSTEGON`, so the settings
/// loader (which reads `RUSTEGON__SECTION__KEY`) never treats the key as a setting.
pub const DEFAULT_KEY_ENV: &str = "RUSTEGON_KEK";
/// Settings-layer prefix a KEK variable must not use (rustegon-common `ENV_PREFIX`).
const SETTINGS_ENV_PREFIX: &str = "RUSTEGON__";

/// Storage engine settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageSettings {
    /// Target uncompressed SST data block size in bytes (storage-engine.md §4).
    pub block_size: u64,
    /// Zstd level for files written to the bottommost LSM level (storage-engine.md §6); passed
    /// to `CompressionPolicy::for_level` by compaction.
    pub bottommost_zstd_level: i32,
    /// Block cache capacity in bytes; 0 disables the cache (storage-engine.md §5). A non-zero
    /// value must be at least 64 x (2 x max(`block_size`, 4 KiB index partition) + 96), so each
    /// of the 64 shards can hold a data block or index partition that overshoots its target
    /// size, plus its bookkeeping charge.
    pub block_cache_size: u64,
    /// Active memtable size in bytes that triggers rotation and flush (storage-engine.md §3).
    pub memtable_size: u64,
    /// Encryption at rest of SSTs and MANIFESTs (storage-engine.md §7): `none` (default) or
    /// `aes-256-gcm`, which requires `encryption_key_file`.
    pub encryption: String,
    /// Path of the 32-byte KEK file of the `file` provider (security.md §6); referenced by
    /// path, never inlined. Required by `aes-256-gcm` with the `file` provider, refused
    /// otherwise.
    pub encryption_key_file: String,
    /// KEK provider (security.md §6, FR-EAR-002): `file` (default) or `env`; KMS providers
    /// arrive with M13.
    pub encryption_key_provider: String,
    /// Name of the environment variable holding the base64 KEK of the `env` provider; the
    /// value itself never enters the configuration.
    pub encryption_key_env: String,
}

impl Default for StorageSettings {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE as u64,
            bottommost_zstd_level: DEFAULT_BOTTOMMOST_ZSTD_LEVEL,
            block_cache_size: DEFAULT_BLOCK_CACHE_SIZE,
            memtable_size: DEFAULT_MEMTABLE_SIZE,
            encryption: ENCRYPTION_NONE.to_owned(),
            encryption_key_file: String::new(),
            encryption_key_provider: KEY_PROVIDER_FILE.to_owned(),
            encryption_key_env: DEFAULT_KEY_ENV.to_owned(),
        }
    }
}

impl Settings for StorageSettings {
    const SECTION: &'static str = "storage";
    const FIELDS: &'static [FieldSpec] = &[
        FieldSpec {
            name: "block_size",
            kind: Kind::Integer {
                min: MIN_BLOCK_SIZE,
                max: MAX_BLOCK_SIZE,
            },
            // New files would pick a change up, but the engine reads it once at open.
            mutability: Mutability::Static,
            sensitivity: Sensitivity::Public,
            doc: "Target uncompressed SST data block size in bytes.",
        },
        FieldSpec {
            name: "bottommost_zstd_level",
            kind: Kind::Integer {
                min: MIN_ZSTD_LEVEL as i64,
                max: MAX_ZSTD_LEVEL as i64,
            },
            // Read when compaction picks writer options; existing files keep their codec.
            mutability: Mutability::Static,
            sensitivity: Sensitivity::Public,
            doc: "Zstd compression level (1..19) for SST data blocks on the bottommost LSM level.",
        },
        FieldSpec {
            name: "block_cache_size",
            kind: Kind::Integer {
                min: 0,
                max: MAX_BLOCK_CACHE_SIZE,
            },
            // The cache is created once at engine open; resizing live is not supported.
            mutability: Mutability::Static,
            sensitivity: Sensitivity::Public,
            doc: "Block cache capacity in bytes (0 disables the cache); otherwise at least \
                  64 * (2 * max(block_size, 4096) + 96).",
        },
        FieldSpec {
            name: "memtable_size",
            kind: Kind::Integer {
                min: MIN_MEMTABLE_SIZE,
                max: MAX_MEMTABLE_SIZE,
            },
            // Read when the engine opens.
            mutability: Mutability::Static,
            sensitivity: Sensitivity::Public,
            doc: "Memtable size in bytes that triggers a flush to an L0 SST.",
        },
        FieldSpec {
            name: "encryption",
            kind: Kind::Enum(&[ENCRYPTION_NONE, ENCRYPTION_AES_256_GCM]),
            // Decides how new files are written; the KEK is unwrapped once at open.
            mutability: Mutability::Static,
            sensitivity: Sensitivity::Public,
            doc: "Encryption at rest of SST and MANIFEST files: none or aes-256-gcm \
                  (requires encryption_key_file).",
        },
        FieldSpec {
            name: "encryption_key_file",
            kind: Kind::Path,
            // Read once at open (the KEK is kept in memory).
            mutability: Mutability::Static,
            // The path is not the secret; the file's contents are, and are never loaded into
            // the configuration.
            sensitivity: Sensitivity::Public,
            doc: "Path of the 32-byte key-encryption key file (32 raw bytes or 64 hex digits, \
                  owner-only) used when encryption = aes-256-gcm and the provider is file.",
        },
        FieldSpec {
            name: "encryption_key_provider",
            kind: Kind::Enum(&[KEY_PROVIDER_FILE, KEY_PROVIDER_ENV]),
            // The KEK is obtained once at open.
            mutability: Mutability::Static,
            sensitivity: Sensitivity::Public,
            doc: "Source of the key-encryption key: file (encryption_key_file) or env \
                  (base64 in the variable named by encryption_key_env).",
        },
        FieldSpec {
            name: "encryption_key_env",
            kind: Kind::String,
            // Read once at open.
            mutability: Mutability::Static,
            // A variable name, not the key: the value is read from the process environment and
            // never stored in the configuration.
            sensitivity: Sensitivity::Public,
            doc: "Environment variable holding the base64 key-encryption key when \
                  encryption_key_provider = env.",
        },
    ];

    fn validate(&self) -> std::result::Result<(), String> {
        // Secure defaults (security.md §1): encryption never silently runs without a key, and
        // a key file next to `none` is a misconfiguration that would leave data in plaintext.
        // The same holds for an explicit `env` provider next to `none`; a key file next to the
        // `env` provider is ambiguous (which key protects the store?).
        match (
            self.encryption.as_str(),
            self.encryption_key_provider.as_str(),
            self.encryption_key_file.is_empty(),
        ) {
            (ENCRYPTION_AES_256_GCM, KEY_PROVIDER_FILE, true) => {
                return Err(
                    "encryption = aes-256-gcm requires storage.encryption_key_file".to_owned(),
                );
            }
            (ENCRYPTION_NONE, _, false) => {
                return Err("storage.encryption_key_file is set but encryption = none; \
                            set encryption = aes-256-gcm or remove the key file"
                    .to_owned());
            }
            (ENCRYPTION_NONE, KEY_PROVIDER_ENV, _) => {
                return Err(
                    "storage.encryption_key_provider = env but encryption = none; \
                            set encryption = aes-256-gcm or remove the provider"
                        .to_owned(),
                );
            }
            (_, KEY_PROVIDER_ENV, false) => {
                return Err(
                    "storage.encryption_key_file is only used by the file provider; \
                            remove it or set encryption_key_provider = file"
                        .to_owned(),
                );
            }
            _ => {}
        }
        validate_env_name(&self.encryption_key_env)?;
        // Each of the cache's shards gets 1/SHARD_COUNT of the capacity and refuses entries
        // charged above that (block bytes + ENTRY_OVERHEAD), so a smaller non-zero cache would
        // silently cache no data block: reject it at load (fail fast) rather than run with a
        // cache that only costs memory. Index partitions are cached too and have their own
        // (fixed) target size, so plan for the larger target. The writer cuts a block once it
        // reaches its target, so a block overshoots by its last entry; BLOCK_OVERSHOOT_FACTOR
        // leaves room for that.
        let max_charge = self
            .block_size
            .max(DEFAULT_INDEX_PARTITION_SIZE as u64)
            .saturating_mul(BLOCK_OVERSHOOT_FACTOR)
            .saturating_add(ENTRY_OVERHEAD as u64);
        let min_cache = (SHARD_COUNT as u64).saturating_mul(max_charge);
        if self.block_cache_size != 0 && self.block_cache_size < min_cache {
            return Err(format!(
                "block_cache_size ({}) must be 0 (disabled) or at least {SHARD_COUNT} * \
                 ({BLOCK_OVERSHOOT_FACTOR} * max(block_size, {DEFAULT_INDEX_PARTITION_SIZE}) + \
                 {ENTRY_OVERHEAD}) = {min_cache} \
                 bytes, so every cache shard can hold a block",
                self.block_cache_size
            ));
        }
        Ok(())
    }
}

/// A portable environment variable name (`[A-Za-z_][A-Za-z0-9_]*`, at most 255 bytes) outside
/// the settings layer's `RUSTEGON__` namespace.
fn validate_env_name(name: &str) -> std::result::Result<(), String> {
    let mut chars = name.chars();
    let portable = name.len() <= 255
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !portable {
        return Err(
            "storage.encryption_key_env must be an environment variable name \
                    ([A-Za-z_][A-Za-z0-9_]*, at most 255 characters)"
                .to_owned(),
        );
    }
    if name.starts_with(SETTINGS_ENV_PREFIX) {
        return Err(format!(
            "storage.encryption_key_env must not start with {SETTINGS_ENV_PREFIX} (reserved \
             for settings)"
        ));
    }
    Ok(())
}

impl BlockCache {
    /// The shared block cache configured by `storage.block_cache_size`, or `None` when it is 0.
    #[must_use]
    pub fn from_settings(settings: &StorageSettings) -> Option<Arc<Self>> {
        // Saturates only on 32-bit targets, where 1 TiB cannot be addressed anyway.
        let size = usize::try_from(settings.block_cache_size).unwrap_or(usize::MAX);
        (size > 0).then(|| Arc::new(Self::new(size)))
    }
}

impl StorageSettings {
    /// Whether encryption at rest is enabled.
    #[must_use]
    pub fn encryption_enabled(&self) -> bool {
        self.encryption == ENCRYPTION_AES_256_GCM
    }

    /// The KEK provider configured by `storage.encryption` and `storage.encryption_key_*`,
    /// or `None` when encryption is off. The engine passes it to `KeyManager::open` (recovery
    /// step "unwrap KEK / load DEK registry", storage-engine.md §9). For `env`, `env` looks up
    /// the variable: the caller decides where the environment comes from (the server's
    /// captured environment, a test map), and the text it returns is zeroized after use.
    ///
    /// # Errors
    /// [`crate::StorageError::KeyUnavailable`] if the key file or variable is missing,
    /// malformed or (Unix) accessible by others.
    pub fn kek_provider(
        &self,
        fs: &dyn FileSystem,
        env: &dyn Fn(&str) -> Option<Zeroizing<String>>,
    ) -> Result<Option<Arc<dyn KekProvider>>> {
        if !self.encryption_enabled() {
            return Ok(None);
        }
        let provider = if self.encryption_key_provider == KEY_PROVIDER_ENV {
            let value = env(&self.encryption_key_env);
            FileKekProvider::from_env_value(
                &self.encryption_key_env,
                value.as_deref().map(String::as_str),
            )?
        } else {
            FileKekProvider::open(fs, Path::new(&self.encryption_key_file))?
        };
        Ok(Some(Arc::new(provider)))
    }

    /// Whether the `env` provider is configured (the server then removes the variable's value
    /// from its captured environment once the KEK is read).
    #[must_use]
    pub fn kek_from_env(&self) -> bool {
        self.encryption_enabled() && self.encryption_key_provider == KEY_PROVIDER_ENV
    }
}

impl SstWriterOptions {
    /// Writer options derived from the configuration; other fields keep their defaults.
    #[must_use]
    pub fn from_settings(settings: &StorageSettings) -> Self {
        Self {
            // Lossless: the setting is range-checked to at most 4 MiB on load.
            block_size: usize::try_from(settings.block_size).unwrap_or(DEFAULT_BLOCK_SIZE),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use rustegon_common::settings::{Registry, Sources};

    use super::*;

    #[test]
    fn storage_settings_load_with_range_check() {
        let mut registry = Registry::new();
        registry.register::<StorageSettings>().unwrap();
        let config = registry.load(&Sources::default()).unwrap();
        let settings: StorageSettings = config.section().unwrap();
        assert_eq!(settings, StorageSettings::default());
        assert_eq!(
            SstWriterOptions::from_settings(&settings).block_size,
            DEFAULT_BLOCK_SIZE
        );

        let sources = Sources {
            flags: vec!["storage.block_size=512".into()],
            ..Sources::default()
        };
        let err = registry.load(&sources).unwrap_err();
        assert!(err.message().contains("storage.block_size"), "{err}");

        let sources = Sources {
            flags: vec!["storage.bottommost_zstd_level=20".into()],
            ..Sources::default()
        };
        let err = registry.load(&sources).unwrap_err();
        assert!(err.message().contains("bottommost_zstd_level"), "{err}");
        let cache = BlockCache::from_settings(&settings).unwrap();
        assert_eq!(cache.capacity() as u64, DEFAULT_BLOCK_CACHE_SIZE);
        let off = StorageSettings {
            block_cache_size: 0,
            ..settings
        };
        assert!(BlockCache::from_settings(&off).is_none());
    }

    /// A non-zero cache too small to give each shard room for one block is a load error;
    /// 0 (disabled) and exactly 64 blocks are accepted.
    #[test]
    fn block_cache_size_must_fit_a_block_per_shard() {
        let mut registry = Registry::new();
        registry.register::<StorageSettings>().unwrap();
        let load = |flags: &[&str]| {
            registry.load(&Sources {
                flags: flags.iter().map(|f| (*f).to_owned()).collect(),
                ..Sources::default()
            })
        };
        // 64 * (2 * 4096 + 96) = 530_432; block_size 1024 is below the 4 KiB index partition
        // target, which then sets the minimum.
        assert!(load(&["storage.block_size=1024", "storage.block_cache_size=530431"]).is_err());
        let err =
            load(&["storage.block_size=4096", "storage.block_cache_size=530431"]).unwrap_err();
        assert!(err.message().contains("block_cache_size"), "{err}");
        assert!(load(&["storage.block_size=4096", "storage.block_cache_size=530432"]).is_ok());
        assert!(load(&["storage.block_cache_size=0"]).is_ok());
    }

    /// `storage.encryption` defaults to none; aes-256-gcm needs a key file, none refuses one,
    /// unknown modes are rejected; the provider is built from the key file.
    #[test]
    fn encryption_settings_require_a_key_and_build_the_provider() {
        let mut registry = Registry::new();
        registry.register::<StorageSettings>().unwrap();
        let load = |flags: &[&str]| {
            registry.load(&Sources {
                flags: flags.iter().map(|f| (*f).to_owned()).collect(),
                ..Sources::default()
            })
        };
        let no_env = |_: &str| None;
        let defaults = StorageSettings::default();
        assert!(!defaults.encryption_enabled());
        assert!(
            defaults
                .kek_provider(&rustegon_sim_api::StdFileSystem, &no_env)
                .unwrap()
                .is_none()
        );
        let err = load(&["storage.encryption=aes-256-gcm"]).unwrap_err();
        assert!(err.message().contains("encryption_key_file"), "{err}");
        let err = load(&["storage.encryption_key_file=/k"]).unwrap_err();
        assert!(err.message().contains("encryption = none"), "{err}");
        assert!(load(&["storage.encryption=aes-128"]).is_err());
        // PD-057: env provider rules.
        let err = load(&["storage.encryption_key_provider=env"]).unwrap_err();
        assert!(err.message().contains("encryption = none"), "{err}");
        let err = load(&[
            "storage.encryption=aes-256-gcm",
            "storage.encryption_key_provider=env",
            "storage.encryption_key_file=/k",
        ])
        .unwrap_err();
        assert!(
            err.message().contains("only used by the file provider"),
            "{err}"
        );
        for bad in ["1KEK", "MY-KEK", "", "RUSTEGON__STORAGE__KEK"] {
            let flag = format!("storage.encryption_key_env={bad}");
            assert!(
                load(&[
                    "storage.encryption=aes-256-gcm",
                    "storage.encryption_key_provider=env",
                    &flag
                ])
                .is_err(),
                "{bad:?}"
            );
        }
        assert!(load(&["storage.encryption_key_provider=kms"]).is_err());

        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("kek");
        rustegon_sim_api::StdFileSystem
            .create_new_private(&key)
            .and_then(|mut f| f.append(&[7u8; 32]))
            .unwrap();
        let key_flag = format!("storage.encryption_key_file={}", key.display());
        let config = load(&["storage.encryption=aes-256-gcm", &key_flag]).unwrap();
        let settings: StorageSettings = config.section().unwrap();
        assert!(settings.encryption_enabled());
        assert!(!settings.kek_from_env());
        let provider = settings
            .kek_provider(&rustegon_sim_api::StdFileSystem, &no_env)
            .unwrap()
            .unwrap();
        assert!(provider.key_id().as_str().starts_with("file:"));

        // The env provider reads the named variable through the caller's lookup and yields the
        // same KEK id for the same key.
        let config = load(&[
            "storage.encryption=aes-256-gcm",
            "storage.encryption_key_provider=env",
            "storage.encryption_key_env=APP_KEK",
        ])
        .unwrap();
        let env_settings: StorageSettings = config.section().unwrap();
        assert!(env_settings.kek_from_env());
        let lookup = |name: &str| {
            (name == "APP_KEK")
                .then(|| Zeroizing::new("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".to_owned()))
        };
        let from_env = env_settings
            .kek_provider(&rustegon_sim_api::StdFileSystem, &lookup)
            .unwrap()
            .unwrap();
        assert_eq!(from_env.key_id(), provider.key_id());
        let err = env_settings
            .kek_provider(&rustegon_sim_api::StdFileSystem, &no_env)
            .err()
            .unwrap();
        assert!(err.to_string().contains("APP_KEK"), "{err}");

        let missing = StorageSettings {
            encryption_key_file: dir.path().join("absent").display().to_string(),
            ..settings
        };
        let err = missing
            .kek_provider(&rustegon_sim_api::StdFileSystem, &no_env)
            .err()
            .unwrap();
        assert!(
            matches!(err, crate::StorageError::KeyUnavailable(_)),
            "{err}"
        );
    }
}
