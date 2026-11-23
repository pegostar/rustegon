// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Runtime settings for `AdminService.GetSettings` / `UpdateSettings` (protocol.md §3 "settings
//! travel as TOML text per key", PD-045; persistence PD-051).
//!
//! - The node's configuration is the settings registry's layered load (defaults < file < env <
//!   flags, `rustegon_common::settings`). Values changed through `UpdateSettings` are
//!   **runtime overrides**: they are persisted in the system keyspace and applied as the
//!   highest-precedence layer, so a runtime change wins over the startup files (otherwise an
//!   update of a key also set in `rustegon.toml` would silently do nothing).
//! - Settings declared [`Mutability::Dynamic`] are runtime overrides. An update is validated as a
//!   whole by the registry (types, ranges, cross-field rules, inline-secret rule) and applied
//!   atomically: all keys or none.
//! - **Static settings** (PD-230) are written into the node's configuration file
//!   ([`RuntimeSettings::with_config_file`], `rustegon.toml`) and take effect when the node
//!   restarts; until then [`SettingInfo::pending_value`] shows them. The file is edited in place
//!   (`toml_edit`: comments and layout kept), the whole new file is validated with the node's
//!   environment and flags before it replaces the old one (temporary file + rename), and a value
//!   equal to the default removes the key. A static setting is [`Locked`] (`RGN-1001` on update)
//!   when the node has no writable configuration file, when an environment variable or a `--set`
//!   flag sets it (they win over the file), or when changing it needs files moved or re-encrypted
//!   (`node.data_dir`, the store encryption settings).
//! - Values are TOML text: `600000`, `true`, `"text"`. Secrets (`FieldSpec::is_secret`) are
//!   returned as the redaction marker and cannot be set inline (the registry refuses inline
//!   secrets; they are referenced by path).
//!
//! **Setting override record format 1** (*Provisional (PD-051)*; fixture
//! `crates/rustegon-server/tests/fixtures/formats/setting/1/`):
//! ```text
//! key    0x02 'g' <section>.<key> (ASCII)
//! value  { setting_format: 1, type: "setting", name, value: <TOML text>, updated_at: datetime }
//! ```
//! The sub-namespace byte `'g'` is taken next to the catalog's `d n s i b t` and security's
//! `u k e r`; names are ASCII without NUL, so no key is a strict prefix of another followed by
//! `0x00`.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, PoisonError, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustegon_catalog::{CatalogRead, Mutation};
use rustegon_common::{
    Error, ErrorCode,
    settings::{Config, ENV_PREFIX, FieldSpec, Kind, Mutability, Registry, Sources},
};
use rustegon_doc::{Document, Value, keyspace::NS_SYSTEM, rdoc};
use rustegon_security::{
    audit::AuditSettings, authn::AuthnSettings, lockout::LockoutSettings,
    ratelimit::RateLimitSettings,
};
use rustegon_sim_api::{FileSystem, OpenMode};

/// Sub-namespace byte of setting override records.
pub const SUB_SETTING: u8 = b'g';
/// Version of the setting override record format.
pub const SETTING_FORMAT: i64 = 1;
/// Longest accepted TOML text of one value.
pub const MAX_VALUE_LEN: usize = 4096;
const TYPE: &str = "setting";
const FIELDS: &[&str] = &["setting_format", "type", "name", "value", "updated_at"];

/// Registers the settings sections of the security layer: `[auth]`, `[audit]`, `[rate_limit]`,
/// `[lockout]` (for `rustegond`, wave 2c, and tests).
///
/// # Errors
/// A section registered twice.
pub fn register_security_settings(registry: &mut Registry) -> Result<(), Error> {
    registry
        .register::<AuthnSettings>()?
        .register::<AuditSettings>()?
        .register::<RateLimitSettings>()?
        .register::<LockoutSettings>()?;
    Ok(())
}

/// Key of the override record of `name` (`section.key`).
#[must_use]
pub fn setting_key(name: &str) -> Vec<u8> {
    let mut k = setting_prefix();
    k.extend_from_slice(name.as_bytes());
    k
}

/// Prefix of every setting override record.
#[must_use]
pub fn setting_prefix() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_SETTING]
}

fn corrupt(msg: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::StorageCorruption,
        format!("setting record: {msg}"),
    )
}

fn millis(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// A persisted override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingRecord {
    /// `section.key`.
    pub name: String,
    /// TOML text of the value.
    pub value: String,
    /// Time of the update (millisecond resolution).
    pub updated_at: SystemTime,
}

/// Encodes an override record (format 1).
///
/// # Errors
/// Encoding failures.
pub fn encode_setting(r: &SettingRecord) -> Result<Vec<u8>, Error> {
    let mut doc = Document::new();
    doc.insert("setting_format", Value::Int64(SETTING_FORMAT));
    doc.insert("type", Value::String(TYPE.to_owned()));
    doc.insert("name", Value::String(r.name.clone()));
    doc.insert("value", Value::String(r.value.clone()));
    doc.insert("updated_at", Value::DateTime(millis(r.updated_at)));
    Ok(rdoc::encode(&doc)?)
}

/// Decodes an override record (format 1, strict).
///
/// # Errors
/// `RGN-5002` for anything but a valid format-1 record.
pub fn decode_setting(bytes: &[u8]) -> Result<SettingRecord, Error> {
    let doc = rdoc::decode(bytes).map_err(corrupt)?;
    if let Some((n, _)) = doc.iter().find(|(n, _)| !FIELDS.contains(n)) {
        return Err(corrupt(format!("unknown field {n:?}")));
    }
    match doc.get("setting_format") {
        Some(Value::Int64(SETTING_FORMAT)) => {}
        _ => return Err(corrupt("unsupported or missing setting_format")),
    }
    let text = |name: &str| match doc.get(name) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(corrupt(format!("{name} missing or not a string"))),
    };
    if text("type")? != TYPE {
        return Err(corrupt("type is not \"setting\""));
    }
    let updated_at = match doc.get("updated_at") {
        Some(Value::DateTime(ms)) => u64::try_from(*ms)
            .ok()
            .and_then(|ms| UNIX_EPOCH.checked_add(Duration::from_millis(ms)))
            .ok_or_else(|| corrupt("updated_at < 0"))?,
        _ => return Err(corrupt("updated_at missing or not a datetime")),
    };
    Ok(SettingRecord {
        name: text("name")?,
        value: text("value")?,
        updated_at,
    })
}

/// Every persisted override, by name.
///
/// # Errors
/// Store errors; `RGN-5002`.
pub fn load_overrides(txn: &dyn CatalogRead) -> Result<BTreeMap<String, String>, Error> {
    let prefix = setting_prefix();
    let mut out = BTreeMap::new();
    for (key, value) in txn.scan_prefix(&prefix)? {
        let r = decode_setting(&value)?;
        if key[prefix.len()..] != *r.name.as_bytes() {
            return Err(corrupt(format!("{:?} stored under a foreign key", r.name)));
        }
        out.insert(r.name, r.value);
    }
    Ok(out)
}

/// The mutations persisting `values` (validated by [`RuntimeSettings::prepare`]).
///
/// # Errors
/// Encoding failures.
pub fn override_mutations(
    values: &BTreeMap<String, String>,
    now: SystemTime,
) -> Result<Vec<Mutation>, Error> {
    values
        .iter()
        .map(|(name, value)| {
            Ok(Mutation::Put {
                key: setting_key(name),
                value: encode_setting(&SettingRecord {
                    name: name.clone(),
                    value: value.clone(),
                    updated_at: now,
                })?,
            })
        })
        .collect()
}

/// One setting as reported by `GetSettings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingInfo {
    /// `section.key`.
    pub name: String,
    /// Current value as TOML text (secrets redacted).
    pub value: String,
    /// Default value as TOML text (secrets redacted).
    pub default_value: String,
    /// Changeable at runtime.
    pub runtime_mutable: bool,
    /// Documentation.
    pub description: String,
    /// Value type and range.
    pub kind: Kind,
    /// Why it cannot be changed through the API (`None`: it can).
    pub locked: Option<Locked>,
    /// A static setting's value in the configuration file when it differs from the running one:
    /// it takes effect at the next restart (module docs).
    pub pending_value: Option<String>,
}

/// Why a setting cannot be changed through `UpdateSettings` (module docs, PD-230).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locked {
    /// A secret: referenced by path in the configuration file, never set inline.
    Secret,
    /// A nested table: configuration file only.
    Table,
    /// Static, and the node has no configuration file it may write.
    NoConfigFile,
    /// Static, and an environment variable or a `--set` flag sets it.
    Environment,
    /// Static, and changing it needs files moved or re-encrypted.
    Manual,
}

impl Locked {
    /// Stable name for APIs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Table => "table",
            Self::NoConfigFile => "no_config_file",
            Self::Environment => "environment",
            Self::Manual => "manual",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Secret => "a secret is set by reference in the configuration file",
            Self::Table => "a table is set in the configuration file",
            Self::NoConfigFile => "the node has no configuration file it may write",
            Self::Environment => "an environment variable or a --set flag sets it",
            Self::Manual => "changing it needs files moved or re-encrypted; edit rustegon.toml",
        }
    }
}

/// Setting name → TOML text.
pub type Values = BTreeMap<String, String>;

/// Static settings never written through the API (module docs).
const MANUAL: &[&str] = &[
    "node.data_dir",
    "storage.encryption",
    "storage.encryption_key_provider",
    "storage.encryption_key_file",
    "storage.encryption_key_env",
];

fn invalid(name: &str, msg: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::InvalidArgument, format!("setting {name}: {msg}"))
        .with_detail("setting", name)
}

/// Converts a TOML value text into the registry's flag syntax, checking it fits `kind`.
fn flag_value(name: &str, kind: Kind, text: &str) -> Result<String, Error> {
    if text.len() > MAX_VALUE_LEN {
        return Err(invalid(name, "value too long"));
    }
    let table: toml::Table = toml::from_str(&format!("v = {text}"))
        .map_err(|_| invalid(name, "value is not a TOML value"))?;
    let value = table
        .get("v")
        .filter(|_| table.len() == 1)
        .ok_or_else(|| invalid(name, "value is not a single TOML value"))?;
    match (kind, value) {
        (Kind::Integer { .. }, toml::Value::Integer(i)) => Ok(i.to_string()),
        (Kind::Bool, toml::Value::Boolean(b)) => Ok(b.to_string()),
        (Kind::String | Kind::Path | Kind::Enum(_), toml::Value::String(s)) => Ok(s.clone()),
        _ => Err(invalid(name, "value has the wrong type")),
    }
}

fn flatten(config: &Config) -> Result<toml::Table, Error> {
    toml::from_str(&config.dump_redacted()?)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("settings dump: {e}")))
}

/// `text` and `other` are the same TOML value (paths dump as literal strings, for example).
fn same_value(text: &str, other: &str) -> bool {
    let parse = |t: &str| toml::from_str::<toml::Table>(&format!("v = {t}")).ok();
    match (parse(text), parse(other)) {
        (Some(a), Some(b)) => a == b,
        _ => text == other,
    }
}

fn value_text(table: &toml::Table, section: &str, key: &str) -> String {
    table
        .get(section)
        .and_then(|s| s.get(key))
        .map_or_else(String::new, ToString::to_string)
}

struct State {
    overrides: BTreeMap<String, String>,
    config: Config,
}

/// The node's effective configuration plus the runtime overrides (module docs).
pub struct RuntimeSettings {
    registry: Arc<Registry>,
    base: Sources,
    defaults: toml::Table,
    state: RwLock<State>,
    /// The configuration file static settings are written to (module docs).
    config_file: Option<PathBuf>,
    /// Its text as last read or written: differs from `base.file` once a static setting was
    /// changed and the node has not restarted yet.
    disk: RwLock<Option<String>>,
}

impl std::fmt::Debug for RuntimeSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeSettings").finish_non_exhaustive()
    }
}

impl RuntimeSettings {
    /// Loads the configuration from `base` plus the persisted `overrides`. An override that no
    /// longer validates (a setting removed or made static by an upgrade) is ignored with a
    /// warning rather than preventing the node from starting.
    ///
    /// # Errors
    /// `RGN-1001` when `base` itself does not load.
    pub fn open(
        registry: Arc<Registry>,
        base: Sources,
        overrides: BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        let defaults = flatten(&registry.load(&Sources::default())?)?;
        let mut usable = BTreeMap::new();
        for (name, value) in overrides {
            let mut one = BTreeMap::new();
            one.insert(name.clone(), value.clone());
            if Self::layered(&registry, &base, &usable, &one).is_ok() {
                usable.insert(name, value);
            } else {
                tracing::warn!(setting = %name, "ignoring a persisted setting override that no longer validates");
            }
        }
        let config = Self::layered(&registry, &base, &usable, &BTreeMap::new())?;
        let disk = RwLock::new(base.file.clone());
        Ok(Self {
            registry,
            base,
            defaults,
            state: RwLock::new(State {
                overrides: usable,
                config,
            }),
            config_file: None,
            disk,
        })
    }

    /// Lets static settings be changed by writing `path`, the configuration file the startup
    /// layer `base.file` was read from (module docs). `None`: static settings stay read-only.
    /// The file is read now (blocking): after a restart that fell back to the previous
    /// configuration it holds changes still pending.
    #[must_use]
    pub fn with_config_file(mut self, path: Option<PathBuf>, fs: &dyn FileSystem) -> Self {
        if let Some(text) = path.as_deref().and_then(|p| read_text(fs, p).ok()) {
            *self.disk.write().unwrap_or_else(PoisonError::into_inner) = Some(text);
        }
        self.config_file = path;
        self
    }

    fn locked(&self, section: &str, spec: &FieldSpec) -> Option<Locked> {
        if spec.is_secret() {
            return Some(Locked::Secret);
        }
        if spec.kind == Kind::Table {
            return Some(Locked::Table);
        }
        if spec.mutability == Mutability::Dynamic {
            return None;
        }
        let name = format!("{section}.{}", spec.name);
        if MANUAL.contains(&name.as_str()) {
            Some(Locked::Manual)
        } else if self.config_file.is_none() {
            Some(Locked::NoConfigFile)
        } else if self.externally_set(section, spec.name) {
            Some(Locked::Environment)
        } else {
            None
        }
    }

    /// An environment variable or a `--set` flag sets `section.key` (both win over the file).
    fn externally_set(&self, section: &str, key: &str) -> bool {
        let env = format!("{ENV_PREFIX}{section}__{key}");
        let name = format!("{section}.{key}");
        self.base
            .env
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(&env))
            || self
                .base
                .flags
                .iter()
                .any(|f| f.split_once('=').is_some_and(|(p, _)| p == name))
    }

    /// Splits an update into runtime overrides and static settings for the configuration file.
    ///
    /// # Errors
    /// `RGN-1030` for an unknown name, `RGN-1001` for a [`Locked`] one or an empty update.
    pub fn split(&self, values: &BTreeMap<String, String>) -> Result<(Values, Values), Error> {
        if values.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "no settings to update",
            ));
        }
        let (mut dynamic, mut stat) = (BTreeMap::new(), BTreeMap::new());
        for (name, value) in values {
            let (section, spec) = Self::spec(&self.registry, name)?;
            if let Some(locked) = self.locked(section, &spec) {
                return Err(
                    invalid(name, format!("cannot be changed here: {}", locked.reason()))
                        .with_detail("reason", locked.as_str()),
                );
            }
            if spec.mutability == Mutability::Dynamic {
                dynamic.insert(name.clone(), value.clone());
            } else {
                stat.insert(name.clone(), value.clone());
            }
        }
        Ok((dynamic, stat))
    }

    /// Writes static `values` (from [`Self::split`]) into the configuration file, all or
    /// nothing (module docs). Blocking: call it from a blocking thread.
    ///
    /// # Errors
    /// `RGN-1001` (malformed value, the new file does not validate, a value another layer
    /// overrides), `RGN-5001` for file errors.
    pub fn write_static(
        &self,
        fs: &dyn FileSystem,
        values: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        let path = self
            .config_file
            .as_deref()
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, Locked::NoConfigFile.reason()))?;
        // Read again: an operator may have edited the file since the node started.
        let current = read_text(fs, path)?;
        let mut doc: toml_edit::DocumentMut = current.parse().map_err(|e| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("{} is not valid TOML: {e}", path.display()),
            )
        })?;
        for (name, text) in values {
            let (section, spec) = Self::spec(&self.registry, name)?;
            if text.len() > MAX_VALUE_LEN {
                return Err(invalid(name, "value too long"));
            }
            if same_value(text, &value_text(&self.defaults, section, spec.name)) {
                if let Some(table) = doc.get_mut(section).and_then(|i| i.as_table_like_mut()) {
                    table.remove(spec.name);
                }
                continue;
            }
            let value: toml_edit::Value = text
                .parse()
                .map_err(|_| invalid(name, "value is not a TOML value"))?;
            let table = doc
                .entry(section)
                .or_insert(toml_edit::table())
                .as_table_like_mut()
                .ok_or_else(|| invalid(name, "its section is not a table in the file"))?;
            table.insert(spec.name, toml_edit::Item::Value(value));
        }
        let text = doc.to_string();
        // The node's other layers stay as they are: validate the file together with them.
        let config = self.registry.load(&Sources {
            file: Some(text.clone()),
            ..self.base.clone()
        })?;
        let loaded = flatten(&config)?;
        for (name, value) in values {
            let (section, spec) = Self::spec(&self.registry, name)?;
            if !same_value(value, &value_text(&loaded, section, spec.name)) {
                return Err(invalid(name, Locked::Environment.reason()));
            }
        }
        write_text(fs, path, &text)?;
        *self.disk.write().unwrap_or_else(PoisonError::into_inner) = Some(text);
        Ok(())
    }

    /// The configuration the node would start with now (`None`: unchanged or unreadable).
    fn pending_config(&self, overrides: &BTreeMap<String, String>) -> Option<toml::Table> {
        let disk = self
            .disk
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if disk == self.base.file {
            return None;
        }
        let sources = Sources {
            file: disk,
            ..self.base.clone()
        };
        let config = Self::layered(&self.registry, &sources, overrides, &BTreeMap::new()).ok()?;
        flatten(&config).ok()
    }

    fn spec(registry: &Registry, name: &str) -> Result<(&'static str, FieldSpec), Error> {
        let (section, key) = name
            .split_once('.')
            .ok_or_else(|| invalid(name, "expected <section>.<key>"))?;
        registry
            .specs()
            .find(|(s, f)| *s == section && f.name == key)
            .map(|(s, f)| (s, *f))
            .ok_or_else(|| {
                Error::new(ErrorCode::NotFound, format!("unknown setting {name}"))
                    .with_detail("setting", name)
            })
    }

    fn layered(
        registry: &Registry,
        base: &Sources,
        overrides: &BTreeMap<String, String>,
        extra: &BTreeMap<String, String>,
    ) -> Result<Config, Error> {
        let mut sources = base.clone();
        let mut merged = overrides.clone();
        merged.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
        for (name, text) in &merged {
            let (_, spec) = Self::spec(registry, name)?;
            if spec.mutability != Mutability::Dynamic {
                return Err(invalid(name, "not runtime-mutable (requires a restart)"));
            }
            sources
                .flags
                .push(format!("{name}={}", flag_value(name, spec.kind, text)?));
        }
        registry.load(&sources)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        // The state is replaced whole under the write lock; a poisoned lock still holds a
        // consistent previous state.
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The effective configuration.
    #[must_use]
    pub fn config(&self) -> Config {
        self.read().config.clone()
    }

    /// The settings named in `names` (all when empty), by name.
    ///
    /// # Errors
    /// `RGN-1030` for an unknown name.
    pub fn describe(&self, names: &[String]) -> Result<Vec<SettingInfo>, Error> {
        let (current, pending) = {
            let state = self.read();
            (
                flatten(&state.config)?,
                self.pending_config(&state.overrides),
            )
        };
        let wanted: Vec<(&'static str, FieldSpec)> = if names.is_empty() {
            self.registry.specs().map(|(s, f)| (s, *f)).collect()
        } else {
            names
                .iter()
                .map(|n| Self::spec(&self.registry, n))
                .collect::<Result<_, _>>()?
        };
        let mut out: Vec<SettingInfo> = wanted
            .into_iter()
            .map(|(section, spec)| {
                let value = value_text(&current, section, spec.name);
                let pending_value = pending
                    .as_ref()
                    .map(|p| value_text(p, section, spec.name))
                    .filter(|p| spec.mutability == Mutability::Static && !same_value(p, &value));
                SettingInfo {
                    name: format!("{section}.{}", spec.name),
                    value,
                    default_value: value_text(&self.defaults, section, spec.name),
                    runtime_mutable: spec.mutability == Mutability::Dynamic,
                    description: spec.doc.to_owned(),
                    kind: spec.kind,
                    locked: self.locked(section, &spec),
                    pending_value,
                }
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out.dedup_by(|a, b| a.name == b.name);
        Ok(out)
    }

    /// Validates an update of `values` (all or nothing) and returns the configuration it would
    /// produce; nothing changes until [`RuntimeSettings::commit`].
    ///
    /// # Errors
    /// `RGN-1001` (empty update, malformed value, static setting, range or cross-field
    /// violation), `RGN-1030` (unknown setting).
    pub fn prepare(&self, values: &BTreeMap<String, String>) -> Result<Config, Error> {
        if values.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "no settings to update",
            ));
        }
        let overrides = self.read().overrides.clone();
        Self::layered(&self.registry, &self.base, &overrides, values)
    }

    /// Installs a committed update.
    pub fn commit(&self, values: BTreeMap<String, String>, config: Config) {
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        state.overrides.extend(values);
        state.config = config;
    }
}

fn file_error(path: &Path, e: &std::io::Error) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("configuration file {}: {e}", path.display()),
    )
}

/// Largest configuration file read (it is a few kilobytes).
const MAX_CONFIG_BYTES: u64 = 1 << 20;

fn read_text(fs: &dyn FileSystem, path: &Path) -> Result<String, Error> {
    let file = fs
        .open(path, OpenMode::Read)
        .map_err(|e| file_error(path, &e))?;
    let size = file.size().map_err(|e| file_error(path, &e))?;
    if size > MAX_CONFIG_BYTES {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{} is larger than {MAX_CONFIG_BYTES} bytes", path.display()),
        ));
    }
    let mut buf = vec![0u8; usize::try_from(size).unwrap_or(0)];
    file.read_exact_at(&mut buf, 0)
        .map_err(|e| file_error(path, &e))?;
    String::from_utf8(buf).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("{} is not UTF-8", path.display()),
        )
    })
}

/// Replaces `path` with `text`: an owner-only temporary file next to it, synced, renamed over it.
fn write_text(fs: &dyn FileSystem, path: &Path, text: &str) -> Result<(), Error> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    // A temporary file left by an interrupted write is replaced.
    let _ = fs.remove_file(&tmp);
    let mut file = fs
        .create_new_private(&tmp)
        .map_err(|e| file_error(&tmp, &e))?;
    file.append(text.as_bytes())
        .and_then(|()| file.sync_data())
        .map_err(|e| file_error(&tmp, &e))?;
    drop(file);
    fs.rename(&tmp, path).map_err(|e| file_error(path, &e))?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs.sync_dir(dir).map_err(|e| file_error(dir, &e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn settings(overrides: &[(&str, &str)]) -> RuntimeSettings {
        let mut registry = Registry::new();
        register_security_settings(&mut registry).unwrap();
        let base = Sources {
            file: Some("[auth]\nscram_iterations = 200000\n".into()),
            ..Sources::default()
        };
        RuntimeSettings::open(
            Arc::new(registry),
            base,
            overrides
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
        .unwrap()
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn fr_sec_001_runtime_settings_override_the_file_and_validate_atomically() {
        let s = settings(&[
            ("auth.session_idle_timeout_gui_secs", "600"),
            ("lockout.max_failures", "3"),
        ]);
        let auth: AuthnSettings = s.config().section().unwrap();
        assert_eq!(auth.scram_iterations, 200_000, "file layer");
        assert_eq!(auth.session_idle_timeout_gui_secs, 600, "override layer");
        let lockout: LockoutSettings = s.config().section().unwrap();
        assert_eq!(lockout.max_failures, 10, "static override ignored at open");

        let info = s.describe(&["auth.scram_iterations".into()]).unwrap();
        assert_eq!(info[0].value, "200000");
        assert_eq!(info[0].default_value, "600000");
        assert!(info[0].runtime_mutable);
        assert!(s.describe(&[]).unwrap().len() > 10);
        assert_eq!(
            s.describe(&["auth.nope".into()]).unwrap_err().code(),
            ErrorCode::NotFound
        );

        for bad in [
            map(&[("auth.scram_iterations", "5")]),
            map(&[("auth.scram_iterations", "\"700000\"")]),
            map(&[
                ("auth.scram_iterations", "700000"),
                ("lockout.max_failures", "4"),
            ]),
            map(&[("auth.session_idle_timeout_gui_secs", "100000")]),
            map(&[("auth.scram_iterations", "1 2")]),
            BTreeMap::new(),
        ] {
            assert!(s.prepare(&bad).is_err(), "{bad:?}");
        }
        let good = map(&[("auth.scram_iterations", "700000")]);
        let config = s.prepare(&good).unwrap();
        s.commit(good, config);
        let auth: AuthnSettings = s.config().section().unwrap();
        assert_eq!(auth.scram_iterations, 700_000);
        assert_eq!(auth.session_idle_timeout_gui_secs, 600);
    }

    #[test]
    fn setting_record_round_trips_strictly() {
        let r = SettingRecord {
            name: "auth.scram_iterations".into(),
            value: "700000".into(),
            updated_at: UNIX_EPOCH + Duration::from_millis(1_800_000_000_123),
        };
        assert_eq!(decode_setting(&encode_setting(&r).unwrap()).unwrap(), r);
        assert!(decode_setting(b"junk").is_err());
        assert_eq!(setting_key("a.b"), b"\x02ga.b".to_vec());
    }

    /// PD-230: static settings go to the configuration file (comments kept), show as pending
    /// until a restart, and are locked when another layer or no file owns them.
    #[test]
    fn fr_sec_001_static_settings_are_written_to_the_configuration_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rustegon.toml");
        let text = "# operator note
[auth]
scram_iterations = 200000 # tuned
";
        std::fs::write(&path, text).unwrap();
        let mut registry = Registry::new();
        register_security_settings(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let base = Sources {
            file: Some(text.into()),
            env: vec![("RUSTEGON__LOCKOUT__WINDOW_SECS".into(), "60".into())],
            ..Sources::default()
        };
        let open = |file: Option<PathBuf>| {
            RuntimeSettings::open(Arc::clone(&registry), base.clone(), BTreeMap::new())
                .unwrap()
                .with_config_file(file, &rustegon_sim_api::StdFileSystem)
        };
        let fs = rustegon_sim_api::StdFileSystem;

        // Without a file a static setting is locked; dynamic ones are not.
        let none = open(None);
        let err = none
            .split(&map(&[("lockout.max_failures", "4")]))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let info = none.describe(&["lockout.max_failures".into()]).unwrap();
        assert_eq!(info[0].locked, Some(Locked::NoConfigFile));
        assert!(
            none.split(&map(&[("auth.scram_iterations", "700000")]))
                .is_ok()
        );

        let s = open(Some(path.clone()));
        let (dynamic, stat) = s
            .split(&map(&[
                ("lockout.max_failures", "4"),
                ("auth.scram_iterations", "700000"),
            ]))
            .unwrap();
        assert_eq!(
            dynamic.keys().collect::<Vec<_>>(),
            ["auth.scram_iterations"]
        );
        s.write_static(&fs, &stat).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("# operator note") && written.contains("# tuned"),
            "{written}"
        );
        assert!(
            written.contains("[lockout]") && written.contains("max_failures = 4"),
            "{written}"
        );
        let info = s.describe(&["lockout.max_failures".into()]).unwrap();
        assert_eq!(info[0].value, "10", "still the running value");
        assert_eq!(info[0].pending_value.as_deref(), Some("4"));
        assert_eq!(info[0].locked, None);

        // Set by the environment: locked. Out of range: refused, file unchanged.
        let info = s.describe(&["lockout.window_secs".into()]).unwrap();
        assert_eq!(info[0].locked, Some(Locked::Environment));
        assert!(s.split(&map(&[("lockout.window_secs", "30")])).is_err());
        assert!(
            s.write_static(&fs, &map(&[("lockout.max_failures", "0")]))
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), written);
        assert!(s.split(&map(&[("node.data_dir", "\"x\"")])).is_err());

        // Back to the default: the key leaves the file and nothing is pending.
        s.write_static(&fs, &map(&[("lockout.max_failures", "10")]))
            .unwrap();
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("max_failures")
        );
        let info = s.describe(&["lockout.max_failures".into()]).unwrap();
        assert_eq!(info[0].pending_value, None);
    }
}
