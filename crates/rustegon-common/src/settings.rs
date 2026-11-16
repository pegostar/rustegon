// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Typed settings registry and layered configuration loader (system-overview.md §8,
//! implementation-rules.md §5).
//!
//! Each crate declares one settings struct per config section implementing [`Settings`]; the
//! binary registers all of them in a [`Registry`] and loads a [`Config`] from:
//!
//! 1. defaults (`Default` of each struct),
//! 2. the TOML file (`rustegon.toml`),
//! 3. environment variables `RUSTEGON__<SECTION>__<KEY>`,
//! 4. command-line flags `--set <section>.<key>=<value>`,
//!
//! later layers overriding earlier ones (precedence: flag > env > file > default). Unknown
//! sections and keys are rejected so typos never silently fall back to defaults.

use std::{collections::BTreeMap, path::PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use toml::{Table, Value};

use crate::{Error, ErrorCode, Result, redacted::REDACTED};

/// Prefix of configuration environment variables.
pub const ENV_PREFIX: &str = "RUSTEGON__";

/// Value type of a setting; drives parsing of env/flag strings and range validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Free text.
    String,
    /// File system path.
    Path,
    /// `true` / `false`.
    Bool,
    /// Integer within an inclusive range.
    Integer {
        /// Minimum allowed value.
        min: i64,
        /// Maximum allowed value.
        max: i64,
    },
    /// One of a fixed set of lowercase names.
    Enum(&'static [&'static str]),
    /// A list of strings: a TOML array of strings in the configuration file, comma-separated
    /// text in an environment variable or a `--set` flag (empty text = empty list). Items are
    /// trimmed; an item cannot contain a comma when given through the environment or a flag.
    StringList,
    /// A nested table (e.g. `[backup.s3]`), settable in the configuration file only; its
    /// fields are checked by the section's own `validate` (they deserialize with the section).
    Table,
}

/// Whether a setting can change at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutability {
    /// Requires a restart.
    Static,
    /// Changeable at runtime, cluster-wide (stored in the system `settings` collection, M4+).
    Dynamic,
}

/// Whether a setting holds a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Safe to display.
    Public,
    /// Secret: rejected as an inline literal (security.md §6) and redacted in dumps.
    Secret,
}

/// Static description of one setting.
#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    /// Key inside the section.
    pub name: &'static str,
    /// Value type and range.
    pub kind: Kind,
    /// Static or dynamic.
    pub mutability: Mutability,
    /// Secret or public.
    pub sensitivity: Sensitivity,
    /// One-sentence documentation, used for the generated settings reference.
    pub doc: &'static str,
}

impl FieldSpec {
    /// Secrets are fields marked [`Sensitivity::Secret`] plus, by naming convention, any key
    /// ending in `_password`, `_secret` or `_key` (security.md §6).
    #[must_use]
    pub fn is_secret(&self) -> bool {
        self.sensitivity == Sensitivity::Secret
            || ["_password", "_secret", "_key"]
                .iter()
                .any(|s| self.name.ends_with(s))
    }
}

/// A typed configuration section.
pub trait Settings: Default + Serialize + DeserializeOwned + 'static {
    /// Section name in `rustegon.toml` (`[section]`).
    const SECTION: &'static str;
    /// One spec per field; registration fails if a field has no spec.
    const FIELDS: &'static [FieldSpec];

    /// Cross-field validation beyond types and ranges.
    ///
    /// # Errors
    /// A human-readable reason.
    fn validate(&self) -> std::result::Result<(), String> {
        Ok(())
    }
}

type SectionCheck = fn(&Table) -> std::result::Result<(), String>;

struct Section {
    fields: &'static [FieldSpec],
    defaults: Table,
    check: SectionCheck,
}

fn check_section<T: Settings>(table: &Table) -> std::result::Result<(), String> {
    let settings: T = Value::Table(table.clone())
        .try_into()
        .map_err(|e| e.to_string())?;
    settings.validate()
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

/// Registry of all settings sections known to the binary.
pub struct Registry {
    sections: BTreeMap<&'static str, Section>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// Creates a registry containing the loader's own [`DevSettings`] section.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Self {
            sections: BTreeMap::new(),
        };
        // DevSettings serialises to a one-key table with a matching spec: cannot fail.
        if let Err(e) = registry.register::<DevSettings>() {
            debug_assert!(false, "DevSettings registration failed: {e}");
        }
        registry
    }

    /// Registers a section.
    ///
    /// # Errors
    /// Duplicate section, default value not representable in TOML, or a field without spec.
    pub fn register<T: Settings>(&mut self) -> Result<&mut Self> {
        if self.sections.contains_key(T::SECTION) {
            return Err(invalid(format!(
                "settings section [{}] registered twice",
                T::SECTION
            )));
        }
        let defaults = Table::try_from(T::default())
            .map_err(|e| invalid(format!("[{}] defaults: {e}", T::SECTION)))?;
        if let Some(key) = defaults
            .keys()
            .find(|k| !T::FIELDS.iter().any(|f| f.name == *k))
        {
            return Err(invalid(format!(
                "[{}] field `{key}` has no FieldSpec",
                T::SECTION
            )));
        }
        let check = check_section::<T> as SectionCheck;
        self.sections.insert(
            T::SECTION,
            Section {
                fields: T::FIELDS,
                defaults,
                check,
            },
        );
        Ok(self)
    }

    /// Specs of every registered setting as `(section, spec)`, for the settings reference.
    pub fn specs(&self) -> impl Iterator<Item = (&'static str, &FieldSpec)> {
        self.sections
            .iter()
            .flat_map(|(name, s)| s.fields.iter().map(move |f| (*name, f)))
    }

    fn field(&self, section: &str, key: &str, origin: &str) -> Result<&'static FieldSpec> {
        let s = self
            .sections
            .get(section)
            .ok_or_else(|| invalid(format!("{origin}: unknown settings section [{section}]")))?;
        s.fields
            .iter()
            .find(|f| f.name == key)
            .ok_or_else(|| invalid(format!("{origin}: unknown setting {section}.{key}")))
    }

    /// Loads and validates the configuration from all layers.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`] naming the offending layer and key: TOML syntax, unknown
    /// section/key, type or range violation, inline secret, malformed flag.
    pub fn load(&self, sources: &Sources) -> Result<Config> {
        let mut merged: Table = self
            .sections
            .iter()
            .map(|(name, s)| ((*name).to_owned(), Value::Table(s.defaults.clone())))
            .collect();
        if let Some(text) = &sources.file {
            let file: Table =
                toml::from_str(text).map_err(|e| invalid(format!("config file: {e}")))?;
            for (section, value) in file {
                let Value::Table(entries) = value else {
                    return Err(invalid(format!("config file: `{section}` must be a table")));
                };
                for (key, value) in entries {
                    self.field(&section, &key, "config file")?;
                    set(&mut merged, &section, key, value);
                }
            }
        }
        for (name, raw) in &sources.env {
            let Some(rest) = name.strip_prefix(ENV_PREFIX) else {
                continue;
            };
            let origin = format!("environment variable {name}");
            let path: Vec<String> = rest.split("__").map(str::to_lowercase).collect();
            let [section, key] = path.as_slice() else {
                return Err(invalid(format!(
                    "{origin}: expected RUSTEGON__SECTION__KEY"
                )));
            };
            self.set_parsed(&mut merged, section, key, raw, &origin)?;
        }
        for flag in &sources.flags {
            let origin = format!("flag --set {flag}");
            let (path, raw) = flag
                .split_once('=')
                .ok_or_else(|| invalid(format!("{origin}: expected section.key=value")))?;
            let (section, key) = path
                .split_once('.')
                .ok_or_else(|| invalid(format!("{origin}: expected section.key=value")))?;
            self.set_parsed(&mut merged, section, key, raw, &origin)?;
        }
        self.validate(&merged)?;
        Ok(Config {
            table: merged,
            secrets: self.secret_paths(),
        })
    }

    fn set_parsed(
        &self,
        merged: &mut Table,
        section: &str,
        key: &str,
        raw: &str,
        origin: &str,
    ) -> Result<()> {
        let spec = self.field(section, key, origin)?;
        let value = match spec.kind {
            Kind::String | Kind::Path | Kind::Enum(_) => Value::String(raw.to_owned()),
            Kind::Bool => Value::Boolean(
                raw.parse()
                    .map_err(|_| invalid(format!("{origin}: expected true or false")))?,
            ),
            Kind::Integer { .. } => Value::Integer(
                raw.trim()
                    .parse()
                    .map_err(|_| invalid(format!("{origin}: expected an integer")))?,
            ),
            Kind::Table => {
                return Err(invalid(format!(
                    "{origin}: {section}.{key} is a table; set it in the configuration file"
                )));
            }
            Kind::StringList => Value::Array(
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_owned()))
                    .collect(),
            ),
        };
        set(merged, section, key.to_owned(), value);
        Ok(())
    }

    fn validate(&self, merged: &Table) -> Result<()> {
        let allow_inline_secrets = merged
            .get(DevSettings::SECTION)
            .and_then(|d| d.get("allow_inline_secrets"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        for (name, section) in &self.sections {
            let Some(Value::Table(table)) = merged.get(*name) else {
                continue;
            };
            for spec in section.fields {
                let Some(value) = table.get(spec.name) else {
                    continue;
                };
                let key = format!("{name}.{}", spec.name);
                match (spec.kind, value) {
                    (Kind::Integer { min, max }, Value::Integer(v)) if !(min..=max).contains(v) => {
                        return Err(invalid(format!("{key} = {v} outside {min}..={max}")));
                    }
                    (Kind::Enum(allowed), Value::String(v)) if !allowed.contains(&v.as_str()) => {
                        return Err(invalid(format!(
                            "{key} = {v:?}, expected one of {allowed:?}"
                        )));
                    }
                    (Kind::StringList, v)
                        if !v
                            .as_array()
                            .is_some_and(|items| items.iter().all(Value::is_str)) =>
                    {
                        return Err(invalid(format!("{key}: expected a list of strings")));
                    }
                    (Kind::Table, v) if !v.is_table() => {
                        return Err(invalid(format!("{key}: expected a table")));
                    }
                    (_, Value::String(v))
                        if spec.is_secret() && !v.is_empty() && !allow_inline_secrets =>
                    {
                        return Err(invalid(format!(
                            "{key}: inline secret values are not allowed; reference a file or                              provider instead (dev.allow_inline_secrets enables them)"
                        )));
                    }
                    _ => {}
                }
            }
            (section.check)(table).map_err(|e| invalid(format!("[{name}]: {e}")))?;
        }
        Ok(())
    }

    fn secret_paths(&self) -> Vec<(&'static str, &'static str)> {
        self.specs()
            .filter(|(_, f)| f.is_secret())
            .map(|(s, f)| (s, f.name))
            .collect()
    }
}

fn set(merged: &mut Table, section: &str, key: String, value: Value) {
    if let Value::Table(t) = merged
        .entry(section.to_owned())
        .or_insert_with(|| Value::Table(Table::new()))
    {
        t.insert(key, value);
    }
}

/// Raw configuration inputs. The binary reads the file and the process environment; keeping
/// the loader free of I/O makes it deterministic and testable.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    /// Contents of `rustegon.toml`, if a file was given.
    pub file: Option<String>,
    /// Environment variables (all of them; non-`RUSTEGON__` names are ignored).
    pub env: Vec<(String, String)>,
    /// `--set section.key=value` flags, in command-line order.
    pub flags: Vec<String>,
}

/// Validated, merged configuration.
#[derive(Debug, Clone)]
pub struct Config {
    table: Table,
    secrets: Vec<(&'static str, &'static str)>,
}

impl Config {
    /// Deserialises one section.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`] if the section does not match `T` (should not happen for
    /// registered sections, which are validated on load).
    pub fn section<T: Settings>(&self) -> Result<T> {
        let table = self
            .table
            .get(T::SECTION)
            .cloned()
            .unwrap_or(Value::Table(Table::new()));
        table
            .try_into()
            .map_err(|e| invalid(format!("[{}]: {e}", T::SECTION)))
    }

    /// Effective configuration as TOML with every secret value replaced by `‹redacted›`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] if TOML serialisation fails.
    pub fn dump_redacted(&self) -> Result<String> {
        let mut table = self.table.clone();
        for (section, key) in &self.secrets {
            if let Some(Value::Table(t)) = table.get_mut(*section)
                && let Some(v) = t.get_mut(*key)
            {
                *v = Value::String(REDACTED.to_owned());
            }
        }
        toml::to_string(&table).map_err(|e| Error::new(ErrorCode::Internal, e.to_string()))
    }
}

/// `[dev]` section: development-only switches. Never enable in production.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DevSettings {
    /// Allow secret values inline in configuration (security.md §6).
    pub allow_inline_secrets: bool,
}

impl Settings for DevSettings {
    const SECTION: &'static str = "dev";
    const FIELDS: &'static [FieldSpec] = &[FieldSpec {
        name: "allow_inline_secrets",
        kind: Kind::Bool,
        mutability: Mutability::Static,
        sensitivity: Sensitivity::Public,
        doc: "Allow secret values inline in configuration (development only).",
    }];
}

/// `[node]` section: identity and storage location of this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeSettings {
    /// Data directory (stores, Raft logs, default log directory).
    pub data_dir: PathBuf,
}

impl Default for NodeSettings {
    fn default() -> Self {
        // Relative default suits development; packages set an absolute path (linux.md, windows.md).
        Self {
            data_dir: PathBuf::from("rustegon-data"),
        }
    }
}

impl Settings for NodeSettings {
    const SECTION: &'static str = "node";
    const FIELDS: &'static [FieldSpec] = &[FieldSpec {
        name: "data_dir",
        kind: Kind::Path,
        mutability: Mutability::Static,
        sensitivity: Sensitivity::Public,
        doc: "Data directory of the node.",
    }];

    fn validate(&self) -> std::result::Result<(), String> {
        if self.data_dir.as_os_str().is_empty() {
            return Err("data_dir must not be empty".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    #[serde(default, deny_unknown_fields)]
    struct TestSettings {
        name: String,
        port: i64,
        mode: String,
        api_key: String,
    }

    impl Default for TestSettings {
        fn default() -> Self {
            Self {
                name: "default".into(),
                port: 7700,
                mode: "fast".into(),
                api_key: String::new(),
            }
        }
    }

    const fn spec(name: &'static str, kind: Kind) -> FieldSpec {
        FieldSpec {
            name,
            kind,
            mutability: Mutability::Static,
            sensitivity: Sensitivity::Public,
            doc: "test",
        }
    }

    impl Settings for TestSettings {
        const SECTION: &'static str = "test";
        const FIELDS: &'static [FieldSpec] = &[
            spec("name", Kind::String),
            spec("port", Kind::Integer { min: 1, max: 65535 }),
            spec("mode", Kind::Enum(&["fast", "safe"])),
            spec("api_key", Kind::String),
        ];
    }

    fn registry() -> Registry {
        let mut r = Registry::new();
        r.register::<TestSettings>().unwrap();
        r.register::<NodeSettings>().unwrap();
        r
    }

    fn load(file: Option<&str>, env: &[(&str, &str)], flags: &[&str]) -> Result<Config> {
        registry().load(&Sources {
            file: file.map(str::to_owned),
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            flags: flags.iter().map(|f| (*f).to_owned()).collect(),
        })
    }

    #[test]
    fn tc_ops_001_precedence_flag_over_env_over_file_over_default() {
        let file = "[test]\nname = \"file\"\nport = 1000\nmode = \"safe\"\n";
        let env = [
            ("RUSTEGON__TEST__NAME", "env"),
            ("RUSTEGON__TEST__PORT", "2000"),
        ];
        let cfg = load(Some(file), &env, &["test.name=flag"]).unwrap();
        let s: TestSettings = cfg.section().unwrap();
        assert_eq!(s.name, "flag"); // flag > env > file
        assert_eq!(s.port, 2000); // env > file
        assert_eq!(s.mode, "safe"); // file > default
        assert_eq!(s.api_key, ""); // default
        let node: NodeSettings = cfg.section().unwrap();
        assert_eq!(node.data_dir, PathBuf::from("rustegon-data"));
    }

    #[test]
    fn tc_ops_001_defaults_only() {
        let s: TestSettings = load(None, &[], &[]).unwrap().section().unwrap();
        assert_eq!(s, TestSettings::default());
    }

    #[test]
    fn tc_ops_001_unrelated_env_vars_ignored_and_env_keys_case_insensitive() {
        let env = [
            ("PATH", "/bin"),
            ("RUSTEGON_SINGLE", "x"),
            ("RUSTEGON__test__Port", "9"),
        ];
        let s: TestSettings = load(None, &env, &[]).unwrap().section().unwrap();
        assert_eq!(s.port, 9);
    }

    #[test]
    fn tc_ops_001_rejects_unknown_type_and_range_errors() {
        type Case<'a> = (
            Option<&'a str>,
            &'a [(&'a str, &'a str)],
            &'a [&'a str],
            &'a str,
        );
        let cases: [Case<'_>; 9] = [
            (
                Some("[nope]\na = 1\n"),
                &[],
                &[],
                "unknown settings section [nope]",
            ),
            (
                Some("[test]\nprot = 1\n"),
                &[],
                &[],
                "unknown setting test.prot",
            ),
            (Some("[test]\nport = \"x\"\n"), &[], &[], "[test]"),
            (Some("test = 1\n"), &[], &[], "must be a table"),
            (Some("[test\n"), &[], &[], "config file"),
            (
                None,
                &[("RUSTEGON__TEST__PORT", "70000")],
                &[],
                "outside 1..=65535",
            ),
            (
                None,
                &[("RUSTEGON__TEST__PORT", "abc")],
                &[],
                "expected an integer",
            ),
            (None, &[], &["test.mode=slow"], "expected one of"),
            (None, &[], &["testmode"], "expected section.key=value"),
        ];
        for (file, env, flags, needle) in cases {
            let err = load(file, env, flags).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(
                err.message().contains(needle),
                "`{}` lacks `{needle}`",
                err.message()
            );
        }
        let err = load(None, &[("RUSTEGON__NODE__DATA_DIR", "")], &[]).unwrap_err();
        assert!(err.message().contains("data_dir must not be empty"));
    }

    #[test]
    fn tc_ops_003_inline_secret_rejected_unless_dev_allows() {
        let env = [("RUSTEGON__TEST__API_KEY", "CANARY-key")];
        let err = load(None, &env, &[]).unwrap_err();
        assert!(err.message().contains("inline secret"));
        assert!(
            !err.message().contains("CANARY"),
            "error message leaked the secret"
        );
        let cfg = load(None, &env, &["dev.allow_inline_secrets=true"]).unwrap();
        let s: TestSettings = cfg.section().unwrap();
        assert_eq!(s.api_key, "CANARY-key");
        let dump = cfg.dump_redacted().unwrap();
        assert!(!dump.contains("CANARY"), "dump leaked secret:\n{dump}");
        assert!(dump.contains(REDACTED));
        assert!(dump.contains("port = 7700"));
    }

    #[test]
    fn registry_rejects_duplicate_sections_and_missing_specs() {
        #[derive(Default, Serialize, Deserialize)]
        struct Undocumented {
            field: i64,
        }
        impl Settings for Undocumented {
            const SECTION: &'static str = "undocumented";
            const FIELDS: &'static [FieldSpec] = &[];
        }

        let mut r = Registry::new();
        assert!(r.register::<DevSettings>().is_err());
        let err = r.register::<Undocumented>().err().unwrap();
        assert!(err.message().contains("no FieldSpec"));
    }
}
