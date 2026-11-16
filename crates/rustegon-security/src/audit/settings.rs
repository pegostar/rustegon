// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `[audit]` configuration section (security.md §4, implementation-rules.md §5).

use std::path::{Path, PathBuf};

use rustegon_common::settings::{FieldSpec, Kind, Mutability, Sensitivity, Settings};
use serde::{Deserialize, Serialize};

use super::AuditEventKind;

const MIB: u64 = 1024 * 1024;
const MIN_FILE_SIZE: i64 = 1024 * 1024;
const MAX_FILE_SIZE: i64 = 16 * 1024 * 1024 * 1024;

/// Audit settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditSettings {
    /// Write the audit log. On by default (secure by default).
    pub enabled: bool,
    /// Sink; only `file` exists so far (`syslog`, `internal` arrive with the server, PD-048).
    pub sink: String,
    /// Directory of the audit segments; unset means `<node.data_dir>/audit`.
    pub dir: Option<PathBuf>,
    /// Size in bytes at which a new segment is started.
    pub max_file_size: u64,
    /// Segments kept; 0 keeps all (default: audit evidence is never deleted implicitly).
    pub max_files: u32,
    /// Also audit data writes made through the GUI.
    pub data_writes: bool,
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            sink: "file".into(),
            dir: None,
            max_file_size: 64 * MIB,
            max_files: 0,
            data_writes: false,
        }
    }
}

impl AuditSettings {
    /// Audit directory given the node's data directory.
    #[must_use]
    pub fn dir_for(&self, data_dir: &Path) -> PathBuf {
        self.dir.clone().unwrap_or_else(|| data_dir.join("audit"))
    }

    /// Whether events of `kind` are recorded.
    #[must_use]
    pub fn records(&self, kind: AuditEventKind) -> bool {
        self.enabled && (kind != AuditEventKind::DataWrite || self.data_writes)
    }
}

const fn spec(name: &'static str, kind: Kind, doc: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        kind,
        mutability: Mutability::Static,
        sensitivity: Sensitivity::Public,
        doc,
    }
}

impl Settings for AuditSettings {
    const SECTION: &'static str = "audit";
    const FIELDS: &'static [FieldSpec] = &[
        spec("enabled", Kind::Bool, "Write the security audit log."),
        spec("sink", Kind::Enum(&["file"]), "Audit sink (`file`)."),
        spec(
            "dir",
            Kind::Path,
            "Directory of audit segment files (default `<node.data_dir>/audit`).",
        ),
        spec(
            "max_file_size",
            Kind::Integer {
                min: MIN_FILE_SIZE,
                max: MAX_FILE_SIZE,
            },
            "Size in bytes at which a new audit segment file is started.",
        ),
        spec(
            "max_files",
            Kind::Integer {
                min: 0,
                max: 1_000_000,
            },
            "Audit segment files kept; 0 keeps all.",
        ),
        spec(
            "data_writes",
            Kind::Bool,
            "Also audit data writes made through the GUI.",
        ),
    ];
}

#[cfg(test)]
mod tests {
    use rustegon_common::settings::{Registry, Sources};

    use super::*;

    #[test]
    fn audit_settings_defaults_and_range_check() {
        let mut registry = Registry::new();
        registry.register::<AuditSettings>().unwrap();
        let config = registry.load(&Sources::default()).unwrap();
        let s: AuditSettings = config.section().unwrap();
        assert_eq!(s, AuditSettings::default());
        assert!(s.records(AuditEventKind::LoginFailure));
        assert!(!s.records(AuditEventKind::DataWrite));
        assert_eq!(s.dir_for(Path::new("d")), Path::new("d").join("audit"));
        let bad = Sources {
            flags: vec!["audit.max_file_size=10".into()],
            ..Sources::default()
        };
        assert!(registry.load(&bad).is_err());
        let bad = Sources {
            flags: vec!["audit.sink=syslog".into()],
            ..Sources::default()
        };
        assert!(registry.load(&bad).is_err());
    }
}
