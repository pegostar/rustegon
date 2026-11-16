// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `[raft]` configuration section (implementation-rules.md §5, coding-standards.md §3.7).
//! Fields are added by the task that introduces each tunable.

use rustegon_common::settings::{FieldSpec, Kind, Mutability, Sensitivity, Settings};
use serde::{Deserialize, Serialize};

/// Default Raft log segment size: 128 MiB (replication.md §2).
pub const DEFAULT_LOG_SEGMENT_SIZE: u64 = 128 << 20;
/// Smallest accepted segment size: 1 MiB. Every segment starts with a snapshot of all groups'
/// metadata, so tiny segments would mostly hold snapshots.
const MIN_LOG_SEGMENT_SIZE: i64 = 1 << 20;
/// Largest accepted segment size: 1 GiB. Recovery rewrites the valid prefix of a torn last
/// segment, and a segment is deleted only as a whole, so larger segments delay reclamation.
const MAX_LOG_SEGMENT_SIZE: i64 = 1 << 30;

/// Raft settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RaftSettings {
    /// Size in bytes at which the log store rolls over to a new segment (replication.md §2).
    pub log_segment_size: u64,
}

impl Default for RaftSettings {
    fn default() -> Self {
        Self {
            log_segment_size: DEFAULT_LOG_SEGMENT_SIZE,
        }
    }
}

impl Settings for RaftSettings {
    const SECTION: &'static str = "raft";
    const FIELDS: &'static [FieldSpec] = &[FieldSpec {
        name: "log_segment_size",
        kind: Kind::Integer {
            min: MIN_LOG_SEGMENT_SIZE,
            max: MAX_LOG_SEGMENT_SIZE,
        },
        // Read when the log store opens; existing segments keep their size.
        mutability: Mutability::Static,
        sensitivity: Sensitivity::Public,
        doc: "Raft log segment size in bytes at which the log store starts a new segment file.",
    }];
}

#[cfg(test)]
mod tests {
    use rustegon_common::settings::{Registry, Sources};

    use super::*;

    #[test]
    fn raft_settings_load_with_range_check() {
        let mut registry = Registry::new();
        registry.register::<RaftSettings>().unwrap();
        let config = registry.load(&Sources::default()).unwrap();
        let settings: RaftSettings = config.section().unwrap();
        assert_eq!(settings, RaftSettings::default());
        let load = |flag: &str| {
            registry.load(&Sources {
                flags: vec![flag.to_owned()],
                ..Sources::default()
            })
        };
        assert!(load("raft.log_segment_size=1024").is_err());
        let ok = load("raft.log_segment_size=2097152").unwrap();
        assert_eq!(
            ok.section::<RaftSettings>().unwrap().log_segment_size,
            2 << 20
        );
    }
}
