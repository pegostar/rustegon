// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `[backup]` settings of a node (M13a; PD-077 owner note, PD-082; configuration reference in
//! docs/deployment/configuration.md).
//!
//! The section is registered by `rustegond`. It holds what the server needs to serve
//! `BackupService` safely:
//! - `allowed_destinations`: where a caller holding the `backup` privilege may make the server
//!   read or write backups (see [`crate::policy::DestinationPolicy`]);
//! - `[backup.s3]`: how the server reaches S3-compatible destinations ([`S3Settings`]:
//!   credentials file, endpoint, region, CA, part size, retries; backup-restore.md
//!   "S3-compatible destination"). A nested table: configuration file only.

use rustegon_common::settings::{FieldSpec, Kind, Mutability, Sensitivity, Settings};
use serde::{Deserialize, Serialize};

use crate::dest::s3::S3Settings;

/// `[backup]` (module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupSettings {
    /// Destinations the server may use besides its default `<data_dir>/backups`: absolute local
    /// directories (plain path or `file://` URL) and `s3://bucket[/prefix]` URLs. A request's
    /// destination is allowed when it is one of them or lies below one of them (PD-082).
    pub allowed_destinations: Vec<String>,
    /// `[backup.s3]`: S3-compatible destinations.
    pub s3: S3Settings,
    /// `[backup.pitr]`: continuous archiving of the Raft log for point-in-time recovery.
    pub pitr: PitrSettings,
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

impl Settings for BackupSettings {
    const SECTION: &'static str = "backup";
    const FIELDS: &'static [FieldSpec] = &[
        spec(
            "allowed_destinations",
            Kind::StringList,
            "Backup destinations the server may read and write besides <data_dir>/backups: \
             absolute directories or file:// URLs, s3://bucket[/prefix] URLs (a destination \
             below one of them is allowed too). Empty: only <data_dir>/backups.",
        ),
        spec(
            "pitr",
            Kind::Table,
            "[backup.pitr]: point-in-time recovery log archiving (enabled, destination, \
             segment_interval_secs, max_unarchived_bytes); configuration file only.",
        ),
        spec(
            "s3",
            Kind::Table,
            "[backup.s3]: S3-compatible destinations (credentials_file, endpoint, region, \
             force_path_style, ca_file, part_size_mib, max_attempts, connect_timeout_secs, \
             request_timeout_secs); configuration file only.",
        ),
    ];

    fn validate(&self) -> Result<(), String> {
        for entry in &self.allowed_destinations {
            crate::policy::AllowedDestination::parse(entry).map_err(|e| e.message().to_owned())?;
        }
        self.s3.validate().map_err(|e| e.to_string())?;
        self.pitr.validate()
    }
}

/// Default `backup.pitr.segment_interval_secs`: the RPO of the archive (backup-restore.md §7).
pub const DEFAULT_SEGMENT_INTERVAL_SECS: u64 = 300;
/// Default `backup.pitr.max_unarchived_bytes`.
pub const DEFAULT_MAX_UNARCHIVED_BYTES: u64 = 1 << 30;

/// `[backup.pitr]` (FR-BKP-002/004, PD-066; backup-restore.md "Point-in-time recovery").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PitrSettings {
    /// Archive the Raft log (the WAL) to `destination`.
    pub enabled: bool,
    /// Archive destination (path, `file://` or `s3://` URL); must be allowed by
    /// `backup.allowed_destinations` (or be below `<data_dir>/backups`).
    pub destination: Option<String>,
    /// The active log segment is sealed and archived at least this often (seconds): the RPO.
    pub segment_interval_secs: u64,
    /// Sealed segments the archive may lag behind before the archiver gives up on them,
    /// releases them and breaks PITR continuity (writes are never blocked).
    pub max_unarchived_bytes: u64,
}

impl Default for PitrSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            destination: None,
            segment_interval_secs: DEFAULT_SEGMENT_INTERVAL_SECS,
            max_unarchived_bytes: DEFAULT_MAX_UNARCHIVED_BYTES,
        }
    }
}

impl PitrSettings {
    /// Checks the values (the destination's allowlist check needs the data directory and is
    /// done by the server).
    ///
    /// # Errors
    /// A message naming the offending setting.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=86_400).contains(&self.segment_interval_secs) {
            return Err("backup.pitr.segment_interval_secs must be between 1 and 86400".into());
        }
        if self.max_unarchived_bytes == 0 {
            return Err("backup.pitr.max_unarchived_bytes must be at least 1".into());
        }
        match (&self.destination, self.enabled) {
            (Some(d), _) => crate::url::DestinationUrl::parse(d)
                .map(|_| ())
                .map_err(|e| format!("backup.pitr.destination: {e}")),
            (None, true) => Err("backup.pitr.enabled needs backup.pitr.destination".into()),
            (None, false) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::assert_is_empty)]

    use rustegon_common::settings::{Registry, Sources};

    use super::*;

    fn load(
        file: Option<&str>,
        env: &[(&str, &str)],
        flags: &[&str],
    ) -> rustegon_common::Result<BackupSettings> {
        let mut registry = Registry::new();
        registry.register::<BackupSettings>()?;
        registry
            .load(&Sources {
                file: file.map(str::to_owned),
                env: env
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                flags: flags.iter().map(|f| (*f).to_owned()).collect(),
            })?
            .section()
    }

    fn abs(name: &str) -> String {
        std::env::temp_dir().join(name).display().to_string()
    }

    /// PD-082: the list comes from a TOML array, or comma-separated from the environment or a
    /// flag; the default is empty; relative paths and unsupported schemes are refused at load.
    #[test]
    fn pd_082_allowed_destinations_load_from_every_layer() {
        assert!(
            load(None, &[], &[])
                .unwrap()
                .allowed_destinations
                .is_empty()
        );
        let (a, b) = (abs("a"), abs("b"));
        let file = format!("[backup]\nallowed_destinations = [{a:?}, \"s3://bucket/prefix\"]\n");
        assert_eq!(
            load(Some(&file), &[], &[]).unwrap().allowed_destinations,
            [a.clone(), "s3://bucket/prefix".to_owned()]
        );
        let env = format!("{a}, {b}");
        assert_eq!(
            load(
                None,
                &[("RUSTEGON__BACKUP__ALLOWED_DESTINATIONS", &env)],
                &[]
            )
            .unwrap()
            .allowed_destinations,
            [a.clone(), b.clone()]
        );
        let flag = format!("backup.allowed_destinations={b}");
        assert_eq!(
            load(Some(&file), &[], &[&flag])
                .unwrap()
                .allowed_destinations,
            [b]
        );
        assert!(
            load(None, &[], &["backup.allowed_destinations="])
                .unwrap()
                .allowed_destinations
                .is_empty()
        );
        for bad in ["relative/dir", "azure://c/p", "s3://"] {
            let flag = format!("backup.allowed_destinations={bad}");
            assert!(load(None, &[], &[&flag]).is_err(), "{bad}");
        }
        let err = load(Some("[backup]\nallowed_destinations = \"x\"\n"), &[], &[]).unwrap_err();
        assert!(err.message().contains("list of strings"), "{err}");
    }

    /// `[backup.s3]` (lane BS3's `S3Settings`) parses as a nested table of `[backup]` and is
    /// validated with the section; it cannot be set through the environment or a flag.
    #[test]
    fn fr_bkp_002_backup_pitr_table_parses_and_validates() {
        assert_eq!(load(None, &[], &[]).unwrap().pitr, PitrSettings::default());
        let dir = abs("archive");
        let file = format!(
            "[backup.pitr]
enabled = true
destination = {dir:?}
segment_interval_secs = 30
             max_unarchived_bytes = 1048576
"
        );
        let s = load(Some(&file), &[], &[]).unwrap().pitr;
        assert!(s.enabled);
        assert_eq!(s.destination.as_deref(), Some(dir.as_str()));
        assert_eq!(
            (s.segment_interval_secs, s.max_unarchived_bytes),
            (30, 1 << 20)
        );
        for bad in [
            "[backup.pitr]
enabled = true
",
            "[backup.pitr]
segment_interval_secs = 0
",
            "[backup.pitr]
max_unarchived_bytes = 0
",
            "[backup.pitr]
destination = \"azure://c/p\"
",
            "[backup.pitr]
unknown = 1
",
        ] {
            assert!(load(Some(bad), &[], &[]).is_err(), "{bad}");
        }
        assert!(load(None, &[], &["backup.pitr=x"]).is_err());
    }

    #[test]
    fn fr_bkp_006_backup_s3_table_parses_and_validates() {
        let file = "[backup.s3]\nendpoint = \"https://minio:9000\"\nregion = \"eu-south-1\"\n\
                    part_size_mib = 32\nforce_path_style = true\n";
        let s = load(Some(file), &[], &[]).unwrap();
        assert_eq!(s.s3.endpoint.as_deref(), Some("https://minio:9000"));
        assert_eq!(s.s3.region.as_deref(), Some("eu-south-1"));
        assert_eq!(s.s3.part_size_mib, 32);
        assert_eq!(s.s3.force_path_style, Some(true));
        assert_eq!(load(None, &[], &[]).unwrap().s3, S3Settings::default());
        let err = load(Some("[backup.s3]\npart_size_mib = 1\n"), &[], &[]).unwrap_err();
        assert!(err.message().contains("part_size_mib"), "{err}");
        assert!(load(Some("[backup.s3]\nsecret = \"x\"\n"), &[], &[]).is_err());
        assert!(load(None, &[], &["backup.s3=x"]).is_err());
        assert!(load(None, &[("RUSTEGON__BACKUP__S3", "x")], &[]).is_err());
        assert!(load(Some("[backup]\ns3 = 1\n"), &[], &[]).is_err());
    }
}
