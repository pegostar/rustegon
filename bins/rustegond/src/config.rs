// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Settings sections owned by the server binary and the full registry of `rustegond`
//! (system-overview.md §8, security.md §5, PD-054).
//!
//! - `[listen]`: client listener addresses (gRPC 7700, REST 7780) and the shutdown drain time;
//! - `[security]`: the TLS switch (`tls`, ADR-034), the default certificate directory and the
//!   key file sealing cursor continuation tokens;
//! - `[gui]`: whether the REST listener serves the embedded GUI under `/ui` (ADR-027, PD-130);
//! - `[gc]`: how much MVCC history the background GC keeps (`ttl_secs`, PD-232);
//! - `[tls]`: certificate, key and CA paths (defaulting to files in `security.certs_dir`), the
//!   client-certificate policy, the minimum TLS version and the reload intervals.
//!
//! Every value here is static: listeners, certificates paths and keys are read at startup.
//! Certificate *contents* are reloaded at runtime (FR-TLS-003), their paths are not.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use rustegon_common::{
    Error, ErrorCode, Result,
    logging::LogSettings,
    settings::{FieldSpec, Kind, Mutability, NodeSettings, Registry, Sensitivity, Settings},
};
use rustegon_net::{ClientCertPolicy, TlsMinVersion, TlsSettings};
use rustegon_server::security::register_security_settings;
use rustegon_storage::settings::StorageSettings;
use serde::{Deserialize, Serialize};

/// Every settings section known to the server. New crates register theirs here.
///
/// # Errors
/// A section registered twice (a programming error).
pub fn registry() -> Result<Registry> {
    let mut registry = Registry::new();
    registry
        .register::<NodeSettings>()?
        .register::<LogSettings>()?
        .register::<StorageSettings>()?
        .register::<ListenSettings>()?
        .register::<SecuritySettings>()?
        .register::<TlsFileSettings>()?
        .register::<GuiSettings>()?
        .register::<GcSettings>()?
        .register::<rustegon_backup::BackupSettings>()?;
    register_security_settings(&mut registry)?;
    Ok(registry)
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

/// `[listen]`: client listener addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListenSettings {
    /// Client gRPC listener, `ip:port` (protocol.md §1: 7700).
    pub grpc: String,
    /// REST listener, `ip:port` (protocol.md §1: 7780).
    pub http: String,
    /// How long shutdown waits for in-flight requests before closing connections.
    pub shutdown_grace_secs: u64,
    /// How long a shutdown keeps serving with `/api/v1/health/ready` answering 503 before the
    /// listeners stop accepting, so load balancers stop routing first (PD-059).
    pub drain_delay_secs: u64,
}

impl Default for ListenSettings {
    fn default() -> Self {
        // Loopback by default (security.md §1: minimal listener exposure on a single node until
        // the operator chooses an address).
        Self {
            grpc: "127.0.0.1:7700".into(),
            http: "127.0.0.1:7780".into(),
            shutdown_grace_secs: 30,
            drain_delay_secs: 0,
        }
    }
}

impl ListenSettings {
    /// The gRPC address.
    ///
    /// # Errors
    /// `RGN-1001` for a value that is not `ip:port` (checked on load already).
    pub fn grpc_addr(&self) -> Result<SocketAddr> {
        parse_addr("listen.grpc", &self.grpc)
    }

    /// The REST address.
    ///
    /// # Errors
    /// As [`Self::grpc_addr`].
    pub fn http_addr(&self) -> Result<SocketAddr> {
        parse_addr("listen.http", &self.http)
    }

    /// The drain period of a graceful shutdown.
    #[must_use]
    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(self.shutdown_grace_secs)
    }

    /// How long a shutdown reports not-ready before it stops accepting.
    #[must_use]
    pub fn drain_delay(&self) -> Duration {
        Duration::from_secs(self.drain_delay_secs)
    }
}

fn parse_addr(key: &str, value: &str) -> Result<SocketAddr> {
    value.parse().map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} = {value:?} is not an ip:port address"),
        )
    })
}

impl Settings for ListenSettings {
    const SECTION: &'static str = "listen";
    const FIELDS: &'static [FieldSpec] = &[
        spec(
            "grpc",
            Kind::String,
            "Client gRPC listener address (ip:port); port 0 picks a free port.",
        ),
        spec(
            "http",
            Kind::String,
            "REST listener address (ip:port); port 0 picks a free port.",
        ),
        spec(
            "shutdown_grace_secs",
            Kind::Integer { min: 0, max: 600 },
            "Seconds a graceful shutdown waits for in-flight requests.",
        ),
        spec(
            "drain_delay_secs",
            Kind::Integer { min: 0, max: 600 },
            "Seconds a shutdown keeps serving with the readiness probe failing before it stops \
             accepting connections.",
        ),
    ];

    fn validate(&self) -> std::result::Result<(), String> {
        let grpc = parse_addr("grpc", &self.grpc).map_err(|e| e.message().to_owned())?;
        let http = parse_addr("http", &self.http).map_err(|e| e.message().to_owned())?;
        if grpc == http && grpc.port() != 0 {
            return Err(format!("grpc and http must differ (both {grpc})"));
        }
        Ok(())
    }
}

/// `[gui]`: the embedded GUI (ADR-027, PD-130).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuiSettings {
    /// Serve the GUI under `/ui` of the REST listener (and redirect `/` there).
    pub enabled: bool,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Settings for GuiSettings {
    const SECTION: &'static str = "gui";
    const FIELDS: &'static [FieldSpec] = &[spec(
        "enabled",
        Kind::Bool,
        "Serve the embedded GUI under /ui of the REST listener; false = /ui is an unknown path.",
    )];
}

/// Default `gc.ttl_secs`: 4 h of MVCC history (ADR-005, storage-engine.md §11).
pub const DEFAULT_GC_TTL_SECS: u64 = 4 * 3600;
/// Smallest `gc.ttl_secs`: 10 min (storage-engine.md §11), far above `txn.max_duration` (60 s),
/// so GC never removes a version a read-write transaction can still read.
const MIN_GC_TTL_SECS: i64 = 600;
/// Largest `gc.ttl_secs`: 30 days.
const MAX_GC_TTL_SECS: i64 = 30 * 86_400;

/// `[gc]`: MVCC garbage collection (storage-engine.md §11, PD-232).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GcSettings {
    /// MVCC history kept, in seconds: versions shadowed for longer are collected, and reads
    /// older than this fail with the retryable `RGN-2007`.
    pub ttl_secs: u64,
}

impl Default for GcSettings {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_GC_TTL_SECS,
        }
    }
}

impl GcSettings {
    /// The TTL as a duration.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_secs)
    }
}

impl Settings for GcSettings {
    const SECTION: &'static str = "gc";
    const FIELDS: &'static [FieldSpec] = &[spec(
        "ttl_secs",
        Kind::Integer {
            min: MIN_GC_TTL_SECS,
            max: MAX_GC_TTL_SECS,
        },
        "Seconds of MVCC history kept (600..2592000): older overwritten or deleted versions \
         are removed, and reads further in the past fail with RGN-2007.",
    )];
}

/// `[security]`: transport policy and key files of the node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecuritySettings {
    /// TLS on the client listeners. Off (plain text) by default on a single node; cluster mode
    /// refuses plain text (ADR-034, security.md §5).
    pub tls: bool,
    /// Directory of the default certificate files; default `<node.data_dir>/certs`.
    pub certs_dir: Option<PathBuf>,
    /// 32-byte key (64 hex digits) sealing cursor continuation tokens (PD-053, PD-054);
    /// default `<node.data_dir>/cursor-token.key`, created owner-only on first start.
    pub cursor_token_key_file: Option<PathBuf>,
    /// First start without `--admin-password-file`: create `admin` with the turnkey password
    /// `admin`, to be changed at first login (ADR-036; written by `rustegon init --turnkey`).
    /// The node refuses to start while that password is unchanged and a listener is not on
    /// loopback.
    pub turnkey_admin: bool,
}

impl SecuritySettings {
    /// The certificate directory.
    #[must_use]
    pub fn certs_dir(&self, data_dir: &Path) -> PathBuf {
        self.certs_dir
            .clone()
            .unwrap_or_else(|| data_dir.join("certs"))
    }

    /// The continuation-token key file.
    #[must_use]
    pub fn cursor_token_key_file(&self, data_dir: &Path) -> PathBuf {
        self.cursor_token_key_file
            .clone()
            .unwrap_or_else(|| data_dir.join(crate::token_key::DEFAULT_FILE))
    }
}

impl Settings for SecuritySettings {
    const SECTION: &'static str = "security";
    const FIELDS: &'static [FieldSpec] = &[
        spec(
            "tls",
            Kind::Bool,
            "TLS on the client listeners (single node; always on in cluster mode).",
        ),
        spec(
            "certs_dir",
            Kind::Path,
            "Directory of ca.crt, node.crt and node.key (default <data_dir>/certs).",
        ),
        spec(
            "cursor_token_key_file",
            Kind::Path,
            "Key file sealing cursor continuation tokens (default <data_dir>/cursor-token.key).",
        ),
        spec(
            "turnkey_admin",
            Kind::Bool,
            "First start: create admin/admin, to be changed at first login; loopback only (ADR-036).",
        ),
    ];

    fn validate(&self) -> std::result::Result<(), String> {
        for (name, path) in [
            ("certs_dir", &self.certs_dir),
            ("cursor_token_key_file", &self.cursor_token_key_file),
        ] {
            if path.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
                return Err(format!("{name} must not be empty"));
            }
        }
        Ok(())
    }
}

/// `[tls]` as configured in `rustegon.toml`. Unlike [`TlsSettings`] every path is optional and
/// defaults to a file in `security.certs_dir`; [`TlsFileSettings::resolve`] produces the
/// `rustegon-net` settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsFileSettings {
    /// PEM certificate chain of this node; default `<certs_dir>/node.crt`.
    pub cert_file: Option<PathBuf>,
    /// PEM private key of this node; default `<certs_dir>/node.key`.
    pub key_file: Option<PathBuf>,
    /// PEM cluster CA; default `<certs_dir>/ca.crt`.
    pub ca_file: Option<PathBuf>,
    /// CA for client certificates on the client ports; default `ca_file`.
    pub client_ca_file: Option<PathBuf>,
    /// Client-certificate policy of the client ports.
    pub client_cert: ClientCertPolicy,
    /// Minimum TLS version.
    pub min_version: TlsMinVersion,
    /// Fallback reload poll, seconds (security.md §5: 1 h).
    pub reload_poll_secs: u64,
    /// Change check of the certificate files, seconds; 0 disables it (PD-054).
    pub watch_secs: u64,
}

impl Default for TlsFileSettings {
    fn default() -> Self {
        Self {
            cert_file: None,
            key_file: None,
            ca_file: None,
            client_ca_file: None,
            client_cert: ClientCertPolicy::None,
            min_version: TlsMinVersion::Tls13,
            reload_poll_secs: rustegon_net::DEFAULT_RELOAD_POLL.as_secs(),
            watch_secs: 10,
        }
    }
}

impl TlsFileSettings {
    /// The `rustegon-net` settings with defaults filled from `certs_dir`.
    ///
    /// # Errors
    /// `RGN-1001` when the result does not validate.
    pub fn resolve(&self, certs_dir: &Path) -> Result<TlsSettings> {
        let or =
            |p: &Option<PathBuf>, name: &str| p.clone().unwrap_or_else(|| certs_dir.join(name));
        let settings = TlsSettings {
            cert_file: or(&self.cert_file, "node.crt"),
            key_file: or(&self.key_file, "node.key"),
            ca_file: or(&self.ca_file, "ca.crt"),
            client_ca_file: self.client_ca_file.clone(),
            client_cert: self.client_cert,
            min_version: self.min_version,
            reload_poll_secs: self.reload_poll_secs,
        };
        settings
            .validate()
            .map_err(|e| Error::new(ErrorCode::InvalidArgument, format!("[tls]: {e}")))?;
        Ok(settings)
    }

    /// Period of the certificate reload loop: the change check when enabled (it subsumes the
    /// slower poll, both re-read the same files), else the poll.
    #[must_use]
    pub fn reload_period(&self) -> Duration {
        let poll = self.reload_poll_secs.max(1);
        let secs = if self.watch_secs == 0 {
            poll
        } else {
            self.watch_secs.min(poll)
        };
        Duration::from_secs(secs)
    }
}

impl Settings for TlsFileSettings {
    const SECTION: &'static str = "tls";
    const FIELDS: &'static [FieldSpec] = &[
        spec(
            "cert_file",
            Kind::Path,
            "PEM certificate chain of this node (default <certs_dir>/node.crt).",
        ),
        spec(
            "key_file",
            Kind::Path,
            "PEM private key of this node (default <certs_dir>/node.key).",
        ),
        spec(
            "ca_file",
            Kind::Path,
            "PEM cluster CA (default <certs_dir>/ca.crt).",
        ),
        spec(
            "client_ca_file",
            Kind::Path,
            "CA verifying client certificates on the client ports (default ca_file).",
        ),
        spec(
            "client_cert",
            Kind::Enum(&["none", "optional"]),
            "Client certificates on the client ports: none or optional (X.509 login).",
        ),
        spec(
            "min_version",
            Kind::Enum(&["1.3", "1.2"]),
            "Minimum TLS version.",
        ),
        spec(
            "reload_poll_secs",
            Kind::Integer {
                min: 1,
                max: 604_800,
            },
            "Fallback certificate reload poll in seconds.",
        ),
        spec(
            "watch_secs",
            Kind::Integer { min: 0, max: 3600 },
            "Seconds between certificate file change checks (0 = off; SIGHUP reloads at once).",
        ),
    ];

    fn validate(&self) -> std::result::Result<(), String> {
        for (name, path) in [
            ("cert_file", &self.cert_file),
            ("key_file", &self.key_file),
            ("ca_file", &self.ca_file),
            ("client_ca_file", &self.client_ca_file),
        ] {
            if path.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
                return Err(format!("{name} must not be empty"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rustegon_common::settings::Sources;

    use super::*;

    fn load(flags: &[&str]) -> Result<rustegon_common::settings::Config> {
        registry()?.load(&Sources {
            flags: flags.iter().map(|f| (*f).to_owned()).collect(),
            ..Sources::default()
        })
    }

    #[test]
    fn tc_ops_001_server_sections_have_safe_defaults() {
        let config = load(&[]).unwrap();
        let listen: ListenSettings = config.section().unwrap();
        assert_eq!(listen.grpc_addr().unwrap().to_string(), "127.0.0.1:7700");
        assert_eq!(listen.http_addr().unwrap().to_string(), "127.0.0.1:7780");
        let security: SecuritySettings = config.section().unwrap();
        assert!(
            !security.tls,
            "plain text is the single-node default (ADR-034)"
        );
        let on: SecuritySettings = load(&["security.tls=true"]).unwrap().section().unwrap();
        assert!(on.tls);
        let gui: GuiSettings = config.section().unwrap();
        assert!(gui.enabled, "the GUI is served by default (ADR-027)");
        let gui: GuiSettings = load(&["gui.enabled=false"]).unwrap().section().unwrap();
        assert!(!gui.enabled);
        let tls: TlsFileSettings = config.section().unwrap();
        let resolved = tls.resolve(&security.certs_dir(Path::new("d"))).unwrap();
        assert_eq!(
            resolved.cert_file,
            Path::new("d").join("certs").join("node.crt")
        );
        assert_eq!(
            resolved.key_file,
            Path::new("d").join("certs").join("node.key")
        );
        assert_eq!(
            resolved.ca_file,
            Path::new("d").join("certs").join("ca.crt")
        );
        assert_eq!(tls.reload_period(), Duration::from_secs(10));
    }

    #[test]
    fn tc_ops_001_server_sections_reject_invalid_values() {
        let err = load(&["listen.grpc=localhost"]).unwrap_err();
        assert!(err.message().contains("not an ip:port"), "{err}");
        let err = load(&["listen.grpc=127.0.0.1:9", "listen.http=127.0.0.1:9"]).unwrap_err();
        assert!(err.message().contains("must differ"), "{err}");
        let err = load(&["tls.min_version=1.1"]).unwrap_err();
        assert!(err.message().contains("expected one of"), "{err}");
        let err = load(&["tls.client_cert=required"]).unwrap_err();
        assert!(err.message().contains("expected one of"), "{err}");
        let err = load(&["tls.reload_poll_secs=0"]).unwrap_err();
        assert!(err.message().contains("outside"), "{err}");
        let err = load(&["security.unknown=1"]).unwrap_err();
        assert!(err.message().contains("unknown setting"), "{err}");
        // PD-232: 4 h of MVCC history by default; never below 10 min (storage-engine.md §11).
        let gc: GcSettings = load(&[]).unwrap().section().unwrap();
        assert_eq!(gc.ttl(), Duration::from_hours(4));
        let err = load(&["gc.ttl_secs=599"]).unwrap_err();
        assert!(err.message().contains("outside"), "{err}");
        let gc: GcSettings = load(&["gc.ttl_secs=600"]).unwrap().section().unwrap();
        assert_eq!(gc.ttl_secs, 600);
    }

    #[test]
    fn tls_reload_period_uses_the_watch_unless_disabled() {
        let tls = TlsFileSettings {
            watch_secs: 0,
            reload_poll_secs: 120,
            ..TlsFileSettings::default()
        };
        assert_eq!(tls.reload_period(), Duration::from_secs(120));
        let tls = TlsFileSettings {
            watch_secs: 300,
            reload_poll_secs: 120,
            ..TlsFileSettings::default()
        };
        assert_eq!(tls.reload_period(), Duration::from_secs(120));
    }
}
