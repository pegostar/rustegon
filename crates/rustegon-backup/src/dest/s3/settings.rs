// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! S3 destination settings and credentials (PD-065, PD-086; security.md: secrets never in an
//! RPC, never logged).
//!
//! [`S3Settings`] is the server-side `[backup.s3]` table (wired into `[backup]` by the daemon) and
//! the CLI's source for offline commands. Everything a URL can carry (`region=`, `endpoint=`)
//! overrides the setting; credentials can never come from a URL.
//!
//! # Credentials (PD-086)
//! 1. `credentials_file`, when set: a JSON file `{"access_key_id": "â€¦", "secret_access_key": "â€¦",
//!    "session_token": "â€¦"}` (session token optional). The AWS CLI spellings `AccessKeyId`,
//!    `SecretAccessKey`, `SessionToken` (the output of `aws sts assume-role`) are accepted too. A
//!    configured file that cannot be read is an error, never a silent fallback.
//! 2. Otherwise the standard environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
//!    and optionally `AWS_SESSION_TOKEN`.
//!
//! Credentials are read when a destination is opened, so a rotated file is picked up by the next
//! operation without a restart.

use std::path::{Path, PathBuf};

use rustegon_common::Redacted;
use rustegon_sim_api::{FileSystem, OpenMode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{BackupError, Result};

/// Default multipart part size (MiB). Also the single-PUT threshold.
pub const DEFAULT_PART_SIZE_MIB: u32 = 16;
/// Smallest part size S3 accepts for all parts but the last (MiB).
pub const MIN_PART_SIZE_MIB: u32 = 5;
/// Largest part size accepted here (MiB): S3 allows 5 GiB, but a part is buffered in memory to
/// make it retryable and to hash it for the signature.
pub const MAX_PART_SIZE_MIB: u32 = 512;

/// Settings of S3-compatible destinations (`[backup.s3]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct S3Settings {
    /// JSON credentials file (module docs); `None` = the `AWS_*` environment variables.
    pub credentials_file: Option<PathBuf>,
    /// Endpoint `http(s)://host[:port]` of an S3-compatible store (`MinIO`, Ceph RGW, â€¦); the URL's
    /// `endpoint=` overrides it. `None`: `AWS_ENDPOINT_URL_S3`, `AWS_ENDPOINT_URL`, else AWS
    /// (`https://s3.<region>.amazonaws.com`). A plain `http://` endpoint is used only when
    /// configured explicitly.
    pub endpoint: Option<String>,
    /// Region for signing; the URL's `region=` overrides it. `None`: `AWS_REGION`,
    /// `AWS_DEFAULT_REGION`, else `us-east-1`.
    pub region: Option<String>,
    /// Path-style addressing (`https://host/bucket/key`) instead of virtual-hosted
    /// (`https://bucket.host/key`). `None` = path-style for a custom endpoint and for bucket names
    /// with dots (their virtual host would not match the TLS wildcard certificate), else
    /// virtual-hosted.
    pub force_path_style: Option<bool>,
    /// PEM CA bundle that replaces the operating-system trust store (private CA, self-signed
    /// `MinIO`). `None` = the platform roots.
    pub ca_file: Option<PathBuf>,
    /// Multipart part size in MiB (5â€“512); objects up to this size are sent with one PUT.
    pub part_size_mib: u32,
    /// Attempts per request, including the first, for transient failures (connection errors,
    /// timeouts, HTTP 5xx, 429, `SlowDown`, `RequestTimeout`); at least 1.
    pub max_attempts: u32,
    /// TCP + TLS connect timeout (seconds).
    pub connect_timeout_secs: u64,
    /// Timeout of one request including its body transfer (seconds).
    pub request_timeout_secs: u64,
}

impl Default for S3Settings {
    fn default() -> Self {
        Self {
            credentials_file: None,
            endpoint: None,
            region: None,
            force_path_style: None,
            ca_file: None,
            part_size_mib: DEFAULT_PART_SIZE_MIB,
            max_attempts: 5,
            connect_timeout_secs: 10,
            request_timeout_secs: 300,
        }
    }
}

impl S3Settings {
    /// Checks the numeric bounds.
    ///
    /// # Errors
    /// [`BackupError::InvalidArgument`] naming the offending setting.
    pub fn validate(&self) -> Result<()> {
        let bad = |what: &str| Err(BackupError::InvalidArgument(format!("backup.s3.{what}")));
        if !(MIN_PART_SIZE_MIB..=MAX_PART_SIZE_MIB).contains(&self.part_size_mib) {
            return bad("part_size_mib must be between 5 and 512");
        }
        if self.max_attempts == 0 || self.max_attempts > 20 {
            return bad("max_attempts must be between 1 and 20");
        }
        if self.connect_timeout_secs == 0 || self.request_timeout_secs == 0 {
            return bad("timeouts must be at least 1 second");
        }
        Ok(())
    }
}

/// Resolved S3 credentials. Secrets are wrapped so that `Debug` never shows them.
#[derive(Debug, Clone)]
pub struct S3Credentials {
    /// Access key id (not secret, but kept out of messages anyway).
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: Redacted<Zeroizing<String>>,
    /// STS session token, if any.
    pub session_token: Option<Redacted<Zeroizing<String>>>,
}

/// Upper bound of a credentials file: a real one is well below 4 KiB.
const MAX_CREDENTIALS_FILE: u64 = 64 << 10;

#[derive(Deserialize)]
struct CredentialsFile {
    #[serde(alias = "AccessKeyId")]
    access_key_id: String,
    #[serde(alias = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(default, alias = "SessionToken")]
    session_token: Option<String>,
}

impl S3Credentials {
    /// Resolves the credentials (module docs): the file of `settings` if configured, else the
    /// environment as seen through `env`.
    ///
    /// # Errors
    /// [`BackupError::Local`] when the configured file cannot be read;
    /// [`BackupError::InvalidArgument`] when it is malformed or no credentials are found. Errors
    /// never contain secret values.
    pub fn resolve(
        settings: &S3Settings,
        fs: &dyn FileSystem,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        if let Some(path) = &settings.credentials_file {
            return Self::from_file(fs, path);
        }
        let get = |name: &str| env(name).filter(|v| !v.is_empty());
        match (get("AWS_ACCESS_KEY_ID"), get("AWS_SECRET_ACCESS_KEY")) {
            (Some(id), Some(secret)) => Ok(Self {
                access_key_id: id,
                secret_access_key: Redacted::new(Zeroizing::new(secret)),
                session_token: get("AWS_SESSION_TOKEN").map(|t| Redacted::new(Zeroizing::new(t))),
            }),
            _ => Err(BackupError::InvalidArgument(
                "no S3 credentials: set backup.s3.credentials_file or the environment variables \
                 AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
                    .into(),
            )),
        }
    }

    /// Reads a JSON credentials file through `fs`.
    ///
    /// # Errors
    /// As [`Self::resolve`].
    pub fn from_file(fs: &dyn FileSystem, path: &Path) -> Result<Self> {
        let file = fs
            .open(path, OpenMode::Read)
            .map_err(|e| BackupError::local("open S3 credentials file", path, e))?;
        let size = file
            .size()
            .map_err(|e| BackupError::local("stat S3 credentials file", path, e))?;
        if size > MAX_CREDENTIALS_FILE {
            return Err(BackupError::InvalidArgument(format!(
                "S3 credentials file {} is larger than 64 KiB",
                path.display()
            )));
        }
        let len = usize::try_from(size)
            .map_err(|_| BackupError::InvalidArgument("S3 credentials file too large".into()))?;
        let mut buf = Zeroizing::new(vec![0u8; len]);
        file.read_exact_at(&mut buf, 0)
            .map_err(|e| BackupError::local("read S3 credentials file", path, e))?;
        // serde_json's error text quotes at most a position, never the input, so it is safe to
        // pass on; the file's content stays out of the message.
        let parsed: CredentialsFile = serde_json::from_slice(&buf).map_err(|e| {
            BackupError::InvalidArgument(format!(
                "S3 credentials file {} is not valid: {}",
                path.display(),
                e.classify_reason()
            ))
        })?;
        if parsed.access_key_id.is_empty() || parsed.secret_access_key.is_empty() {
            return Err(BackupError::InvalidArgument(format!(
                "S3 credentials file {} has an empty access key id or secret",
                path.display()
            )));
        }
        Ok(Self {
            access_key_id: parsed.access_key_id,
            // Moved, not copied, into zeroizing wrappers.
            secret_access_key: Redacted::new(Zeroizing::new(parsed.secret_access_key)),
            session_token: parsed
                .session_token
                .filter(|t| !t.is_empty())
                .map(|t| Redacted::new(Zeroizing::new(t))),
        })
    }
}

/// Short reason of a JSON error without the line/column noise (and without input excerpts).
trait ClassifyReason {
    fn classify_reason(&self) -> &'static str;
}

impl ClassifyReason for serde_json::Error {
    fn classify_reason(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "I/O error",
            serde_json::error::Category::Syntax => "malformed JSON",
            serde_json::error::Category::Data => {
                "expected access_key_id, secret_access_key and optional session_token strings"
            }
            serde_json::error::Category::Eof => "truncated JSON",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustegon_sim::SimFileSystem;

    use super::*;

    fn write(fs: &SimFileSystem, path: &str, content: &[u8]) {
        let mut f = fs.open(Path::new(path), OpenMode::Truncate).unwrap();
        f.append(content).unwrap();
        f.sync_data().unwrap();
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn tc_bkp_006_credentials_from_file_and_env() {
        let fs = SimFileSystem::new();
        fs.create_dir_all(Path::new("/etc")).unwrap();
        write(
            &fs,
            "/etc/s3.json",
            br#"{"access_key_id":"AKID","secret_access_key":"s3cr3t-value","session_token":"tok"}"#,
        );
        let settings = S3Settings {
            credentials_file: Some("/etc/s3.json".into()),
            ..S3Settings::default()
        };
        let creds = S3Credentials::resolve(&settings, &fs, &no_env).unwrap();
        assert_eq!(creds.access_key_id, "AKID");
        assert_eq!(creds.secret_access_key.expose().as_str(), "s3cr3t-value");
        assert!(creds.session_token.is_some());
        // Secrets never reach Debug output.
        let debug = format!("{creds:?}");
        assert!(
            !debug.contains("s3cr3t") && !debug.contains("tok\""),
            "{debug}"
        );

        // AWS CLI spelling.
        write(
            &fs,
            "/etc/sts.json",
            br#"{"AccessKeyId":"ASIA","SecretAccessKey":"x","SessionToken":"y","Expiration":"z"}"#,
        );
        let sts = S3Credentials::from_file(&fs, Path::new("/etc/sts.json"));
        // Unknown fields are allowed (STS output has `Expiration`).
        assert_eq!(sts.unwrap().access_key_id, "ASIA");

        let env = |name: &str| match name {
            "AWS_ACCESS_KEY_ID" => Some("ENVID".to_owned()),
            "AWS_SECRET_ACCESS_KEY" => Some("envsecret".to_owned()),
            _ => None,
        };
        let creds = S3Credentials::resolve(&S3Settings::default(), &fs, &env).unwrap();
        assert_eq!(creds.access_key_id, "ENVID");
        assert!(creds.session_token.is_none());
    }

    #[test]
    fn tc_bkp_006_bad_credentials_are_reported_without_secrets() {
        let fs = Arc::new(SimFileSystem::new());
        let err = S3Credentials::resolve(&S3Settings::default(), fs.as_ref(), &no_env).unwrap_err();
        assert!(err.to_string().contains("AWS_ACCESS_KEY_ID"), "{err}");

        fs.create_dir_all(Path::new("/etc")).unwrap();
        write(
            &fs,
            "/etc/bad.json",
            br#"{"access_key_id":"A","secret_access_key":"leakme""#,
        );
        let err = S3Credentials::from_file(fs.as_ref(), Path::new("/etc/bad.json")).unwrap_err();
        assert!(!err.to_string().contains("leakme"), "{err}");
        write(
            &fs,
            "/etc/num.json",
            br#"{"access_key_id":"A","secret_access_key":12345678}"#,
        );
        let err = S3Credentials::from_file(fs.as_ref(), Path::new("/etc/num.json")).unwrap_err();
        assert!(!err.to_string().contains("12345678"), "{err}");

        let missing = S3Settings {
            credentials_file: Some("/etc/missing.json".into()),
            ..S3Settings::default()
        };
        // A configured but missing file is an error even when the environment has credentials.
        let env = |_: &str| Some("x".to_owned());
        assert!(S3Credentials::resolve(&missing, fs.as_ref(), &env).is_err());
    }

    #[test]
    fn s3_settings_defaults_and_bounds() {
        let s: S3Settings = toml_like_default();
        assert_eq!(s, S3Settings::default());
        s.validate().unwrap();
        for bad in [
            S3Settings {
                part_size_mib: 4,
                ..S3Settings::default()
            },
            S3Settings {
                max_attempts: 0,
                ..S3Settings::default()
            },
            S3Settings {
                request_timeout_secs: 0,
                ..S3Settings::default()
            },
        ] {
            assert!(bad.validate().is_err());
        }
        assert!(serde_json::from_str::<S3Settings>(r#"{"secret":"x"}"#).is_err());
    }

    fn toml_like_default() -> S3Settings {
        serde_json::from_str("{}").unwrap()
    }
}
