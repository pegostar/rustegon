// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Server-side destination allowlist (`backup.allowed_destinations`; PD-077 owner note, PD-082).
//!
//! # Why
//! Server-side destinations are interpreted by the server process: without a limit, a caller
//! holding the `backup` privilege could make the server list, read (verify) or write (create)
//! backups in any directory the service account can reach, or upload the whole store to a bucket
//! of their choosing. The allowlist turns the `backup` privilege into "back up to the places the
//! operator chose", which is what the privilege was meant to grant.
//!
//! # Rules (PD-082)
//! - An entry is an absolute local directory (plain path or `file://` URL) or an
//!   `s3://bucket[/prefix]` URL (optionally with `endpoint=`). `rustegond` always adds its
//!   default directory `<data_dir>/backups`; with an empty list that is the only destination.
//! - A local destination is allowed when its path equals an entry or lies below it, compared
//!   component by component (so `/srv/backups-evil` is not below `/srv/backups`), ASCII
//!   case-insensitively on Windows. Paths with `..` components are refused outright, so
//!   `/srv/backups/../etc` cannot pass a prefix check (`.` components name the same directory
//!   and are dropped). Symbolic links inside an allowed
//!   directory are not resolved: whoever can create links there controls that directory anyway.
//! - An S3 destination is allowed when the bucket is the entry's and its prefix equals the
//!   entry's or lies below it (segment-wise); the endpoint must match too, and an entry without
//!   `endpoint=` admits only requests without one, so a caller cannot redirect an allowed
//!   bucket name to a server of their own. The region is not part of the match.
//! - A refusal is `RGN-4002 PermissionDenied` with `details.reason = destination_not_allowed`.

use std::path::{Component, Path, PathBuf};

use rustegon_common::{Error, ErrorCode};

use crate::{settings::BackupSettings, url::DestinationUrl};

/// `ErrorDetail.details.reason` of a destination outside the allowlist.
pub const NOT_ALLOWED_REASON: &str = "destination_not_allowed";

/// One allowlist entry (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedDestination {
    /// An absolute local directory and everything below it.
    Local {
        /// Normalised absolute path.
        path: PathBuf,
    },
    /// An S3 bucket (and key prefix) and everything below it.
    S3 {
        /// Bucket.
        bucket: String,
        /// Key prefix without leading/trailing `/` (empty = the whole bucket).
        prefix: String,
        /// Custom endpoint, if the entry names one.
        endpoint: Option<String>,
    },
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, msg)
        .with_detail("setting", "backup.allowed_destinations")
}

/// Rejects relative paths and `.`/`..` components (module docs).
fn checked_local(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    if path
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(format!("{} contains '.' or '..'", path.display()));
    }
    Ok(path.components().collect())
}

/// Component equality: ASCII case-insensitive on Windows (NTFS and SMB compare names that way).
fn same_component(a: Component<'_>, b: Component<'_>) -> bool {
    if cfg!(windows) {
        a.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
    } else {
        a == b
    }
}

fn path_below(path: &Path, root: &Path) -> bool {
    let mut path = path.components();
    for want in root.components() {
        match path.next() {
            Some(have) if same_component(have, want) => {}
            _ => return false,
        }
    }
    true
}

fn prefix_below(prefix: &str, root: &str) -> bool {
    root.is_empty()
        || prefix == root
        || prefix
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

impl AllowedDestination {
    /// Parses an entry of `backup.allowed_destinations`.
    ///
    /// # Errors
    /// `RGN-1001` for a relative path, `.`/`..` components, an unparsable URL or another scheme.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let url = DestinationUrl::parse(text.trim())
            .map_err(|e| invalid(format!("backup.allowed_destinations: {e}")))?;
        match url {
            DestinationUrl::Local { path } => Ok(Self::Local {
                path: checked_local(&path)
                    .map_err(|e| invalid(format!("backup.allowed_destinations: {e}")))?,
            }),
            DestinationUrl::S3 {
                bucket,
                prefix,
                endpoint,
                ..
            } => Ok(Self::S3 {
                bucket,
                prefix,
                endpoint,
            }),
        }
    }

    /// An absolute local directory entry (e.g. the default `<data_dir>/backups`).
    ///
    /// # Errors
    /// `RGN-1001` for a relative path or `.`/`..` components.
    pub fn local(path: &Path) -> Result<Self, Error> {
        Ok(Self::Local {
            path: checked_local(path).map_err(invalid)?,
        })
    }

    /// Whether `url` is this entry or lies below it (module docs).
    #[must_use]
    pub fn covers(&self, url: &DestinationUrl) -> bool {
        match (self, url) {
            (Self::Local { path: root }, DestinationUrl::Local { path }) => {
                checked_local(path).is_ok_and(|p| path_below(&p, root))
            }
            (
                Self::S3 {
                    bucket: b,
                    prefix: p,
                    endpoint: e,
                },
                DestinationUrl::S3 {
                    bucket,
                    prefix,
                    endpoint,
                    ..
                },
            ) => b == bucket && e == endpoint && prefix_below(prefix, p),
            _ => false,
        }
    }
}

impl std::fmt::Display for AllowedDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local { path } => write!(f, "{}", path.display()),
            Self::S3 { bucket, prefix, .. } if prefix.is_empty() => write!(f, "s3://{bucket}"),
            Self::S3 { bucket, prefix, .. } => write!(f, "s3://{bucket}/{prefix}"),
        }
    }
}

/// The allowlist the server checks every request destination against (module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationPolicy {
    allowed: Vec<AllowedDestination>,
}

impl DestinationPolicy {
    /// A policy that refuses every destination (a server without `[backup]` configuration
    /// wiring, e.g. a test harness that does not opt in).
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// A policy allowing exactly `allowed`.
    #[must_use]
    pub fn new(allowed: Vec<AllowedDestination>) -> Self {
        Self { allowed }
    }

    /// The policy of `[backup]` plus the node's default directory `default_dir`
    /// (`<data_dir>/backups`), which is always allowed (PD-082).
    ///
    /// # Errors
    /// `RGN-1001` for an invalid entry or a relative `default_dir`.
    pub fn from_settings(settings: &BackupSettings, default_dir: &Path) -> Result<Self, Error> {
        let mut allowed = vec![AllowedDestination::local(default_dir)?];
        for entry in &settings.allowed_destinations {
            allowed.push(AllowedDestination::parse(entry)?);
        }
        Ok(Self { allowed })
    }

    /// The entries.
    #[must_use]
    pub fn entries(&self) -> &[AllowedDestination] {
        &self.allowed
    }

    /// Checks a request's destination.
    ///
    /// # Errors
    /// `RGN-4002 PermissionDenied` (`details.reason = destination_not_allowed`) when no entry
    /// covers `url`.
    pub fn check(&self, url: &DestinationUrl) -> Result<(), Error> {
        if self.allowed.iter().any(|a| a.covers(url)) {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::PermissionDenied,
            format!(
                "backup destination {url} is not allowed on this server (see \
                 backup.allowed_destinations)"
            ),
        )
        .with_detail("reason", NOT_ALLOWED_REASON)
        .with_detail("field", "destination"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::assert_is_empty)]

    use super::*;

    fn root() -> PathBuf {
        std::env::temp_dir().join("rg-policy")
    }

    fn url(text: &str) -> DestinationUrl {
        DestinationUrl::parse(text).unwrap()
    }

    fn local(p: &Path) -> DestinationUrl {
        DestinationUrl::Local {
            path: p.to_path_buf(),
        }
    }

    /// PD-082 local rules: equal or below by components; siblings sharing a text prefix,
    /// parents, traversal and relative paths are refused; the default directory is allowed.
    #[test]
    fn pd_082_local_destinations_match_by_components() {
        let base = root();
        let settings = BackupSettings {
            allowed_destinations: vec![base.join("allowed").display().to_string()],
            ..BackupSettings::default()
        };
        let policy =
            DestinationPolicy::from_settings(&settings, &base.join("data/backups")).unwrap();
        for ok in [
            base.join("allowed"),
            base.join("allowed").join("nightly"),
            base.join("data").join("backups"),
            base.join("data").join("backups").join("x"),
        ] {
            policy.check(&local(&ok)).unwrap();
        }
        for bad in [
            base.join("allowed-evil"),
            base.clone(),
            base.join("data"),
            base.join("allowed").join("..").join("etc"),
            PathBuf::from("relative"),
        ] {
            let e = policy.check(&local(&bad)).unwrap_err();
            assert_eq!(e.code(), ErrorCode::PermissionDenied, "{}", bad.display());
            assert_eq!(
                e.details().get("reason").map(String::as_str),
                Some(NOT_ALLOWED_REASON)
            );
        }
        assert!(policy.check(&url("s3://bucket")).is_err());
        assert!(DestinationPolicy::deny_all().check(&local(&base)).is_err());
        if cfg!(windows) {
            let upper = PathBuf::from(base.join("ALLOWED").display().to_string().to_uppercase());
            policy.check(&local(&upper)).unwrap();
        }
    }

    /// PD-082 S3 rules: bucket, prefix by segments and endpoint must match.
    #[test]
    fn pd_082_s3_destinations_match_bucket_prefix_and_endpoint() {
        let policy = DestinationPolicy::new(vec![
            AllowedDestination::parse("s3://backups/prod").unwrap(),
            AllowedDestination::parse("s3://lab?endpoint=https://minio:9000").unwrap(),
        ]);
        for ok in [
            "s3://backups/prod",
            "s3://backups/prod/node1",
            "s3://backups/prod?region=eu-south-1",
            "s3://lab?endpoint=https://minio:9000",
            "s3://lab/any/prefix?endpoint=https://minio:9000",
        ] {
            policy.check(&url(ok)).unwrap();
        }
        for bad in [
            "s3://backups",
            "s3://backups/production",
            "s3://backups/prod?endpoint=https://evil.example",
            "s3://other/prod",
            "s3://lab",
            "s3://lab?endpoint=https://evil.example",
        ] {
            assert!(policy.check(&url(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn pd_082_invalid_entries_are_refused() {
        for bad in ["relative", "azure://c/p", "", "file://"] {
            let e = AllowedDestination::parse(bad).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
        }
        let traversal = root().join("..").join("x");
        assert!(AllowedDestination::parse(&traversal.display().to_string()).is_err());
        assert_eq!(
            AllowedDestination::parse("s3://bkt/p").unwrap().to_string(),
            "s3://bkt/p"
        );
    }
}
