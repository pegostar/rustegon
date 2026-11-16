// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Destination URLs (`--to`, `--from`, `--dest`; backup-restore.md §3, PD-064).
//!
//! Accepted forms:
//! - a plain path: `/var/backups/rustegon`, `D:\backups`, `\\server\share\rustegon` (UNC),
//!   relative paths; local disk or NFS/SMB mount.
//! - `file:///var/backups`, `file:///D:/backups`, `file://server/share/dir` (UNC on Windows),
//!   `file://localhost/var/backups`; `%XX` escapes are decoded.
//! - `s3://bucket/prefix?region=eu-south-1&endpoint=https://minio:9000`: an S3-compatible bucket
//!   ([`crate::S3Destination`]); `region=` and `endpoint=` override the `[backup.s3]` settings.
//!
//! Credentials are never part of a URL (PD-065: they come from a credentials file or the
//! environment), so `user:password@` is rejected rather than silently logged with the URL.

use std::{fmt, path::PathBuf, sync::Arc};

use rustegon_sim_api::FileSystem;

use crate::{
    dest::{
        Destination,
        local::LocalDestination,
        s3::{S3Destination, S3Io, S3Location, S3Settings, process_env},
    },
    error::{BackupError, Result},
};

/// A parsed destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationUrl {
    /// A directory on a local or network file system.
    Local {
        /// Root directory.
        path: PathBuf,
    },
    /// An S3-compatible bucket.
    S3 {
        /// Bucket name.
        bucket: String,
        /// Key prefix inside the bucket, without leading or trailing `/` (may be empty).
        prefix: String,
        /// Region (`region=`), if given.
        region: Option<String>,
        /// Custom endpoint for S3-compatible stores (`endpoint=`, `http(s)://…`), if given.
        endpoint: Option<String>,
    },
}

impl fmt::Display for DestinationUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local { path } => write!(f, "{}", path.display()),
            Self::S3 { bucket, prefix, .. } if prefix.is_empty() => write!(f, "s3://{bucket}"),
            Self::S3 { bucket, prefix, .. } => write!(f, "s3://{bucket}/{prefix}"),
        }
    }
}

impl DestinationUrl {
    /// Parses a destination URL or path (module docs).
    ///
    /// # Errors
    /// [`BackupError::InvalidDestination`] for malformed input;
    /// [`BackupError::UnsupportedDestination`] for a well-formed URL of another scheme
    /// (`azure://`, `gs://`, … follow in M13b).
    pub fn parse(input: &str) -> Result<Self> {
        let invalid = |reason: &str| BackupError::InvalidDestination {
            url: redact_userinfo(input),
            reason: reason.to_owned(),
        };
        if input.trim().is_empty() {
            return Err(invalid("empty destination"));
        }
        let Some((scheme, rest)) = split_scheme(input) else {
            return Ok(Self::Local {
                path: PathBuf::from(input),
            });
        };
        match scheme.to_ascii_lowercase().as_str() {
            "file" => parse_file(rest).map_err(|r| invalid(&r)),
            "s3" => parse_s3(rest).map_err(|r| invalid(&r)),
            _ => Err(BackupError::UnsupportedDestination {
                scheme: scheme.to_owned(),
            }),
        }
    }

    /// Opens the destination with default S3 settings (credentials, region and endpoint from the
    /// `AWS_*` environment variables); see [`open_destination`].
    ///
    /// # Errors
    /// As [`open_destination`].
    pub fn open(&self, fs: Arc<dyn FileSystem>) -> Result<Box<dyn Destination>> {
        open_destination(self, fs, &S3Settings::default())
    }
}

/// Opens a destination: local paths through `fs`; `s3://` with `s3` (the server's
/// `[backup.s3]` settings or the CLI's defaults), production network and clock, and the process
/// environment for credentials not given by a file (PD-065, PD-086).
///
/// # Errors
/// As [`LocalDestination::open`] or [`S3Destination::open`].
pub fn open_destination(
    url: &DestinationUrl,
    fs: Arc<dyn FileSystem>,
    s3: &S3Settings,
) -> Result<Box<dyn Destination>> {
    match url {
        DestinationUrl::Local { path } => Ok(Box::new(LocalDestination::open(fs, path.clone())?)),
        DestinationUrl::S3 {
            bucket,
            prefix,
            region,
            endpoint,
        } => Ok(Box::new(S3Destination::open(
            &S3Location {
                bucket: bucket.clone(),
                prefix: prefix.clone(),
                region: region.clone(),
                endpoint: endpoint.clone(),
            },
            s3,
            S3Io::production(fs),
            &process_env,
        )?)),
    }
}

/// The input with a `user:password@` part replaced, so a rejected URL can be echoed in an error
/// without leaking the secret someone put into it (security.md: secrets are never logged).
fn redact_userinfo(input: &str) -> String {
    let Some((scheme, rest)) = input.split_once("://") else {
        return input.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{scheme}://\u{2039}redacted\u{203a}{}", &rest[at..]),
        None => input.to_owned(),
    }
}

/// `scheme://rest`, where the scheme is RFC 3986 `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
/// One-letter schemes are taken as Windows drive letters (`C://x` is a path, not a URL).
fn split_scheme(input: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = input.split_once("://")?;
    let mut chars = scheme.chars();
    let valid = scheme.len() > 1
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then_some((scheme, rest))
}

/// The part after `file://`: `[host]/path`.
fn parse_file(rest: &str) -> std::result::Result<DestinationUrl, String> {
    if rest.contains(['?', '#']) {
        return Err("file URLs take no query or fragment".into());
    }
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let path = percent_decode(path)?;
    let host = percent_decode(host)?;
    if host.contains('@') {
        return Err("credentials are not allowed in a destination URL".into());
    }
    if path.is_empty() || (path == "/" && host.is_empty()) {
        return Err("missing path".into());
    }
    let local = if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
        local_file_path(&path)
    } else {
        // file://server/share/dir names a UNC path (RFC 8089 appendix E.3).
        if path.len() <= 1 {
            return Err("missing share in a UNC file URL".into());
        }
        unc_path(&host, &path)
    };
    Ok(DestinationUrl::Local { path: local })
}

/// `file:///C:/x` → `C:/x` (drive letter after the root slash), `file:///var/x` → `/var/x`.
fn local_file_path(path: &str) -> PathBuf {
    let bytes = path.as_bytes();
    let drive =
        bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':';
    PathBuf::from(if drive { &path[1..] } else { path })
}

#[cfg(windows)]
fn unc_path(host: &str, path: &str) -> PathBuf {
    PathBuf::from(format!(r"\\{host}{}", path.replace('/', "\\")))
}

#[cfg(not(windows))]
fn unc_path(host: &str, path: &str) -> PathBuf {
    // Elsewhere a remote share is reached through a mount; keep the UNC spelling for messages.
    PathBuf::from(format!("//{host}{path}"))
}

/// The part after `s3://`: `bucket[/prefix][?query]`.
fn parse_s3(rest: &str) -> std::result::Result<DestinationUrl, String> {
    if rest.contains('#') {
        return Err("s3 URLs take no fragment".into());
    }
    let (location, query) = match rest.split_once('?') {
        Some((l, q)) => (l, Some(q)),
        None => (rest, None),
    };
    let (bucket, prefix) = match location.split_once('/') {
        Some((b, p)) => (b, p),
        None => (location, ""),
    };
    if bucket.contains('@') {
        return Err("credentials are not allowed in a destination URL".into());
    }
    validate_bucket(bucket)?;
    let prefix = percent_decode(prefix.trim_matches('/'))?;
    if prefix.split('/').any(|s| s == "." || s == "..") || prefix.contains("//") {
        return Err("prefix contains empty, `.` or `..` segments".into());
    }
    let (mut region, mut endpoint) = (None, None);
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v)?;
        if v.is_empty() {
            return Err(format!("empty value for {k:?}"));
        }
        let slot = match k {
            "region" => &mut region,
            "endpoint" => {
                if !(v.starts_with("https://") || v.starts_with("http://")) {
                    return Err("endpoint must be an http:// or https:// URL".into());
                }
                &mut endpoint
            }
            other => return Err(format!("unknown parameter {other:?}")),
        };
        if slot.replace(v).is_some() {
            return Err(format!("parameter {k:?} given twice"));
        }
    }
    Ok(DestinationUrl::S3 {
        bucket: bucket.to_owned(),
        prefix,
        region,
        endpoint,
    })
}

/// S3 bucket naming rules (3–63 characters of lowercase letters, digits, `.` and `-`, starting
/// and ending with a letter or digit).
fn validate_bucket(bucket: &str) -> std::result::Result<(), String> {
    let ok = (3..=63).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        && bucket
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && bucket
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(format!("invalid bucket name {bucket:?}"))
    }
}

/// Decodes `%XX` escapes (UTF-8).
fn percent_decode(s: &str) -> std::result::Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| format!("invalid percent escape in {s:?}"))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("percent escapes in {s:?} are not UTF-8"))
}

#[cfg(test)]
mod tests {
    use rustegon_common::ErrorCode;

    use super::*;

    fn local(input: &str) -> PathBuf {
        match DestinationUrl::parse(input).unwrap() {
            DestinationUrl::Local { path } => path,
            other @ DestinationUrl::S3 { .. } => panic!("expected local, got {other:?}"),
        }
    }

    #[test]
    fn tc_bkp_009_plain_paths_and_file_urls_are_local() {
        assert_eq!(local("/var/backups"), PathBuf::from("/var/backups"));
        assert_eq!(local(r"D:\backups"), PathBuf::from(r"D:\backups"));
        assert_eq!(local(r"\\nas\share\rg"), PathBuf::from(r"\\nas\share\rg"));
        assert_eq!(local("relative/dir"), PathBuf::from("relative/dir"));
        assert_eq!(local("file:///var/backups"), PathBuf::from("/var/backups"));
        assert_eq!(local("FILE:///var/b%20x"), PathBuf::from("/var/b x"));
        assert_eq!(local("file://localhost/var/b"), PathBuf::from("/var/b"));
        assert_eq!(local("file:///D:/backups"), PathBuf::from("D:/backups"));
        #[cfg(windows)]
        assert_eq!(
            local("file://nas/share/rg"),
            PathBuf::from(r"\\nas\share\rg")
        );
        #[cfg(not(windows))]
        assert_eq!(
            local("file://nas/share/rg"),
            PathBuf::from("//nas/share/rg")
        );
    }

    #[test]
    fn s3_urls_are_parsed() {
        let url = DestinationUrl::parse(
            "s3://acme-backups/rustegon/shop/?region=eu-south-1&endpoint=https%3A%2F%2Fminio%3A9000",
        )
        .unwrap();
        assert_eq!(
            url,
            DestinationUrl::S3 {
                bucket: "acme-backups".into(),
                prefix: "rustegon/shop".into(),
                region: Some("eu-south-1".into()),
                endpoint: Some("https://minio:9000".into()),
            }
        );
        assert_eq!(url.to_string(), "s3://acme-backups/rustegon/shop");
        let bare = DestinationUrl::parse("s3://bucket").unwrap();
        assert_eq!(bare.to_string(), "s3://bucket");
    }

    #[test]
    fn tc_bkp_006_s3_url_opens_an_s3_destination() {
        let url = DestinationUrl::parse(
            "s3://bucket-x/a/b?region=eu-south-1&endpoint=http%3A%2F%2F127.0.0.1%3A9",
        )
        .unwrap();
        let fs = Arc::new(rustegon_sim::SimFileSystem::new());
        fs.create_dir_all(std::path::Path::new("/etc")).unwrap();
        let mut f = fs
            .open(
                std::path::Path::new("/etc/s3.json"),
                rustegon_sim_api::OpenMode::Truncate,
            )
            .unwrap();
        f.append(br#"{"access_key_id":"A","secret_access_key":"S"}"#)
            .unwrap();
        drop(f);
        let settings = S3Settings {
            credentials_file: Some("/etc/s3.json".into()),
            ..S3Settings::default()
        };
        // Opening sends no request, so no server is needed.
        let dest = open_destination(&url, fs, &settings).unwrap();
        assert_eq!(dest.describe(), "s3://bucket-x/a/b");
    }

    #[test]
    fn malformed_destinations_are_rejected() {
        for bad in [
            "",
            "   ",
            "file://",
            "file:///",
            "file:///x?y=1",
            "file://user:pw@host/share",
            "s3://user:secret@bucket/p",
            "s3://Bucket/p",
            "s3://ab/p",
            "s3://bucket/a/../b",
            "s3://bucket/p?region=",
            "s3://bucket/p?foo=bar",
            "s3://bucket/p?region=a&region=b",
            "s3://bucket/p?endpoint=minio:9000",
            "s3://bucket/%zz",
        ] {
            let err = DestinationUrl::parse(bad).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{bad:?}");
            assert!(
                matches!(err, BackupError::InvalidDestination { .. }),
                "{bad:?}: {err}"
            );
        }
        let leaked = DestinationUrl::parse("s3://user:secret@bucket/p").unwrap_err();
        assert!(!leaked.to_string().contains("secret"), "{leaked}");
        assert!(matches!(
            DestinationUrl::parse("azure://container/p"),
            Err(BackupError::UnsupportedDestination { .. })
        ));
    }
}
