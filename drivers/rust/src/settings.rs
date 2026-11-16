// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Client settings and their builder (rust-driver.md §3, connstring.yaml defaults, ADR-034).

use std::{fmt, path::PathBuf, time::Duration};

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Driver version (semantic versioning; driver major = protocol major).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Driver name sent in `ClientInfo` and the user agent.
pub const DRIVER_NAME: &str = "rustegon-rust";
/// Default gRPC port.
pub const DEFAULT_PORT: u16 = 7700;

/// Authentication mechanism (protocol.md §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMechanism {
    /// SCRAM-SHA-256 with `SASLprep`, no channel binding (PD-074).
    ScramSha256,
    /// TLS client certificate.
    X509,
    /// API key sent as `authorization: ApiKey <key>`.
    ApiKey,
}

impl AuthMechanism {
    /// The connection-string name (`SCRAM-SHA-256`, `X509`, `APIKEY`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::X509 => "X509",
            Self::ApiKey => "APIKEY",
        }
    }
}

/// Credentials of a client. `Debug` never shows the password or key.
#[derive(Clone)]
pub struct Credential {
    mechanism: AuthMechanism,
    user: Option<String>,
    secret: Option<Zeroizing<String>>,
}

impl Credential {
    /// SCRAM-SHA-256 user and password.
    pub fn scram(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            mechanism: AuthMechanism::ScramSha256,
            user: Some(user.into()),
            secret: Some(Zeroizing::new(password.into())),
        }
    }

    /// An API key (`rgn_…`).
    pub fn api_key(key: impl Into<String>) -> Self {
        Self {
            mechanism: AuthMechanism::ApiKey,
            user: None,
            secret: Some(Zeroizing::new(key.into())),
        }
    }

    /// X.509: the TLS client certificate of [`TlsSettings`] authenticates the client.
    #[must_use]
    pub fn x509() -> Self {
        Self {
            mechanism: AuthMechanism::X509,
            user: None,
            secret: None,
        }
    }

    pub(crate) fn scram_without_password(user: String) -> Self {
        Self {
            mechanism: AuthMechanism::ScramSha256,
            user: Some(user),
            secret: None,
        }
    }

    /// The mechanism.
    #[must_use]
    pub fn mechanism(&self) -> AuthMechanism {
        self.mechanism
    }

    /// The user (SCRAM only).
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// The password or API key. A secret: never log it.
    #[must_use]
    pub fn secret(&self) -> Option<&str> {
        self.secret.as_ref().map(|s| s.as_str())
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.user {
            Some(u) => write!(f, "{}({u}, <redacted>)", self.mechanism.name()),
            None => write!(f, "{}(<redacted>)", self.mechanism.name()),
        }
    }
}

/// TLS settings. ADR-034: off by default; a CA file, server name or client certificate (or an
/// X.509 credential) turns it on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsSettings {
    /// Explicit switch (the implications above apply on top of it).
    pub enabled: bool,
    /// CA certificate (PEM) verifying the server; operating-system roots when absent.
    pub ca_file: Option<PathBuf>,
    /// Name verified in the server certificate (default: the endpoint host).
    pub server_name: Option<String>,
    /// Client certificate chain (PEM), for X.509 authentication.
    pub certificate_file: Option<PathBuf>,
    /// Key of the client certificate (PEM).
    pub key_file: Option<PathBuf>,
}

/// Read consistency level (consistency.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadConsistency {
    /// Linearizable reads (server default).
    Linearizable,
    /// Reads at most `max_staleness` old (needs a bound).
    BoundedStaleness,
    /// Any replica.
    Follower,
}

/// Write concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteConcern {
    /// Majority of the replicas (server default).
    Majority,
    /// Every replica.
    All,
}

/// Client settings (connstring.yaml `defaults`). Build them with [`Settings::builder`] or
/// [`Settings::from_connection_string`]; [`crate::Client::new`] validates them again.
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Settings {
    /// Seed endpoints `host:port` (normalized: lowercase host, default port, IPv6 in brackets).
    pub endpoints: Vec<String>,
    /// Credentials (none: unauthenticated, only useful for `get_server_info`).
    pub credential: Option<Credential>,
    /// TLS.
    pub tls: TlsSettings,
    /// Database of `Client::default_database` and of transactions' collection names.
    pub default_database: Option<String>,
    /// Application name sent at login (`ClientInfo.application`).
    pub application_name: Option<String>,
    /// TCP + TLS connect timeout.
    pub connect_timeout: Duration,
    /// Deadline of one operation, every attempt and backoff included (PD-097).
    pub operation_timeout: Duration,
    /// Default read consistency (server default when `None`).
    pub read_consistency: Option<ReadConsistency>,
    /// Staleness bound of `BoundedStaleness` / `Follower`.
    pub max_staleness: Option<Duration>,
    /// Default write concern (server default when `None`).
    pub write_concern: Option<WriteConcern>,
    /// Retry reads on retryable errors.
    pub retry_reads: bool,
    /// Retry writes on retryable errors (same `rgn-request-id` on every attempt).
    pub retry_writes: bool,
    /// Retries per operation (0..=10).
    pub max_retries: u32,
    /// HTTP/2 connections per endpoint (1..=64).
    pub connections_per_endpoint: u32,
    /// Accept a login whose account must change its password (only `change_password` works).
    pub allow_password_change_only: bool,
    /// Mechanism named by a connection string without credentials (set in code later).
    pub(crate) mechanism: Option<AuthMechanism>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            endpoints: vec![format!("localhost:{DEFAULT_PORT}")],
            credential: None,
            tls: TlsSettings::default(),
            default_database: None,
            application_name: None,
            connect_timeout: Duration::from_secs(10),
            operation_timeout: Duration::from_secs(30),
            read_consistency: None,
            max_staleness: None,
            write_concern: None,
            retry_reads: true,
            retry_writes: true,
            max_retries: 1,
            connections_per_endpoint: 2,
            allow_password_change_only: false,
            mechanism: None,
        }
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("endpoints", &self.endpoints)
            .field("credential", &self.credential)
            .field("tls", &self.tls_enabled())
            .field("default_database", &self.default_database)
            .finish_non_exhaustive()
    }
}

impl Settings {
    /// A builder starting from the defaults.
    #[must_use]
    pub fn builder() -> SettingsBuilder {
        SettingsBuilder {
            settings: Self::default(),
        }
    }

    /// Parses `rustegon://[user[:password]@]host[:port][,…][/database][?options]`
    /// (connstring.yaml, DEC-014). No I/O; errors never quote the string.
    pub fn from_connection_string(uri: &str) -> Result<Self> {
        crate::connstring::parse(uri)
    }

    /// Whether the client uses TLS (ADR-034 implications included).
    #[must_use]
    pub fn tls_enabled(&self) -> bool {
        let t = &self.tls;
        t.enabled
            || t.ca_file.is_some()
            || t.server_name.is_some()
            || t.certificate_file.is_some()
            || t.key_file.is_some()
            || self
                .credential
                .as_ref()
                .is_some_and(|c| c.mechanism == AuthMechanism::X509)
    }

    /// The authentication mechanism (of the credential, or named by the connection string).
    #[must_use]
    pub fn auth_mechanism(&self) -> Option<AuthMechanism> {
        self.credential
            .as_ref()
            .map(Credential::mechanism)
            .or(self.mechanism)
    }

    /// Checks every rule and normalizes the endpoints.
    pub(crate) fn validate(&mut self) -> Result<()> {
        if self.endpoints.is_empty() {
            return Err(Error::argument("at least one endpoint is required"));
        }
        for e in &mut self.endpoints {
            *e = normalize_endpoint(e)?;
        }
        if self.connect_timeout.is_zero() || self.operation_timeout.is_zero() {
            return Err(Error::argument("timeouts must be positive"));
        }
        if self.max_retries > 10 {
            return Err(Error::argument("max_retries must be in 0..=10"));
        }
        if !(1..=64).contains(&self.connections_per_endpoint) {
            return Err(Error::argument(
                "connections_per_endpoint must be in 1..=64",
            ));
        }
        if self.read_consistency == Some(ReadConsistency::BoundedStaleness)
            && self.max_staleness.is_none_or(|d| d.is_zero())
        {
            return Err(Error::argument("BoundedStaleness needs max_staleness"));
        }
        if self.tls.certificate_file.is_some() != self.tls.key_file.is_some() {
            return Err(Error::argument(
                "the TLS certificate file and key file go together",
            ));
        }
        if let Some(c) = &self.credential {
            match c.mechanism {
                AuthMechanism::ScramSha256 => {
                    if c.user.as_deref().is_none_or(str::is_empty) {
                        return Err(Error::argument("a SCRAM credential needs a user"));
                    }
                    if c.secret.is_none() {
                        return Err(Error::argument(
                            "the SCRAM credential has no password: set one with Credential::scram",
                        ));
                    }
                }
                AuthMechanism::ApiKey => {
                    if c.secret().is_none_or(str::is_empty) {
                        return Err(Error::argument("an API key credential needs a key"));
                    }
                }
                AuthMechanism::X509 => {
                    if self.tls.certificate_file.is_none() {
                        return Err(Error::argument(
                            "an X.509 credential needs the TLS certificate and key files",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Builder of [`Settings`]; [`build`](Self::build) validates.
#[derive(Debug, Clone)]
pub struct SettingsBuilder {
    settings: Settings,
}

impl SettingsBuilder {
    /// Starts from a connection string (its values can then be overridden).
    pub fn connection_string(uri: &str) -> Result<Self> {
        Ok(Self {
            settings: Settings::from_connection_string(uri)?,
        })
    }

    /// Seed endpoints `host[:port]`.
    #[must_use]
    pub fn endpoints<I, S>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.settings.endpoints = endpoints.into_iter().map(Into::into).collect();
        self
    }

    /// Credentials.
    #[must_use]
    pub fn credential(mut self, credential: Credential) -> Self {
        self.settings.credential = Some(credential);
        self
    }

    /// TLS settings.
    #[must_use]
    pub fn tls(mut self, tls: TlsSettings) -> Self {
        self.settings.tls = tls;
        self
    }

    /// Default database.
    #[must_use]
    pub fn default_database(mut self, name: impl Into<String>) -> Self {
        self.settings.default_database = Some(name.into());
        self
    }

    /// Application name.
    #[must_use]
    pub fn application_name(mut self, name: impl Into<String>) -> Self {
        self.settings.application_name = Some(name.into());
        self
    }

    /// Connect timeout.
    #[must_use]
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.settings.connect_timeout = d;
        self
    }

    /// Operation timeout.
    #[must_use]
    pub fn operation_timeout(mut self, d: Duration) -> Self {
        self.settings.operation_timeout = d;
        self
    }

    /// Default read consistency and its staleness bound.
    #[must_use]
    pub fn read_consistency(
        mut self,
        level: ReadConsistency,
        max_staleness: Option<Duration>,
    ) -> Self {
        self.settings.read_consistency = Some(level);
        self.settings.max_staleness = max_staleness;
        self
    }

    /// Default write concern.
    #[must_use]
    pub fn write_concern(mut self, wc: WriteConcern) -> Self {
        self.settings.write_concern = Some(wc);
        self
    }

    /// Retry reads.
    #[must_use]
    pub fn retry_reads(mut self, on: bool) -> Self {
        self.settings.retry_reads = on;
        self
    }

    /// Retry writes.
    #[must_use]
    pub fn retry_writes(mut self, on: bool) -> Self {
        self.settings.retry_writes = on;
        self
    }

    /// Retries per operation.
    #[must_use]
    pub fn max_retries(mut self, n: u32) -> Self {
        self.settings.max_retries = n;
        self
    }

    /// Connections per endpoint.
    #[must_use]
    pub fn connections_per_endpoint(mut self, n: u32) -> Self {
        self.settings.connections_per_endpoint = n;
        self
    }

    /// Accept a login that must change its password.
    #[must_use]
    pub fn allow_password_change_only(mut self, on: bool) -> Self {
        self.settings.allow_password_change_only = on;
        self
    }

    /// Validated settings.
    pub fn build(mut self) -> Result<Settings> {
        self.settings.validate()?;
        Ok(self.settings)
    }
}

/// Normalizes `host[:port]` / `[ipv6][:port]` to `host:port` (lowercase host, default port).
pub(crate) fn normalize_endpoint(text: &str) -> Result<String> {
    let bad = |why: &str| Error::argument(format!("invalid endpoint: {why}"));
    let (host, port, ipv6) = if let Some(rest) = text.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| bad("unterminated IPv6 literal"))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return Err(bad("text after the IPv6 literal")),
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(bad("invalid IPv6 literal"));
        }
        (host.to_owned(), port, true)
    } else {
        let (host, port) = match text.rfind(':') {
            Some(i) => (&text[..i], Some(&text[i + 1..])),
            None => (text, None),
        };
        if host.contains(':') {
            return Err(bad("an IPv6 address needs brackets"));
        }
        if host.is_empty() {
            return Err(bad("empty host"));
        }
        if !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        {
            return Err(bad("invalid character in a host name"));
        }
        (host.to_ascii_lowercase(), port, false)
    };
    let port = match port {
        None => DEFAULT_PORT,
        Some("") => return Err(bad("empty port")),
        Some(p) => {
            if !p.bytes().all(|b| b.is_ascii_digit()) || p.len() > 5 {
                return Err(bad("the port must be numeric"));
            }
            match p.parse::<u16>() {
                Ok(n) if n > 0 => n,
                _ => return Err(bad("the port must be in 1..=65535")),
            }
        }
    };
    Ok(if ipv6 {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

/// Splits a normalized endpoint into host (without brackets) and port.
pub(crate) fn split_endpoint(e: &str) -> (&str, u16) {
    let (h, p) = e.rsplit_once(':').unwrap_or((e, ""));
    (
        h.trim_start_matches('[').trim_end_matches(']'),
        p.parse().unwrap_or(DEFAULT_PORT),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_drv_rs_005_endpoint_normalization() {
        assert_eq!(
            normalize_endpoint("DB1.Example.COM").unwrap(),
            "db1.example.com:7700"
        );
        assert_eq!(normalize_endpoint("[::1]:7702").unwrap(), "[::1]:7702");
        assert!(normalize_endpoint("::1:7700").is_err());
        assert!(normalize_endpoint("h:0").is_err());
        assert!(normalize_endpoint("h:65536").is_err());
        assert_eq!(split_endpoint("[::1]:7702"), ("::1", 7702));
    }

    #[test]
    fn tc_drv_rs_005_tls_implication_and_redaction() {
        let mut s = Settings::default();
        assert!(!s.tls_enabled());
        s.tls.ca_file = Some("ca.crt".into());
        assert!(s.tls_enabled());
        let c = Credential::scram("u", "secret-pw");
        assert!(!format!("{c:?}").contains("secret-pw"));
        assert!(Settings::builder().max_retries(11).build().is_err());
    }
}
