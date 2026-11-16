// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Connection strings `rustegon://[user[:password]@]host[:port][,…][/database][?options]`
//! (grammar, options and defaults: `drivers/conformance/connstring.yaml`, DEC-014).
//!
//! ADR-034: TLS is off by default; without an explicit `tls` option, any `tls*` option or
//! `authMechanism=X509` turns it on, and `tls=false` together with either is an error. Errors
//! are argument errors and never quote the string or a decoded value (it may hold a secret).

use std::time::Duration;

use crate::{
    error::{Error, Result},
    settings::{
        AuthMechanism, Credential, ReadConsistency, Settings, WriteConcern, normalize_endpoint,
    },
};

fn err(reason: &str) -> Error {
    Error::argument(format!("invalid connection string: {reason}"))
}

pub(crate) fn parse(uri: &str) -> Result<Settings> {
    const SCHEME: &str = "rustegon://";
    let Some(rest) = uri.strip_prefix(SCHEME) else {
        if uri.starts_with("rustegon+srv://") {
            return Err(err("rustegon+srv is not supported yet"));
        }
        return Err(err("the scheme must be rustegon://"));
    };
    let (rest, options) = match rest.split_once('?') {
        Some((r, o)) => (r, Some(o)),
        None => (rest, None),
    };
    // The user information ends at the first '@'; a second one is a raw '@' in the password
    // (RFC 3986 needs %40) and is refused rather than guessed at.
    let at = rest.find('@');
    if let Some(at) = at
        && rest[at + 1..].contains('@')
    {
        return Err(err(
            "the user information contains a raw '@': percent-encode it as %40",
        ));
    }
    let after_user = at.map_or(0, |a| a + 1);
    let (authority, path) = match rest[after_user..].find('/') {
        Some(slash) => (
            &rest[..after_user + slash],
            Some(&rest[after_user + slash + 1..]),
        ),
        None => (rest, None),
    };
    let mut user = None;
    let mut password = None;
    let hosts = if let Some(at) = at {
        let info = &authority[..at];
        let (u, p) = match info.split_once(':') {
            Some((u, p)) => (u, Some(p)),
            None => (info, None),
        };
        let u = decode(u, "user")?;
        if u.is_empty() {
            return Err(err("empty user name"));
        }
        user = Some(u);
        if let Some(p) = p {
            password = Some(decode(p, "password")?);
        }
        &authority[at + 1..]
    } else {
        authority
    };
    let mut s = Settings::default();
    if hosts.is_empty() {
        return Err(err("at least one host is required"));
    }
    s.endpoints.clear();
    for h in hosts.split(',') {
        if h.contains([' ', '\t']) {
            return Err(err("whitespace in a host"));
        }
        s.endpoints
            .push(normalize_endpoint(h).map_err(|_| err("invalid host"))?);
    }
    if let Some(path) = path
        && !path.is_empty()
    {
        if path.contains('/') {
            return Err(err("the database name cannot contain '/'"));
        }
        s.default_database = Some(decode(path, "database")?);
    }
    apply_options(&mut s, options, user, password)?;
    Ok(s)
}

#[derive(Default)]
struct Seen {
    tls_off: bool,
    other_tls: bool,
    staleness: bool,
    mechanism: Option<String>,
    api_key: Option<String>,
}

fn apply_options(
    s: &mut Settings,
    options: Option<&str>,
    user: Option<String>,
    password: Option<String>,
) -> Result<()> {
    let mut seen_keys = Vec::new();
    let mut seen = Seen::default();
    for pair in options
        .filter(|o| !o.is_empty())
        .into_iter()
        .flat_map(|o| o.split('&'))
    {
        let Some((key, raw)) = pair.split_once('=').filter(|(k, _)| !k.is_empty()) else {
            return Err(err("every option needs a name and a value (name=value)"));
        };
        let value = decode(raw, "option value")?;
        let k = key.to_ascii_lowercase();
        if seen_keys.contains(&k) {
            return Err(err(&format!("option '{key}' is repeated")));
        }
        seen_keys.push(k.clone());
        apply_option(s, &mut seen, key, &k, value)?;
    }
    let x509 = seen.mechanism.as_deref() == Some("X509");
    if seen.tls_off && (seen.other_tls || x509) {
        return Err(err(
            "tls=false contradicts the other tls options or authMechanism=X509",
        ));
    }
    // ADR-034: plain text by default; a tls* option or X.509 (which needs TLS) turns it on.
    if seen.other_tls || x509 {
        s.tls.enabled = true;
    }
    if s.tls.certificate_file.is_some() != s.tls.key_file.is_some() {
        return Err(err("tlsCertificateFile and tlsKeyFile go together"));
    }
    if s.read_consistency == Some(ReadConsistency::BoundedStaleness) && !seen.staleness {
        return Err(err(
            "readConsistency=bounded_staleness needs maxStalenessMs",
        ));
    }
    let mechanism = seen.mechanism.as_deref();
    let api_key = seen.api_key;
    match mechanism {
        None | Some("APIKEY" | "API-KEY") if mechanism.is_some() || api_key.is_some() => {
            let (Some(key), None) = (api_key, &user) else {
                return Err(err("authMechanism=APIKEY needs apiKey=... and no user"));
            };
            s.credential = Some(Credential::api_key(key));
        }
        Some("X509") => {
            if password.is_some() || api_key.is_some() {
                return Err(err("authMechanism=X509 takes no password or apiKey"));
            }
            s.credential = Some(Credential::x509());
        }
        None | Some("SCRAM-SHA-256") => {
            if api_key.is_some() {
                return Err(err("apiKey is only valid with authMechanism=APIKEY"));
            }
            match (user, password) {
                (Some(u), Some(p)) => s.credential = Some(Credential::scram(u, p)),
                (Some(u), None) => s.credential = Some(Credential::scram_without_password(u)),
                // Without a user the string names the mechanism only; the credential is set in
                // code.
                (None, _) => {
                    s.mechanism = mechanism.map(|_| AuthMechanism::ScramSha256);
                }
            }
        }
        Some(_) => return Err(err("unknown authMechanism")),
    }
    Ok(())
}

fn apply_option(
    s: &mut Settings,
    seen: &mut Seen,
    key: &str,
    k: &str,
    value: String,
) -> Result<()> {
    let empty = || err(&format!("option '{key}' is empty"));
    match k {
        "tls" => {
            let b = bool_opt(key, &value)?;
            s.tls.enabled = b;
            seen.tls_off = !b;
        }
        "tlscafile" | "tlsservername" | "tlscertificatefile" | "tlskeyfile" => {
            if value.is_empty() {
                return Err(empty());
            }
            seen.other_tls = true;
            match k {
                "tlscafile" => s.tls.ca_file = Some(value.into()),
                "tlsservername" => s.tls.server_name = Some(value),
                "tlscertificatefile" => s.tls.certificate_file = Some(value.into()),
                _ => s.tls.key_file = Some(value.into()),
            }
        }
        "authmechanism" => seen.mechanism = Some(value.to_ascii_uppercase()),
        "apikey" => {
            if value.is_empty() {
                return Err(empty());
            }
            seen.api_key = Some(value);
        }
        "appname" => {
            if value.is_empty() {
                return Err(empty());
            }
            s.application_name = Some(value);
        }
        "connecttimeoutms" | "operationtimeoutms" | "maxstalenessms" => {
            let d = Duration::from_millis(int_opt(key, &value, 1, i64::from(i32::MAX))?);
            match k {
                "connecttimeoutms" => s.connect_timeout = d,
                "operationtimeoutms" => s.operation_timeout = d,
                _ => {
                    s.max_staleness = Some(d);
                    seen.staleness = true;
                }
            }
        }
        "connectionsperendpoint" => {
            s.connections_per_endpoint = u32::try_from(int_opt(key, &value, 1, 64)?).unwrap_or(1);
        }
        "maxretries" => s.max_retries = u32::try_from(int_opt(key, &value, 0, 10)?).unwrap_or(0),
        "readconsistency" => {
            s.read_consistency = Some(match value.to_ascii_lowercase().as_str() {
                "linearizable" => ReadConsistency::Linearizable,
                "bounded_staleness" => ReadConsistency::BoundedStaleness,
                "follower" => ReadConsistency::Follower,
                _ => return Err(err(&format!("unknown value of option '{key}'"))),
            });
        }
        "writeconcern" => {
            s.write_concern = Some(match value.to_ascii_lowercase().as_str() {
                "majority" => WriteConcern::Majority,
                "all" => WriteConcern::All,
                _ => return Err(err(&format!("unknown value of option '{key}'"))),
            });
        }
        "retryreads" => s.retry_reads = bool_opt(key, &value)?,
        "retrywrites" => s.retry_writes = bool_opt(key, &value)?,
        _ => return Err(err(&format!("unknown option '{key}'"))),
    }
    Ok(())
}

/// Strict UTF-8 percent-decoding; `+` stays a plus sign.
fn decode(s: &str, what: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or_else(|| err(&format!("invalid percent-encoding in the {what}")))?;
                out.push(hex);
                i += 3;
            }
            c if c <= b' ' || c == 0x7F => {
                return Err(err(&format!(
                    "whitespace or a control character in the {what}"
                )));
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out)
        .map_err(|_| err(&format!("the {what} is not valid percent-encoded UTF-8")))
}

fn bool_opt(key: &str, v: &str) -> Result<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(err(&format!("option '{key}' must be true or false"))),
    }
}

fn int_opt(key: &str, v: &str, lo: i64, hi: i64) -> Result<u64> {
    let range = || err(&format!("option '{key}' must be an integer in {lo}..={hi}"));
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(range());
    }
    let n: i64 = v.parse().map_err(|_| range())?;
    if n < lo || n > hi {
        return Err(range());
    }
    u64::try_from(n).map_err(|_| range())
}
