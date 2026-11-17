// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Session tokens (security.md §2.1, FR-SEC-001, TC-SEC-007; PD-047).
//!
//! - **Token**: 32 bytes from the CSPRNG, base64url without padding (43 characters). Only
//!   `BLAKE3(token bytes)` is stored (key `0x02 'e' 0x01 hash`), plus a by-user index entry
//!   (`0x02 'e' 0x02 user 0x00 hash`) so that all sessions of a user can be revoked with one
//!   prefix scan. A read of the system keyspace (backup, dump) yields no usable token; 256
//!   random bits make guessing pointless, so a fast hash suffices (no Argon2).
//! - **Session record format 1** (fixtures `tests/fixtures/formats/session/1/`):
//!   ```text
//!   session { session_format: 1, type: "session", user, kind: "gui"|"driver", created_at,
//!             last_seen, expires_at, credential_epoch: int64, client_info: string }
//!   ```
//! - **Validation** ([`validate_session`]): unknown token, absolute expiry (`expires_at`), idle
//!   expiry (`last_seen` + idle timeout of the kind), missing or disabled user, or a credential
//!   epoch different from the user's → `RGN-4005 SessionExpired` (drivers re-authenticate
//!   transparently, security.md §2.1), and the stale record is deleted in the same transaction.
//!   `last_seen` is rewritten only when it is at least [`LAST_SEEN_GRANULARITY`] old, so a
//!   busy session costs one write per minute rather than one per request; idle expiry is
//!   therefore precise to that granularity.
//! - The functions read and write through the caller's transaction ([`SystemTxn`]); the caller
//!   commits it (validation may write: refresh and cleanup).

use std::time::{Duration, SystemTime};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustegon_catalog::{CatalogRead, Mutation};
use rustegon_doc::{Document, Value};
use rustegon_sim_api::Rng;
use zeroize::Zeroize;

use crate::authn::{
    AuthMethod, Principal, SecretString,
    codec::{self, Fields},
    error::{AuthnError, AuthnResult},
    secret,
    settings::AuthnSettings,
    store::{SystemTxn, session_key, session_prefix, session_user_key, session_user_prefix},
    users::{UserRecord, UserState, get_user},
};

/// Version of the session record format.
pub const SESSION_FORMAT: i64 = 1;
/// Random bytes of a token.
pub const TOKEN_BYTES: usize = 32;
/// Minimum age of `last_seen` before it is rewritten (module docs).
pub const LAST_SEEN_GRANULARITY: Duration = Duration::from_secs(60);
/// Longest stored `client_info` in bytes (longer input is truncated: it is informational).
pub const MAX_CLIENT_INFO: usize = 256;
const WHAT: &str = "session record";
const TYPE: &str = "session";
const FIELDS: &[&str] = &[
    "session_format",
    "type",
    "user",
    "kind",
    "created_at",
    "last_seen",
    "expires_at",
    "credential_epoch",
    "client_info",
];

/// The client kind, which selects the idle timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// Browser GUI (30 min idle by default).
    Gui,
    /// Driver or CLI (12 h idle by default).
    Driver,
}

impl SessionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Gui => "gui",
            Self::Driver => "driver",
        }
    }

    /// The idle timeout of this kind.
    #[must_use]
    pub const fn idle_timeout(self, settings: &AuthnSettings) -> Duration {
        Duration::from_secs(match self {
            Self::Gui => settings.session_idle_timeout_gui_secs,
            Self::Driver => settings.session_idle_timeout_driver_secs,
        })
    }
}

/// A stored session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Owner.
    pub user: String,
    /// Client kind.
    pub kind: SessionKind,
    /// Creation time.
    pub created_at: SystemTime,
    /// Last activity (refreshed with [`LAST_SEEN_GRANULARITY`]).
    pub last_seen: SystemTime,
    /// Absolute expiry.
    pub expires_at: SystemTime,
    /// The owner's credential epoch at creation.
    pub credential_epoch: u64,
    /// Free-form client description (driver name/version, user agent), truncated.
    pub client_info: String,
}

/// Encodes a session record (format 1).
///
/// # Errors
/// `InvalidArgument` for an epoch beyond `i64::MAX`; encoding failures.
pub fn encode_session(s: &SessionRecord) -> AuthnResult<Vec<u8>> {
    let epoch = i64::try_from(s.credential_epoch)
        .map_err(|_| AuthnError::InvalidArgument("credential epoch overflow".into()))?;
    let mut doc = Document::new();
    doc.insert("session_format", Value::Int64(SESSION_FORMAT));
    doc.insert("type", codec::string(TYPE));
    doc.insert("user", codec::string(&s.user));
    doc.insert("kind", codec::string(s.kind.as_str()));
    doc.insert("created_at", codec::time(s.created_at));
    doc.insert("last_seen", codec::time(s.last_seen));
    doc.insert("expires_at", codec::time(s.expires_at));
    doc.insert("credential_epoch", Value::Int64(epoch));
    doc.insert("client_info", codec::string(&s.client_info));
    codec::encode(&doc)
}

/// Decodes a session record (format 1).
///
/// # Errors
/// `Corrupt` for anything but a valid format-1 record.
pub fn decode_session(bytes: &[u8]) -> AuthnResult<SessionRecord> {
    let doc = codec::decode(bytes, WHAT)?;
    let f = Fields {
        doc: &doc,
        what: WHAT,
    };
    f.only(FIELDS)?;
    f.header("session_format", SESSION_FORMAT, TYPE)?;
    let kind = match f.str("kind")?.as_str() {
        "gui" => SessionKind::Gui,
        "driver" => SessionKind::Driver,
        other => return Err(AuthnError::corrupt(WHAT, format!("kind {other:?}"))),
    };
    Ok(SessionRecord {
        user: f.str("user")?,
        kind,
        created_at: f.time("created_at")?,
        last_seen: f.time("last_seen")?,
        expires_at: f.time("expires_at")?,
        credential_epoch: f.u64("credential_epoch")?,
        client_info: f.str("client_info")?,
    })
}

/// Hash of a presented token; `None` when it is not a well-formed token.
fn token_hash(token: &str) -> Option<[u8; 32]> {
    let mut bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    let hash = (bytes.len() == TOKEN_BYTES).then(|| *blake3::hash(&bytes).as_bytes());
    bytes.zeroize();
    hash
}

fn truncate(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// Creates a session for `user` (already authenticated by the caller); returns the token —
/// shown to the client once — and the stored record.
///
/// # Errors
/// Store errors.
pub fn create_session(
    txn: &mut dyn SystemTxn,
    user: &UserRecord,
    kind: SessionKind,
    client_info: &str,
    settings: &AuthnSettings,
    now: SystemTime,
    rng: &dyn Rng,
) -> AuthnResult<(SecretString, SessionRecord)> {
    let mut raw = [0u8; TOKEN_BYTES];
    rng.fill_bytes(&mut raw);
    let token = secret(URL_SAFE_NO_PAD.encode(raw));
    let hash = *blake3::hash(&raw).as_bytes();
    raw.zeroize();
    let now = codec::trunc_millis(now);
    let record = SessionRecord {
        user: user.name.clone(),
        kind,
        created_at: now,
        last_seen: now,
        expires_at: now + settings.absolute_timeout(),
        credential_epoch: user.credential_epoch,
        client_info: truncate(client_info, MAX_CLIENT_INFO),
    };
    txn.apply(vec![
        Mutation::Put {
            key: session_key(&hash),
            value: encode_session(&record)?,
        },
        Mutation::Put {
            key: session_user_key(&user.name, &hash),
            value: Vec::new(),
        },
    ])?;
    Ok((token, record))
}

fn delete(txn: &mut dyn SystemTxn, user: &str, hash: &[u8; 32]) -> AuthnResult<()> {
    txn.apply(vec![
        Mutation::Delete {
            key: session_key(hash),
        },
        Mutation::Delete {
            key: session_user_key(user, hash),
        },
    ])?;
    Ok(())
}

/// Whether `s` is expired at `now` (absolute or idle).
#[must_use]
pub fn is_expired(s: &SessionRecord, settings: &AuthnSettings, now: SystemTime) -> bool {
    now >= s.expires_at || now >= s.last_seen + s.kind.idle_timeout(settings)
}

/// Validates a presented token and returns the session's principal (module docs).
///
/// # Errors
/// `SessionExpired` for any invalid, expired or revoked token; store errors; `Corrupt`.
pub fn validate_session(
    txn: &mut dyn SystemTxn,
    token: &str,
    settings: &AuthnSettings,
    now: SystemTime,
) -> AuthnResult<Principal> {
    let hash = token_hash(token).ok_or(AuthnError::SessionExpired)?;
    let Some(bytes) = txn.get(&session_key(&hash))? else {
        return Err(AuthnError::SessionExpired);
    };
    let mut s = decode_session(&bytes)?;
    let user = get_user(txn, &s.user)?;
    let valid_user = user
        .as_ref()
        .filter(|u| u.state == UserState::Enabled && u.credential_epoch == s.credential_epoch);
    let (Some(user), false) = (valid_user, is_expired(&s, settings, now)) else {
        delete(txn, &s.user, &hash)?;
        return Err(AuthnError::SessionExpired);
    };
    let principal = user.principal(AuthMethod::Session);
    if now.duration_since(s.last_seen).unwrap_or_default() >= LAST_SEEN_GRANULARITY {
        s.last_seen = codec::trunc_millis(now);
        txn.apply(vec![Mutation::Put {
            key: session_key(&hash),
            value: encode_session(&s)?,
        }])?;
    }
    Ok(principal)
}

/// The stored session of a presented token, without validating or refreshing it (`WhoAmI`
/// reports its expiry); `None` for a malformed or unknown token.
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn session_of(txn: &dyn CatalogRead, token: &str) -> AuthnResult<Option<SessionRecord>> {
    let Some(hash) = token_hash(token) else {
        return Ok(None);
    };
    txn.get(&session_key(&hash))?
        .map(|b| decode_session(&b))
        .transpose()
}

/// Revokes the session of `token` (logout); `false` if it did not exist.
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn revoke_session(txn: &mut dyn SystemTxn, token: &str) -> AuthnResult<bool> {
    let Some(hash) = token_hash(token) else {
        return Ok(false);
    };
    let Some(bytes) = txn.get(&session_key(&hash))? else {
        return Ok(false);
    };
    let s = decode_session(&bytes)?;
    delete(txn, &s.user, &hash)?;
    Ok(true)
}

/// Revokes every session of `user`; returns how many.
///
/// # Errors
/// Store errors.
pub fn revoke_user_sessions(txn: &mut dyn SystemTxn, user: &str) -> AuthnResult<usize> {
    let prefix = session_user_prefix(user);
    let entries = txn.scan_prefix(&prefix)?;
    let mut mutations = Vec::with_capacity(entries.len() * 2);
    for (key, _) in &entries {
        let hash: [u8; 32] = key[prefix.len()..]
            .try_into()
            .map_err(|_| AuthnError::corrupt("session index", "bad key length"))?;
        mutations.push(Mutation::Delete {
            key: session_key(&hash),
        });
        mutations.push(Mutation::Delete { key: key.clone() });
    }
    txn.apply(mutations)?;
    Ok(entries.len())
}

/// Revokes every session of every user; returns how many. After an online restore the store
/// holds the sessions that were valid when the backup was taken, including ones closed or
/// revoked since: they must not come back (ADR-037).
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn revoke_all_sessions(txn: &mut dyn SystemTxn) -> AuthnResult<usize> {
    let prefix = session_prefix();
    let entries = txn.scan_prefix(&prefix)?;
    for (key, value) in &entries {
        let s = decode_session(value)?;
        let hash: [u8; 32] = key[prefix.len()..]
            .try_into()
            .map_err(|_| AuthnError::corrupt(WHAT, "bad key length"))?;
        delete(txn, &s.user, &hash)?;
    }
    Ok(entries.len())
}

/// Deletes up to `limit` expired sessions (background cleanup; validation also deletes the
/// expired sessions it meets). Returns how many were deleted.
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn purge_expired(
    txn: &mut dyn SystemTxn,
    settings: &AuthnSettings,
    now: SystemTime,
    limit: usize,
) -> AuthnResult<usize> {
    let prefix = session_prefix();
    let mut purged = 0;
    for (key, value) in txn.scan_prefix(&prefix)? {
        if purged >= limit {
            break;
        }
        let s = decode_session(&value)?;
        if is_expired(&s, settings, now) {
            let hash: [u8; 32] = key[prefix.len()..]
                .try_into()
                .map_err(|_| AuthnError::corrupt(WHAT, "bad key length"))?;
            delete(txn, &s.user, &hash)?;
            purged += 1;
        }
    }
    Ok(purged)
}

/// Sessions that are not expired (the `rustegon_active_sessions` gauge, PD-059). Reads every
/// session record: O(sessions), meant for a scrape every few seconds, not for request paths.
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn count_active_sessions(
    txn: &dyn CatalogRead,
    settings: &AuthnSettings,
    now: SystemTime,
) -> AuthnResult<usize> {
    let mut active = 0;
    for (_, value) in txn.scan_prefix(&session_prefix())? {
        if !is_expired(&decode_session(&value)?, settings, now) {
            active += 1;
        }
    }
    Ok(active)
}

/// Every session of `user` (admin listing).
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn list_user_sessions(txn: &dyn CatalogRead, user: &str) -> AuthnResult<Vec<SessionRecord>> {
    let prefix = session_user_prefix(user);
    let mut out = Vec::new();
    for (key, _) in txn.scan_prefix(&prefix)? {
        let hash: [u8; 32] = key[prefix.len()..]
            .try_into()
            .map_err(|_| AuthnError::corrupt("session index", "bad key length"))?;
        if let Some(v) = txn.get(&session_key(&hash))? {
            out.push(decode_session(&v)?);
        }
    }
    Ok(out)
}
