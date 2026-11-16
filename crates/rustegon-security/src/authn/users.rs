// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Users and their SCRAM credentials (security.md §2, FR-SEC-001, TC-SEC-007; PD-047).
//!
//! User record **format 1** at `0x02 'u' name` (canonical `RDoc`, strict decoding; fixtures
//! `crates/rustegon-security/tests/fixtures/formats/user/1/`):
//! ```text
//! user { user_format: 1, type: "user", name, roles: [string], state: "enabled"|"disabled",
//!        must_change_password: bool, credential_epoch: int64 ≥ 0, created_at, updated_at,
//!        scram?: { salt: bin, iterations: int64, stored_key: bin(32), server_key: bin(32) } }
//! ```
//! - **Credential epoch.** Every password change, role change and disable increments
//!   `credential_epoch` and deletes the user's sessions (security.md §2.1). Sessions also record
//!   the epoch they were created under and are rejected when it differs, so a session that
//!   escaped the deletion (e.g. created concurrently on another node and committed later in
//!   serial order) is still invalid.
//! - **Names** ([`validate_user_name`]): 1–256 bytes of UTF-8, no control characters (hence no
//!   NUL: the by-user session index relies on it), no leading/trailing white space. Names
//!   starting with [`X509_PREFIX`] are certificate users (`x509:CN=…`, [`crate::authn::x509`])
//!   and cannot have a password; [`NODE_PREFIX`] is reserved for cluster node principals.

use std::time::SystemTime;

use rustegon_catalog::{CatalogRead, Mutation};
use rustegon_doc::{Document, Value};
use rustegon_sim_api::Rng;

use crate::authn::{
    AuthMethod, PasswordChange, Principal, SecretString,
    codec::{self, Fields},
    error::{AuthnError, AuthnResult, FailureReason},
    password::check_strength,
    scram::{CredentialState, FakeSaltKey, ScramCredentials},
    session,
    settings::AuthnSettings,
    store::{SystemTxn, user_key, user_prefix},
};

/// Version of the user record format.
pub const USER_FORMAT: i64 = 1;
/// Prefix of users authenticated by a client certificate.
pub const X509_PREFIX: &str = "x509:";
/// Prefix reserved for cluster node principals (never a user record).
pub const NODE_PREFIX: &str = "node:";
/// Longest user name in bytes.
pub const MAX_NAME_LEN: usize = 256;
const WHAT: &str = "user record";
const TYPE: &str = "user";
const FIELDS: &[&str] = &[
    "user_format",
    "type",
    "name",
    "roles",
    "state",
    "must_change_password",
    "credential_epoch",
    "created_at",
    "updated_at",
    "scram",
];
const SCRAM_FIELDS: &[&str] = &["salt", "iterations", "stored_key", "server_key"];

/// Whether a user may authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserState {
    /// Can authenticate.
    Enabled,
    /// Every authentication fails; existing sessions were revoked.
    Disabled,
}

/// A stored user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// Unique name.
    pub name: String,
    /// Role names, sorted and unique.
    pub roles: Vec<String>,
    /// Enabled or disabled.
    pub state: UserState,
    /// Whether the next action must be a password change.
    pub password_change: PasswordChange,
    /// Incremented by every credential, role or state change that revokes sessions.
    pub credential_epoch: u64,
    /// Creation time (millisecond resolution).
    pub created_at: SystemTime,
    /// Last change (millisecond resolution).
    pub updated_at: SystemTime,
    /// SCRAM credentials; `None` for certificate users and API-key-only service accounts.
    pub scram: Option<ScramCredentials>,
}

impl UserRecord {
    /// The principal of this user for `method`.
    #[must_use]
    pub fn principal(&self, method: AuthMethod) -> Principal {
        Principal {
            user: self.name.clone(),
            roles: self.roles.clone(),
            method,
            password_change: self.password_change,
        }
    }
}

/// Validates a user name (module docs).
///
/// # Errors
/// `InvalidArgument` naming the rule.
pub fn validate_user_name(name: &str) -> AuthnResult<()> {
    let bad = |m: &str| Err(AuthnError::InvalidArgument(format!("user name {m}")));
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return bad(&format!("must have 1 to {MAX_NAME_LEN} bytes"));
    }
    if name.chars().any(char::is_control) {
        return bad("must not contain control characters");
    }
    if name.trim() != name {
        return bad("must not start or end with white space");
    }
    if name.starts_with(NODE_PREFIX) {
        return bad(&format!("must not start with {NODE_PREFIX:?} (reserved)"));
    }
    if name.starts_with(X509_PREFIX) && name.len() == X509_PREFIX.len() {
        return bad("needs a subject after \"x509:\"");
    }
    Ok(())
}

fn normalise_roles(mut roles: Vec<String>) -> AuthnResult<Vec<String>> {
    if roles
        .iter()
        .any(|r| r.is_empty() || r.chars().any(char::is_control))
    {
        return Err(AuthnError::InvalidArgument("invalid role name".into()));
    }
    roles.sort();
    roles.dedup();
    Ok(roles)
}

/// Encodes a user record (format 1).
///
/// # Errors
/// `InvalidArgument` for an epoch beyond `i64::MAX`; encoding failures.
pub fn encode_user(u: &UserRecord) -> AuthnResult<Vec<u8>> {
    let epoch = i64::try_from(u.credential_epoch)
        .map_err(|_| AuthnError::InvalidArgument("credential epoch overflow".into()))?;
    let mut doc = Document::new();
    doc.insert("user_format", Value::Int64(USER_FORMAT));
    doc.insert("type", codec::string(TYPE));
    doc.insert("name", codec::string(&u.name));
    doc.insert("roles", codec::strings(&u.roles));
    let state = match u.state {
        UserState::Enabled => "enabled",
        UserState::Disabled => "disabled",
    };
    doc.insert("state", codec::string(state));
    doc.insert(
        "must_change_password",
        Value::Bool(u.password_change == PasswordChange::Required),
    );
    doc.insert("credential_epoch", Value::Int64(epoch));
    doc.insert("created_at", codec::time(u.created_at));
    doc.insert("updated_at", codec::time(u.updated_at));
    if let Some(c) = &u.scram {
        let mut s = Document::new();
        s.insert("salt", codec::bin(c.salt()));
        s.insert("iterations", Value::Int64(i64::from(c.iterations())));
        s.insert("stored_key", codec::bin(c.stored_key()));
        s.insert("server_key", codec::bin(c.server_key()));
        doc.insert("scram", Value::Object(s));
    }
    codec::encode(&doc)
}

/// Decodes a user record (format 1).
///
/// # Errors
/// `Corrupt` for anything but a valid format-1 record.
pub fn decode_user(bytes: &[u8]) -> AuthnResult<UserRecord> {
    let doc = codec::decode(bytes, WHAT)?;
    let f = Fields {
        doc: &doc,
        what: WHAT,
    };
    f.only(FIELDS)?;
    f.header("user_format", USER_FORMAT, TYPE)?;
    let state = match f.str("state")?.as_str() {
        "enabled" => UserState::Enabled,
        "disabled" => UserState::Disabled,
        other => return Err(AuthnError::corrupt(WHAT, format!("state {other:?}"))),
    };
    let scram = match f.object("scram")? {
        None => None,
        Some(d) => {
            let s = Fields { doc: d, what: WHAT };
            s.only(SCRAM_FIELDS)?;
            Some(ScramCredentials::from_parts(
                s.bin("salt")?,
                s.u32("iterations")?,
                s.bin_n::<32>("stored_key")?,
                s.bin_n::<32>("server_key")?,
            ))
        }
    };
    Ok(UserRecord {
        name: f.str("name")?,
        roles: f.str_array("roles")?,
        state,
        password_change: if f.bool("must_change_password")? {
            PasswordChange::Required
        } else {
            PasswordChange::NotRequired
        },
        credential_epoch: f.u64("credential_epoch")?,
        created_at: f.time("created_at")?,
        updated_at: f.time("updated_at")?,
        scram,
    })
}

/// The user `name`, if it exists.
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn get_user(txn: &dyn CatalogRead, name: &str) -> AuthnResult<Option<UserRecord>> {
    txn.get(&user_key(name))?
        .map(|b| decode_user(&b))
        .transpose()
}

fn require_user(txn: &dyn CatalogRead, name: &str) -> AuthnResult<UserRecord> {
    get_user(txn, name)?.ok_or_else(|| AuthnError::NotFound(format!("user {name:?}")))
}

/// Every user, in name byte order.
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn list_users(txn: &dyn CatalogRead) -> AuthnResult<Vec<UserRecord>> {
    txn.scan_prefix(&user_prefix())?
        .iter()
        .map(|(_, v)| decode_user(v))
        .collect()
}

fn put(txn: &mut dyn SystemTxn, u: &UserRecord) -> AuthnResult<()> {
    txn.apply(vec![Mutation::Put {
        key: user_key(&u.name),
        value: encode_user(u)?,
    }])?;
    Ok(())
}

/// A user to create.
#[derive(Debug)]
pub struct NewUser<'a> {
    /// Name ([`validate_user_name`]).
    pub name: &'a str,
    /// Password (checked against the policy), or `None` for certificate / API-key-only users.
    pub password: Option<&'a SecretString>,
    /// Role names.
    pub roles: Vec<String>,
    /// Whether the first action must be a password change.
    pub password_change: PasswordChange,
}

/// A user whose password has been turned into SCRAM credentials ([`prepare_user`]), ready
/// for [`insert_user`].
#[derive(Debug, Clone)]
pub struct PreparedUser {
    name: String,
    roles: Vec<String>,
    password_change: PasswordChange,
    scram: Option<ScramCredentials>,
}

impl PreparedUser {
    /// Replaces the credentials without the password policy: only for the turnkey bootstrap
    /// (`bootstrap::AdminPassword::Turnkey`, ADR-036).
    pub(crate) fn with_scram(mut self, scram: ScramCredentials) -> Self {
        self.scram = Some(scram);
        self
    }
}

/// Validates `new` and derives its SCRAM credentials (PBKDF2 at `settings.scram_iterations`).
///
/// This is the expensive half of a user creation and needs no store: callers run it before the
/// transaction, so the transaction never spans a key derivation. A transaction that stays open
/// through hundreds of milliseconds of CPU work (seconds on slow hardware or in debug builds)
/// outlives the liveness timeout and aborts with `timeout_pushed`, and its body would derive
/// again on every retry.
///
/// # Errors
/// `InvalidArgument` (name, roles, weak password, password on an `x509:` user).
pub fn prepare_user(
    new: &NewUser<'_>,
    settings: &AuthnSettings,
    rng: &dyn Rng,
) -> AuthnResult<PreparedUser> {
    validate_user_name(new.name)?;
    let roles = normalise_roles(new.roles.clone())?;
    let scram = match new.password {
        Some(pw) => Some(prepare_password(new.name, pw, settings, rng)?),
        None => None,
    };
    Ok(PreparedUser {
        name: new.name.to_owned(),
        roles,
        password_change: new.password_change,
        scram,
    })
}

/// Checks `password` for `name` (policy, certificate users) and derives its SCRAM credentials;
/// the expensive half of [`set_password`] (see [`prepare_user`] for why it runs outside the
/// transaction).
///
/// # Errors
/// `InvalidArgument` (weak password, certificate user).
pub fn prepare_password(
    name: &str,
    password: &SecretString,
    settings: &AuthnSettings,
    rng: &dyn Rng,
) -> AuthnResult<ScramCredentials> {
    if name.starts_with(X509_PREFIX) {
        return Err(AuthnError::InvalidArgument(
            "certificate users (x509:…) cannot have a password".into(),
        ));
    }
    check_strength(password.expose(), name)?;
    ScramCredentials::generate(password.expose(), settings.scram_iterations, rng)
}

/// Writes a [`prepare_user`] result in `txn`.
///
/// # Errors
/// `AlreadyExists`, store errors.
pub fn insert_user(
    txn: &mut dyn SystemTxn,
    prepared: &PreparedUser,
    now: SystemTime,
) -> AuthnResult<UserRecord> {
    // Read before write: two concurrent creations of one name conflict in the transaction
    // layer instead of the later one overwriting the earlier (store.rs module docs).
    if get_user(txn, &prepared.name)?.is_some() {
        return Err(AuthnError::AlreadyExists(format!(
            "user {:?}",
            prepared.name
        )));
    }
    let now = codec::trunc_millis(now);
    let user = UserRecord {
        name: prepared.name.clone(),
        roles: prepared.roles.clone(),
        state: UserState::Enabled,
        password_change: prepared.password_change,
        credential_epoch: 0,
        created_at: now,
        updated_at: now,
        scram: prepared.scram.clone(),
    };
    put(txn, &user)?;
    Ok(user)
}

/// Creates a user in `txn`: [`prepare_user`] then [`insert_user`] (for callers whose
/// transaction is short anyway, such as tests; services prepare first).
///
/// # Errors
/// `InvalidArgument` (name, roles, weak password, password on an `x509:` user),
/// `AlreadyExists`, store errors.
pub fn create_user(
    txn: &mut dyn SystemTxn,
    new: &NewUser<'_>,
    settings: &AuthnSettings,
    now: SystemTime,
    rng: &dyn Rng,
) -> AuthnResult<UserRecord> {
    let prepared = prepare_user(new, settings, rng)?;
    insert_user(txn, &prepared, now)
}

/// Rewrites `user` with a new epoch and revokes its sessions.
fn bump_and_revoke(
    txn: &mut dyn SystemTxn,
    mut user: UserRecord,
    now: SystemTime,
) -> AuthnResult<UserRecord> {
    user.credential_epoch += 1;
    user.updated_at = codec::trunc_millis(now);
    put(txn, &user)?;
    session::revoke_user_sessions(txn, &user.name)?;
    Ok(user)
}

/// Sets the password of `name` (clears `must_change_password`), bumps the credential epoch and
/// revokes every session of the user (security.md §2.1, TC-SEC-007): [`prepare_password`] then
/// [`set_credentials`].
///
/// # Errors
/// `NotFound`, `InvalidArgument` (weak password, certificate user), store errors.
pub fn set_password(
    txn: &mut dyn SystemTxn,
    name: &str,
    password: &SecretString,
    settings: &AuthnSettings,
    now: SystemTime,
    rng: &dyn Rng,
) -> AuthnResult<UserRecord> {
    require_user(txn, name)?;
    let scram = prepare_password(name, password, settings, rng)?;
    set_credentials(txn, name, scram, now)
}

/// Stores credentials from [`prepare_password`] as the password of `name`: clears
/// `must_change_password`, bumps the credential epoch and revokes every session of the user.
///
/// # Errors
/// `NotFound`, `InvalidArgument` (certificate user), store errors.
pub fn set_credentials(
    txn: &mut dyn SystemTxn,
    name: &str,
    scram: ScramCredentials,
    now: SystemTime,
) -> AuthnResult<UserRecord> {
    let mut user = require_user(txn, name)?;
    if name.starts_with(X509_PREFIX) {
        return Err(AuthnError::InvalidArgument(
            "certificate users (x509:…) cannot have a password".into(),
        ));
    }
    user.scram = Some(scram);
    user.password_change = PasswordChange::NotRequired;
    bump_and_revoke(txn, user, now)
}

/// Replaces the roles of `name`; bumps the epoch and revokes sessions (security.md §2.1).
///
/// # Errors
/// `NotFound`, `InvalidArgument`, store errors.
pub fn set_roles(
    txn: &mut dyn SystemTxn,
    name: &str,
    roles: Vec<String>,
    now: SystemTime,
) -> AuthnResult<UserRecord> {
    let mut user = require_user(txn, name)?;
    user.roles = normalise_roles(roles)?;
    bump_and_revoke(txn, user, now)
}

/// Enables or disables `name`. Disabling bumps the epoch and revokes sessions.
///
/// # Errors
/// `NotFound`, store errors.
pub fn set_state(
    txn: &mut dyn SystemTxn,
    name: &str,
    state: UserState,
    now: SystemTime,
) -> AuthnResult<UserRecord> {
    let mut user = require_user(txn, name)?;
    if user.state == state {
        return Ok(user);
    }
    user.state = state;
    match state {
        UserState::Disabled => bump_and_revoke(txn, user, now),
        UserState::Enabled => {
            user.updated_at = codec::trunc_millis(now);
            put(txn, &user)?;
            Ok(user)
        }
    }
}

/// Sets or clears the `must_change_password` flag of `name` (administrator action). Setting it
/// does not revoke sessions by itself: the flag restricts what the user's principals may do
/// from the next request on, and the next password change revokes the sessions anyway.
///
/// # Errors
/// `NotFound`, store errors.
pub fn set_password_change(
    txn: &mut dyn SystemTxn,
    name: &str,
    change: PasswordChange,
    now: SystemTime,
) -> AuthnResult<UserRecord> {
    let mut user = require_user(txn, name)?;
    if user.password_change != change {
        user.password_change = change;
        user.updated_at = codec::trunc_millis(now);
        put(txn, &user)?;
    }
    Ok(user)
}

/// Deletes `name`, its sessions and its API keys.
///
/// # Errors
/// `NotFound`, store errors.
pub fn drop_user(txn: &mut dyn SystemTxn, name: &str) -> AuthnResult<()> {
    require_user(txn, name)?;
    txn.apply(vec![Mutation::Delete {
        key: user_key(name),
    }])?;
    session::revoke_user_sessions(txn, name)?;
    crate::authn::apikey::delete_user_keys(txn, name)?;
    Ok(())
}

/// What the SCRAM server needs for `name` ([`CredentialState`]).
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn scram_lookup(txn: &dyn CatalogRead, name: &str) -> AuthnResult<CredentialState> {
    Ok(match get_user(txn, name)? {
        Some(UserRecord {
            scram: Some(c),
            state: UserState::Enabled,
            ..
        }) => CredentialState::Usable(c),
        Some(UserRecord {
            scram: Some(c),
            state: UserState::Disabled,
            ..
        }) => CredentialState::Disabled(c),
        _ => CredentialState::Unknown,
    })
}

/// Password login without SCRAM on the wire (GUI over TLS, protocol.md §3): verifies with the
/// stored SCRAM verifier. Unknown, password-less and disabled users run the same PBKDF2 on
/// fake credentials, so response time does not reveal whether the user exists.
///
/// # Errors
/// Generic authentication failure; store errors.
pub fn authenticate_password(
    txn: &dyn CatalogRead,
    name: &str,
    password: &SecretString,
    fake: &FakeSaltKey,
    settings: &AuthnSettings,
) -> AuthnResult<Principal> {
    let user = get_user(txn, name)?;
    verify_user_password(user.as_ref(), name, password, fake, settings)
}

/// The store-free half of [`authenticate_password`]: verifies `password` against `user` as read
/// by [`get_user`] (`None`: unknown), so the PBKDF2 can run outside the transaction that read
/// the record (see [`prepare_user`]). Same timing behaviour for unknown, password-less and
/// disabled users.
///
/// # Errors
/// Generic authentication failure.
pub fn verify_user_password(
    user: Option<&UserRecord>,
    name: &str,
    password: &SecretString,
    fake: &FakeSaltKey,
    settings: &AuthnSettings,
) -> AuthnResult<Principal> {
    let verified = if let Some(c) = user.and_then(|u| u.scram.as_ref()) {
        c.verify_password(password.expose())
    } else {
        let fake_creds = ScramCredentials::from_parts(
            fake.salt_for(name).to_vec(),
            settings.scram_iterations,
            [0; 32],
            [0; 32],
        );
        // The result is ignored on purpose: only the time spent matters.
        let _ = fake_creds.verify_password(password.expose());
        false
    };
    match user {
        Some(u) if verified && u.state == UserState::Enabled => {
            Ok(u.principal(AuthMethod::Password))
        }
        _ => Err(AuthnError::failed(FailureReason::BadCredentials)),
    }
}

#[cfg(test)]
mod tests;
