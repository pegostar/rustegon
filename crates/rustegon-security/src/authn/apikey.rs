// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! API keys (security.md §2, FR-SEC-001, TC-SEC-011; PD-047).
//!
//! - **Format** `rgn_<key_id>_<secret>`: `key_id` = 12 random base62 characters (~71 bits,
//!   the lookup key, not secret), `secret` = 32 random bytes in exactly 43 base62 digits
//!   (module `authn::base62`). Base62 keeps `_` unambiguous as the separator.
//! - **Storage**: record **format 1** at `0x02 'k' key_id` (fixtures
//!   `tests/fixtures/formats/api_key/1/`); the secret is stored only as
//!   Argon2id(m = 64 MiB, t = 3, p = 1) with a 16-byte random salt (security.md §2). The
//!   parameters are stored per key, so stronger defaults later do not invalidate old keys.
//!   ```text
//!   api_key { api_key_format: 1, type: "api_key", key_id, user, name, roles: [string],
//!             created_at, expires_at?: datetime, allow_cidrs: [string],
//!             argon2_m_kib: int64, argon2_t: int64, argon2_p: int64, salt: bin(16), hash: bin(32) }
//!   ```
//! - **Scope**: `roles` must be a subset of the owner's roles at creation; at use the key
//!   grants `roles ∩ owner's current roles`, so removing a role from the user also removes it
//!   from the user's keys. A disabled or dropped owner disables the key.
//! - **Checks at use** ([`authenticate_api_key`]), all failing with the generic `RGN-4001`:
//!   format, existence, expiry, client address in `allow_cidrs` (empty list = any address),
//!   Argon2id verification (constant-time compare), owner enabled. The cheap checks run
//!   before Argon2id so that a flood of requests from a disallowed address does not cost
//!   64 MiB of hashing each.

use std::{net::IpAddr, str::FromStr, time::SystemTime};

use argon2::{Algorithm, Argon2, Params, Version};
use rustegon_catalog::{CatalogRead, Mutation};
use rustegon_doc::{Document, Value};
use rustegon_sim_api::Rng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::authn::{
    AuthMethod, PasswordChange, Principal, SecretString,
    base62::{ALPHABET, SECRET_CHARS, decode_secret, encode_secret, random_string},
    codec::{self, Fields},
    error::{AuthnError, AuthnResult, FailureReason},
    secret,
    store::{SystemTxn, api_key_key, api_key_prefix},
    users::{UserState, get_user},
};

/// Version of the API key record format.
pub const API_KEY_FORMAT: i64 = 1;
/// Prefix of every API key string.
pub const KEY_PREFIX: &str = "rgn_";
/// Characters of a key id.
pub const KEY_ID_LEN: usize = 12;
/// Longest key name (label) in characters.
pub const MAX_NAME_LEN: usize = 128;
/// Salt length in bytes.
const SALT_LEN: usize = 16;
/// Hash length in bytes.
const HASH_LEN: usize = 32;
const WHAT: &str = "API key record";
const TYPE: &str = "api_key";
const FIELDS: &[&str] = &[
    "api_key_format",
    "type",
    "key_id",
    "user",
    "name",
    "roles",
    "created_at",
    "expires_at",
    "allow_cidrs",
    "argon2_m_kib",
    "argon2_t",
    "argon2_p",
    "salt",
    "hash",
];

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Cost {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

/// The cost of new keys (security.md §2: m = 64 MiB, t = 3, p = 1).
pub const ARGON2_COST: Argon2Cost = Argon2Cost {
    m_kib: 64 * 1024,
    t: 3,
    p: 1,
};

/// Cost actually used for new keys: unit tests use a tiny cost so that debug builds stay fast;
/// verification always uses the cost stored with each key.
#[cfg(not(test))]
const NEW_KEY_COST: Argon2Cost = ARGON2_COST;
#[cfg(test)]
const NEW_KEY_COST: Argon2Cost = Argon2Cost {
    m_kib: 64,
    t: 1,
    p: 1,
};

/// An IPv4 or IPv6 network (`10.0.0.0/8`, `2001:db8::/32`, or a single address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Whether `ip` is inside the network. IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, how
    /// dual-stack sockets report IPv4 clients) are compared as IPv4.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = AuthnError;

    fn from_str(s: &str) -> AuthnResult<Self> {
        let bad = || AuthnError::InvalidArgument(format!("invalid CIDR {s:?}"));
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr = IpAddr::from_str(addr).map_err(|_| bad())?.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(bad)?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// A stored API key (without its secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyRecord {
    /// Key id (the middle part of the key string).
    pub key_id: String,
    /// Owner.
    pub user: String,
    /// Label.
    pub name: String,
    /// Scope: role names, sorted and unique.
    pub roles: Vec<String>,
    /// Creation time.
    pub created_at: SystemTime,
    /// Optional expiry.
    pub expires_at: Option<SystemTime>,
    /// Allowed client networks (empty = any).
    pub allow: Vec<Cidr>,
    /// Argon2id cost of `hash`.
    pub cost: Argon2Cost,
    /// Argon2id salt.
    pub salt: [u8; SALT_LEN],
    /// Argon2id(secret).
    pub hash: [u8; HASH_LEN],
}

pub(crate) fn argon2_hash(
    secret: &[u8],
    salt: &[u8],
    cost: Argon2Cost,
) -> AuthnResult<Zeroizing<[u8; HASH_LEN]>> {
    let params = Params::new(cost.m_kib, cost.t, cost.p, Some(HASH_LEN))
        .map_err(|e| AuthnError::InvalidArgument(format!("Argon2 parameters: {e}")))?;
    let mut out = Zeroizing::new([0u8; HASH_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret, salt, out.as_mut_slice())
        .map_err(|e| AuthnError::InvalidArgument(format!("Argon2: {e}")))?;
    Ok(out)
}

/// Encodes an API key record (format 1).
///
/// # Errors
/// Encoding failures.
pub fn encode_api_key(k: &ApiKeyRecord) -> AuthnResult<Vec<u8>> {
    let mut doc = Document::new();
    doc.insert("api_key_format", Value::Int64(API_KEY_FORMAT));
    doc.insert("type", codec::string(TYPE));
    doc.insert("key_id", codec::string(&k.key_id));
    doc.insert("user", codec::string(&k.user));
    doc.insert("name", codec::string(&k.name));
    doc.insert("roles", codec::strings(&k.roles));
    doc.insert("created_at", codec::time(k.created_at));
    if let Some(t) = k.expires_at {
        doc.insert("expires_at", codec::time(t));
    }
    let cidrs: Vec<String> = k.allow.iter().map(ToString::to_string).collect();
    doc.insert("allow_cidrs", codec::strings(&cidrs));
    doc.insert("argon2_m_kib", Value::Int64(i64::from(k.cost.m_kib)));
    doc.insert("argon2_t", Value::Int64(i64::from(k.cost.t)));
    doc.insert("argon2_p", Value::Int64(i64::from(k.cost.p)));
    doc.insert("salt", codec::bin(&k.salt));
    doc.insert("hash", codec::bin(&k.hash));
    codec::encode(&doc)
}

/// Decodes an API key record (format 1).
///
/// # Errors
/// `Corrupt` for anything but a valid format-1 record.
pub fn decode_api_key(bytes: &[u8]) -> AuthnResult<ApiKeyRecord> {
    let doc = codec::decode(bytes, WHAT)?;
    let f = Fields {
        doc: &doc,
        what: WHAT,
    };
    f.only(FIELDS)?;
    f.header("api_key_format", API_KEY_FORMAT, TYPE)?;
    let allow = f
        .str_array("allow_cidrs")?
        .iter()
        .map(|c| Cidr::from_str(c).map_err(|e| AuthnError::corrupt(WHAT, e)))
        .collect::<AuthnResult<_>>()?;
    Ok(ApiKeyRecord {
        key_id: f.str("key_id")?,
        user: f.str("user")?,
        name: f.str("name")?,
        roles: f.str_array("roles")?,
        created_at: f.time("created_at")?,
        expires_at: f.opt_time("expires_at")?,
        allow,
        cost: Argon2Cost {
            m_kib: f.u32("argon2_m_kib")?,
            t: f.u32("argon2_t")?,
            p: f.u32("argon2_p")?,
        },
        salt: f.bin_n("salt")?,
        hash: f.bin_n("hash")?,
    })
}

/// An API key to create.
#[derive(Debug)]
pub struct NewApiKey<'a> {
    /// Owner (must exist and be enabled).
    pub user: &'a str,
    /// Label (1–[`MAX_NAME_LEN`] characters, no control characters).
    pub name: &'a str,
    /// Scope: non-empty subset of the owner's roles.
    pub roles: Vec<String>,
    /// Optional expiry, after `now`.
    pub expires_at: Option<SystemTime>,
    /// Allowed client networks (empty = any).
    pub allow: Vec<Cidr>,
}

/// Creates an API key; returns the record and the full key string, which is shown once and
/// never stored.
///
/// # Errors
/// `InvalidArgument` (name, scope outside the owner's roles, expiry in the past), `NotFound`
/// (owner missing or disabled), store errors.
pub fn create_api_key(
    txn: &mut dyn SystemTxn,
    new: NewApiKey<'_>,
    now: SystemTime,
    rng: &dyn Rng,
) -> AuthnResult<(ApiKeyRecord, SecretString)> {
    create_api_key_with_cost(txn, new, now, rng, NEW_KEY_COST)
}

/// [`create_api_key`] with an explicit Argon2id cost for the new key. Servers pass
/// [`ARGON2_COST`]; only tests and benchmarks lower it, because every verification uses the
/// cost stored with the key (a weak cost weakens that key only).
///
/// # Errors
/// As [`create_api_key`]; `InvalidArgument` for Argon2 parameters the library rejects.
pub fn create_api_key_with_cost(
    txn: &mut dyn SystemTxn,
    new: NewApiKey<'_>,
    now: SystemTime,
    rng: &dyn Rng,
    cost: Argon2Cost,
) -> AuthnResult<(ApiKeyRecord, SecretString)> {
    let prepared = prepare_api_key(rng, cost)?;
    insert_api_key(txn, new, &prepared, now)
}

/// The secret part of a new API key, hashed ([`prepare_api_key`]), ready for
/// [`insert_api_key`].
#[derive(Clone)]
pub struct PreparedApiKey {
    key_id: String,
    full: SecretString,
    salt: [u8; SALT_LEN],
    hash: Zeroizing<[u8; HASH_LEN]>,
    cost: Argon2Cost,
}

impl std::fmt::Debug for PreparedApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedApiKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Draws a key id and secret and hashes the secret with Argon2id at `cost`: the expensive half
/// of [`create_api_key_with_cost`] (64 MiB and several passes at [`ARGON2_COST`]). It needs no
/// store, so services run it before the transaction (a transaction open through the hash can
/// outlive the liveness timeout, and its body would hash again on every retry).
///
/// # Errors
/// `InvalidArgument` for Argon2 parameters the library rejects.
pub fn prepare_api_key(rng: &dyn Rng, cost: Argon2Cost) -> AuthnResult<PreparedApiKey> {
    // 62^12 ids make a collision practically impossible; `insert_api_key` reads the id, which
    // also makes concurrent creations of one id conflict in the transaction layer.
    let key_id = random_string(rng, ALPHABET, KEY_ID_LEN);
    let mut raw = [0u8; 32];
    rng.fill_bytes(&mut raw);
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let hash = argon2_hash(&raw, &salt, cost)?;
    let full = secret(format!("{KEY_PREFIX}{key_id}_{}", encode_secret(&raw)));
    raw.zeroize();
    Ok(PreparedApiKey {
        key_id,
        full,
        salt,
        hash,
        cost,
    })
}

/// Stores a [`prepare_api_key`] result for `new` after checking the owner and scope; returns
/// the record and the full key string, which is shown once and never stored.
///
/// # Errors
/// As [`create_api_key`]; `AlreadyExists` if the drawn id exists.
pub fn insert_api_key(
    txn: &mut dyn SystemTxn,
    new: NewApiKey<'_>,
    prepared: &PreparedApiKey,
    now: SystemTime,
) -> AuthnResult<(ApiKeyRecord, SecretString)> {
    let owner = get_user(txn, new.user)?
        .filter(|u| u.state == UserState::Enabled)
        .ok_or_else(|| AuthnError::NotFound(format!("user {:?}", new.user)))?;
    let name_len = new.name.chars().count();
    if name_len == 0 || name_len > MAX_NAME_LEN || new.name.chars().any(char::is_control) {
        return Err(AuthnError::InvalidArgument("invalid API key name".into()));
    }
    let mut roles = new.roles;
    roles.sort();
    roles.dedup();
    if roles.is_empty() || roles.iter().any(|r| !owner.roles.contains(r)) {
        return Err(AuthnError::InvalidArgument(
            "API key scope must be a non-empty subset of the owner's roles".into(),
        ));
    }
    if new.expires_at.is_some_and(|t| t <= now) {
        return Err(AuthnError::InvalidArgument(
            "API key expiry is in the past".into(),
        ));
    }
    if txn.get(&api_key_key(&prepared.key_id))?.is_some() {
        return Err(AuthnError::AlreadyExists(format!(
            "API key {}",
            prepared.key_id
        )));
    }
    let record = ApiKeyRecord {
        key_id: prepared.key_id.clone(),
        user: owner.name,
        name: new.name.to_owned(),
        roles,
        created_at: codec::trunc_millis(now),
        expires_at: new.expires_at.map(codec::trunc_millis),
        allow: new.allow,
        cost: prepared.cost,
        salt: prepared.salt,
        hash: *prepared.hash,
    };
    txn.apply(vec![Mutation::Put {
        key: api_key_key(&record.key_id),
        value: encode_api_key(&record)?,
    }])?;
    Ok((record, prepared.full.clone()))
}

/// Splits `rgn_<key_id>_<secret>`; `None` when malformed.
pub(crate) fn parse_key(presented: &str) -> Option<(&str, [u8; 32])> {
    let rest = presented.strip_prefix(KEY_PREFIX)?;
    let (key_id, secret) = rest.split_once('_')?;
    let id_ok = key_id.len() == KEY_ID_LEN && key_id.bytes().all(|c| ALPHABET.contains(&c));
    if !id_ok || secret.len() != SECRET_CHARS {
        return None;
    }
    Some((key_id, decode_secret(secret)?))
}

/// Authenticates a presented API key from `client` at `now` (module docs).
///
/// # Errors
/// Generic authentication failure; store errors; `Corrupt`.
pub fn authenticate_api_key(
    txn: &dyn CatalogRead,
    presented: &str,
    client: IpAddr,
    now: SystemTime,
) -> AuthnResult<Principal> {
    let (key_id, mut raw) =
        parse_key(presented).ok_or(AuthnError::failed(FailureReason::Malformed))?;
    let result = check_key(txn, key_id, &raw, client, now);
    raw.zeroize();
    result
}

fn check_key(
    txn: &dyn CatalogRead,
    key_id: &str,
    raw: &[u8; 32],
    client: IpAddr,
    now: SystemTime,
) -> AuthnResult<Principal> {
    let Some(bytes) = txn.get(&api_key_key(key_id))? else {
        return Err(AuthnError::failed(FailureReason::BadCredentials));
    };
    let key = decode_api_key(&bytes)?;
    if key.expires_at.is_some_and(|t| now >= t) {
        return Err(AuthnError::failed(FailureReason::Expired));
    }
    if !key.allow.is_empty() && !key.allow.iter().any(|c| c.contains(client)) {
        return Err(AuthnError::failed(FailureReason::AddressNotAllowed));
    }
    let hash = argon2_hash(raw, &key.salt, key.cost)?;
    if !bool::from(hash.ct_eq(&key.hash)) {
        return Err(AuthnError::failed(FailureReason::BadCredentials));
    }
    let owner = get_user(txn, &key.user)?
        .filter(|u| u.state == UserState::Enabled)
        .ok_or(AuthnError::failed(FailureReason::BadCredentials))?;
    let roles = key
        .roles
        .into_iter()
        .filter(|r| owner.roles.contains(r))
        .collect();
    Ok(Principal {
        user: owner.name,
        roles,
        method: AuthMethod::ApiKey(key.key_id),
        // A key is a machine credential: the owner's pending password change does not apply.
        password_change: PasswordChange::NotRequired,
    })
}

/// The key `key_id`, if it exists.
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn get_api_key(txn: &dyn CatalogRead, key_id: &str) -> AuthnResult<Option<ApiKeyRecord>> {
    txn.get(&api_key_key(key_id))?
        .map(|b| decode_api_key(&b))
        .transpose()
}

/// Every key, or the keys of `user`.
///
/// # Errors
/// Store errors; `Corrupt`.
pub fn list_api_keys(txn: &dyn CatalogRead, user: Option<&str>) -> AuthnResult<Vec<ApiKeyRecord>> {
    let mut out = Vec::new();
    for (_, v) in txn.scan_prefix(&api_key_prefix())? {
        let k = decode_api_key(&v)?;
        if user.is_none_or(|u| u == k.user) {
            out.push(k);
        }
    }
    Ok(out)
}

/// Revokes (deletes) the key `key_id`.
///
/// # Errors
/// `NotFound`, store errors.
pub fn revoke_api_key(txn: &mut dyn SystemTxn, key_id: &str) -> AuthnResult<()> {
    if txn.get(&api_key_key(key_id))?.is_none() {
        return Err(AuthnError::NotFound(format!("API key {key_id}")));
    }
    txn.apply(vec![Mutation::Delete {
        key: api_key_key(key_id),
    }])?;
    Ok(())
}

/// Deletes every key of `user` (user drop). Keys have no by-user index: dropping a user is a
/// rare admin operation and the key count is small, so a scan is fine.
pub(crate) fn delete_user_keys(txn: &mut dyn SystemTxn, user: &str) -> AuthnResult<()> {
    let mutations = list_api_keys(txn, Some(user))?
        .into_iter()
        .map(|k| Mutation::Delete {
            key: api_key_key(&k.key_id),
        })
        .collect();
    txn.apply(mutations)?;
    Ok(())
}

#[cfg(test)]
mod tests;
