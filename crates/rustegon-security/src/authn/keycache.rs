// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Bounded cache of verified API key secrets (security.md §2, FR-SEC-001; PD-051).
//!
//! An API key secret is stored as Argon2id(m = 64 MiB, t = 3, p = 1): verifying it costs about
//! a hundred milliseconds of CPU and 64 MiB of memory, which is right for an offline attacker
//! holding a stolen record but wrong for an automation client sending one request per key use.
//! This cache memoizes **only the outcome of the Argon2id comparison**; everything else is
//! re-checked on every request from the current records:
//!
//! - the key record must still exist (revocation is immediate, on every node) and carry the same
//!   stored hash the cached verification was made against;
//! - expiry and the client address allowlist are evaluated with the current time and address;
//! - the owner must exist and be enabled, and the effective scope is recomputed as
//!   `key roles ∩ owner's current roles`;
//! - the owner's **credential epoch** must equal the one recorded at verification: a password,
//!   role or state change bumps it (`crate::authn::users`), which turns the next use into a full
//!   Argon2id verification again.
//!
//! Entries are keyed by `(key_id, BLAKE3-keyed(process key, presented key string))`. The
//! process key is random per process, so the cache holds no stable digest of a secret: a memory
//! dump yields nothing reusable on another node or after a restart, and since secrets carry
//! 256 random bits the keyed digest cannot be inverted. A wrong secret for a valid key id never
//! matches an entry and always pays the full Argon2id cost, so the cache gives an attacker no
//! cheap guessing oracle; callers bound those full verifications with the authentication rate
//! limit (security.md §8). Entries expire after a short TTL (default 60 s) and the cache holds at
//! most `max_entries` (expired first, then oldest evicted), so memory is bounded whatever the
//! traffic.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime},
};

use rustegon_catalog::CatalogRead;
use rustegon_sim_api::Rng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::authn::{
    AuthMethod, PasswordChange, Principal,
    apikey::{ApiKeyRecord, argon2_hash, get_api_key, parse_key},
    error::{AuthnError, AuthnResult, FailureReason},
    users::{UserRecord, UserState, get_user},
};

/// Default lifetime of a cached verification.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);
/// Default bound on cached verifications (one per distinct presented key).
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    key_id: String,
    digest: [u8; 32],
}

#[derive(Debug, Clone)]
struct Entry {
    /// Owner at verification (for [`VerifiedKeyCache::invalidate_user`]).
    owner: String,
    /// Argon2id hash stored in the key record the secret was verified against.
    stored_hash: [u8; 32],
    /// Owner's credential epoch at verification.
    owner_epoch: u64,
    /// Monotonic time of verification.
    verified_at: Duration,
}

/// The cache (module docs). Thread-safe; share it behind an `Arc`.
pub struct VerifiedKeyCache {
    process_key: Zeroizing<[u8; 32]>,
    ttl: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<CacheKey, Entry>>,
}

impl std::fmt::Debug for VerifiedKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedKeyCache")
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// Result of [`VerifiedKeyCache::lookup`].
#[derive(Debug)]
pub enum KeyLookup {
    /// Cache hit: every cheap check passed and the secret was verified recently.
    Verified(Principal),
    /// The cheap checks passed; the secret still needs [`PendingKey::verify`].
    Pending(Box<PendingKey>),
}

/// A presented key that passed the record checks but not yet the Argon2id verification. It
/// holds the decoded secret (wiped on drop); verify it outside any transaction.
pub struct PendingKey {
    cache_key: CacheKey,
    raw: Zeroizing<[u8; 32]>,
    record: ApiKeyRecord,
    owner: UserRecord,
}

impl std::fmt::Debug for PendingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingKey")
            .field("key_id", &self.cache_key.key_id)
            .finish_non_exhaustive()
    }
}

fn principal(record: &ApiKeyRecord, owner: &UserRecord) -> Principal {
    Principal {
        user: owner.name.clone(),
        roles: record
            .roles
            .iter()
            .filter(|r| owner.roles.contains(r))
            .cloned()
            .collect(),
        method: AuthMethod::ApiKey(record.key_id.clone()),
        password_change: PasswordChange::NotRequired,
    }
}

impl VerifiedKeyCache {
    /// A cache with a fresh random process key from `rng` (the server's CSPRNG).
    #[must_use]
    pub fn new(rng: &dyn Rng, ttl: Duration, max_entries: usize) -> Self {
        let mut process_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(process_key.as_mut_slice());
        Self {
            process_key,
            ttl,
            max_entries: max_entries.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Entry>> {
        // Entries are inserted and removed whole; a poisoned lock still guards a consistent map.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of cached verifications.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Checks a presented key against the current records at `now` (wall clock, expiry) and
    /// `mono_now` (monotonic, TTL). Cheap: no Argon2id. A cache hit returns the principal; a
    /// miss returns the [`PendingKey`] to verify.
    ///
    /// # Errors
    /// Generic authentication failure (malformed, unknown, expired, address not allowed,
    /// owner missing or disabled); store errors; `Corrupt`.
    pub fn lookup(
        &self,
        txn: &dyn CatalogRead,
        presented: &str,
        client: IpAddr,
        now: SystemTime,
        mono_now: Duration,
    ) -> AuthnResult<KeyLookup> {
        let (key_id, raw) =
            parse_key(presented).ok_or(AuthnError::failed(FailureReason::Malformed))?;
        let raw = Zeroizing::new(raw);
        let cache_key = CacheKey {
            key_id: key_id.to_owned(),
            digest: *blake3::keyed_hash(&self.process_key, presented.as_bytes()).as_bytes(),
        };
        let Some(record) = get_api_key(txn, key_id)? else {
            self.invalidate_key(key_id);
            return Err(AuthnError::failed(FailureReason::BadCredentials));
        };
        if record.expires_at.is_some_and(|t| now >= t) {
            return Err(AuthnError::failed(FailureReason::Expired));
        }
        if !record.allow.is_empty() && !record.allow.iter().any(|c| c.contains(client)) {
            return Err(AuthnError::failed(FailureReason::AddressNotAllowed));
        }
        let owner = get_user(txn, &record.user)?
            .filter(|u| u.state == UserState::Enabled)
            .ok_or(AuthnError::failed(FailureReason::BadCredentials))?;
        if self.hit(&cache_key, &record, &owner, mono_now) {
            return Ok(KeyLookup::Verified(principal(&record, &owner)));
        }
        Ok(KeyLookup::Pending(Box::new(PendingKey {
            cache_key,
            raw,
            record,
            owner,
        })))
    }

    fn hit(
        &self,
        key: &CacheKey,
        record: &ApiKeyRecord,
        owner: &UserRecord,
        now: Duration,
    ) -> bool {
        let mut entries = self.lock();
        let Some(e) = entries.get(key) else {
            return false;
        };
        // The stored hash is not secret, but comparing it in constant time costs nothing.
        let same_key = bool::from(e.stored_hash.ct_eq(&record.hash));
        let fresh = now.saturating_sub(e.verified_at) < self.ttl;
        if same_key && fresh && e.owner_epoch == owner.credential_epoch && e.owner == owner.name {
            return true;
        }
        entries.remove(key);
        false
    }

    fn insert(&self, key: CacheKey, entry: Entry) {
        let mut entries = self.lock();
        if !entries.contains_key(&key) && entries.len() >= self.max_entries {
            let ttl = self.ttl;
            let now = entry.verified_at;
            entries.retain(|_, e| now.saturating_sub(e.verified_at) < ttl);
            if entries.len() >= self.max_entries
                && let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, e)| e.verified_at)
                    .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, entry);
    }

    /// Drops every cached verification of `key_id` (key revoked).
    pub fn invalidate_key(&self, key_id: &str) {
        self.lock().retain(|k, _| k.key_id != key_id);
    }

    /// Drops every cached verification of keys owned by `user` (user dropped or changed).
    pub fn invalidate_user(&self, user: &str) {
        self.lock().retain(|_, e| e.owner != user);
    }
}

impl PendingKey {
    /// The key id.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.cache_key.key_id
    }

    /// Runs the Argon2id verification (expensive: run it on a blocking thread, outside any
    /// transaction) and, on success, caches the outcome at `mono_now`.
    ///
    /// # Errors
    /// Generic authentication failure for a wrong secret.
    pub fn verify(self, cache: &VerifiedKeyCache, mono_now: Duration) -> AuthnResult<Principal> {
        let Self {
            cache_key,
            raw,
            record,
            owner,
        } = self;
        let mut hash = argon2_hash(raw.as_slice(), &record.salt, record.cost)?;
        let ok = bool::from(hash.ct_eq(&record.hash));
        hash.zeroize();
        if !ok {
            return Err(AuthnError::failed(FailureReason::BadCredentials));
        }
        cache.insert(
            cache_key,
            Entry {
                owner: owner.name.clone(),
                stored_hash: record.hash,
                owner_epoch: owner.credential_epoch,
                verified_at: mono_now,
            },
        );
        Ok(principal(&record, &owner))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::net::Ipv4Addr;

    use super::*;
    use crate::authn::{
        apikey::{NewApiKey, revoke_api_key},
        store::MemSystemTxn,
        testutil::{SeqRng, fast_settings, t0},
        users::{NewUser, create_user, set_roles},
    };

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn setup() -> (MemSystemTxn, String, String) {
        let rng = SeqRng::new(7);
        let mut t = MemSystemTxn::new();
        create_user(
            &mut t,
            &NewUser {
                name: "svc",
                password: None,
                roles: vec!["read".into(), "monitor".into()],
                password_change: PasswordChange::NotRequired,
            },
            &fast_settings(),
            t0(),
            &rng,
        )
        .unwrap();
        let (rec, full) = crate::authn::apikey::create_api_key(
            &mut t,
            NewApiKey {
                user: "svc",
                name: "scraper",
                roles: vec!["read".into(), "monitor".into()],
                expires_at: None,
                allow: vec![],
            },
            t0(),
            &rng,
        )
        .unwrap();
        (t, rec.key_id, full.expose().to_string())
    }

    fn verified(c: &VerifiedKeyCache, t: &MemSystemTxn, key: &str, mono: u64) -> Option<Principal> {
        match c.lookup(t, key, IP, t0(), Duration::from_secs(mono)).ok()? {
            KeyLookup::Verified(p) => Some(p),
            KeyLookup::Pending(p) => {
                p.verify(c, Duration::from_secs(mono)).ok()?;
                None
            }
        }
    }

    #[test]
    fn fr_sec_001_cache_hits_after_one_verification_and_expires() {
        let (t, _, key) = setup();
        let c = VerifiedKeyCache::new(&SeqRng::new(1), Duration::from_secs(60), 16);
        assert!(verified(&c, &t, &key, 0).is_none(), "first use verifies");
        let p = verified(&c, &t, &key, 10).expect("cache hit");
        assert_eq!(p.roles, ["monitor", "read"]);
        assert!(verified(&c, &t, &key, 100).is_none(), "TTL expired");
        // A wrong secret for the same key id never hits.
        let mut wrong = key.clone();
        let last = wrong.pop().unwrap();
        wrong.push(if last == 'a' { 'b' } else { 'a' });
        match c
            .lookup(&t, &wrong, IP, t0(), Duration::from_secs(101))
            .unwrap()
        {
            KeyLookup::Pending(p) => assert!(p.verify(&c, Duration::from_secs(101)).is_err()),
            KeyLookup::Verified(_) => panic!("wrong secret must not hit"),
        }
    }

    #[test]
    fn fr_sec_001_cache_is_invalidated_by_revocation_and_credential_epoch() {
        let (mut t, key_id, key) = setup();
        let c = VerifiedKeyCache::new(&SeqRng::new(2), Duration::from_secs(60), 16);
        verified(&c, &t, &key, 0);
        assert!(verified(&c, &t, &key, 1).is_some());
        // Role change bumps the owner's epoch: the next use verifies again, with the new scope.
        set_roles(&mut t, "svc", vec!["read".into()], t0()).unwrap();
        assert!(verified(&c, &t, &key, 2).is_none());
        let p = verified(&c, &t, &key, 3).unwrap();
        assert_eq!(p.roles, ["read"]);
        // Revocation is seen on the very next request.
        revoke_api_key(&mut t, &key_id).unwrap();
        assert!(
            c.lookup(&t, &key, IP, t0(), Duration::from_secs(4))
                .is_err()
        );
        assert!(c.is_empty());
    }

    #[test]
    fn fr_sec_001_cache_is_bounded() {
        let (t, _, key) = setup();
        let c = VerifiedKeyCache::new(&SeqRng::new(3), Duration::from_secs(60), 1);
        verified(&c, &t, &key, 0);
        assert_eq!(c.len(), 1);
        c.insert(
            CacheKey {
                key_id: "other".into(),
                digest: [0; 32],
            },
            Entry {
                owner: "svc".into(),
                stored_hash: [0; 32],
                owner_epoch: 0,
                verified_at: Duration::from_secs(1),
            },
        );
        assert_eq!(c.len(), 1);
        c.invalidate_user("svc");
        assert!(c.is_empty());
    }
}
