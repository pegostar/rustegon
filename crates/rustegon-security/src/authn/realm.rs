// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The cluster-wide authentication secret ("realm", PD-047): the key of the fake SCRAM salts
//! of unknown users ([`crate::authn::scram::FakeSaltKey`]). It must be identical on every node
//! (module docs of `scram`), so it lives in the replicated system keyspace at
//! [`crate::authn::store::realm_key`], created by [`crate::authn::bootstrap`].
//!
//! ```text
//! realm { realm_format: 1, type: "realm", fake_salt_key: bin(32), created_at: datetime }
//! ```

use std::time::SystemTime;

use rustegon_catalog::{CatalogRead, Mutation};
use rustegon_doc::{Document, Value};
use rustegon_sim_api::Rng;

use crate::authn::{
    codec::{self, Fields},
    error::AuthnResult,
    scram::FakeSaltKey,
    store::{SystemTxn, realm_key},
};

/// Version of the realm record format.
pub const REALM_FORMAT: i64 = 1;
const WHAT: &str = "realm record";
const TYPE: &str = "realm";

/// Encodes the realm record.
///
/// # Errors
/// Encoding failure (never for valid inputs).
pub fn encode_realm(key: &FakeSaltKey, created_at: SystemTime) -> AuthnResult<Vec<u8>> {
    let mut doc = Document::new();
    doc.insert("realm_format", Value::Int64(REALM_FORMAT));
    doc.insert("type", codec::string(TYPE));
    doc.insert("fake_salt_key", codec::bin(key.expose()));
    doc.insert("created_at", codec::time(created_at));
    codec::encode(&doc)
}

/// Decodes the realm record.
///
/// # Errors
/// `Corrupt` for anything but a valid format-1 record.
pub fn decode_realm(bytes: &[u8]) -> AuthnResult<FakeSaltKey> {
    let doc = codec::decode(bytes, WHAT)?;
    let f = Fields {
        doc: &doc,
        what: WHAT,
    };
    f.only(&["realm_format", "type", "fake_salt_key", "created_at"])?;
    f.header("realm_format", REALM_FORMAT, TYPE)?;
    f.time("created_at")?;
    Ok(FakeSaltKey::new(f.bin_n::<32>("fake_salt_key")?))
}

/// The stored key, if the realm was created.
///
/// # Errors
/// Store errors; `Corrupt` for an undecodable record.
pub fn load(txn: &dyn CatalogRead) -> AuthnResult<Option<FakeSaltKey>> {
    txn.get(&realm_key())?.map(|b| decode_realm(&b)).transpose()
}

/// The stored key, or a random per-call key before bootstrap. Before bootstrap no user exists,
/// so a key that differs between nodes or calls reveals nothing.
///
/// # Errors
/// As [`load`].
pub fn load_or_ephemeral(txn: &dyn CatalogRead, rng: &dyn Rng) -> AuthnResult<FakeSaltKey> {
    Ok(load(txn)?.unwrap_or_else(|| FakeSaltKey::generate(rng)))
}

/// Creates the realm record if absent (idempotent) and returns the effective key.
///
/// # Errors
/// Store errors.
pub fn ensure(txn: &mut dyn SystemTxn, now: SystemTime, rng: &dyn Rng) -> AuthnResult<FakeSaltKey> {
    if let Some(key) = load(txn)? {
        return Ok(key);
    }
    let key = FakeSaltKey::generate(rng);
    txn.apply(vec![Mutation::Put {
        key: realm_key(),
        value: encode_realm(&key, now)?,
    }])?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use rustegon_sim_api::OsRng;

    use super::*;
    use crate::authn::store::MemSystemTxn;

    #[test]
    fn realm_is_created_once_and_round_trips() {
        let mut t = MemSystemTxn::new();
        assert!(load(&t).unwrap().is_none());
        let k1 = ensure(&mut t, SystemTime::UNIX_EPOCH, &OsRng).unwrap();
        let k2 = ensure(&mut t, SystemTime::UNIX_EPOCH, &OsRng).unwrap();
        assert_eq!(k1.expose(), k2.expose());
        assert_eq!(load_or_ephemeral(&t, &OsRng).unwrap().expose(), k1.expose());
        assert!(decode_realm(b"junk").is_err());
    }
}
