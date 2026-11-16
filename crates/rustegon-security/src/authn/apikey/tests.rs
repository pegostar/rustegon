// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-SEC-011: API keys (format, Argon2id storage, scope, expiry, IP allowlist).

use std::time::Duration;

use rustegon_sim_api::OsRng;

use super::*;
use crate::authn::{
    store::MemSystemTxn,
    testutil::{fast_settings, t0},
    users::{NewUser, UserState, create_user, drop_user, set_roles, set_state},
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn setup() -> MemSystemTxn {
    let mut t = MemSystemTxn::new();
    create_user(
        &mut t,
        &NewUser {
            name: "svc",
            password: None,
            roles: vec!["monitor".into(), "read".into()],
            password_change: PasswordChange::Required,
        },
        &fast_settings(),
        t0(),
        &OsRng,
    )
    .unwrap();
    t
}

fn new_key<'a>(roles: &[&str], expires_at: Option<SystemTime>, allow: &[&str]) -> NewApiKey<'a> {
    NewApiKey {
        user: "svc",
        name: "prometheus scraper",
        roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        expires_at,
        allow: allow.iter().map(|c| c.parse().unwrap()).collect(),
    }
}

fn failed(r: &AuthnResult<Principal>, reason: FailureReason) -> bool {
    matches!(r, Err(AuthnError::AuthenticationFailed(x)) if *x == reason)
}

#[test]
fn tc_sec_011_key_format_storage_and_authentication() {
    let mut t = setup();
    let (rec, key) =
        create_api_key(&mut t, new_key(&["monitor"], None, &[]), t0(), &OsRng).unwrap();
    let k = key.expose();
    assert_eq!(k.len(), KEY_PREFIX.len() + KEY_ID_LEN + 1 + SECRET_CHARS);
    assert!(k.starts_with(&format!("rgn_{}_", rec.key_id)));
    assert!(
        k.bytes()
            .skip(4)
            .all(|c| c == b'_' || c.is_ascii_alphanumeric())
    );
    // The secret is not stored anywhere in the keyspace, only its Argon2id hash.
    let secret_part = &k[k.len() - SECRET_CHARS..];
    for (_, v) in t.dump() {
        assert!(!v.windows(SECRET_CHARS).any(|w| w == secret_part.as_bytes()));
    }
    assert_eq!(get_api_key(&t, &rec.key_id).unwrap(), Some(rec.clone()));
    assert_eq!(decode_api_key(&encode_api_key(&rec).unwrap()).unwrap(), rec);

    let principal = authenticate_api_key(&t, k, ip("10.1.2.3"), t0()).unwrap();
    assert_eq!(principal.user, "svc");
    assert_eq!(principal.roles, ["monitor"]);
    assert_eq!(principal.method, AuthMethod::ApiKey(rec.key_id.clone()));
    assert_eq!(principal.password_change, PasswordChange::NotRequired);

    // One flipped secret character, or a key id that does not exist: generic failure.
    let mut wrong = k.to_owned();
    let last = wrong.pop().unwrap();
    wrong.push(if last == 'A' { 'B' } else { 'A' });
    let r = authenticate_api_key(&t, &wrong, ip("10.1.2.3"), t0());
    assert!(failed(&r, FailureReason::BadCredentials), "{r:?}");
    let other_id = format!(
        "rgn_{}_{}",
        "Z".repeat(KEY_ID_LEN),
        &k[k.len() - SECRET_CHARS..]
    );
    assert!(failed(
        &authenticate_api_key(&t, &other_id, ip("10.1.2.3"), t0()),
        FailureReason::BadCredentials
    ));
    for junk in [
        "",
        "rgn_",
        "rgn_abc_def",
        &k[..k.len() - 1],
        &k.replace("rgn_", "rgx_"),
    ] {
        let r = authenticate_api_key(&t, junk, ip("10.1.2.3"), t0());
        assert!(failed(&r, FailureReason::Malformed), "{junk}");
    }
    let e: rustegon_common::Error = r.unwrap_err().into();
    assert_eq!(e.message(), crate::authn::AUTHENTICATION_FAILED);
}

#[test]
fn tc_sec_011_scope_must_be_subset_and_follows_owner_roles() {
    let mut t = setup();
    for roles in [&[][..], &["root"][..], &["read", "cluster_admin"][..]] {
        let r = create_api_key(&mut t, new_key(roles, None, &[]), t0(), &OsRng);
        assert!(
            matches!(r, Err(AuthnError::InvalidArgument(_))),
            "{roles:?}"
        );
    }
    let (_, key) = create_api_key(
        &mut t,
        new_key(&["read", "monitor"], None, &[]),
        t0(),
        &OsRng,
    )
    .unwrap();
    let p = authenticate_api_key(&t, key.expose(), ip("::1"), t0()).unwrap();
    assert_eq!(p.roles, ["monitor", "read"]);
    // Removing a role from the owner removes it from the key.
    set_roles(&mut t, "svc", vec!["read".into()], t0()).unwrap();
    let p = authenticate_api_key(&t, key.expose(), ip("::1"), t0()).unwrap();
    assert_eq!(p.roles, ["read"]);
    // A disabled owner disables the key; a dropped owner deletes it.
    set_state(&mut t, "svc", UserState::Disabled, t0()).unwrap();
    assert!(authenticate_api_key(&t, key.expose(), ip("::1"), t0()).is_err());
    assert!(create_api_key(&mut t, new_key(&["read"], None, &[]), t0(), &OsRng).is_err());
    set_state(&mut t, "svc", UserState::Enabled, t0()).unwrap();
    drop_user(&mut t, "svc").unwrap();
    assert_eq!(list_api_keys(&t, None).unwrap().len(), 0);
    assert!(t.is_empty());
}

#[test]
fn tc_sec_011_expiry() {
    let mut t = setup();
    let past = create_api_key(&mut t, new_key(&["read"], Some(t0()), &[]), t0(), &OsRng);
    assert!(matches!(past, Err(AuthnError::InvalidArgument(_))));
    let exp = t0() + Duration::from_hours(1);
    let (_, key) =
        create_api_key(&mut t, new_key(&["read"], Some(exp), &[]), t0(), &OsRng).unwrap();
    authenticate_api_key(&t, key.expose(), ip("::1"), exp - Duration::from_millis(1)).unwrap();
    let r = authenticate_api_key(&t, key.expose(), ip("::1"), exp);
    assert!(failed(&r, FailureReason::Expired));
}

#[test]
fn tc_sec_011_ip_allowlist() {
    let mut t = setup();
    let (_, key) = create_api_key(
        &mut t,
        new_key(
            &["read"],
            None,
            &["10.0.0.0/8", "192.168.1.7", "2001:db8::/32"],
        ),
        t0(),
        &OsRng,
    )
    .unwrap();
    for ok in [
        "10.255.0.1",
        "192.168.1.7",
        "::ffff:10.0.0.9",
        "2001:db8:1::5",
    ] {
        authenticate_api_key(&t, key.expose(), ip(ok), t0()).unwrap();
    }
    for bad in ["11.0.0.1", "192.168.1.8", "2001:db9::1", "::1"] {
        let r = authenticate_api_key(&t, key.expose(), ip(bad), t0());
        assert!(failed(&r, FailureReason::AddressNotAllowed), "{bad}");
    }
}

#[test]
fn tc_sec_011_cidr_parsing() {
    for bad in ["10.0.0.0/33", "::/129", "10.0.0/8", "x", "10.0.0.0/-1", ""] {
        assert!(bad.parse::<Cidr>().is_err(), "{bad}");
    }
    let c: Cidr = "0.0.0.0/0".parse().unwrap();
    assert!(c.contains(ip("8.8.8.8")) && !c.contains(ip("::2")));
    let c: Cidr = "::/0".parse().unwrap();
    assert!(c.contains(ip("2001::1")));
    assert_eq!(
        "192.168.1.7".parse::<Cidr>().unwrap().to_string(),
        "192.168.1.7/32"
    );
    assert_eq!(
        "::ffff:1.2.3.4/32".parse::<Cidr>().unwrap().to_string(),
        "1.2.3.4/32"
    );
}

#[test]
fn tc_sec_011_revoke_and_list() {
    let mut t = setup();
    let (a, ka) = create_api_key(&mut t, new_key(&["read"], None, &[]), t0(), &OsRng).unwrap();
    let (_, kb) = create_api_key(&mut t, new_key(&["monitor"], None, &[]), t0(), &OsRng).unwrap();
    assert_eq!(list_api_keys(&t, Some("svc")).unwrap().len(), 2);
    assert_eq!(list_api_keys(&t, Some("other")).unwrap().len(), 0);
    revoke_api_key(&mut t, &a.key_id).unwrap();
    assert!(authenticate_api_key(&t, ka.expose(), ip("::1"), t0()).is_err());
    authenticate_api_key(&t, kb.expose(), ip("::1"), t0()).unwrap();
    assert!(matches!(
        revoke_api_key(&mut t, &a.key_id),
        Err(AuthnError::NotFound(_))
    ));
}

#[test]
fn tc_sec_011_spec_cost_is_argon2id_64mib_t3_p1() {
    assert_eq!(
        ARGON2_COST,
        Argon2Cost {
            m_kib: 65_536,
            t: 3,
            p: 1
        }
    );
    // Verification uses the cost stored with the key: a key hashed at another cost verifies.
    let salt = [1u8; SALT_LEN];
    let a = argon2_hash(
        b"secret",
        &salt,
        Argon2Cost {
            m_kib: 32,
            t: 2,
            p: 1,
        },
    )
    .unwrap();
    let b = argon2_hash(
        b"secret",
        &salt,
        Argon2Cost {
            m_kib: 32,
            t: 2,
            p: 1,
        },
    )
    .unwrap();
    let c = argon2_hash(
        b"secret",
        &salt,
        Argon2Cost {
            m_kib: 32,
            t: 1,
            p: 1,
        },
    )
    .unwrap();
    assert_eq!(*a, *b);
    assert_ne!(*a, *c);
}
