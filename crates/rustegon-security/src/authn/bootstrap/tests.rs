// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-SEC-003: no default credentials; the first admin comes only from bootstrap.

use std::net::IpAddr;

use rustegon_sim_api::OsRng;

use super::*;
use crate::authn::{
    PasswordChange,
    apikey::authenticate_api_key,
    scram::{
        ClientBinding, ClientFirst, CredentialState, ScramClient, ScramServer, ServerBinding,
        ServerContext,
    },
    secret,
    store::MemSystemTxn,
    testutil::{fast_settings, t0},
    users::{authenticate_password, get_user, scram_lookup},
    x509::authenticate_certificate,
};

/// Full SCRAM handshake against the store; `Ok` only if the server accepts.
fn scram_login(t: &MemSystemTxn, user: &str, pw: &str) -> AuthnResult<()> {
    let key = realm::load_or_ephemeral(t, &OsRng)?;
    let ctx = ServerContext {
        binding: ServerBinding::Unavailable,
        fake_salt_key: &key,
        default_iterations: fast_settings().scram_iterations,
    };
    let (c, mech, first) = ScramClient::new(user, &secret(pw), ClientBinding::Unsupported, &OsRng);
    let first = ClientFirst::parse(mech, &first)?;
    let state = scram_lookup(t, first.user())?;
    let (s, sf) = ScramServer::start(first, state, &ctx, &OsRng)?;
    let (_, cf) = c.server_first(&sf)?;
    s.finish(&cf).map(|_| ())
}

/// Guesses an attacker would try on a fresh install.
const DEFAULTS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("root", "root"),
    ("root", ""),
    ("rustegon", "rustegon"),
];

#[test]
fn tc_sec_003_fresh_install_has_no_usable_credentials() {
    let t = MemSystemTxn::new();
    assert!(!is_bootstrapped(&t).unwrap());
    let fake = realm::load_or_ephemeral(&t, &OsRng).unwrap();
    for (user, pw) in DEFAULTS {
        assert!(scram_lookup(&t, user).is_ok_and(|s| matches!(s, CredentialState::Unknown)));
        assert!(scram_login(&t, user, pw).is_err(), "{user}/{pw}");
        assert!(authenticate_password(&t, user, &secret(*pw), &fake, &fast_settings()).is_err());
    }
    let any_key = format!("rgn_{}_{}", "A".repeat(12), "0".repeat(43));
    assert!(authenticate_api_key(&t, &any_key, IpAddr::from([127, 0, 0, 1]), t0()).is_err());
    // Not even a syntactically valid certificate is needed to see that no user exists.
    assert!(authenticate_certificate(&t, b"").is_err());
    assert!(t.is_empty(), "authentication attempts write nothing");
}

#[test]
fn tc_sec_003_bootstrap_with_provided_password() {
    let mut t = MemSystemTxn::new();
    let weak = bootstrap_admin(
        &mut t,
        DEFAULT_ADMIN_USER,
        AdminPassword::Provided(secret("admin")),
        &fast_settings(),
        t0(),
        &OsRng,
    );
    assert!(matches!(weak, Err(AuthnError::InvalidArgument(_))));
    let b = bootstrap_admin(
        &mut t,
        DEFAULT_ADMIN_USER,
        AdminPassword::Provided(secret("a long and unusual passphrase")),
        &fast_settings(),
        t0(),
        &OsRng,
    )
    .unwrap();
    assert!(b.generated_password.is_none());
    assert_eq!(b.admin.roles, [ADMIN_ROLE]);
    assert_eq!(b.admin.password_change, PasswordChange::NotRequired);
    assert!(realm::load(&t).unwrap().is_some());
    scram_login(&t, "admin", "a long and unusual passphrase").unwrap();
    for (user, pw) in DEFAULTS {
        assert!(scram_login(&t, user, pw).is_err(), "{user}/{pw}");
    }
}

#[test]
fn tc_sec_003_bootstrap_generates_password_once() {
    let mut t = MemSystemTxn::new();
    let b = bootstrap_admin(
        &mut t,
        DEFAULT_ADMIN_USER,
        AdminPassword::Generate,
        &fast_settings(),
        t0(),
        &OsRng,
    )
    .unwrap();
    let pw = b.generated_password.unwrap();
    assert_eq!(pw.expose().len(), crate::authn::password::GENERATED_LENGTH);
    assert!(!format!("{:?}", b.admin).contains(pw.expose().as_str()));
    let admin = get_user(&t, "admin").unwrap().unwrap();
    assert_eq!(admin.password_change, PasswordChange::Required);
    scram_login(&t, "admin", pw.expose()).unwrap();
    // Exactly once.
    let again = bootstrap_admin(
        &mut t,
        "other",
        AdminPassword::Generate,
        &fast_settings(),
        t0(),
        &OsRng,
    );
    assert!(matches!(again, Err(AuthnError::PreconditionFailed(_))));
    assert!(get_user(&t, "other").unwrap().is_none());
}

/// TC-SEC-021 (ADR-036): the turnkey bootstrap is the one path that stores `admin`/`admin`;
/// it is flagged `must_change_password`, detected by [`has_turnkey_password`] until changed,
/// and runs only once like every bootstrap.
#[test]
fn tc_sec_021_turnkey_bootstrap_admin_admin_must_change() {
    let mut t = MemSystemTxn::new();
    let b = bootstrap_admin(
        &mut t,
        DEFAULT_ADMIN_USER,
        AdminPassword::Turnkey,
        &fast_settings(),
        t0(),
        &OsRng,
    )
    .unwrap();
    assert!(b.generated_password.is_none(), "nothing to hand out");
    assert_eq!(b.admin.roles, [ADMIN_ROLE]);
    assert_eq!(b.admin.password_change, PasswordChange::Required);
    scram_login(&t, "admin", TURNKEY_ADMIN_PASSWORD).unwrap();
    let admin = get_user(&t, "admin").unwrap().unwrap();
    assert!(has_turnkey_password(&admin));
    // The policy still refuses the same password on every other path.
    assert!(matches!(
        crate::authn::users::prepare_password(
            "admin",
            &secret(TURNKEY_ADMIN_PASSWORD),
            &fast_settings(),
            &OsRng
        ),
        Err(AuthnError::InvalidArgument(_))
    ));
    // Changed: no longer the turnkey password, whatever the flag says.
    crate::authn::users::set_password(
        &mut t,
        "admin",
        &secret("a long and unusual passphrase"),
        &fast_settings(),
        t0(),
        &OsRng,
    )
    .unwrap();
    let mut changed = get_user(&t, "admin").unwrap().unwrap();
    assert!(!has_turnkey_password(&changed));
    changed.password_change = PasswordChange::Required;
    assert!(!has_turnkey_password(&changed));
    let again = bootstrap_admin(
        &mut t,
        DEFAULT_ADMIN_USER,
        AdminPassword::Turnkey,
        &fast_settings(),
        t0(),
        &OsRng,
    );
    assert!(matches!(again, Err(AuthnError::PreconditionFailed(_))));
}
