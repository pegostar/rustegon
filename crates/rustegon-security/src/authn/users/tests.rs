// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! User management and sessions, including TC-SEC-007 (session revocation on password change).

use std::time::Duration;

use rustegon_sim_api::OsRng;

use super::*;
use crate::authn::{
    AuthMethod,
    error::AuthnError,
    scram::FakeSaltKey,
    secret,
    session::{
        LAST_SEEN_GRANULARITY, SessionKind, create_session, list_user_sessions, purge_expired,
        revoke_all_sessions, revoke_session, validate_session,
    },
    store::{MemSystemTxn, session_user_prefix},
    testutil::{SeqRng, fast_settings, t0},
};

const PW: &str = "correct horse battery";

fn with_alice() -> (MemSystemTxn, UserRecord) {
    let mut t = MemSystemTxn::new();
    let u = create_user(
        &mut t,
        &NewUser {
            name: "alice",
            password: Some(&secret(PW)),
            roles: vec!["read_write".into(), "read".into(), "read".into()],
            password_change: PasswordChange::NotRequired,
        },
        &fast_settings(),
        t0(),
        &OsRng,
    )
    .unwrap();
    (t, u)
}

#[test]
fn create_get_list_and_duplicate() {
    let (mut t, u) = with_alice();
    assert_eq!(u.roles, ["read", "read_write"]);
    assert_eq!(u.credential_epoch, 0);
    assert_eq!(get_user(&t, "alice").unwrap(), Some(u.clone()));
    assert_eq!(list_users(&t).unwrap(), vec![u]);
    let again = create_user(
        &mut t,
        &NewUser {
            name: "alice",
            password: None,
            roles: vec![],
            password_change: PasswordChange::NotRequired,
        },
        &fast_settings(),
        t0(),
        &OsRng,
    );
    assert!(matches!(again, Err(AuthnError::AlreadyExists(_))));
}

#[test]
fn user_names_and_passwords_are_validated() {
    for bad in ["", " bob", "bob ", "a\0b", "tab\tname", "node:n1", "x509:"] {
        assert!(validate_user_name(bad).is_err(), "{bad:?}");
    }
    assert!(validate_user_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
    for good in ["bob", "Bob Smith", "x509:CN=svc, O=Acme", "ünïcödé"] {
        validate_user_name(good).unwrap();
    }
    let mut t = MemSystemTxn::new();
    let mk = |t: &mut MemSystemTxn, name: &str, pw: Option<&SecretString>| {
        create_user(
            t,
            &NewUser {
                name,
                password: pw,
                roles: vec![],
                password_change: PasswordChange::NotRequired,
            },
            &fast_settings(),
            t0(),
            &OsRng,
        )
    };
    assert!(matches!(
        mk(&mut t, "weak", Some(&secret("password1234"))),
        Err(AuthnError::InvalidArgument(_))
    ));
    assert!(mk(&mut t, "x509:CN=svc", Some(&secret(PW))).is_err());
    mk(&mut t, "x509:CN=svc", None).unwrap();
    assert!(t.get(&user_key("weak")).unwrap().is_none());
}

#[test]
fn record_round_trip_and_strict_decoding() {
    let (_, u) = with_alice();
    let bytes = encode_user(&u).unwrap();
    assert_eq!(decode_user(&bytes).unwrap(), u);
    let mut doc = rustegon_doc::rdoc::decode(&bytes).unwrap();
    doc.insert("extra", Value::Bool(true));
    assert!(matches!(
        decode_user(&rustegon_doc::rdoc::encode(&doc).unwrap()),
        Err(AuthnError::Corrupt(_))
    ));
    doc.remove("extra");
    doc.insert("user_format", Value::Int64(2));
    assert!(decode_user(&rustegon_doc::rdoc::encode(&doc).unwrap()).is_err());
    let e: rustegon_common::Error = decode_user(b"junk").unwrap_err().into();
    assert_eq!(e.code(), rustegon_common::ErrorCode::StorageCorruption);
}

#[test]
fn tc_sec_007_password_change_revokes_sessions_and_bumps_epoch() {
    let (mut t, u) = with_alice();
    let s = fast_settings();
    let (tok1, rec) = create_session(
        &mut t,
        &u,
        SessionKind::Driver,
        "dotnet/1.0",
        &s,
        t0(),
        &OsRng,
    )
    .unwrap();
    let (tok2, _) =
        create_session(&mut t, &u, SessionKind::Gui, "firefox", &s, t0(), &OsRng).unwrap();
    assert_eq!(rec.credential_epoch, 0);
    let p = validate_session(&mut t, tok1.expose(), &s, t0()).unwrap();
    assert_eq!((p.user.as_str(), p.method), ("alice", AuthMethod::Session));
    assert_eq!(list_user_sessions(&t, "alice").unwrap().len(), 2);

    let u2 = set_password(
        &mut t,
        "alice",
        &secret("another long passphrase"),
        &s,
        t0(),
        &OsRng,
    )
    .unwrap();
    assert_eq!(u2.credential_epoch, 1);
    for tok in [&tok1, &tok2] {
        assert!(matches!(
            validate_session(&mut t, tok.expose(), &s, t0()),
            Err(AuthnError::SessionExpired)
        ));
    }
    assert_eq!(
        t.scan_prefix(&session_user_prefix("alice")).unwrap().len(),
        0
    );
    // The old password no longer verifies, the new one does.
    let creds = get_user(&t, "alice").unwrap().unwrap().scram.unwrap();
    assert!(!creds.verify_password(PW));
    assert!(creds.verify_password("another long passphrase"));
    // A weak new password is refused and changes nothing.
    assert!(set_password(&mut t, "alice", &secret("alice123alice"), &s, t0(), &OsRng).is_err());
    assert_eq!(get_user(&t, "alice").unwrap().unwrap().credential_epoch, 1);
}

#[test]
fn tc_sec_007_epoch_mismatch_rejects_a_session_that_escaped_deletion() {
    let (mut t, u) = with_alice();
    let s = fast_settings();
    let (tok, _) = create_session(&mut t, &u, SessionKind::Driver, "", &s, t0(), &OsRng).unwrap();
    // Simulate a concurrent session creation that survived revocation: bump the epoch only.
    let mut bumped = get_user(&t, "alice").unwrap().unwrap();
    bumped.credential_epoch = 5;
    put(&mut t, &bumped).unwrap();
    assert!(matches!(
        validate_session(&mut t, tok.expose(), &s, t0()),
        Err(AuthnError::SessionExpired)
    ));
    assert_eq!(
        list_user_sessions(&t, "alice").unwrap().len(),
        0,
        "stale session deleted"
    );
}

#[test]
fn tc_sec_007_role_change_disable_and_drop_revoke_sessions() {
    let s = fast_settings();
    let (mut t, u) = with_alice();
    let (tok, _) = create_session(&mut t, &u, SessionKind::Driver, "", &s, t0(), &OsRng).unwrap();
    let u = set_roles(&mut t, "alice", vec!["read".into()], t0()).unwrap();
    assert_eq!(
        (u.roles.as_slice(), u.credential_epoch),
        (&["read".to_owned()][..], 1)
    );
    assert!(validate_session(&mut t, tok.expose(), &s, t0()).is_err());

    let (tok, _) = create_session(&mut t, &u, SessionKind::Driver, "", &s, t0(), &OsRng).unwrap();
    let u = set_state(&mut t, "alice", UserState::Disabled, t0()).unwrap();
    assert_eq!(u.credential_epoch, 2);
    assert!(validate_session(&mut t, tok.expose(), &s, t0()).is_err());
    assert!(matches!(
        scram_lookup(&t, "alice").unwrap(),
        CredentialState::Disabled(_)
    ));
    let u = set_state(&mut t, "alice", UserState::Enabled, t0()).unwrap();
    assert_eq!(u.credential_epoch, 2, "enabling does not need a new epoch");
    assert!(matches!(
        scram_lookup(&t, "alice").unwrap(),
        CredentialState::Usable(_)
    ));

    let (tok, _) = create_session(&mut t, &u, SessionKind::Driver, "", &s, t0(), &OsRng).unwrap();
    drop_user(&mut t, "alice").unwrap();
    assert!(validate_session(&mut t, tok.expose(), &s, t0()).is_err());
    assert!(
        t.is_empty(),
        "user, sessions and index gone: {:?}",
        t.dump()
    );
    assert!(matches!(
        drop_user(&mut t, "alice"),
        Err(AuthnError::NotFound(_))
    ));
    assert!(matches!(
        scram_lookup(&t, "alice").unwrap(),
        CredentialState::Unknown
    ));
}

#[test]
fn sessions_expire_idle_and_absolute_and_refresh_last_seen() {
    let s = fast_settings();
    let (mut t, u) = with_alice();
    let rng = SeqRng::new(7);
    let (gui, _) = create_session(&mut t, &u, SessionKind::Gui, "", &s, t0(), &rng).unwrap();
    let (drv, _) = create_session(&mut t, &u, SessionKind::Driver, "", &s, t0(), &rng).unwrap();
    assert_ne!(gui.expose(), drv.expose());
    assert_eq!(gui.expose().len(), 43);
    // 29 min: both alive; the GUI session's last_seen moves forward.
    let t29 = t0() + Duration::from_mins(29);
    validate_session(&mut t, gui.expose(), &s, t29).unwrap();
    let t58 = t0() + Duration::from_mins(58);
    validate_session(&mut t, gui.expose(), &s, t58).unwrap();
    // 30 min after the last activity: idle expiry for the GUI, the driver lives on (12 h).
    let t88 = t0() + Duration::from_mins(88);
    assert!(validate_session(&mut t, gui.expose(), &s, t88).is_err());
    validate_session(&mut t, drv.expose(), &s, t88).unwrap();
    // A request every 11 h keeps the driver session idle-alive, but the absolute 24 h ends it.
    validate_session(&mut t, drv.expose(), &s, t0() + Duration::from_hours(11)).unwrap();
    validate_session(&mut t, drv.expose(), &s, t0() + Duration::from_hours(22)).unwrap();
    assert!(validate_session(&mut t, drv.expose(), &s, t0() + Duration::from_hours(24)).is_err());
    assert_eq!(list_user_sessions(&t, "alice").unwrap().len(), 0);
    assert!(LAST_SEEN_GRANULARITY <= Duration::from_mins(1));
}

#[test]
fn sessions_logout_purge_and_malformed_tokens() {
    let s = fast_settings();
    let (mut t, u) = with_alice();
    let (tok_a, _) = create_session(
        &mut t,
        &u,
        SessionKind::Gui,
        &"x".repeat(1000),
        &s,
        t0(),
        &OsRng,
    )
    .unwrap();
    let (tok_b, _) = create_session(&mut t, &u, SessionKind::Driver, "", &s, t0(), &OsRng).unwrap();
    let infos: Vec<usize> = list_user_sessions(&t, "alice")
        .unwrap()
        .iter()
        .map(|s| s.client_info.len())
        .collect();
    assert!(infos.contains(&crate::authn::session::MAX_CLIENT_INFO) && infos.contains(&0));
    assert!(revoke_session(&mut t, tok_a.expose()).unwrap());
    assert!(!revoke_session(&mut t, tok_a.expose()).unwrap());
    assert!(validate_session(&mut t, tok_a.expose(), &s, t0()).is_err());
    for junk in ["", "short", "!!!!", &"A".repeat(44)] {
        assert!(matches!(
            validate_session(&mut t, junk, &s, t0()),
            Err(AuthnError::SessionExpired)
        ));
    }
    assert_eq!(purge_expired(&mut t, &s, t0(), 10).unwrap(), 0);
    assert_eq!(
        purge_expired(&mut t, &s, t0() + Duration::from_hours(25), 10).unwrap(),
        1
    );
    assert!(validate_session(&mut t, tok_b.expose(), &s, t0()).is_err());
    assert_eq!(t.len(), 1, "only the user record is left");
}

#[test]
fn password_login_is_generic_for_every_failure() {
    let s = fast_settings();
    let (mut t, _) = with_alice();
    let fake = FakeSaltKey::new([3; 32]);
    let p = authenticate_password(&t, "alice", &secret(PW), &fake, &s).unwrap();
    assert_eq!((p.user.as_str(), p.method), ("alice", AuthMethod::Password));
    for (user, pw) in [("alice", "wrong password here"), ("nobody", PW)] {
        let r = authenticate_password(&t, user, &secret(pw), &fake, &s);
        assert!(matches!(r, Err(AuthnError::AuthenticationFailed(_))));
    }
    set_state(&mut t, "alice", UserState::Disabled, t0()).unwrap();
    assert!(authenticate_password(&t, "alice", &secret(PW), &fake, &s).is_err());
}

/// ADR-037: after an online restore every session of the backup is revoked, for every user.
#[test]
fn fr_bkp_001_revoke_all_sessions_after_a_restore() {
    let (mut t, alice) = with_alice();
    let s = fast_settings();
    let bob = create_user(
        &mut t,
        &NewUser {
            name: "bob",
            password: Some(&secret(PW)),
            roles: vec![],
            password_change: PasswordChange::NotRequired,
        },
        &s,
        t0(),
        &OsRng,
    )
    .unwrap();
    let (a, _) = create_session(&mut t, &alice, SessionKind::Gui, "", &s, t0(), &OsRng).unwrap();
    let (b, _) = create_session(&mut t, &bob, SessionKind::Driver, "", &s, t0(), &OsRng).unwrap();
    assert_eq!(revoke_all_sessions(&mut t).unwrap(), 2);
    for tok in [a, b] {
        assert!(validate_session(&mut t, tok.expose(), &s, t0()).is_err());
    }
    assert_eq!(list_user_sessions(&t, "alice").unwrap().len(), 0);
    assert_eq!(list_user_sessions(&t, "bob").unwrap().len(), 0);
    assert_eq!(revoke_all_sessions(&mut t).unwrap(), 0);
}
