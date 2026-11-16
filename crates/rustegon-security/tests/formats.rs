// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted-format fixtures of the authentication records (implementation-rules.md §6;
//! PD-047): user format 1, API key format 1, session format 1, realm format 1, and the system
//! key layout.
//!
//! - `<format>/1/<case>.rdoc` + `<case>.json`: canonical record bytes of a fixed record and
//!   their canonical JSON. Compatibility: every committed `.rdoc` must decode to the recorded
//!   value, forever. Stability: the current encoder must reproduce the bytes exactly; a failure
//!   means the format changed and needs version 2 plus new fixtures, not a regeneration.
//! - `keys/1/keys.txt`: system keys, `<label> <hex>` per line.
//!
//! The byte strings standing for salts, verifiers, hashes and keys are constants, not derived
//! from any real password or key (implementation-rules.md §8: no secrets in fixtures).
//!
//! Generate missing fixtures (existing files are never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-security --test formats`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustegon_doc::{
    json::{JsonMode, to_json},
    rdoc,
};
use rustegon_security::authn::{
    PasswordChange,
    apikey::{ApiKeyRecord, Argon2Cost, decode_api_key, encode_api_key},
    realm::{decode_realm, encode_realm},
    scram::{FakeSaltKey, ScramCredentials},
    session::{SessionKind, SessionRecord, decode_session, encode_session},
    store,
    users::{UserRecord, UserState, decode_user, encode_user},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats")
}

fn write_mode() -> bool {
    std::env::var_os("RUSTEGON_WRITE_FIXTURES").is_some()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Checks `bytes` against the committed fixture `<format>/1/<name>` and returns the committed
/// bytes for the decode check.
fn check(format: &str, name: &str, bytes: &[u8]) -> Vec<u8> {
    let dir = root().join(format).join("1");
    let json = to_json(&rdoc::decode(bytes).unwrap(), JsonMode::Canonical);
    let (rdoc_path, json_path) = (
        dir.join(format!("{name}.rdoc")),
        dir.join(format!("{name}.json")),
    );
    if write_mode() && !rdoc_path.exists() {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&rdoc_path, bytes).unwrap();
        std::fs::write(&json_path, &json).unwrap();
    }
    let committed = std::fs::read(&rdoc_path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (generate with RUSTEGON_WRITE_FIXTURES=1)",
            rdoc_path.display()
        )
    });
    assert_eq!(bytes, committed, "{format}/{name}: encoder output changed");
    assert_eq!(
        std::fs::read_to_string(&json_path).unwrap(),
        json,
        "{format}/{name}: JSON changed"
    );
    committed
}

fn users() -> Vec<(&'static str, UserRecord)> {
    vec![
        (
            "user_password",
            UserRecord {
                name: "alice".into(),
                roles: vec!["read@shop".into(), "read_write@shop".into()],
                state: UserState::Enabled,
                password_change: PasswordChange::NotRequired,
                credential_epoch: 3,
                created_at: at(1_800_000_000),
                updated_at: at(1_800_000_600),
                scram: Some(ScramCredentials::from_parts(
                    vec![0x11; 16],
                    600_000,
                    [0x22; 32],
                    [0x33; 32],
                )),
            },
        ),
        (
            "user_x509_disabled_must_change",
            UserRecord {
                name: "x509:CN=billing-service".into(),
                roles: vec![],
                state: UserState::Disabled,
                password_change: PasswordChange::Required,
                credential_epoch: 0,
                created_at: at(1_800_000_000),
                updated_at: at(1_800_000_000),
                scram: None,
            },
        ),
    ]
}

#[test]
fn user_v1_fixtures_stable_and_readable() {
    for (name, user) in users() {
        let committed = check("user", name, &encode_user(&user).unwrap());
        assert_eq!(decode_user(&committed).unwrap(), user, "{name}: decode");
    }
}

#[test]
fn api_key_v1_fixtures_stable_and_readable() {
    let full = ApiKeyRecord {
        key_id: "AbCdEf012345".into(),
        user: "svc".into(),
        name: "prometheus scraper".into(),
        roles: vec!["monitor".into()],
        created_at: at(1_800_000_000),
        expires_at: Some(at(1_900_000_000)),
        allow: vec![
            "10.0.0.0/8".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ],
        cost: Argon2Cost {
            m_kib: 65_536,
            t: 3,
            p: 1,
        },
        salt: [0x44; 16],
        hash: [0x55; 32],
    };
    let minimal = ApiKeyRecord {
        key_id: "zzzzzzzzzzzz".into(),
        expires_at: None,
        allow: vec![],
        ..full.clone()
    };
    for (name, key) in [("api_key_full", full), ("api_key_minimal", minimal)] {
        let committed = check("api_key", name, &encode_api_key(&key).unwrap());
        assert_eq!(decode_api_key(&committed).unwrap(), key, "{name}: decode");
    }
}

#[test]
fn session_v1_fixtures_stable_and_readable() {
    let gui = SessionRecord {
        user: "alice".into(),
        kind: SessionKind::Gui,
        created_at: at(1_800_000_000),
        last_seen: at(1_800_000_120),
        expires_at: at(1_800_086_400),
        credential_epoch: 3,
        client_info: "Mozilla/5.0".into(),
    };
    let driver = SessionRecord {
        kind: SessionKind::Driver,
        client_info: String::new(),
        ..gui.clone()
    };
    for (name, s) in [("session_gui", gui), ("session_driver", driver)] {
        let committed = check("session", name, &encode_session(&s).unwrap());
        assert_eq!(decode_session(&committed).unwrap(), s, "{name}: decode");
    }
}

#[test]
fn realm_v1_fixture_stable_and_readable() {
    let key = FakeSaltKey::new([0x5A; 32]);
    let committed = check(
        "realm",
        "realm",
        &encode_realm(&key, at(1_800_000_000)).unwrap(),
    );
    assert_eq!(decode_realm(&committed).unwrap().expose(), key.expose());
}

#[test]
fn authn_key_layout_fixture() {
    let h = [0xAB; 32];
    let lines = [
        ("user_key(alice)", store::user_key("alice")),
        ("user_prefix", store::user_prefix()),
        (
            "api_key_key(AbCdEf012345)",
            store::api_key_key("AbCdEf012345"),
        ),
        ("api_key_prefix", store::api_key_prefix()),
        ("session_key(ab*32)", store::session_key(&h)),
        (
            "session_user_key(alice,ab*32)",
            store::session_user_key("alice", &h),
        ),
        (
            "session_user_prefix(alice)",
            store::session_user_prefix("alice"),
        ),
        ("session_prefix", store::session_prefix()),
        ("realm_key", store::realm_key()),
    ];
    let text = lines.iter().fold(String::new(), |mut s, (label, bytes)| {
        let _ = writeln!(s, "{label} {}", hex(bytes));
        s
    });
    let path = root().join("keys/1/keys.txt");
    if write_mode() && !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &text).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (generate with RUSTEGON_WRITE_FIXTURES=1)",
            path.display()
        )
    });
    assert_eq!(text, committed, "authn key layout changed");
}
