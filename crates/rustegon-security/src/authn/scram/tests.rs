// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-SEC-002: SCRAM test vectors, channel binding and generic failures.

use rustegon_sim_api::OsRng;

use super::*;
use crate::authn::secret;

/// RFC 7677 §3 example (user `user`, password `pencil`).
const RFC_SALT: &str = "W22ZaJ0SNY7soEsUEjb6gQ==";
const RFC_CNONCE: &str = "rOprNGfwEbeRWgbNEkqO";
const RFC_SNONCE: &str = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
const RFC_CLIENT_FIRST: &str = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
const RFC_SERVER_FIRST: &str =
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const RFC_CLIENT_FINAL: &str = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                                p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
const RFC_SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
/// Iterations of the non-vector tests: the RFC minimum keeps debug-build tests fast.
const ITER: u32 = MIN_ITERATIONS;

fn rfc_creds() -> ScramCredentials {
    ScramCredentials::derive("pencil", &B64.decode(RFC_SALT).unwrap(), 4096).unwrap()
}

fn key() -> FakeSaltKey {
    FakeSaltKey::new([9u8; 32])
}

fn ctx(key: &FakeSaltKey, binding: ServerBinding) -> ServerContext<'_> {
    ServerContext {
        binding,
        fake_salt_key: key,
        default_iterations: ITER,
    }
}

fn is_generic_failure(r: &AuthnResult<impl std::fmt::Debug>) -> bool {
    matches!(r, Err(AuthnError::AuthenticationFailed(_)))
}

/// Runs a full handshake with `client_pw` against `state`.
fn handshake(
    client_pw: &str,
    state: CredentialState,
    client: ClientBinding,
    server: ServerBinding,
) -> AuthnResult<()> {
    let key = key();
    let (c, mech, first) = ScramClient::new("alice", &secret(client_pw), client, &OsRng);
    let first = ClientFirst::parse(mech, &first)?;
    assert_eq!(first.user(), "alice");
    let (s, server_first) = ScramServer::start(first, state, &ctx(&key, server), &OsRng)?;
    let (c, client_final) = c.server_first(&server_first)?;
    let ok = s.finish(&client_final)?;
    assert_eq!(ok.user, "alice");
    c.server_final(&ok.server_final)
}

fn alice() -> ScramCredentials {
    ScramCredentials::generate("correct horse battery", ITER, &OsRng).unwrap()
}

#[test]
fn tc_sec_002_rfc7677_vector_server() {
    let first = ClientFirst::parse(Mechanism::ScramSha256, RFC_CLIENT_FIRST).unwrap();
    assert_eq!(first.user(), "user");
    let key = key();
    let (server, server_first) = ScramServer::start_with_nonce(
        first,
        CredentialState::Usable(rfc_creds()),
        &ctx(&key, ServerBinding::Unavailable),
        &OsRng,
        RFC_SNONCE,
    )
    .unwrap();
    assert_eq!(server_first, RFC_SERVER_FIRST);
    let ok = server.finish(RFC_CLIENT_FINAL).unwrap();
    assert_eq!(ok.server_final, RFC_SERVER_FINAL);
    assert_eq!(ok.user, "user");
}

#[test]
fn tc_sec_002_rfc7677_vector_client() {
    let (client, mech, first) = ScramClient::with_nonce(
        "user",
        &secret("pencil"),
        ClientBinding::Unsupported,
        RFC_CNONCE,
    );
    assert_eq!(mech, Mechanism::ScramSha256);
    assert_eq!(first, RFC_CLIENT_FIRST);
    let (fin, client_final) = client.server_first(RFC_SERVER_FIRST).unwrap();
    assert_eq!(client_final, RFC_CLIENT_FINAL);
    fin.server_final(RFC_SERVER_FINAL).unwrap();
}

#[test]
fn tc_sec_002_rfc7677_client_rejects_forged_server_signature() {
    let (client, _, _) = ScramClient::with_nonce(
        "user",
        &secret("pencil"),
        ClientBinding::Unsupported,
        RFC_CNONCE,
    );
    let (fin, _) = client.server_first(RFC_SERVER_FIRST).unwrap();
    let forged = "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert!(is_generic_failure(&fin.server_final(forged)));
}

#[test]
fn tc_sec_002_credentials_and_plain_password_verification() {
    let c = rfc_creds();
    assert!(c.verify_password("pencil"));
    assert!(!c.verify_password("pencil "));
    assert!(!format!("{c:?}").contains(&B64.encode(c.stored_key())));
    // SASLprep: U+00A0 (non-ASCII space) maps to U+0020, so both spellings derive one key.
    let a = ScramCredentials::derive("a\u{00A0}b", b"salt", ITER).unwrap();
    let b = ScramCredentials::derive("a b", b"salt", ITER).unwrap();
    assert_eq!(a.stored_key(), b.stored_key());
    assert!(ScramCredentials::derive("x", b"salt", ITER - 1).is_err());
    assert!(ScramCredentials::derive("x", b"", ITER).is_err());
}

#[test]
fn tc_sec_002_round_trip_without_and_with_channel_binding() {
    handshake(
        "correct horse battery",
        CredentialState::Usable(alice()),
        ClientBinding::Unsupported,
        ServerBinding::Unavailable,
    )
    .unwrap();
    // `n` is accepted even when the server could bind (client without exporter support).
    handshake(
        "correct horse battery",
        CredentialState::Usable(alice()),
        ClientBinding::Unsupported,
        ServerBinding::TlsExporter([1; 32]),
    )
    .unwrap();
    handshake(
        "correct horse battery",
        CredentialState::Usable(alice()),
        ClientBinding::NotOffered,
        ServerBinding::Unavailable,
    )
    .unwrap();
    handshake(
        "correct horse battery",
        CredentialState::Usable(alice()),
        ClientBinding::TlsExporter([7; 32]),
        ServerBinding::TlsExporter([7; 32]),
    )
    .unwrap();
}

#[test]
fn tc_sec_002_channel_binding_mismatch_and_downgrade_fail() {
    // Different exporters: a TLS-terminating man in the middle.
    let r = handshake(
        "correct horse battery",
        CredentialState::Usable(alice()),
        ClientBinding::TlsExporter([7; 32]),
        ServerBinding::TlsExporter([8; 32]),
    );
    assert!(matches!(
        r,
        Err(AuthnError::AuthenticationFailed(
            FailureReason::ChannelBinding
        ))
    ));
    // `y` while the server supports binding: the PLUS mechanism was stripped in transit.
    let r = handshake(
        "correct horse battery",
        CredentialState::Usable(alice()),
        ClientBinding::NotOffered,
        ServerBinding::TlsExporter([8; 32]),
    );
    assert!(matches!(
        r,
        Err(AuthnError::AuthenticationFailed(
            FailureReason::ChannelBinding
        ))
    ));
    // `p=` without an exporter on the server side.
    let r = handshake(
        "correct horse battery",
        CredentialState::Usable(alice()),
        ClientBinding::TlsExporter([7; 32]),
        ServerBinding::Unavailable,
    );
    assert!(is_generic_failure(&r));
    // Mechanism / flag mismatches and unknown binding types.
    for (mech, msg) in [
        (
            Mechanism::ScramSha256Plus,
            "n,,n=alice,r=0123456789abcdefXYZ",
        ),
        (
            Mechanism::ScramSha256,
            "p=tls-exporter,,n=alice,r=0123456789abcdefXYZ",
        ),
        (
            Mechanism::ScramSha256Plus,
            "p=tls-unique,,n=alice,r=0123456789abcdefXYZ",
        ),
    ] {
        assert!(is_generic_failure(&ClientFirst::parse(mech, msg)), "{msg}");
    }
}

#[test]
fn tc_sec_002_wrong_password_unknown_and_disabled_fail_identically() {
    let creds = alice();
    for (pw, state) in [
        ("wrong password!!", CredentialState::Usable(creds.clone())),
        (
            "correct horse battery",
            CredentialState::Disabled(creds.clone()),
        ),
        ("correct horse battery", CredentialState::Unknown),
    ] {
        let r = handshake(
            pw,
            state,
            ClientBinding::Unsupported,
            ServerBinding::Unavailable,
        );
        assert!(
            matches!(
                r,
                Err(AuthnError::AuthenticationFailed(
                    FailureReason::BadCredentials
                ))
            ),
            "{r:?}"
        );
        let e: rustegon_common::Error = r.unwrap_err().into();
        assert_eq!(e.message(), crate::authn::AUTHENTICATION_FAILED);
    }
}

#[test]
fn tc_sec_002_fake_salt_is_stable_per_user_and_shaped_like_a_real_one() {
    let key = key();
    let server_first = |user: &str, k: &FakeSaltKey| {
        let msg = format!("n,,n={user},r=0123456789abcdefXYZ");
        let first = ClientFirst::parse(Mechanism::ScramSha256, &msg).unwrap();
        let (_, sf) = ScramServer::start(
            first,
            CredentialState::Unknown,
            &ctx(k, ServerBinding::Unavailable),
            &OsRng,
        )
        .unwrap();
        let mut parts = sf.split(',');
        parts.next();
        (
            parts.next().unwrap().to_owned(),
            parts.next().unwrap().to_owned(),
        )
    };
    let (s1, i1) = server_first("ghost", &key);
    let (s2, _) = server_first("ghost", &key);
    let (s3, _) = server_first("other", &key);
    let (s4, _) = server_first("ghost", &FakeSaltKey::new([1; 32]));
    assert_eq!(s1, s2, "same unknown user, same salt");
    assert_ne!(s1, s3);
    assert_ne!(s1, s4);
    assert_eq!(i1, format!("i={ITER}"));
    // Same length as a real 16-byte salt.
    assert_eq!(B64.decode(&s1[2..]).unwrap().len(), SALT_LEN);
}

#[test]
fn tc_sec_002_tampered_messages_fail() {
    let key = key();
    let run = |tamper: &dyn Fn(String) -> String| {
        let (c, mech, first) = ScramClient::new(
            "alice",
            &secret("correct horse battery"),
            ClientBinding::Unsupported,
            &OsRng,
        );
        let first = ClientFirst::parse(mech, &first).unwrap();
        let (s, sf) = ScramServer::start(
            first,
            CredentialState::Usable(alice()),
            &ctx(&key, ServerBinding::Unavailable),
            &OsRng,
        )
        .unwrap();
        let (_, cf) = c.server_first(&sf).unwrap();
        s.finish(&tamper(cf))
    };
    assert!(run(&|cf| cf).is_ok());
    // Nonce replaced.
    let r = run(&|cf| {
        let mut parts: Vec<String> = cf.split(',').map(str::to_owned).collect();
        parts[1] = "r=0123456789abcdefXYZother".into();
        parts.join(",")
    });
    assert!(is_generic_failure(&r));
    // Proof truncated / garbage.
    assert!(is_generic_failure(&run(&|cf| format!(
        "{}AA",
        &cf[..cf.len() - 4]
    ))));
    assert!(is_generic_failure(&run(&|_| "garbage".into())));
}

#[test]
fn tc_sec_002_parser_rejects_malformed_client_first() {
    for msg in [
        "",
        "n,,",
        "n,,n=alice",
        "n,,r=0123456789abcdefXYZ,n=alice",
        "n,,n=alice,r=short",
        "n,,n=,r=0123456789abcdefXYZ",
        "n,,n=al=ice,r=0123456789abcdefXYZ",
        "n,,m=ext,n=alice,r=0123456789abcdefXYZ",
        "n,,n=alice,r=0123456789abcdefXYZ,x=ext",
        "x,,n=alice,r=0123456789abcdefXYZ",
        "n,a=bob,n=alice,r=0123456789abcdefXYZ",
    ] {
        assert!(
            is_generic_failure(&ClientFirst::parse(Mechanism::ScramSha256, msg)),
            "{msg:?}"
        );
    }
    let long = format!("n,,n=alice,r={}", "x".repeat(MAX_MESSAGE_LEN));
    assert!(is_generic_failure(&ClientFirst::parse(
        Mechanism::ScramSha256,
        &long
    )));
    // Escaped names and a matching authzid are fine.
    let first = ClientFirst::parse(
        Mechanism::ScramSha256,
        "n,a=a=2Cb=3Dc,n=a=2Cb=3Dc,r=0123456789abcdefXYZ",
    )
    .unwrap();
    assert_eq!(first.user(), "a,b=c");
    assert_eq!(encode_saslname("a,b=c"), "a=2Cb=3Dc");
}

#[test]
fn tc_sec_002_client_rejects_downgraded_or_foreign_server_first() {
    let mk = || {
        ScramClient::with_nonce(
            "u",
            &secret("pencil"),
            ClientBinding::Unsupported,
            RFC_CNONCE,
        )
        .0
    };
    for sf in [
        "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4095",
        "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=10000001",
        "r=otherNonceXXXXXXXXXXXXXX,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        "r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        "r=rOprNGfwEbeRWgbNEkqOx,s=,i=4096",
        "e=other-error",
    ] {
        assert!(is_generic_failure(&mk().server_first(sf)), "{sf}");
    }
    assert!(Mechanism::parse("PLAIN").is_err());
    assert_eq!(
        Mechanism::parse(MECHANISM_PLUS).unwrap(),
        Mechanism::ScramSha256Plus
    );
}
