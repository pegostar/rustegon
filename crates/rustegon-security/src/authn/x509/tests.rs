// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-SEC-012: X.509 subject → user mapping and node role detection.
//!
//! Certificates are generated in the test as DER from their parts. The signature is a dummy:
//! chain verification is the TLS layer's job and the mapping never looks at it.

use std::str::FromStr;

use rustegon_sim_api::OsRng;
use x509_cert::der::Encode;

use super::*;
use crate::authn::{
    store::MemSystemTxn,
    testutil::{fast_settings, t0},
    users::{NewUser, create_user, set_state},
};

/// DER tag-length-value.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    // DER: minimal length encoding (X.690 §10.1).
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else if len < 0x100 {
        out.push(0x81);
        out.push(u8::try_from(len).unwrap());
    } else {
        let bytes = u16::try_from(len).unwrap().to_be_bytes();
        out.push(0x82);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

fn oid(dotted: &str) -> Vec<u8> {
    tlv(0x06, &oid_content(dotted).unwrap())
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// EKU extension with the given purposes.
fn eku(purposes: &[&str]) -> Vec<u8> {
    let list = seq(&purposes.iter().map(|p| oid(p)).collect::<Vec<_>>());
    seq(&[oid("2.5.29.37"), tlv(0x04, &list)])
}

/// SAN extension; entries are `(context tag, value)`: 0x81 e-mail, 0x82 DNS, 0x86 URI.
fn san(entries: &[(u8, &str)]) -> Vec<u8> {
    let names = seq(&entries
        .iter()
        .map(|(t, v)| tlv(*t, v.as_bytes()))
        .collect::<Vec<_>>());
    seq(&[oid("2.5.29.17"), tlv(0x04, &names)])
}

const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

/// A v3 certificate with subject `subject` (RFC 4514 string) and `extensions`.
fn cert(subject: &str, extensions: &[Vec<u8>]) -> Vec<u8> {
    let name = |s: &str| Name::from_str(s).unwrap().to_der().unwrap();
    let alg = seq(&[oid("1.2.840.10045.4.3.2")]);
    let mut tbs = vec![
        tlv(0xA0, &tlv(0x02, &[2])),
        tlv(0x02, &[0x01, 0x23]),
        alg.clone(),
        name("CN=Rustegon Test CA"),
        seq(&[tlv(0x17, b"250101000000Z"), tlv(0x17, b"350101000000Z")]),
        name(subject),
        seq(&[
            seq(&[oid("1.3.101.112")]),
            tlv(0x03, &[[0u8].as_slice(), &[7u8; 32]].concat()),
        ]),
    ];
    if !extensions.is_empty() {
        tbs.push(tlv(0xA3, &seq(extensions)));
    }
    seq(&[seq(&tbs), alg, tlv(0x03, &[0, 1, 2, 3])])
}

fn with_users(names: &[&str]) -> MemSystemTxn {
    let mut t = MemSystemTxn::new();
    for name in names {
        create_user(
            &mut t,
            &NewUser {
                name,
                password: None,
                roles: vec!["read".into()],
                password_change: PasswordChange::NotRequired,
            },
            &fast_settings(),
            t0(),
            &OsRng,
        )
        .unwrap();
    }
    t
}

#[test]
fn tc_sec_012_node_role_oid_encoding_matches_shared_constant() {
    // 2.25.<uuid> (PD-046): the 128-bit arc needs 19 base-128 groups at most.
    let content = oid_content(NODE_ROLE_OID).unwrap();
    assert_eq!(&content[..1], &[0x69]); // 2 * 40 + 25 = 105
    assert!(content.len() > 10);
    assert_eq!(oid_content("2.5.29.37").unwrap(), [0x55, 0x1D, 0x25]);
    assert_eq!(
        oid_content("1.2.840.10045.4.3.2").unwrap(),
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
    );
    for bad in ["", "1", "3.1", "1.40", "1.2.x"] {
        assert!(oid_content(bad).is_none(), "{bad}");
    }
}

#[test]
fn tc_sec_012_client_cn_maps_to_x509_user() {
    let t = with_users(&["x509:CN=billing-service"]);
    let der = cert("CN=billing-service,O=Acme", &[eku(&[CLIENT_AUTH])]);
    assert_eq!(
        identity_from_cert(&der).unwrap(),
        CertIdentity::User("x509:CN=billing-service".into())
    );
    let p = authenticate_certificate(&t, &der).unwrap();
    assert_eq!(p.user, "x509:CN=billing-service");
    assert_eq!(p.roles, ["read"]);
    assert_eq!(p.method, AuthMethod::Certificate);
}

#[test]
fn tc_sec_012_san_is_used_without_cn() {
    let der = cert(
        "O=Acme",
        &[san(&[(0x82, "svc.example.com"), (0x81, "a@example.com")])],
    );
    assert_eq!(
        identity_from_cert(&der).unwrap(),
        CertIdentity::User("x509:DNS=svc.example.com".into())
    );
    let der = cert("O=Acme", &[san(&[(0x81, "ops@example.com")])]);
    assert_eq!(
        identity_from_cert(&der).unwrap(),
        CertIdentity::User("x509:email=ops@example.com".into())
    );
    let der = cert("O=Acme", &[san(&[(0x86, "spiffe://acme/billing")])]);
    assert_eq!(
        identity_from_cert(&der).unwrap(),
        CertIdentity::User("x509:URI=spiffe://acme/billing".into())
    );
    // No CN and no usable SAN.
    assert!(identity_from_cert(&cert("O=Acme", &[])).is_err());
}

#[test]
fn tc_sec_012_node_certificate_maps_to_node_role() {
    let der = cert(
        "CN=node-1",
        &[
            eku(&[SERVER_AUTH, CLIENT_AUTH, NODE_ROLE_OID]),
            san(&[(0x82, "node-1.cluster")]),
        ],
    );
    assert_eq!(
        identity_from_cert(&der).unwrap(),
        CertIdentity::Node("node-1".into())
    );
    // No user record is needed for a node.
    let p = authenticate_certificate(&MemSystemTxn::new(), &der).unwrap();
    assert_eq!(p.user, "node:node-1");
    assert_eq!(p.roles, [NODE_ROLE]);
    // A node certificate needs a CN.
    let der = cert(
        "O=Acme",
        &[eku(&[NODE_ROLE_OID]), san(&[(0x82, "n.cluster")])],
    );
    assert!(identity_from_cert(&der).is_err());
    // A different 2.25 OID is not the node role.
    let der = cert("CN=node-1", &[eku(&["2.25.1", CLIENT_AUTH])]);
    assert_eq!(
        identity_from_cert(&der).unwrap(),
        CertIdentity::User("x509:CN=node-1".into())
    );
}

/// Node certificate format 2 (ADR-035): the node role is the URI SAN `urn:rustegon:role:node`.
#[test]
fn tc_sec_012_node_role_uri_san_maps_to_node_role() {
    let der = cert(
        "CN=node-1",
        &[
            eku(&[SERVER_AUTH, CLIENT_AUTH]),
            san(&[(0x82, "node-1.cluster"), (0x86, NODE_ROLE_URI)]),
        ],
    );
    assert_eq!(
        identity_from_cert(&der).unwrap(),
        CertIdentity::Node("node-1".into())
    );
    let p = authenticate_certificate(&MemSystemTxn::new(), &der).unwrap();
    assert_eq!(p.user, "node:node-1");
    assert_eq!(p.roles, [NODE_ROLE]);
    // A node certificate needs a CN; without one the URI is not taken as a user name either.
    let der = cert("O=Acme", &[san(&[(0x86, NODE_ROLE_URI)])]);
    assert!(identity_from_cert(&der).is_err());
    // Near misses are ordinary URIs of a user certificate: exact, case-sensitive match only.
    for uri in [
        "urn:rustegon:role:node2",
        "URN:RUSTEGON:ROLE:NODE",
        "urn:rustegon:role:admin",
    ] {
        let der = cert("CN=svc", &[eku(&[CLIENT_AUTH]), san(&[(0x86, uri)])]);
        assert_eq!(
            identity_from_cert(&der).unwrap(),
            CertIdentity::User("x509:CN=svc".into()),
            "{uri}"
        );
    }
    // Neither marker: a user, even with serverAuth + clientAuth like a node.
    let der = cert(
        "CN=node-1",
        &[
            eku(&[SERVER_AUTH, CLIENT_AUTH]),
            san(&[(0x82, "n.cluster")]),
        ],
    );
    assert_eq!(
        identity_from_cert(&der).unwrap(),
        CertIdentity::User("x509:CN=node-1".into())
    );
    // A repeated SAN extension or a malformed EKU next to the URI is refused, not guessed.
    for der in [
        cert(
            "CN=node-1",
            &[san(&[(0x86, NODE_ROLE_URI)]), san(&[(0x82, "n.cluster")])],
        ),
        cert(
            "CN=node-1",
            &[
                san(&[(0x86, NODE_ROLE_URI)]),
                eku(&[CLIENT_AUTH]),
                eku(&[SERVER_AUTH]),
            ],
        ),
    ] {
        assert!(identity_from_cert(&der).is_err());
    }
}

/// Real node certificates written by `rustegon init --tls`, committed as rustegon-net format
/// fixtures: format 1 (legacy EKU OID, before ADR-035) and format 2 (URI SAN) both map to the
/// node principal; their CA certificates do not.
#[test]
fn tc_sec_012_node_cert_fixtures_of_both_formats_map_to_node() {
    const V1: &[u8] =
        include_bytes!("../../../../rustegon-net/tests/fixtures/formats/node_cert/1/node.der");
    const V2: &[u8] =
        include_bytes!("../../../../rustegon-net/tests/fixtures/formats/node_cert/2/node.der");
    const CA1: &[u8] =
        include_bytes!("../../../../rustegon-net/tests/fixtures/formats/node_cert/1/ca.der");
    for der in [V1, V2] {
        assert_eq!(
            identity_from_cert(der).unwrap(),
            CertIdentity::Node("node1".into())
        );
    }
    assert!(!matches!(
        identity_from_cert(CA1),
        Ok(CertIdentity::Node(_))
    ));
}

#[test]
fn tc_sec_012_unknown_disabled_and_ambiguous_certificates_fail_generically() {
    let mut t = with_users(&["x509:CN=alice"]);
    let alice = cert("CN=alice", &[]);
    authenticate_certificate(&t, &alice).unwrap();
    let r = authenticate_certificate(&t, &cert("CN=mallory", &[]));
    assert!(matches!(
        r,
        Err(AuthnError::AuthenticationFailed(
            FailureReason::BadCredentials
        ))
    ));
    set_state(
        &mut t,
        "x509:CN=alice",
        crate::authn::users::UserState::Disabled,
        t0(),
    )
    .unwrap();
    assert!(authenticate_certificate(&t, &alice).is_err());
    for der in [
        cert("CN=a,CN=b", &[]),
        cert("CN=alice", &[eku(&[CLIENT_AUTH]), eku(&[NODE_ROLE_OID])]),
        b"not a certificate".to_vec(),
        alice[..alice.len() - 1].to_vec(),
    ] {
        let r = authenticate_certificate(&t, &der);
        assert!(
            matches!(
                r,
                Err(AuthnError::AuthenticationFailed(FailureReason::Malformed))
            ),
            "{r:?}"
        );
    }
}
