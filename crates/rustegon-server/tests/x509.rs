// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! X.509 authentication over a real mTLS connection (TC-SEC-012, PD-046/PD-047/PD-051): a node
//! certificate issued by `rustegon_net::CertAuthority` (rcgen, node role URI SAN, ADR-035) maps through
//! `rustegon_security::authn::x509` to the principal `node:<CN>` with the built-in `node` role;
//! a client certificate maps to its `x509:CN=<cn>` user.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{Harness, authed, base_flags, bearer, code_of};
use rustegon_net::has_node_role;
use rustegon_proto::v1::{
    AuthMechanism, CreateUserRequest, GetSettingsRequest, ListUsersRequest, RoleGrant,
    WhoAmIRequest, admin_service_client::AdminServiceClient,
    auth_service_client::AuthServiceClient,
};
use rustegon_security::authn::x509::{CertIdentity, identity_from_cert};

fn grant(role: &str, resource: &str) -> RoleGrant {
    RoleGrant {
        role: role.into(),
        resource: resource.into(),
    }
}

#[tokio::test]
async fn tc_sec_012_node_certificate_maps_to_node_principal_over_mtls() {
    let h = Harness::start(base_flags()).await;
    let node = h.pki.node_cert("node9");
    let der = rustegon_net::parse_certificates(
        node.cert_pem.as_bytes(),
        std::path::Path::new("node9.crt"),
    )
    .unwrap()
    .remove(0);
    // The rcgen certificate carries the node role URI SAN, and authn::x509 sees it.
    assert!(has_node_role(&der).unwrap());
    assert_eq!(
        identity_from_cert(der.as_ref()).unwrap(),
        CertIdentity::Node("node9".into())
    );

    let conn = h.connect(Some(h.pki.identity("node9", &node))).await;
    // No `authorization`: the verified certificate of the connection authenticates.
    let me = AuthServiceClient::new(conn.channel.clone())
        .who_am_i(WhoAmIRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(me.user, "node:node9");
    assert_eq!(me.roles, vec![grant("node", "cluster")]);
    assert_eq!(me.mechanism, AuthMechanism::X509 as i32);
    // Authenticate{X509} succeeds without a session for nodes.
    let ok = conn.login_x509().await.unwrap();
    assert_eq!(ok.user, "node:node9");
    assert_eq!(ok.session_token, "");
    // The node role sees topology/settings (cluster_view) but administers nothing.
    let mut admin = AdminServiceClient::new(conn.channel.clone());
    admin
        .get_settings(GetSettingsRequest { names: vec![] })
        .await
        .unwrap();
    let e = admin.list_users(ListUsersRequest {}).await.unwrap_err();
    assert_eq!(code_of(&e), 4002);
    h.stop().await;
}

#[tokio::test]
async fn tc_sec_012_client_certificate_maps_to_its_x509_user() {
    let h = Harness::start(base_flags()).await;
    let svc = h.pki.client_cert("svc");
    let conn = h.connect(Some(h.pki.identity("svc", &svc))).await;
    // Unknown user: rejected like any credential.
    let e = AuthServiceClient::new(conn.channel.clone())
        .who_am_i(WhoAmIRequest {})
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 4001);
    let e = conn.login_x509().await.unwrap_err();
    assert_eq!(code_of(&e), 4001);

    let admin_conn = h.channel().await;
    let token = bearer(&admin_conn.admin_token().await);
    AdminServiceClient::new(admin_conn.channel.clone())
        .create_user(authed(
            CreateUserRequest {
                name: "x509:CN=svc".into(),
                password: None,
                roles: vec![grant("monitor", "cluster")],
                must_change_password: false,
                x509_subject: Some("CN=svc".into()),
            },
            &token,
        ))
        .await
        .unwrap();
    // Certificate users cannot get a password.
    let e = AdminServiceClient::new(admin_conn.channel.clone())
        .create_user(authed(
            CreateUserRequest {
                name: "x509:CN=other".into(),
                password: Some("Zr8&uW3n!Kd5Qe2p".into()),
                ..CreateUserRequest::default()
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), 1001);

    let ok = conn.login_x509().await.unwrap();
    assert_eq!(ok.user, "x509:CN=svc");
    assert_ne!(ok.session_token, "");
    let me = AuthServiceClient::new(conn.channel.clone())
        .who_am_i(authed(WhoAmIRequest {}, &bearer(&ok.session_token)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(me.user, "x509:CN=svc");
    assert_eq!(me.mechanism, AuthMechanism::X509 as i32);
    assert_eq!(me.roles, vec![grant("monitor", "cluster")]);
    h.stop().await;
}
