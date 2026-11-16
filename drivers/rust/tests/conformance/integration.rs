// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Driver-specific tests against a real node (rust-driver.md §11).

use std::time::Duration;

use rustegon::{
    Client, Credential, Error, ErrorClass, Filter, Settings, TlsSettings, Value, doc,
    pb::{self, admin_service_client::AdminServiceClient},
};

use crate::fixture::{self, CLIENT_CERT_USER, Server};

fn tls_of(s: &Server) -> TlsSettings {
    TlsSettings {
        enabled: true,
        ca_file: Some(s.ca_file()),
        ..TlsSettings::default()
    }
}

fn admin_of(s: &Server, database: &str) -> Client {
    Client::new(
        Settings::builder()
            .endpoints([s.grpc.clone()])
            .tls(tls_of(s))
            .credential(Credential::scram("admin", s.admin_password.clone()))
            .default_database(database)
            .build()
            .unwrap(),
    )
    .unwrap()
}

async fn user(admin: &Client, req: pb::CreateUserRequest) {
    admin
        .admin(|ch, md| {
            let mut r = tonic::Request::new(req.clone());
            *r.metadata_mut() = md;
            async move { AdminServiceClient::new(ch).create_user(r).await }
        })
        .await
        .unwrap();
}

async fn drop_user(admin: &Client, name: &str) {
    let req = pb::DropUserRequest {
        name: name.to_owned(),
    };
    let _ = admin
        .admin(|ch, md| {
            let mut r = tonic::Request::new(req.clone());
            *r.metadata_mut() = md;
            async move { AdminServiceClient::new(ch).drop_user(r).await }
        })
        .await;
}

/// TC-DRV-RS-009 (ADR-034): a node with the default configuration serves plain text, and the
/// DEC-014 connection string without TLS options reaches it; a TLS client cannot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tc_drv_rs_009_plain_text_default() {
    let dir = match fixture::find_binaries() {
        Ok(d) => d,
        Err(r) => return fixture::skip_or_fail(&r),
    };
    let s = Server::start(&dir, false).unwrap();
    let uri = format!("rustegon://admin:{}@{}/plain", s.admin_password, s.grpc);
    let c = Client::from_connection_string(&uri).unwrap();
    assert!(!c.settings().tls_enabled());
    c.create_database("plain")
        .if_not_exists(true)
        .await
        .unwrap();
    c.default_database()
        .create_collection("items")
        .await
        .unwrap();
    let coll = c.default_database().collection("items");
    coll.insert_one(doc! { "_id" => 1, "n" => "one" })
        .await
        .unwrap();
    let d = coll.find_by_id(1).await.unwrap().unwrap();
    assert_eq!(d.get("n"), Some(&Value::from("one")));
    c.close().await;
    let tls = Client::new(
        Settings::builder()
            .endpoints([s.grpc.clone()])
            .credential(Credential::scram("admin", s.admin_password.clone()))
            .tls(TlsSettings {
                enabled: true,
                ..TlsSettings::default()
            })
            .connect_timeout(Duration::from_secs(5))
            .operation_timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
    )
    .unwrap();
    assert!(
        tls.connect().await.is_err(),
        "a TLS client must not reach a plain-text node"
    );
}

/// TC-DRV-RS-007: TLS with the node's CA (the certificates of `rustegon init --tls`, node role as
/// URI SAN, ADR-035), wrong password, plain text refused, X.509 login.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tc_drv_rs_007_tls_and_credentials() {
    let node = match fixture::shared_tls() {
        Ok(s) => s,
        Err(r) => return fixture::skip_or_fail(&r),
    };
    let s = &*node;
    let admin = admin_of(s, "x509db");
    admin.connect().await.unwrap();
    let info = admin.server_info().await.unwrap();
    assert_ne!(info.server_version, "");
    let bad = Client::new(
        Settings::builder()
            .endpoints([s.grpc.clone()])
            .tls(tls_of(s))
            .credential(Credential::scram("admin", "wrong-password-123"))
            .build()
            .unwrap(),
    )
    .unwrap();
    let e = bad.connect().await.unwrap_err();
    assert!(e.is(ErrorClass::Authentication), "{e}");
    let plain = Client::new(
        Settings::builder()
            .endpoints([s.grpc.clone()])
            .credential(Credential::scram("admin", s.admin_password.clone()))
            .operation_timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
    )
    .unwrap();
    assert!(
        plain.connect().await.is_err(),
        "plain text must not reach a TLS node"
    );
    // X.509: the client certificate issued by init maps to x509:CN=conf_x509.
    let name = format!("x509:CN={CLIENT_CERT_USER}");
    let _ = admin.drop_database("x509db").if_exists(true).await;
    admin.create_database("x509db").await.unwrap();
    admin
        .default_database()
        .create_collection("c")
        .await
        .unwrap();
    drop_user(&admin, &name).await;
    user(
        &admin,
        pb::CreateUserRequest {
            name: name.clone(),
            roles: vec![pb::RoleGrant {
                role: "read_write".into(),
                resource: "database:x509db".into(),
            }],
            ..Default::default()
        },
    )
    .await;
    let mut t = tls_of(s);
    t.certificate_file = Some(s.client_cert_file());
    t.key_file = Some(s.client_key_file());
    let x = Client::new(
        Settings::builder()
            .endpoints([s.grpc.clone()])
            .credential(Credential::x509())
            .tls(t)
            .default_database("x509db")
            .build()
            .unwrap(),
    )
    .unwrap();
    let coll = x.default_database().collection("c");
    coll.insert_one(doc! { "_id" => 1 }).await.unwrap();
    assert!(coll.find_by_id(1).await.unwrap().is_some());
    x.close().await;
    drop_user(&admin, &name).await;
    admin.drop_database("x509db").await.unwrap();
    // A closed client refuses operations without I/O.
    admin.close().await;
    assert!(matches!(
        admin.list_database_names().await,
        Err(Error::InvalidState(_))
    ));
}

/// TC-DRV-RS-026: one client shared by many concurrent tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tc_drv_rs_026_concurrent_tasks() {
    let node = match fixture::shared_tls() {
        Ok(s) => s,
        Err(r) => return fixture::skip_or_fail(&r),
    };
    let s = &*node;
    let c = admin_of(s, "stress");
    let _ = c.drop_database("stress").if_exists(true).await;
    c.create_database("stress").await.unwrap();
    c.default_database().create_collection("c").await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..64i64 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            let coll = c.default_database().collection("c");
            coll.insert_one(doc! { "_id" => i, "v" => i * 2 }).await?;
            coll.find_by_id(i).await
        }));
    }
    for t in tasks {
        assert!(t.await.unwrap().unwrap().is_some());
    }
    let all = c
        .default_database()
        .collection("c")
        .find(Filter::empty())
        .to_list()
        .await
        .unwrap();
    assert_eq!(all.len(), 64);
    c.drop_database("stress").await.unwrap();
    c.close().await;
}
