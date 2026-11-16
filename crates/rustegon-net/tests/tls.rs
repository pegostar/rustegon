// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! TC-TLS-001…005 (security.md §11, acceptance-criteria.md AC-TLS-001…003) on real loopback
//! sockets (sim-api `TokioNetwork`) and real files (sim-api `StdFileSystem`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use rustegon_common::Redacted;
use rustegon_net::{
    CertAuthority, CertSource, Deployment, GeneratedCert, KeyAlgorithm, ReloadOutcome,
    ReloadableCert, TlsContext, TlsError, TlsMinVersion, TlsSettings, TransportSecurity,
    TrustAnchors, has_node_role, not_after_unix, parse_certificates, peer_certificate_chain,
    rustls::{
        self, ClientConfig, ServerConfig,
        crypto::ring,
        pki_types::{CertificateDer, ServerName},
    },
    tokio_rustls::{TlsAcceptor, TlsConnector},
    transport_security,
};
use rustegon_sim_api::{
    BoxFuture, Clock, Connection, FileSystem, Network, OsRng, StdFileSystem, SystemClock,
    TokioNetwork,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A clock whose wall time tests set explicitly (expiry, not-yet-valid checks).
struct ManualClock(Mutex<SystemTime>);

impl Clock for ManualClock {
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn wall(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        SystemClock::new().sleep(d)
    }
}

struct Pki {
    dir: tempfile::TempDir,
    fs: Arc<dyn FileSystem>,
    clock: Arc<dyn Clock>,
    ca: CertAuthority,
    ca_anchors: TrustAnchors,
}

impl Pki {
    fn new(alg: KeyAlgorithm) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let (ca, ca_gen) =
            CertAuthority::generate("rustegon test CA", alg, clock.as_ref(), &OsRng).unwrap();
        let anchors = TrustAnchors::from_pem(ca_gen.cert_pem.as_bytes(), "ca.pem").unwrap();
        Self {
            dir: tempfile::tempdir().unwrap(),
            fs: Arc::new(StdFileSystem),
            clock,
            ca,
            ca_anchors: anchors,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn node(&self, name: &str) -> GeneratedCert {
        self.ca
            .issue_node(
                name,
                &["127.0.0.1".into(), "localhost".into()],
                self.clock.as_ref(),
                &OsRng,
            )
            .unwrap()
    }

    /// Writes `cert` under `name` and loads it as a reloadable identity.
    fn identity(&self, name: &str, cert: &GeneratedCert) -> Arc<ReloadableCert> {
        let (c, k) = (
            self.path(&format!("{name}.crt")),
            self.path(&format!("{name}.key")),
        );
        cert.write_files(self.fs.as_ref(), &c, &k).unwrap();
        ReloadableCert::load(
            CertSource::new(Arc::clone(&self.fs), c, k),
            rustegon_net::crypto_provider(),
            Arc::clone(&self.clock),
        )
        .unwrap()
    }

    fn ctx(&self, min: TlsMinVersion) -> TlsContext {
        TlsContext::new(Arc::clone(&self.clock), min)
    }
}

/// Replaces a file's contents (test helper, plain std I/O on a temp dir).
fn overwrite(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
}

/// Starts a one-shot TLS echo server; returns its address and a handle yielding the server's
/// view of the peer chain (or the handshake error).
async fn serve_once(
    config: ServerConfig,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<Result<Option<Vec<CertificateDer<'static>>>, std::io::Error>>,
) {
    let mut listener = TokioNetwork
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let task = tokio::spawn(async move {
        let (conn, _) = listener.accept().await?;
        let mut tls = acceptor.accept(conn).await?;
        let chain = peer_certificate_chain(tls.get_ref().1);
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await?;
        tls.write_all(&buf).await?;
        tls.shutdown().await?;
        Ok(chain)
    });
    (addr, task)
}

/// Connects, does a 4-byte echo and returns the server's leaf certificate and the negotiated
/// protocol version.
async fn connect(
    addr: SocketAddr,
    config: ClientConfig,
) -> Result<(CertificateDer<'static>, rustls::ProtocolVersion), std::io::Error> {
    let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await?;
    let connector = TlsConnector::from(Arc::new(config));
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), conn)
        .await?;
    tls.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    tls.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"ping");
    let (_, session) = tls.get_ref();
    let leaf = session.peer_certificates().unwrap()[0].clone();
    let version = session.protocol_version().unwrap();
    Ok((leaf, version))
}

#[tokio::test]
async fn tc_tls_001_handshake_uses_tls13_by_default() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    let (addr, task) = serve_once(ctx.client_listener_config(server, None).unwrap()).await;
    let (_, version) = connect(addr, ctx.client_config(&pki.ca_anchors, None).unwrap())
        .await
        .unwrap();
    assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
    assert!(task.await.unwrap().unwrap().is_none());
}

#[tokio::test]
async fn tc_tls_001_server_refuses_tls12_by_default() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    let (addr, task) = serve_once(ctx.client_listener_config(server, None).unwrap()).await;
    // A legacy client that speaks only TLS 1.2.
    let legacy = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(pki.ca_anchors.roots())
        .with_no_client_auth();
    assert!(connect(addr, legacy).await.is_err());
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn tc_tls_001_min_version_12_accepts_legacy_tls12_client() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let ctx = pki.ctx(TlsMinVersion::Tls12);
    let (addr, task) = serve_once(ctx.client_listener_config(server, None).unwrap()).await;
    let legacy = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(pki.ca_anchors.roots())
        .with_no_client_auth();
    let (_, version) = connect(addr, legacy).await.unwrap();
    assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    task.await.unwrap().unwrap();
}

#[test]
fn tc_tls_001_provider_offers_only_aead_suites_and_x25519_p256() {
    let provider = rustegon_net::crypto_provider();
    for suite in &provider.cipher_suites {
        let name = format!("{:?}", suite.suite());
        assert!(
            name.contains("_GCM_") || name.contains("CHACHA20_POLY1305"),
            "non-AEAD suite {name}"
        );
        if suite.version() == &rustls::version::TLS12 {
            assert!(name.starts_with("TLS_ECDHE_"), "non-ECDHE suite {name}");
        }
    }
    let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
    assert_eq!(
        groups,
        [rustls::NamedGroup::X25519, rustls::NamedGroup::secp256r1]
    );
}

#[tokio::test]
async fn tc_tls_002_peer_mtls_accepts_cluster_node() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let client_node = pki.node("node2");
    let client = pki.identity("node2", &client_node);
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    let (addr, task) = serve_once(ctx.peer_listener_config(server, &pki.ca_anchors).unwrap()).await;
    connect(
        addr,
        ctx.peer_client_config(&pki.ca_anchors, client).unwrap(),
    )
    .await
    .unwrap();
    let chain = task.await.unwrap().unwrap().expect("peer chain exposed");
    let expected = parse_certificates(client_node.cert_pem.as_bytes(), Path::new("n2")).unwrap();
    assert_eq!(chain[0], expected[0]);
}

#[tokio::test]
async fn tc_tls_002_peer_mtls_refuses_missing_client_cert() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    let (addr, task) = serve_once(ctx.peer_listener_config(server, &pki.ca_anchors).unwrap()).await;
    // In TLS 1.3 the client may finish its side before the server's alert arrives; the echo
    // then fails. Either way the server side must fail.
    let _ = connect(addr, ctx.client_config(&pki.ca_anchors, None).unwrap()).await;
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn tc_tls_002_peer_mtls_refuses_foreign_ca_cert() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let foreign = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    // Signed by another CA, but the client trusts our CA for the server.
    let intruder = pki.identity("intruder", &foreign.node("intruder"));
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    let (addr, task) = serve_once(ctx.peer_listener_config(server, &pki.ca_anchors).unwrap()).await;
    let _ = connect(
        addr,
        ctx.peer_client_config(&pki.ca_anchors, intruder).unwrap(),
    )
    .await;
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn tc_tls_003_client_refuses_server_of_foreign_ca() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let foreign = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = foreign.identity("rogue", &foreign.node("rogue"));
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    let (addr, task) = serve_once(ctx.client_listener_config(server, None).unwrap()).await;
    let err = connect(addr, ctx.client_config(&pki.ca_anchors, None).unwrap())
        .await
        .unwrap_err();
    // Same CA subject name, other key: webpki finds the issuer by name and rejects the
    // signature (BadSignature); a differently named CA would give UnknownIssuer.
    assert!(
        err.to_string().contains("invalid peer certificate"),
        "{err}"
    );
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn tc_tls_003_client_port_optional_client_cert() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let foreign = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let ctx = pki.ctx(TlsMinVersion::Tls13);

    // Without a client certificate: accepted, no chain.
    let cfg = ctx
        .client_listener_config(Arc::clone(&server), Some(&pki.ca_anchors))
        .unwrap();
    let (addr, task) = serve_once(cfg).await;
    connect(addr, ctx.client_config(&pki.ca_anchors, None).unwrap())
        .await
        .unwrap();
    assert!(task.await.unwrap().unwrap().is_none());

    // With a valid client certificate: accepted, chain exposed with the CN.
    let alice_gen = pki
        .ca
        .issue_client("alice", pki.clock.as_ref(), &OsRng)
        .unwrap();
    let alice = pki.identity("alice", &alice_gen);
    let cfg = ctx
        .client_listener_config(Arc::clone(&server), Some(&pki.ca_anchors))
        .unwrap();
    let (addr, task) = serve_once(cfg).await;
    connect(
        addr,
        ctx.client_config(&pki.ca_anchors, Some(alice)).unwrap(),
    )
    .await
    .unwrap();
    let chain = task.await.unwrap().unwrap().unwrap();
    let parsed = x509_cn(&chain[0]);
    assert_eq!(parsed, "alice");

    // With a certificate of a foreign CA: refused.
    let mallory = pki.identity(
        "mallory",
        &foreign
            .ca
            .issue_client("mallory", pki.clock.as_ref(), &OsRng)
            .unwrap(),
    );
    let cfg = ctx
        .client_listener_config(server, Some(&pki.ca_anchors))
        .unwrap();
    let (addr, task) = serve_once(cfg).await;
    let _ = connect(
        addr,
        ctx.client_config(&pki.ca_anchors, Some(mallory)).unwrap(),
    )
    .await;
    assert!(task.await.unwrap().is_err());
}

/// Subject CN of a DER certificate, via the same x509 parser the crate uses.
fn x509_cn(cert: &CertificateDer<'_>) -> String {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
    parsed
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn tc_tls_004_generated_chain_verifies_and_has_spec_parameters() {
    for alg in [KeyAlgorithm::EcdsaP256, KeyAlgorithm::Ed25519] {
        let clock = SystemClock::new();
        let now = clock
            .wall()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .cast_signed();
        let (ca, ca_gen) = CertAuthority::generate("CA", alg, &clock, &OsRng).unwrap();
        let node = ca
            .issue_node(
                "n1",
                &["10.0.0.7".into(), "db1.example".into()],
                &clock,
                &OsRng,
            )
            .unwrap();

        let ca_der = parse_certificates(ca_gen.cert_pem.as_bytes(), Path::new("ca")).unwrap();
        let node_der = parse_certificates(node.cert_pem.as_bytes(), Path::new("n1")).unwrap();
        // Validity: CA 10 y, node 1 y (security.md §5).
        let ca_life = not_after_unix(&ca_der[0]).unwrap() - now;
        let node_life = not_after_unix(&node_der[0]).unwrap() - now;
        assert!((3650 * 86_400 - 60..=3650 * 86_400 + 60).contains(&ca_life));
        assert!((365 * 86_400 - 60..=365 * 86_400 + 60).contains(&node_life));
        assert_eq!(node.not_after_unix, not_after_unix(&node_der[0]).unwrap());

        // The chain verifies with webpki for both SANs.
        let anchors = TrustAnchors::from_pem(ca_gen.cert_pem.as_bytes(), "ca").unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            anchors.roots(),
            rustegon_net::crypto_provider(),
        )
        .build()
        .unwrap();
        for name in ["10.0.0.7", "db1.example"] {
            rustls::client::danger::ServerCertVerifier::verify_server_cert(
                verifier.as_ref(),
                &node_der[0],
                &[],
                &ServerName::try_from(name).unwrap(),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap();
        }
        // A name not in the SAN is refused.
        assert!(
            rustls::client::danger::ServerCertVerifier::verify_server_cert(
                verifier.as_ref(),
                &node_der[0],
                &[],
                &ServerName::try_from("other.example").unwrap(),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .is_err()
        );
        // The CA is a CA with pathLen 0; the leaf is not.
        let (_, ca_x) = x509_parser::parse_x509_certificate(ca_der[0].as_ref()).unwrap();
        let bc = ca_x.basic_constraints().unwrap().unwrap().value;
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(0));
        let (_, node_x) = x509_parser::parse_x509_certificate(node_der[0].as_ref()).unwrap();
        assert!(!node_x.is_ca());
    }
}

#[test]
fn tc_tls_004_ca_reloaded_from_pem_issues_verifiable_certs() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let (_, ca_gen) =
        CertAuthority::generate("CA2", KeyAlgorithm::Ed25519, pki.clock.as_ref(), &OsRng).unwrap();
    let ca = CertAuthority::from_pem(&ca_gen.cert_pem, &ca_gen.key_pem).unwrap();
    let client = ca.issue_client("bob", pki.clock.as_ref(), &OsRng).unwrap();
    let anchors = TrustAnchors::from_pem(ca.cert_pem().as_bytes(), "ca2").unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        anchors.roots(),
        rustegon_net::crypto_provider(),
    )
    .build()
    .unwrap();
    let der = parse_certificates(client.cert_pem.as_bytes(), Path::new("bob")).unwrap();
    verifier
        .verify_client_cert(&der[0], &[], rustls::pki_types::UnixTime::now())
        .unwrap();
}

#[test]
fn tc_tls_004_written_files_load_and_key_is_redacted() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let node = pki.node("n1");
    let id = pki.identity("n1", &node);
    assert_eq!(id.generation(), 0);
    assert!(id.expiry_seconds() > 364 * 86_400);
    // Never overwrite existing files.
    let err = node
        .write_files(pki.fs.as_ref(), &pki.path("n1.crt"), &pki.path("n1.key"))
        .unwrap_err();
    assert!(matches!(err, TlsError::Io { .. }), "{err}");
    // Debug output of generated material never contains the key.
    let dbg = format!(
        "{node:?} {:?}",
        Redacted::new(node.key_pem.expose().clone())
    );
    assert!(!dbg.contains("PRIVATE KEY"), "{dbg}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(pki.path("n1.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn tc_tls_004_node_cert_carries_node_role_uri_san_client_cert_does_not() {
    for alg in [KeyAlgorithm::EcdsaP256, KeyAlgorithm::Ed25519] {
        let pki = Pki::new(alg);
        let node = pki.node("n1");
        let client = pki
            .ca
            .issue_client("alice", pki.clock.as_ref(), &OsRng)
            .unwrap();
        let node_der = parse_certificates(node.cert_pem.as_bytes(), Path::new("n1")).unwrap();
        let client_der = parse_certificates(client.cert_pem.as_bytes(), Path::new("c")).unwrap();

        assert!(has_node_role(&node_der[0]).unwrap());
        assert!(!has_node_role(&client_der[0]).unwrap());

        // Node certificate format 2 (ADR-035), checked with x509-parser independently of
        // `has_node_role`: the node role is the URI SAN, the EKU is serverAuth + clientAuth only
        // (no 2.25 OID, which Go's crypto/x509 refuses, PD-193).
        let (_, node_x) = x509_parser::parse_x509_certificate(node_der[0].as_ref()).unwrap();
        assert_eq!(uri_sans(&node_x), [rustegon_common::pki::NODE_ROLE_URI]);
        let eku = node_x.extended_key_usage().unwrap().unwrap();
        assert!(!eku.critical);
        assert!(eku.value.server_auth && eku.value.client_auth);
        assert!(eku.value.other.is_empty(), "{:?}", eku.value.other);

        let (_, client_x) = x509_parser::parse_x509_certificate(client_der[0].as_ref()).unwrap();
        assert_eq!(uri_sans(&client_x), Vec::<&str>::new());
        let ceku = client_x.extended_key_usage().unwrap().unwrap();
        assert!(ceku.value.client_auth && !ceku.value.server_auth);
        assert_eq!(
            ceku.value.other.len(),
            0,
            "client cert must carry no extra EKU"
        );

        // The URI SAN does not disturb webpki: the node cert still verifies as a client (peer
        // mTLS) and as a server.
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            pki.ca_anchors.roots(),
            rustegon_net::crypto_provider(),
        )
        .build()
        .unwrap();
        client_verifier
            .verify_client_cert(&node_der[0], &[], rustls::pki_types::UnixTime::now())
            .unwrap();
        let server_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            pki.ca_anchors.roots(),
            rustegon_net::crypto_provider(),
        )
        .build()
        .unwrap();
        rustls::client::danger::ServerCertVerifier::verify_server_cert(
            server_verifier.as_ref(),
            &node_der[0],
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        )
        .unwrap();
    }
}

/// The URI subject alternative names of a certificate.
fn uri_sans<'a>(cert: &'a x509_parser::certificate::X509Certificate<'_>) -> Vec<&'a str> {
    cert.subject_alternative_name()
        .unwrap()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    x509_parser::extensions::GeneralName::URI(u) => Some(*u),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A committed node certificate fixture (`tests/fixtures/formats/node_cert/<version>/`).
fn node_cert_fixture(version: u32, file: &str) -> CertificateDer<'static> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/formats/node_cert/{version}/{file}"));
    CertificateDer::from(std::fs::read(path).unwrap())
}

/// Node certificate formats (implementation-rules.md §6, ADR-035): format 1 (node role as the
/// 2.25 EKU OID, written by `rustegon init --tls` before ADR-035) stays recognised during the
/// transition; format 2 (URI SAN) is what is issued now. Validity is not checked here: the
/// fixtures expire, the node-role marker does not.
#[test]
fn tc_tls_004_node_cert_formats_1_and_2_are_both_recognised() {
    assert_eq!(rustegon_common::pki::NODE_CERT_FORMAT, 2);
    let v1 = node_cert_fixture(1, "node.der");
    assert!(has_node_role(&v1).unwrap());
    let (_, x) = x509_parser::parse_x509_certificate(v1.as_ref()).unwrap();
    assert_eq!(uri_sans(&x), Vec::<&str>::new());
    let other = x.extended_key_usage().unwrap().unwrap().value.other.clone();
    assert_eq!(other.len(), 1);
    assert_eq!(
        rustegon_common::pki::NODE_ROLE_OID,
        format!("2.25.{}", uuid_arc(other[0].as_bytes()))
    );

    let v2 = node_cert_fixture(2, "node.der");
    assert!(has_node_role(&v2).unwrap());
    let (_, x) = x509_parser::parse_x509_certificate(v2.as_ref()).unwrap();
    assert_eq!(uri_sans(&x), [rustegon_common::pki::NODE_ROLE_URI]);
    assert_eq!(
        x.extended_key_usage().unwrap().unwrap().value.other.len(),
        0
    );

    // Neither CA certificate is a node certificate.
    for v in [1, 2] {
        assert!(!has_node_role(&node_cert_fixture(v, "ca.der")).unwrap());
    }
}

/// The node-role marker is trusted only as far as the CA: a node certificate (URI SAN) from
/// another CA is refused by the peer listener's verifier before any role mapping happens
/// (ADR-035).
#[test]
fn tc_tls_004_node_role_from_another_ca_is_refused() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let rogue = Pki::new(KeyAlgorithm::EcdsaP256);
    let forged = rogue.node("n1");
    let der = parse_certificates(forged.cert_pem.as_bytes(), Path::new("n1")).unwrap();
    // The marker is there, so only the chain check stands between it and the node role.
    assert!(has_node_role(&der[0]).unwrap());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        pki.ca_anchors.roots(),
        rustegon_net::crypto_provider(),
    )
    .build()
    .unwrap();
    assert!(
        verifier
            .verify_client_cert(&der[0], &[], rustls::pki_types::UnixTime::now())
            .is_err()
    );
}

/// PD-193 regression: a Go client (crypto/x509 + crypto/tls) parses a node certificate issued
/// by `CertAuthority::issue_node` (what `rustegon init --tls` writes) and completes an mTLS
/// handshake with it against the peer listener. Skipped, with a message, when Go is missing
/// (`GO` overrides the binary).
#[tokio::test]
async fn tc_tls_004_go_client_handshakes_with_a_node_certificate() {
    let go = std::env::var_os("GO").map(PathBuf::from).or_else(|| {
        [
            "go",
            "C:/Program Files/Go/bin/go.exe",
            "/usr/local/go/bin/go",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|g| {
            std::process::Command::new(g)
                .arg("version")
                .output()
                .is_ok()
        })
    });
    let Some(go) = go else {
        eprintln!("SKIPPED tc_tls_004_go_client_handshakes_with_a_node_certificate: Go not found");
        return;
    };
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let (crt, key, ca) = (
        pki.path("node2.crt"),
        pki.path("node2.key"),
        pki.path("ca.pem"),
    );
    pki.node("node2")
        .write_files(pki.fs.as_ref(), &crt, &key)
        .unwrap();
    std::fs::write(&ca, pki.ca.cert_pem()).unwrap();
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    let (addr, task) = serve_once(ctx.peer_listener_config(server, &pki.ca_anchors).unwrap()).await;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/go/handshake.go");
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(go)
            .arg("run")
            .arg(script)
            .arg(addr.to_string())
            .args([ca, crt, key])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("OK"),
        "go: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The server saw the Go client's node certificate, which carries the node role.
    let chain = task.await.unwrap().unwrap().unwrap();
    assert!(has_node_role(&chain[0]).unwrap());
}

/// Decodes the content octets of a `2.25.<n>` OID back into `n` (test-side decoder, written
/// independently of the crate's encoder).
fn uuid_arc(content: &[u8]) -> u128 {
    assert_eq!(content[0], 2 * 40 + 25);
    content[1..]
        .iter()
        .fold(0u128, |acc, b| (acc << 7) | u128::from(b & 0x7f))
}

#[test]
fn tc_tls_004_node_cert_requires_an_address() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let err = pki
        .ca
        .issue_node("n1", &[], pki.clock.as_ref(), &OsRng)
        .unwrap_err();
    assert!(matches!(err, TlsError::Config(_)), "{err}");
}

#[tokio::test]
async fn tc_tls_005_reload_swaps_served_cert_without_restart() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let first = pki.node("node1");
    let server = pki.identity("node1", &first);
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    let config = Arc::new(
        ctx.client_listener_config(Arc::clone(&server), None)
            .unwrap(),
    );
    let first_der = parse_certificates(first.cert_pem.as_bytes(), Path::new("a")).unwrap();

    // One listener, kept open for the whole test (no restart).
    let mut listener = TokioNetwork
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(config);
    let accept_loop = tokio::spawn(async move {
        loop {
            let (conn, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(conn).await {
                    let mut buf = [0u8; 4];
                    if tls.read_exact(&mut buf).await.is_ok() {
                        let _ = tls.write_all(&buf).await;
                        let _ = tls.shutdown().await;
                    }
                }
            });
        }
    });
    let client = || ctx.client_config(&pki.ca_anchors, None).unwrap();
    let (leaf, _) = connect(addr, client()).await.unwrap();
    assert_eq!(leaf, first_der[0]);

    // Unchanged files: no swap.
    assert_eq!(server.reload().unwrap(), ReloadOutcome::Unchanged);

    // Replace the files; the poll loop picks them up on trigger (SIGHUP/watch path).
    let second = pki.node("node1");
    let second_der = parse_certificates(second.cert_pem.as_bytes(), Path::new("b")).unwrap();
    overwrite(&pki.path("node1.crt"), &second.cert_pem);
    overwrite(&pki.path("node1.key"), second.key_pem.expose());
    let poll = tokio::spawn(Arc::clone(&server).run_poll(Duration::from_secs(3600)));
    server.trigger();
    for _ in 0..200 {
        if server.generation() == 1 {
            break;
        }
        SystemClock::new().sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.generation(), 1, "{:?}", server.last_error());
    let (leaf, _) = connect(addr, client()).await.unwrap();
    assert_eq!(leaf, second_der[0]);
    assert_ne!(leaf, first_der[0]);

    poll.abort();
    accept_loop.abort();
}

#[tokio::test]
async fn tc_tls_005_poll_interval_reloads_without_trigger() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let poll = tokio::spawn(Arc::clone(&server).run_poll(Duration::from_millis(20)));
    let second = pki.node("node1");
    overwrite(&pki.path("node1.crt"), &second.cert_pem);
    overwrite(&pki.path("node1.key"), second.key_pem.expose());
    for _ in 0..300 {
        if server.generation() == 1 {
            break;
        }
        SystemClock::new().sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.generation(), 1, "{:?}", server.last_error());
    poll.abort();
}

#[test]
fn tc_tls_005_bad_reload_keeps_old_cert() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let first = pki.node("node1");
    let server = pki.identity("node1", &first);
    let before = server.certified_key();
    let crt = pki.path("node1.crt");
    let key = pki.path("node1.key");

    // 1. Garbage certificate.
    overwrite(
        &crt,
        "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
    );
    assert!(server.reload().is_err());
    assert!(server.last_error().is_some());
    // 2. New certificate with the old key (half-replaced pair).
    let second = pki.node("node1");
    overwrite(&crt, &second.cert_pem);
    let err = server.reload().unwrap_err();
    assert!(matches!(err, TlsError::Rustls(_)), "{err}");
    // 3. Key file deleted.
    std::fs::remove_file(&key).unwrap();
    assert!(matches!(server.reload().unwrap_err(), TlsError::Io { .. }));
    // 4. Empty key file.
    overwrite(&key, "");
    assert!(matches!(
        server.reload().unwrap_err(),
        TlsError::NoPrivateKey(_)
    ));

    assert_eq!(server.generation(), 0);
    assert!(Arc::ptr_eq(&before, &server.certified_key()));
    // Error messages never contain key material.
    assert!(!server.last_error().unwrap().contains("PRIVATE KEY"));

    // Fixing the pair recovers and clears the error.
    std::fs::remove_file(&key).unwrap();
    overwrite(&key, second.key_pem.expose());
    assert_eq!(
        server.reload().unwrap(),
        ReloadOutcome::Replaced { generation: 1 }
    );
    assert!(server.last_error().is_none());
}

#[test]
fn tc_tls_005_expired_cert_refused_and_expiry_gauge_uses_clock() {
    let now = SystemClock::new().wall();
    let manual = Arc::new(ManualClock(Mutex::new(now)));
    let clock: Arc<dyn Clock> = manual.clone();
    let (ca, _) =
        CertAuthority::generate("CA", KeyAlgorithm::EcdsaP256, clock.as_ref(), &OsRng).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let fs: Arc<dyn FileSystem> = Arc::new(StdFileSystem);
    let (crt, key) = (dir.path().join("n.crt"), dir.path().join("n.key"));
    let node = ca
        .issue_node("n", &["127.0.0.1".into()], clock.as_ref(), &OsRng)
        .unwrap();
    node.write_files(fs.as_ref(), &crt, &key).unwrap();
    let id = ReloadableCert::load(
        CertSource::new(Arc::clone(&fs), &crt, &key),
        rustegon_net::crypto_provider(),
        Arc::clone(&clock),
    )
    .unwrap();
    let year = 365 * 86_400;
    assert!((year - 5..=year).contains(&id.expiry_seconds()));

    // Ten days later the gauge has moved accordingly.
    *manual.0.lock().unwrap() = now + Duration::from_hours(10 * 24);
    assert!((year - 10 * 86_400 - 5..=year - 10 * 86_400).contains(&id.expiry_seconds()));

    // Two years later: the gauge is negative and an expired replacement is refused.
    *manual.0.lock().unwrap() = now + Duration::from_secs(2 * year.cast_unsigned());
    assert!(id.expiry_seconds() < 0);
    let stale = ca
        .issue_node("n", &["127.0.0.1".into()], &SystemClock::new(), &OsRng)
        .unwrap();
    overwrite(&crt, &stale.cert_pem);
    overwrite(&key, stale.key_pem.expose());
    assert!(matches!(id.reload().unwrap_err(), TlsError::Expired { .. }));
    assert_eq!(id.generation(), 0);
}

/// ADR-034: `security.tls` selects TLS; without it a single node serves plain text and a
/// cluster member refuses to start.
#[test]
fn tc_tls_001_plain_text_only_on_single_node() {
    assert_eq!(
        transport_security(true, Deployment::Cluster).unwrap(),
        TransportSecurity::Tls
    );
    assert_eq!(
        transport_security(true, Deployment::SingleNode).unwrap(),
        TransportSecurity::Tls
    );
    assert_eq!(
        transport_security(false, Deployment::SingleNode).unwrap(),
        TransportSecurity::PlainText
    );
    assert!(matches!(
        transport_security(false, Deployment::Cluster),
        Err(TlsError::InsecureRefused(_))
    ));
}

#[test]
fn tc_tls_001_settings_defaults_and_validation() {
    let s: TlsSettings = toml_from(
        r#"cert_file = "n.crt"
key_file = "n.key"
ca_file = "ca.crt""#,
    );
    assert_eq!(s.min_version, TlsMinVersion::Tls13);
    assert_eq!(s.reload_poll_secs, 3600);
    s.validate().unwrap();
    let s: TlsSettings = toml_from(
        r#"cert_file = "n.crt"
key_file = "n.key"
ca_file = "ca.crt"
min_version = "1.2"
client_cert = "optional"
reload_poll_secs = 0"#,
    );
    assert_eq!(s.min_version, TlsMinVersion::Tls12);
    assert!(s.validate().is_err());
}

fn toml_from<T: serde::de::DeserializeOwned>(s: &str) -> T {
    toml::from_str(s).unwrap()
}

// ---------------------------------------------------------------------------------------------
// TC-TLS-006 (PD-060): certificate validity windows and the negotiated suite on the wire.
// ---------------------------------------------------------------------------------------------

/// A leaf of `pki`'s CA issued as if the wall clock were `at` (so it is expired, or not yet
/// valid, now), loaded as an identity with that same clock (the loader refuses certificates
/// outside their validity at its own clock).
fn identity_issued_at(pki: &Pki, name: &str, at: SystemTime, node: bool) -> Arc<ReloadableCert> {
    let clock: Arc<dyn Clock> = Arc::new(ManualClock(Mutex::new(at)));
    let cert = if node {
        pki.ca
            .issue_node(
                name,
                &["127.0.0.1".into(), "localhost".into()],
                clock.as_ref(),
                &OsRng,
            )
            .unwrap()
    } else {
        pki.ca.issue_client(name, clock.as_ref(), &OsRng).unwrap()
    };
    let (c, k) = (
        pki.path(&format!("{name}.crt")),
        pki.path(&format!("{name}.key")),
    );
    cert.write_files(pki.fs.as_ref(), &c, &k).unwrap();
    ReloadableCert::load(
        CertSource::new(Arc::clone(&pki.fs), c, k),
        rustegon_net::crypto_provider(),
        clock,
    )
    .unwrap()
}

/// Two years ago (leaf validity is one year) and one month ahead.
fn outside_validity() -> [(SystemTime, &'static str); 2] {
    let now = SystemClock::new().wall();
    [
        (now - Duration::from_hours(2 * 365 * 24), "expired"),
        (now + Duration::from_hours(30 * 24), "not yet valid"),
    ]
}

#[tokio::test]
async fn tc_tls_006_client_certificate_outside_its_validity_is_refused() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    for (i, (at, what)) in outside_validity().into_iter().enumerate() {
        // Client port with optional client certificates.
        let alice = identity_issued_at(&pki, &format!("alice{i}"), at, false);
        let cfg = ctx
            .client_listener_config(Arc::clone(&server), Some(&pki.ca_anchors))
            .unwrap();
        let (addr, task) = serve_once(cfg).await;
        let _ = connect(
            addr,
            ctx.client_config(&pki.ca_anchors, Some(alice)).unwrap(),
        )
        .await;
        let err = task.await.unwrap().expect_err(what);
        assert!(
            err.to_string().contains("invalid peer certificate"),
            "{what}: {err}"
        );

        // Peer port (mTLS) with a node certificate.
        let node = identity_issued_at(&pki, &format!("old{i}"), at, true);
        let cfg = ctx
            .peer_listener_config(Arc::clone(&server), &pki.ca_anchors)
            .unwrap();
        let (addr, task) = serve_once(cfg).await;
        let _ = connect(addr, ctx.peer_client_config(&pki.ca_anchors, node).unwrap()).await;
        assert!(
            task.await.unwrap().is_err(),
            "peer port accepted a node certificate that is {what}"
        );
    }
}

#[tokio::test]
async fn tc_tls_006_client_refuses_server_certificate_outside_its_validity() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let ctx = pki.ctx(TlsMinVersion::Tls13);
    for (i, (at, what)) in outside_validity().into_iter().enumerate() {
        let server = identity_issued_at(&pki, &format!("stale{i}"), at, true);
        let (addr, task) = serve_once(ctx.client_listener_config(server, None).unwrap()).await;
        let err = connect(addr, ctx.client_config(&pki.ca_anchors, None).unwrap())
            .await
            .expect_err(what);
        let text = err.to_string();
        assert!(
            text.contains("certificate expired") || text.contains("not valid yet"),
            "{what}: {text}"
        );
        assert!(task.await.unwrap().is_err());
    }
}

#[tokio::test]
async fn tc_tls_006_tls12_opt_in_negotiates_only_ecdhe_aead_suites() {
    let pki = Pki::new(KeyAlgorithm::EcdsaP256);
    let server = pki.identity("node1", &pki.node("node1"));
    let ctx = pki.ctx(TlsMinVersion::Tls12);
    // A legacy client offering every TLS 1.2 suite its provider knows.
    let mut provider = ring::default_provider();
    provider
        .cipher_suites
        .retain(|s| s.version() == &rustls::version::TLS12);
    assert_ne!(provider.cipher_suites.len(), 0);
    let (addr, task) = serve_once(ctx.client_listener_config(server, None).unwrap()).await;
    let legacy = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(pki.ca_anchors.roots())
        .with_no_client_auth();
    let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(Arc::new(legacy))
        .connect(ServerName::try_from("localhost").unwrap(), conn)
        .await
        .unwrap();
    tls.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tls.read_exact(&mut buf).await.unwrap();
    let (_, session) = tls.get_ref();
    assert_eq!(
        session.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    let suite = format!("{:?}", session.negotiated_cipher_suite().unwrap().suite());
    assert!(suite.starts_with("TLS_ECDHE_"), "{suite}");
    assert!(
        suite.contains("_GCM_") || suite.contains("CHACHA20_POLY1305"),
        "{suite}"
    );
    let kx = session.negotiated_key_exchange_group().unwrap().name();
    assert!(
        [rustls::NamedGroup::X25519, rustls::NamedGroup::secp256r1].contains(&kx),
        "{kx:?}"
    );
    drop(tls);
    let _ = task.await.unwrap();
}
