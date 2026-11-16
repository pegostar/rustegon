// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! S3 destination against an in-process fake S3 server (TC-BKP-006 unit level; FR-BKP-006,
//! PD-065): object operations, listing pagination, multipart sequencing, abort on failure,
//! retries, timeouts, size mismatches and a whole backup round trip. Every request's signature
//! is verified by the fake with an independent `SigV4` implementation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use rustegon_backup::{BackupError, Destination, S3Destination, S3Io, S3Location, S3Settings};
use rustegon_common::{Error, ErrorCode};
use rustegon_sim::SimFileSystem;
use rustegon_sim_api::{FileSystem as _, OpenMode};
use support::{
    fake_s3::{ACCESS_KEY, BUCKET, FakeS3, SECRET_KEY},
    pattern,
};

const MIB: usize = 1 << 20;

fn env(name: &str) -> Option<String> {
    match name {
        "AWS_ACCESS_KEY_ID" => Some(ACCESS_KEY.to_owned()),
        "AWS_SECRET_ACCESS_KEY" => Some(SECRET_KEY.to_owned()),
        _ => None,
    }
}

fn open_with(endpoint: String, prefix: &str, settings: &S3Settings) -> S3Destination {
    S3Destination::open(
        &S3Location {
            bucket: BUCKET.into(),
            prefix: prefix.into(),
            region: Some("eu-south-1".into()),
            endpoint: Some(endpoint),
        },
        settings,
        S3Io::production(Arc::new(SimFileSystem::new())),
        &env,
    )
    .unwrap()
}

fn settings() -> S3Settings {
    S3Settings {
        part_size_mib: 5,
        max_attempts: 3,
        request_timeout_secs: 30,
        ..S3Settings::default()
    }
}

fn open(fake: &FakeS3, prefix: &str) -> S3Destination {
    open_with(fake.endpoint(), prefix, &settings())
}

#[test]
fn tc_bkp_006_s3_object_operations_and_paginated_listing() {
    let fake = FakeS3::start();
    let d = open(&fake, "rg/shop");
    assert_eq!(d.describe(), format!("s3://{BUCKET}/rg/shop"));
    d.put_bytes("a/b/c.bin", b"hello").unwrap();
    d.put_bytes("a/top", b"x").unwrap();
    d.put_bytes("a/z1", b"1").unwrap();
    d.put_bytes("a/z2", b"2").unwrap();
    d.put_bytes("empty", b"").unwrap();
    // Objects outside the destination prefix or outside the key alphabet are not listed.
    fake.with(|s| {
        s.objects
            .insert("rg/other/x".into(), (bytes::Bytes::new(), "\"e\"".into()));
        s.objects.insert(
            "rg/shop/a/sp ace".into(),
            (bytes::Bytes::new(), "\"e\"".into()),
        );
    });
    assert!(fake.with(|s| s.objects.contains_key("rg/shop/a/b/c.bin")));
    assert_eq!(d.get_bytes("a/b/c.bin", 100).unwrap(), b"hello");
    assert_eq!(d.get_bytes("empty", 100).unwrap(), b"");
    assert_eq!(d.size("a/b/c.bin").unwrap(), Some(5));
    assert_eq!(d.size("a/none").unwrap(), None);
    assert!(d.exists("a/top").unwrap());
    // Page size 2 on the fake: these listings take several pages.
    assert_eq!(
        d.list("").unwrap(),
        ["a/b/c.bin", "a/top", "a/z1", "a/z2", "empty"]
    );
    assert_eq!(d.list("a/b").unwrap(), ["a/b/c.bin"]);
    assert_eq!(d.list("zzz").unwrap(), Vec::<String>::new());
    assert_eq!(d.list_children("a").unwrap(), ["b", "top", "z1", "z2"]);
    assert_eq!(d.list_children("").unwrap(), ["a", "empty"]);
    assert!(d.get_bytes("a/b/c.bin", 4).is_err());
    let reader = d.open("a/b/c.bin").unwrap();
    let mut two = [0u8; 2];
    reader.read_exact_at(&mut two, 3).unwrap();
    assert_eq!(&two, b"lo");
    assert!(
        reader.read_exact_at(&mut two, 4).is_err(),
        "read past the end"
    );
    d.delete("a/top").unwrap();
    d.delete("a/top").unwrap();
    assert!(matches!(
        d.open("a/top"),
        Err(BackupError::ObjectNotFound { .. })
    ));
    assert_eq!(
        Error::from(d.open("a/top").err().unwrap()).code(),
        ErrorCode::NotFound
    );
    for key in ["../x", "/x", "a//b", "a~partial"] {
        assert!(matches!(
            d.put_bytes(key, b"x"),
            Err(BackupError::InvalidArgument(_))
        ));
    }
    let log = fake.with(|s| s.log.clone());
    assert!(
        log.iter().any(|l| l.contains("continuation-token")),
        "pagination exercised: {log:?}"
    );
}

#[test]
fn tc_bkp_006_s3_multipart_upload_sequence_and_ranged_reads() {
    let fake = FakeS3::start();
    let d = open(&fake, "");
    let data = pattern(12 * MIB + 3, 1);
    fake.with(|s| s.log.clear());
    let mut src: &[u8] = &data;
    d.put_reader("big.bin", data.len() as u64, &mut src)
        .unwrap();
    let log = fake.with(|s| s.log.clone());
    let path = format!("/{BUCKET}/big.bin");
    assert_eq!(
        log,
        [
            format!("POST {path}?uploads"),
            format!("PUT {path}?partNumber&uploadId"),
            format!("PUT {path}?partNumber&uploadId"),
            format!("PUT {path}?partNumber&uploadId"),
            format!("POST {path}?uploadId"),
        ]
    );
    assert!(fake.with(|s| s.uploads.is_empty()));
    // Reads across read-ahead windows and part boundaries.
    let reader = d.open("big.bin").unwrap();
    assert_eq!(reader.size(), data.len() as u64);
    for (offset, len) in [
        (0, MIB),
        (5 * MIB - 7, 20),
        (9 * MIB, 3 * MIB + 3),
        (MIB, 10),
    ] {
        let mut buf = vec![0u8; len];
        reader.read_exact_at(&mut buf, offset as u64).unwrap();
        assert_eq!(buf, data[offset..offset + len], "range {offset}+{len}");
    }
    assert_eq!(d.get_bytes("big.bin", u64::MAX).unwrap(), data);

    // An object replaced while a reader is open is detected (If-Match).
    let small = pattern(100, 2);
    d.put_bytes("big.bin", &small).unwrap();
    let mut buf = vec![0u8; 10];
    let err = reader.read_exact_at(&mut buf, 11 * MIB as u64).unwrap_err();
    assert!(err.to_string().contains("changed"), "{err}");
}

#[test]
fn tc_bkp_006_s3_failed_multipart_upload_is_aborted() {
    let fake = FakeS3::start();
    let d = open(&fake, "p");
    fake.with(|s| s.deny_part = Some(2));
    let data = pattern(11 * MIB, 3);
    let mut src: &[u8] = &data;
    let err = d
        .put_reader("k.bin", data.len() as u64, &mut src)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable, "{err}");
    let common = Error::from(err);
    assert!(!common.retryable(), "access denied is not retryable");
    let log = fake.with(|s| s.log.clone());
    assert!(
        log.last()
            .unwrap()
            .starts_with("DELETE /fake-bucket/p/k.bin?uploadId"),
        "{log:?}"
    );
    assert!(fake.with(|s| s.uploads.is_empty() && !s.objects.contains_key("p/k.bin")));
}

#[test]
fn tc_bkp_006_s3_wrong_size_stores_nothing() {
    let fake = FakeS3::start();
    let d = open(&fake, "");
    let mut short: &[u8] = b"abc";
    assert!(d.put_reader("k", 4, &mut short).is_err());
    let mut long: &[u8] = b"abcde";
    assert!(d.put_reader("k", 4, &mut long).is_err());
    let data = pattern(6 * MIB, 4);
    let mut short: &[u8] = &data[..6 * MIB - 1];
    assert!(d.put_reader("m", 6 * MIB as u64, &mut short).is_err());
    let mut long: &[u8] = &data;
    assert!(d.put_reader("m", 6 * MIB as u64 - 1, &mut long).is_err());
    assert!(fake.with(|s| s.objects.is_empty() && s.uploads.is_empty()));
}

#[test]
fn tc_bkp_006_s3_transient_errors_are_retried() {
    let fake = FakeS3::start();
    let d = open(&fake, "");
    fake.with(|s| s.fail_next = 2);
    d.put_bytes("k", b"v").unwrap();
    assert_eq!(d.get_bytes("k", 10).unwrap(), b"v");
    // More failures than attempts: RGN-3002, retryable.
    fake.with(|s| s.fail_next = 3);
    let err = d.put_bytes("k2", b"v").unwrap_err();
    assert!(err.to_string().contains("SlowDown"), "{err}");
    let common = Error::from(err);
    assert_eq!(common.code(), ErrorCode::Unavailable);
    assert!(common.retryable());
}

#[test]
fn tc_bkp_006_s3_lost_complete_response_is_accepted() {
    let fake = FakeS3::start();
    let d = open(&fake, "");
    fake.with(|s| s.lose_complete = true);
    let data = pattern(6 * MIB, 5);
    let mut src: &[u8] = &data;
    d.put_reader("k.bin", data.len() as u64, &mut src).unwrap();
    assert_eq!(d.get_bytes("k.bin", u64::MAX).unwrap(), data);
}

#[test]
fn tc_bkp_006_s3_timeouts_and_unreachable_endpoint_are_rgn_3002() {
    let fake = FakeS3::start();
    fake.with(|s| s.stall = true);
    let d = open_with(
        fake.endpoint(),
        "",
        &S3Settings {
            max_attempts: 1,
            request_timeout_secs: 1,
            ..settings()
        },
    );
    let err = d.size("k").unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.to_string().contains("timed out"), "{err}");

    // Nothing listens on the port of a dropped server.
    let addr = fake.addr;
    drop(fake);
    let d = open_with(
        format!("http://{addr}"),
        "",
        &S3Settings {
            max_attempts: 2,
            ..settings()
        },
    );
    let err = d.list("").unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable, "{err}");
}

#[test]
fn tc_bkp_006_s3_backup_round_trip_against_fake() {
    let fake = FakeS3::start();
    let d = open(&fake, "rustegon/prod");
    support::round_trip(&d, 11 * MIB + 5, 1);
    assert!(fake.with(|s| s.uploads.is_empty()));
}

#[test]
fn tc_bkp_006_s3_create_bucket_is_idempotent() {
    let fake = FakeS3::start();
    fake.with(|s| s.bucket_exists = false);
    let d = open(&fake, "");
    d.create_bucket().unwrap();
    d.create_bucket().unwrap();
}

#[test]
fn tc_bkp_006_s3_missing_credentials_are_rejected_at_open() {
    let err = S3Destination::open(
        &S3Location {
            bucket: BUCKET.into(),
            prefix: String::new(),
            region: None,
            endpoint: Some("http://127.0.0.1:9".into()),
        },
        &S3Settings::default(),
        S3Io::production(Arc::new(SimFileSystem::new())),
        &|_| None,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

/// A CA and a server certificate for 127.0.0.1, as `rustegon init` would create them.
fn ca_and_server_cert() -> (String, String, String) {
    let clock = rustegon_sim_api::SystemClock::new();
    let (ca, _) = rustegon_net::CertAuthority::generate(
        "test-ca",
        rustegon_net::KeyAlgorithm::EcdsaP256,
        &clock,
        &rustegon_sim_api::OsRng,
    )
    .unwrap();
    let leaf = ca
        .issue_node(
            "fake-s3",
            &["127.0.0.1".to_owned()],
            &clock,
            &rustegon_sim_api::OsRng,
        )
        .unwrap();
    (
        ca.cert_pem().to_owned(),
        leaf.cert_pem.clone(),
        leaf.key_pem.expose().clone(),
    )
}

fn open_tls(fake: &FakeS3, ca_pem: &str) -> S3Destination {
    let fs = SimFileSystem::new();
    fs.create_dir_all(std::path::Path::new("/etc")).unwrap();
    let mut f = fs
        .open(std::path::Path::new("/etc/ca.crt"), OpenMode::Truncate)
        .unwrap();
    f.append(ca_pem.as_bytes()).unwrap();
    drop(f);
    S3Destination::open(
        &S3Location {
            bucket: BUCKET.into(),
            prefix: String::new(),
            region: None,
            endpoint: Some(fake.https_endpoint()),
        },
        &S3Settings {
            ca_file: Some("/etc/ca.crt".into()),
            max_attempts: 1,
            ..settings()
        },
        S3Io::production(Arc::new(fs)),
        &env,
    )
    .unwrap()
}

#[test]
fn tc_bkp_006_s3_https_with_custom_ca() {
    let (ca, cert, key) = ca_and_server_cert();
    let fake = FakeS3::start_tls(&cert, &key);
    let d = open_tls(&fake, &ca);
    d.put_bytes("tls/k", b"over tls").unwrap();
    assert_eq!(d.get_bytes("tls/k", 100).unwrap(), b"over tls");
    assert_eq!(d.list("tls").unwrap(), ["tls/k"]);

    // A server whose certificate is not issued by the configured CA is refused.
    let (other_ca, _, _) = ca_and_server_cert();
    let d = open_tls(&fake, &other_ca);
    let err = d.size("tls/k").unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable, "{err}");
}
