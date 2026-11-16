// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Unit tests of the S3 destination internals (addressing, part sizing, backoff). Behaviour
//! against a server is tested in `tests/s3.rs` (fake) and `tests/s3_minio.rs` (TC-BKP-006).

use super::*;

#[test]
fn tc_bkp_006_endpoint_addressing_styles() {
    // AWS default: virtual-hosted, default port omitted.
    let e = Endpoint::new("https://s3.eu-south-1.amazonaws.com", "acme", None, false).unwrap();
    assert!(e.https && !e.path_style);
    assert_eq!(e.host, "acme.s3.eu-south-1.amazonaws.com");
    assert_eq!(
        (e.port, e.host_header.as_str()),
        (443, "acme.s3.eu-south-1.amazonaws.com")
    );
    // A bucket with dots would not match the wildcard certificate: path-style.
    let e = Endpoint::new("https://s3.amazonaws.com", "a.b.c", None, false).unwrap();
    assert!(e.path_style);
    assert_eq!(e.host_header, "s3.amazonaws.com");
    // Custom endpoint: path-style unless forced off; explicit port kept in Host.
    let e = Endpoint::new("http://minio:9000/", "bkt", None, true).unwrap();
    assert!(!e.https && e.path_style);
    assert_eq!((e.host.as_str(), e.port), ("minio", 9000));
    assert_eq!(e.host_header, "minio:9000");
    let e = Endpoint::new("https://storage.example", "bkt", Some(false), true).unwrap();
    assert_eq!(e.host_header, "bkt.storage.example");
    // IP literals are always path-style; IPv6 is bracketed in Host.
    let e = Endpoint::new("http://[::1]:9000", "bkt", Some(false), true).unwrap();
    assert!(e.path_style);
    assert_eq!(
        (e.host.as_str(), e.host_header.as_str()),
        ("::1", "[::1]:9000")
    );
    let e = Endpoint::new("http://127.0.0.1:80", "bkt", None, true).unwrap();
    assert_eq!(e.host_header, "127.0.0.1");
    for bad in [
        "minio:9000",
        "ftp://x",
        "https://",
        "https://h/path",
        "https://u:p@h",
        "https://h:0",
        "https://h:x",
        "https://[::1",
    ] {
        assert!(Endpoint::new(bad, "bkt", None, true).is_err(), "{bad}");
    }
}

fn destination(part_size_mib: u32) -> S3Destination {
    S3Destination::open(
        &S3Location {
            bucket: "bkt".into(),
            prefix: "p".into(),
            region: None,
            endpoint: Some("http://127.0.0.1:9".into()),
        },
        &S3Settings {
            part_size_mib,
            ..S3Settings::default()
        },
        S3Io::production(Arc::new(rustegon_sim::SimFileSystem::new())),
        &|name| match name {
            "AWS_ACCESS_KEY_ID" | "AWS_SECRET_ACCESS_KEY" => Some("x".into()),
            _ => None,
        },
    )
    .unwrap()
}

#[test]
fn part_size_grows_to_stay_within_ten_thousand_parts() {
    let d = destination(5);
    let mib = 1u64 << 20;
    assert_eq!(d.part_size_for(100 * mib), 5 * mib);
    assert_eq!(d.part_size_for(50_000 * mib), 5 * mib);
    // 1 TiB / 10 000 = 104.9 MiB → 105 MiB parts.
    let tib = 1u64 << 40;
    let part = d.part_size_for(tib);
    assert_eq!(part, 105 * mib);
    assert!(tib.div_ceil(part) <= MAX_PARTS);
}

#[test]
fn backoff_is_bounded_and_grows() {
    let d = destination(16);
    for attempt in 1..30 {
        let delay = d.client.backoff(attempt);
        assert!(delay <= BACKOFF_CAP, "{attempt}: {delay:?}");
        let ceiling = BACKOFF_BASE
            .saturating_mul(1 << (attempt.min(16) - 1))
            .min(BACKOFF_CAP);
        assert!(delay >= ceiling / 2, "{attempt}: {delay:?}");
    }
}

#[test]
fn full_keys_and_listing_prefixes() {
    let d = destination(16);
    assert_eq!(d.full_key("backups/x"), "p/backups/x");
    assert_eq!(d.list_prefix("").unwrap(), "p/");
    assert_eq!(d.list_prefix("backups").unwrap(), "p/backups/");
    assert!(d.list_prefix("../x").is_err());
    assert_eq!(d.client.path(Some("p/a b")), "/bkt/p/a%20b");
    assert_eq!(d.client.path(None), "/bkt");
    // Dropping a destination never blocks or panics, also inside an async context.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async move { drop(d) });
}
