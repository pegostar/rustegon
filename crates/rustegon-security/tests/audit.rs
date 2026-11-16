// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Audit log (FR-SEC-004, AC-SEC-004, TC-SEC-004): every event kind with the required fields,
//! BLAKE3 hash chain across rotations and reopen, torn-tail recovery, verifier detection of
//! edits/deletions/reordering, secret canaries never written; audit record format 1 fixture
//! (implementation-rules.md §6).
//!
//! Generate a missing fixture (an existing file is never overwritten):
//! `RUSTEGON_WRITE_FIXTURES=1 cargo nextest run -p rustegon-security --test audit`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use common::ManualClock;
use rustegon_common::{ErrorCode, Redacted, redacted::REDACTED};
use rustegon_security::audit::{
    AuditError, AuditEvent, AuditEventKind, AuditLog, AuditLogConfig, AuditOutcome, ChainFault,
    GENESIS_HASH, log::segment_name, verify_dir,
};
use rustegon_sim_api::{FileSystem, OpenMode, StdFileSystem};

const REQUIRED: [&str; 13] = [
    "v",
    "seq",
    "ts",
    "node",
    "event",
    "user",
    "roles",
    "source_ip",
    "resource",
    "action",
    "outcome",
    "details",
    "prev_hash",
];

struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    fs: Arc<StdFileSystem>,
    clock: Arc<ManualClock>,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        Self {
            _tmp: tmp,
            dir,
            fs: Arc::new(StdFileSystem),
            clock: Arc::new(ManualClock::default()),
        }
    }

    fn open(&self, max_file_size: u64, max_files: u32) -> AuditLog {
        self.open_res(max_file_size, max_files).unwrap()
    }

    fn open_res(&self, max_file_size: u64, max_files: u32) -> Result<AuditLog, AuditError> {
        AuditLog::open(
            self.fs.clone(),
            self.clock.clone(),
            AuditLogConfig {
                dir: self.dir.clone(),
                node: "n1".into(),
                max_file_size,
                max_files,
            },
        )
    }

    fn segments(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        v.sort();
        v
    }

    fn all_text(&self) -> String {
        self.segments()
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect()
    }
}

fn login(i: u64) -> AuditEvent {
    AuditEvent::new(AuditEventKind::LoginFailure, AuditOutcome::Failure)
        .user(format!("user{i}"))
        .source_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
        .detail("reason", "bad credentials")
}

fn full_event(kind: AuditEventKind) -> AuditEvent {
    AuditEvent::new(kind, AuditOutcome::Success)
        .user("alice")
        .roles(["read@shop", "monitor"])
        .source_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        .resource("collection:shop.orders")
        .action("find")
        .detail("request_id", "r-1")
}

#[test]
fn tc_sec_004_all_event_kinds_written_with_required_fields() {
    let f = Fixture::new();
    let log = f.open(64 << 20, 0);
    for kind in AuditEventKind::ALL {
        f.clock.advance(Duration::from_millis(5));
        log.record(&full_event(kind)).unwrap();
    }
    let text = f.all_text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), AuditEventKind::ALL.len());
    for (i, (line, kind)) in lines.iter().zip(AuditEventKind::ALL).enumerate() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let obj = v.as_object().unwrap();
        for key in REQUIRED {
            assert!(obj.contains_key(key), "{kind}: missing {key}");
        }
        assert_eq!(obj.len(), REQUIRED.len(), "{kind}: unexpected fields");
        assert_eq!(obj["event"], kind.as_str());
        assert_eq!(obj["seq"], i as u64 + 1);
        assert_eq!(obj["node"], "n1");
        assert_eq!(obj["user"], "alice");
        assert_eq!(obj["roles"], serde_json::json!(["read@shop", "monitor"]));
        assert_eq!(obj["source_ip"], "192.0.2.1");
        assert_eq!(obj["resource"], "collection:shop.orders");
        assert_eq!(obj["action"], "find");
        assert_eq!(obj["outcome"], "success");
        assert_eq!(obj["details"]["request_id"], "r-1");
        assert!(
            obj["ts"]
                .as_str()
                .unwrap()
                .starts_with("2026-11-08T00:00:00.")
        );
    }
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(lines[0]).unwrap()["prev_hash"],
        GENESIS_HASH
    );
    let report = verify_dir(f.fs.as_ref(), &f.dir).unwrap();
    assert_eq!(report.records, AuditEventKind::ALL.len() as u64);
    assert_eq!((report.first_seq, report.last_seq), (1, 19));
    assert_eq!(report.head_hash, log.head_hash().unwrap());
}

#[test]
fn tc_sec_004_chain_continues_across_rotation_and_reopen() {
    let f = Fixture::new();
    {
        let log = f.open(700, 0);
        for i in 0..20 {
            log.record(&login(i)).unwrap();
        }
    }
    let log = f.open(700, 0);
    assert_eq!(log.next_seq().unwrap(), 21);
    for i in 20..25 {
        log.record(&login(i)).unwrap();
    }
    let segs = f.segments();
    assert!(segs.len() > 3, "expected rotation, got {segs:?}");
    // Each file is named after its first record.
    for s in &segs {
        let first = std::fs::read_to_string(s).unwrap();
        let first: serde_json::Value = serde_json::from_str(first.lines().next().unwrap()).unwrap();
        let name = s.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, segment_name(first["seq"].as_u64().unwrap()));
    }
    let report = verify_dir(f.fs.as_ref(), &f.dir).unwrap();
    assert_eq!((report.records, report.last_seq), (25, 25));
    assert_eq!(report.files, segs.len());
    assert!(!report.torn_tail);
}

#[test]
fn tc_sec_004_torn_tail_and_empty_segment_recovered() {
    let f = Fixture::new();
    {
        let log = f.open(64 << 20, 0);
        for i in 0..3 {
            log.record(&login(i)).unwrap();
        }
    }
    // An unsynced, partial append.
    let newest = f.segments().pop().unwrap();
    let mut file = f.fs.open(&newest, OpenMode::Append).unwrap();
    file.append(br#"{"v":1,"seq":4,"ts":"#).unwrap();
    drop(file);
    assert!(verify_dir(f.fs.as_ref(), &f.dir).unwrap().torn_tail);
    {
        let log = f.open(64 << 20, 0);
        assert_eq!(log.next_seq().unwrap(), 4);
        log.record(&login(3)).unwrap();
    }
    // A rotation that created its segment but crashed before the first record was durable.
    std::fs::write(f.dir.join(segment_name(5)), b"").unwrap();
    let log = f.open(64 << 20, 0);
    assert_eq!(log.next_seq().unwrap(), 5);
    log.record(&login(4)).unwrap();
    let report = verify_dir(f.fs.as_ref(), &f.dir).unwrap();
    // The empty segment was removed; record 5 continued the previous one.
    assert_eq!((report.records, report.files), (5, 1));
    assert!(!report.torn_tail);
}

#[test]
fn tc_sec_004_corrupt_complete_line_refuses_open() {
    let f = Fixture::new();
    {
        let log = f.open(64 << 20, 0);
        for i in 0..3 {
            log.record(&login(i)).unwrap();
        }
    }
    let seg = f.segments().pop().unwrap();
    let text = std::fs::read_to_string(&seg)
        .unwrap()
        .replacen("user1", "userX", 1);
    std::fs::write(&seg, text).unwrap();
    let err = f.open_res(64 << 20, 0).unwrap_err();
    assert!(
        matches!(
            err,
            AuditError::Corrupt {
                line: 3,
                fault: ChainFault::HashMismatch,
                ..
            }
        ),
        "{err:?}"
    );
    let e: rustegon_common::Error = err.into();
    assert_eq!(e.code(), ErrorCode::StorageCorruption);
}

fn write_lines(path: &Path, lines: &[&str]) {
    let mut s = lines.join("\n");
    s.push('\n');
    std::fs::write(path, s).unwrap();
}

#[test]
fn tc_sec_004_verifier_detects_edit_deletion_and_reordering() {
    let f = Fixture::new();
    {
        let log = f.open(64 << 20, 0);
        for i in 0..6 {
            log.record(&login(i)).unwrap();
        }
    }
    let seg = f.segments().pop().unwrap();
    let orig = std::fs::read_to_string(&seg).unwrap();
    let lines: Vec<&str> = orig.lines().collect();
    let fault = |lines: &[&str]| {
        write_lines(&seg, lines);
        match verify_dir(f.fs.as_ref(), &f.dir) {
            Err(AuditError::Corrupt { line, fault, .. }) => (line, fault),
            other => panic!("tampering not detected: {other:?}"),
        }
    };

    // Edit: the next line's prev_hash no longer matches.
    let edited = lines[2].replace("bad credentials", "ok");
    let mut l = lines.clone();
    l[2] = &edited;
    assert_eq!(fault(&l), (4, ChainFault::HashMismatch));

    // Deletion of a middle line.
    let mut l = lines.clone();
    l.remove(3);
    assert_eq!(
        fault(&l),
        (
            4,
            ChainFault::SeqMismatch {
                expected: 4,
                found: 5
            }
        )
    );

    // Reordering, also with renumbered `seq` (only the hash chain can catch that).
    let mut l = lines.clone();
    l.swap(1, 2);
    assert!(matches!(fault(&l).1, ChainFault::SeqMismatch { .. }));
    let a = lines[1].replace(r#""seq":2"#, r#""seq":3"#);
    let b = lines[2].replace(r#""seq":3"#, r#""seq":2"#);
    let l = vec![lines[0], &b, &a, lines[3], lines[4], lines[5]];
    assert_eq!(fault(&l), (2, ChainFault::HashMismatch));

    // Untouched again: verifies.
    write_lines(&seg, &lines);
    assert_eq!(verify_dir(f.fs.as_ref(), &f.dir).unwrap().records, 6);
}

#[test]
fn tc_sec_004_verifier_detects_missing_segment_and_retention_keeps_chain() {
    let f = Fixture::new();
    {
        let log = f.open(700, 0);
        for i in 0..12 {
            log.record(&login(i)).unwrap();
        }
    }
    let segs = f.segments();
    assert!(segs.len() >= 3);
    let middle = &segs[1];
    let saved = std::fs::read(middle).unwrap();
    std::fs::remove_file(middle).unwrap();
    assert!(matches!(
        verify_dir(f.fs.as_ref(), &f.dir),
        Err(AuditError::Corrupt {
            fault: ChainFault::SeqMismatch { .. },
            ..
        })
    ));
    std::fs::write(middle, saved).unwrap();

    // Retention: only the newest segments remain, the chain verifies from the first present.
    let log = f.open(700, 2);
    for i in 12..20 {
        log.record(&login(i)).unwrap();
    }
    assert_eq!(f.segments().len(), 2);
    let report = verify_dir(f.fs.as_ref(), &f.dir).unwrap();
    assert!(report.first_seq > 1);
    assert_eq!(report.last_seq, 20);
    assert_eq!(report.records, 20 - report.first_seq + 1);
}

#[test]
fn tc_sec_004_secret_canaries_never_written() {
    let f = Fixture::new();
    let log = f.open(64 << 20, 0);
    let canaries = [
        "CANARY-7f3a91-explicit",
        "CANARY-7f3a92-password",
        "CANARY-7f3a93-apikey",
        "CANARY-7f3a94-token",
    ];
    log.record(
        &AuditEvent::new(AuditEventKind::UserChange, AuditOutcome::Success)
            .user("admin")
            .resource("cluster")
            .action("user_manage")
            .secret_detail("initial", Redacted::new(canaries[0].to_owned()))
            .detail("new_password", canaries[1])
            .detail("api_key", canaries[2])
            .detail("Session_Token", canaries[3])
            .detail("target_user", "bob"),
    )
    .unwrap();
    let text = f.all_text();
    for c in canaries {
        assert!(!text.contains(c), "canary {c} leaked");
    }
    let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    for k in ["initial", "new_password", "api_key", "Session_Token"] {
        assert_eq!(v["details"][k], REDACTED, "{k}");
    }
    assert_eq!(v["details"]["target_user"], "bob");
}

/// Fixed events for the format fixture.
fn fixture_events() -> Vec<AuditEvent> {
    vec![
        AuditEvent::new(AuditEventKind::LoginSuccess, AuditOutcome::Success)
            .user("alice")
            .roles(["read_write@shop"])
            .source_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
            .detail("mechanism", "scram-sha-256"),
        AuditEvent::new(AuditEventKind::PrivilegeDenied, AuditOutcome::Denied)
            .user("alice")
            .roles(["read_write@shop"])
            .source_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
            .resource("database:shop")
            .action("drop_database"),
        AuditEvent::new(AuditEventKind::Ddl, AuditOutcome::Success)
            .user("root")
            .roles(["root"])
            .resource("collection:shop.orders")
            .action("create_index")
            .detail("index", "by_customer"),
    ]
}

#[test]
fn tc_sec_004_audit_record_v1_fixture() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formats/audit/1");
    let fixture = fixture_dir.join(segment_name(1));
    let f = Fixture::new();
    {
        let log = f.open(64 << 20, 0);
        for e in fixture_events() {
            f.clock.advance(Duration::from_millis(1500));
            log.record(&e).unwrap();
        }
    }
    let produced = std::fs::read(f.dir.join(segment_name(1))).unwrap();
    if std::env::var_os("RUSTEGON_WRITE_FIXTURES").is_some() && !fixture.exists() {
        std::fs::create_dir_all(&fixture_dir).unwrap();
        std::fs::write(&fixture, &produced).unwrap();
    }
    let committed = std::fs::read(&fixture).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (generate with RUSTEGON_WRITE_FIXTURES=1)",
            fixture.display()
        )
    });
    assert_eq!(committed, produced, "audit record format 1 changed");
    let report = verify_dir(&StdFileSystem, &fixture_dir).unwrap();
    assert_eq!((report.records, report.last_seq), (3, 3));
    // The committed log continues: a reader of format 1 recovers its tail.
    let copy = Fixture::new();
    copy.fs.create_dir_all(&copy.dir).unwrap();
    std::fs::write(copy.dir.join(segment_name(1)), &committed).unwrap();
    let log = copy.open(64 << 20, 0);
    assert_eq!(log.next_seq().unwrap(), 4);
    assert_eq!(log.head_hash().unwrap(), report.head_hash);
}
