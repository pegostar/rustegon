// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Fuzz oracles of the security-relevant input parsers (TC-SEC-010, NFR-SEC-004, PD-060).
//!
//! Each check takes arbitrary bytes, drives one parser exactly as the server does and returns
//! `Err` when a property is violated; a panic, stack overflow or hang inside the parser is a
//! finding as well. The cargo-fuzz targets in `fuzz/fuzz_targets/` call these functions (with
//! the `fuzzing` feature), and the stable smoke test of this module (`tests` below) runs the
//! same checks in every `cargo nextest run` on golden seeds, byte mutations, random bytes and
//! the reproducers committed under `fuzz/regressions/<target>/`.
//!
//! | Target | Parser | Oracle besides "no panic" |
//! |---|---|---|
//! | `scram_server` | SCRAM client-first / client-final (RFC 5802/7677, `rustegon-security`) | a proof never verifies against random keys; server-first carries `r=`, `s=`, `i=` |
//! | `request_headers` | gRPC metadata and REST header context (PD-050/PD-052 rules), cookie, CSRF, `If-Match` | a cookie-authenticated unsafe request is admitted only with the session's CSRF token; credentials come from `authorization` or the cookie only |
//! | `rest_body` | extended-JSON documents/values/params, list `filter`/`sort` (PD-055), path ids | accepted documents round-trip through canonical JSON and RDoc; the list statement always parses as one query |
//! | `continuation_token` | base64url + AES-GCM sealed continuation tokens | an opened token is bound to its owner |
//! | `authorization` | `authorization` header → session token / API key lookup | only the one valid session token and API key authenticate |
//! | `x509_identity` | client certificate DER → node / `x509:` identity, node role (URI SAN or legacy EKU, ADR-035) | the node role read by `rustegon-security` (x509-cert) and `rustegon-net` (x509-parser) agree |
//!
//! The module is compiled for tests and with the `fuzzing` feature only; it is not part of the
//! server's API.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rustegon_doc::{
    json::{JsonMode, parse_document, parse_value, to_json, value_to_json},
    rdoc,
};
use rustegon_net::rustls::pki_types::CertificateDer;
use rustegon_query::{Statement, parse_statement};
use rustegon_security::authn::{
    AuthnSettings, MemSystemTxn, PasswordChange,
    apikey::{Argon2Cost, NewApiKey, authenticate_api_key, create_api_key_with_cost},
    scram::{
        ClientFirst, CredentialState, FakeSaltKey, Mechanism, ScramCredentials, ScramServer,
        ServerBinding, ServerContext,
    },
    session::{SessionKind, create_session, validate_session},
    users::{NewUser, create_user, get_user},
    x509::{CertIdentity, identity_from_cert},
};
use rustegon_sim_api::{Clock, Rng, SystemClock};
use serde_json::value::RawValue;
use tonic::metadata::MetadataMap;

use crate::{
    Executor,
    grpc::metadata::context_from_metadata,
    rest::{
        CSRF_HEADER,
        auth::session_cookie,
        context_from_headers, csrf_token,
        documents::{ListQuery, list_statement},
        is_safe_method, wire,
    },
    security::{credential, key_id_of},
    services::{RawRequestHeaders, RequestContext, ServiceDeps, token::TokenSealer},
};

/// A fuzz oracle: `Err` describes a violated property.
pub type Check = fn(&[u8]) -> Result<(), String>;

/// The fuzz targets (`fuzz/Cargo.toml` `[[bin]]` names) and their oracles.
pub const TARGETS: &[(&str, Check)] = &[
    ("scram_server", scram_server),
    ("request_headers", request_headers),
    ("rest_body", rest_body),
    ("continuation_token", continuation_token),
    ("authorization", authorization),
    ("x509_identity", x509_identity),
];

/// Runs `check` on `data` for a cargo-fuzz target; on a violated property, saves the input as
/// `artifacts/<target>/violation-<hash>` (relative to the fuzz directory) and panics.
///
/// The input is saved here because on Windows a Rust panic in a libFuzzer target aborts with
/// `STATUS_STACK_BUFFER_OVERRUN`, which bypasses libFuzzer's own crash-artifact writer.
pub fn run_target(target: &str, check: Check, data: &[u8]) {
    if let Err(violation) = check(data) {
        let hash = blake3::hash(data).to_hex();
        let dir = std::path::Path::new("artifacts").join(target);
        // Best effort: the panic below is the finding even if the file cannot be written.
        let _ = std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::write(dir.join(format!("violation-{}", &hash[..16])), data));
        #[allow(clippy::panic)] // a violated oracle is a fuzzing finding: abort the run
        {
            panic!("{target}: {violation}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------------------------

/// Deterministic, non-cryptographic randomness: a fuzzer must replay an input to the same
/// outcome, and nothing here protects a secret.
#[derive(Debug, Default)]
struct DetRng(AtomicU64);

impl Rng for DetRng {
    fn fill_bytes(&self, buf: &mut [u8]) {
        for b in buf {
            // SplitMix64 step; one byte per step keeps the code obvious.
            let x = self
                .0
                .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
                .wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *b = (z ^ (z >> 31)).to_le_bytes()[0];
        }
    }
}

fn deps() -> ServiceDeps {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    ServiceDeps {
        executor: Executor::new(Arc::clone(&clock), 1),
        clock,
        rng: Arc::new(DetRng::default()),
    }
}

/// A fixed point in time (the stored session and key were created then).
fn epoch() -> SystemTime {
    UNIX_EPOCH + Duration::from_hours(500_000)
}

/// The stored credentials of the `authorization` oracle: one user, one live session, one
/// API key (Argon2id at the smallest cost: a fuzzer finds the key id and then hashes often).
struct AuthFixture {
    txn: MemSystemTxn,
    token: String,
    key: String,
    settings: AuthnSettings,
}

fn auth_fixture() -> Result<AuthFixture, String> {
    let rng = DetRng::default();
    let settings = AuthnSettings::default();
    let mut txn = MemSystemTxn::new();
    let now = epoch();
    create_user(
        &mut txn,
        &NewUser {
            name: "svc",
            password: None,
            roles: vec!["read".into()],
            password_change: PasswordChange::NotRequired,
        },
        &settings,
        now,
        &rng,
    )
    .map_err(|e| e.to_string())?;
    let user = get_user(&txn, "svc")
        .map_err(|e| e.to_string())?
        .ok_or("fixture user missing")?;
    let (token, _) = create_session(
        &mut txn,
        &user,
        SessionKind::Driver,
        "fuzz",
        &settings,
        now,
        &rng,
    )
    .map_err(|e| e.to_string())?;
    let (_, key) = create_api_key_with_cost(
        &mut txn,
        NewApiKey {
            user: "svc",
            name: "fuzz",
            roles: vec!["read".into()],
            expires_at: None,
            allow: vec![],
        },
        now,
        &rng,
        Argon2Cost {
            m_kib: 8,
            t: 1,
            p: 1,
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(AuthFixture {
        txn,
        token: token.expose().as_str().to_owned(),
        key: key.expose().as_str().to_owned(),
        settings,
    })
}

thread_local! {
    // Thread-local: the store is a `RefCell` map, and fuzzers and smoke tests run one input at
    // a time per thread.
    static AUTH: RefCell<Option<AuthFixture>> = const { RefCell::new(None) };
    static SEALER: TokenSealer = TokenSealer::new(&SEALER_KEY, Arc::new(DetRng::default()));
}

const SEALER_KEY: [u8; 32] = [0x5A; 32];
const OWNER: &str = "admin";

// ---------------------------------------------------------------------------------------------
// scram_server
// ---------------------------------------------------------------------------------------------

/// Credentials no proof can match without inverting SHA-256.
fn random_credentials() -> ScramCredentials {
    ScramCredentials::from_parts(vec![1; 16], 4096, [0x11; 32], [0x22; 32])
}

/// `mode` byte, then `client-first` `\n` `client-final`. Bits of `mode`: 0 = PLUS mechanism,
/// 1 = the connection offers a TLS exporter, 2–3 = usable / disabled / unknown user,
/// 4 = complete the client-final from the server nonce (so mutations reach the proof check).
///
/// # Errors
/// A violated property (module docs).
pub fn scram_server(data: &[u8]) -> Result<(), String> {
    let Some((&mode, rest)) = data.split_first() else {
        return Ok(());
    };
    // The server refuses non-UTF-8 payloads before parsing (`grpc::auth`).
    let Ok(text) = std::str::from_utf8(rest) else {
        return Ok(());
    };
    let (first, last) = text.split_once('\n').unwrap_or((text, ""));
    let mechanism = if mode & 1 == 0 {
        Mechanism::ScramSha256
    } else {
        Mechanism::ScramSha256Plus
    };
    let exporter = [0x42; 32];
    let binding = if mode & 2 == 0 {
        ServerBinding::Unavailable
    } else {
        ServerBinding::TlsExporter(exporter)
    };
    let state = match (mode >> 2) & 3 {
        0 => CredentialState::Usable(random_credentials()),
        1 => CredentialState::Disabled(random_credentials()),
        _ => CredentialState::Unknown,
    };
    let Ok(parsed) = ClientFirst::parse(mechanism, first) else {
        return Ok(());
    };
    let fake = FakeSaltKey::new([9; 32]);
    let ctx = ServerContext {
        binding,
        fake_salt_key: &fake,
        default_iterations: 4096,
    };
    let Ok((server, server_first)) = ScramServer::start(parsed, state, &ctx, &DetRng::default())
    else {
        return Ok(());
    };
    let mut attrs = server_first.split(',');
    let nonce = attrs
        .next()
        .and_then(|a| a.strip_prefix("r="))
        .ok_or_else(|| format!("server-first without r=: {server_first:?}"))?;
    if !attrs.next().is_some_and(|a| a.starts_with("s="))
        || !attrs.next().is_some_and(|a| a.starts_with("i="))
    {
        return Err(format!("malformed server-first {server_first:?}"));
    }
    let client_final = if mode & 16 == 0 {
        last.to_owned()
    } else {
        // The gs2 header is the first two fields of client-first; the channel binding data is
        // the exporter for `p=`.
        let mut gs2 = first.splitn(3, ',');
        let header = format!(
            "{},{},",
            gs2.next().unwrap_or_default(),
            gs2.next().unwrap_or_default()
        );
        let mut cb = header.into_bytes();
        if first.starts_with("p=") {
            cb.extend_from_slice(&exporter);
        }
        format!("c={},r={nonce}{last}", B64.encode(cb))
    };
    if server.finish(&client_final).is_ok() {
        return Err(format!(
            "a SCRAM proof verified against random keys: {client_final:?}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// request_headers
// ---------------------------------------------------------------------------------------------

/// Header names the fuzzer picks from (one byte per header line).
const HEADER_NAMES: &[&str] = &[
    "rgn-request-id",
    "traceparent",
    "grpc-timeout",
    "rgn-txn-id",
    "rgn-causality-token",
    "authorization",
    "x-rgn-timeout-ms",
    "cookie",
    CSRF_HEADER,
    "if-match",
    "rgn-unknown",
];

/// `method` byte, then header lines `name-byte value` separated by `\n`.
fn header_map(data: &[u8]) -> (Method, HeaderMap) {
    let (method, rest) = match data.split_first() {
        Some((&m, rest)) => (
            match m % 4 {
                0 => Method::GET,
                1 => Method::POST,
                2 => Method::DELETE,
                _ => Method::PATCH,
            },
            rest,
        ),
        None => (Method::GET, data),
    };
    let mut headers = HeaderMap::new();
    for line in rest.split(|&b| b == b'\n') {
        let Some((&n, value)) = line.split_first() else {
            continue;
        };
        let name = HEADER_NAMES[usize::from(n) % HEADER_NAMES.len()];
        // Values the HTTP layer would refuse never reach the server.
        if let Ok(v) = HeaderValue::from_bytes(value) {
            headers.append(HeaderName::from_static(name), v);
        }
    }
    (method, headers)
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a HeaderValue> {
    let mut all = headers.get_all(name).iter();
    let first = all.next()?;
    all.next().is_none().then_some(first)
}

/// # Errors
/// A violated property (module docs).
pub fn request_headers(data: &[u8]) -> Result<(), String> {
    let (method, headers) = header_map(data);
    let deps = deps();
    let authorization = single(&headers, "authorization").and_then(|v| v.to_str().ok());

    // gRPC: every header is metadata; credentials are the `authorization` value as is.
    let metadata = MetadataMap::from_headers(headers.clone());
    if let Ok(ctx) = context_from_metadata(&metadata, &deps) {
        let presented = ctx.credentials().map(|c| c.expose().as_str());
        if presented != authorization {
            return Err(format!(
                "gRPC credentials {presented:?} do not come from `authorization`"
            ));
        }
        check_ids(&ctx, &headers)?;
    }

    // REST: `authorization` wins; otherwise the session cookie, behind the CSRF check.
    if let Ok(ctx) = context_from_headers(&method, &headers, &deps) {
        let presented = ctx.credentials().map(|c| c.expose().clone());
        let cookie = session_cookie(&headers).ok().flatten();
        let expected = match (authorization, &cookie) {
            (Some(a), _) => Some(a.to_owned()),
            (None, Some(token)) => Some(format!("Bearer {token}")),
            (None, None) => None,
        };
        if presented != expected {
            return Err(format!(
                "REST credentials {presented:?}, expected {expected:?}"
            ));
        }
        if let (None, Some(token)) = (authorization, &cookie)
            && !is_safe_method(&method)
        {
            let csrf = single(&headers, CSRF_HEADER).and_then(|v| v.to_str().ok());
            if csrf != Some(csrf_token(token).as_str()) {
                return Err(format!(
                    "{method} with a session cookie admitted without its CSRF token"
                ));
            }
        }
        check_ids(&ctx, &headers)?;
    }

    if let Ok(Some(rev)) = wire::if_match(&headers)
        && (rev.is_empty() || rev.contains('"'))
    {
        return Err(format!("If-Match accepted the revision {rev:?}"));
    }
    Ok(())
}

/// A client-supplied request id is the header's; transaction ids and causality tokens are
/// passed through unchanged.
fn check_ids(ctx: &RequestContext, headers: &HeaderMap) -> Result<(), String> {
    let has_id = single(headers, "rgn-request-id").is_some();
    if ctx.has_client_request_id() != has_id {
        return Err("client request id flag does not match the header".into());
    }
    let txn = single(headers, "rgn-txn-id").and_then(|v| v.to_str().ok());
    if ctx.txn_id() != txn {
        return Err(format!(
            "transaction id {:?} != header {txn:?}",
            ctx.txn_id()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// rest_body
// ---------------------------------------------------------------------------------------------

/// `mode` byte, then the input: 0 document body, 1 value, 2 query parameters, 3 list filter
/// (`filter` `\n` `sort`), 4 document id from a path segment.
///
/// # Errors
/// A violated property (module docs).
pub fn rest_body(data: &[u8]) -> Result<(), String> {
    let Some((&mode, rest)) = data.split_first() else {
        return Ok(());
    };
    match mode % 5 {
        0 => {
            let Ok(raw) = serde_json::from_slice::<Box<RawValue>>(rest) else {
                return Ok(());
            };
            if let Ok(doc) = wire::document_in(&raw, "document") {
                let text = to_json(&doc, JsonMode::Canonical);
                let again = parse_document(&text)
                    .map_err(|e| format!("canonical JSON {text:?} does not parse: {e}"))?;
                if again != doc {
                    return Err(format!("canonical JSON {text:?} changes the document"));
                }
                if let Ok(bytes) = rdoc::encode(&doc) {
                    let back = rdoc::decode(&bytes)
                        .map_err(|e| format!("RDoc of {text:?} does not decode: {e}"))?;
                    if back != doc {
                        return Err(format!("RDoc round trip changes {text:?}"));
                    }
                }
            }
        }
        1 => {
            let Ok(raw) = serde_json::from_slice::<Box<RawValue>>(rest) else {
                return Ok(());
            };
            if let Ok(v) = wire::value_in(&raw, "value") {
                let text = value_to_json(&v, JsonMode::Canonical);
                let again = parse_value(&text)
                    .map_err(|e| format!("canonical JSON {text:?} does not parse: {e}"))?;
                if again != v {
                    return Err(format!("canonical JSON {text:?} changes the value"));
                }
            }
        }
        2 => {
            if let Ok(map) = serde_json::from_slice::<BTreeMap<String, Box<RawValue>>>(rest) {
                let _ = wire::params_in(&map);
            }
        }
        3 => {
            // Query strings reach the handler percent-decoded as UTF-8.
            let Ok(text) = std::str::from_utf8(rest) else {
                return Ok(());
            };
            let (filter, sort) = match text.split_once('\n') {
                Some((f, s)) => (f, Some(s.to_owned())),
                None => (text, None),
            };
            let q = ListQuery {
                filter: Some(filter.to_owned()),
                sort,
                ..ListQuery::default()
            };
            if let Ok(stmt) = list_statement("items", &q) {
                // The filter is spliced into a statement: whatever it is, the result must be
                // exactly one query (no injection of clauses or statements).
                match parse_statement(&stmt) {
                    Ok(Statement::Query(_)) => {}
                    Ok(other) => {
                        return Err(format!("list statement {stmt:?} is not a query: {other:?}"));
                    }
                    Err(e) => return Err(format!("list statement {stmt:?} does not parse: {e}")),
                }
            }
        }
        _ => {
            let Ok(text) = std::str::from_utf8(rest) else {
                return Ok(());
            };
            let id = wire::id_from_path(text);
            wire::value_out(&id).map_err(|e| format!("path id {text:?} not printable: {e}"))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// continuation_token
// ---------------------------------------------------------------------------------------------

/// `mode` byte, then a sealed token: raw bytes (gRPC, `mode` even) or base64url text (REST).
///
/// # Errors
/// A violated property (module docs).
pub fn continuation_token(data: &[u8]) -> Result<(), String> {
    let Some((&mode, rest)) = data.split_first() else {
        return Ok(());
    };
    let sealed = if mode % 2 == 0 {
        rest.to_vec()
    } else {
        let Ok(text) = std::str::from_utf8(rest) else {
            return Ok(());
        };
        match wire::token_in(text) {
            Ok(b) => b,
            Err(_) => return Ok(()),
        }
    };
    SEALER.with(|sealer| {
        for owner in [Some(OWNER), None] {
            let Ok(body) = sealer.open(&sealed, owner) else {
                continue;
            };
            let other = Some("mallory");
            if sealer.open(&sealed, other).is_ok() {
                return Err("a continuation token opened for two owners".to_owned());
            }
            let again = sealer
                .seal(&body, owner)
                .map_err(|e| format!("re-seal failed: {e}"))?;
            if sealer.open(&again, owner).ok().as_deref() != Some(body.as_slice()) {
                return Err("seal/open round trip changed the token".into());
            }
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------------------------
// authorization
// ---------------------------------------------------------------------------------------------

/// The `authorization` header value.
///
/// # Errors
/// A violated property (module docs).
pub fn authorization(data: &[u8]) -> Result<(), String> {
    // Header values are visible ASCII by the time the server reads them.
    let Ok(text) = HeaderValue::from_bytes(data)
        .ok()
        .and_then(|v| v.to_str().ok().map(str::to_owned))
        .ok_or(())
    else {
        return Ok(());
    };
    let deps = deps();
    let headers = RawRequestHeaders {
        authorization: Some(&text),
        ..RawRequestHeaders::default()
    };
    let Ok(ctx) = RequestContext::from_headers(&headers, deps.clock.as_ref(), deps.rng.as_ref())
    else {
        return Ok(());
    };
    let Some(raw) = ctx.credentials().map(|c| c.expose().clone()) else {
        return Err("authorization header lost".into());
    };
    AUTH.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(auth_fixture()?);
        }
        let Some(fx) = slot.as_mut() else {
            return Err("no fixture".to_owned());
        };
        let now = epoch() + Duration::from_secs(1);
        if let Some(token) = credential(&raw, "Bearer")
            && validate_session(&mut fx.txn, token, &fx.settings, now).is_ok()
            && token != fx.token
        {
            return Err(format!("session token {token:?} accepted"));
        }
        if let Some(key) = credential(&raw, "ApiKey") {
            let _ = key_id_of(key);
            let ok =
                authenticate_api_key(&fx.txn, key, IpAddr::V4(Ipv4Addr::LOCALHOST), now).is_ok();
            if ok && key != fx.key {
                return Err(format!("API key {key:?} accepted"));
            }
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------------------------
// x509_identity
// ---------------------------------------------------------------------------------------------

/// A certificate in DER.
///
/// # Errors
/// A violated property (module docs).
pub fn x509_identity(data: &[u8]) -> Result<(), String> {
    let identity = identity_from_cert(data);
    let net = rustegon_net::has_node_role(&CertificateDer::from(data));
    match (&identity, &net) {
        (Ok(CertIdentity::Node(_)), Ok(false)) => {
            Err("node role seen by x509-cert but not by x509-parser".into())
        }
        (Ok(CertIdentity::User(_)), Ok(true)) => {
            Err("node role seen by x509-parser but not by x509-cert".into())
        }
        (Ok(CertIdentity::User(u)), _) if !u.starts_with("x509:") => Err(format!(
            "certificate user {u:?} outside the x509: namespace"
        )),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------------------------
// Seeds
// ---------------------------------------------------------------------------------------------

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    B64.decode(body).map_err(|e| e.to_string())
}

/// Golden inputs of `target`: valid messages the server produces or accepts, plus typical
/// near misses.
///
/// # Errors
/// Fixture generation failures; an unknown target.
#[allow(clippy::too_many_lines)] // one literal seed list per target, read side by side
pub fn seeds(target: &str) -> Result<Vec<Vec<u8>>, String> {
    let with_mode = |mode: u8, s: &str| {
        let mut v = vec![mode];
        v.extend_from_slice(s.as_bytes());
        v
    };
    Ok(match target {
        "scram_server" => {
            let rng = DetRng::default();
            let mut out = Vec::new();
            for (mode, binding) in [
                (
                    0u8,
                    rustegon_security::authn::scram::ClientBinding::Unsupported,
                ),
                (
                    0b11,
                    rustegon_security::authn::scram::ClientBinding::TlsExporter([0x42; 32]),
                ),
                (
                    0b10,
                    rustegon_security::authn::scram::ClientBinding::NotOffered,
                ),
            ] {
                let (_, _, first) = rustegon_security::authn::scram::ScramClient::new(
                    "alice",
                    &rustegon_security::authn::secret("pencil"),
                    binding,
                    &rng,
                );
                for extra in [0, 16, 4, 8] {
                    out.push(with_mode(
                        mode | extra,
                        &format!("{first}\nc=biws,r=x,p=dGVzdHByb29mdGVzdHByb29mdGVzdHByb29mMDE="),
                    ));
                    out.push(with_mode(
                        mode | extra | 16,
                        &format!("{first}\n,p=dGVzdHByb29mdGVzdHByb29mdGVzdHByb29mMDE="),
                    ));
                }
            }
            out.push(with_mode(0, "n,a=bob,n=alice,r=abcdefghijklmnopqrstuvwx\n"));
            out.push(with_mode(
                0,
                "n,,n=al=2Cice=3D,r=abcdefghijklmnopqrstuvwx,m=ext\n",
            ));
            out
        }
        "request_headers" => {
            let token = "c2Vzc2lvbi10b2tlbi1mb3ItdGVzdHMtMDEyMzQ1Njc4OWFi";
            let csrf = csrf_token(token);
            let line = |name: &str, value: &str| {
                let n = HEADER_NAMES.iter().position(|h| *h == name).unwrap_or(0);
                let mut v = vec![u8::try_from(n).unwrap_or(0)];
                v.extend_from_slice(value.as_bytes());
                v
            };
            let join = |method: u8, lines: &[Vec<u8>]| {
                let mut v = vec![method];
                v.extend(lines.join(&b'\n'));
                v
            };
            vec![
                join(
                    0,
                    &[
                        line("rgn-request-id", "01890a5d-ac96-774b-bcce-b302099a8057"),
                        line(
                            "traceparent",
                            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                        ),
                        line("grpc-timeout", "500m"),
                        line("rgn-txn-id", "0001-txn"),
                        line("authorization", "Bearer abc"),
                    ],
                ),
                join(
                    1,
                    &[
                        line("cookie", &format!("theme=dark; rgn_session={token}")),
                        line(CSRF_HEADER, &csrf),
                        line("x-rgn-timeout-ms", "1500"),
                        line("if-match", "\"0000000000000001\""),
                    ],
                ),
                join(1, &[line("cookie", &format!("rgn_session={token}"))]),
                join(
                    3,
                    &[
                        line("rgn-causality-token", "ct-1"),
                        line("if-match", "W/\"x\""),
                        line("grpc-timeout", "99999999H"),
                    ],
                ),
            ]
        }
        "rest_body" => vec![
            with_mode(
                0,
                r#"{"_id": 1, "n": {"$numberLong": "9007199254740993"}, "d": {"$date": "2026-11-08T10:00:00.000Z"}, "x": {"$decimal": "9.99"}, "a": [1, 2.5, null, true, "s"], "o": {"$oid": "65f1a2b3c4d5e6f708192a3b"}}"#,
            ),
            with_mode(
                0,
                r#"{"b": {"$binary": {"base64": "AAEC", "subType": "00"}}, "u": {"$uuid": "123e4567-e89b-12d3-a456-426614174000"}}"#,
            ),
            with_mode(1, r#"{"$numberDouble": "-0.0"}"#),
            with_mode(1, "1e308"),
            with_mode(2, r#"{"1": 5, "min": {"$numberLong": "2"}, "s": "x"}"#),
            with_mode(3, "n >= 2 AND tag = 'x'\n-n,_id"),
            with_mode(3, "n > 1) UNION (FROM x"),
            with_mode(3, "`a``b` IN [1, 2] OR NOT exists(c)\na.b,-c"),
            with_mode(4, "42"),
            with_mode(4, r#"{"$oid": "65f1a2b3c4d5e6f708192a3b"}"#),
            with_mode(4, "alice"),
        ],
        "continuation_token" => SEALER.with(|sealer| {
            let mut out = Vec::new();
            for owner in [Some(OWNER), None] {
                let sealed = sealer
                    .seal(b"\x01engine token bytes", owner)
                    .map_err(|e| e.to_string())?;
                let mut raw = vec![0];
                raw.extend_from_slice(&sealed);
                out.push(raw);
                out.push(with_mode(1, &wire::token_out(&sealed)));
            }
            Ok::<_, String>(out)
        })?,
        "authorization" => {
            let fx = auth_fixture()?;
            vec![
                format!("Bearer {}", fx.token).into_bytes(),
                format!("ApiKey {}", fx.key).into_bytes(),
                format!("bearer   {}", fx.token).into_bytes(),
                b"Basic YWRtaW46YWRtaW4=".to_vec(),
                b"ApiKey rgn_abc_def".to_vec(),
                b"Bearer ".to_vec(),
            ]
        }
        "x509_identity" => {
            let clock = SystemClock::new();
            let rng = rustegon_sim_api::OsRng;
            let (ca, ca_cert) = rustegon_net::CertAuthority::generate(
                "fuzz CA",
                rustegon_net::KeyAlgorithm::EcdsaP256,
                &clock,
                &rng,
            )
            .map_err(|e| e.to_string())?;
            let node = ca
                .issue_node("node1", &["127.0.0.1".into()], &clock, &rng)
                .map_err(|e| e.to_string())?;
            let client = ca
                .issue_client("alice", &clock, &rng)
                .map_err(|e| e.to_string())?;
            vec![
                pem_to_der(&ca_cert.cert_pem)?,
                pem_to_der(&node.cert_pem)?,
                pem_to_der(&client.cert_pem)?,
                // Legacy node certificate format 1 (EKU OID), still recognised (ADR-035).
                include_bytes!("../../rustegon-net/tests/fixtures/formats/node_cert/1/node.der")
                    .to_vec(),
            ]
        }
        other => return Err(format!("unknown fuzz target {other}")),
    })
}

#[cfg(test)]
mod tests {
    //! TC-SEC-010 stable smoke test: the oracles of the cargo-fuzz targets on stable Rust
    //! (committed reproducers, golden seeds, byte mutations of the seeds, random bytes).
    //! Case count per target: `RGN_SEC_FUZZ_CASES` (default 1500). Setting
    //! `RGN_SEC_FUZZ_SEED_DIR` also writes the seeds as a libFuzzer corpus
    //! (`<dir>/<target>/seed-<n>`), see `fuzz/README.md`.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::path::PathBuf;

    use super::*;

    const DEFAULT_CASES: usize = 1500;

    fn cases() -> usize {
        std::env::var("RGN_SEC_FUZZ_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_CASES)
    }

    /// xorshift64*: reproducible mutations without a dependency.
    struct Prng(u64);

    impl Prng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap()).unwrap()
        }

        fn byte(&mut self) -> u8 {
            self.next().to_le_bytes()[0]
        }
    }

    /// One libFuzzer-style mutation: flip, replace, insert, delete, duplicate a range, or
    /// splice in an interesting byte.
    fn mutate(seed: &[u8], rng: &mut Prng) -> Vec<u8> {
        let mut v = seed.to_vec();
        for _ in 0..=rng.below(4) {
            let len = v.len();
            match rng.below(6) {
                0 if len > 0 => {
                    let i = rng.below(len);
                    v[i] ^= 1 << rng.below(8);
                }
                1 if len > 0 => {
                    let i = rng.below(len);
                    v[i] = rng.byte();
                }
                2 => {
                    let i = rng.below(len + 1);
                    v.insert(i, rng.byte());
                }
                3 if len > 0 => {
                    let i = rng.below(len);
                    let n = rng.below(len - i) + 1;
                    v.drain(i..i + n);
                }
                4 if len > 0 => {
                    let i = rng.below(len);
                    let n = (rng.below(len - i) + 1).min(64);
                    let chunk = v[i..i + n].to_vec();
                    let at = rng.below(v.len() + 1);
                    v.splice(at..at, chunk);
                }
                _ => {
                    let interesting = [0u8, b'\n', b',', b'=', b'"', b'\\', b'{', 0x7F, 0xFF];
                    let i = rng.below(len + 1);
                    v.insert(i, interesting[rng.below(interesting.len())]);
                }
            }
        }
        v
    }

    fn regressions(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/regressions")
            .join(target);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .map(|e| e.unwrap().path())
            .filter(|p| p.is_file())
            .map(|p| {
                let bytes = std::fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect()
    }

    fn run(target: &str, check: Check) {
        let fail = |what: &str, input: &[u8], e: &str| {
            panic!("{target}: {what} violates a property: {e}\ninput: {input:?}")
        };
        for (path, input) in regressions(target) {
            if let Err(e) = check(&input) {
                fail(&path.display().to_string(), &input, &e);
            }
        }
        let seeds = seeds(target).unwrap();
        if let Ok(dir) = std::env::var("RGN_SEC_FUZZ_SEED_DIR") {
            let dir = PathBuf::from(dir).join(target);
            std::fs::create_dir_all(&dir).unwrap();
            for (i, s) in seeds.iter().enumerate() {
                std::fs::write(dir.join(format!("seed-{i}")), s).unwrap();
            }
        }
        for s in &seeds {
            if let Err(e) = check(s) {
                fail("seed", s, &e);
            }
        }
        let mut rng = Prng(0x00C0_FFEE_D00D_F00D ^ target.len() as u64);
        let n = cases();
        for i in 0..n {
            let input = if i % 4 == 3 {
                (0..rng.below(256)).map(|_| rng.byte()).collect()
            } else {
                mutate(&seeds[rng.below(seeds.len())], &mut rng)
            };
            if let Err(e) = check(&input) {
                fail("mutated input", &input, &e);
            }
        }
    }

    #[test]
    fn tc_sec_010_fuzz_smoke_scram_server() {
        run("scram_server", scram_server);
    }

    #[test]
    fn tc_sec_010_fuzz_smoke_request_headers() {
        run("request_headers", request_headers);
    }

    #[test]
    fn tc_sec_010_fuzz_smoke_rest_body() {
        run("rest_body", rest_body);
    }

    #[test]
    fn tc_sec_010_fuzz_smoke_continuation_token() {
        run("continuation_token", continuation_token);
    }

    #[test]
    fn tc_sec_010_fuzz_smoke_authorization() {
        run("authorization", authorization);
    }

    #[test]
    fn tc_sec_010_fuzz_smoke_x509_identity() {
        run("x509_identity", x509_identity);
    }

    /// The seeds that must succeed do: the real session token and API key authenticate, a
    /// sealed token opens for its owner only, the generated certificates map to identities.
    #[test]
    fn tc_sec_010_fuzz_oracles_accept_the_valid_inputs() {
        AUTH.with(|cell| *cell.borrow_mut() = Some(auth_fixture().unwrap()));
        AUTH.with(|cell| {
            let mut slot = cell.borrow_mut();
            let fx = slot.as_mut().unwrap();
            let now = epoch() + Duration::from_secs(1);
            let token = fx.token.clone();
            assert!(validate_session(&mut fx.txn, &token, &fx.settings, now).is_ok());
            assert!(
                authenticate_api_key(&fx.txn, &fx.key, IpAddr::V4(Ipv4Addr::LOCALHOST), now)
                    .is_ok()
            );
        });
        SEALER.with(|s| {
            let sealed = s.seal(b"t", Some(OWNER)).unwrap();
            assert_eq!(s.open(&sealed, Some(OWNER)).unwrap(), b"t");
            assert!(s.open(&sealed, None).is_err());
        });
        let certs = seeds("x509_identity").unwrap();
        assert!(matches!(
            identity_from_cert(&certs[1]),
            Ok(CertIdentity::Node(_))
        ));
        assert!(matches!(
            identity_from_cert(&certs[2]),
            Ok(CertIdentity::User(_))
        ));
        assert!(matches!(
            identity_from_cert(&certs[3]),
            Ok(CertIdentity::Node(_))
        ));
        assert_eq!(TARGETS.len(), 6);
    }
}
