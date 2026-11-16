// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! In-process fake of the S3 REST subset used by `S3Destination` (path-style only): objects,
//! ranged GET with `If-Match`, HEAD, DELETE, ListObjectsV2 with delimiter and pagination,
//! multipart upload (initiate, part, complete, abort), bucket creation, and fault injection.
//!
//! Every request's SigV4 signature is verified with an implementation written independently of
//! the client's (decode the received path and query, re-encode, rebuild the canonical request),
//! together with `x-amz-content-sha256` against the received body: a mismatch between what the
//! client signs and what it sends fails with 403 `SignatureDoesNotMatch`.

// Test fake: brevity over the pedantic style lints of production code.
#![allow(
    dead_code,
    clippy::doc_markdown,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::redundant_closure_for_method_calls,
    clippy::similar_names,
    clippy::single_match_else,
    clippy::too_many_lines
)]

use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http::{Request, Response, StatusCode, request::Parts};
use http_body_util::{BodyExt as _, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rustegon_net::{rustls, tokio_rustls::TlsAcceptor};
use rustegon_sim_api::{Connection, Network as _, TokioNetwork};
use sha2::{Digest, Sha256};

pub const ACCESS_KEY: &str = "FAKEACCESSKEY";
pub const SECRET_KEY: &str = "fake/secret+key";
pub const BUCKET: &str = "fake-bucket";

/// Mutable server state, shared with the test for assertions and fault injection.
#[derive(Default)]
pub struct State {
    pub objects: BTreeMap<String, (Bytes, String)>,
    pub uploads: HashMap<String, BTreeMap<u32, Bytes>>,
    pub counter: u64,
    /// `METHOD /path?sorted-query-names` of every request, in order.
    pub log: Vec<String>,
    /// The next N requests answer 503 SlowDown.
    pub fail_next: u32,
    /// Part number whose upload answers 403 AccessDenied.
    pub deny_part: Option<u32>,
    /// The next CompleteMultipartUpload succeeds but answers 500.
    pub lose_complete: bool,
    /// Requests hang forever.
    pub stall: bool,
    /// Listing page size (small, to exercise pagination).
    pub page_size: usize,
    pub bucket_exists: bool,
}

pub struct FakeS3 {
    pub addr: SocketAddr,
    pub state: Arc<Mutex<State>>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for FakeS3 {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

impl FakeS3 {
    pub fn start() -> Self {
        Self::start_with(None)
    }

    /// A fake serving HTTPS with cert_pem / key_pem (TLS 1.3, Rustegon's ring provider).
    pub fn start_tls(cert_pem: &str, key_pem: &str) -> Self {
        let certs =
            rustegon_net::parse_certificates(cert_pem.as_bytes(), Path::new("cert")).unwrap();
        let key = rustegon_net::parse_private_key(key_pem.as_bytes(), Path::new("key")).unwrap();
        let mut config =
            rustls::ServerConfig::builder_with_provider(rustegon_net::crypto_provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key.expose().clone_key())
                .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self::start_with(Some(TlsAcceptor::from(Arc::new(config))))
    }

    fn start_with(tls: Option<TlsAcceptor>) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let state = Arc::new(Mutex::new(State {
            page_size: 2,
            bucket_exists: true,
            ..State::default()
        }));
        let mut listener = runtime
            .block_on(TokioNetwork.bind("127.0.0.1:0".parse().unwrap()))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let shared = Arc::clone(&state);
        runtime.spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let state = Arc::clone(&shared);
                let tls = tls.clone();
                tokio::spawn(async move {
                    let conn: Box<dyn Connection> = match tls {
                        Some(acceptor) => match acceptor.accept(conn).await {
                            Ok(stream) => Box::new(stream),
                            Err(_) => return,
                        },
                        None => conn,
                    };
                    let service = service_fn(move |req| handle(Arc::clone(&state), req));
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(conn), service)
                        .await;
                });
            }
        });
        Self {
            addr,
            state,
            runtime: Some(runtime),
        }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn https_endpoint(&self) -> String {
        format!("https://{}", self.addr)
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }
}

fn reply(status: u16, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(body.into()));
    *resp.status_mut() = StatusCode::from_u16(status).unwrap();
    resp
}

fn error(status: u16, code: &str) -> Response<Full<Bytes>> {
    reply(
        status,
        format!("<Error><Code>{code}</Code><Message>fake {code}</Message></Error>"),
    )
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn encode(s: &str, keep_slash: bool) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) || (keep_slash && b == b'/') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn query_pairs(parts: &Parts) -> Vec<(String, String)> {
    parts
        .uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

/// Independent SigV4 check of a received request (module docs).
fn verify_signature(parts: &Parts, body: &[u8]) -> Result<(), String> {
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let auth = header("authorization").ok_or("no authorization")?;
    let rest = auth
        .strip_prefix("AWS4-HMAC-SHA256 Credential=")
        .ok_or("bad algorithm")?;
    let (credential, rest) = rest.split_once(", SignedHeaders=").ok_or("bad header")?;
    let (signed, signature) = rest.split_once(", Signature=").ok_or("bad header")?;
    let mut scope = credential.splitn(2, '/');
    if scope.next() != Some(ACCESS_KEY) {
        return Err("wrong access key".into());
    }
    let scope = scope.next().ok_or("no scope")?;
    let payload = header("x-amz-content-sha256").ok_or("no payload hash")?;
    if payload != hex(&Sha256::digest(body)) {
        return Err("payload hash does not match the body".into());
    }
    let amz_date = header("x-amz-date").ok_or("no date")?;
    let path = encode(&decode(parts.uri.path()), true);
    let mut query: Vec<String> = query_pairs(parts)
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k, false), encode(v, false)))
        .collect();
    query.sort();
    let mut headers = String::new();
    for name in signed.split(';') {
        let value = header(name).ok_or_else(|| format!("signed header {name} missing"))?;
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        headers.push_str(&format!("{name}:{value}\n"));
    }
    let creq = format!(
        "{}\n{path}\n{}\n{headers}\n{signed}\n{payload}",
        parts.method,
        query.join("&")
    );
    let sts = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(creq.as_bytes()))
    );
    let fields: Vec<&str> = scope.split('/').collect();
    let mut key = hmac(format!("AWS4{SECRET_KEY}").as_bytes(), fields[0]);
    for f in &fields[1..] {
        key = hmac(&key, f);
    }
    if hex(&hmac(&key, &sts)) == signature {
        Ok(())
    } else {
        Err(format!("signature mismatch; canonical request:\n{creq}"))
    }
}

async fn handle(
    state: Arc<Mutex<State>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    if state.lock().unwrap().stall {
        std::future::pending::<()>().await;
    }
    if let Err(why) = verify_signature(&parts, &body) {
        eprintln!("fake S3: {why}");
        return Ok(error(403, "SignatureDoesNotMatch"));
    }
    let mut st = state.lock().unwrap();
    let query: BTreeMap<String, String> = query_pairs(&parts).into_iter().collect();
    let names: Vec<&str> = query.keys().map(String::as_str).collect();
    st.log.push(format!(
        "{} {}?{}",
        parts.method,
        parts.uri.path(),
        names.join("&")
    ));
    if st.fail_next > 0 {
        st.fail_next -= 1;
        return Ok(error(503, "SlowDown"));
    }
    let path = decode(parts.uri.path());
    let rest = path.strip_prefix(&format!("/{BUCKET}")).unwrap_or("\u{0}");
    if rest == "\u{0}" {
        return Ok(error(404, "NoSuchBucket"));
    }
    let key = rest.strip_prefix('/').unwrap_or("").to_owned();
    let method = parts.method.as_str();
    let resp = match (method, key.is_empty()) {
        ("PUT", true) => {
            if st.bucket_exists {
                error(409, "BucketAlreadyOwnedByYou")
            } else {
                st.bucket_exists = true;
                reply(200, "")
            }
        }
        ("GET", true) => list(&st, &query),
        ("PUT", false) => match (query.get("partNumber"), query.get("uploadId")) {
            (Some(n), Some(id)) => {
                let n: u32 = n.parse().unwrap();
                if st.deny_part == Some(n) {
                    error(403, "AccessDenied")
                } else if let Some(parts) = st.uploads.get_mut(id) {
                    parts.insert(n, body.clone());
                    let mut r = reply(200, "");
                    r.headers_mut().insert(
                        "etag",
                        format!("\"part-{n}-{}\"", body.len()).parse().unwrap(),
                    );
                    r
                } else {
                    error(404, "NoSuchUpload")
                }
            }
            _ => {
                st.counter += 1;
                let etag = format!("\"obj-{}\"", st.counter);
                st.objects.insert(key, (body, etag.clone()));
                let mut r = reply(200, "");
                r.headers_mut().insert("etag", etag.parse().unwrap());
                r
            }
        },
        ("POST", false) if query.contains_key("uploads") => {
            st.counter += 1;
            let id = format!("upload-{}", st.counter);
            st.uploads.insert(id.clone(), BTreeMap::new());
            reply(
                200,
                format!(
                    "<InitiateMultipartUploadResult><Bucket>{BUCKET}</Bucket><Key>{key}</Key>\
                     <UploadId>{id}</UploadId></InitiateMultipartUploadResult>"
                ),
            )
        }
        ("POST", false) if query.contains_key("uploadId") => {
            complete(&mut st, &key, &query["uploadId"], &body)
        }
        ("DELETE", false) if query.contains_key("uploadId") => {
            st.uploads.remove(&query["uploadId"]);
            reply(204, "")
        }
        ("DELETE", false) => {
            st.objects.remove(&key);
            reply(204, "")
        }
        ("HEAD", false) => match st.objects.get(&key) {
            Some((data, etag)) => {
                let mut r = reply(200, "");
                r.headers_mut()
                    .insert("content-length", data.len().to_string().parse().unwrap());
                r.headers_mut().insert("etag", etag.parse().unwrap());
                r
            }
            None => reply(404, ""),
        },
        ("GET", false) => get(&st, &key, &parts),
        _ => error(405, "MethodNotAllowed"),
    };
    Ok(resp)
}

fn get(st: &State, key: &str, parts: &Parts) -> Response<Full<Bytes>> {
    let Some((data, etag)) = st.objects.get(key) else {
        return error(404, "NoSuchKey");
    };
    if let Some(m) = parts.headers.get("if-match")
        && m.to_str().unwrap() != etag
    {
        return error(412, "PreconditionFailed");
    }
    match parts.headers.get("range").and_then(|r| r.to_str().ok()) {
        Some(range) => {
            let (a, b) = range
                .strip_prefix("bytes=")
                .and_then(|r| r.split_once('-'))
                .unwrap();
            let a: usize = a.parse().unwrap();
            let b: usize = b.parse::<usize>().unwrap().min(data.len() - 1);
            reply(206, data.slice(a..=b))
        }
        None => reply(200, data.clone()),
    }
}

fn complete(st: &mut State, key: &str, id: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let Some(parts) = st.uploads.get(id) else {
        return error(404, "NoSuchUpload");
    };
    let body = std::str::from_utf8(body).unwrap();
    let mut data = Vec::new();
    let listed: Vec<&str> = body.split("<Part>").skip(1).collect();
    for (i, part) in listed.iter().enumerate() {
        let n: u32 = part
            .split("<PartNumber>")
            .nth(1)
            .and_then(|s| s.split("</PartNumber>").next())
            .unwrap()
            .parse()
            .unwrap();
        let etag = part
            .split("<ETag>")
            .nth(1)
            .and_then(|s| s.split("</ETag>").next())
            .unwrap()
            .replace("&quot;", "\"");
        let Some(bytes) = parts.get(&n) else {
            return error(400, "InvalidPart");
        };
        if etag != format!("\"part-{n}-{}\"", bytes.len()) {
            return error(400, "InvalidPart");
        }
        if i + 1 < listed.len() && bytes.len() < 5 << 20 {
            return error(400, "EntityTooSmall");
        }
        if u32::try_from(i + 1).unwrap() != n {
            return error(400, "InvalidPartOrder");
        }
        data.extend_from_slice(bytes);
    }
    st.uploads.remove(id);
    st.counter += 1;
    let etag = format!("\"mp-{}\"", st.counter);
    st.objects.insert(key.to_owned(), (Bytes::from(data), etag));
    if st.lose_complete {
        st.lose_complete = false;
        return error(500, "InternalError");
    }
    reply(
        200,
        format!("<CompleteMultipartUploadResult><Key>{key}</Key></CompleteMultipartUploadResult>"),
    )
}

fn list(st: &State, query: &BTreeMap<String, String>) -> Response<Full<Bytes>> {
    if query.get("list-type").map(String::as_str) != Some("2") {
        return error(400, "InvalidArgument");
    }
    let prefix = query.get("prefix").cloned().unwrap_or_default();
    let delimiter = query.get("delimiter").cloned();
    let after = query.get("continuation-token").map(|t| {
        t.strip_prefix("tok/")
            .unwrap()
            .strip_suffix("+=")
            .unwrap()
            .to_owned()
    });
    // Entries in key order: (name, is_prefix).
    let mut entries: Vec<(String, bool)> = Vec::new();
    for key in st.objects.keys().filter(|k| k.starts_with(&prefix)) {
        let rest = &key[prefix.len()..];
        match delimiter.as_deref().and_then(|d| rest.find(d)) {
            Some(i) => {
                let p = format!("{prefix}{}/", &rest[..i]);
                if entries.last().map(|(n, _)| n) != Some(&p) {
                    entries.push((p, true));
                }
            }
            None => entries.push((key.clone(), false)),
        }
    }
    let start = after.as_ref().map_or(0, |a| {
        entries
            .iter()
            .position(|(n, _)| n > a)
            .unwrap_or(entries.len())
    });
    let page: Vec<&(String, bool)> = entries.iter().skip(start).take(st.page_size).collect();
    let truncated = start + page.len() < entries.len();
    let mut xml = String::from("<ListBucketResult>");
    for (name, is_prefix) in &page {
        let name = name.replace('&', "&amp;");
        if *is_prefix {
            xml.push_str(&format!(
                "<CommonPrefixes><Prefix>{name}</Prefix></CommonPrefixes>"
            ));
        } else {
            xml.push_str(&format!(
                "<Contents><Key>{name}</Key><Size>0</Size></Contents>"
            ));
        }
    }
    xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    if truncated && let Some((last, _)) = page.last() {
        xml.push_str(&format!(
            "<NextContinuationToken>tok/{last}+=</NextContinuationToken>"
        ));
    }
    xml.push_str("</ListBucketResult>");
    reply(200, xml)
}
