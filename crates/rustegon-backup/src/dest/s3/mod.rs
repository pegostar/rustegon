// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! S3-compatible destination (FR-BKP-006, PD-065 option b, PD-086, TC-BKP-006): AWS S3, `MinIO`,
//! Ceph RGW and other stores speaking the S3 REST API with Signature Version 4.
//!
//! # Why a hand-written client (PD-065)
//! `object_store`'s `aws` feature pulls `aws-lc-rs`/`aws-lc-sys` (banned in `deny.toml`), so the
//! client is a small `SigV4` implementation (`sigv4`) over HTTP/1.1 from `hyper`, connections
//! from the sim-api [`Network`], and TLS from `rustls` with the `ring` provider configured like
//! every other Rustegon TLS client ([`rustegon_net::crypto_provider`]).
//!
//! # Driving async I/O from the synchronous trait
//! [`Destination`] is blocking and runs on the I/O / blocking pool (coding-standards.md §3.3).
//! Each destination owns a small private Tokio runtime (2 workers): a call spawns its future on
//! that runtime and waits for the result on a `std::sync::mpsc` channel. Unlike
//! `Handle::block_on` this never panics when the calling thread belongs to another runtime's
//! blocking pool, and the sockets are always driven by the runtime that created them. The runtime
//! is shut down with `shutdown_background` when the destination and every reader opened from it
//! are gone, which is legal from any thread. Calling a destination from an async worker thread
//! would block that worker: callers must use `spawn_blocking`, as for every `Destination`.
//!
//! # Atomicity (same contract as [`super::local::LocalDestination`])
//! - Objects up to the part size are one `PUT`; larger ones a multipart upload (initiate, parts,
//!   complete). S3 makes an object visible only when the `PUT` or `CompleteMultipartUpload`
//!   succeeds, so a reader never sees a partial object and `COMPLETE`, written last by the
//!   writer, stays the commit point of a backup.
//! - A failed multipart upload is aborted (best effort); an upload left behind by a crash is
//!   invisible to listings and reclaimed by a bucket lifecycle rule
//!   (`AbortIncompleteMultipartUpload`, backup-restore.md).
//! - A source that yields fewer or more bytes than declared stores nothing.
//! - Every request carries the SHA-256 of its body in the signature (`x-amz-content-sha256`), so
//!   the store rejects a body corrupted in transit.
//! - Ranged reads send `If-Match` with the `ETag` seen when the object was opened: an object
//!   replaced while it is read fails instead of mixing two versions.
//!
//! # Retries and timeouts
//! Connection errors, timeouts, HTTP 500/502/503/504, 429, `SlowDown` and `RequestTimeout` are
//! retried up to `max_attempts` with exponential backoff (200 ms doubling, capped at 10 s,
//! jittered). Every request body is held in memory (at most one part), so a retry resends exactly
//! the same bytes; the caller's reader is consumed once. A `CompleteMultipartUpload` whose first
//! attempt succeeded but whose answer was lost sees `NoSuchUpload` on the retry; the object is
//! then checked with `HEAD` and accepted when its size matches.
//!
//! # Errors (PD-064)
//! Transport failures and HTTP errors are [`BackupError::Destination`] (`RGN-3002`), with the
//! S3 error code and message in the text; 403 is reported as permission denied and 507
//! (`MinIO` "storage full") as disk full (`RGN-5003`). A missing object is
//! [`BackupError::ObjectNotFound`] (`RGN-1030`). Requests, headers and credentials are never
//! logged or put into messages.

pub mod settings;
pub(crate) mod sigv4;
mod xml;

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use rustegon_net::{
    ClockTimeProvider, TlsMinVersion, TrustAnchors,
    rustls::{
        self, ClientConfig, RootCertStore, client::WebPkiServerVerifier, pki_types::ServerName,
    },
    tokio_rustls::TlsConnector,
};
use rustegon_sim_api::{Clock, Connection, FileSystem, Network, Rng};
pub use settings::{S3Credentials, S3Settings};

use super::{Destination, ObjectReader, join_key, validate_key};
use crate::{
    error::{BackupError, Result},
    id::UtcTime,
};

/// Read-ahead of ranged reads: callers read 1 MiB at a time ([`super::CHUNK_BYTES`]); fetching
/// 8 MiB per GET divides the request count by eight at a bounded memory cost per open object.
const READ_AHEAD: u64 = 8 << 20;
/// Most parts of one multipart upload (S3 limit).
const MAX_PARTS: u64 = 10_000;
/// Body limit of responses that are not object data (listings, errors, multipart replies).
const MAX_META_BODY: usize = 16 << 20;
/// Idle connections kept for reuse.
const MAX_IDLE: usize = 4;
/// First retry delay; doubled per attempt.
const BACKOFF_BASE: Duration = Duration::from_millis(200);
/// Longest retry delay.
const BACKOFF_CAP: Duration = Duration::from_secs(10);
/// Keys per listing page (S3 maximum).
const LIST_PAGE: &str = "1000";

/// Where an `s3://` URL points (from [`crate::DestinationUrl::S3`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Location {
    /// Bucket name.
    pub bucket: String,
    /// Key prefix inside the bucket, without leading or trailing `/` (may be empty).
    pub prefix: String,
    /// `region=` of the URL, overriding the settings.
    pub region: Option<String>,
    /// `endpoint=` of the URL, overriding the settings.
    pub endpoint: Option<String>,
}

/// Injected I/O (ADR-029): file system for the credentials and CA files, network, clock (request
/// time, timeouts, backoff) and randomness (backoff jitter).
#[derive(Clone)]
pub struct S3Io {
    /// Reads `credentials_file` and `ca_file`.
    pub fs: Arc<dyn FileSystem>,
    /// Opens TCP connections.
    pub network: Arc<dyn Network>,
    /// Signing time, timeouts and backoff sleeps.
    pub clock: Arc<dyn Clock>,
    /// Backoff jitter.
    pub rng: Arc<dyn Rng>,
}

impl S3Io {
    /// Production I/O: OS network, clock and CSPRNG with the given file system.
    #[must_use]
    pub fn production(fs: Arc<dyn FileSystem>) -> Self {
        Self {
            fs,
            network: Arc::new(rustegon_sim_api::TokioNetwork),
            clock: Arc::new(rustegon_sim_api::SystemClock::new()),
            rng: Arc::new(rustegon_sim_api::OsRng),
        }
    }
}

/// Reads an environment variable of the process (production `env` for [`S3Destination::open`]).
#[must_use]
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The endpoint requests go to.
#[derive(Debug, Clone)]
struct Endpoint {
    https: bool,
    /// Host to connect to (DNS name or IP literal without brackets).
    host: String,
    port: u16,
    /// `Host` header (signed): `host[:port]`, IPv6 in brackets, default port omitted.
    host_header: String,
    /// Path-style (`/bucket/key`) or virtual-hosted (`bucket.` prefixed host, `/key`).
    path_style: bool,
}

impl Endpoint {
    /// Parses `http(s)://host[:port][/]` and applies the addressing style for `bucket`.
    fn new(url: &str, bucket: &str, force_path_style: Option<bool>, custom: bool) -> Result<Self> {
        let invalid = |why: &str| {
            Err(BackupError::InvalidArgument(format!(
                "S3 endpoint {url:?}: {why}"
            )))
        };
        let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return invalid("must start with http:// or https://");
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
            return invalid("must be scheme://host[:port] without path, query or credentials");
        }
        let default_port = if https { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let Some((h, after)) = v6.split_once(']') else {
                return invalid("unterminated IPv6 address");
            };
            match after.strip_prefix(':') {
                Some(p) => (h, p.parse::<u16>().ok()),
                None if after.is_empty() => (h, Some(default_port)),
                None => return invalid("bad port"),
            }
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().ok()),
                None => (authority, Some(default_port)),
            }
        };
        let Some(port) = port.filter(|p| *p != 0) else {
            return invalid("bad port");
        };
        if host.is_empty() {
            return invalid("missing host");
        }
        let ip = host.parse::<IpAddr>().is_ok();
        // Virtual-hosted addressing needs a DNS name, and a bucket with dots would not match
        // the endpoint's wildcard certificate (`*.s3.amazonaws.com` covers one label only).
        let path_style = ip || force_path_style.unwrap_or(custom || bucket.contains('.'));
        let host = if path_style {
            host.to_owned()
        } else {
            format!("{bucket}.{host}")
        };
        let bracketed = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let host_header = if port == default_port {
            bracketed
        } else {
            format!("{bracketed}:{port}")
        };
        Ok(Self {
            https,
            host,
            port,
            host_header,
            path_style,
        })
    }
}

/// One request to the bucket.
struct S3Request {
    method: Method,
    /// Full object key (prefix included), or `None` for a bucket-level request.
    key: Option<String>,
    query: Vec<(String, String)>,
    /// Extra signed headers (`range`, `if-match`, `content-type`).
    headers: Vec<(String, String)>,
    body: Bytes,
    /// Largest accepted response body.
    max_body: usize,
}

impl S3Request {
    fn new(method: Method, key: Option<String>) -> Self {
        Self {
            method,
            key,
            query: Vec::new(),
            headers: Vec::new(),
            body: Bytes::new(),
            max_body: MAX_META_BODY,
        }
    }

    fn query(mut self, name: &str, value: &str) -> Self {
        self.query.push((name.to_owned(), value.to_owned()));
        self
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn body(mut self, body: Bytes) -> Self {
        self.body = body;
        self
    }
}

/// A complete response.
struct S3Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl S3Response {
    /// `<Code>` of an S3 error body, if any.
    fn error_code(&self) -> Option<String> {
        std::str::from_utf8(&self.body)
            .ok()
            .and_then(|b| xml::first_text(b, "Code"))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn content_length(&self) -> Option<u64> {
        self.header("content-length").and_then(|v| v.parse().ok())
    }
}

/// Owner of the private runtime; dropped last (after every reader), on a caller thread.
struct RuntimeOwner(Option<tokio::runtime::Runtime>);

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            // Never blocks, so it is legal from any context (a plain drop would panic inside
            // an async context).
            rt.shutdown_background();
        }
    }
}

/// State shared by the destination, its readers and the futures on the runtime.
struct Client {
    handle: tokio::runtime::Handle,
    endpoint: Endpoint,
    bucket: String,
    region: String,
    credentials: S3Credentials,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    io: S3Io,
    idle: Mutex<Vec<SendRequest<Full<Bytes>>>>,
    max_attempts: u32,
    connect_timeout: Duration,
    request_timeout: Duration,
    describe: String,
}

impl Client {
    /// Runs `fut` on the private runtime and waits for it (module docs).
    fn run<T: Send + 'static>(&self, fut: impl Future<Output = T> + Send + 'static) -> Result<T> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.handle.spawn(async move {
            // The receiver only disappears if the caller is gone; nothing to report then.
            let _ = tx.send(fut.await);
        });
        rx.recv()
            .map_err(|_| BackupError::Internal("the S3 client runtime stopped".into()))
    }

    fn destination_error(&self, op: &'static str, key: &str, source: io::Error) -> BackupError {
        BackupError::Destination {
            destination: self.describe.clone(),
            op,
            key: key.to_owned(),
            source,
        }
    }

    /// Error for an unexpected HTTP status; the S3 code and message are included (they never
    /// contain credentials), the request is not.
    fn status_error(&self, op: &'static str, key: &str, resp: &S3Response) -> BackupError {
        let body = std::str::from_utf8(&resp.body).unwrap_or("");
        let code = xml::first_text(body, "Code").unwrap_or_default();
        let mut message = xml::first_text(body, "Message").unwrap_or_default();
        message.truncate(message.floor_char_boundary(200));
        let kind = match resp.status.as_u16() {
            401 | 403 => io::ErrorKind::PermissionDenied,
            404 => io::ErrorKind::NotFound,
            400 | 405 | 411 | 412 | 416 => io::ErrorKind::InvalidInput,
            507 => io::ErrorKind::StorageFull,
            _ => io::ErrorKind::Other,
        };
        let text = match (code.is_empty(), message.is_empty()) {
            (true, _) => format!("HTTP {}", resp.status),
            (false, true) => format!("HTTP {}: {code}", resp.status),
            (false, false) => format!("HTTP {}: {code}: {message}", resp.status),
        };
        self.destination_error(op, key, io::Error::new(kind, text))
    }

    /// URI path of a request (encoded once, see `sigv4`).
    fn path(&self, key: Option<&str>) -> String {
        let raw = match (self.endpoint.path_style, key) {
            (true, Some(k)) => format!("/{}/{k}", self.bucket),
            (true, None) => format!("/{}", self.bucket),
            (false, Some(k)) => format!("/{k}"),
            (false, None) => "/".to_owned(),
        };
        sigv4::uri_encode_path(&raw)
    }

    /// Builds and signs one attempt of `req` (signed per attempt: the time is part of it).
    fn build(&self, req: &S3Request) -> io::Result<http::Request<Full<Bytes>>> {
        let path = self.path(req.key.as_deref());
        let query = sigv4::canonical_query(&req.query);
        let uri = if query.is_empty() {
            path.clone()
        } else {
            format!("{path}?{query}")
        };
        let amz_date = UtcTime::from_system_time(self.io.clock.wall())
            .map_err(|e| io::Error::other(e.to_string()))?
            .compact();
        let payload = sigv4::sha256_hex(&req.body);
        let mut signed = vec![
            ("host".to_owned(), self.endpoint.host_header.clone()),
            ("x-amz-date".to_owned(), amz_date.clone()),
            ("x-amz-content-sha256".to_owned(), payload.clone()),
        ];
        if let Some(token) = &self.credentials.session_token {
            signed.push((
                "x-amz-security-token".to_owned(),
                token.expose().as_str().to_owned(),
            ));
        }
        signed.extend(req.headers.iter().cloned());
        let authorization = sigv4::authorization(
            &sigv4::SigningCredentials {
                access_key_id: &self.credentials.access_key_id,
                secret_access_key: self.credentials.secret_access_key.expose().as_str(),
            },
            &sigv4::SigningScope {
                amz_date: &amz_date,
                region: &self.region,
                service: "s3",
            },
            &sigv4::SigningRequest {
                method: req.method.as_str(),
                canonical_uri: &path,
                query: &req.query,
                headers: &signed,
                payload_sha256: &payload,
            },
        );
        let mut builder = http::Request::builder()
            .method(req.method.clone())
            .uri(uri)
            .header("authorization", authorization)
            .header(
                "user-agent",
                concat!("rustegon/", env!("CARGO_PKG_VERSION")),
            );
        for (name, value) in &signed {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if matches!(req.method, Method::PUT | Method::POST) {
            builder = builder.header("content-length", req.body.len().to_string());
        }
        builder
            .body(Full::new(req.body.clone()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
    }

    /// A ready connection: an idle one if still usable (`true`), else a new one (`false`).
    async fn checkout(&self) -> io::Result<(SendRequest<Full<Bytes>>, bool)> {
        loop {
            let idle = self
                .idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop();
            let Some(mut sender) = idle else {
                break;
            };
            if !sender.is_closed() && sender.ready().await.is_ok() {
                return Ok((sender, true));
            }
        }
        Ok((self.connect().await?, false))
    }

    fn checkin(&self, sender: SendRequest<Full<Bytes>>) {
        if sender.is_closed() {
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < MAX_IDLE {
            idle.push(sender);
        }
    }

    /// Resolves the endpoint host (IP literals directly, names through the system resolver).
    async fn resolve(&self) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = self.endpoint.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, self.endpoint.port)]);
        }
        let addrs: Vec<SocketAddr> =
            tokio::net::lookup_host((self.endpoint.host.as_str(), self.endpoint.port))
                .await?
                .collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: no address", self.endpoint.host),
            ));
        }
        Ok(addrs)
    }

    /// New connection: TCP through the sim-api network, TLS when https, HTTP/1.1 handshake.
    async fn connect(&self) -> io::Result<SendRequest<Full<Bytes>>> {
        let connect = async {
            let mut last = None;
            let mut stream = None;
            for addr in self.resolve().await? {
                match self.io.network.connect(addr).await {
                    Ok(s) => {
                        stream = Some(s);
                        break;
                    }
                    Err(e) => last = Some(e),
                }
            }
            let stream = match (stream, last) {
                (Some(s), _) => s,
                (None, Some(e)) => return Err(e),
                (None, None) => return Err(io::Error::other("no address to connect to")),
            };
            let io: Box<dyn Connection> = match &self.tls {
                Some((tls, name)) => Box::new(tls.connect(name.clone(), stream).await?),
                None => stream,
            };
            http1::handshake::<_, Full<Bytes>>(TokioIo::new(io))
                .await
                .map_err(io::Error::other)
        };
        let (sender, connection) = tokio::select! {
            r = connect => r?,
            () = self.io.clock.sleep(self.connect_timeout) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
            }
        };
        // The connection task ends when the server closes the connection or every sender is
        // dropped; its error, if any, is reported to the request that was in flight.
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(sender)
    }

    /// One attempt: connection, request, whole response body (bounded).
    async fn attempt(&self, req: &S3Request) -> io::Result<S3Response> {
        let (mut sender, reused) = self.checkout().await?;
        let response = match sender.send_request(self.build(req)?).await {
            Ok(r) => r,
            // A pooled connection the server closed while idle fails before the request was
            // processed: retry once on a fresh connection without spending a retry attempt.
            Err(e) if reused && (e.is_canceled() || e.is_incomplete_message()) => {
                sender = self.connect().await?;
                sender
                    .send_request(self.build(req)?)
                    .await
                    .map_err(io::Error::other)?
            }
            Err(e) => return Err(io::Error::other(e)),
        };
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, req.max_body)
            .collect()
            .await
            .map_err(io::Error::other)?
            .to_bytes();
        self.checkin(sender);
        Ok(S3Response {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }

    /// Whether a response is a transient failure worth retrying.
    fn transient(resp: &S3Response) -> bool {
        match resp.status.as_u16() {
            429 | 500 | 502 | 503 | 504 => true,
            400 => resp.error_code().as_deref() == Some("RequestTimeout"),
            _ => false,
        }
    }

    /// Backoff before attempt `attempt + 1`: exponential with "equal jitter" (half fixed, half
    /// random) so that concurrent clients spread out without ever retrying immediately.
    fn backoff(&self, attempt: u32) -> Duration {
        let exp = BACKOFF_BASE.saturating_mul(1 << attempt.min(16).saturating_sub(1));
        let ceiling = exp.min(BACKOFF_CAP);
        let half = ceiling / 2;
        let half_ms = u64::try_from(half.as_millis()).unwrap_or(u64::MAX).max(1);
        half + Duration::from_millis(self.io.rng.next_u64() % half_ms)
    }

    /// Sends `req` with retries (module docs). Returns the last response for a final HTTP
    /// status (including a transient one after the last attempt), or the last transport error.
    async fn execute(&self, req: S3Request) -> io::Result<S3Response> {
        let mut attempt = 1;
        loop {
            let result = tokio::select! {
                r = self.attempt(&req) => r,
                () = self.io.clock.sleep(self.request_timeout) => {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "request timed out"))
                }
            };
            let retry = match &result {
                Ok(resp) => Self::transient(resp),
                Err(_) => true,
            };
            if !retry || attempt >= self.max_attempts {
                return result;
            }
            let delay = self.backoff(attempt);
            match &result {
                Ok(resp) => tracing::debug!(
                    destination = %self.describe,
                    method = %req.method,
                    status = resp.status.as_u16(),
                    attempt,
                    ?delay,
                    "S3 request failed transiently, retrying"
                ),
                Err(e) => tracing::debug!(
                    destination = %self.describe,
                    method = %req.method,
                    error = %e,
                    attempt,
                    ?delay,
                    "S3 request failed, retrying"
                ),
            }
            self.io.clock.sleep(delay).await;
            attempt += 1;
        }
    }

    /// [`Self::execute`] from a synchronous caller.
    fn call(self: &Arc<Self>, op: &'static str, key: &str, req: S3Request) -> Result<S3Response> {
        let client = Arc::clone(self);
        self.run(async move { client.execute(req).await })?
            .map_err(|e| self.destination_error(op, key, e))
    }
}

/// An S3-compatible destination (module docs).
pub struct S3Destination {
    client: Arc<Client>,
    runtime: Arc<RuntimeOwner>,
    prefix: String,
    part_size: u64,
}

impl std::fmt::Debug for S3Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Destination")
            .field("destination", &self.client.describe)
            .field("endpoint", &self.client.endpoint.host_header)
            .field("region", &self.client.region)
            .finish_non_exhaustive()
    }
}

impl S3Destination {
    /// Opens the destination: resolves region, endpoint and credentials (settings, URL and
    /// `env`, see [`S3Settings`]), builds the TLS configuration and starts the private runtime.
    /// No request is sent.
    ///
    /// # Errors
    /// [`BackupError::InvalidArgument`] for invalid settings, endpoint, CA file or missing
    /// credentials; [`BackupError::Local`] when the credentials file cannot be read;
    /// [`BackupError::Internal`] when the runtime cannot start.
    pub fn open(
        location: &S3Location,
        settings: &S3Settings,
        io: S3Io,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        settings.validate()?;
        let get = |name: &str| env(name).filter(|v| !v.is_empty());
        let region = location
            .region
            .clone()
            .or_else(|| settings.region.clone())
            .or_else(|| get("AWS_REGION"))
            .or_else(|| get("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|| "us-east-1".to_owned());
        let custom = location
            .endpoint
            .clone()
            .or_else(|| settings.endpoint.clone())
            .or_else(|| get("AWS_ENDPOINT_URL_S3"))
            .or_else(|| get("AWS_ENDPOINT_URL"));
        let endpoint_url = custom
            .clone()
            .unwrap_or_else(|| format!("https://s3.{region}.amazonaws.com"));
        let endpoint = Endpoint::new(
            &endpoint_url,
            &location.bucket,
            settings.force_path_style,
            custom.is_some(),
        )?;
        let credentials = S3Credentials::resolve(settings, io.fs.as_ref(), env)?;
        let tls = if endpoint.https {
            let config = tls_config(settings, &io)?;
            let name = ServerName::try_from(endpoint.host.clone()).map_err(|_| {
                BackupError::InvalidArgument(format!(
                    "S3 endpoint host {:?} is not a valid TLS server name",
                    endpoint.host
                ))
            })?;
            Some((TlsConnector::from(Arc::new(config)), name))
        } else {
            tracing::warn!(
                endpoint = %endpoint_url,
                "S3 destination uses plain HTTP: backups and credentials signatures travel \
                 unencrypted"
            );
            None
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rustegon-s3")
            .enable_io()
            .enable_time()
            .build()
            .map_err(|e| BackupError::Internal(format!("S3 client runtime: {e}")))?;
        let describe = if location.prefix.is_empty() {
            format!("s3://{}", location.bucket)
        } else {
            format!("s3://{}/{}", location.bucket, location.prefix)
        };
        let client = Client {
            handle: runtime.handle().clone(),
            endpoint,
            bucket: location.bucket.clone(),
            region,
            credentials,
            tls,
            io,
            idle: Mutex::new(Vec::new()),
            max_attempts: settings.max_attempts,
            connect_timeout: Duration::from_secs(settings.connect_timeout_secs),
            request_timeout: Duration::from_secs(settings.request_timeout_secs),
            describe,
        };
        Ok(Self {
            client: Arc::new(client),
            runtime: Arc::new(RuntimeOwner(Some(runtime))),
            prefix: location.prefix.clone(),
            part_size: u64::from(settings.part_size_mib) << 20,
        })
    }

    /// Full object key of a destination key or prefix (`""` = the root prefix).
    fn full_key(&self, key: &str) -> String {
        join_key(&[&self.prefix, key])
    }

    /// Creates the bucket if it does not exist yet (tests and first-time setup; a production
    /// bucket is normally created by the operator with its own policies).
    ///
    /// # Errors
    /// [`BackupError::Destination`] when the bucket cannot be created.
    pub fn create_bucket(&self) -> Result<()> {
        let mut req = S3Request::new(Method::PUT, None);
        if self.client.region != "us-east-1" {
            req = req.body(Bytes::from(format!(
                "<CreateBucketConfiguration><LocationConstraint>{}</LocationConstraint>\
                 </CreateBucketConfiguration>",
                xml::escape(&self.client.region)
            )));
        }
        let resp = self.client.call("create bucket", "", req)?;
        match (resp.status.as_u16(), resp.error_code().as_deref()) {
            (200, _) | (409, Some("BucketAlreadyOwnedByYou")) => Ok(()),
            _ => Err(self.client.status_error("create bucket", "", &resp)),
        }
    }

    /// `HEAD` of a full key: `Some((size, etag))`, `None` when missing.
    fn head(&self, key: &str) -> Result<Option<(u64, Option<String>)>> {
        let resp = self.client.call(
            "head",
            key,
            S3Request::new(Method::HEAD, Some(self.full_key(key))),
        )?;
        match resp.status.as_u16() {
            200 => {
                let size = resp.content_length().ok_or_else(|| {
                    self.client.destination_error(
                        "head",
                        key,
                        io::Error::new(io::ErrorKind::InvalidData, "HEAD without Content-Length"),
                    )
                })?;
                Ok(Some((size, resp.header("etag").map(str::to_owned))))
            }
            404 => Ok(None),
            _ => Err(self.client.status_error("head", key, &resp)),
        }
    }

    /// Reads exactly `len` bytes of `reader` into a buffer, then checks for (and reports)
    /// excess input when `last` is set.
    fn read_part(
        &self,
        key: &str,
        reader: &mut dyn io::Read,
        len: u64,
        last: bool,
    ) -> Result<Bytes> {
        let err = |e: io::Error| self.client.destination_error("put", key, e);
        let len = usize::try_from(len).map_err(|_| {
            err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "part too large",
            ))
        })?;
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "source yielded fewer bytes than declared",
                ))
            } else {
                err(e)
            }
        })?;
        if last {
            let mut probe = [0u8; 1];
            if reader.read(&mut probe).map_err(err)? != 0 {
                return Err(err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "source yielded more bytes than declared",
                )));
            }
        }
        Ok(Bytes::from(buf))
    }

    /// Single `PUT`.
    fn put_single(&self, key: &str, body: Bytes) -> Result<()> {
        let req = S3Request::new(Method::PUT, Some(self.full_key(key))).body(body);
        let resp = self.client.call("put", key, req)?;
        if resp.status.is_success() {
            Ok(())
        } else {
            Err(self.client.status_error("put", key, &resp))
        }
    }

    /// Part size for an object of `size` bytes: the configured size, raised (in MiB steps) when
    /// the object would need more than 10 000 parts.
    fn part_size_for(&self, size: u64) -> u64 {
        let needed = size.div_ceil(MAX_PARTS);
        let mib = 1u64 << 20;
        self.part_size.max(needed.div_ceil(mib) * mib)
    }

    /// Multipart upload: initiate, parts, complete; aborted on any failure.
    fn put_multipart(&self, key: &str, size: u64, reader: &mut dyn io::Read) -> Result<()> {
        let full = self.full_key(key);
        let resp = self.client.call(
            "put",
            key,
            S3Request::new(Method::POST, Some(full.clone())).query("uploads", ""),
        )?;
        if !resp.status.is_success() {
            return Err(self.client.status_error("put", key, &resp));
        }
        let upload_id = std::str::from_utf8(&resp.body)
            .ok()
            .and_then(|b| xml::first_text(b, "UploadId"))
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                self.client.destination_error(
                    "put",
                    key,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "multipart upload without UploadId",
                    ),
                )
            })?;
        let result = self.upload_parts(key, &full, &upload_id, size, reader);
        if result.is_err() {
            // Best effort: the upload is invisible either way, and a lifecycle rule reclaims it
            // if this request fails too.
            let abort = S3Request::new(Method::DELETE, Some(full)).query("uploadId", &upload_id);
            if let Err(e) = self.client.call("abort multipart upload", key, abort) {
                tracing::warn!(destination = %self.client.describe, key, error = %e,
                    "aborting a failed multipart upload failed");
            }
        }
        result
    }

    fn upload_parts(
        &self,
        key: &str,
        full: &str,
        upload_id: &str,
        size: u64,
        reader: &mut dyn io::Read,
    ) -> Result<()> {
        let part_size = self.part_size_for(size);
        let mut parts: Vec<(u32, String)> = Vec::new();
        let mut offset = 0;
        let mut number = 0u32;
        while offset < size {
            number += 1;
            let len = part_size.min(size - offset);
            let last = offset + len == size;
            let body = self.read_part(key, reader, len, last)?;
            let req = S3Request::new(Method::PUT, Some(full.to_owned()))
                .query("partNumber", &number.to_string())
                .query("uploadId", upload_id)
                .body(body);
            let resp = self.client.call("put part", key, req)?;
            if !resp.status.is_success() {
                return Err(self.client.status_error("put part", key, &resp));
            }
            let etag = resp.header("etag").map(str::to_owned).ok_or_else(|| {
                self.client.destination_error(
                    "put part",
                    key,
                    io::Error::new(io::ErrorKind::InvalidData, "part upload without ETag"),
                )
            })?;
            parts.push((number, etag));
            offset += len;
        }
        let body = Bytes::from(xml::complete_multipart_body(&parts));
        let req = S3Request::new(Method::POST, Some(full.to_owned()))
            .query("uploadId", upload_id)
            .header("content-type", "application/xml")
            .body(body);
        let resp = self.client.call("complete multipart upload", key, req)?;
        // S3 may answer 200 and still report an error in the body (the status line is sent
        // before the parts are combined).
        let failed_in_body =
            std::str::from_utf8(&resp.body).is_ok_and(|b| !xml::elements(b, "Error").is_empty());
        if resp.status.is_success() && !failed_in_body {
            return Ok(());
        }
        if resp.status == StatusCode::NOT_FOUND
            && resp.error_code().as_deref() == Some("NoSuchUpload")
            && self.head(key)?.is_some_and(|(s, _)| s == size)
        {
            // A retried complete whose first attempt succeeded (module docs).
            return Ok(());
        }
        Err(self
            .client
            .status_error("complete multipart upload", key, &resp))
    }

    /// One `ListObjectsV2` walk below `prefix` (full, with trailing `/` or empty).
    fn list_raw(&self, op_key: &str, prefix: &str, delimiter: bool) -> Result<xml::ListPage> {
        let mut all = xml::ListPage::default();
        let mut token: Option<String> = None;
        loop {
            let mut req = S3Request::new(Method::GET, None)
                .query("list-type", "2")
                .query("max-keys", LIST_PAGE)
                .query("prefix", prefix);
            if delimiter {
                req = req.query("delimiter", "/");
            }
            if let Some(t) = &token {
                req = req.query("continuation-token", t);
            }
            let resp = self.client.call("list", op_key, req)?;
            if !resp.status.is_success() {
                return Err(self.client.status_error("list", op_key, &resp));
            }
            let body = std::str::from_utf8(&resp.body).map_err(|_| {
                self.client.destination_error(
                    "list",
                    op_key,
                    io::Error::new(io::ErrorKind::InvalidData, "listing is not UTF-8"),
                )
            })?;
            let page = xml::parse_list(body);
            all.keys.extend(page.keys);
            all.common_prefixes.extend(page.common_prefixes);
            match page.next_token {
                Some(t) if Some(&t) != token.as_ref() => token = Some(t),
                // Truncated without a new token would loop forever; the store is broken.
                Some(_) => {
                    return Err(self.client.destination_error(
                        "list",
                        op_key,
                        io::Error::new(io::ErrorKind::InvalidData, "listing token did not advance"),
                    ));
                }
                None => return Ok(all),
            }
        }
    }

    /// Full listing prefix of a destination prefix: `<root>/<prefix>/`, or `""` for the root of
    /// an unprefixed destination.
    fn list_prefix(&self, prefix: &str) -> Result<String> {
        if !prefix.is_empty() {
            validate_key(prefix)?;
        }
        let full = self.full_key(prefix);
        Ok(if full.is_empty() {
            full
        } else {
            format!("{full}/")
        })
    }
}

/// TLS client configuration: the Rustegon `ring` provider, TLS 1.2 minimum (S3-compatible
/// appliances still exist that stop at 1.2; the suites are AEAD + ECDHE only either way), and
/// either the configured CA bundle or the operating-system roots.
fn tls_config(settings: &S3Settings, io: &S3Io) -> Result<ClientConfig> {
    let roots: Arc<RootCertStore> = if let Some(ca) = &settings.ca_file {
        TrustAnchors::load(io.fs.as_ref(), ca)
            .map_err(|e| BackupError::InvalidArgument(format!("backup.s3.ca_file: {e}")))?
            .roots()
    } else {
        // The platform store is read directly (not through the sim-api FileSystem): it is the
        // operating system's configuration, not Rustegon data, and has no simulated equivalent.
        let native = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(native.certs);
        if added == 0 {
            return Err(BackupError::InvalidArgument(
                "no trusted root certificates found in the operating-system store; set \
                 backup.s3.ca_file"
                    .into(),
            ));
        }
        Arc::new(roots)
    };
    let provider = rustegon_net::crypto_provider();
    let tls_err = |e: rustls::Error| BackupError::Internal(format!("S3 TLS configuration: {e}"));
    let verifier = WebPkiServerVerifier::builder_with_provider(roots, Arc::clone(&provider))
        .build()
        .map_err(|e| BackupError::InvalidArgument(format!("S3 TLS trust anchors: {e}")))?;
    let mut config = ClientConfig::builder_with_details(
        provider,
        Arc::new(ClockTimeProvider::new(Arc::clone(&io.clock))),
    )
    .with_protocol_versions(TlsMinVersion::Tls12.protocol_versions())
    .map_err(tls_err)?
    .with_webpki_verifier(verifier)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

impl Drop for S3Destination {
    fn drop(&mut self) {
        // Idle connections hold tasks on the runtime; dropping them first lets the runtime
        // shut down without stray I/O.
        self.client
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

impl Destination for S3Destination {
    fn describe(&self) -> String {
        self.client.describe.clone()
    }

    fn put_reader(&self, key: &str, size: u64, reader: &mut dyn io::Read) -> Result<()> {
        validate_key(key)?;
        if size <= self.part_size {
            let body = self.read_part(key, reader, size, true)?;
            self.put_single(key, body)
        } else {
            self.put_multipart(key, size, reader)
        }
    }

    fn open(&self, key: &str) -> Result<Box<dyn ObjectReader>> {
        validate_key(key)?;
        let Some((size, etag)) = self.head(key)? else {
            return Err(BackupError::ObjectNotFound {
                key: key.to_owned(),
                destination: self.describe(),
            });
        };
        Ok(Box::new(S3Object {
            client: Arc::clone(&self.client),
            _runtime: Arc::clone(&self.runtime),
            key: key.to_owned(),
            full_key: self.full_key(key),
            size,
            etag,
            window: Mutex::new(None),
        }))
    }

    fn size(&self, key: &str) -> Result<Option<u64>> {
        validate_key(key)?;
        Ok(self.head(key)?.map(|(size, _)| size))
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let full = self.list_prefix(prefix)?;
        let root = self.list_prefix("")?;
        let page = self.list_raw(prefix, &full, false)?;
        let mut keys: Vec<String> = page
            .keys
            .into_iter()
            .filter_map(|k| {
                let rel = k.strip_prefix(&root)?;
                // Foreign objects outside the key alphabet are not ours (as for local).
                validate_key(rel).ok()?;
                Some(rel.to_owned())
            })
            .collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    fn list_children(&self, prefix: &str) -> Result<Vec<String>> {
        let full = self.list_prefix(prefix)?;
        let page = self.list_raw(prefix, &full, true)?;
        let mut names: Vec<String> = page
            .keys
            .iter()
            .chain(&page.common_prefixes)
            .filter_map(|k| {
                let name = k.strip_prefix(&full)?.trim_end_matches('/');
                (!name.contains('/') && validate_key(name).is_ok()).then(|| name.to_owned())
            })
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn delete(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        let resp = self.client.call(
            "delete",
            key,
            S3Request::new(Method::DELETE, Some(self.full_key(key))),
        )?;
        match resp.status.as_u16() {
            // Some S3-compatible stores answer 404 for a missing key; S3 itself answers 204.
            200 | 204 | 404 => Ok(()),
            _ => Err(self.client.status_error("delete", key, &resp)),
        }
    }
}

/// A ranged reader with a single read-ahead window.
struct S3Object {
    client: Arc<Client>,
    _runtime: Arc<RuntimeOwner>,
    key: String,
    full_key: String,
    size: u64,
    etag: Option<String>,
    /// Last fetched window: (offset, bytes).
    window: Mutex<Option<(u64, Bytes)>>,
}

impl S3Object {
    fn fetch(&self, start: u64, end: u64) -> Result<Bytes> {
        let len = usize::try_from(end - start).map_err(|_| {
            BackupError::InvalidArgument(format!("read window of {} too large", self.key))
        })?;
        let mut req = S3Request::new(Method::GET, Some(self.full_key.clone()))
            .header("range", &format!("bytes={start}-{}", end - 1));
        if let Some(etag) = &self.etag {
            req = req.header("if-match", etag);
        }
        // A server that ignores Range sends the whole object.
        req.max_body = usize::try_from(self.size).map_or(usize::MAX, |s| s.max(len));
        let resp = self.client.call("read", &self.key, req)?;
        let data = match resp.status.as_u16() {
            206 => resp.body,
            200 => {
                let s = usize::try_from(start).unwrap_or(usize::MAX);
                if resp.body.len() < s + len {
                    Bytes::new()
                } else {
                    resp.body.slice(s..s + len)
                }
            }
            412 => {
                return Err(self.client.destination_error(
                    "read",
                    &self.key,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "object changed while it was being read",
                    ),
                ));
            }
            _ => return Err(self.client.status_error("read", &self.key, &resp)),
        };
        if data.len() != len {
            return Err(self.client.destination_error(
                "read",
                &self.key,
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("ranged read returned {} of {len} bytes", data.len()),
                ),
            ));
        }
        Ok(data)
    }
}

impl ObjectReader for S3Object {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        let len = buf.len() as u64;
        let end = offset
            .checked_add(len)
            .filter(|e| *e <= self.size)
            .ok_or_else(|| {
                self.client.destination_error(
                    "read",
                    &self.key,
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "read past the end of the object",
                    ),
                )
            })?;
        if len == 0 {
            return Ok(());
        }
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        let hit = window.as_ref().and_then(|(start, data)| {
            let from = usize::try_from(offset.checked_sub(*start)?).ok()?;
            let to = from.checked_add(buf.len())?;
            data.get(from..to)
        });
        if let Some(bytes) = hit {
            buf.copy_from_slice(bytes);
            return Ok(());
        }
        let fetch_end = self
            .size
            .min(offset.saturating_add(len.max(READ_AHEAD)))
            .max(end);
        let data = self.fetch(offset, fetch_end)?;
        buf.copy_from_slice(&data[..buf.len()]);
        *window = Some((offset, data));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
