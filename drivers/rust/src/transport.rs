// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Connection pool and the call executor: deadlines, headers, authentication and the retry
//! policy of `drivers/conformance/retry.yaml` R1–R8 (rust-driver.md §3 and §8, PD-097).
//!
//! Every operation runs through [`Executor::run`]: one deadline for the whole operation (every
//! attempt and backoff included, R8; each attempt sends the remaining time as `grpc-timeout`),
//! one `rgn-request-id` (`UUIDv7`) for every attempt so the server deduplicates retried writes
//! (R2), and a retry only when the failure's `ErrorDetail.retryable` (or the transport fallback)
//! says so and the operation class allows it (R1, R2, R7). A stream that already delivered a
//! batch is never retried (R3); RGN-4005 on a session login re-authenticates once (R5).

use std::{
    future::Future,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tonic::{
    metadata::{AsciiMetadataValue, MetadataMap},
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

use crate::{
    auth::Authenticator,
    codes,
    error::{Error, ErrorClass, Result},
    session::Session,
    settings::{Settings, split_endpoint},
};

pub(crate) const REQUEST_ID_HEADER: &str = "rgn-request-id";
pub(crate) const CAUSALITY_TOKEN_HEADER: &str = "rgn-causality-token";
/// Largest message in either direction (protocol.md §2).
pub(crate) const MAX_MESSAGE_SIZE: usize = 64 << 20;
const BACKOFF_BASE: Duration = Duration::from_millis(10);
const BACKOFF_CAP: Duration = Duration::from_secs(1);

/// Operation class (retry.yaml R7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpKind {
    /// Retried when `retry_reads`.
    Read,
    /// Retried when `retry_writes`.
    Write,
    /// Never retried alone (DDL, transaction control, cursors, admin, inside transactions).
    NoRetry,
}

/// What the executor needs to know about one operation.
#[derive(Clone, Copy)]
pub(crate) struct CallSpec<'a> {
    pub kind: OpKind,
    pub timeout: Option<Duration>,
    pub session: Option<&'a Session>,
}

impl CallSpec<'_> {
    pub(crate) fn of(kind: OpKind) -> Self {
        Self {
            kind,
            timeout: None,
            session: None,
        }
    }
}

/// Per-attempt request data handed to the call closure.
pub(crate) struct Attempt {
    pub channel: Channel,
    headers: MetadataMap,
    timeout: Duration,
}

impl Attempt {
    /// A request carrying the attempt's headers and deadline.
    pub(crate) fn request<M>(&self, message: M) -> tonic::Request<M> {
        let mut r = tonic::Request::new(message);
        *r.metadata_mut() = self.headers.clone();
        r.set_timeout(self.timeout);
        r
    }
}

/// A failed attempt: the status and whether a stream already delivered data (R3).
pub(crate) struct Failure {
    pub error: Error,
    pub delivered: bool,
}

impl From<tonic::Status> for Failure {
    fn from(s: tonic::Status) -> Self {
        Self {
            error: Error::from_status(&s),
            delivered: false,
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self {
            error,
            delivered: false,
        }
    }
}

struct Slot {
    endpoint: Endpoint,
    // Created on first use: tonic spawns the channel's worker on the current Tokio runtime, and
    // `Client::new` may run outside one.
    channel: OnceLock<Channel>,
    in_flight: AtomicI64,
}

/// `ConnectionsPerEndpoint` HTTP/2 channels per endpoint; node selection power-of-two-choices
/// on in-flight calls, avoiding the slot that just failed on a retry.
pub(crate) struct Pool {
    slots: Vec<Slot>,
}

impl Pool {
    pub(crate) fn new(s: &Settings) -> Result<Self> {
        let tls = tls_config(s)?;
        let mut slots = Vec::new();
        for e in &s.endpoints {
            let scheme = if tls.is_some() { "https" } else { "http" };
            let mut ep = Endpoint::from_shared(format!("{scheme}://{e}"))
                .map_err(|_| Error::argument(format!("invalid endpoint {e}")))?
                .connect_timeout(s.connect_timeout)
                .http2_keep_alive_interval(Duration::from_secs(30))
                .keep_alive_timeout(Duration::from_secs(10))
                .keep_alive_while_idle(true)
                .tcp_nodelay(true)
                .user_agent(format!(
                    "{}/{}",
                    crate::settings::DRIVER_NAME,
                    crate::settings::VERSION
                ))
                .map_err(|_| Error::argument("invalid user agent"))?;
            if let Some(t) = &tls {
                let mut t = t.clone();
                if s.tls.server_name.is_none() {
                    t = t.domain_name(split_endpoint(e).0);
                }
                ep = ep
                    .tls_config(t)
                    .map_err(|e| Error::argument(format!("TLS configuration: {e}")))?;
            }
            for _ in 0..s.connections_per_endpoint {
                slots.push(Slot {
                    endpoint: ep.clone(),
                    channel: OnceLock::new(),
                    in_flight: AtomicI64::new(0),
                });
            }
        }
        Ok(Self { slots })
    }

    fn channel(&self, i: usize) -> Channel {
        let s = &self.slots[i];
        s.channel.get_or_init(|| s.endpoint.connect_lazy()).clone()
    }

    /// The first channel (login of `Client::connect`, logout).
    pub(crate) fn first(&self) -> Channel {
        self.channel(0)
    }

    fn acquire(&self, avoid: Option<usize>) -> usize {
        let n = self.slots.len();
        let pick = || -> usize {
            if n == 1 {
                return 0;
            }
            match avoid {
                None => usize::try_from(crate::random::below_or_equal(n as u64 - 1)).unwrap_or(0),
                Some(a) => {
                    let i =
                        usize::try_from(crate::random::below_or_equal(n as u64 - 2)).unwrap_or(0);
                    if i >= a { i + 1 } else { i }
                }
            }
        };
        let (a, b) = (pick(), pick());
        let chosen = if self.slots[b].in_flight.load(Ordering::Relaxed)
            < self.slots[a].in_flight.load(Ordering::Relaxed)
        {
            b
        } else {
            a
        };
        self.slots[chosen].in_flight.fetch_add(1, Ordering::Relaxed);
        chosen
    }

    fn release(&self, i: usize) {
        self.slots[i].in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

fn tls_config(s: &Settings) -> Result<Option<ClientTlsConfig>> {
    if !s.tls_enabled() {
        return Ok(None);
    }
    let read = |p: &std::path::Path, what: &str| {
        std::fs::read(p).map_err(|e| Error::argument(format!("cannot read the TLS {what}: {e}")))
    };
    let mut c = ClientTlsConfig::new();
    match &s.tls.ca_file {
        Some(ca) => c = c.ca_certificate(Certificate::from_pem(read(ca, "CA file")?)),
        None => c = c.with_native_roots(),
    }
    if let (Some(cert), Some(key)) = (&s.tls.certificate_file, &s.tls.key_file) {
        c = c.identity(Identity::from_pem(
            read(cert, "certificate file")?,
            read(key, "key file")?,
        ));
    }
    if let Some(name) = &s.tls.server_name {
        c = c.domain_name(name.clone());
    }
    Ok(Some(c))
}

/// A new `UUIDv7` request id (RFC 9562): 48-bit Unix milliseconds, then random bits.
pub(crate) fn new_request_id() -> String {
    let mut b = [0u8; 16];
    crate::random::fill(&mut b);
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
    b[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    b[6] = (b[6] & 0x0F) | 0x70;
    b[8] = (b[8] & 0x3F) | 0x80;
    let h = crate::codec::to_hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// Full-jitter backoff of the n-th retry (n ≥ 1): uniform in [0, min(cap, base·2^(n−1))].
pub(crate) fn backoff_delay(attempt: u32) -> Duration {
    let ceiling = BACKOFF_BASE
        .checked_mul(
            1u32.checked_shl(attempt.saturating_sub(1))
                .unwrap_or(u32::MAX),
        )
        .map_or(BACKOFF_CAP, |d| d.min(BACKOFF_CAP));
    let ms = u64::try_from(ceiling.as_millis()).unwrap_or(1000);
    Duration::from_millis(crate::random::below_or_equal(ms))
}

/// Shared by the client and every handle derived from it.
pub(crate) struct Executor {
    pub(crate) pool: Pool,
    pub(crate) auth: Authenticator,
    pub(crate) settings: Settings,
    closed: AtomicBool,
}

impl Executor {
    pub(crate) fn new(settings: Settings) -> Result<Arc<Self>> {
        let pool = Pool::new(&settings)?;
        let auth = Authenticator::new(&settings);
        Ok(Arc::new(Self {
            pool,
            auth,
            settings,
            closed: AtomicBool::new(false),
        }))
    }

    pub(crate) fn check_open(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(Error::closed("the client"))
        } else {
            Ok(())
        }
    }

    /// Marks the executor closed; `true` the first time.
    pub(crate) fn mark_closed(&self) -> bool {
        !self.closed.swap(true, Ordering::AcqRel)
    }

    /// Runs one operation with the retry policy. `call` performs one attempt and returns the
    /// response (whose metadata may carry the causality token) or a [`Failure`].
    pub(crate) async fn run<T, F, Fut>(&self, spec: CallSpec<'_>, mut call: F) -> Result<T>
    where
        F: FnMut(Attempt) -> Fut,
        Fut: Future<Output = std::result::Result<tonic::Response<T>, Failure>>,
    {
        self.check_open()?;
        let timeout = spec.timeout.unwrap_or(self.settings.operation_timeout);
        let deadline = Instant::now() + timeout;
        let request_id = AsciiMetadataValue::try_from(new_request_id())
            .map_err(|_| Error::argument("request id"))?;
        let mut retries = 0u32;
        let mut reauthenticated = false;
        let mut avoid = None;
        loop {
            let slot = self.pool.acquire(avoid);
            let channel = self.pool.channel(slot);
            let outcome = self
                .attempt(spec, &request_id, deadline, channel, &mut call)
                .await;
            self.pool.release(slot);
            let (failure, authorization) = match outcome {
                Ok(v) => return Ok(v),
                Err(f) => f,
            };
            avoid = Some(slot);
            if failure.delivered {
                return Err(failure.error);
            }
            let Some(e) = failure.error.rustegon() else {
                return Err(failure.error);
            };
            if e.code == codes::SESSION_EXPIRED {
                // R5: re-authenticate once and resend once, outside the retry budget.
                if reauthenticated || !self.auth.uses_sessions() {
                    return Err(failure.error);
                }
                reauthenticated = true;
                self.auth.invalidate(authorization.as_deref()).await;
                continue;
            }
            let allowed = match spec.kind {
                OpKind::Read => self.settings.retry_reads,
                OpKind::Write => self.settings.retry_writes,
                OpKind::NoRetry => false,
            };
            if !e.retryable || !allowed || retries >= self.settings.max_retries {
                return Err(failure.error);
            }
            retries += 1;
            let mut delay = backoff_delay(retries);
            if e.class == ErrorClass::RateLimited
                && let Some(after) = e.retry_after
            {
                delay = delay.max(after);
            }
            if Instant::now() + delay > deadline {
                return Err(failure.error);
            }
            tokio::time::sleep(delay).await;
        }
    }

    /// One attempt; on failure also returns the authorization it used (to invalidate it).
    async fn attempt<T, F, Fut>(
        &self,
        spec: CallSpec<'_>,
        request_id: &AsciiMetadataValue,
        deadline: Instant,
        channel: Channel,
        call: &mut F,
    ) -> std::result::Result<T, (Failure, Option<String>)>
    where
        F: FnMut(Attempt) -> Fut,
        Fut: Future<Output = std::result::Result<tonic::Response<T>, Failure>>,
    {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timed_out = || {
            Failure::from(Error::from_transport(
                tonic::Code::DeadlineExceeded,
                "the operation timeout expired",
            ))
        };
        if remaining.is_zero() {
            return Err((timed_out(), None));
        }
        let fut = async {
            let authorization = self
                .auth
                .authorization(&channel)
                .await
                .map_err(|e| (Failure::from(e), None))?;
            let mut headers = MetadataMap::new();
            headers.insert(REQUEST_ID_HEADER, request_id.clone());
            if let Some(a) = &authorization {
                let v = AsciiMetadataValue::try_from(a.as_str())
                    .map_err(|_| (Failure::from(Error::argument("invalid credential")), None))?;
                headers.insert("authorization", v);
            }
            if let Some(s) = spec.session
                && let Some(t) = s.token_to_send().map_err(|e| (Failure::from(e), None))?
                && let Ok(v) = AsciiMetadataValue::try_from(t)
            {
                headers.insert(CAUSALITY_TOKEN_HEADER, v);
            }
            let attempt = Attempt {
                channel: channel.clone(),
                headers,
                timeout: deadline.saturating_duration_since(Instant::now()),
            };
            match call(attempt).await {
                Ok(r) => {
                    if let Some(s) = spec.session {
                        s.observe(r.metadata());
                    }
                    Ok(r.into_inner())
                }
                Err(mut f) => {
                    // tonic enforces `grpc-timeout` client-side too and reports its own expiry
                    // as CANCELLED; past the deadline any failure without detail is the
                    // operation timeout (R4, never retried).
                    if Instant::now() >= deadline
                        && f.error.rustegon().is_some_and(|r| !r.has_detail)
                    {
                        f.error = timed_out().error;
                    }
                    Err((f, authorization))
                }
            }
        };
        match tokio::time::timeout(remaining, fut).await {
            Ok(r) => r,
            Err(_) => Err((timed_out(), None)),
        }
    }
}

/// `true` when a failure without `ErrorDetail` may have reached the server (a lost commit
/// reply, PD-122): every transport failure except a connection that never opened.
pub(crate) fn may_have_reached_server(e: &Error) -> bool {
    let Some(r) = e.rustegon() else {
        return false;
    };
    // A connect failure is UNAVAILABLE with a connection message: the commit never left.
    if r.has_detail {
        return false;
    }
    let m = r.message.to_ascii_lowercase();
    let connect_failure = [
        "connection refused",
        "tcp connect",
        "dns",
        "no such host",
        "handshake",
        "actively refused",
        "unreachable",
        "trying to connect",
    ]
    .iter()
    .any(|s| m.contains(s));
    !(r.code == 3002 && connect_failure)
}

/// Runs one unary RPC through [`Executor::run`]:
/// `unary!(exec, spec, document_service_client::DocumentServiceClient, get, request)`.
macro_rules! unary {
    ($exec:expr, $spec:expr, $client:ident :: $ty:ident, $method:ident, $req:expr) => {{
        let req = $req;
        $exec
            .run($spec, |a: $crate::transport::Attempt| {
                let req = req.clone();
                async move {
                    $crate::pb::$client::$ty::new(a.channel.clone())
                        .max_decoding_message_size($crate::transport::MAX_MESSAGE_SIZE)
                        .max_encoding_message_size($crate::transport::MAX_MESSAGE_SIZE)
                        .$method(a.request(req))
                        .await
                        .map_err($crate::transport::Failure::from)
                }
            })
            .await
    }};
}
pub(crate) use unary;
