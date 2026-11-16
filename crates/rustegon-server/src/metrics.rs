// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Node metrics in the `OpenMetrics` text format, served at `GET /metrics` (system-overview.md
//! §7; FR-OPS-001; PD-059).
//!
//! # Model
//! Two kinds of sources:
//! - **recorded** here: one [`RequestMetrics`] series per route (gRPC method or REST endpoint)
//!   with a count per outcome and a latency histogram, fed by the gRPC connection service and
//!   the REST router middleware;
//! - **pulled** at scrape time from the components that already count: executor gauges
//!   ([`crate::Executor`]), security counters ([`crate::security::SecurityCounters`]), active
//!   sessions (a read of the session records), the data plane's transaction and cursor
//!   registries, the transaction coordinator's outcome counters and the storage engine's
//!   statistics, plus the certificate expiry, build information and the PITR log archiver's
//!   counters ([`rustegon_backup::pitr::PitrMetrics`], FR-BKP-002) registered by the binary.
//!
//! Pulling keeps the hot paths free of metric plumbing and avoids a global recorder: every
//! number is owned by the component that produces it, and several nodes in one process (tests)
//! never share counters.
//!
//! # Label cardinality
//! Every label value comes from a closed set, so the number of series is bounded by the code:
//! `service`/`method` are the declared RPCs ([`crate::security::RPC_ACCESS`]) or REST endpoints
//! ([`crate::rest::REST_ENDPOINTS`]), anything else is `unknown`/`unmatched`; `code` is `ok`, a
//! catalog code (`ErrorCode::from_code`), `grpc_<0..16>` for statuses produced outside the
//! service layer, or `cancelled`; `reason` and `class` are enum names. Request paths, user
//! names, database names and ids are never labels.
//!
//! # Format
//! `OpenMetrics` 1.0 text (`application/openmetrics-text; version=1.0.0`), accepted by Prometheus
//! scrapers: counter families are declared without their `_total` suffix, histograms have
//! cumulative `_bucket` samples ending in `le="+Inf"`, `_count` and `_sum`, the document ends
//! with `# EOF`. Histograms use the fixed buckets [`DURATION_BUCKETS`]; native (sparse)
//! histograms have no text representation (PD-059).

use std::{
    collections::BTreeMap,
    fmt::{self, Write as _},
    sync::{Arc, Mutex, PoisonError, atomic::Ordering},
    time::Duration,
};

use rustegon_backup::pitr::PitrMetrics;

use rustegon_common::ErrorCode;
use rustegon_sim_api::Clock;

use crate::{
    Completion,
    rest::REST_ENDPOINTS,
    security::{LIMIT_CLASSES, Security, access_of, service_of},
    services::{DataServices, Deadline, RequestContext, Services},
};

/// `Content-Type` of the `/metrics` response.
pub const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Upper bounds (seconds) of the request latency histogram: 0.5 ms to 60 s, covering point
/// reads through the 60 s query deadline of the GUI.
pub const DURATION_BUCKETS: [f64; 16] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
    60.0,
];

/// How long each engine read of a scrape (session records, storage statistics) may take.
const SCRAPE_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// `service` label of every REST endpoint.
pub const REST_SERVICE: &str = "rest";
/// Label value of a request that matched no declared route.
pub const UNKNOWN: &str = "unknown";

/// The route a request is counted under (bounded, see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Route {
    /// gRPC service (`rustegon.v1.QueryService`), [`REST_SERVICE`] or [`UNKNOWN`].
    pub service: &'static str,
    /// gRPC method name (`Execute`) or REST `"<VERB> <path template>"`; [`UNKNOWN`] when the
    /// request matched nothing declared.
    pub method: &'static str,
    /// HTTP verb of a REST endpoint (empty for gRPC), rendered as the prefix of `method`.
    verb: &'static str,
}

impl Route {
    /// The route of a gRPC request to `path` (`/pkg.Service/Method`): the declared RPC, or
    /// `unknown` for any other path, so arbitrary paths cannot create series.
    #[must_use]
    pub fn grpc(path: &str) -> Self {
        access_of(path)
            .and_then(|rule| {
                let service = service_of(rule.method)?;
                let method = rule.method.rsplit_once('/')?.1;
                Some(Self {
                    service,
                    method,
                    verb: "",
                })
            })
            .unwrap_or(Self {
                service: UNKNOWN,
                method: UNKNOWN,
                verb: "",
            })
    }

    /// The route of a REST request matched to the documented `template` with `verb`; requests
    /// that matched no endpoint (404, 405) share one `unknown` series.
    #[must_use]
    pub fn rest(verb: &str, template: Option<&str>) -> Self {
        template
            .and_then(|t| {
                REST_ENDPOINTS
                    .iter()
                    .find(|e| e.method == verb && e.path == t)
            })
            .map_or(
                Self {
                    service: REST_SERVICE,
                    method: UNKNOWN,
                    verb: "",
                },
                |e| Self {
                    service: REST_SERVICE,
                    method: e.path,
                    verb: e.method,
                },
            )
    }

    fn method_label(&self) -> String {
        if self.verb.is_empty() {
            self.method.to_owned()
        } else {
            format!("{} {}", self.verb, self.method)
        }
    }
}

/// How a request ended (the `code` label).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Success.
    Ok,
    /// A Rustegon error (`RGN-<code>`).
    Error(ErrorCode),
    /// A gRPC status without a Rustegon detail (produced by the transport: unknown method,
    /// undecodable message, …); the gRPC status code 1–16.
    Status(u8),
    /// The client went away before the response completed.
    Cancelled,
}

impl Outcome {
    /// The outcome of a gRPC status code and the RGN code of its detail, if any.
    #[must_use]
    pub fn from_grpc(status: i32, rgn: Option<u32>) -> Self {
        if status == 0 {
            return Self::Ok;
        }
        if let Some(code) = rgn
            .and_then(|c| u16::try_from(c).ok())
            .and_then(ErrorCode::from_code)
        {
            return Self::Error(code);
        }
        // Clamped into the 17 gRPC codes so a foreign status cannot create series.
        Self::Status(u8::try_from(status.clamp(0, 16)).unwrap_or(2))
    }

    fn label(self) -> String {
        match self {
            Self::Ok => "ok".to_owned(),
            Self::Error(code) => code.code().to_string(),
            Self::Status(s) => format!("grpc_{s}"),
            Self::Cancelled => "cancelled".to_owned(),
        }
    }
}

#[derive(Debug, Default)]
struct Series {
    outcomes: BTreeMap<Outcome, u64>,
    buckets: [u64; DURATION_BUCKETS.len()],
    count: u64,
    sum: f64,
}

/// Request counts and latencies per route (module docs). Shared by both front ends through
/// [`Services::metrics`].
#[derive(Debug, Default)]
pub struct RequestMetrics {
    // One short critical section per finished request; the map holds at most a few hundred
    // series (module docs), so a mutex is cheaper than per-series atomics plus a concurrent map.
    series: Mutex<BTreeMap<Route, Series>>,
}

impl RequestMetrics {
    /// Records one finished request.
    pub fn record(&self, route: Route, outcome: Outcome, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        let mut all = self.series.lock().unwrap_or_else(PoisonError::into_inner);
        let series = all.entry(route).or_default();
        *series.outcomes.entry(outcome).or_insert(0) += 1;
        series.count += 1;
        series.sum += seconds;
        if let Some(i) = DURATION_BUCKETS.iter().position(|b| seconds <= *b) {
            series.buckets[i] += 1;
        }
    }

    /// Requests counted for `route` with `outcome` (tests, diagnostics).
    #[must_use]
    pub fn count(&self, route: Route, outcome: Outcome) -> u64 {
        self.series
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&route)
            .and_then(|s| s.outcomes.get(&outcome).copied())
            .unwrap_or(0)
    }
}

/// Seconds until a certificate expires (negative once expired).
pub type CertExpiry = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Everything `/metrics` exports besides what it pulls from the services (module docs).
#[derive(Default)]
pub struct ServerMetrics {
    requests: RequestMetrics,
    certs: Mutex<Vec<(&'static str, CertExpiry)>>,
    pitr: Mutex<Option<Arc<PitrMetrics>>>,
}

impl fmt::Debug for ServerMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerMetrics")
            .field("requests", &self.requests)
            .finish_non_exhaustive()
    }
}

impl ServerMetrics {
    /// The request counters.
    #[must_use]
    pub fn requests(&self) -> &RequestMetrics {
        &self.requests
    }

    /// Exports the expiry of a served certificate as `rustegon_cert_expiry_seconds{cert=name}`
    /// (security.md §5). `name` is a fixed identifier (`node`), never a subject or path.
    pub fn register_cert(&self, name: &'static str, expiry: CertExpiry) {
        let mut certs = self.certs.lock().unwrap_or_else(PoisonError::into_inner);
        certs.retain(|(n, _)| *n != name);
        certs.push((name, expiry));
    }

    /// Exports the counters of the node's PITR log archiver (`rustegon_backup_pitr_*`,
    /// backup-restore.md "Point-in-time recovery"); a node without `[backup.pitr]` registers
    /// nothing and exports no PITR family.
    pub fn register_pitr(&self, metrics: Arc<PitrMetrics>) {
        *self.pitr.lock().unwrap_or_else(PoisonError::into_inner) = Some(metrics);
    }

    /// Starts timing a request on `route`; the returned guard records it when finished, or as
    /// [`Outcome::Cancelled`] when dropped unfinished (client disconnect).
    #[must_use]
    pub fn start(self: &Arc<Self>, route: Route, clock: &Arc<dyn Clock>) -> InFlight {
        InFlight {
            metrics: Arc::clone(self),
            clock: Arc::clone(clock),
            route,
            started: clock.monotonic(),
            done: false,
        }
    }
}

/// A request being timed ([`ServerMetrics::start`]).
pub struct InFlight {
    metrics: Arc<ServerMetrics>,
    clock: Arc<dyn Clock>,
    route: Route,
    started: Duration,
    done: bool,
}

impl fmt::Debug for InFlight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InFlight")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

impl InFlight {
    /// Records the request with `outcome`.
    pub fn finish(mut self, outcome: Outcome) {
        self.record(outcome);
    }

    fn record(&mut self, outcome: Outcome) {
        if self.done {
            return;
        }
        self.done = true;
        let elapsed = self.clock.monotonic().saturating_sub(self.started);
        self.metrics.requests.record(self.route, outcome, elapsed);
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.record(Outcome::Cancelled);
    }
}

/// Escapes a label value (`OpenMetrics`: backslash, double quote, line feed).
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// The exposition being written.
struct Exposition(String);

impl Exposition {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
        let _ = writeln!(self.0, "# HELP {name} {help}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl fmt::Display) {
        self.0.push_str(name);
        if !labels.is_empty() {
            self.0.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.0.push(',');
                }
                let _ = write!(self.0, "{k}=\"{}\"", escape(v));
            }
            self.0.push('}');
        }
        let _ = writeln!(self.0, " {value}");
    }

    fn gauge(&mut self, name: &str, help: &str, value: impl fmt::Display) {
        self.family(name, "gauge", help);
        self.sample(name, &[], value);
    }

    /// A counter family `name` (without `_total`) with one unlabelled sample.
    fn counter(&mut self, name: &str, help: &str, value: u64) {
        self.family(name, "counter", help);
        self.sample(&format!("{name}_total"), &[], value);
    }
}

/// Formats a float the way `OpenMetrics` expects (`+Inf`, `-Inf`, `NaN`).
struct Float(f64);

impl fmt::Display for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_nan() {
            f.write_str("NaN")
        } else if self.0.is_infinite() {
            f.write_str(if self.0 > 0.0 { "+Inf" } else { "-Inf" })
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Renders every family this node exports (module docs). Reads the session records (with the
/// security layer) and the storage statistics (with the data plane) on the executor, each
/// bounded by a 5 s deadline; a source that fails leaves its family without samples.
pub async fn render(services: &Services) -> String {
    let mut out = Exposition(String::with_capacity(16 * 1024));
    write_node(&mut out, services);
    write_requests(&mut out, services.metrics().requests());
    if let Some(security) = services.security() {
        write_security(&mut out, services, security).await;
    }
    if let Some(data) = services.data() {
        write_data(&mut out, services, data).await;
    }
    write_certs(&mut out, services.metrics());
    write_pitr(&mut out, services.metrics());
    out.0.push_str("# EOF\n");
    out.0
}

/// Build information, readiness and executor gauges.
fn write_node(out: &mut Exposition, services: &Services) {
    out.family(
        "rustegon_build",
        "info",
        "Version and platform of this binary.",
    );
    out.sample(
        "rustegon_build_info",
        &[
            ("version", env!("CARGO_PKG_VERSION")),
            ("os", std::env::consts::OS),
            ("arch", std::env::consts::ARCH),
        ],
        1,
    );
    out.gauge(
        "rustegon_ready",
        "1 when the node reports ready on /api/v1/health/ready, else 0.",
        u8::from(crate::health::status(services) == crate::health::ReadyStatus::Ready),
    );
    let executor = &services.deps().executor;
    out.gauge(
        "rustegon_executor_in_flight",
        "Engine calls holding an executor permit.",
        executor.in_flight(),
    );
    out.gauge(
        "rustegon_executor_queued",
        "Engine calls waiting for an executor permit.",
        executor.queued(),
    );
    out.gauge(
        "rustegon_executor_max_in_flight",
        "Bound on concurrently running engine calls.",
        executor.max_in_flight(),
    );
}

/// Security counters and the active session gauge.
async fn write_security(out: &mut Exposition, services: &Services, security: &Security) {
    {
        let counters = security.counters();
        out.counter(
            "rustegon_auth_failures",
            "Failed authentications (password, SCRAM, API key, certificate).",
            counters.auth_failures(),
        );
        out.counter(
            "rustegon_lockouts",
            "Accounts locked by the lockout policy.",
            counters.lockouts(),
        );
        out.counter(
            "rustegon_audit_write_failures",
            "Audit records that could not be written.",
            counters.audit_write_failures(),
        );
        out.family(
            "rustegon_rate_limited",
            "counter",
            "Requests rejected by the rate limiter (RGN-4003), per limit class.",
        );
        for class in LIMIT_CLASSES {
            out.sample(
                "rustegon_rate_limited_total",
                &[("class", class.as_str())],
                counters.rate_limited(class),
            );
        }
        let ctx = scrape_ctx(services);
        out.family(
            "rustegon_active_sessions",
            "gauge",
            "Sessions that are not expired.",
        );
        match security.active_sessions(&ctx).await {
            Ok(n) => out.sample("rustegon_active_sessions", &[], n),
            // The family stays (empty) so a failing count is visible as a missing sample, not
            // as a scrape error.
            Err(e) => tracing::warn!(error = %e, "cannot count active sessions for /metrics"),
        }
    }
}

/// Data-plane registries, transaction outcomes and storage statistics.
async fn write_data(out: &mut Exposition, services: &Services, data: &DataServices) {
    {
        out.gauge(
            "rustegon_active_transactions",
            "Open interactive transactions.",
            data.transaction.active_count(),
        );
        out.gauge(
            "rustegon_open_cursors",
            "Open query cursors.",
            data.open_cursors(),
        );
        let engine = data.engine();
        let txn = engine.txn_stats();
        out.counter(
            "rustegon_txn_commits",
            "Committed transactions (including read-only and internal ones).",
            txn.commits,
        );
        out.family(
            "rustegon_txn_aborts",
            "counter",
            "Aborted transactions per final abort reason.",
        );
        for (reason, n) in txn.aborts_by_reason() {
            out.sample("rustegon_txn_aborts_total", &[("reason", reason)], n);
        }
        out.family(
            "rustegon_txn_restarts",
            "counter",
            "Transaction restarts per reason.",
        );
        for (reason, n) in txn.restarts_by_reason() {
            out.sample("rustegon_txn_restarts_total", &[("reason", reason)], n);
        }
        out.gauge(
            "rustegon_storage_healthy",
            "1 while the store accepts writes, 0 after a failed apply (reopen required).",
            u8::from(engine.is_healthy()),
        );
        // The engine's statistics take its in-memory locks: read them on the executor, never
        // on an async worker.
        let engine = Arc::clone(engine);
        let storage = services
            .deps()
            .executor
            .run(&scrape_ctx(services), Completion::Abandon, move |_| {
                Ok(engine.storage_metrics().families())
            })
            .await;
        match storage {
            Ok(families) => {
                for (name, value) in families {
                    match name.strip_suffix("_total") {
                        Some(base) => out.family(base, "counter", "Storage engine statistic."),
                        None => out.family(name, "gauge", "Storage engine statistic."),
                    }
                    out.sample(name, &[], Float(value));
                }
            }
            // Omitted families make a failing source visible without failing the scrape.
            Err(e) => tracing::warn!(error = %e, "cannot read storage statistics for /metrics"),
        }
    }
}

/// Context of the engine reads a scrape makes, bounded so a stuck store cannot hang it.
fn scrape_ctx(services: &Services) -> RequestContext {
    let deps = services.deps();
    RequestContext::internal(deps.clock.as_ref(), deps.rng.as_ref()).with_deadline(Some(
        Deadline::after(deps.clock.as_ref(), SCRAPE_READ_TIMEOUT),
    ))
}

/// Expiry of the registered certificates.
fn write_certs(out: &mut Exposition, metrics: &ServerMetrics) {
    let certs: Vec<(&'static str, CertExpiry)> = metrics
        .certs
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if !certs.is_empty() {
        out.family(
            "rustegon_cert_expiry_seconds",
            "gauge",
            "Seconds until the served certificate expires (negative once expired).",
        );
        for (name, expiry) in certs {
            out.sample("rustegon_cert_expiry_seconds", &[("cert", name)], expiry());
        }
    }
}

/// The PITR log archiver's counters, if one is registered. `Relaxed` loads: each value is an
/// independent monotone counter or a gauge, and a scrape needs no ordering between them.
fn write_pitr(out: &mut Exposition, metrics: &ServerMetrics) {
    let Some(pitr) = metrics
        .pitr
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
    else {
        return;
    };
    out.counter(
        "rustegon_backup_pitr_archived_segments",
        "Raft log segments copied to the PITR archive since start.",
        pitr.archived_segments.load(Ordering::Relaxed),
    );
    out.counter(
        "rustegon_backup_pitr_archived_bytes",
        "Bytes of log segments copied to the PITR archive since start.",
        pitr.archived_bytes.load(Ordering::Relaxed),
    );
    out.gauge(
        "rustegon_backup_pitr_unarchived_bytes",
        "Bytes of sealed log segments not yet archived (after the last archiver pass).",
        pitr.unarchived_bytes.load(Ordering::Relaxed),
    );
    out.counter(
        "rustegon_backup_pitr_continuity_breaks",
        "Times the archiver gave up segments beyond backup.pitr.max_unarchived_bytes (PITR \
         across them is impossible; alert on any increase).",
        pitr.continuity_breaks.load(Ordering::Relaxed),
    );
    out.counter(
        "rustegon_backup_pitr_failed_passes",
        "Archiver passes that failed (destination or log errors) since start.",
        pitr.failed_passes.load(Ordering::Relaxed),
    );
    let wall_ns = pitr.last_archived_wall_ns.load(Ordering::Relaxed);
    // Precision loss above 2^53 ns (year 2255) is irrelevant for an age alert.
    #[allow(clippy::cast_precision_loss)]
    let seconds = wall_ns as f64 / 1e9;
    out.gauge(
        "rustegon_backup_pitr_last_archived_timestamp_seconds",
        "Wall time (Unix seconds) of the newest log entry in the PITR archive; 0 before the \
         first segment is archived.",
        Float(seconds),
    );
}

fn write_requests(out: &mut Exposition, requests: &RequestMetrics) {
    let all = requests
        .series
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    out.family(
        "rustegon_requests",
        "counter",
        "Finished requests per service, method and outcome code (ok, RGN code, grpc_<n>, \
         cancelled).",
    );
    let mut errors: BTreeMap<Outcome, u64> = BTreeMap::new();
    for (route, series) in all.iter() {
        let method = route.method_label();
        for (outcome, n) in &series.outcomes {
            let code = outcome.label();
            out.sample(
                "rustegon_requests_total",
                &[
                    ("service", route.service),
                    ("method", &method),
                    ("code", &code),
                ],
                n,
            );
            if *outcome != Outcome::Ok {
                *errors.entry(*outcome).or_insert(0) += n;
            }
        }
    }
    out.family(
        "rustegon_errors",
        "counter",
        "Failed requests per outcome code, over all services.",
    );
    for (outcome, n) in errors {
        out.sample("rustegon_errors_total", &[("code", &outcome.label())], n);
    }
    out.family(
        "rustegon_request_duration_seconds",
        "histogram",
        "Request latency per service and method.",
    );
    for (route, series) in all.iter() {
        let method = route.method_label();
        let mut cumulative = 0;
        for (bound, n) in DURATION_BUCKETS.iter().zip(series.buckets) {
            cumulative += n;
            let le = Float(*bound).to_string();
            out.sample(
                "rustegon_request_duration_seconds_bucket",
                &[("service", route.service), ("method", &method), ("le", &le)],
                cumulative,
            );
        }
        let labels = [("service", route.service), ("method", method.as_str())];
        out.sample(
            "rustegon_request_duration_seconds_bucket",
            &[labels[0], labels[1], ("le", "+Inf")],
            series.count,
        );
        out.sample(
            "rustegon_request_duration_seconds_count",
            &labels,
            series.count,
        );
        out.sample(
            "rustegon_request_duration_seconds_sum",
            &labels,
            Float(series.sum),
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn fr_ops_001_routes_are_bounded_to_declared_endpoints() {
        let r = Route::grpc("/rustegon.v1.QueryService/Execute");
        assert_eq!(
            (r.service, r.method),
            ("rustegon.v1.QueryService", "Execute")
        );
        let unknown = Route::grpc("/evil.Service/<script>");
        assert_eq!((unknown.service, unknown.method), (UNKNOWN, UNKNOWN));
        let rest = Route::rest("GET", Some("/api/v1/users/{name}"));
        assert_eq!(rest.method_label(), "GET /api/v1/users/{name}");
        assert_eq!(Route::rest("GET", Some("/x")).method, UNKNOWN);
        assert_eq!(Route::rest("PUT", None).method, UNKNOWN);
    }

    #[test]
    fn fr_ops_001_outcome_labels_are_bounded() {
        assert_eq!(Outcome::from_grpc(0, None), Outcome::Ok);
        assert_eq!(
            Outcome::from_grpc(16, Some(4001)).label(),
            "4001",
            "catalog code"
        );
        // A code outside the catalog falls back to the gRPC status, clamped.
        assert_eq!(Outcome::from_grpc(99, Some(65_000)).label(), "grpc_16");
        assert_eq!(Outcome::from_grpc(-3, None).label(), "grpc_0");
    }

    #[test]
    fn fr_ops_001_histogram_is_cumulative_and_escaped() {
        let m = RequestMetrics::default();
        let route = Route::grpc("/rustegon.v1.SessionService/Ping");
        m.record(route, Outcome::Ok, Duration::from_micros(300));
        m.record(route, Outcome::Ok, Duration::from_millis(30));
        m.record(
            route,
            Outcome::Error(ErrorCode::NotFound),
            Duration::from_secs(120),
        );
        let mut out = Exposition(String::new());
        write_requests(&mut out, &m);
        let text = out.0;
        assert!(text.contains(
            "rustegon_requests_total{service=\"rustegon.v1.SessionService\",method=\"Ping\",code=\"ok\"} 2"
        ));
        assert!(text.contains("le=\"0.0005\"} 1"), "{text}");
        assert!(text.contains("le=\"60\"} 2"), "{text}");
        assert!(text.contains("le=\"+Inf\"} 3"), "{text}");
        assert!(
            text.contains("rustegon_errors_total{code=\"1030\"} 1"),
            "{text}"
        );
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn fr_bkp_002_pitr_families_only_when_registered() {
        let m = ServerMetrics::default();
        let mut out = Exposition(String::new());
        write_pitr(&mut out, &m);
        assert!(out.0.is_empty(), "no archiver, no family");

        let pitr = Arc::new(PitrMetrics::default());
        pitr.archived_segments.store(3, Ordering::Relaxed);
        pitr.continuity_breaks.store(1, Ordering::Relaxed);
        pitr.unarchived_bytes.store(4096, Ordering::Relaxed);
        pitr.last_archived_wall_ns
            .store(1_500_000_000, Ordering::Relaxed);
        m.register_pitr(pitr);
        let mut out = Exposition(String::new());
        write_pitr(&mut out, &m);
        let text = out.0;
        for want in [
            "# TYPE rustegon_backup_pitr_archived_segments counter",
            "rustegon_backup_pitr_archived_segments_total 3",
            "rustegon_backup_pitr_continuity_breaks_total 1",
            "rustegon_backup_pitr_unarchived_bytes 4096",
            "rustegon_backup_pitr_failed_passes_total 0",
            "rustegon_backup_pitr_last_archived_timestamp_seconds 1.5",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
    }
}
