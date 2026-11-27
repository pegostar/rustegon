// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Structured JSON logging with rotation (FR-OPS-002, system-overview.md §7).
//!
//! Events become one JSON object per line with the fields `ts`, `level`, `node_id`, `channel`,
//! `msg`, `trace_id`, `target` plus the event's own key/values. Lines are handed to a dedicated
//! writer thread through a bounded queue, so callers (often async tasks) never block on disk
//! I/O; if the queue is full, lines are dropped and the loss is reported in the log. The writer
//! rotates files daily (UTC) or when they reach `max_file_size`, keeping `max_files` files.
//! File access and time go through `rustegon-sim-api` so rotation is testable without waiting.

use std::{
    fmt, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime},
};

use rustegon_sim_api::{Clock, File, FileSystem, OpenMode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    Layer,
    filter::Targets,
    layer::{Context, SubscriberExt},
    util::SubscriberInitExt,
};

use crate::{
    Error, ErrorCode, Result,
    settings::{FieldSpec, Kind, Mutability, Sensitivity, Settings},
};

const MIB: u64 = 1024 * 1024;
const SECS_PER_DAY: i64 = 86_400;
/// Lines buffered for the writer thread; beyond this, new lines are dropped rather than
/// blocking the producer. 64 Ki lines of ~300 B is ~20 MiB worst case.
const QUEUE_LINES: usize = 64 * 1024;
/// Log channels (system-overview.md §7). An event's target selects its channel; any other
/// target goes to `main`.
pub const CHANNELS: [&str; 4] = ["main", "audit", "slow_query", "security"];
/// Prefix and suffix of log file names; rotation only ever deletes files matching both.
const FILE_PREFIX: &str = "rustegon-";
const FILE_SUFFIX: &str = ".log";

/// `[log]` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogSettings {
    /// Filter directives, e.g. `info` or `info,rustegon_storage=debug`.
    pub level: String,
    /// Directory for JSON log files; unset means `<node.data_dir>/logs`.
    pub dir: Option<PathBuf>,
    /// Rotate a file when it reaches this many bytes.
    pub max_file_size: u64,
    /// Number of log files kept, including the active one.
    pub max_files: u64,
    /// Also write human-readable logs to stderr (journald, Windows service host, Docker).
    pub stderr: bool,
}

impl Default for LogSettings {
    fn default() -> Self {
        // Rotation defaults from system-overview.md §7: daily or 100 MiB, keep 14.
        Self {
            level: "info".into(),
            dir: None,
            max_file_size: 100 * MIB,
            max_files: 14,
            stderr: true,
        }
    }
}

const fn spec(name: &'static str, kind: Kind, doc: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        kind,
        mutability: Mutability::Static,
        sensitivity: Sensitivity::Public,
        doc,
    }
}

/// 1 MiB and 16 GiB as `i64` for the `max_file_size` range.
const MIN_FILE_SIZE: i64 = 1024 * 1024;
const MAX_FILE_SIZE: i64 = 16 * 1024 * 1024 * 1024;

impl Settings for LogSettings {
    const SECTION: &'static str = "log";
    const FIELDS: &'static [FieldSpec] = &[
        spec(
            "level",
            Kind::String,
            "Log filter directives (e.g. `info,rustegon_storage=debug`).",
        ),
        spec(
            "dir",
            Kind::Path,
            "Directory of JSON log files (default `<node.data_dir>/logs`).",
        ),
        spec(
            "max_file_size",
            Kind::Integer {
                min: MIN_FILE_SIZE,
                max: MAX_FILE_SIZE,
            },
            "Size in bytes at which the active log file is rotated.",
        ),
        spec(
            "max_files",
            Kind::Integer {
                min: 1,
                max: 10_000,
            },
            "Number of log files kept.",
        ),
        spec(
            "stderr",
            Kind::Bool,
            "Also write human-readable logs to stderr.",
        ),
    ];

    fn validate(&self) -> std::result::Result<(), String> {
        self.level
            .parse::<Targets>()
            .map(|_| ())
            .map_err(|e| format!("level: {e}"))
    }
}

/// Runtime dependencies of the logger.
pub struct LogContext {
    /// File system for log files.
    pub fs: Arc<dyn FileSystem>,
    /// Clock for timestamps and daily rotation.
    pub clock: Arc<dyn Clock>,
    /// Node id once known; `null` in log lines before the node joins a cluster.
    pub node_id: Option<String>,
}

enum Msg {
    /// Event time (drives daily rotation, so queueing delay cannot misfile a line) and line.
    Line(SystemTime, String),
    Shutdown,
}

/// Keeps the writer thread alive; dropping it flushes queued lines and stops the thread.
pub struct LogGuard {
    tx: mpsc::SyncSender<Msg>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        // Blocking send: lines queued before shutdown are written first (FIFO).
        let _ = self.tx.send(Msg::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// `tracing` layer producing JSON lines for the writer thread.
pub struct JsonLayer {
    clock: Arc<dyn Clock>,
    node_id: Option<String>,
    tx: mpsc::SyncSender<Msg>,
    dropped: AtomicU64,
}

impl JsonLayer {
    fn send(&self, at: SystemTime, line: String) -> bool {
        match self.tx.try_send(Msg::Line(at, line)) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            // Writer already shut down (process exit): nothing left to do.
            Err(mpsc::TrySendError::Disconnected(_)) => false,
        }
    }

    fn line(&self, at: SystemTime, level: &str, target: &str, fields: JsonVisitor) -> String {
        let channel = CHANNELS
            .iter()
            .find(|c| **c == target)
            .copied()
            .unwrap_or(CHANNELS[0]);
        let mut obj = Map::new();
        obj.insert("ts".into(), rfc3339(at).into());
        obj.insert("level".into(), level.into());
        obj.insert("node_id".into(), self.node_id.clone().into());
        obj.insert("channel".into(), channel.into());
        obj.insert("msg".into(), fields.message.unwrap_or_default().into());
        obj.insert("trace_id".into(), fields.trace_id.into());
        obj.insert("target".into(), target.into());
        for (key, value) in fields.fields {
            // Reserved names keep their meaning; a colliding event field is kept under a prefix.
            let key = if obj.contains_key(&key) {
                format!("field.{key}")
            } else {
                key
            };
            obj.insert(key, value);
        }
        Value::Object(obj).to_string()
    }
}

impl<S: Subscriber> Layer<S> for JsonLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Relaxed: the counter is a statistic, it orders nothing else.
        let at = self.clock.wall();
        let lost = self.dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            let notice = JsonVisitor {
                message: Some(format!("{lost} log lines dropped: writer queue full")),
                ..JsonVisitor::default()
            };
            if !self.send(
                at,
                self.line(at, "WARN", "rustegon_common::logging", notice),
            ) {
                self.dropped.fetch_add(lost, Ordering::Relaxed);
            }
        }
        let mut fields = JsonVisitor::default();
        event.record(&mut fields);
        let meta = event.metadata();
        self.send(
            at,
            self.line(at, meta.level().as_str(), meta.target(), fields),
        );
    }
}

#[derive(Default)]
struct JsonVisitor {
    message: Option<String>,
    trace_id: Option<String>,
    fields: Vec<(String, Value)>,
}

impl JsonVisitor {
    fn put(&mut self, field: &Field, value: Value) {
        let text = || match &value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        match field.name() {
            "message" => self.message = Some(text()),
            "trace_id" => self.trace_id = Some(text()),
            name => self.fields.push((name.to_owned(), value)),
        }
    }
}

impl Visit for JsonVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.put(field, Value::String(format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, Value::String(value.to_owned()));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, value.into());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, value.into());
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, value.into());
    }
}

/// Creates the JSON file layer and starts its writer thread.
///
/// # Errors
/// [`ErrorCode::Internal`] if the writer thread cannot be started.
pub fn json_file_layer(
    settings: &LogSettings,
    dir: &Path,
    ctx: LogContext,
) -> Result<(JsonLayer, LogGuard)> {
    let (tx, rx) = mpsc::sync_channel(QUEUE_LINES);
    let mut file = RollingFile {
        fs: ctx.fs,
        dir: dir.to_path_buf(),
        max_bytes: settings.max_file_size,
        max_files: usize::try_from(settings.max_files).unwrap_or(usize::MAX),
        current: None,
        seq: 0,
    };
    let worker = thread::Builder::new()
        .name("rustegon-log".into())
        .spawn(move || {
            let mut failing = false;
            while let Ok(Msg::Line(at, line)) = rx.recv() {
                match file.write_line(at, &line) {
                    Ok(()) => failing = false,
                    // The logger cannot log its own failure; report once per failure streak.
                    Err(e) if !failing => {
                        failing = true;
                        eprintln!(
                            "rustegon: cannot write log file in {}: {e}",
                            file.dir.display()
                        );
                    }
                    Err(_) => {}
                }
            }
        })
        .map_err(|e| Error::new(ErrorCode::Internal, "cannot start log writer").with_source(e))?;
    let layer = JsonLayer {
        clock: ctx.clock,
        node_id: ctx.node_id,
        tx: tx.clone(),
        dropped: AtomicU64::new(0),
    };
    Ok((
        layer,
        LogGuard {
            tx,
            worker: Some(worker),
        },
    ))
}

/// Installs the global subscriber: level filter, JSON file layer and optional stderr layer.
///
/// # Errors
/// [`ErrorCode::InvalidArgument`] for an invalid level; [`ErrorCode::Internal`] if a global
/// subscriber is already installed or the writer thread cannot start.
pub fn init(settings: &LogSettings, dir: &Path, ctx: LogContext) -> Result<LogGuard> {
    let filter: Targets = settings
        .level
        .parse()
        .map_err(|e| Error::new(ErrorCode::InvalidArgument, format!("log.level: {e}")))?;
    let (json, guard) = json_file_layer(settings, dir, ctx)?;
    let stderr = settings.stderr.then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(io::stderr)
            .without_time()
    });
    tracing_subscriber::registry()
        .with(json)
        .with(stderr)
        .with(filter)
        .try_init()
        .map_err(|e| {
            Error::new(ErrorCode::Internal, "logging already initialised").with_source(e)
        })?;
    Ok(guard)
}

struct RollingFile {
    fs: Arc<dyn FileSystem>,
    dir: PathBuf,
    max_bytes: u64,
    max_files: usize,
    current: Option<ActiveFile>,
    /// Disambiguates files opened within the same second.
    seq: u64,
}

struct ActiveFile {
    file: Box<dyn File>,
    size: u64,
    /// UTC day (days since epoch) the file was opened on.
    day: i64,
}

impl RollingFile {
    fn write_line(&mut self, now: SystemTime, line: &str) -> io::Result<()> {
        let day = unix_time(now).0.div_euclid(SECS_PER_DAY);
        let len = line.len() as u64 + 1;
        let rotate = match &self.current {
            None => true,
            // A single line larger than max_bytes still gets written, alone in its file.
            Some(a) => a.day != day || (a.size > 0 && a.size + len > self.max_bytes),
        };
        if rotate {
            self.rotate(now, day)?;
        }
        let Some(active) = &mut self.current else {
            return Err(io::Error::other("no active log file"));
        };
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        active.file.append(&buf)?;
        active.size += len;
        Ok(())
    }

    fn rotate(&mut self, now: SystemTime, day: i64) -> io::Result<()> {
        self.current = None;
        self.fs.create_dir_all(&self.dir)?;
        let stamp = file_stamp(now);
        loop {
            self.seq += 1;
            let path = self
                .dir
                .join(format!("{FILE_PREFIX}{stamp}-{:06}{FILE_SUFFIX}", self.seq));
            match self.fs.open(&path, OpenMode::CreateNew) {
                Ok(file) => {
                    self.prune(&path)?;
                    self.current = Some(ActiveFile { file, size: 0, day });
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Deletes the oldest log files beyond `max_files`. Names sort chronologically
    /// (`rustegon-<UTC stamp>-<seq>.log`); the active file is never deleted.
    fn prune(&self, active: &Path) -> io::Result<()> {
        let mut logs: Vec<PathBuf> = self
            .fs
            .read_dir(&self.dir)?
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(FILE_PREFIX) && n.ends_with(FILE_SUFFIX))
            })
            .collect();
        logs.sort();
        let excess = logs.len().saturating_sub(self.max_files);
        for path in logs.iter().take(excess).filter(|p| p.as_path() != active) {
            self.fs.remove_file(path)?;
        }
        Ok(())
    }
}

/// Seconds and microseconds since the Unix epoch; times before 1970 clamp to the epoch.
fn unix_time(t: SystemTime) -> (i64, u32) {
    let d = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    (
        i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        d.subsec_micros(),
    )
}

/// Proleptic Gregorian date from days since 1970-01-01 (H. Hinnant, "chrono-Compatible
/// Low-Level Date Algorithms", `civil_from_days`).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // month 1..=12, day 1..=31
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// UTC calendar date and time of day.
struct UtcParts {
    year: i64,
    month: u32,
    day: u32,
    hour: i64,
    minute: i64,
    second: i64,
    micros: u32,
}

fn utc_parts(t: SystemTime) -> UtcParts {
    let (secs, micros) = unix_time(t);
    let (year, month, day) = civil_from_days(secs.div_euclid(SECS_PER_DAY));
    let sod = secs.rem_euclid(SECS_PER_DAY);
    UtcParts {
        year,
        month,
        day,
        hour: sod / 3600,
        minute: sod % 3600 / 60,
        second: sod % 60,
        micros,
    }
}

/// RFC 3339 UTC timestamp with microseconds, e.g. `2026-11-02T14:05:09.123456Z`.
fn rfc3339(t: SystemTime) -> String {
    let p = utc_parts(t);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        p.year, p.month, p.day, p.hour, p.minute, p.second, p.micros
    )
}

/// Compact UTC stamp for file names, e.g. `20261102T140509Z`.
fn file_stamp(t: SystemTime) -> String {
    let p = utc_parts(t);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        p.year, p.month, p.day, p.hour, p.minute, p.second
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use rustegon_sim_api::{BoxFuture, StdFileSystem};
    use tracing::{info, warn};

    use super::*;
    use crate::Redacted;

    /// Wall clock under test control.
    struct FakeClock(Mutex<SystemTime>);

    impl FakeClock {
        fn at(unix_secs: u64) -> Arc<Self> {
            Arc::new(Self(Mutex::new(
                SystemTime::UNIX_EPOCH + Duration::from_secs(unix_secs),
            )))
        }
        fn advance(&self, d: Duration) {
            *self.0.lock().unwrap() += d;
        }
    }

    impl Clock for FakeClock {
        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
        fn wall(&self) -> SystemTime {
            *self.0.lock().unwrap()
        }
        fn sleep(&self, _: Duration) -> BoxFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    /// 2026-11-02T23:59:00Z
    const T0: u64 = 1_793_663_940;

    fn settings(max_file_size: u64, max_files: u64) -> LogSettings {
        LogSettings {
            max_file_size,
            max_files,
            ..LogSettings::default()
        }
    }

    /// Runs `f` with a subscriber writing to `dir`, then flushes and returns the lines per file
    /// (files in name order, i.e. chronological).
    fn capture(
        dir: &Path,
        s: &LogSettings,
        clock: &Arc<FakeClock>,
        f: impl FnOnce(&FakeClock),
    ) -> Vec<Vec<String>> {
        let ctx = LogContext {
            fs: Arc::new(StdFileSystem),
            clock: Arc::clone(clock) as Arc<dyn Clock>,
            node_id: Some("n1".into()),
        };
        let (layer, guard) = json_file_layer(s, dir, ctx).unwrap();
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || f(clock));
        drop(guard);
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        files
            .iter()
            .map(|p| {
                std::fs::read_to_string(p)
                    .unwrap()
                    .lines()
                    .map(str::to_owned)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn tc_ops_002_json_lines_have_required_fields() {
        let dir = tempfile::tempdir().unwrap();
        let files = capture(
            dir.path(),
            &LogSettings::default(),
            &FakeClock::at(T0),
            |_| {
                info!(user = "bob", count = 3, "hello {}", "world");
                warn!(target: "audit", trace_id = "4bf92f3577b34da6", ts = "x", "audited");
            },
        );
        assert_eq!(files.len(), 1);
        let lines: Vec<Value> = files[0]
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        let first = &lines[0];
        assert_eq!(first["ts"], "2026-11-02T23:59:00.000000Z");
        assert_eq!(first["level"], "INFO");
        assert_eq!(first["node_id"], "n1");
        assert_eq!(first["channel"], "main");
        assert_eq!(first["msg"], "hello world");
        assert_eq!(first["trace_id"], Value::Null);
        assert_eq!(first["user"], "bob");
        assert_eq!(first["count"], 3);
        let second = &lines[1];
        assert_eq!(second["channel"], "audit");
        assert_eq!(second["level"], "WARN");
        assert_eq!(second["trace_id"], "4bf92f3577b34da6");
        assert_eq!(second["ts"], "2026-11-02T23:59:00.000000Z");
        assert_eq!(
            second["field.ts"], "x",
            "colliding field must not override ts"
        );
    }

    #[test]
    fn tc_ops_002_rotates_by_size_and_keeps_max_files() {
        let dir = tempfile::tempdir().unwrap();
        let files = capture(dir.path(), &settings(400, 3), &FakeClock::at(T0), |_| {
            for i in 0..40 {
                info!(i, "padding line to fill the file");
            }
        });
        assert_eq!(files.len(), 3, "retention must keep exactly max_files");
        for f in &files {
            let bytes: usize = f.iter().map(|l| l.len() + 1).sum();
            assert!(bytes <= 400, "file of {bytes} bytes exceeds max_file_size");
        }
        // The newest file holds the last line.
        let last: Value = serde_json::from_str(files[2].last().unwrap()).unwrap();
        assert_eq!(last["i"], 39);
    }

    #[test]
    fn tc_ops_002_rotates_daily_utc() {
        let dir = tempfile::tempdir().unwrap();
        let files = capture(
            dir.path(),
            &LogSettings::default(),
            &FakeClock::at(T0),
            |clock| {
                info!("before midnight");
                clock.advance(Duration::from_secs(30));
                info!("still same day");
                clock.advance(Duration::from_secs(60)); // crosses 2026-11-03T00:00:00Z
                info!("next day");
            },
        );
        assert_eq!(files.iter().map(Vec::len).collect::<Vec<_>>(), [2, 1]);
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("rustegon-20261102T235900Z-")),
            "{names:?}"
        );
        assert!(
            names.iter().any(|n| n.starts_with("rustegon-20261103T")),
            "{names:?}"
        );
    }

    #[test]
    fn tc_ops_003_redacted_values_never_reach_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret = Redacted::new(String::from("CANARY-9f8e7d"));
        let files = capture(
            dir.path(),
            &LogSettings::default(),
            &FakeClock::at(T0),
            |_| {
                info!(password = ?secret, token = %secret, "login {:?}", secret);
            },
        );
        let all = files.concat().join("\n");
        assert!(!all.contains("CANARY"), "secret leaked into log: {all}");
        assert!(all.contains(crate::redacted::REDACTED));
    }

    #[test]
    fn log_settings_validate_level_directives() {
        assert!(LogSettings::default().validate().is_ok());
        let ok = LogSettings {
            level: "info,rustegon_storage=debug".into(),
            ..LogSettings::default()
        };
        assert!(ok.validate().is_ok());
        let bad = LogSettings {
            level: "info,=bogus=".into(),
            ..LogSettings::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn civil_dates_and_timestamps() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        let t = SystemTime::UNIX_EPOCH + Duration::from_micros(1_793_663_940_123_456);
        assert_eq!(rfc3339(t), "2026-11-02T23:59:00.123456Z");
        assert_eq!(file_stamp(t), "20261102T235900Z");
    }
}
