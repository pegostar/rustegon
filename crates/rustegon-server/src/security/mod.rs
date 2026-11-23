// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Security wiring of the server: authentication of every request, RBAC enforcement, audit,
//! rate limiting, lockout, the system store and runtime settings (security.md §2–§4, §8;
//! FR-SEC-001…006; PD-051).
//!
//! [`Security`] is shared by every front end (gRPC gate, `AuthService`, `AdminService`, and the REST
//! layer of lane I). The rules it implements:
//!
//! - **Credentials** ([`Security::authenticate`]): `authorization: Bearer <session token>` →
//!   session validation (idle/absolute expiry, credential epoch; `RGN-4005` when expired);
//!   `authorization: ApiKey rgn_…` → API key (expiry, CIDR allowlist, Argon2id through the
//!   verified-key cache); no `authorization` on a connection with a verified client
//!   certificate → X.509 mapping (`x509:` user or `node:<CN>`); nothing → anonymous. Any
//!   rejected credential is the uniform `RGN-4001`.
//! - **Privileges**: the principal's roles are resolved against the built-in and the stored
//!   custom roles in the same transaction that validated the credential, so a role change is
//!   visible on the next request. [`Security::require`] checks one action and audits a denial
//!   (`privilege_denied`) before returning `RGN-4002`.
//! - **Rate limits** (`[rate_limit]`): every request per source IP (and per user when
//!   configured); every authentication attempt — SCRAM handshake, X.509 login, API key
//!   presentation that misses the verified-key cache — in the authentication class, so the
//!   Argon2id and PBKDF2 work an address can trigger is bounded. Rejections are `RGN-4003`
//!   with `ErrorDetail.retry_after_ms`, and are not audited (security.md §4).
//! - **Lockout** (`[lockout]`): checked before any password is verified (`RGN-4007`).
//! - **Audit**: every record is written (synced) on the blocking pool before the client sees
//!   the outcome. Logins fail closed when their audit record cannot be written; for committed
//!   administrative changes the failure is logged at error level and the success is still
//!   reported, because reporting a committed change as failed would be worse (PD-051).
//!
//! Engine work runs through the [`crate::Executor`] (`Completion::Await` whenever the
//! transaction may write), audit and Argon2id/PBKDF2 on the blocking pool: nothing blocks an
//! async worker.

mod bootstrap;
mod privileges;
mod settings;
mod store;

use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

pub use bootstrap::{BootstrapOutcome, INITIAL_ADMIN_PASSWORD_FILE, write_initial_password};
pub use privileges::{
    Access, HTTP_ACCESS, METRICS_ENDPOINT, RPC_ACCESS, RpcAccess, access_of, service_of,
};
use rustegon_common::{
    Error, ErrorCode,
    settings::{Registry, Sources},
};
use rustegon_engine::EmbeddedDb;
use rustegon_security::{
    audit::{AuditEvent, AuditEventKind, AuditLog, AuditLogConfig, AuditOutcome, AuditSettings},
    authn::{
        self, AuthnError, AuthnSettings, FailureReason, SecretString, SystemTxn,
        apikey::{ARGON2_COST, Argon2Cost, KEY_ID_LEN, KEY_PREFIX},
        keycache::{DEFAULT_MAX_ENTRIES, DEFAULT_TTL, KeyLookup, PendingKey, VerifiedKeyCache},
        secret, session, x509,
    },
    lockout::{LockoutSettings, LockoutTracker},
    ratelimit::{LimitClass, RateLimitSettings, RateLimiter},
    rbac::{Action, Resource, ResourceKind, permission_denied, store::load_roles},
};
use rustegon_sim_api::{BoxFuture, Clock, FileSystem, Rng};
pub use settings::{
    MAX_VALUE_LEN, RuntimeSettings, SETTING_FORMAT, SUB_SETTING, SettingInfo, SettingRecord,
    decode_setting, encode_setting, load_overrides, override_mutations, register_security_settings,
    setting_key, setting_prefix,
};
pub use store::{EngineTxn, Reader};

use crate::{
    Completion, ConnectionInfo, Executor,
    services::{Principal, PrincipalResolver, RequestContext, ServiceDeps, unauthenticated},
};

/// Inputs of [`Security::open`].
pub struct SecurityConfig {
    /// The node's engine (system keyspace).
    pub engine: Arc<EmbeddedDb>,
    /// File system of the audit log.
    pub fs: Arc<dyn FileSystem>,
    /// Data directory (`<data_dir>/audit` is the default audit directory).
    pub data_dir: PathBuf,
    /// Node name written in audit records.
    pub node_name: String,
    /// Settings registry with at least the sections of [`register_security_settings`].
    pub registry: Arc<Registry>,
    /// Startup configuration layers (file, environment, flags).
    pub sources: Sources,
    /// The configuration file `sources.file` was read from, when static settings may be written
    /// to it (PD-230, `RuntimeSettings::with_config_file`); `None`: static settings read-only.
    pub config_file: Option<PathBuf>,
    /// Argon2id cost of new API keys: [`ARGON2_COST`] in production; tests lower it.
    pub api_key_cost: Argon2Cost,
    /// Lifetime of a cached API key verification.
    pub key_cache_ttl: Duration,
    /// Bound on cached API key verifications.
    pub key_cache_entries: usize,
}

impl std::fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("data_dir", &self.data_dir)
            .field("node_name", &self.node_name)
            .finish_non_exhaustive()
    }
}

impl SecurityConfig {
    /// Lets static settings be written to `path` (see [`Self::config_file`]).
    #[must_use]
    pub fn with_config_file(mut self, path: Option<PathBuf>) -> Self {
        self.config_file = path;
        self
    }

    /// A configuration with production defaults for the API key parameters.
    #[must_use]
    pub fn new(
        engine: Arc<EmbeddedDb>,
        fs: Arc<dyn FileSystem>,
        data_dir: PathBuf,
        node_name: impl Into<String>,
        registry: Arc<Registry>,
        sources: Sources,
    ) -> Self {
        Self {
            engine,
            fs,
            data_dir,
            node_name: node_name.into(),
            registry,
            sources,
            config_file: None,
            api_key_cost: ARGON2_COST,
            key_cache_ttl: DEFAULT_TTL,
            key_cache_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// Shared security state of a node (module docs).
pub struct Security {
    engine: Arc<EmbeddedDb>,
    /// The node's file system (audit log; backup destinations of `BackupService`, PD-077).
    fs: Arc<dyn FileSystem>,
    executor: Executor,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    settings: RuntimeSettings,
    authn: RwLock<AuthnSettings>,
    audit: Option<Arc<AuditLog>>,
    audit_settings: AuditSettings,
    limiter: RateLimiter,
    lockout: LockoutTracker,
    keys: Arc<VerifiedKeyCache>,
    api_key_cost: Argon2Cost,
    settings_update: tokio::sync::Mutex<()>,
    counters: SecurityCounters,
}

/// Monotonic counters of security events, exported at `/metrics` (PD-059). `Relaxed`: each is
/// an independent statistic, read only for reporting.
#[derive(Debug, Default)]
pub struct SecurityCounters {
    auth_failures: AtomicU64,
    lockouts: AtomicU64,
    audit_write_failures: AtomicU64,
    /// Indexed by [`LIMIT_CLASSES`].
    rate_limited: [AtomicU64; 4],
}

/// The rate limit classes, in the order of [`SecurityCounters::rate_limited`].
pub const LIMIT_CLASSES: [LimitClass; 4] = [
    LimitClass::Authentication,
    LimitClass::SessionCreation,
    LimitClass::Request,
    LimitClass::AdminOp,
];

impl SecurityCounters {
    /// Failed authentications (every `login_failure` event: wrong password, unknown user,
    /// rejected API key or certificate), audited or not.
    #[must_use]
    pub fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    /// Accounts locked by the lockout policy (`account_locked` events).
    #[must_use]
    pub fn lockouts(&self) -> u64 {
        self.lockouts.load(Ordering::Relaxed)
    }

    /// Audit records that could not be written.
    #[must_use]
    pub fn audit_write_failures(&self) -> u64 {
        self.audit_write_failures.load(Ordering::Relaxed)
    }

    /// Requests rejected by the rate limiter in `class` (`RGN-4003`).
    #[must_use]
    pub fn rate_limited(&self, class: LimitClass) -> u64 {
        LIMIT_CLASSES
            .iter()
            .position(|c| *c == class)
            .map_or(0, |i| self.rate_limited[i].load(Ordering::Relaxed))
    }

    fn count_rate_limited(&self, class: LimitClass) {
        if let Some(i) = LIMIT_CLASSES.iter().position(|c| *c == class) {
            self.rate_limited[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts the security events of `kind` (called for every event before the audit filter,
    /// so the counters do not depend on the audit configuration).
    fn count_event(&self, kind: AuditEventKind) {
        match kind {
            AuditEventKind::LoginFailure => {
                self.auth_failures.fetch_add(1, Ordering::Relaxed);
            }
            AuditEventKind::AccountLocked => {
                self.lockouts.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

impl std::fmt::Debug for Security {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Security")
            .field("audit", &self.audit.is_some())
            .finish_non_exhaustive()
    }
}

/// Splits `<scheme> <value>` with a case-insensitive scheme (RFC 9110 §11.1).
pub(crate) fn credential<'a>(raw: &'a str, scheme: &str) -> Option<&'a str> {
    let (s, rest) = raw.split_once(' ')?;
    let rest = rest.trim_start_matches(' ');
    (s.eq_ignore_ascii_case(scheme) && !rest.is_empty()).then_some(rest)
}

/// The non-secret key id of a presented API key, for audit records.
pub(crate) fn key_id_of(presented: &str) -> Option<&str> {
    presented
        .strip_prefix(KEY_PREFIX)?
        .get(..KEY_ID_LEN)
        .filter(|id| id.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn reason_text(e: &AuthnError) -> &'static str {
    match e {
        AuthnError::AuthenticationFailed(r) => match r {
            FailureReason::BadCredentials => "bad_credentials",
            FailureReason::NonceMismatch => "nonce_mismatch",
            FailureReason::ChannelBinding => "channel_binding",
            FailureReason::Malformed => "malformed",
            FailureReason::Expired => "expired",
            FailureReason::AddressNotAllowed => "address_not_allowed",
        },
        AuthnError::SessionExpired => "session_expired",
        _ => "error",
    }
}

/// Resolves the privileges of an authentication result in the same transaction.
///
/// # Errors
/// Store errors; a corrupt role record.
pub fn resolve(txn: &dyn SystemTxn, principal: authn::Principal) -> Result<Principal, Error> {
    let catalog = load_roles(&Reader(txn)).map_err(Error::from)?;
    let privileges = catalog.resolve(&principal.roles);
    Ok(Principal::resolved(principal, privileges))
}

/// The authentication layer of both front ends (PD-052 extension point): gRPC's gate and REST's
/// `Ctx` extractor call it with the request's connection.
impl PrincipalResolver for Security {
    fn resolve<'a>(
        &'a self,
        ctx: &'a RequestContext,
        conn: Option<&'a ConnectionInfo>,
    ) -> BoxFuture<'a, Result<Option<Principal>, Error>> {
        Box::pin(async move {
            match conn {
                Some(conn) if ctx.peer().is_none() => {
                    let ctx = ctx.clone().with_peer(Some(conn.clone()));
                    self.authenticate(&ctx).await
                }
                _ => self.authenticate(ctx).await,
            }
        })
    }
}

enum KeyStep {
    Done(Principal),
    Pending(Box<PendingKey>),
    Failed(AuthnError),
}

impl Security {
    /// Opens the security layer: loads the persisted setting overrides, builds the effective
    /// configuration, opens the audit log (when enabled) and the in-memory limiters. Blocking
    /// (store read, audit recovery): call it at startup or from a blocking thread.
    ///
    /// # Errors
    /// Configuration errors (`RGN-1001`, including an unsupported audit sink), store errors,
    /// audit log recovery errors (a corrupt chain refuses to open, security.md §4).
    pub fn open(config: SecurityConfig, deps: &ServiceDeps) -> Result<Arc<Self>, Error> {
        let overrides = config
            .engine
            .system_transaction(|h| load_overrides(&EngineTxn(h)))?;
        let settings = RuntimeSettings::open(config.registry, config.sources, overrides)?
            .with_config_file(config.config_file, config.fs.as_ref());
        let effective = settings.config();
        let authn: AuthnSettings = effective.section()?;
        let audit_settings: AuditSettings = effective.section()?;
        let rate: RateLimitSettings = effective.section()?;
        let lockout: LockoutSettings = effective.section()?;
        let audit = if audit_settings.enabled {
            if audit_settings.sink != "file" {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("audit.sink {:?} is not supported yet", audit_settings.sink),
                ));
            }
            let log = AuditLog::open(
                Arc::clone(&config.fs),
                Arc::clone(&deps.clock),
                AuditLogConfig {
                    dir: audit_settings.dir_for(&config.data_dir),
                    node: config.node_name,
                    max_file_size: audit_settings.max_file_size,
                    max_files: audit_settings.max_files,
                },
            )?;
            Some(Arc::new(log))
        } else {
            None
        };
        Ok(Arc::new(Self {
            engine: config.engine,
            fs: config.fs,
            executor: deps.executor.clone(),
            clock: Arc::clone(&deps.clock),
            rng: Arc::clone(&deps.rng),
            settings,
            authn: RwLock::new(authn),
            audit,
            audit_settings,
            limiter: RateLimiter::new(Arc::clone(&deps.clock), rate.to_config()),
            lockout: LockoutTracker::new(Arc::clone(&deps.clock), lockout.to_policy()),
            keys: Arc::new(VerifiedKeyCache::new(
                deps.rng.as_ref(),
                config.key_cache_ttl,
                config.key_cache_entries,
            )),
            api_key_cost: config.api_key_cost,
            settings_update: tokio::sync::Mutex::new(()),
            counters: SecurityCounters::default(),
        }))
    }

    /// Security event counters (`/metrics`).
    #[must_use]
    pub fn counters(&self) -> &SecurityCounters {
        &self.counters
    }

    /// Sessions that are not expired (`/metrics`; reads every session record).
    ///
    /// # Errors
    /// Store errors.
    pub async fn active_sessions(&self, ctx: &RequestContext) -> Result<usize, Error> {
        let settings = self.authn_settings();
        let now = self.clock.wall();
        self.transact(ctx, Completion::Abandon, move |t| {
            session::count_active_sessions(&*t, &settings, now).map_err(Error::from)
        })
        .await
    }

    /// The current `[auth]` settings (runtime-mutable).
    #[must_use]
    pub fn authn_settings(&self) -> AuthnSettings {
        self.authn
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The runtime settings.
    #[must_use]
    pub fn settings(&self) -> &RuntimeSettings {
        &self.settings
    }

    /// The engine.
    #[must_use]
    pub fn engine(&self) -> &Arc<EmbeddedDb> {
        &self.engine
    }

    /// The node's file system (the one the audit log uses).
    #[must_use]
    pub fn fs(&self) -> &Arc<dyn FileSystem> {
        &self.fs
    }

    /// The lockout tracker (admin unlock, tests).
    #[must_use]
    pub fn lockout(&self) -> &LockoutTracker {
        &self.lockout
    }

    /// The verified API key cache.
    #[must_use]
    pub fn key_cache(&self) -> &VerifiedKeyCache {
        &self.keys
    }

    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub(crate) fn rng(&self) -> &Arc<dyn Rng> {
        &self.rng
    }

    pub(crate) fn api_key_cost(&self) -> Argon2Cost {
        self.api_key_cost
    }

    /// Serializes runtime settings updates: each update is validated against the overrides
    /// in force, so two concurrent updates must not both validate against the same state.
    pub(crate) fn settings_update_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.settings_update
    }

    /// Re-reads the runtime-mutable `[auth]` settings after an update.
    pub(crate) fn reload_runtime_settings(&self) -> Result<(), Error> {
        let authn: AuthnSettings = self.settings.config().section()?;
        *self.authn.write().unwrap_or_else(PoisonError::into_inner) = authn;
        Ok(())
    }

    /// Runs CPU-bound `work` (PBKDF2, Argon2id) on the executor, outside any transaction: a
    /// key derivation inside [`Self::transact`] would keep the transaction open for its whole
    /// duration — long enough on slow hardware to be aborted for liveness (`timeout_pushed`)
    /// — and be repeated on every retry of the body.
    ///
    /// # Errors
    /// The work's error, executor errors.
    pub async fn compute<T, F>(&self, ctx: &RequestContext, work: F) -> Result<T, Error>
    where
        F: FnOnce() -> Result<T, Error> + Send + 'static,
        T: Send + 'static,
    {
        let mut work = Some(work);
        self.executor
            .run(ctx, Completion::Await, move |_token| match work.take() {
                Some(w) => w(),
                None => Err(Error::new(ErrorCode::Internal, "compute ran twice")),
            })
            .await
    }

    /// Runs `body` in one system-keyspace transaction on the executor (module docs). Use
    /// [`Completion::Await`] whenever the body may write.
    ///
    /// # Errors
    /// The body's error (nothing written), transaction and executor errors.
    pub async fn transact<T, F>(
        &self,
        ctx: &RequestContext,
        completion: Completion,
        mut body: F,
    ) -> Result<T, Error>
    where
        F: FnMut(&mut dyn SystemTxn) -> Result<T, Error> + Send + 'static,
        T: Send + 'static,
    {
        let engine = Arc::clone(&self.engine);
        self.executor
            .run(ctx, completion, move |_token| {
                engine.system_transaction(|h| body(&mut EngineTxn(h)))
            })
            .await
    }

    /// Charges one request of `class` to `user` and `ip` (`RGN-4003` when over the limit).
    ///
    /// # Errors
    /// `RGN-4003` with detail `retry_after_ms`.
    pub fn rate_limit(
        &self,
        class: LimitClass,
        user: Option<&str>,
        ip: Option<IpAddr>,
    ) -> Result<(), Error> {
        let result = self.limiter.check(class, user, ip);
        if result.is_err() {
            self.counters.count_rate_limited(class);
        }
        result
    }

    /// An audit event pre-filled from the request: user and roles of the principal (if any),
    /// source address.
    #[must_use]
    pub fn event(
        &self,
        ctx: &RequestContext,
        kind: AuditEventKind,
        outcome: AuditOutcome,
    ) -> AuditEvent {
        let mut e = AuditEvent::new(kind, outcome);
        if let Some(p) = ctx.principal() {
            e = e.user(p.user.clone()).roles(p.roles.iter().cloned());
        }
        if let Some(peer) = ctx.peer() {
            e = e.source_ip(peer.remote_addr.ip());
        }
        e
    }

    /// Writes `event` durably (on the blocking pool) when auditing is enabled for its kind.
    ///
    /// # Errors
    /// `RGN-5001` when the record cannot be written; the log then refuses further records
    /// until the node restarts (security-relevant operations fail closed).
    pub async fn audit(&self, event: AuditEvent) -> Result<(), Error> {
        self.counters.count_event(event.kind());
        let Some(log) = self.audit.as_ref().map(Arc::clone) else {
            return Ok(());
        };
        if !self.audit_settings.records(event.kind()) {
            return Ok(());
        }
        let result = tokio::task::spawn_blocking(move || log.record(&event))
            .await
            .map_err(|_| Error::new(ErrorCode::Internal, "audit task failed"))
            .and_then(|r| r.map(|_| ()).map_err(Error::from));
        if result.is_err() {
            self.counters
                .audit_write_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// [`Security::audit`] for events whose operation already happened (failures, denials,
    /// committed changes): an audit error is logged, not returned (module docs).
    pub async fn audit_or_log(&self, event: AuditEvent) {
        let kind = event.kind();
        if let Err(e) = self.audit(event).await {
            tracing::error!(event = %kind, error = %e, "audit record could not be written");
        }
    }

    /// Checks `action` on `resource` for the request's principal; a denial is audited
    /// (`privilege_denied`) and returned as `RGN-4002`. The entry point for handlers that check
    /// database or collection privileges (lane G) and for the gRPC gate.
    ///
    /// # Errors
    /// `RGN-4001` without a principal, `RGN-4002` when denied.
    pub async fn require(
        &self,
        ctx: &RequestContext,
        resource: &Resource,
        action: Action,
    ) -> Result<(), Error> {
        let principal = ctx.require_principal()?;
        if principal.allows(resource, action) {
            return Ok(());
        }
        let event = self
            .event(ctx, AuditEventKind::PrivilegeDenied, AuditOutcome::Denied)
            .resource(resource.to_string())
            .action(action.as_str());
        self.audit_or_log(event).await;
        Err(permission_denied(resource, action))
    }

    /// The checks of `rule` that need no request payload: password-change restriction and
    /// cluster-level privileges. The principal must be set on `ctx`.
    ///
    /// # Errors
    /// `RGN-4001` without a principal, `RGN-4002` (detail `reason = password_change_required`
    /// for a principal that must change its password first).
    pub async fn admit(&self, ctx: &RequestContext, rule: &RpcAccess) -> Result<(), Error> {
        let principal = ctx.require_principal()?;
        if principal.password_change == authn::PasswordChange::Required
            && !rule.during_password_change
        {
            let event = self
                .event(ctx, AuditEventKind::PrivilegeDenied, AuditOutcome::Denied)
                .detail("endpoint", rule.method)
                .detail("reason", "password_change_required");
            self.audit_or_log(event).await;
            return Err(Error::new(
                ErrorCode::PermissionDenied,
                "the password must be changed before any other operation",
            )
            .with_detail("reason", "password_change_required"));
        }
        if let Access::Privilege(actions, ResourceKind::Cluster) = rule.access {
            for action in actions {
                self.require(ctx, &Resource::Cluster, *action).await?;
            }
        }
        Ok(())
    }

    /// Authenticates the request's credentials (module docs); `None` when it carries none.
    ///
    /// # Errors
    /// `RGN-4001` for rejected credentials or an unsupported `authorization` scheme,
    /// `RGN-4005` for an expired or revoked session, `RGN-4003` when API key or certificate
    /// verifications from this address exceed the authentication rate limit, store errors.
    pub async fn authenticate(&self, ctx: &RequestContext) -> Result<Option<Principal>, Error> {
        if let Some(raw) = ctx.credentials() {
            let raw = raw.expose();
            if let Some(token) = credential(raw, "Bearer") {
                return self.session_principal(ctx, secret(token)).await.map(Some);
            }
            if let Some(key) = credential(raw, "ApiKey") {
                return self.api_key_principal(ctx, secret(key)).await.map(Some);
            }
            return Err(unauthenticated());
        }
        let leaf = ctx
            .peer()
            .and_then(|p| p.peer_certificates.as_ref())
            .and_then(|chain| chain.first().cloned());
        match leaf {
            Some(der) => self
                .certificate_principal(ctx, der.as_ref().to_vec())
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn session_principal(
        &self,
        ctx: &RequestContext,
        token: SecretString,
    ) -> Result<Principal, Error> {
        let settings = self.authn_settings();
        let now = self.clock.wall();
        // The outer `Ok` commits the transaction even when validation fails, so the cleanup of
        // an expired or revoked session (and the `last_seen` refresh) is kept.
        self.transact(ctx, Completion::Await, move |t| {
            Ok(session::validate_session(t, token.expose(), &settings, now)
                .map_err(Error::from)
                .and_then(|p| resolve(t, p)))
        })
        .await?
    }

    fn client_ip(ctx: &RequestContext) -> IpAddr {
        // Internal calls have no peer; the unspecified address matches no allowlist.
        ctx.peer()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |p| p.remote_addr.ip())
    }

    async fn api_key_principal(
        &self,
        ctx: &RequestContext,
        presented: SecretString,
    ) -> Result<Principal, Error> {
        let ip = Self::client_ip(ctx);
        let now = self.clock.wall();
        let mono = self.clock.monotonic();
        let keys = Arc::clone(&self.keys);
        let key_id = key_id_of(presented.expose()).map(str::to_owned);
        let presented_txn = presented.clone();
        let step = self
            .transact(ctx, Completion::Abandon, move |t| {
                Ok(
                    match keys.lookup(t, presented_txn.expose(), ip, now, mono) {
                        Ok(KeyLookup::Verified(p)) => KeyStep::Done(resolve(t, p)?),
                        Ok(KeyLookup::Pending(pending)) => KeyStep::Pending(pending),
                        Err(e @ AuthnError::AuthenticationFailed(_)) => KeyStep::Failed(e),
                        Err(e) => return Err(e.into()),
                    },
                )
            })
            .await?;
        let pending = match step {
            KeyStep::Done(p) => return Ok(p),
            KeyStep::Failed(e) => {
                // A failed presentation is an authentication attempt: charge it, so unknown
                // key ids cannot be probed (or the audit log flooded) at the request rate.
                self.rate_limit(LimitClass::Authentication, None, Some(ip))?;
                return Err(self.key_failure(ctx, key_id.as_deref(), e).await);
            }
            KeyStep::Pending(p) => p,
        };
        // A cache miss costs one Argon2id verification: bounded per address by the
        // authentication rate limit before the work is done.
        self.rate_limit(LimitClass::Authentication, None, Some(ip))?;
        let keys = Arc::clone(&self.keys);
        let verified = self
            .executor
            .run(ctx, Completion::Await, move |_| {
                Ok(pending.verify(&keys, mono))
            })
            .await?;
        let principal = match verified {
            Ok(p) => p,
            Err(e) => return Err(self.key_failure(ctx, key_id.as_deref(), e).await),
        };
        let user = principal.user.clone();
        let resolved = self
            .transact(ctx, Completion::Abandon, move |t| {
                resolve(t, principal.clone())
            })
            .await?;
        let mut event = self
            .event(ctx, AuditEventKind::LoginSuccess, AuditOutcome::Success)
            .user(user)
            .roles(resolved.roles.iter().cloned())
            .detail("mechanism", "api_key");
        if let Some(id) = &key_id {
            event = event.detail("key_id", id.clone());
        }
        // Logins fail closed: no audit record, no access.
        self.audit(event).await?;
        Ok(resolved)
    }

    async fn key_failure(
        &self,
        ctx: &RequestContext,
        key_id: Option<&str>,
        e: AuthnError,
    ) -> Error {
        let mut event = self
            .event(ctx, AuditEventKind::LoginFailure, AuditOutcome::Failure)
            .detail("mechanism", "api_key")
            .detail("reason", reason_text(&e));
        if let Some(id) = key_id {
            event = event.detail("key_id", id);
        }
        self.audit_or_log(event).await;
        Error::from(e)
    }

    async fn certificate_principal(
        &self,
        ctx: &RequestContext,
        der: Vec<u8>,
    ) -> Result<Principal, Error> {
        let result = self
            .transact(ctx, Completion::Abandon, move |t| {
                Ok(match x509::authenticate_certificate(t, &der) {
                    Ok(p) => Ok(resolve(t, p)?),
                    Err(e @ AuthnError::AuthenticationFailed(_)) => Err(e),
                    Err(e) => return Err(e.into()),
                })
            })
            .await?;
        match result {
            Ok(p) => Ok(p),
            Err(e) => {
                self.rate_limit(LimitClass::Authentication, None, Some(Self::client_ip(ctx)))?;
                let event = self
                    .event(ctx, AuditEventKind::LoginFailure, AuditOutcome::Failure)
                    .detail("mechanism", "x509")
                    .detail("reason", reason_text(&e));
                self.audit_or_log(event).await;
                Err(e.into())
            }
        }
    }
}
