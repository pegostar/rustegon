// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Hot-reloadable certificate and key (FR-TLS-003, security.md §5).
//!
//! [`ReloadableCert`] holds the current `CertifiedKey` and is installed as the rustls server
//! certificate resolver (and as the client-certificate resolver of peer connections). Every
//! handshake asks it for the key, so a swap takes effect for the next handshake without
//! restarting the listener; established connections keep the key they negotiated with.
//!
//! Reload triggers: [`ReloadableCert::reload`] on demand, the periodic poll of
//! [`ReloadableCert::run_poll`] (1 h default, sim-api [`Clock`]), and
//! [`ReloadableCert::trigger`], which the binary wires to SIGHUP and the file watcher.
//!
//! Failure semantics: a reload that fails (unreadable file, bad PEM, key not matching the
//! certificate, certificate expired or not yet valid) keeps serving the previous certificate,
//! records the error ([`ReloadableCert::last_error`]) and logs it. Certificate and key files are
//! replaced by operators non-atomically (two files), so a poll that observes a new certificate
//! with the old key fails the key-match check and is retried by the next trigger or poll.
//!
//! Concurrency: `state` is the only lock; it is held only to clone or swap an `Arc`, never across
//! I/O or `.await`, so handshakes on executor threads never wait on file reads. Reloads read the
//! files before taking the lock; two concurrent reloads may both read, the last swap wins, and
//! both installed values are valid.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
};

use rustegon_common::Redacted;
use rustegon_sim_api::{Clock, FileSystem};
use rustls::{
    SignatureScheme,
    client::ResolvesClientCert,
    crypto::CryptoProvider,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::sync::Notify;

use crate::{
    TlsError,
    pem::{not_after_unix, parse_certificates, parse_private_key, read_file},
};

/// Default period of the reload poll (security.md §5: "1 h poll").
pub const DEFAULT_RELOAD_POLL: Duration = Duration::from_hours(1);

/// Where a certificate chain and its private key are read from (paths, never inline PEM;
/// security.md §7).
#[derive(Clone)]
pub struct CertSource {
    fs: Arc<dyn FileSystem>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl CertSource {
    /// A PEM certificate chain file (leaf first) and a PEM private key file.
    #[must_use]
    pub fn new(
        fs: Arc<dyn FileSystem>,
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            fs,
            cert_path: cert_path.into(),
            key_path: key_path.into(),
        }
    }

    /// The certificate chain file.
    #[must_use]
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// The private key file.
    #[must_use]
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }
}

impl fmt::Debug for CertSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertSource")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .finish_non_exhaustive()
    }
}

/// Result of a successful [`ReloadableCert::reload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// The files are byte-identical to the served ones; nothing changed.
    Unchanged,
    /// A new certificate is served from the next handshake on.
    Replaced {
        /// The new generation number (starts at 0 for the initial load).
        generation: u64,
    },
}

/// One validated certificate/key pair.
struct Loaded {
    key: Arc<CertifiedKey>,
    /// Raw file contents, kept to detect "unchanged" on a poll without re-validating. The key
    /// file bytes are as secret as the signing key already held in `key`.
    cert_file: Vec<u8>,
    key_file: Redacted<Vec<u8>>,
    not_after_unix: i64,
}

/// A certificate/key pair that can be swapped at runtime (FR-TLS-003). See the module docs.
pub struct ReloadableCert {
    source: CertSource,
    provider: Arc<CryptoProvider>,
    clock: Arc<dyn Clock>,
    state: RwLock<Arc<Loaded>>,
    generation: AtomicU64,
    last_error: Mutex<Option<String>>,
    trigger: Notify,
}

impl ReloadableCert {
    /// Loads the initial certificate and key. Unlike a reload, failure here is fatal to the
    /// caller: a listener must not start without a valid certificate.
    ///
    /// # Errors
    /// Any [`TlsError`] from reading, parsing or validating the pair (see [`Self::reload`]).
    pub fn load(
        source: CertSource,
        provider: Arc<CryptoProvider>,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, TlsError> {
        let loaded = read_and_validate(&source, &provider, clock.as_ref())?;
        Ok(Arc::new(Self {
            source,
            provider,
            clock,
            state: RwLock::new(Arc::new(loaded)),
            generation: AtomicU64::new(0),
            last_error: Mutex::new(None),
            trigger: Notify::new(),
        }))
    }

    /// Re-reads the certificate and key files and swaps them in if they changed and are valid.
    /// On error the previously loaded pair stays in use and the error is recorded in
    /// [`Self::last_error`]; on success the recorded error is cleared.
    ///
    /// Performs two small synchronous file reads (a few KiB, once per trigger or poll).
    ///
    /// # Errors
    /// [`TlsError::Io`], [`TlsError::Pem`], [`TlsError::NoCertificate`],
    /// [`TlsError::NoPrivateKey`], [`TlsError::Rustls`] (unsupported key, key/cert mismatch),
    /// [`TlsError::Certificate`], [`TlsError::Expired`].
    pub fn reload(&self) -> Result<ReloadOutcome, TlsError> {
        let result = self.try_reload();
        let mut last = self
            .last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match &result {
            Ok(_) => *last = None,
            Err(e) => *last = Some(e.to_string()),
        }
        result
    }

    fn try_reload(&self) -> Result<ReloadOutcome, TlsError> {
        let fs = self.source.fs.as_ref();
        let cert_file = read_file(fs, &self.source.cert_path)?;
        let key_file = Redacted::new(read_file(fs, &self.source.key_path)?);
        {
            let current = self.current();
            if current.cert_file == cert_file && current.key_file == key_file {
                return Ok(ReloadOutcome::Unchanged);
            }
        }
        let loaded = validate(
            &self.source,
            cert_file,
            key_file,
            &self.provider,
            self.clock.as_ref(),
        )?;
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        *state = Arc::new(loaded);
        // Relaxed: the generation is informational (tests, diagnostics); the swap itself is
        // published by the RwLock.
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        drop(state);
        tracing::info!(
            cert = %self.source.cert_path.display(),
            generation,
            "TLS certificate reloaded"
        );
        Ok(ReloadOutcome::Replaced { generation })
    }

    /// Reload, logging (not returning) a failure; used by the poll loop.
    fn reload_logged(&self) {
        if let Err(e) = self.reload() {
            tracing::error!(
                cert = %self.source.cert_path.display(),
                error = %e,
                "TLS certificate reload failed; keeping the previous certificate"
            );
        }
    }

    /// Wakes [`Self::run_poll`] to reload now (SIGHUP, file-watch event, admin request). A
    /// trigger raised while no poll loop is waiting is remembered and consumed by the next wait.
    pub fn trigger(&self) {
        self.trigger.notify_one();
    }

    /// Reload loop: reloads every `interval` (use [`DEFAULT_RELOAD_POLL`]) and whenever
    /// [`Self::trigger`] is called. Never returns; the caller spawns it (sim-api `Spawner`) and
    /// aborts it at shutdown.
    pub async fn run_poll(self: Arc<Self>, interval: Duration) {
        loop {
            tokio::select! {
                () = self.clock.sleep(interval) => {}
                () = self.trigger.notified() => {}
            }
            self.reload_logged();
        }
    }

    /// The pair served now.
    #[must_use]
    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.current().key)
    }

    /// Number of successful swaps since the initial load.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// The error of the last reload attempt, if it failed.
    #[must_use]
    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// `notAfter` of the served leaf certificate, seconds since the Unix epoch.
    #[must_use]
    pub fn not_after_unix(&self) -> i64 {
        self.current().not_after_unix
    }

    /// Seconds until the served leaf certificate expires (negative once expired); the value of
    /// the `rustegon_cert_expiry_seconds` gauge (security.md §5).
    #[must_use]
    pub fn expiry_seconds(&self) -> i64 {
        self.not_after_unix() - unix_now(self.clock.as_ref())
    }

    /// The files this pair is loaded from.
    #[must_use]
    pub fn source(&self) -> &CertSource {
        &self.source
    }

    fn current(&self) -> Arc<Loaded> {
        Arc::clone(&self.state.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl fmt::Debug for ReloadableCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadableCert")
            .field("source", &self.source)
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for ReloadableCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key())
    }
}

impl ResolvesClientCert for ReloadableCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn unix_now(clock: &dyn Clock) -> i64 {
    // Before the epoch only on a broken host clock; 0 then makes every certificate look valid
    // for its whole lifetime, which is the conservative reading for a metric.
    clock
        .wall()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn read_and_validate(
    source: &CertSource,
    provider: &CryptoProvider,
    clock: &dyn Clock,
) -> Result<Loaded, TlsError> {
    let fs = source.fs.as_ref();
    let cert_file = read_file(fs, &source.cert_path)?;
    let key_file = Redacted::new(read_file(fs, &source.key_path)?);
    validate(source, cert_file, key_file, provider, clock)
}

fn validate(
    source: &CertSource,
    cert_file: Vec<u8>,
    key_file: Redacted<Vec<u8>>,
    provider: &CryptoProvider,
    clock: &dyn Clock,
) -> Result<Loaded, TlsError> {
    let chain = parse_certificates(&cert_file, &source.cert_path)?;
    let key = parse_private_key(key_file.expose(), &source.key_path)?;
    let not_after = chain
        .first()
        .map(not_after_unix)
        .ok_or_else(|| TlsError::NoCertificate(source.cert_path.clone()))??;
    // Refuse an expired leaf: serving it would fail every handshake, while keeping the previous
    // certificate keeps the node reachable until the operator fixes the file.
    if not_after <= unix_now(clock) {
        return Err(TlsError::Expired {
            not_after_unix: not_after,
        });
    }
    // `from_der` loads the key through the provider and checks that it matches the leaf's
    // public key, so a half-replaced pair (new cert, old key) is rejected here.
    let certified = CertifiedKey::from_der(chain, key.expose().clone_key(), provider)?;
    Ok(Loaded {
        key: Arc::new(certified),
        cert_file,
        key_file,
        not_after_unix: not_after,
    })
}
