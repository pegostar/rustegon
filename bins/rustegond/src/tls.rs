// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Transport security of the client listeners and certificate hot reload (FR-TLS-001,
//! FR-TLS-003, security.md §5, PD-054).
//!
//! - The policy comes from [`rustegon_net::transport_security`]: TLS with `security.tls = true`,
//!   plain text otherwise on a single node (ADR-034); in cluster mode plain text is refused (the
//!   node is always [`Deployment::SingleNode`] until M5 adds cluster membership). Plain text is
//!   logged as a warning at startup and every [`PLAIN_TEXT_WARNING_PERIOD`] (F27).
//! - With TLS, the node certificate is a [`ReloadableCert`] installed as the rustls certificate
//!   resolver, so a reload takes effect at the next handshake on both listeners without a
//!   restart; established connections keep their certificate.
//! - Reload triggers (PD-054): a change check every `tls.watch_secs` (default 10 s, which is
//!   what meets AC-TLS-003's one minute), the `tls.reload_poll_secs` poll as fallback when the
//!   check is off, and SIGHUP on Unix. The change check re-reads the two PEM files and compares
//!   them with the served ones (`ReloadableCert::reload` returns `Unchanged` without
//!   re-validating), which works on every OS and file system, including network shares and
//!   Kubernetes secret volumes whose symlink swaps OS file-notification APIs often miss, and
//!   needs no new dependency. Reads run on the blocking pool, never on an async worker.
//! - A failed reload (missing file, bad PEM, key not matching, expired) keeps the previous
//!   certificate and logs an error; certificate and key are usually replaced one after the
//!   other, so the next check picks up the completed pair.

use std::{sync::Arc, time::Duration};

use rustegon_common::{Error, ErrorCode, Result};
use rustegon_net::{
    CertSource, ClientCertPolicy, Deployment, ReloadOutcome, ReloadableCert, TlsContext,
    TlsSettings, TransportSecurity, TrustAnchors, transport_security,
};
use rustegon_server::ListenerSecurity;
use rustegon_sim_api::{Clock, FileSystem};
use tokio::sync::Notify;

fn tls_error(e: &impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::InvalidArgument, format!("TLS: {e}"))
}

/// The listeners' transport security and, with TLS, the reloadable node certificate.
pub struct Transport {
    /// Shared by the gRPC and REST listeners (each sets its own ALPN list).
    pub listener: ListenerSecurity,
    /// The node certificate; `None` in plain-text mode.
    pub cert: Option<Arc<ReloadableCert>>,
}

/// Selects the transport security and, with TLS, loads the certificate, key and (for
/// `client_cert = "optional"`) the client CA. Blocking (file reads at startup).
///
/// # Errors
/// `RGN-1001` for a plain-text request the policy refuses or any unusable TLS file; the
/// message names the file.
pub fn setup(
    tls_on: bool,
    tls: &TlsSettings,
    fs: &Arc<dyn FileSystem>,
    clock: &Arc<dyn Clock>,
) -> Result<Transport> {
    let policy = transport_security(tls_on, Deployment::SingleNode).map_err(|e| tls_error(&e))?;
    if policy == TransportSecurity::PlainText {
        return Ok(Transport {
            listener: ListenerSecurity::plain_text(policy).map_err(|e| tls_error(&e))?,
            cert: None,
        });
    }
    let context = TlsContext::new(Arc::clone(clock), tls.min_version);
    let cert = ReloadableCert::load(
        CertSource::new(Arc::clone(fs), &tls.cert_file, &tls.key_file),
        context.provider(),
        Arc::clone(clock),
    )
    .map_err(|e| tls_error(&e))?;
    let client_ca = match tls.client_cert {
        ClientCertPolicy::None => None,
        ClientCertPolicy::Optional => {
            let path = tls.client_ca_file.as_ref().unwrap_or(&tls.ca_file);
            Some(TrustAnchors::load(fs.as_ref(), path).map_err(|e| tls_error(&e))?)
        }
    };
    let config = context
        .client_listener_config(Arc::clone(&cert), client_ca.as_ref())
        .map_err(|e| tls_error(&e))?;
    Ok(Transport {
        listener: ListenerSecurity::tls(config),
        cert: Some(cert),
    })
}

/// Interval of the plain-text warning (feature-analysis.md F27).
pub const PLAIN_TEXT_WARNING_PERIOD: Duration = Duration::from_secs(600);

/// Repeats the plain-text warning of [`transport_security`] every
/// [`PLAIN_TEXT_WARNING_PERIOD`], so it is not lost in a long log. Never returns; the caller
/// aborts it at shutdown.
pub async fn plain_text_warning_loop(clock: Arc<dyn Clock>) {
    loop {
        clock.sleep(PLAIN_TEXT_WARNING_PERIOD).await;
        tracing::warn!(
            "security.tls = false: listeners accept plain-text connections; credentials and data \
             travel unencrypted (set security.tls = true to enable TLS)"
        );
    }
}

/// Reloads `cert` every `period` and whenever `now` is notified (SIGHUP). Never returns; the
/// caller aborts it at shutdown.
pub async fn reload_loop(
    cert: Arc<ReloadableCert>,
    clock: Arc<dyn Clock>,
    period: Duration,
    now: Arc<Notify>,
) {
    loop {
        tokio::select! {
            () = clock.sleep(period) => {}
            () = now.notified() => {
                tracing::info!("certificate reload requested");
            }
        }
        let target = Arc::clone(&cert);
        match tokio::task::spawn_blocking(move || target.reload()).await {
            // `ReloadableCert` logs a replacement itself.
            Ok(Ok(ReloadOutcome::Replaced { .. } | ReloadOutcome::Unchanged)) => {}
            Ok(Err(e)) => tracing::error!(
                cert = %cert.source().cert_path().display(),
                error = %e,
                "TLS certificate reload failed; keeping the previous certificate"
            ),
            Err(e) => tracing::error!(error = %e, "TLS certificate reload task failed"),
        }
    }
}
