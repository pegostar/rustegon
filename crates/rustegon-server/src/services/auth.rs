// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `AuthService`: SCRAM-SHA-256(-PLUS) and X.509 logins, logout, identity (protocol.md §8,
//! security.md §2; FR-SEC-001, FR-SEC-006; PD-051).
//!
//! The SCRAM exchange is split into [`AuthService::scram_start`] (client-first →
//! server-first) and [`AuthService::scram_finish`] (client-final → session), so the gRPC
//! stream and the two REST calls (`/auth/scram/start`, `/auth/scram/finish`) share it.
//!
//! Order of checks of a password login, chosen so that nothing reveals whether a user exists
//! or what its password is (AC-SEC-002):
//! 1. parse the client-first message (bounded, cheap);
//! 2. authentication rate limit per source IP (and per claimed user if configured): `RGN-4003`;
//! 3. lockout of the claimed name, existing or not: `RGN-4007` **before** any credential check;
//! 4. full SCRAM handshake, with a fake salt for unknown, password-less and disabled users;
//! 5. any failure: one failure counted for the claimed name (a lockout is audited as
//!    `account_locked`), `login_failure` audited with the precise reason, and the uniform
//!    `RGN-4001` returned;
//! 6. success: lockout escalation reset, session creation rate limit per user, session created,
//!    `login_success` audited (fail closed) before the token is returned.
//!
//! The SCRAM mechanism (with or without `-PLUS`) is the one the gs2 header implies: a client-first
//! message starting with `p=tls-exporter` selects SCRAM-SHA-256-PLUS (the wire enum has one
//! `SCRAM_SHA_256` value for both, PD-051). The server binds to the connection's RFC 9266
//! exporter when TLS 1.3 provides one, so a `y` flag on such a connection is a downgrade and fails.
//!
//! Sessions record how they were created in their free-form `client_info`
//! (`<mechanism> <driver>/<version> <application>`), which `WhoAmI` reports.

use std::{sync::Arc, time::SystemTime};

use rustegon_common::Error;
use rustegon_security::{
    audit::{AuditEventKind, AuditOutcome},
    authn::{
        AuthMethod, AuthnError, FailureReason, PasswordChange, SecretString, apikey, realm,
        scram::{ClientFirst, Mechanism, ScramServer, ServerBinding, ServerContext},
        session::{self, SessionKind},
        users::{self, NODE_PREFIX, UserState},
        x509::{self, CertIdentity},
    },
    lockout::FailureOutcome,
    ratelimit::LimitClass,
};

use super::{Principal, RequestContext, unauthenticated};
use crate::{Completion, security::Security};

/// Client identification stored with the session (`ClientInfo` of auth.proto).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfo {
    /// Driver or tool name.
    pub driver_name: String,
    /// Driver version.
    pub driver_version: String,
    /// Application name.
    pub application: String,
}

/// How a principal authenticated, as reported by [`AuthService::who_am_i`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMechanism {
    /// Not known (session created before the mechanism was recorded).
    Unspecified,
    /// SCRAM-SHA-256(-PLUS).
    Scram,
    /// TLS client certificate.
    X509,
    /// API key.
    ApiKey,
}

impl LoginMechanism {
    fn tag(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Scram => "scram",
            Self::X509 => "x509",
            Self::ApiKey => "api_key",
        }
    }

    fn from_client_info(info: &str) -> Self {
        match info.split(' ').next() {
            Some("scram") => Self::Scram,
            Some("x509") => Self::X509,
            _ => Self::Unspecified,
        }
    }
}

/// A SCRAM handshake between server-first and client-final.
pub struct ScramPending {
    server: ScramServer,
    user: String,
    kind: SessionKind,
    client_info: String,
}

impl std::fmt::Debug for ScramPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramPending")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// A completed login.
#[derive(Debug, Clone)]
pub struct AuthSuccess {
    /// SCRAM server-final message (empty for X.509).
    pub server_final: String,
    /// Session token; empty for node certificates, which authenticate every request by the
    /// connection's certificate instead of a session (PD-051). Secret.
    pub session_token: SecretString,
    /// Absolute session expiry (`None` without a session).
    pub expires_at: Option<SystemTime>,
    /// Authenticated user.
    pub user: String,
    /// The user must change its password before anything else.
    pub must_change_password: bool,
}

/// Identity of the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoAmI {
    /// User name.
    pub user: String,
    /// Role references in effect (`read@shop`, `root`, …).
    pub roles: Vec<String>,
    /// How the caller authenticated.
    pub mechanism: LoginMechanism,
    /// Session or API key expiry.
    pub expires_at: Option<SystemTime>,
    /// API key id for API key callers.
    pub api_key_id: Option<String>,
}

/// The authentication service (module docs).
#[derive(Debug, Clone)]
pub struct AuthService {
    security: Option<Arc<Security>>,
}

fn client_info_text(mechanism: LoginMechanism, info: &ClientInfo) -> String {
    format!(
        "{} {}/{} {}",
        mechanism.tag(),
        info.driver_name,
        info.driver_version,
        info.application
    )
    .trim_end()
    .to_owned()
}

impl AuthService {
    /// Creates the service; without a security layer every call fails with `RGN-4001`.
    #[must_use]
    pub fn new(security: Option<Arc<Security>>) -> Self {
        Self { security }
    }

    fn security(&self) -> Result<&Arc<Security>, Error> {
        self.security.as_ref().ok_or_else(unauthenticated)
    }

    async fn login_failure(
        &self,
        sec: &Security,
        ctx: &RequestContext,
        user: Option<&str>,
        mechanism: LoginMechanism,
        reason: &str,
    ) -> Error {
        let mut event = sec
            .event(ctx, AuditEventKind::LoginFailure, AuditOutcome::Failure)
            .detail("mechanism", mechanism.tag())
            .detail("reason", reason);
        if let Some(u) = user {
            event = event.user(u);
        }
        sec.audit_or_log(event).await;
        unauthenticated()
    }

    /// Counts a failed password for `user`, auditing a resulting lockout.
    async fn password_failure(&self, sec: &Security, ctx: &RequestContext, user: &str) {
        if let FailureOutcome::Locked { duration } = sec.lockout().record_failure(user) {
            let event = sec
                .event(ctx, AuditEventKind::AccountLocked, AuditOutcome::Success)
                .user(user)
                .detail("lock_secs", duration.as_secs().to_string());
            sec.audit_or_log(event).await;
        }
    }

    /// SCRAM step 1: checks a client-first message and returns the server-first message.
    ///
    /// # Errors
    /// `RGN-4003` (rate limit), `RGN-4007` (locked), `RGN-4001` (malformed or channel binding
    /// mismatch), store errors.
    pub async fn scram_start(
        &self,
        ctx: &RequestContext,
        client_first: &str,
        kind: SessionKind,
        info: &ClientInfo,
    ) -> Result<(ScramPending, String), Error> {
        let sec = self.security()?;
        let ip = ctx.peer().map(|p| p.remote_addr.ip());
        let mechanism = if client_first.starts_with("p=") {
            Mechanism::ScramSha256Plus
        } else {
            Mechanism::ScramSha256
        };
        let first = match ClientFirst::parse(mechanism, client_first) {
            Ok(first) => first,
            Err(e) => {
                sec.rate_limit(LimitClass::Authentication, None, ip)?;
                let reason = reason(&e);
                return Err(self
                    .login_failure(sec, ctx, None, LoginMechanism::Scram, reason)
                    .await);
            }
        };
        let user = first.user().to_owned();
        sec.rate_limit(LimitClass::Authentication, Some(&user), ip)?;
        if let Err(locked) = sec.lockout().check(&user) {
            self.login_failure(
                sec,
                ctx,
                Some(&user),
                LoginMechanism::Scram,
                "account_locked",
            )
            .await;
            return Err(locked);
        }
        let binding = ctx
            .peer()
            .and_then(|p| p.tls_exporter.as_ref())
            .map_or(ServerBinding::Unavailable, |e| {
                ServerBinding::TlsExporter(*e.expose())
            });
        let iterations = sec.authn_settings().scram_iterations;
        let rng = Arc::clone(sec.rng());
        let lookup_user = user.clone();
        let (fake, state) = sec
            .transact(ctx, Completion::Abandon, move |t| {
                let fake = realm::load_or_ephemeral(t, rng.as_ref())?;
                Ok((fake, users::scram_lookup(t, &lookup_user)?))
            })
            .await?;
        let server_ctx = ServerContext {
            binding,
            fake_salt_key: &fake,
            default_iterations: iterations,
        };
        match ScramServer::start(first, state, &server_ctx, sec.rng().as_ref()) {
            Ok((server, server_first)) => Ok((
                ScramPending {
                    server,
                    user,
                    kind,
                    client_info: client_info_text(LoginMechanism::Scram, info),
                },
                server_first,
            )),
            Err(e) => {
                self.password_failure(sec, ctx, &user).await;
                Err(self
                    .login_failure(sec, ctx, Some(&user), LoginMechanism::Scram, reason(&e))
                    .await)
            }
        }
    }

    /// SCRAM step 2: verifies the client-final message and creates the session.
    ///
    /// # Errors
    /// `RGN-4001` (any credential failure), `RGN-4003` (session creation limit), `RGN-5001`
    /// when the login cannot be audited, store errors.
    pub async fn scram_finish(
        &self,
        ctx: &RequestContext,
        pending: ScramPending,
        client_final: &str,
    ) -> Result<AuthSuccess, Error> {
        let sec = self.security()?;
        let ScramPending {
            server,
            user,
            kind,
            client_info,
        } = pending;
        let server_final = match server.finish(client_final) {
            Ok(done) => done.server_final,
            Err(e) => {
                self.password_failure(sec, ctx, &user).await;
                return Err(self
                    .login_failure(sec, ctx, Some(&user), LoginMechanism::Scram, reason(&e))
                    .await);
            }
        };
        sec.lockout().record_success(&user);
        self.open_session(sec, ctx, &user, kind, client_info, LoginMechanism::Scram)
            .await
            .map(|mut s| {
                s.server_final = server_final;
                s
            })
    }

    async fn open_session(
        &self,
        sec: &Security,
        ctx: &RequestContext,
        user: &str,
        kind: SessionKind,
        client_info: String,
        mechanism: LoginMechanism,
    ) -> Result<AuthSuccess, Error> {
        let ip = ctx.peer().map(|p| p.remote_addr.ip());
        sec.rate_limit(LimitClass::SessionCreation, Some(user), ip)?;
        let settings = sec.authn_settings();
        let now = sec.clock().wall();
        let rng = Arc::clone(sec.rng());
        let name = user.to_owned();
        let created = sec
            .transact(ctx, Completion::Await, move |t| {
                // The user may have been disabled or dropped since the handshake started.
                let Some(u) = users::get_user(t, &name)?.filter(|u| u.state == UserState::Enabled)
                else {
                    return Ok(None);
                };
                let (token, record) = session::create_session(
                    t,
                    &u,
                    kind,
                    &client_info,
                    &settings,
                    now,
                    rng.as_ref(),
                )?;
                Ok(Some((token, record, u.password_change, u.roles)))
            })
            .await?;
        let Some((token, record, change, roles)) = created else {
            return Err(self
                .login_failure(sec, ctx, Some(user), mechanism, "bad_credentials")
                .await);
        };
        let event = sec
            .event(ctx, AuditEventKind::LoginSuccess, AuditOutcome::Success)
            .user(user)
            .roles(roles)
            .detail("mechanism", mechanism.tag());
        // Fail closed: a login that cannot be audited is not granted.
        sec.audit(event).await?;
        Ok(AuthSuccess {
            server_final: String::new(),
            session_token: token,
            expires_at: Some(record.expires_at),
            user: user.to_owned(),
            must_change_password: change == PasswordChange::Required,
        })
    }

    /// X.509 login with the connection's verified client certificate: a session for an
    /// `x509:` user; for a node certificate a success without session (nodes authenticate each
    /// request by their certificate).
    ///
    /// # Errors
    /// `RGN-4001` (no certificate, unknown or disabled user), `RGN-4003`, store errors.
    pub async fn certificate(
        &self,
        ctx: &RequestContext,
        kind: SessionKind,
        info: &ClientInfo,
    ) -> Result<AuthSuccess, Error> {
        let sec = self.security()?;
        let ip = ctx.peer().map(|p| p.remote_addr.ip());
        sec.rate_limit(LimitClass::Authentication, None, ip)?;
        let Some(der) = ctx
            .peer()
            .and_then(|p| p.peer_certificates.as_ref())
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec())
        else {
            return Err(self
                .login_failure(sec, ctx, None, LoginMechanism::X509, "no_certificate")
                .await);
        };
        let identity = match x509::identity_from_cert(&der) {
            Ok(identity) => identity,
            Err(e) => {
                return Err(self
                    .login_failure(sec, ctx, None, LoginMechanism::X509, reason(&e))
                    .await);
            }
        };
        match identity {
            CertIdentity::Node(cn) => {
                let user = format!("{NODE_PREFIX}{cn}");
                let event = sec
                    .event(ctx, AuditEventKind::LoginSuccess, AuditOutcome::Success)
                    .user(user.clone())
                    .roles([x509::NODE_ROLE])
                    .detail("mechanism", "x509");
                sec.audit(event).await?;
                Ok(AuthSuccess {
                    server_final: String::new(),
                    session_token: rustegon_security::authn::secret(""),
                    expires_at: None,
                    user,
                    must_change_password: false,
                })
            }
            CertIdentity::User(user) => {
                let info = client_info_text(LoginMechanism::X509, info);
                self.open_session(sec, ctx, &user, kind, info, LoginMechanism::X509)
                    .await
            }
        }
    }

    /// Revokes the caller's session (a no-op for API key and certificate callers, which have
    /// none).
    ///
    /// # Errors
    /// `RGN-4001` without a principal, store errors.
    pub async fn logout(&self, ctx: &RequestContext) -> Result<(), Error> {
        let sec = self.security()?;
        ctx.require_principal()?;
        let Some(token) = ctx
            .credentials()
            .and_then(|c| bearer(c.expose()))
            .map(rustegon_security::authn::secret)
        else {
            return Ok(());
        };
        let revoked = sec
            .transact(ctx, Completion::Await, move |t| {
                Ok(session::revoke_session(t, token.expose())?)
            })
            .await?;
        if revoked {
            let event = sec.event(ctx, AuditEventKind::Logout, AuditOutcome::Success);
            sec.audit_or_log(event).await;
        }
        Ok(())
    }

    /// The caller's identity.
    ///
    /// # Errors
    /// `RGN-4001` without a principal, store errors.
    pub async fn who_am_i(&self, ctx: &RequestContext) -> Result<WhoAmI, Error> {
        let sec = self.security()?;
        let principal: Principal = ctx.require_principal()?.clone();
        let token = ctx
            .credentials()
            .and_then(|c| bearer(c.expose()))
            .map(rustegon_security::authn::secret);
        let key_id = principal.api_key_id().map(str::to_owned);
        let lookup_key = key_id.clone();
        let (mechanism, expires_at) = sec
            .transact(ctx, Completion::Abandon, move |t| {
                if let Some(token) = &token
                    && let Some(s) = session::session_of(t, token.expose())?
                {
                    return Ok((
                        LoginMechanism::from_client_info(&s.client_info),
                        Some(s.expires_at),
                    ));
                }
                if let Some(id) = &lookup_key {
                    let expiry = apikey::get_api_key(t, id)?.and_then(|k| k.expires_at);
                    return Ok((LoginMechanism::ApiKey, expiry));
                }
                Ok((LoginMechanism::X509, None))
            })
            .await?;
        let mechanism = match principal.method {
            AuthMethod::Certificate => LoginMechanism::X509,
            AuthMethod::ApiKey(_) => LoginMechanism::ApiKey,
            AuthMethod::Password | AuthMethod::Session => mechanism,
        };
        Ok(WhoAmI {
            user: principal.user,
            roles: principal.roles,
            mechanism,
            expires_at,
            api_key_id: key_id,
        })
    }
}

fn bearer(raw: &str) -> Option<&str> {
    let (scheme, rest) = raw.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then(|| rest.trim_start_matches(' '))
}

fn reason(e: &AuthnError) -> &'static str {
    match e {
        AuthnError::AuthenticationFailed(FailureReason::NonceMismatch) => "nonce_mismatch",
        AuthnError::AuthenticationFailed(FailureReason::ChannelBinding) => "channel_binding",
        AuthnError::AuthenticationFailed(FailureReason::Malformed) => "malformed",
        AuthnError::AuthenticationFailed(FailureReason::Expired) => "expired",
        AuthnError::AuthenticationFailed(FailureReason::AddressNotAllowed) => "address_not_allowed",
        _ => "bad_credentials",
    }
}
