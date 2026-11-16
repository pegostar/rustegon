// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! REST adapter of [`crate::services::AuthService`] and of `AdminService.ChangePassword`
//! (protocol.md §4 "session", §8; security.md §2.1; FR-SEC-001, FR-API-002; PD-051, PD-055).
//!
//! # SCRAM over two calls
//! `POST /auth/scram/start` carries the SASL client-first message and returns the server-first
//! message with a `handshakeId`; `POST /auth/scram/finish` carries that id and the client-final
//! message and returns the server-final message (which the client must verify) and the
//! session. Between the calls the handshake lives in a bounded in-memory table
//! ([`Handshakes`]): at most [`MAX_HANDSHAKES`], each for at most [`HANDSHAKE_TIMEOUT`] (the
//! gRPC bound), bound to the source address of the start call, consumed by the first finish
//! (success or not). An unknown, expired, foreign or reused id is the uniform RGN-4001.
//! `POST /auth/login` (`{user, password}`) is the plain-password variant protocol.md §4 allows
//! over TLS: the server runs the client side of SCRAM against itself, so lockout, rate limits,
//! the fake salt of unknown users and audit are exactly those of a SCRAM login.
//!
//! # Session delivery
//! `delivery: "cookie"` (default; the GUI) creates a GUI session (30 min idle) and sets
//! `rgn_session` (`HttpOnly; Secure; SameSite=Strict; Path=/`) and `rgn_csrf` (readable by
//! scripts) until the session's absolute expiry. `Secure` is left out on a plain-text
//! connection (`security.tls = false`, ADR-034): browsers drop `Secure` cookies received over
//! `http://` from non-localhost hosts, which would make the GUI unusable there; the token is *not* in the body, so page
//! scripts never see it, while the CSRF token is (`csrfToken`) for clients that cannot read
//! cookies. `delivery: "token"` (tools, curl) creates a driver session and returns the token in
//! the body for `Authorization: Bearer`; no cookie is set. Logout revokes the session and
//! clears both cookies (also when the session had already expired or been revoked, so a
//! browser is never left with a dead cookie).
//!
//! The login endpoints read no credentials ([`AnonCtx`]): a stale cookie must not block a new
//! login. They are not CSRF-protected (there is no session yet); `SameSite=Strict` and the
//! JSON content type (which forces a CORS preflight cross-origin) keep other sites from
//! logging a browser into another account.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime},
};

use axum::{
    extract::State,
    response::{AppendHeaders, IntoResponse, Response},
};
use http::{HeaderValue, header::SET_COOKIE};
use rustegon_common::{Error, ErrorCode};
use rustegon_security::authn::{
    scram::{ClientBinding, ScramClient},
    secret,
    session::SessionKind,
};
use rustegon_sim_api::{Clock, Rng};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    ApiError, Ctx, JsonBody, Reply, RestState,
    admin::{RoleGrantJson, grants_out},
    auth::{CSRF_COOKIE, SESSION_COOKIE, csrf_token},
    context::AnonCtx,
    wire::unix_ms,
};
use crate::{
    Completion, ConnectionInfo,
    services::{
        RequestContext,
        auth::{AuthSuccess, ClientInfo, LoginMechanism, ScramPending},
        unauthenticated,
    },
};

/// Longest time between `scram/start` and `scram/finish` (the gRPC handshake bound).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Most SCRAM handshakes waiting for their finish call on this node. Each holds a few hundred
/// bytes; the bound keeps an address that only ever starts handshakes (already limited by the
/// authentication rate limit) from growing the table without limit.
pub const MAX_HANDSHAKES: usize = 10_000;

/// Routes of this module.
pub(super) fn routes() -> OpenApiRouter<RestState> {
    OpenApiRouter::new()
        .routes(routes!(scram_start))
        .routes(routes!(scram_finish))
        .routes(routes!(login))
        .routes(routes!(logout))
        .routes(routes!(me))
        .routes(routes!(change_password))
}

// ---------------------------------------------------------------------------------------------
// Handshake table
// ---------------------------------------------------------------------------------------------

struct Waiting {
    pending: ScramPending,
    started: Duration,
    ip: Option<IpAddr>,
    delivery: Delivery,
}

/// SCRAM handshakes between their two REST calls (module docs).
pub(crate) struct Handshakes {
    map: Mutex<HashMap<String, Waiting>>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
}

impl std::fmt::Debug for Handshakes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshakes").finish_non_exhaustive()
    }
}

impl Handshakes {
    pub(crate) fn new(clock: Arc<dyn Clock>, rng: Arc<dyn Rng>) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            clock,
            rng,
        }
    }

    fn expired(w: &Waiting, now: Duration) -> bool {
        now.saturating_sub(w.started) >= HANDSHAKE_TIMEOUT
    }

    /// Stores a handshake and returns its id (128 random bits, hex).
    fn insert(&self, w: Waiting) -> Result<String, Error> {
        let mut bytes = [0u8; 16];
        self.rng.fill_bytes(&mut bytes);
        let id = bytes.iter().fold(String::with_capacity(32), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        let now = self.clock.monotonic();
        // No await while the lock is held; the critical sections are map operations only.
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() >= MAX_HANDSHAKES {
            map.retain(|_, w| !Self::expired(w, now));
            if map.len() >= MAX_HANDSHAKES {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "too many authentication handshakes in progress",
                ));
            }
        }
        map.insert(id.clone(), w);
        Ok(id)
    }

    /// Takes the handshake `id` if it is alive and was started from `ip`.
    fn take(&self, id: &str, ip: Option<IpAddr>) -> Option<Waiting> {
        let now = self.clock.monotonic();
        let w = self
            .map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id)?;
        (!Self::expired(&w, now) && w.ip == ip).then_some(w)
    }

    /// Handshakes currently stored (tests).
    pub(crate) fn len(&self) -> usize {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

/// How the session reaches the client (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    /// GUI session in the `rgn_session` cookie (default).
    #[default]
    Cookie,
    /// Driver session token in the response body.
    Token,
}

impl Delivery {
    fn kind(self) -> SessionKind {
        match self {
            Self::Cookie => SessionKind::Gui,
            Self::Token => SessionKind::Driver,
        }
    }
}

/// Client identification stored with the session.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientInfoJson {
    /// Driver or tool name.
    #[serde(default)]
    pub driver_name: String,
    /// Driver version.
    #[serde(default)]
    pub driver_version: String,
    /// Application name.
    #[serde(default)]
    pub application: String,
}

fn client_info(c: Option<ClientInfoJson>) -> ClientInfo {
    let c = c.unwrap_or_default();
    ClientInfo {
        driver_name: c.driver_name,
        driver_version: c.driver_version,
        application: c.application,
    }
}

/// `POST /auth/scram/start` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScramStartRequest {
    /// SASL client-first message (`n,,n=<user>,r=<nonce>`; `p=tls-exporter` selects
    /// SCRAM-SHA-256-PLUS, which requires both calls on the same TLS 1.3 connection).
    pub client_first: String,
    /// Session delivery.
    #[serde(default)]
    pub delivery: Delivery,
    /// Client identification.
    #[serde(default)]
    pub client_info: Option<ClientInfoJson>,
}

/// `POST /auth/scram/start` response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScramStartResponse {
    /// Id to send with the client-final message (valid 30 s, once).
    pub handshake_id: String,
    /// SASL server-first message.
    pub server_first: String,
}

/// `POST /auth/scram/finish` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScramFinishRequest {
    /// Id from the start call.
    pub handshake_id: String,
    /// SASL client-final message.
    pub client_final: String,
}

/// `POST /auth/login` body (plain password over TLS; module docs).
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginRequest {
    /// User name.
    pub user: String,
    /// Password (never logged).
    pub password: String,
    /// Session delivery.
    #[serde(default)]
    pub delivery: Delivery,
    /// Client identification.
    #[serde(default)]
    pub client_info: Option<ClientInfoJson>,
}

/// A completed login.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    /// Authenticated user.
    pub user: String,
    /// Absolute session expiry (Unix ms).
    pub expires_at_unix_ms: i64,
    /// The user must change its password (`POST /auth/password`) before anything else.
    pub must_change_password: bool,
    /// SASL server-final message to verify (`scram/finish` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_final: Option<String>,
    /// CSRF token to send as `X-RGN-CSRF` (cookie delivery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    /// Session token for `Authorization: Bearer` (token delivery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

/// Empty success body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EmptyResponse {}

/// How the caller authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MechanismName {
    /// Not recorded.
    Unspecified,
    /// SCRAM-SHA-256(-PLUS) or password login.
    Scram,
    /// TLS client certificate.
    X509,
    /// API key.
    ApiKey,
}

/// `GET /auth/me` response (`AuthService.WhoAmI`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    /// User name.
    pub user: String,
    /// Roles in effect.
    pub roles: Vec<RoleGrantJson>,
    /// How the caller authenticated.
    pub mechanism: MechanismName,
    /// Session or API key expiry (Unix ms; 0 = none).
    pub expires_at_unix_ms: i64,
    /// API key id for API key callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
}

/// `POST /auth/password` body.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangePasswordRequest {
    /// Current password (a wrong one is RGN-4001 and counts towards lockout).
    pub current_password: String,
    /// New password (checked against the password policy).
    pub new_password: String,
}

// ---------------------------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------------------------

/// Whether cookies set on a response to `peer` carry `Secure`: always, except on a known
/// plain-text connection (module docs). An unknown connection (in-process calls) gets `Secure`.
pub(super) fn secure_cookies(peer: Option<&ConnectionInfo>) -> bool {
    peer.is_none_or(|c| c.tls)
}

fn cookie(
    name: &str,
    value: &str,
    http_only: bool,
    secure: bool,
    max_age: u64,
) -> Option<HeaderValue> {
    let http_only = if http_only { "; HttpOnly" } else { "" };
    let secure = if secure { " Secure;" } else { "" };
    // Values are base64url (session) and hex (CSRF): no quoting or escaping needed.
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/;{secure} SameSite=Strict{http_only}; Max-Age={max_age}"
    ))
    .ok()
}

pub(super) fn clearing_cookies(secure: bool) -> Vec<(http::HeaderName, HeaderValue)> {
    [(SESSION_COOKIE, true), (CSRF_COOKIE, false)]
        .into_iter()
        .filter_map(|(name, http_only)| {
            cookie(name, "", http_only, secure, 0).map(|v| (SET_COOKIE, v))
        })
        .collect()
}

/// The response of a completed login (module docs).
fn login_reply(
    state: &RestState,
    ctx: &RequestContext,
    success: AuthSuccess,
    delivery: Delivery,
    server_final: Option<String>,
) -> Response {
    let token = success.session_token.expose().to_string();
    let expires_at = success.expires_at.unwrap_or(SystemTime::UNIX_EPOCH);
    let mut body = LoginResponse {
        user: success.user,
        expires_at_unix_ms: unix_ms(expires_at),
        must_change_password: success.must_change_password,
        server_final,
        csrf_token: None,
        session_token: None,
    };
    let mut cookies = Vec::new();
    match delivery {
        Delivery::Token => body.session_token = Some(token),
        Delivery::Cookie => {
            let max_age = expires_at
                .duration_since(state.services.deps().clock.wall())
                .map_or(0, |d| d.as_secs());
            let csrf = csrf_token(&token);
            let secure = secure_cookies(ctx.peer());
            cookies.extend(
                cookie(SESSION_COOKIE, &token, true, secure, max_age).map(|v| (SET_COOKIE, v)),
            );
            cookies.extend(
                cookie(CSRF_COOKIE, &csrf, false, secure, max_age).map(|v| (SET_COOKIE, v)),
            );
            body.csrf_token = Some(csrf);
        }
    }
    (AppendHeaders(cookies), Reply::passthrough(body, ctx)).into_response()
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// SCRAM step 1: client-first → server-first (`AuthService.Authenticate`, first message).
#[utoipa::path(
    post,
    path = "/api/v1/auth/scram/start",
    tag = "auth",
    operation_id = "scramStart",
    request_body = ScramStartRequest,
    responses((status = 200, description = "The server-first message.", body = ScramStartResponse))
)]
async fn scram_start(
    State(state): State<RestState>,
    AnonCtx(ctx): AnonCtx,
    JsonBody(body): JsonBody<ScramStartRequest>,
) -> Result<Reply<ScramStartResponse>, ApiError> {
    let out = async {
        let (pending, server_first) = state
            .services
            .auth()
            .scram_start(
                &ctx,
                &body.client_first,
                body.delivery.kind(),
                &client_info(body.client_info),
            )
            .await?;
        let handshake_id = state.handshakes.insert(Waiting {
            pending,
            started: state.services.deps().clock.monotonic(),
            ip: ctx.peer().map(|p| p.remote_addr.ip()),
            delivery: body.delivery,
        })?;
        Ok::<_, Error>(ScramStartResponse {
            handshake_id,
            server_first,
        })
    }
    .await
    .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(out, &ctx))
}

/// SCRAM step 2: client-final → server-final and session (`AuthService.Authenticate`).
#[utoipa::path(
    post,
    path = "/api/v1/auth/scram/finish",
    tag = "auth",
    operation_id = "scramFinish",
    request_body = ScramFinishRequest,
    responses((status = 200, description = "Logged in; cookie delivery also sets `rgn_session` and `rgn_csrf`.", body = LoginResponse))
)]
async fn scram_finish(
    State(state): State<RestState>,
    AnonCtx(ctx): AnonCtx,
    JsonBody(body): JsonBody<ScramFinishRequest>,
) -> Result<Response, ApiError> {
    let ip = ctx.peer().map(|p| p.remote_addr.ip());
    let waiting = state
        .handshakes
        .take(&body.handshake_id, ip)
        .ok_or_else(|| ApiError::on(&ctx)(unauthenticated()))?;
    let mut success = state
        .services
        .auth()
        .scram_finish(&ctx, waiting.pending, &body.client_final)
        .await
        .map_err(ApiError::on(&ctx))?;
    let server_final = std::mem::take(&mut success.server_final);
    Ok(login_reply(
        &state,
        &ctx,
        success,
        waiting.delivery,
        Some(server_final),
    ))
}

/// Plain-password login over TLS, verified with SCRAM on the server (module docs).
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    operation_id = "login",
    request_body = LoginRequest,
    responses((status = 200, description = "Logged in; cookie delivery also sets `rgn_session` and `rgn_csrf`.", body = LoginResponse))
)]
async fn login(
    State(state): State<RestState>,
    AnonCtx(ctx): AnonCtx,
    JsonBody(body): JsonBody<LoginRequest>,
) -> Result<Response, ApiError> {
    let auth = state.services.auth();
    let deps = state.services.deps();
    let password = secret(body.password);
    // No channel binding: the server talks to itself, the TLS connection already protects
    // the password in transit.
    let (client, _, client_first) = ScramClient::new(
        &body.user,
        &password,
        ClientBinding::Unsupported,
        deps.rng.as_ref(),
    );
    drop(password);
    let (pending, server_first) = auth
        .scram_start(
            &ctx,
            &client_first,
            body.delivery.kind(),
            &client_info(body.client_info),
        )
        .await
        .map_err(ApiError::on(&ctx))?;
    // The client proof costs one PBKDF2 (≥ 100 000 iterations): blocking work for the pool.
    let client_final = deps
        .executor
        .run(&ctx, Completion::Abandon, move |_| {
            client
                .server_first(&server_first)
                .map(|(_, client_final)| client_final)
                // Malformed only for a broken server-first message; the user sees the
                // uniform login failure.
                .map_err(|_| unauthenticated())
        })
        .await
        .map_err(ApiError::on(&ctx))?;
    let success = auth
        .scram_finish(&ctx, pending, &client_final)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(login_reply(&state, &ctx, success, body.delivery, None))
}

/// Revokes the caller's session and clears the session cookies (`AuthService.Logout`).
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    operation_id = "logout",
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Logged out; both session cookies are cleared.", body = EmptyResponse))
)]
async fn logout(State(state): State<RestState>, Ctx(ctx): Ctx) -> Result<Response, ApiError> {
    // A dead session never reaches this handler: the gate clears the cookies on its refusal.
    state
        .services
        .auth()
        .logout(&ctx)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok((
        AppendHeaders(clearing_cookies(secure_cookies(ctx.peer()))),
        Reply::passthrough(EmptyResponse {}, &ctx),
    )
        .into_response())
}

/// The caller's identity (`AuthService.WhoAmI`).
#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "auth",
    operation_id = "whoAmI",
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "The caller.", body = MeResponse))
)]
async fn me(State(state): State<RestState>, Ctx(ctx): Ctx) -> Result<Reply<MeResponse>, ApiError> {
    let me = state
        .services
        .auth()
        .who_am_i(&ctx)
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(
        MeResponse {
            roles: grants_out(&me.roles),
            user: me.user,
            mechanism: match me.mechanism {
                LoginMechanism::Unspecified => MechanismName::Unspecified,
                LoginMechanism::Scram => MechanismName::Scram,
                LoginMechanism::X509 => MechanismName::X509,
                LoginMechanism::ApiKey => MechanismName::ApiKey,
            },
            expires_at_unix_ms: me.expires_at.map_or(0, unix_ms),
            api_key_id: me.api_key_id,
        },
        &ctx,
    ))
}

/// Changes the caller's own password (`AdminService.ChangePassword`; allowed while a password
/// change is required). The user's sessions are revoked, this one included.
#[utoipa::path(
    post,
    path = "/api/v1/auth/password",
    tag = "auth",
    operation_id = "changePassword",
    request_body = ChangePasswordRequest,
    security(("bearer" = []), ("apiKey" = []), ("sessionCookie" = [])),
    responses((status = 200, description = "Changed.", body = EmptyResponse))
)]
async fn change_password(
    State(state): State<RestState>,
    Ctx(ctx): Ctx,
    JsonBody(body): JsonBody<ChangePasswordRequest>,
) -> Result<Reply<EmptyResponse>, ApiError> {
    state
        .services
        .admin()
        .change_password(
            &ctx,
            secret(body.current_password),
            secret(body.new_password),
        )
        .await
        .map_err(ApiError::on(&ctx))?;
    Ok(Reply::passthrough(EmptyResponse {}, &ctx))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rustegon_sim_api::{OsRng, SystemClock};

    use super::*;

    #[test]
    fn fr_sec_001_cookies_carry_the_security_attributes() {
        let v = cookie(SESSION_COOKIE, "tok", true, true, 60).unwrap();
        assert_eq!(
            v,
            "rgn_session=tok; Path=/; Secure; SameSite=Strict; HttpOnly; Max-Age=60"
        );
        let v = cookie(CSRF_COOKIE, "abc", false, true, 60).unwrap();
        assert_eq!(
            v,
            "rgn_csrf=abc; Path=/; Secure; SameSite=Strict; Max-Age=60"
        );
        // ADR-034: no `Secure` on a plain-text connection, so browsers keep the cookie.
        let v = cookie(SESSION_COOKIE, "tok", true, false, 60).unwrap();
        assert_eq!(
            v,
            "rgn_session=tok; Path=/; SameSite=Strict; HttpOnly; Max-Age=60"
        );
        let peer = |tls| ConnectionInfo {
            remote_addr: ([127, 0, 0, 1], 1).into(),
            tls,
            peer_certificates: None,
            tls_exporter: None,
        };
        assert!(secure_cookies(None));
        assert!(secure_cookies(Some(&peer(true))));
        assert!(!secure_cookies(Some(&peer(false))));
        let cleared = clearing_cookies(true);
        assert_eq!(cleared.len(), 2);
        assert!(
            cleared
                .iter()
                .all(|(_, v)| v.to_str().unwrap().ends_with("Max-Age=0"))
        );
    }

    #[test]
    fn fr_sec_001_unknown_handshake_ids_are_refused() {
        let h = Handshakes::new(Arc::new(SystemClock::new()), Arc::new(OsRng));
        assert_eq!(h.len(), 0);
        assert!(h.take("missing", None).is_none());
    }
}
