// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Authentication (protocol.md §8): SCRAM-SHA-256 and X.509 logins yield a session token sent as
//! `authorization: Bearer <token>`; API keys are sent as `authorization: ApiKey <key>` on every
//! call. One login at a time per client (an async mutex makes concurrent callers wait for the
//! same login), refreshed shortly before the token expires.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tonic::{metadata::AsciiMetadataValue, transport::Channel};
use zeroize::Zeroizing;

use crate::{
    codes,
    error::{Error, ErrorClass, Result},
    pb::{
        AuthMechanism as PbMechanism, AuthSuccess, AuthenticateRequest, ClientInfo, LogoutRequest,
        auth_service_client::AuthServiceClient, authenticate_response::Step,
    },
    scram::ScramClient,
    settings::{AuthMechanism, Credential, DRIVER_NAME, Settings, VERSION},
    transport::{REQUEST_ID_HEADER, new_request_id},
};

/// Tokens closer than this to their expiry are renewed before use.
const REFRESH_MARGIN: Duration = Duration::from_secs(30);

struct Token {
    value: Zeroizing<String>,
    expires_at_ms: Option<i64>,
}

impl Token {
    fn expiring(&self) -> bool {
        let Some(at) = self.expires_at_ms else {
            return false;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        let margin = i64::try_from(REFRESH_MARGIN.as_millis()).unwrap_or(0);
        at - now <= margin
    }
}

pub(crate) struct Authenticator {
    credential: Option<Credential>,
    application: String,
    allow_password_change_only: bool,
    timeout: Duration,
    token: Mutex<Option<Token>>,
}

fn auth_failed(what: &str) -> Error {
    Error::coded(
        codes::UNAUTHENTICATED,
        false,
        format!("authentication failed: {what}"),
    )
}

impl Authenticator {
    pub(crate) fn new(s: &Settings) -> Self {
        Self {
            credential: s.credential.clone(),
            application: s.application_name.clone().unwrap_or_default(),
            allow_password_change_only: s.allow_password_change_only,
            timeout: s.operation_timeout,
            token: Mutex::new(None),
        }
    }

    /// SCRAM and X.509 logins create server sessions (R5 applies to them only).
    pub(crate) fn uses_sessions(&self) -> bool {
        self.credential
            .as_ref()
            .is_some_and(|c| c.mechanism() != AuthMechanism::ApiKey)
    }

    /// The `authorization` header value, logging in first when needed.
    pub(crate) async fn authorization(&self, channel: &Channel) -> Result<Option<String>> {
        let Some(cred) = &self.credential else {
            return Ok(None);
        };
        if cred.mechanism() == AuthMechanism::ApiKey {
            return Ok(Some(format!(
                "ApiKey {}",
                cred.secret().unwrap_or_default()
            )));
        }
        let mut guard = self.token.lock().await;
        if let Some(t) = guard.as_ref()
            && !t.expiring()
        {
            return Ok(Some(format!("Bearer {}", t.value.as_str())));
        }
        let token = tokio::time::timeout(self.timeout, self.login(cred, channel.clone()))
            .await
            .map_err(|_| {
                Error::from_transport(tonic::Code::DeadlineExceeded, "the login timed out")
            })??;
        let header = format!("Bearer {}", token.value.as_str());
        *guard = Some(token);
        Ok(Some(header))
    }

    /// Forgets the session token that failed with RGN-4005 (unless a newer one replaced it).
    pub(crate) async fn invalidate(&self, authorization: Option<&str>) {
        let mut guard = self.token.lock().await;
        if let (Some(t), Some(a)) = (guard.as_ref(), authorization)
            && a.strip_prefix("Bearer ") == Some(t.value.as_str())
        {
            *guard = None;
        }
    }

    /// Logs the session out (best effort, client close).
    pub(crate) async fn logout(&self, channel: Channel) {
        let Some(token) = self.token.lock().await.take() else {
            return;
        };
        let mut req = tonic::Request::new(LogoutRequest {});
        req.set_timeout(Duration::from_secs(5));
        if let (Ok(a), Ok(id)) = (
            AsciiMetadataValue::try_from(format!("Bearer {}", token.value.as_str())),
            AsciiMetadataValue::try_from(new_request_id()),
        ) {
            req.metadata_mut().insert("authorization", a);
            req.metadata_mut().insert(REQUEST_ID_HEADER, id);
        }
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            AuthServiceClient::new(channel).logout(req),
        )
        .await;
    }

    async fn login(&self, cred: &Credential, channel: Channel) -> Result<Token> {
        let info = ClientInfo {
            driver_name: DRIVER_NAME.into(),
            driver_version: VERSION.into(),
            application: self.application.clone(),
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<AuthenticateRequest>(2);
        let mut req = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx));
        req.set_timeout(self.timeout);
        if let Ok(id) = AsciiMetadataValue::try_from(new_request_id()) {
            req.metadata_mut().insert(REQUEST_ID_HEADER, id);
        }
        let send = |m: AuthenticateRequest| {
            let tx = tx.clone();
            async move {
                tx.send(m)
                    .await
                    .map_err(|_| auth_failed("the login stream closed"))
            }
        };
        if cred.mechanism() == AuthMechanism::X509 {
            send(AuthenticateRequest {
                mechanism: PbMechanism::X509.into(),
                payload: Vec::new(),
                client_info: Some(info),
            })
            .await?;
            let mut stream = AuthServiceClient::new(channel)
                .authenticate(req)
                .await
                .map_err(|s| Error::from_status(&s))?
                .into_inner();
            let reply = stream.message().await.map_err(|s| Error::from_status(&s))?;
            drop(tx);
            return match reply.and_then(|r| r.step) {
                Some(Step::Success(s)) => self.accept(s),
                _ => Err(auth_failed("no X.509 success")),
            };
        }
        let user = cred.user().unwrap_or_default();
        let password = cred.secret().unwrap_or_default();
        let (scram, first) = ScramClient::new(user, password)
            .map_err(|_| auth_failed("the credential cannot be prepared (SASLprep)"))?;
        send(AuthenticateRequest {
            mechanism: PbMechanism::ScramSha256.into(),
            payload: first.into_bytes(),
            client_info: Some(info),
        })
        .await?;
        let mut stream = AuthServiceClient::new(channel)
            .authenticate(req)
            .await
            .map_err(|s| Error::from_status(&s))?
            .into_inner();
        let Some(Step::Challenge(challenge)) = stream
            .message()
            .await
            .map_err(|s| Error::from_status(&s))?
            .and_then(|r| r.step)
        else {
            return Err(auth_failed("no SCRAM challenge"));
        };
        let server_first = String::from_utf8(challenge)
            .map_err(|_| auth_failed("the SCRAM challenge is not UTF-8"))?;
        // PBKDF2 with the server's iteration count is CPU-bound: off the async workers.
        let (fin, client_final) =
            tokio::task::spawn_blocking(move || scram.server_first(&server_first))
                .await
                .map_err(|_| auth_failed("SCRAM task"))?
                .map_err(|_| auth_failed("invalid SCRAM challenge"))?;
        send(AuthenticateRequest {
            mechanism: PbMechanism::Unspecified.into(),
            payload: client_final.into_bytes(),
            client_info: None,
        })
        .await?;
        let Some(Step::Success(success)) = stream
            .message()
            .await
            .map_err(|s| Error::from_status(&s))?
            .and_then(|r| r.step)
        else {
            return Err(auth_failed("no SCRAM success"));
        };
        drop(tx);
        let server_final = String::from_utf8_lossy(&success.server_final).into_owned();
        // Mutual authentication: the server proves it knows the stored key.
        fin.server_final(&server_final)
            .map_err(|_| auth_failed("the server signature is invalid"))?;
        self.accept(success)
    }

    fn accept(&self, s: AuthSuccess) -> Result<Token> {
        if s.session_token.is_empty() {
            return Err(auth_failed("the server returned no session token"));
        }
        if s.must_change_password && !self.allow_password_change_only {
            // PD-076: a dedicated class under Authentication, raised by the driver.
            let mut e = Error::coded(
                codes::PERMISSION_DENIED,
                false,
                "the account must change its password before other operations are allowed \
                 (set allow_password_change_only to change it through this client)",
            );
            if let Some(r) = e.rustegon_mut() {
                r.class = ErrorClass::PasswordChangeRequired;
            }
            return Err(e);
        }
        Ok(Token {
            value: Zeroizing::new(s.session_token),
            expires_at_ms: (s.expires_at_unix_ms > 0).then_some(s.expires_at_unix_ms),
        })
    }
}
