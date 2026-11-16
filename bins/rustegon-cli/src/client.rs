// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Connection of the CLI to a node: gRPC (protocol.md §1, port 7700) and login
//! (protocol.md §8, security.md §2; PD-058).
//!
//! - Plain text by default, matching a single node's default (`security.tls = false`,
//!   ADR-034); TLS 1.3 through `rustegon-net` (rustls, `ring`) when `--ca` is given, the server
//!   verified against it (the `ca.crt` written by `rustegon init --tls`).
//! - Authentication: an API key (`authorization: ApiKey …`, from `--api-key-file` or
//!   `RUSTEGON_API_KEY`) or SCRAM-SHA-256 with the user's password (from `--password-file`,
//!   `RUSTEGON_PASSWORD` or a prompt) that yields a session token sent as `Bearer`. The session
//!   is revoked (`Logout`) when the command ends. Channel binding (SCRAM-SHA-256-PLUS) is not
//!   used yet: the TLS exporter would have to be taken from the connection inside the tonic
//!   connector (PD-058 follow-up); the server certificate is verified, so the exchange is still
//!   protected against an active attacker without the CA key.
//! - Every RPC runs on a private runtime through [`Client::call`]; the command logic stays
//!   synchronous, so reading stdin or prompting never blocks an async worker.

use std::{
    future::Future,
    net::{SocketAddr, ToSocketAddrs as _},
    path::PathBuf,
    sync::Arc,
};

use clap::Args;
use hyper_util::rt::TokioIo;
use rustegon_net::{
    TlsContext, TlsMinVersion, TrustAnchors, rustls::pki_types::ServerName,
    tokio_rustls::TlsConnector,
};
use rustegon_proto::v1::{
    AuthMechanism, AuthenticateRequest, ClientInfo, LogoutRequest,
    auth_service_client::AuthServiceClient, authenticate_response::Step,
};
use rustegon_security::authn::{
    SecretString,
    scram::{ClientBinding, Mechanism, ScramClient},
};
use rustegon_sim_api::{Connection, Network as _, OsRng, StdFileSystem, SystemClock, TokioNetwork};
use tonic::{
    Request,
    codegen::tokio_stream::wrappers::ReceiverStream,
    metadata::{AsciiMetadataValue, MetadataValue},
    transport::{Channel, Endpoint},
};
use zeroize::Zeroizing;

use crate::{
    output::{CliError, CliResult, err, fail, io_err},
    secrets,
};

/// Environment variable with the login password.
pub const PASSWORD_ENV: &str = "RUSTEGON_PASSWORD";
/// Environment variable with an API key.
pub const API_KEY_ENV: &str = "RUSTEGON_API_KEY";

/// Connection and login options shared by the commands that talk to a node.
#[derive(Debug, Clone, Args)]
pub struct ConnArgs {
    /// Node host name or address.
    #[arg(long, env = "RUSTEGON_HOST", default_value = "localhost")]
    pub host: String,
    /// gRPC port of the node.
    #[arg(long, env = "RUSTEGON_PORT", default_value_t = 7700)]
    pub port: u16,
    /// CA certificate verifying the node; turns TLS on (a node with `security.tls = true`:
    /// `<data_dir>/certs/ca.crt` after `rustegon init --tls`). Without it: plain text.
    #[arg(long, env = "RUSTEGON_CA", value_name = "PATH")]
    pub ca: Option<PathBuf>,
    /// Name expected in the node certificate (default: --host).
    #[arg(long, value_name = "NAME", requires = "ca")]
    pub tls_server_name: Option<String>,
    /// User to log in as (SCRAM-SHA-256).
    #[arg(long, short = 'u', env = "RUSTEGON_USER")]
    pub user: Option<String>,
    /// File with the password of --user (else `RUSTEGON_PASSWORD`, else a prompt).
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
    /// File with an API key used instead of a password login (else `RUSTEGON_API_KEY`).
    #[arg(long, value_name = "PATH", conflicts_with_all = ["user", "password_file"])]
    pub api_key_file: Option<PathBuf>,
}

/// An authenticated connection.
pub struct Client {
    runtime: tokio::runtime::Runtime,
    channel: Channel,
    authorization: AsciiMetadataValue,
    /// The logged-in user (`None` with an API key).
    pub user: Option<String>,
    /// Whether the server requires a password change before anything else.
    pub must_change_password: bool,
    session: bool,
}

impl Client {
    /// Connects and authenticates (module docs).
    ///
    /// # Errors
    /// Missing options or secrets, connection, TLS and authentication failures.
    pub fn connect(args: &ConnArgs) -> CliResult<Self> {
        Self::connect_with(args, None)
    }

    /// Like [`Self::connect`], with an already obtained login password (used by `user passwd`,
    /// which needs the current password twice).
    ///
    /// # Errors
    /// As [`Self::connect`].
    pub fn connect_with(args: &ConnArgs, password: Option<&SecretString>) -> CliResult<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| io_err("runtime", &e))?;
        let api_key = match &args.api_key_file {
            Some(path) => Some(secrets::read_secret_file(path)?),
            None if args.user.is_none() => std::env::var(API_KEY_ENV)
                .ok()
                .filter(|k| !k.is_empty())
                .map(|k| rustegon_security::authn::secret(Zeroizing::new(k).as_str())),
            None => None,
        };
        let user = match (&api_key, &args.user) {
            (Some(_), _) => None,
            (None, Some(u)) => Some(u.clone()),
            (None, None) => {
                return fail(format!(
                    "no credentials: use --user (with --password-file, {PASSWORD_ENV} or a \
                     prompt) or --api-key-file / {API_KEY_ENV}"
                ));
            }
        };
        let addr = resolve(&args.host, args.port)?;
        let channel = runtime.block_on(open_channel(args, addr))?;
        let mut client = Self {
            runtime,
            channel,
            authorization: MetadataValue::from_static(""),
            user: user.clone(),
            must_change_password: false,
            session: false,
        };
        if let Some(key) = api_key {
            client.authorization =
                MetadataValue::try_from(format!("ApiKey {}", key.expose().as_str()))
                    .map_err(|_| CliError("the API key contains invalid characters".into()))?;
            return Ok(client);
        }
        let user = user.unwrap_or_default();
        let password = match password {
            Some(p) => p.clone(),
            None => secrets::obtain(
                &format!("password of {user}"),
                args.password_file.as_deref(),
                PASSWORD_ENV,
                "--password-file",
                false,
            )?,
        };
        let channel = client.channel.clone();
        let (token, must_change) = client.runtime.block_on(login(channel, &user, &password))?;
        client.authorization = MetadataValue::try_from(format!("Bearer {}", token.as_str()))
            .map_err(|_| CliError("the server returned an invalid session token".into()))?;
        client.session = true;
        client.must_change_password = must_change;
        if must_change {
            err(&format!(
                "warning: the password of {user} must be changed before anything else \
                 (`rustegon user passwd`)"
            ));
        }
        Ok(client)
    }

    /// The channel, for building service clients.
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }

    /// Wraps a request message with the credentials.
    pub fn request<T>(&self, message: T) -> Request<T> {
        let mut r = Request::new(message);
        r.metadata_mut()
            .insert("authorization", self.authorization.clone());
        r
    }

    /// Runs one RPC future to completion.
    pub fn call<F: Future>(&self, f: F) -> F::Output {
        self.runtime.block_on(f)
    }

    /// Starts `f` on the client's runtime without waiting for it (a client-streaming RPC fed
    /// from the command's thread); collect the result with [`Self::call`] on the handle.
    pub fn spawn<F>(&self, f: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.runtime.spawn(f)
    }

    /// Ends the session (best effort: the session expires anyway).
    pub fn close(self) {
        if self.session {
            let request = self.request(LogoutRequest {});
            let channel = self.channel.clone();
            let _ = self
                .runtime
                .block_on(async move { AuthServiceClient::new(channel).logout(request).await });
        }
    }
}

/// Resolves `host:port` (blocking, before any async work).
fn resolve(host: &str, port: u16) -> CliResult<SocketAddr> {
    let target = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    target
        .to_socket_addrs()
        .map_err(|e| io_err(&target, &e))?
        .next()
        .ok_or_else(|| CliError(format!("{target}: no address")))
}

async fn open_channel(args: &ConnArgs, addr: SocketAddr) -> CliResult<Channel> {
    let endpoint =
        |uri: String| Endpoint::from_shared(uri).map_err(|e| CliError(format!("endpoint: {e}")));
    let Some(ca) = &args.ca else {
        return endpoint(format!("http://{addr}"))?
            .connect()
            .await
            .map_err(|e| CliError(format!("{addr}: {e}")));
    };
    let anchors = TrustAnchors::load(&StdFileSystem, ca)
        .map_err(|e| CliError(format!("{}: {e}", ca.display())))?;
    let tls = TlsContext::new(Arc::new(SystemClock::new()), TlsMinVersion::Tls13);
    let mut config = tls
        .client_config(&anchors, None)
        .map_err(|e| CliError(format!("TLS: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let config = Arc::new(config);
    let name = args.tls_server_name.clone().unwrap_or_else(|| {
        args.host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned()
    });
    let server_name = ServerName::try_from(name.clone())
        .map_err(|_| CliError(format!("invalid TLS server name {name:?}")))?;
    endpoint(format!("http://{addr}"))?
        .connect_with_connector(tower::service_fn(move |_| {
            let tls = TlsConnector::from(Arc::clone(&config));
            let server_name = server_name.clone();
            async move {
                let conn: Box<dyn Connection> = TokioNetwork.connect(addr).await?;
                let stream = tls.connect(server_name, conn).await?;
                let io: Box<dyn Connection> = Box::new(stream);
                Ok::<_, std::io::Error>(TokioIo::new(io))
            }
        }))
        .await
        .map_err(|e| {
            // tonic's transport error hides the TLS reason in its source chain.
            let mut text = e.to_string();
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                text.push_str(": ");
                text.push_str(&s.to_string());
                source = s.source();
            }
            CliError(format!("{addr}: {text}"))
        })
}

fn auth_failed(step: &str) -> CliError {
    CliError(format!("authentication failed ({step})"))
}

/// SCRAM-SHA-256 login (protocol.md §8). Returns the session token and whether the password
/// must be changed.
async fn login(
    channel: Channel,
    user: &str,
    password: &SecretString,
) -> CliResult<(Zeroizing<String>, bool)> {
    let (client, mechanism, first) =
        ScramClient::new(user, password, ClientBinding::Unsupported, &OsRng);
    let mechanism = match mechanism {
        Mechanism::ScramSha256 | Mechanism::ScramSha256Plus => AuthMechanism::ScramSha256,
    };
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    tx.send(AuthenticateRequest {
        mechanism: mechanism as i32,
        payload: first.into_bytes(),
        client_info: Some(ClientInfo {
            driver_name: "rustegon-cli".into(),
            driver_version: env!("CARGO_PKG_VERSION").into(),
            application: "rustegon".into(),
        }),
    })
    .await
    .map_err(|_| auth_failed("request stream closed"))?;
    let mut stream = AuthServiceClient::new(channel)
        .authenticate(ReceiverStream::new(rx))
        .await?
        .into_inner();
    let Some(Step::Challenge(server_first)) = stream.message().await?.and_then(|m| m.step) else {
        return Err(auth_failed("no SCRAM challenge"));
    };
    let server_first =
        String::from_utf8(server_first).map_err(|_| auth_failed("challenge is not UTF-8"))?;
    // PBKDF2 with the server's iteration count is CPU-bound: off the async workers.
    let (fin, client_final) =
        tokio::task::spawn_blocking(move || client.server_first(&server_first))
            .await
            .map_err(|_| auth_failed("SCRAM task"))?
            .map_err(|e| CliError(format!("authentication failed: {e}")))?;
    tx.send(AuthenticateRequest {
        mechanism: 0,
        payload: client_final.into_bytes(),
        client_info: None,
    })
    .await
    .map_err(|_| auth_failed("request stream closed"))?;
    let Some(Step::Success(success)) = stream.message().await?.and_then(|m| m.step) else {
        return Err(auth_failed("no SCRAM success"));
    };
    let server_final = std::str::from_utf8(&success.server_final)
        .map_err(|_| auth_failed("server-final is not UTF-8"))?;
    // Mutual authentication: the server proves it knows the stored key.
    fin.server_final(server_final)
        .map_err(|_| auth_failed("server signature mismatch"))?;
    Ok((
        Zeroizing::new(success.session_token),
        success.must_change_password,
    ))
}
