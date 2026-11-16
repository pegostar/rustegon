// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using Grpc.Core;
using Rustegon.V1;
using Rustegon.Driver.Errors;

namespace Rustegon.Driver.Internal.Auth;

/// <summary>A session token and its expiry.</summary>
internal sealed record SessionToken(string Token, DateTimeOffset? ExpiresAt, bool MustChangePassword)
{
    /// <summary>Re-authenticate this long before the server-side expiry.</summary>
    internal static readonly TimeSpan RefreshMargin = TimeSpan.FromSeconds(30);

    internal bool IsExpiring(DateTimeOffset now) => ExpiresAt is { } e && e - RefreshMargin <= now;

    /// <summary>Never print the token (CLAUDE.md rule 9).</summary>
    public override string ToString() => "SessionToken ‹redacted›";
}

/// <summary>
/// Produces the <c>authorization</c> header of a client (protocol.md §8): a constant
/// <c>ApiKey rgn_…</c> for API keys; for SCRAM and X.509 a session token from the
/// <c>Authenticate</c> stream, cached until it expires or the server reports RGN-4005.
/// </summary>
/// <remarks>
/// Concurrency: <see cref="_gate"/> protects <see cref="_login"/> only, and is never held across an
/// await. Logins are single-flight: concurrent callers share one login task; a failed or expired
/// login is replaced by the next caller, so a transient failure is not cached. The login runs with
/// its own deadline, not with any single caller's cancellation token, because other callers may
/// be waiting for it; each caller still stops waiting when its own token is cancelled.
/// </remarks>
internal sealed class SessionAuthenticator
{
    internal const string DriverName = "rustegon-dotnet";

    private readonly RustegonCredential? _credential;
    private readonly RustegonClientSettings _settings;
    private readonly Lock _gate = new();
    private Task<SessionToken>? _login;

    internal SessionAuthenticator(RustegonCredential? credential, RustegonClientSettings settings)
    {
        _credential = credential;
        _settings = settings;
    }

    /// <summary>Whether RGN-4005 can be cured by logging in again.</summary>
    internal bool UsesSessions => _credential?.Mechanism is AuthenticationMechanism.ScramSha256 or AuthenticationMechanism.X509;

    /// <summary>The driver version reported in <c>ClientInfo</c>.</summary>
    internal static string DriverVersion { get; } =
        typeof(SessionAuthenticator).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";

    /// <summary>The header value, or null for anonymous clients.</summary>
    internal async ValueTask<string?> GetAuthorizationAsync(CallInvoker invoker, CancellationToken cancellationToken)
    {
        switch (_credential?.Mechanism)
        {
            case null:
                return null;
            case AuthenticationMechanism.ApiKey:
                return "ApiKey " + _credential.Secret;
        }

        Task<SessionToken> login;
        lock (_gate)
        {
            if (_login is null || _login.IsFaulted || _login.IsCanceled
                || (Completed(_login)?.IsExpiring(DateTimeOffset.UtcNow) ?? false))
            {
                _login = LoginAsync(invoker);
            }

            login = _login;
        }

        SessionToken token = await login.WaitAsync(cancellationToken).ConfigureAwait(false);
        return "Bearer " + token.Token;
    }

    /// <summary>Drops the cached session if it is the one that produced <paramref name="authorization"/> (after RGN-4005).</summary>
    internal void Invalidate(string? authorization)
    {
        lock (_gate)
        {
            if (_login is not null && "Bearer " + Completed(_login)?.Token == authorization)
            {
                _login = null;
            }
        }
    }

    /// <summary>Revokes the cached session (best effort, on dispose).</summary>
    internal async Task LogoutAsync(CallInvoker invoker)
    {
        Task<SessionToken>? login;
        lock (_gate)
        {
            login = _login;
            _login = null;
        }

        SessionToken? token = login is null ? null : Completed(login);
        if (token is null)
        {
            return;
        }

        var headers = new Metadata { { "authorization", "Bearer " + token.Token } };
        try
        {
            await new AuthService.AuthServiceClient(invoker)
                .LogoutAsync(new LogoutRequest(), new CallOptions(headers, DateTime.UtcNow + TimeSpan.FromSeconds(5)))
                .ResponseAsync.ConfigureAwait(false);
        }
        catch (RpcException)
        {
            // Best effort: the session expires on its own; disposal must not fail because the
            // server is gone.
        }
    }

    /// <summary>The token of a login that already succeeded, else null (never blocks).</summary>
    private static SessionToken? Completed(Task<SessionToken> login)
    {
#pragma warning disable CA1849 // Result of a task known to be complete: reading it cannot block.
        return login.IsCompletedSuccessfully ? login.Result : null;
#pragma warning restore CA1849
    }

    private Task<SessionToken> LoginAsync(CallInvoker invoker) =>
        _credential!.Mechanism == AuthenticationMechanism.X509 ? X509LoginAsync(invoker) : ScramLoginAsync(invoker);

    private ClientInfo Info() => new()
    {
        DriverName = DriverName,
        DriverVersion = DriverVersion,
        Application = _settings.ApplicationName ?? string.Empty,
    };

    private CallOptions LoginOptions() => new(
        new Metadata { { Transport.RustegonInterceptor.RequestIdHeader, Transport.RustegonInterceptor.NewRequestId() } },
        DateTime.UtcNow + _settings.DefaultOperationTimeout);

    private async Task<SessionToken> ScramLoginAsync(CallInvoker invoker)
    {
        var scram = new ScramSha256Client(_credential!.User!, _credential.Secret);
        try
        {
            using AsyncDuplexStreamingCall<AuthenticateRequest, AuthenticateResponse> call =
                new AuthService.AuthServiceClient(invoker).Authenticate(LoginOptions());
            await call.RequestStream.WriteAsync(new AuthenticateRequest
            {
                Mechanism = AuthMechanism.ScramSha256,
                Payload = ByteString.CopyFromUtf8(scram.ClientFirst),
                ClientInfo = Info(),
            }).ConfigureAwait(false);
            AuthenticateResponse challenge = await NextAsync(call, AuthenticateResponse.StepOneofCase.Challenge, "no SCRAM challenge").ConfigureAwait(false);
            string serverFirst = challenge.Challenge.ToStringUtf8();
            // PBKDF2 with the server's iteration count is CPU bound: off the caller's async flow.
            string clientFinal = await Task.Run(() => scram.ProcessServerFirst(serverFirst)).ConfigureAwait(false);
            await call.RequestStream.WriteAsync(new AuthenticateRequest { Payload = ByteString.CopyFromUtf8(clientFinal) }).ConfigureAwait(false);
            AuthenticateResponse done = await NextAsync(call, AuthenticateResponse.StepOneofCase.Success, "no SCRAM success").ConfigureAwait(false);
            // Mutual authentication: the server proves it knows the stored key before the token is used.
            scram.VerifyServerFinal(done.Success.ServerFinal.ToStringUtf8());
            await call.RequestStream.CompleteAsync().ConfigureAwait(false);
            return Accept(done.Success);
        }
        catch (RpcException e)
        {
            throw ErrorMapper.FromRpcException(e);
        }
    }

    private async Task<SessionToken> X509LoginAsync(CallInvoker invoker)
    {
        try
        {
            using AsyncDuplexStreamingCall<AuthenticateRequest, AuthenticateResponse> call =
                new AuthService.AuthServiceClient(invoker).Authenticate(LoginOptions());
            await call.RequestStream.WriteAsync(new AuthenticateRequest { Mechanism = AuthMechanism.X509, ClientInfo = Info() }).ConfigureAwait(false);
            AuthenticateResponse done = await NextAsync(call, AuthenticateResponse.StepOneofCase.Success, "no X.509 success").ConfigureAwait(false);
            await call.RequestStream.CompleteAsync().ConfigureAwait(false);
            return Accept(done.Success);
        }
        catch (RpcException e)
        {
            throw ErrorMapper.FromRpcException(e);
        }
    }

    private static async Task<AuthenticateResponse> NextAsync(
        AsyncDuplexStreamingCall<AuthenticateRequest, AuthenticateResponse> call,
        AuthenticateResponse.StepOneofCase expected,
        string failure)
    {
        if (!await call.ResponseStream.MoveNext(CancellationToken.None).ConfigureAwait(false)
            || call.ResponseStream.Current.StepCase != expected)
        {
            throw new AuthenticationException(RustegonError.Client(ErrorCodes.Unauthenticated), "authentication failed: " + failure);
        }

        return call.ResponseStream.Current;
    }

    private SessionToken Accept(AuthSuccess success)
    {
        if (string.IsNullOrEmpty(success.SessionToken))
        {
            throw new AuthenticationException(RustegonError.Client(ErrorCodes.Unauthenticated), "authentication failed: the server returned no session token");
        }

        if (success.MustChangePassword && !_settings.AllowPasswordChangeOnly)
        {
            throw new PasswordChangeRequiredException(
                RustegonError.Client(ErrorCodes.PermissionDenied),
                $"The account '{success.User}' must change its password before other operations are allowed (set AllowPasswordChangeOnly to change it through this client).");
        }

        DateTimeOffset? expires = success.ExpiresAtUnixMs > 0 ? DateTimeOffset.FromUnixTimeMilliseconds(success.ExpiresAtUnixMs) : null;
        return new SessionToken(success.SessionToken, expires, success.MustChangePassword);
    }
}
