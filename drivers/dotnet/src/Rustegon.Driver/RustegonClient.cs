// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Rustegon.Driver.Internal;
using Rustegon.Driver.Internal.Auth;
using Rustegon.Driver.Internal.DataPlane;
using Rustegon.Driver.Internal.Transport;
using V1 = Rustegon.V1;

namespace Rustegon.Driver;

/// <summary>
/// Entry point of the driver (dotnet-driver.md §1): thread-safe and long-lived; owns the channel
/// pool and the session. Create one per application (per cluster and credential) and dispose it
/// at shutdown. Authentication happens on the first operation and is renewed transparently.
/// </summary>
/// <remarks>
/// R1 scope (PD-069, <c>drivers/conformance/model.yaml</c>): databases, collections and indexes,
/// CRUD by id and by filter, finds and cursors, RGQL with parameters, bulk writes by id, sessions
/// as causality-token pass-through, interactive transactions and <see cref="WithTransactionAsync{TResult}"/>,
/// <see cref="ChangePasswordAsync"/>. Every operation follows the retry policy of
/// dotnet-driver.md §8 (<c>drivers/conformance/retry.yaml</c>).
/// </remarks>
public sealed class RustegonClient : IAsyncDisposable, IDisposable
{
    private readonly ChannelPool _pool;
    private readonly TlsMaterial _tls;
    private readonly SessionAuthenticator _auth;
    private readonly OperationExecutor _executor;
    private int _disposed;

    /// <summary>Creates a client.</summary>
    /// <param name="settings">The configuration; it is read now, later changes have no effect.</param>
    /// <exception cref="ArgumentException">Invalid settings, or a certificate file that cannot be loaded.</exception>
    public RustegonClient(RustegonClientSettings settings)
        : this(settings, null)
    {
    }

    /// <summary>Creates a client from a <c>rustegon://</c> connection string.</summary>
    /// <param name="connectionString">The connection string.</param>
    /// <exception cref="ArgumentException">Invalid connection string or settings.</exception>
    public RustegonClient(string connectionString)
        : this(RustegonClientSettings.FromConnectionString(connectionString))
    {
    }

    /// <summary>Creates a client; <paramref name="handler"/> replaces the network (in-process fake server of the tests, PD-073).</summary>
    internal RustegonClient(RustegonClientSettings settings, HttpMessageHandler? handler)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings = settings.Snapshot();
        IReadOnlyList<Endpoint> endpoints = settings.Validate();
        _tls = TlsMaterial.Load(settings.Tls, settings.Credential);
        try
        {
            _pool = new ChannelPool(endpoints, settings, _tls, handler);
        }
        catch
        {
            _tls.Dispose();
            throw;
        }

        _auth = new SessionAuthenticator(settings.Credential, settings);
        _executor = new OperationExecutor(_pool, _auth, settings);
        DefaultDatabase = settings.DefaultDatabase;
    }

    /// <summary>The database used when an operation names none.</summary>
    public string? DefaultDatabase { get; }

    /// <summary>The executor (driver internal; tests reach other services through it).</summary>
    internal OperationExecutor Executor => _executor;

    /// <summary>Round trip to a node (<c>SessionService.Ping</c>); authenticates first when a credential is set.</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>A task completing when the node answered.</returns>
    /// <exception cref="RustegonException">The node failed or rejected the call (e.g. <see cref="AuthenticationException"/>).</exception>
    public async Task PingAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _executor.UnaryAsync(
            (invoker, options) => new V1.SessionService.SessionServiceClient(invoker).PingAsync(new V1.PingRequest(), options),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Server versions and capabilities (<c>SessionService.GetServerInfo</c>).</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The server information.</returns>
    /// <exception cref="RustegonException">The node failed or rejected the call.</exception>
    public async Task<ServerInfo> GetServerInfoAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        V1.GetServerInfoResponse r = await _executor.UnaryAsync(
            (invoker, options) => new V1.SessionService.SessionServiceClient(invoker).GetServerInfoAsync(new V1.GetServerInfoRequest(), options),
            cancellationToken).ConfigureAwait(false);
        return new ServerInfo(r.ServerVersion, r.ProtocolVersion, [.. r.Features], [.. r.NodeAddresses]);
    }

    /// <summary>
    /// Logs in now instead of at the first operation (<c>Client.Create</c> of the conformance
    /// suite: wrong credentials and a required password change surface here).
    /// </summary>
    internal async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        _ = await _auth.GetAuthorizationAsync(_executor.AnyInvoker(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>A database handle (no I/O).</summary>
    /// <param name="name">Database name; null = <see cref="DefaultDatabase"/>.</param>
    /// <returns>The handle.</returns>
    /// <exception cref="ArgumentException">No name and no default database.</exception>
    public IRustegonDatabase GetDatabase(string? name = null)
    {
        ThrowIfDisposed();
        string db = name ?? DefaultDatabase ?? throw new ArgumentException("No database name and no DefaultDatabase in the settings.", nameof(name));
        return new RustegonDatabase(new DataContext(_executor, db, null));
    }

    /// <summary>The database names, sorted (<c>SchemaService.ListDatabases</c>).</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The names.</returns>
    public async Task<IReadOnlyList<string>> ListDatabaseNamesAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        V1.ListDatabasesResponse r = await _executor.UnaryAsync(
            (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).ListDatabasesAsync(new V1.ListDatabasesRequest(), o),
            new CallSpec(OperationKind.Read),
            cancellationToken).ConfigureAwait(false);
        return [.. r.Databases.Select(d => d.Name).Order(StringComparer.Ordinal)];
    }

    /// <summary>Creates a database.</summary>
    /// <param name="name">Database name.</param>
    /// <param name="options">Options (if-not-exists).</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Whether it was created (false only with <see cref="CreateDatabaseOptions.IfNotExists"/>).</returns>
    public async Task<bool> CreateDatabaseAsync(string name, CreateDatabaseOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ThrowIfDisposed();
        var request = new V1.CreateDatabaseRequest { Name = name, IfNotExists = options?.IfNotExists ?? false };
        V1.CreateDatabaseResponse r = await _executor.UnaryAsync(
            (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).CreateDatabaseAsync(request, o),
            new CallSpec(OperationKind.NoRetry, options?.Timeout),
            cancellationToken).ConfigureAwait(false);
        return r.Created;
    }

    /// <summary>Drops a database with all its collections.</summary>
    /// <param name="name">Database name.</param>
    /// <param name="options">Options (if-exists).</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Whether it was dropped (false only with <see cref="DropOptions.IfExists"/>).</returns>
    public async Task<bool> DropDatabaseAsync(string name, DropOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ThrowIfDisposed();
        var request = new V1.DropDatabaseRequest { Name = name, IfExists = options?.IfExists ?? false };
        V1.DropDatabaseResponse r = await _executor.UnaryAsync(
            (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).DropDatabaseAsync(request, o),
            new CallSpec(OperationKind.NoRetry, options?.Timeout),
            cancellationToken).ConfigureAwait(false);
        return r.Dropped;
    }

    /// <summary>Starts a session (R1: causality-token pass-through, no server call; PD-069).</summary>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The session; pass it in the operations' options.</returns>
    public Task<IClientSession> StartSessionAsync(SessionOptions? options = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IClientSession>(new ClientSession(options?.CausalConsistency ?? true));
    }

    /// <summary>Starts an interactive transaction (manual mode); dispose it to roll back what was not committed.</summary>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The transaction.</returns>
    public async Task<ITransaction> BeginTransactionAsync(TransactionOptions? options = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return await RustegonTransaction.BeginAsync(_executor, DefaultDatabase, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs <paramref name="callback"/> in a transaction and commits it, retrying the whole
    /// transaction on retryable errors until <see cref="TransactionOptions.MaxRetryTime"/>
    /// (transactions.md §5): full-jitter backoff base 10 ms ×2 capped at 1 s; an unknown commit
    /// outcome (RGN-2006) is resolved with the transaction status, never by re-running blindly;
    /// non-retryable errors and exceptions of the callback roll back and propagate. The callback
    /// may run several times: it must be idempotent with respect to external side effects.
    /// </summary>
    /// <typeparam name="TResult">Result of the callback.</typeparam>
    /// <param name="callback">The work, given the transaction and the cancellation token.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The callback's result after a successful commit.</returns>
    public Task<TResult> WithTransactionAsync<TResult>(
        Func<ITransaction, CancellationToken, Task<TResult>> callback,
        TransactionOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return TransactionRunner.RunAsync(_executor, DefaultDatabase, callback, options, cancellationToken);
    }

    /// <summary>As <see cref="WithTransactionAsync{TResult}"/> for a callback without result.</summary>
    /// <param name="callback">The work.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>A task completing after a successful commit.</returns>
    public Task WithTransactionAsync(
        Func<ITransaction, CancellationToken, Task> callback,
        TransactionOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(callback);
        return WithTransactionAsync<bool>(
            async (txn, ct) =>
            {
                await callback(txn, ct).ConfigureAwait(false);
                return true;
            },
            options,
            cancellationToken);
    }

    /// <summary>
    /// Changes the password of the logged-in user (<c>AdminService.ChangePassword</c>, PD-076);
    /// allowed while a password change is required (<see cref="RustegonClientSettings.AllowPasswordChangeOnly"/>).
    /// </summary>
    /// <param name="currentPassword">The current password.</param>
    /// <param name="newPassword">The new password (the server's password policy applies).</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>A task completing when changed.</returns>
    public async Task ChangePasswordAsync(string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(currentPassword);
        ArgumentException.ThrowIfNullOrEmpty(newPassword);
        ThrowIfDisposed();
        var request = new V1.ChangePasswordRequest { CurrentPassword = currentPassword, NewPassword = newPassword };
        await _executor.UnaryAsync(
            (invoker, o) => new V1.AdminService.AdminServiceClient(invoker).ChangePasswordAsync(request, o),
            new CallSpec(OperationKind.Write),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Identity of the session (<c>AuthService.WhoAmI</c>); not in the R1 model (driver internal).</summary>
    internal Task<V1.WhoAmIResponse> WhoAmIAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return _executor.UnaryAsync(
            (invoker, options) => new V1.AuthService.AuthServiceClient(invoker).WhoAmIAsync(new V1.WhoAmIRequest(), options),
            cancellationToken);
    }

    /// <summary>Revokes the session (best effort) and closes every connection; idempotent. Later operations throw <see cref="ObjectDisposedException"/>.</summary>
    /// <returns>A task completing when the client is closed.</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _executor.Close();
        await _auth.LogoutAsync(_executor.AnyInvoker()).ConfigureAwait(false);
        _pool.Dispose();
        _tls.Dispose();
    }

    /// <summary>Closes every connection without revoking the session (prefer <see cref="DisposeAsync"/>; the session then simply expires).</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _executor.Close();
        _pool.Dispose();
        _tls.Dispose();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
}
