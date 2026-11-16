// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Rustegon.Driver.Internal.Transport;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Internal.DataPlane;

/// <summary>
/// An interactive transaction (see <see cref="ITransaction"/>; transactions.md §3, §5).
/// </summary>
/// <remarks>
/// State machine: <c>Active</c> → <c>Committed</c> (commit succeeded) | <c>Unknown</c> (commit
/// raised RGN-2006) | <c>Ended</c> (rollback sent). Only an <c>Active</c> transaction is rolled back
/// by <see cref="DisposeAsync"/>: rolling back after an unknown commit outcome could race the
/// commit, and the outcome is the caller's to resolve. A commit that failed definitively (e.g.
/// RGN-2001) leaves the state <c>Active</c>, so dispose still sends the (idempotent) rollback.
/// Operations are not checked against the state locally: the server is the authority (an
/// operation after a rollback fails there with RGN-2002, a second commit returns the first
/// outcome, FR-TXN-006). The heartbeat runs on its own task until the transaction leaves
/// <c>Active</c>; <see cref="_state"/> is read and written with <see cref="Interlocked"/>.
/// </remarks>
internal sealed class RustegonTransaction : ITransaction
{
    private const int Active = 0;
    private const int Committed = 1;
    private const int Unknown = 2;
    private const int Ended = 3;

    private readonly OperationExecutor _executor;
    private readonly string? _defaultDatabase;
    private readonly CancellationTokenSource _heartbeat = new();
    private int _state;
    private int _disposed;

    private RustegonTransaction(OperationExecutor executor, string? defaultDatabase, string id, TimeSpan heartbeatInterval)
    {
        _executor = executor;
        _defaultDatabase = defaultDatabase;
        TransactionId = id;
        if (heartbeatInterval > TimeSpan.Zero)
        {
            _ = HeartbeatAsync(heartbeatInterval, _heartbeat.Token);
        }
    }

    public string TransactionId { get; }

    /// <summary>Starts a transaction (<c>TransactionService.Begin</c>; transaction control is never retried alone, PD-097).</summary>
    internal static async Task<RustegonTransaction> BeginAsync(OperationExecutor executor, string? defaultDatabase, TransactionOptions? options, CancellationToken cancellationToken)
    {
        var request = new V1.BeginRequest
        {
            Isolation = options?.Isolation switch
            {
                null => V1.AstIsolation.Unspecified,
                IsolationLevel.Serializable => V1.AstIsolation.Serializable,
                IsolationLevel.Snapshot => V1.AstIsolation.Snapshot,
                _ => V1.AstIsolation.ReadCommitted,
            },
            ReadOnly = options?.ReadOnly ?? false,
            WriteConcern = executor.Concern(options?.WriteConcern),
        };

        // Follower and bounded-staleness reads exist only for read-only transactions (the server
        // refuses them otherwise, consistency.md): the consistency is sent for those only.
        if (request.ReadOnly)
        {
            request.Consistency = executor.Consistency(options?.ReadConsistency, options?.MaxStaleness);
        }

        V1.BeginResponse response = await executor.UnaryAsync(
            (invoker, o) => new V1.TransactionService.TransactionServiceClient(invoker).BeginAsync(request, o),
            new CallSpec(OperationKind.NoRetry),
            cancellationToken).ConfigureAwait(false);
        return new RustegonTransaction(executor, defaultDatabase, response.TxnId, TimeSpan.FromMilliseconds(response.HeartbeatIntervalMs));
    }

    /// <summary>The id for an operation of this transaction (a disposed transaction is a caller bug).</summary>
    internal string IdForOperation()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return TransactionId;
    }

    public IRustegonCollection<T> Collection<T>(string name)
        where T : class
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        int dot = name.IndexOf('.', StringComparison.Ordinal);
        return dot > 0
            ? GetDatabase(name[..dot]).GetCollection<T>(name[(dot + 1)..])
            : GetDatabase(DefaultDatabase()).GetCollection<T>(name);
    }

    public IRustegonDatabase GetDatabase(string name) => new RustegonDatabase(new DataContext(_executor, name, this));

    public IAsyncEnumerable<T> QueryAsync<T>(string rgql, RDocument? parameters = null, QueryOptions? options = null)
        where T : class => GetDatabase(DefaultDatabase()).QueryAsync<T>(rgql, parameters, options);

    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await Call(
                (invoker, o) => new V1.TransactionService.TransactionServiceClient(invoker).CommitAsync(new V1.CommitRequest { TxnId = IdForOperation() }, o),
                cancellationToken).ConfigureAwait(false);
            Leave(Committed);
        }
        catch (CommitOutcomeUnknownException e)
        {
            Leave(Unknown);
            e.AttachResolver(ResolveAsync);
            throw;
        }
        catch (RustegonException e) when (e.InnerException is Grpc.Core.RpcException rpc && ErrorMapper.MayHaveReachedServer(rpc))
        {
            // A commit lost after it was sent (connection reset, node killed, deadline without an
            // answer) may have committed: never report it as a retryable transport error, or
            // WithTransactionAsync would run the callback again (PD-119, as Java PD-122).
            var unknown = new CommitOutcomeUnknownException(
                new RustegonError(Errors.ErrorCodes.CommitOutcomeUnknown, ErrorCatalog.NameOf(Errors.ErrorCodes.CommitOutcomeUnknown), false, null, RustegonError.NoDetails, e.TraceId, null),
                "The commit reply was lost (" + e.Message + "); the outcome is unknown.",
                e);
            Leave(Unknown);
            unknown.AttachResolver(ResolveAsync);
            throw unknown;
        }
    }

    public async Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        // Ended before the call: a failed rollback must not be repeated by dispose (best effort
        // callers) and the server aborts an abandoned transaction on its own anyway.
        Leave(Ended);
        await Call(
            (invoker, o) => new V1.TransactionService.TransactionServiceClient(invoker).RollbackAsync(new V1.RollbackRequest { TxnId = IdForOperation() }, o),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<TransactionOutcome> ResolveAsync(CancellationToken cancellationToken = default)
    {
        V1.StatusResponse status = await Call(
            (invoker, o) => new V1.TransactionService.TransactionServiceClient(invoker).StatusAsync(new V1.StatusRequest { TxnId = TransactionId }, o),
            cancellationToken).ConfigureAwait(false);
        return status.State switch
        {
            V1.TransactionState.Committed => TransactionOutcome.Committed,
            V1.TransactionState.Aborted => TransactionOutcome.Aborted,

            // ACTIVE, COMMITTING and states unknown to this driver: never "aborted" by guess.
            _ => TransactionOutcome.Unknown,
        };
    }

    /// <summary>Rolls back without failing (transactions.md §5 "rollback(txn) (best effort)").</summary>
    internal async Task RollbackBestEffortAsync()
    {
        if (Volatile.Read(ref _state) != Active)
        {
            return;
        }

        try
        {
            await RollbackAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (RustegonException)
        {
            // Best effort: the server rolls an abandoned transaction back when it expires.
        }
        catch (ObjectDisposedException)
        {
            // The client was closed meanwhile.
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (Volatile.Read(ref _state) == Active)
        {
            // Leave Active first so a concurrent dispose cannot send a second rollback.
            Leave(Ended);
            try
            {
                await Call(
                    (invoker, o) => new V1.TransactionService.TransactionServiceClient(invoker).RollbackAsync(new V1.RollbackRequest { TxnId = TransactionId }, o),
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (RustegonException)
            {
                // As RollbackBestEffortAsync.
            }
            catch (ObjectDisposedException)
            {
                // As RollbackBestEffortAsync.
            }
        }

        StopHeartbeat();
        _heartbeat.Dispose();
    }

    private string DefaultDatabase() =>
        _defaultDatabase ?? throw new InvalidOperationException("The client has no DefaultDatabase: name the collection \"db.coll\" or use GetDatabase(name).");

    private Task<TResponse> Call<TResponse>(Func<Grpc.Core.CallInvoker, Grpc.Core.CallOptions, Grpc.Core.AsyncUnaryCall<TResponse>> call, CancellationToken cancellationToken) =>
        _executor.UnaryAsync(call, new CallSpec(OperationKind.NoRetry), cancellationToken);

    private void Leave(int state)
    {
        if (Interlocked.CompareExchange(ref _state, state, Active) == Active)
        {
            StopHeartbeat();
        }
    }

    private void StopHeartbeat()
    {
        try
        {
            _heartbeat.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already stopped.
        }
    }

    /// <summary>
    /// Keeps the transaction alive while the application is busy elsewhere (transaction.proto:
    /// the coordinator aborts a transaction idle beyond its liveness timeout with RGN-2003 /
    /// RGN-2002). Failures are ignored: the next operation reports a dead transaction anyway.
    /// </summary>
    private async Task HeartbeatAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        try
        {
            using var timer = new PeriodicTimer(interval);
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    await Call(
                        (invoker, o) => new V1.TransactionService.TransactionServiceClient(invoker).HeartbeatAsync(new V1.HeartbeatRequest { TxnId = TransactionId }, o),
                        cancellationToken).ConfigureAwait(false);
                }
                catch (RustegonException)
                {
                    // Ignored (see the summary).
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Stopped by commit, rollback or dispose.
        }
        catch (ObjectDisposedException)
        {
            // The client was closed.
        }
    }
}

/// <summary>
/// <c>WithTransactionAsync</c>: the normative retry loop of transactions.md §5 (and its
/// clarifications), pinned by retry.yaml R6.
/// </summary>
internal static class TransactionRunner
{
    internal static async Task<TResult> RunAsync<TResult>(
        OperationExecutor executor,
        string? defaultDatabase,
        Func<ITransaction, CancellationToken, Task<TResult>> callback,
        TransactionOptions? options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(callback);
        DateTime deadline = DateTime.UtcNow + (options?.MaxRetryTime ?? TimeSpan.FromMinutes(2));
        int attempt = 0;
        while (true)
        {
            RustegonTransaction txn = await RustegonTransaction.BeginAsync(executor, defaultDatabase, options, cancellationToken).ConfigureAwait(false);
            await using (txn.ConfigureAwait(false))
            {
                RustegonException retryable;
                try
                {
                    TResult result = await callback(txn, cancellationToken).ConfigureAwait(false);
                    try
                    {
                        await txn.CommitAsync(cancellationToken).ConfigureAwait(false);
                        return result;
                    }
                    catch (CommitOutcomeUnknownException unknown)
                    {
                        // Never re-run blindly while the outcome is unknown: ask the server.
                        if (await ResolveAsync(txn, unknown, deadline, cancellationToken).ConfigureAwait(false))
                        {
                            return result;
                        }

                        // Resolved as ABORTED: it definitely did not commit, so it is handled like a
                        // retryable error.
                        retryable = new TransactionAbortedException(
                            new RustegonError(Errors.ErrorCodes.TransactionAborted, ErrorCatalog.NameOf(Errors.ErrorCodes.TransactionAborted), true, false, RustegonError.NoDetails, unknown.TraceId, null),
                            "The commit outcome was unknown and the transaction status reports it aborted.",
                            unknown);
                    }
                }
                catch (RustegonException e) when (e.IsRetryable && e is not CommitOutcomeUnknownException && DateTime.UtcNow < deadline)
                {
                    retryable = e;
                }
                catch
                {
                    // Non-retryable errors, errors at the deadline and exceptions of the callback
                    // itself: roll back and propagate unchanged.
                    await txn.RollbackBestEffortAsync().ConfigureAwait(false);
                    throw;
                }

                await txn.RollbackBestEffortAsync().ConfigureAwait(false);
                if (DateTime.UtcNow >= deadline)
                {
                    throw retryable;
                }
            }

            attempt++;
            await OperationExecutor.DelayAtLeastAsync(Clamp(OperationExecutor.Backoff(attempt), deadline), cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Resolves an unknown commit with <c>Status</c>: true = committed, false = aborted; while the
    /// state stays ACTIVE / COMMITTING / UNSPECIFIED it polls with the same backoff until the
    /// deadline and then rethrows <paramref name="unknown"/> (with its resolver attached).
    /// </summary>
    private static async Task<bool> ResolveAsync(RustegonTransaction txn, CommitOutcomeUnknownException unknown, DateTime deadline, CancellationToken cancellationToken)
    {
        int attempt = 0;
        while (true)
        {
            TransactionOutcome outcome;
            try
            {
                outcome = await txn.ResolveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (RustegonException)
            {
                // A failed Status call says nothing about the commit: still unknown. It must never
                // reach the re-run path (the transaction could apply twice): keep polling.
                outcome = TransactionOutcome.Unknown;
            }

            switch (outcome)
            {
                case TransactionOutcome.Committed:
                    return true;
                case TransactionOutcome.Aborted:
                    return false;
            }

            if (DateTime.UtcNow >= deadline)
            {
                throw unknown;
            }

            attempt++;
            await OperationExecutor.DelayAtLeastAsync(Clamp(OperationExecutor.Backoff(attempt), deadline), cancellationToken).ConfigureAwait(false);
        }
    }

    private static TimeSpan Clamp(TimeSpan delay, DateTime deadline)
    {
        TimeSpan left = deadline - DateTime.UtcNow;
        return left <= TimeSpan.Zero ? TimeSpan.Zero : (delay < left ? delay : left);
    }
}
