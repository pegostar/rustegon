// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;
using Rustegon.Driver.Errors;
using Rustegon.Driver.Internal.Auth;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Internal.Transport;

/// <summary>How the retry policy treats an operation (retry.yaml R2).</summary>
internal enum OperationKind
{
    /// <summary>A read: retried when <see cref="RustegonClientSettings.RetryReads"/>.</summary>
    Read,

    /// <summary>A write outside a transaction: retried when <see cref="RustegonClientSettings.RetryWrites"/>, with the same request id.</summary>
    Write,

    /// <summary>Never retried alone: operations inside a transaction, transaction control (begin/commit/rollback/status/heartbeat), DDL (create/drop), GetMore, KillCursor (R2, R3, PD-097).</summary>
    NoRetry,
}

/// <summary>What the executor needs to know about one operation.</summary>
/// <param name="Kind">Retry class.</param>
/// <param name="Timeout">Deadline of the whole operation (all attempts); null = the client default.</param>
/// <param name="Session">Session whose causality token is sent and updated, or null.</param>
internal readonly record struct CallSpec(OperationKind Kind, TimeSpan? Timeout = null, ClientSession? Session = null);

/// <summary>
/// Runs one operation: picks a channel, attaches request id, authorization, causality token and
/// deadline, maps failures to the exception hierarchy, and applies the retry policy of
/// dotnet-driver.md §8 as pinned by <c>drivers/conformance/retry.yaml</c>:
/// <list type="bullet">
/// <item>R1: retried only when the failure's <c>ErrorDetail.retryable</c> (or its transport
/// fallback) says so, at most <see cref="RustegonClientSettings.MaxRetries"/> times, full-jitter
/// backoff base 10 ms ×2 capped at 1 s; RateLimited waits at least <c>retry_after_ms</c>;</item>
/// <item>R2: reads need <c>RetryReads</c>; writes need <c>RetryWrites</c> and resend the same
/// <c>rgn-request-id</c> (the server deduplicates, protocol.md §5.1); nothing inside a transaction
/// is retried alone;</item>
/// <item>R4: the deadline belongs to the operation, not to an attempt; once it has passed (or a
/// backoff would pass it) nothing is retried;</item>
/// <item>R5: RGN-4005 on a session credential re-authenticates once and resends once, outside the
/// retry budget; a second RGN-4005 is surfaced.</item>
/// </list>
/// R3 (no retry of GetMore / of a stream that delivered data) is the callers' choice of
/// <see cref="OperationKind.NoRetry"/> and of <see cref="ServerStreamAsync"/>.
/// </summary>
internal sealed class OperationExecutor
{
    /// <summary>Backoff base (retry.yaml <c>defaults.backoff</c>, transactions.md §5).</summary>
    internal static readonly TimeSpan BackoffBase = TimeSpan.FromMilliseconds(10);

    /// <summary>Backoff cap.</summary>
    internal static readonly TimeSpan BackoffCap = TimeSpan.FromSeconds(1);

    private readonly ChannelPool _pool;
    private readonly SessionAuthenticator _auth;
    private readonly RustegonClientSettings _settings;
    private int _closed;

    internal OperationExecutor(ChannelPool pool, SessionAuthenticator auth, RustegonClientSettings settings)
    {
        _pool = pool;
        _auth = auth;
        _settings = settings;
    }

    /// <summary>The client settings (read-only use).</summary>
    internal RustegonClientSettings Settings => _settings;

    /// <summary>The authenticator (eager login of <c>RustegonClient.ConnectAsync</c>).</summary>
    internal SessionAuthenticator Authenticator => _auth;

    /// <summary>The channel pool (driver internal; the stress tests read its counters).</summary>
    internal ChannelPool Pool => _pool;

    /// <summary>Marks the client closed: later operations fail with <see cref="ObjectDisposedException"/> before any I/O.</summary>
    internal void Close() => Volatile.Write(ref _closed, 1);

    internal void ThrowIfClosed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _closed) != 0, typeof(RustegonClient));

    /// <summary>Full-jitter backoff of the <paramref name="attempt"/>-th retry (1-based): uniform in [0, min(cap, base·2^(attempt−1))].</summary>
    internal static TimeSpan Backoff(int attempt)
    {
        double ceiling = Math.Min(BackoffCap.TotalMilliseconds, BackoffBase.TotalMilliseconds * Math.Pow(2, Math.Max(0, attempt - 1)));
        return TimeSpan.FromMilliseconds(RandomNumberGenerator.GetInt32((int)ceiling + 1));
    }

    /// <summary>
    /// Waits at least <paramref name="delay"/>: timer-based delays may fire up to a clock tick
    /// early, and RateLimited must wait at least <c>retry_after_ms</c> (retry.yaml R1).
    /// </summary>
    internal static async Task DelayAtLeastAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        long start = Stopwatch.GetTimestamp();
        TimeSpan left = delay;
        while (left > TimeSpan.Zero)
        {
            await Task.Delay(left, cancellationToken).ConfigureAwait(false);
            left = delay - Stopwatch.GetElapsedTime(start);
        }
    }

    /// <summary>Runs a unary call with the retry policy (Ping, GetServerInfo and older call sites: reads).</summary>
    internal Task<TResponse> UnaryAsync<TResponse>(
        Func<CallInvoker, CallOptions, AsyncUnaryCall<TResponse>> call,
        CancellationToken cancellationToken) => UnaryAsync(call, new CallSpec(OperationKind.Read), cancellationToken);

    /// <summary>Runs a unary call with the retry policy.</summary>
    /// <param name="call">Starts the call on an invoker with the given options.</param>
    /// <param name="spec">Retry class, timeout and session.</param>
    /// <param name="cancellationToken">Caller cancellation.</param>
    internal async Task<TResponse> UnaryAsync<TResponse>(
        Func<CallInvoker, CallOptions, AsyncUnaryCall<TResponse>> call,
        CallSpec spec,
        CancellationToken cancellationToken)
    {
        ThrowIfClosed();
        var attempt = new Attempts(this, spec);
        ChannelPool.Slot? failed = null;
        while (true)
        {
            ChannelPool.Lease lease = _pool.Acquire(failed);
            string? authorization = null;
            RustegonException failure;
            try
            {
                authorization = await _auth.GetAuthorizationAsync(lease.Invoker, cancellationToken).ConfigureAwait(false);
                using AsyncUnaryCall<TResponse> pending = call(lease.Invoker, attempt.Options(authorization, cancellationToken));
                TResponse response = await pending.ResponseAsync.ConfigureAwait(false);
                spec.Session?.Observe(pending.GetTrailers());
                return response;
            }
            catch (RpcException e) when (e.StatusCode == StatusCode.Cancelled && cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException("The operation was cancelled.", e, cancellationToken);
            }
            catch (RpcException e)
            {
                failure = ErrorMapper.FromRpcException(e);
            }
            catch (RustegonException e)
            {
                // A failed login (mapped by the authenticator) follows the same policy.
                failure = e;
            }
            finally
            {
                lease.Dispose();
            }

            failed = lease.Slot;

            if (!await attempt.RetryAsync(failure, authorization, cancellationToken).ConfigureAwait(false))
            {
                throw failure;
            }
        }
    }

    /// <summary>
    /// Runs a server-streaming call and reads every message. A failure before the first message
    /// follows the retry policy; once a message has arrived the stream is never retried (R3), so
    /// no row can be delivered twice.
    /// </summary>
    internal async Task<List<TResponse>> ServerStreamAsync<TResponse>(
        Func<CallInvoker, CallOptions, AsyncServerStreamingCall<TResponse>> call,
        CallSpec spec,
        CancellationToken cancellationToken)
    {
        ThrowIfClosed();
        var attempt = new Attempts(this, spec);
        ChannelPool.Slot? failed = null;
        while (true)
        {
            ChannelPool.Lease lease = _pool.Acquire(failed);
            string? authorization = null;
            var messages = new List<TResponse>();
            RustegonException failure;
            try
            {
                authorization = await _auth.GetAuthorizationAsync(lease.Invoker, cancellationToken).ConfigureAwait(false);
                using AsyncServerStreamingCall<TResponse> pending = call(lease.Invoker, attempt.Options(authorization, cancellationToken));
                while (await pending.ResponseStream.MoveNext(cancellationToken).ConfigureAwait(false))
                {
                    messages.Add(pending.ResponseStream.Current);
                }

                spec.Session?.Observe(pending.GetTrailers());
                return messages;
            }
            catch (RpcException e) when (e.StatusCode == StatusCode.Cancelled && cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException("The operation was cancelled.", e, cancellationToken);
            }
            catch (RpcException e)
            {
                failure = ErrorMapper.FromRpcException(e);
            }
            catch (RustegonException e)
            {
                failure = e;
            }
            finally
            {
                lease.Dispose();
            }

            failed = lease.Slot;

            if (messages.Count > 0 || !await attempt.RetryAsync(failure, authorization, cancellationToken).ConfigureAwait(false))
            {
                throw failure;
            }
        }
    }

    /// <summary>A channel for calls that manage their own lifecycle (logout on dispose).</summary>
    internal CallInvoker AnyInvoker()
    {
        using ChannelPool.Lease lease = _pool.Acquire();
        return lease.Invoker;
    }

    /// <summary>The proto read consistency of an operation (null = server default; never inside a transaction).</summary>
    internal V1.ReadConsistency? Consistency(ReadConsistency? level, TimeSpan? maxStaleness)
    {
        ReadConsistency? effective = level ?? _settings.ReadConsistency;
        if (effective is null)
        {
            return null;
        }

        TimeSpan? staleness = maxStaleness ?? _settings.MaxStaleness;
        if (effective == ReadConsistency.BoundedStaleness && staleness is null)
        {
            throw new ArgumentException("ReadConsistency.BoundedStaleness needs MaxStaleness.");
        }

        if (staleness <= TimeSpan.Zero)
        {
            throw new ArgumentException("MaxStaleness must be positive.");
        }

        var c = new V1.ReadConsistency
        {
            Level = effective switch
            {
                ReadConsistency.Linearizable => V1.ReadConsistencyLevel.Linearizable,
                ReadConsistency.BoundedStaleness => V1.ReadConsistencyLevel.BoundedStaleness,
                _ => V1.ReadConsistencyLevel.Follower,
            },
        };
        if (effective != ReadConsistency.Linearizable && staleness is { } s)
        {
            c.MaxStalenessMs = (uint)Math.Min(uint.MaxValue, Math.Ceiling(s.TotalMilliseconds));
        }

        return c;
    }

    /// <summary>The proto write concern of an operation (unspecified = server default).</summary>
    internal V1.WriteConcern Concern(WriteConcern? concern) => (concern ?? _settings.WriteConcern) switch
    {
        null => V1.WriteConcern.Unspecified,
        WriteConcern.Majority => V1.WriteConcern.Majority,
        WriteConcern.All => V1.WriteConcern.All,
        WriteConcern.LocalDcMajority => V1.WriteConcern.LocalDcMajority,
        WriteConcern.SyncCrossDc => V1.WriteConcern.SyncCrossDc,
        _ => V1.WriteConcern.AsyncCrossDc,
    };

    /// <summary>Per-operation state of the retry loop.</summary>
    private sealed class Attempts
    {
        private readonly OperationExecutor _executor;
        private readonly CallSpec _spec;

        // One id for every attempt: a retry after a lost response is deduplicated by the server
        // (protocol.md §5.1) instead of executing twice.
        private readonly string _requestId = RustegonInterceptor.NewRequestId();
        private readonly DateTime _deadline;
        private int _retries;
        private bool _reauthenticated;

        internal Attempts(OperationExecutor executor, CallSpec spec)
        {
            _executor = executor;
            _spec = spec;
            _deadline = DateTime.UtcNow + (spec.Timeout ?? executor._settings.DefaultOperationTimeout);
        }

        internal CallOptions Options(string? authorization, CancellationToken cancellationToken)
        {
            var headers = new Metadata { { RustegonInterceptor.RequestIdHeader, _requestId } };
            if (authorization is not null)
            {
                headers.Add("authorization", authorization);
            }

            if (_spec.Session?.TokenToSend is { } token)
            {
                headers.Add(ClientSession.CausalityTokenHeader, token);
            }

            return new CallOptions(headers, _deadline, cancellationToken);
        }

        /// <summary>Whether to resend after <paramref name="failure"/> (after the backoff wait).</summary>
        internal async Task<bool> RetryAsync(RustegonException failure, string? authorization, CancellationToken cancellationToken)
        {
            if (failure.Code == ErrorCodes.SessionExpired)
            {
                // R5: an expired session is cured by a new login, once, outside the budget.
                if (_reauthenticated || !_executor._auth.UsesSessions)
                {
                    return false;
                }

                _reauthenticated = true;
                _executor._auth.Invalidate(authorization);
                return true;
            }

            RustegonClientSettings s = _executor._settings;
            bool allowed = _spec.Kind switch
            {
                OperationKind.Read => s.RetryReads,
                OperationKind.Write => s.RetryWrites,
                _ => false,
            };
            if (!failure.IsRetryable || !allowed || _retries >= s.MaxRetries)
            {
                return false;
            }

            _retries++;
            TimeSpan delay = Backoff(_retries);
            if (failure is RateLimitedException { RetryAfter: { } after } && after > delay)
            {
                delay = after;
            }

            if (DateTime.UtcNow + delay >= _deadline)
            {
                return false;
            }

            await DelayAtLeastAsync(delay, cancellationToken).ConfigureAwait(false);
            return true;
        }
    }
}
