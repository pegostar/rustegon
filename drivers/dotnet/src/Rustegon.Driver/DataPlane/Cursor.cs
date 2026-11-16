// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Rustegon.Driver.Internal.Transport;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Internal.DataPlane;

/// <summary>
/// A query cursor (protocol.md §3, query.proto). Queries run with <c>max_batches = 1</c>, so the
/// <c>Execute</c> stream carries one batch and, when more rows exist, a <c>cursor_id</c>; each
/// further batch is one <c>GetMore</c>. Memory is bounded by one batch, a failed <c>Execute</c> is
/// retried only before its batch arrived and <c>GetMore</c> never (retry.yaml R3: it would skip or
/// repeat rows). Disposing a cursor that still has a server cursor kills it (best effort: the
/// server also expires idle cursors).
/// </summary>
/// <remarks>Not thread-safe, like any enumerator: one consumer at a time.</remarks>
internal sealed class AsyncCursor<T> : IAsyncCursor<T>
    where T : class
{
    private static readonly TimeSpan KillTimeout = TimeSpan.FromSeconds(5);

    private readonly DataContext _context;
    private readonly ClientSession? _session;
    private readonly uint? _batchSize;
    private readonly CancellationToken _cancellationToken;
    private readonly Queue<V1.Document> _buffer = new();
    private string? _cursorId;
    private T? _current;
    private bool _disposed;

    private AsyncCursor(DataContext context, ClientSession? session, uint? batchSize, CancellationToken cancellationToken)
    {
        _context = context;
        _session = session;
        _batchSize = batchSize;
        _cancellationToken = cancellationToken;
    }

    public T Current => _current ?? throw new InvalidOperationException("MoveNextAsync has not returned true.");

    /// <summary>Runs the query and positions the cursor before its first row.</summary>
    internal static async Task<AsyncCursor<T>> OpenAsync(DataContext context, V1.ExecuteRequest request, CallSpec spec, CancellationToken cancellationToken)
    {
        request.Options ??= new V1.ExecOptions();
        request.Options.MaxBatches = 1;
        var cursor = new AsyncCursor<T>(context, spec.Session, request.Options.HasBatchSize ? request.Options.BatchSize : null, cancellationToken);
        foreach (V1.ResultBatch batch in await context.ExecuteAsync(request, spec, cancellationToken).ConfigureAwait(false))
        {
            cursor.Take(batch);
        }

        return cursor;
    }

    public async ValueTask<bool> MoveNextAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        while (_buffer.Count == 0)
        {
            if (_cursorId is null)
            {
                _current = null;
                return false;
            }

            var request = new V1.GetMoreRequest { CursorId = _cursorId };
            if (_batchSize is { } size)
            {
                request.BatchSize = size;
            }

            // The cursor is spent whatever happens: a failed GetMore is not retried (R3), and the
            // server closes an exhausted cursor itself.
            _cursorId = null;
            V1.GetMoreResponse response = await _context.Executor.UnaryAsync(
                (invoker, o) => new V1.QueryService.QueryServiceClient(invoker).GetMoreAsync(request, o),
                new CallSpec(OperationKind.NoRetry, Session: _session),
                _cancellationToken).ConfigureAwait(false);
            Take(response.Batch ?? new V1.ResultBatch());
        }

        _current = DocumentCodec<T>.Decode(_buffer.Dequeue());
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _buffer.Clear();
        string? id = _cursorId;
        _cursorId = null;
        if (id is null)
        {
            return;
        }

        try
        {
            await _context.Executor.UnaryAsync(
                (invoker, o) => new V1.QueryService.QueryServiceClient(invoker).KillCursorAsync(new V1.KillCursorRequest { CursorId = id }, o),
                new CallSpec(OperationKind.NoRetry, KillTimeout),
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (RustegonException)
        {
            // Best effort: an unreachable server expires the cursor on its own.
        }
        catch (ObjectDisposedException)
        {
            // The client was closed first; its server-side cursors die with the session.
        }
    }

    private void Take(V1.ResultBatch batch)
    {
        foreach (V1.Document d in batch.Docs)
        {
            _buffer.Enqueue(d);
        }

        if (batch.HasCursorId && batch.CursorId.Length > 0)
        {
            _cursorId = batch.CursorId;
        }
    }
}

/// <summary>Async enumeration over a cursor that is opened on the first <c>MoveNextAsync</c>.</summary>
internal static class CursorEnumerable
{
    internal static async IAsyncEnumerable<T> Enumerate<T>(
        Func<CancellationToken, Task<IAsyncCursor<T>>> open,
        [EnumeratorCancellation] CancellationToken cancellationToken)
        where T : class
    {
        IAsyncCursor<T> cursor = await open(cancellationToken).ConfigureAwait(false);
        await using (cursor.ConfigureAwait(false))
        {
            while (await cursor.MoveNextAsync().ConfigureAwait(false))
            {
                yield return cursor.Current;
            }
        }
    }
}
