// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using Rustegon.Driver.Internal.Builders;
using Rustegon.Driver.Internal.Transport;
using Rustegon.Driver.Mapping;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Internal.DataPlane;

/// <summary>
/// The codec of a document type (dotnet-driver.md §7): <see cref="RDocument"/> as is, otherwise the
/// generated or (opted-in) reflection codec of <see cref="RDocCodecRegistry"/>. Handles resolve it
/// when they are created, so an unmapped type fails there rather than at the first I/O.
/// </summary>
internal static class DocumentCodec<T>
    where T : class
{
    internal static void EnsureSupported() => _ = RDocCodecRegistry.Get<T>();

    internal static RDocument ToDocument(T value) => RDocCodecRegistry.Get<T>().Encode(value ?? throw new ArgumentNullException(nameof(value)));

    internal static T FromDocument(RDocument document) => RDocCodecRegistry.Get<T>().Decode(document);

    internal static V1.Document Encode(T value) => new() { Rdoc = UnsafeByteOperations.UnsafeWrap(ToDocument(value).ToBytes()) };

    internal static T Decode(V1.Document document) => FromDocument(RDocReader.ReadDocument(document.Rdoc.Span));
}

/// <summary>
/// Where data-plane operations run: the client's executor, a database, and optionally a
/// transaction. Inside a transaction requests carry its id, are never retried alone (retry.yaml
/// R2), and per-operation consistency / write concern are not sent (the transaction's apply).
/// </summary>
internal sealed class DataContext
{
    internal DataContext(OperationExecutor executor, string database, RustegonTransaction? transaction)
    {
        ArgumentException.ThrowIfNullOrEmpty(database);
        Executor = executor;
        Database = database;
        Transaction = transaction;
    }

    internal OperationExecutor Executor { get; }

    internal string Database { get; }

    internal RustegonTransaction? Transaction { get; }

    /// <summary>The transaction id to put into a request, or null outside a transaction.</summary>
    internal string? TxnId => Transaction?.IdForOperation();

    internal DataContext WithDatabase(string database) => new(Executor, database, Transaction);

    internal CallSpec Spec(OperationKind kind, OperationOptions? options) => Transaction is null
        ? new CallSpec(kind, options?.Timeout, ClientSession.Of(options?.Session))
        : new CallSpec(OperationKind.NoRetry, options?.Timeout);

    internal V1.ReadConsistency? Consistency(ReadOperationOptions? options) =>
        Transaction is null ? Executor.Consistency(options?.ReadConsistency, options?.MaxStaleness) : null;

    internal V1.WriteOptions? WriteOptions(WriteOperationOptions? options) =>
        Transaction is null ? new V1.WriteOptions { WriteConcern = Executor.Concern(options?.WriteConcern) } : null;

    internal void ThrowIfTransactional(string what)
    {
        if (Transaction is not null)
        {
            throw new NotSupportedException($"{what} is not transactional; run it on a handle of RustegonClient.GetDatabase.");
        }
    }

    /// <summary>Runs an <c>Execute</c> (retry before the first batch only) and returns its batches.</summary>
    internal async Task<List<V1.ResultBatch>> ExecuteAsync(V1.ExecuteRequest request, CallSpec spec, CancellationToken cancellationToken)
    {
        if (TxnId is { } txn)
        {
            request.TxnId = txn;
        }

        List<V1.ExecuteResponse> responses = await Executor.ServerStreamAsync(
            (invoker, o) => new V1.QueryService.QueryServiceClient(invoker).Execute(request, o),
            spec,
            cancellationToken).ConfigureAwait(false);
        var batches = new List<V1.ResultBatch>(responses.Count);
        foreach (V1.ExecuteResponse r in responses)
        {
            batches.Add(r.Batch ?? new V1.ResultBatch());
        }

        return batches;
    }

    /// <summary>Runs a data-modifying statement and returns the server's <c>docs_affected</c>.</summary>
    internal async Task<long> ExecuteWriteAsync(V1.AstStatement statement, ParamSink sink, WriteOperationOptions? options, CancellationToken cancellationToken)
    {
        var request = new V1.ExecuteRequest { Database = Database, Ast = statement, Options = new V1.ExecOptions() };
        request.Params.Add(sink.Params);
        if (Transaction is null)
        {
            request.Options.WriteConcern = Executor.Concern(options?.WriteConcern);
        }

        List<V1.ResultBatch> batches = await ExecuteAsync(request, Spec(OperationKind.Write, options), cancellationToken).ConfigureAwait(false);
        long affected = 0;
        foreach (V1.ResultBatch b in batches)
        {
            if (b.Stats is not null)
            {
                affected = (long)b.Stats.DocsAffected;
            }
        }

        return affected;
    }

    /// <summary>The parameters of a query as wire values.</summary>
    internal static void AddParameters(V1.ExecuteRequest request, RDocument? parameters)
    {
        if (parameters is null)
        {
            return;
        }

        foreach (KeyValuePair<string, RDocValue> p in parameters)
        {
            request.Params[p.Key] = AstBuild.Value(p.Value);
        }
    }
}
