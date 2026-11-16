// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Rustegon.Driver.Internal.Transport;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Internal.DataPlane;

/// <summary>The database handle (see <see cref="IRustegonDatabase"/>).</summary>
internal sealed class RustegonDatabase : IRustegonDatabase
{
    private readonly DataContext _context;

    internal RustegonDatabase(DataContext context)
    {
        _context = context;
    }

    public string Name => _context.Database;

    private OperationExecutor Executor => _context.Executor;

    public IRustegonCollection<T> GetCollection<T>(string name)
        where T : class => new RustegonCollection<T>(_context, name);

    public IAsyncEnumerable<T> QueryAsync<T>(string rgql, RDocument? parameters = null, QueryOptions? options = null)
        where T : class
    {
        ArgumentException.ThrowIfNullOrEmpty(rgql);
        DocumentCodec<T>.EnsureSupported();
        return CursorEnumerable.Enumerate(ct => OpenQueryAsync<T>(_context, rgql, parameters, options, ct), CancellationToken.None);
    }

    /// <summary>Runs RGQL text as a cursor (shared with <see cref="ITransaction.QueryAsync{T}"/>).</summary>
    internal static async Task<IAsyncCursor<T>> OpenQueryAsync<T>(DataContext context, string rgql, RDocument? parameters, QueryOptions? options, CancellationToken cancellationToken)
        where T : class
    {
        var request = new V1.ExecuteRequest { Database = context.Database, Rgql = rgql, Options = new V1.ExecOptions { Consistency = context.Consistency(options) } };
        DataContext.AddParameters(request, parameters);
        if (options?.BatchSize is { } b)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(b, nameof(options));
            request.Options.BatchSize = (uint)b;
        }

        if (context.Transaction is null)
        {
            request.Options.WriteConcern = context.Executor.Concern(options?.WriteConcern);
        }

        // RGQL text may write: it is retried as a write (RetryWrites; the server deduplicates a
        // resent write by its request id, protocol.md §5.1), as the Java driver does (PD-097).
        return await AsyncCursor<T>.OpenAsync(context, request, context.Spec(OperationKind.Write, options), cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> CreateCollectionAsync(string name, CreateCollectionOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        _context.ThrowIfTransactional("CreateCollection");
        var request = new V1.CreateCollectionRequest { Database = Name, Name = name, IfNotExists = options?.IfNotExists ?? false };
        if (options?.Validator is { } v)
        {
            request.Validator = new V1.Validator
            {
                DefinitionJson = "{\"$jsonSchema\":" + v.JsonSchema + "}",
                Level = v.Level switch
                {
                    null => V1.ValidationLevel.Unspecified,
                    ValidationLevel.Off => V1.ValidationLevel.Off,
                    ValidationLevel.Strict => V1.ValidationLevel.Strict,
                    _ => V1.ValidationLevel.Moderate,
                },
                Action = v.Action switch
                {
                    null => V1.ValidationAction.Unspecified,
                    ValidationAction.Error => V1.ValidationAction.Error,
                    _ => V1.ValidationAction.Warn,
                },
            };
        }

        V1.CreateCollectionResponse response = await Executor.UnaryAsync(
            (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).CreateCollectionAsync(request, o),
            _context.Spec(OperationKind.NoRetry, options),
            cancellationToken).ConfigureAwait(false);
        return response.Created;
    }

    public async Task<bool> DropCollectionAsync(string name, DropOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        _context.ThrowIfTransactional("DropCollection");
        var request = new V1.DropCollectionRequest { Database = Name, Name = name, IfExists = options?.IfExists ?? false };
        V1.DropCollectionResponse response = await Executor.UnaryAsync(
            (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).DropCollectionAsync(request, o),
            _context.Spec(OperationKind.NoRetry, options),
            cancellationToken).ConfigureAwait(false);
        return response.Dropped;
    }

    public async Task<IReadOnlyList<string>> ListCollectionNamesAsync(CancellationToken cancellationToken = default)
    {
        _context.ThrowIfTransactional("ListCollections");
        var request = new V1.ListCollectionsRequest { Database = Name };
        V1.ListCollectionsResponse response = await Executor.UnaryAsync(
            (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).ListCollectionsAsync(request, o),
            _context.Spec(OperationKind.Read, null),
            cancellationToken).ConfigureAwait(false);
        return [.. response.Collections.Select(c => c.Name).Order(StringComparer.Ordinal)];
    }
}
