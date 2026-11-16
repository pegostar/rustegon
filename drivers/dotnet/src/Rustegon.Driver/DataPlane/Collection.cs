// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Rustegon.Driver.Internal.Builders;
using Rustegon.Driver.Internal.Transport;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Internal.DataPlane;

/// <summary>
/// The statements of collection operations with non-id filters (conformance README §4 rules 3–6,
/// PD-070), pinned by <c>drivers/conformance/ast/statements.json</c>.
/// </summary>
internal static class Statements
{
    /// <summary><c>FROM c [WHERE f] [SELECT p] [ORDER BY s] [LIMIT n] [OFFSET m]</c>.</summary>
    internal static V1.AstStatement Find(string collection, Filter filter, Sort? sort, Projection? projection, long? limit, long? skip, ParamSink sink)
    {
        var query = new V1.AstQuery
        {
            From = new V1.AstFromClause { Source = new V1.AstSource { Collection = new V1.AstQualifiedName { Name = collection } } },
            Where = filter.ToAst(sink),
            Select = projection?.ToAst(),
            Limit = limit is { } l ? AstBuild.Int(l) : null,
            Offset = skip is { } s ? AstBuild.Int(s) : null,
        };
        if (sort is not null)
        {
            query.OrderBy.Add(sort.ToAst());
        }

        return new V1.AstStatement { Query = query };
    }

    /// <summary><c>UPDATE c &lt;ops&gt; [WHERE f] [LIMIT 1] [OPTIONS (allow_full_scan_write = true)]</c>.</summary>
    internal static V1.AstStatement Update(string collection, Filter filter, Update update, bool one, ParamSink sink)
    {
        // Filter parameters first (f*), then update parameters (u*): the two counters are
        // independent, so the order only matters within each kind.
        V1.AstExpr? where = filter.ToAst(sink);
        var u = new V1.AstUpdate
        {
            Target = new V1.AstQualifiedName { Name = collection },
            Where = where,
            Limit = one ? AstBuild.Int(1) : null,
        };
        u.Ops.Add(update.ToAst(sink));
        if (filter.IsEmpty)
        {
            // Without a WHERE the server refuses a write unless asked explicitly (RGN-1013); the
            // empty filter is that explicit request (README §4 rule 5).
            u.Options.Add(AstBuild.AllowFullScanWrite());
        }

        return new V1.AstStatement { Update = u };
    }

    /// <summary><c>DELETE FROM c [WHERE f] [LIMIT 1] [OPTIONS (allow_full_scan_write = true)]</c>.</summary>
    internal static V1.AstStatement Delete(string collection, Filter filter, bool one, ParamSink sink)
    {
        var d = new V1.AstDelete
        {
            Target = new V1.AstQualifiedName { Name = collection },
            Where = filter.ToAst(sink),
            Limit = one ? AstBuild.Int(1) : null,
        };
        if (filter.IsEmpty)
        {
            d.Options.Add(AstBuild.AllowFullScanWrite());
        }

        return new V1.AstStatement { Delete = d };
    }
}

/// <summary>The collection handle (see <see cref="IRustegonCollection{T}"/>).</summary>
internal sealed class RustegonCollection<T> : IRustegonCollection<T>
    where T : class
{
    private readonly DataContext _context;

    internal RustegonCollection(DataContext context, string name)
    {
        DocumentCodec<T>.EnsureSupported();
        ArgumentException.ThrowIfNullOrEmpty(name);
        _context = context;
        Name = name;
    }

    public string DatabaseName => _context.Database;

    public string Name { get; }

    private OperationExecutor Executor => _context.Executor;

    public async Task<InsertOneResult> InsertOneAsync(T document, InsertOptions? options = null, CancellationToken cancellationToken = default)
    {
        InsertManyResult r = await InsertAsync([document], options, cancellationToken).ConfigureAwait(false);
        return new InsertOneResult(r.InsertedIds[0]);
    }

    public Task<InsertManyResult> InsertManyAsync(IEnumerable<T> documents, InsertOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(documents);
        T[] all = [.. documents];
        if (all.Length == 0)
        {
            throw new ArgumentException("InsertMany needs at least one document.", nameof(documents));
        }

        return InsertAsync(all, options, cancellationToken);
    }

    private async Task<InsertManyResult> InsertAsync(T[] documents, InsertOptions? options, CancellationToken cancellationToken)
    {
        var request = new V1.InsertRequest { Database = _context.Database, Collection = Name, Options = _context.WriteOptions(options) };
        foreach (T d in documents)
        {
            request.Documents.Add(DocumentCodec<T>.Encode(d));
        }

        SetTxn(id => request.TxnId = id);
        V1.InsertResponse response = await Executor.UnaryAsync(
            (invoker, o) => new V1.DocumentService.DocumentServiceClient(invoker).InsertAsync(request, o),
            _context.Spec(OperationKind.Write, options),
            cancellationToken).ConfigureAwait(false);
        return new InsertManyResult([.. response.Results.Select(r => AstBuild.FromValue(r.Id))]);
    }

    public async Task<T?> FindByIdAsync(RDocValue id, FindOptions? options = null, CancellationToken cancellationToken = default)
    {
        var request = new V1.GetRequest { Database = _context.Database, Collection = Name, Id = AstBuild.Value(id), Consistency = _context.Consistency(options) };
        SetTxn(t => request.TxnId = t);
        V1.GetResponse response = await Executor.UnaryAsync(
            (invoker, o) => new V1.DocumentService.DocumentServiceClient(invoker).GetAsync(request, o),
            _context.Spec(OperationKind.Read, options),
            cancellationToken).ConfigureAwait(false);
        return response.Document is null ? null : DocumentCodec<T>.Decode(response.Document);
    }

    public IFindFluent<T> Find(Filter filter, FindOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return new FindFluent<T>(_context, Name, filter, options);
    }

    public Task<UpdateResult> UpdateOneAsync(Filter filter, Update update, UpdateOptions? options = null, CancellationToken cancellationToken = default) =>
        UpdateAsync(filter, update, options, one: true, cancellationToken);

    public Task<UpdateResult> UpdateManyAsync(Filter filter, Update update, UpdateOptions? options = null, CancellationToken cancellationToken = default) =>
        UpdateAsync(filter, update, options, one: false, cancellationToken);

    private async Task<UpdateResult> UpdateAsync(Filter filter, Update update, UpdateOptions? options, bool one, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);
        ArgumentNullException.ThrowIfNull(update);
        var sink = new ParamSink();
        if (one && filter.IdValue is { } id)
        {
            var request = new V1.UpdateRequest { Database = _context.Database, Collection = Name, Id = AstBuild.Value(id), Options = _context.WriteOptions(options) };
            request.Operations.Add(update.ToAst(sink));
            request.Params.Add(sink.Params);
            if (options?.IfRev is { } rev)
            {
                request.IfRev = rev;
            }

            SetTxn(t => request.TxnId = t);
            V1.UpdateResponse response = await Executor.UnaryAsync(
                (invoker, o) => new V1.DocumentService.DocumentServiceClient(invoker).UpdateAsync(request, o),
                _context.Spec(OperationKind.Write, options),
                cancellationToken).ConfigureAwait(false);
            return new UpdateResult(response.Matched ? 1 : 0, response.Modified ? 1 : 0);
        }

        RequireNoIfRev(options?.IfRev);
        long n = await _context.ExecuteWriteAsync(Statements.Update(Name, filter, update, one, sink), sink, options, cancellationToken).ConfigureAwait(false);

        // A statement reports the documents it wrote (docs_affected); it rewrites every match, so
        // matched = modified (conformance README §5 "Result conventions").
        return new UpdateResult(n, n);
    }

    public async Task<UpdateResult> ReplaceOneAsync(Filter filter, T replacement, ReplaceOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        RDocument document = DocumentCodec<T>.ToDocument(replacement);
        if (filter.IdValue is not { } id)
        {
            if (options?.IsUpsert == true)
            {
                throw new ArgumentException("An upserting ReplaceOne needs Filter.Id.", nameof(filter));
            }

            RequireNoIfRev(options?.IfRev);
            var sink = new ParamSink();
            long n = await _context.ExecuteWriteAsync(
                Statements.Update(Name, filter, Update.Replace(document), one: true, sink), sink, options, cancellationToken).ConfigureAwait(false);
            return new UpdateResult(n, n);
        }

        if (options?.IsUpsert == true)
        {
            var request = new V1.UpsertRequest
            {
                Database = _context.Database,
                Collection = Name,
                Document = new V1.Document { Rdoc = Google.Protobuf.UnsafeByteOperations.UnsafeWrap(WithId(document, id).ToBytes()) },
                Options = _context.WriteOptions(options),
            };
            if (options.IfRev is { } rev)
            {
                request.IfRev = rev;
            }

            SetTxn(t => request.TxnId = t);
            V1.UpsertResponse response = await Executor.UnaryAsync(
                (invoker, o) => new V1.DocumentService.DocumentServiceClient(invoker).UpsertAsync(request, o),
                _context.Spec(OperationKind.Write, options),
                cancellationToken).ConfigureAwait(false);
            return response.Inserted ? new UpdateResult(0, 0, id) : new UpdateResult(1, 1);
        }

        var replace = new V1.ReplaceRequest
        {
            Database = _context.Database,
            Collection = Name,
            Id = AstBuild.Value(id),
            Document = DocumentCodec<T>.Encode(replacement),
            Options = _context.WriteOptions(options),
        };
        if (options?.IfRev is { } ifRev)
        {
            replace.IfRev = ifRev;
        }

        SetTxn(t => replace.TxnId = t);
        V1.ReplaceResponse replaced = await Executor.UnaryAsync(
            (invoker, o) => new V1.DocumentService.DocumentServiceClient(invoker).ReplaceAsync(request: replace, options: o),
            _context.Spec(OperationKind.Write, options),
            cancellationToken).ConfigureAwait(false);
        return replaced.Matched ? new UpdateResult(1, 1) : new UpdateResult(0, 0);
    }

    public Task<DeleteResult> DeleteOneAsync(Filter filter, DeleteOptions? options = null, CancellationToken cancellationToken = default) =>
        DeleteAsync(filter, options, one: true, cancellationToken);

    public Task<DeleteResult> DeleteManyAsync(Filter filter, DeleteOptions? options = null, CancellationToken cancellationToken = default) =>
        DeleteAsync(filter, options, one: false, cancellationToken);

    private async Task<DeleteResult> DeleteAsync(Filter filter, DeleteOptions? options, bool one, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);
        if (one && filter.IdValue is { } id)
        {
            var request = new V1.DeleteRequest { Database = _context.Database, Collection = Name, Id = AstBuild.Value(id), Options = _context.WriteOptions(options) };
            if (options?.IfRev is { } rev)
            {
                request.IfRev = rev;
            }

            SetTxn(t => request.TxnId = t);
            V1.DeleteResponse response = await Executor.UnaryAsync(
                (invoker, o) => new V1.DocumentService.DocumentServiceClient(invoker).DeleteAsync(request, o),
                _context.Spec(OperationKind.Write, options),
                cancellationToken).ConfigureAwait(false);
            return new DeleteResult(response.Deleted ? 1 : 0);
        }

        RequireNoIfRev(options?.IfRev);
        var sink = new ParamSink();
        long n = await _context.ExecuteWriteAsync(Statements.Delete(Name, filter, one, sink), sink, options, cancellationToken).ConfigureAwait(false);
        return new DeleteResult(n);
    }

    public async Task<BulkWriteResult> BulkWriteAsync(IEnumerable<BulkOperation<T>> operations, BulkWriteOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operations);
        var request = new V1.BulkWriteRequest
        {
            Database = _context.Database,
            Collection = Name,
            Ordered = options?.Ordered ?? true,
            Options = _context.WriteOptions(options),
        };

        // One sink for the whole request: BulkWriteRequest.params is shared by every update
        // operation, so their parameters are numbered u0, u1, … across operations.
        var sink = new ParamSink();
        foreach (BulkOperation<T> op in operations)
        {
            ArgumentNullException.ThrowIfNull(op, nameof(operations));
            request.Operations.Add(ToProto(op, sink));
        }

        if (request.Operations.Count == 0)
        {
            throw new ArgumentException("A bulk write needs at least one operation.", nameof(operations));
        }

        request.Params.Add(sink.Params);
        SetTxn(t => request.TxnId = t);
        V1.BulkWriteResponse response = await Executor.UnaryAsync(
            (invoker, o) => new V1.DocumentService.DocumentServiceClient(invoker).BulkWriteAsync(request, o),
            _context.Spec(OperationKind.Write, options),
            cancellationToken).ConfigureAwait(false);
        return new BulkWriteResult(
            (long)response.Inserted,
            (long)response.Matched,
            (long)response.Modified,
            (long)response.Deleted,
            [.. response.Errors.Select(e => new BulkWriteError((int)e.Index, e.Error is null ? ErrorMapper.FromStatus(Grpc.Core.StatusCode.Unknown) : ErrorMapper.FromDetail(e.Error), e.Message))]);
    }

    private static V1.BulkOperation ToProto(BulkOperation<T> op, ParamSink sink)
    {
        switch (op.Kind)
        {
            case BulkOperation<T>.OpKind.Insert:
                return new V1.BulkOperation { Insert = new V1.BulkInsert { Document = DocumentCodec<T>.Encode(op.Document!) } };
            case BulkOperation<T>.OpKind.Upsert:
                return new V1.BulkOperation { Upsert = new V1.BulkUpsert { Document = DocumentCodec<T>.Encode(op.Document!) } };
            case BulkOperation<T>.OpKind.Replace:
                var replace = new V1.BulkReplace { Id = AstBuild.Value(op.Id), Document = DocumentCodec<T>.Encode(op.Document!) };
                if (op.IfRev is { } rr)
                {
                    replace.IfRev = rr;
                }

                return new V1.BulkOperation { Replace = replace };
            case BulkOperation<T>.OpKind.Update:
                var update = new V1.BulkUpdate { Id = AstBuild.Value(op.Id) };
                update.Operations.Add(op.UpdateDefinition!.ToAst(sink));
                if (op.IfRev is { } ur)
                {
                    update.IfRev = ur;
                }

                return new V1.BulkOperation { Update = update };
            default:
                var delete = new V1.BulkDelete { Id = AstBuild.Value(op.Id) };
                if (op.IfRev is { } dr)
                {
                    delete.IfRev = dr;
                }

                return new V1.BulkOperation { Delete = delete };
        }
    }

    public async Task<IndexDescription> CreateIndexAsync(string name, IndexKeys keys, CreateIndexOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(keys);
        _context.ThrowIfTransactional("CreateIndex");
        var definition = new V1.AstCreateIndex
        {
            IndexType = options?.Unique == true ? V1.AstIndexType.Unique : V1.AstIndexType.Standard,
            Name = name,
            On = new V1.AstQualifiedName { Name = Name },
        };
        foreach (IndexKey k in keys.Keys)
        {
            definition.Keys.Add(new V1.AstIndexKey { Path = AstBuild.Path(k.Path), Descending = k.Descending });
        }

        var request = new V1.CreateIndexRequest { Database = _context.Database, Definition = definition };
        V1.CreateIndexResponse created = await Executor.UnaryAsync(
            (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).CreateIndexAsync(request, o),
            _context.Spec(OperationKind.NoRetry, options),
            cancellationToken).ConfigureAwait(false);

        // The build runs in the background on the server; the operation completes when it has
        // finished (conformance README §5: createIndex returns the final state), polling with a
        // doubling interval so a quick build costs a few milliseconds and a long one few calls.
        V1.IndexState state = created.Index?.State ?? V1.IndexState.Building;
        var delay = TimeSpan.FromMilliseconds(10);
        while (state == V1.IndexState.Building)
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            delay = TimeSpan.FromMilliseconds(Math.Min(500, delay.TotalMilliseconds * 2));
            var progress = new V1.IndexBuildProgressRequest { Database = _context.Database, Collection = Name, Name = name };
            V1.IndexBuildProgressResponse p = await Executor.UnaryAsync(
                (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).IndexBuildProgressAsync(progress, o),
                _context.Spec(OperationKind.Read, options),
                cancellationToken).ConfigureAwait(false);
            state = p.State;
        }

        return Describe(created.Index?.Definition ?? definition, state, created.Index?.Error);
    }

    public async Task<bool> DropIndexAsync(string name, DropOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        _context.ThrowIfTransactional("DropIndex");
        var request = new V1.DropIndexRequest { Database = _context.Database, Collection = Name, Name = name, IfExists = options?.IfExists ?? false };
        V1.DropIndexResponse response = await Executor.UnaryAsync(
            (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).DropIndexAsync(request, o),
            _context.Spec(OperationKind.NoRetry, options),
            cancellationToken).ConfigureAwait(false);
        return response.Dropped;
    }

    public async Task<IReadOnlyList<IndexDescription>> ListIndexesAsync(CancellationToken cancellationToken = default)
    {
        _context.ThrowIfTransactional("ListIndexes");
        var request = new V1.ListIndexesRequest { Database = _context.Database, Collection = Name };
        V1.ListIndexesResponse response = await Executor.UnaryAsync(
            (invoker, o) => new V1.SchemaService.SchemaServiceClient(invoker).ListIndexesAsync(request, o),
            _context.Spec(OperationKind.Read, null),
            cancellationToken).ConfigureAwait(false);
        return [.. response.Indexes.Select(i => Describe(i.Definition, i.State, i.HasError ? i.Error : null)).OrderBy(i => i.Name, StringComparer.Ordinal)];
    }

    private static IndexDescription Describe(V1.AstCreateIndex definition, V1.IndexState state, string? error) => new(
        definition.Name,
        [.. definition.Keys.Select(k => new IndexKey(AstBuild.PathText(k.Path), k.Descending))],
        definition.IndexType == V1.AstIndexType.Unique,
        state switch
        {
            V1.IndexState.Ready => IndexState.Ready,
            V1.IndexState.Failed => IndexState.Failed,
            V1.IndexState.Hidden => IndexState.Hidden,
            _ => IndexState.Building,
        },
        error);

    private static RDocument WithId(RDocument document, RDocValue id)
    {
        if (document.TryGetValue("_id", out RDocValue existing))
        {
            return existing.Equals(id)
                ? document
                : throw new ArgumentException("The replacement's _id differs from the id of Filter.Id.", nameof(document));
        }

        var copy = new RDocument(document.Count + 1) { { "_id", id } };
        foreach (KeyValuePair<string, RDocValue> f in document)
        {
            copy.Add(f.Key, f.Value);
        }

        return copy;
    }

    private static void RequireNoIfRev(string? ifRev)
    {
        if (ifRev is not null)
        {
            throw new ArgumentException("IfRev applies to Filter.Id operations only.");
        }
    }

    private void SetTxn(Action<string> set)
    {
        if (_context.TxnId is { } id)
        {
            set(id);
        }
    }
}

/// <summary>The fluent find (see <see cref="IFindFluent{T}"/>); mutable until enumerated, like its builders' callers expect.</summary>
internal sealed class FindFluent<T> : IFindFluent<T>
    where T : class
{
    private readonly DataContext _context;
    private readonly string _collection;
    private readonly Filter _filter;
    private readonly FindOptions? _options;
    private Sort? _sort;
    private Projection? _projection;
    private long? _limit;
    private long? _skip;
    private int? _batchSize;

    internal FindFluent(DataContext context, string collection, Filter filter, FindOptions? options)
    {
        _context = context;
        _collection = collection;
        _filter = filter;
        _options = options;
    }

    public IFindFluent<T> Sort(Sort sort)
    {
        _sort = sort ?? throw new ArgumentNullException(nameof(sort));
        return this;
    }

    public IFindFluent<T> Limit(int limit)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(limit);
        _limit = limit;
        return this;
    }

    public IFindFluent<T> Skip(int skip)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(skip);
        _skip = skip;
        return this;
    }

    public IFindFluent<T> Project(Projection projection)
    {
        _projection = projection ?? throw new ArgumentNullException(nameof(projection));
        return this;
    }

    public IFindFluent<T> BatchSize(int batchSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(batchSize);
        _batchSize = batchSize;
        return this;
    }

    public async Task<List<T>> ToListAsync(CancellationToken cancellationToken = default)
    {
        var list = new List<T>();
        IAsyncCursor<T> cursor = await ToCursorAsync(cancellationToken).ConfigureAwait(false);
        await using (cursor.ConfigureAwait(false))
        {
            while (await cursor.MoveNextAsync().ConfigureAwait(false))
            {
                list.Add(cursor.Current);
            }
        }

        return list;
    }

    public async Task<T?> FirstOrDefaultAsync(CancellationToken cancellationToken = default)
    {
        IAsyncCursor<T> cursor = await OpenAsync(Math.Min(_limit ?? 1, 1), cancellationToken).ConfigureAwait(false);
        await using (cursor.ConfigureAwait(false))
        {
            return await cursor.MoveNextAsync().ConfigureAwait(false) ? cursor.Current : null;
        }
    }

    public Task<IAsyncCursor<T>> ToCursorAsync(CancellationToken cancellationToken = default) => OpenAsync(_limit, cancellationToken);

    public IAsyncEnumerable<T> ToAsyncEnumerable(CancellationToken cancellationToken = default) =>
        CursorEnumerable.Enumerate(ToCursorAsync, cancellationToken);

    public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default) =>
        ToAsyncEnumerable(cancellationToken).GetAsyncEnumerator(cancellationToken);

    /// <summary>The request of this find (also used by the AST conformance vectors).</summary>
    internal V1.ExecuteRequest Request(long? limit)
    {
        var sink = new ParamSink();
        var request = new V1.ExecuteRequest
        {
            Database = _context.Database,
            Ast = Statements.Find(_collection, _filter, _sort, _projection, limit, _skip, sink),
            Options = new V1.ExecOptions { Consistency = _context.Consistency(_options) },
        };
        request.Params.Add(sink.Params);
        if (_batchSize is { } b)
        {
            request.Options.BatchSize = (uint)b;
        }

        return request;
    }

    private async Task<IAsyncCursor<T>> OpenAsync(long? limit, CancellationToken cancellationToken) =>
        await AsyncCursor<T>.OpenAsync(_context, Request(limit), _context.Spec(OperationKind.Read, _options), cancellationToken).ConfigureAwait(false);
}
