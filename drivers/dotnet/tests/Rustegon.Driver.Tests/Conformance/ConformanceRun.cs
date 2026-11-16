// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Rustegon.Driver.Tests.Conformance;

/// <summary>The exception of <c>runner.throwApplicationError</c> (an error of the application, not of the driver).</summary>
internal sealed class ApplicationErrorException : Exception
{
    internal ApplicationErrorException()
        : base("application error raised by the conformance callback")
    {
    }
}

/// <summary>An expectation that did not hold (reported as the test's failure reason).</summary>
internal sealed class ConformanceFailure : Exception
{
    internal ConformanceFailure(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Executes the operations of one conformance test (README §5, §7) against a client: the shared
/// engine of the server runner (ConformanceSuiteTests) and of the fake-server retry
/// scenarios (<see cref="RetryScenarios"/>). Operations are translated into the public API of the
/// driver (the DSL of README §4 into <see cref="Filter"/>, <see cref="Update"/>, …); results are
/// turned into RDoc values with the field names of the README's operation table so they can be
/// matched and normalised uniformly.
/// </summary>
internal sealed class ConformanceRun : IAsyncDisposable
{
    private readonly Dictionary<string, object?> _saved = new(StringComparer.Ordinal);
    private readonly List<RustegonClient> _opened = [];
    private readonly Normalizer _normalizer;
    private readonly ConformanceDsl _dsl;
    private ITransaction? _transaction;
    private Exception? _lastError;

    internal ConformanceRun(RustegonClient client, string database, string? defaultCollection, Func<string, string> substitute, string testText)
    {
        Client = client;
        Database = database;
        DefaultCollection = defaultCollection;
        Substitute = substitute;
        _normalizer = new Normalizer(testText);
        _dsl = new ConformanceDsl(ResolveString);
        Matcher = new Matcher(Substitute, ResolveRef);
    }

    internal RustegonClient Client { get; }

    internal string Database { get; }

    internal string? DefaultCollection { get; }

    internal Func<string, string> Substitute { get; }

    internal Matcher Matcher { get; }

    /// <summary>Opens a client for <c>client.open</c> (credential arguments, allowPasswordChangeOnly); null when the run cannot.</summary>
    internal Func<Dictionary<string, object?>, RustegonClient>? OpenClient { get; init; }

    /// <summary>Runner operations beyond the built-in ones (vectors, scenarios); returns false when unknown.</summary>
    internal Func<string, Dictionary<string, object?>, Task<bool>>? RunnerExtension { get; init; }

    /// <summary>Observations of the top-level operations (README §6).</summary>
    internal List<string> Observations { get; } = [];

    /// <summary>Runs operations in order; at the top level every one is observed, inside callbacks/steps an unexpected error propagates.</summary>
    internal async Task RunAsync(List<object?> operations, bool topLevel)
    {
        for (int i = 0; i < operations.Count; i++)
        {
            var op = (Dictionary<string, object?>)operations[i]!;
            await RunOneAsync(op, topLevel ? i : null).ConfigureAwait(false);
        }
    }

    private async Task RunOneAsync(Dictionary<string, object?> op, int? index)
    {
        string name = Str(op, "name");
        string target = Str(op, "object");
        var expect = op.GetValueOrDefault("expect") as Dictionary<string, object?>;
        object? result = null;
        Exception? error = null;
        try
        {
            result = await DispatchAsync(target, name, op).ConfigureAwait(false);
            if (result is RDocument d)
            {
                result = RDocValue.FromDocument(d);
            }
        }
        catch (ConformanceFailure)
        {
            throw;
        }
        catch (Exception e)
        {
            error = e;
            _lastError = e;
        }

        string label = $"{target}.{name}";
        if (error is not null)
        {
            if (index is { } i)
            {
                Observations.Add($"{{\"error\":{ErrorJson(error)},\"op\":{i}}}");
            }

            if (expect?.GetValueOrDefault("error") is not Dictionary<string, object?> expectedError)
            {
                if (index is null)
                {
                    // Inside a callback or a step: the error belongs to the enclosing operation.
                    throw error is RustegonException or ApplicationErrorException or OperationCanceledException
                        ? error
                        : new ConformanceFailure($"{label} threw {error.GetType().Name}: {error.Message}");
                }

                throw new ConformanceFailure($"{label} threw {error.GetType().Name}: {error.Message}");
            }

            CheckError(label, expectedError, error);
            return;
        }

        RDocValue value = result as RDocValue? ?? RDocValue.Null;
        if (index is { } j)
        {
            // Saved clients, sessions, cursors and transactions are observed as "<handle>" (README §6).
            string observed = result switch
            {
                RDocValue r => _normalizer.Json(VolatileResult(name, r)),
                null => "null",
                _ => "\"<handle>\"",
            };
            Observations.Add($"{{\"op\":{j},\"result\":{observed}}}");
        }

        if (op.GetValueOrDefault("saveAs") is string saveAs)
        {
            _saved[saveAs] = result;
        }

        if (expect is null)
        {
            return;
        }

        if (expect.ContainsKey("error"))
        {
            throw new ConformanceFailure($"{label} succeeded but an error was expected");
        }

        if (expect.TryGetValue("result", out object? expected))
        {
            var mode = new MatchMode(
                op.GetValueOrDefault("match") as string == "subset",
                op.GetValueOrDefault("ordered") is not false,
                op.GetValueOrDefault("fieldOrder") is true);
            if (Matcher.Result(expected, value, mode) is { } why)
            {
                throw new ConformanceFailure($"{label}: {why}");
            }
        }
    }

    /// <summary>
    /// Causality tokens are volatile; <c>listDatabaseNames</c> keeps only the databases of this
    /// file (other files and runners share the server), with <c>${database}</c> as
    /// <c>&lt;database&gt;</c> (README §6).
    /// </summary>
    private RDocValue VolatileResult(string name, RDocValue r)
    {
        if (name == "causalityToken" && r.Type == RDocType.String)
        {
            return RDocValue.FromString("<volatile>");
        }

        if (name == "listDatabaseNames" && r.Type == RDocType.Array)
        {
            var own = new RDocArray();
            foreach (RDocValue n in r.AsArray())
            {
                if (n.AsString().StartsWith(Database, StringComparison.Ordinal))
                {
                    own.Add(RDocValue.FromString("<database>" + n.AsString()[Database.Length..]));
                }
            }

            return RDocValue.FromArray(own);
        }

        return r;
    }

    private static void CheckError(string label, Dictionary<string, object?> expected, Exception error)
    {
        void Require(bool ok, string what)
        {
            if (!ok)
            {
                throw new ConformanceFailure($"{label}: {what}; got {error.GetType().Name} {(error as RustegonException)?.Code} {error.Message}");
            }
        }

        if (expected.GetValueOrDefault("applicationError") is true)
        {
            Require(error is ApplicationErrorException, "expected the application's exception unchanged");
            return;
        }

        var r = error as RustegonException;
        if (expected.GetValueOrDefault("exception") is string cls)
        {
            Require(ErrorClasses.TypeOf(cls).IsInstanceOfType(error), $"expected an instance of {cls}");
        }

        if (expected.GetValueOrDefault("code") is long code)
        {
            Require(r?.Code == code, $"expected code {code}");
        }

        if (expected.GetValueOrDefault("name") is string n)
        {
            Require(r?.Name == n, $"expected name {n}");
        }

        if (expected.GetValueOrDefault("retryable") is bool retryable)
        {
            Require(r?.IsRetryable == retryable, $"expected retryable {retryable}");
        }

        if (expected.GetValueOrDefault("committed") is bool committed)
        {
            Require(r?.Committed == committed, $"expected committed {committed}");
        }
    }

    /// <summary>The observation of an error (README §6): code, class id, retryable.</summary>
    internal static string ErrorJson(Exception e) => e switch
    {
        ApplicationErrorException => "{\"applicationError\":true}",
        RustegonException r => $"{{\"code\":{r.Code},\"exception\":\"{ErrorClasses.IdOf(e)}\",\"retryable\":{(r.IsRetryable ? "true" : "false")}}}",
        _ => $"{{\"exception\":\"{ErrorClasses.IdOf(e)}\"}}",
    };

    // ------------------------------------------------------------------ dispatch

    private async Task<object?> DispatchAsync(string target, string name, Dictionary<string, object?> op)
    {
        Dictionary<string, object?> args = op.GetValueOrDefault("args") as Dictionary<string, object?> ?? [];
        switch (target)
        {
            case "runner":
                await RunnerAsync(name, args).ConfigureAwait(false);
                return null;
            case "client":
                return await ClientAsync(Client, name, op, args).ConfigureAwait(false);
            case "database":
                return await DatabaseAsync(Client.GetDatabase(Database), name, args).ConfigureAwait(false);
            case "collection":
                return await CollectionAsync(Client.GetDatabase(Database).GetCollection<RDocument>(CollectionName(op)), name, op, args).ConfigureAwait(false);
            case "transaction":
                return await TransactionAsync(_transaction ?? throw new ConformanceFailure("object: transaction outside a callback"), name, op, args).ConfigureAwait(false);
        }

        return _saved.GetValueOrDefault(target) switch
        {
            RustegonClient c => await ClientAsync(c, name, op, args).ConfigureAwait(false),
            ITransaction t => await TransactionAsync(t, name, op, args).ConfigureAwait(false),
            IClientSession s => await SessionAsync(s, name).ConfigureAwait(false),
            IAsyncCursor<RDocument> cur => await CursorAsync(cur, name).ConfigureAwait(false),
            _ => throw new ConformanceFailure($"unknown object '{target}'"),
        };
    }

    private string CollectionName(Dictionary<string, object?> op) =>
        op.GetValueOrDefault("collection") as string ?? DefaultCollection ?? throw new ConformanceFailure("no collection");

    private async Task<object?> ClientAsync(RustegonClient client, string name, Dictionary<string, object?> op, Dictionary<string, object?> args)
    {
        switch (name)
        {
            case "open":
                RustegonClient opened = (OpenClient ?? throw new ConformanceFailure("client.open is not available here"))(args);
                return await ConnectAsync(opened).ConfigureAwait(false);
            case "openFromConnectionString":
                return await ConnectAsync(new RustegonClient(Substitute(Str(args, "uri")))).ConfigureAwait(false);
            case "getServerInfo":
                ServerInfo info = await client.GetServerInfoAsync(Ct).ConfigureAwait(false);
                return Doc(("serverVersion", info.ServerVersion), ("protocolVersion", info.ProtocolVersion), ("features", Array(info.Features.Select(f => (RDocValue)f))));
            case "listDatabaseNames":
                return Array((await client.ListDatabaseNamesAsync(Ct).ConfigureAwait(false)).Select(n => (RDocValue)n));
            case "createDatabase":
                return Doc(("created", await client.CreateDatabaseAsync(Substitute(Str(args, "name")), new CreateDatabaseOptions { IfNotExists = args.GetValueOrDefault("ifNotExists") is true }, Ct).ConfigureAwait(false)));
            case "dropDatabase":
                return Doc(("dropped", await client.DropDatabaseAsync(Substitute(Str(args, "name")), new DropOptions { IfExists = args.GetValueOrDefault("ifExists") is true }, Ct).ConfigureAwait(false)));
            case "startSession":
                return await client.StartSessionAsync(new SessionOptions { CausalConsistency = args.GetValueOrDefault("causalConsistency") is not false }, Ct).ConfigureAwait(false);
            case "beginTransaction":
                return await client.BeginTransactionAsync(TxnOptions(args), Ct).ConfigureAwait(false);
            case "withTransaction":
                var callback = (List<object?>)args["callback"]!;
                await client.WithTransactionAsync(
                    async (txn, _) => await WithTransactionScopeAsync(txn, callback).ConfigureAwait(false),
                    TxnOptions(args),
                    Ct).ConfigureAwait(false);
                return RDocValue.Null;
            case "manualTransaction":
                ITransaction manual = await client.BeginTransactionAsync(TxnOptions(args), Ct).ConfigureAwait(false);
                await using (manual.ConfigureAwait(false))
                {
                    await WithTransactionScopeAsync(manual, (List<object?>)args["steps"]!).ConfigureAwait(false);
                }

                return RDocValue.Null;
            case "changePassword":
                await client.ChangePasswordAsync(Str(args, "currentPassword"), Str(args, "newPassword"), Ct).ConfigureAwait(false);
                return RDocValue.Null;
            case "close":
                await client.DisposeAsync().ConfigureAwait(false);
                return RDocValue.Null;
            default:
                // README §5: collection operations are also available on a saved client.
                return await CollectionAsync(client.GetDatabase(Database).GetCollection<RDocument>(CollectionName(op)), name, op, args).ConfigureAwait(false);
        }
    }

    private async Task<RustegonClient> ConnectAsync(RustegonClient client)
    {
        try
        {
            await client.ConnectAsync(Ct).ConfigureAwait(false);
        }
        catch
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        _opened.Add(client);
        return client;
    }

    private async Task WithTransactionScopeAsync(ITransaction txn, List<object?> operations)
    {
        ITransaction? outer = _transaction;
        _transaction = txn;
        try
        {
            await RunAsync(operations, topLevel: false).ConfigureAwait(false);
        }
        finally
        {
            _transaction = outer;
        }
    }

    private async Task<object?> TransactionAsync(ITransaction txn, string name, Dictionary<string, object?> op, Dictionary<string, object?> args)
    {
        switch (name)
        {
            case "query":
                return await ToArrayAsync(txn.QueryAsync<RDocument>(Str(args, "rgql"), Params(args), BatchSize(args))).ConfigureAwait(false);
            case "commit":
                await txn.CommitAsync(Ct).ConfigureAwait(false);
                return RDocValue.Null;
            case "rollback":
                await txn.RollbackAsync(Ct).ConfigureAwait(false);
                return RDocValue.Null;
            case "close":
                await txn.DisposeAsync().ConfigureAwait(false);
                return RDocValue.Null;
            case "resolve":
                // In manual mode the exception of the commit carries the resolver (transactions.md §5);
                // the transaction's own ResolveAsync asks the same Status.
                TransactionOutcome outcome = _lastError is CommitOutcomeUnknownException unknown
                    ? await unknown.ResolveAsync(Ct).ConfigureAwait(false)
                    : await txn.ResolveAsync(Ct).ConfigureAwait(false);
                return (RDocValue)outcome.ToString().ToLowerInvariant();
            default:
                return await CollectionAsync(txn.Collection<RDocument>(CollectionName(op)), name, op, args).ConfigureAwait(false);
        }
    }

    private static async Task<object?> SessionAsync(IClientSession session, string name)
    {
        switch (name)
        {
            case "causalityToken":
                return session.CausalityToken is { } t ? (RDocValue)t : RDocValue.Null;
            case "close":
                await session.DisposeAsync().ConfigureAwait(false);
                return RDocValue.Null;
            default:
                throw new ConformanceFailure($"unknown session operation '{name}'");
        }
    }

    private static async Task<object?> CursorAsync(IAsyncCursor<RDocument> cursor, string name)
    {
        switch (name)
        {
            case "next":
                return await cursor.MoveNextAsync().ConfigureAwait(false) ? RDocValue.FromDocument(cursor.Current) : RDocValue.Null;
            case "close":
                await cursor.DisposeAsync().ConfigureAwait(false);
                return RDocValue.Null;
            default:
                throw new ConformanceFailure($"unknown cursor operation '{name}'");
        }
    }

    private async Task<object?> DatabaseAsync(IRustegonDatabase db, string name, Dictionary<string, object?> args)
    {
        switch (name)
        {
            case "query":
                return await ToArrayAsync(db.QueryAsync<RDocument>(Str(args, "rgql"), Params(args), BatchSize(args))).ConfigureAwait(false);
            case "createCollection":
                var options = new CreateCollectionOptions { IfNotExists = args.GetValueOrDefault("ifNotExists") is true };
                if (args.GetValueOrDefault("validator") is Dictionary<string, object?> v)
                {
                    options.Validator = Validator(v);
                }

                return Doc(("created", await db.CreateCollectionAsync(Str(args, "name"), options, Ct).ConfigureAwait(false)));
            case "dropCollection":
                return Doc(("dropped", await db.DropCollectionAsync(Str(args, "name"), new DropOptions { IfExists = args.GetValueOrDefault("ifExists") is true }, Ct).ConfigureAwait(false)));
            case "listCollectionNames":
                return Array((await db.ListCollectionNamesAsync(Ct).ConfigureAwait(false)).Select(n => (RDocValue)n));
            default:
                throw new ConformanceFailure($"unknown database operation '{name}'");
        }
    }

    internal static CollectionValidator Validator(Dictionary<string, object?> v) => new(ConformanceValues.ToJson(v["jsonSchema"]))
    {
        Level = v.GetValueOrDefault("level") switch
        {
            null => null,
            "off" => ValidationLevel.Off,
            "strict" => ValidationLevel.Strict,
            "moderate" => ValidationLevel.Moderate,
            var l => throw new FormatException($"level {l}"),
        },
        Action = v.GetValueOrDefault("action") switch
        {
            null => null,
            "error" => ValidationAction.Error,
            "warn" => ValidationAction.Warn,
            var a => throw new FormatException($"action {a}"),
        },
    };

    private async Task<object?> CollectionAsync(IRustegonCollection<RDocument> c, string name, Dictionary<string, object?> op, Dictionary<string, object?> args)
    {
        IClientSession? session = op.GetValueOrDefault("session") is string s ? (IClientSession)_saved[s]! : null;
        var options = args.GetValueOrDefault("options") as Dictionary<string, object?> ?? [];
        string? ifRev = options.GetValueOrDefault("ifRev") is string rev ? Value(rev).AsString() : null;
        switch (name)
        {
            case "insertOne":
                InsertOneResult one = await c.InsertOneAsync(Document(args["document"]), new InsertOptions { Session = session }, Ct).ConfigureAwait(false);
                return Doc(("insertedId", one.InsertedId));
            case "insertMany":
                InsertManyResult many = await c.InsertManyAsync(((List<object?>)args["documents"]!).Select(Document), new InsertOptions { Session = session }, Ct).ConfigureAwait(false);
                return Doc(("insertedIds", Array(many.InsertedIds)));
            case "findById":
                RDocument? found = await c.FindByIdAsync(Value(args["id"]), new FindOptions { Session = session }, Ct).ConfigureAwait(false);
                return found is null ? RDocValue.Null : RDocValue.FromDocument(found);
            case "find":
                IFindFluent<RDocument> find = c.Find(Filter(args["filter"]), new FindOptions { Session = session });
                if (args.GetValueOrDefault("sort") is List<object?> sort)
                {
                    find.Sort(ConformanceDsl.SortOf(sort));
                }

                if (args.GetValueOrDefault("limit") is long limit)
                {
                    find.Limit((int)limit);
                }

                if (args.GetValueOrDefault("skip") is long skip)
                {
                    find.Skip((int)skip);
                }

                if (args.GetValueOrDefault("projection") is Dictionary<string, object?> projection)
                {
                    find.Project(ConformanceDsl.ProjectionOf(projection));
                }

                if (args.GetValueOrDefault("batchSize") is long batch)
                {
                    find.BatchSize((int)batch);
                }

                return op.GetValueOrDefault("then") switch
                {
                    "first" => await find.FirstOrDefaultAsync(Ct).ConfigureAwait(false) is { } first ? RDocValue.FromDocument(first) : RDocValue.Null,
                    "cursor" => await find.ToCursorAsync(Ct).ConfigureAwait(false),
                    _ => Array((await find.ToListAsync(Ct).ConfigureAwait(false)).Select(RDocValue.FromDocument)),
                };
            case "updateOne":
            case "updateMany":
                Update update = UpdateOf((List<object?>)args["update"]!);
                var uo = new UpdateOptions { Session = session, IfRev = ifRev };
                UpdateResult u = name == "updateOne"
                    ? await c.UpdateOneAsync(Filter(args["filter"]), update, uo, Ct).ConfigureAwait(false)
                    : await c.UpdateManyAsync(Filter(args["filter"]), update, uo, Ct).ConfigureAwait(false);
                return Counts(u);
            case "replaceOne":
                UpdateResult r = await c.ReplaceOneAsync(
                    Filter(args["filter"]),
                    Document(args["replacement"]),
                    new ReplaceOptions { Session = session, IfRev = ifRev, IsUpsert = options.GetValueOrDefault("upsert") is true },
                    Ct).ConfigureAwait(false);
                return Counts(r);
            case "deleteOne":
            case "deleteMany":
                var dopt = new DeleteOptions { Session = session, IfRev = ifRev };
                DeleteResult d = name == "deleteOne"
                    ? await c.DeleteOneAsync(Filter(args["filter"]), dopt, Ct).ConfigureAwait(false)
                    : await c.DeleteManyAsync(Filter(args["filter"]), dopt, Ct).ConfigureAwait(false);
                return Doc(("deletedCount", d.DeletedCount));
            case "bulkWrite":
                BulkWriteResult b = await c.BulkWriteAsync(
                    ((List<object?>)args["operations"]!).Select(o => BulkOf((Dictionary<string, object?>)o!)),
                    new BulkWriteOptions { Session = session, Ordered = args.GetValueOrDefault("ordered") is not false },
                    Ct).ConfigureAwait(false);
                return Doc(
                    ("insertedCount", b.InsertedCount),
                    ("matchedCount", b.MatchedCount),
                    ("modifiedCount", b.ModifiedCount),
                    ("deletedCount", b.DeletedCount),
                    ("errors", Array(b.Errors.Select(e => (RDocValue)Doc(("index", (long)e.Index), ("code", (long)e.Error.Code))))));
            case "createIndex":
                IndexDescription created = await c.CreateIndexAsync(
                    Str(args, "name"),
                    ConformanceDsl.KeysOf((List<object?>)args["keys"]!),
                    new CreateIndexOptions { Unique = args.GetValueOrDefault("unique") is true },
                    Ct).ConfigureAwait(false);
                return Doc(("name", created.Name), ("state", StateName(created.State)));
            case "dropIndex":
                return Doc(("dropped", await c.DropIndexAsync(Str(args, "name"), new DropOptions { IfExists = args.GetValueOrDefault("ifExists") is true }, Ct).ConfigureAwait(false)));
            case "listIndexes":
                return Array((await c.ListIndexesAsync(Ct).ConfigureAwait(false)).Select(i => (RDocValue)Doc(
                    ("name", i.Name),
                    ("keys", Array(i.Keys.Select(k => (RDocValue)Doc(("path", k.Path), ("descending", k.Descending))))),
                    ("unique", i.Unique),
                    ("state", StateName(i.State)))));
            default:
                throw new ConformanceFailure($"unknown collection operation '{name}'");
        }
    }

    private async Task RunnerAsync(string name, Dictionary<string, object?> args)
    {
        switch (name)
        {
            case "sleep":
                await Task.Delay(TimeSpan.FromMilliseconds((long)args["ms"]!), Ct).ConfigureAwait(false);
                return;
            case "throwApplicationError":
                throw new ApplicationErrorException();
            case "assertLastErrorHasTraceId":
                if (_lastError is not RustegonException { TraceId.Length: > 0 })
                {
                    throw new ConformanceFailure("the last error has no trace id");
                }

                return;
        }

        if (RunnerExtension is null || !await RunnerExtension(name, args).ConfigureAwait(false))
        {
            throw new ConformanceFailure($"unknown runner operation '{name}'");
        }
    }

    // ------------------------------------------------------------------ values

    internal RDocValue Value(object? yaml) => _dsl.Value(yaml);

    internal RDocument Document(object? yaml) => _dsl.Document(yaml);

    internal Filter Filter(object? yaml) => _dsl.Filter(yaml);

    internal Update UpdateOf(List<object?> ops) => _dsl.UpdateOf(ops);

    private RDocValue ResolveString(string s) => s.StartsWith("$$ref:", StringComparison.Ordinal) ? ResolveRef(s) : RDocValue.FromString(Substitute(s));

    private RDocValue ResolveRef(string reference)
    {
        string[] parts = reference["$$ref:".Length..].Split('.');
        if (_saved.GetValueOrDefault(parts[0]) is not RDocValue v)
        {
            throw new ConformanceFailure($"no saved value '{parts[0]}'");
        }

        foreach (string p in parts.Skip(1))
        {
            v = v.Type == RDocType.Object ? v.AsDocument()[p] : RDocValue.Missing;
        }

        return v;
    }

    private BulkOperation<RDocument> BulkOf(Dictionary<string, object?> o)
    {
        (string kind, object? a) = o.Single();
        var m = (Dictionary<string, object?>)a!;
        string? ifRev = m.GetValueOrDefault("ifRev") is string r ? Value(r).AsString() : null;
        return kind switch
        {
            "insert" => BulkOperation.Insert(Document(m["document"])),
            "replace" => BulkOperation.Replace(Value(m["id"]), Document(m["document"]), ifRev),
            "update" => BulkOperation.Update<RDocument>(Value(m["id"]), UpdateOf((List<object?>)m["update"]!), ifRev),
            "upsert" => BulkOperation.Upsert(Document(m["document"])),
            "delete" => BulkOperation.Delete<RDocument>(Value(m["id"]), ifRev),
            _ => throw new FormatException($"unknown bulk operation '{kind}'"),
        };
    }

    private static TransactionOptions? TxnOptions(Dictionary<string, object?> args)
    {
        if (args.GetValueOrDefault("options") is not Dictionary<string, object?> o)
        {
            return null;
        }

        var options = new TransactionOptions { ReadOnly = o.GetValueOrDefault("readOnly") is true };
        if (o.GetValueOrDefault("isolation") is string iso)
        {
            options.Isolation = iso switch
            {
                "serializable" => IsolationLevel.Serializable,
                "snapshot" => IsolationLevel.Snapshot,
                "read_committed" => IsolationLevel.ReadCommitted,
                _ => throw new FormatException($"isolation {iso}"),
            };
        }

        if (o.GetValueOrDefault("maxRetryTimeMs") is long ms)
        {
            options.MaxRetryTime = TimeSpan.FromMilliseconds(ms);
        }

        return options;
    }

    private RDocument? Params(Dictionary<string, object?> args) =>
        args.GetValueOrDefault("params") is Dictionary<string, object?> p ? Document(p) : null;

    private static QueryOptions? BatchSize(Dictionary<string, object?> args) =>
        args.GetValueOrDefault("batchSize") is long b ? new QueryOptions { BatchSize = (int)b } : null;

    private static async Task<RDocValue> ToArrayAsync(IAsyncEnumerable<RDocument> rows)
    {
        var array = new RDocArray();
        await foreach (RDocument r in rows.WithCancellation(Ct).ConfigureAwait(false))
        {
            array.Add(RDocValue.FromDocument(r));
        }

        return RDocValue.FromArray(array);
    }

    private static RDocValue Counts(UpdateResult u)
    {
        RDocument d = Doc(("matchedCount", u.MatchedCount), ("modifiedCount", u.ModifiedCount));
        if (u.UpsertedId is { } id)
        {
            d.Add("upsertedId", id);
        }

        return d;
    }

    private static string StateName(IndexState s) => s.ToString().ToLowerInvariant();

    internal static RDocument Doc(params (string Name, RDocValue Value)[] fields)
    {
        var d = new RDocument(fields.Length);
        foreach ((string n, RDocValue v) in fields)
        {
            d.Add(n, v);
        }

        return d;
    }

    internal static RDocValue Array(IEnumerable<RDocValue> items) => RDocValue.FromArray(new RDocArray(items));

    internal static string Str(Dictionary<string, object?> map, string key) =>
        map.GetValueOrDefault(key) as string ?? throw new FormatException($"'{key}' is required");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async ValueTask DisposeAsync()
    {
        foreach (object? v in _saved.Values)
        {
            switch (v)
            {
                case IAsyncCursor<RDocument> c:
                    await c.DisposeAsync().ConfigureAwait(false);
                    break;
                case ITransaction t:
                    await t.DisposeAsync().ConfigureAwait(false);
                    break;
            }
        }

        foreach (RustegonClient c in _opened)
        {
            await c.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>A short description of an exception for failure reasons.</summary>
    internal static string Describe(Exception e)
    {
        var sb = new StringBuilder(e.GetType().Name);
        if (e is RustegonException r)
        {
            sb.Append(" RGN-").Append(r.Code);
        }

        return sb.Append(": ").Append(e.Message).ToString();
    }
}

/// <summary>The class ids of <c>errors-map.yaml</c> (plus <c>Argument</c> and <c>InvalidState</c>, README §5) and their .NET types.</summary>
internal static class ErrorClasses
{
    private static readonly Lazy<List<(string Id, Type Type)>> Classes = new(Load);

    internal static Type TypeOf(string id) =>
        Classes.Value.FirstOrDefault(c => c.Id == id).Type ?? throw new FormatException($"unknown exception class id '{id}'");

    /// <summary>The id of the most specific listed class the exception is an instance of.</summary>
    internal static string IdOf(Exception e)
    {
        for (Type? t = e.GetType(); t is not null; t = t.BaseType)
        {
            foreach ((string id, Type type) in Classes.Value)
            {
                if (type == t)
                {
                    return id;
                }
            }
        }

        return e.GetType().Name;
    }

    private static List<(string, Type)> Load()
    {
        var root = (Dictionary<string, object?>)ConformanceYaml.Load(System.IO.Path.Combine(TestPaths.Conformance, "errors-map.yaml"))!;
        var list = new List<(string, Type)>
        {
            ("Argument", typeof(ArgumentException)),
            ("InvalidState", typeof(ObjectDisposedException)),
        };
        foreach (Dictionary<string, object?> c in ((List<object?>)root["classes"]!).Cast<Dictionary<string, object?>>())
        {
            Type type = typeof(RustegonException).Assembly.GetType("Rustegon.Driver." + (string)c["dotnet"]!)
                ?? throw new FormatException($"no .NET class {c["dotnet"]}");
            list.Add(((string)c["id"]!, type));
        }

        return list;
    }
}
