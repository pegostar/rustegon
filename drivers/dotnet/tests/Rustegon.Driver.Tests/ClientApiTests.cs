// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Rustegon.Driver.Tests.Conformance;
using Xunit;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Tests;

/// <summary>
/// TC-DRV-NET-017 (FR-DRV-001, dotnet-driver.md §3, §6, consistency.md, PD-081, PD-095): client
/// settings reach the wire — read consistency and staleness bound on every read, write concern on
/// every write, per-operation overrides, nothing per operation inside a transaction (the
/// transaction's values go to <c>Begin</c>), the per-operation deadline as <c>grpc-timeout</c>,
/// the causality token of a session; <c>ConnectTimeout</c> is enforced. Observed on the fake
/// gRPC server, which records every request message.
/// </summary>
public sealed class ClientSettingsWireTests
{
    private static (RustegonClient Client, FakeGrpcServer Fake) Fake(Action<RustegonClientSettings>? configure = null)
    {
        var fake = new FakeGrpcServer(null);
        var s = new RustegonClientSettings
        {
            Tls = new TlsSettings { Enabled = false },
            Credential = RustegonCredential.ApiKey("rgn_fake_key"),
            DefaultDatabase = "fake",
            ConnectionsPerEndpoint = 1,
        };
        s.Endpoints.Add("fake.invalid:7700");
        configure?.Invoke(s);
        return (new RustegonClient(s, fake), fake);
    }

    private static T Last<T>(FakeGrpcServer fake, string rpc)
        where T : class => (T)fake.Calls.Last(c => c.Rpc == rpc).Request!;

    [Fact]
    public async Task tc_drv_net_017_consistency_and_write_concern_are_sent_on_every_data_request()
    {
        (RustegonClient client, FakeGrpcServer fake) = Fake(s =>
        {
            s.ReadConsistency = ReadConsistency.BoundedStaleness;
            s.MaxStaleness = TimeSpan.FromSeconds(5);
            s.WriteConcern = WriteConcern.All;
        });
        await using (client)
        {
            var ct = TestContext.Current.CancellationToken;
            IRustegonDatabase db = client.GetDatabase();
            IRustegonCollection<RDocument> c = db.GetCollection<RDocument>("c");
            var bounded = new V1.ReadConsistency { Level = V1.ReadConsistencyLevel.BoundedStaleness, MaxStalenessMs = 5000 };

            await c.FindByIdAsync(1, cancellationToken: ct);
            Assert.Equal(bounded, Last<V1.GetRequest>(fake, "DocumentService.Get").Consistency);
            await c.Find(Filter.Eq("a", 1)).ToListAsync(ct);
            Assert.Equal(bounded, Last<V1.ExecuteRequest>(fake, "QueryService.Execute").Options.Consistency);
            await foreach (RDocument _ in db.QueryAsync<RDocument>("FROM c").WithCancellation(ct))
            {
            }

            V1.ExecuteRequest query = Last<V1.ExecuteRequest>(fake, "QueryService.Execute");
            Assert.Equal(bounded, query.Options.Consistency);
            Assert.Equal(V1.WriteConcern.All, query.Options.WriteConcern);

            await c.InsertOneAsync(new RDocument { { "_id", 1 } }, cancellationToken: ct);
            Assert.Equal(V1.WriteConcern.All, Last<V1.InsertRequest>(fake, "DocumentService.Insert").Options.WriteConcern);
            await c.UpdateOneAsync(Filter.Id(1), Update.Set("a", 1), cancellationToken: ct);
            Assert.Equal(V1.WriteConcern.All, Last<V1.UpdateRequest>(fake, "DocumentService.Update").Options.WriteConcern);
            await c.UpdateManyAsync(Filter.Eq("a", 1), Update.Set("a", 2), cancellationToken: ct);
            Assert.Equal(V1.WriteConcern.All, Last<V1.ExecuteRequest>(fake, "QueryService.Execute").Options.WriteConcern);
            await c.ReplaceOneAsync(Filter.Id(1), new RDocument { { "a", 3 } }, cancellationToken: ct);
            Assert.Equal(V1.WriteConcern.All, Last<V1.ReplaceRequest>(fake, "DocumentService.Replace").Options.WriteConcern);
            await c.ReplaceOneAsync(Filter.Id(1), new RDocument { { "a", 3 } }, new ReplaceOptions { IsUpsert = true }, ct);
            V1.UpsertRequest upsert = Last<V1.UpsertRequest>(fake, "DocumentService.Upsert");
            Assert.Equal(V1.WriteConcern.All, upsert.Options.WriteConcern);
            Assert.Equal("{\"_id\":1,\"a\":3}", RDocument.FromBytes(upsert.Document.Rdoc.Span).ToJson());
            await c.DeleteOneAsync(Filter.Id(1), cancellationToken: ct);
            Assert.Equal(V1.WriteConcern.All, Last<V1.DeleteRequest>(fake, "DocumentService.Delete").Options.WriteConcern);
            await c.DeleteManyAsync(Filter.Empty, cancellationToken: ct);
            Assert.Equal(V1.WriteConcern.All, Last<V1.ExecuteRequest>(fake, "QueryService.Execute").Options.WriteConcern);
            await c.BulkWriteAsync([BulkOperation.Delete<RDocument>(1)], cancellationToken: ct);
            Assert.Equal(V1.WriteConcern.All, Last<V1.BulkWriteRequest>(fake, "DocumentService.BulkWrite").Options.WriteConcern);
        }
    }

    [Fact]
    public async Task tc_drv_net_017_per_operation_options_override_the_settings()
    {
        (RustegonClient client, FakeGrpcServer fake) = Fake(s =>
        {
            s.ReadConsistency = ReadConsistency.Follower;
            s.WriteConcern = WriteConcern.All;
        });
        await using (client)
        {
            var ct = TestContext.Current.CancellationToken;
            IRustegonCollection<RDocument> c = client.GetDatabase().GetCollection<RDocument>("c");
            await c.FindByIdAsync(1, new FindOptions { ReadConsistency = ReadConsistency.Linearizable }, ct);
            Assert.Equal(new V1.ReadConsistency { Level = V1.ReadConsistencyLevel.Linearizable }, Last<V1.GetRequest>(fake, "DocumentService.Get").Consistency);
            await c.FindByIdAsync(1, new FindOptions { ReadConsistency = ReadConsistency.BoundedStaleness, MaxStaleness = TimeSpan.FromMilliseconds(1500) }, ct);
            Assert.Equal(new V1.ReadConsistency { Level = V1.ReadConsistencyLevel.BoundedStaleness, MaxStalenessMs = 1500 }, Last<V1.GetRequest>(fake, "DocumentService.Get").Consistency);
            await c.FindByIdAsync(1, cancellationToken: ct);
            Assert.Equal(new V1.ReadConsistency { Level = V1.ReadConsistencyLevel.Follower }, Last<V1.GetRequest>(fake, "DocumentService.Get").Consistency);
            await c.InsertOneAsync(new RDocument { { "_id", 1 } }, new InsertOptions { WriteConcern = WriteConcern.Majority }, ct);
            Assert.Equal(V1.WriteConcern.Majority, Last<V1.InsertRequest>(fake, "DocumentService.Insert").Options.WriteConcern);

            // A bounded-staleness read without its bound is refused before any I/O.
            int calls = fake.Calls.Count;
            await Assert.ThrowsAsync<ArgumentException>(() => c.FindByIdAsync(1, new FindOptions { ReadConsistency = ReadConsistency.BoundedStaleness }, ct));
            Assert.Equal(calls, fake.Calls.Count);

            // The per-operation deadline is sent as grpc-timeout (at most the 2 s asked for).
            await c.FindByIdAsync(1, new FindOptions { Timeout = TimeSpan.FromSeconds(2) }, ct);
            Assert.InRange(GrpcTimeout(fake.Calls.Last().GrpcTimeout!), TimeSpan.FromMilliseconds(1), TimeSpan.FromSeconds(2));
        }
    }

    [Fact]
    public async Task tc_drv_net_017_server_defaults_send_nothing_and_transactions_carry_their_own()
    {
        (RustegonClient client, FakeGrpcServer fake) = Fake();
        await using (client)
        {
            var ct = TestContext.Current.CancellationToken;
            IRustegonCollection<RDocument> c = client.GetDatabase().GetCollection<RDocument>("c");
            await c.FindByIdAsync(1, cancellationToken: ct);
            Assert.Null(Last<V1.GetRequest>(fake, "DocumentService.Get").Consistency);
            await c.InsertOneAsync(new RDocument { { "_id", 1 } }, cancellationToken: ct);
            Assert.Equal(V1.WriteConcern.Unspecified, Last<V1.InsertRequest>(fake, "DocumentService.Insert").Options.WriteConcern);

            await using (ITransaction txn = await client.BeginTransactionAsync(new TransactionOptions { WriteConcern = WriteConcern.All, Isolation = IsolationLevel.Snapshot }, ct))
            {
                V1.BeginRequest begin = Last<V1.BeginRequest>(fake, "TransactionService.Begin");
                Assert.Equal(V1.WriteConcern.All, begin.WriteConcern);
                Assert.Equal(V1.AstIsolation.Snapshot, begin.Isolation);
                Assert.Null(begin.Consistency);
                IRustegonCollection<RDocument> tc = txn.Collection<RDocument>("c");
                await tc.InsertOneAsync(new RDocument { { "_id", 2 } }, new InsertOptions { WriteConcern = WriteConcern.Majority }, ct);
                V1.InsertRequest insert = Last<V1.InsertRequest>(fake, "DocumentService.Insert");
                Assert.Equal(FakeGrpcServer.FakeTxnId, insert.TxnId);
                Assert.Null(insert.Options);
                await tc.FindByIdAsync(2, new FindOptions { ReadConsistency = ReadConsistency.Linearizable }, ct);
                V1.GetRequest get = Last<V1.GetRequest>(fake, "DocumentService.Get");
                Assert.Equal(FakeGrpcServer.FakeTxnId, get.TxnId);
                Assert.Null(get.Consistency);
                await tc.UpdateManyAsync(Filter.Eq("a", 1), Update.Inc("n", 1), cancellationToken: ct);
                Assert.Equal(FakeGrpcServer.FakeTxnId, Last<V1.ExecuteRequest>(fake, "QueryService.Execute").TxnId);
                await txn.CommitAsync(ct);
            }

            // Follower / bounded-staleness reads exist for read-only transactions only.
            await using (ITransaction ro = await client.BeginTransactionAsync(new TransactionOptions { ReadOnly = true, ReadConsistency = ReadConsistency.Follower }, ct))
            {
                V1.BeginRequest begin = Last<V1.BeginRequest>(fake, "TransactionService.Begin");
                Assert.True(begin.ReadOnly);
                Assert.Equal(V1.ReadConsistencyLevel.Follower, begin.Consistency.Level);
            }

            // Disposing a transaction that was neither committed nor rolled back rolls it back once.
            Assert.Single(fake.Calls, call => call.Rpc == "TransactionService.Rollback");
        }
    }

    [Fact]
    public async Task tc_drv_net_017_session_passes_the_causality_token_through()
    {
        (RustegonClient client, FakeGrpcServer fake) = Fake();
        await using (client)
        {
            var ct = TestContext.Current.CancellationToken;
            IRustegonCollection<RDocument> c = client.GetDatabase().GetCollection<RDocument>("c");
            await using IClientSession session = await client.StartSessionAsync(cancellationToken: ct);
            Assert.Null(session.CausalityToken);
            fake.CausalityToken = "ct-1";
            await c.InsertOneAsync(new RDocument { { "_id", 1 } }, new InsertOptions { Session = session }, ct);
            Assert.Equal("ct-1", session.CausalityToken);
            fake.CausalityToken = "ct-2";
            await c.FindByIdAsync(1, new FindOptions { Session = session }, ct);
            Assert.Equal("ct-2", session.CausalityToken);
            Assert.Equal("ct-1", fake.Calls.Last().Headers("rgn-causality-token"));

            // Without the session the token is neither sent nor taken.
            await c.FindByIdAsync(1, cancellationToken: ct);
            Assert.Null(fake.Calls.Last().Headers("rgn-causality-token"));
            Assert.Equal("ct-2", session.CausalityToken);
        }
    }

    [Fact]
    public async Task tc_drv_net_017_connect_timeout_is_enforced()
    {
        // A listener that accepts TCP connections and never answers the TLS ClientHello: only the
        // connect timeout (TCP + TLS, SocketsHttpHandler.ConnectTimeout) can end the attempt before
        // the 20 s operation deadline.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var held = new List<Socket>();
        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    held.Add(await listener.AcceptSocketAsync());
                }
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException)
            {
                // Listener stopped.
            }
        }, TestContext.Current.CancellationToken);

        var settings = new RustegonClientSettings
        {
            ConnectTimeout = TimeSpan.FromMilliseconds(300),
            DefaultOperationTimeout = TimeSpan.FromSeconds(20),
            RetryReads = false,
            ConnectionsPerEndpoint = 1,
            // TLS is opt-in (ADR-034); the handshake is the phase this test stalls.
            Tls = new TlsSettings { Enabled = true },
        };
        settings.Endpoints.Add($"127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}");
        await using var client = new RustegonClient(settings);
        var watch = Stopwatch.StartNew();
        UnavailableException e = await Assert.ThrowsAsync<UnavailableException>(() => client.PingAsync(TestContext.Current.CancellationToken));
        watch.Stop();
        Assert.Equal(3002, e.Code);
        Assert.InRange(watch.Elapsed, TimeSpan.FromMilliseconds(250), TimeSpan.FromSeconds(5));
        listener.Stop();
        foreach (Socket s in held)
        {
            s.Dispose();
        }
    }

    /// <summary>Parses a <c>grpc-timeout</c> header (<c>&lt;digits&gt;&lt;H|M|S|m|u|n&gt;</c>).</summary>
    private static TimeSpan GrpcTimeout(string value)
    {
        long n = long.Parse(value[..^1], CultureInfo.InvariantCulture);
        return value[^1] switch
        {
            'H' => TimeSpan.FromHours(n),
            'M' => TimeSpan.FromMinutes(n),
            'S' => TimeSpan.FromSeconds(n),
            'm' => TimeSpan.FromMilliseconds(n),
            'u' => TimeSpan.FromMicroseconds(n),
            _ => TimeSpan.FromTicks(n / 100),
        };
    }
}

/// <summary>
/// TC-DRV-NET-015 (FR-TXN-005, FR-TXN-006, transactions.md §5): while an unknown commit outcome
/// (RGN-2006) is resolved, a failing <c>Status</c> call means "still unknown": the driver keeps
/// polling and never rolls back or re-runs the callback (which could apply the transaction twice).
/// </summary>
public sealed class WithTransactionResolutionTests
{
    private static Dictionary<string, object?> Error(long code, bool retryable) =>
        new() { ["error"] = new Dictionary<string, object?> { ["code"] = code, ["retryable"] = retryable } };

    private static Dictionary<string, object?> Ok(string state) =>
        new() { ["ok"] = new Dictionary<string, object?> { ["state"] = state } };

    private static async Task<(int Runs, Exception? Error, FakeGrpcServer Fake)> RunAsync(List<object?> status, TimeSpan maxRetryTime)
    {
        var fake = new FakeGrpcServer(new Dictionary<string, object?>
        {
            ["TransactionService.Commit"] = new List<object?> { Error(2006, false) },
            ["TransactionService.Status"] = status,
        });
        var s = new RustegonClientSettings { Tls = new TlsSettings { Enabled = false }, Credential = RustegonCredential.ApiKey("rgn_fake_key"), DefaultDatabase = "fake" };
        s.Endpoints.Add("fake.invalid:7700");
        await using var client = new RustegonClient(s, fake);
        int runs = 0;
        try
        {
            int result = await client.WithTransactionAsync(
                async (txn, ct) =>
                {
                    runs++;
                    await txn.Collection<RDocument>("c").InsertOneAsync(new RDocument { { "_id", 1 } }, cancellationToken: ct);
                    return 7;
                },
                new TransactionOptions { MaxRetryTime = maxRetryTime },
                TestContext.Current.CancellationToken);
            Assert.Equal(7, result);
            return (runs, null, fake);
        }
        catch (RustegonException e)
        {
            return (runs, e, fake);
        }
    }

    [Fact]
    public async Task tc_drv_net_015_failed_status_poll_keeps_resolving_then_committed()
    {
        (int runs, Exception? error, FakeGrpcServer fake) = await RunAsync([Error(3004, true), Ok("TRANSACTION_STATE_COMMITTED")], TimeSpan.FromSeconds(30));
        Assert.Null(error);
        Assert.Equal(1, runs);
        Assert.Equal(2, fake.Calls.Count(c => c.Rpc == "TransactionService.Status"));
        Assert.Equal(1, fake.Calls.Count(c => c.Rpc == "TransactionService.Begin"));
        Assert.DoesNotContain(fake.Calls, c => c.Rpc == "TransactionService.Rollback");
    }

    [Fact]
    public async Task tc_drv_net_015_status_failing_until_the_deadline_is_commit_outcome_unknown()
    {
        (int runs, Exception? error, FakeGrpcServer fake) = await RunAsync([Error(3004, true)], TimeSpan.FromSeconds(2));
        Assert.IsType<CommitOutcomeUnknownException>(error);
        Assert.Equal(1, runs);
        Assert.True(fake.Calls.Count(c => c.Rpc == "TransactionService.Status") >= 2);
        Assert.Equal(1, fake.Calls.Count(c => c.Rpc == "TransactionService.Begin"));
        Assert.DoesNotContain(fake.Calls, c => c.Rpc == "TransactionService.Rollback");
    }
}

/// <summary>
/// TC-DRV-NET-019 (FR-DRV-001, PD-070, PD-071, PD-099): the client API refuses invalid input before
/// any I/O (the fake server records no call), and its handles behave as documented.
/// </summary>
public sealed class ClientApiValidationTests
{
    [Fact]
    public void tc_drv_net_019_builders_validate_their_input()
    {
        Assert.Throws<ArgumentException>(() => Filter.Eq(string.Empty, 1));
        Assert.Throws<ArgumentException>(() => Filter.Eq("a..b", 1));
        Assert.Throws<ArgumentException>(() => Filter.Eq("a", RDocValue.Missing));
        Assert.Throws<ArgumentException>(() => Filter.Not(Filter.Empty));
        Assert.Throws<ArgumentException>(() => Filter.ElemMatch("items", Filter.Empty));
        Assert.Throws<ArgumentException>(() => Update.Set("a", RDocValue.Missing));
        Assert.Throws<ArgumentException>(() => Sort.Ascending());
        Assert.Throws<ArgumentException>(() => Projection.Include());
        Assert.Throws<ArgumentException>(() => IndexKeys.Ascending());
        Assert.Throws<ArgumentException>(() => BulkOperation.Delete<RDocument>(RDocValue.Missing));
        Assert.Throws<ArgumentException>(() => Update.Combine().ToAst(new Internal.Builders.ParamSink()));

        // And/Or ignore empty filters and flatten nesting (PD-070 rule 2); one operand is itself.
        Filter a = Filter.Eq("a", 1);
        Assert.Same(a, Filter.And(Filter.Empty, a));
        Assert.True(Filter.Or(Filter.Empty, Filter.Empty).IsEmpty);
        var sink = new Internal.Builders.ParamSink();
        V1.AstExpr flat = (a & Filter.Eq("b", 2) & Filter.Eq("c", 3)).ToAst(sink)!;
        Assert.Equal(3, flat.And.Args.Count);
        Assert.Equal(["f0", "f1", "f2"], sink.Params.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(V1.AstExpr.KindOneofCase.Or, (a | !Filter.Eq("b", 2)).ToAst(new Internal.Builders.ParamSink())!.KindCase);

        // Chained updates keep their order and number parameters u0, u1, ….
        var us = new Internal.Builders.ParamSink();
        V1.AstUpdateOp[] ops = [.. Update.Set("s", "x").Inc("n", 1).Unset("old").CurrentDate("at").ToAst(us)];
        Assert.Equal([V1.AstUpdateOp.KindOneofCase.Set, V1.AstUpdateOp.KindOneofCase.Inc, V1.AstUpdateOp.KindOneofCase.Unset, V1.AstUpdateOp.KindOneofCase.CurrentDate], ops.Select(o => o.KindCase));
        Assert.Equal(["u0", "u1"], us.Params.Keys.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task tc_drv_net_019_operations_refuse_invalid_arguments_before_any_io()
    {
        var fake = new FakeGrpcServer(null);
        var s = new RustegonClientSettings { Tls = new TlsSettings { Enabled = false }, Credential = RustegonCredential.ApiKey("rgn_fake_key") };
        s.Endpoints.Add("fake.invalid:7700");
        await using var client = new RustegonClient(s, fake);
        var ct = TestContext.Current.CancellationToken;

        // No DefaultDatabase: a database must be named.
        Assert.Throws<ArgumentException>(() => client.GetDatabase());
        IRustegonDatabase db = client.GetDatabase("db");
        Assert.Throws<NotSupportedException>(() => db.GetCollection<string>("c"));
        IRustegonCollection<RDocument> c = db.GetCollection<RDocument>("c");
        await Assert.ThrowsAsync<ArgumentException>(() => c.ReplaceOneAsync(Filter.Eq("a", 1), new RDocument(), new ReplaceOptions { IsUpsert = true }, ct));
        await Assert.ThrowsAsync<ArgumentException>(() => c.UpdateOneAsync(Filter.Eq("a", 1), Update.Set("b", 1), new UpdateOptions { IfRev = "r" }, ct));
        await Assert.ThrowsAsync<ArgumentException>(() => c.ReplaceOneAsync(Filter.Id(1), new RDocument { { "_id", 2 } }, new ReplaceOptions { IsUpsert = true }, ct));
        await Assert.ThrowsAsync<ArgumentException>(() => c.InsertManyAsync([], cancellationToken: ct));
        await Assert.ThrowsAsync<ArgumentException>(() => c.BulkWriteAsync([], cancellationToken: ct));
        await Assert.ThrowsAsync<RDocException>(() => c.InsertOneAsync(new RDocument { { "$set", 1 } }, cancellationToken: ct));
        Assert.Throws<ArgumentOutOfRangeException>(() => c.Find(Filter.Empty).Limit(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => c.Find(Filter.Empty).BatchSize(0));
        Assert.Empty(fake.Calls);

        // A transaction without DefaultDatabase needs "db.coll" (PD-099); DDL is not transactional.
        await using ITransaction txn = await client.BeginTransactionAsync(cancellationToken: ct);
        Assert.Throws<InvalidOperationException>(() => txn.Collection<RDocument>("c"));
        Assert.Equal("db", txn.Collection<RDocument>("db.c").DatabaseName);
        await Assert.ThrowsAsync<NotSupportedException>(() => txn.GetDatabase("db").CreateCollectionAsync("x", cancellationToken: ct));

        // A closed client fails before any I/O, through existing handles too.
        await client.DisposeAsync();
        await client.DisposeAsync();
        Assert.Throws<ObjectDisposedException>(() => client.GetDatabase("db"));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => c.FindByIdAsync(1, cancellationToken: ct));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.ListDatabaseNamesAsync(ct));
    }

    [Fact]
    public async Task tc_drv_net_019_commit_outcome_unknown_resolve_needs_a_commit()
    {
        var e = new CommitOutcomeUnknownException(new RustegonError(2006, "CommitOutcomeUnknown", false, null, RustegonError.NoDetails, null, null), "unknown");
        await Assert.ThrowsAsync<InvalidOperationException>(() => e.ResolveAsync(TestContext.Current.CancellationToken));
    }
}
