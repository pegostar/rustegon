// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Rustegon.Driver.TestServer;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// Robustness against a real <c>rustegond</c> (dotnet-driver.md §11): 1000 concurrent operations
/// through one client (TC-DRV-NET-028) and a node killed and restarted on the same data directory
/// and port under the same client (TC-DRV-NET-029).
/// </summary>
[Collection(ServerGroup.Name)]
public sealed class RobustnessTests
{
    private const int Concurrency = 1000;

    // Generous bounds for a debug server on a loaded CI host: the point is "finishes", not speed.
    private static readonly TimeSpan StressBound = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan PhaseBound = TimeSpan.FromMinutes(1);

    // Two reconnect backoff caps plus a debug node's start: the client must not stay away longer.
    private static readonly TimeSpan RecoveryBound = TimeSpan.FromSeconds(20);

    /// <summary>
    /// Time for a transaction lost in a crash to be reported aborted after the restart: the
    /// server's <c>txn.liveness_timeout</c> (5 s) plus margin (PD-121).
    /// </summary>
    private static readonly TimeSpan AbortBound = TimeSpan.FromSeconds(30);

    private readonly ServerFixture _fixture;

    public RobustnessTests(ServerFixture fixture)
    {
        _fixture = fixture;
    }

    private static RustegonCredential Admin(RustegonTestServer server) => RustegonCredential.Scram(RustegonTestServer.AdminUser, server.AdminPassword);

    [Fact]
    public async Task tc_drv_net_028_thousand_concurrent_operations_complete_within_the_pool()
    {
        var ct = TestContext.Current.CancellationToken;
        RustegonTestServer server = _fixture.Require();
        string db = "net_stress_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4));
        RustegonClientSettings settings = server.Settings(Admin(server));
        settings.DefaultDatabase = db;
        await using var client = new RustegonClient(settings);
        Assert.True(await client.CreateDatabaseAsync(db, cancellationToken: ct));
        try
        {
            IRustegonCollection<RDocument> docs = client.GetDatabase().GetCollection<RDocument>("docs");

            // Phase 1: 1000 inserts started at once (one login shared by all, PD-072 fixture).
            await Task.WhenAll(Enumerable.Range(0, Concurrency).Select(i =>
                docs.InsertOneAsync(new RDocument { { "_id", i }, { "n", 0 } }, cancellationToken: ct)))
                .WaitAsync(StressBound, ct);

            // Phase 2: 1000 mixed operations at once: point reads, updates of distinct documents,
            // filtered finds (streams) and small transactions on distinct documents.
            var tasks = new List<Task>(Concurrency);
            for (int i = 0; i < Concurrency; i++)
            {
                int id = i;
                tasks.Add((i % 4) switch
                {
                    0 => docs.FindByIdAsync(id, cancellationToken: ct),
                    1 => docs.UpdateOneAsync(Filter.Id(id), Update.Inc("n", 1), cancellationToken: ct),
                    // A find (server stream) on the operation's own document. Range or full-scan
                    // finds over documents that 500 concurrent writers are changing wait on their
                    // write intents and exceeded the 30 s default deadline on a debug node in about
                    // half of the full-suite runs: server load, not the driver under test.
                    2 => docs.Find(Filter.Eq("_id", id)).ToListAsync(ct),
                    _ => client.WithTransactionAsync(
                        (txn, token) => txn.Collection<RDocument>("docs").UpdateOneAsync(Filter.Id(id), Update.Inc("n", 1), cancellationToken: token),
                        cancellationToken: ct),
                });
            }

            await Task.WhenAll(tasks).WaitAsync(StressBound, ct);

            // Every update and transaction applied exactly once.
            List<RDocument> all = await docs.Find(Filter.Empty).ToListAsync(ct);
            Assert.Equal(Concurrency, all.Count);
            Assert.Equal(Concurrency / 2, all.Sum(d => d["n"].AsInt64()));

            // Pool limits: the fixed channel set (ConnectionsPerEndpoint per endpoint, no channel
            // created on demand), and every call counted out again (no leaked lease = no stuck call).
            Assert.Equal(settings.ConnectionsPerEndpoint, client.Executor.Pool.ChannelCount);
            Assert.Equal(0, client.Executor.Pool.InFlight);
        }
        finally
        {
            await client.DropDatabaseAsync(db, new DropOptions { IfExists = true }, CancellationToken.None);
        }
    }

    [Fact]
    public async Task tc_drv_net_029_client_recovers_after_the_node_is_killed_and_restarted()
    {
        var ct = TestContext.Current.CancellationToken;
        string bin = RequireBinaries();
        await using RustegonTestServer server = await RustegonTestServer.StartAsync(bin, ct);
        const string db = "net_reconnect";
        RustegonClientSettings settings = server.Settings(Admin(server));
        settings.DefaultDatabase = db;
        await using var client = new RustegonClient(settings);
        Assert.True(await client.CreateDatabaseAsync(db, cancellationToken: ct));
        IRustegonCollection<RDocument> docs = client.GetDatabase().GetCollection<RDocument>("docs");
        await docs.InsertManyAsync(Enumerable.Range(0, 100).Select(i => new RDocument { { "_id", i }, { "v", i } }), cancellationToken: ct);

        // A transaction open across the crash: its write is never committed.
        ITransaction open = await client.BeginTransactionAsync(cancellationToken: ct);
        await open.Collection<RDocument>("docs").InsertOneAsync(new RDocument { { "_id", "in-txn" } }, cancellationToken: ct);

        // Writers in flight when the node dies: each runs until its first failure.
        var acknowledged = new ConcurrentBag<long>();
        var failures = new ConcurrentBag<Exception>();
        long next = 1000;
        using var enoughAcks = new SemaphoreSlim(0);
        Task[] writers = [.. Enumerable.Range(0, 8).Select(_ => Task.Run(
            async () =>
            {
                while (true)
                {
                    long id = Interlocked.Increment(ref next);
                    try
                    {
                        await docs.InsertOneAsync(new RDocument { { "_id", id } }, cancellationToken: ct);
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        failures.Add(e);
                        return;
                    }

                    acknowledged.Add(id);
                    if (acknowledged.Count == 50)
                    {
                        enoughAcks.Release();
                    }
                }
            },
            ct))];
        Assert.True(await enoughAcks.WaitAsync(PhaseBound, ct), "the writers made no progress");

        await server.CrashAsync();
        await Task.WhenAll(writers).WaitAsync(PhaseBound, ct);

        // Unknown outcomes surface as driver exceptions, never as raw transport errors.
        Assert.Equal(8, failures.Count);
        Assert.All(failures, e => Assert.IsAssignableFrom<RustegonException>(e));

        // While the node is down: Unavailable (RGN-3002), retryable, after the read retry.
        UnavailableException down = await Assert.ThrowsAsync<UnavailableException>(() => docs.FindByIdAsync(1, cancellationToken: ct));
        Assert.True(down.IsRetryable);

        await server.RestartAsync(ct);

        // The same client recovers by itself (no reconfiguration, no new client): its channels
        // reconnect after the gRPC reconnect backoff (capped at ChannelPool.MaxReconnectBackoff,
        // PD-119) and it logs in again; until then calls fail fast as Unavailable.
        var recovery = System.Diagnostics.Stopwatch.StartNew();
        RDocument? one = null;
        while (one is null)
        {
            try
            {
                one = await docs.FindByIdAsync(1, cancellationToken: ct);
            }
            catch (UnavailableException) when (recovery.Elapsed < RecoveryBound)
            {
                await Task.Delay(100, ct);
            }
        }

        Assert.Equal(1, one["v"].AsInt64());

        // Durability: everything acknowledged before the crash is there; the open transaction's
        // write is not; writes that failed in flight may or may not have committed.
        HashSet<long> ids = [.. (await docs.Find(Filter.Empty).ToListAsync(ct)).Select(d => d["_id"]).Where(v => v.Type == RDocType.Int64).Select(v => v.AsInt64())];
        Assert.Subset(ids, Enumerable.Range(0, 100).Select(i => (long)i).ToHashSet());
        Assert.Subset(ids, acknowledged.ToHashSet());
        Assert.Null(await docs.FindByIdAsync("in-txn", cancellationToken: ct));

        // The transaction did not survive the crash (PD-121 option (a'), server side): its
        // persisted record decides. Status answers COMMITTING (Unknown) until the liveness
        // timeout (5 s) has passed since its last write, then ABORTED coordinator_lost; it never
        // turns committed. Calls on a channel still in its reconnect backoff fail with
        // Unavailable before anything is sent, so they are repeated here.
        var resolving = System.Diagnostics.Stopwatch.StartNew();
        TransactionOutcome outcome = TransactionOutcome.Unknown;
        while (outcome != TransactionOutcome.Aborted)
        {
            Assert.True(resolving.Elapsed < AbortBound, "the lost transaction was never reported aborted");
            try
            {
                outcome = await open.ResolveAsync(ct);
            }
            catch (UnavailableException)
            {
            }

            Assert.NotEqual(TransactionOutcome.Committed, outcome);
            if (outcome != TransactionOutcome.Aborted)
            {
                await Task.Delay(200, ct);
            }
        }

        // Committing it now fails with RGN-2002 coordinator_lost, retryable (a re-run of the
        // whole transaction is safe); nothing is applied.
        TransactionAbortedException lost;
        while (true)
        {
            RustegonException e = await Assert.ThrowsAnyAsync<RustegonException>(() => open.CommitAsync(ct));
            if (e is UnavailableException && recovery.Elapsed < RecoveryBound + AbortBound)
            {
                continue;
            }

            lost = Assert.IsType<TransactionAbortedException>(e);
            break;
        }

        Assert.Equal(2002, lost.Code);
        Assert.Equal("coordinator_lost", lost.Details["reason"]);
        Assert.True(lost.IsRetryable);
        Assert.Null(await docs.FindByIdAsync("in-txn", cancellationToken: ct));
        await open.DisposeAsync();

        // New writes work again.
        await docs.InsertOneAsync(new RDocument { { "_id", "after" } }, cancellationToken: ct);
        Assert.NotNull(await docs.FindByIdAsync("after", cancellationToken: ct));
    }

    private static string RequireBinaries()
    {
        string? bin = RustegonTestServer.FindBinaries(out string reason);
        if (bin is null)
        {
            if (string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase))
            {
                Assert.Fail("CI=true but no server binaries: " + reason);
            }

            Assert.Skip("integration test skipped: " + reason);
        }

        return bin;
    }
}

/// <summary>Channel choice of a retry (TC-DRV-NET-029, PD-119), without a server.</summary>
public sealed class ChannelChoiceTests
{
    [Fact]
    public async Task tc_drv_net_029_a_retry_avoids_the_channel_that_failed()
    {
        await using var client = new RustegonClient(new RustegonClientSettings { Endpoints = { "127.0.0.1:1" }, ConnectionsPerEndpoint = 3 });
        Internal.Transport.ChannelPool pool = client.Executor.Pool;
        var seen = new HashSet<Internal.Transport.ChannelPool.Slot>();
        Internal.Transport.ChannelPool.Slot failed;
        using (Internal.Transport.ChannelPool.Lease first = pool.Acquire())
        {
            failed = first.Slot;
        }

        for (int i = 0; i < 200; i++)
        {
            using Internal.Transport.ChannelPool.Lease retry = pool.Acquire(failed);
            Assert.NotSame(failed, retry.Slot);
            seen.Add(retry.Slot);
        }

        Assert.Equal(2, seen.Count); // both other channels are used
        Assert.Equal(0, pool.InFlight);
    }
}
