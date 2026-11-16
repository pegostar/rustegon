// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Rustegon.Driver.TestServer;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// The typed client API against <c>rustegond</c>, as an application writes it (the conformance
/// runner, TC-DRV-NET-020, drives the same API from the shared YAML files):
/// TC-DRV-NET-012 CRUD, finds, cursors and RGQL; TC-DRV-NET-013 bulk writes, collections and
/// indexes; TC-DRV-NET-014 sessions and credentials; TC-DRV-NET-015 transactions and
/// <c>WithTransactionAsync</c> (FR-DRV-001, FR-TXN-005, FR-TXN-006).
/// </summary>
[Collection(ServerGroup.Name)]
public sealed class ClientApiIntegrationTests
{
    private readonly ServerFixture _fixture;

    public ClientApiIntegrationTests(ServerFixture fixture)
    {
        _fixture = fixture;
    }

    private async Task<(RustegonClient Client, string Database)> ClientAsync()
    {
        RustegonTestServer server = _fixture.Require();
        string db = "net_api_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4));
        RustegonClientSettings s = server.Settings(RustegonCredential.Scram(RustegonTestServer.AdminUser, server.AdminPassword));
        s.DefaultDatabase = db;
        var client = new RustegonClient(s);
        Assert.True(await client.CreateDatabaseAsync(db, cancellationToken: TestContext.Current.CancellationToken));
        _fixture.OnDispose(async () =>
        {
            await client.DropDatabaseAsync(db, new DropOptions { IfExists = true });
            await client.DisposeAsync();
        });
        return (client, db);
    }

    [Fact]
    public async Task tc_drv_net_012_crud_find_cursor_and_rgql()
    {
        var ct = TestContext.Current.CancellationToken;
        (RustegonClient client, _) = await ClientAsync();
        IRustegonCollection<RDocument> orders = client.GetDatabase().GetCollection<RDocument>("orders");
        InsertManyResult inserted = await orders.InsertManyAsync(
            Enumerable.Range(1, 7).Select(i => new RDocument { { "_id", i }, { "status", i % 2 == 0 ? "paid" : "new" }, { "total", i * 10 } }),
            cancellationToken: ct);
        Assert.Equal(new long[] { 1, 2, 3, 4, 5, 6, 7 }, inserted.InsertedIds.Select(v => v.AsInt64()));
        InsertOneResult generated = await orders.InsertOneAsync(new RDocument { { "status", "draft" } }, cancellationToken: ct);
        Assert.Equal(RDocType.ObjectId, generated.InsertedId.Type);

        RDocument? one = await orders.FindByIdAsync(4, cancellationToken: ct);
        Assert.Equal("paid", one!["status"].AsString());
        Assert.Null(await orders.FindByIdAsync(99, cancellationToken: ct));

        // Typed filters and operators; `await foreach` over the find, two documents per batch.
        var paid = new List<long>();
        await foreach (RDocument d in orders.Find(Filter.Eq("status", "paid") & Filter.Gte("total", 20)).Sort(Sort.Descending("total")).BatchSize(2).WithCancellation(ct))
        {
            paid.Add(d["_id"].AsInt64());
        }

        Assert.Equal(new long[] { 6, 4, 2 }, paid);
        Assert.Equal(7, (await orders.Find(Filter.Exists("total")).Skip(0).Limit(100).ToListAsync(ct)).Count);
        RDocument? first = await orders.Find(Filter.In("status", ["new", "late"])).Sort(Sort.Ascending("total")).Project(Projection.Include("total")).FirstOrDefaultAsync(ct);
        Assert.Equal("{\"total\":10}", first!.ToJson());

        // A cursor left early is killed; the next query still works.
        await using (IAsyncCursor<RDocument> cursor = await orders.Find(Filter.Empty).Sort(Sort.Ascending("_id")).BatchSize(1).ToCursorAsync(ct))
        {
            Assert.True(await cursor.MoveNextAsync());
            Assert.Equal(1, cursor.Current["_id"].AsInt64());
        }

        UpdateResult byId = await orders.UpdateOneAsync(Filter.Id(1), Update.Set("status", "paid").Inc("total", 5), cancellationToken: ct);
        Assert.Equal(new UpdateResult(1, 1), byId);
        UpdateResult many = await orders.UpdateManyAsync(Filter.Eq("status", "new"), Update.Set("status", "late"), cancellationToken: ct);
        Assert.Equal(3, many.MatchedCount);
        Assert.Equal(new UpdateResult(0, 0, 50), await orders.ReplaceOneAsync(Filter.Id(50), new RDocument { { "status", "x" } }, new ReplaceOptions { IsUpsert = true }, ct));
        Assert.Equal(new DeleteResult(1), await orders.DeleteOneAsync(Filter.Id(50), cancellationToken: ct));
        Assert.Equal(new DeleteResult(3), await orders.DeleteManyAsync(Filter.Eq("status", "late"), cancellationToken: ct));

        // RGQL with parameters (values never become text).
        var totals = new List<long>();
        await foreach (RDocument row in client.GetDatabase().QueryAsync<RDocument>(
            "FROM orders WHERE status = $s SELECT VALUE total ORDER BY _id",
            new RDocument { { "s", "paid" } },
            new QueryOptions { BatchSize = 1 }).WithCancellation(ct))
        {
            totals.Add(row["value"].AsInt64());
        }

        Assert.Equal(new long[] { 15, 20, 40, 60 }, totals);
    }

    [Fact]
    public async Task tc_drv_net_013_bulk_write_collections_and_indexes()
    {
        var ct = TestContext.Current.CancellationToken;
        (RustegonClient client, _) = await ClientAsync();
        IRustegonDatabase db = client.GetDatabase();
        Assert.True(await db.CreateCollectionAsync("people", new CreateCollectionOptions { Validator = new CollectionValidator("{\"required\":[\"email\"]}") }, ct));
        Assert.False(await db.CreateCollectionAsync("people", new CreateCollectionOptions { IfNotExists = true }, ct));
        Assert.Contains("people", await db.ListCollectionNamesAsync(ct));
        IRustegonCollection<RDocument> people = db.GetCollection<RDocument>("people");
        IndexDescription index = await people.CreateIndexAsync("by_email", IndexKeys.Ascending("email"), new CreateIndexOptions { Unique = true }, ct);
        Assert.Equal(("by_email", true, IndexState.Ready), (index.Name, index.Unique, index.State));
        Assert.Equal(new IndexKey("email", false), Assert.Single(index.Keys));
        Assert.Equal("by_email", Assert.Single(await people.ListIndexesAsync(ct)).Name);

        BulkWriteResult bulk = await people.BulkWriteAsync(
            [
                BulkOperation.Insert(new RDocument { { "_id", 1 }, { "email", "a@example.com" } }),
                BulkOperation.Insert(new RDocument { { "_id", 2 }, { "email", "a@example.com" } }),
                BulkOperation.Insert(new RDocument { { "_id", 3 } }),
                BulkOperation.Update<RDocument>(1, Update.Set("name", "Ann")),
            ],
            new BulkWriteOptions { Ordered = false },
            ct);
        Assert.Equal(1, bulk.InsertedCount);
        Assert.Equal(1, bulk.ModifiedCount);
        Assert.Equal(new[] { (1, 1005), (2, 1006) }, bulk.Errors.Select(e => (e.Index, e.Error.Code)));

        Assert.True(await people.DropIndexAsync("by_email", cancellationToken: ct));
        Assert.True(await db.DropCollectionAsync("people", cancellationToken: ct));
        Assert.DoesNotContain("people", await db.ListCollectionNamesAsync(ct));
    }

    [Fact]
    public async Task tc_drv_net_014_sessions_and_password_change()
    {
        var ct = TestContext.Current.CancellationToken;
        RustegonTestServer server = _fixture.Require();
        (RustegonClient admin, string db) = await ClientAsync();
        var create = new Rustegon.V1.CreateUserRequest { Name = "net_api_user", Password = "first-pass-123456", MustChangePassword = true };
        create.Roles.Add(new Rustegon.V1.RoleGrant { Role = "read_write", Resource = "database:" + db });
        await admin.Executor.UnaryAsync((invoker, o) => new Rustegon.V1.AdminService.AdminServiceClient(invoker).CreateUserAsync(create, o), ct);
        try
        {
            await using (var refused = new RustegonClient(server.Settings(RustegonCredential.Scram("net_api_user", "first-pass-123456"))))
            {
                await Assert.ThrowsAsync<PasswordChangeRequiredException>(() => refused.ListDatabaseNamesAsync(ct));
            }

            RustegonClientSettings limited = server.Settings(RustegonCredential.Scram("net_api_user", "first-pass-123456"));
            limited.AllowPasswordChangeOnly = true;
            await using (var c = new RustegonClient(limited))
            {
                await c.ChangePasswordAsync("first-pass-123456", "second-pass-7890ab", ct);
            }

            RustegonClientSettings normal = server.Settings(RustegonCredential.Scram("net_api_user", "second-pass-7890ab"));
            normal.DefaultDatabase = db;
            await using var user = new RustegonClient(normal);
            await using IClientSession session = await user.StartSessionAsync(new SessionOptions { CausalConsistency = true }, ct);
            IRustegonCollection<RDocument> items = user.GetDatabase().GetCollection<RDocument>("items");
            await items.InsertOneAsync(new RDocument { { "_id", 1 } }, new InsertOptions { Session = session }, ct);
            Assert.NotNull(await items.FindByIdAsync(1, new FindOptions { Session = session }, ct));
        }
        finally
        {
            await admin.Executor.UnaryAsync((invoker, o) => new Rustegon.V1.AdminService.AdminServiceClient(invoker).DropUserAsync(new Rustegon.V1.DropUserRequest { Name = "net_api_user" }, o), ct);
        }
    }

    [Fact]
    public async Task tc_drv_net_015_with_transaction_and_manual_mode()
    {
        var ct = TestContext.Current.CancellationToken;
        (RustegonClient client, string db) = await ClientAsync();
        IRustegonCollection<RDocument> accounts = client.GetDatabase().GetCollection<RDocument>("accounts");
        await accounts.InsertManyAsync([new RDocument { { "_id", "a1" }, { "balance", 100 } }, new RDocument { { "_id", "a2" }, { "balance", 50 } }], cancellationToken: ct);

        long after = await client.WithTransactionAsync(
            async (txn, token) =>
            {
                IRustegonCollection<RDocument> a = txn.Collection<RDocument>(db + ".accounts");
                RDocument? from = await a.FindByIdAsync("a1", cancellationToken: token);
                await a.UpdateOneAsync(Filter.Id("a1"), Update.Inc("balance", -10), cancellationToken: token);
                await a.UpdateOneAsync(Filter.Id("a2"), Update.Inc("balance", 10), cancellationToken: token);
                return from!["balance"].AsInt64() - 10;
            },
            new TransactionOptions { Isolation = IsolationLevel.Serializable, MaxRetryTime = TimeSpan.FromSeconds(30) },
            ct);
        Assert.Equal(90, after);
        Assert.Equal(60, (await accounts.FindByIdAsync("a2", cancellationToken: ct))!["balance"].AsInt64());

        // An exception of the callback rolls back and propagates unchanged.
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.WithTransactionAsync(
            async (txn, token) =>
            {
                await txn.Collection<RDocument>("accounts").UpdateOneAsync(Filter.Id("a1"), Update.Set("balance", 0), cancellationToken: token);
                throw new InvalidOperationException("application");
            },
            cancellationToken: ct));
        Assert.Equal(90, (await accounts.FindByIdAsync("a1", cancellationToken: ct))!["balance"].AsInt64());

        // Manual mode: dispose without commit rolls back; commit then resolve reports committed.
        await using (ITransaction txn = await client.BeginTransactionAsync(cancellationToken: ct))
        {
            await txn.Collection<RDocument>("accounts").DeleteOneAsync(Filter.Id("a1"), cancellationToken: ct);
        }

        Assert.NotNull(await accounts.FindByIdAsync("a1", cancellationToken: ct));
        await using (ITransaction txn = await client.BeginTransactionAsync(cancellationToken: ct))
        {
            var rows = new List<RDocument>();
            await foreach (RDocument r in txn.QueryAsync<RDocument>("UPDATE accounts SET balance = balance + $d WHERE _id = $id RETURNING NEW balance", new RDocument { { "d", 1 }, { "id", "a2" } }).WithCancellation(ct))
            {
                rows.Add(r);
            }

            Assert.Equal(61, Assert.Single(rows)["balance"].AsInt64());
            await txn.CommitAsync(ct);
            Assert.Equal(TransactionOutcome.Committed, await txn.ResolveAsync(ct));
        }

        Assert.Equal(61, (await accounts.FindByIdAsync("a2", cancellationToken: ct))!["balance"].AsInt64());
    }
}
