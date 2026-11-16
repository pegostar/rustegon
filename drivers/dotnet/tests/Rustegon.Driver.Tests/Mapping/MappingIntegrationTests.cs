// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Rustegon.Driver.MappedTypes;
using Rustegon.Driver.TestServer;
using Xunit;

namespace Rustegon.Driver.Tests.Mapping;

/// <summary>
/// Typed CRUD with generated codecs against <c>rustegond</c> (TC-DRV-NET-023, TC-DRV-NET-024;
/// FR-DRV-001): inserts, reads by id with the server's <c>_rev</c>, expression filters, an
/// optimistic replace with <c>IfRev</c>, updates by <see cref="FieldPath"/>, a polymorphic
/// collection and a typed handle inside a transaction.
/// </summary>
[Collection(ServerGroup.Name)]
public sealed class MappingIntegrationTests
{
    private readonly ServerFixture _fixture;

    public MappingIntegrationTests(ServerFixture fixture)
    {
        _fixture = fixture;
    }

    private async Task<RustegonClient> ClientAsync()
    {
        RustegonTestServer server = _fixture.Require();
        string db = "net_map_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4));
        RustegonClientSettings s = server.Settings(RustegonCredential.Scram(RustegonTestServer.AdminUser, server.AdminPassword));
        s.DefaultDatabase = db;
        var client = new RustegonClient(s);
        Assert.True(await client.CreateDatabaseAsync(db, cancellationToken: TestContext.Current.CancellationToken));
        _fixture.OnDispose(async () =>
        {
            await client.DropDatabaseAsync(db, new DropOptions { IfExists = true });
            await client.DisposeAsync();
        });
        return client;
    }

    private static Order NewOrder(long id, OrderStatus status, decimal total, string sku) =>
        new(id, status, total) { Customer = "c" + id, Lines = [new Line { Sku = sku, Qty = (int)id }], Embedding = [id, 0.5f, -1f], Location = [12.5, 41.9] };

    [Fact]
    public async Task tc_drv_net_023_typed_crud_against_rustegond()
    {
        var ct = TestContext.Current.CancellationToken;
        RustegonClient client = await ClientAsync();
        IRustegonCollection<Order> orders = client.GetDatabase().GetCollection<Order>("orders");
        InsertManyResult inserted = await orders.InsertManyAsync(
            [NewOrder(1, OrderStatus.New, 10m, "a"), NewOrder(2, OrderStatus.Paid, 20.5m, "b"), NewOrder(3, OrderStatus.Paid, 30m, "a")],
            cancellationToken: ct);
        Assert.Equal([1L, 2L, 3L], inserted.InsertedIds.Select(v => v.AsInt64()));

        Order? two = await orders.FindByIdAsync(2, cancellationToken: ct);
        Assert.NotNull(two);
        Assert.Equal((OrderStatus.Paid, 20.5m, "c2", "b"), (two.Status, two.Total, two.Customer, two.Lines.Single().Sku));
        Assert.Equal([2f, 0.5f, -1f], two.Embedding!);
        Assert.Equal([12.5, 41.9], two.Location!);
        Assert.False(string.IsNullOrEmpty(two.Rev));

        List<Order> paid = await orders.Find(Filter.Eq<Order>(x => x.Status, nameof(OrderStatus.Paid))).Sort(Sort.Ascending(FieldPath.Of<Order>(x => x.Id))).ToListAsync(ct);
        Assert.Equal([2L, 3L], paid.Select(o => o.Id));
        Assert.Equal([1L, 3L], (await orders.Find(Filter.Eq<Order>(x => x.Lines[0].Sku, "a")).ToListAsync(ct)).Select(o => o.Id).Order());
        Assert.Equal([3L], (await orders.Find(Filter.Gt<Order>(x => x.Total, 25m)).ToListAsync(ct)).Select(o => o.Id));

        // Optimistic concurrency with the mapped revision.
        UpdateResult replaced = await orders.ReplaceOneAsync(Filter.Id(2), two with { Total = 99m }, new ReplaceOptions { IfRev = two.Rev }, ct);
        Assert.Equal(1, replaced.ModifiedCount);
        Order? again = await orders.FindByIdAsync(2, cancellationToken: ct);
        Assert.Equal(99m, again!.Total);
        Assert.NotEqual(two.Rev, again.Rev);
        await Assert.ThrowsAnyAsync<RustegonException>(() => orders.ReplaceOneAsync(Filter.Id(2), two, new ReplaceOptions { IfRev = two.Rev }, ct));

        await orders.UpdateOneAsync(Filter.Id(1), Update.Set(FieldPath.Of<Order>(x => x.Status), nameof(OrderStatus.Shipped)), cancellationToken: ct);
        Assert.Equal(OrderStatus.Shipped, (await orders.FindByIdAsync(1, cancellationToken: ct))!.Status);
        Assert.Equal(1, (await orders.DeleteManyAsync(Filter.Lt<Order>(x => x.Total, 15m), cancellationToken: ct)).DeletedCount);

        // A typed handle inside a transaction.
        await client.WithTransactionAsync(
            async (txn, token) =>
            {
                IRustegonCollection<Order> t = txn.Collection<Order>("orders");
                await t.InsertOneAsync(NewOrder(4, OrderStatus.New, 1m, "z"), cancellationToken: token);
                return 0;
            },
            cancellationToken: ct);
        Assert.Equal("z", (await orders.FindByIdAsync(4, cancellationToken: ct))!.Lines.Single().Sku);
    }

    [Fact]
    public async Task tc_drv_net_024_polymorphic_collection_against_rustegond()
    {
        var ct = TestContext.Current.CancellationToken;
        RustegonClient client = await ClientAsync();
        IRustegonCollection<Shape> shapes = client.GetDatabase().GetCollection<Shape>("shapes");
        await shapes.InsertManyAsync([new Circle { Id = "c", Radius = 1 }, new Square { Id = "s", Width = 2, Height = 2 }, new Rect { Id = "r", Width = 1, Height = 3 }], cancellationToken: ct);
        List<Shape> all = await shapes.Find(Filter.Empty).Sort(Sort.Ascending("_id")).ToListAsync(ct);
        Assert.Equal([typeof(Circle), typeof(Rect), typeof(Square)], all.Select(s => s.GetType()));
        List<Shape> rects = await shapes.Find(Filter.In("_type", ["rect", "square"])).ToListAsync(ct);
        Assert.Equal(2, rects.Count);
        Assert.All(rects, r => Assert.IsAssignableFrom<Rect>(r));
        Circle? c = await client.GetDatabase().GetCollection<Circle>("shapes").FindByIdAsync("c", cancellationToken: ct);
        Assert.Equal(1, c!.Radius);
    }
}
