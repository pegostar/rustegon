// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using Rustegon.Driver;
using Rustegon.Driver.Mapping;

namespace Rustegon.Driver.Sample;

/// <summary>An order mapped by the source generator (no reflection: Native AOT safe).</summary>
/// <param name="Id">Document id.</param>
/// <param name="Customer">Customer name.</param>
/// <param name="Total">Order total.</param>
[RustegonDocument]
internal sealed record Order([property: RgnId] long Id, string Customer, decimal Total)
{
    /// <summary>Order lines.</summary>
    public List<string> Items { get; init; } = [];
}

/// <summary>
/// The driver sample (AC-DRV-001) and the Native AOT smoke test (TC-DRV-NET-026): typed CRUD,
/// an expression filter, a transaction and RGQL against a running node.
/// </summary>
/// <remarks>
/// Configuration from the environment: <c>RUSTEGON_ENDPOINT</c> (<c>host:port</c>),
/// <c>RUSTEGON_CA</c> (CA certificate, PEM), <c>RUSTEGON_USER</c>, <c>RUSTEGON_PASSWORD</c>.
/// Exit code 0 = every step returned what it should.
/// </remarks>
internal static class Program
{
    /// <summary>Runs the sample.</summary>
    /// <returns>The exit code.</returns>
    public static async Task<int> Main()
    {
        string? endpoint = Environment.GetEnvironmentVariable("RUSTEGON_ENDPOINT");
        string? user = Environment.GetEnvironmentVariable("RUSTEGON_USER");
        string? password = Environment.GetEnvironmentVariable("RUSTEGON_PASSWORD");
        if (endpoint is null || user is null || password is null)
        {
            await Console.Error.WriteLineAsync("set RUSTEGON_ENDPOINT, RUSTEGON_USER and RUSTEGON_PASSWORD (and RUSTEGON_CA for a node with TLS)");
            return 2;
        }

        string db = "sample_" + DateTime.UtcNow.Ticks.ToString(CultureInfo.InvariantCulture);
        var settings = new RustegonClientSettings
        {
            Credential = RustegonCredential.Scram(user, password),
            // Plain text unless RUSTEGON_CA names the CA of a node with TLS (ADR-034).
            Tls = new TlsSettings { CaCertificatePath = Environment.GetEnvironmentVariable("RUSTEGON_CA") },
            DefaultDatabase = db,
        };
        settings.Endpoints.Add(endpoint);

        await using var client = new RustegonClient(settings);
        await client.CreateDatabaseAsync(db);
        try
        {
            IRustegonCollection<Order> orders = client.GetDatabase().GetCollection<Order>("orders");
            await orders.InsertManyAsync([new Order(1, "ada", 10m) { Items = ["pen"] }, new Order(2, "bob", 25.5m)]);

            List<Order> big = await orders.Find(Filter.Gt<Order>(x => x.Total, 20m)).ToListAsync();
            Check(big.Count == 1 && big[0].Customer == "bob", "expression filter");

            await client.WithTransactionAsync(async (txn, ct) =>
            {
                IRustegonCollection<Order> t = txn.Collection<Order>("orders");
                await t.InsertOneAsync(new Order(3, "cy", 7m), cancellationToken: ct);
                await t.UpdateOneAsync(Filter.Id(1), Update.Inc("total", 1), cancellationToken: ct);
            });

            Order? one = await orders.FindByIdAsync(1);
            Check(one is { Total: 11m, Items: ["pen"] }, "transaction");

            long rows = 0;
            await foreach (RDocument _ in client.GetDatabase().QueryAsync<RDocument>("FROM orders WHERE total < $max", new RDocument { { "max", 20 } }))
            {
                rows++;
            }

            Check(rows == 2, "RGQL");
            Console.WriteLine("rustegon sample: ok");
            return 0;
        }
        finally
        {
            await client.DropDatabaseAsync(db);
        }
    }

    private static void Check(bool condition, string step)
    {
        if (!condition)
        {
            throw new InvalidOperationException("sample step failed: " + step);
        }
    }
}
