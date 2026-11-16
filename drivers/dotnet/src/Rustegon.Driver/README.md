# Rustegon.Driver

Official .NET driver of [Rustegon](https://github.com/rustegon/rustegon), a distributed ACID document
database. Target framework `net10.0`; trimming and Native AOT compatible (source-generated codecs).

```csharp
using Rustegon.Driver;
using Rustegon.Driver.Mapping;

[RustegonDocument]
public sealed record Order([property: RgnId] long Id, string Customer, decimal Total);

// A single node started with its defaults speaks plain text (ADR-034).
await using var client = new RustegonClient($"rustegon://admin:{Uri.EscapeDataString(password)}@localhost:7700/shop");
// A node with TLS (security.tls = true; always in a cluster): name its CA, which turns TLS on.
var settings = new RustegonClientSettings
{
    Endpoints = { "node1.example.com:7700" },
    Credential = RustegonCredential.Scram("app_user", password),
    Tls = new TlsSettings { CaCertificatePath = "/etc/rustegon/ca.crt" }, // or "...?tls=true&tlsCaFile=ca.crt"
    DefaultDatabase = "shop",
};
await using var tlsClient = new RustegonClient(settings);
IRustegonCollection<Order> orders = client.GetDatabase().GetCollection<Order>("orders");
await orders.InsertOneAsync(new Order(42, "ada", 120m));
List<Order> big = await orders.Find(Filter.Gt<Order>(x => x.Total, 100m)).ToListAsync();
await client.WithTransactionAsync(async (txn, ct) =>
    await txn.Collection<Order>("orders").UpdateOneAsync(Filter.Id(42), Update.Inc("total", -10), cancellationToken: ct));
```

Versioning: semantic versioning; the driver's major version is the wire protocol's major version.
Documentation, specification and sources: <https://github.com/rustegon/rustegon/tree/main/drivers/dotnet>.
Licensed under Apache-2.0.
