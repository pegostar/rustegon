# Rustegon .NET driver (`Rustegon.Driver`)

Official .NET driver of Rustegon (spec: [`docs/specifications/dotnet-driver.md`](../../docs/specifications/dotnet-driver.md)).
Target framework **`net10.0`** only (DEC-020). M11 waves 1–2: RDoc codec, extended JSON, exceptions,
SCRAM-SHA-256, connection strings, TLS, channel pool (wave 1) and the R1 client API of
`drivers/conformance/model.yaml` (wave 2, PD-069): databases, collections and indexes, CRUD, finds and
cursors, RGQL with parameters, bulk writes by id, sessions, transactions and `WithTransactionAsync`,
`ChangePasswordAsync`, with the retry policy of `drivers/conformance/retry.yaml`. Wave 2 added object
mapping (typed POCOs, TC-DRV-NET-021…025), wave 3 packaging and robustness (TC-DRV-NET-026…029);
observability follows.

## Layout

| Path | Content |
|---|---|
| `Rustegon.Driver.sln`, `Directory.Build.props`, `Directory.Packages.props`, `global.json`, `.editorconfig` | solution, shared build settings (nullable, warnings as errors, `AnalysisLevel=latest-all`, XML docs, deterministic, SourceLink), central package versions, SDK pin (10.0.x, `latestFeature`) |
| `Rustegon.snk` | strong-name key pair of every assembly (public on purpose, PD-117) |
| `src/Rustegon.Driver/` | the driver (`README.md` = the package readme); gRPC client stubs are generated at build time from `../../proto/rustegon/v1/*.proto` (internal) |
| `src/Rustegon.Driver/Codec/` | `RDocWriter`, `RDocReader` (RDoc v1, data-model.md §4, byte-exact with `rustegon-doc`) |
| `src/Rustegon.Driver/Json/` | canonical / extended JSON (`RDocument.FromJson` / `ToJson`) |
| `src/Rustegon.Driver/Auth/` | SCRAM-SHA-256 client, SASLprep (RFC 4013), session authenticator |
| `src/Rustegon.Driver/Connection/`, `Transport/` | `rustegon://` parser, endpoints, channel pool, interceptor, executor with the retry policy, TLS material |
| `src/Rustegon.Driver/Builders/`, `DataPlane/` | `Filter` / `Update` / `Sort` / `Projection` / `IndexKeys` → structured AST (PD-070); database, collection, find, cursor, transaction implementations |
| `src/Rustegon.Driver/Errors/` | code → exception mapping; the catalog `ErrorCodes` (namespace `Rustegon.Driver.Errors`) is compiled from `drivers/conformance/generated/ErrorCodes.g.cs` (linked, PD-075) |
| `src/Rustegon.Driver/Mapping/` | object mapping: attributes, `RDocCodecRegistry`, converters, the opt-in reflection codec (dotnet-driver.md §7) |
| `src/Rustegon.Driver.Generators/` | the `[RustegonDocument]` source generator (netstandard2.0), packed into `Rustegon.Driver` under `analyzers/dotnet/cs` |
| `tests/Rustegon.Driver.MappedTypes/` | mapped sample types built with the trimming/AOT analyzers as errors (TC-DRV-NET-021), used by the tests |
| `tests/Rustegon.Driver.Tests/` | xUnit v3 + FsCheck 3 tests (TC ids in [`TESTS.md`](TESTS.md)); `Conformance/`: the runner of `drivers/conformance/` and the in-process fake gRPC server of `retry.yaml` |
| `tests/Rustegon.Driver.TestServer/` | starts a real single-node `rustegond` for integration tests (PD-072); can crash and restart it on the same data directory and port (TC-DRV-NET-029) |
| `samples/Rustegon.Driver.Sample/` | console sample (AC-DRV-001), built with the solution; published with Native AOT by TC-DRV-NET-026 |

## Build and test

```bash
cd drivers/dotnet
dotnet build -c Release -warnaserror        # the gate: zero warnings
dotnet test                                  # unit + integration tests (Microsoft Testing Platform)
```

Integration tests start `rustegond` from the binaries of the Rust workspace:

```bash
# from the repository root (once): the CLI runs `rustegon init`, the daemon serves the tests
CARGO_BUILD_JOBS=6 cargo build -p rustegond -p rustegon-cli
```

- `RUSTEGON_BIN_DIR` — directory with `rustegon` and `rustegond` (default `<repo>/target/debug`).
- Without the binaries the integration tests are **skipped** with the reason; with `CI=true` they **fail** instead.
- Each test run uses one fresh node in a temporary directory: `rustegon init --data-dir … --grpc-port 0 --http-port 0
  --admin-password-file … --non-interactive --tls --client-user …` (TLS opt-in, ADR-034, so the tests keep TLS
  and X.509 covered), then `rustegond --config … --admin-password-file … --stop-on-stdin-eof
  --set auth.scram_iterations=100000`; the node stops when the tests close its stdin.

## Using the client

```csharp
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
IRustegonCollection<RDocument> orders = client.GetDatabase().GetCollection<RDocument>("orders");

await orders.InsertOneAsync(new RDocument { { "_id", 42 }, { "status", "paid" }, { "total", 120 } }, cancellationToken: ct);
RDocument? order = await orders.FindByIdAsync(42, cancellationToken: ct);
await foreach (RDocument d in orders.Find(Filter.Eq("status", "paid") & Filter.Gte("total", 100))
                                    .Sort(Sort.Descending("total")).Limit(50).WithCancellation(ct)) { … }
await orders.UpdateOneAsync(Filter.Id(42), Update.Set("status", "shipped").Inc("version", 1),
                            new UpdateOptions { IfRev = order!["_rev"].AsString() }, ct);

// RGQL: values are parameters, never text (PD-096: parameters as an RDocument).
await foreach (RDocument row in client.GetDatabase().QueryAsync<RDocument>(
    "FROM orders WHERE status = $s SELECT VALUE total", new RDocument { { "s", "paid" } }).WithCancellation(ct)) { … }

// Transactions: the callback may run several times (retryable conflicts); keep it free of external side effects.
long total = await client.WithTransactionAsync(async (txn, token) =>
{
    IRustegonCollection<RDocument> o = txn.Collection<RDocument>("shop.orders");
    await o.UpdateOneAsync(Filter.Id(42), Update.Inc("total", -10), cancellationToken: token);
    return (await o.FindByIdAsync(42, cancellationToken: token))!["total"].AsInt64();
}, cancellationToken: ct);
```

Builders produce the structured AST (`query_ast.proto`), never RGQL text (PD-070): a filter that is exactly
`Filter.Id(v)` makes single-document writes use `DocumentService`; any other filter runs as a statement
(`UPDATE … LIMIT 1` for the `One` variants, the document with the lowest `_id`; the empty filter adds
`allow_full_scan_write`). Every operation follows dotnet-driver.md §8 (`retry.yaml` R1–R6): it is retried
only when the server marks the error retryable, reads when `RetryReads`, writes when `RetryWrites` (same
`rgn-request-id`), never alone inside a transaction, never past its deadline (`Timeout` of the options or
`DefaultOperationTimeout`, covering every attempt, PD-097).

### Object mapping (dotnet-driver.md §7)

```csharp
[RustegonDocument]
public sealed record Order([property: RgnId] long Id, OrderStatus Status, decimal Total)
{
    [RgnRev] public string? Rev { get; init; }              // server revision: read, never written
    public List<Line> Lines { get; init; } = [];             // nested [RustegonDocument] types
    [RgnVector(768)] public float[]? Embedding { get; init; }
    [RgnField("cust")] public required string Customer { get; init; }
}

IRustegonCollection<Order> orders = client.GetDatabase().GetCollection<Order>("orders");
Order? o = await orders.FindByIdAsync(42, cancellationToken: ct);
await orders.ReplaceOneAsync(Filter.Id(42), o! with { Total = 99m }, new ReplaceOptions { IfRev = o.Rev }, ct);
List<Order> paid = await orders.Find(Filter.Eq<Order>(x => x.Status, nameof(OrderStatus.Paid))
                                    & Filter.Gt<Order>(x => x.Lines[0].Qty, 1)).ToListAsync(ct);
await orders.UpdateOneAsync(Filter.Id(42), Update.Set(FieldPath.Of<Order>(x => x.Customer), "ann"), cancellationToken: ct);
```

The `Rustegon.Driver.Generators` source generator (shipped in the package under `analyzers/dotnet/cs`)
emits an `IRDocCodec<T>` for every `[RustegonDocument]` class, record or struct and registers it from a
module initializer: no reflection, trimming and AOT safe; unmappable members are build errors
(RGNG001–RGNG004). Members are the public properties with a getter that have a `set`/`init` or are bound
by the constructor with the most matching parameters; names are camelCase unless `[RgnField]`,
`[RgnId]` (`_id`, omitted when null; without it a property named `Id`/`id`) or `[RgnRev]` (`_rev`) say otherwise; `_id` is written first, then `_type`, then the members in declaration order; `[RgnIgnore]` excludes a
member. Types: `long`/`int`/`short` → int64, `double`/`float` → float64, `decimal` → decimal128,
`string`, `byte[]`/`ReadOnlyMemory<byte>` → binary, `DateTime` (UTC only) / `DateTimeOffset` →
datetime, `Guid` → uuid, `ObjectId`, `Decimal128`, `float[]`/`ReadOnlyMemory<float>` → vector_f32
(`[RgnVector(n)]` checks the dimensions), `[RgnGeoPoint] double[]` `[lng, lat]` → GeoJSON point with range checks (PD-109),
`[RgnCounter] long` (read-only counter projection), enums as their names, `T?`, `List<T>`, `T[]`,
`Dictionary<string, T>`, `RDocument`/`RDocArray`/`RDocValue` for schemaless parts. Unknown fields are
ignored on read; an absent field gives the member its default (PD-108, the same rules as the Java
mapper). Polymorphism: `[RgnDiscriminator("circle")]` (or `[RgnDiscriminator]` for the simple type name) on derived classes stores `_type`, and
the base type's codec reads and writes every derived type (PD-110). Types without `[RustegonDocument]`
fail with `NotSupportedException` when the handle is created, unless the application opts in to the
reflection codec with `RDocCodecRegistry.EnableReflectionFallback()` (same rules and bytes, not
trimming/AOT safe). Generic filter overloads (`Eq`, `Ne`, `Gt`, `Gte`, `Lt`, `Lte`, `In`, `Nin`,
`Exists`) take member expressions; `FieldPath.Of<T>(x => …)` gives the path for every other builder.
Values stay `RDocValue` (pass an enum by name).

### Connection string (normative: `drivers/conformance/connstring.yaml`)

```
rustegon://[user[:password]@]host[:port][,host[:port]...][/[database]][?option=value&...]
```

Lower-case scheme; default port 7700; host names are kept in lower case, IPv6 hosts in brackets
(`[::1]:7700`); user, password, database and values are percent-decoded as UTF-8 (`%40` for `@`; a raw
`@` in the user information is an error). Options (names case-insensitive; unknown or repeated options
are errors): `tls` (`true`|`false`, default `false`: plain text, ADR-034; without an explicit `tls`, any
`tls*` option or `authMechanism=X509` turns TLS on, and `tls=false` with either is an error), `tlsCaFile`, `authMechanism` (`SCRAM-SHA-256` |
`X509`), `appName`, `connectTimeoutMs` (default 10000), `operationTimeoutMs` (default 30000),
`readConsistency` (`linearizable` | `bounded_staleness` | `follower`), `maxStalenessMs` (required by
`bounded_staleness`), `writeConcern` (`majority` | `all` | `local_dc_majority` | `sync_cross_dc` |
`async_cross_dc`), `retryReads`, `retryWrites` (default `true`), `maxRetries` (0..10, default 1),
`connectionsPerEndpoint` (1..64, default 2). Extensions outside the shared grammar
([`../DIVERGENCES.md`](../DIVERGENCES.md)): `tlsServerName`, `tlsCertificateFile`, `tlsKeyFile`, and
`authMechanism=APIKEY` with `apiKey`. A user without a password parses, but the client refuses it until
`Credential = RustegonCredential.Scram(user, password)` is set. `rustegon+srv://` is not supported yet
(PD-069). Prefer a `RustegonCredential` object over a password in the string. Read consistency and
write concern are sent on every data-plane request whose proto has the field; per-operation options
override them (`FindOptions.ReadConsistency` / `MaxStaleness`, `InsertOptions.WriteConcern`, …, PD-095).

## Packaging (dotnet-driver.md §2, PD-117, PD-118)

```bash
dotnet pack src/Rustegon.Driver -c Release -o out     # Rustegon.Driver.<v>.nupkg + .snupkg, package validation included
dotnet publish samples/Rustegon.Driver.Sample -c Release -r win-x64   # Native AOT (warnings are errors)
```

- **Version**: semantic versioning, driver major = protocol major (`1.x` speaks protocol 1; `0.x` are previews).
  `Version` in `Directory.Build.props`; `AssemblyVersion` changes only with a breaking release (`major.0.0.0`,
  `0.minor.0.0` before 1.0), so strong-named consumers bind across compatible updates.
- **Package**: `lib/net10.0` (assembly + XML docs), the source generator under `analyzers/dotnet/cs`, readme, Apache-2.0
  license expression, repository URL and commit; runtime dependencies `Google.Protobuf`, `Grpc.Net.Client`,
  `Grpc.StatusProto`, `System.IO.Hashing`. Symbols (portable PDB with SourceLink) in the `.snupkg`.
- **Package validation**: `EnablePackageValidation` runs on every pack. Before the first release there is no baseline;
  afterwards set `PackageValidationBaselineVersion` to the latest published version.
- **Deterministic**: always; `ContinuousIntegrationBuild` when `CI`, `GITHUB_ACTIONS` or `TF_BUILD` is set. SourceLink is
  part of the SDK and derives source URLs from the `origin` remote (a clone without one gets an empty map).
- **Strong name**: every assembly is signed with `Rustegon.snk` (public key token `94910bc398a01f69`). The key is public
  on purpose: a strong name is an identity, not a proof of origin.
- **Release signing** (not automated, needs the project's code-signing certificate):
  `dotnet nuget sign out/*.nupkg out/*.snupkg --certificate-path <cert.pfx> --certificate-password <pw> --timestamper <rfc3161-url>`,
  then `dotnet nuget verify --all out/*.nupkg`.
- **Native AOT**: the driver and generated codecs are `IsAotCompatible`; the publish needs the platform toolchain
  (Windows: Visual Studio "Desktop development with C++"; Linux: clang and zlib). With Visual Studio 2026 the
  `vswhere.exe` directory (`%ProgramFiles(x86)%\Microsoft Visual Studio\Installer`) must be on `PATH` (TC-DRV-NET-026
  adds it for its child process).

## Reconnect

A channel whose connection failed reconnects by itself with gRPC's exponential backoff from 1 s, capped at 5 s
(PD-119); calls made meanwhile fail fast with `UnavailableException` (RGN-3002, retryable), and a retried call goes to
another channel than the attempt that failed. After a node restart the same client logs in again on the next call. A commit whose reply is lost after it was sent is `CommitOutcomeUnknownException` (RGN-2006), never a retryable
Unavailable: `WithTransactionAsync` resolves it with `Status` and never runs the callback twice (PD-119). Transactions
open on a node that crashed are lost: their `Commit` fails
(today RGN-1030, see `../DIVERGENCES.md` §4.2) and their writes are not applied.

## Generated sources

- `drivers/conformance/generated/ErrorCodes.g.cs` — linked into the driver project (`Errors/ErrorCodes.g.cs`) and
  compiled as is (PD-075). It joins `proto/errors.yaml` with `drivers/conformance/errors-map.yaml` and is written by
  `RGN_FIXTURES_BLESS=1 cargo nextest run -p rustegon-common --test driver_tables`; never edit it here. The exception
  class is chosen from its `ExceptionType` column (`ErrorMapper.CreateByType`).
- `src/Rustegon.Driver/Auth/SaslPrepTables.g.cs` — RFC 3454 table A.1, extracted from the `stringprep` 0.1.5 crate the
  server uses, so both sides reject the same unassigned code points.
