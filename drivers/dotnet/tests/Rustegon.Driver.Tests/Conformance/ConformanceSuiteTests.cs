// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Rustegon.Driver.Internal.Auth;
using Rustegon.Driver.TestServer;
using Xunit;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Tests.Conformance;

/// <summary>
/// TC-DRV-NET-020 (FR-DRV-003, AC-DRV-001, AC-DRV-003): the runner of the shared conformance suite
/// (README §5–§7): every test of <c>crud/ query/ cursor/ bulk/ txn/ errors/ schema/ auth/ client/</c>
/// is one case, run against the fixture's <c>rustegond</c> (PD-072) with a fresh database per file
/// and a reset of its collections per test, or without a server when it consists of runner
/// operations only. Every case is recorded in <c>conformance-results.json</c> (README §6;
/// <c>RUSTEGON_CONFORMANCE_RESULTS</c> overrides the path, default next to the test binaries).
/// </summary>
[Collection(ServerGroup.Name)]
public sealed class ConformanceSuiteTests
{
    private static readonly string[] Categories = ["crud", "query", "cursor", "bulk", "txn", "errors", "schema", "auth", "client"];

    /// <summary><c>requires</c> values this runner provides (README §5).</summary>
    private static readonly string[] Capabilities = ["admin", "api-key", "x509-client-cert", "slow", "fixture-connection-string"];

    private static readonly ResultsFile Results = new();

    private readonly ServerFixture _fixture;

    public ConformanceSuiteTests(ServerFixture fixture)
    {
        _fixture = fixture;
    }

    public static TheoryData<string> Tests()
    {
        var data = new TheoryData<string>();
        foreach (string category in Categories)
        {
            foreach (string file in Directory.GetFiles(Path.Combine(TestPaths.Conformance, category), "*.yaml").Order(StringComparer.Ordinal))
            {
                var root = (Dictionary<string, object?>)ConformanceYaml.Load(file)!;
                foreach (Dictionary<string, object?> t in ((List<object?>)root["tests"]!).Cast<Dictionary<string, object?>>())
                {
                    data.Add($"{category}/{Path.GetFileName(file)}#{t["id"]}");
                }
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Tests))]
    public async Task tc_drv_net_020_conformance_suite(string test)
    {
        int hash = test.IndexOf('#', StringComparison.Ordinal);
        string relative = test[..hash];
        string id = test[(hash + 1)..];
        string path = Path.Combine(TestPaths.Conformance, relative);
        var root = (Dictionary<string, object?>)ConformanceYaml.Load(path)!;
        Dictionary<string, object?> t = ((List<object?>)root["tests"]!).Cast<Dictionary<string, object?>>().Single(x => (string)x["id"]! == id);
        var setup = (t.GetValueOrDefault("setup") ?? root.GetValueOrDefault("setup")) as Dictionary<string, object?>;
        var operations = (List<object?>)t["operations"]!;
        bool unitLevel = setup is null && operations.Cast<Dictionary<string, object?>>().All(o => (string)o["object"]! == "runner");

        string? missing = (t.GetValueOrDefault("requires") as List<object?> ?? []).Cast<string>().FirstOrDefault(r => !Capabilities.Contains(r));
        string? skip = missing is not null ? $"requires {missing}" : (!unitLevel && _fixture.Server is null ? "no server binaries (RUSTEGON_BIN_DIR)" : null);
        if (skip is not null)
        {
            Results.Add(new ResultEntry(id, "skipped", skip, [], null));
            _fixture.Require();
            Assert.Skip(skip);
        }

        string text = await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken);
        try
        {
            (List<string> observations, string? outcome) = unitLevel
                ? await RunUnitLevelAsync(operations, text)
                : await RunWithServerAsync(_fixture.Require(), relative, t, setup, operations, text);
            Results.Add(new ResultEntry(id, "passed", null, observations, outcome));
        }
        catch (Exception e)
        {
            Results.Add(new ResultEntry(id, "failed", e.Message, [], null));
            throw;
        }
    }

    private static async Task<(List<string>, string?)> RunUnitLevelAsync(List<object?> operations, string text)
    {
        // Runner operations need no server; the run still needs a client object, which is never used.
        var settings = new RustegonClientSettings { Tls = new TlsSettings { Enabled = false } };
        settings.Endpoints.Add("unused.invalid:7700");
        await using var client = new RustegonClient(settings);
        await using var run = new ConformanceRun(client, "unused", null, s => s, text) { RunnerExtension = RunnerChecks.RunAsync };
        await run.RunAsync(operations, topLevel: true);
        return (run.Observations, null);
    }

    private async Task<(List<string>, string?)> RunWithServerAsync(
        RustegonTestServer server,
        string relative,
        Dictionary<string, object?> test,
        Dictionary<string, object?>? setup,
        List<object?> operations,
        string text)
    {
        FileContext file = await FileContextAsync(server, relative);
        Results.ServerVersion ??= (await file.Client.GetServerInfoAsync(TestContext.Current.CancellationToken)).ServerVersion;
        var requires = (test.GetValueOrDefault("requires") as List<object?> ?? []).Cast<string>().ToList();
        string apiKey = requires.Contains("api-key") ? await ApiKeyAsync(server) : string.Empty;
        string host = server.GrpcEndpoint[..server.GrpcEndpoint.LastIndexOf(':')];
        string port = server.GrpcEndpoint[(server.GrpcEndpoint.LastIndexOf(':') + 1)..];
        var substitutions = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["${database}"] = file.Database,
            ["${host}"] = host,
            ["${port}"] = port,
            ["${adminUser}"] = RustegonTestServer.AdminUser,
            ["${adminPassword}"] = server.AdminPassword,
            ["${adminUserEncoded}"] = Uri.EscapeDataString(RustegonTestServer.AdminUser),
            ["${adminPasswordEncoded}"] = Uri.EscapeDataString(server.AdminPassword),
            ["${caFile}"] = server.CaCertificatePath,
            ["${caFileEncoded}"] = Uri.EscapeDataString(server.CaCertificatePath),
            ["${apiKey}"] = apiKey,
            ["${clientCertFile}"] = server.ClientCertificatePath,
            ["${clientKeyFile}"] = server.ClientKeyPath,
        };
        string Substitute(string s)
        {
            foreach ((string k, string v) in substitutions)
            {
                s = s.Replace(k, v, StringComparison.Ordinal);
            }

            return s;
        }

        var users = new List<string>();
        try
        {
            string? firstCollection = await SetupAsync(file, setup, users, requires.Contains("x509-client-cert"), Substitute);
            await using var run = new ConformanceRun(file.Client, file.Database, firstCollection, Substitute, text)
            {
                RunnerExtension = RunnerChecks.RunAsync,
                OpenClient = args => Open(server, file.Database, args, Substitute),
            };
            await run.RunAsync(operations, topLevel: true);
            string? outcome = test.GetValueOrDefault("outcome") is Dictionary<string, object?> expected
                ? await CheckOutcomeAsync(file, run, expected, text)
                : null;
            return (run.Observations, outcome);
        }
        finally
        {
            foreach (string u in users)
            {
                await file.Client.Executor.UnaryAsync(
                    (invoker, o) => new V1.AdminService.AdminServiceClient(invoker).DropUserAsync(new V1.DropUserRequest { Name = u }, o),
                    TestContext.Current.CancellationToken);
            }
        }
    }

    /// <summary>README §5 per-test fixture: reset the collections, then collections, indexes, data, users.</summary>
    private static async Task<string?> SetupAsync(FileContext file, Dictionary<string, object?>? setup, List<string> users, bool x509, Func<string, string> substitute)
    {
        var ct = TestContext.Current.CancellationToken;
        IRustegonDatabase db = file.Client.GetDatabase(file.Database);
        foreach (string name in await db.ListCollectionNamesAsync(ct))
        {
            await db.DropCollectionAsync(name, new DropOptions { IfExists = true }, ct);
        }

        string? first = null;
        foreach (Dictionary<string, object?> c in (setup?.GetValueOrDefault("collections") as List<object?> ?? []).Cast<Dictionary<string, object?>>())
        {
            string name = (string)c["name"]!;
            first ??= name;
            var options = new CreateCollectionOptions();
            if (c.GetValueOrDefault("validator") is Dictionary<string, object?> v)
            {
                options.Validator = ConformanceRun.Validator(v);
            }

            await db.CreateCollectionAsync(name, options, ct);
        }

        foreach (Dictionary<string, object?> i in (setup?.GetValueOrDefault("indexes") as List<object?> ?? []).Cast<Dictionary<string, object?>>())
        {
            IndexDescription index = await db.GetCollection<RDocument>((string)i["collection"]!).CreateIndexAsync(
                (string)i["name"]!,
                ConformanceDsl.KeysOf((List<object?>)i["keys"]!),
                new CreateIndexOptions { Unique = i.GetValueOrDefault("unique") is true },
                ct);
            Assert.Equal(IndexState.Ready, index.State);
        }

        foreach ((string collection, object? docs) in setup?.GetValueOrDefault("data") as Dictionary<string, object?> ?? [])
        {
            List<object?> list = (List<object?>)docs!;
            if (list.Count > 0)
            {
                await db.GetCollection<RDocument>(collection).InsertManyAsync(list.Select(d => ConformanceValues.ToDocument((Dictionary<string, object?>)d!)), cancellationToken: ct);
            }
        }

        foreach (Dictionary<string, object?> u in (setup?.GetValueOrDefault("users") as List<object?> ?? []).Cast<Dictionary<string, object?>>())
        {
            var request = new V1.CreateUserRequest
            {
                Name = (string)u["name"]!,
                Password = (string)u["password"]!,
                MustChangePassword = u.GetValueOrDefault("mustChangePassword") is true,
            };
            request.Roles.AddRange(((List<object?>)u["roles"]!).Cast<string>().Select(r => Grant(substitute(r))));
            await CreateUserAsync(file, request, users);
        }

        if (x509)
        {
            // README §5: the init client certificate maps to a user with read-write on ${database}.
            var request = new V1.CreateUserRequest { Name = "x509:CN=" + RustegonTestServer.ClientCertificateUser };
            request.Roles.Add(Grant("read_write@" + file.Database));
            await CreateUserAsync(file, request, users);
        }

        return first;
    }

    private static async Task CreateUserAsync(FileContext file, V1.CreateUserRequest request, List<string> users)
    {
        await file.Client.Executor.UnaryAsync(
            (invoker, o) => new V1.AdminService.AdminServiceClient(invoker).CreateUserAsync(request, o),
            TestContext.Current.CancellationToken);
        users.Add(request.Name);
    }

    /// <summary>A role reference <c>role@db</c> / <c>role@db.coll</c> / <c>role</c> as a grant (protocol.md §8 mapping).</summary>
    private static V1.RoleGrant Grant(string reference)
    {
        int at = reference.IndexOf('@', StringComparison.Ordinal);
        if (at < 0)
        {
            return new V1.RoleGrant { Role = reference };
        }

        string scope = reference[(at + 1)..];
        return new V1.RoleGrant { Role = reference[..at], Resource = (scope.Contains('.', StringComparison.Ordinal) ? "collection:" : "database:") + scope };
    }

    private static RustegonClient Open(RustegonTestServer server, string database, Dictionary<string, object?> args, Func<string, string> substitute)
    {
        var credential = (Dictionary<string, object?>)args["credential"]!;
        RustegonClientSettings settings;
        if (credential.GetValueOrDefault("scram") is Dictionary<string, object?> scram)
        {
            settings = server.Settings(RustegonCredential.Scram(substitute((string)scram["user"]!), substitute((string)scram["password"]!)));
        }
        else if (credential.GetValueOrDefault("apiKey") is string key)
        {
            settings = server.Settings(RustegonCredential.ApiKey(substitute(key)));
        }
        else
        {
            var x509 = (Dictionary<string, object?>)credential["x509"]!;
            settings = server.Settings(RustegonCredential.X509());
            settings.Tls.ClientCertificatePath = substitute((string)x509["certificateFile"]!);
            settings.Tls.ClientKeyPath = substitute((string)x509["keyFile"]!);
        }

        settings.DefaultDatabase = database;
        settings.AllowPasswordChangeOnly = args.GetValueOrDefault("allowPasswordChangeOnly") is true;
        return new RustegonClient(settings);
    }

    /// <summary>README §5 <c>outcome</c>: every listed collection, sorted by <c>_id</c>, compared exactly.</summary>
    private static async Task<string> CheckOutcomeAsync(FileContext file, ConformanceRun run, Dictionary<string, object?> expected, string text)
    {
        var normalizer = new Normalizer(text);
        var parts = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach ((string collection, object? docs) in expected)
        {
            List<RDocument> actual = await file.Client.GetDatabase(file.Database).GetCollection<RDocument>(collection)
                .Find(Filter.Empty).Sort(Sort.Ascending("_id")).ToListAsync(TestContext.Current.CancellationToken);
            RDocValue value = ConformanceRun.Array(actual.Select(RDocValue.FromDocument));
            if (run.Matcher.Result(docs, value, new MatchMode(false, true, false)) is { } why)
            {
                throw new ConformanceFailure($"outcome of {collection}: {why}");
            }

            parts[collection] = normalizer.Json(value);
        }

        return "{" + string.Join(",", parts.Select(p => JsonSerializer.Serialize(p.Key) + ":" + p.Value)) + "}";
    }

    private async Task<FileContext> FileContextAsync(RustegonTestServer server, string relative)
    {
        string key = "conformance-file:" + relative;
        if (_fixture.Items.TryGetValue(key, out object? existing))
        {
            return (FileContext)existing;
        }

        string category = relative[..relative.IndexOf('/', StringComparison.Ordinal)];
        string stem = Path.GetFileNameWithoutExtension(relative).Replace('-', '_');
        string database = $"conf_{category}_{stem}_{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4))}";
        RustegonClientSettings settings = server.Settings(RustegonCredential.Scram(RustegonTestServer.AdminUser, server.AdminPassword));
        settings.DefaultDatabase = database;
        var client = new RustegonClient(settings);
        await client.CreateDatabaseAsync(database, cancellationToken: TestContext.Current.CancellationToken);
        var context = new FileContext(database, client);
        _fixture.Items[key] = context;
        _fixture.OnDispose(async () =>
        {
            await client.DropDatabaseAsync(database, new DropOptions { IfExists = true });
            await client.DisposeAsync();
        });
        return context;
    }

    private async Task<string> ApiKeyAsync(RustegonTestServer server)
    {
        if (_fixture.Items.TryGetValue("conformance-api-key", out object? existing))
        {
            return (string)existing;
        }

        await using var admin = new RustegonClient(server.Settings(RustegonCredential.Scram(RustegonTestServer.AdminUser, server.AdminPassword)));
        V1.WhoAmIResponse owner = await admin.WhoAmIAsync(TestContext.Current.CancellationToken);
        var request = new V1.CreateApiKeyRequest { Description = "dotnet conformance runner" };
        request.Roles.AddRange(owner.Roles);
        V1.CreateApiKeyResponse created = await admin.Executor.UnaryAsync(
            (invoker, o) => new V1.AdminService.AdminServiceClient(invoker).CreateApiKeyAsync(request, o),
            TestContext.Current.CancellationToken);
        _fixture.Items["conformance-api-key"] = created.Secret;
        return created.Secret;
    }

    private sealed record FileContext(string Database, RustegonClient Client);

    private sealed record ResultEntry(string Id, string Status, string? Reason, List<string> Observations, string? Outcome);

    /// <summary><c>conformance-results.json</c> (README §6), rewritten after every case.</summary>
    private sealed class ResultsFile
    {
        private readonly SortedDictionary<string, ResultEntry> _entries = new(StringComparer.Ordinal);

        internal string? ServerVersion { get; set; }

        internal static string FilePath =>
            Environment.GetEnvironmentVariable("RUSTEGON_CONFORMANCE_RESULTS") is { Length: > 0 } p ? p : Path.Combine(AppContext.BaseDirectory, "conformance-results.json");

        internal void Add(ResultEntry entry)
        {
            lock (_entries)
            {
                _entries[entry.Id] = entry;
                var buffer = new ArrayBufferWriter<byte>();
                using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
                {
                    w.WriteStartObject();
                    w.WriteString("driver", "dotnet");
                    w.WriteString("driverVersion", SessionAuthenticator.DriverVersion);
                    w.WriteString("serverVersion", ServerVersion ?? string.Empty);
                    w.WriteStartArray("results");
                    foreach (ResultEntry e in _entries.Values)
                    {
                        w.WriteStartObject();
                        w.WriteString("id", e.Id);
                        w.WriteString("status", e.Status);
                        if (e.Reason is not null)
                        {
                            w.WriteString("reason", e.Reason);
                        }

                        w.WriteStartArray("observations");
                        foreach (string o in e.Observations)
                        {
                            w.WriteRawValue(o, skipInputValidation: false);
                        }

                        w.WriteEndArray();
                        if (e.Outcome is not null)
                        {
                            w.WritePropertyName("outcome");
                            w.WriteRawValue(e.Outcome, skipInputValidation: false);
                        }

                        w.WriteEndObject();
                    }

                    w.WriteEndArray();
                    w.WriteEndObject();
                }

                File.WriteAllText(FilePath, Encoding.UTF8.GetString(buffer.WrittenSpan));
            }
        }
    }
}
