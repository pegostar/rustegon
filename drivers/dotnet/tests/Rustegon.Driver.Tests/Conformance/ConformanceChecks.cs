// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Google.Protobuf;
using Rustegon.Driver.Internal.Auth;
using Rustegon.Driver.Internal.Builders;
using Rustegon.Driver.Internal.DataPlane;
using Rustegon.Driver.Internal.Transport;
using Xunit;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Tests.Conformance;

/// <summary>
/// The runner operations of README §7 that need no server: they run the vector files through the
/// same checks as the dedicated theories (one case per vector there; here all of a file at once,
/// for the conformance test that names the operation).
/// </summary>
internal static class RunnerChecks
{
    internal static async Task<bool> RunAsync(string name, Dictionary<string, object?> args)
    {
        string file = args.GetValueOrDefault("file") as string ?? string.Empty;
        switch (name)
        {
            case "checkErrorMapping":
                var errors = new ErrorMappingTests();
                foreach (int code in ErrorMappingTests.CatalogCodes().Select(r => r.Data))
                {
                    errors.tc_drv_net_006_conformance_error_mapping_code(code);
                }

                errors.tc_drv_net_006_conformance_unknown_code_maps_to_the_base_class();
                foreach (string status in ErrorMappingTests.TransportStatuses().Select(r => r.Data))
                {
                    errors.tc_drv_net_006_conformance_transport_fallback(status);
                }

                return true;
            case "checkValueVectors":
            case "checkDocumentVectors":
            case "checkInvalidVectors":
                var codec = new CodecConformanceTests();
                string prefix = Path.GetFileName(file) + "#";
                string[] vectors = [.. CodecConformanceTests.Vectors().Select(r => r.Data).Where(v => v.StartsWith(prefix, StringComparison.Ordinal))];
                Assert.NotEmpty(vectors);
                foreach (string v in vectors)
                {
                    codec.tc_drv_net_001_conformance_codec_vectors(v);
                }

                return true;
            case "checkAstVectors":
                foreach (string c in AstVectors.Cases(file))
                {
                    AstVectors.Check(file, c);
                }

                return true;
            case "checkConnectionStrings":
                var cs = new ConnectionStringTests();
                foreach (string c in ConnectionStringTests.ConformanceCases().Select(r => r.Data))
                {
                    cs.tc_drv_net_008_conformance_connstring_cases(c);
                }

                return true;
            case "runRetryScenarios":
                foreach (string s in RetryScenarios.Names(file))
                {
                    await RetryScenarios.RunAsync(file, s);
                }

                return true;
            case "checkScramVectors":
                foreach (string c in ScramVectors.Cases(file))
                {
                    ScramVectors.Check(file, c);
                }

                return true;
            default:
                return false;
        }
    }
}

/// <summary>
/// <c>checkAstVectors</c> (README §4, PD-070): builder calls translated from the DSL produce exactly
/// the protobuf AST and the encoded parameters of <c>drivers/conformance/ast/*.json</c>. The
/// golden protobuf JSON is parsed into messages and compared structurally (field order of the
/// JSON is irrelevant), parameters byte for byte.
/// </summary>
internal static class AstVectors
{
    internal static IEnumerable<string> Cases(string file) => Root(file).GetProperty("cases").EnumerateArray().Select(c => c.GetProperty("name").GetString()!);

    internal static void Check(string file, string name)
    {
        JsonElement c = Root(file).GetProperty("cases").EnumerateArray().Single(e => e.GetProperty("name").GetString() == name);
        string collection = Root(file).GetProperty("collection").GetString()!;
        ConformanceDsl dsl = ConformanceDsl.Plain;
        var sink = new ParamSink();
        switch (Path.GetFileName(file))
        {
            case "filters.json":
                Filter filter = dsl.Filter(Model(c.GetProperty("filter")));
                V1.AstExpr? where = filter.ToAst(sink);
                if (c.TryGetProperty("where", out JsonElement w))
                {
                    Assert.Equal(JsonParser.Default.Parse<V1.AstExpr>(w.GetRawText()), where);
                }
                else
                {
                    Assert.Null(where);
                }

                CheckParams(c, sink);
                var sink2 = new ParamSink();
                Assert.Equal(JsonParser.Default.Parse<V1.AstStatement>(c.GetProperty("statement").GetRawText()), Statements.Find(collection, filter, null, null, null, null, sink2));
                CheckParams(c, sink2);
                break;
            case "updates.json":
                var ops = (List<object?>)Model(c.GetProperty("update"))!;
                IEnumerable<V1.AstUpdateOp> actual = ops is [Dictionary<string, object?> only] && only.TryGetValue("replace", out object? replacement)
                    ? Update.Replace(dsl.Document(replacement)).ToAst(sink)
                    : dsl.UpdateOf(ops).ToAst(sink);
                Assert.Equal(
                    c.GetProperty("operations").EnumerateArray().Select(o => JsonParser.Default.Parse<V1.AstUpdateOp>(o.GetRawText())),
                    actual);
                CheckParams(c, sink);
                break;
            case "statements.json":
                var args = (Dictionary<string, object?>)Model(c.GetProperty("args"))!;
                Filter f = dsl.Filter(args["filter"]);
                V1.AstStatement statement = c.GetProperty("op").GetString() switch
                {
                    "find" => Statements.Find(
                        collection,
                        f,
                        args.GetValueOrDefault("sort") is List<object?> s ? ConformanceDsl.SortOf(s) : null,
                        args.GetValueOrDefault("projection") is Dictionary<string, object?> p ? ConformanceDsl.ProjectionOf(p) : null,
                        args.GetValueOrDefault("limit") as long?,
                        args.GetValueOrDefault("skip") as long?,
                        sink),
                    "updateOne" => Statements.Update(collection, f, dsl.UpdateOf((List<object?>)args["update"]!), true, sink),
                    "updateMany" => Statements.Update(collection, f, dsl.UpdateOf((List<object?>)args["update"]!), false, sink),
                    "replaceOne" => Statements.Update(collection, f, Update.Replace(dsl.Document(args["replacement"])), true, sink),
                    "deleteOne" => Statements.Delete(collection, f, true, sink),
                    "deleteMany" => Statements.Delete(collection, f, false, sink),
                    var op => throw new InvalidDataException($"unknown op '{op}'"),
                };
                Assert.Equal(JsonParser.Default.Parse<V1.AstStatement>(c.GetProperty("statement").GetRawText()), statement);
                CheckParams(c, sink);
                break;
            default:
                throw new InvalidDataException($"no AST check for {file}");
        }
    }

    private static void CheckParams(JsonElement c, ParamSink sink)
    {
        var expected = c.GetProperty("params").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetProperty("hex").GetString()!);
        Assert.Equal(expected.Keys.Order(StringComparer.Ordinal), sink.Params.Keys.Order(StringComparer.Ordinal));
        foreach ((string k, string hex) in expected)
        {
            Assert.Equal(hex, Convert.ToHexStringLower(sink.Params[k].RdocValue.ToByteArray()));
        }
    }

    private static JsonElement Root(string file)
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(TestPaths.Conformance, file)));
        return doc.RootElement.Clone();
    }

    /// <summary>A JSON value in the model of <see cref="ConformanceYaml"/> (integers long, fractions double).</summary>
    internal static object? Model(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Null => null,
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.TryGetInt64(out long l) && !e.GetRawText().Contains('.', StringComparison.Ordinal) && !e.GetRawText().Contains('e', StringComparison.OrdinalIgnoreCase) ? (object)l : e.GetDouble(),
        JsonValueKind.Array => e.EnumerateArray().Select(Model).ToList(),
        JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => Model(p.Value), StringComparer.Ordinal),
        _ => throw new InvalidDataException($"unexpected JSON {e.ValueKind}"),
    };
}

/// <summary>
/// <c>checkScramVectors</c> (README §7, PD-074): every SASLprep input gives its output or is refused;
/// every exchange, with the client nonce forced, sends exactly <c>clientFirst</c> and
/// <c>clientFinal</c>, accepts <c>serverFinal</c> and rejects it with one character changed.
/// </summary>
internal static class ScramVectors
{
    internal static IEnumerable<string> Cases(string file)
    {
        var root = (Dictionary<string, object?>)ConformanceYaml.Load(Path.Combine(TestPaths.Conformance, file))!;
        return ((List<object?>)root["saslprep"]!).Select(e => "saslprep/" + Name(e))
            .Concat(((List<object?>)root["exchanges"]!).Select(e => "exchange/" + Name(e)));
    }

    internal static void Check(string file, string id)
    {
        var root = (Dictionary<string, object?>)ConformanceYaml.Load(Path.Combine(TestPaths.Conformance, file))!;
        string section = id[..id.IndexOf('/', StringComparison.Ordinal)];
        string name = id[(section.Length + 1)..];
        var v = ((List<object?>)root[section == "saslprep" ? "saslprep" : "exchanges"]!).Cast<Dictionary<string, object?>>().Single(e => Name(e) == name);
        if (section == "saslprep")
        {
            bool ok = SaslPrep.TryPrepare((string)v["input"]!, out string prepared);
            if (v.GetValueOrDefault("error") is true)
            {
                Assert.False(ok, $"{name}: expected a refusal, got '{prepared}'");
            }
            else
            {
                Assert.True(ok, $"{name}: refused");
                Assert.Equal((string)v["output"]!, prepared);
            }

            return;
        }

        string S(string k) => (string)v[k]!;
        var client = new ScramSha256Client(S("user"), S("password"), S("clientNonce"));
        Assert.Equal(S("clientFirst"), client.ClientFirst);
        Assert.Equal(S("clientFinal"), client.ProcessServerFirst(S("serverFirst")));
        client.VerifyServerFinal(S("serverFinal"));

        string serverFinal = S("serverFinal");
        char changed = serverFinal[2] == 'A' ? 'B' : 'A';
        string forged = serverFinal[..2] + changed + serverFinal[3..];
        var again = new ScramSha256Client(S("user"), S("password"), S("clientNonce"));
        _ = again.ProcessServerFirst(S("serverFirst"));
        Assert.ThrowsAny<Exception>(() => again.VerifyServerFinal(forged));
    }

    private static string Name(object? e) => (string)((Dictionary<string, object?>)e!)["name"]!;
}

/// <summary>
/// <c>runRetryScenarios</c> (README §8, retry.yaml, PD-073): each scenario runs its operation
/// through the driver against <see cref="FakeGrpcServer"/> and checks the outcome, the number of
/// calls per RPC, request-id reuse, the deadline header and the backoff gaps.
/// </summary>
internal static class RetryScenarios
{
    /// <summary>Tolerance of the backoff check (retry.yaml header).</summary>
    private static readonly TimeSpan Tolerance = TimeSpan.FromMilliseconds(250);

    internal static IEnumerable<string> Names(string file) => Scenarios(file).Select(s => (string)s["name"]!);

    internal static async Task RunAsync(string file, string name)
    {
        var root = (Dictionary<string, object?>)ConformanceYaml.Load(Path.Combine(TestPaths.Conformance, file))!;
        Dictionary<string, object?> scenario = Scenarios(file).Single(s => (string)s["name"]! == name);
        var defaults = (Dictionary<string, object?>)root["defaults"]!;
        var settings = new Dictionary<string, object?>((Dictionary<string, object?>)defaults["settings"]!);
        foreach ((string k, object? v) in scenario.GetValueOrDefault("settings") as Dictionary<string, object?> ?? [])
        {
            settings[k] = v;
        }

        var backoff = (Dictionary<string, object?>)defaults["backoff"]!;
        var fake = new FakeGrpcServer(scenario.GetValueOrDefault("server") as Dictionary<string, object?>);
        var s = new RustegonClientSettings
        {
            Tls = new TlsSettings { Enabled = false },
            Credential = scenario.GetValueOrDefault("credential") as string == "scram"
                ? RustegonCredential.Scram(FakeGrpcServer.ScramUser, FakeGrpcServer.ScramPassword)
                : RustegonCredential.ApiKey("rgn_fake_key"),
            RetryReads = (bool)settings["retryReads"]!,
            RetryWrites = (bool)settings["retryWrites"]!,
            MaxRetries = (int)(long)settings["maxRetries"]!,
            DefaultOperationTimeout = TimeSpan.FromMilliseconds((long)settings["operationTimeoutMs"]!),
            DefaultDatabase = "fake",
            ConnectionsPerEndpoint = 1,
        };
        s.Endpoints.Add("fake.invalid:7700");

        var expect = (Dictionary<string, object?>)scenario["expect"]!;
        var op = new Dictionary<string, object?>((Dictionary<string, object?>)scenario["operation"]!)
        {
            ["expect"] = expect["outcome"],
            ["match"] = "subset",
        };
        await using (var client = new RustegonClient(s, fake))
        {
            await using var run = new ConformanceRun(client, "fake", "c", x => x, string.Empty);
            try
            {
                await run.RunAsync([op], topLevel: true);
            }
            catch (ConformanceFailure e)
            {
                Assert.Fail($"{name}: {e.Message}");
            }
        }

        List<FakeCall> calls = fake.Calls;
        foreach ((string rpc, object? n) in expect.GetValueOrDefault("calls") as Dictionary<string, object?> ?? [])
        {
            Assert.True(calls.Count(c => c.Rpc == rpc) == (long)n!, $"{name}: {rpc} called {calls.Count(c => c.Rpc == rpc)} times, expected {n}; calls: {string.Join(", ", calls.Select(c => c.Rpc))}");
        }

        foreach (string rpc in (expect.GetValueOrDefault("sameRequestId") as List<object?> ?? []).Cast<string>())
        {
            string?[] ids = [.. calls.Where(c => c.Rpc == rpc).Select(c => c.RequestId).Distinct()];
            Assert.True(ids is [{ Length: > 0 }], $"{name}: {rpc} request ids {string.Join(",", ids)}");
        }

        if (expect.GetValueOrDefault("grpcTimeoutSent") is true)
        {
            Assert.All(calls.Where(c => c.Rpc != "AuthService.Logout"), c => Assert.False(string.IsNullOrEmpty(c.GrpcTimeout), $"{name}: {c.Rpc} without grpc-timeout"));
        }

        if (expect.GetValueOrDefault("delays") is List<object?> delays)
        {
            // Failed replies that led to a retry, in order (a failed best-effort rollback is not one).
            FakeCall[] failures = [.. calls.Where(c => c.Failed && c.Replied is not null && c.Rpc != "TransactionService.Rollback").OrderBy(c => c.Arrival)];
            foreach (Dictionary<string, object?> d in delays.Cast<Dictionary<string, object?>>())
            {
                int n = (int)(long)d["retry"]!;
                Assert.True(failures.Length >= n, $"{name}: retry {n} expected but only {failures.Length} failures");
                FakeCall failed = failures[n - 1];
                FakeCall next = calls.Where(c => c.Arrival > failed.Replied && c.Rpc is not "TransactionService.Rollback" and not "TransactionService.Heartbeat")
                    .OrderBy(c => c.Arrival).First();
                TimeSpan gap = next.Arrival - failed.Replied!.Value;
                if (d.GetValueOrDefault("minMs") is long min)
                {
                    Assert.True(gap >= TimeSpan.FromMilliseconds(min), $"{name}: retry {n} after {gap.TotalMilliseconds} ms, expected at least {min} ms");
                }
                else
                {
                    double ceiling = Math.Min((long)backoff["capMs"]!, (long)backoff["baseMs"]! * Math.Pow((long)backoff["factor"]!, n - 1));
                    Assert.True(gap <= TimeSpan.FromMilliseconds(ceiling) + Tolerance, $"{name}: retry {n} after {gap.TotalMilliseconds} ms, expected at most {ceiling} ms + {Tolerance.TotalMilliseconds} ms");
                }
            }
        }
    }

    private static IEnumerable<Dictionary<string, object?>> Scenarios(string file)
    {
        var root = (Dictionary<string, object?>)ConformanceYaml.Load(Path.Combine(TestPaths.Conformance, file))!;
        return ((List<object?>)root["scenarios"]!).Cast<Dictionary<string, object?>>();
    }
}
