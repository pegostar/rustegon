// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System.Threading.Tasks;
using Xunit;

namespace Rustegon.Driver.Tests.Conformance;

/// <summary>
/// TC-DRV-NET-011 (FR-DRV-001, FR-DRV-003, PD-070): filter, update, sort and projection builders and the
/// statements of collection operations produce exactly <c>drivers/conformance/ast/*.json</c> (one
/// case per vector).
/// </summary>
public sealed class AstVectorTests
{
    public static TheoryData<string> Vectors()
    {
        var data = new TheoryData<string>();
        foreach (string file in new[] { "ast/filters.json", "ast/updates.json", "ast/statements.json" })
        {
            foreach (string c in AstVectors.Cases(file))
            {
                data.Add(file + "#" + c);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void tc_drv_net_011_conformance_ast_vector(string vector)
    {
        int hash = vector.IndexOf('#', System.StringComparison.Ordinal);
        AstVectors.Check(vector[..hash], vector[(hash + 1)..]);
    }
}

/// <summary>TC-DRV-NET-018 (FR-SEC-001, PD-074): SASLprep and SCRAM-SHA-256 against <c>drivers/conformance/scram/vectors.yaml</c> (one case per vector).</summary>
public sealed class ScramVectorTests
{
    private const string File = "scram/vectors.yaml";

    public static TheoryData<string> Vectors() => [.. ScramVectors.Cases(File)];

    [Theory]
    [MemberData(nameof(Vectors))]
    public void tc_drv_net_018_conformance_scram_vector(string vector) => ScramVectors.Check(File, vector);
}

/// <summary>
/// TC-DRV-NET-016 (FR-DRV-001, dotnet-driver.md §8, transactions.md §5, PD-073): the retry policy
/// R1–R6 on the in-process fake gRPC server, one case per scenario of <c>drivers/conformance/retry.yaml</c>.
/// </summary>
public sealed class RetryScenarioTests
{
    private const string File = "retry.yaml";

    public static TheoryData<string> Scenarios() => [.. RetryScenarios.Names(File)];

    [Theory]
    [MemberData(nameof(Scenarios))]
    public Task tc_drv_net_016_retry_scenario(string scenario) => RetryScenarios.RunAsync(File, scenario);
}
