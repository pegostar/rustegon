// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Rustegon.Driver.TestServer;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// One <c>rustegond</c> for all integration tests (PD-072). Without binaries the tests skip with
/// the reason; under <c>CI=true</c> a missing binary is a failure instead, so CI cannot pass
/// without running them.
/// </summary>
public sealed class ServerFixture : IAsyncLifetime
{
    private readonly List<Func<ValueTask>> _cleanups = [];
    private string _skipReason = string.Empty;

    /// <summary>State shared by the tests of a run (per-file conformance databases, API key, …).</summary>
    public ConcurrentDictionary<string, object> Items { get; } = new(StringComparer.Ordinal);

    /// <summary>Runs <paramref name="cleanup"/> before the server stops (latest first).</summary>
    public void OnDispose(Func<ValueTask> cleanup)
    {
        lock (_cleanups)
        {
            _cleanups.Add(cleanup);
        }
    }

    /// <summary>The running server, or null when skipped.</summary>
    public RustegonTestServer? Server { get; private set; }

    /// <summary>Returns the server or skips the calling test.</summary>
    public RustegonTestServer Require()
    {
        if (Server is null)
        {
            Assert.Skip(_skipReason);
        }

        return Server;
    }

    public async ValueTask InitializeAsync()
    {
        string? bin = RustegonTestServer.FindBinaries(out string reason);
        if (bin is null)
        {
            if (string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("CI=true but no server binaries: " + reason);
            }

            _skipReason = "integration test skipped: " + reason;
            return;
        }

        Server = await RustegonTestServer.StartAsync(bin);
    }

    public async ValueTask DisposeAsync()
    {
        Func<ValueTask>[] cleanups;
        lock (_cleanups)
        {
            cleanups = [.. _cleanups];
        }

        foreach (Func<ValueTask> c in cleanups.Reverse())
        {
            try
            {
                await c();
            }
            catch (RustegonException)
            {
                // Cleanup only: the server and its directory are discarded next anyway.
            }
        }

        if (Server is not null)
        {
            await Server.DisposeAsync();
        }
    }
}

/// <summary>The collection sharing <see cref="ServerFixture"/> (started only when one of its tests runs).</summary>
[CollectionDefinition(Name)]
public sealed class ServerGroup : ICollectionFixture<ServerFixture>
{
    public const string Name = "rustegond";
}
