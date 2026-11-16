// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System.IO;
using Rustegon.Driver.TestServer;

namespace Rustegon.Driver.Tests;

/// <summary>Shared fixture locations of the repository.</summary>
internal static class TestPaths
{
    internal static string Repo { get; } =
        RustegonTestServer.RepositoryRoot() ?? throw new DirectoryNotFoundException("repository root (Cargo.toml + proto/) not found above the test binaries");

    /// <summary>Rust RDoc v1 fixtures (data-model.md §4, frozen at M2 exit).</summary>
    internal static string RdocFixtures => Path.Combine(Repo, "crates", "rustegon-doc", "tests", "fixtures", "formats", "rdoc", "1");

    /// <summary>The shared conformance suite of lane DK (absent until it is merged).</summary>
    internal static string Conformance => Path.Combine(Repo, "drivers", "conformance");

    internal static string ErrorsYaml => Path.Combine(Repo, "proto", "errors.yaml");
}
