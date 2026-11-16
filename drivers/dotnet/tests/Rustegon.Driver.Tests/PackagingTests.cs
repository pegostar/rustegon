// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Rustegon.Driver.TestServer;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// Packaging (dotnet-driver.md §2, §11, AC-DRV-001): the Native AOT publish of the sample run
/// against <c>rustegond</c> (TC-DRV-NET-026) and the NuGet package as produced by <c>dotnet pack</c>
/// with the SDK's package validation (TC-DRV-NET-027). Both run the .NET SDK as a child process
/// in Release; they share this class so the two builds of the driver never overlap.
/// </summary>
[Collection(ServerGroup.Name)]
public sealed class PackagingTests
{
    // Public key token of Rustegon.snk (PD-117).
    private const string PublicKeyToken = "94910bc398a01f69";

    // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#source-link-c-and-vb-compilers
    private static readonly Guid SourceLinkKind = new("CC110556-A091-4D38-9FEC-25AB9A351A6A");

    private static readonly TimeSpan SdkTimeout = TimeSpan.FromMinutes(10);

    private readonly ServerFixture _fixture;

    public PackagingTests(ServerFixture fixture)
    {
        _fixture = fixture;
    }

    private static string DriverRoot =>
        Path.Combine(RustegonTestServer.RepositoryRoot() ?? throw new InvalidOperationException("repository root not found"), "drivers", "dotnet");

    [Fact]
    public async Task tc_drv_net_026_native_aot_sample_runs_against_rustegond()
    {
        var ct = TestContext.Current.CancellationToken;
        RustegonTestServer server = _fixture.Require();
        string output = Directory.CreateTempSubdirectory("rustegon-aot-").FullName;
        try
        {
            // PublishAot + warnings as errors: any trimming/AOT warning (IL2xxx/IL3xxx) of the
            // driver, its dependencies or the generated codecs fails here.
            (int exit, string log) = await RunAsync(
                "dotnet",
                ["publish", Path.Combine(DriverRoot, "samples", "Rustegon.Driver.Sample"), "-c", "Release", "-r", RuntimeInformation.RuntimeIdentifier, "-warnaserror", "-o", output],
                SdkEnvironment(),
                ct);
            Assert.True(exit == 0, "dotnet publish (Native AOT) failed:\n" + log);

            // Native code: one executable, no managed driver assembly next to it.
            string exe = Path.Combine(output, OperatingSystem.IsWindows() ? "Rustegon.Driver.Sample.exe" : "Rustegon.Driver.Sample");
            Assert.True(File.Exists(exe), "no native executable in " + output);
            Assert.False(File.Exists(Path.Combine(output, "Rustegon.Driver.dll")), "the publish is not native: Rustegon.Driver.dll was copied");

            (exit, log) = await RunAsync(
                exe,
                [],
                new Dictionary<string, string?>
                {
                    ["RUSTEGON_ENDPOINT"] = server.GrpcEndpoint,
                    ["RUSTEGON_CA"] = server.CaCertificatePath,
                    ["RUSTEGON_USER"] = RustegonTestServer.AdminUser,
                    ["RUSTEGON_PASSWORD"] = server.AdminPassword,
                },
                ct);
            Assert.True(exit == 0, "the AOT sample failed:\n" + log);
            Assert.Contains("rustegon sample: ok", log, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(output, recursive: true);
        }
    }

    [Fact]
    public async Task tc_drv_net_027_package_validation_and_contents()
    {
        var ct = TestContext.Current.CancellationToken;
        string output = Directory.CreateTempSubdirectory("rustegon-pack-").FullName;
        try
        {
            // EnablePackageValidation runs inside pack: a validation error fails the command.
            (int exit, string log) = await RunAsync(
                "dotnet",
                ["pack", Path.Combine(DriverRoot, "src", "Rustegon.Driver"), "-c", "Release", "-warnaserror", "-o", output],
                SdkEnvironment(),
                ct);
            Assert.True(exit == 0, "dotnet pack failed:\n" + log);

            string nupkg = Assert.Single(Directory.GetFiles(output, "Rustegon.Driver.*.nupkg"));
            string snupkg = Assert.Single(Directory.GetFiles(output, "Rustegon.Driver.*.snupkg"));
            string unpacked = Path.Combine(output, "nupkg");
            await ZipFile.ExtractToDirectoryAsync(nupkg, unpacked, ct);

            // Payload: the driver with its XML docs, the generator as a C# analyzer, the readme.
            string[] payload = [.. Directory.GetFiles(unpacked, "*", SearchOption.AllDirectories)
                .Select(f => Path.GetRelativePath(unpacked, f).Replace('\\', '/'))
                .Where(f => f.StartsWith("lib/", StringComparison.Ordinal) || f.StartsWith("analyzers/", StringComparison.Ordinal) || f == "README.md")
                .Order(StringComparer.Ordinal)];
            Assert.Equal(["README.md", "analyzers/dotnet/cs/Rustegon.Driver.Generators.dll", "lib/net10.0/Rustegon.Driver.dll", "lib/net10.0/Rustegon.Driver.xml"], payload);
            Assert.Contains("<member name=\"T:Rustegon.Driver.RustegonClient\">", await File.ReadAllTextAsync(Path.Combine(unpacked, "lib", "net10.0", "Rustegon.Driver.xml"), ct), StringComparison.Ordinal);

            // Metadata: license expression, readme, repository with the commit (SourceLink), and
            // exactly the runtime dependencies of dotnet-driver.md §2 that exist so far.
            XDocument nuspec = XDocument.Load(Path.Combine(unpacked, "Rustegon.Driver.nuspec"));
            XNamespace ns = nuspec.Root!.Name.Namespace;
            XElement meta = nuspec.Root.Element(ns + "metadata")!;
            Assert.Equal("Apache-2.0", meta.Element(ns + "license")?.Value);
            Assert.Equal("expression", meta.Element(ns + "license")?.Attribute("type")?.Value);
            Assert.Equal("README.md", meta.Element(ns + "readme")?.Value);
            XElement repo = meta.Element(ns + "repository")!;
            Assert.Equal("https://github.com/pegostar/rustegon", repo.Attribute("url")?.Value);
            Assert.Matches("^[0-9a-f]{40}$", repo.Attribute("commit")?.Value ?? string.Empty);
            XElement group = Assert.Single(meta.Element(ns + "dependencies")!.Elements(ns + "group"));
            Assert.Equal("net10.0", group.Attribute("targetFramework")?.Value);
            Assert.Equal(
                ["Google.Protobuf", "Grpc.Net.Client", "Grpc.StatusProto", "System.IO.Hashing"],
                group.Elements(ns + "dependency").Select(d => d.Attribute("id")!.Value).Order(StringComparer.Ordinal));

            // The assembly: strong-named with Rustegon.snk, versioned per PD-118, deterministic.
            string dll = Path.Combine(unpacked, "lib", "net10.0", "Rustegon.Driver.dll");
            AssemblyName name = AssemblyName.GetAssemblyName(dll);
            Assert.Equal(PublicKeyToken, Convert.ToHexStringLower(name.GetPublicKeyToken() ?? []));
            Assert.Equal(0, name.Version!.Build);
            Assert.Equal(0, name.Version.Revision);
            using (var pe = new PEReader(File.OpenRead(dll)))
            {
                Assert.Contains(pe.ReadDebugDirectory(), e => e.Type == DebugDirectoryEntryType.Reproducible);
                Assert.True((pe.PEHeaders.CorHeader!.Flags & CorFlags.StrongNameSigned) != 0, "the assembly is not strong-name signed");
            }

            // Symbols: a portable PDB in the .snupkg, with a SourceLink map when the clone has an
            // origin remote (SourceLink derives the source URLs from it; a clone without one,
            // e.g. a local worktree, builds an empty map).
            using ZipArchive symbols = await ZipFile.OpenReadAsync(snupkg, ct);
            ZipArchiveEntry pdbEntry = Assert.Single(symbols.Entries, e => e.FullName == "lib/net10.0/Rustegon.Driver.pdb");
            using var pdb = new MemoryStream();
            using (Stream s = await pdbEntry.OpenAsync(ct))
            {
                await s.CopyToAsync(pdb, ct);
            }

            pdb.Position = 0;
            using MetadataReaderProvider provider = MetadataReaderProvider.FromPortablePdbStream(pdb);
            MetadataReader reader = provider.GetMetadataReader();
            Assert.NotEmpty(reader.Documents);
            if ((await RunAsync("git", ["remote", "get-url", "origin"], new Dictionary<string, string?>(), ct)).ExitCode == 0)
            {
                Assert.Contains(reader.CustomDebugInformation, h => reader.GetGuid(reader.GetCustomDebugInformation(h).Kind) == SourceLinkKind);
            }
        }
        finally
        {
            Directory.Delete(output, recursive: true);
        }
    }

    private static Dictionary<string, string?> SdkEnvironment()
    {
        var env = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (OperatingSystem.IsWindows())
        {
            // The ILCompiler package locates the MSVC linker through vcvarsall.bat, which (Visual
            // Studio 2026) runs vswhere.exe from PATH; the installer directory is not on PATH by
            // default.
            string vsInstaller = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft Visual Studio", "Installer");
            env["PATH"] = vsInstaller + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
        }

        return env;
    }

    private static async Task<(int ExitCode, string Output)> RunAsync(string exe, string[] args, IDictionary<string, string?> environment, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = DriverRoot,
        };
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        foreach ((string key, string? value) in environment)
        {
            psi.Environment[key] = value;
        }

        using var process = Process.Start(psi) ?? throw new InvalidOperationException(exe + " did not start");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(SdkTimeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        var log = new StringBuilder();
        log.Append(await stdout).Append(await stderr);
        return (process.ExitCode, log.ToString());
    }
}
