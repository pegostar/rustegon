// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Rustegon.Driver.TestServer;

/// <summary>
/// A single-node <c>rustegond</c> for integration tests (PD-072): <c>rustegon init</c> into a
/// fresh temporary directory (CA, node certificate, configuration, the first administrator's
/// password file), then <c>rustegond --stop-on-stdin-eof</c>, which prints
/// <c>rustegond ready grpc=… http=…</c> on stdout and stops gracefully when stdin closes.
/// Binaries come from <c>RUSTEGON_BIN_DIR</c> (default <c>&lt;repo&gt;/target/debug</c>).
/// </summary>
public sealed class RustegonTestServer : IAsyncDisposable
{
    /// <summary>The first administrator created by the first start (PD-054).</summary>
    public const string AdminUser = "admin";

    /// <summary>
    /// CN of the client certificate issued by <c>rustegon init --client-user</c>; it logs in as the
    /// user <c>x509:CN=&lt;name&gt;</c>, which a test must create (conformance README §5,
    /// <c>requires: x509-client-cert</c>).
    /// </summary>
    public const string ClientCertificateUser = "conf_x509";

    private const string ReadyPrefix = "rustegond ready ";
    private static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(30);

    private readonly string _binDir;
    private readonly string _root;
    private Process _process;
    private StringBuilder _stderr;

    private RustegonTestServer(string binDir, Process process, StringBuilder stderr, string root, string grpc, string http, string password)
    {
        _binDir = binDir;
        _process = process;
        _stderr = stderr;
        _root = root;
        GrpcEndpoint = grpc;
        HttpEndpoint = http;
        AdminPassword = password;
    }

    /// <summary>gRPC endpoint <c>127.0.0.1:port</c>.</summary>
    public string GrpcEndpoint { get; }

    /// <summary>REST endpoint <c>127.0.0.1:port</c>.</summary>
    public string HttpEndpoint { get; }

    /// <summary>The generated password of <see cref="AdminUser"/>.</summary>
    public string AdminPassword { get; }

    /// <summary>The CA certificate of the node (PEM).</summary>
    public string CaCertificatePath => Path.Combine(_root, "data", "certs", "ca.crt");

    /// <summary>The client certificate (PEM) of <see cref="ClientCertificateUser"/>.</summary>
    public string ClientCertificatePath => Path.Combine(_root, "data", "certs", "client-" + ClientCertificateUser, "client.crt");

    /// <summary>The private key (PEM) of <see cref="ClientCertificatePath"/>.</summary>
    public string ClientKeyPath => Path.Combine(_root, "data", "certs", "client-" + ClientCertificateUser, "client.key");

    /// <summary>Everything the current server process wrote to stderr so far (diagnostics).</summary>
    public string StandardError
    {
        get
        {
            StringBuilder stderr = _stderr;
            lock (stderr)
            {
                return stderr.ToString();
            }
        }
    }

    private string DataDir => Path.Combine(_root, "data");

    private string PasswordFile => Path.Combine(_root, "admin.pw");

    /// <summary>Settings for this server with TLS on its CA and the given credential.</summary>
    /// <param name="credential">The credential, or null for anonymous calls.</param>
    /// <returns>New settings.</returns>
    public RustegonClientSettings Settings(RustegonCredential? credential)
    {
        var s = new RustegonClientSettings
        {
            Credential = credential,
            Tls = new TlsSettings { CaCertificatePath = CaCertificatePath },
            ApplicationName = "rustegon-dotnet-tests",
        };
        s.Endpoints.Add(GrpcEndpoint);
        return s;
    }

    /// <summary>The binary directory, or null with the reason when it has no binaries.</summary>
    /// <param name="reason">Why no server can be started.</param>
    /// <returns>The directory.</returns>
    public static string? FindBinaries(out string reason)
    {
        string? dir = Environment.GetEnvironmentVariable("RUSTEGON_BIN_DIR");
        if (string.IsNullOrEmpty(dir))
        {
            string? repo = RepositoryRoot();
            if (repo is null)
            {
                reason = "RUSTEGON_BIN_DIR is not set and the repository root was not found";
                return null;
            }

            dir = Path.Combine(repo, "target", "debug");
        }

        foreach (string name in new[] { "rustegon", "rustegond" })
        {
            if (!File.Exists(Path.Combine(dir, Exe(name))))
            {
                reason = $"{Exe(name)} not found in {dir} (build with `cargo build -p rustegond -p rustegon-cli` or set RUSTEGON_BIN_DIR)";
                return null;
            }
        }

        reason = string.Empty;
        return dir;
    }

    /// <summary>The repository root (directory with <c>Cargo.toml</c> and <c>proto/</c>), searched upwards from the test binaries.</summary>
    /// <returns>The path, or null.</returns>
    public static string? RepositoryRoot()
    {
        for (DirectoryInfo? d = new(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            if (File.Exists(Path.Combine(d.FullName, "Cargo.toml")) && Directory.Exists(Path.Combine(d.FullName, "proto")))
            {
                return d.FullName;
            }
        }

        return null;
    }

    private static string Exe(string name) => OperatingSystem.IsWindows() ? name + ".exe" : name;

    /// <summary>Initializes and starts a node.</summary>
    /// <param name="binDir">Directory of <c>rustegon</c> and <c>rustegond</c>.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The running server.</returns>
    /// <exception cref="InvalidOperationException">init failed or the node did not become ready.</exception>
    public static async Task<RustegonTestServer> StartAsync(string binDir, CancellationToken cancellationToken = default)
    {
        string root = Path.Combine(Path.GetTempPath(), "rustegon-dotnet-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(root);
        string passwordFile = Path.Combine(root, "admin.pw");
        // 24 uniform base62 characters pass the password policy (as the server's own generator).
        string password = RandomNumberGenerator.GetString("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 24);
        await File.WriteAllTextAsync(passwordFile, password, cancellationToken).ConfigureAwait(false);
        string data = Path.Combine(root, "data");

        await RunInitAsync(binDir, data, passwordFile, cancellationToken).ConfigureAwait(false);

        (Process process, StringBuilder stderr, string line) = await LaunchAsync(binDir, data, passwordFile, [], cancellationToken).ConfigureAwait(false);
        var addrs = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string kv in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = kv.IndexOf('=', StringComparison.Ordinal);
            if (eq > 0)
            {
                addrs[kv[..eq]] = kv[(eq + 1)..];
            }
        }

        return new RustegonTestServer(binDir, process, stderr, root, addrs["grpc"], addrs["http"], password);
    }

    /// <summary>
    /// Kills the node process (no graceful shutdown: a crash as far as the node can tell) and
    /// keeps its data directory (TC-DRV-NET-029).
    /// </summary>
    /// <returns>A task completing when the process is gone.</returns>
    public async Task CrashAsync()
    {
        Kill(_process);
        await _process.WaitForExitAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Starts the node again on the same data directory and the same gRPC and REST addresses
    /// (after <see cref="CrashAsync"/>), so a client keeps its endpoint.
    /// </summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>A task completing when the node is ready again.</returns>
    public async Task RestartAsync(CancellationToken cancellationToken = default)
    {
        (Process process, StringBuilder stderr, _) = await LaunchAsync(
            _binDir,
            DataDir,
            PasswordFile,
            ["--set", "listen.grpc=" + GrpcEndpoint, "--set", "listen.http=" + HttpEndpoint],
            cancellationToken).ConfigureAwait(false);
        _process.Dispose();
        _process = process;
        _stderr = stderr;
    }

    private static async Task<(Process Process, StringBuilder Stderr, string ReadyLine)> LaunchAsync(
        string binDir, string data, string passwordFile, string[] extraArgs, CancellationToken cancellationToken)
    {
        var psi = NewStartInfo(Path.Combine(binDir, Exe("rustegond")));
        foreach (string a in new[]
        {
            "--config", Path.Combine(data, "rustegon.toml"), "--admin-password-file", passwordFile, "--stop-on-stdin-eof",
            // The smallest iteration count the configuration accepts: fast logins in debug builds.
            "--set", "auth.scram_iterations=100000", "--set", "log.stderr=false",
            // Client certificates are requested (and verified against the cluster CA) when
            // presented, for X.509 logins; clients without one are unaffected.
            "--set", "tls.client_cert=optional",
            // One node serves every test of a run from one address: the conformance suite logs in
            // (and fails logins on purpose) far more often than the per-IP/per-user defaults allow,
            // which would turn its expected errors into RGN-4003 RateLimited. 0 = unlimited.
            "--set", "rate_limit.auth_per_ip_per_min=0", "--set", "rate_limit.auth_per_user_per_min=0",
            "--set", "rate_limit.session_per_user_per_min=0", "--set", "rate_limit.admin_per_user_per_min=0",
        })
        {
            psi.ArgumentList.Add(a);
        }

        foreach (string a in extraArgs)
        {
            psi.ArgumentList.Add(a);
        }

        var process = Process.Start(psi) ?? throw new InvalidOperationException("rustegond did not start");
        var stderr = new StringBuilder();
        process.ErrorDataReceived += (_, e) =>
        {
            lock (stderr)
            {
                stderr.AppendLine(e.Data);
            }
        };
        process.BeginErrorReadLine();
        var ready = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null)
            {
                ready.TrySetException(new InvalidOperationException("rustegond closed stdout before it was ready"));
            }
            else if (e.Data.StartsWith(ReadyPrefix, StringComparison.Ordinal))
            {
                ready.TrySetResult(e.Data[ReadyPrefix.Length..]);
            }
        };
        process.BeginOutputReadLine();

        string line;
        try
        {
            line = await ready.Task.WaitAsync(StartTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (e is System.TimeoutException or InvalidOperationException)
        {
            Kill(process);
            string err;
            lock (stderr)
            {
                err = stderr.ToString();
            }

            throw new InvalidOperationException("rustegond did not become ready; stderr:\n" + err, e);
        }

        return (process, stderr, line);
    }

    private static async Task RunInitAsync(string binDir, string data, string passwordFile, CancellationToken cancellationToken)
    {
        var psi = NewStartInfo(Path.Combine(binDir, Exe("rustegon")));
        foreach (string a in new[]
        {
            "init", "--data-dir", data, "--grpc-port", "0", "--http-port", "0",
            "--admin-password-file", passwordFile, "--non-interactive", "--tls", "--client-user", ClientCertificateUser,
        })
        {
            psi.ArgumentList.Add(a);
        }

        using var init = Process.Start(psi) ?? throw new InvalidOperationException("rustegon init did not start");
        init.StandardInput.Close();
        Task<string> stdout = init.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderr = init.StandardError.ReadToEndAsync(cancellationToken);
        await init.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        if (init.ExitCode != 0)
        {
            throw new InvalidOperationException($"rustegon init failed ({init.ExitCode}):\n{await stdout.ConfigureAwait(false)}\n{await stderr.ConfigureAwait(false)}");
        }
    }

    private static ProcessStartInfo NewStartInfo(string exe)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        // The node must see only the flags given here, not an operator's environment.
        foreach (string key in new List<string>(psi.Environment.Keys))
        {
            if (key.StartsWith("RUSTEGON_", StringComparison.OrdinalIgnoreCase))
            {
                psi.Environment.Remove(key);
            }
        }

        return psi;
    }

    private static void Kill(Process p)
    {
        try
        {
            p.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
            // Already exited.
        }
    }

    /// <summary>Stops the node (stdin closed = graceful shutdown; killed after 30 s) and deletes its directory.</summary>
    /// <returns>A task completing when the node is gone.</returns>
    public async ValueTask DisposeAsync()
    {
        try
        {
            _process.StandardInput.Close();
            using var timeout = new CancellationTokenSource(StopTimeout);
            await _process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Kill(_process);
        }
        finally
        {
            _process.Dispose();
        }

        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A file still held open (antivirus, slow handle release) leaves a temp directory behind.
        }
        catch (UnauthorizedAccessException)
        {
            // As above.
        }
    }
}
