// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using Rustegon.Driver.Internal;

namespace Rustegon.Driver;

/// <summary>
/// Client configuration (dotnet-driver.md §3, DEC-014): endpoints, credential, TLS, database and
/// timeouts. Build it in code, or from a <c>rustegon://</c> connection string with
/// <see cref="FromConnectionString"/>.
/// </summary>
public sealed class RustegonClientSettings
{
    /// <summary>Default gRPC port of a node (protocol.md §1).</summary>
    public const int DefaultPort = 7700;

    private List<string> _endpoints = [];

    /// <summary>Seed endpoints as <c>host[:port]</c> (IPv6 in brackets: <c>[::1]:7700</c>).</summary>
    public IList<string> Endpoints => _endpoints;

    /// <summary>The credential; null for anonymous calls (only <c>Ping</c>/<c>GetServerInfo</c> are anonymous).</summary>
    public RustegonCredential? Credential { get; set; }

    /// <summary>TLS configuration (plain text unless a TLS option or X.509 authentication is set, ADR-034).</summary>
    public TlsSettings Tls { get; set; } = new();

    /// <summary>Database used when an operation names none.</summary>
    public string? DefaultDatabase { get; set; }

    /// <summary>gRPC channels (HTTP/2 connection groups) per endpoint, 1..64; HTTP/2 multiplexes streams on each (default 2, connstring.yaml).</summary>
    public int ConnectionsPerEndpoint { get; set; } = 2;

    /// <summary>Read consistency; null = server default (linearizable). Parsed and validated; applied by the data-plane API (wave 2).</summary>
    public ReadConsistency? ReadConsistency { get; set; }

    /// <summary>Staleness bound of <see cref="Driver.ReadConsistency.BoundedStaleness"/> (required by it).</summary>
    public TimeSpan? MaxStaleness { get; set; }

    /// <summary>Write concern; null = server default (majority). Parsed and validated; applied by the data-plane API (wave 2).</summary>
    public WriteConcern? WriteConcern { get; set; }

    /// <summary>Retry retryable reads automatically (dotnet-driver.md §8, default true; the retry policy is wave 2).</summary>
    public bool RetryReads { get; set; } = true;

    /// <summary>Retry idempotent writes outside transactions automatically (dotnet-driver.md §8, default true; wave 2).</summary>
    public bool RetryWrites { get; set; } = true;

    /// <summary>Automatic retries per operation, 0..10 (default 1, dotnet-driver.md §8).</summary>
    public int MaxRetries { get; set; } = 1;

    /// <summary>TCP + TLS connect timeout (default 10 s).</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Deadline of an operation without its own (default 30 s); sent as <c>grpc-timeout</c>.</summary>
    public TimeSpan DefaultOperationTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Application name reported to the server (<c>ClientInfo.application</c>).</summary>
    public string? ApplicationName { get; set; }

    /// <summary>
    /// Accept a login whose account must change its password (PD-076): the client then allows only
    /// the password change. When false (default) such a login raises
    /// <see cref="PasswordChangeRequiredException"/>.
    /// </summary>
    public bool AllowPasswordChangeOnly { get; set; }

    /// <summary>Parses a <c>rustegon://</c> connection string (see <c>drivers/dotnet/README.md</c> for the grammar).</summary>
    /// <param name="connectionString">The connection string.</param>
    /// <returns>The settings.</returns>
    /// <exception cref="ArgumentException">Malformed string, unknown or duplicate option, invalid value.</exception>
    public static RustegonClientSettings FromConnectionString(string connectionString) => ConnectionString.Parse(connectionString).Settings;

    /// <summary>Whether connections use TLS: <see cref="TlsSettings.Enabled"/>, or X.509 authentication (it needs TLS).</summary>
    internal bool UseTls => Tls.Enabled || Credential?.Mechanism == AuthenticationMechanism.X509;

    /// <summary>A copy the client keeps, so later changes of the caller's object have no effect.</summary>
    internal RustegonClientSettings Snapshot()
    {
        var copy = (RustegonClientSettings)MemberwiseClone();
        copy._endpoints = [.. _endpoints];
        return copy;
    }

    /// <summary>Checks the settings before a client uses them.</summary>
    internal IReadOnlyList<Endpoint> Validate()
    {
        if (Endpoints.Count == 0)
        {
            throw new ArgumentException("At least one endpoint is required.");
        }

        if (ConnectionsPerEndpoint is < 1 or > 64)
        {
            throw new ArgumentException("ConnectionsPerEndpoint must be between 1 and 64.");
        }

        if (ConnectTimeout <= TimeSpan.Zero || DefaultOperationTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentException("Timeouts must be positive.");
        }

        if (MaxRetries is < 0 or > 10)
        {
            throw new ArgumentException("MaxRetries must be between 0 and 10.");
        }

        if (MaxStaleness <= TimeSpan.Zero)
        {
            throw new ArgumentException("MaxStaleness must be positive.");
        }

        if (ReadConsistency == Driver.ReadConsistency.BoundedStaleness && MaxStaleness is null)
        {
            throw new ArgumentException("ReadConsistency.BoundedStaleness needs MaxStaleness.");
        }

        // A connection string may name a user without (or with an empty) password; the password is
        // then supplied with RustegonCredential.Scram before the client is created.
        if (Credential?.Mechanism == AuthenticationMechanism.ScramSha256 && string.IsNullOrEmpty(Credential.SecretOrNull))
        {
            throw new ArgumentException("The SCRAM credential has no password: set Credential = RustegonCredential.Scram(user, password).");
        }

        ArgumentNullException.ThrowIfNull(Tls);
        if (Tls.ExplicitlyDisabled && (Tls.HasOptions || Credential?.Mechanism == AuthenticationMechanism.X509))
        {
            throw new ArgumentException("Tls.Enabled = false contradicts the other TLS options or X.509 authentication.");
        }

        if (Credential?.Mechanism == AuthenticationMechanism.X509 && Credential.Certificate is null
            && Tls.ClientCertificate is null && Tls.ClientCertificatePath is null)
        {
            throw new ArgumentException("X.509 authentication needs a client certificate.");
        }

        var endpoints = new List<Endpoint>(Endpoints.Count);
        foreach (string e in Endpoints)
        {
            endpoints.Add(Endpoint.Parse(e));
        }

        return endpoints;
    }
}
