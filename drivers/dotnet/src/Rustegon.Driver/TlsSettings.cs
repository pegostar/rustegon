// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System.Security.Cryptography.X509Certificates;

namespace Rustegon.Driver;

/// <summary>
/// TLS configuration (dotnet-driver.md §3). Plain text by default, like a single node started
/// with its defaults (ADR-034); a node with <c>security.tls = true</c>, and every cluster node,
/// requires TLS 1.3.
/// </summary>
public sealed class TlsSettings
{
    private bool? enabled;

    /// <summary>
    /// Whether to use TLS. Unless set explicitly, TLS is on as soon as any other TLS option (CA,
    /// server name, client certificate) is set, and off otherwise; plain text sends credentials
    /// in clear text. Setting it to false together with another TLS option is an error.
    /// </summary>
    public bool Enabled
    {
        get => enabled ?? HasOptions;
        set => enabled = value;
    }

    /// <summary>Whether <see cref="Enabled"/> was set to false explicitly.</summary>
    internal bool ExplicitlyDisabled => enabled == false;

    /// <summary>Whether a TLS option other than <see cref="Enabled"/> is set.</summary>
    internal bool HasOptions => CaCertificatePath is not null || CaCertificates.Count > 0 || ServerName is not null
        || ClientCertificatePath is not null || ClientKeyPath is not null || ClientCertificate is not null;

    /// <summary>
    /// PEM file with the CA certificate(s) the server certificate must chain to (e.g. the
    /// <c>ca.crt</c> written by <c>rustegon init</c>). When neither this nor
    /// <see cref="CaCertificates"/> is set, the operating system trust store is used.
    /// </summary>
    public string? CaCertificatePath { get; set; }

    /// <summary>CA certificates the server certificate must chain to (instead of the system store; empty = not used).</summary>
    public X509Certificate2Collection CaCertificates { get; } = [];

    /// <summary>Name to verify in the server certificate (default: the endpoint host).</summary>
    public string? ServerName { get; set; }

    /// <summary>PEM file of a client certificate (mutual TLS / X.509 login); needs <see cref="ClientKeyPath"/>.</summary>
    public string? ClientCertificatePath { get; set; }

    /// <summary>PEM file of the client certificate's private key.</summary>
    public string? ClientKeyPath { get; set; }

    /// <summary>A client certificate with private key (takes precedence over the PEM paths).</summary>
    public X509Certificate2? ClientCertificate { get; set; }
}
