// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Rustegon.Driver.Internal.Transport;

/// <summary>
/// Certificates of a client, loaded once from <see cref="TlsSettings"/> (and an X.509 credential)
/// and shared by all its channels.
/// </summary>
internal sealed class TlsMaterial : IDisposable
{
    private readonly bool _ownsClientCertificate;

    private TlsMaterial(X509Certificate2Collection? trustAnchors, X509Certificate2? clientCertificate, bool ownsClientCertificate, string? serverName)
    {
        TrustAnchors = trustAnchors;
        ClientCertificate = clientCertificate;
        _ownsClientCertificate = ownsClientCertificate;
        ServerName = serverName;
    }

    /// <summary>Custom roots, or null for the operating system store.</summary>
    internal X509Certificate2Collection? TrustAnchors { get; }

    /// <summary>Client certificate (mutual TLS), or null.</summary>
    internal X509Certificate2? ClientCertificate { get; }

    /// <summary>Name to verify instead of the endpoint host, or null.</summary>
    internal string? ServerName { get; }

    /// <summary>Loads the material (reads PEM files; called once per client, not per call).</summary>
    /// <exception cref="ArgumentException">A file cannot be read or holds no certificate.</exception>
    internal static TlsMaterial Load(TlsSettings tls, RustegonCredential? credential)
    {
        X509Certificate2Collection? anchors = tls.CaCertificates.Count > 0 ? tls.CaCertificates : null;
        if (anchors is null && tls.CaCertificatePath is not null)
        {
            anchors = new X509Certificate2Collection();
            try
            {
                anchors.ImportFromPemFile(tls.CaCertificatePath);
            }
            catch (Exception e) when (e is CryptographicException or System.IO.IOException or UnauthorizedAccessException)
            {
                throw new ArgumentException($"Cannot load the CA certificate file '{tls.CaCertificatePath}': {e.Message}", nameof(tls), e);
            }

            if (anchors.Count == 0)
            {
                throw new ArgumentException($"The CA certificate file '{tls.CaCertificatePath}' holds no certificate.", nameof(tls));
            }
        }

        X509Certificate2? client = credential?.Certificate ?? tls.ClientCertificate;
        bool owns = false;
        if (client is null && tls.ClientCertificatePath is not null)
        {
            client = LoadClientPem(tls.ClientCertificatePath, tls.ClientKeyPath);
            owns = true;
        }

        return new TlsMaterial(anchors, client, owns, tls.ServerName);
    }

    private static X509Certificate2 LoadClientPem(string certPath, string? keyPath)
    {
        try
        {
            using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(certPath, keyPath);
            // Windows SChannel cannot use the ephemeral key of a PEM import for client
            // authentication; a PKCS#12 round trip gives it a usable key container.
            return X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), password: null);
        }
        catch (Exception e) when (e is CryptographicException or System.IO.IOException or UnauthorizedAccessException)
        {
            throw new ArgumentException($"Cannot load the client certificate '{certPath}': {e.Message}", nameof(certPath), e);
        }
    }

    /// <summary>TLS options of one endpoint.</summary>
    internal SslClientAuthenticationOptions SslOptions(Endpoint endpoint)
    {
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = ServerName ?? endpoint.Host,
        };
        if (TrustAnchors is not null)
        {
            // Only the given roots are trusted (not the system store); revocation is not checked
            // because a private cluster CA publishes no CRL/OCSP (security.md §5: short-lived certs).
            var policy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
            };
            policy.CustomTrustStore.AddRange(TrustAnchors);
            options.CertificateChainPolicy = policy;
        }

        if (ClientCertificate is not null)
        {
            options.ClientCertificates = new X509CertificateCollection { ClientCertificate };
        }

        return options;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsClientCertificate)
        {
            ClientCertificate?.Dispose();
        }
    }
}
