// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Security.Cryptography.X509Certificates;

namespace Rustegon.Driver;

/// <summary>How a credential authenticates (protocol.md §8).</summary>
public enum AuthenticationMechanism
{
    /// <summary>SCRAM-SHA-256 handshake with user name and password, yielding a session token.</summary>
    ScramSha256,

    /// <summary>API key sent as <c>authorization: ApiKey rgn_…</c> (no handshake).</summary>
    ApiKey,

    /// <summary>TLS client certificate, then <c>Authenticate{X509}</c> for a session token.</summary>
    X509,
}

/// <summary>
/// A credential (dotnet-driver.md §3, DEC-014). Secrets are kept private and never appear in
/// <see cref="ToString"/>, logs or exception messages.
/// </summary>
public sealed class RustegonCredential
{
    private readonly string? _secret;

    private RustegonCredential(AuthenticationMechanism mechanism, string? user, string? secret, X509Certificate2? certificate)
    {
        Mechanism = mechanism;
        User = user;
        _secret = secret;
        Certificate = certificate;
    }

    /// <summary>The mechanism.</summary>
    public AuthenticationMechanism Mechanism { get; }

    /// <summary>User name (SCRAM), else null.</summary>
    public string? User { get; }

    /// <summary>Client certificate with its private key (X.509), else null.</summary>
    public X509Certificate2? Certificate { get; }

    /// <summary>The password or API key (driver internal; never logged).</summary>
    internal string Secret => _secret ?? string.Empty;

    /// <summary>The password or API key as given, null when none was (connection string without a password).</summary>
    internal string? SecretOrNull => _secret;

    /// <summary>
    /// The SCRAM credential of a connection string (connstring.yaml cases
    /// <c>user_without_password</c> and <c>empty_password</c>): the string may name a user with no or
    /// an empty password, which <see cref="Scram"/> refuses. Such a credential is rejected when a
    /// client is created (<see cref="RustegonClientSettings"/> validation), so the password must
    /// then be supplied with <see cref="Scram"/>.
    /// </summary>
    internal static RustegonCredential ScramFromConnectionString(string user, string? password)
    {
        ArgumentException.ThrowIfNullOrEmpty(user);
        return new RustegonCredential(AuthenticationMechanism.ScramSha256, user, password, null);
    }

    /// <summary>A SCRAM-SHA-256 credential.</summary>
    /// <param name="user">User name.</param>
    /// <param name="password">Password.</param>
    /// <returns>The credential.</returns>
    /// <exception cref="ArgumentException">Empty user or password.</exception>
    public static RustegonCredential Scram(string user, string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(user);
        ArgumentException.ThrowIfNullOrEmpty(password);
        return new RustegonCredential(AuthenticationMechanism.ScramSha256, user, password, null);
    }

    /// <summary>An API key credential.</summary>
    /// <param name="apiKey">The full key <c>rgn_&lt;key_id&gt;_&lt;secret&gt;</c>.</param>
    /// <returns>The credential.</returns>
    /// <exception cref="ArgumentException">Not an <c>rgn_</c> key.</exception>
    public static RustegonCredential ApiKey(string apiKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(apiKey);
        if (!apiKey.StartsWith("rgn_", StringComparison.Ordinal) || apiKey.Contains(' ', StringComparison.Ordinal))
        {
            throw new ArgumentException("An API key has the form rgn_<key_id>_<secret>.", nameof(apiKey));
        }

        return new RustegonCredential(AuthenticationMechanism.ApiKey, null, apiKey, null);
    }

    /// <summary>An X.509 credential: the certificate is presented in the TLS handshake.</summary>
    /// <param name="certificate">Client certificate with its private key.</param>
    /// <returns>The credential.</returns>
    /// <exception cref="ArgumentException">The certificate has no private key.</exception>
    public static RustegonCredential X509(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("The client certificate needs its private key.", nameof(certificate));
        }

        return new RustegonCredential(AuthenticationMechanism.X509, null, null, certificate);
    }

    /// <summary>An X.509 credential using the client certificate of <see cref="TlsSettings"/>.</summary>
    /// <returns>The credential.</returns>
    public static RustegonCredential X509() => new(AuthenticationMechanism.X509, null, null, null);

    /// <summary>Mechanism and user only (no secret).</summary>
    /// <returns>The text.</returns>
    public override string ToString() => Mechanism switch
    {
        AuthenticationMechanism.ScramSha256 => $"SCRAM-SHA-256 user={User}",
        AuthenticationMechanism.X509 => $"X509 subject={Certificate?.Subject}",
        _ => "ApiKey ‹redacted›",
    };
}
