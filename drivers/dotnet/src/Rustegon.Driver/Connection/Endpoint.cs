// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Globalization;
using System.Net;

namespace Rustegon.Driver.Internal;

/// <summary>A node address: DNS name, IPv4 or IPv6 host, and port.</summary>
internal readonly record struct Endpoint(string Host, int Port)
{
    /// <summary>Parses <c>host</c>, <c>host:port</c> or <c>[ipv6]:port</c>.</summary>
    /// <exception cref="ArgumentException">Empty host or invalid port.</exception>
    internal static Endpoint Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        string host;
        string? port = null;
        if (text.StartsWith('['))
        {
            int close = text.IndexOf(']', StringComparison.Ordinal);
            if (close < 0 || !IPAddress.TryParse(text[1..close], out IPAddress? v6) || v6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                throw new ArgumentException($"Invalid IPv6 endpoint '{text}'.", nameof(text));
            }

            host = text[1..close];
            string rest = text[(close + 1)..];
            if (rest.Length > 0)
            {
                port = rest.StartsWith(':') ? rest[1..] : throw new ArgumentException($"Invalid endpoint '{text}'.", nameof(text));
            }
        }
        else
        {
            int colon = text.LastIndexOf(':');
            if (colon >= 0 && text.IndexOf(':', StringComparison.Ordinal) != colon)
            {
                throw new ArgumentException($"IPv6 endpoints need brackets: '[{text}]'.", nameof(text));
            }

            host = colon < 0 ? text : text[..colon];
            port = colon < 0 ? null : text[(colon + 1)..];
        }

        if (host.Length == 0 || host.AsSpan().ContainsAny("/?#@ "))
        {
            throw new ArgumentException($"Invalid host in endpoint '{text}'.", nameof(text));
        }

        int p = RustegonClientSettings.DefaultPort;
        if (port is not null && (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out p) || p is < 1 or > 65535))
        {
            throw new ArgumentException($"Invalid port in endpoint '{text}'.", nameof(text));
        }

        return new Endpoint(host, p);
    }

    /// <summary>Whether the host is an IPv6 literal.</summary>
    internal bool IsIPv6 => Host.Contains(':', StringComparison.Ordinal);

    /// <summary>The URI authority (<c>host:port</c>, IPv6 in brackets).</summary>
    internal string Authority => IsIPv6 ? $"[{Host}]:{Port}" : $"{Host}:{Port}";

    /// <inheritdoc/>
    public override string ToString() => Authority;
}
