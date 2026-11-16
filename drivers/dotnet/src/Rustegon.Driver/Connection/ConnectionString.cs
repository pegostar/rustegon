// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Rustegon.Driver.Internal;

/// <summary>
/// A parsed connection string: the settings plus what the string itself said about the user,
/// password and mechanism (a mechanism can be named without a user, connstring.yaml case
/// <c>spec_example_dotnet</c>; the settings then carry no credential).
/// </summary>
internal sealed record ParsedConnectionString(
    RustegonClientSettings Settings,
    string? User,
    string? Password,
    string? AuthMechanism);

/// <summary>
/// Parser of <c>rustegon://[user[:password]@]host[:port][,host[:port]…][/[database]][?options]</c>
/// (DEC-014, dotnet-driver.md §3). The grammar and the normative cases are
/// <c>drivers/conformance/connstring.yaml</c> (run by <c>tc_drv_net_008_conformance_connstring_cases</c>).
/// </summary>
/// <remarks>
/// The scheme is lower case. Hosts are DNS names (kept in lower case), IPv4 or bracketed IPv6
/// addresses; the default port is 7700. User, password, database and option values are
/// percent-decoded as UTF-8; a raw <c>@</c> in the user information is an error. Option names are
/// case-insensitive, each may appear once and an unknown name is an error (a typo must not
/// silently change security settings). Options of connstring.yaml: <c>tls</c>, <c>tlsCaFile</c>,
/// <c>tlsServerName</c>, <c>tlsCertificateFile</c> + <c>tlsKeyFile</c> (both or neither),
/// <c>authMechanism</c> (SCRAM-SHA-256 | X509 | APIKEY) with <c>apiKey</c>, <c>appName</c>,
/// <c>connectTimeoutMs</c>, <c>operationTimeoutMs</c>, <c>readConsistency</c>,
/// <c>maxStalenessMs</c>, <c>writeConcern</c>, <c>retryReads</c>, <c>retryWrites</c>,
/// <c>maxRetries</c>, <c>connectionsPerEndpoint</c>. TLS is off by default (ADR-034); without an
/// explicit <c>tls</c>, any tls* option or <c>authMechanism=X509</c> turns it on, and
/// <c>tls=false</c> with either is an error.
/// </remarks>
internal static class ConnectionString
{
    internal const string Scheme = "rustegon://";
    internal const string SrvScheme = "rustegon+srv://";

    internal static ParsedConnectionString Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.StartsWith(SrvScheme, StringComparison.Ordinal))
        {
            throw Bad("DNS SRV seeds (rustegon+srv://) are not supported yet (PD-069)");
        }

        // connstring.yaml: the scheme is case-sensitive (case scheme_upper_case_is_not_accepted).
        if (!text.StartsWith(Scheme, StringComparison.Ordinal))
        {
            throw Bad("the connection string must start with rustegon://");
        }

        string rest = text[Scheme.Length..];
        int query = rest.IndexOf('?', StringComparison.Ordinal);
        string? options = query < 0 ? null : rest[(query + 1)..];
        rest = query < 0 ? rest : rest[..query];

        // The user information ends at the first '@'; a second one is an unescaped '@' in the
        // password (RFC 3986 needs %40) and is rejected rather than guessed at. A '/' inside a raw
        // password would otherwise be taken for the start of the path.
        int at = rest.IndexOf('@', StringComparison.Ordinal);
        if (at >= 0 && rest.IndexOf('@', at + 1) >= 0)
        {
            throw Bad("the user information contains a raw '@': percent-encode it as %40");
        }

        int slash = rest.IndexOf('/', at + 1);
        string authority = slash < 0 ? rest : rest[..slash];
        string? path = slash < 0 ? null : rest[(slash + 1)..];

        string? user = null;
        string? password = null;
        at = authority.IndexOf('@', StringComparison.Ordinal);
        if (at >= 0)
        {
            string userInfo = authority[..at];
            authority = authority[(at + 1)..];
            int colon = userInfo.IndexOf(':', StringComparison.Ordinal);
            user = Decode(colon < 0 ? userInfo : userInfo[..colon], "user");
            password = colon < 0 ? null : Decode(userInfo[(colon + 1)..], "password");
            if (user.Length == 0)
            {
                throw Bad("empty user name");
            }
        }

        var settings = new RustegonClientSettings();
        if (authority.Length == 0)
        {
            throw Bad("at least one host is required");
        }

        foreach (string host in authority.Split(','))
        {
            settings.Endpoints.Add(ParseHost(host));
        }

        if (!string.IsNullOrEmpty(path))
        {
            if (path.Contains('/', StringComparison.Ordinal))
            {
                throw Bad("the database name cannot contain '/'");
            }

            settings.DefaultDatabase = Decode(path, "database");
        }

        string? mechanism = ApplyOptions(settings, options, user, password);
        return new ParsedConnectionString(settings, user, password, mechanism ?? (user is null ? null : "SCRAM-SHA-256"));
    }

    /// <summary><c>host[:port]</c> → canonical authority; DNS names in lower case, the same spelling for equal hosts.</summary>
    private static string ParseHost(string text)
    {
        Endpoint e;
        try
        {
            e = Endpoint.Parse(text);
        }
        catch (ArgumentException ex)
        {
            throw Bad(ex.Message);
        }

        // Same host characters as the Java driver: DNS labels (letters, digits, '-', '_', '.') or
        // an IPv6 literal (validated by Endpoint.Parse).
        if (!e.IsIPv6)
        {
            foreach (char c in e.Host)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c is not ('-' or '.' or '_'))
                {
                    throw Bad("invalid character in a host name");
                }
            }
        }

        // CA1308 prefers upper case for normalisation; connstring.yaml (host_is_lowercased) pins
        // lower case, and host names are ASCII here, so no locale-sensitive mapping is involved.
#pragma warning disable CA1308
        return (e with { Host = e.Host.ToLowerInvariant() }).Authority;
#pragma warning restore CA1308
    }

    /// <returns>The <c>authMechanism</c> option in upper case, or null.</returns>
    private static string? ApplyOptions(RustegonClientSettings settings, string? options, string? user, string? password)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? mechanism = null;
        string? apiKey = null;
        bool tlsDisabled = false;
        bool otherTlsOption = false;
        bool hasMaxStaleness = false;

        // `?` with nothing after it is accepted; an empty pair (`a=1&&b=2`) is not.
        IEnumerable<string> pairs = string.IsNullOrEmpty(options) ? [] : options.Split('&');
        foreach (string pair in pairs)
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
            {
                throw Bad("every option needs a name and a value (name=value)");
            }

            string key = pair[..eq];
            string value = Decode(pair[(eq + 1)..], "option " + key);
            if (!seen.Add(key))
            {
                throw Bad($"option '{key}' is repeated");
            }

            switch (key.ToUpperInvariant())
            {
                case "TLS":
                    settings.Tls.Enabled = Bool(key, value);
                    tlsDisabled = !settings.Tls.Enabled;
                    break;
                case "TLSCAFILE":
                    settings.Tls.CaCertificatePath = NonEmpty(key, value);
                    otherTlsOption = true;
                    break;
                case "TLSSERVERNAME":
                    settings.Tls.ServerName = NonEmpty(key, value);
                    otherTlsOption = true;
                    break;
                case "TLSCERTIFICATEFILE":
                    settings.Tls.ClientCertificatePath = NonEmpty(key, value);
                    otherTlsOption = true;
                    break;
                case "TLSKEYFILE":
                    settings.Tls.ClientKeyPath = NonEmpty(key, value);
                    otherTlsOption = true;
                    break;
                case "AUTHMECHANISM":
                    mechanism = value.ToUpperInvariant();
                    break;
                case "APIKEY":
                    apiKey = NonEmpty(key, value);
                    break;
                case "APPNAME":
                    settings.ApplicationName = NonEmpty(key, value);
                    break;
                case "CONNECTTIMEOUTMS":
                    settings.ConnectTimeout = TimeSpan.FromMilliseconds(Int(key, value, 1, int.MaxValue));
                    break;
                case "OPERATIONTIMEOUTMS":
                    settings.DefaultOperationTimeout = TimeSpan.FromMilliseconds(Int(key, value, 1, int.MaxValue));
                    break;
                case "CONNECTIONSPERENDPOINT":
                    settings.ConnectionsPerEndpoint = Int(key, value, 1, 64);
                    break;
                case "READCONSISTENCY":
                    settings.ReadConsistency = Enum<ReadConsistency>(key, value);
                    break;
                case "MAXSTALENESSMS":
                    settings.MaxStaleness = TimeSpan.FromMilliseconds(Int(key, value, 1, int.MaxValue));
                    hasMaxStaleness = true;
                    break;
                case "WRITECONCERN":
                    settings.WriteConcern = Enum<WriteConcern>(key, value);
                    break;
                case "RETRYREADS":
                    settings.RetryReads = Bool(key, value);
                    break;
                case "RETRYWRITES":
                    settings.RetryWrites = Bool(key, value);
                    break;
                case "MAXRETRIES":
                    settings.MaxRetries = Int(key, value, 0, 10);
                    break;
                default:
                    throw Bad($"unknown option '{key}'");
            }
        }

        if (tlsDisabled && (otherTlsOption || mechanism == "X509"))
        {
            throw Bad("tls=false contradicts the other tls options or authMechanism=X509");
        }

        // ADR-034: plain text by default; X.509 needs TLS, so it turns TLS on like a tls* option.
        if (mechanism == "X509")
        {
            settings.Tls.Enabled = true;
        }

        if ((settings.Tls.ClientCertificatePath is null) != (settings.Tls.ClientKeyPath is null))
        {
            throw Bad("tlsCertificateFile and tlsKeyFile go together");
        }

        if (settings.ReadConsistency == ReadConsistency.BoundedStaleness && !hasMaxStaleness)
        {
            throw Bad("readConsistency=bounded_staleness needs maxStalenessMs");
        }

        settings.Credential = Credential(mechanism, user, password, apiKey);
        return mechanism;
    }

    private static RustegonCredential? Credential(string? mechanism, string? user, string? password, string? apiKey)
    {
        switch (mechanism)
        {
            case null when apiKey is not null:
            case "APIKEY" or "API-KEY":
                if (apiKey is null || user is not null)
                {
                    throw Bad("authMechanism=APIKEY needs apiKey=... and no user");
                }

                return RustegonCredential.ApiKey(apiKey);
            case "X509":
                if (password is not null || apiKey is not null)
                {
                    throw Bad("authMechanism=X509 takes no password or apiKey");
                }

                // The user, if any, is informative: the certificate identifies the principal.
                return RustegonCredential.X509();
            case null or "SCRAM-SHA-256":
                if (apiKey is not null)
                {
                    throw Bad("apiKey is only valid with authMechanism=APIKEY");
                }

                // Without a user the string only names the mechanism; the credential is set in
                // code. A user without a password is accepted here and must get its password
                // through RustegonCredential.Scram before a client is created (connstring.yaml).
                return user is null ? null : RustegonCredential.ScramFromConnectionString(user, password);
            default:
                throw Bad($"unknown authMechanism '{mechanism}'");
        }
    }

    private static string Decode(string s, string what)
    {
        // Strict UTF-8 percent-decoding; '+' stays a plus sign. Malformed escapes and byte
        // sequences that are not UTF-8 are errors (Uri.UnescapeDataString would keep them).
        var bytes = new List<byte>(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '%')
            {
                if (i + 2 >= s.Length || !char.IsAsciiHexDigit(s[i + 1]) || !char.IsAsciiHexDigit(s[i + 2]))
                {
                    throw Bad($"invalid percent-encoding in the {what}");
                }

                bytes.Add(byte.Parse(s.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                i += 2;
            }
            else if (c is ' ' or (< ' ') or '\u007f')
            {
                throw Bad($"whitespace or a control character in the {what}");
            }
            else
            {
                int len = char.IsHighSurrogate(c) && i + 1 < s.Length ? 2 : 1;
                bytes.AddRange(Encoding.UTF8.GetBytes(s.Substring(i, len)));
                i += len - 1;
            }
        }

        try
        {
            return new UTF8Encoding(false, true).GetString([.. bytes]);
        }
        catch (DecoderFallbackException)
        {
            throw Bad($"the {what} is not valid percent-encoded UTF-8");
        }
    }

    private static string NonEmpty(string key, string value) => value.Length > 0 ? value : throw Bad($"option '{key}' is empty");

    private static bool Bool(string key, string value) => value.ToUpperInvariant() switch
    {
        "TRUE" => true,
        "FALSE" => false,
        _ => throw Bad($"option '{key}' must be true or false"),
    };

    private static int Int(string key, string value, int min, int max) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int v) && v >= min && v <= max
            ? v
            : throw Bad($"option '{key}' must be an integer in {min}..{max}");

    /// <summary>Enumeration values in snake case, any letter case (<c>bounded_staleness</c> → <c>BoundedStaleness</c>).</summary>
    private static T Enum<T>(string key, string value)
        where T : struct, System.Enum
    {
        foreach (T candidate in System.Enum.GetValues<T>())
        {
            if (string.Equals(SnakeCase(candidate.ToString()), value, StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }
        }

        throw Bad($"unknown value of option '{key}'");
    }

    private static string SnakeCase(string pascal)
    {
        var sb = new StringBuilder(pascal.Length + 4);
        for (int i = 0; i < pascal.Length; i++)
        {
            if (i > 0 && char.IsAsciiLetterUpper(pascal[i]))
            {
                sb.Append('_');
            }

            sb.Append(char.ToLowerInvariant(pascal[i]));
        }

        return sb.ToString();
    }

    // The message never repeats the connection string or a decoded value: it may hold a password.
    private static ArgumentException Bad(string reason) => new("Invalid connection string: " + reason + ".");
}
