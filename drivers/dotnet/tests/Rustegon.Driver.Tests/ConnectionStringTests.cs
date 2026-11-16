// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Rustegon.Driver.Internal;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>TC-DRV-NET-008 (FR-DRV-001, DEC-014, dotnet-driver.md §3): connection strings and settings.</summary>
public sealed class ConnectionStringTests
{
    [Fact]
    public void tc_drv_net_008_full_connection_string()
    {
        RustegonClientSettings s = RustegonClientSettings.FromConnectionString(
            "rustegon://app_user:p%40ss%3Aw0rd@node1.example.com:7701,node2.example.com/shop?tls=true&authMechanism=SCRAM-SHA-256&appName=orders&operationTimeoutMs=5000&connectTimeoutMs=2000&connectionsPerEndpoint=2");
        Assert.Equal(new[] { "node1.example.com:7701", "node2.example.com:7700" }, s.Endpoints);
        Assert.Equal("shop", s.DefaultDatabase);
        Assert.Equal(AuthenticationMechanism.ScramSha256, s.Credential!.Mechanism);
        Assert.Equal("app_user", s.Credential.User);
        Assert.Equal("p@ss:w0rd", s.Credential.Secret);
        Assert.True(s.Tls.Enabled);
        Assert.Equal("orders", s.ApplicationName);
        Assert.Equal(TimeSpan.FromSeconds(5), s.DefaultOperationTimeout);
        Assert.Equal(TimeSpan.FromSeconds(2), s.ConnectTimeout);
        Assert.Equal(2, s.ConnectionsPerEndpoint);
        Assert.DoesNotContain("p@ss", s.Credential.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("rustegon://localhost", "localhost:7700", null)]
    [InlineData("rustegon://localhost/", "localhost:7700", null)]
    [InlineData("rustegon://127.0.0.1:7000/db", "127.0.0.1:7000", "db")]
    [InlineData("rustegon://[::1]:7700/d%20b", "[::1]:7700", "d b")]
    [InlineData("rustegon://[::1]", "[::1]:7700", null)]
    [InlineData("rustegon://Host.Example", "host.example:7700", null)]
    public void tc_drv_net_008_hosts_ports_and_database(string text, string endpoint, string? database)
    {
        RustegonClientSettings s = RustegonClientSettings.FromConnectionString(text);
        Assert.Equal(endpoint, Assert.Single(s.Endpoints));
        Assert.Equal(database, s.DefaultDatabase);
        Assert.Null(s.Credential);
        Assert.False(s.Tls.Enabled); // ADR-034: plain text by default
    }

    [Fact]
    public void tc_drv_net_008_tls_options_api_key_and_x509()
    {
        RustegonClientSettings a = RustegonClientSettings.FromConnectionString("rustegon://h/?tls=false&apiKey=rgn_abc_def");
        Assert.False(a.Tls.Enabled);
        Assert.Equal(AuthenticationMechanism.ApiKey, a.Credential!.Mechanism);
        Assert.Equal("rgn_abc_def", a.Credential.Secret);
        Assert.DoesNotContain("rgn_abc_def", a.Credential.ToString(), StringComparison.Ordinal);

        RustegonClientSettings x = RustegonClientSettings.FromConnectionString(
            "rustegon://h?authMechanism=X509&tlsCertificateFile=c%2Fclient.crt&tlsKeyFile=client.key&tlsCaFile=ca.crt&tlsServerName=node1");
        Assert.Equal(AuthenticationMechanism.X509, x.Credential!.Mechanism);
        Assert.Equal("c/client.crt", x.Tls.ClientCertificatePath);
        Assert.Equal("client.key", x.Tls.ClientKeyPath);
        Assert.Equal("ca.crt", x.Tls.CaCertificatePath);
        Assert.Equal("node1", x.Tls.ServerName);
        Assert.True(x.Tls.Enabled); // tls* options imply TLS (ADR-034)
        Assert.True(RustegonClientSettings.FromConnectionString("rustegon://h?tlsCaFile=ca.crt").Tls.Enabled);
        Assert.True(RustegonClientSettings.FromConnectionString("rustegon://h?authMechanism=X509").Tls.Enabled);
        Assert.Equal(AuthenticationMechanism.ApiKey, RustegonClientSettings.FromConnectionString("rustegon://h?authMechanism=APIKEY&apiKey=rgn_a_b").Credential!.Mechanism);
    }

    [Theory]
    [InlineData("http://h")]
    [InlineData("rustegon+srv://cluster.example.com")]
    [InlineData("rustegon://")]
    [InlineData("rustegon:///db")]
    [InlineData("RUSTEGON://h")]
    [InlineData("rustegon://u:p@ss@h")]
    [InlineData("rustegon://:pw@h")]
    [InlineData("rustegon://h:0")]
    [InlineData("rustegon://h:70000")]
    [InlineData("rustegon://h:x")]
    [InlineData("rustegon://::1")]
    [InlineData("rustegon://h,")]
    [InlineData("rustegon://h?foo=1")]
    [InlineData("rustegon://h?tls=1")]
    [InlineData("rustegon://h?tls")]
    [InlineData("rustegon://h?tls=true&TLS=false")]
    [InlineData("rustegon://h?authMechanism=PLAIN")]
    [InlineData("rustegon://h?tls=false&tlsCaFile=ca.crt")]
    [InlineData("rustegon://h?tls=false&authMechanism=X509")]
    [InlineData("rustegon://h?a=1&&b=2")]
    [InlineData("rustegon://u:p@h?apiKey=rgn_a_b")]
    [InlineData("rustegon://h?apiKey=notakey")]
    [InlineData("rustegon://u:p@h?authMechanism=X509")]
    [InlineData("rustegon://h?connectionsPerEndpoint=65")]
    [InlineData("rustegon://h?operationTimeoutMs=0")]
    [InlineData("rustegon://h?timeoutMs=1000")]
    [InlineData("rustegon://h?maxStalenessMs=0")]
    [InlineData("rustegon://h?writeConcern=one")]
    [InlineData("rustegon://h/a/b")]
    [InlineData("rustegon://h?appName=%zz")]
    public void tc_drv_net_008_invalid_connection_strings_are_rejected(string text) =>
        Assert.ThrowsAny<ArgumentException>(() => RustegonClientSettings.FromConnectionString(text));

    [Fact]
    public void tc_drv_net_008_errors_never_echo_the_password()
    {
        ArgumentException e = Assert.ThrowsAny<ArgumentException>(() => RustegonClientSettings.FromConnectionString("rustegon://u:s3cr3t@h?bogus=1"));
        Assert.DoesNotContain("s3cr3t", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void tc_drv_net_008_settings_validation_and_client_construction()
    {
        Assert.Throws<ArgumentException>(() => new RustegonClient(new RustegonClientSettings()));
        var s = new RustegonClientSettings { ConnectionsPerEndpoint = 0 };
        s.Endpoints.Add("h");
        Assert.Throws<ArgumentException>(() => new RustegonClient(s));
        var missingCa = new RustegonClientSettings { Tls = new TlsSettings { CaCertificatePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".crt") } };
        missingCa.Endpoints.Add("h");
        Assert.Throws<ArgumentException>(() => new RustegonClient(missingCa));
        var x509 = new RustegonClientSettings { Credential = RustegonCredential.X509() };
        x509.Endpoints.Add("h");
        Assert.Throws<ArgumentException>(() => new RustegonClient(x509));
        var contradiction = new RustegonClientSettings { Tls = new TlsSettings { Enabled = false, ServerName = "node1" } };
        contradiction.Endpoints.Add("h");
        Assert.Throws<ArgumentException>(() => new RustegonClient(contradiction));
        Assert.False(new TlsSettings().Enabled);
        Assert.True(new TlsSettings { ServerName = "node1" }.Enabled);

        // A user without (or with an empty) password parses (connstring.yaml) but cannot log in:
        // the client refuses it until a password is supplied with RustegonCredential.Scram.
        Assert.Throws<ArgumentException>(() => new RustegonClient("rustegon://app_user@localhost:1/db"));
        Assert.Throws<ArgumentException>(() => new RustegonClient("rustegon://app_user:@localhost:1/db"));
        RustegonClientSettings later = RustegonClientSettings.FromConnectionString("rustegon://app_user@localhost:1/db");
        later.Credential = RustegonCredential.Scram("app_user", "secret");
        using (new RustegonClient(later))
        {
        }

        var stale = new RustegonClientSettings { ReadConsistency = ReadConsistency.BoundedStaleness };
        stale.Endpoints.Add("h");
        Assert.Throws<ArgumentException>(() => new RustegonClient(stale));
        var retries = new RustegonClientSettings { MaxRetries = 11 };
        retries.Endpoints.Add("h");
        Assert.Throws<ArgumentException>(() => new RustegonClient(retries));

        // Constructing a client does not connect: channels are lazy.
        using var client = new RustegonClient("rustegon://localhost:1/db");
        Assert.Equal("db", client.DefaultDatabase);
    }

    [Fact]
    public void tc_drv_net_008_credentials_validate_their_input()
    {
        Assert.Throws<ArgumentException>(() => RustegonCredential.Scram(string.Empty, "p"));
        Assert.Throws<ArgumentException>(() => RustegonCredential.Scram("u", string.Empty));
        Assert.Throws<ArgumentException>(() => RustegonCredential.ApiKey("Bearer x"));
        Assert.Equal("SCRAM-SHA-256 user=u", RustegonCredential.Scram("u", "secret").ToString());
    }

    private const string Missing = "<connstring.yaml absent>";

    private static string ConnstringYaml => Path.Combine(TestPaths.Conformance, "connstring.yaml");

    public static TheoryData<string> ConformanceCases()
    {
        var data = new TheoryData<string>();
        if (!File.Exists(ConnstringYaml))
        {
            data.Add(Missing);
            return data;
        }

        var root = (Dictionary<string, object?>)ConformanceYaml.Load(ConnstringYaml)!;
        foreach (Dictionary<string, object?> c in ((List<object?>)root["cases"]!).Cast<Dictionary<string, object?>>())
        {
            data.Add((string)c["name"]!);
        }

        return data;
    }

    /// <summary>
    /// Runner of <c>drivers/conformance/connstring.yaml</c> (DEC-014), one theory case per string:
    /// a valid string gives the <c>defaults</c> overlaid by <c>expect</c> for every setting; an
    /// invalid one throws <see cref="ArgumentException"/> whose message never contains the password.
    /// </summary>
    [Theory]
    [MemberData(nameof(ConformanceCases))]
    public void tc_drv_net_008_conformance_connstring_cases(string name)
    {
        if (name == Missing)
        {
            Assert.Skip("drivers/conformance/connstring.yaml not present");
        }

        var root = (Dictionary<string, object?>)ConformanceYaml.Load(ConnstringYaml)!;
        Assert.Equal(1L, root["version"]);
        var defaults = (Dictionary<string, object?>)root["defaults"]!;
        Dictionary<string, object?> c = ((List<object?>)root["cases"]!).Cast<Dictionary<string, object?>>().Single(x => (string)x["name"]! == name);
        string uri = (string)c["uri"]!;
        if (c["valid"] is true)
        {
            var want = new Dictionary<string, object?>(defaults, StringComparer.Ordinal);
            if (c.TryGetValue("expect", out object? expect) && expect is Dictionary<string, object?> e)
            {
                foreach ((string k, object? v) in e)
                {
                    Assert.True(defaults.ContainsKey(k), $"expect key '{k}' has no default");
                    want[k] = v;
                }
            }

            Dictionary<string, object?> got = Observed(uri);
            Assert.Equal(defaults.Keys.Order(StringComparer.Ordinal), got.Keys.Order(StringComparer.Ordinal));
            var mismatches = defaults.Keys
                .Where(k => Canon(want[k]) != Canon(got[k]))
                .Select(k => $"{k}: expected {Canon(want[k])}, got {Canon(got[k])}")
                .ToList();
            Assert.True(mismatches.Count == 0, string.Join("; ", mismatches));
        }
        else
        {
            Assert.Equal(false, c["valid"]);
            ArgumentException ex = Assert.ThrowsAny<ArgumentException>(() => RustegonClientSettings.FromConnectionString(uri));
            string? password = RawPassword(uri);
            if (password is { Length: >= 3 })
            {
                Assert.DoesNotContain(password, ex.Message, StringComparison.Ordinal);
            }
        }
    }

    /// <summary>The settings of a string under the key names of connstring.yaml.</summary>
    private static Dictionary<string, object?> Observed(string uri)
    {
        ParsedConnectionString p = ConnectionString.Parse(uri);
        RustegonClientSettings s = p.Settings;
        Assert.Equal(RustegonClientSettings.FromConnectionString(uri).Endpoints, s.Endpoints);
        if (s.Credential is { Mechanism: AuthenticationMechanism.ScramSha256 } scram)
        {
            // The credential carries what the string said, nothing more.
            Assert.Equal(p.User, scram.User);
            Assert.Equal(p.Password, scram.SecretOrNull);
        }

        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["hosts"] = s.Endpoints.Select(Endpoint.Parse)
                .Select(e => (object?)new Dictionary<string, object?> { ["host"] = e.Host, ["port"] = (long)e.Port })
                .ToList(),
            ["user"] = p.User,
            ["password"] = p.Password,
            ["database"] = s.DefaultDatabase,
            ["tls"] = s.Tls.Enabled,
            ["tlsCaFile"] = s.Tls.CaCertificatePath,
            ["tlsServerName"] = s.Tls.ServerName,
            ["tlsCertificateFile"] = s.Tls.ClientCertificatePath,
            ["tlsKeyFile"] = s.Tls.ClientKeyPath,
            ["authMechanism"] = s.Credential?.Mechanism switch
            {
                AuthenticationMechanism.ScramSha256 => "SCRAM-SHA-256",
                AuthenticationMechanism.X509 => "X509",
                AuthenticationMechanism.ApiKey => "APIKEY",
                _ => p.AuthMechanism,
            },
            ["applicationName"] = s.ApplicationName,
            ["connectTimeoutMs"] = (long)s.ConnectTimeout.TotalMilliseconds,
            ["operationTimeoutMs"] = (long)s.DefaultOperationTimeout.TotalMilliseconds,
            ["readConsistency"] = s.ReadConsistency is { } r ? SnakeCase(r.ToString()) : null,
            ["maxStalenessMs"] = s.MaxStaleness is { } m ? (long)m.TotalMilliseconds : null,
            ["writeConcern"] = s.WriteConcern is { } w ? SnakeCase(w.ToString()) : null,
            ["retryReads"] = s.RetryReads,
            ["retryWrites"] = s.RetryWrites,
            ["maxRetries"] = (long)s.MaxRetries,
            ["connectionsPerEndpoint"] = (long)s.ConnectionsPerEndpoint,
        };
    }

    /// <summary>A canonical text of a YAML value (maps with sorted keys) for comparison and messages.</summary>
    private static string Canon(object? v) => v switch
    {
        null => "null",
        bool b => b ? "true" : "false",
        long l => l.ToString(CultureInfo.InvariantCulture),
        string str => "\"" + str + "\"",
        List<object?> list => "[" + string.Join(",", list.Select(Canon)) + "]",
        Dictionary<string, object?> map => "{" + string.Join(",", map.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => kv.Key + ":" + Canon(kv.Value))) + "}",
        _ => throw new InvalidDataException($"unexpected value type {v.GetType()}"),
    };

    private static string SnakeCase(string pascal) =>
        string.Concat(pascal.Select((ch, i) => i > 0 && char.IsAsciiLetterUpper(ch) ? "_" + char.ToLowerInvariant(ch) : char.ToLowerInvariant(ch).ToString()));

    /// <summary>The raw password of a string (after the first ':' of the user information, up to the last '@'), or null.</summary>
    private static string? RawPassword(string uri)
    {
        int start = uri.IndexOf("://", StringComparison.Ordinal);
        int at = uri.LastIndexOf('@');
        if (start < 0 || at < start)
        {
            return null;
        }

        string userInfo = uri[(start + 3)..at];
        int colon = userInfo.IndexOf(':', StringComparison.Ordinal);
        return colon < 0 ? null : userInfo[(colon + 1)..];
    }
}
