// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using Rustegon.Driver.Internal.Auth;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>TC-DRV-NET-007 (FR-SEC-001, protocol.md §8, PD-074): SCRAM-SHA-256 client and SASLprep.</summary>
public sealed class ScramTests
{
    // RFC 7677 §3 test vector.
    private const string ClientNonce = "rOprNGfwEbeRWgbNEkqO";
    private const string ServerFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    private const string ClientFinal = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    private const string ServerFinal = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    [Fact]
    public void tc_drv_net_007_rfc7677_test_vector()
    {
        var c = new ScramSha256Client("user", "pencil", ClientNonce);
        Assert.Equal("n,,n=user,r=" + ClientNonce, c.ClientFirst);
        Assert.Equal(ClientFinal, c.ProcessServerFirst(ServerFirst));
        c.VerifyServerFinal(ServerFinal);
    }

    [Fact]
    public void tc_drv_net_007_wrong_server_signature_fails_mutual_authentication()
    {
        var c = new ScramSha256Client("user", "pencil", ClientNonce);
        c.ProcessServerFirst(ServerFirst);
        Assert.Throws<AuthenticationException>(() => c.VerifyServerFinal("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        Assert.Throws<AuthenticationException>(() => c.VerifyServerFinal("e=invalid-proof"));
    }

    [Theory]
    [InlineData("r=other%hvYDpWUa2RaTCAfuxFIlj,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")] // nonce does not extend ours
    [InlineData("r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")] // no server part
    [InlineData("r=rOprNGfwEbeRWgbNEkqO%x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4095")] // downgrade
    [InlineData("r=rOprNGfwEbeRWgbNEkqO%x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=10000001")] // client DoS
    [InlineData("r=rOprNGfwEbeRWgbNEkqO%x,s=,i=4096")] // empty salt
    [InlineData("r=rOprNGfwEbeRWgbNEkqO%x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=ext")] // extension
    [InlineData("s=W22ZaJ0SNY7soEsUEjb6gQ==,r=rOprNGfwEbeRWgbNEkqO%x,i=4096")] // attribute order
    public void tc_drv_net_007_malformed_server_first_is_rejected(string serverFirst)
    {
        var c = new ScramSha256Client("user", "pencil", ClientNonce);
        Assert.Throws<AuthenticationException>(() => c.ProcessServerFirst(serverFirst));
    }

    [Fact]
    public void tc_drv_net_007_user_name_is_sasl_escaped_and_nonce_is_random()
    {
        Assert.Equal("n,,n=a=3Db=2Cc,r=xyz", new ScramSha256Client("a=b,c", "p", "xyz").ClientFirst);
        string n1 = new ScramSha256Client("u", "p").ClientFirst;
        string n2 = new ScramSha256Client("u", "p").ClientFirst;
        Assert.NotEqual(n1, n2);
        Assert.Equal("n,,n=u,r=".Length + 24, n1.Length);
    }

    [Theory]
    [InlineData("I­X", "IX")] // RFC 4013 §3: soft hyphen mapped to nothing
    [InlineData("user", "user")]
    [InlineData("USER", "USER")] // no case folding
    [InlineData("ª", "a")] // NFKC
    [InlineData("Ⅸ", "IX")] // NFKC
    [InlineData("a b", "a b")] // non-ASCII space → SPACE
    [InlineData("a​b", "a b")] // U+200B is in C.1.2 and mapped to SPACE first (as the Rust crate)
    [InlineData("a️b", "ab")] // variation selector mapped to nothing
    [InlineData("אב", "אב")] // RandALCat only
    [InlineData("café", "café")]
    [InlineData("café", "café")] // NFKC composes
    [InlineData("pass word 1", "pass word 1")]
    public void tc_drv_net_007_saslprep_maps_and_normalizes(string input, string expected)
    {
        Assert.True(SaslPrep.TryPrepare(input, out string prepared));
        Assert.Equal(expected, prepared);
    }

    [Theory]
    [InlineData("\u0007")] // RFC 4013 §3: prohibited (C.2.1)
    [InlineData("ا1")] // RFC 4013 §3: RandALCat not last
    [InlineData("אa")] // RandALCat with LCat
    [InlineData("a\u0080")] // C.2.2
    [InlineData("")] // C.3 private use
    [InlineData("﷐")] // C.4
    [InlineData("\uD800")] // C.5 lone surrogate
    [InlineData("�")] // C.6
    [InlineData("⿰")] // C.7
    [InlineData("‎")] // C.8
    [InlineData("\U000E0001")] // C.9
    [InlineData("ȡ")] // A.1 unassigned in Unicode 3.2
    [InlineData("x \u0007")]
    public void tc_drv_net_007_saslprep_rejects_prohibited_output(string input) =>
        Assert.False(SaslPrep.TryPrepare(input, out _));

    [Fact]
    public void tc_drv_net_007_invalid_saslprep_password_fails_before_any_proof()
    {
        var c = new ScramSha256Client("user", "bad\u0007", ClientNonce);
        AuthenticationException e = Assert.Throws<AuthenticationException>(() => c.ProcessServerFirst(ServerFirst));
        Assert.DoesNotContain("bad", e.Message, StringComparison.Ordinal);
    }
}
