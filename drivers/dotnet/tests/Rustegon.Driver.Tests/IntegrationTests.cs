// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System.Threading.Tasks;
using Rustegon.Driver.TestServer;
using Rustegon.V1;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// TC-DRV-NET-009 (FR-DRV-001, FR-SEC-001, protocol.md §8): the whole stack against a real
/// <c>rustegond</c> — TLS on the node's CA, SCRAM-SHA-256 login as the administrator created by
/// <c>rustegon init</c>, Ping, GetServerInfo, WhoAmI, failed logins, API keys.
/// </summary>
[Collection(ServerGroup.Name)]
public sealed class IntegrationTests
{
    private readonly ServerFixture _fixture;

    public IntegrationTests(ServerFixture fixture)
    {
        _fixture = fixture;
    }

    private static RustegonClient Admin(RustegonTestServer server) =>
        new(server.Settings(RustegonCredential.Scram(RustegonTestServer.AdminUser, server.AdminPassword)));

    [Fact]
    public async Task tc_drv_net_009_scram_login_ping_server_info_and_whoami()
    {
        RustegonTestServer server = _fixture.Require();
        await using RustegonClient client = Admin(server);
        await client.PingAsync(TestContext.Current.CancellationToken);
        ServerInfo info = await client.GetServerInfoAsync(TestContext.Current.CancellationToken);
        Assert.False(string.IsNullOrEmpty(info.ServerVersion));
        Assert.StartsWith("1.", info.ProtocolVersion, System.StringComparison.Ordinal);
        WhoAmIResponse me = await client.WhoAmIAsync(TestContext.Current.CancellationToken);
        Assert.Equal(RustegonTestServer.AdminUser, me.User);
        Assert.Equal(AuthMechanism.ScramSha256, me.Mechanism);
        Assert.True(me.ExpiresAtUnixMs > 0);
    }

    [Fact]
    public async Task tc_drv_net_009_connection_string_login()
    {
        RustegonTestServer server = _fixture.Require();
        string cs = $"rustegon://{RustegonTestServer.AdminUser}:{System.Uri.EscapeDataString(server.AdminPassword)}@{server.GrpcEndpoint}/app" +
                    $"?tlsCaFile={System.Uri.EscapeDataString(server.CaCertificatePath)}&appName=tests";
        await using var client = new RustegonClient(cs);
        Assert.Equal("app", client.DefaultDatabase);
        Assert.Equal(RustegonTestServer.AdminUser, (await client.WhoAmIAsync(TestContext.Current.CancellationToken)).User);
    }

    [Fact]
    public async Task tc_drv_net_009_wrong_password_is_an_authentication_exception()
    {
        RustegonTestServer server = _fixture.Require();
        await using var client = new RustegonClient(server.Settings(RustegonCredential.Scram(RustegonTestServer.AdminUser, server.AdminPassword + "x")));
        AuthenticationException e = await Assert.ThrowsAsync<AuthenticationException>(() => client.PingAsync(TestContext.Current.CancellationToken));
        Assert.Equal(4001, e.Code);
        Assert.Equal("Unauthenticated", e.Name);
        Assert.False(e.IsRetryable);
        Assert.DoesNotContain(server.AdminPassword, e.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task tc_drv_net_009_unknown_user_fails_like_a_wrong_password()
    {
        RustegonTestServer server = _fixture.Require();
        await using var client = new RustegonClient(server.Settings(RustegonCredential.Scram("nobody", "Wh4tever-Passw0rd")));
        AuthenticationException e = await Assert.ThrowsAsync<AuthenticationException>(() => client.WhoAmIAsync(TestContext.Current.CancellationToken));
        Assert.Equal(4001, e.Code);
    }

    [Fact]
    public async Task tc_drv_net_009_anonymous_ping_and_server_info()
    {
        RustegonTestServer server = _fixture.Require();
        await using var client = new RustegonClient(server.Settings(null));
        await client.PingAsync(TestContext.Current.CancellationToken);
        Assert.False(string.IsNullOrEmpty((await client.GetServerInfoAsync(TestContext.Current.CancellationToken)).ServerVersion));
        AuthenticationException e = await Assert.ThrowsAsync<AuthenticationException>(() => client.WhoAmIAsync(TestContext.Current.CancellationToken));
        Assert.Equal(4001, e.Code);
    }

    [Fact]
    public async Task tc_drv_net_009_api_key_login()
    {
        RustegonTestServer server = _fixture.Require();
        await using RustegonClient admin = Admin(server);
        // The key scope must be a non-empty subset of the owner's grants: take the admin's own.
        WhoAmIResponse owner = await admin.WhoAmIAsync(TestContext.Current.CancellationToken);
        var request = new CreateApiKeyRequest { Description = "dotnet driver test" };
        request.Roles.AddRange(owner.Roles);
        CreateApiKeyResponse created = await admin.Executor.UnaryAsync(
            (invoker, options) => new AdminService.AdminServiceClient(invoker).CreateApiKeyAsync(request, options),
            TestContext.Current.CancellationToken);
        Assert.StartsWith("rgn_", created.Secret, System.StringComparison.Ordinal);

        await using var client = new RustegonClient(server.Settings(RustegonCredential.ApiKey(created.Secret)));
        await client.PingAsync(TestContext.Current.CancellationToken);
        WhoAmIResponse me = await client.WhoAmIAsync(TestContext.Current.CancellationToken);
        Assert.Equal(RustegonTestServer.AdminUser, me.User);
        Assert.Equal(AuthMechanism.ApiKey, me.Mechanism);
        Assert.Equal(created.Key.KeyId, me.ApiKeyId);

        await using var forged = new RustegonClient(server.Settings(RustegonCredential.ApiKey(created.Secret + "x")));
        AuthenticationException e = await Assert.ThrowsAsync<AuthenticationException>(() => forged.WhoAmIAsync(TestContext.Current.CancellationToken));
        Assert.Equal(4001, e.Code);
    }
}
