// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Rustegon.Driver.Internal.Transport;
using Rustegon.Driver.TestServer;
using Rustegon.V1;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// TC-DRV-NET-010 (FR-DRV-001, protocol.md §2/§5.3): request metadata (UUIDv7 request id,
/// deadline), single-flight session login under concurrency, TLS verification against the node CA.
/// </summary>
public sealed partial class TransportTests
{
    [GeneratedRegex("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    private static partial Regex UuidV7();

    /// <summary>Captures the options of the call it would make.</summary>
    private sealed class CapturingInvoker : CallInvoker
    {
        public CallOptions Options { get; private set; }

        public override TResponse BlockingUnaryCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request) =>
            throw new NotSupportedException();

        public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request)
        {
            Options = options;
            return new AsyncUnaryCall<TResponse>(
                Task.FromResult(Activator.CreateInstance<TResponse>()),
                Task.FromResult(new Metadata()),
                () => Status.DefaultSuccess,
                () => [],
                () => { });
        }

        public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request) =>
            throw new NotSupportedException();

        public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options) =>
            throw new NotSupportedException();

        public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options) =>
            throw new NotSupportedException();
    }

    [Fact]
    public async Task tc_drv_net_010_interceptor_adds_uuidv7_request_id_and_default_deadline()
    {
        var inner = new CapturingInvoker();
        CallInvoker invoker = inner.Intercept(new RustegonInterceptor(TimeSpan.FromSeconds(30)));
        DateTime before = DateTime.UtcNow;
        await new SessionService.SessionServiceClient(invoker).PingAsync(new PingRequest(), cancellationToken: TestContext.Current.CancellationToken);
        string id = inner.Options.Headers!.GetValue(RustegonInterceptor.RequestIdHeader)!;
        Assert.Matches(UuidV7(), id);
        Assert.InRange(inner.Options.Deadline!.Value, before.AddSeconds(29), DateTime.UtcNow.AddSeconds(31));

        // An explicit request id and deadline win (the executor reuses one id across retries).
        DateTime deadline = DateTime.UtcNow.AddSeconds(5);
        var headers = new Metadata { { RustegonInterceptor.RequestIdHeader, "0190a6f0-0000-7000-8000-000000000000" } };
        await new SessionService.SessionServiceClient(invoker).PingAsync(new PingRequest(), headers, deadline, TestContext.Current.CancellationToken);
        Assert.Equal("0190a6f0-0000-7000-8000-000000000000", inner.Options.Headers!.GetValue(RustegonInterceptor.RequestIdHeader));
        Assert.Single(inner.Options.Headers!, e => e.Key == RustegonInterceptor.RequestIdHeader);
        Assert.Equal(deadline, inner.Options.Deadline);
    }

    [Fact]
    public void tc_drv_net_010_request_ids_are_unique_uuidv7()
    {
        string[] ids = Enumerable.Range(0, 1000).Select(_ => RustegonInterceptor.NewRequestId()).ToArray();
        Assert.All(ids, id => Assert.Matches(UuidV7(), id));
        Assert.Equal(ids.Length, ids.Distinct().Count());
    }

    [Fact]
    public async Task tc_drv_net_010_unreachable_endpoint_is_unavailable()
    {
        // Port 1 on loopback refuses connections: the transport failure maps to RGN-3002.
        await using var client = new RustegonClient(new RustegonClientSettings { Endpoints = { "127.0.0.1:1" }, ConnectTimeout = TimeSpan.FromSeconds(2) });
        UnavailableException e = await Assert.ThrowsAsync<UnavailableException>(() => client.PingAsync(TestContext.Current.CancellationToken));
        Assert.True(e.IsRetryable);
    }
}

/// <summary>TC-DRV-NET-010, server part.</summary>
[Collection(ServerGroup.Name)]
public sealed class TransportServerTests
{
    private readonly ServerFixture _fixture;

    public TransportServerTests(ServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task tc_drv_net_010_concurrent_first_calls_share_one_login()
    {
        RustegonTestServer server = _fixture.Require();
        RustegonClientSettings settings = server.Settings(RustegonCredential.Scram(RustegonTestServer.AdminUser, server.AdminPassword));
        settings.ConnectionsPerEndpoint = 2;
        await using var client = new RustegonClient(settings);
        WhoAmIResponse[] all = await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => client.WhoAmIAsync(TestContext.Current.CancellationToken)));
        Assert.All(all, r => Assert.Equal(RustegonTestServer.AdminUser, r.User));
        // One session: every call saw the same expiry (a second login would have a later one).
        Assert.Single(all.Select(r => r.ExpiresAtUnixMs).Distinct());
    }

    [Fact]
    public async Task tc_drv_net_010_server_certificate_must_chain_to_the_configured_ca()
    {
        RustegonTestServer server = _fixture.Require();
        // Without the node CA the operating system store is used, which does not trust it.
        RustegonClientSettings settings = server.Settings(null);
        settings.Tls = new TlsSettings { Enabled = true };
        await using var client = new RustegonClient(settings);
        await Assert.ThrowsAsync<UnavailableException>(() => client.PingAsync(TestContext.Current.CancellationToken));

        // A wrong expected server name fails too.
        RustegonClientSettings misnamed = server.Settings(null);
        misnamed.Tls.ServerName = "not-the-node.example.com";
        await using var other = new RustegonClient(misnamed);
        await Assert.ThrowsAsync<UnavailableException>(() => other.PingAsync(TestContext.Current.CancellationToken));

        // An expected name that is in the node certificate (SAN localhost) succeeds.
        RustegonClientSettings named = server.Settings(null);
        named.Tls.ServerName = "localhost";
        await using var good = new RustegonClient(named);
        await good.PingAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task tc_drv_net_010_cancellation_is_an_operation_canceled_exception()
    {
        RustegonTestServer server = _fixture.Require();
        await using var client = new RustegonClient(server.Settings(null));
        using var cts = new System.Threading.CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.PingAsync(cts.Token));
    }
}
