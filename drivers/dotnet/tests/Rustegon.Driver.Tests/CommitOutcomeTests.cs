// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using Grpc.Core;
using Rustegon.Driver.Tests.Conformance;
using Xunit;

namespace Rustegon.Driver.Tests;

/// <summary>
/// A commit lost after it was sent has an unknown outcome (TC-DRV-NET-029, PD-119, as Java
/// PD-122): it surfaces as <see cref="CommitOutcomeUnknownException"/> (RGN-2006), and
/// <c>WithTransactionAsync</c> resolves it with <c>Status</c> instead of running the callback again.
/// Fake server (PD-073): a bare <c>UNAVAILABLE</c> status without <c>ErrorDetail</c> stands for a
/// reply lost after the request reached the node.
/// </summary>
public sealed class CommitOutcomeTests
{
    private static readonly Dictionary<string, object?> LostReply = new() { ["transport"] = "UNAVAILABLE" };

    private static RustegonClient Client(FakeGrpcServer fake)
    {
        var s = new RustegonClientSettings { Tls = new TlsSettings { Enabled = false }, Credential = RustegonCredential.ApiKey("rgn_fake_key"), DefaultDatabase = "fake" };
        s.Endpoints.Add("fake.invalid:7700");
        return new RustegonClient(s, fake);
    }

    [Fact]
    public async Task tc_drv_net_029_commit_reply_lost_is_commit_outcome_unknown()
    {
        var ct = TestContext.Current.CancellationToken;
        var fake = new FakeGrpcServer(new Dictionary<string, object?> { ["TransactionService.Commit"] = new List<object?> { LostReply } });
        await using RustegonClient client = Client(fake);
        await using ITransaction txn = await client.BeginTransactionAsync(cancellationToken: ct);
        await txn.Collection<RDocument>("c").InsertOneAsync(new RDocument { { "_id", 1 } }, cancellationToken: ct);

        CommitOutcomeUnknownException unknown = await Assert.ThrowsAsync<CommitOutcomeUnknownException>(() => txn.CommitAsync(ct));
        Assert.Equal(2006, unknown.Code);
        Assert.False(unknown.IsRetryable);
        Assert.Equal(TransactionOutcome.Committed, await unknown.ResolveAsync(ct));
        Assert.Equal(1, fake.Calls.Count(c => c.Rpc == "TransactionService.Commit"));
    }

    [Theory]
    [InlineData("TRANSACTION_STATE_COMMITTED", 1)]
    [InlineData("TRANSACTION_STATE_ABORTED", 2)]
    public async Task tc_drv_net_029_with_transaction_resolves_a_lost_commit_reply(string state, int expectedRuns)
    {
        var ct = TestContext.Current.CancellationToken;
        var fake = new FakeGrpcServer(new Dictionary<string, object?>
        {
            ["TransactionService.Commit"] = new List<object?> { LostReply, new Dictionary<string, object?> { ["ok"] = new Dictionary<string, object?>() } },
            ["TransactionService.Status"] = new List<object?> { new Dictionary<string, object?> { ["ok"] = new Dictionary<string, object?> { ["state"] = state } } },
        });
        await using RustegonClient client = Client(fake);
        int runs = 0;
        int result = await client.WithTransactionAsync(
            async (txn, token) =>
            {
                runs++;
                await txn.Collection<RDocument>("c").InsertOneAsync(new RDocument { { "_id", 1 } }, cancellationToken: token);
                return 7;
            },
            cancellationToken: ct);

        // Committed: the callback ran once (no double apply). Aborted: it definitely did not
        // commit, so the transaction is run again.
        Assert.Equal(7, result);
        Assert.Equal(expectedRuns, runs);
        Assert.Equal(1, fake.Calls.Count(c => c.Rpc == "TransactionService.Status"));
    }

    [Fact]
    public void tc_drv_net_029_failures_before_sending_are_not_ambiguous()
    {
        static RpcException Rpc(StatusCode code, Exception? debug) => new(new Status(code, "x", debug));

        // Nothing sent: connection refused, unreachable, TLS handshake failure, connect timeout.
        Assert.False(ErrorMapper.MayHaveReachedServer(Rpc(StatusCode.Unavailable, new SocketException((int)SocketError.ConnectionRefused))));
        Assert.False(ErrorMapper.MayHaveReachedServer(Rpc(StatusCode.Unavailable, new System.Net.Http.HttpRequestException("x", new SocketException((int)SocketError.HostUnreachable)))));
        Assert.False(ErrorMapper.MayHaveReachedServer(Rpc(StatusCode.Unavailable, new System.Security.Authentication.AuthenticationException("x"))));
        Assert.False(ErrorMapper.MayHaveReachedServer(Rpc(StatusCode.Cancelled, new System.Net.Http.HttpRequestException("x", new System.TimeoutException()))));

        // Possibly sent: reset or closed connection, deadline, bare status from the node.
        Assert.True(ErrorMapper.MayHaveReachedServer(Rpc(StatusCode.Unavailable, new IOException("reset", new SocketException((int)SocketError.ConnectionReset)))));
        Assert.True(ErrorMapper.MayHaveReachedServer(Rpc(StatusCode.DeadlineExceeded, null)));
        Assert.True(ErrorMapper.MayHaveReachedServer(Rpc(StatusCode.Unavailable, null)));
    }
}
