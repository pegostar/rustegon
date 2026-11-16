// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;

namespace Rustegon.Driver.Internal;

/// <summary>
/// The R1 session (PD-069): remembers the last <c>rgn-causality-token</c> trailer and sends it on
/// later operations of the session (protocol.md §2). Thread-safe: the token is a single reference
/// read and written atomically; with concurrent operations the last trailer seen wins, which is
/// what a causality token allows (tokens only ever move forward on the server).
/// </summary>
internal sealed class ClientSession : IClientSession
{
    internal const string CausalityTokenHeader = "rgn-causality-token";

    private string? _token;
    private int _closed;

    internal ClientSession(bool causalConsistency)
    {
        CausalConsistency = causalConsistency;
    }

    public string? CausalityToken => Volatile.Read(ref _token);

    public bool CausalConsistency { get; }

    /// <summary>The token to send on the next operation, or null; using a closed session is a caller bug.</summary>
    internal string? TokenToSend
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _closed) != 0, this);
            return CausalConsistency ? CausalityToken : null;
        }
    }

    /// <summary>Takes the causality token of a response's trailers, when present.</summary>
    internal void Observe(Metadata trailers)
    {
        string? token = trailers.GetValue(CausalityTokenHeader);
        if (!string.IsNullOrEmpty(token))
        {
            Volatile.Write(ref _token, token);
        }
    }

    /// <summary>Closes the session (idempotent; there is no server-side state in R1).</summary>
    /// <returns>A completed task.</returns>
    public ValueTask DisposeAsync()
    {
        Volatile.Write(ref _closed, 1);
        return ValueTask.CompletedTask;
    }

    /// <summary>The session of an option, checked to be one of this driver's.</summary>
    internal static ClientSession? Of(IClientSession? session) => session switch
    {
        null => null,
        ClientSession s => s,
        _ => throw new ArgumentException("The session was not created by RustegonClient.StartSessionAsync.", nameof(session)),
    };
}
