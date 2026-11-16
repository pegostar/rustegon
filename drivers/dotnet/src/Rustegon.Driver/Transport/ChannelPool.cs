// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Grpc.Net.Client;

namespace Rustegon.Driver.Internal.Transport;

/// <summary>
/// The client's gRPC channels: <see cref="RustegonClientSettings.ConnectionsPerEndpoint"/>
/// channels per endpoint, each over its own <see cref="SocketsHttpHandler"/> (dotnet-driver.md §3,
/// protocol.md §5.3: HTTP/2 keepalive 30 s / 10 s, several HTTP/2 connections when the server's
/// stream limit is reached). Calls pick a channel by power-of-two-choices on in-flight requests.
/// </summary>
/// <remarks>
/// Thread-safe. The slot array is immutable after construction; each slot's in-flight counter is
/// changed only with <see cref="Interlocked"/> and read without a lock (a stale read merely makes
/// a slightly worse choice). A failed connection is retried by the channel itself
/// (exponential backoff from 1 s, capped at <see cref="MaxReconnectBackoff"/>); calls made
/// meanwhile fail fast as Unavailable. Endpoint ejection and topology refresh come with M5.
/// </remarks>
internal sealed class ChannelPool : IDisposable
{
    /// <summary>HTTP/2 keepalive ping interval (protocol.md §5.3).</summary>
    internal static readonly TimeSpan KeepAliveInterval = TimeSpan.FromSeconds(30);

    /// <summary>Keepalive acknowledgement timeout (protocol.md §5.3).</summary>
    internal static readonly TimeSpan KeepAliveTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Cap of the channel's reconnect backoff after a connection failure (PD-119, TC-DRV-NET-029):
    /// gRPC's default cap is 120 s, so a node back after a long outage would stay unreachable for
    /// up to two minutes; 5 s matches the shortest endpoint ejection of dotnet-driver.md §3.
    /// </summary>
    internal static readonly TimeSpan MaxReconnectBackoff = TimeSpan.FromSeconds(5);

    /// <summary>Message size limit: documents are ≤ 16 MiB, bulk requests ≤ 48 MiB (protocol.md §5.4).</summary>
    private const int MaxMessageSize = 64 * 1024 * 1024;

    private readonly Slot[] _slots;

    /// <param name="endpoints">The endpoints.</param>
    /// <param name="settings">The settings.</param>
    /// <param name="tls">The TLS material.</param>
    /// <param name="handler">Test hook: an in-process HTTP/2 handler (the fake gRPC server of
    /// retry.yaml, PD-073) used instead of sockets; null in production.</param>
    internal ChannelPool(IReadOnlyList<Endpoint> endpoints, RustegonClientSettings settings, TlsMaterial tls, HttpMessageHandler? handler = null)
    {
        var interceptor = new RustegonInterceptor(settings.DefaultOperationTimeout);
        var slots = new List<Slot>();
        foreach (Endpoint e in endpoints)
        {
            for (int i = 0; i < settings.ConnectionsPerEndpoint; i++)
            {
                GrpcChannel channel = handler is null
                    ? CreateChannel(e, settings, tls)
                    : GrpcChannel.ForAddress(new Uri($"http://{e.Authority}"), new GrpcChannelOptions { HttpHandler = handler, DisposeHttpClient = false });
                slots.Add(new Slot(e, channel, channel.Intercept(interceptor)));
            }
        }

        _slots = [.. slots];
    }

    private static GrpcChannel CreateChannel(Endpoint endpoint, RustegonClientSettings settings, TlsMaterial tls)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = settings.ConnectTimeout,
            EnableMultipleHttp2Connections = true,
            KeepAlivePingDelay = KeepAliveInterval,
            KeepAlivePingTimeout = KeepAliveTimeout,
            KeepAlivePingPolicy = HttpKeepAlivePingPolicy.Always,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
        };
        string authority = endpoint.Authority;
        if (settings.UseTls)
        {
            handler.SslOptions = tls.SslOptions(endpoint);
            if (tls.ServerName is not null)
            {
                // SocketsHttpHandler takes the TLS target name (SNI and certificate check) from the
                // request URI, not from SslOptions.TargetHost: address the channel by the expected
                // name and connect the socket to the real endpoint.
                authority = new Endpoint(tls.ServerName, endpoint.Port).Authority;
                handler.ConnectCallback = (_, ct) => ConnectAsync(endpoint, ct);
            }
        }

        string scheme = settings.UseTls ? "https" : "http";
        return GrpcChannel.ForAddress(new Uri($"{scheme}://{authority}"), new GrpcChannelOptions
        {
            HttpHandler = handler,
            DisposeHttpClient = true,
            MaxReceiveMessageSize = MaxMessageSize,
            MaxSendMessageSize = MaxMessageSize,
            MaxReconnectBackoff = MaxReconnectBackoff,
        });
    }

    private static async ValueTask<Stream> ConnectAsync(Endpoint endpoint, CancellationToken cancellationToken)
    {
        // Ownership moves to the NetworkStream on success and is released in the catch otherwise.
#pragma warning disable CA2000
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
#pragma warning restore CA2000
        try
        {
            await socket.ConnectAsync(endpoint.Host, endpoint.Port, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>Picks a channel (power of two choices on in-flight calls) and counts the call in.</summary>
    /// <param name="avoid">The channel of a failed previous attempt: a retry goes to another one when
    /// there is one, so a channel still in its reconnect backoff (e.g. after a node restart, PD-119)
    /// does not fail the retry too.</param>
    internal Lease Acquire(Slot? avoid = null)
    {
        Slot chosen;
        if (_slots.Length == 1)
        {
            chosen = _slots[0];
        }
        else
        {
            Slot a = Pick(avoid);
            Slot b = Pick(avoid);
            chosen = Volatile.Read(ref b.InFlight) < Volatile.Read(ref a.InFlight) ? b : a;
        }

        Interlocked.Increment(ref chosen.InFlight);
        return new Lease(chosen);
    }

    private Slot Pick(Slot? avoid)
    {
        if (avoid is null)
        {
            return _slots[RandomNumberGenerator.GetInt32(_slots.Length)];
        }

        // Uniform over the other slots: skip the avoided index by shifting the ones after it.
        int i = RandomNumberGenerator.GetInt32(_slots.Length - 1);
        int avoided = Array.IndexOf(_slots, avoid);
        return _slots[avoided >= 0 && i >= avoided ? i + 1 : i];
    }

    /// <summary>Number of channels: <see cref="RustegonClientSettings.ConnectionsPerEndpoint"/> per endpoint, fixed at construction.</summary>
    internal int ChannelCount => _slots.Length;

    /// <summary>Calls currently counted in on any channel (a snapshot; 0 when the client is idle).</summary>
    internal int InFlight
    {
        get
        {
            int n = 0;
            foreach (Slot s in _slots)
            {
                n += Volatile.Read(ref s.InFlight);
            }

            return n;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        foreach (Slot s in _slots)
        {
            s.Channel.Dispose();
        }
    }

    /// <summary>One channel and its in-flight counter.</summary>
    internal sealed class Slot
    {
        internal Slot(Endpoint endpoint, GrpcChannel channel, CallInvoker invoker)
        {
            Endpoint = endpoint;
            Channel = channel;
            Invoker = invoker;
        }

        internal Endpoint Endpoint { get; }

        internal GrpcChannel Channel { get; }

        internal CallInvoker Invoker { get; }

        // Only touched through Interlocked/Volatile (see the class remarks).
#pragma warning disable CA1051 // A ref-able field is needed for Interlocked.
        internal int InFlight;
#pragma warning restore CA1051
    }

    /// <summary>A channel in use by one call; disposing counts the call out.</summary>
    internal readonly struct Lease : IDisposable
    {
        private readonly Slot _slot;

        internal Lease(Slot slot)
        {
            _slot = slot;
        }

        internal CallInvoker Invoker => _slot.Invoker;

        internal Endpoint Endpoint => _slot.Endpoint;

        internal Slot Slot => _slot;

        public void Dispose() => Interlocked.Decrement(ref _slot.InFlight);
    }
}
