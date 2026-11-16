// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Diagnostics;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Rustegon.Driver.Internal.Transport;

/// <summary>
/// Adds the common request metadata of protocol.md §2 to every call that does not carry it yet:
/// <c>rgn-request-id</c> (UUIDv7, RFC 9562), the default deadline (sent as <c>grpc-timeout</c>),
/// and the W3C <c>traceparent</c> of the current activity. The executor sets the request id itself
/// so that retries of one operation share it (idempotency, protocol.md §5.1); the authorization
/// header is added by the executor after the session authenticator produced it.
/// </summary>
internal sealed class RustegonInterceptor : Interceptor
{
    internal const string RequestIdHeader = "rgn-request-id";
    internal const string TraceParentHeader = "traceparent";

    private readonly TimeSpan _defaultTimeout;

    internal RustegonInterceptor(TimeSpan defaultTimeout)
    {
        _defaultTimeout = defaultTimeout;
    }

    /// <summary>A new request id: canonical lowercase hyphenated UUIDv7.</summary>
    internal static string NewRequestId() => Guid.CreateVersion7().ToString("D");

    private ClientInterceptorContext<TRequest, TResponse> Decorate<TRequest, TResponse>(ClientInterceptorContext<TRequest, TResponse> context)
        where TRequest : class
        where TResponse : class
    {
        CallOptions options = context.Options;
        Metadata headers = options.Headers ?? new Metadata();
        if (headers.Get(RequestIdHeader) is null)
        {
            headers.Add(RequestIdHeader, NewRequestId());
        }

        Activity? activity = Activity.Current;
        if (activity is { IdFormat: ActivityIdFormat.W3C } && headers.Get(TraceParentHeader) is null)
        {
            headers.Add(TraceParentHeader, activity.Id!);
        }

        options = options.WithHeaders(headers);
        if (options.Deadline is null)
        {
            options = options.WithDeadline(DateTime.UtcNow + _defaultTimeout);
        }

        return new ClientInterceptorContext<TRequest, TResponse>(context.Method, context.Host, options);
    }

    /// <inheritdoc/>
    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        ArgumentNullException.ThrowIfNull(continuation);
        return continuation(request, Decorate(context));
    }

    /// <inheritdoc/>
    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncServerStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        ArgumentNullException.ThrowIfNull(continuation);
        return continuation(request, Decorate(context));
    }

    /// <inheritdoc/>
    public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncClientStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        ArgumentNullException.ThrowIfNull(continuation);
        return continuation(Decorate(context));
    }

    /// <inheritdoc/>
    public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncDuplexStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        ArgumentNullException.ThrowIfNull(continuation);
        return continuation(Decorate(context));
    }

    /// <inheritdoc/>
    public override TResponse BlockingUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        BlockingUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        // The driver is async only (dotnet-driver.md §4); a blocking call is a driver bug.
        throw new NotSupportedException("Rustegon.Driver makes no blocking gRPC calls.");
    }
}
