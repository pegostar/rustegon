// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Google.Protobuf;
using Grpc.Core;
using Rustegon.V1;
using Rustegon.Driver.Errors;

namespace Rustegon.Driver;

/// <summary>
/// Maps server errors onto the exception hierarchy of dotnet-driver.md §8. The code → exception
/// table is <c>drivers/conformance/errors-map.yaml</c>, joined with the catalog into the generated
/// <see cref="ErrorCodes"/> (PD-075): the class is chosen by <see cref="ErrorCodeInfo.ExceptionType"/>
/// only, so a re-blessed table changes the mapping without touching this file.
/// </summary>
internal static class ErrorMapper
{
    /// <summary>Creates the exception of an error code (unknown codes → <see cref="RustegonException"/>).</summary>
    internal static RustegonException Create(RustegonError error, string message, Exception? inner = null)
    {
        ArgumentNullException.ThrowIfNull(error);
        string type = ErrorCodes.Find(error.Code)?.ExceptionType ?? ErrorCodes.UnknownCodeExceptionType;
        return CreateByType(type, error, message, inner);
    }

    /// <summary>
    /// The exception of a class name of the generated table. A name this driver does not know
    /// (a table generated for a newer hierarchy) falls back to the base class rather than failing;
    /// <c>tc_drv_net_006_every_generated_exception_type_is_known</c> keeps the list complete.
    /// </summary>
    internal static RustegonException CreateByType(string exceptionType, RustegonError error, string message, Exception? inner = null) => exceptionType switch
    {
        nameof(RustegonClientException) => new RustegonClientException(error, message, inner),
        nameof(QuerySyntaxException) => new QuerySyntaxException(error, message, inner),
        nameof(DuplicateKeyException) => new DuplicateKeyException(error, message, inner),
        nameof(DocumentValidationException) => new DocumentValidationException(error, message, inner),
        nameof(TransactionConflictException) => new TransactionConflictException(error, message, inner),
        nameof(TransactionAbortedException) => new TransactionAbortedException(error, message, inner),
        nameof(CommitOutcomeUnknownException) => new CommitOutcomeUnknownException(error, message, inner),
        nameof(AuthenticationException) => new AuthenticationException(error, message, inner),
        nameof(PasswordChangeRequiredException) => new PasswordChangeRequiredException(error, message, inner),
        nameof(AuthorizationException) => new AuthorizationException(error, message, inner),
        nameof(UnavailableException) => new UnavailableException(error, message, inner),
        nameof(RateLimitedException) => new RateLimitedException(error, message, inner),
        nameof(TimeoutException) => new TimeoutException(error, message, inner),
        nameof(RustegonServerException) => new RustegonServerException(error, message, inner),
        _ => new RustegonException(error, message, inner),
    };

    /// <summary>
    /// Converts a gRPC failure: the <c>ErrorDetail</c> of the <c>grpc-status-details-bin</c>
    /// trailer when present (protocol.md §3), else a code derived from the gRPC status (transport
    /// failures, proxies, servers that crashed before answering).
    /// </summary>
    internal static RustegonException FromRpcException(RpcException ex)
    {
        ArgumentNullException.ThrowIfNull(ex);
        string message = string.IsNullOrEmpty(ex.Status.Detail) ? ex.StatusCode.ToString() : ex.Status.Detail;
        ErrorDetail? detail = TryGetDetail(ex);
        if (detail is not null)
        {
            return Create(FromDetail(detail), message, ex);
        }

        // errors-map.yaml `transport`: the fallback names the class as well as the code, so a
        // bare status is mapped by the fallback entry, not by the code it synthesizes.
        TransportFallback fallback = ErrorCatalog.FallbackOf(IsConnectionFailure(ex) ? StatusCode.Unavailable : ex.StatusCode);
        return CreateByType(fallback.ExceptionType, FromFallback(fallback), message, ex);
    }

    /// <summary>
    /// Grpc.Net reports a failed connection (refused, reset, TLS handshake or certificate
    /// failure) as <c>Internal</c> or <c>Unavailable</c> with the HTTP exception attached, and an
    /// expired <see cref="RustegonClientSettings.ConnectTimeout"/> as <c>Cancelled</c> with a
    /// <see cref="System.TimeoutException"/> inside (the caller's own cancellation is handled
    /// before mapping); the server never saw the call, so it is RGN-3002 Unavailable (another
    /// node may be reachable).
    /// </summary>
    private static bool IsConnectionFailure(RpcException ex) => ex.StatusCode switch
    {
        StatusCode.Internal or StatusCode.Unavailable =>
            ex.Status.DebugException is System.Net.Http.HttpRequestException or System.IO.IOException or System.Net.Sockets.SocketException,
        StatusCode.Cancelled => HasConnectTimeout(ex.Status.DebugException),
        _ => false,
    };

    private static bool HasConnectTimeout(Exception? e)
    {
        for (; e is not null; e = e.InnerException)
        {
            if (e is System.TimeoutException)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when a failed call may have reached the server: no <c>ErrorDetail</c> (so not an
    /// answer of the server's error path) and no proof that nothing was sent (connection refused,
    /// unreachable host, TLS handshake failure, connect timeout). A <c>Commit</c> failing this way
    /// may have been applied: its outcome is unknown (PD-119, as Java PD-122).
    /// </summary>
    internal static bool MayHaveReachedServer(RpcException ex)
    {
        ArgumentNullException.ThrowIfNull(ex);
        if (TryGetDetail(ex) is not null || (ex.StatusCode == StatusCode.Cancelled && HasConnectTimeout(ex.Status.DebugException)))
        {
            return false;
        }

        for (Exception? e = ex.Status.DebugException; e is not null; e = e.InnerException)
        {
            if (e is System.Security.Authentication.AuthenticationException
                || (e is System.Net.Sockets.SocketException s && s.SocketErrorCode is System.Net.Sockets.SocketError.ConnectionRefused
                    or System.Net.Sockets.SocketError.HostNotFound or System.Net.Sockets.SocketError.HostUnreachable
                    or System.Net.Sockets.SocketError.NetworkUnreachable or System.Net.Sockets.SocketError.AddressNotAvailable))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The error of an <c>ErrorDetail</c>.</summary>
    internal static RustegonError FromDetail(ErrorDetail d)
    {
        IReadOnlyDictionary<string, string> details = d.Details.Count == 0
            ? RustegonError.NoDetails
            : new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(d.Details));
        return new RustegonError(
            (int)d.Code,
            string.IsNullOrEmpty(d.Name) ? ErrorCatalog.NameOf((int)d.Code) : d.Name,
            d.Retryable,
            d.HasCommitted ? d.Committed : null,
            details,
            string.IsNullOrEmpty(d.TraceId) ? null : d.TraceId,
            d.HasRetryAfterMs ? TimeSpan.FromMilliseconds(d.RetryAfterMs) : null);
    }

    /// <summary>The error a transport fallback synthesizes: its code and its retryable flag.</summary>
    internal static RustegonError FromFallback(TransportFallback fallback)
    {
        ArgumentNullException.ThrowIfNull(fallback);
        return new RustegonError(fallback.Code, ErrorCatalog.NameOf(fallback.Code), fallback.Retryable, null, RustegonError.NoDetails, null, null);
    }

    /// <summary>The error that stands for a bare gRPC status (errors-map.yaml <c>transport</c>).</summary>
    internal static RustegonError FromStatus(StatusCode status) => FromFallback(ErrorCatalog.FallbackOf(status));

    private static ErrorDetail? TryGetDetail(RpcException ex)
    {
        try
        {
            Google.Rpc.Status? status = ex.GetRpcStatus();
            return status?.GetDetail<ErrorDetail>();
        }
        catch (InvalidProtocolBufferException)
        {
            // A corrupt trailer must not hide the original failure: fall back to the status code.
            return null;
        }
    }
}
