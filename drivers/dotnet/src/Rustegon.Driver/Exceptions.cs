// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Rustegon.Driver;

/// <summary>
/// Base of every error the driver raises for a Rustegon error code (dotnet-driver.md §8). The
/// subclass is chosen from the code (<c>proto/errors.yaml</c>); the properties come from the
/// server's <c>ErrorDetail</c>.
/// </summary>
public class RustegonException : Exception
{
    /// <summary>Creates an exception for an error.</summary>
    /// <param name="error">The error.</param>
    /// <param name="message">Human-readable message (never secrets or document contents).</param>
    /// <param name="innerException">The transport exception, when there is one.</param>
    public RustegonException(RustegonError error, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        ArgumentNullException.ThrowIfNull(error);
        Error = error;
    }

    /// <summary>The full error.</summary>
    public RustegonError Error { get; }

    /// <summary>Numeric error code (RGN-&lt;code&gt;).</summary>
    public int Code => Error.Code;

    /// <summary>Stable error name.</summary>
    public string Name => Error.Name;

    /// <summary>Whether the operation may be retried.</summary>
    public bool IsRetryable => Error.IsRetryable;

    /// <summary>For commit errors: whether the transaction is known to have committed.</summary>
    public bool? Committed => Error.Committed;

    /// <summary>Structured details.</summary>
    public IReadOnlyDictionary<string, string> Details => Error.Details;

    /// <summary>W3C trace id of the failed request.</summary>
    public string? TraceId => Error.TraceId;
}

/// <summary>An error caused by the request (RGN-1xxx and similar): fix the request, do not retry.</summary>
public class RustegonClientException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public RustegonClientException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>
/// A document or value that the RDoc codec or the extended-JSON parser rejects (RGN-1001 malformed,
/// RGN-1002 too large, RGN-1003 too deep, RGN-1004 invalid field name, RGN-1040 invalid vector).
/// Raised on the client before anything is sent.
/// </summary>
public sealed class RDocException : RustegonClientException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="code">The error code.</param>
    /// <param name="message">What is wrong.</param>
    /// <param name="position">Byte (RDoc) or character (JSON) offset, when known.</param>
    public RDocException(int code, string message, long? position = null)
        : base(RustegonError.Client(code), position is null ? message : $"{message} (at offset {position})")
    {
        Position = position;
    }

    /// <summary>Byte (RDoc) or character (JSON) offset of the problem, when known.</summary>
    public long? Position { get; }
}

/// <summary>
/// RGQL text or a structured query the server cannot parse or type-check (RGN-1010
/// QuerySyntaxError, RGN-1011 QueryTypeError, RGN-1012 UnknownFunction;
/// <c>drivers/conformance/errors-map.yaml</c>, PD-075).
/// </summary>
public class QuerySyntaxException : RustegonClientException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public QuerySyntaxException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>A unique index rejected a write (RGN-1005).</summary>
public sealed class DuplicateKeyException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public DuplicateKeyException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>A collection validator rejected a document (RGN-1006).</summary>
public sealed class DocumentValidationException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public DocumentValidationException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>A transaction conflicted with another one (RGN-2001, 2005, 2007, 2008); retryable as a whole.</summary>
public sealed class TransactionConflictException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public TransactionConflictException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>The transaction was aborted (RGN-2002; retryability depends on the reason).</summary>
public sealed class TransactionAbortedException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public TransactionAbortedException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>
/// The commit outcome is unknown (RGN-2006): never retry blindly, resolve it through the
/// transaction status (transactions.md §5).
/// </summary>
public sealed class CommitOutcomeUnknownException : RustegonException
{
    private Func<CancellationToken, Task<TransactionOutcome>>? _resolver;

    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public CommitOutcomeUnknownException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }

    /// <summary>
    /// Asks the server for the transaction's outcome (<c>TransactionService.Status</c>,
    /// transactions.md §5): <see cref="TransactionOutcome.Committed"/>,
    /// <see cref="TransactionOutcome.Aborted"/>, or <see cref="TransactionOutcome.Unknown"/> while
    /// the commit is still in progress (ask again later; never re-run the transaction blindly).
    /// </summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The outcome.</returns>
    /// <exception cref="InvalidOperationException">The exception was not raised by a commit of this driver.</exception>
    public Task<TransactionOutcome> ResolveAsync(CancellationToken cancellationToken = default) =>
        _resolver?.Invoke(cancellationToken)
        ?? throw new InvalidOperationException("This exception was not raised by ITransaction.CommitAsync; there is no transaction to resolve.");

    /// <summary>Binds the exception to the transaction whose commit raised it.</summary>
    internal void AttachResolver(Func<CancellationToken, Task<TransactionOutcome>> resolver) => _resolver = resolver;
}

/// <summary>Authentication failed (RGN-4001; RGN-4005 expired session; RGN-4007 account locked).</summary>
public class AuthenticationException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public AuthenticationException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>
/// The account must change its password before other operations are allowed (PD-076). Raised by
/// the login unless <see cref="RustegonClientSettings.AllowPasswordChangeOnly"/> is set.
/// </summary>
public sealed class PasswordChangeRequiredException : AuthenticationException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public PasswordChangeRequiredException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>The principal lacks a privilege (RGN-4002).</summary>
public sealed class AuthorizationException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public AuthorizationException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>The node or range is unavailable (RGN-3xxx, or a transport failure); retryable, possibly on another node.</summary>
public sealed class UnavailableException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public UnavailableException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>The request was rate limited (RGN-4003); retry after <see cref="RetryAfter"/>.</summary>
public sealed class RateLimitedException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public RateLimitedException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }

    /// <summary>Suggested wait before retrying, when the server gave one.</summary>
    public TimeSpan? RetryAfter => Error.RetryAfter;
}

/// <summary>
/// A deadline expired (RGN-5006 DeadlineExceeded, RGN-2003 TransactionTimeout, RGN-1024, RGN-3006
/// with <see cref="RustegonException.Committed"/> = true). Not <see cref="System.TimeoutException"/>:
/// the name follows dotnet-driver.md §8 and the shared exception names of both drivers.
/// </summary>
public sealed class TimeoutException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public TimeoutException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}

/// <summary>A server-side failure (RGN-5xxx except 5006, RGN-4006).</summary>
public sealed class RustegonServerException : RustegonException
{
    /// <inheritdoc cref="RustegonException(RustegonError, string, Exception?)"/>
    public RustegonServerException(RustegonError error, string message, Exception? innerException = null)
        : base(error, message, innerException)
    {
    }
}
