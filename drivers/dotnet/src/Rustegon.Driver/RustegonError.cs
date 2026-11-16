// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Rustegon.Driver;

/// <summary>
/// A Rustegon error as the server reports it (<c>ErrorDetail</c>, protocol.md §3/§7), or as the
/// driver derives it for client-side failures.
/// </summary>
/// <param name="Code">Numeric code (<c>RGN-&lt;code&gt;</c>, proto/errors.yaml); 0 when the server sent no detail.</param>
/// <param name="Name">Stable name, e.g. <c>DuplicateKey</c>.</param>
/// <param name="IsRetryable">Whether the operation may be retried.</param>
/// <param name="Committed">For commit errors: whether the transaction is known to have committed.</param>
/// <param name="Details">Structured details (never document contents or secrets).</param>
/// <param name="TraceId">W3C trace id of the failed request, when known.</param>
/// <param name="RetryAfter">Suggested wait before retrying (rate limiting and similar).</param>
public sealed record RustegonError(
    int Code,
    string Name,
    bool IsRetryable,
    bool? Committed,
    IReadOnlyDictionary<string, string> Details,
    string? TraceId,
    TimeSpan? RetryAfter)
{
    /// <summary>An empty details map.</summary>
    internal static readonly IReadOnlyDictionary<string, string> NoDetails =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>());

    /// <summary>A client-side error of a catalog code (proto/errors.yaml).</summary>
    internal static RustegonError Client(int code) =>
        new(code, ErrorCatalog.NameOf(code), ErrorCatalog.IsRetryable(code), null, NoDetails, null, null);

    /// <summary>The <c>RGN-&lt;code&gt;</c> text.</summary>
    /// <returns>The code text.</returns>
    public override string ToString() => $"RGN-{Code} {Name}";
}
