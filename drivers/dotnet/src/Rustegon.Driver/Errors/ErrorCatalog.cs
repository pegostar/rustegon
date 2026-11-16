// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System.Text;
using Grpc.Core;
using Rustegon.Driver.Errors;

namespace Rustegon.Driver;

/// <summary>
/// Driver-side lookups over the generated catalog <see cref="ErrorCodes"/>
/// (<c>drivers/conformance/generated/ErrorCodes.g.cs</c>, compiled as is, PD-075).
/// </summary>
internal static class ErrorCatalog
{
    /// <summary>The name of a code (<c>RGN-&lt;code&gt;</c> for an unknown one, e.g. from a newer server).</summary>
    internal static string NameOf(int code) => ErrorCodes.Find(code)?.Name ?? $"RGN-{code}";

    /// <summary>Whether a code is unconditionally retryable in the catalog.</summary>
    internal static bool IsRetryable(int code) => ErrorCodes.Find(code)?.Retryable == ErrorRetryable.Yes;

    /// <summary>
    /// The transport fallback of a gRPC status without <c>ErrorDetail</c>
    /// (<c>errors-map.yaml</c> <c>transport</c>); the entry named <c>default</c> covers the others.
    /// </summary>
    internal static TransportFallback FallbackOf(StatusCode status)
    {
        string name = GoogleRpcName(status);
        TransportFallback? fallback = null;
        foreach (TransportFallback f in ErrorCodes.TransportFallbacks)
        {
            if (f.GrpcStatusName == name)
            {
                return f;
            }

            if (f.GrpcStatusName == "default")
            {
                fallback = f;
            }
        }

        // The generator guarantees a `default` entry (driver_tables.rs); Internal is the safe answer otherwise.
        return fallback ?? new TransportFallback("default", ErrorCodes.Internal, false, nameof(RustegonServerException));
    }

    /// <summary><c>DeadlineExceeded</c> → <c>DEADLINE_EXCEEDED</c> (google.rpc.Code names).</summary>
    internal static string GoogleRpcName(StatusCode status)
    {
        string pascal = status.ToString();
        var sb = new StringBuilder(pascal.Length + 4);
        for (int i = 0; i < pascal.Length; i++)
        {
            char c = pascal[i];
            if (i > 0 && char.IsAsciiLetterUpper(c))
            {
                sb.Append('_');
            }

            sb.Append(char.ToUpperInvariant(c));
        }

        return sb.ToString();
    }
}
