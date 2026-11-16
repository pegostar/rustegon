// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using Microsoft.CodeAnalysis;

namespace Rustegon.Driver.Generators;

/// <summary>Errors of the [RustegonDocument] generator: an unmappable type fails the build, not a run.</summary>
internal static class Diagnostics
{
    private const string Category = "Rustegon.Mapping";

    internal static readonly DiagnosticDescriptor UnsupportedMember = new(
        "RGNG001", "Member cannot be mapped", "{0}.{1} of type '{2}' cannot be mapped: {3}", Category, DiagnosticSeverity.Error, isEnabledByDefault: true);

    internal static readonly DiagnosticDescriptor NoConstructor = new(
        "RGNG002", "No usable constructor", "{0} has no public constructor whose parameters all match properties (name ignoring case, same type)", Category, DiagnosticSeverity.Error, isEnabledByDefault: true);

    internal static readonly DiagnosticDescriptor InvalidMapping = new(
        "RGNG003", "Invalid mapping", "{0} cannot be mapped: {1}", Category, DiagnosticSeverity.Error, isEnabledByDefault: true);

    internal static readonly DiagnosticDescriptor InvalidType = new(
        "RGNG004", "Invalid [RustegonDocument] type", "{0} cannot be a [RustegonDocument]: {1}", Category, DiagnosticSeverity.Error, isEnabledByDefault: true);
}
