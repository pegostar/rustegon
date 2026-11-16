// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Linq;

namespace Rustegon.Driver;

/// <summary>Versions and capabilities of a server (<c>SessionService.GetServerInfo</c>, protocol.md §9).</summary>
/// <param name="ServerVersion">Server version (semver).</param>
/// <param name="ProtocolVersion">Wire protocol version <c>1.&lt;minor&gt;</c>.</param>
/// <param name="Features">Capability flags; drivers gate features on these, not on versions.</param>
/// <param name="NodeAddresses">Client endpoints of cluster nodes (topology hint).</param>
public sealed record ServerInfo(
    string ServerVersion,
    string ProtocolVersion,
    IReadOnlyList<string> Features,
    IReadOnlyList<string> NodeAddresses)
{
    /// <summary>Whether the server announces a capability flag.</summary>
    /// <param name="feature">Flag name, e.g. <c>vector</c>.</param>
    /// <returns>Whether the flag is present.</returns>
    public bool HasFeature(string feature) => Features.Contains(feature, StringComparer.Ordinal);
}
