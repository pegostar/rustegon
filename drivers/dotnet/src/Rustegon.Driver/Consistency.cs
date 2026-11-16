// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

namespace Rustegon.Driver;

/// <summary>
/// Read consistency of a client (dotnet-driver.md §3/§6, consistency.md); connection-string option
/// <c>readConsistency</c> (<c>linearizable</c> | <c>bounded_staleness</c> | <c>follower</c>). Same
/// values as Java's <c>ReadConsistency</c>. Null in the settings means the server default
/// (linearizable).
/// </summary>
public enum ReadConsistency
{
    /// <summary>Reads see every write committed before they started (leaseholder reads).</summary>
    Linearizable,

    /// <summary>Reads may lag by at most <see cref="RustegonClientSettings.MaxStaleness"/>.</summary>
    BoundedStaleness,

    /// <summary>Reads from any replica, without a staleness bound.</summary>
    Follower,
}

/// <summary>
/// Write concern of a client (dotnet-driver.md §3, consistency.md); connection-string option
/// <c>writeConcern</c>. Same values as Java's <c>WriteConcern</c>. Null in the settings means the
/// server default (majority).
/// </summary>
public enum WriteConcern
{
    /// <summary>Acknowledged by a majority of the replicas.</summary>
    Majority,

    /// <summary>Acknowledged by every replica.</summary>
    All,

    /// <summary>Acknowledged by a majority in the local data centre.</summary>
    LocalDcMajority,

    /// <summary>Synchronously replicated across data centres.</summary>
    SyncCrossDc,

    /// <summary>Asynchronously replicated across data centres.</summary>
    AsyncCrossDc,
}
