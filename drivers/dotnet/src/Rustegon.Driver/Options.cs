// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;

namespace Rustegon.Driver;

/// <summary>
/// Options every operation accepts (dotnet-driver.md §4, §6). Per-operation values override the
/// client settings; unset values use them.
/// </summary>
public abstract class OperationOptions
{
    /// <summary>Session whose causality token the operation sends and updates (ignored inside a transaction).</summary>
    public IClientSession? Session { get; set; }

    /// <summary>Deadline of this operation, retries included (sent as <c>grpc-timeout</c>); null = <see cref="RustegonClientSettings.DefaultOperationTimeout"/>.</summary>
    public TimeSpan? Timeout { get; set; }
}

/// <summary>Options of reads: per-operation read consistency (dotnet-driver.md §6, PD-095).</summary>
public abstract class ReadOperationOptions : OperationOptions
{
    /// <summary>Read consistency of this read; null = <see cref="RustegonClientSettings.ReadConsistency"/>. Ignored inside a transaction.</summary>
    public ReadConsistency? ReadConsistency { get; set; }

    /// <summary>Staleness bound for <see cref="Driver.ReadConsistency.BoundedStaleness"/> (required by it) and <see cref="Driver.ReadConsistency.Follower"/>; null = <see cref="RustegonClientSettings.MaxStaleness"/>.</summary>
    public TimeSpan? MaxStaleness { get; set; }
}

/// <summary>Options of writes: per-operation write concern.</summary>
public abstract class WriteOperationOptions : OperationOptions
{
    /// <summary>Write concern of this write; null = <see cref="RustegonClientSettings.WriteConcern"/>. Ignored inside a transaction (the transaction's applies at commit).</summary>
    public WriteConcern? WriteConcern { get; set; }
}

/// <summary>Options of <c>FindByIdAsync</c> and <c>Find</c>.</summary>
public sealed class FindOptions : ReadOperationOptions
{
}

/// <summary>Options of <c>QueryAsync</c> (RGQL text; may read and write).</summary>
public sealed class QueryOptions : ReadOperationOptions
{
    /// <summary>Preferred rows per batch (the server caps it); null = server default.</summary>
    public int? BatchSize { get; set; }

    /// <summary>Write concern of a data-modifying statement; null = <see cref="RustegonClientSettings.WriteConcern"/>.</summary>
    public WriteConcern? WriteConcern { get; set; }
}

/// <summary>Options of <c>InsertOneAsync</c> / <c>InsertManyAsync</c>.</summary>
public sealed class InsertOptions : WriteOperationOptions
{
}

/// <summary>Options of <c>UpdateOneAsync</c> / <c>UpdateManyAsync</c>.</summary>
public sealed class UpdateOptions : WriteOperationOptions
{
    /// <summary>Expected current <c>_rev</c> (optimistic concurrency, by-id updates only); a different or missing document fails with RGN-2009 PreconditionFailed.</summary>
    public string? IfRev { get; set; }
}

/// <summary>Options of <c>ReplaceOneAsync</c>.</summary>
public sealed class ReplaceOptions : WriteOperationOptions
{
    /// <summary>Insert the replacement when no document has the id (needs <see cref="Filter.Id"/>).</summary>
    public bool IsUpsert { get; set; }

    /// <summary>Expected current <c>_rev</c> (by-id replacements only).</summary>
    public string? IfRev { get; set; }
}

/// <summary>Options of <c>DeleteOneAsync</c> / <c>DeleteManyAsync</c>.</summary>
public sealed class DeleteOptions : WriteOperationOptions
{
    /// <summary>Expected current <c>_rev</c> (by-id deletes only).</summary>
    public string? IfRev { get; set; }
}

/// <summary>
/// Options of <c>BulkWriteAsync</c>. R1 has <see cref="Ordered"/> only (PD-071): the server runs a
/// bulk write in one transaction where, outside an interactive transaction, failed operations
/// roll back alone and the others commit together (protocol.md §3).
/// </summary>
public sealed class BulkWriteOptions : WriteOperationOptions
{
    /// <summary>Stop at the first failed operation (default true) or attempt all.</summary>
    public bool Ordered { get; set; } = true;
}

/// <summary>Options of <c>CreateIndexAsync</c>.</summary>
public sealed class CreateIndexOptions : OperationOptions
{
    /// <summary>A unique index (duplicates fail with RGN-1005).</summary>
    public bool Unique { get; set; }
}

/// <summary>Options of <c>CreateDatabaseAsync</c>.</summary>
public sealed class CreateDatabaseOptions : OperationOptions
{
    /// <summary>Succeed (with <c>false</c>) when the database exists, instead of RGN-1031.</summary>
    public bool IfNotExists { get; set; }
}

/// <summary>Options of <c>CreateCollectionAsync</c>.</summary>
public sealed class CreateCollectionOptions : OperationOptions
{
    /// <summary>Succeed (with <c>false</c>) when the collection exists, instead of RGN-1031.</summary>
    public bool IfNotExists { get; set; }

    /// <summary>A JSON Schema validator, or null.</summary>
    public CollectionValidator? Validator { get; set; }
}

/// <summary>Options of the drop operations (databases, collections, indexes).</summary>
public sealed class DropOptions : OperationOptions
{
    /// <summary>Succeed (with <c>false</c>) when the object does not exist, instead of RGN-1030 / RGN-1021.</summary>
    public bool IfExists { get; set; }
}

/// <summary>A collection validator (JSON Schema 2020-12 subset, PD-027).</summary>
public sealed class CollectionValidator
{
    /// <summary>Creates a validator.</summary>
    /// <param name="jsonSchema">The JSON Schema as JSON text (the driver sends <c>{"$jsonSchema": &lt;schema&gt;}</c>).</param>
    public CollectionValidator(string jsonSchema)
    {
        ArgumentException.ThrowIfNullOrEmpty(jsonSchema);
        JsonSchema = jsonSchema;
    }

    /// <summary>The JSON Schema text.</summary>
    public string JsonSchema { get; }

    /// <summary>Which writes are validated; null = server default (strict).</summary>
    public ValidationLevel? Level { get; set; }

    /// <summary>What a violation does; null = server default (error).</summary>
    public ValidationAction? Action { get; set; }
}

/// <summary>Which writes a validator checks.</summary>
public enum ValidationLevel
{
    /// <summary>No validation.</summary>
    Off,

    /// <summary>Every insert and update.</summary>
    Strict,

    /// <summary>Inserts, and updates of documents that were valid.</summary>
    Moderate,
}

/// <summary>What a validator does with an invalid document.</summary>
public enum ValidationAction
{
    /// <summary>Reject the write with RGN-1006.</summary>
    Error,

    /// <summary>Accept the write and report a warning.</summary>
    Warn,
}

/// <summary>Options of <c>StartSessionAsync</c>.</summary>
public sealed class SessionOptions
{
    /// <summary>Causal consistency: send the last causality token on every operation (default true).</summary>
    public bool CausalConsistency { get; set; } = true;
}

/// <summary>Isolation level of a transaction (transactions.md §2).</summary>
public enum IsolationLevel
{
    /// <summary>Serializable (the server default).</summary>
    Serializable,

    /// <summary>Snapshot isolation.</summary>
    Snapshot,

    /// <summary>Read committed.</summary>
    ReadCommitted,
}

/// <summary>Options of <c>BeginTransactionAsync</c> and <c>WithTransactionAsync</c> (dotnet-driver.md §5).</summary>
public sealed class TransactionOptions
{
    /// <summary>Isolation level; null = server default (serializable).</summary>
    public IsolationLevel? Isolation { get; set; }

    /// <summary>Read-only transaction.</summary>
    public bool ReadOnly { get; set; }

    /// <summary>How long <c>WithTransactionAsync</c> keeps retrying (default 120 s, transactions.md §5).</summary>
    public TimeSpan MaxRetryTime { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Read consistency of a read-only transaction; null = the client setting (sent for read-only transactions only, consistency.md).</summary>
    public ReadConsistency? ReadConsistency { get; set; }

    /// <summary>Staleness bound of <see cref="ReadConsistency"/>; null = the client setting.</summary>
    public TimeSpan? MaxStaleness { get; set; }

    /// <summary>Write concern applied at commit; null = the client setting.</summary>
    public WriteConcern? WriteConcern { get; set; }
}
