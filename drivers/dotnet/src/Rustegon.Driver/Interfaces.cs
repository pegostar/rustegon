// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Rustegon.Driver;

/// <summary>
/// A database (dotnet-driver.md §1, §4). A handle: creating one does no I/O. Obtained from
/// <see cref="RustegonClient.GetDatabase"/>, or from <see cref="ITransaction.GetDatabase"/> for
/// operations inside a transaction.
/// </summary>
public interface IRustegonDatabase
{
    /// <summary>Database name.</summary>
    string Name { get; }

    /// <summary>
    /// A collection handle (no I/O). <typeparamref name="T"/> is <see cref="RDocument"/> or a mapped
    /// type (<see cref="Mapping.RustegonDocumentAttribute"/>, or any type after
    /// <see cref="Mapping.RDocCodecRegistry.EnableReflectionFallback"/>; dotnet-driver.md §7).
    /// </summary>
    /// <typeparam name="T">Document type.</typeparam>
    /// <param name="name">Collection name.</param>
    /// <returns>The handle.</returns>
    /// <exception cref="NotSupportedException"><typeparamref name="T"/> has no codec.</exception>
    IRustegonCollection<T> GetCollection<T>(string name)
        where T : class;

    /// <summary>
    /// Runs RGQL text with parameters (never build RGQL from user input by string concatenation:
    /// pass values as <paramref name="parameters"/>, <c>$name</c> in the text; PD-096). Rows are
    /// documents; <c>SELECT VALUE</c> rows arrive as <c>{"value": x}</c>. Enumeration executes the
    /// statement; batches beyond the first are fetched with <c>GetMore</c>.
    /// </summary>
    /// <typeparam name="T">Row type.</typeparam>
    /// <param name="rgql">The statement.</param>
    /// <param name="parameters">Parameters by name (<c>$name</c>) or position (<c>"1"</c> for <c>$1</c>).</param>
    /// <param name="options">Options.</param>
    /// <returns>The rows.</returns>
    IAsyncEnumerable<T> QueryAsync<T>(string rgql, RDocument? parameters = null, QueryOptions? options = null)
        where T : class;

    /// <summary>Creates a collection.</summary>
    /// <param name="name">Collection name.</param>
    /// <param name="options">Options (validator, if-not-exists).</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Whether it was created (false only with <see cref="CreateCollectionOptions.IfNotExists"/>).</returns>
    Task<bool> CreateCollectionAsync(string name, CreateCollectionOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Drops a collection with its documents and indexes.</summary>
    /// <param name="name">Collection name.</param>
    /// <param name="options">Options (if-exists).</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Whether it was dropped (false only with <see cref="DropOptions.IfExists"/>).</returns>
    Task<bool> DropCollectionAsync(string name, DropOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>The collection names, sorted.</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The names.</returns>
    Task<IReadOnlyList<string>> ListCollectionNamesAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// A collection (dotnet-driver.md §1, §4). Writes with <see cref="Filter.Id"/> go to
/// <c>DocumentService</c>; any other filter runs as an RGQL statement built from the structured
/// AST (PD-070), single-document variants with <c>LIMIT 1</c> (the matching document with the
/// lowest <c>_id</c>).
/// </summary>
/// <typeparam name="T">Document type.</typeparam>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix", Justification = "The name is fixed by the Driver Conceptual Model (dotnet-driver.md §1).")]
public interface IRustegonCollection<T>
    where T : class
{
    /// <summary>Database name.</summary>
    string DatabaseName { get; }

    /// <summary>Collection name.</summary>
    string Name { get; }

    /// <summary>Inserts a document; the server generates an objectId <c>_id</c> when it has none.</summary>
    /// <param name="document">The document.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The id.</returns>
    Task<InsertOneResult> InsertOneAsync(T document, InsertOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Inserts documents atomically: one failure (e.g. a duplicate id) inserts none.</summary>
    /// <param name="documents">The documents.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The ids, in input order.</returns>
    Task<InsertManyResult> InsertManyAsync(IEnumerable<T> documents, InsertOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>The document with an id, or null.</summary>
    /// <param name="id">The id.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The document or null.</returns>
    Task<T?> FindByIdAsync(RDocValue id, FindOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>A find (no I/O until it is enumerated).</summary>
    /// <param name="filter">The filter (<see cref="Filter.Empty"/> for all documents).</param>
    /// <param name="options">Options.</param>
    /// <returns>The fluent find.</returns>
    IFindFluent<T> Find(Filter filter, FindOptions? options = null);

    /// <summary>Updates the document with <see cref="Filter.Id"/>, or the matching document with the lowest <c>_id</c>.</summary>
    /// <param name="filter">The filter.</param>
    /// <param name="update">The operators.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Counts.</returns>
    Task<UpdateResult> UpdateOneAsync(Filter filter, Update update, UpdateOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Updates every matching document (the empty filter updates all of them).</summary>
    /// <param name="filter">The filter.</param>
    /// <param name="update">The operators.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Counts.</returns>
    Task<UpdateResult> UpdateManyAsync(Filter filter, Update update, UpdateOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Replaces the whole document (its <c>_id</c> is kept); with <see cref="ReplaceOptions.IsUpsert"/> and <see cref="Filter.Id"/> inserts it when absent.</summary>
    /// <param name="filter">The filter.</param>
    /// <param name="replacement">The new document.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Counts and the upserted id.</returns>
    Task<UpdateResult> ReplaceOneAsync(Filter filter, T replacement, ReplaceOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes the document with <see cref="Filter.Id"/>, or the matching document with the lowest <c>_id</c>.</summary>
    /// <param name="filter">The filter.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The count.</returns>
    Task<DeleteResult> DeleteOneAsync(Filter filter, DeleteOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes every matching document (the empty filter deletes all of them).</summary>
    /// <param name="filter">The filter.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The count.</returns>
    Task<DeleteResult> DeleteManyAsync(Filter filter, DeleteOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Runs operations by id in one request (PD-071). Outside a transaction failed operations are
    /// reported in <see cref="BulkWriteResult.Errors"/> (not thrown); inside one any failure fails
    /// the call and undoes the whole bulk.
    /// </summary>
    /// <param name="operations">The operations.</param>
    /// <param name="options">Options.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Counts and per-operation errors.</returns>
    Task<BulkWriteResult> BulkWriteAsync(IEnumerable<BulkOperation<T>> operations, BulkWriteOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Creates an index and waits until its build has finished.</summary>
    /// <param name="name">Index name.</param>
    /// <param name="keys">Keys.</param>
    /// <param name="options">Options (unique).</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The index (state <see cref="IndexState.Ready"/>, or <see cref="IndexState.Failed"/> with the error).</returns>
    Task<IndexDescription> CreateIndexAsync(string name, IndexKeys keys, CreateIndexOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Drops an index.</summary>
    /// <param name="name">Index name.</param>
    /// <param name="options">Options (if-exists).</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Whether it was dropped (false only with <see cref="DropOptions.IfExists"/>).</returns>
    Task<bool> DropIndexAsync(string name, DropOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>The indexes, sorted by name.</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The indexes.</returns>
    Task<IReadOnlyList<IndexDescription>> ListIndexesAsync(CancellationToken cancellationToken = default);
}

/// <summary>A find being built (dotnet-driver.md §4); enumerating it runs the query.</summary>
/// <typeparam name="T">Document type.</typeparam>
public interface IFindFluent<T> : IAsyncEnumerable<T>
    where T : class
{
    /// <summary>Sort order (<c>ORDER BY</c>).</summary>
    /// <param name="sort">The order.</param>
    /// <returns>This find.</returns>
    IFindFluent<T> Sort(Sort sort);

    /// <summary>At most <paramref name="limit"/> documents (<c>LIMIT</c>).</summary>
    /// <param name="limit">A non-negative count.</param>
    /// <returns>This find.</returns>
    IFindFluent<T> Limit(int limit);

    /// <summary>Skips documents (<c>OFFSET</c>).</summary>
    /// <param name="skip">A non-negative count.</param>
    /// <returns>This find.</returns>
    IFindFluent<T> Skip(int skip);

    /// <summary>Projection (<c>SELECT</c>).</summary>
    /// <param name="projection">The projection.</param>
    /// <returns>This find.</returns>
    IFindFluent<T> Project(Projection projection);

    /// <summary>Preferred documents per batch (the server caps it).</summary>
    /// <param name="batchSize">A positive count.</param>
    /// <returns>This find.</returns>
    IFindFluent<T> BatchSize(int batchSize);

    /// <summary>Every document.</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The documents.</returns>
    Task<List<T>> ToListAsync(CancellationToken cancellationToken = default);

    /// <summary>The first document, or null.</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The document or null.</returns>
    Task<T?> FirstOrDefaultAsync(CancellationToken cancellationToken = default);

    /// <summary>Runs the query and returns a cursor positioned before the first document.</summary>
    /// <param name="cancellationToken">Cancellation of every call of the cursor.</param>
    /// <returns>The cursor; dispose it (an unfinished cursor is killed on the server).</returns>
    Task<IAsyncCursor<T>> ToCursorAsync(CancellationToken cancellationToken = default);

    /// <summary>The documents as an async sequence (runs the query when enumerated).</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The sequence.</returns>
    IAsyncEnumerable<T> ToAsyncEnumerable(CancellationToken cancellationToken = default);
}

/// <summary>
/// A server cursor (dotnet-driver.md §1): <see cref="IAsyncEnumerator{T}.MoveNextAsync"/> fetches
/// the next batch with <c>GetMore</c> when the current one is used up; disposing an unfinished
/// cursor kills it (<c>KillCursor</c>). A failed <c>GetMore</c> is not retried (retry.yaml R3).
/// </summary>
/// <typeparam name="T">Document type.</typeparam>
public interface IAsyncCursor<T> : IAsyncEnumerator<T>
{
}

/// <summary>
/// A client session (dotnet-driver.md §6). In R1 a pass-through of the causality token (PD-069):
/// operations given this session send the last <c>rgn-causality-token</c> and remember the one
/// the server returns.
/// </summary>
public interface IClientSession : IAsyncDisposable
{
    /// <summary>The last causality token, or null before the server returned one.</summary>
    string? CausalityToken { get; }

    /// <summary>Whether causal consistency is on (tokens are sent).</summary>
    bool CausalConsistency { get; }
}

/// <summary>
/// An interactive transaction (dotnet-driver.md §5, transactions.md). Operations through
/// <see cref="Collection{T}(string)"/>, <see cref="GetDatabase"/> and <see cref="QueryAsync{T}"/>
/// carry its id and are never retried alone. While it is open the driver sends heartbeats so the
/// server does not abort it as idle. <see cref="IAsyncDisposable.DisposeAsync"/> rolls back a
/// transaction that was neither committed nor rolled back.
/// </summary>
public interface ITransaction : IAsyncDisposable
{
    /// <summary>The transaction id.</summary>
    string TransactionId { get; }

    /// <summary>A collection in the transaction: <c>"db.coll"</c>, or <c>"coll"</c> in the client's default database.</summary>
    /// <typeparam name="T">Document type.</typeparam>
    /// <param name="name">The collection name.</param>
    /// <returns>The handle.</returns>
    IRustegonCollection<T> Collection<T>(string name)
        where T : class;

    /// <summary>A database whose operations run in the transaction.</summary>
    /// <param name="name">Database name.</param>
    /// <returns>The handle.</returns>
    IRustegonDatabase GetDatabase(string name);

    /// <summary>RGQL in the transaction, in the client's default database (see <see cref="IRustegonDatabase.QueryAsync{T}"/>).</summary>
    /// <typeparam name="T">Row type.</typeparam>
    /// <param name="rgql">The statement.</param>
    /// <param name="parameters">Parameters.</param>
    /// <param name="options">Options.</param>
    /// <returns>The rows.</returns>
    IAsyncEnumerable<T> QueryAsync<T>(string rgql, RDocument? parameters = null, QueryOptions? options = null)
        where T : class;

    /// <summary>Commits. On RGN-2006 the outcome is unknown: <see cref="CommitOutcomeUnknownException"/> carries <see cref="CommitOutcomeUnknownException.ResolveAsync"/>.</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>A task completing when committed.</returns>
    Task CommitAsync(CancellationToken cancellationToken = default);

    /// <summary>Rolls back (idempotent on the server).</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>A task completing when rolled back.</returns>
    Task RollbackAsync(CancellationToken cancellationToken = default);

    /// <summary>The transaction's state as the server reports it (<c>TransactionService.Status</c>).</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Committed, aborted, or unknown while active or committing.</returns>
    Task<TransactionOutcome> ResolveAsync(CancellationToken cancellationToken = default);
}

/// <summary>Factories of <see cref="BulkOperation{T}"/> (bulk operations address documents by <c>_id</c>, PD-071).</summary>
public static class BulkOperation
{
    /// <summary>Inserts a document.</summary>
    /// <typeparam name="T">Document type.</typeparam>
    /// <param name="document">The document.</param>
    /// <returns>The operation.</returns>
    public static BulkOperation<T> Insert<T>(T document)
        where T : class => new(BulkOperation<T>.OpKind.Insert, RDocValue.Missing, document ?? throw new ArgumentNullException(nameof(document)), null, null);

    /// <summary>Replaces the document with an id.</summary>
    /// <typeparam name="T">Document type.</typeparam>
    /// <param name="id">The id.</param>
    /// <param name="document">The new document.</param>
    /// <param name="ifRev">Expected current <c>_rev</c>, or null.</param>
    /// <returns>The operation.</returns>
    public static BulkOperation<T> Replace<T>(RDocValue id, T document, string? ifRev = null)
        where T : class => new(BulkOperation<T>.OpKind.Replace, CheckId(id), document ?? throw new ArgumentNullException(nameof(document)), null, ifRev);

    /// <summary>Updates the document with an id.</summary>
    /// <typeparam name="T">Document type.</typeparam>
    /// <param name="id">The id.</param>
    /// <param name="update">The operators.</param>
    /// <param name="ifRev">Expected current <c>_rev</c>, or null.</param>
    /// <returns>The operation.</returns>
    public static BulkOperation<T> Update<T>(RDocValue id, Update update, string? ifRev = null)
        where T : class => new(BulkOperation<T>.OpKind.Update, CheckId(id), null, update ?? throw new ArgumentNullException(nameof(update)), ifRev);

    /// <summary>Inserts the document, or replaces the one with its <c>_id</c> (the document needs an <c>_id</c>).</summary>
    /// <typeparam name="T">Document type.</typeparam>
    /// <param name="document">The document.</param>
    /// <returns>The operation.</returns>
    public static BulkOperation<T> Upsert<T>(T document)
        where T : class => new(BulkOperation<T>.OpKind.Upsert, RDocValue.Missing, document ?? throw new ArgumentNullException(nameof(document)), null, null);

    /// <summary>Deletes the document with an id.</summary>
    /// <typeparam name="T">Document type.</typeparam>
    /// <param name="id">The id.</param>
    /// <param name="ifRev">Expected current <c>_rev</c>, or null.</param>
    /// <returns>The operation.</returns>
    public static BulkOperation<T> Delete<T>(RDocValue id, string? ifRev = null)
        where T : class => new(BulkOperation<T>.OpKind.Delete, CheckId(id), null, null, ifRev);

    private static RDocValue CheckId(RDocValue id) =>
        id.IsMissing ? throw new ArgumentException("A bulk operation needs an id.", nameof(id)) : id;
}

/// <summary>One operation of a bulk write; create it with <see cref="BulkOperation"/>.</summary>
/// <typeparam name="T">Document type.</typeparam>
public sealed class BulkOperation<T>
    where T : class
{
    internal BulkOperation(OpKind kind, RDocValue id, T? document, Update? update, string? ifRev)
    {
        Kind = kind;
        Id = id;
        Document = document;
        UpdateDefinition = update;
        IfRev = ifRev;
    }

    internal enum OpKind
    {
        Insert,
        Replace,
        Update,
        Upsert,
        Delete,
    }

    internal OpKind Kind { get; }

    internal RDocValue Id { get; }

    internal T? Document { get; }

    internal Update? UpdateDefinition { get; }

    internal string? IfRev { get; }
}
