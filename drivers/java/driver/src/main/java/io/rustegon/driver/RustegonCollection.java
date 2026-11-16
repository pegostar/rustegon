// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.ErrorMapper;
import io.rustegon.driver.internal.proto.AstCreateIndex;
import io.rustegon.driver.internal.proto.AstIndexKey;
import io.rustegon.driver.internal.proto.AstIndexType;
import io.rustegon.driver.internal.proto.AstPath;
import io.rustegon.driver.internal.proto.AstQualifiedName;
import io.rustegon.driver.internal.proto.AstSegment;
import io.rustegon.driver.internal.proto.BulkDelete;
import io.rustegon.driver.internal.proto.BulkInsert;
import io.rustegon.driver.internal.proto.BulkReplace;
import io.rustegon.driver.internal.proto.BulkUpdate;
import io.rustegon.driver.internal.proto.BulkUpsert;
import io.rustegon.driver.internal.proto.BulkWriteRequest;
import io.rustegon.driver.internal.proto.BulkWriteResponse;
import io.rustegon.driver.internal.proto.CreateIndexRequest;
import io.rustegon.driver.internal.proto.DeleteRequest;
import io.rustegon.driver.internal.proto.Document;
import io.rustegon.driver.internal.proto.DocumentServiceGrpc;
import io.rustegon.driver.internal.proto.DropIndexRequest;
import io.rustegon.driver.internal.proto.GetRequest;
import io.rustegon.driver.internal.proto.GetResponse;
import io.rustegon.driver.internal.proto.IndexBuildProgressRequest;
import io.rustegon.driver.internal.proto.InsertRequest;
import io.rustegon.driver.internal.proto.InsertResponse;
import io.rustegon.driver.internal.proto.ListIndexesRequest;
import io.rustegon.driver.internal.proto.ReplaceRequest;
import io.rustegon.driver.internal.proto.SchemaServiceGrpc;
import io.rustegon.driver.internal.proto.UpdateRequest;
import io.rustegon.driver.internal.proto.UpdateResponse;
import io.rustegon.driver.internal.proto.UpsertRequest;
import io.rustegon.driver.internal.proto.Value;
import io.rustegon.driver.internal.proto.WriteOptions;
import io.rustegon.driver.internal.proto.WriteResult;
import io.rustegon.driver.rdoc.RDocReader;
import io.rustegon.driver.rdoc.RDocument;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A collection handle (java-driver.md §3; {@code Collection.*} of the model). Creating one does
 * no I/O. Immutable and thread-safe.
 *
 * <p>Routing (PD-070): a filter that is exactly {@link Filters#id(Object)} sends single-document
 * writes to the by-id calls of {@code DocumentService} ({@code Update}, {@code Replace},
 * {@code Upsert}, {@code Delete}); any other filter runs an RGQL statement built as an AST
 * ({@code UPDATE … LIMIT 1} for the {@code …One} variants, which writes the matching document
 * with the lowest {@code _id}). Handles obtained from a {@link Transaction} run every call
 * inside it.
 *
 * @param <T> the document type
 */
public final class RustegonCollection<T> {
    /** Poll period while an index builds. */
    private static final long INDEX_POLL_MILLIS = 50;

    private final RustegonDatabase db;
    private final String name;
    private final DocCodec<T> codec;
    private final OpContext ctx;

    RustegonCollection(RustegonDatabase db, String name, DocCodec<T> codec, OpContext ctx) {
        this.db = db;
        this.name = Objects.requireNonNull(name, "name");
        this.codec = codec;
        this.ctx = ctx;
    }

    /**
     * The collection name.
     *
     * @return the name
     */
    public String name() {
        return name;
    }

    /**
     * The database handle.
     *
     * @return the database
     */
    public RustegonDatabase database() {
        return db;
    }

    OpContext context() {
        return ctx;
    }

    DocCodec<T> codec() {
        return codec;
    }

    private Operations ops() {
        return db.ops();
    }

    private RustegonCollection<T> with(OpContext c) {
        return new RustegonCollection<>(db, name, codec, c);
    }

    /**
     * This collection with calls carrying the causality token of {@code session} (PD-069).
     *
     * @param session the session
     * @return the handle
     */
    public RustegonCollection<T> withSession(ClientSession session) {
        return with(ctx.withSession(Objects.requireNonNull(session, "session")));
    }

    /**
     * This collection with another operation deadline.
     *
     * @param timeout a positive duration
     * @return the handle
     */
    public RustegonCollection<T> withTimeout(Duration timeout) {
        return with(ctx.withTimeout(RustegonDatabase.positive(timeout)));
    }

    /**
     * This collection with another read consistency (reads outside transactions).
     *
     * @param level the level
     * @return the handle
     */
    public RustegonCollection<T> withReadConsistency(ReadConsistency level) {
        return withReadConsistency(level, null);
    }

    /**
     * This collection with another read consistency and staleness bound.
     *
     * @param level the level
     * @param maxStaleness the bound, or {@code null}
     * @return the handle
     */
    public RustegonCollection<T> withReadConsistency(ReadConsistency level,
            Duration maxStaleness) {
        return with(ctx.withReadConsistency(RustegonDatabase.checkConsistency(level,
                maxStaleness), maxStaleness));
    }

    /**
     * This collection with another write concern (writes outside transactions).
     *
     * @param concern the concern
     * @return the handle
     */
    public RustegonCollection<T> withWriteConcern(WriteConcern concern) {
        return with(ctx.withWriteConcern(Objects.requireNonNull(concern, "concern")));
    }

    // ------------------------------------------------------------------ requests

    private Document document(T value) {
        return Document.newBuilder().setRdoc(Ast.document(codec.toDocument(
                Objects.requireNonNull(value, "document")))).build();
    }

    private WriteOptions writeOptions() {
        return WriteOptions.newBuilder().setWriteConcern(ops().writeConcern(ctx)).build();
    }

    private String txn() {
        return ctx.txnId();
    }

    // ------------------------------------------------------------------ inserts and reads

    /**
     * Inserts a document ({@code DocumentService.Insert}); a missing {@code _id} is generated
     * by the server (an objectId, placed first).
     *
     * @param document the document
     * @return the id
     * @throws DuplicateKeyException if the id exists
     * @throws RustegonException on other failures
     */
    public InsertOneResult insertOne(T document) {
        return new InsertOneResult(insert(List.of(document)).get(0));
    }

    /**
     * Inserts documents atomically: one failure (e.g. a duplicate id) inserts none.
     *
     * @param documents the documents (at least one)
     * @return the ids, in input order
     * @throws RustegonException on failure
     */
    public InsertManyResult insertMany(List<? extends T> documents) {
        return new InsertManyResult(insert(documents));
    }

    private List<Object> insert(List<? extends T> documents) {
        if (documents.isEmpty()) {
            throw new IllegalArgumentException("nothing to insert");
        }
        InsertRequest.Builder r = InsertRequest.newBuilder().setDatabase(db.name())
                .setCollection(name).setOptions(writeOptions());
        for (T d : documents) {
            r.addDocuments(document(d));
        }
        if (txn() != null) {
            r.setTxnId(txn());
        }
        InsertResponse resp = ops().unary(DocumentServiceGrpc.getInsertMethod(), r.build(),
                Operations.Kind.WRITE, ctx);
        List<Object> ids = new ArrayList<>(resp.getResultsCount());
        for (WriteResult w : resp.getResultsList()) {
            ids.add(Ast.decode(w.getId()));
        }
        return ids;
    }

    /**
     * Reads the document with id {@code id} ({@code DocumentService.Get}).
     *
     * @param id the id
     * @return the document, empty when none has the id
     * @throws RustegonException on failure
     */
    public Optional<T> findById(Object id) {
        GetRequest.Builder r = GetRequest.newBuilder().setDatabase(db.name()).setCollection(name)
                .setId(Ast.value(id));
        if (txn() != null) {
            r.setTxnId(txn());
        }
        var consistency = ops().readConsistency(ctx);
        if (consistency != null) {
            r.setConsistency(consistency);
        }
        GetResponse resp = ops().unary(DocumentServiceGrpc.getGetMethod(), r.build(),
                Operations.Kind.READ, ctx);
        return resp.hasDocument() ? Optional.of(decode(resp.getDocument())) : Optional.empty();
    }

    private T decode(Document d) {
        return codec.fromDocument(RDocReader.decode(d.getRdoc().toByteArray()));
    }

    /**
     * A query on the documents matching {@code filter}; runs when its result is read.
     *
     * @param filter the filter ({@link Filters})
     * @return the query
     */
    public FindIterable<T> find(Filter filter) {
        return new FindIterable<>(this, filter);
    }

    /**
     * A query on every document.
     *
     * @return the query
     */
    public FindIterable<T> find() {
        return find(Filters.empty());
    }

    // ------------------------------------------------------------------ updates

    /**
     * Updates the matching document with the lowest {@code _id}.
     *
     * @param filter the filter
     * @param update the operators ({@link Updates})
     * @return the counts
     * @throws RustegonException on failure (RGN-2009 for a stale {@code ifRev})
     */
    public UpdateResult updateOne(Filter filter, Update update) {
        return updateOne(filter, update, UpdateOptions.defaults());
    }

    /**
     * Updates the matching document with the lowest {@code _id}.
     *
     * @param filter the filter
     * @param update the operators
     * @param options options ({@code ifRev} needs {@link Filters#id(Object)})
     * @return the counts
     * @throws RustegonException on failure
     */
    public UpdateResult updateOne(Filter filter, Update update, UpdateOptions options) {
        if (filter.isId()) {
            Ast.ParamSink params = Ast.ParamSink.of("u");
            UpdateRequest.Builder r = UpdateRequest.newBuilder().setDatabase(db.name())
                    .setCollection(name).setId(Ast.value(filter.idValue()))
                    .addAllOperations(update.toAst(params)).putAllParams(params.params())
                    .setOptions(writeOptions());
            if (options.ifRev() != null) {
                r.setIfRev(options.ifRev());
            }
            if (txn() != null) {
                r.setTxnId(txn());
            }
            UpdateResponse resp = ops().unary(DocumentServiceGrpc.getUpdateMethod(), r.build(),
                    Operations.Kind.WRITE, ctx);
            return new UpdateResult(resp.getMatched() ? 1 : 0, resp.getModified() ? 1 : 0, null);
        }
        return statementUpdate(filter, update, true, options.ifRev());
    }

    /**
     * Updates every matching document (the empty filter updates the whole collection).
     *
     * @param filter the filter
     * @param update the operators
     * @return the counts
     * @throws RustegonException on failure
     */
    public UpdateResult updateMany(Filter filter, Update update) {
        return statementUpdate(filter, update, false, null);
    }

    /**
     * Updates every matching document.
     *
     * @param filter the filter
     * @param update the operators
     * @param options options ({@code ifRev} is not available here)
     * @return the counts
     * @throws RustegonException on failure
     */
    public UpdateResult updateMany(Filter filter, Update update, UpdateOptions options) {
        return statementUpdate(filter, update, false, options.ifRev());
    }

    private UpdateResult statementUpdate(Filter filter, Update update, boolean one,
            String ifRev) {
        if (ifRev != null) {
            throw new IllegalArgumentException("ifRev needs a Filters.id filter");
        }
        Map<String, Value> params = new LinkedHashMap<>();
        long n = db.executeWrite(Statements.update(name, filter, update, one,
                new Ast.ParamSink("f", params), new Ast.ParamSink("u", params)), params, ctx);
        return new UpdateResult(n, n, null);
    }

    /**
     * Replaces the matching document with the lowest {@code _id}, keeping its {@code _id}.
     *
     * @param filter the filter
     * @param replacement the new document
     * @return the counts
     * @throws RustegonException on failure
     */
    public UpdateResult replaceOne(Filter filter, T replacement) {
        return replaceOne(filter, replacement, ReplaceOptions.defaults());
    }

    /**
     * Replaces the matching document with the lowest {@code _id}; with {@code upsert} (which
     * needs {@link Filters#id(Object)}) inserts it when missing.
     *
     * @param filter the filter
     * @param replacement the new document
     * @param options options
     * @return the counts, and the id of an inserted document
     * @throws RustegonException on failure
     */
    public UpdateResult replaceOne(Filter filter, T replacement, ReplaceOptions options) {
        if (options.upsert() || filter.isId()) {
            if (!filter.isId()) {
                throw new IllegalArgumentException("upsert needs a Filters.id filter");
            }
            return replaceById(filter.idValue(), replacement, options);
        }
        if (options.ifRev() != null) {
            throw new IllegalArgumentException("ifRev needs a Filters.id filter");
        }
        Map<String, Value> params = new LinkedHashMap<>();
        long n = db.executeWrite(Statements.update(name, filter,
                Update.replaceWith(codec.toDocument(Objects.requireNonNull(replacement,
                        "replacement"))), true, new Ast.ParamSink("f", params),
                new Ast.ParamSink("u", params)), params, ctx);
        return new UpdateResult(n, n, null);
    }

    private UpdateResult replaceById(Object id, T replacement, ReplaceOptions options) {
        if (options.upsert()) {
            // The document's _id selects the target: put the filter's id first.
            RDocument doc = new RDocument().append("_id", id);
            codec.toDocument(Objects.requireNonNull(replacement, "replacement")).forEach(
                    (k, v) -> {
                        if (!"_id".equals(k)) {
                            doc.put(k, v);
                        }
                    });
            UpsertRequest.Builder r = UpsertRequest.newBuilder().setDatabase(db.name())
                    .setCollection(name).setDocument(Document.newBuilder()
                            .setRdoc(Ast.document(doc))).setOptions(writeOptions());
            if (options.ifRev() != null) {
                r.setIfRev(options.ifRev());
            }
            if (txn() != null) {
                r.setTxnId(txn());
            }
            boolean inserted = ops().unary(DocumentServiceGrpc.getUpsertMethod(), r.build(),
                    Operations.Kind.WRITE, ctx).getInserted();
            return inserted ? new UpdateResult(0, 0, id) : new UpdateResult(1, 1, null);
        }
        ReplaceRequest.Builder r = ReplaceRequest.newBuilder().setDatabase(db.name())
                .setCollection(name).setId(Ast.value(id)).setDocument(document(replacement))
                .setOptions(writeOptions());
        if (options.ifRev() != null) {
            r.setIfRev(options.ifRev());
        }
        if (txn() != null) {
            r.setTxnId(txn());
        }
        boolean matched = ops().unary(DocumentServiceGrpc.getReplaceMethod(), r.build(),
                Operations.Kind.WRITE, ctx).getMatched();
        return matched ? new UpdateResult(1, 1, null) : new UpdateResult(0, 0, null);
    }

    // ------------------------------------------------------------------ deletes

    /**
     * Deletes the matching document with the lowest {@code _id}.
     *
     * @param filter the filter
     * @return the count (0 or 1)
     * @throws RustegonException on failure
     */
    public DeleteResult deleteOne(Filter filter) {
        return deleteOne(filter, DeleteOptions.defaults());
    }

    /**
     * Deletes the matching document with the lowest {@code _id}.
     *
     * @param filter the filter
     * @param options options ({@code ifRev} needs {@link Filters#id(Object)})
     * @return the count (0 or 1)
     * @throws RustegonException on failure
     */
    public DeleteResult deleteOne(Filter filter, DeleteOptions options) {
        if (filter.isId()) {
            DeleteRequest.Builder r = DeleteRequest.newBuilder().setDatabase(db.name())
                    .setCollection(name).setId(Ast.value(filter.idValue()))
                    .setOptions(writeOptions());
            if (options.ifRev() != null) {
                r.setIfRev(options.ifRev());
            }
            if (txn() != null) {
                r.setTxnId(txn());
            }
            return new DeleteResult(ops().unary(DocumentServiceGrpc.getDeleteMethod(), r.build(),
                    Operations.Kind.WRITE, ctx).getDeleted() ? 1 : 0);
        }
        return statementDelete(filter, true, options.ifRev());
    }

    /**
     * Deletes every matching document (the empty filter empties the collection).
     *
     * @param filter the filter
     * @return the count
     * @throws RustegonException on failure
     */
    public DeleteResult deleteMany(Filter filter) {
        return statementDelete(filter, false, null);
    }

    /**
     * Deletes every matching document.
     *
     * @param filter the filter
     * @param options options ({@code ifRev} is not available here)
     * @return the count
     * @throws RustegonException on failure
     */
    public DeleteResult deleteMany(Filter filter, DeleteOptions options) {
        return statementDelete(filter, false, options.ifRev());
    }

    private DeleteResult statementDelete(Filter filter, boolean one, String ifRev) {
        if (ifRev != null) {
            throw new IllegalArgumentException("ifRev needs a Filters.id filter");
        }
        Ast.ParamSink params = Ast.ParamSink.of("f");
        return new DeleteResult(db.executeWrite(Statements.delete(name, filter, one, params),
                params.params(), ctx));
    }

    // ------------------------------------------------------------------ bulk

    /**
     * Runs by-id operations in one request ({@code DocumentService.BulkWrite}), ordered.
     *
     * @param operations the operations
     * @return the counts and the failed operations
     * @throws RustegonException if the call fails (inside a transaction, any failed operation
     *     fails the call and undoes the whole bulk)
     */
    public BulkWriteResult bulkWrite(List<BulkOperation<T>> operations) {
        return bulkWrite(operations, BulkWriteOptions.defaults());
    }

    /**
     * Runs by-id operations in one request. Outside a transaction, failed operations are
     * reported in the result and rolled back alone while the others commit; {@code ordered}
     * stops at the first failure (protocol.md §3, PD-071).
     *
     * @param operations the operations
     * @param options options
     * @return the counts and the failed operations
     * @throws RustegonException if the call fails
     */
    public BulkWriteResult bulkWrite(List<BulkOperation<T>> operations,
            BulkWriteOptions options) {
        Ast.ParamSink params = Ast.ParamSink.of("u");
        BulkWriteRequest.Builder r = BulkWriteRequest.newBuilder().setDatabase(db.name())
                .setCollection(name).setOrdered(options.ordered()).setOptions(writeOptions());
        for (BulkOperation<T> op : operations) {
            var b = io.rustegon.driver.internal.proto.BulkOperation.newBuilder();
            switch (op.kind) {
                case INSERT -> b.setInsert(BulkInsert.newBuilder().setDocument(document(
                        op.document)));
                case UPSERT -> b.setUpsert(BulkUpsert.newBuilder().setDocument(document(
                        op.document)));
                case REPLACE -> {
                    BulkReplace.Builder x = BulkReplace.newBuilder().setId(Ast.value(op.id))
                            .setDocument(document(op.document));
                    if (op.ifRev != null) {
                        x.setIfRev(op.ifRev);
                    }
                    b.setReplace(x);
                }
                case UPDATE -> {
                    BulkUpdate.Builder x = BulkUpdate.newBuilder().setId(Ast.value(op.id))
                            .addAllOperations(op.update.toAst(params));
                    if (op.ifRev != null) {
                        x.setIfRev(op.ifRev);
                    }
                    b.setUpdate(x);
                }
                case DELETE -> {
                    BulkDelete.Builder x = BulkDelete.newBuilder().setId(Ast.value(op.id));
                    if (op.ifRev != null) {
                        x.setIfRev(op.ifRev);
                    }
                    b.setDelete(x);
                }
                default -> throw new IllegalStateException("unknown bulk operation " + op.kind);
            }
            r.addOperations(b);
        }
        r.putAllParams(params.params());
        if (txn() != null) {
            r.setTxnId(txn());
        }
        BulkWriteResponse resp = ops().unary(DocumentServiceGrpc.getBulkWriteMethod(), r.build(),
                Operations.Kind.WRITE, ctx);
        List<BulkWriteError> errors = new ArrayList<>();
        for (var e : resp.getErrorsList()) {
            errors.add(new BulkWriteError(e.getIndex(), ErrorMapper.fromDetail(e.getError()),
                    e.getMessage()));
        }
        return new BulkWriteResult(resp.getInserted(), resp.getMatched(), resp.getModified(),
                resp.getDeleted(), errors);
    }

    // ------------------------------------------------------------------ indexes

    /**
     * Creates an index and waits until it is built (or its build failed).
     *
     * @param indexName the index name
     * @param keys the keys
     * @return the index, normally {@link IndexState#READY}
     * @throws RustegonException on failure (RGN-1020 when the name exists)
     */
    public IndexInfo createIndex(String indexName, IndexKeys keys) {
        return createIndex(indexName, keys, CreateIndexOptions.defaults());
    }

    /**
     * Creates an index and waits until it is built (or its build failed), at most for the
     * operation timeout.
     *
     * @param indexName the index name
     * @param keys the keys
     * @param options options (unique)
     * @return the index
     * @throws RustegonException on failure
     */
    public IndexInfo createIndex(String indexName, IndexKeys keys, CreateIndexOptions options) {
        AstCreateIndex.Builder def = AstCreateIndex.newBuilder()
                .setIndexType(options.unique() ? AstIndexType.AST_INDEX_TYPE_UNIQUE
                        : AstIndexType.AST_INDEX_TYPE_STANDARD)
                .setName(indexName).setOn(AstQualifiedName.newBuilder().setName(name));
        for (IndexKey k : keys.keys()) {
            def.addKeys(AstIndexKey.newBuilder().setPath(Ast.path(k.path()))
                    .setDescending(k.descending()));
        }
        IndexInfo info = info(ops().unary(SchemaServiceGrpc.getCreateIndexMethod(),
                CreateIndexRequest.newBuilder().setDatabase(db.name()).setDefinition(def)
                        .build(), Operations.Kind.NONE, ctx).getIndex());
        Duration timeout = ctx.timeout() != null ? ctx.timeout()
                : ops().settings().defaultOperationTimeout();
        long deadline = System.nanoTime() + timeout.toNanos();
        IndexState state = info.state();
        while (state == IndexState.BUILDING) {
            if (System.nanoTime() - deadline > 0) {
                throw ErrorMapper.local(5006, "index " + indexName + " still building after "
                        + timeout.toMillis() + " ms", null);
            }
            Operations.sleep(INDEX_POLL_MILLIS);
            state = state(ops().unary(SchemaServiceGrpc.getIndexBuildProgressMethod(),
                    IndexBuildProgressRequest.newBuilder().setDatabase(db.name())
                            .setCollection(name).setName(indexName).build(),
                    Operations.Kind.READ, ctx).getState());
        }
        return new IndexInfo(info.name(), info.keys(), info.unique(), state);
    }

    /**
     * Drops an index.
     *
     * @param indexName the index name
     * @return {@code true}
     * @throws RustegonException RGN-1021 when it does not exist
     */
    public boolean dropIndex(String indexName) {
        return dropIndex(indexName, DropOptions.defaults());
    }

    /**
     * Drops an index.
     *
     * @param indexName the index name
     * @param options options (if-exists)
     * @return whether it was dropped
     * @throws RustegonException on failure
     */
    public boolean dropIndex(String indexName, DropOptions options) {
        return ops().unary(SchemaServiceGrpc.getDropIndexMethod(), DropIndexRequest.newBuilder()
                .setDatabase(db.name()).setCollection(name).setName(indexName)
                .setIfExists(options.ifExists()).build(), Operations.Kind.NONE, ctx)
                .getDropped();
    }

    /**
     * The indexes of the collection, sorted by name.
     *
     * @return the indexes
     * @throws RustegonException on failure
     */
    public List<IndexInfo> listIndexes() {
        return ops().unary(SchemaServiceGrpc.getListIndexesMethod(), ListIndexesRequest
                .newBuilder().setDatabase(db.name()).setCollection(name).build(),
                Operations.Kind.READ, ctx).getIndexesList().stream()
                .map(RustegonCollection::info)
                .sorted(Comparator.comparing(IndexInfo::name)).toList();
    }

    private static IndexInfo info(io.rustegon.driver.internal.proto.IndexInfo i) {
        List<IndexKey> keys = new ArrayList<>();
        for (AstIndexKey k : i.getDefinition().getKeysList()) {
            keys.add(new IndexKey(dotted(k.getPath()), k.getDescending()));
        }
        return new IndexInfo(i.getDefinition().getName(), keys,
                i.getDefinition().getIndexType() == AstIndexType.AST_INDEX_TYPE_UNIQUE,
                state(i.getState()));
    }

    private static String dotted(AstPath p) {
        StringBuilder s = new StringBuilder();
        for (AstSegment seg : p.getSegmentsList()) {
            if (s.length() > 0) {
                s.append('.');
            }
            s.append(seg.hasPosition() ? String.valueOf(seg.getPosition()) : seg.getField());
        }
        return s.toString();
    }

    private static IndexState state(io.rustegon.driver.internal.proto.IndexState s) {
        return switch (s) {
            case INDEX_STATE_BUILDING -> IndexState.BUILDING;
            case INDEX_STATE_READY -> IndexState.READY;
            case INDEX_STATE_FAILED -> IndexState.FAILED;
            case INDEX_STATE_HIDDEN -> IndexState.HIDDEN;
            default -> IndexState.UNKNOWN;
        };
    }

    @Override
    public String toString() {
        return "RustegonCollection[" + db.name() + "." + name + "]";
    }
}
