// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.proto.AstStatement;
import io.rustegon.driver.internal.proto.CollectionInfo;
import io.rustegon.driver.internal.proto.CreateCollectionRequest;
import io.rustegon.driver.internal.proto.DropCollectionRequest;
import io.rustegon.driver.internal.proto.ExecOptions;
import io.rustegon.driver.internal.proto.ExecuteRequest;
import io.rustegon.driver.internal.proto.ListCollectionsRequest;
import io.rustegon.driver.internal.proto.ResultBatch;
import io.rustegon.driver.internal.proto.SchemaServiceGrpc;
import io.rustegon.driver.internal.proto.ValidationAction;
import io.rustegon.driver.internal.proto.ValidationLevel;
import io.rustegon.driver.internal.proto.Value;
import io.rustegon.driver.rdoc.RDocument;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A database handle (java-driver.md §3; {@code Database.*} of the model). Creating one does no
 * I/O. Immutable and thread-safe; the {@code with…} methods derive handles whose calls use a
 * session, a timeout, a read consistency or a write concern other than the client's.
 */
public final class RustegonDatabase {
    private final Operations ops;
    private final String name;
    private final OpContext ctx;

    RustegonDatabase(Operations ops, String name, OpContext ctx) {
        this.ops = ops;
        this.name = Objects.requireNonNull(name, "name");
        this.ctx = ctx;
    }

    /**
     * The database name.
     *
     * @return the name
     */
    public String name() {
        return name;
    }

    Operations ops() {
        return ops;
    }

    OpContext context() {
        return ctx;
    }

    /**
     * This database with calls carrying the causality token of {@code session} (PD-069).
     *
     * @param session the session
     * @return the handle
     */
    public RustegonDatabase withSession(ClientSession session) {
        return new RustegonDatabase(ops, name, ctx.withSession(Objects.requireNonNull(session,
                "session")));
    }

    /**
     * This database with another operation deadline.
     *
     * @param timeout a positive duration
     * @return the handle
     */
    public RustegonDatabase withTimeout(Duration timeout) {
        return new RustegonDatabase(ops, name, ctx.withTimeout(positive(timeout)));
    }

    /**
     * This database with another read consistency.
     *
     * @param level the level ({@link ReadConsistency#BOUNDED_STALENESS} needs
     *     {@link #withReadConsistency(ReadConsistency, Duration)})
     * @return the handle
     */
    public RustegonDatabase withReadConsistency(ReadConsistency level) {
        return withReadConsistency(level, null);
    }

    /**
     * This database with another read consistency and staleness bound.
     *
     * @param level the level
     * @param maxStaleness the bound, or {@code null}
     * @return the handle
     */
    public RustegonDatabase withReadConsistency(ReadConsistency level, Duration maxStaleness) {
        return new RustegonDatabase(ops, name, ctx.withReadConsistency(
                checkConsistency(level, maxStaleness), maxStaleness));
    }

    /**
     * This database with another write concern.
     *
     * @param concern the concern
     * @return the handle
     */
    public RustegonDatabase withWriteConcern(WriteConcern concern) {
        return new RustegonDatabase(ops, name, ctx.withWriteConcern(Objects.requireNonNull(
                concern, "concern")));
    }

    static Duration positive(Duration d) {
        if (Objects.requireNonNull(d, "timeout").isNegative() || d.isZero()) {
            throw new IllegalArgumentException("the timeout must be positive");
        }
        return d;
    }

    static ReadConsistency checkConsistency(ReadConsistency level, Duration maxStaleness) {
        Objects.requireNonNull(level, "level");
        if (level == ReadConsistency.BOUNDED_STALENESS && maxStaleness == null) {
            throw new IllegalArgumentException("BOUNDED_STALENESS needs a max staleness");
        }
        if (maxStaleness != null && (maxStaleness.isNegative() || maxStaleness.isZero())) {
            throw new IllegalArgumentException("maxStaleness must be positive");
        }
        return level;
    }

    /**
     * A collection of schemaless documents. No I/O.
     *
     * @param collection the collection name
     * @return the handle
     */
    public RustegonCollection<RDocument> collection(String collection) {
        return collection(collection, RDocument.class);
    }

    /**
     * A collection handle. No I/O.
     *
     * @param collection the collection name
     * @param type the document type: {@link RDocument} or a mapped type
     *     ({@link io.rustegon.driver.mapping.Mapper})
     * @param <T> the document type
     * @return the handle
     * @throws IllegalArgumentException for a type that cannot be mapped
     */
    public <T> RustegonCollection<T> collection(String collection, Class<T> type) {
        return new RustegonCollection<>(this, collection, DocCodec.of(type), ctx);
    }

    /**
     * Runs RGQL text with named parameters ({@code QueryService.Execute}); parameters are typed
     * values, never interpolated into the text.
     *
     * @param rgql the statement
     * @param params the parameters ({@code $name})
     * @param type the row type ({@link RDocument} or a mapped type; {@code SELECT VALUE}
     *     rows are {@code {"value": x}} documents)
     * @param <T> the row type
     * @return the rows (close the cursor)
     * @throws RustegonException on failure ({@link QuerySyntaxException} for RGN-1010…1012)
     */
    public <T> Cursor<T> query(String rgql, Params params, Class<T> type) {
        return query(rgql, params, QueryOptions.defaults(), type);
    }

    /**
     * {@link #query(String, Params, Class)} with options.
     *
     * @param rgql the statement
     * @param params the parameters
     * @param options the options
     * @param type the row type
     * @param <T> the row type
     * @return the rows (close the cursor)
     */
    public <T> Cursor<T> query(String rgql, Params params, QueryOptions options, Class<T> type) {
        return query(rgql, params, options, type, ctx);
    }

    <T> Cursor<T> query(String rgql, Params params, QueryOptions options, Class<T> type,
            OpContext context) {
        Map<String, Value> values = new LinkedHashMap<>();
        params.values().forEach((k, v) -> values.put(k, Ast.value(v)));
        // RGQL text may write: retried only under retryWrites, with the same request id.
        return open(null, Objects.requireNonNull(rgql, "rgql"), values, options.batchSize(),
                Operations.Kind.WRITE, context, DocCodec.of(type));
    }

    /** Executes a statement and opens a cursor on its first batch. */
    <T> Cursor<T> open(AstStatement ast, String rgql, Map<String, Value> params,
            Integer batchSize, Operations.Kind kind, OpContext context, DocCodec<T> codec) {
        return new Cursor<>(ops, context, codec, batchSize,
                execute(ast, rgql, params, batchSize, kind, context));
    }

    /** Executes a write statement; the number of documents it changed. */
    long executeWrite(AstStatement ast, Map<String, Value> params, OpContext context) {
        List<ResultBatch> batches = execute(ast, null, params, null, Operations.Kind.WRITE,
                context);
        return batches.isEmpty() ? 0 : batches.get(batches.size() - 1).getStats()
                .getDocsAffected();
    }

    private List<ResultBatch> execute(AstStatement ast, String rgql, Map<String, Value> params,
            Integer batchSize, Operations.Kind kind, OpContext context) {
        // One batch in the Execute stream, the rest through GetMore: a cursor then holds at
        // most one batch, and the stream is never retried after it delivered something (R3).
        ExecOptions.Builder o = ExecOptions.newBuilder().setMaxBatches(1)
                .setWriteConcern(ops.writeConcern(context));
        if (batchSize != null) {
            o.setBatchSize(batchSize);
        }
        var consistency = ops.readConsistency(context);
        if (consistency != null) {
            o.setConsistency(consistency);
        }
        ExecuteRequest.Builder r = ExecuteRequest.newBuilder().setDatabase(name)
                .putAllParams(params).setOptions(o);
        if (ast != null) {
            r.setAst(ast);
        } else {
            r.setRgql(rgql);
        }
        if (context.txnId() != null) {
            r.setTxnId(context.txnId());
        }
        return ops.execute(r.build(), kind, context);
    }

    /**
     * Creates a collection ({@code SchemaService.CreateCollection}).
     *
     * @param collection the name
     * @return {@code true}
     * @throws RustegonException RGN-1031 when it exists
     */
    public boolean createCollection(String collection) {
        return createCollection(collection, CreateCollectionOptions.defaults());
    }

    /**
     * Creates a collection.
     *
     * @param collection the name
     * @param options options (validator, if-not-exists)
     * @return whether it was created ({@code false}: it existed and {@code ifNotExists} was set)
     * @throws RustegonException on failure
     */
    public boolean createCollection(String collection, CreateCollectionOptions options) {
        CreateCollectionRequest.Builder r = CreateCollectionRequest.newBuilder().setDatabase(name)
                .setName(collection).setIfNotExists(options.ifNotExists());
        Validator v = options.validator();
        if (v != null) {
            var b = io.rustegon.driver.internal.proto.Validator.newBuilder()
                    .setDefinitionJson("{\"$jsonSchema\":" + v.jsonSchema() + "}");
            if (v.level() != null) {
                b.setLevel(ValidationLevel.valueOf("VALIDATION_LEVEL_" + v.level().name()));
            }
            if (v.action() != null) {
                b.setAction(ValidationAction.valueOf("VALIDATION_ACTION_" + v.action().name()));
            }
            r.setValidator(b);
        }
        return ops.unary(SchemaServiceGrpc.getCreateCollectionMethod(), r.build(),
                Operations.Kind.NONE, ctx).getCreated();
    }

    /**
     * Drops a collection and its documents.
     *
     * @param collection the name
     * @return {@code true}
     * @throws RustegonException RGN-1030 when it does not exist
     */
    public boolean dropCollection(String collection) {
        return dropCollection(collection, DropOptions.defaults());
    }

    /**
     * Drops a collection and its documents.
     *
     * @param collection the name
     * @param options options (if-exists)
     * @return whether it was dropped
     * @throws RustegonException on failure
     */
    public boolean dropCollection(String collection, DropOptions options) {
        return ops.unary(SchemaServiceGrpc.getDropCollectionMethod(), DropCollectionRequest
                .newBuilder().setDatabase(name).setName(collection)
                .setIfExists(options.ifExists()).build(), Operations.Kind.NONE, ctx).getDropped();
    }

    /**
     * The collection names, sorted.
     *
     * @return the names
     * @throws RustegonException on failure
     */
    public List<String> listCollectionNames() {
        return ops.unary(SchemaServiceGrpc.getListCollectionsMethod(), ListCollectionsRequest
                .newBuilder().setDatabase(name).build(), Operations.Kind.READ, ctx)
                .getCollectionsList().stream().map(CollectionInfo::getName).sorted().toList();
    }

    @Override
    public String toString() {
        return "RustegonDatabase[" + name + "]";
    }
}
