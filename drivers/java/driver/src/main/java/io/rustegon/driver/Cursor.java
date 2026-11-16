// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.proto.Document;
import io.rustegon.driver.internal.proto.GetMoreRequest;
import io.rustegon.driver.internal.proto.KillCursorRequest;
import io.rustegon.driver.internal.proto.QueryServiceGrpc;
import io.rustegon.driver.internal.proto.ResultBatch;
import io.rustegon.driver.rdoc.RDocReader;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * The rows of a query, fetched in batches (java-driver.md §3; {@code Cursor.Next},
 * {@code Cursor.Close}): the first batch comes with {@code QueryService.Execute}, later ones
 * with {@code GetMore} as iteration needs them. Use it in try-with-resources: {@link #close()}
 * releases a server cursor that was not read to the end ({@code KillCursor}).
 *
 * <p>A cursor is an {@link Iterator} and a single-use {@link Iterable} ({@code for (T x : c)}).
 * A failed {@code GetMore} is not retried (retry rule R3): the error surfaces from
 * {@link #hasNext()}. Not thread-safe.
 *
 * @param <T> the row type
 */
public final class Cursor<T> implements Iterator<T>, Iterable<T>, AutoCloseable {
    private final Operations ops;
    private final OpContext ctx;
    private final DocCodec<T> codec;
    private final Integer batchSize;
    private final ArrayDeque<Document> buffer = new ArrayDeque<>();
    private String cursorId;
    private boolean closed;

    Cursor(Operations ops, OpContext ctx, DocCodec<T> codec, Integer batchSize,
            List<ResultBatch> first) {
        this.ops = ops;
        this.ctx = ctx;
        this.codec = codec;
        this.batchSize = batchSize;
        for (ResultBatch b : first) {
            take(b);
        }
    }

    private void take(ResultBatch b) {
        buffer.addAll(b.getDocsList());
        cursorId = b.hasCursorId() ? b.getCursorId() : null;
    }

    /**
     * Whether another row exists; fetches the next batch when the current one is used up.
     *
     * @return {@code true} if {@link #next()} has a row
     * @throws RustegonException if fetching the next batch fails
     */
    @Override
    public boolean hasNext() {
        while (buffer.isEmpty() && cursorId != null && !closed) {
            GetMoreRequest.Builder r = GetMoreRequest.newBuilder().setCursorId(cursorId);
            if (batchSize != null) {
                r.setBatchSize(batchSize);
            }
            take(ops.unary(QueryServiceGrpc.getGetMoreMethod(), r.build(),
                    Operations.Kind.NONE, ctx).getBatch());
        }
        return !buffer.isEmpty() && !closed;
    }

    /**
     * The next row.
     *
     * @return the row
     * @throws NoSuchElementException at the end
     */
    @Override
    public T next() {
        if (!hasNext()) {
            throw new NoSuchElementException("the cursor has no more rows");
        }
        return codec.fromDocument(RDocReader.decode(buffer.poll().getRdoc().toByteArray()));
    }

    /**
     * This cursor (it can be iterated once).
     *
     * @return this
     */
    @Override
    public Iterator<T> iterator() {
        return this;
    }

    /**
     * Releases the cursor; idempotent. A server cursor still open is killed (best effort: it
     * also expires on its own).
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        buffer.clear();
        String id = cursorId;
        cursorId = null;
        if (id != null) {
            try {
                ops.unary(QueryServiceGrpc.getKillCursorMethod(),
                        KillCursorRequest.newBuilder().setCursorId(id).build(),
                        Operations.Kind.NONE, ctx);
            } catch (RustegonException | IllegalStateException e) {
                // Best effort: the server reaps idle cursors; closing must not fail.
            }
        }
    }
}
