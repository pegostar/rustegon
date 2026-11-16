// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A query on a collection, executed when {@link #toList()}, {@link #first()} or
 * {@link #cursor()} is called ({@code Collection.Find}, {@code Find.*} of the model):
 * {@code FROM c [WHERE filter] [SELECT projection] [ORDER BY sort] [LIMIT n] [OFFSET m]}
 * (PD-070). A fluent builder: each setter returns this object. Not thread-safe.
 *
 * @param <T> the document type
 */
public final class FindIterable<T> {
    private final RustegonCollection<T> collection;
    private final Filter filter;
    private Sort sort;
    private Projection projection;
    private Long limit;
    private Long skip;
    private Integer batchSize;

    FindIterable(RustegonCollection<T> collection, Filter filter) {
        this.collection = collection;
        this.filter = Objects.requireNonNull(filter, "filter");
    }

    /**
     * Sets the order.
     *
     * @param order the order ({@link Sorts})
     * @return this
     */
    public FindIterable<T> sort(Sort order) {
        this.sort = Objects.requireNonNull(order, "order");
        return this;
    }

    /**
     * Returns at most {@code n} rows.
     *
     * @param n zero or more
     * @return this
     */
    public FindIterable<T> limit(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("limit must not be negative");
        }
        this.limit = (long) n;
        return this;
    }

    /**
     * Skips the first {@code n} rows (after sorting).
     *
     * @param n zero or more
     * @return this
     */
    public FindIterable<T> skip(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("skip must not be negative");
        }
        this.skip = (long) n;
        return this;
    }

    /**
     * Sets the projection.
     *
     * @param p the projection ({@link Projections})
     * @return this
     */
    public FindIterable<T> projection(Projection p) {
        this.projection = Objects.requireNonNull(p, "projection");
        return this;
    }

    /**
     * Sets the preferred rows per batch (the server caps it).
     *
     * @param n one or more
     * @return this
     */
    public FindIterable<T> batchSize(int n) {
        if (n < 1) {
            throw new IllegalArgumentException("batchSize must be positive");
        }
        this.batchSize = n;
        return this;
    }

    /**
     * Runs the query and returns a cursor over its rows.
     *
     * @return the cursor (close it)
     * @throws RustegonException on failure
     */
    public Cursor<T> cursor() {
        return open(limit);
    }

    private Cursor<T> open(Long effectiveLimit) {
        Ast.ParamSink params = Ast.ParamSink.of("f");
        return collection.database().open(Statements.find(collection.name(), filter, sort,
                projection, effectiveLimit, skip, params), null, params.params(), batchSize,
                Operations.Kind.READ, collection.context(), collection.codec());
    }

    /**
     * Runs the query and reads every row.
     *
     * @return the rows
     * @throws RustegonException on failure
     */
    public List<T> toList() {
        List<T> out = new ArrayList<>();
        try (Cursor<T> c = cursor()) {
            c.forEachRemaining(out::add);
        }
        return out;
    }

    /**
     * Runs the query with {@code LIMIT 1} and returns its first row.
     *
     * @return the row, empty when there is none
     * @throws RustegonException on failure
     */
    public Optional<T> first() {
        try (Cursor<T> c = open(limit == null ? 1L : Math.min(limit, 1L))) {
            return c.hasNext() ? Optional.of(c.next()) : Optional.empty();
        }
    }
}
