// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.Objects;

/**
 * One operation of {@link RustegonCollection#bulkWrite}. Operations address documents by
 * {@code _id} only ({@code BulkOperation} of document.proto; DIVERGENCES.md §1). Immutable.
 *
 * @param <T> the document type
 */
public final class BulkOperation<T> {
    /** The operation kind. */
    enum Kind {
        INSERT, REPLACE, UPDATE, UPSERT, DELETE
    }

    final Kind kind;
    final Object id;
    final T document;
    final Update update;
    final String ifRev;

    private BulkOperation(Kind kind, Object id, T document, Update update, String ifRev) {
        this.kind = kind;
        this.id = id;
        this.document = document;
        this.update = update;
        this.ifRev = ifRev;
    }

    /**
     * Inserts {@code document} (RGN-1005 if its id exists).
     *
     * @param document the document
     * @param <T> the document type
     * @return the operation
     */
    public static <T> BulkOperation<T> insert(T document) {
        return new BulkOperation<>(Kind.INSERT, null, Objects.requireNonNull(document,
                "document"), null, null);
    }

    /**
     * Replaces the document with id {@code id} (nothing happens when it does not exist).
     *
     * @param id the document id
     * @param document the new document
     * @param <T> the document type
     * @return the operation
     */
    public static <T> BulkOperation<T> replace(Object id, T document) {
        return new BulkOperation<>(Kind.REPLACE, id, Objects.requireNonNull(document,
                "document"), null, null);
    }

    /**
     * Applies {@code update} to the document with id {@code id}.
     *
     * @param id the document id
     * @param update the operators
     * @param <T> the document type
     * @return the operation
     */
    public static <T> BulkOperation<T> update(Object id, Update update) {
        return new BulkOperation<>(Kind.UPDATE, id, null, Objects.requireNonNull(update,
                "update"), null);
    }

    /**
     * Inserts {@code document} or replaces the document with its {@code _id}.
     *
     * @param document the document
     * @param <T> the document type
     * @return the operation
     */
    public static <T> BulkOperation<T> upsert(T document) {
        return new BulkOperation<>(Kind.UPSERT, null, Objects.requireNonNull(document,
                "document"), null, null);
    }

    /**
     * Deletes the document with id {@code id}.
     *
     * @param id the document id
     * @param <T> the document type
     * @return the operation
     */
    public static <T> BulkOperation<T> delete(Object id) {
        return new BulkOperation<>(Kind.DELETE, id, null, null, null);
    }

    /**
     * This replace, update or delete, applied only when the document's {@code _rev} is
     * {@code rev} (RGN-2009 for this operation otherwise).
     *
     * @param rev the expected revision
     * @return the operation
     * @throws IllegalStateException for inserts and upserts
     */
    public BulkOperation<T> ifRev(String rev) {
        if (kind == Kind.INSERT || kind == Kind.UPSERT) {
            throw new IllegalStateException("ifRev applies to replace, update and delete");
        }
        return new BulkOperation<>(kind, id, document, update, Objects.requireNonNull(rev, "rev"));
    }

    @Override
    public String toString() {
        return "BulkOperation[" + kind + "]";
    }
}
