// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.Optional;

/**
 * Result of {@code updateOne}, {@code updateMany} and {@code replaceOne}. For a statement (non-id
 * filter) the server reports the documents it rewrote, so both counts are that number.
 *
 * @param matchedCount documents matched
 * @param modifiedCount documents changed
 * @param upsertedId the id of a document inserted by an upsert, or {@code null}
 */
public record UpdateResult(long matchedCount, long modifiedCount, Object upsertedId) {
    /**
     * {@link #upsertedId()} as an optional.
     *
     * @return the id, empty when nothing was inserted
     */
    public Optional<Object> upserted() {
        return Optional.ofNullable(upsertedId);
    }
}
