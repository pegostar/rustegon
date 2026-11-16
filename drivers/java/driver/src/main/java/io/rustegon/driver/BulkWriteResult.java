// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.List;

/**
 * Result of {@code bulkWrite}. Outside a transaction, failed operations are reported here (and
 * rolled back alone) instead of failing the call.
 *
 * @param insertedCount documents inserted (inserts and inserting upserts)
 * @param matchedCount documents matched by replace/update/upsert
 * @param modifiedCount documents changed by replace/update/upsert
 * @param deletedCount documents deleted
 * @param errors failed operations
 */
public record BulkWriteResult(long insertedCount, long matchedCount, long modifiedCount,
        long deletedCount, List<BulkWriteError> errors) {
    /**
     * Copies the error list.
     *
     * @param insertedCount inserted
     * @param matchedCount matched
     * @param modifiedCount modified
     * @param deletedCount deleted
     * @param errors errors
     */
    public BulkWriteResult {
        errors = List.copyOf(errors);
    }
}
