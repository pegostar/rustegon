// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of {@code bulkWrite} (no {@code AtomicMode} in R1, PD-071: the server runs the bulk in
 * one transaction where failed operations roll back alone, protocol.md §3).
 *
 * @param ordered stop at the first failed operation (default) or attempt all
 */
public record BulkWriteOptions(boolean ordered) {
    /**
     * Ordered (the default).
     *
     * @return the options
     */
    public static BulkWriteOptions defaults() {
        return new BulkWriteOptions(true);
    }

    /**
     * Unordered: every operation is attempted.
     *
     * @return the options
     */
    public static BulkWriteOptions unordered() {
        return new BulkWriteOptions(false);
    }
}
