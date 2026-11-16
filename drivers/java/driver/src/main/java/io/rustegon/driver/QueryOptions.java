// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of RGQL queries ({@code RustegonDatabase.query}).
 *
 * @param batchSize preferred rows per batch, or {@code null} for the server default
 */
public record QueryOptions(Integer batchSize) {
    /**
     * Checks the batch size.
     *
     * @param batchSize the size
     */
    public QueryOptions {
        if (batchSize != null && batchSize < 1) {
            throw new IllegalArgumentException("batchSize must be positive");
        }
    }

    /**
     * The server's default batch size.
     *
     * @return the options
     */
    public static QueryOptions defaults() {
        return new QueryOptions(null);
    }
}
