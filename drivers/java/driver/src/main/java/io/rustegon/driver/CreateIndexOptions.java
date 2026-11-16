// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of {@code createIndex}.
 *
 * @param unique reject duplicate keys (a unique index)
 */
public record CreateIndexOptions(boolean unique) {
    /**
     * A plain secondary index.
     *
     * @return the options
     */
    public static CreateIndexOptions defaults() {
        return new CreateIndexOptions(false);
    }

    /**
     * A unique index.
     *
     * @return the options
     */
    public static CreateIndexOptions uniqueIndex() {
        return new CreateIndexOptions(true);
    }
}
