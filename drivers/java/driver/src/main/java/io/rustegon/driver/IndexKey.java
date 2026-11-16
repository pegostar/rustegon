// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.Objects;

/**
 * One key of an index.
 *
 * @param path the field path
 * @param descending descending order
 */
public record IndexKey(String path, boolean descending) {
    /**
     * Checks the path.
     *
     * @param path the path
     * @param descending the order
     */
    public IndexKey {
        Ast.path(Objects.requireNonNull(path, "path"));
    }

    /**
     * An ascending key.
     *
     * @param path the field path
     * @return the key
     */
    public static IndexKey asc(String path) {
        return new IndexKey(path, false);
    }

    /**
     * A descending key.
     *
     * @param path the field path
     * @return the key
     */
    public static IndexKey desc(String path) {
        return new IndexKey(path, true);
    }
}
