// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of {@code createDatabase}.
 *
 * @param ifNotExists succeed (with {@code false}) when the database exists
 */
public record CreateDatabaseOptions(boolean ifNotExists) {
    /**
     * Fail when the database exists (RGN-1031).
     *
     * @return the options
     */
    public static CreateDatabaseOptions defaults() {
        return new CreateDatabaseOptions(false);
    }

    /**
     * Succeed when the database exists.
     *
     * @return the options
     */
    public static CreateDatabaseOptions whenMissing() {
        return new CreateDatabaseOptions(true);
    }
}
