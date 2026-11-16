// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Options of the drop operations.
 *
 * @param ifExists succeed (with {@code false}) when there is nothing to drop
 */
public record DropOptions(boolean ifExists) {
    /**
     * Fail when there is nothing to drop (RGN-1030 / RGN-1021).
     *
     * @return the options
     */
    public static DropOptions defaults() {
        return new DropOptions(false);
    }

    /**
     * Succeed when there is nothing to drop.
     *
     * @return the options
     */
    public static DropOptions whenExists() {
        return new DropOptions(true);
    }
}
