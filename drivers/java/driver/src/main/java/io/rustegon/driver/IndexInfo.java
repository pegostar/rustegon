// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.List;

/**
 * An index of a collection.
 *
 * @param name the index name
 * @param keys the keys
 * @param unique whether keys are unique
 * @param state the build state
 */
public record IndexInfo(String name, List<IndexKey> keys, boolean unique, IndexState state) {
    /**
     * Copies the keys.
     *
     * @param name name
     * @param keys keys
     * @param unique unique
     * @param state state
     */
    public IndexInfo {
        keys = List.copyOf(keys);
    }
}
