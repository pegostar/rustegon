// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.Arrays;
import java.util.List;

/**
 * The keys of an index, in order: {@code IndexKeys.of(IndexKey.asc("sku"), IndexKey.desc("qty"))}.
 *
 * @param keys the keys (at least one)
 */
public record IndexKeys(List<IndexKey> keys) {
    /**
     * Copies and checks the keys.
     *
     * @param keys the keys
     */
    public IndexKeys {
        keys = List.copyOf(keys);
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("an index needs at least one key");
        }
    }

    /**
     * The given keys.
     *
     * @param keys the keys
     * @return the index keys
     */
    public static IndexKeys of(IndexKey... keys) {
        return new IndexKeys(List.of(keys));
    }

    /**
     * Ascending keys on {@code paths}.
     *
     * @param paths field paths
     * @return the index keys
     */
    public static IndexKeys asc(String... paths) {
        return new IndexKeys(Arrays.stream(paths).map(IndexKey::asc).toList());
    }
}
