// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.proto.AstOrderItem;
import java.util.ArrayList;
import java.util.List;

/**
 * A sort order, built with {@link Sorts}: keys in priority order. Immutable. Rows with equal
 * keys come back in {@code _id} order (query-language.md §4.3).
 */
public final class Sort {
    /** One key. */
    record Key(String path, boolean descending) {}

    private final List<Key> keys;

    Sort(List<Key> keys) {
        this.keys = List.copyOf(keys);
    }

    /**
     * This order, then {@code next} for rows with equal keys.
     *
     * @param next the following keys
     * @return the combined order
     */
    public Sort then(Sort next) {
        List<Key> all = new ArrayList<>(keys);
        all.addAll(next.keys);
        return new Sort(all);
    }

    List<AstOrderItem> toAst() {
        List<AstOrderItem> out = new ArrayList<>();
        for (Key k : keys) {
            out.add(AstOrderItem.newBuilder().setExpr(Ast.pathExpr(k.path()))
                    .setDescending(k.descending()).build());
        }
        return out;
    }

    @Override
    public String toString() {
        return "Sort" + keys;
    }
}
