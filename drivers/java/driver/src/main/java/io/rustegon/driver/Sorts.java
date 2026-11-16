// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.ArrayList;
import java.util.List;

/** Sort builders ({@code Sort.Ascending} / {@code Sort.Descending} of the model). */
public final class Sorts {
    private Sorts() {}

    private static Sort of(boolean descending, String... paths) {
        List<Sort.Key> keys = new ArrayList<>();
        for (String p : paths) {
            Ast.path(p); // validates the path when the order is built, not at execution
            keys.add(new Sort.Key(p, descending));
        }
        return new Sort(keys);
    }

    /**
     * Ascending on each of {@code paths}, in order.
     *
     * @param paths field paths
     * @return the order
     */
    public static Sort asc(String... paths) {
        return of(false, paths);
    }

    /**
     * Descending on each of {@code paths}, in order.
     *
     * @param paths field paths
     * @return the order
     */
    public static Sort desc(String... paths) {
        return of(true, paths);
    }

    /**
     * The keys of {@code sorts}, in order.
     *
     * @param sorts the orders
     * @return the combined order
     */
    public static Sort orderBy(Sort... sorts) {
        Sort s = new Sort(List.of());
        for (Sort x : sorts) {
            s = s.then(x);
        }
        return s;
    }
}
