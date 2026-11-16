// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.List;

/** Projection builders ({@code Projection.Include} / {@code Projection.Exclude}). */
public final class Projections {
    private Projections() {}

    /**
     * Only {@code paths}.
     *
     * @param paths field paths
     * @return the projection
     */
    public static Projection include(String... paths) {
        return new Projection(false, List.of(paths));
    }

    /**
     * Everything but {@code paths}.
     *
     * @param paths field paths
     * @return the projection
     */
    public static Projection exclude(String... paths) {
        return new Projection(true, List.of(paths));
    }
}
