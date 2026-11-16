// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Named parameters of an RGQL text ({@code $name}): sent as typed values
 * ({@code Value.rdoc_value}), never spliced into the text, so a value cannot change the query.
 * Immutable: {@code Params.of("s", "paid").and("min", 10)}.
 */
public final class Params {
    private static final Params EMPTY = new Params(Map.of());

    private final Map<String, Object> values;

    private Params(Map<String, Object> values) {
        this.values = values;
    }

    /**
     * No parameters.
     *
     * @return the empty set
     */
    public static Params empty() {
        return EMPTY;
    }

    /**
     * One parameter.
     *
     * @param name the name without {@code $}
     * @param value the value
     * @return the parameters
     */
    public static Params of(String name, Object value) {
        return EMPTY.and(name, value);
    }

    /**
     * These parameters and {@code name = value} (replacing an earlier value of {@code name}).
     *
     * @param name the name without {@code $}
     * @param value the value
     * @return the parameters
     */
    public Params and(String name, Object value) {
        if (Objects.requireNonNull(name, "name").isEmpty() || name.startsWith("$")) {
            throw new IllegalArgumentException("a parameter name is given without '$'");
        }
        Map<String, Object> next = new LinkedHashMap<>(values);
        next.put(name, value);
        return new Params(Collections.unmodifiableMap(next));
    }

    Map<String, Object> values() {
        return values;
    }

    @Override
    public String toString() {
        // Names only: values are user data.
        return "Params" + values.keySet();
    }
}
