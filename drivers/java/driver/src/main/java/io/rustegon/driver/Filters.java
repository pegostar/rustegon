// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Filter builders (java-driver.md §3, PD-070; operation ids {@code Filter.*} of
 * {@code drivers/conformance/model.yaml}). Paths are dotted field names; an all-digit segment
 * after the first is an array position ({@code items.0.sku}). Comparisons follow RGQL
 * semantics (query-language.md §4.3): a missing or null field never satisfies a comparison,
 * numbers compare across int64, float64 and decimal128, and an array field matches when any
 * element does.
 */
public final class Filters {
    private Filters() {}

    private static Filter field(Filter.Op op, String path, Object value) {
        return new Filter(op, Objects.requireNonNull(path, "path"), value, List.of());
    }

    private static List<Object> list(Collection<?> values) {
        // A list copy that accepts null elements (List.copyOf does not).
        return java.util.Collections.unmodifiableList(
                new java.util.ArrayList<>(Objects.requireNonNull(values, "values")));
    }

    /**
     * Matches every document. Writes with it carry {@code allow_full_scan_write}.
     *
     * @return the empty filter
     */
    public static Filter empty() {
        return Filter.EMPTY;
    }

    /**
     * {@code _id = id}. On its own it routes single-document writes to the by-id calls.
     *
     * @param id the document id
     * @return the filter
     */
    public static Filter id(Object id) {
        return new Filter(Filter.Op.ID, null, id, List.of());
    }

    /**
     * {@code path = value}.
     *
     * @param path field path
     * @param value value
     * @return the filter
     */
    public static Filter eq(String path, Object value) {
        return field(Filter.Op.EQ, path, value);
    }

    /**
     * {@code path != value} (a missing or null field does not match).
     *
     * @param path field path
     * @param value value
     * @return the filter
     */
    public static Filter ne(String path, Object value) {
        return field(Filter.Op.NE, path, value);
    }

    /**
     * {@code path > value}.
     *
     * @param path field path
     * @param value value
     * @return the filter
     */
    public static Filter gt(String path, Object value) {
        return field(Filter.Op.GT, path, value);
    }

    /**
     * {@code path >= value}.
     *
     * @param path field path
     * @param value value
     * @return the filter
     */
    public static Filter gte(String path, Object value) {
        return field(Filter.Op.GTE, path, value);
    }

    /**
     * {@code path < value}.
     *
     * @param path field path
     * @param value value
     * @return the filter
     */
    public static Filter lt(String path, Object value) {
        return field(Filter.Op.LT, path, value);
    }

    /**
     * {@code path <= value}.
     *
     * @param path field path
     * @param value value
     * @return the filter
     */
    public static Filter lte(String path, Object value) {
        return field(Filter.Op.LTE, path, value);
    }

    /**
     * {@code path IN values} (one array parameter; an empty list matches nothing).
     *
     * @param path field path
     * @param values the values
     * @return the filter
     */
    public static Filter in(String path, Collection<?> values) {
        return field(Filter.Op.IN, path, list(values));
    }

    /**
     * {@code path NOT IN values}.
     *
     * @param path field path
     * @param values the values
     * @return the filter
     */
    public static Filter nin(String path, Collection<?> values) {
        return field(Filter.Op.NIN, path, list(values));
    }

    /**
     * Whether the field is present ({@code true}: {@code IS NOT MISSING}; a null value is
     * present) or absent ({@code false}: {@code IS MISSING}).
     *
     * @param path field path
     * @param exists the expected presence
     * @return the filter
     */
    public static Filter exists(String path, boolean exists) {
        return field(Filter.Op.EXISTS, path, exists);
    }

    /**
     * The field is present ({@code exists(path, true)}).
     *
     * @param path field path
     * @return the filter
     */
    public static Filter exists(String path) {
        return exists(path, true);
    }

    /**
     * {@code path IS NULL}: null or missing.
     *
     * @param path field path
     * @return the filter
     */
    public static Filter isNull(String path) {
        return field(Filter.Op.IS_NULL, path, null);
    }

    /**
     * The array field contains {@code value}.
     *
     * @param path field path
     * @param value the element
     * @return the filter
     */
    public static Filter contains(String path, Object value) {
        return field(Filter.Op.CONTAINS, path, value);
    }

    /**
     * The array field contains at least one of {@code values}.
     *
     * @param path field path
     * @param values the elements
     * @return the filter
     */
    public static Filter containsAny(String path, Collection<?> values) {
        return field(Filter.Op.CONTAINS_ANY, path, list(values));
    }

    /**
     * The array field contains every one of {@code values}.
     *
     * @param path field path
     * @param values the elements
     * @return the filter
     */
    public static Filter containsAll(String path, Collection<?> values) {
        return field(Filter.Op.CONTAINS_ALL, path, list(values));
    }

    /**
     * One element of the array field satisfies {@code filter} (whose paths are relative to
     * the element).
     *
     * @param path field path of the array
     * @param filter the element filter
     * @return the filter
     */
    public static Filter elemMatch(String path, Filter filter) {
        return new Filter(Filter.Op.ELEM_MATCH, Objects.requireNonNull(path, "path"), null,
                List.of(Objects.requireNonNull(filter, "filter")));
    }

    /**
     * SQL {@code LIKE} on the whole string ({@code %} any run, {@code _} one character).
     *
     * @param path field path
     * @param pattern the pattern
     * @return the filter
     */
    public static Filter like(String path, String pattern) {
        return field(Filter.Op.LIKE, path, Objects.requireNonNull(pattern, "pattern"));
    }

    /**
     * Unanchored regular expression ({@code MATCHES}, Rust regex syntax).
     *
     * @param path field path
     * @param regex the expression
     * @return the filter
     */
    public static Filter regex(String path, String regex) {
        return field(Filter.Op.REGEX, path, Objects.requireNonNull(regex, "regex"));
    }

    /**
     * All of {@code filters} (nested conjunctions are flattened).
     *
     * @param filters the filters
     * @return the filter
     */
    public static Filter and(Filter... filters) {
        return new Filter(Filter.Op.AND, null, null, List.of(filters));
    }

    /**
     * Any of {@code filters} (nested disjunctions are flattened).
     *
     * @param filters the filters
     * @return the filter
     */
    public static Filter or(Filter... filters) {
        return new Filter(Filter.Op.OR, null, null, List.of(filters));
    }

    /**
     * The negation of {@code filter}.
     *
     * @param filter the filter
     * @return the filter
     */
    public static Filter not(Filter filter) {
        return new Filter(Filter.Op.NOT, null, null, List.of(Objects.requireNonNull(filter,
                "filter")));
    }
}
