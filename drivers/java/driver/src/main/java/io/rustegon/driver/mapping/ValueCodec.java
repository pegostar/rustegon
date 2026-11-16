// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

/**
 * Converts one Java value to and from its {@link io.rustegon.driver.rdoc.RDocument} value form
 * (java-driver.md §5). Implementations never see {@code null}: properties, lists and maps handle
 * nulls themselves. Built-in codecs are in {@link Values}.
 *
 * @param <J> the Java type
 */
public interface ValueCodec<J> {
    /**
     * The document value of {@code value}.
     *
     * @param value the Java value (not {@code null})
     * @return a value {@link io.rustegon.driver.rdoc.RDocWriter} encodes
     * @throws IllegalArgumentException if the value cannot be represented
     */
    Object write(J value);

    /**
     * The Java value of a decoded document value.
     *
     * @param raw the decoded value (not {@code null})
     * @param path the field path, for error messages
     * @return the Java value
     * @throws IllegalArgumentException if {@code raw} does not fit the Java type
     */
    J read(Object raw, String path);
}
