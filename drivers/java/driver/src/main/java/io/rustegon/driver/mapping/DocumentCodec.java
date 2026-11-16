// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import io.rustegon.driver.rdoc.RDocument;
import java.util.Map;

/**
 * Maps a document type to and from {@link RDocument} (java-driver.md §5). Obtained from
 * {@link Mapper#codec(Class)}; generated codecs ({@code <Type>_RgnCodec.INSTANCE}) and the
 * {@code MethodHandles} mapper produce identical documents.
 *
 * @param <T> the document type
 */
public interface DocumentCodec<T> extends ValueCodec<T> {
    /**
     * The document of {@code value}.
     *
     * @param value the value (not {@code null})
     * @return the document, fields in property order ({@code _id} first)
     * @throws IllegalArgumentException if a property cannot be represented
     */
    RDocument encode(T value);

    /**
     * The value of a decoded document; unknown fields are ignored.
     *
     * @param document the document
     * @param path the path of the document ({@code ""} at the top level), for error messages
     * @return the value
     * @throws IllegalArgumentException if a field does not fit its property
     */
    T decode(Map<String, ?> document, String path);

    @Override
    default Object write(T value) {
        return encode(value);
    }

    @Override
    @SuppressWarnings("unchecked")
    default T read(Object raw, String path) {
        if (!(raw instanceof Map<?, ?> m)) {
            throw Values.mismatch(path, "object", raw);
        }
        return decode((Map<String, ?>) m, path);
    }
}
