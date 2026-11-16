// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.mapping.DocumentCodec;
import io.rustegon.driver.mapping.Mapper;
import io.rustegon.driver.rdoc.RDocument;

/**
 * Maps the document type of a collection handle to and from {@link RDocument}.
 *
 * <p>{@link RDocument} is passed through; any other type uses its object-mapping codec
 * ({@link Mapper#codec(Class)}, java-driver.md §5).
 *
 * @param <T> the document type
 */
interface DocCodec<T> {
    /** The schemaless codec. */
    DocCodec<RDocument> RDOCUMENT = new DocCodec<>() {
        @Override
        public RDocument toDocument(RDocument value) {
            return value;
        }

        @Override
        public RDocument fromDocument(RDocument doc) {
            return doc;
        }
    };

    RDocument toDocument(T value);

    T fromDocument(RDocument doc);

    /** The codec of {@code type}. */
    @SuppressWarnings("unchecked")
    static <T> DocCodec<T> of(Class<T> type) {
        if (type == RDocument.class) {
            return (DocCodec<T>) RDOCUMENT;
        }
        DocumentCodec<T> codec = Mapper.codec(type);
        return new DocCodec<>() {
            @Override
            public RDocument toDocument(T value) {
                return codec.encode(value);
            }

            @Override
            public T fromDocument(RDocument doc) {
                return codec.decode(doc, "");
            }
        };
    }
}
