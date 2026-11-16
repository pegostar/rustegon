// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import io.rustegon.driver.rdoc.RDocument;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The codec of a sealed interface or sealed abstract class ({@link RgnDiscriminator}): the
 * document of the value's subtype plus a discriminator field placed after {@code _id} (first
 * without one). Reading picks the subtype from the discriminator; a missing or unknown value is
 * an {@link IllegalArgumentException}.
 *
 * @param <T> the sealed root type
 */
public final class SealedCodec<T> implements DocumentCodec<T> {
    private final Class<T> type;
    private final String field;
    private final Map<Class<?>, String> tags;
    private final Map<String, DocumentCodec<? extends T>> codecs;

    private SealedCodec(Builder<T> b) {
        this.type = b.type;
        this.field = b.field;
        this.tags = Map.copyOf(b.tags);
        this.codecs = Map.copyOf(b.codecs);
    }

    /**
     * A builder.
     *
     * @param type the sealed root
     * @param field the discriminator field name
     * @param <T> the root type
     * @return the builder
     */
    public static <T> Builder<T> builder(Class<T> type, String field) {
        return new Builder<>(Objects.requireNonNull(type, "type"),
                Objects.requireNonNull(field, "field"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public RDocument encode(T value) {
        String tag = tags.get(value.getClass());
        if (tag == null) {
            throw new IllegalArgumentException(value.getClass().getName()
                    + " is not a mapped subtype of " + type.getName());
        }
        RDocument inner = ((DocumentCodec<T>) codecs.get(tag)).encode(value);
        if (inner.containsKey(field)) {
            throw new IllegalArgumentException(value.getClass().getName() + " maps a property "
                    + "to the discriminator field " + field);
        }
        RDocument doc = new RDocument();
        if (inner.containsKey("_id")) {
            doc.put("_id", inner.get("_id"));
        }
        doc.put(field, tag);
        inner.forEach((k, v) -> {
            if (!"_id".equals(k)) {
                doc.put(k, v);
            }
        });
        return doc;
    }

    @Override
    public T decode(Map<String, ?> document, String path) {
        String at = path.isEmpty() ? field : path + "." + field;
        Object tag = document.get(field);
        DocumentCodec<? extends T> codec = tag instanceof String s ? codecs.get(s) : null;
        if (codec == null) {
            throw new IllegalArgumentException(at + ": " + (tag == null ? "missing" : "unknown")
                    + " discriminator of " + type.getName()
                    + (tag == null ? "" : " (" + tag + ")"));
        }
        return codec.decode(document, path);
    }

    @Override
    public String toString() {
        return "SealedCodec[" + type.getName() + "]";
    }

    /**
     * Collects the subtypes.
     *
     * @param <T> the root type
     */
    public static final class Builder<T> {
        private final Class<T> type;
        private final String field;
        private final Map<Class<?>, String> tags = new LinkedHashMap<>();
        private final Map<String, DocumentCodec<? extends T>> codecs = new LinkedHashMap<>();

        private Builder(Class<T> type, String field) {
            this.type = type;
            this.field = field;
        }

        /**
         * Adds a concrete subtype.
         *
         * @param tag its discriminator value
         * @param subtype the class
         * @param codec its codec (it must not map a property to the discriminator field)
         * @param <S> the subtype
         * @return this builder
         * @throws IllegalArgumentException for a duplicate value or subtype
         */
        public <S extends T> Builder<T> subtype(String tag, Class<S> subtype,
                DocumentCodec<S> codec) {
            if (codecs.containsKey(tag) || tags.containsKey(subtype)) {
                throw new IllegalArgumentException(type.getName() + ": duplicate discriminator '"
                        + tag + "' or subtype " + subtype.getName());
            }
            tags.put(subtype, tag);
            codecs.put(tag, Objects.requireNonNull(codec, "codec"));
            return this;
        }

        /**
         * The codec.
         *
         * @return the codec
         */
        public SealedCodec<T> build() {
            return new SealedCodec<>(this);
        }
    }
}
