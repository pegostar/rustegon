// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import io.rustegon.driver.rdoc.RDocument;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * The codec of a record or POJO: an ordered list of properties and a creator (java-driver.md
 * §5). Built by generated codecs (getters and creators are lambdas: no reflection) and by the
 * {@code MethodHandles} mapper ({@link Mapper}), so both write the same documents.
 *
 * <p>Writing: properties in declaration order, {@code _id} first; a {@code null} {@code _id} is
 * omitted (the server generates one); other {@code null}s are written as null; an empty
 * {@link Optional} is omitted; {@link Kind#READ_ONLY} and {@link Kind#IGNORED} properties are
 * never written. Reading: unknown fields (including {@code _createdAt}/{@code _updatedAt}) are
 * ignored; a missing field gives the property's absent value ({@code null}, zero or
 * {@code false} for primitives, {@link Optional#empty()}); an explicit null for a primitive is
 * an {@link IllegalArgumentException}.
 *
 * @param <T> the document type
 */
public final class ObjectCodec<T> implements DocumentCodec<T> {
    /** How a property takes part in the mapping. */
    public enum Kind {
        /** Written and read. */
        FIELD,
        /** An {@link Optional} property: written when present, read as empty when missing. */
        OPTIONAL,
        /** Read, never written ({@link RgnRev}, {@link RgnCounter}). */
        READ_ONLY,
        /** Neither written nor read ({@link RgnIgnore}); the creator gets the absent value. */
        IGNORED
    }

    private record Property<T>(Kind kind, String name, ValueCodec<Object> codec,
            Function<? super T, ?> getter, Object absent) {}

    private final Class<T> type;
    private final List<Property<T>> properties;
    private final List<Property<T>> writeOrder;
    private final Function<Object[], T> creator;

    private ObjectCodec(Class<T> type, List<Property<T>> properties,
            Function<Object[], T> creator) {
        this.type = type;
        this.properties = List.copyOf(properties);
        List<Property<T>> order = new ArrayList<>();
        properties.stream().filter(p -> "_id".equals(p.name)).forEach(order::add);
        properties.stream().filter(p -> !"_id".equals(p.name)).forEach(order::add);
        this.writeOrder = List.copyOf(order);
        this.creator = creator;
    }

    /**
     * A builder for {@code type}.
     *
     * @param type the document type
     * @param <T> the document type
     * @return the builder
     */
    public static <T> Builder<T> builder(Class<T> type) {
        return new Builder<>(Objects.requireNonNull(type, "type"));
    }

    /**
     * The mapped type.
     *
     * @return the class
     */
    public Class<T> type() {
        return type;
    }

    @Override
    @SuppressWarnings("unchecked")
    public RDocument encode(T value) {
        Objects.requireNonNull(value, "value");
        RDocument doc = new RDocument();
        for (Property<T> p : writeOrder) {
            if (p.kind == Kind.READ_ONLY || p.kind == Kind.IGNORED) {
                continue;
            }
            Object v = p.getter.apply(value);
            if (p.kind == Kind.OPTIONAL) {
                Optional<Object> o = (Optional<Object>) v;
                if (o == null || o.isEmpty()) {
                    continue;
                }
                v = o.get();
            }
            if (v == null) {
                if (!"_id".equals(p.name)) {
                    doc.put(p.name, null);
                }
            } else {
                try {
                    doc.put(p.name, p.codec.write(v));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException(type.getSimpleName() + "." + p.name + ": "
                            + e.getMessage(), e);
                }
            }
        }
        return doc;
    }

    @Override
    public T decode(Map<String, ?> document, String path) {
        Object[] args = new Object[properties.size()];
        for (int i = 0; i < args.length; i++) {
            Property<T> p = properties.get(i);
            if (p.kind == Kind.IGNORED) {
                args[i] = p.absent;
                continue;
            }
            String at = path.isEmpty() ? p.name : path + "." + p.name;
            Object raw = document.get(p.name);
            if (p.kind == Kind.OPTIONAL) {
                args[i] = raw == null ? Optional.empty() : Optional.of(p.codec.read(raw, at));
            } else if (raw != null) {
                args[i] = p.codec.read(raw, at);
            } else if (p.absent != null && document.containsKey(p.name)) {
                throw new IllegalArgumentException(at + ": null for a primitive property");
            } else {
                args[i] = p.absent;
            }
        }
        return creator.apply(args);
    }

    @Override
    public String toString() {
        return "ObjectCodec[" + type.getName() + "]";
    }

    /**
     * Collects the properties of a type in declaration order.
     *
     * @param <T> the document type
     */
    public static final class Builder<T> {
        private final Class<T> type;
        private final List<Property<T>> properties = new ArrayList<>();
        private final Set<String> names = new HashSet<>();

        private Builder(Class<T> type) {
            this.type = type;
        }

        /**
         * Adds a property; the creator receives its value at the same position.
         *
         * @param kind how it is mapped
         * @param name the document field name (ignored for {@link Kind#IGNORED})
         * @param codec the value codec (of the {@link Optional}'s element for
         *     {@link Kind#OPTIONAL}; ignored for {@link Kind#IGNORED})
         * @param getter reads the property
         * @param absent the value when the field is missing: {@code null}, the primitive zero,
         *     or {@link Optional#empty()}
         * @return this builder
         * @throws IllegalArgumentException for a duplicate field name
         */
        @SuppressWarnings("unchecked")
        public Builder<T> property(Kind kind, String name, ValueCodec<?> codec,
                Function<? super T, ?> getter, Object absent) {
            Objects.requireNonNull(kind, "kind");
            if (kind != Kind.IGNORED) {
                Objects.requireNonNull(codec, "codec");
                Objects.requireNonNull(getter, "getter");
                if (name.isEmpty() || !names.add(name)) {
                    throw new IllegalArgumentException(type.getName()
                            + ": empty or duplicate field name '" + name + "'");
                }
            }
            properties.add(new Property<>(kind, name, (ValueCodec<Object>) codec, getter,
                    absent));
            return this;
        }

        /**
         * The codec.
         *
         * @param creator builds a value from the property values, in property order
         * @return the codec
         */
        public ObjectCodec<T> build(Function<Object[], T> creator) {
            return new ObjectCodec<>(type, properties, Objects.requireNonNull(creator,
                    "creator"));
        }
    }
}
