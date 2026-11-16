// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import io.rustegon.driver.rdoc.Decimal128;
import io.rustegon.driver.rdoc.ObjectId;
import io.rustegon.driver.rdoc.RBinary;
import io.rustegon.driver.rdoc.RCounter;
import io.rustegon.driver.rdoc.RDocument;
import io.rustegon.driver.rdoc.RVector;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * The built-in value codecs of the type mapping (java-driver.md §5). Reads are strict: a value
 * of another RDoc type is an {@link IllegalArgumentException} naming the field path; the only
 * conversions are int64 → float64 (precision above 2<sup>53</sup> is lost) and int64 →
 * decimal128.
 */
public final class Values {
    private Values() {}

    /** {@code long}/{@code Long} ↔ int64. */
    public static final ValueCodec<Long> LONG = of(v -> v, (raw, path) -> int64(raw, path));

    /** {@code int}/{@code Integer} ↔ int64 (out-of-range values are rejected when read). */
    public static final ValueCodec<Integer> INT = of(v -> (long) v, (raw, path) -> {
        long v = int64(raw, path);
        if (v != (int) v) {
            throw new IllegalArgumentException(at(path) + "int64 " + v + " overflows int");
        }
        return (int) v;
    });

    /** {@code short}/{@code Short} ↔ int64 (out-of-range values are rejected when read). */
    public static final ValueCodec<Short> SHORT = of(v -> (long) v, (raw, path) -> {
        long v = int64(raw, path);
        if (v != (short) v) {
            throw new IllegalArgumentException(at(path) + "int64 " + v + " overflows short");
        }
        return (short) v;
    });

    /** {@code double}/{@code Double} ↔ float64 (int64 is accepted when read). */
    public static final ValueCodec<Double> DOUBLE = of(v -> v, (raw, path) -> float64(raw, path));

    /** {@code float}/{@code Float} → float64 (widened); read back narrowed to float. */
    public static final ValueCodec<Float> FLOAT = of(v -> (double) v,
            (raw, path) -> (float) float64(raw, path));

    /** {@code boolean}/{@code Boolean} ↔ bool. */
    public static final ValueCodec<Boolean> BOOLEAN = of(v -> v,
            (raw, path) -> cast(raw, Boolean.class, "bool", path));

    /** {@code String} ↔ string. */
    public static final ValueCodec<String> STRING = of(v -> v,
            (raw, path) -> cast(raw, String.class, "string", path));

    /**
     * {@code BigDecimal} ↔ decimal128, exact (same cohort); more than 34 significant digits is an
     * {@link IllegalArgumentException} when written. NaN and infinities cannot be read.
     */
    public static final ValueCodec<BigDecimal> DECIMAL = of(v -> {
        // Spec rule on the BigDecimal's precision, so the stored cohort (scale) is always
        // exact: 10^34 is rejected even though decimal128 could hold it as 1E+34.
        if (v.precision() > Decimal128.MAX_DIGITS) {
            throw new IllegalArgumentException("BigDecimal " + v + " has " + v.precision()
                    + " digits; decimal128 holds at most " + Decimal128.MAX_DIGITS);
        }
        return Decimal128.of(v);
    }, (raw, path) -> {
        if (raw instanceof Long l) {
            return BigDecimal.valueOf(l);
        }
        Decimal128 d = cast(raw, Decimal128.class, "decimal128", path);
        if (d.isNaN() || d.isInfinite()) {
            throw new IllegalArgumentException(at(path) + "decimal128 " + d
                    + " has no BigDecimal value");
        }
        return d.toBigDecimal();
    });

    /** {@code byte[]} ↔ binary (generic subtype when written; any subtype is read). */
    public static final ValueCodec<byte[]> BYTES = of(RBinary::of,
            (raw, path) -> cast(raw, RBinary.class, "binary", path).data());

    /** {@code Instant} ↔ datetime; sub-millisecond digits are truncated (floor). */
    public static final ValueCodec<Instant> INSTANT = of(Values::millis,
            (raw, path) -> cast(raw, Instant.class, "datetime", path));

    /**
     * {@code OffsetDateTime} ↔ datetime: the instant is stored (ms, floor); read back at
     * {@link ZoneOffset#UTC} (the offset is not stored).
     */
    public static final ValueCodec<OffsetDateTime> OFFSET_DATE_TIME = of(
            v -> millis(v.toInstant()),
            (raw, path) -> cast(raw, Instant.class, "datetime", path).atOffset(ZoneOffset.UTC));

    /**
     * {@code ZonedDateTime} ↔ datetime: the instant is stored (ms, floor); read back at
     * {@link ZoneOffset#UTC} (the zone is not stored).
     */
    public static final ValueCodec<ZonedDateTime> ZONED_DATE_TIME = of(
            v -> millis(v.toInstant()),
            (raw, path) -> cast(raw, Instant.class, "datetime", path).atZone(ZoneOffset.UTC));

    /** {@code UUID} ↔ uuid. */
    public static final ValueCodec<UUID> UUID_CODEC = of(v -> v,
            (raw, path) -> cast(raw, UUID.class, "uuid", path));

    /** {@link ObjectId} ↔ objectId. */
    public static final ValueCodec<ObjectId> OBJECT_ID = of(v -> v,
            (raw, path) -> cast(raw, ObjectId.class, "objectId", path));

    /** {@code Object}: any value of {@link RDocument}'s value model, unchanged. */
    public static final ValueCodec<Object> ANY = of(v -> v, (raw, path) -> raw);

    /** {@link RDocument} ↔ object, unchanged. */
    public static final ValueCodec<RDocument> DOCUMENT = of(v -> v, (raw, path) -> {
        if (raw instanceof RDocument d) {
            return d;
        }
        if (raw instanceof Map<?, ?> m) {
            RDocument d = new RDocument();
            m.forEach((k, v) -> d.put((String) k, v));
            return d;
        }
        throw mismatch(path, "object", raw);
    });

    /**
     * {@code long}/{@code Long} ← counter projection ({@link RgnCounter}); int64 is accepted.
     * Never written.
     */
    public static final ValueCodec<Long> COUNTER = of(v -> {
        throw new IllegalArgumentException("counters are read-only");
    }, (raw, path) -> raw instanceof RCounter c ? c.value() : int64(raw, path));

    /** {@code double[] {lon, lat}} ↔ GeoJSON point ({@link RgnGeoPoint}). */
    public static final ValueCodec<double[]> GEO_POINT = of(v -> {
        checkPoint(v, "");
        return new RDocument().append("type", "Point").append("coordinates",
                List.of(v[0], v[1]));
    }, (raw, path) -> {
        if (!(raw instanceof Map<?, ?> m) || !"Point".equals(m.get("type"))
                || !(m.get("coordinates") instanceof List<?> c) || c.size() != 2) {
            throw mismatch(path, "GeoJSON point", raw);
        }
        double[] p = {float64(c.get(0), path + ".coordinates.0"),
            float64(c.get(1), path + ".coordinates.1")};
        checkPoint(p, path);
        return p;
    });

    /**
     * {@code float[]} ↔ vector_f32.
     *
     * @param dims the required number of dimensions, or 0 for any
     * @return the codec
     */
    public static ValueCodec<float[]> vector(int dims) {
        if (dims < 0) {
            throw new IllegalArgumentException("vector dimensions must be positive: " + dims);
        }
        return of(v -> new RVector(checkDims(v, dims, "")),
                (raw, path) -> checkDims(cast(raw, RVector.class, "vector_f32", path).values(),
                        dims, path));
    }

    /**
     * {@code List<E>} ↔ array; elements may be {@code null}. Read as a mutable
     * {@link ArrayList}.
     *
     * @param element the element codec
     * @param <E> the element type
     * @return the codec
     */
    public static <E> ValueCodec<List<E>> list(ValueCodec<E> element) {
        Objects.requireNonNull(element, "element");
        return of(v -> {
            List<Object> out = new ArrayList<>(v.size());
            for (E e : v) {
                out.add(e == null ? null : element.write(e));
            }
            return out;
        }, (raw, path) -> {
            if (!(raw instanceof List<?> l)) {
                throw mismatch(path, "array", raw);
            }
            List<E> out = new ArrayList<>(l.size());
            for (int i = 0; i < l.size(); i++) {
                Object e = l.get(i);
                out.add(e == null ? null : element.read(e, path + "." + i));
            }
            return out;
        });
    }

    /**
     * {@code Map<String, V>} ↔ object, in iteration order; values may be {@code null}. Read as
     * a mutable {@link LinkedHashMap}.
     *
     * @param value the value codec
     * @param <V> the value type
     * @return the codec
     */
    public static <V> ValueCodec<Map<String, V>> map(ValueCodec<V> value) {
        Objects.requireNonNull(value, "value");
        return of(v -> {
            RDocument out = new RDocument();
            v.forEach((k, e) -> out.put(Objects.requireNonNull(k, "map key"),
                    e == null ? null : value.write(e)));
            return out;
        }, (raw, path) -> {
            if (!(raw instanceof Map<?, ?> m)) {
                throw mismatch(path, "object", raw);
            }
            Map<String, V> out = new LinkedHashMap<>();
            m.forEach((k, e) -> out.put((String) k, e == null ? null
                    : value.read(e, path.isEmpty() ? (String) k : path + "." + k)));
            return out;
        });
    }

    /**
     * An enum ↔ string ({@link Enum#name()}); an unknown name is rejected when read.
     *
     * @param type the enum class
     * @param <E> the enum type
     * @return the codec
     */
    public static <E extends Enum<E>> ValueCodec<E> enumOf(Class<E> type) {
        Objects.requireNonNull(type, "type");
        return of(Enum::name, (raw, path) -> {
            String name = cast(raw, String.class, "string", path);
            try {
                return Enum.valueOf(type, name);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(at(path) + "no constant " + name + " in "
                        + type.getName(), e);
            }
        });
    }

    /**
     * A nested document codec resolved on first use (types may refer to each other or to
     * themselves).
     *
     * @param codec supplies the codec
     * @param <T> the document type
     * @return the codec
     */
    public static <T> DocumentCodec<T> lazy(Supplier<? extends DocumentCodec<T>> codec) {
        Objects.requireNonNull(codec, "codec");
        return new DocumentCodec<>() {
            @Override
            public RDocument encode(T value) {
                return codec.get().encode(value);
            }

            @Override
            public T decode(Map<String, ?> document, String path) {
                return codec.get().decode(document, path);
            }
        };
    }

    // ------------------------------------------------------------------ helpers

    /** A codec from a writer and a reader. */
    static <J> ValueCodec<J> of(Function<J, Object> writer, Reader<J> reader) {
        return new ValueCodec<>() {
            @Override
            public Object write(J value) {
                return writer.apply(value);
            }

            @Override
            public J read(Object raw, String path) {
                return reader.read(raw, path);
            }
        };
    }

    @FunctionalInterface
    interface Reader<J> {
        J read(Object raw, String path);
    }

    static String at(String path) {
        return path.isEmpty() ? "" : path + ": ";
    }

    static IllegalArgumentException mismatch(String path, String expected, Object raw) {
        return new IllegalArgumentException(at(path) + "expected " + expected + ", found "
                + raw.getClass().getSimpleName());
    }

    private static <V> V cast(Object raw, Class<V> type, String rdocType, String path) {
        if (!type.isInstance(raw)) {
            throw mismatch(path, rdocType, raw);
        }
        return type.cast(raw);
    }

    private static long int64(Object raw, String path) {
        return cast(raw, Long.class, "int64", path);
    }

    private static double float64(Object raw, String path) {
        if (raw instanceof Long l) {
            return l;
        }
        return cast(raw, Double.class, "float64", path);
    }

    /** The datetime value: milliseconds, floor (as the RDoc writer). */
    private static Instant millis(Instant t) {
        try {
            return Instant.ofEpochMilli(t.toEpochMilli());
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("datetime outside the int64 millisecond range: "
                    + t, e);
        }
    }

    private static float[] checkDims(float[] v, int dims, String path) {
        if (dims > 0 && v.length != dims) {
            throw new IllegalArgumentException(at(path) + "vector has " + v.length
                    + " dimensions, expected " + dims);
        }
        return v;
    }

    private static void checkPoint(double[] p, String path) {
        if (p.length != 2 || !(p[0] >= -180 && p[0] <= 180) || !(p[1] >= -90 && p[1] <= 90)) {
            throw new IllegalArgumentException(at(path)
                    + "a geo point is [longitude in [-180, 180], latitude in [-90, 90]]");
        }
    }
}
