// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * TC-DRV-JAVA-002: property-based round trips of the codecs (java-driver.md §9: jqwik for
 * codecs; data-model.md §12 TC-DOC-001/006 counterparts): RDoc encode → decode is the identity
 * and canonical (re-encoding gives identical bytes), a document without the canonical flag
 * decodes to the same value, the value encoding round-trips, and JSON in both modes round-trips
 * to the same RDoc bytes.
 */
class RDocPropertiesTest {
    @Property(tries = 400)
    void tc_drv_java_002_rdoc_round_trip_is_identity_and_canonical(
            @ForAll("documents") RDocument doc) {
        byte[] bytes = RDocWriter.encode(doc);
        RDocument back = RDocReader.decode(bytes);
        assertEquals(doc, back);
        assertArrayEquals(bytes, RDocWriter.encode(back));
        // Without the canonical flag the same bytes are accepted (lenient reader).
        byte[] lenient = bytes.clone();
        lenient[2] = 0;
        assertEquals(doc, RDocReader.decode(lenient));
    }

    @Property(tries = 300)
    void tc_drv_java_002_json_round_trip_gives_the_same_rdoc(
            @ForAll("jsonDocuments") RDocument doc) {
        byte[] bytes = RDocWriter.encode(doc);
        for (JsonMode mode : JsonMode.values()) {
            String json = doc.toJson(mode);
            RDocument parsed = RDocument.parse(json);
            assertArrayEquals(bytes, RDocWriter.encode(parsed), mode + " " + json);
        }
    }

    @Property(tries = 300)
    void tc_drv_java_002_value_encoding_round_trips(@ForAll("values") Object value) {
        byte[] bytes = RDocWriter.encodeValue(value);
        Object back = RDocReader.decodeValue(bytes);
        assertEquals(value, back);
        assertArrayEquals(bytes, RDocWriter.encodeValue(back));
    }

    @Provide
    Arbitrary<RDocument> documents() {
        return documentsOf(values(true, DEPTH));
    }

    @Provide
    Arbitrary<RDocument> jsonDocuments() {
        return documentsOf(values(false, DEPTH));
    }

    @Provide
    Arbitrary<Object> values() {
        return values(true, DEPTH);
    }

    /** Container levels below a generated value (bounded: unbounded recursion explodes). */
    private static final int DEPTH = 3;

    private static Arbitrary<RDocument> documentsOf(Arbitrary<Object> values) {
        return Arbitraries.maps(fieldNames(), values).ofMaxSize(8).map(RDocument::new);
    }

    private static Arbitrary<String> fieldNames() {
        Arbitrary<String> plain = Arbitraries.strings().withCharRange('a', 'z')
                .withChars('_', '.', ' ', 'é', '日').ofMinLength(1).ofMaxLength(12);
        return Arbitraries.oneOf(plain, Arbitraries.of("_id", "x", "a.b c", "😀"));
    }

    /** Values up to {@code depth} container levels deep; counters only where JSON is not involved. */
    private static Arbitrary<Object> values(boolean withCounter, int depth) {
        if (depth == 0) {
            return leaves(withCounter);
        }
        Arbitrary<Object> inner = values(withCounter, depth - 1);
        return Arbitraries.frequencyOf(
                net.jqwik.api.Tuple.of(6, leaves(withCounter)),
                net.jqwik.api.Tuple.of(1, inner.list().ofMaxSize(4).map(l -> (Object) l)),
                net.jqwik.api.Tuple.of(1, Arbitraries.maps(fieldNames(), inner).ofMaxSize(4)
                        .map(m -> (Object) new RDocument(m))));
    }

    private static Arbitrary<Object> leaves(boolean withCounter) {
        Arbitrary<Object> base = Arbitraries.oneOf(List.of(
                Arbitraries.just(null),
                Arbitraries.of(true, false).map(b -> (Object) b),
                Arbitraries.longs().map(l -> (Object) l),
                Arbitraries.longs().between(-(1L << 53) - 2, (1L << 53) + 2).map(l -> (Object) l),
                Arbitraries.doubles().withSpecialValue(Double.NaN)
                        .withSpecialValue(Double.POSITIVE_INFINITY)
                        .withSpecialValue(-0.0).withSpecialValue(5e-324)
                        .withSpecialValue(Double.MAX_VALUE).map(d -> (Object) d),
                Arbitraries.longs().map(Double::longBitsToDouble).map(d -> (Object) d),
                decimals(),
                Arbitraries.strings().withCharRange('\u0000', '퟿').ofMaxLength(20)
                        .map(s -> (Object) s),
                Arbitraries.of("", "😀", "a\u0000b", "\"\\\n").map(s -> (Object) s),
                Arbitraries.bytes().array(byte[].class).ofMaxSize(20)
                        .map(b -> (Object) new RBinary(0x80, b)),
                Arbitraries.bytes().array(byte[].class).ofMaxSize(20)
                        .map(b -> (Object) RBinary.of(b)),
                Arbitraries.longs().map(ms -> (Object) Instant.ofEpochMilli(ms)),
                Combinators.combine(Arbitraries.longs(), Arbitraries.integers())
                        .as((w, l) -> (Object) new RTimestamp(w, l)),
                Arbitraries.bytes().array(byte[].class).ofSize(12)
                        .map(b -> (Object) ObjectId.of(b)),
                Combinators.combine(Arbitraries.longs(), Arbitraries.longs())
                        .as((a, b) -> (Object) new UUID(a, b)),
                Arbitraries.floats().between(-1e30f, 1e30f).array(float[].class).ofMaxSize(6)
                        .map(f -> (Object) new RVector(f)),
                Arbitraries.of(MinKey.INSTANCE, MaxKey.INSTANCE).map(k -> (Object) k)));
        if (!withCounter) {
            return base;
        }
        return Arbitraries.oneOf(base, Arbitraries.longs().map(c -> (Object) new RCounter(c)));
    }

    private static Arbitrary<Object> decimals() {
        Arbitrary<Object> finite = Combinators.combine(
                        Arbitraries.bigIntegers().between(BigInteger.ZERO,
                                BigInteger.TEN.pow(34).subtract(BigInteger.ONE)),
                        Arbitraries.integers().between(Decimal128.EXP_MIN, Decimal128.EXP_MAX),
                        Arbitraries.of(true, false))
                .as((c, e, neg) -> (Object) Decimal128.finite(neg, c, e));
        Arbitrary<Object> fromBigDecimal = Arbitraries.bigDecimals()
                .between(new BigDecimal("-1e20"), new BigDecimal("1e20")).ofScale(6)
                .map(d -> (Object) Decimal128.of(d));
        return Arbitraries.oneOf(finite, fromBigDecimal, Arbitraries.of(Decimal128.NaN,
                Decimal128.POSITIVE_INFINITY, Decimal128.NEGATIVE_INFINITY).map(d -> (Object) d));
    }
}
