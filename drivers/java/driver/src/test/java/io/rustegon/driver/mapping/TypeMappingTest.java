// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.mapping.MappingModel.Status;
import io.rustegon.driver.rdoc.Decimal128;
import io.rustegon.driver.rdoc.ObjectId;
import io.rustegon.driver.rdoc.RBinary;
import io.rustegon.driver.rdoc.RDocReader;
import io.rustegon.driver.rdoc.RDocument;
import io.rustegon.driver.rdoc.RVector;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Example;

/**
 * TC-DRV-JAVA-023 (FR-DRV-002, java-driver.md §5): the type mapping. Property tests (jqwik):
 * every mapped type survives Java → RDoc bytes → Java (datetimes at millisecond precision,
 * floor; offsets and zones read back at UTC) and generated codecs write the same bytes as the
 * {@code MethodHandles} mapper. Examples: the RDoc type of each Java type and the errors.
 */
class TypeMappingTest {
    @RustegonDocument
    record Scalars(long l, int i, short s, double d, float f, boolean b, String str,
            BigDecimal dec, byte[] bin, Instant t, OffsetDateTime odt, ZonedDateTime zdt, UUID u,
            ObjectId oid, Status e, float[] vec, List<Long> list, Map<String, String> map,
            Optional<Integer> opt) {}

    @RustegonDocument
    record Boxed(Long l, Integer i, Short s, Double d, Float f, Boolean b) {}

    @RustegonDocument
    record Vec(@RgnVector(2) float[] v) {}

    @RustegonDocument
    record Geo(@RgnGeoPoint double[] p) {}

    private static <T> T viaBytes(Class<T> type, T value) {
        byte[] bytes = Samples.sameBytes(type, value);
        return Mapper.codec(type).decode(RDocReader.decode(bytes), "");
    }

    @Property(tries = 300)
    void tc_drv_java_023_every_type_round_trips(@ForAll long l, @ForAll int i, @ForAll short s,
            @ForAll double d, @ForAll float f, @ForAll boolean b, @ForAll("strings") String str,
            @ForAll("decimals") BigDecimal dec, @ForAll("bytes") byte[] bin,
            @ForAll("instants") Instant t, @ForAll("offsets") ZoneOffset off, @ForAll long uuidHi,
            @ForAll long uuidLo, @ForAll Status e, @ForAll("vectors") float[] vec,
            @ForAll("longLists") List<Long> list, @ForAll("stringMaps") Map<String, String> map,
            @ForAll("optionalInts") Optional<Integer> opt) {
        Scalars v = new Scalars(l, i, s, d, f, b, str, dec, bin, t, t.atOffset(off),
                t.atZone(off), new UUID(uuidHi, uuidLo), ObjectId.get(), e, vec, list, map, opt);
        Scalars back = viaBytes(Scalars.class, v);
        assertEquals(l, back.l());
        assertEquals(i, back.i());
        assertEquals(s, back.s());
        assertEquals(Double.doubleToLongBits(d), Double.doubleToLongBits(back.d()));
        assertEquals(Float.floatToIntBits(f), Float.floatToIntBits(back.f()));
        assertEquals(b, back.b());
        assertEquals(str, back.str());
        // Same cohort: scale is preserved, so equals (not only compareTo) holds.
        assertEquals(dec, back.dec());
        assertArrayEquals(bin, back.bin());
        Instant ms = Instant.ofEpochMilli(t.toEpochMilli());
        assertEquals(ms, back.t());
        assertEquals(ms.atOffset(ZoneOffset.UTC), back.odt());
        assertEquals(ms.atZone(ZoneOffset.UTC), back.zdt());
        assertEquals(v.u(), back.u());
        assertEquals(v.oid(), back.oid());
        assertEquals(e, back.e());
        assertArrayEquals(vec, back.vec());
        assertEquals(list, back.list());
        assertEquals(map, back.map());
        assertEquals(opt, back.opt());
    }

    @Property(tries = 100)
    void tc_drv_java_023_boxed_types_and_nulls_round_trip(@ForAll("maybeLong") Long l,
            @ForAll("maybeInt") Integer i, @ForAll("maybeBool") Boolean b) {
        Boxed v = new Boxed(l, i, i == null ? null : (short) (int) i, l == null ? null
                : (double) l, i == null ? null : (float) (int) i, b);
        assertEquals(v, viaBytes(Boxed.class, v));
    }

    @Example
    void tc_drv_java_023_rdoc_types_of_java_types() {
        Instant t = Instant.parse("2026-11-12T10:15:30.123999Z");
        Scalars v = new Scalars(1, 2, (short) 3, 4.5, 5.5f, true, "s", new BigDecimal("1.10"),
                new byte[] {9}, t, t.atOffset(ZoneOffset.ofHours(-5)),
                t.atZone(ZoneOffset.ofHours(9)), new UUID(1, 2), ObjectId.parse(
                        "6553f0a1b2c3d4e5f6a7b8c9"), Status.NEW, new float[] {1f}, List.of(7L),
                Map.of("k", "v"), Optional.of(8));
        RDocument doc = RDocReader.decode(Samples.sameBytes(Scalars.class, v));
        assertEquals(1L, doc.get("l"));
        assertEquals(2L, doc.get("i"));
        assertEquals(3L, doc.get("s"));
        assertEquals(4.5, doc.get("d"));
        assertEquals(5.5, doc.get("f"));
        assertEquals(Decimal128.parse("1.10"), doc.get("dec"));
        assertEquals(RBinary.of(new byte[] {9}), doc.get("bin"));
        Instant ms = Instant.parse("2026-11-12T10:15:30.123Z");
        assertEquals(ms, doc.get("t"), "sub-millisecond digits are truncated");
        assertEquals(ms, doc.get("odt"));
        assertEquals(ms, doc.get("zdt"));
        assertInstanceOf(UUID.class, doc.get("u"));
        assertEquals("NEW", doc.get("e"));
        assertEquals(new RVector(new float[] {1f}), doc.get("vec"));
        assertEquals(List.of(7L), doc.get("list"));
        assertEquals(RDocument.of("k", "v"), doc.get("map"));
        assertEquals(8L, doc.get("opt"));
        // Negative instants floor as well (the RDoc writer's rule).
        Instant before = Instant.parse("1969-12-31T23:59:59.999500Z");
        assertEquals(Instant.parse("1969-12-31T23:59:59.999Z"), Values.INSTANT.write(before));
    }

    @Example
    void tc_drv_java_023_decimal_over_34_digits_is_rejected() {
        BigDecimal big = new BigDecimal(BigInteger.TEN.pow(34)); // 35 digits
        assertThrows(IllegalArgumentException.class, () -> Values.DECIMAL.write(big));
        assertThrows(IllegalArgumentException.class,
                () -> Values.DECIMAL.write(new BigDecimal("0.12345678901234567890123456789012345")));
        Values.DECIMAL.write(new BigDecimal("-1234567890123456789012345678901234E-6000"));
        Scalars v = new Scalars(0, 0, (short) 0, 0, 0, false, "", big, new byte[0],
                Instant.EPOCH, Instant.EPOCH.atOffset(ZoneOffset.UTC), Instant.EPOCH.atZone(
                        ZoneOffset.UTC), new UUID(0, 0), ObjectId.get(), Status.NEW,
                new float[0], List.of(), Map.of(), Optional.empty());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Mapper.codec(Scalars.class).encode(v));
        assertTrue(e.getMessage().contains("dec"), e.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> Mapper.reflective(Scalars.class).encode(v));
    }

    @Example
    void tc_drv_java_023_read_errors_name_the_path() {
        assertError(Map.of("i", (long) Integer.MAX_VALUE + 1), "i: int64 2147483648 overflows int");
        assertError(Map.of("s", 40_000L), "s: int64 40000 overflows short");
        assertError(Map.of("l", "x"), "l: expected int64, found String");
        assertError(Map.of("e", "LOST"), "e: no constant LOST");
        assertError(Map.of("list", List.of(1L, "x")), "list.1: expected int64");
        assertError(Map.of("map", RDocument.of("k", 1L)), "map.k: expected string");
        assertError(Map.of("dec", Decimal128.NaN), "dec: decimal128 NaN has no BigDecimal");
        assertError(Map.of("vec", List.of()), "vec: expected vector_f32");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Mapper.codec(Vec.class).encode(new Vec(new float[3])));
        assertTrue(e.getMessage().contains("3 dimensions, expected 2"), e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> Mapper.codec(Vec.class).decode(
                RDocument.of("v", new RVector(new float[1])), ""));
        assertTrue(e.getMessage().contains("v: vector has 1 dimensions"), e.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> Mapper.codec(Geo.class).encode(new Geo(new double[] {181, 0})));
        assertThrows(IllegalArgumentException.class,
                () -> Mapper.codec(Geo.class).encode(new Geo(new double[] {0, 91})));
        assertThrows(IllegalArgumentException.class, () -> Mapper.codec(Geo.class).decode(
                RDocument.of("p", RDocument.of("type", "LineString")), ""));
        Geo g = new Geo(new double[] {-180, 90});
        assertArrayEquals(g.p(), viaBytes(Geo.class, g).p());
    }

    private static void assertError(Map<String, Object> fields, String message) {
        for (Function<RDocument, Scalars> decode : List.<Function<RDocument, Scalars>>of(
                d -> Mapper.codec(Scalars.class).decode(d, ""),
                d -> Mapper.reflective(Scalars.class).decode(d, ""))) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> decode.apply(new RDocument(fields)));
            assertTrue(e.getMessage().contains(message), e.getMessage());
        }
    }

    // ------------------------------------------------------------------ arbitraries

    @Provide
    Arbitrary<String> strings() {
        return Arbitraries.oneOf(Arbitraries.strings().withCharRange('\u0000', '퟿')
                .ofMaxLength(20), Arbitraries.of("", "😀", "a\u0000b"));
    }

    @Provide
    Arbitrary<BigDecimal> decimals() {
        return Combinators.combine(Arbitraries.bigIntegers().between(
                BigInteger.TEN.pow(34).negate().add(BigInteger.ONE),
                BigInteger.TEN.pow(34).subtract(BigInteger.ONE)),
                Arbitraries.integers().between(-6000, 6000))
            .as(BigDecimal::new);
    }

    @Provide
    Arbitrary<byte[]> bytes() {
        return Arbitraries.bytes().array(byte[].class).ofMaxSize(32);
    }

    @Provide
    Arbitrary<Instant> instants() {
        // Any int64 millisecond plus sub-millisecond nanos.
        return Combinators.combine(Arbitraries.longs(), Arbitraries.integers().between(0,
                999_999))
            .as((ms, nanos) -> Instant.ofEpochMilli(ms).plusNanos(nanos));
    }

    @Provide
    Arbitrary<ZoneOffset> offsets() {
        return Arbitraries.integers().between(-18 * 3600, 18 * 3600)
            .map(ZoneOffset::ofTotalSeconds);
    }

    @Provide
    Arbitrary<float[]> vectors() {
        return Arbitraries.floats().between(-1e30f, 1e30f).array(float[].class).ofMaxSize(8);
    }

    @Provide
    Arbitrary<List<Long>> longLists() {
        return Arbitraries.longs().injectNull(0.1).list().ofMaxSize(6);
    }

    @Provide
    Arbitrary<Map<String, String>> stringMaps() {
        return Arbitraries.maps(Arbitraries.strings().withCharRange('a', 'z').ofMinLength(1)
                .ofMaxLength(6), Arbitraries.strings().ofMaxLength(4).withCharRange('a', 'z')
                .injectNull(0.1)).ofMaxSize(5);
    }

    @Provide
    Arbitrary<Optional<Integer>> optionalInts() {
        return Arbitraries.integers().optional();
    }

    @Provide
    Arbitrary<Long> maybeLong() {
        return Arbitraries.longs().between(-(1L << 53), 1L << 53).injectNull(0.2);
    }

    @Provide
    Arbitrary<Integer> maybeInt() {
        return Arbitraries.integers().between(Short.MIN_VALUE, Short.MAX_VALUE).injectNull(0.2);
    }

    @Provide
    Arbitrary<Boolean> maybeBool() {
        return Arbitraries.of(true, false).injectNull(0.2);
    }
}
