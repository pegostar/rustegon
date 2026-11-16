// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-005: {@link Decimal128} (the server's {@code decimal.rs} vectors: syntax,
 * exactness, to-scientific-string, BID bits, non-canonical detection; {@code BigDecimal} with at
 * most 34 digits, else {@link IllegalArgumentException} — java-driver.md §5) and
 * {@link ObjectId} (hex, layout, uniqueness, order).
 */
class Decimal128AndObjectIdTest {
    private static String rt(String s) {
        return Decimal128.parse(s).toString();
    }

    @Test
    void tc_drv_java_005_decimal_format_matches_to_scientific_string() {
        assertEquals("12.50", rt("12.50"));
        assertEquals("0", rt("0"));
        assertEquals("-0", rt("-0"));
        assertEquals("0.000001", rt("0.000001"));
        assertEquals("1E-7", rt("0.0000001"));
        assertEquals("1E+3", rt("1e3"));
        assertEquals("1.23", rt("123e-2"));
        assertEquals("1.5E+10", rt("1.5E+10"));
        assertEquals("0E+10", rt("0e10"));
        assertEquals("Infinity", rt("inf"));
        assertEquals("-Infinity", rt("-Infinity"));
        assertEquals("NaN", rt("nan"));
        assertEquals("123.4500", rt("000123.4500"));
        assertEquals(".5 → 0.5", ".5 → " + rt(".5"));
    }

    @Test
    void tc_drv_java_005_decimal_parse_rejects_inexact_and_garbage() {
        assertThrows(RDocException.class,
                () -> Decimal128.parse("12345678901234567890123456789012345"));
        Decimal128.parse("1234567890123456789012345678901234");
        Decimal128.parse("12345678901234567890123456789012340");
        Decimal128.parse("1e6112");
        Decimal128.parse("1e6144");
        assertThrows(RDocException.class, () -> Decimal128.parse("1e6145"));
        Decimal128.parse("1e-6176");
        assertThrows(RDocException.class, () -> Decimal128.parse("1e-6177"));
        Decimal128.parse("10e-6177");
        Decimal128.parse("0e-99999");
        for (String bad : new String[] {"", "-", ".", "e5", "1e", "1.2.3", "1x", " 1", "--1",
            "1e+"}) {
            assertThrows(RDocException.class, () -> Decimal128.parse(bad), bad);
        }
    }

    @Test
    void tc_drv_java_005_decimal_bits_round_trip_and_known_values() {
        Decimal128 one = Decimal128.parse("1");
        assertEquals(0x1820L << 49, one.highBits());
        assertEquals(1L, one.lowBits());
        for (String s : new String[] {"1", "-12.50", "0", "-0", "1E+6111",
            "9.999999999999999999999999999999999E+6144", "1E-6176", "Infinity", "-Infinity",
            "NaN"}) {
            Decimal128 d = Decimal128.parse(s);
            assertTrue(Decimal128.isCanonical(d.highBits(), d.lowBits()), s);
            assertEquals(d, Decimal128.fromBits(d.highBits(), d.lowBits()), s);
        }
    }

    @Test
    void tc_drv_java_005_decimal_non_canonical_bits_detected() {
        long nanHigh = 0x7CL << 56;
        long infHigh = 0x78L << 56;
        assertTrue(Decimal128.fromBits(nanHigh, 1).isNaN());
        assertFalse(Decimal128.isCanonical(nanHigh, 1));
        assertEquals(Decimal128.POSITIVE_INFINITY, Decimal128.fromBits(infHigh, 5));
        assertFalse(Decimal128.isCanonical(infHigh, 5));
        // Coefficient 10^34 (one above the maximum) in the small form.
        BigInteger over = BigInteger.TEN.pow(34);
        long high = (0x1820L << 49) | over.shiftRight(64).longValue();
        long low = over.longValue();
        assertFalse(Decimal128.isCanonical(high, low));
        assertEquals("0", Decimal128.fromBits(high, low).toString());
        assertFalse(Decimal128.isCanonical(0x3L << 61, 0));
    }

    @Test
    void tc_drv_java_005_big_decimal_conversion() {
        assertEquals("12.50", Decimal128.of(new BigDecimal("12.50")).toString());
        assertEquals(new BigDecimal("12.50"), Decimal128.parse("12.50").toBigDecimal());
        assertEquals(new BigDecimal("-1E+3"), Decimal128.parse("-1E+3").toBigDecimal());
        BigDecimal max = new BigDecimal("1234567890123456789012345678901234");
        assertEquals(max, Decimal128.of(max).toBigDecimal());
        assertThrows(IllegalArgumentException.class,
                () -> Decimal128.of(new BigDecimal("12345678901234567890123456789012345")));
        assertThrows(IllegalArgumentException.class,
                () -> Decimal128.of(new BigDecimal("0.12345678901234567890123456789012345")));
        assertThrows(ArithmeticException.class, () -> Decimal128.NaN.toBigDecimal());
        assertEquals(Decimal128.parse("-42"), Decimal128.of(-42L));
        assertEquals("-9223372036854775808", Decimal128.of(Long.MIN_VALUE).toString());
        // Cohort members are distinct representations.
        assertNotEquals(Decimal128.parse("1.0"), Decimal128.parse("1.00"));
        // A BigDecimal written into a document is a decimal128.
        RDocument d = RDocument.parse(RDocument.of("p", new BigDecimal("9.99")).toJson());
        assertEquals(Decimal128.parse("9.99"), d.get("p"));
    }

    @Test
    void tc_drv_java_005_object_id() {
        ObjectId id = ObjectId.of(new byte[] {(byte) 0xAB, (byte) 0xAB, (byte) 0xAB, (byte) 0xAB,
            (byte) 0xAB, (byte) 0xAB, (byte) 0xAB, (byte) 0xAB, (byte) 0xAB, (byte) 0xAB,
            (byte) 0xAB, (byte) 0xAB});
        assertEquals("abababababababababababab", id.toString());
        assertEquals(id, ObjectId.parse("ABABABABABABABABABABABAB"));
        assertThrows(RDocException.class, () -> ObjectId.parse("abc"));
        assertThrows(RDocException.class, () -> ObjectId.parse("zzababababababababababab"));
        assertThrows(RDocException.class, () -> ObjectId.parse("٠٠ababababababababababab"));
        assertThrows(IllegalArgumentException.class, () -> ObjectId.of(new byte[11]));
        long now = System.currentTimeMillis() / 1000;
        Set<ObjectId> seen = new HashSet<>();
        ObjectId prev = null;
        for (int i = 0; i < 10_000; i++) {
            ObjectId g = ObjectId.get();
            assertTrue(seen.add(g), "duplicate id");
            assertTrue(Math.abs(g.seconds() - now) <= 5);
            if (prev != null && prev.seconds() == g.seconds()) {
                // Same second and process bytes: the counter orders them (until it wraps).
                byte[] a = prev.toByteArray();
                byte[] b = g.toByteArray();
                assertEquals(java.util.Arrays.toString(java.util.Arrays.copyOfRange(a, 4, 9)),
                        java.util.Arrays.toString(java.util.Arrays.copyOfRange(b, 4, 9)));
            }
            prev = g;
        }
        assertTrue(ObjectId.parse("000000000000000000000001")
                .compareTo(ObjectId.parse("ff0000000000000000000000")) < 0, "unsigned order");
    }
}
