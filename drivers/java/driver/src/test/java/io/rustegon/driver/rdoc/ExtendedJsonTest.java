// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-004: canonical / extended JSON matches the server's {@code rustegon-doc} codec
 * (data-model.md §2 type-system notes) — the expected texts are the server's own unit-test
 * vectors ({@code json/mod.rs}, {@code json/parse.rs}, {@code json/datetime.rs}).
 */
class ExtendedJsonTest {
    @Test
    void tc_drv_java_004_canonical_json_of_every_type() {
        RDocument d = new RDocument()
                .append("n", null)
                .append("b", true)
                .append("i", -5L)
                .append("big", (1L << 53) + 1)
                .append("f", 1.0)
                .append("nan", Double.NaN)
                .append("dec", Decimal128.parse("12.50"))
                .append("s", "a\"\\\n\u0001é")
                .append("bin", new RBinary(0x80, new byte[] {1, 2, 3}))
                .append("dt", Instant.EPOCH)
                .append("ts", new RTimestamp(7, 2))
                .append("oid", ObjectId.parse("111111111111111111111111"))
                .append("u", UUID.fromString("abababab-abab-abab-abab-abababababab"))
                .append("a", List.of(1L, MinKey.INSTANCE, MaxKey.INSTANCE))
                .append("v", new float[] {0.5f, -1.0f})
                .append("c", new RCounter(3));
        String expected = "{\"n\":null,\"b\":true,\"i\":-5,\"big\":{\"$int64\":\"9007199254740993\"},"
                + "\"f\":1.0,\"nan\":{\"$float\":\"NaN\"},\"dec\":{\"$decimal\":\"12.50\"},"
                + "\"s\":\"a\\\"\\\\\\n\\u0001é\","
                + "\"bin\":{\"$binary\":{\"base64\":\"AQID\",\"subType\":\"80\"}},"
                + "\"dt\":{\"$date\":\"1970-01-01T00:00:00.000Z\"},\"ts\":{\"$ts\":\"7.2\"},"
                + "\"oid\":{\"$oid\":\"111111111111111111111111\"},"
                + "\"u\":{\"$uuid\":\"abababab-abab-abab-abab-abababababab\"},"
                + "\"a\":[1,{\"$minKey\":1},{\"$maxKey\":1}],\"v\":{\"$vector\":[0.5,-1.0]},"
                + "\"c\":{\"$counter\":3}}";
        assertEquals(expected, d.toJson());
        assertEquals("{\"$int64\":\"1\"}", ExtendedJson.valueToJson(1L, JsonMode.EXTENDED));
        assertEquals("{\"$float\":\"1e300\"}",
                ExtendedJson.valueToJson(1e300, JsonMode.EXTENDED));
    }

    @Test
    void tc_drv_java_004_float_text_follows_the_server() {
        // Rust `{:?}`: plain in [1e-4, 1e16), exponent outside, shortest digits.
        String[][] cases = {
            {"1.0", "1.0"}, {"0.1", "0.1"}, {"-0.0", "-0.0"}, {"0.0", "0.0"},
            {"1.5", "1.5"}, {"1e300", "1e300"}, {"5e-324", "5e-324"},
            {"1.7976931348623157e308", "1.7976931348623157e308"}, {"0.0001", "0.0001"},
            {"0.00001", "1e-5"}, {"9999999999999998.0", "9999999999999998.0"},
            {"1e16", "1e16"}, {"123456789.125", "123456789.125"}, {"1.5e-7", "1.5e-7"},
            {"100.0", "100.0"}, {"2.5e20", "2.5e20"},
        };
        for (String[] c : cases) {
            assertEquals(c[1], ExtendedJson.floatText(Double.parseDouble(c[0])), c[0]);
        }
        assertEquals("{\"$vector\":[0.0001,1e-5,1e16,0.1]}", ExtendedJson.valueToJson(
                new RVector(new float[] {1e-4f, 1e-5f, 1e16f, 0.1f}), JsonMode.CANONICAL));
    }

    @Test
    void tc_drv_java_004_numbers_map_to_types() {
        assertEquals(5L, ExtendedJson.parseValue("5"));
        assertEquals(0L, ExtendedJson.parseValue("-0"));
        assertEquals(5.0, ExtendedJson.parseValue("5.0"));
        assertEquals(5.0, ExtendedJson.parseValue("5e0"));
        assertEquals(-0.0, ExtendedJson.parseValue("-0.0"));
        assertEquals(Long.MAX_VALUE, ExtendedJson.parseValue("9223372036854775807"));
        assertEquals(9.223372036854775808e18, ExtendedJson.parseValue("9223372036854775808"));
        assertThrows(RDocException.class, () -> ExtendedJson.parseValue("1e400"));
        for (String bad : new String[] {"01", "1.", ".5", "-", "1e", "+1", "0x1", "NaN"}) {
            assertThrows(RDocException.class, () -> ExtendedJson.parseValue(bad), bad);
        }
    }

    @Test
    void tc_drv_java_004_strings_and_wrappers() {
        assertEquals("😀é/", ExtendedJson.parseValue("\"😀é\\/\""));
        assertEquals("😀", ExtendedJson.parseValue("\"\\ud83d\\ude00\""));
        assertThrows(RDocException.class, () -> ExtendedJson.parseValue("\"\\ud83d\""));
        assertThrows(RDocException.class, () -> ExtendedJson.parseValue("\"\\ude00\""));
        assertThrows(RDocException.class, () -> ExtendedJson.parseValue("\"a\u0001\""));
        assertEquals(-7L, ExtendedJson.parseValue("{\"$int64\":\"-7\"}"));
        assertEquals(MinKey.INSTANCE, ExtendedJson.parseValue("{\"$minKey\":1}"));
        assertThrows(RDocException.class,
                () -> ExtendedJson.parseValue("{\"$int64\":\"1\",\"x\":1}"));
        assertEquals(1004, assertThrows(RDocException.class,
                () -> ExtendedJson.parseValue("{\"a\":1,\"$b\":1}")).code());
        assertEquals(new RBinary(4, new byte[16]), ExtendedJson.parseValue(
                "{\"$binary\":{\"subType\":\"04\",\"base64\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}}"));
        assertThrows(RDocException.class, () -> ExtendedJson.parseValue(
                "{\"$binary\":{\"base64\":\"AA==\",\"subType\":\"04\"}}"));
        assertThrows(RDocException.class, () -> ExtendedJson.parseValue(
                "{\"$binary\":{\"base64\":\"AA==\",\"subType\":\"05\"}}"));
        assertThrows(RDocException.class, () -> ExtendedJson.parseValue(
                "{\"$binary\":{\"base64\":\"AB==\",\"subType\":\"00\"}}"), "non-zero pad bits");
        assertThrows(RDocException.class, () -> ExtendedJson.parseValue(
                "{\"$binary\":{\"base64\":\"AA\",\"subType\":\"00\"}}"), "missing padding");
        assertEquals(1004, assertThrows(RDocException.class,
                () -> ExtendedJson.parseValue("{\"$counter\":1}")).code());
        assertEquals(1040, assertThrows(RDocException.class,
                () -> ExtendedJson.parseValue("{\"$vector\":[1e39]}")).code());
        assertEquals(1004, assertThrows(RDocException.class,
                () -> ExtendedJson.parseValue("{\"a\":1,\"a\":2}")).code(), "duplicate name");
        assertEquals(1004, assertThrows(RDocException.class,
                () -> ExtendedJson.parseValue("{\"$where\":1}")).code());
        assertEquals(Double.POSITIVE_INFINITY,
                ExtendedJson.parseValue("{\"$float\":\"Infinity\"}"));
        assertEquals(new RTimestamp(1767225600000L, 7),
                ExtendedJson.parseValue("{\"$ts\":\"1767225600000.7\"}"));
        assertEquals(UUID.fromString("01234567-89ab-cdef-0123-456789abcdef"),
                ExtendedJson.parseValue("{\"$uuid\":\"01234567-89AB-CDEF-0123-456789ABCDEF\"}"));
        assertThrows(RDocException.class,
                () -> ExtendedJson.parseValue("{\"$oid\":\"zzababababababababababab\"}"));
        assertThrows(RDocException.class, () -> RDocument.parse("[1]"), "not an object");
        assertThrows(RDocException.class, () -> ExtendedJson.parseValue("{} x"), "trailing");
    }

    @Test
    void tc_drv_java_004_dates_known_values_and_extremes() {
        assertEquals("1970-01-01T00:00:00.000Z", IsoDate.format(0));
        assertEquals("1969-12-31T23:59:59.999Z", IsoDate.format(-1));
        assertEquals(1_767_225_600_000L, IsoDate.parse("2026-01-01T00:00:00.000Z"));
        assertEquals(1_709_208_000_000L, IsoDate.parse("2024-02-29T12:00:00Z"));
        assertEquals(1_709_208_000_500L, IsoDate.parse("2024-02-29T12:00:00.5Z"));
        for (long ms : new long[] {Long.MIN_VALUE, Long.MAX_VALUE, 0, -62_167_219_200_001L,
            253_402_300_800_000L}) {
            assertEquals(ms, IsoDate.parse(IsoDate.format(ms)), IsoDate.format(ms));
        }
        assertEquals("-292275055-05-16T16:47:04.192Z", IsoDate.format(Long.MIN_VALUE));
        for (String bad : new String[] {"2023-02-29T00:00:00Z", "2026-13-01T00:00:00Z",
            "2026-01-01T24:00:00Z", "2026-01-01T00:00:00", "2026-01-01T00:00:00.0000Z",
            "+2026-01-01T00:00:00Z", "+999999999999-01-01T00:00:00Z"}) {
            assertThrows(RDocException.class, () -> IsoDate.parse(bad), bad);
        }
    }

    @Test
    void tc_drv_java_004_nesting_limit() {
        String ok = "[".repeat(99) + "]".repeat(99);
        RDocument.parse("{\"a\":" + ok + "}");
        String deep = "[".repeat(100) + "]".repeat(100);
        assertEquals(1003, assertThrows(RDocException.class,
                () -> RDocument.parse("{\"a\":" + deep + "}")).code());
    }
}
