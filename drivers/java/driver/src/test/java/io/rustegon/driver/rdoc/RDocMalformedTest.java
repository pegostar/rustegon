// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-003: every malformed input is rejected with an {@link RDocException} carrying the
 * server's error code, never another exception (data-model.md §4: truncation, lengths past the
 * enclosing value, unknown tags, invalid UTF-8, inconsistent index or offsets, trailing bytes,
 * non-canonical encodings under the canonical flag, limits), and the encoder enforces the same
 * limits (FR-DOC-004, FR-DOC-005).
 */
class RDocMalformedTest {
    private static final HexFormat HEX = HexFormat.of();

    /** Header + body with {@code total_len} set to the real length. */
    private static byte[] doc(int flags, String bodyHex) {
        byte[] body = HEX.parseHex(bodyHex.replace(" ", ""));
        int total = 7 + body.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xD7);
        out.write(1);
        out.write(flags);
        out.write(total);
        out.write(total >>> 8);
        out.write(total >>> 16);
        out.write(total >>> 24);
        out.writeBytes(body);
        return out.toByteArray();
    }

    /** {@code {"a": <valueHex>}}: one field, hash of "a" from the encoder. */
    private static byte[] oneField(int flags, String valueHex) {
        byte[] value = HEX.parseHex(valueHex.replace(" ", ""));
        int hash = Xxh3.nameHash16(new byte[] {'a'});
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x0D);
        body.write(1);
        writeVarint(body, 2 + value.length);
        body.writeBytes(new byte[] {(byte) hash, (byte) (hash >>> 8), 0, 0, 0, 0, 1, (byte) 'a'});
        body.writeBytes(value);
        return doc(flags, HEX.formatHex(body.toByteArray()));
    }

    private static int code(byte[] bytes) {
        return assertThrows(RDocException.class, () -> RDocReader.decode(bytes)).code();
    }

    @Test
    void tc_drv_java_003_header_errors() {
        assertEquals(1001, code(new byte[0]));
        assertEquals(1001, code(HEX.parseHex("d701010700000000")));
        byte[] ok = RDocWriter.encode(new RDocument());
        assertEquals(10, ok.length);
        byte[] magic = ok.clone();
        magic[0] = 0x00;
        assertEquals(1001, code(magic));
        byte[] version = ok.clone();
        version[1] = 2;
        assertEquals(1001, code(version));
        byte[] flags = ok.clone();
        flags[2] = 0x03;
        assertEquals(1001, code(flags));
        byte[] total = ok.clone();
        total[3] = 11;
        assertEquals(1001, code(total));
        byte[] huge = ok.clone();
        huge[3] = 1;
        huge[6] = 0x01; // 16 MiB + 1
        assertEquals(1002, code(huge));
        assertEquals(1001, code(doc(1, "0c000000")), "root is an array");
        assertEquals(1001, code(doc(1, "0d0000 00")), "trailing bytes");
    }

    @Test
    void tc_drv_java_003_value_errors() {
        assertEquals(1001, code(oneField(1, "ee")), "unknown tag");
        assertEquals(1001, code(oneField(1, "0202")), "bool 2");
        assertEquals(1001, code(oneField(1, "0602c328")), "invalid UTF-8");
        assertEquals(1001, code(oneField(1, "0605616263")), "string past the field");
        assertEquals(1001, code(oneField(1, "0701010a")), "reserved binary subtype");
        assertEquals(1001, code(oneField(1, "070401aa")), "uuid binary of 1 byte");
        assertEquals(1040, code(oneField(1, "0e01 0000c07f")), "NaN vector element");
        assertEquals(1001, code(oneField(1, "03ffffffffffffffffff7f")), "varint > 10 bytes");
        // Non-canonical forms: rejected with the flag, normalized without it.
        assertEquals(1001, code(oneField(1, "038100")), "non-minimal varint");
        assertEquals(-1L, (long) RDocReader.decode(oneField(0, "038100")).get("a"));
        String payloadNan = "04 0100000000 00f87f";
        assertEquals(1001, code(oneField(1, payloadNan)), "NaN with payload");
        assertTrue(Double.isNaN((Double) RDocReader.decode(oneField(0, payloadNan)).get("a")));
        String bigCoefficient = "05 ffffffffffffffffffffffffffff3f30";
        assertEquals(1001, code(oneField(1, bigCoefficient)), "coefficient above 10^34");
        assertEquals(Decimal128.fromBits(0x303fffffffffffffL, 0xffffffffffffffffL),
                RDocReader.decode(oneField(0, bigCoefficient)).get("a"));
    }

    @Test
    void tc_drv_java_003_index_errors() {
        byte[] good = oneField(1, "01");
        RDocReader.decode(good);
        byte[] hash = good.clone();
        hash[10] ^= 1;
        assertEquals(1001, code(hash), "hash mismatch");
        byte[] offset = good.clone();
        offset[12] = 1;
        assertEquals(1001, code(offset), "offset not at a field start");
        // Two fields "a","a": same hash and name → duplicate (RGN-1004).
        int h = Xxh3.nameHash16(new byte[] {'a'});
        String e = String.format("%02x%02x", h & 0xFF, h >>> 8);
        assertEquals(1004, code(doc(1, "0d0206" + e + "00000000" + e + "03000000"
                + "016101" + "016101")), "duplicate name");
        // Fields "a","b" with the index in the wrong order.
        RDocument ab = new RDocument().append("a", null).append("b", null);
        byte[] sorted = RDocWriter.encode(ab);
        byte[] swapped = sorted.clone();
        System.arraycopy(sorted, 10, swapped, 16, 6);
        System.arraycopy(sorted, 16, swapped, 10, 6);
        assertEquals(1001, code(swapped), "index not sorted");
        assertEquals(1004, code(doc(1, nameField("$a"))), "name starting with $");
        assertEquals(1004, code(doc(1, nameField("a\0b"))), "name with NUL");
    }

    /** {@code {<name>: null}} with a correct index. */
    private static String nameField(String name) {
        byte[] n = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int h = Xxh3.nameHash16(n);
        return String.format("0d01%02x%02x%02x00000000%02x", n.length + 2, h & 0xFF, h >>> 8,
                n.length) + HEX.formatHex(n) + "01";
    }

    @Test
    void tc_drv_java_003_depth_limit() {
        // 100 levels are accepted (root = 1), 101 are not, on both sides.
        Object v = List.of();
        for (int i = 0; i < 98; i++) {
            v = List.of(v);
        }
        RDocument ok = RDocument.of("a", v);
        RDocReader.decode(RDocWriter.encode(ok));
        RDocument deep = RDocument.of("a", List.of(v));
        assertEquals(1003, assertThrows(RDocException.class, () -> RDocWriter.encode(deep))
                .code());
        // Hand-built: 101 nested arrays below the root.
        byte[] inner = HEX.parseHex("0c0000");
        for (int i = 0; i < 100; i++) {
            ByteArrayOutputStream a = new ByteArrayOutputStream();
            a.write(0x0C);
            a.write(1);
            writeVarint(a, inner.length);
            a.writeBytes(new byte[4]);
            a.writeBytes(inner);
            inner = a.toByteArray();
        }
        assertEquals(1003, code(oneField(0, HEX.formatHex(inner))));
    }

    private static void writeVarint(ByteArrayOutputStream out, int v) {
        while (v >= 0x80) {
            out.write((v & 0x7F) | 0x80);
            v >>>= 7;
        }
        out.write(v);
    }

    @Test
    void tc_drv_java_003_encoder_limits() {
        assertEquals(1004, assertThrows(RDocException.class,
                () -> RDocWriter.encode(RDocument.of("$x", 1L))).code());
        assertEquals(1004, assertThrows(RDocException.class,
                () -> RDocWriter.encode(RDocument.of("", 1L))).code());
        assertEquals(1004, assertThrows(RDocException.class,
                () -> RDocWriter.encode(RDocument.of("x".repeat(1025), 1L))).code());
        RDocWriter.encode(RDocument.of("x".repeat(1024), 1L));
        assertEquals(1001, assertThrows(RDocException.class,
                () -> RDocWriter.encode(RDocument.of("s", "\uD800"))).code());
        assertEquals(1040, assertThrows(RDocException.class,
                () -> RDocWriter.encode(RDocument.of("v", new float[] {Float.NaN}))).code());
        assertEquals(1001, assertThrows(RDocException.class,
                () -> RDocWriter.encode(RDocument.of("x", new Object()))).code());
        // 16 MiB including the header: a string just over the limit fails before writing.
        String big = "x".repeat(16 * 1024 * 1024);
        assertEquals(1002, assertThrows(RDocException.class,
                () -> RDocWriter.encode(RDocument.of("s", big))).code());
        // header 7, tag 1, count 1, body length 4, index 6, name 2, value tag 1, length 4.
        int exact = 16 * 1024 * 1024 - 26;
        byte[] max = RDocWriter.encode(RDocument.of("s", "x".repeat(exact)));
        assertEquals(16 * 1024 * 1024, max.length);
        assertEquals(exact, ((String) RDocReader.decode(max).get("s")).length());
    }

    @Test
    void tc_drv_java_003_truncations_and_bit_flips_never_escape() throws IOException {
        Random random = new Random(42);
        List<String> escapes = new ArrayList<>();
        for (Path f : TestPaths.rdocPairs(TestPaths.rdocFixtures())) {
            byte[] bytes = Files.readAllBytes(f);
            for (int len = 0; len < bytes.length; len++) {
                byte[] cut = java.util.Arrays.copyOf(bytes, len);
                if (len >= 7) {
                    // Keep total_len consistent so the body parser sees the truncation.
                    cut[3] = (byte) len;
                    cut[4] = (byte) (len >>> 8);
                    cut[5] = 0;
                    cut[6] = 0;
                }
                expectRejected(cut, f + " cut at " + len, escapes);
            }
            for (int i = 0; i < 3000; i++) {
                byte[] flipped = bytes.clone();
                int at = 7 + random.nextInt(bytes.length - 7);
                flipped[at] ^= (byte) (1 << random.nextInt(8));
                try {
                    RDocReader.decode(flipped);
                } catch (RDocException e) {
                    // Expected for most flips; the others decode to another valid document.
                } catch (RuntimeException e) {
                    escapes.add(f + " flip at " + at + ": " + e);
                }
            }
        }
        if (!escapes.isEmpty()) {
            fail(String.join("\n", escapes));
        }
    }

    private static void expectRejected(byte[] b, String what, List<String> escapes) {
        try {
            RDocReader.decode(b);
            escapes.add(what + ": accepted");
        } catch (RDocException e) {
            // Expected.
        } catch (RuntimeException e) {
            escapes.add(what + ": " + e);
        }
    }

    @Test
    void tc_drv_java_003_value_decoding_rejects_trailing_bytes() {
        assertThrows(RDocException.class, () -> RDocReader.decodeValue(new byte[0]));
        assertThrows(RDocException.class, () -> RDocReader.decodeValue(new byte[] {(byte) 0xEE}));
        assertThrows(RDocException.class, () -> RDocReader.decodeValue(new byte[] {1, 1}));
    }
}
