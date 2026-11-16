// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * TC-DRV-JAVA-001: the codec is byte-exact with the server — every committed RDoc v1 fixture of
 * {@code rustegon-doc} decodes to its canonical JSON, and encoding the decoded document (or the
 * parsed JSON) reproduces the fixture bytes exactly (FR-DOC-001, FR-DOC-003, data-model.md §4).
 * The shared conformance vectors are run by {@link ConformanceCodecTest}.
 */
class RDocFixturesTest {
    static Stream<Path> serverFixtures() {
        List<Path> pairs = TestPaths.rdocPairs(TestPaths.rdocFixtures());
        assertFalse(pairs.isEmpty(), "no RDoc fixtures in " + TestPaths.rdocFixtures());
        return pairs.stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("serverFixtures")
    void tc_drv_java_001_server_fixtures_are_byte_exact(Path rdoc) throws IOException {
        checkPair(rdoc);
    }

    private static void checkPair(Path rdoc) throws IOException {
        byte[] bytes = Files.readAllBytes(rdoc);
        String json = Files.readString(TestPaths.json(rdoc), StandardCharsets.UTF_8);
        RDocument decoded = RDocReader.decode(bytes);
        assertEquals(json, decoded.toJson(), "decode → canonical JSON");
        assertArrayEquals(bytes, RDocWriter.encode(decoded), "decode → encode");
        assertEquals(bytes.length, RDocWriter.encodedLength(decoded));
        // `{"$counter":…}` is a read-only projection: JSON input rejects it by design.
        if (!json.contains("\"$counter\"")) {
            RDocument parsed = RDocument.parse(json);
            assertArrayEquals(bytes, parsed.toRDoc(), "parse JSON → encode");
            assertEquals(json, parsed.toJson(), "parse JSON → canonical JSON");
        }
    }

    @Test
    void tc_drv_java_001_value_encoding_is_the_field_suffix() {
        // protocol.md §3: Value.rdoc_value = exactly the bytes of the value inside a document.
        Object[] values = {null, -5L, "héllo", ObjectId.of(new byte[12]), List.of(true, 1.5),
            RDocument.of("a", 1L)};
        for (Object v : values) {
            byte[] value = RDocWriter.encodeValue(v);
            byte[] doc = RDocWriter.encode(RDocument.of("v", v));
            byte[] tail = java.util.Arrays.copyOfRange(doc, doc.length - value.length,
                    doc.length);
            assertArrayEquals(value, tail, String.valueOf(v));
            assertEquals(v, RDocReader.decodeValue(value));
        }
    }
}
