// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.rustegon.driver.mapping.VectorModel.MapDrawing;
import io.rustegon.driver.mapping.VectorModel.MapGeo;
import io.rustegon.driver.mapping.VectorModel.MapItem;
import io.rustegon.driver.mapping.VectorModel.MapShape;
import io.rustegon.driver.rdoc.RDocWriter;
import io.rustegon.driver.rdoc.RDocument;
import io.rustegon.driver.rdoc.TestPaths;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

/**
 * TC-DRV-JAVA-023 (FR-DRV-002, java-driver.md §11): the cross-driver mapping vectors of
 * {@code drivers/conformance/mapping/vectors.yaml}, through the generated codec and the
 * {@code MethodHandles} mapper; the .NET runner reads the same file (PD-108…PD-113).
 */
class MappingVectorsTest {
    private static final Map<String, Class<?>> MODELS = Map.of("MapItem", MapItem.class,
            "MapGeo", MapGeo.class, "MapShape", MapShape.class, "MapDrawing", MapDrawing.class);

    @Test
    @SuppressWarnings("unchecked")
    void tc_drv_java_023_cross_driver_mapping_vectors() throws IOException {
        Path file = TestPaths.conformance().map(p -> p.resolve("mapping/vectors.yaml"))
                .filter(Files::isRegularFile).orElse(null);
        Assumptions.assumeTrue(file != null, "drivers/conformance/mapping/vectors.yaml not found");
        Map<String, Object> root = (Map<String, Object>) new Load(LoadSettings.builder().build())
                .loadFromString(Files.readString(file, StandardCharsets.UTF_8));
        int count = 0;
        for (String section : List.of("roundTrip", "build", "invalid")) {
            for (Map<String, Object> v : (List<Map<String, Object>>) root.get(section)) {
                for (boolean reflective : new boolean[] {false, true}) {
                    run(section, v, reflective);
                }
                count++;
            }
        }
        assertFalse(count == 0, "no vectors");
    }

    @SuppressWarnings("unchecked")
    private static void run(String section, Map<String, Object> v, boolean reflective) {
        Class<Object> type = (Class<Object>) MODELS.get((String) v.get("model"));
        String name = v.get("name") + (reflective ? " (MethodHandles)" : " (generated)");
        DocumentCodec<Object> codec = reflective ? Mapper.reflective(type) : Mapper.codec(type);
        String json = (String) v.get("json");
        switch (section) {
            case "roundTrip" -> {
                String input = (String) v.getOrDefault("input", json);
                assertWrites(codec, codec.decode(RDocument.parse(input), ""), json, name);
                assertWrites(codec, codec.decode(RDocument.parse(json), ""), json, name);
            }
            case "build" -> assertWrites(codec, build((String) v.get("name")), json, name);
            default -> assertThrows(IllegalArgumentException.class,
                    () -> codec.decode(RDocument.parse((String) v.get("input")), ""), name);
        }
    }

    private static void assertWrites(DocumentCodec<Object> codec, Object value, String json,
            String name) {
        RDocument written = codec.encode(value);
        assertEquals(json, written.toJson(), name);
        assertArrayEquals(RDocWriter.encode(RDocument.parse(json)), RDocWriter.encode(written),
                name);
    }

    /** The {@code build} values, as their {@code value} text describes them. */
    private static Object build(String name) {
        return switch (name) {
            case "null_id_omitted_read_only_not_written" -> item(null, "n", 0f, null, "r1", 99);
            case "datetime_rounded_down_to_ms" ->
                item("t1", null, 0f, "2026-11-12T10:15:30.123456789Z", null, 0);
            case "datetime_rounded_down_before_1970" ->
                item("t2", null, 0f, "1969-12-31T23:59:59.9995Z", null, 0);
            case "datetime_offset_dropped" ->
                item("t3", null, 0f, "2026-01-02T03:04:05.999+02:00", null, 0);
            case "float_widened_to_float64" -> item("f1", null, 0.1f, null, null, 0);
            default -> throw new AssertionError("unknown build vector " + name);
        };
    }

    private static MapItem item(String id, String itemName, float ratio, String when, String rev,
            long views) {
        return new MapItem(itemName, id, 0, ratio, null, null, null, null, null, rev, views,
                when == null ? null : OffsetDateTime.parse(when));
    }
}
