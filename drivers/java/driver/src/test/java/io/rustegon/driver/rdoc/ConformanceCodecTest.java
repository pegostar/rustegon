// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

/**
 * Runner of the shared RDoc codec vectors {@code drivers/conformance/codec/*.yaml} (format:
 * {@code drivers/conformance/README.md} §3, generated from {@code rustegon-doc} by
 * {@code driver_vectors.rs}). TC-DRV-JAVA-001 covers the valid vectors (values, documents,
 * name hashes, non-canonical inputs), TC-DRV-JAVA-003 the inputs that must be rejected. Every
 * test is skipped, with the reason, while the suite is not in the tree (lane DK).
 *
 * <p>Each test collects every failing vector before failing, so one run shows the whole
 * divergence between this codec and the server's.
 */
public class ConformanceCodecTest {
    private static final HexFormat HEX = HexFormat.of();

    @SuppressWarnings("unchecked")
    private static Map<String, Object> vectors(String file) throws IOException {
        Optional<Path> path = TestPaths.conformance().map(p -> p.resolve("codec").resolve(file))
                .filter(Files::isRegularFile);
        Assumptions.assumeTrue(path.isPresent(),
                "drivers/conformance/codec/" + file + " not merged yet (lane DK)");
        return (Map<String, Object>) new Load(LoadSettings.builder().build())
                .loadFromString(Files.readString(path.get(), StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Map<String, Object> root, String key) {
        Object v = root.get(key);
        return v == null ? List.of() : (List<Map<String, Object>>) v;
    }

    private static boolean decodeOnly(Map<String, Object> v) {
        return Boolean.TRUE.equals(v.get("decode_only"));
    }

    /** Runs {@code check}, recording its failure under {@code name}. */
    private static void collect(List<String> failures, Object name, Check check) {
        try {
            check.run();
        } catch (AssertionError | RuntimeException e) {
            failures.add(name + ": " + e);
        }
    }

    @FunctionalInterface
    private interface Check {
        void run();
    }

    private static void same(Object expected, Object actual, String what) {
        if (!Objects.equals(expected, actual)) {
            throw new AssertionError(what + ": expected <" + expected + "> but was <" + actual
                    + ">");
        }
    }

    @Test
    public void tc_drv_java_001_conformance_values() throws IOException {
        Map<String, Object> root = vectors("values.yaml");
        List<String> failures = new ArrayList<>();
        List<Map<String, Object>> values = list(root, "values");
        assertTrue(!values.isEmpty(), "values.yaml has no values");
        for (Map<String, Object> v : values) {
            collect(failures, v.get("name"), () -> {
                byte[] hex = HEX.parseHex((String) v.get("hex"));
                String ext = (String) v.get("ext_json");
                // Decode → both JSON modes, exactly.
                Object decoded = RDocReader.decodeValue(hex);
                same(ext, ExtendedJson.valueToJson(decoded, JsonMode.CANONICAL), "canonical");
                same(v.get("extended_json"), ExtendedJson.valueToJson(decoded, JsonMode.EXTENDED),
                        "extended");
                if (!decodeOnly(v)) {
                    // input and ext_json parse to the same value, which encodes to hex.
                    Object fromExt = ExtendedJson.parseValue(ext);
                    Object fromInput = ExtendedJson.parseValue((String) v.get("input"));
                    same(HEX.formatHex(hex), HEX.formatHex(RDocWriter.encodeValue(fromExt)),
                            "encode(ext_json)");
                    same(HEX.formatHex(hex), HEX.formatHex(RDocWriter.encodeValue(fromInput)),
                            "encode(input)");
                    same(HEX.formatHex(hex), HEX.formatHex(RDocWriter.encodeValue(decoded)),
                            "encode(decode(hex))");
                }
            });
        }
        for (Map<String, Object> v : list(root, "noncanonical")) {
            collect(failures, "noncanonical " + v.get("name"), () -> {
                Object decoded = RDocReader.decodeValue(HEX.parseHex((String) v.get("hex")));
                same(v.get("ext_json"), ExtendedJson.valueToJson(decoded, JsonMode.CANONICAL),
                        "canonical");
                same(v.get("canonical_hex"), HEX.formatHex(RDocWriter.encodeValue(decoded)),
                        "re-encoded");
            });
        }
        assertTrue(failures.isEmpty(), failures.size() + " failing vectors:\n"
                + String.join("\n", failures));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void tc_drv_java_001_conformance_documents() throws IOException {
        Map<String, Object> root = vectors("documents.yaml");
        List<String> failures = new ArrayList<>();
        List<Map<String, Object>> documents = list(root, "documents");
        assertTrue(!documents.isEmpty(), "documents.yaml has no documents");
        for (Map<String, Object> d : documents) {
            collect(failures, d.get("name"), () -> {
                byte[] hex = HEX.parseHex((String) d.get("hex"));
                String ext = (String) d.get("ext_json");
                RDocument decoded = RDocReader.decode(hex);
                same(ext, decoded.toJson(), "decode -> canonical JSON");
                if (!decodeOnly(d)) {
                    same(HEX.formatHex(hex), HEX.formatHex(RDocument.parse(ext).toRDoc()),
                            "encode(ext_json)");
                    same(HEX.formatHex(hex), HEX.formatHex(RDocWriter.encode(decoded)),
                            "encode(decode(hex))");
                }
                Object hashes = d.get("name_hash16");
                for (Map<String, Object> h : hashes == null ? List.<Map<String, Object>>of()
                        : (List<Map<String, Object>>) hashes) {
                    int hash = Xxh3.nameHash16(((String) h.get("name"))
                            .getBytes(StandardCharsets.UTF_8));
                    same(h.get("hash"), String.format("%04x", hash), "name_hash16 " + h.get("name"));
                }
            });
        }
        for (Map<String, Object> d : list(root, "noncanonical")) {
            collect(failures, "noncanonical " + d.get("name"), () -> {
                RDocument decoded = RDocReader.decode(HEX.parseHex((String) d.get("hex")));
                same(d.get("ext_json"), decoded.toJson(), "canonical JSON");
                same(d.get("canonical_hex"), HEX.formatHex(RDocWriter.encode(decoded)),
                        "re-encoded");
            });
        }
        assertTrue(failures.isEmpty(), failures.size() + " failing vectors:\n"
                + String.join("\n", failures));
    }

    @Test
    public void tc_drv_java_003_conformance_invalid_inputs() throws IOException {
        Map<String, Object> root = vectors("invalid.yaml");
        List<String> failures = new ArrayList<>();
        for (Map<String, Object> v : list(root, "documents")) {
            collect(failures, "document " + v.get("name"), () -> rejected(v,
                    () -> RDocReader.decode(HEX.parseHex((String) v.get("hex")))));
        }
        for (Map<String, Object> v : list(root, "values")) {
            collect(failures, "value " + v.get("name"), () -> rejected(v,
                    () -> RDocReader.decodeValue(HEX.parseHex((String) v.get("hex")))));
        }
        for (Map<String, Object> v : list(root, "json")) {
            collect(failures, "json " + v.get("name"), () -> rejected(v, () -> {
                String json = (String) v.get("json");
                if ("document".equals(v.get("kind"))) {
                    // Encoding is part of accepting a document (field-name and size rules).
                    RDocument.parse(json).toRDoc();
                } else {
                    RDocWriter.encodeValue(ExtendedJson.parseValue(json));
                }
            }));
        }
        assertTrue(failures.isEmpty(), failures.size() + " failing vectors:\n"
                + String.join("\n", failures));
    }

    /** {@code action} must fail with an {@link RDocException} carrying the vector's code. */
    private static void rejected(Map<String, Object> v, Check action) {
        int code = ((Number) v.get("code")).intValue();
        try {
            action.run();
        } catch (RDocException e) {
            same(code, e.code(), "code (" + v.get("error") + ", message: " + e.getMessage() + ")");
            return;
        }
        throw new AssertionError("accepted; expected " + v.get("error") + " (" + code + ")"
                + " for " + Arrays.toString(new Object[] {v.get("hex"), v.get("json")}));
    }
}
