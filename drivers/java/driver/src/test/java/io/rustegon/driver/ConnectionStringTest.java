// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.internal.UuidV7;
import io.rustegon.driver.rdoc.TestPaths;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

/**
 * TC-DRV-JAVA-008: the {@code rustegon://} connection string (DEC-014: host, port, user,
 * password, database), the settings builder and its defaults (java-driver.md §2),
 * credential redaction (CLAUDE.md rule 9), and the shared cases of
 * {@code drivers/conformance/connstring.yaml}; TC-DRV-JAVA-010 part: UUIDv7 request ids
 * (protocol.md §2).
 */
public class ConnectionStringTest {
    @Test
    void tc_drv_java_008_api_key_is_a_secret() {
        ConnectionString cs = ConnectionString.parse("rustegon://db1/?appName=a&apiKey=rgn_a_b");
        assertEquals("APIKEY", cs.authMechanism().orElseThrow());
        assertFalse(cs.options().containsKey("apiKey"), "the key stays out of options()");
        assertFalse(cs.toString().contains("rgn_a_b"));
        assertTrue(cs.toString().endsWith("&apiKey=‹redacted›"));
        assertEquals(RustegonCredential.apiKey("rgn_a_b"), RustegonClientSettings
                .fromConnectionString("rustegon://db1/?apiKey=rgn_a_b").credential()
                .orElseThrow());
    }

    @Test
    void tc_drv_java_008_dec014_full_form() {
        ConnectionString cs = ConnectionString.parse(
                "rustegon://app_user:s%3Acr%40t@node1.example.com:7701,node2:7702/shop"
                        + "?tls=true&appName=orders&connectTimeoutMs=5000");
        assertEquals(List.of("node1.example.com:7701", "node2:7702"), cs.endpoints());
        assertEquals("app_user", cs.user().orElseThrow());
        assertArrayEquals("s:cr@t".toCharArray(), cs.password().orElseThrow());
        assertEquals("shop", cs.database().orElseThrow());
        assertEquals("orders", cs.options().get("appName"));
        assertFalse(cs.toString().contains("s:cr@t"));
        assertFalse(cs.toString().contains("s%3Acr"));
        assertTrue(cs.toString().contains("‹redacted›"));

        RustegonClientSettings s = RustegonClientSettings.fromConnectionString(
                "rustegon://app_user:pw@node1/shop?appName=orders&operationTimeoutMs=1500"
                        + "&connectionsPerEndpoint=3&retryWrites=false"
                        + "&readConsistency=bounded_staleness&maxStalenessMs=5000"
                        + "&writeConcern=majority&tlsCaFile=ca.crt");
        assertEquals(List.of("node1:7700"), s.endpoints());
        RustegonCredential c = s.credential().orElseThrow();
        assertEquals(RustegonCredential.Mechanism.SCRAM_SHA_256, c.mechanism());
        assertEquals("app_user", c.user());
        assertFalse(c.toString().contains("pw"));
        assertEquals("shop", s.defaultDatabase().orElseThrow());
        assertEquals(Duration.ofMillis(1500), s.defaultOperationTimeout());
        assertEquals(3, s.connectionsPerEndpoint());
        assertFalse(s.retryWrites());
        assertTrue(s.retryReads());
        assertEquals(ReadConsistency.BOUNDED_STALENESS, s.readConsistency().orElseThrow());
        assertEquals(Duration.ofSeconds(5), s.maxStaleness().orElseThrow());
        assertEquals(WriteConcern.MAJORITY, s.writeConcern().orElseThrow());
        assertEquals(Path.of("ca.crt"), s.tls().caCertificate().orElseThrow());
        assertFalse(s.toString().contains("pw"));
    }

    @Test
    void tc_drv_java_008_hosts_ports_and_defaults() {
        assertEquals(List.of("localhost:7700"),
                ConnectionString.parse("rustegon://localhost").endpoints());
        assertEquals(List.of("[::1]:7700", "[fe80::1]:9000", "10.0.0.1:1"),
                ConnectionString.parse("rustegon://[::1],[fe80::1]:9000,10.0.0.1:1/").endpoints());
        ConnectionString bare = ConnectionString.parse("rustegon://h:7700");
        assertTrue(bare.user().isEmpty());
        assertTrue(bare.password().isEmpty());
        assertTrue(bare.database().isEmpty());
        RustegonClientSettings s = RustegonClientSettings.fromConnectionString("rustegon://h");
        assertTrue(s.credential().isEmpty());
        assertFalse(s.tls().enabled(), "plain text by default (ADR-034)");
        assertTrue(RustegonClientSettings.fromConnectionString("rustegon://h?tlsCaFile=ca.crt")
                .tls().enabled(), "a tls* option implies TLS");
        assertTrue(RustegonClientSettings.fromConnectionString("rustegon://h?authMechanism=X509")
                .tls().enabled(), "X.509 implies TLS");
        assertFalse(TlsSettings.builder().build().enabled());
        assertTrue(TlsSettings.builder().serverNameOverride("n").build().enabled());
        assertThrows(IllegalArgumentException.class,
                () -> TlsSettings.builder().enabled(false).serverNameOverride("n").build());
        assertTrue(RustegonClientSettings.builder().endpoints("h")
                .credential(RustegonCredential.x509()).build().tls().enabled());
        assertEquals(RustegonClientSettings.DEFAULT_CONNECTIONS_PER_ENDPOINT,
                s.connectionsPerEndpoint());
        assertEquals(Duration.ofSeconds(10), s.connectTimeout());
        assertEquals(Duration.ofSeconds(30), s.defaultOperationTimeout());
        assertTrue(s.retryReads() && s.retryWrites());
        assertTrue(s.readConsistency().isEmpty());
        assertTrue(s.writeConcern().isEmpty());
        assertFalse(RustegonClientSettings.fromConnectionString("rustegon://h?TLS=false")
                .tls().enabled(), "option names are case-insensitive");
        // User without a password: SCRAM with the password supplied elsewhere is not possible
        // from the string alone, but the user is kept.
        assertEquals("bob", ConnectionString.parse("rustegon://bob@h").user().orElseThrow());
        assertEquals("p+q", new String(ConnectionString.parse("rustegon://u:p+q@h")
                .password().orElseThrow()), "+ is not a space");
        assertEquals("日本", ConnectionString.parse("rustegon://h/%E6%97%A5%E6%9C%AC")
                .database().orElseThrow());
        assertEquals(RustegonCredential.Mechanism.X509, RustegonClientSettings.builder()
                .connectionString("rustegon://h?authMechanism=X509&tlsCertificateFile=c.pem"
                        + "&tlsKeyFile=k.pem").build().credential().orElseThrow().mechanism());
    }

    @Test
    void tc_drv_java_008_invalid_strings_are_rejected_without_leaking_the_password() {
        String[] bad = {
            "mongodb://h", "rustegon://", "rustegon://h:0", "rustegon://h:65536",
            "rustegon://h:x", "rustegon://::1", "rustegon://[::1", "rustegon://h?bogus=1",
            "rustegon://h?tls=maybe", "rustegon://h?tls=true&tls=false", "rustegon://h?appName",
            "rustegon://h/a/b", "rustegon://:secret@h", "rustegon://h,", "rustegon://h?tls=false"
                    + "&tlsCaFile=x", "rustegon://h?tlsCertificateFile=c.pem",
            "rustegon://h?connectTimeoutMs=0", "rustegon://h?authMechanism=PLAIN",
            "rustegon://h?tls=false&authMechanism=X509",
            "RUSTEGON://h", "rustegon+srv://cluster.example.com", "rustegon://u:p@ss@h",
            "rustegon://u:%ZZsecret@h", "rustegon://u:%E6secret@h", "rustegon://h_ost!/db",
        };
        for (String s : bad) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> RustegonClientSettings.fromConnectionString(s), s);
            assertFalse(String.valueOf(e.getMessage()).contains("secret"), s);
        }
    }

    @Test
    void tc_drv_java_008_builder_validation() {
        assertThrows(IllegalStateException.class, () -> RustegonClientSettings.builder().build());
        assertThrows(IllegalArgumentException.class, () -> RustegonClientSettings
                .fromConnectionString("rustegon://h?readConsistency=bounded_staleness"));
        assertThrows(IllegalStateException.class, () -> RustegonClientSettings.builder()
                .endpoints("h").readConsistency(ReadConsistency.BOUNDED_STALENESS).build());
        // X.509 without a client certificate: valid settings, refused when the client is made.
        RustegonClientSettings x509 = RustegonClientSettings.builder()
                .endpoints("h").credential(RustegonCredential.x509()).build();
        assertThrows(IllegalArgumentException.class, () -> RustegonClient.create(x509));
        assertThrows(IllegalArgumentException.class,
                () -> RustegonClientSettings.builder().maxRetries(11));
        assertEquals(0, RustegonClientSettings.builder().endpoints("h").maxRetries(0).build()
                .maxRetries());
        assertThrows(IllegalArgumentException.class,
                () -> RustegonClientSettings.builder().connectionsPerEndpoint(0));
        assertThrows(IllegalArgumentException.class,
                () -> RustegonClientSettings.builder().defaultOperationTimeout(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> RustegonCredential.scram("", "p"
                .toCharArray()));
        assertThrows(IllegalArgumentException.class,
                () -> RustegonCredential.apiKey("rgn key".toCharArray()));
        RustegonCredential key = RustegonCredential.apiKey("rgn_abc".toCharArray());
        assertFalse(key.toString().contains("rgn_abc"));
        char[] pw = "hunter2hunter2".toCharArray();
        RustegonCredential c = RustegonCredential.scram("u", pw);
        java.util.Arrays.fill(pw, 'x');
        assertArrayEquals("hunter2hunter2".toCharArray(), c.secret(), "defensive copy");
        assertEquals(List.of("h:7700", "[::1]:7701"),
                RustegonClientSettings.builder().endpoints("h", "[::1]:7701").build().endpoints());
    }

    @Test
    void tc_drv_java_010_request_ids_are_uuid_v7() {
        long before = System.currentTimeMillis();
        UUID a = UuidV7.next();
        UUID b = UuidV7.next();
        assertEquals(7, a.version());
        assertEquals(2, a.variant(), "RFC 9562 variant");
        assertFalse(a.equals(b));
        long ms = a.getMostSignificantBits() >>> 16;
        assertTrue(ms >= before && ms <= System.currentTimeMillis());
        assertEquals(a.toString().toLowerCase(), a.toString(), "canonical hyphenated text");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void tc_drv_java_008_conformance_connstring_cases() throws IOException {
        Optional<Path> file = TestPaths.conformance().map(p -> p.resolve("connstring.yaml"))
                .filter(Files::isRegularFile);
        Assumptions.assumeTrue(file.isPresent(),
                "drivers/conformance/connstring.yaml not merged yet (lane DK)");
        Map<String, Object> root = (Map<String, Object>) new Load(LoadSettings.builder().build())
                .loadFromString(Files.readString(file.get(), StandardCharsets.UTF_8));
        Map<String, Object> defaults = (Map<String, Object>) root.get("defaults");
        List<Map<String, Object>> cases = (List<Map<String, Object>>) root.get("cases");
        assertFalse(cases.isEmpty(), "no cases");
        List<String> failures = new ArrayList<>();
        for (Map<String, Object> c : cases) {
            String name = (String) c.get("name");
            String uri = (String) c.get("uri");
            if (Boolean.TRUE.equals(c.get("valid"))) {
                try {
                    Map<String, Object> want = new HashMap<>(defaults);
                    Object expect = c.get("expect");
                    if (expect != null) {
                        want.putAll((Map<String, Object>) expect);
                    }
                    Map<String, Object> got = observed(uri);
                    for (String key : defaults.keySet()) {
                        if (!Objects.equals(normalize(want.get(key)), got.get(key))) {
                            failures.add(name + ": " + key + " expected <" + want.get(key)
                                    + "> but was <" + got.get(key) + ">");
                        }
                    }
                } catch (RuntimeException e) {
                    failures.add(name + ": rejected (" + e + ")");
                }
            } else {
                try {
                    RustegonClientSettings.fromConnectionString(uri);
                    failures.add(name + ": accepted, expected IllegalArgumentException");
                } catch (IllegalArgumentException e) {
                    String password = rawPassword(uri);
                    if (password != null && password.length() >= 3
                            && String.valueOf(e.getMessage()).contains(password)) {
                        failures.add(name + ": the message quotes the password");
                    }
                } catch (RuntimeException e) {
                    failures.add(name + ": " + e + ", expected IllegalArgumentException");
                }
            }
        }
        assertTrue(failures.isEmpty(), failures.size() + " failing cases:\n"
                + String.join("\n", failures));
    }

    /** The settings of a string, under the key names of connstring.yaml. */
    private static Map<String, Object> observed(String uri) {
        ConnectionString cs = ConnectionString.parse(uri);
        RustegonClientSettings s = RustegonClientSettings.fromConnectionString(uri);
        Map<String, Object> out = new HashMap<>();
        List<Object> hosts = new ArrayList<>();
        for (String e : s.endpoints()) {
            int colon = e.lastIndexOf(':');
            String host = e.substring(0, colon);
            if (host.startsWith("[")) {
                host = host.substring(1, host.length() - 1);
            }
            hosts.add(Map.of("host", host, "port", Long.parseLong(e.substring(colon + 1))));
        }
        out.put("hosts", hosts);
        out.put("user", cs.user().orElse(null));
        out.put("password", cs.password().map(String::new).orElse(null));
        out.put("database", s.defaultDatabase().orElse(null));
        out.put("tls", s.tls().enabled());
        // The option text: a Path would use the platform's separators.
        out.put("tlsCaFile", cs.options().get("tlsCaFile"));
        out.put("tlsServerName", cs.options().get("tlsServerName"));
        out.put("tlsCertificateFile", cs.options().get("tlsCertificateFile"));
        out.put("tlsKeyFile", cs.options().get("tlsKeyFile"));
        // The credential when the string makes one, else the mechanism it only names.
        out.put("authMechanism", s.credential().map(c -> switch (c.mechanism()) {
            case SCRAM_SHA_256 -> "SCRAM-SHA-256";
            case X509 -> "X509";
            case API_KEY -> "APIKEY";
        }).or(cs::authMechanism).orElse(null));
        out.put("applicationName", s.applicationName().orElse(null));
        out.put("connectTimeoutMs", s.connectTimeout().toMillis());
        out.put("operationTimeoutMs", s.defaultOperationTimeout().toMillis());
        out.put("readConsistency", s.readConsistency()
                .map(r -> r.name().toLowerCase(Locale.ROOT)).orElse(null));
        out.put("maxStalenessMs", s.maxStaleness().map(Duration::toMillis).orElse(null));
        out.put("writeConcern", s.writeConcern()
                .map(w -> w.name().toLowerCase(Locale.ROOT)).orElse(null));
        out.put("retryReads", s.retryReads());
        out.put("retryWrites", s.retryWrites());
        out.put("maxRetries", (long) s.maxRetries());
        out.put("connectionsPerEndpoint", (long) s.connectionsPerEndpoint());
        return out;
    }

    /** YAML integers to {@code long}, recursively, so they compare with the observed values. */
    @SuppressWarnings("unchecked")
    private static Object normalize(Object v) {
        if (v instanceof Number n) {
            return n.longValue();
        }
        if (v instanceof List<?> l) {
            return l.stream().map(ConnectionStringTest::normalize).toList();
        }
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> out = new HashMap<>();
            ((Map<String, Object>) m).forEach((k, x) -> out.put(k, normalize(x)));
            return out;
        }
        return v;
    }

    /** The raw password of a string, or {@code null}. */
    private static String rawPassword(String uri) {
        int start = uri.indexOf("://");
        int at = uri.lastIndexOf('@');
        if (start < 0 || at < start) {
            return null;
        }
        String userInfo = uri.substring(start + 3, at);
        int colon = userInfo.indexOf(':');
        return colon < 0 ? null : userInfo.substring(colon + 1);
    }
}
