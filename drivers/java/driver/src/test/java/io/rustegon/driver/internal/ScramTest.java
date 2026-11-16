// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.rdoc.TestPaths;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

/**
 * TC-DRV-JAVA-007: SCRAM-SHA-256 client (RFC 7677 §3 test vector, gs2 header {@code n,,},
 * PD-074), defences against hostile server messages, and SASLprep (RFC 4013 §3 examples plus
 * the mapping, prohibition and bidi rules), and the shared vectors of
 * {@code drivers/conformance/scram/vectors.yaml} generated from the server's implementation.
 */
public class ScramTest {
    private static final String NONCE = "rOprNGfwEbeRWgbNEkqO";
    private static final String SERVER_FIRST =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,"
                    + "i=4096";

    @Test
    void tc_drv_java_007_rfc7677_vector() {
        ScramClient c = new ScramClient("user", "pencil".toCharArray(), NONCE);
        assertEquals("n,,n=user,r=rOprNGfwEbeRWgbNEkqO", c.clientFirst());
        assertEquals("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                + "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", c.clientFinal(SERVER_FIRST));
        c.verifyServerFinal("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
    }

    @Test
    void tc_drv_java_007_server_signature_mismatch_is_rejected() {
        ScramClient c = new ScramClient("user", "pencil".toCharArray(), NONCE);
        c.clientFinal(SERVER_FIRST);
        assertThrows(ScramException.class,
                () -> c.verifyServerFinal("v=AAAATRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
        assertThrows(ScramException.class, () -> c.verifyServerFinal("e=other-error"));
        assertThrows(IllegalStateException.class,
                () -> new ScramClient("u", new char[0], NONCE).verifyServerFinal("v=AA=="));
    }

    @Test
    void tc_drv_java_007_hostile_server_first_is_rejected() {
        String[] bad = {
            "garbage",
            "r=someoneElsesNonce1234567890,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            "r=" + NONCE + "short,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            "r=" + NONCE + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4095",
            "r=" + NONCE + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,"
                    + "i=10000001",
            "r=" + NONCE + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=,i=4096",
            "r=" + NONCE + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=!!!,i=4096",
            "r=" + NONCE + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=x",
        };
        for (String s : bad) {
            ScramClient c = new ScramClient("user", "pencil".toCharArray(), NONCE);
            assertThrows(ScramException.class, () -> c.clientFinal(s), s);
        }
    }

    @Test
    void tc_drv_java_007_user_names_are_sasl_escaped_and_nonces_random() {
        assertEquals("a=3Db=2Cc", ScramClient.saslName("a=b,c"));
        String first = new ScramClient("u", "p".toCharArray()).clientFirst();
        String nonce = first.substring(first.indexOf(",r=") + 3);
        assertEquals(24, nonce.length());
        assertEquals(-1, new ScramClient("u", "p".toCharArray()).clientFirst().indexOf(nonce));
    }

    @Test
    void tc_drv_java_007_saslprep_rfc4013_examples() {
        assertEquals("IX", SaslPrep.prepare("I­X"), "soft hyphen mapped to nothing");
        assertEquals("user", SaslPrep.prepare("user"));
        assertEquals("USER", SaslPrep.prepare("USER"), "case preserved");
        assertEquals("a", SaslPrep.prepare("ª"), "NFKC");
        assertEquals("IX", SaslPrep.prepare("Ⅸ"), "NFKC");
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("\u0007"));
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("ا1"),
                "bidi: RandALCat must be first and last");
    }

    @Test
    void tc_drv_java_007_saslprep_mapping_prohibition_bidi() {
        assertEquals(" a b", SaslPrep.prepare(" a　b"), "non-ASCII spaces");
        // U+200B is in both C.1.2 and B.1; like the server's stringprep crate, the space
        // mapping applies first.
        assertEquals("a b", SaslPrep.prepare("a​b"));
        assertEquals("ab", SaslPrep.prepare("a‍b"), "ZWJ mapped to nothing (B.1)");
        assertEquals("", SaslPrep.prepare(""));
        assertEquals("ا1ب", SaslPrep.prepare("ا1ب"));
        assertEquals("pässwörd", SaslPrep.prepare("pässwörd"), "NFKC composes");
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("اaب"),
                "RandAL with L");
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("a"),
                "private use");
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("a\uD800"),
                "lone surrogate");
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("a￾"),
                "non-character");
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("a‎"),
                "LRM (C.8)");
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("a⿰"),
                "ideographic description (C.7)");
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("a󠀁"),
                "language tag (C.9)");
        assertThrows(IllegalArgumentException.class, () -> SaslPrep.prepare("a͸"),
                "unassigned");
        assertEquals("😀x", SaslPrep.prepare("😀x"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> conformanceVectors() throws IOException {
        Optional<Path> path = TestPaths.conformance()
                .map(p -> p.resolve("scram/vectors.yaml")).filter(Files::isRegularFile);
        Assumptions.assumeTrue(path.isPresent(),
                "drivers/conformance/scram/vectors.yaml not merged yet (lane DK, PD-074)");
        return (Map<String, Object>) new Load(LoadSettings.builder().build())
                .loadFromString(Files.readString(path.get(), StandardCharsets.UTF_8));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void tc_drv_java_007_conformance_saslprep() throws IOException {
        List<String> failures = new ArrayList<>();
        for (Map<String, Object> c : (List<Map<String, Object>>) conformanceVectors()
                .get("saslprep")) {
            String input = (String) c.get("input");
            try {
                String out = SaslPrep.prepare(input);
                if (Boolean.TRUE.equals(c.get("error")) || !out.equals(c.get("output"))) {
                    failures.add(c.get("name") + ": got \"" + out + "\"");
                }
            } catch (IllegalArgumentException e) {
                if (!Boolean.TRUE.equals(c.get("error"))) {
                    failures.add(c.get("name") + ": rejected (" + e.getMessage() + ")");
                }
            }
        }
        assertTrue(failures.isEmpty(), String.join("\n", failures));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void tc_drv_java_007_conformance_exchanges() throws IOException {
        List<Map<String, Object>> exchanges =
                (List<Map<String, Object>>) conformanceVectors().get("exchanges");
        assertTrue(!exchanges.isEmpty(), "no SCRAM exchanges");
        for (Map<String, Object> x : exchanges) {
            String name = (String) x.get("name");
            ScramClient c = new ScramClient((String) x.get("user"),
                    ((String) x.get("password")).toCharArray(), (String) x.get("clientNonce"));
            assertEquals(x.get("clientFirst"), c.clientFirst(), name);
            assertEquals(x.get("clientFinal"), c.clientFinal((String) x.get("serverFirst")), name);
            c.verifyServerFinal((String) x.get("serverFinal"));
            // Any other server-final message is rejected: flip one signature character.
            String good = (String) x.get("serverFinal");
            char flipped = good.charAt(2) == 'A' ? 'B' : 'A';
            String bad = good.substring(0, 2) + flipped + good.substring(3);
            ScramClient d = new ScramClient((String) x.get("user"),
                    ((String) x.get("password")).toCharArray(), (String) x.get("clientNonce"));
            d.clientFirst();
            d.clientFinal((String) x.get("serverFirst"));
            assertThrows(ScramException.class, () -> d.verifyServerFinal(bad), name);
        }
    }
}
