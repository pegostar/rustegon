// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.rdoc.TestPaths;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Client API checks without a server (FR-DRV-002, FR-DRV-003): the builders produce exactly
 * the golden AST vectors (TC-DRV-JAVA-011, PD-070) and the retry policy passes every scenario of
 * {@code retry.yaml} on the in-process fake server (TC-DRV-JAVA-017, PD-073).
 */
class ClientApiUnitTest {
    static Path conformance(String relative) {
        Path dir = TestPaths.conformance().orElse(null);
        Assumptions.assumeTrue(dir != null, "drivers/conformance is not present");
        return dir.resolve(relative);
    }

    private static void none(List<String> failures) {
        assertTrue(failures.isEmpty(), failures.size() + " failures:\n"
                + String.join("\n", failures));
    }

    @Test
    void tc_drv_java_011_filter_builders_match_ast_filters_json() throws Exception {
        none(AstVectors.check(conformance("ast/filters.json")));
    }

    @Test
    void tc_drv_java_011_update_builders_match_ast_updates_json() throws Exception {
        none(AstVectors.check(conformance("ast/updates.json")));
    }

    @Test
    void tc_drv_java_011_collection_statements_match_ast_statements_json() throws Exception {
        none(AstVectors.check(conformance("ast/statements.json")));
    }

    @Test
    void tc_drv_java_017_retry_scenarios_on_the_fake_server() throws Exception {
        none(RetryScenarios.run(conformance("retry.yaml")));
    }

    @Test
    void tc_drv_java_017_backoff_is_full_jitter_with_cap() {
        for (int n = 1; n <= 12; n++) {
            long ceiling = Math.min(Operations.BACKOFF_CAP_MS, 10L << Math.min(n - 1, 20));
            for (int i = 0; i < 200; i++) {
                long b = Operations.backoffMillis(n, null);
                assertTrue(b >= 0 && b <= ceiling, "retry " + n + ": " + b);
            }
        }
        assertEquals(200, Math.max(200, Operations.backoffMillis(1,
                java.time.Duration.ofMillis(200))));
        assertTrue(Operations.backoffMillis(1, java.time.Duration.ofMillis(200)) >= 200);
    }
}
