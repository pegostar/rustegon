// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.grpc.StatusRuntimeException;
import io.rustegon.driver.rdoc.RDocument;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-030, fake-server part (PD-122): a {@code Commit} that fails in transport after it
 * was sent (no {@code ErrorDetail}: connection reset, node killed) has an unknown outcome. It
 * surfaces as {@link CommitOutcomeUnknownException} (RGN-2006) resolved through
 * {@code TransactionService.Status}, and {@code withTransaction} never re-runs the callback for
 * it, which could apply the transaction twice. The real kill/restart is
 * {@code robustness.ReconnectTest}.
 */
class CommitTransportUnitTest {
    private static FakeServer fake(Map<String, List<Map<String, Object>>> script)
            throws IOException {
        return new FakeServer(script, y -> ConformanceValues.value(y, r -> null, s -> s));
    }

    private static RustegonClient client(FakeServer server) {
        return RustegonClient.create(RustegonClientSettings.builder()
                .endpoints(server.endpoint()).tls(TlsSettings.disabled()).defaultDatabase("fake")
                .credential(RustegonCredential.apiKey("rgn_fake_key")).build());
    }

    @Test
    void tc_drv_java_030_manual_commit_transport_failure_is_outcome_unknown() throws Exception {
        Map<String, List<Map<String, Object>>> script = Map.of(
                "TransactionService.Commit", List.of(Map.of("transport", "UNAVAILABLE")),
                "TransactionService.Status", List.of(
                        Map.of("ok", Map.of("state", "TRANSACTION_STATE_ABORTED"))));
        try (FakeServer server = fake(script); RustegonClient client = client(server)) {
            CommitOutcomeUnknownException e;
            try (Transaction txn = client.beginTransaction()) {
                txn.collection("c").insertOne(RDocument.of("_id", 1));
                e = assertThrows(CommitOutcomeUnknownException.class, txn::commit);
            }
            assertEquals(2006, e.code());
            assertInstanceOf(StatusRuntimeException.class, rootCause(e));
            assertEquals(TransactionOutcome.ABORTED, e.resolve());
            // Never retried, and close() leaves an unknown outcome alone.
            assertEquals(1, server.calls("TransactionService.Commit").size());
            assertEquals(0, server.calls("TransactionService.Rollback").size());
        }
    }

    @Test
    void tc_drv_java_030_with_transaction_resolves_transport_failure_without_rerun()
            throws Exception {
        Map<String, List<Map<String, Object>>> script = Map.of(
                "TransactionService.Commit", List.of(Map.of("transport", "UNAVAILABLE")),
                "TransactionService.Status", List.of(
                        Map.of("ok", Map.of("state", "TRANSACTION_STATE_COMMITTED"))));
        try (FakeServer server = fake(script); RustegonClient client = client(server)) {
            AtomicInteger runs = new AtomicInteger();
            String result = client.withTransaction(txn -> {
                runs.incrementAndGet();
                txn.collection("c").insertOne(RDocument.of("_id", 1));
                return "done";
            });
            assertEquals("done", result);
            assertEquals(1, runs.get());
            assertEquals(1, server.calls("TransactionService.Begin").size());
            assertEquals(1, server.calls("TransactionService.Status").size());
            assertEquals(0, server.calls("TransactionService.Rollback").size());
        }
    }

    private static Throwable rootCause(Throwable t) {
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }
}
