// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.robustness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rustegon.driver.CommitOutcomeUnknownException;
import io.rustegon.driver.Filters;
import io.rustegon.driver.RustegonClient;
import io.rustegon.driver.RustegonCollection;
import io.rustegon.driver.Transaction;
import io.rustegon.driver.TransactionOutcome;
import io.rustegon.driver.UnavailableException;
import io.rustegon.driver.rdoc.RDocument;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * TC-DRV-JAVA-030 (java-driver.md §9, testing-strategy.md "Fault injection"): the node is
 * killed (no graceful shutdown) and restarted on the same data directory and gRPC port while
 * one client stays open.
 *
 * <ul>
 *   <li>while the node is down, a read fails with the retryable {@link UnavailableException}
 *       (RGN-3002) within the connect timeout and retry budget, and the commit of a transaction
 *       opened before the kill surfaces as {@link CommitOutcomeUnknownException} (RGN-2006,
 *       PD-122), never as a plain retryable error;
 *   <li>after the restart the same client recovers by itself (channel reconnect and a new
 *       login: the node's sessions died with the process), within {@link #RECOVERY};
 *   <li>every acknowledged write is still there (durability across a crash), the write of
 *       the uncommitted transaction is not, and resolving the unknown commit never reports
 *       {@code COMMITTED}: the restarted node finds the transaction's persisted record and
 *       answers {@code Status} with {@code COMMITTING} ({@code UNKNOWN}) until the server's
 *       {@code txn.liveness_timeout} has passed since its last write, then {@code ABORTED}
 *       ({@code coordinator_lost}); polling reaches {@code ABORTED} within {@link #ABORTED}
 *       (PD-121 option (a'));
 *   <li>new writes succeed on the same client.
 * </ul>
 */
@Tag("integration")
class ReconnectTest {
    private static final int DOCS = 100;
    /** Upper bound for the client to recover after the node is ready again. */
    private static final Duration RECOVERY = Duration.ofSeconds(60);
    /** Bound for the lost transaction to be reported aborted: liveness timeout (5 s) + margin. */
    private static final Duration ABORTED = Duration.ofSeconds(30);

    @Test
    void tc_drv_java_030_kill_and_restart_same_client_recovers() throws Exception {
        try (OwnedServer server = OwnedServer.start();
                RustegonClient client = RustegonClient.create(server.adminSettings()
                        .connectTimeout(Duration.ofSeconds(2))
                        .defaultOperationTimeout(Duration.ofSeconds(10)).build())) {
            client.createDatabase("reconnect");
            client.database("reconnect").createCollection("items");
            RustegonCollection<RDocument> items = client.database("reconnect").collection("items");
            List<RDocument> docs = new ArrayList<>();
            for (int i = 0; i < DOCS; i++) {
                docs.add(new RDocument().append("_id", "c-" + i).append("n", (long) i));
            }
            items.insertMany(docs);
            Transaction open = client.beginTransaction();
            open.collection("reconnect.items").insertOne(RDocument.of("_id", "in-flight"));

            server.kill();

            UnavailableException down = assertThrows(UnavailableException.class,
                    () -> items.findById("c-0"));
            assertTrue(down.isRetryable(), down::toString);
            CommitOutcomeUnknownException unknown =
                    assertThrows(CommitOutcomeUnknownException.class, open::commit);
            assertEquals(2006, unknown.code());

            server.restart();

            long recoveredMs = awaitRecovery(() -> items.findById("c-0").orElseThrow());
            System.out.println("TC-DRV-JAVA-030: client recovered " + recoveredMs
                    + " ms after the node was ready");
            assertEquals(DOCS, items.find(Filters.empty()).toList().size());
            for (int i = 0; i < DOCS; i += 17) {
                assertEquals((long) i, items.findById("c-" + i).orElseThrow().get("n"));
            }
            assertTrue(items.findById("in-flight").isEmpty(),
                    "an uncommitted write survived the crash");
            // PD-121 (a'): UNKNOWN (COMMITTING) until the record expires, then ABORTED; never
            // COMMITTED, which would be a lost abort.
            long deadline = System.nanoTime() + ABORTED.toNanos();
            TransactionOutcome outcome = TransactionOutcome.UNKNOWN;
            while (outcome != TransactionOutcome.ABORTED) {
                assertTrue(System.nanoTime() - deadline < 0,
                        "the lost transaction was never reported aborted");
                try {
                    outcome = unknown.resolve();
                } catch (UnavailableException e) {
                    outcome = TransactionOutcome.UNKNOWN;
                }
                assertNotEquals(TransactionOutcome.COMMITTED, outcome);
                if (outcome != TransactionOutcome.ABORTED) {
                    Thread.sleep(200);
                }
            }

            items.insertOne(RDocument.of("_id", "after-restart"));
            assertTrue(items.findById("after-restart").isPresent());
        }
    }

    /**
     * Retries {@code op} while the node is still unreachable (the channel's reconnect backoff);
     * any other failure is a test failure.
     */
    private static long awaitRecovery(Supplier<?> op) throws InterruptedException {
        long start = System.nanoTime();
        long deadline = start + RECOVERY.toNanos();
        while (true) {
            try {
                op.get();
                return (System.nanoTime() - start) / 1_000_000;
            } catch (UnavailableException e) {
                if (System.nanoTime() - deadline >= 0) {
                    throw new AssertionError("TC-DRV-JAVA-030: the client did not recover within "
                            + RECOVERY, e);
                }
                Thread.sleep(200);
            }
        }
    }
}
